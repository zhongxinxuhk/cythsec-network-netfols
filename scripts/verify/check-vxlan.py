#!/usr/bin/env python3
"""V014 VXLAN 回归：VNI、基础 flags、内层以太网/VLAN/IPv4/IPv6 的有界解析。

语料由本脚本按 RFC 7348 独立拼字节，**不调用 Rust 编码器**。`--tshark` 让
Wireshark 解同一份 pcap，比较 VNI、内层 MAC/VLAN 与内层 IP；这样
“我们的实现和我们的期望值一起错”不会变成绿。

检查项：
  1. 有效 VXLAN：IPv4/IPv6 内层、单层 VLAN、QinQ、ARP、legacy 8472、抓包截断。
  2. 负例：7 字节头、I 位为 0、保留位非零、完整抓包下内层不足、三层 VLAN。
  3. 主流水线：外层 UDP 流保留，内层 IP 不另造 FlowRecord。
  4. 独立采集器：事件字段与统计行逐项可核对。
  5. 反向注入：事件 VNI/MAC/VLAN、记录集合、统计、tshark 对照任一被改坏必须判红。
"""

import argparse
import contextlib
import copy
import ipaddress
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VXLAN_BIN = Path(os.environ.get("VXLAN_BIN", ROOT / "target/debug/cythsec-vxlan"))
ANALYZE_BIN = Path(os.environ.get("ANALYZE_BIN", ROOT / "target/debug/cythsec-analyze"))

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
VXLAN_PORT = 4789
VXLAN_LEGACY_PORT = 8472


def run(args, check=True):
    p = subprocess.run([str(v) for v in args], text=True, capture_output=True, timeout=60)
    if check and p.returncode:
        raise AssertionError(f"{args[0]} 失败（{p.returncode}）：{p.stderr[-1600:]}")
    return p


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src, dst, proto, payload, ident=1):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64, proto, 0, src, dst)
    c = checksum(hdr)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64, proto, c, src, dst)
    return hdr + payload


def ipv6(src, dst, next_header, payload):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), next_header, 64, src, dst) + payload


def udp(sport, dport, payload):
    # 校验和留 0：本门禁不校验 UDP 校验和（与主流水线“校验和卸载”边界一致）。
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def eth(dst, src, ether_type, payload):
    return dst + src + struct.pack("!H", ether_type) + payload


def tagged_eth(dst, src, tags, ether_type, payload):
    out = dst + src
    for tag in tags:
        out += struct.pack("!HH", 0x8100, tag & 0x0FFF)
    out += struct.pack("!H", ether_type)
    return out + payload


def mac(text):
    return bytes.fromhex(text.replace(":", ""))


def vxlan(vni, inner, flags=0x08, reserved=0):
    return struct.pack("!BBBB", flags, 0, 0, 0) + vni.to_bytes(3, "big") + bytes([reserved]) + inner


def outer4(sport, dport, payload, src=b"\xc0\x00\x02\x01", dst=b"\xc0\x00\x02\x02"):
    return eth(
        mac("aa:bb:cc:dd:ee:ff"),
        mac("00:11:22:33:44:55"),
        ETH_IPV4,
        ipv4(src, dst, 17, udp(sport, dport, payload)),
    )


def outer6(sport, dport, payload):
    src = ipaddress.IPv6Address("2001:db8::1").packed
    dst = ipaddress.IPv6Address("2001:db8::2").packed
    return eth(
        mac("aa:bb:cc:dd:ee:ff"),
        mac("00:11:22:33:44:55"),
        ETH_IPV6,
        ipv6(src, dst, 17, udp(sport, dport, payload)),
    )


def write_pcap(path, records, linktype=1):
    """records: [frame_bytes | (frame_bytes, orig_len)]。"""
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, item in enumerate(records):
        frame, orig_len = item if isinstance(item, tuple) else (item, len(item))
        out += struct.pack("<IIII", 1_700_000_000 + i, i * 1000, len(frame), orig_len)
        out += frame
    path.write_bytes(out)


def parse_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def parse_stats(text, prefix, marker):
    for line in text.splitlines():
        start = f"[{prefix}] "
        if not line.startswith(start):
            continue
        body = line[len(start) :]
        if not body.startswith(marker + " "):
            continue
        out = {}
        for part in body.split():
            if "=" in part:
                k, v = part.split("=", 1)
                with contextlib.suppress(ValueError):
                    out[k] = int(v)
        if out:
            return out
    raise AssertionError(f"缺少 {prefix} {marker} 统计行：{text[-1200:]}")


def corpus(path):
    """返回 (frames, expected_events)。帧顺序固定：1..6 有效，7..11 负例，12 非 VXLAN。"""
    arp = struct.pack("!HHBBH6s4s6s4s", 1, ETH_IPV4, 6, 4, 1,
                      mac("00:11:22:33:44:55"), b"\x0a\x00\x00\x01",
                      b"\x00" * 6, b"\x0a\x00\x00\x02")
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x00\x00\x01\x00\x01"
    tcp = struct.pack("!HHIIBBHHH", 40000, 80, 1, 0, 5 << 4, 0x02, 65535, 0, 0)
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1)

    inner_a = eth(mac("00:11:22:33:44:55"), mac("66:77:88:99:aa:bb"), ETH_IPV4,
                  ipv4(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 17, udp(12345, 53, dns)))
    inner_b = tagged_eth(mac("00:11:22:33:44:55"), mac("66:77:88:99:aa:bb"), [10], ETH_IPV4,
                         ipv4(b"\x0a\x01\x00\x01", b"\x0a\x01\x00\x02", 6, tcp))
    inner_c = tagged_eth(mac("00:11:22:33:44:55"), mac("66:77:88:99:aa:bb"), [20, 30], ETH_IPV6,
                         ipv6(ipaddress.IPv6Address("2001:db8::1").packed,
                              ipaddress.IPv6Address("2001:db8::2").packed, 17, udp(12345, 53, dns)))
    inner_d = eth(mac("ff:ff:ff:ff:ff:ff"), mac("00:11:22:33:44:55"), ETH_ARP, arp)
    inner_e = eth(mac("00:11:22:33:44:55"), mac("66:77:88:99:aa:bb"), ETH_IPV4,
                  ipv4(b"\x0a\x02\x00\x01", b"\x0a\x02\x00\x02", 1, icmp))
    inner_f = eth(mac("00:11:22:33:44:55"), mac("66:77:88:99:aa:bb"), ETH_IPV4,
                  ipv4(b"\x0a\x03\x00\x01", b"\x0a\x03\x00\x02", 17, udp(12345, 53, dns)))

    valid = [
        outer4(55555, VXLAN_PORT, vxlan(100, inner_a)),
        outer4(55556, VXLAN_PORT, vxlan(200, inner_b)),
        outer6(55557, VXLAN_PORT, vxlan(300, inner_c)),
        outer4(55558, VXLAN_PORT, vxlan(0, inner_d)),
        outer4(55559, VXLAN_LEGACY_PORT, vxlan(0xFFFFFF, inner_e)),
    ]
    full_f = outer4(55560, VXLAN_PORT, vxlan(400, inner_f))
    # caplen 截到 VXLAN 头 + 10 字节内层：完整抓包下是畸形，抓包截断下只记 capture_truncated。
    short_f = full_f[:14 + 20 + 8 + 8 + 10]
    valid.append((short_f, len(full_f)))

    short_header = outer4(55561, VXLAN_PORT, b"\x08" + b"\x00" * 6)
    missing_i = outer4(55562, VXLAN_PORT, vxlan(500, inner_a, flags=0))
    reserved = outer4(55563, VXLAN_PORT, vxlan(501, inner_a, reserved=1))
    inner_short = outer4(55564, VXLAN_PORT, vxlan(502, inner_a[:10]))
    three_vlans = outer4(
        55565,
        VXLAN_PORT,
        vxlan(503, tagged_eth(mac("00:11:22:33:44:55"), mac("66:77:88:99:aa:bb"),
                              [1, 2, 3], ETH_IPV4,
                              ipv4(b"\x0a\x04\x00\x01", b"\x0a\x04\x00\x02", 17, udp(1, 2, b"")))),
    )
    non_vxlan = outer4(55566, 9999, b"\x00" * 8)
    frames = valid + [short_header, missing_i, reserved, inner_short, three_vlans, non_vxlan]
    write_pcap(path, frames)

    expected = {
        1: dict(vni=100, vlan=[], etype=ETH_IPV4, src="10.0.0.1", dst="10.0.0.2", proto=17, complete=True),
        2: dict(vni=200, vlan=[10], etype=ETH_IPV4, src="10.1.0.1", dst="10.1.0.2", proto=6, complete=True),
        3: dict(vni=300, vlan=[20, 30], tshark_vlan=[30], etype=ETH_IPV6,
                src="2001:db8::1", dst="2001:db8::2", proto=17, complete=True),
        4: dict(vni=0, vlan=[], etype=ETH_ARP, src=None, dst=None, proto=None, complete=None,
                src_mac="00:11:22:33:44:55", dst_mac="ff:ff:ff:ff:ff:ff"),
        5: dict(vni=0xFFFFFF, vlan=[], etype=ETH_IPV4, src="10.2.0.1", dst="10.2.0.2", proto=1, complete=True),
        6: dict(vni=400, vlan=[], etype=None, src=None, dst=None, proto=None, complete=False),
    }
    return expected


def check_events(events, expected):
    assert len(events) == 6, f"应有 6 条有效 VXLAN 事件，实际 {len(events)}"
    for ev in events:
        f = ev["frame"]
        exp = expected[f]
        assert ev["vni"] == exp["vni"], f"frame {f} VNI 不符: {ev['vni']} != {exp['vni']}"
        assert ev["inner_vlan_ids"] == exp["vlan"], f"frame {f} VLAN 不符: {ev['inner_vlan_ids']}"
        if f == 6:
            assert ev["inner_truncated"] is True, "抓包截断帧应标记 inner_truncated"
            assert ev["inner_ether_type"] is None, "抓包截断帧不应伪造内层类型"
            assert ev["capture_truncated"] is True, "抓包截断帧应标记 capture_truncated"
            continue
        assert ev["inner_src_mac"] == exp.get("src_mac", "66:77:88:99:aa:bb"), f"frame {f} 内层源 MAC 不符"
        assert ev["inner_dst_mac"] == exp.get("dst_mac", "00:11:22:33:44:55"), f"frame {f} 内层目的 MAC 不符"
        assert ev["inner_ether_type"] == exp["etype"], f"frame {f} EtherType 不符"
        assert ev["inner_vlan_ids"] == exp["vlan"], f"frame {f} VLAN 不符"
        assert ev["inner_src_ip"] == exp["src"], f"frame {f} 内层源地址不符"
        assert ev["inner_dst_ip"] == exp["dst"], f"frame {f} 内层目的地址不符"
        assert ev["inner_ip_protocol"] == exp["proto"], f"frame {f} 内层协议不符"
        assert ev["inner_complete"] is exp["complete"] if exp["complete"] is not None else ev["inner_complete"] is True, \
            f"frame {f} 内层完整性不符"
        if exp["complete"] is None:
            assert ev["inner_ip_complete"] is None, f"frame {f} 非 IP 内层不应伪造完整性"
        else:
            assert ev["inner_ip_complete"] is exp["complete"], f"frame {f} 内层 IP 完整性不符"
    assert events[0]["outer_dst_port"] == VXLAN_PORT
    assert events[4]["outer_dst_port"] == VXLAN_LEGACY_PORT


def check_stats(stats):
    wanted = {
        "vxlan_frames": 6,
        "vni_zero": 1,
        "vlan_tagged": 2,
        "inner_ipv4": 3,
        "inner_ipv6": 1,
        "inner_arp": 1,
        "inner_other": 0,
        "inner_complete": 5,
        "inner_incomplete": 1,
        "capture_truncated": 1,
        "truncated": 2,
        "malformed": 3,
        "missing_i_flag": 1,
        "reserved_nonzero": 1,
        "too_many_vlans": 1,
        "non_vxlan": 1,
        "decode_errors": 0,
    }
    for k, v in wanted.items():
        assert stats.get(k) == v, f"统计 {k} 期望 {v}，实际 {stats.get(k)}: {stats}"


def check_flows(records):
    assert len(records) == 12, f"应为 12 条外层流（每帧一条），实际 {len(records)}"
    for r in records:
        flow = r["flow"]
        assert flow["dst_port"] in (VXLAN_PORT, VXLAN_LEGACY_PORT, 9999), \
            f"出现了非外层流记录: {flow}"
        assert flow["proto"] == 17, f"VXLAN 外层应为 UDP: {flow}"


def check_tshark(rows, expected):
    assert len(rows) == 6, f"tshark 应解出 6 帧 VXLAN，实际 {len(rows)}: {rows}"
    for row in rows:
        parts = row.split("|")
        assert len(parts) == 12, f"tshark 列数不符: {row}"
        frame = int(parts[0])
        exp = expected[frame]
        assert int(parts[1]) == exp["vni"], f"tshark frame {frame} VNI 不符: {row}"
        assert parts[2] == "True", f"tshark frame {frame} I 位不符: {row}"
        if frame == 6:
            continue
        assert parts[3] == exp.get("src_mac", "66:77:88:99:aa:bb"), f"tshark frame {frame} 内层源 MAC: {row}"
        assert parts[4] == exp.get("dst_mac", "00:11:22:33:44:55"), f"tshark frame {frame} 内层目的 MAC: {row}"
        vlan = [int(v) for v in parts[5].split(",") if v]
        # `occurrence=l` 取最内层 VLAN；QinQ 的外层 20 由事件检查覆盖。
        assert vlan == exp.get("tshark_vlan", exp["vlan"]), f"tshark frame {frame} VLAN: {row}"
        if exp["etype"] == ETH_IPV4:
            assert parts[6] == exp["src"] and parts[8] == exp["dst"], f"tshark frame {frame} IPv4: {row}"
            assert parts[10] == str(exp["proto"]), f"tshark frame {frame} IP proto: {row}"
        elif exp["etype"] == ETH_IPV6:
            assert parts[7] == exp["src"] and parts[9] == exp["dst"], f"tshark frame {frame} IPv6: {row}"
            assert parts[11] == str(exp["proto"]), f"tshark frame {frame} IPv6 next: {row}"
        else:
            # ARP 内层没有 IP；tshark 的 `ip.src` 此时仍可能显示外层地址，
            # 因此不在这一列断言“无内层 IP”。事件字段已覆盖该结论。
            pass


def expect_injection(name, fn):
    try:
        fn()
    except AssertionError:
        print(f"  ✓ 反向注入被检出：{name}")
        return
    raise AssertionError(f"反向注入未被检出：{name}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", action="store_true")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="cythsec-vxlan-") as td:
        td = Path(td)
        pcap = td / "vxlan.pcap"
        expected = corpus(pcap)
        events_path = td / "events.jsonl"
        stats_path = td / "stats.txt"

        p = run([VXLAN_BIN, "--pcap", pcap, "-o", events_path])
        stats_path.write_text(p.stderr, encoding="utf-8")
        events = parse_jsonl(events_path)
        stats = parse_stats(p.stderr, "cythsec-vxlan", "vxlan")

        records_path = td / "flows.jsonl"
        a = run([ANALYZE_BIN, "-r", pcap, "-o", records_path, "--no-dpi"])
        astats = parse_stats(a.stderr, "cythsec-analyze", "vxlan")
        records = parse_jsonl(records_path)

        tshark_rows = []
        if args.tshark:
            p = run([
                "tshark", "-r", pcap,
                "-Y", "frame.number <= 6 && vxlan.vni",
                "-T", "fields", "-E", "separator=|", "-E", "occurrence=l",
                "-e", "frame.number", "-e", "vxlan.vni", "-e", "vxlan.flag_i",
                "-e", "eth.src", "-e", "eth.dst", "-e", "vlan.id",
                "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
                "-e", "ip.proto", "-e", "ipv6.nxt",
            ])
            tshark_rows = [line for line in p.stdout.splitlines() if line.strip()]

        check_events(events, expected)
        check_stats(stats)
        check_flows(records)
        assert astats["vxlan_frames"] == 6, f"analyze VXLAN 统计不符: {astats}"
        if args.tshark:
            check_tshark(tshark_rows, expected)

        print("==> VXLAN 正例/负例/统计/流水线全部通过")
        expect_injection("事件 VNI", lambda: check_events(
            [{**events[0], "vni": 101}] + events[1:], expected))
        expect_injection("事件内层 MAC", lambda: check_events(
            [{**events[0], "inner_src_mac": "00:00:00:00:00:00"}] + events[1:], expected))
        expect_injection("事件 VLAN", lambda: check_events(
            [{**events[0]}] + [{**events[1], "inner_vlan_ids": []}] + events[2:], expected))
        expect_injection("记录集合（少一条）", lambda: check_flows(records[:-1]))
        expect_injection("统计 vxlan_frames", lambda: check_stats({**stats, "vxlan_frames": 5}))
        if args.tshark:
            expect_injection("tshark VNI", lambda: check_tshark(
                ["1|999|True|66:77:88:99:aa:bb|00:11:22:33:44:55||10.0.0.1||10.0.0.2||17|"] + tshark_rows[1:],
                expected))
            expect_injection("tshark 少一帧", lambda: check_tshark(tshark_rows[:-1], expected))

    print("V014 VXLAN：全部检查通过")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(1)
