#!/usr/bin/env python3
"""V015 Geneve 回归：版本、选项、O/C 位、VNI 与可见内层头的有界解析。

语料由本脚本按 RFC 8926 独立拼字节，**不调用 Rust 编码器**。`--tshark` 让
Wireshark 解同一份 pcap，比较 VNI、C 位、选项、内层 MAC/VLAN 与内层 IP；
“我们的实现和我们的期望值一起错”不会变成绿。

检查项：
  1. 有效 Geneve：TEB IPv4/VLAN/QinQ/ARP、裸 IPv4/IPv6、控制报文、
     抓包截断、非零保留位。
  2. 负例：短头、未知版本、选项区截断、选项越界、C 位不一致、内层不足、
     三层 VLAN。
  3. 主流水线：外层 UDP 流保留，内层 IP 不另造 FlowRecord。
  4. 独立采集器：事件字段与统计行逐项可核对。
  5. 反向注入：事件 VNI/MAC/VLAN、记录集合、统计、tshark 对照任一被改坏必须判红。
"""

import argparse
import contextlib
import ipaddress
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENEVE_BIN = Path(os.environ.get("GENEVE_BIN", ROOT / "target/debug/cythsec-geneve"))
ANALYZE_BIN = Path(os.environ.get("ANALYZE_BIN", ROOT / "target/debug/cythsec-analyze"))

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
ETH_TEB = 0x6558
GENEVE_PORT = 6081


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


def option(option_class, type_, data):
    assert len(data) % 4 == 0, "Geneve 选项数据必须按 4 字节对齐"
    return struct.pack("!HBB", option_class, type_, len(data) // 4) + data


def geneve(flags, protocol_type, vni, options=b"", body=b""):
    assert len(options) % 4 == 0
    return (
        bytes([len(options) // 4, flags])
        + struct.pack("!H", protocol_type)
        + vni.to_bytes(3, "big")
        + b"\0"
        + options
        + body
    )


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
    """返回 expected_events。帧顺序固定：1..9 有效，10..16 负例，17 非 Geneve。"""
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x00\x00\x01\x00\x01"
    tcp = struct.pack("!HHIIBBHHH", 40000, 80, 1, 0, 5 << 4, 0x02, 65535, 0, 0)
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        ETH_IPV4,
        6,
        4,
        1,
        mac("00:11:22:33:44:55"),
        b"\x0a\x00\x00\x01",
        b"\x00" * 6,
        b"\x0a\x00\x00\x02",
    )

    teb_v4 = eth(
        mac("00:11:22:33:44:55"),
        mac("66:77:88:99:aa:bb"),
        ETH_IPV4,
        ipv4(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 17, udp(12345, 53, dns)),
    )
    teb_vlan = tagged_eth(
        mac("00:11:22:33:44:55"),
        mac("66:77:88:99:aa:bb"),
        [10],
        ETH_IPV4,
        ipv4(b"\x0a\x01\x00\x01", b"\x0a\x01\x00\x02", 6, tcp),
    )
    teb_qinq_v6 = tagged_eth(
        mac("00:11:22:33:44:55"),
        mac("66:77:88:99:aa:bb"),
        [20, 30],
        ETH_IPV6,
        ipv6(
            ipaddress.IPv6Address("2001:db8::1").packed,
            ipaddress.IPv6Address("2001:db8::2").packed,
            17,
            udp(12345, 53, dns),
        ),
    )
    teb_arp = eth(mac("ff:ff:ff:ff:ff:ff"), mac("00:11:22:33:44:55"), ETH_ARP, arp)
    raw_v4 = ipv4(b"\x0a\x02\x00\x01", b"\x0a\x02\x00\x02", 17, udp(12345, 53, dns))
    raw_v6 = ipv6(
        ipaddress.IPv6Address("2001:db8::3").packed,
        ipaddress.IPv6Address("2001:db8::4").packed,
        59,
        b"",
    )
    reserved_teb = teb_v4.replace(b"\x0a\x00\x00\x01", b"\x0a\x03\x00\x01", 1).replace(
        b"\x0a\x00\x00\x02", b"\x0a\x03\x00\x02", 1
    )

    critical = option(0x0100, 0x81, b"\x01\x02\x03\x04")
    control_option = option(0x0200, 0x01, b"\x00\x00\x00\x00")

    valid = [
        outer4(55555, GENEVE_PORT, geneve(0, ETH_TEB, 100, body=teb_v4)),
        outer4(55556, GENEVE_PORT, geneve(0x40, ETH_TEB, 200, options=critical, body=teb_vlan)),
        outer6(55557, GENEVE_PORT, geneve(0, ETH_TEB, 300, body=teb_qinq_v6)),
        outer4(55558, GENEVE_PORT, geneve(0, ETH_TEB, 50, body=teb_arp)),
        outer4(55559, GENEVE_PORT, geneve(0, ETH_IPV4, 0, body=raw_v4)),
        outer4(55560, GENEVE_PORT, geneve(0, ETH_IPV6, 0xFFFFFF, body=raw_v6)),
        outer4(55561, GENEVE_PORT, geneve(0x80, ETH_TEB, 400, options=control_option, body=teb_v4)),
        # 只抓 Geneve 头 + 10 字节内层以太头；完整抓包是畸形，抓包截断只记 capture。
        (outer4(55562, GENEVE_PORT, geneve(0, ETH_TEB, 500, body=teb_v4))[: 14 + 20 + 8 + 8 + 10],
         len(outer4(55562, GENEVE_PORT, geneve(0, ETH_TEB, 500, body=teb_v4)))),
        outer4(55563, GENEVE_PORT, geneve(0x20, ETH_TEB, 501, body=reserved_teb)),
    ]

    short_header = outer4(55564, GENEVE_PORT, b"\x00" * 7)
    unknown_version = outer4(55565, GENEVE_PORT, b"\x40" + geneve(0, ETH_TEB, 502, body=teb_v4)[1:])
    trunc_opts = bytearray(geneve(0, ETH_TEB, 503, options=b"\x00" * 4))
    trunc_opts[0] = 2
    trunc_opts = outer4(55566, GENEVE_PORT, bytes(trunc_opts))
    overrun = bytearray(geneve(0, ETH_TEB, 504, options=b"\x00" * 4))
    overrun[11] = 1
    overrun = outer4(55567, GENEVE_PORT, bytes(overrun))
    mismatch = outer4(
        55568,
        GENEVE_PORT,
        geneve(0, ETH_TEB, 505, options=option(0x0100, 0x81, b"\x00" * 4), body=teb_v4),
    )
    inner_short = outer4(55569, GENEVE_PORT, geneve(0, ETH_TEB, 506, body=teb_v4[:10]))
    three_vlans = outer4(
        55570,
        GENEVE_PORT,
        geneve(
            0,
            ETH_TEB,
            507,
            body=tagged_eth(
                mac("00:11:22:33:44:55"),
                mac("66:77:88:99:aa:bb"),
                [1, 2, 3],
                ETH_IPV4,
                ipv4(b"\x0a\x04\x00\x01", b"\x0a\x04\x00\x02", 17, udp(1, 2, b"")),
            ),
        ),
    )
    non_geneve = outer4(55571, 9999, b"\x00" * 8)
    frames = valid + [
        short_header,
        unknown_version,
        trunc_opts,
        overrun,
        mismatch,
        inner_short,
        three_vlans,
        non_geneve,
    ]
    write_pcap(path, frames)

    expected = {
        1: dict(vni=100, kind="ethernet", vlan=[], etype=ETH_IPV4,
                src="10.0.0.1", dst="10.0.0.2", proto=17, complete=True,
                src_mac="66:77:88:99:aa:bb", dst_mac="00:11:22:33:44:55"),
        2: dict(vni=200, kind="ethernet", vlan=[10], etype=ETH_IPV4,
                src="10.1.0.1", dst="10.1.0.2", proto=6, complete=True,
                critical=True, options=1),
        3: dict(vni=300, kind="ethernet", vlan=[20, 30], tshark_vlan=[30], etype=ETH_IPV6,
                src="2001:db8::1", dst="2001:db8::2", proto=17, complete=True),
        4: dict(vni=50, kind="ethernet", vlan=[], etype=ETH_ARP,
                src=None, dst=None, proto=None, complete=True, ip_complete=None,
                src_mac="00:11:22:33:44:55", dst_mac="ff:ff:ff:ff:ff:ff"),
        5: dict(vni=0, kind="ipv4", vlan=[], etype=ETH_IPV4,
                src="10.2.0.1", dst="10.2.0.2", proto=17, complete=True, no_mac=True),
        6: dict(vni=0xFFFFFF, kind="ipv6", vlan=[], etype=ETH_IPV6,
                src="2001:db8::3", dst="2001:db8::4", proto=59, complete=True, no_mac=True),
        7: dict(vni=400, kind="control", complete=None, options=1),
        8: dict(vni=500, kind="truncated", complete=None, truncated=True),
        9: dict(vni=501, kind="ethernet", vlan=[], etype=ETH_IPV4,
                src="10.3.0.1", dst="10.3.0.2", proto=17, complete=True, reserved=True),
    }
    return expected


def check_events(events, expected):
    assert len(events) == 9, f"应有 9 条有效 Geneve 事件，实际 {len(events)}"
    for ev in events:
        f = ev["frame"]
        exp = expected[f]
        assert ev["vni"] == exp["vni"], f"frame {f} VNI 不符: {ev['vni']} != {exp['vni']}"
        assert ev["version"] == 0, f"frame {f} version 不符"
        assert ev["inner_kind"] == exp["kind"], f"frame {f} inner_kind 不符: {ev['inner_kind']}"
        assert ev["control"] is (exp["kind"] == "control"), f"frame {f} O 位不符"
        assert ev["critical"] is bool(exp.get("critical")), f"frame {f} C 位不符"
        assert ev["reserved_nonzero"] is bool(exp.get("reserved")), f"frame {f} 保留位标记不符"
        if "options" in exp:
            assert len(ev["options"]) == exp["options"], f"frame {f} 选项数不符"
        if exp["kind"] == "control":
            assert ev["inner_complete"] is None, "控制报文不得声称内层完整"
            assert ev["inner_src_ip"] is None, "控制报文不得解释载荷 IP"
            continue
        if exp["kind"] == "truncated":
            assert ev["inner_truncated"] is True, "抓包截断帧应标记 inner_truncated"
            assert ev["capture_truncated"] is True, "抓包截断帧应标记 capture_truncated"
            assert ev["inner_complete"] is None, "截断帧不得声称内层完整"
            continue
        assert ev["inner_vlan_ids"] == exp["vlan"], f"frame {f} VLAN 不符: {ev['inner_vlan_ids']}"
        if exp.get("no_mac"):
            assert ev["inner_src_mac"] is None and ev["inner_dst_mac"] is None, \
                f"frame {f} 裸 IP 不应伪造 MAC"
        else:
            assert ev["inner_src_mac"] == exp.get("src_mac", "66:77:88:99:aa:bb"), \
                f"frame {f} 内层源 MAC 不符"
            assert ev["inner_dst_mac"] == exp.get("dst_mac", "00:11:22:33:44:55"), \
                f"frame {f} 内层目的 MAC 不符"
        assert ev["inner_ether_type"] == exp["etype"], f"frame {f} EtherType 不符"
        assert ev["inner_src_ip"] == exp["src"], f"frame {f} 内层源地址不符"
        assert ev["inner_dst_ip"] == exp["dst"], f"frame {f} 内层目的地址不符"
        assert ev["inner_ip_protocol"] == exp["proto"], f"frame {f} 内层协议不符"
        if exp["kind"] == "ethernet" and exp["etype"] == ETH_ARP:
            assert ev["inner_ip_complete"] is None, "ARP 不应伪造 IP 完整性"
        else:
            assert ev["inner_ip_complete"] is exp["complete"], f"frame {f} 内层 IP 完整性不符"
        assert ev["inner_complete"] is exp["complete"], f"frame {f} 内层完整性不符"


def check_stats(stats):
    wanted = {
        "geneve_frames": 9,
        "vni_zero": 1,
        "control": 1,
        "critical": 1,
        "options": 2,
        "options_critical": 1,
        "inner_ethernet": 5,
        "inner_ipv4": 4,
        "inner_ipv6": 2,
        "inner_arp": 1,
        "inner_other": 0,
        "inner_complete": 7,
        "inner_incomplete": 1,
        "capture_truncated": 1,
        "options_truncated": 0,
        "truncated": 3,
        "malformed": 4,
        "unsupported_version": 1,
        "critical_mismatch": 1,
        "option_overrun": 1,
        "too_many_vlans": 1,
        "reserved_nonzero": 1,
        "non_geneve": 1,
        "decode_errors": 0,
    }
    for k, v in wanted.items():
        assert stats.get(k) == v, f"统计 {k} 期望 {v}，实际 {stats.get(k)}: {stats}"


def check_flows(records):
    assert len(records) == 17, f"应为 17 条外层流（每帧一条），实际 {len(records)}"
    for r in records:
        flow = r["flow"]
        assert flow["dst_port"] in (GENEVE_PORT, 9999), f"出现了非外层流记录: {flow}"
        assert flow["proto"] == 17, f"Geneve 外层应为 UDP: {flow}"


def check_tshark(rows, expected):
    assert len(rows) == 9, f"tshark 应解出 9 帧 Geneve，实际 {len(rows)}: {rows}"
    for row in rows:
        parts = row.split("|")
        assert len(parts) == 15, f"tshark 列数不符: {row}"
        frame = int(parts[0])
        exp = expected[frame]
        assert int(parts[1], 0) == exp["vni"], f"tshark frame {frame} VNI 不符: {row}"
        assert parts[2] == "0", f"tshark frame {frame} version 不符: {row}"
        assert parts[3] == ("True" if exp.get("critical") else "False"), \
            f"tshark frame {frame} C 位不符: {row}"
        if exp["kind"] in ("control", "truncated"):
            continue
        if not exp.get("no_mac"):
            assert parts[4] == exp.get("src_mac", "66:77:88:99:aa:bb"), f"tshark frame {frame} 内层源 MAC: {row}"
            assert parts[5] == exp.get("dst_mac", "00:11:22:33:44:55"), f"tshark frame {frame} 内层目的 MAC: {row}"
            vlan = [int(v) for v in parts[6].split(",") if v]
            # `occurrence=l` 取最内层 VLAN；QinQ 的外层 20 由事件检查覆盖。
            assert vlan == exp.get("tshark_vlan", exp["vlan"]), f"tshark frame {frame} VLAN: {row}"
        if exp["etype"] == ETH_IPV4 and exp["src"] is not None:
            assert parts[7] == exp["src"] and parts[9] == exp["dst"], f"tshark frame {frame} IPv4: {row}"
            assert parts[11] == str(exp["proto"]), f"tshark frame {frame} IP proto: {row}"
        elif exp["etype"] == ETH_IPV6 and exp["src"] is not None:
            assert parts[8] == exp["src"] and parts[10] == exp["dst"], f"tshark frame {frame} IPv6: {row}"
            assert parts[12] == str(exp["proto"]), f"tshark frame {frame} IPv6 next: {row}"


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

    with tempfile.TemporaryDirectory(prefix="cythsec-geneve-") as td:
        td = Path(td)
        pcap = td / "geneve.pcap"
        expected = corpus(pcap)
        events_path = td / "events.jsonl"

        p = run([GENEVE_BIN, "--pcap", pcap, "-o", events_path])
        events = parse_jsonl(events_path)
        stats = parse_stats(p.stderr, "cythsec-geneve", "geneve")

        records_path = td / "flows.jsonl"
        a = run([ANALYZE_BIN, "-r", pcap, "-o", records_path, "--no-dpi"])
        astats = parse_stats(a.stderr, "cythsec-analyze", "geneve")
        records = parse_jsonl(records_path)

        tshark_rows = []
        if args.tshark:
            p = run([
                "tshark", "-r", pcap,
                "-Y", "frame.number <= 9 && geneve.vni",
                "-T", "fields", "-E", "separator=|", "-E", "occurrence=l",
                "-e", "frame.number", "-e", "geneve.vni", "-e", "geneve.version",
                "-e", "geneve.flags.critical",
                "-e", "eth.src", "-e", "eth.dst", "-e", "vlan.id",
                "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
                "-e", "ip.proto", "-e", "ipv6.nxt",
                "-e", "geneve.option.class", "-e", "geneve.option.type",
            ])
            tshark_rows = [line for line in p.stdout.splitlines() if line.strip()]

        check_events(events, expected)
        check_stats(stats)
        check_flows(records)
        assert astats["geneve_frames"] == 9, f"analyze Geneve 统计不符: {astats}"
        if args.tshark:
            check_tshark(tshark_rows, expected)

        print("==> Geneve 正例/负例/统计/流水线全部通过")
        expect_injection("事件 VNI", lambda: check_events(
            [{**events[0], "vni": 101}] + events[1:], expected))
        expect_injection("事件内层 MAC", lambda: check_events(
            [{**events[0], "inner_src_mac": "00:00:00:00:00:00"}] + events[1:], expected))
        expect_injection("事件 VLAN", lambda: check_events(
            [{**events[0]}] + [{**events[1], "inner_vlan_ids": []}] + events[2:], expected))
        expect_injection("记录集合（少一条）", lambda: check_flows(records[:-1]))
        expect_injection("统计 geneve_frames", lambda: check_stats({**stats, "geneve_frames": 8}))
        if args.tshark:
            expect_injection("tshark VNI", lambda: check_tshark(
                ["1|999|0|False|66:77:88:99:aa:bb|00:11:22:33:44:55||10.0.0.1||10.0.0.2||17|||"] + tshark_rows[1:],
                expected))
            expect_injection("tshark 少一帧", lambda: check_tshark(tshark_rows[:-1], expected))

    print("V015 Geneve：全部检查通过")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(1)
