#!/usr/bin/env python3
"""B004 ARP/RARP 有界解析回归，独立拼字节并用 tshark 交叉核验。

语料由本脚本按 RFC 826 / RFC 903 构造，**不调用 Rust 编码器**。`--tshark`
让 Wireshark 解同一份 pcap，比较 opcode、发送方 MAC/IP 与 VLAN；这样
“我们的实现和我们的期望值一起错”不会变成绿。

检查项：
  1. 请求/应答/RARP/未知 op 的字段与操作名；
  2. 单层 VLAN、QinQ、gratuitous、probe、IPv6 协议地址、未知 HTYPE/PTYPE；
  3. 截断、超 VLAN 层数、非 ARP 帧的分类；
  4. Ethernet 尾部填充不误判；
  5. 主流水线 `cythsec-analyze` 只做帧级 ARP 统计，不伪造 FlowRecord；
  6. 3 项反向注入（字段、统计、VLAN）必须被本检查器检出。
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARP_BIN = Path(os.environ.get("ARP_BIN", ROOT / "target/debug/cythsec-arp"))
ANALYZE_BIN = Path(os.environ.get("ANALYZE_BIN", ROOT / "target/debug/cythsec-analyze"))

SHA = bytes([0x02, 0, 0, 0, 0, 1])
THA = bytes([0, 0, 0, 0, 0, 0])
SPA = bytes([192, 0, 2, 10])
TPA = bytes([192, 0, 2, 1])
ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
ETH_RARP = 0x8035


def run(args, check=True):
    p = subprocess.run([str(v) for v in args], text=True, capture_output=True, timeout=30)
    if check and p.returncode:
        raise AssertionError(f"{args[0]} 失败（{p.returncode}）：{p.stderr[-800:]}")
    return p


def eth(payload, ether_type=ETH_ARP, vlans=()):
    """Ethernet + 0..2 层 VLAN；vlans 从外到内。"""
    out = bytearray(12)
    for i, vid in enumerate(vlans):
        # 外层用 0x88A8，最内层用 0x8100；TPID 之后是 TCI。
        out += struct.pack("!H", 0x88A8 if i + 1 < len(vlans) else 0x8100)
        out += struct.pack("!H", vid & 0x0FFF)
    out += struct.pack("!H", ether_type)
    out += payload
    return bytes(out)


def arp_body(htype=1, ptype=ETH_IPV4, hlen=6, plen=4, op=1, sha=SHA, spa=SPA, tha=THA, tpa=TPA):
    assert len(sha) == hlen and len(tha) == hlen
    assert len(spa) == plen and len(tpa) == plen
    return struct.pack("!HHBBH", htype, ptype, hlen, plen, op) + sha + spa + tha + tpa


def arp_frame(op=1, sha=SHA, spa=SPA, tha=THA, tpa=TPA, vlans=(), ptype=ETH_IPV4, hlen=6, plen=4, htype=1):
    return eth(arp_body(htype, ptype, hlen, plen, op, sha, spa, tha, tpa), vlans=vlans)


def udp_frame():
    payload = b"\x00" * 8
    udp = struct.pack("!HHHH", 40000, 9, 8, 0) + payload
    ip = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
        )
    )
    ip[10:12] = struct.pack("!H", checksum(bytes(ip)))
    return eth(bytes(ip) + udp, ether_type=ETH_IPV4)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def write_pcap(path, records):
    """records: [(frame_bytes, orig_len_or_None)]"""
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, (frame, orig_len) in enumerate(records):
        wire = len(frame) if orig_len is None else orig_len
        out += struct.pack("<IIII", 1_700_000_000 + i, i * 1000, len(frame), wire)
        out += frame
    path.write_bytes(out)


def parse_jsonl(path):
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def parse_stats(text):
    m = re.search(r"\[cythsec-arp\] arp (.*)", text)
    if not m:
        raise AssertionError(f"缺少 ARP 统计行：{text[-500:]}")
    out = {}
    for part in m.group(1).split():
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k] = int(v)
    return out


def expected_stats():
    return {
        "arp_frames": 13,
        "requests": 9,
        "replies": 2,
        "rarp_requests": 1,
        "rarp_replies": 0,
        "other_operations": 1,
        "probes": 1,
        "gratuitous": 1,
        "vlan_tagged": 2,
        "unknown_hardware": 1,
        "unknown_protocol": 1,
        "malformed": 1,
        "truncated": 1,
        "non_arp": 1,
        "capture_truncated": 1,
        "frames": 16,
    }


def validate_stats(stats):
    want = expected_stats()
    for k, v in want.items():
        assert stats.get(k) == v, f"统计 {k}={stats.get(k)}，期望 {v}（全部：{stats}）"


def validate_records(records):
    assert len(records) == 13, f"应输出 13 条有效 ARP，实际 {len(records)}"
    by_frame = {r["frame"]: r for r in records}
    assert sorted(by_frame) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 14, 15, 16], sorted(by_frame)

    r = by_frame[1]
    assert r["operation"] == 1 and r["operation_name"] == "request"
    assert r["sender_mac"] == "02:00:00:00:00:01"
    assert r["sender_ipv4"] == "192.0.2.10" and r["target_ipv4"] == "192.0.2.1"
    assert r["vlan_ids"] == [] and r["gratuitous"] is False and r["probe"] is False
    assert r["sender_hardware"] == "020000000001"

    assert by_frame[2]["operation_name"] == "reply"
    assert by_frame[3]["vlan_ids"] == [100]
    assert by_frame[4]["vlan_ids"] == [200, 300]

    assert by_frame[5]["gratuitous"] is True
    assert by_frame[6]["probe"] is True
    assert by_frame[6]["sender_ipv4"] == "0.0.0.0"

    assert by_frame[7]["operation_name"] == "rarp_request"
    assert by_frame[7]["protocol_type_name"] == "rarp"
    assert by_frame[7]["sender_ipv4"] is None and by_frame[7]["gratuitous"] is None

    assert by_frame[8]["operation"] == 99 and by_frame[8]["operation_name"] == "unknown"

    assert by_frame[9]["sender_ipv6"] == "fe80::1"
    assert by_frame[9]["target_ipv6"] == "fe80::2"
    assert by_frame[9]["sender_ipv4"] is None

    assert by_frame[12]["operation_name"] == "request"  # 尾部填充不影响
    assert by_frame[14]["hardware_type_name"] == "unknown"
    assert by_frame[14]["sender_mac"] is None
    assert by_frame[15]["capture_truncated"] is True
    assert by_frame[15]["frame_len"] == 52, by_frame[15]["frame_len"]  # 42 字节 ARP + 10 字节未捕获
    assert by_frame[16]["protocol_type_name"] == "unknown"
    assert by_frame[16]["sender_ipv4"] is None


def validate_pipeline(pcap_path, work):
    flows = work / "flows.jsonl"
    p = run([ANALYZE_BIN, "-r", pcap_path, "-o", flows])
    line = next((ln for ln in p.stderr.splitlines() if ln.startswith("[cythsec-analyze] arp ")), "")
    assert line, f"cythsec-analyze 缺少 ARP 统计行：{p.stderr[-500:]}"
    stats = {}
    for part in line.split():
        if "=" in part:
            k, v = part.split("=", 1)
            stats[k] = int(v)
    assert stats["arp_frames"] == 13, stats
    assert stats["requests"] == 9, stats
    assert stats["replies"] == 2, stats
    assert stats["malformed"] == 1, stats
    assert stats["truncated"] == 1, stats
    assert stats["non_arp"] == 0, "主流水线只对非 IP 帧旁路解析 ARP，不该把普通 IP 记成非 ARP"
    assert len(flows.read_text().splitlines()) == 1, "ARP 不得伪造 FlowRecord；只有那一条 UDP 流"


def validate_tshark(pcap_path):
    """用 tshark 的 JSON 输出核对 opcode/MAC/IP 与两层 VLAN。

    不用 `-T fields -e vlan.id`：QinQ 时 Wireshark 把外层放在 `ieee8021ad.id`、
    内层放在 `vlan.id`，而 `vlan.id` 只返回最内层；拿一个字段比两层会静默少比。
    """
    p = run(["tshark", "-r", pcap_path, "-Y", "arp", "-T", "json"])
    packets = json.loads(p.stdout)
    want = {
        1: ("1", "02:00:00:00:00:01", "192.0.2.10", "192.0.2.1", []),
        2: ("2", "02:00:00:00:00:01", "192.0.2.1", "192.0.2.10", []),
        3: ("1", "02:00:00:00:00:01", "192.0.2.10", "192.0.2.1", ["100"]),
        4: ("2", "02:00:00:00:00:01", "192.0.2.1", "192.0.2.10", ["200", "300"]),
        5: ("1", "02:00:00:00:00:01", "192.0.2.20", "192.0.2.20", []),
        6: ("1", "02:00:00:00:00:01", "0.0.0.0", "192.0.2.1", []),
        7: ("3", "", "", "", []),
        8: ("99", "", "", "", []),
        12: ("1", "02:00:00:00:00:01", "192.0.2.10", "192.0.2.1", []),
        15: ("1", "02:00:00:00:00:01", "192.0.2.10", "192.0.2.1", []),
    }
    seen = set()
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        arp = layers.get("arp")
        if not arp:
            continue
        frame = int(layers["frame"]["frame.number"])
        if frame not in want:
            continue
        op, mac, spa, tpa, vlans = want[frame]
        assert arp.get("arp.opcode") == op, f"tshark frame {frame} opcode={arp.get('arp.opcode')}，期望 {op}"
        if mac:
            assert (
                arp.get("arp.src.hw_mac", "").lower() == mac
            ), f"tshark frame {frame} src mac={arp.get('arp.src.hw_mac')}"
        if spa:
            assert arp.get("arp.src.proto_ipv4") == spa, f"tshark frame {frame} spa={arp.get('arp.src.proto_ipv4')}"
            assert arp.get("arp.dst.proto_ipv4") == tpa, f"tshark frame {frame} tpa={arp.get('arp.dst.proto_ipv4')}"
        got_vlans = []
        if "ieee8021ad" in layers:
            got_vlans.append(layers["ieee8021ad"]["ieee8021ad.id"])
        if "vlan" in layers:
            got_vlans.append(layers["vlan"]["vlan.id"])
        assert got_vlans == vlans, f"tshark frame {frame} vlan={got_vlans}，期望 {vlans}"
        seen.add(frame)
    missing = sorted(set(want) - seen)
    assert not missing, f"tshark 没有解出期望的 ARP 帧：{missing}"


def reverse_injections(records, stats, work):
    # 字段注入：只改一份副本，原记录保持不动。
    bad = [dict(r) for r in records]
    bad[0]["sender_ipv4"] = "192.0.2.99"
    try:
        validate_records(bad)
    except AssertionError:
        pass
    else:
        raise AssertionError("反向注入未检出：改坏 sender_ipv4")

    bad_stats = dict(stats)
    bad_stats["requests"] = 8
    try:
        validate_stats(bad_stats)
    except AssertionError:
        pass
    else:
        raise AssertionError("反向注入未检出：改坏 requests")

    bad = [dict(r) for r in records]
    bad[2]["vlan_ids"] = []
    try:
        validate_records(bad)
    except AssertionError:
        pass
    else:
        raise AssertionError("反向注入未检出：改坏 vlan_ids")


def have_tshark():
    return subprocess.run(["sh", "-c", "command -v tshark"], capture_output=True).returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", action="store_true")
    args = ap.parse_args()
    if args.tshark and not have_tshark():
        print("⚠ 缺少 tshark：独立对照未执行", file=sys.stderr)
        return 3

    with tempfile.TemporaryDirectory(prefix="cythsec-arp-") as td:
        work = Path(td)
        pcap = work / "arp.pcap"
        full = arp_frame(1)
        records = [
            (arp_frame(1), None),
            (arp_frame(2, spa=TPA, tpa=SPA, tha=SHA), None),
            (arp_frame(1, vlans=(100,)), None),
            (arp_frame(2, spa=TPA, tpa=SPA, tha=SHA, vlans=(200, 300)), None),
            (arp_frame(1, spa=bytes([192, 0, 2, 20]), tpa=bytes([192, 0, 2, 20])), None),
            (arp_frame(1, spa=b"\0\0\0\0"), None),
            (arp_frame(3, ptype=ETH_RARP), None),
            (arp_frame(99), None),
            (
                arp_frame(
                    1,
                    ptype=ETH_IPV6,
                    plen=16,
                    spa=bytes.fromhex("fe800000000000000000000000000001"),
                    tpa=bytes.fromhex("fe800000000000000000000000000002"),
                ),
                None,
            ),
            (udp_frame(), None),
            (full[:-2], None),
            (full + b"\0" * 18, None),
            (arp_frame(1, vlans=(1, 2, 3)), None),
            (arp_frame(1, htype=99), None),
            (arp_frame(1), len(arp_frame(1)) + 10),
            (arp_frame(1, ptype=0x1234), None),
        ]
        write_pcap(pcap, records)

        out = work / "arp.jsonl"
        p = run([ARP_BIN, "--pcap", pcap, "-o", out])
        parsed = parse_jsonl(out)
        stats = parse_stats(p.stderr)
        validate_records(parsed)
        validate_stats(stats)
        validate_pipeline(pcap, work)
        reverse_injections(parsed, stats, work)
        print("  ✓ 13 条有效 ARP/RARP 事件：请求/应答/RARP/未知 op、VLAN/QinQ、gratuitous/probe、IPv6、未知类型")
        print("  ✓ 16 帧统计：13 ARP + 1 非 ARP + 1 截断 + 1 超 VLAN 层；填充被忽略")
        print("  ✓ 主流水线只做帧级 ARP 统计，未把 ARP 塞进 FlowRecord")
        print("  ✓ 3 项反向注入（sender_ipv4 / requests / vlan_ids）均被检出")

        if args.tshark:
            validate_tshark(pcap)
            print("  ✓ tshark 独立核对 opcode/MAC/IP/VLAN：10 帧逐项一致")

    print("✓ B004 ARP 回归通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
