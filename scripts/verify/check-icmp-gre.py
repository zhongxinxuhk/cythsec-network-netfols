#!/usr/bin/env python3
"""B011/B012/V009 基础协议识别回归：ICMPv4、ICMPv6、GRE/mGRE 的有界解析。

语料由本脚本按 RFC 792 / RFC 4443 / RFC 4861 / RFC 2784 / RFC 2890 / RFC 2637
独立拼字节，**不调用 Rust 编码器**。`--tshark` 让 Wireshark 解同一份 pcap，
比较 type/code/echo 标识、GRE 版本/protocol/key 与内层地址；这样
“我们的实现和我们的期望值一起错”不会变成绿。

检查项：
  1. ICMPv4：echo、目的不可达（含分片 MTU）、源抑制、超时、参数问题、重定向、
     时间戳、未知类型、截断；错误报文内嵌原始 IP 头。
  2. ICMPv6：echo、Packet Too Big、NS/NA/RA（target/flags/选项）、MLD、未知类型、
     截断；NDP 选项长度与越界分类。
  3. GRE：v0 无 key、key、checksum+key+seq、SRE 源路由、TEB（含 VLAN）、MPLS、
     未知协议、内层截断；v1 PPTP 基础与 S/A；版本 2、缺 K、头截断的分类。
  4. 主流水线只统计报文级信息；GRE 内层 IP 不得另造一条 FlowRecord。
  5. 反向注入：事件字段、统计、内层地址任一被改坏必须被本检查器检出。
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
ICMP_BIN = Path(os.environ.get("ICMP_BIN", ROOT / "target/debug/cythsec-icmp"))
GRE_BIN = Path(os.environ.get("GRE_BIN", ROOT / "target/debug/cythsec-gre"))
ANALYZE_BIN = Path(os.environ.get("ANALYZE_BIN", ROOT / "target/debug/cythsec-analyze"))

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_GRE_INNER_TEB = 0x6558
PPTP_PROTO = 0x880B


def run(args, check=True):
    p = subprocess.run([str(v) for v in args], text=True, capture_output=True, timeout=60)
    if check and p.returncode:
        raise AssertionError(f"{args[0]} 失败（{p.returncode}）：{p.stderr[-1200:]}")
    return p


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src, dst, proto, payload, ident=1, flags=0x4000):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, flags, 64, proto, 0, src, dst)
    c = checksum(hdr)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, flags, 64, proto, c, src, dst)
    return hdr + payload


def ipv6(src, dst, next_header, payload):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), next_header, 64, src, dst) + payload


def eth(payload, ether_type):
    return bytes(12) + struct.pack("!H", ether_type) + payload


def icmp4(src, dst, ty, code, rest, body=b""):
    msg = struct.pack("!BBH", ty, code, 0) + rest + body
    c = checksum(msg)
    msg = struct.pack("!BBH", ty, code, c) + rest + body
    return eth(ipv4(src, dst, 1, msg), ETH_IPV4)


def icmp6(src, dst, ty, code, rest, body=b""):
    msg = struct.pack("!BBH", ty, code, 0) + rest + body
    pseudo = src + dst + struct.pack("!I3xB", len(msg), 58)
    c = checksum(pseudo + msg)
    msg = struct.pack("!BBH", ty, code, c) + rest + body
    return eth(ipv6(src, dst, 58, msg), ETH_IPV6)


def gre0(flags, proto, inner, checksum_value=None, key=None, seq=None, sre=None):
    out = struct.pack("!HH", flags, proto)
    if checksum_value is not None or flags & 0x4000:
        out += struct.pack("!HH", checksum_value or 0, 0)
    if key is not None:
        out += struct.pack("!I", key)
    if seq is not None:
        out += struct.pack("!I", seq)
    if sre is not None:
        for af, offset, data in sre:
            out += struct.pack("!HBB", af, offset, len(data)) + data
        out += struct.pack("!HBB", 0, 0, 0)  # SRE Length=0 结束标记
    return out + inner


def gre_frame(payload, src=bytes([192, 0, 2, 1]), dst=bytes([192, 0, 2, 2]), orig_len=None):
    frame = eth(ipv4(src, dst, 47, payload), ETH_IPV4)
    return frame, orig_len


def pptp(flags, payload_len, call_id, tail=b""):
    return struct.pack("!HHHH", flags, PPTP_PROTO, payload_len, call_id) + tail


def write_pcap(path, records):
    """records: [(frame_bytes, orig_len_or_None)]"""
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, (frame, orig_len) in enumerate(records):
        wire = len(frame) if orig_len is None else orig_len
        out += struct.pack("<IIII", 1_700_000_000 + i, i * 1000, len(frame), wire)
        out += frame
    path.write_bytes(out)


def parse_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def parse_stats(text, prefix, marker=None):
    for line in text.splitlines():
        start = f"[{prefix}] "
        if not line.startswith(start):
            continue
        body = line[len(start) :]
        if marker is not None and not body.startswith(marker + " "):
            continue
        out = {}
        for part in body.split():
            if "=" in part:
                k, v = part.split("=", 1)
                with contextlib.suppress(ValueError):
                    out[k] = int(v)
        if out:
            return out
    raise AssertionError(f"缺少 {prefix} 统计行：{text[-800:]}")


def v4(s):
    return ipaddress.IPv4Address(s).packed


def v6(s):
    return ipaddress.IPv6Address(s).packed


def icmp_corpus():
    src4, dst4 = v4("10.0.0.1"), v4("10.0.0.2")
    src6, dst6 = v6("2001:db8::1"), v6("2001:db8::2")
    orig4 = ipv4(src4, dst4, 17, struct.pack("!HHHH", 40000, 53, 8, 0))
    orig6 = ipv6(src6, dst6, 17, struct.pack("!HHHH", 40000, 53, 8, 0))

    ns_body = bytes(4) + v6("fe80::1") + struct.pack("!BB", 1, 1) + bytes([2, 0, 0, 0, 0, 1])
    na_body = struct.pack("!I", 0xE0000000) + v6("2001:db8::2") + struct.pack("!BB", 2, 1) + bytes([2, 0, 0, 0, 0, 2])
    ra_body = (
        struct.pack("!BBHII", 64, 0xC0, 1800, 30000, 1000)
        + struct.pack("!BBBB", 3, 4, 64, 0xC0)
        + struct.pack("!II", 3600, 1800)
        + bytes(4)
        + v6("2001:db8::")
    )
    frames = [
        icmp4(src4, dst4, 8, 0, struct.pack("!HH", 0x1234, 7), b"abcdefgh"),  # 1 echo req
        icmp4(dst4, src4, 0, 0, struct.pack("!HH", 0x1234, 7), b"abcdefgh"),  # 2 echo rep
        icmp4(dst4, src4, 3, 3, bytes(4), orig4),  # 3 port unreachable
        icmp4(dst4, src4, 3, 4, struct.pack("!HH", 0, 1400), orig4),  # 4 frag needed
        icmp4(dst4, src4, 11, 0, bytes(4), orig4),  # 5 time exceeded
        icmp4(dst4, src4, 12, 0, bytes([9, 0, 0, 0]), orig4),  # 6 param problem
        icmp4(dst4, src4, 5, 1, v4("192.0.2.254"), orig4),  # 7 redirect
        icmp4(src4, dst4, 13, 0, struct.pack("!HH", 0x2222, 3), bytes(12)),  # 8 timestamp
        icmp4(src4, dst4, 42, 0, bytes(4), b"????"),  # 9 unknown
        icmp4(src4, dst4, 8, 0, struct.pack("!HH", 1, 1), b"")[: 14 + 20 + 4],  # 10 truncated header
        (
            icmp4(src4, dst4, 8, 0, struct.pack("!HH", 0x1234, 9), b"abcdefgh"),  # 11 capture truncated
            len(icmp4(src4, dst4, 8, 0, struct.pack("!HH", 0x1234, 9), b"abcdefgh")) + 10,
        ),
        icmp6(src6, dst6, 128, 0, struct.pack("!HH", 0x5678, 9), b"abcdefgh"),  # 12 v6 echo req
        icmp6(dst6, src6, 129, 0, struct.pack("!HH", 0x5678, 9), b"abcdefgh"),  # 13 v6 echo rep
        icmp6(dst6, src6, 2, 0, struct.pack("!I", 1280), orig6),  # 14 packet too big
        icmp6(v6("fe80::1"), v6("ff02::1:ff00:2"), 135, 0, bytes(4), ns_body),  # 15 NS
        icmp6(v6("fe80::2"), v6("fe80::1"), 136, 0, bytes(4), na_body),  # 16 NA
        icmp6(v6("fe80::1"), v6("ff02::1"), 134, 0, bytes(4), ra_body),  # 17 RA
        icmp6(v6("fe80::1"), v6("ff02::1"), 130, 0, bytes(4), bytes(20)),  # 18 MLD query
        icmp6(src6, dst6, 200, 0, bytes(4), b""),  # 19 unknown
        icmp6(src6, dst6, 128, 0, struct.pack("!HH", 1, 1), b"")[: 14 + 40 + 4],  # 20 truncated
    ]
    records = []
    for f in frames:
        if isinstance(f, tuple):
            records.append(f)
        else:
            records.append((f, None))
    return records


def gre_corpus():
    inner4 = ipv4(v4("10.0.0.1"), v4("10.0.0.2"), 6, bytes(20))
    inner6 = ipv6(v6("2001:db8::1"), v6("2001:db8::2"), 59, bytes(8))
    teb = bytes(12) + struct.pack("!HHH", 0x8100, 100, ETH_IPV4) + bytes(20)
    records = [
        (gre_frame(gre0(0x0000, ETH_IPV4, inner4))[0], None),  # 1 plain, set below
        (gre_frame(gre0(0x2000, ETH_IPV4, inner4, key=0xDEADBEEF))[0], None),  # 2 key
        (gre_frame(gre0(0xB000, ETH_IPV6, inner6, checksum_value=0xBEEF, key=0x11223344, seq=7))[0], None),  # 3 C+K+S
        (gre_frame(gre0(0x4000, ETH_IPV4, inner4, sre=[(0x0800, 0, bytes([10, 0, 0, 9]))]))[0], None),  # 4 SRE
        (gre_frame(gre0(0x0000, ETH_GRE_INNER_TEB, teb))[0], None),  # 5 TEB
        (gre_frame(gre0(0x0000, 0x8847, struct.pack("!I", 0x00010001)))[0], None),  # 6 MPLS
        (gre_frame(gre0(0x0000, 0x1234, bytes(8)))[0], None),  # 7 unknown
        (gre_frame(gre0(0x0000, ETH_IPV4, inner4[:12]))[0], None),  # 8 inner truncated
        (gre_frame(pptp(0x2001, 8, 1, bytes([0, 0x21]) + bytes(6)))[0], None),  # 9 PPTP
        (gre_frame(pptp(0x3081, 0, 3, struct.pack("!II", 0x0A0B0C0D, 0x11223344)))[0], None),  # 10 PPTP S+A
        (gre_frame(pptp(0x0001, 8, 1, bytes(8)))[0], None),  # 11 missing K
        (gre_frame(gre0(0x0002, ETH_IPV4, inner4))[0], None),  # 12 version 2
        (gre_frame(gre0(0x2000, ETH_IPV4, b"")[: 4 + 2])[0], None),  # 13 truncated key
        (gre_frame(gre0(0x0000, ETH_GRE_INNER_TEB, bytes(10)))[0], None),  # 14 TEB truncated
        (
            eth(ipv4(v4("192.0.2.9"), v4("192.0.2.10"), 17, struct.pack("!HHHH", 1, 2, 8, 0)), ETH_IPV4),
            None,
        ),  # 15 non-GRE
    ]
    # 第 1 帧标记为“抓包截断但 GRE 头完整”：orig_len 比 caplen 多 10。
    first = records[0][0]
    records[0] = (first, len(first) + 10)
    return records


def validate_icmp(records, stats):
    assert len(records) == 18, f"应输出 18 条有效 ICMP，实际 {len(records)}"
    by = {r["frame"]: r for r in records}
    assert sorted(by) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19], sorted(by)

    r = by[1]
    assert r["family"] == "ipv4" and r["ip_proto"] == 1
    assert r["type_name"] == "echo_request" and r["type"] == 8 and r["code"] == 0
    assert r["identifier"] == 0x1234 and r["sequence"] == 7
    assert r["embedded"] is None and r["ndp"] is None and r["truncated"] is False

    r = by[3]
    assert r["type_name"] == "destination_unreachable" and r["mtu"] is None
    assert r["embedded"]["source"] == "10.0.0.1"
    assert r["embedded"]["destination"] == "10.0.0.2"
    assert r["embedded"]["protocol"] == 17 and r["embedded"]["header_complete"] is True

    assert by[4]["mtu"] == 1400, by[4]
    assert by[5]["type_name"] == "time_exceeded"
    assert by[6]["pointer"] == 9
    assert by[7]["type_name"] == "redirect" and by[7]["embedded"]["source"] == "10.0.0.1"
    assert by[8]["type_name"] == "timestamp_request" and by[8]["identifier"] == 0x2222
    assert by[9]["type_name"] == "unknown"
    assert by[11]["capture_truncated"] is True and by[11]["frame_len"] > 0

    r = by[12]
    assert r["family"] == "ipv6" and r["ip_proto"] == 58
    assert r["type_name"] == "echo_request" and r["identifier"] == 0x5678 and r["sequence"] == 9

    r = by[14]
    assert r["type_name"] == "packet_too_big" and r["mtu"] == 1280
    assert r["embedded"]["version"] == 6
    assert r["embedded"]["source"] == "2001:db8::1" and r["embedded"]["destination"] == "2001:db8::2"

    n = by[15]["ndp"]
    assert n["target"] == "fe80::1", n
    assert n["options"] == [{"kind": 1, "len": 1}], n

    n = by[16]["ndp"]
    assert n["na_flags"] == 0xE0000000 and n["target"] == "2001:db8::2", n

    n = by[17]["ndp"]
    assert n["cur_hop_limit"] == 64 and n["ra_flags"] == 0xC0, n
    assert n["router_lifetime"] == 1800 and n["reachable_time"] == 30000, n
    assert n["retrans_timer"] == 1000 and n["options"] == [{"kind": 3, "len": 4}], n

    assert by[18]["type_name"] == "mld_query"
    assert by[19]["type_name"] == "unknown"

    want = {
        "icmp_frames": 18,
        "v4": 10,
        "v6": 8,
        "echo_requests": 3,
        "echo_replies": 2,
        "destination_unreachable": 2,
        "packet_too_big": 1,
        "time_exceeded": 1,
        "parameter_problem": 1,
        "redirects": 1,
        "ndp": 3,
        "mld": 1,
        "other": 3,
        "errors": 6,
        "with_embedded": 6,
        "truncated": 2,
        "malformed": 0,
        "ndp_options_truncated": 0,
        "ndp_options_malformed": 0,
        "capture_truncated": 1,
    }
    for k, v in want.items():
        assert stats.get(k) == v, f"ICMP 统计 {k}={stats.get(k)}，期望 {v}（全部：{stats}）"


def validate_gre(records, stats):
    assert len(records) == 11, f"应输出 11 条有效 GRE，实际 {len(records)}"
    by = {r["frame"]: r for r in records}
    assert sorted(by) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14], sorted(by)

    r = by[1]
    assert r["version"] == 0 and r["mode"] == "gre"
    assert r["protocol_name"] == "ipv4" and r["header_len"] == 4
    assert r["key"] is None and r["key_present"] is False
    assert r["inner"]["source"] == "10.0.0.1" and r["inner"]["complete_header"] is True
    assert r["capture_truncated"] is True and r["truncated"] is False

    r = by[2]
    assert r["key"] == 0xDEADBEEF and r["key_present"] is True

    r = by[3]
    assert r["checksum"] == 0xBEEF and r["key"] == 0x11223344 and r["sequence"] == 7
    assert r["protocol_name"] == "ipv6" and r["inner"]["destination"] == "2001:db8::2"
    assert r["header_len"] == 16

    r = by[4]
    assert r["routing_present"] is True and r["sre_count"] == 1 and r["header_len"] == 20
    assert r["inner"]["source"] == "10.0.0.1"

    r = by[5]
    assert r["protocol_name"] == "transparent_ethernet_bridging"
    assert r["inner"]["kind"] == "ethernet"
    assert r["inner"]["inner_ether_type"] == 0x0800
    assert r["inner"]["inner_vlan_ids"] == [100]

    assert by[6]["protocol_name"] == "mpls_unicast" and by[6]["inner"]["kind"] == "mpls"
    assert by[7]["protocol_name"] == "unknown" and by[7]["inner"]["kind"] == "unknown"
    assert by[8]["inner"]["complete_header"] is False and by[8]["truncated"] is True

    r = by[9]
    assert r["mode"] == "pptp" and r["key"] == 0x00080001
    assert r["pptp_payload_len"] == 8 and r["pptp_call_id"] == 1
    assert r["header_len"] == 8 and r["inner"]["kind"] == "ppp"

    r = by[10]
    assert r["mode"] == "pptp" and r["sequence"] == 0x0A0B0C0D and r["ack"] == 0x11223344
    assert r["header_len"] == 16 and r["inner"] is None

    assert by[14]["inner"]["kind"] == "ethernet" and by[14]["inner"]["complete_header"] is False

    want = {
        "gre_frames": 11,
        "version0": 9,
        "version1": 2,
        "keyed": 4,
        "unkeyed": 7,
        "checksum_present": 1,
        "routing_present": 1,
        "sequence_present": 2,
        "ack_present": 1,
        "protocol_ipv4": 4,
        "protocol_ipv6": 1,
        "protocol_ethernet": 2,
        "protocol_ppp": 2,
        "protocol_mpls": 1,
        "protocol_erspan": 0,
        "protocol_other": 1,
        "inner_complete": 7,
        "inner_incomplete": 2,
        "capture_truncated": 1,
        "truncated": 3,
        "malformed": 2,
    }
    for k, v in want.items():
        assert stats.get(k) == v, f"GRE 统计 {k}={stats.get(k)}，期望 {v}（全部：{stats}）"


def validate_pipeline(icmp_pcap, gre_pcap, work):
    flows = work / "icmp-flows.jsonl"
    p = run([ANALYZE_BIN, "-r", icmp_pcap, "-o", flows])
    icmp_stats = parse_stats(p.stderr, "cythsec-analyze", "icmp")
    # 统计行里同时有 arp/icmp/gre，parse_stats 只取整行；按字段名前缀查关键值。
    assert icmp_stats["icmp_frames"] == 18, icmp_stats
    assert icmp_stats["echo_requests"] == 3, icmp_stats
    assert icmp_stats["ndp"] == 3, icmp_stats
    assert icmp_stats["truncated"] == 2, icmp_stats
    nflows = len(flows.read_text().splitlines())
    assert nflows == 5, f"ICMP 流水线应产出 5 条会话（v4 1 + v6 4），实际 {nflows}"

    gre_flows = work / "gre-flows.jsonl"
    p = run([ANALYZE_BIN, "-r", gre_pcap, "-o", gre_flows])
    gre_stats = parse_stats(p.stderr, "cythsec-analyze", "gre")
    assert gre_stats["gre_frames"] == 11, gre_stats
    assert gre_stats["protocol_ipv4"] == 4, gre_stats
    assert gre_stats["inner_complete"] == 7, gre_stats
    assert gre_stats["malformed"] == 2, gre_stats
    nflows = len(gre_flows.read_text().splitlines())
    assert nflows == 2, f"GRE 流水线应只产出 2 条外层会话，实际 {nflows}（内层 IP 不得另造流）"


def _int(value):
    return int(str(value), 0)


def validate_tshark_icmp(pcap_path):
    p = run(["tshark", "-r", pcap_path, "-Y", "icmp || icmpv6", "-T", "json"])
    packets = json.loads(p.stdout)
    want = {
        1: ("icmp", "8", "0", "4660", "7"),
        2: ("icmp", "0", "0", "4660", "7"),
        3: ("icmp", "3", "3", None, None),
        4: ("icmp", "3", "4", None, None),
        5: ("icmp", "11", "0", None, None),
        6: ("icmp", "12", "0", None, None),
        7: ("icmp", "5", "1", None, None),
        8: ("icmp", "13", "0", "8738", "3"),
        12: ("icmpv6", "128", "0", "22136", "9"),
        13: ("icmpv6", "129", "0", "22136", "9"),
        14: ("icmpv6", "2", "0", None, None),
        15: ("icmpv6", "135", "0", None, None),
        16: ("icmpv6", "136", "0", None, None),
        17: ("icmpv6", "134", "0", None, None),
        18: ("icmpv6", "130", "0", None, None),
    }
    seen = set()
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        frame = int(layers["frame"]["frame.number"])
        if frame not in want:
            continue
        key, ty, code, ident, seq = want[frame]
        layer = layers.get(key)
        assert layer, f"tshark frame {frame} 缺少 {key} 层"
        assert layer.get(f"{key}.type") == ty, f"tshark frame {frame} type={layer.get(f'{key}.type')}"
        assert layer.get(f"{key}.code") == code, f"tshark frame {frame} code={layer.get(f'{key}.code')}"
        if ident is not None:
            got = layer.get(f"{key}.ident")
            if got is None and key == "icmpv6":
                got = layer.get("icmpv6.echo.identifier")
            assert _int(got) == int(ident), f"tshark frame {frame} ident={got}"
        if seq is not None:
            got = layer.get(f"{key}.seq")
            if got is None and key == "icmpv6":
                got = layer.get("icmpv6.echo.sequence_number")
            assert _int(got) == int(seq), f"tshark frame {frame} seq={got}"
        seen.add(frame)
    missing = sorted(set(want) - seen)
    assert not missing, f"tshark 没有解出期望的 ICMP 帧：{missing}"


def validate_tshark_gre(pcap_path):
    p = run(["tshark", "-r", pcap_path, "-Y", "gre", "-T", "json"])
    packets = json.loads(p.stdout)
    # (version, proto, v0 key, PPTP payload length, call id, sequence, ack)
    want = {
        1: (0, "0x0800", None, None, None, None, None),
        2: (0, "0x0800", 0xDEADBEEF, None, None, None, None),
        3: (0, "0x86dd", 0x11223344, None, None, 7, None),
        4: (0, "0x0800", None, None, None, None, None),
        5: (0, "0x6558", None, None, None, None, None),
        6: (0, "0x8847", None, None, None, None, None),
        9: (1, "0x880b", None, 8, 1, None, None),
        10: (1, "0x880b", None, 0, 3, 0x0A0B0C0D, 0x11223344),
    }
    seen = set()
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        frame = int(layers["frame"]["frame.number"])
        if frame not in want:
            continue
        gre = layers.get("gre")
        assert gre, f"tshark frame {frame} 缺少 gre 层"
        version, proto, v0key, payload_len, call_id, seq, ack = want[frame]
        flags = _int(gre.get("gre.flags_and_version", "0"))
        assert flags & 7 == version, f"tshark frame {frame} flags={gre.get('gre.flags_and_version')}"
        assert gre.get("gre.proto", "").lower() == proto, f"tshark frame {frame} proto={gre.get('gre.proto')}"
        if v0key is not None:
            assert _int(gre.get("gre.key")) == v0key, f"tshark frame {frame} key mismatch"
        if payload_len is not None:
            assert _int(gre.get("gre.key.payload_length")) == payload_len, gre
            assert _int(gre.get("gre.key.call_id")) == call_id, gre
        if seq is not None:
            assert _int(gre.get("gre.sequence_number")) == seq, gre
        if ack is not None:
            assert _int(gre.get("gre.ack_number")) == ack, gre
        seen.add(frame)
    missing = sorted(set(want) - seen)
    assert not missing, f"tshark 没有解出期望的 GRE 帧：{missing}"


def reverse_injections(icmp_records, icmp_stats, gre_records, gre_stats):
    cases = []

    bad = [dict(r) for r in icmp_records]
    bad[0]["type_name"] = "echo_reply"
    cases.append(("ICMP type_name", lambda: validate_icmp(bad, icmp_stats)))

    bad_stats = dict(icmp_stats)
    bad_stats["echo_requests"] = 2
    cases.append(("ICMP echo_requests", lambda: validate_icmp(icmp_records, bad_stats)))

    bad = [dict(r) for r in icmp_records]
    bad[2]["embedded"] = dict(bad[2]["embedded"])
    bad[2]["embedded"]["source"] = "10.0.0.99"
    cases.append(("ICMP 内嵌源地址", lambda: validate_icmp(bad, icmp_stats)))

    bad = [dict(r) for r in gre_records]
    bad[1]["key"] = 1
    cases.append(("GRE key", lambda: validate_gre(bad, gre_stats)))

    bad_stats = dict(gre_stats)
    bad_stats["inner_complete"] = 6
    cases.append(("GRE inner_complete", lambda: validate_gre(gre_records, bad_stats)))

    bad = [dict(r) for r in gre_records]
    bad[0]["inner"] = dict(bad[0]["inner"])
    bad[0]["inner"]["source"] = "10.0.0.99"
    cases.append(("GRE 内层源地址", lambda: validate_gre(bad, gre_stats)))

    for name, check in cases:
        try:
            check()
        except AssertionError:
            continue
        raise AssertionError(f"反向注入未检出：{name}")


def have_tshark():
    return subprocess.run(["sh", "-c", "command -v tshark"], capture_output=True).returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", action="store_true")
    args = ap.parse_args()
    if args.tshark and not have_tshark():
        print("⚠ 缺少 tshark：独立对照未执行", file=sys.stderr)
        return 3

    with tempfile.TemporaryDirectory(prefix="cythsec-icmp-gre-") as td:
        work = Path(td)
        icmp_pcap = work / "icmp.pcap"
        gre_pcap = work / "gre.pcap"
        write_pcap(icmp_pcap, icmp_corpus())
        write_pcap(gre_pcap, gre_corpus())

        icmp_out = work / "icmp.jsonl"
        p = run([ICMP_BIN, "--pcap", icmp_pcap, "-o", icmp_out])
        icmp_records = parse_jsonl(icmp_out)
        icmp_stats = parse_stats(p.stderr, "cythsec-icmp", "icmp")
        validate_icmp(icmp_records, icmp_stats)

        gre_out = work / "gre.jsonl"
        p = run([GRE_BIN, "--pcap", gre_pcap, "-o", gre_out])
        gre_records = parse_jsonl(gre_out)
        gre_stats = parse_stats(p.stderr, "cythsec-gre", "gre")
        validate_gre(gre_records, gre_stats)

        validate_pipeline(icmp_pcap, gre_pcap, work)
        reverse_injections(icmp_records, icmp_stats, gre_records, gre_stats)
        print("  ✓ ICMP：18 条事件（v4 10 / v6 8）、6 条错误报文内嵌原始 IP、NDP 3 条、2 条截断")
        print("  ✓ GRE：11 条事件（v0 9 / PPTP 2）、SRE/TEB/MPLS、2 条畸形 + 1 条头截断")
        print("  ✓ 主流水线：ICMP 5 条会话；GRE 仅 2 条外层会话，内层 IP 未另造流")
        print("  ✓ 6 项反向注入（类型/统计/内嵌地址/GRE key/inner_complete/内层地址）均被检出")

        if args.tshark:
            validate_tshark_icmp(icmp_pcap)
            validate_tshark_gre(gre_pcap)
            print("  ✓ tshark 独立核对 ICMP type/code/echo 标识与 GRE version/proto/key/seq：16 + 8 帧一致")

    print("✓ B011/B012/V009 基础协议识别回归通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
