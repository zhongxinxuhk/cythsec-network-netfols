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


def gre0_checksum(flags, proto, inner, key=None, seq=None, sre=None):
    """带 C 位的 GREv0，按 RFC 2784 对完整 GRE 报文计算校验和。"""
    p = bytearray(gre0(flags | 0x8000, proto, inner, checksum_value=0, key=key, seq=seq, sre=sre))
    p[4:6] = struct.pack("!H", checksum(bytes(p)))
    return bytes(p)


def gre_frame(payload, src=bytes([192, 0, 2, 1]), dst=bytes([192, 0, 2, 2]), orig_len=None):
    frame = eth(ipv4(src, dst, 47, payload), ETH_IPV4)
    return frame, orig_len


def pptp(flags, payload_len, call_id, tail=b""):
    return struct.pack("!HHHH", flags, PPTP_PROTO, payload_len, call_id) + tail


def write_pcap(path, records, linktype=1):
    """records: [(frame_bytes, orig_len_or_None)]；linktype=1/113/276。"""
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, (frame, orig_len) in enumerate(records):
        wire = len(frame) if orig_len is None else orig_len
        out += struct.pack("<IIII", 1_700_000_000 + i, i * 1000, len(frame), wire)
        out += frame
    path.write_bytes(out)


def sll_wrap(frame, sll2):
    """把 Ethernet 帧去掉 MAC 头，套 Linux cooked capture v1/v2 头。"""
    ether_type = struct.unpack("!H", frame[12:14])[0]
    if sll2:
        return (
            struct.pack("!H", ether_type)
            + struct.pack("!H", 0)
            + struct.pack("!I", 1)
            + struct.pack("!H", 1)
            + bytes([0, 6])
            + bytes(8)
            + frame[14:]
        )
    return struct.pack("!HHH", 0, 1, 6) + bytes(8) + struct.pack("!H", ether_type) + frame[14:]


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
        # MTU 1500
        + struct.pack("!BBHI", 5, 1, 0, 1500)
        # Route Information /64, preference high, lifetime 600
        + struct.pack("!BBBB", 24, 3, 64, 0x08)
        + struct.pack("!I", 600)
        + v6("2001:db8::")
        # RDNSS lifetime 300, one server
        + struct.pack("!BBHI", 25, 3, 0, 300)
        + v6("2001:db8::53")
        # DNSSL lifetime 300, example.com
        + struct.pack("!BBHI", 31, 3, 0, 300)
        + bytes([7])
        + b"example"
        + bytes([3])
        + b"com"
        + bytes([0, 0, 0, 0])
    )
    # 截断选项：声明 16 字节，只给 4 字节数据。
    ns_truncated_option = bytes(4) + v6("fe80::1") + bytes([1, 2, 1, 2, 3, 4])
    # 零长度选项：Length=0 必须显式记 malformed，不能死循环。
    ns_zero_option = bytes(4) + v6("fe80::1") + bytes([1, 0, 0, 0, 0, 0, 0, 0])
    # MLDv2 Query：组播地址 + S/QRV/QQIC + 1 个源。
    mld_query = v6("ff02::1") + bytes([0x0F, 10]) + struct.pack("!H", 1) + v6("2001:db8::9")
    # MLDv2 Report：1 条 MODE_IS_INCLUDE 记录 + 1 个源。
    mld_report = bytes([1, 0]) + struct.pack("!H", 1) + v6("ff02::1") + v6("2001:db8::9")

    bad_checksum = bytearray(icmp4(src4, dst4, 42, 0, bytes(4), b"????"))
    bad_checksum[14 + 20 + 2] ^= 0xFF

    frames = [
        icmp4(src4, dst4, 8, 0, struct.pack("!HH", 0x1234, 7), b"abcdefgh"),  # 1 echo req
        icmp4(dst4, src4, 0, 0, struct.pack("!HH", 0x1234, 7), b"abcdefgh"),  # 2 echo rep
        icmp4(dst4, src4, 3, 3, bytes(4), orig4),  # 3 port unreachable
        icmp4(dst4, src4, 3, 4, struct.pack("!HH", 0, 1400), orig4),  # 4 frag needed
        icmp4(dst4, src4, 11, 0, bytes(4), orig4),  # 5 time exceeded
        icmp4(dst4, src4, 12, 0, bytes([9, 0, 0, 0]), orig4),  # 6 param problem
        icmp4(dst4, src4, 5, 1, v4("192.0.2.254"), orig4),  # 7 redirect
        icmp4(src4, dst4, 13, 0, struct.pack("!HH", 0x2222, 3), bytes(12)),  # 8 timestamp
        bytes(bad_checksum),  # 9 unknown type + invalid checksum
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
        icmp6(v6("fe80::1"), v6("ff02::1"), 130, 0, struct.pack("!HH", 1000, 0), mld_query),  # 18 MLD query
        icmp6(src6, dst6, 200, 0, bytes(4), b""),  # 19 unknown
        icmp6(src6, dst6, 128, 0, struct.pack("!HH", 1, 1), b"")[: 14 + 40 + 4],  # 20 truncated
        icmp6(v6("fe80::2"), v6("ff02::1"), 143, 0, struct.pack("!HH", 0, 1), mld_report),  # 21 MLDv2 report
        icmp6(v6("fe80::1"), v6("ff02::1:ff00:2"), 135, 0, bytes(4), ns_truncated_option),  # 22 option truncated
        icmp6(v6("fe80::1"), v6("ff02::1:ff00:2"), 135, 0, bytes(4), ns_zero_option),  # 23 option malformed
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
    # 两层 MPLS 标签，栈底后是 IPv4 头。
    mpls = (
        struct.pack("!I", (100 << 12) | (5 << 9) | 64)
        + struct.pack("!I", (200 << 12) | (1 << 9) | 0x100 | 63)
        + ipv4(v4("10.0.0.1"), v4("10.0.0.2"), 6, bytes(20))
    )
    eth_inner = bytes(12) + struct.pack("!H", ETH_IPV4) + bytes(20)
    erspan2 = (
        struct.pack("!H", (1 << 12) | 100)
        + struct.pack("!H", (5 << 13) | 0x0123)
        + struct.pack("!I", 0x00012345)
        + eth_inner
    )
    erspan3 = (
        struct.pack("!H", (2 << 12) | 200)
        + struct.pack("!H", (3 << 13) | 0x0256)
        + struct.pack("!I", 0x11223344)
        + struct.pack("!H", 0x0064)
        + struct.pack("!H", (1 << 3) | (1 << 1))
        + eth_inner
    )
    bad_checksum = bytearray(gre0_checksum(0x2000, ETH_IPV4, inner4, key=0xCAFEBABE))
    bad_checksum[4] ^= 0xFF

    records = [
        (gre_frame(gre0(0x0000, ETH_IPV4, inner4))[0], None),  # 1 plain
        (gre_frame(gre0(0x2000, ETH_IPV4, inner4, key=0xDEADBEEF))[0], None),  # 2 key
        (
            gre_frame(gre0_checksum(0xB000, ETH_IPV6, inner6, key=0x11223344, seq=7))[0],
            None,
        ),  # 3 C+K+S valid
        (
            gre_frame(
                gre0_checksum(
                    0x4000,
                    ETH_IPV4,
                    inner4,
                    sre=[(0x0800, 0, bytes([10, 0, 0, 9]))],
                )
            )[0],
            None,
        ),  # 4 C+R+SRE
        (gre_frame(gre0(0x0000, ETH_GRE_INNER_TEB, teb))[0], None),  # 5 TEB
        (gre_frame(gre0(0x0000, 0x8847, mpls))[0], None),  # 6 MPLS
        (gre_frame(gre0(0x0000, 0x1234, bytes(8)))[0], None),  # 7 unknown
        (gre_frame(gre0(0x0000, ETH_IPV4, inner4[:12]))[0], None),  # 8 inner truncated
        (gre_frame(pptp(0x2001, 8, 1, bytes([0, 0x21]) + bytes(6)))[0], None),  # 9 PPTP
        (
            gre_frame(pptp(0x3081, 0, 3, struct.pack("!II", 0x0A0B0C0D, 0x11223344)))[0],
            None,
        ),  # 10 PPTP S+A
        (gre_frame(pptp(0x0001, 8, 1, bytes(8)))[0], None),  # 11 missing K
        (gre_frame(gre0(0x0002, ETH_IPV4, inner4))[0], None),  # 12 version 2
        (gre_frame(gre0(0x2000, ETH_IPV4, b"")[: 4 + 2])[0], None),  # 13 truncated key
        (
            gre_frame(gre0(0x0000, ETH_GRE_INNER_TEB, bytes(10)))[0],
            None,
        ),  # 14 TEB truncated
        (
            eth(
                ipv4(
                    v4("192.0.2.9"),
                    v4("192.0.2.10"),
                    17,
                    struct.pack("!HHHH", 1, 2, 8, 0),
                ),
                ETH_IPV4,
            ),
            None,
        ),  # 15 non-GRE
        (gre_frame(gre0(0x0000, 0x88BE, erspan2))[0], None),  # 16 ERSPAN II
        (gre_frame(gre0(0x0000, 0x22EB, erspan3))[0], None),  # 17 ERSPAN III
        (gre_frame(bytes(bad_checksum))[0], None),  # 18 invalid checksum
    ]
    # 第 1 帧标记为“抓包截断但 GRE 头完整”：orig_len 比 caplen 多 10。
    first = records[0][0]
    records[0] = (first, len(first) + 10)
    return records


def validate_icmp(records, stats):
    assert len(records) == 21, f"应输出 21 条有效 ICMP，实际 {len(records)}"
    by = {r["frame"]: r for r in records}
    assert sorted(by) == [
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        21,
        22,
        23,
    ], sorted(by)

    r = by[1]
    assert r["family"] == "ipv4" and r["ip_proto"] == 1
    assert r["type_name"] == "echo_request" and r["type"] == 8 and r["code"] == 0
    assert r["identifier"] == 0x1234 and r["sequence"] == 7
    assert r["embedded"] is None and r["ndp"] is None and r["truncated"] is False
    assert r["checksum_status"] == "valid", r
    assert by[9]["checksum_status"] == "invalid", by[9]
    assert by[11]["checksum_status"] == "unavailable", by[11]

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
    assert n["link_layer_addresses"] == [{"kind": 1, "address": "02:00:00:00:00:01"}], n

    n = by[16]["ndp"]
    assert n["na_flags"] == 0xE0000000 and n["target"] == "2001:db8::2", n
    assert n["link_layer_addresses"] == [{"kind": 2, "address": "02:00:00:00:00:02"}], n

    n = by[17]["ndp"]
    assert n["cur_hop_limit"] == 64 and n["ra_flags"] == 0xC0, n
    assert n["router_lifetime"] == 1800 and n["reachable_time"] == 30000, n
    assert n["retrans_timer"] == 1000, n
    assert n["options"] == [
        {"kind": 3, "len": 4},
        {"kind": 5, "len": 1},
        {"kind": 24, "len": 3},
        {"kind": 25, "len": 3},
        {"kind": 31, "len": 3},
    ], n
    assert n["prefixes"] == [
        {
            "kind": 3,
            "prefix_len": 64,
            "flags": 0xC0,
            "valid_lifetime": 3600,
            "preferred_lifetime": 1800,
            "prefix": "2001:db8::",
        }
    ], n
    assert n["mtu_options"] == [{"kind": 5, "mtu": 1500}], n
    assert n["route_info"] == [
        {
            "kind": 24,
            "prefix_len": 64,
            "preference": 1,
            "lifetime": 600,
            "prefix": "2001:db8::",
        }
    ], n
    assert n["rdnss"] == [
        {
            "kind": 25,
            "lifetime": 300,
            "servers": ["2001:db8::53"],
        }
    ], n
    assert n["dnssl"] == [
        {
            "kind": 31,
            "lifetime": 300,
            "domains": ["example.com"],
        }
    ], n

    m = by[18]["mld"]
    assert m["kind"] == "query" and m["max_response_delay_ms"] == 1000, m
    assert m["s_flag"] is True and m["qrv"] == 7 and m["qqic"] == 10, m
    assert m["sources"] == ["2001:db8::9"], m
    m = by[21]["mld"]
    assert m["kind"] == "report_v2" and len(m["records"]) == 1, m
    assert m["records"][0]["record_type"] == 1, m
    assert m["records"][0]["multicast_address"] == "ff02::1", m
    assert m["records"][0]["sources"] == ["2001:db8::9"], m

    assert by[22]["ndp"]["options_truncated"] is True, by[22]
    assert by[22]["ndp"]["options"] == [], by[22]
    assert by[23]["ndp"]["options_malformed"] is True, by[23]
    assert by[23]["ndp"]["options"] == [], by[23]

    assert by[19]["type_name"] == "unknown"

    want = {
        "icmp_frames": 21,
        "v4": 10,
        "v6": 11,
        "echo_requests": 3,
        "echo_replies": 2,
        "destination_unreachable": 2,
        "packet_too_big": 1,
        "time_exceeded": 1,
        "parameter_problem": 1,
        "redirects": 1,
        "ndp": 5,
        "mld": 2,
        "other": 3,
        "errors": 6,
        "with_embedded": 6,
        "truncated": 2,
        "malformed": 1,
        "ndp_options_truncated": 1,
        "ndp_options_malformed": 1,
        "capture_truncated": 1,
        "checksum_valid": 19,
        "checksum_invalid": 1,
        "checksum_unavailable": 1,
        "mld_queries": 1,
        "mld_reports": 1,
        "mld_sources": 1,
        "mld_records": 1,
    }
    for k, v in want.items():
        assert stats.get(k) == v, f"ICMP 统计 {k}={stats.get(k)}，期望 {v}（全部：{stats}）"


def validate_gre(records, stats):
    assert len(records) == 14, f"应输出 14 条有效 GRE，实际 {len(records)}"
    by = {r["frame"]: r for r in records}
    assert sorted(by) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 16, 17, 18], sorted(by)

    r = by[1]
    assert r["version"] == 0 and r["mode"] == "gre"
    assert r["protocol_name"] == "ipv4" and r["header_len"] == 4
    assert r["key"] is None and r["key_present"] is False
    assert r["inner"]["source"] == "10.0.0.1" and r["inner"]["complete_header"] is True
    assert r["capture_truncated"] is True and r["truncated"] is False
    assert r["checksum_status"] == "not_present", r

    r = by[2]
    assert r["key"] == 0xDEADBEEF and r["key_present"] is True

    r = by[3]
    assert r["checksum_present"] is True and r["checksum_status"] == "valid", r
    assert r["key"] == 0x11223344 and r["sequence"] == 7
    assert r["protocol_name"] == "ipv6" and r["inner"]["destination"] == "2001:db8::2"
    assert r["header_len"] == 16

    r = by[4]
    assert r["routing_present"] is True and r["sre_count"] == 1 and r["header_len"] == 20
    assert r["checksum_status"] == "valid", r
    assert r["sre_routes"] == [
        {
            "address_family": 0x0800,
            "offset": 0,
            "length": 4,
            "data": "0a000009",
        }
    ], r
    assert r["inner"]["source"] == "10.0.0.1"

    r = by[5]
    assert r["protocol_name"] == "transparent_ethernet_bridging"
    assert r["inner"]["kind"] == "ethernet"
    assert r["inner"]["inner_ether_type"] == 0x0800
    assert r["inner"]["inner_vlan_ids"] == [100]

    r = by[6]
    assert r["protocol_name"] == "mpls_unicast" and r["inner"]["kind"] == "mpls", r
    assert r["inner"]["header_len"] == 8 and r["inner"]["complete_header"] is True, r
    assert r["inner"]["mpls_labels"] == [
        {"label": 100, "traffic_class": 5, "bottom_of_stack": False, "ttl": 64},
        {"label": 200, "traffic_class": 1, "bottom_of_stack": True, "ttl": 63},
    ], r
    assert r["inner"]["mpls_payload"] == "ipv4", r
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

    r = by[16]
    assert r["protocol_name"] == "erspan" and r["erspan"]["version"] == 1, r
    assert r["erspan"]["vlan"] == 100 and r["erspan"]["session_id"] == 0x123, r
    assert r["erspan"]["index"] == 0x12345 and r["erspan"]["header_len"] == 8, r
    assert r["inner"]["kind"] == "erspan" and r["inner"]["inner_ether_type"] == 0x0800, r

    r = by[17]
    assert r["protocol_name"] == "erspan3" and r["erspan"]["version"] == 2, r
    assert r["erspan"]["vlan"] == 200 and r["erspan"]["session_id"] == 0x256, r
    assert r["erspan"]["timestamp"] == 0x11223344 and r["erspan"]["sgt"] == 0x64, r
    assert r["erspan"]["direction"] is True and r["erspan"]["timestamp_granularity"] == 1, r
    assert r["erspan"]["header_len"] == 12, r

    r = by[18]
    assert r["checksum_present"] is True and r["checksum_status"] == "invalid", r

    want = {
        "gre_frames": 14,
        "version0": 12,
        "version1": 2,
        "keyed": 5,
        "unkeyed": 9,
        "checksum_present": 3,
        "routing_present": 1,
        "sequence_present": 2,
        "ack_present": 1,
        "protocol_ipv4": 5,
        "protocol_ipv6": 1,
        "protocol_ethernet": 2,
        "protocol_ppp": 2,
        "protocol_mpls": 1,
        "protocol_erspan": 2,
        "protocol_other": 1,
        "inner_complete": 10,
        "inner_incomplete": 2,
        "capture_truncated": 1,
        "truncated": 3,
        "malformed": 2,
        "checksum_valid": 2,
        "checksum_invalid": 1,
        "checksum_unavailable": 0,
        "checksum_not_present": 11,
        "sre_routes": 1,
        "mpls_labels": 2,
        "erspan_frames": 2,
    }
    for k, v in want.items():
        assert stats.get(k) == v, f"GRE 统计 {k}={stats.get(k)}，期望 {v}（全部：{stats}）"


def validate_pipeline(icmp_pcap, gre_pcap, work):
    flows = work / "icmp-flows.jsonl"
    p = run([ANALYZE_BIN, "-r", icmp_pcap, "-o", flows])
    icmp_stats = parse_stats(p.stderr, "cythsec-analyze", "icmp")
    # 统计行里同时有 arp/icmp/gre，parse_stats 只取整行；按字段名前缀查关键值。
    assert icmp_stats["icmp_frames"] == 21, icmp_stats
    assert icmp_stats["echo_requests"] == 3, icmp_stats
    assert icmp_stats["ndp"] == 5, icmp_stats
    assert icmp_stats["truncated"] == 2, icmp_stats
    assert icmp_stats["checksum_invalid"] == 1, icmp_stats
    nflows = len(flows.read_text().splitlines())
    assert nflows == 6, f"ICMP 流水线应产出 6 条会话（v4 1 + v6 5），实际 {nflows}"

    gre_flows = work / "gre-flows.jsonl"
    p = run([ANALYZE_BIN, "-r", gre_pcap, "-o", gre_flows])
    gre_stats = parse_stats(p.stderr, "cythsec-analyze", "gre")
    assert gre_stats["gre_frames"] == 14, gre_stats
    assert gre_stats["protocol_ipv4"] == 5, gre_stats
    assert gre_stats["inner_complete"] == 10, gre_stats
    assert gre_stats["malformed"] == 2, gre_stats
    assert gre_stats["checksum_invalid"] == 1, gre_stats
    assert gre_stats["erspan_frames"] == 2, gre_stats
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
        9: ("icmp", "42", "0", None, None),
        12: ("icmpv6", "128", "0", "22136", "9"),
        13: ("icmpv6", "129", "0", "22136", "9"),
        14: ("icmpv6", "2", "0", None, None),
        15: ("icmpv6", "135", "0", None, None),
        16: ("icmpv6", "136", "0", None, None),
        17: ("icmpv6", "134", "0", None, None),
        18: ("icmpv6", "130", "0", None, None),
        21: ("icmpv6", "143", "0", None, None),
        22: ("icmpv6", "135", "0", None, None),
        23: ("icmpv6", "135", "0", None, None),
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
        # Wireshark 的 checksum.status：1=good，0=bad。它和我们独立实现必须一致。
        if frame in (1, 9):
            want_status = "1" if frame == 1 else "0"
            assert (
                layer.get(f"{key}.checksum.status") == want_status
            ), f"tshark frame {frame} checksum.status={layer.get(f'{key}.checksum.status')}"
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
        16: (0, "0x88be", None, None, None, None, None),
        17: (0, "0x22eb", None, None, None, None, None),
        18: (0, "0x0800", 0xCAFEBABE, None, None, None, None),
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
        if frame in (3, 18):
            want_status = "1" if frame == 3 else "0"
            assert (
                gre.get("gre.checksum.status") == want_status
            ), f"tshark frame {frame} gre.checksum.status={gre.get('gre.checksum.status')}"
        if frame == 6:
            assert layers.get("mpls", {}).get("mpls.label") == "200", layers.get("mpls")
            assert layers.get("ip", {}).get("ip.src") == "10.0.0.1", "MPLS 内层 IPv4 未被 tshark 解出"
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

    bad = [dict(r) for r in icmp_records]
    bad[0]["checksum_status"] = "invalid"
    cases.append(("ICMP checksum_status", lambda: validate_icmp(bad, icmp_stats)))

    bad = [dict(r) for r in gre_records]
    bad[2]["checksum_status"] = "invalid"
    cases.append(("GRE checksum_status", lambda: validate_gre(bad, gre_stats)))

    bad = [dict(r) for r in gre_records]
    bad[5]["inner"] = dict(bad[5]["inner"])
    bad[5]["inner"]["mpls_labels"] = [dict(v) for v in bad[5]["inner"]["mpls_labels"]]
    bad[5]["inner"]["mpls_labels"][0]["label"] = 1
    cases.append(("GRE MPLS 标签", lambda: validate_gre(bad, gre_stats)))

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

        # SLL/SLL2：同一条 Ethernet 负载换 cooked 头后，采集器必须给出相同统计。
        for sll2, linktype in ((False, 113), (True, 276)):
            tag = "sll2" if sll2 else "sll"
            for proto, corpus, bin_path, marker, want_frames, want_valid in (
                ("icmp", icmp_corpus, ICMP_BIN, "icmp", 3, 3),
                ("gre", gre_corpus, GRE_BIN, "gre", 2, 0),
            ):
                pcap = work / f"{proto}-{tag}.pcap"
                write_pcap(
                    pcap,
                    [(sll_wrap(r[0], sll2), None) for r in corpus()[:want_frames]],
                    linktype,
                )
                out = work / f"{proto}-{tag}.jsonl"
                q = run([bin_path, "--pcap", pcap, "-o", out])
                st = parse_stats(q.stderr, f"cythsec-{marker}", marker)
                assert st["frames"] == want_frames, (proto, tag, st)
                if proto == "icmp":
                    assert st["icmp_frames"] == want_frames, st
                    assert st["checksum_valid"] == want_valid, st
                else:
                    assert st["gre_frames"] == want_frames, st
        print("  ✓ ICMP：21 条事件（v4 10 / v6 11）、校验和 valid/invalid/unavailable、NDP 5 条、MLD 2 条")
        print("  ✓ GRE：14 条事件（v0 12 / PPTP 2）、checksum/SRE/MPLS/ERSPAN、2 条畸形 + 1 条头截断")
        print("  ✓ 主流水线：ICMP 6 条会话；GRE 仅 2 条外层会话，内层 IP 未另造流")
        print("  ✓ 9 项反向注入（类型/统计/内嵌地址/GRE key/inner_complete/内层地址/校验和/MPLS）均被检出")
        print("  ✓ SLL/SLL2 cooked 头：ICMP/GRE 采集器统计与 Ethernet 一致")

        if args.tshark:
            validate_tshark_icmp(icmp_pcap)
            validate_tshark_gre(gre_pcap)
            print(
                "  ✓ tshark 独立核对 ICMP type/code/checksum 与 GRE version/proto/key/seq/checksum/MPLS：19 + 11 帧一致"
            )

    print("✓ B011/B012/V009 基础协议识别回归通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
