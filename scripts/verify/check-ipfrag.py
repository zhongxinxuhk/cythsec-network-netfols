#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""B008 IPv4/IPv6 分片重组回归：本地语义、流水线接线与 tshark 独立对照。

语料由本脚本按 RFC 791 / RFC 8200 / RFC 5722 独立拼字节，不调用 Rust 编码器。
检查项：
  1. IPv4 乱序两片重组后只产生一条 DNS 流，字节数/包数等于完整数据报；
  2. IPv6 带逐跳扩展头的乱序两片同样只产生一条流；
  3. 缺首片、缺尾、重叠、抓包截断、重复片分别走 Pending/Dropped/Complete，
     统计行与 `cythsec-ipfrag` 事件流一致；
  4. 不完整/重叠分片不得进入 FlowRecord，也不得伪造端口 0 的流；
  5. `--tshark` 让 Wireshark 独立重组同一份 pcap，核对 DNS 查询名与分片帧数；
  6. 反向注入：记录、统计或事件任一被改坏，本检查器必须报错。

用法：python3 scripts/verify/check-ipfrag.py [--tshark]
退出码：0 通过；1 断言失败；2 参数/前置错误；3 缺工具（未核验，不计通过）
"""

import argparse
import copy
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANALYZE = Path(os.environ.get("ANALYZE_BIN", ROOT / "target/debug/cythsec-analyze"))
IPFRAG = Path(os.environ.get("IPFRAG_BIN", ROOT / "target/debug/cythsec-ipfrag"))

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
IPV4_SRC = bytes([192, 0, 2, 1])
IPV4_DST = bytes([192, 0, 2, 2])
IPV6_SRC = bytes.fromhex("20010db8000000000000000000000001")
IPV6_DST = bytes.fromhex("20010db8000000000000000000000002")


class Failure(AssertionError):
    pass


def require(cond, msg):
    if not cond:
        raise Failure(msg)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth(payload, ether_type):
    return bytes(12) + struct.pack("!H", ether_type) + payload


def ipv4_fragment(src, dst, ident, proto, offset_units, more, data):
    total = 20 + len(data)
    frag = (offset_units & 0x1FFF) | (0x2000 if more else 0)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, ident, frag, 64, proto, 0, src, dst,
    )
    c = checksum(hdr)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, ident, frag, 64, proto, c, src, dst,
    )
    return hdr + data


def ipv4(payload, proto=17, src=IPV4_SRC, dst=IPV4_DST, ident=1):
    return ipv4_fragment(src, dst, ident, proto, 0, False, payload)


def ipv6_header(payload_len, next_header, src=IPV6_SRC, dst=IPV6_DST):
    return struct.pack("!IHBB16s16s", 0x60000000, payload_len, next_header, 64, src, dst)


def ipv6_fragment(src, dst, ident, next_header, offset_units, more, data, ext=False):
    frag = bytearray(8)
    frag[0] = next_header
    field = (offset_units << 3) | (1 if more else 0)
    frag[2:4] = struct.pack("!H", field)
    frag[4:8] = struct.pack("!I", ident)
    if ext:
        # 逐跳选项：next=44, hdr ext len=0，固定 8 字节。
        body = b"\x2c\x00\x00\x00\x00\x00\x00\x00" + bytes(frag) + data
        return ipv6_header(len(body), 0, src, dst) + body
    body = bytes(frag) + data
    return ipv6_header(len(body), 44, src, dst) + body


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_name(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\0"


def dns_query(txid, name):
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(txid, name, addr):
    q = dns_name(name) + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + addr
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + q + answer


def pcap(frames):
    """frames: [(ts_sec, ts_usec, bytes, orig_len)]；小端、微秒、Ethernet。"""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts_sec, ts_usec, data, orig_len in frames:
        out += struct.pack("<IIII", ts_sec, ts_usec, len(data), orig_len) + data
    return out


def frame(ts_usec, data, orig_len=None):
    return (1_700_000_100, ts_usec, data, len(data) if orig_len is None else orig_len)


def build_valid():
    frames = []
    ts = 1

    def add(data):
        nonlocal ts
        frames.append(frame(ts, data))
        ts += 1

    # IPv4：尾片先到、首片后到；最后一条应答不重组。
    q4 = dns_query(0x1001, "example.com")
    l4q4 = udp(53000, 53, q4)
    add(eth(ipv4_fragment(IPV4_SRC, IPV4_DST, 0x0101, 17, 2, False, l4q4[16:]), ETH_IPV4))
    add(eth(ipv4_fragment(IPV4_SRC, IPV4_DST, 0x0101, 17, 0, True, l4q4[:16]), ETH_IPV4))
    a4 = dns_response(0x1001, "example.com", bytes([203, 0, 113, 7]))
    add(eth(ipv4(udp(53, 53000, a4), 17, IPV4_DST, IPV4_SRC, 0x0102), ETH_IPV4))

    # IPv6：逐跳扩展头在分片头之前，仍然必须能重组。
    q6 = dns_query(0x1002, "ipv6.example")
    l4q6 = udp(53001, 53, q6)
    add(eth(ipv6_fragment(IPV6_SRC, IPV6_DST, 0x0202, 17, 2, False, l4q6[16:], ext=True), ETH_IPV6))
    add(eth(ipv6_fragment(IPV6_SRC, IPV6_DST, 0x0202, 17, 0, True, l4q6[:16], ext=True), ETH_IPV6))
    a6 = dns_response(0x1002, "ipv6.example", bytes.fromhex("20010db8000000000000000000000099"))
    add(eth(ipv6_header(len(udp(53, 53001, a6)), 17, IPV6_DST, IPV6_SRC) + udp(53, 53001, a6), ETH_IPV6))
    return pcap(frames), l4q4, a4, l4q6, a6


def build_incomplete():
    data = eth(ipv4_fragment(IPV4_SRC, IPV4_DST, 0x0303, 17, 1, False, b"\xaa" * 8), ETH_IPV4)
    return pcap([frame(1, data)])


def build_overlap():
    a = eth(ipv4_fragment(IPV4_SRC, IPV4_DST, 0x0404, 17, 0, True, b"\x11" * 16), ETH_IPV4)
    b = eth(ipv4_fragment(IPV4_SRC, IPV4_DST, 0x0404, 17, 1, False, b"\x22" * 16), ETH_IPV4)
    return pcap([frame(1, a), frame(2, b)])


def build_truncated():
    full = eth(
        ipv4_fragment(IPV4_SRC, IPV4_DST, 0x0505, 17, 0, True, b"\x33" * 16),
        ETH_IPV4,
    )
    return pcap([frame(1, full, orig_len=len(full) + 8)])


def build_duplicate():
    q = dns_query(0x1003, "dup.example")
    l4 = udp(53002, 53, q)
    first = eth(ipv4_fragment(IPV4_SRC, IPV4_DST, 0x0606, 17, 0, True, l4[:16]), ETH_IPV4)
    last = eth(ipv4_fragment(IPV4_SRC, IPV4_DST, 0x0606, 17, 2, False, l4[16:]), ETH_IPV4)
    return pcap([frame(1, first), frame(2, first), frame(3, last)])


def run(cmd, timeout=60):
    p = subprocess.run([str(c) for c in cmd], text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise Failure(f"{cmd[0]} 失败（{p.returncode}）：{p.stderr[-1600:]}")
    return p


def analyze(path):
    with tempfile.NamedTemporaryFile("r", encoding="utf-8", suffix=".jsonl", delete=False) as fh:
        out = fh.name
    try:
        p = run([ANALYZE, "-r", path, "-o", out])
        with open(out, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        return records, p.stderr
    finally:
        os.unlink(out)


def ipfrag_events(path):
    p = run([IPFRAG, "--pcap", path])
    events = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
    stats = {}
    for line in p.stderr.splitlines():
        if "[cythsec-ipfrag] ipfrag " in line:
            body = line.split("ipfrag ", 1)[1]
            for part in body.split():
                if "=" in part:
                    k, v = part.split("=", 1)
                    stats[k] = int(v) if re.fullmatch(r"-?\d+", v) else v
    require(stats, "cythsec-ipfrag 没有输出统计行")
    return events, stats


def parse_analyze(stderr):
    stats = {}
    errors = {}
    for line in stderr.splitlines():
        if "[cythsec-analyze] ipfrag " in line:
            body = line.split("ipfrag ", 1)[1]
            for part in body.split():
                if "=" in part:
                    k, v = part.split("=", 1)
                    stats[k] = int(v) if re.fullmatch(r"-?\d+", v) else v
        m = re.search(r"decode_error code=(\S+) count=(\d+)", line)
        if m:
            errors[m.group(1)] = int(m.group(2))
    require(stats, "cythsec-analyze 没有输出 ipfrag 统计行")
    return stats, errors


def find_record(records, src, sport, dst, dport):
    for r in records:
        f = r["flow"]
        if f["src_ip"] == src and f["src_port"] == sport and f["dst_ip"] == dst and f["dst_port"] == dport:
            return r
    raise Failure(f"找不到记录 {src}:{sport} -> {dst}:{dport}；实际 {[r['flow'] for r in records]}")


def check_valid(records, stats, errors, events, event_stats, l4q4, a4, l4q6, a6):
    require(len(records) == 2, f"完整语料应只有 2 条流，实际 {len(records)}")
    require(not errors, f"完整重组不应有 decode_error，实际 {errors}")

    r4 = find_record(records, "192.0.2.1", 53000, "192.0.2.2", 53)
    require(r4["flow"]["proto"] == 17, "IPv4 DNS 流协议号必须是 17")
    require(r4["counters"]["packets"] == 2, "IPv4 查询两片 + 应答一条 = 2 个逻辑包")
    require(r4["counters"]["bytes"] == len(l4q4) + 8 + len(a4), "IPv4 字节数必须是完整 IP 载荷之和")
    require(r4["app"]["outcome"] == "identified" and r4["app"]["app"] == "dns", "IPv4 应识别为 dns")

    r6 = find_record(records, "2001:db8::1", 53001, "2001:db8::2", 53)
    require(r6["flow"]["proto"] == 17, "IPv6 DNS 流协议号必须是 17")
    require(r6["counters"]["packets"] == 2, "IPv6 查询两片 + 应答一条 = 2 个逻辑包")
    require(r6["counters"]["bytes"] == len(l4q6) + 8 + len(a6), "IPv6 字节数必须是完整 IP 载荷之和")
    require(r6["app"]["outcome"] == "identified" and r6["app"]["app"] == "dns", "IPv6 应识别为 dns")

    require(stats.get("frags") == 4, f"应有 4 个分片，实际 {stats}")
    require(stats.get("v4") == 2 and stats.get("v6") == 2, f"IPv4/IPv6 分片数应为 2/2，实际 {stats}")
    require(stats.get("datagrams") == 2, "应有 2 个待重组数据报")
    require(stats.get("complete") == 2, "应完成 2 个数据报")
    require(stats.get("incomplete") == 0, "完整语料不应有未完成数据报")
    require(stats.get("malformed") == 0, "完整语料不应有畸形数据报")
    require(stats.get("dup") == 0, "完整语料没有重复片")
    require(stats.get("pending_at_eof") == 0, "完整语料不应留下待处理分片")
    require(stats.get("bytes") == len(l4q4) + len(l4q6), "重组字节数必须等于两个完整载荷之和")

    completes = [e for e in events if e.get("event") == "datagram_complete"]
    require(len(completes) == 2, f"事件流应有 2 条 datagram_complete，实际 {len(completes)}")
    require(
        {e["version"] for e in completes} == {"ipv4", "ipv6"},
        "完成事件必须同时覆盖 IPv4/IPv6",
    )
    require(event_stats.get("complete") == 2, "事件流统计必须与完成事件一致")


def check_incomplete(stats, errors, events):
    require(stats.get("frags") == 1, "缺首片语料应有 1 个分片")
    require(stats.get("datagrams") == 1, "缺首片语料应有 1 个数据报")
    require(stats.get("complete") == 0, "缺首片不得报告 complete")
    require(stats.get("incomplete") == 1, "缺首片必须报告 incomplete=1")
    require(stats.get("pending_at_eof") == 1, "收尾必须留下 1 个待处理分片")
    require(errors.get("decode.non_initial_fragment") == 1, f"非首片必须显式计数，实际 {errors}")
    require(any(e.get("outcome") == "pending" for e in events), "事件流必须留下 pending")


def check_overlap(stats, errors, events):
    require(stats.get("overlap") == 1, f"重叠必须计数，实际 {stats}")
    require(stats.get("malformed") == 1, "重叠数据报必须计入 malformed")
    require(stats.get("complete") == 0, "重叠不得完成")
    require(stats.get("incomplete") == 0, "重叠是 malformed，不是 incomplete")
    require(errors.get("ipfrag.overlap") == 1, f"重叠必须报 ipfrag.overlap，实际 {errors}")
    require(any(e.get("error") == "ipfrag.overlap" for e in events), "事件流必须报 overlap")


def check_truncated(stats, errors):
    require(stats.get("truncated") == 1, f"截断必须计数，实际 {stats}")
    require(stats.get("malformed") == 1, "截断数据报必须计入 malformed")
    require(stats.get("complete") == 0, "截断不得完成")
    require(errors.get("ipfrag.truncated_capture") == 1, f"截断错误码不对：{errors}")


def check_duplicate(records, stats):
    require(len(records) == 1, "重复片应仍只有 1 条流")
    require(records[0]["counters"]["packets"] == 1, "重复片不得让逻辑包数变成 2")
    require(stats.get("dup") == 1, f"重复片必须计数，实际 {stats}")
    require(stats.get("complete") == 1, "重复片不应阻止完成")


def check_tshark(path):
    tshark = shutil.which("tshark")
    require(tshark is not None, "缺少 tshark")
    common = [tshark, "-r", path, "-o", "ip.defragment:TRUE", "-o", "ipv6.defragment:TRUE"]
    frag = subprocess.run(
        common
        + [
            "-Y",
            "ip.flags.mf == 1 || ip.frag_offset > 0 || ipv6.fraghdr.offset > 0 || ipv6.fraghdr.more == 1",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        text=True,
        capture_output=True,
        timeout=60,
    )
    require(frag.returncode == 0, f"tshark 分片过滤失败：{frag.stderr[-1200:]}")
    require(len(frag.stdout.splitlines()) == 4, f"tshark 应看到 4 个分片：{frag.stdout!r}")

    dns = subprocess.run(
        common
        + [
            "-Y",
            "dns",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "dns.qry.name",
        ],
        text=True,
        capture_output=True,
        timeout=60,
    )
    require(dns.returncode == 0, f"tshark DNS 过滤失败：{dns.stderr[-1200:]}")
    rows = [line.split("\t") for line in dns.stdout.splitlines() if line.strip()]
    require(len(rows) == 4, f"tshark 应重组出 4 条 DNS 消息，实际 {rows}")
    names = {row[1] for row in rows if len(row) > 1 and row[1]}
    require(names == {"example.com", "ipv6.example"}, f"tshark DNS 名称不符：{names}")

    bad = subprocess.run(
        common
        + [
            "-Y",
            "ip.fragment.error || ipv6.fragment.error || ipv6.fragment.overlap.conflict",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        text=True,
        capture_output=True,
        timeout=60,
    )
    require(bad.returncode == 0, f"tshark 分片错误过滤失败：{bad.stderr[-1200:]}")
    require(not bad.stdout.strip(), f"tshark 报告了分片错误：{bad.stdout!r}")


def self_test(records, stats, events, l4q4, a4, l4q6, a6):
    print("-- 反向故障注入")
    # 先证明原始数据能通过，否则下面的“改坏就报错”只是基线本来就错。
    check_valid(copy.deepcopy(records), copy.deepcopy(stats), {}, copy.deepcopy(events), {"complete": 2}, l4q4, a4, l4q6, a6)

    def must_fail(label, mutate):
        r2 = copy.deepcopy(records)
        s2 = copy.deepcopy(stats)
        e2 = copy.deepcopy(events)
        mutate(r2, s2, e2)
        try:
            check_valid(r2, s2, {}, e2, {"complete": 2}, l4q4, a4, l4q6, a6)
        except Failure:
            print(f"   已检出 ← {label}")
            return
        raise Failure(f"反向注入未被检出：{label}")

    must_fail("记录字节数 +1", lambda r, s, e: r[0]["counters"].__setitem__("bytes", r[0]["counters"]["bytes"] + 1))
    must_fail("统计 complete 改为 1", lambda r, s, e: s.__setitem__("complete", 1))
    def drop_complete(r, s, e):
        for i, ev in enumerate(e):
            if ev.get("event") == "datagram_complete":
                e.pop(i)
                return
        raise Failure("语料里没有完成事件")

    must_fail("删掉一条完成事件", drop_complete)


def run_case(path, expect, tmpdir):
    records, stderr = analyze(path)
    stats, errors = parse_analyze(stderr)
    events, event_stats = ipfrag_events(path)
    expect(records, stats, errors, events, event_stats)
    return records, stats, errors, events, event_stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", action="store_true")
    args = ap.parse_args()

    if not ANALYZE.exists():
        print(f"缺少 {ANALYZE}（先 cargo build）", file=sys.stderr)
        return 3
    if not IPFRAG.exists():
        print(f"缺少 {IPFRAG}（先 cargo build）", file=sys.stderr)
        return 3
    if args.tshark and shutil.which("tshark") is None:
        print("缺少 tshark：独立对照未执行（未核验，不计通过）", file=sys.stderr)
        return 3

    with tempfile.TemporaryDirectory(prefix="cythsec-ipfrag-") as td:
        td = Path(td)
        valid, l4q4, a4, l4q6, a6 = build_valid()
        paths = {
            "valid": td / "valid.pcap",
            "incomplete": td / "incomplete.pcap",
            "overlap": td / "overlap.pcap",
            "truncated": td / "truncated.pcap",
            "duplicate": td / "duplicate.pcap",
        }
        paths["valid"].write_bytes(valid)
        paths["incomplete"].write_bytes(build_incomplete())
        paths["overlap"].write_bytes(build_overlap())
        paths["truncated"].write_bytes(build_truncated())
        paths["duplicate"].write_bytes(build_duplicate())

        print("==> 完整 IPv4/IPv6 分片（乱序 + 扩展头）")
        recs, stats, errors, events, event_stats = run_case(
            paths["valid"],
            lambda r, s, er, ev, es: check_valid(r, s, er, ev, es, l4q4, a4, l4q6, a6),
            td,
        )
        self_test(recs, stats, events, l4q4, a4, l4q6, a6)

        print("==> 缺首片")
        run_case(paths["incomplete"], lambda r, s, er, ev, es: check_incomplete(s, er, ev), td)
        print("==> 重叠")
        run_case(paths["overlap"], lambda r, s, er, ev, es: check_overlap(s, er, ev), td)
        print("==> 抓包截断")
        run_case(paths["truncated"], lambda r, s, er, ev, es: check_truncated(s, er), td)
        print("==> 重复片")
        run_case(paths["duplicate"], lambda r, s, er, ev, es: check_duplicate(r, s), td)

        if args.tshark:
            print("==> tshark 独立重组对照")
            check_tshark(paths["valid"])

    print("B008 IP 分片重组：全部检查通过")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as e:
        print(f"检查失败：{e}", file=sys.stderr)
        sys.exit(1)
