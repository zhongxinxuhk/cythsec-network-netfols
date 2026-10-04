#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generate-bench.py —— 生成大样本 pcap，用于量「整条离线流水线」的吞吐与并行加速比

与 generate-samples.py 的分工：
    generate-samples.py 产出的是**小而有手写期望值**的回归样本（几十个包，逐字段核对）；
    本脚本产出的是**大而无期望值**的负载样本（十万级包），只用来量吞吐。
    两者刻意分开：把回归样本撑到几十万包，会让每次门禁都慢得没人愿意跑。

确定性：同样的参数在任何机器上都得到字节级一致的文件（内容由固定算式给出，
不用 random，避免 Python 版本差异）。生成的 pcap 是 gitignore 的产物，不入库。

负载形态（有意做成"真实混合"而不是清一色最大包）：
    * 每 10 条流有 1 条 UDP/DNS（3 个包），其余是 TCP（握手 + 双向数据 + FIN）
    * 数据包载荷 64/128/256/512 字节轮转，方向交替（方向切换要被统计）
    * 流键的**变化部分在前部**（源 IP、源端口），尾部（目的端口 443、协议号）恒定
      —— 这正是真实流量的形态，也是分片哈希最容易踩坑的形态（见 pipeline.rs 的 mix64）

用法：
    python3 datasets/pcap/generate-bench.py <输出.pcap> [流数] [每条流数据包数]
    缺省：20000 条流 / 每条流 50 个包 → 约 88.8 万个包、约 250 MB
"""

import os
import struct
import sys

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535
PAYLOAD_SIZES = (64, 128, 256, 512)
# 一条 DNS 查询（www.example.com A）。内容固定，只为让 DPI/载荷解析有活干。
DNS_QUERY = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
)


def ipv4(l4: bytes, proto: int, src: bytes, dst: bytes, ident: int) -> bytes:
    total = 20 + len(l4)
    return struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, ident & 0xFFFF, 0x4000, 64, proto, 0x0000, src, dst
    ) + l4


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    return struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 0xFFFF, 0, 0
    ) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + payload


def build_flow(f: int, per: int) -> list:
    """一条流的全部帧。`per` 是每条流的总包数（TCP 流会按握手/数据/FIN 分配）。"""
    src = bytes([10, (f >> 16) & 0xFF, (f >> 8) & 0xFF, f & 0xFF])
    dst = bytes([10, 128, 0, 1])
    sport = 1024 + (f % 60000)
    if f % 10 == 9:
        return [
            eth(ipv4(udp(sport, 53, DNS_QUERY), 17, src, dst, f)),
            eth(ipv4(udp(53, sport, DNS_QUERY), 17, dst, src, f)),
            eth(ipv4(udp(sport, 53, DNS_QUERY[:20]), 17, src, dst, f)),
        ]
    frames = [
        eth(ipv4(tcp(sport, 443, 1000, 0, 0x02, b""), 6, src, dst, f)),
        eth(ipv4(tcp(443, sport, 2000, 1001, 0x12, b""), 6, dst, src, f)),
    ]
    for k in range(max(0, per - 3)):
        size = PAYLOAD_SIZES[k % len(PAYLOAD_SIZES)]
        payload = bytes([k & 0xFF]) * size
        if k % 2 == 0:
            frames.append(
                eth(ipv4(tcp(sport, 443, 1000 + k, 2000 + k, 0x18, payload), 6, src, dst, f))
            )
        else:
            body = b"HTTP/1.1 200 OK\r\n" + payload
            frames.append(eth(ipv4(tcp(443, sport, 2000 + k, 1000 + k, 0x18, body), 6, dst, src, f)))
    frames.append(eth(ipv4(tcp(sport, 443, 9999, 9999, 0x11, b""), 6, src, dst, f)))
    return frames


def main() -> int:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "build/bench-pipeline/bench.pcap"
    flows = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
    per = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    parent = os.path.dirname(os.path.abspath(out_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    packets = 0
    ts, usec = 1_700_000_000, 0
    with open(out_path, "wb") as out:
        out.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET))
        for f in range(flows):
            for frame in build_flow(f, per):
                usec += 3
                if usec >= 1_000_000:
                    usec -= 1_000_000
                    ts += 1
                out.write(struct.pack("<IIII", ts, usec, len(frame), len(frame)))
                out.write(frame)
                packets += 1
    size = os.path.getsize(out_path)
    print(f"写出 {packets} 个包 / {size / 1e6:.1f} MB -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
