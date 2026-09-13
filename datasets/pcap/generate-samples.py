#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generate-samples.py —— 生成 datasets/pcap/ 下的确定性 pcap 样本

为什么是「生成器」而不是直接提交二进制 blob：
    样本可复现、可审查、可随协议支持范围扩展。任何人在任何机器上运行本脚本
    都得到字节级一致的文件，便于回归比对。

产出（经典 pcap，LINKTYPE_ETHERNET=1，微秒精度，小端）：
    sample-ipv4-mixed.pcap  4 个报文：IPv4/TCP、IPv4/UDP、IPv4/ICMP、IPv4/TCP(截断捕获)
    sample-ipv6-tcp.pcap    1 个报文：IPv6/TCP

用法：
    python3 datasets/pcap/generate-samples.py [输出目录]
"""

import os
import struct
import sys

MAGIC_MICRO = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535

ETH_DST = bytes.fromhex("001122334455")
ETH_SRC = bytes.fromhex("66778899aabb")
ETH_IPV4 = b"\x08\x00"
ETH_IPV6 = b"\x86\xdd"


def cksum16(data: bytes) -> int:
    """标准 Internet 校验和（RFC 1071）。"""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth(payload: bytes, ethertype: bytes = ETH_IPV4) -> bytes:
    return ETH_DST + ETH_SRC + ethertype + payload


def ipv4(payload: bytes, proto: int, ident: int, src=b"\x0a\x00\x00\x01",
         dst=b"\x0a\x00\x00\x02", ttl: int = 64) -> bytes:
    total_len = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0x00, total_len, ident, 0x4000,
                      ttl, proto, 0) + src + dst
    hdr = hdr[:10] + struct.pack("!H", cksum16(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(payload: bytes, next_hdr: int,
         src=bytes.fromhex("20010db8000000000000000000000001"),
         dst=bytes.fromhex("20010db8000000000000000000000002")) -> bytes:
    hdr = struct.pack("!IHBB", 0x60000000, len(payload), next_hdr, 64) + src + dst
    return hdr + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int,
        payload: bytes = b"") -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags,
                      65535, 0, 0)
    return hdr + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(ident: int, seq: int, payload: bytes = b"") -> bytes:
    body = struct.pack("!HH", ident, seq) + payload
    return struct.pack("!BBH", 8, 0, cksum16(struct.pack("!BB", 8, 0) + body)) + body


def pcap(frames, linktype: int = LINKTYPE_ETHERNET) -> bytes:
    """frames: [(ts_sec, ts_usec, frame_bytes, orig_len)]"""
    out = struct.pack("<IHHiIII", MAGIC_MICRO, 2, 4, 0, 0, SNAPLEN, linktype)
    for ts_sec, ts_usec, frame, orig_len in frames:
        out += struct.pack("<IIII", ts_sec, ts_usec, len(frame), orig_len)
        out += frame
    return out


def build_ipv4_mixed():
    f1 = eth(ipv4(tcp(12345, 80, 0x11223344, 0xAABBCCDD, 0x18, b"GET / HTTP/1.1\r\n"), 6, 1))
    f2 = eth(ipv4(udp(53, 5353, b"\x00\x01query"), 17, 2))
    f3 = eth(ipv4(icmp_echo(0x0102, 7, b"abcdefgh"), 1, 3))
    # 截断捕获：wirelen=66 的帧只存 54 字节（含完整 L2+L3+L4 头，无负载）
    full = eth(ipv4(tcp(443, 51000, 1, 2, 0x10, b"x" * 12), 6, 4))
    frames = [
        (1700000000, 100000, f1, len(f1)),
        (1700000000, 200000, f2, len(f2)),
        (1700000000, 300000, f3, len(f3)),
        (1700000000, 400000, full[:54], len(full)),  # incl=54 < orig=66
    ]
    return pcap(frames), len(frames)


def build_ipv6_tcp():
    f1 = eth(ipv6(tcp(80, 40000, 0x01020304, 0x05060708, 0x02), 6), ETH_IPV6)
    return pcap([(1700000001, 500000, f1, len(f1))]), 1


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    outdir = sys.argv[1] if len(sys.argv) > 1 else here
    os.makedirs(outdir, exist_ok=True)

    for name, (data, count) in (
        ("sample-ipv4-mixed.pcap", build_ipv4_mixed()),
        ("sample-ipv6-tcp.pcap", build_ipv6_tcp()),
    ):
        path = os.path.join(outdir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"生成 {path}  ({len(data)} 字节, {count} 个报文)")


if __name__ == "__main__":
    main()
