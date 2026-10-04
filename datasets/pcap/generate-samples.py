#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generate-samples.py —— 生成 datasets/pcap/ 下的确定性 pcap 样本

为什么是「生成器」而不是直接提交二进制 blob：
    样本可复现、可审查、可随协议支持范围扩展。任何人在任何机器上运行本脚本
    都得到字节级一致的文件，便于回归比对。

产出（经典 pcap，LINKTYPE_ETHERNET=1，微秒精度，小端）：
    sample-ipv4-mixed.pcap    4 个报文：IPv4/TCP、IPv4/UDP、IPv4/ICMP、IPv4/TCP(截断捕获)
    sample-ipv6-tcp.pcap      1 个报文：IPv6/TCP
    sample-session-tcp.pcap  18 个报文 / 5 条会话 + 1 个非首片分片（见下表）

sample-session-tcp.pcap 的**手写期望值**（这条样本是流/会话/状态机的回归载体，
期望值由人按协议语义写出，不是把实现输出抄回来）：

  会话                                    报文  末态        说明
  S1 10.0.0.1:40000 -> 10.0.0.2:80  TCP     9   time_wait  完整握手+双向数据+四次挥手
  S2 10.0.0.3:55000 -> 10.0.0.2:81  TCP     2   reset      SYN 后收到 RST+ACK（连接被拒）
  S3 10.0.0.4:60000 -> 10.0.0.2:443 TCP     2   established 中途接入（无 SYN，双向数据）
  S4 10.0.0.1:53000 <-> 10.0.0.2:53 UDP     2   -           DNS 查询+应答（应识别为 dns）
  S5 10.0.0.1 <-> 10.0.0.2          ICMP    2   -           回显请求+应答（无端口协议）
  合计                                     17 条参与统计 + 1 条非首片分片（解码应显式报错）

  按 IP 载荷（含四层头）口径的字节数：
  S1 = 7*20 + (20+120) + (20+500) = 800（9 个包里 7 个是纯头）；S2 = 2*20 = 40；S3 = 2*20 + 200 + 300 = 540；
  S4 = (8+29) + (8+45) = 90（应答带一条 A 记录，比查询长）；S5 = 2*(8+8) = 32。
  方向切换次数：S1 = 6、S4 = 1、S5 = 1，其余为 0。

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
         dst=b"\x0a\x00\x00\x02", ttl: int = 64,
         frag: int = 0x4000) -> bytes:
    """frag 是「3 位标志 + 13 位分片偏移」的合成字段；默认 0x4000 = DF（不分片）。"""
    total_len = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0x00, total_len, ident, frag,
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


# ---------------------------------------------------------------------------
# sample-session-tcp.pcap —— 会话/状态机回归样本（期望值见文件头表格）
# ---------------------------------------------------------------------------

TCP_SYN = 0x02
TCP_SYN_ACK = 0x12
TCP_ACK = 0x10
TCP_PSH_ACK = 0x18
TCP_FIN_ACK = 0x11
TCP_RST_ACK = 0x14

IP_A = b"\x0a\x00\x00\x01"
IP_B = b"\x0a\x00\x00\x02"


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def dns_query(txid: int, name: str, qtype: int = 1) -> bytes:
    """标准查询：RD 置位，QDCOUNT=1。"""
    return (struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            + dns_name(name) + struct.pack("!HH", qtype, 1))


def dns_response(txid: int, name: str, addr: bytes, qtype: int = 1) -> bytes:
    """标准应答：QR+RD+RA 置位，ANCOUNT=1，应答名用 0xC00C 指回问题区。"""
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(addr)) + addr
    return (struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
            + question + answer)


def build_session_tcp():
    frames = []

    def add(frame: bytes) -> None:
        # 秒固定、微秒递增：时间间隔 1 ms，IAT 与速率特征因此可手算复核。
        usec = 1000 * (len(frames) + 1)
        frames.append((1700000010, usec, frame, len(frame)))

    # ---- S1：完整握手 + 双向数据 + 四次挥手（9 包，末态 time_wait）----
    s1_fwd = {"sport": 40000, "dport": 80}
    s1_rev = {"sport": 80, "dport": 40000}
    add(eth(ipv4(tcp(s1_fwd["sport"], s1_fwd["dport"], 1000, 0, TCP_SYN), 6, 11)))
    add(eth(ipv4(tcp(s1_rev["sport"], s1_rev["dport"], 5000, 1001, TCP_SYN_ACK), 6, 12,
                 src=IP_B, dst=IP_A)))
    add(eth(ipv4(tcp(s1_fwd["sport"], s1_fwd["dport"], 1001, 5001, TCP_ACK), 6, 13)))
    add(eth(ipv4(tcp(s1_fwd["sport"], s1_fwd["dport"], 1001, 5001, TCP_PSH_ACK,
                      b"Q" * 120), 6, 14)))
    add(eth(ipv4(tcp(s1_rev["sport"], s1_rev["dport"], 5001, 1121, TCP_PSH_ACK,
                      b"R" * 500), 6, 15, src=IP_B, dst=IP_A)))
    add(eth(ipv4(tcp(s1_fwd["sport"], s1_fwd["dport"], 1121, 5501, TCP_FIN_ACK), 6, 16)))
    add(eth(ipv4(tcp(s1_rev["sport"], s1_rev["dport"], 5501, 1122, TCP_ACK), 6, 17,
                 src=IP_B, dst=IP_A)))
    add(eth(ipv4(tcp(s1_rev["sport"], s1_rev["dport"], 5501, 1122, TCP_FIN_ACK), 6, 18,
                 src=IP_B, dst=IP_A)))
    add(eth(ipv4(tcp(s1_fwd["sport"], s1_fwd["dport"], 1122, 5502, TCP_ACK), 6, 19)))

    # ---- S2：连接被拒（SYN -> RST+ACK，2 包，末态 reset）----
    add(eth(ipv4(tcp(55000, 81, 2000, 0, TCP_SYN), 6, 20,
                 src=b"\x0a\x00\x00\x03")))
    add(eth(ipv4(tcp(81, 55000, 9000, 2001, TCP_RST_ACK), 6, 21,
                 src=IP_B, dst=b"\x0a\x00\x00\x03")))

    # ---- S3：中途接入（无 SYN 的双向数据，2 包，末态 established）----
    add(eth(ipv4(tcp(60000, 443, 3000, 7000, TCP_PSH_ACK, b"A" * 200), 6, 22,
                 src=b"\x0a\x00\x00\x04")))
    add(eth(ipv4(tcp(443, 60000, 7000, 3200, TCP_PSH_ACK, b"B" * 300), 6, 23,
                 src=IP_B, dst=b"\x0a\x00\x00\x04")))

    # ---- S4：DNS 查询 + 应答（2 包，应识别为 dns）----
    query = dns_query(0x1234, "example.com")
    answer = dns_response(0x1234, "example.com", bytes([93, 184, 216, 34]))
    add(eth(ipv4(udp(53000, 53, query), 17, 24)))
    add(eth(ipv4(udp(53, 53000, answer), 17, 25, src=IP_B, dst=IP_A)))

    # ---- S5：ICMP 回显请求 + 应答（2 包，无端口协议）----
    add(eth(ipv4(icmp_echo(0x0102, 1, b"abcdefgh"), 1, 26)))
    add(eth(ipv4(icmp_echo(0x0102, 1, b"abcdefgh"), 1, 27, src=IP_B, dst=IP_A)))
    # 回显应答的类型是 0：把请求帧的类型字节改掉，而不是另写一个构造函数
    reply = bytearray(frames[-1][2])
    reply[14 + 20] = 0
    full = bytes(reply)
    reply_hdr = struct.pack("!BBH", 0, 0, cksum16(bytes([0, 0]) + full[14 + 20 + 4:]))
    reply[14 + 20:14 + 20 + 4] = reply_hdr
    frames[-1] = (frames[-1][0], frames[-1][1], bytes(reply), len(reply))

    # ---- 非首片分片：解码必须**显式报错**并跳过，不得塌缩成一条假流 ----
    add(eth(ipv4(b"fragment-tail", 6, 28, frag=0x0001)))

    return pcap(frames), len(frames)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    outdir = sys.argv[1] if len(sys.argv) > 1 else here
    os.makedirs(outdir, exist_ok=True)

    for name, (data, count) in (
        ("sample-ipv4-mixed.pcap", build_ipv4_mixed()),
        ("sample-ipv6-tcp.pcap", build_ipv6_tcp()),
        ("sample-session-tcp.pcap", build_session_tcp()),
    ):
        path = os.path.join(outdir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"生成 {path}  ({len(data)} 字节, {count} 个报文)")


if __name__ == "__main__":
    main()
