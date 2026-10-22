#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generate-bench.py —— 生成大样本 pcap，用于量「整条离线流水线」的吞吐与并行加速比

与 generate-samples.py 的分工：
    generate-samples.py 产出的是**小而有手写期望值**的回归样本（几十个包，逐字段核对）；
    本脚本产出的是**大而无期望值**的负载样本（十万级包），只用来量吞吐。
    两者刻意分开：把回归样本撑到几十万包，会让每次门禁都慢得没人愿意跑。

确定性：同样的参数在任何机器上都得到字节级一致的文件（内容由固定算式给出，
不用 random，避免 Python 版本差异）。生成的 pcap 是 gitignore 的产物，不入库。

两种负载形态（`--profile`）：
  * `homogeneous`（默认，逐字节维持历史行为）——就是下面写的"每 10 条流 1 条 DNS、
    载荷 64/128/256/512 轮转、目的端口恒定 443"。它压 gzip 压得极好
    （21.0 B/记录 vs 真实向量 79.4 B），因此**只能用于吞吐/并行度**。
  * `diverse` —— 目的端口/协议/TTL/包长/会话时长/应用识别结果都放开，
    用来量「按列编解码器在字段多样时的真实收益」（见 docs/planning/measurements/
    columnar-*.json）。**它是合成语料，多样性由下面的池子给，不代表任何现场**；
    现场必须用自己的流量重标定，这一点写进了产物里。

负载形态（homogeneous，有意做成"真实混合"而不是清一色最大包）：
    * 每 10 条流有 1 条 UDP/DNS（3 个包），其余是 TCP（握手 + 双向数据 + FIN）
    * 数据包载荷 64/128/256/512 字节轮转，方向交替（方向切换要被统计）
    * 流键的**变化部分在前部**（源 IP、源端口），尾部（目的端口 443、协议号）恒定
      —— 这正是真实流量的形态，也是分片哈希最容易踩坑的形态（见 pipeline.rs 的 mix64）

用法：
    python3 datasets/pcap/generate-bench.py <输出.pcap> [流数] [每条流数据包数] [--profile NAME]
    缺省：20000 条流 / 每条流 50 个包 / --profile homogeneous → 约 88.8 万个包、约 250 MB
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



# ---------------------------------------------------------------------------
# diverse 档：字段多样性由这些池子供
#
# 为什么要单独一档：按列编解码器（Delta / ZSTD / LowCardinality）省的是
# 「同一列里相邻值的重复度」。homogeneous 档里目的端口恒为 443、载荷是等字节填充、
# 会话时长几乎一样 —— 列式压到 5.11 B/记录，那个数**主要是这套重复结构的产物**，
# 不是列式在真实流量上的收益。所以这一档刻意把每一个列的取值都打散，
# 让「较差端」有一个可比的下限。它仍然是合成语料：现场必须自己重标定。
# ---------------------------------------------------------------------------

def mix64(x: int) -> int:
    """splitmix64：确定性、逐位可复现，且不依赖 Python 的 random 实现。"""
    x = (x + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = x
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return z ^ (z >> 31)


DPORTS = (53, 80, 123, 443, 465, 993, 1883, 3306, 3389, 5060, 5353, 5672,
          6379, 8080, 8443, 9200, 11211, 15672, 27017, 31337, 44444, 49152, 50000, 60001)
# 目的地址池：前缀刻意打散（私网 + 公网段混排），不要让 src_ip/dst_ip 两列
# 退化成"只有最后一个字节在变"——那会让 Delta(1) 看起来比实际更省。
DST_POOLS = (b"\x08\x08", b"\x01\x01", b"\x3b\x77", b"\x63\x17", b"\x74\x00",
             b"\x9e\x1c", b"\xa5\x2f", b"\xc3\x50", b"\xe0\x64", b"\xf4\x8a")
LABELS = "abcdefghijklmnopqrstuvwxyz"


def _host_name(f: int) -> str:
    """从流号确定性生成一个"看起来像真的"的域名（三段、长度不一）。"""
    m = mix64(f * 7 + 3)
    l1 = 3 + (m & 7)
    l2 = 2 + ((m >> 8) & 3)
    p1 = "".join(LABELS[(m >> (4 + 3 * i)) % 26] for i in range(l1))
    p2 = "".join(LABELS[(m >> (30 + 3 * i)) % 26] for i in range(l2))
    tld = ("com", "net", "org", "cn", "io", "dev", "top")[(m >> 56) % 7]
    return f"{p1}{p2}-{f % 97}.{tld}"


def _client_hello(host: str, f: int) -> bytes:
    """能被判成 TLS 的 ClientHello，SNI 每流不同（app_server_name 这一列要有料）。"""
    name = host.encode()
    sni = struct.pack("!HHHH", 0x0000, len(name) + 5, len(name) + 3, len(name)) + name
    ext = struct.pack("!HH", 0x000d, 2) + struct.pack("!BB", 1, 0x01)   # signature_algorithms
    ext += struct.pack("!HH", 0x0000, len(sni)) + sni
    ciphers = [0x1301, 0xC02B, 0x009C, 0x0035][(mix64(f) & 3)]
    body = struct.pack("!H", 0x0303) + bytes([(mix64(f + i) >> (i % 8)) & 0xFF for i in range(32)])
    body += b"\x00" + struct.pack("!H", 2) + struct.pack("!H", ciphers) + b"\x01\x00"
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _http_get(host: str, f: int) -> bytes:
    path = "/".join(("api", f"v{1 + (f % 4)}", f"r{f % 13}", "list"))
    ua = ("curl/8.6.0", "python-requests/2.32", "Mozilla/5.0 (X11; Linux x86_64)",
          "okhttp/4.12.0")[mix64(f + 11) % 4]
    return (f"GET /{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept: */*\r\nX-Req-Id: {f:x}\r\n\r\n").encode()


def _dns_query(host: str, txid: int) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def _payload_bytes(seed: int, n: int) -> bytes:
    """逐字节伪随机：载荷不许是等字节填充，否则列式与 gzip 都能把它压成免费。"""
    out = bytearray(n)
    for i in range(n):
        if i % 8 == 0:
            v = mix64(seed + (i >> 3))
        out[i] = (v >> ((i % 8) * 8)) & 0xFF
    return bytes(out)


def build_flow_diverse(f: int) -> list:
    """一条"字段各不相同"的流：返回 [(包间隔 µs, 帧), ...]。"""
    m = mix64(f * 31 + 5)
    src = bytes([10, (m >> 8) & 0xFF, (m >> 16) & 0xFF, (m >> 24) & 0xFF])
    pool = DST_POOLS[m % len(DST_POOLS)]
    dst = pool + bytes([(m >> 36) & 0xFF, (m >> 44) & 0xFF])
    sport = 1024 + (m >> 5) % 63000
    dport = DPORTS[(m >> 13) % len(DPORTS)]
    ttl_c = 32 + (m >> 21) % 96
    ttl_s = 32 + (m >> 25) % 96
    proto_pick = m % 100
    ident = m & 0xFFFF

    if proto_pick < 2:                                     # ICMP：没有端口，端口列恒 0
        ic = struct.pack("!BBHHH", 8, 0, 0, ident & 0xFFFF, f & 0xFFFF) + _payload_bytes(f, 32)
        rc = struct.pack("!BBHHH", 0, 0, 0, ident & 0xFFFF, f & 0xFFFF) + _payload_bytes(f, 32)
        return [(1, eth(ipv4(ic, 1, src, dst, ident))),
                (5000 + (m >> 33) % 40000, eth(ipv4(rc, 1, dst, src, ident + 1)))]

    if proto_pick < 22 or dport in (53, 123, 5353):        # UDP/DNS
        q = _dns_query(_host_name(f), ident) if dport == 53 else _payload_bytes(f + 1, 76)
        frames = [(0, eth(ipv4(udp(sport, dport, q), 17, src, dst, ident))),
                  (3000 + (m >> 29) % 60000, eth(ipv4(udp(dport, sport, _payload_bytes(f + 2, len(q))), 17, dst, src, ident + 1)))]
        if m % 5 == 0:                                     # 重传：让 counters 那一组列有料
            frames.append((120, eth(ipv4(udp(sport, dport, q), 17, src, dst, ident))))
        return frames

    # TCP：握手 + 双向数据 + 乱序/重传 + 末态（FIN 或 RST，各占一部分）
    hs = _client_hello(_host_name(f), f) if dport in (443, 465, 993, 8443, 5672) else (
        _http_get(_host_name(f), f) if dport in (80, 8080, 3128) else _payload_bytes(f + 3, 200))
    sizes = (64, 128, 256, 512, 1024, 1200, 1448)
    n_data = 2 + (m >> 17) % 30
    if m % 40 == 0:
        n_data = 80 + (m >> 23) % 320                       # 重尾：少数长流
    step = 1 + (m >> 11) % 900                              # 会话时长这一列必须各不相同
    seq_c, seq_s = 1000, 2000
    frames = [(0, eth(ipv4(tcp(sport, dport, seq_c, 0, 0x02, b""), 6, src, dst, ident))),
              (step, eth(ipv4(tcp(dport, sport, seq_s, seq_c + 1, 0x12, b""), 6, dst, src, ident + 1)))]
    seq_c += 1
    gap = step
    for k in range(n_data):
        size = sizes[(mix64(f * 97 + k) >> 7) % len(sizes)]
        body = hs if k == 0 else _payload_bytes(f * 131 + k, size)
        if k == 0:
            seq_c += len(hs)
            frames.append((gap, eth(ipv4(tcp(sport, dport, seq_c - len(hs), seq_s, 0x18, hs), 6, src, dst, ident))))
            continue
        flags = 0x18
        if m % 17 == k % 17:                                # 服务端也发数据（方向切换）
            body = _payload_bytes(f * 271 + k, size)
            seq_s += size
            frames.append((gap, eth(ipv4(tcp(dport, sport, seq_s - size, seq_c, flags, b""), 6, dst, src, ident + 1 + k))))
        else:
            seq_c += size
            frames.append((gap, eth(ipv4(tcp(sport, dport, seq_c - size, seq_s, flags, b""), 6, src, dst, ident + 1 + k))))
        if k == 3 and m % 7 == 0:                           # 乱序：先发第 5 段再补第 4 段
            frames.append((2, eth(ipv4(tcp(sport, dport, seq_c + 10, seq_s, flags, b""), 6, src, dst, ident + 40))))
        if k == 5 and m % 9 == 0:                           # 重传：同序号重发
            frames.append((40, eth(ipv4(tcp(sport, dport, seq_c - size, seq_s, flags, b""), 6, src, dst, ident + 50))))
        gap = 1 + (mix64(f + k) >> 9) % max(1, step * 2)
    if m % 6 == 5:
        frames.append((gap, eth(ipv4(tcp(sport, dport, seq_c, seq_s, 0x04, b""), 6, src, dst, ident + 90))))
    else:
        frames.append((gap, eth(ipv4(tcp(sport, dport, seq_c, seq_s, 0x11, b""), 6, src, dst, ident + 90))))
        frames.append((gap, eth(ipv4(tcp(dport, sport, seq_s, seq_c + 1, 0x11, b""), 6, dst, src, ident + 91))))
    return frames


def main() -> int:
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    profile = "homogeneous"
    for i, a in enumerate(sys.argv[1:]):
        if a == "--profile":
            profile = sys.argv[1 + i + 1]
        elif a.startswith("--profile="):
            profile = a.split("=", 1)[1]
    if profile not in ("homogeneous", "diverse"):
        print(f"未知 --profile：{profile}（可选 homogeneous|diverse）", file=sys.stderr)
        return 2
    out_path = argv[0] if len(argv) > 0 else "build/bench-pipeline/bench.pcap"
    flows = int(argv[1]) if len(argv) > 1 else 20000
    per = int(argv[2]) if len(argv) > 2 else 50
    parent = os.path.dirname(os.path.abspath(out_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    packets = 0
    ts, usec = 1_700_000_000, 0
    with open(out_path, "wb") as out:
        out.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET))
        for f in range(flows):
            if profile == "diverse":
                items = build_flow_diverse(f)
            else:
                items = [(3, fr) for fr in build_flow(f, per)]   # 历史行为：逐字节不变
            for dt, frame in items:
                usec += dt
                while usec >= 1_000_000:
                    usec -= 1_000_000
                    ts += 1
                out.write(struct.pack("<IIII", ts, usec, len(frame), len(frame)))
                out.write(frame)
                packets += 1
    size = os.path.getsize(out_path)
    print(f"写出 {packets} 个包 / {size / 1e6:.1f} MB（profile={profile}）-> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
