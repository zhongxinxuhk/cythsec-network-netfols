#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generate-reassembly-samples.py —— 生成 datasets/reassembly/ 下的重组测试向量

为什么是「生成器」而不是直接提交二进制：
    样本可复现、可审查、可随场景扩展。任何人在任何机器上运行本脚本都得到
    字节级一致的文件，便于回归比对。

产出：
    streams/<name>.bin    这条流「完整且正确」的字节流（重组应当还原的东西）
    pcaps/<name>.pcap     该向量在线路上的样子（SYN → 数据段（按到达顺序）→ FIN）
    expected.json         每条向量的到达顺序与**显式写死**的期望值

关于期望值为什么是手写而不是「跑一遍重组器再记下来」：
    那等于让被测实现给自己的答案打分 —— 两边一起错的时候看不出来。
    这里每个向量的期望值都按「我知道我放了什么」逐条写死，
    再由 tshark（scripts/verify/check-reassembly-vectors.sh）作为**第三方实现**
    独立复核。三方里任意一方出错都会让至少一处对不上。

用法：
    python3 datasets/reassembly/generate-reassembly-samples.py [输出目录]
"""

import hashlib
import json
import os
import struct
import sys

# ---------------------------------------------------------------- pcap 构造

MAGIC_MICRO = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535

ETH_DST = bytes.fromhex("001122334455")
ETH_SRC = bytes.fromhex("66778899aabb")
ETH_IPV4 = b"\x08\x00"

CLIENT_IP = bytes([10, 0, 0, 1])
SERVER_IP = bytes([10, 0, 0, 2])
SPORT = 12345
DPORT = 443

IPPROTO_TCP = 6

FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_ACK = 0x10
FLAG_PSH = 0x08


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


def tcp_segment(seq: int, ack: int, flags: int, payload: bytes,
                src=CLIENT_IP, dst=SERVER_IP, sport=SPORT, dport=DPORT) -> bytes:
    """带正确校验和的 TCP 段。

    校验和必须算对：tshark 默认校验 TCP 校验和，算错的话它会在输出里插入
    "校验和不正确" 的告警行，把 follow stream 的输出搅乱，让自动化比对失效。
    """
    tcp_len = 20 + len(payload)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      0x50, flags, 65535, 0, 0)
    pseudo = src + dst + bytes([0, IPPROTO_TCP]) + struct.pack("!H", tcp_len)
    csum = cksum16(pseudo + hdr + payload)
    return hdr[:16] + struct.pack("!H", csum) + hdr[18:] + payload


def frame(payload: bytes, ident: int, src=CLIENT_IP, dst=SERVER_IP) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0x00, total, ident, 0x4000, 64,
                      IPPROTO_TCP, 0) + src + dst
    hdr = hdr[:10] + struct.pack("!H", cksum16(hdr)) + hdr[12:]
    return ETH_DST + ETH_SRC + ETH_IPV4 + hdr + payload


def pcap_bytes(frames) -> bytes:
    """frames: [(ts_sec, ts_usec, frame_bytes)]"""
    out = struct.pack("<IHHiIII", MAGIC_MICRO, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)
    for i, (ts_sec, ts_usec, f) in enumerate(frames):
        out += struct.pack("<IIII", ts_sec, ts_usec, len(f), len(f))
        out += f
    return out


def build_pcap(isn: int, segments, stream_len: int) -> bytes:
    """把一个向量的到达顺序变成 pcap。

    报文顺序固定为：SYN → SYN/ACK → 数据段（按向量的到达顺序）→ 需要时的 FIN。
    服务端除 SYN/ACK 外不发任何数据，这样 tshark 的 follow stream 只反映
    客户端方向 —— 否则两个方向的字节会被拼在同一段输出里，无从比对。
    """
    base_ts = 1700000000
    frames = []
    ident = 0

    def add(ts_off, seg):
        nonlocal ident
        ident += 1
        frames.append((base_ts, ts_off, frame(seg, ident)))

    add(1000, tcp_segment(isn, 0, FLAG_SYN, b""))
    add(2000, tcp_segment(0x9000_0001, isn + 1, FLAG_SYN | FLAG_ACK, b"",
                          src=SERVER_IP, dst=CLIENT_IP, sport=DPORT, dport=SPORT))

    ts = 10000
    for seg in segments:
        seq = (isn + 1 + seg["off"]) & 0xFFFFFFFF
        ack = (0x9000_0001 + 1) & 0xFFFFFFFF
        flags = FLAG_ACK | FLAG_PSH
        if seg["fin"]:
            flags |= FLAG_FIN
        add(ts, tcp_segment(seq, ack, flags, seg_bytes(seg)))
        ts += 10000

    return pcap_bytes(frames)


def seg_bytes(seg) -> bytes:
    """段的实际载荷：`data` 是显式覆盖（用于构造重叠冲突），否则取自流。"""
    if seg.get("data_hex") is not None:
        return bytes.fromhex(seg["data_hex"])
    return seg["stream"][seg["off"]:seg["off"] + seg["len"]]


# ---------------------------------------------------------------- 向量定义

def seg(off, length, fin=False, data=None):
    """一个数据段。`off` 是相对数据起点（ISN+1）的字节偏移。"""
    return {"off": off, "len": length, "fin": fin, "data_hex": data.hex() if data else None}


def wrap32(v: int) -> int:
    return v & 0xFFFFFFFF


def load_tls_client_hello():
    """取 DPI 向量里那条真实的 ClientHello 作为「被切开的首包」用例。

    用它而不是手工拼一段伪 TLS，是因为这条样本已经被 tshark 独立核验过
    （见 datasets/dpi/expected.json）：把它切开再让两边重组，
    校验的是「重组之后 DPI 还能不能认出它」这个真正的目标。
    """
    here = os.path.dirname(os.path.abspath(__file__))
    payload = open(os.path.join(here, "..", "dpi", "payloads", "tls-basic.bin"), "rb").read()
    exp = json.load(open(os.path.join(here, "..", "dpi", "expected.json"), encoding="utf-8"))
    entry = next(e for e in exp["tls"] if e["name"] == "tls-basic")
    return payload, entry


def vectors():
    tls_payload, tls_entry = load_tls_client_hello()

    v = []

    # 1) 顺序到达：基线。任何回归都应该先在这里暴露。
    s = b"A" * 10 + b"B" * 10 + b"C" * 10
    v.append(dict(
        name="in-order",
        isn=1000,
        stream=s,
        segments=[seg(0, 10), seg(10, 10), seg(20, 10), seg(30, 0, fin=True)],
        expect=dict(contiguous_len=30, holes=0, memory_drops=0, conflict_bytes=0,
                    ooo_segments=0, finished=True, prefix_len=30),
        note="顺序到达的基线用例。",
    ))

    # 2) 完全逆序
    v.append(dict(
        name="reversed",
        isn=1000,
        stream=s,
        segments=[seg(20, 10), seg(10, 10), seg(0, 10), seg(30, 0, fin=True)],
        expect=dict(contiguous_len=30, holes=0, memory_drops=0, conflict_bytes=0,
                    ooo_segments=2, finished=True, prefix_len=30),
        note="三段完全逆序；前两段到达时都判为乱序。",
    ))

    # 3) 交错到达（2-4-1-3）
    s4 = b"A" * 10 + b"B" * 10 + b"C" * 10 + b"D" * 10
    v.append(dict(
        name="interleaved",
        isn=2000,
        stream=s4,
        segments=[seg(10, 10), seg(30, 10), seg(0, 10), seg(20, 10), seg(40, 0, fin=True)],
        expect=dict(contiguous_len=40, holes=0, memory_drops=0, conflict_bytes=0,
                    ooo_segments=2, finished=True, prefix_len=40),
        note="块序 2-4-1-3。第 2、4 块到达时前面还没数据 → 乱序（2 次）；"
             "第 1 块到达时顺带把已缓存的第 2 块接上，前缀直接推进到 20；"
             "第 3 块到达时正好接在 20 上 → 顺序到达。",
    ))

    # 4) 重叠但内容一致（真正的重传）：两种仲裁策略结果相同，因此可三方核验
    s30 = b"X" * 30
    v.append(dict(
        name="overlap-same",
        isn=3000,
        stream=s30,
        segments=[seg(0, 20), seg(10, 20), seg(30, 0, fin=True)],
        expect=dict(contiguous_len=30, holes=0, memory_drops=0, conflict_bytes=0,
                    ooo_segments=0, finished=True, prefix_len=30),
        note="重叠 10 字节但内容一致：是重传而非冲突，冲突计数必须为 0。",
    ))

    # 5) 重叠且内容不同：这是「重传攻击」的形状，仲裁策略决定结果。
    #    tshark 的重叠仲裁与本项目不同（且不可配置），故本条不做三方核验。
    s30y = b"Y" * 30
    v.append(dict(
        name="overlap-conflict",
        isn=3000,
        stream=s30y,
        segments=[seg(0, 20),
                  seg(10, 20, data=b"Z" * 10 + s30y[20:30]),
                  seg(30, 0, fin=True)],
        expect=dict(contiguous_len=30, holes=0, memory_drops=0, conflict_bytes=10,
                    ooo_segments=0, finished=True, prefix_len=30),
        tshark_verified=False,
        tshark_note="重叠区内容不同：还原结果取决于重叠仲裁策略（KeepOld/KeepNew）。"
                    "tshark 的策略与本实现不同且不可配置，无法作为独立参照；"
                    "本条只由生成器写死的期望值与 Rust 实现互证。",
        note="重叠 10 字节且内容不同 → 冲突计数 10；流内容仍以先到者为准。",
    ))

    # 6) 整段重复投递
    s20 = b"D" * 20
    v.append(dict(
        name="dup-retransmit",
        isn=4000,
        stream=s20,
        segments=[seg(0, 20), seg(0, 20), seg(20, 0, fin=True)],
        expect=dict(contiguous_len=20, holes=0, memory_drops=0, conflict_bytes=0,
                    ooo_segments=0, finished=True, prefix_len=20),
        note="整段重复投递：净新增字节为 0，且不得计入冲突。",
    ))

    # 7) 序号跨 0 回绕
    s32 = b"W" * 16 + b"V" * 16
    v.append(dict(
        name="wrap-around",
        isn=wrap32(0xFFFF_FFFF - 15),  # ISN+1 = 0xFFFF_FFF0，数据尾端跨过 0
        stream=s32,
        segments=[seg(16, 16), seg(0, 16), seg(32, 0, fin=True)],
        expect=dict(contiguous_len=32, holes=0, memory_drops=0, conflict_bytes=0,
                    ooo_segments=1, finished=True, prefix_len=32),
        note="ISN 接近 2^32：数据序号绕回 0。用裸整数比较会把它判成全部重传。",
    ))

    # 8) 被 TCP 切开的首包：本模块存在的理由
    v.append(dict(
        name="split-clienthello",
        isn=5000,
        stream=tls_payload,
        segments=[seg(0, 40), seg(40, len(tls_payload) - 40),
                  seg(len(tls_payload), 0, fin=True)],
        expect=dict(contiguous_len=len(tls_payload), holes=0, memory_drops=0,
                    conflict_bytes=0, ooo_segments=0, finished=True,
                    prefix_len=len(tls_payload)),
        tshark_mode="ja3",
        tshark_expect=dict(ja3=tls_entry["ja3"], sni=tls_entry["sni"]),
        dpi=dict(after_first="need_more", after_all="identified",
                 sni=tls_entry["sni"], ja3=tls_entry["ja3"]),
        note="真实 ClientHello 被切成 40 + 103 两段。"
             "只看第一段时 DPI 只能判 need_more；重组后必须判 identified。"
             "JA3 期望值直接取自 datasets/dpi/expected.json（已由 tshark 核验），"
             "因此这条同时校验了「重组正确」与「DPI 与重组衔接正确」。",
    ))

    # 9) 内存上限降级：乱序缓冲被打满后，仍能交付开头前缀
    s50 = b"M" * 10 + b"N" * 10 + b"O" * 10 + b"P" * 10 + b"Q" * 10
    v.append(dict(
        name="memory-cap",
        isn=6000,
        stream=s50,
        config=dict(max_buffered=20),
        segments=[seg(0, 10), seg(30, 10), seg(20, 10), seg(10, 10), seg(50, 0, fin=True)],
        expect=dict(contiguous_len=20, holes=1, memory_drops=1, conflict_bytes=0,
                    ooo_segments=1, finished=False, prefix_len=20),
        tshark_verified=False,
        tshark_note="tshark 没有内存上限，会把被本实现丢弃的那个段也算进重组结果，"
                    "两边期望值必然不同；本条只由生成器写死的期望值与 Rust 实现互证。",
        note="乱序缓冲上限 20：第 3 段到达时缓冲已满且无法推进前缀 → 丢弃。"
             "降级后仍然交付开头 20 字节，且残留一个空洞。",
    ))

    # 10) FIN 与载荷同段
    s15 = b"F" * 15
    v.append(dict(
        name="fin-with-payload",
        isn=7000,
        stream=s15,
        segments=[seg(0, 10), seg(10, 5, fin=True)],
        expect=dict(contiguous_len=15, holes=0, memory_drops=0, conflict_bytes=0,
                    ooo_segments=0, finished=True, prefix_len=15),
        note="FIN 与最后 5 字节载荷同段：FIN 序号 = 载荷之后，不是载荷起点。",
    ))

    return v


# ---------------------------------------------------------------- 输出

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    outdir = sys.argv[1] if len(sys.argv) > 1 else here
    for sub in ("streams", "pcaps"):
        os.makedirs(os.path.join(outdir, sub), exist_ok=True)

    out_vectors = []
    for vec in vectors():
        name = vec["name"]
        stream = vec["stream"]
        stream_file = f"streams/{name}.bin"
        pcap_file = f"pcaps/{name}.pcap"

        open(os.path.join(outdir, stream_file), "wb").write(stream)

        # 段要带上流引用，便于 seg_bytes 取默认载荷；序列化前剥掉。
        segs = []
        for sg in vec["segments"]:
            sg = dict(sg)
            sg["stream"] = stream
            segs.append(sg)
        open(os.path.join(outdir, pcap_file), "wb").write(
            build_pcap(vec["isn"], segs, len(stream)))

        prefix_len = vec["expect"]["prefix_len"]
        entry = {
            "name": name,
            "note": vec["note"],
            "isn": vec["isn"],
            "stream_file": stream_file,
            "stream_len": len(stream),
            "stream_sha256": hashlib.sha256(stream).hexdigest(),
            "config": {
                "max_buffered": vec.get("config", {}).get("max_buffered", 65536),
                "max_span": vec.get("config", {}).get("max_span", 4 * 1024 * 1024),
                "policy": vec.get("config", {}).get("policy", "keep_old"),
            },
            "expect": dict(
                vec["expect"],
                prefix_sha256=hashlib.sha256(stream[:prefix_len]).hexdigest(),
            ),
            "tshark": {
                "mode": vec.get("tshark_mode", "stream"),
                "verified": vec.get("tshark_verified", True),
                "note": vec.get("tshark_note"),
                "expect": vec.get("tshark_expect", {
                    "sha256": hashlib.sha256(stream).hexdigest(),
                    "len": len(stream),
                }),
            },
            "dpi": vec.get("dpi"),
            "pcap": pcap_file,
            "segments": [
                {
                    "off": sg["off"],
                    "len": sg["len"],
                    "fin": sg["fin"],
                    "data_hex": sg["data_hex"],
                }
                for sg in vec["segments"]
            ],
        }
        out_vectors.append(entry)
        print(f"生成 {name}: 流 {len(stream)} 字节, {len(vec['segments'])} 个段 "
              f"(tshark {'核验' if entry['tshark']['verified'] else '跳过'})")

    manifest = {
        "generated_by": "datasets/reassembly/generate-reassembly-samples.py",
        "note": (
            "每条向量的 expect 由生成器按「我知道放了什么」写死，"
            "再由 tshark（scripts/verify/check-reassembly-vectors.sh）作为第三方实现复核。"
            "tshark.verified=false 的条目属已知例外："
            "重叠仲裁策略差异（overlap-conflict）与内存上限差异（memory-cap）"
            "会让两边期望值必然不同，未核验的条目必须显式列出，不能默认通过。"
        ),
        "vectors": out_vectors,
    }
    path = os.path.join(outdir, "expected.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"生成 {path}  ({len(out_vectors)} 条向量)")


if __name__ == "__main__":
    main()
