#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generate-tcp-analysis-samples.py —— 生成 datasets/tcp-analysis/ 的会话级 TCP 统计样本

产出：
    sample-tcp-anomaly.pcap   六种确定性 TCP 异常模式 + 一条截断会话（8 个端口会话）
    expected.json             每条模式的**手写期望值**（我们的口径）与 tshark 实测期望

为什么需要这一份样本（CYS-TRF-015）：
    会话级重传/乱序/RTT/上下行的判定住在 `session::SeqTrack`，Rust 单测钉的是
    「实现符合我们的定义」。定义本身对不对，要靠第三方裁判（tshark）在**同一构造**
    上实测 —— 2026-10-23 正式探针（Wireshark 4.6.7 / macOS，完整握手含第三次 ACK）：

        · 完全落在已按序收取之内的重发      → 两边都判 retransmission
        · 部分重叠（前旧后新）              → 两边都判 out_of_order
        · 先发后一段再补前一段（补洞段）    → 两边都判 out_of_order；
                                              超前段 Wireshark 另给 lost_segment
        · 中间段永不再来（只有超前段）      → 两边 retrans/out-of-order 都不计；
                                              Wireshark 给 lost_segment（另一个口径）
        · 重复 ACK                           → 两边都不计入 retrans/ooo

    同批还有一次**反面探针**：握手缺第三次 ACK 时，同样的重叠/补洞字节被 Wireshark
    归成 retransmission —— “分类依赖 ACK 上下文，表格记不住构型”。所以三方比对的
    全部锤点在“同一条 pcap 上同场”：
        ① 我们的 retr == tshark retransmission 帧数
        ② 我们的 ooo  == tshark out_of_order 帧数
        ③ 每条 flow 的 lost/duplicate_ack 帧数也逐格钉住（tshark 侧事实的哨兵）
    若将来某版 tshark 分类变了，关口要么逐项报红、要么把它改成显式的
    verified=false 例外（先例：重组关口）；不许静默。
    RTT 不与 tshark 的 iRTT 比：iRTT 量的是 SYN→第三次握手 ACK，
    我们的 handshake_rtt 是 SYN→SYN/ACK —— 只与生成器真值（我们自己写进 pcap 的
    时间戳差）比对，这是可精确断言的口径。

期望值为什么手写而不是「跑一遍实现记下来」：同重组样本的理由 —— 让被测实现
给自已打分等于没测。每个数都按“我知道我往 pcap 里放了什么”写死。

用法：
    python3 datasets/tcp-analysis/generate-tcp-analysis-samples.py [输出目录]
"""

import json
import os
import struct
import sys

# ---------------------------------------------------------------- 基础构造

MAGIC_MICRO = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535

ETH_DST = bytes.fromhex("001122334455")
ETH_SRC = bytes.fromhex("66778899aabb")
ETH_IPV4 = b"\x08\x00"

CLIENT_IP = bytes([10, 0, 0, 1])
SERVER_IP = bytes([10, 0, 0, 2])
SERVER_PORT = 443

FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_ACK = 0x10
FLAG_PSH = 0x08
F_SYN = FLAG_SYN
F_SYNACK = FLAG_SYN | FLAG_ACK
F_ACK = FLAG_ACK
F_PSHACK = FLAG_PSH | FLAG_ACK

TCP_HDR_LEN = 20


def cksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(payload: bytes) -> bytes:
    return ETH_DST + ETH_SRC + ETH_IPV4 + payload


def ipv4(payload: bytes, src: bytes, dst: bytes) -> bytes:
    total_len = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0x00, total_len, 1, 0x4000,
                      64, 6, 0) + src + dst
    hdr = hdr[:10] + struct.pack("!H", cksum16(hdr)) + hdr[12:]
    return hdr + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int,
        payload: bytes = b"") -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags,
                      65535, 0, 0)
    return hdr + payload


def pcap_bytes(records) -> bytes:
    """records: [(ts_sec, ts_usec, frame, orig_len)]；orig_len>len(frame) 即截断捕获。"""
    out = struct.pack("<IHHiIII", MAGIC_MICRO, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)
    for ts_sec, ts_usec, frame, orig_len in records:
        out += struct.pack("<IIII", ts_sec, ts_usec, len(frame), orig_len)
        out += frame
    return out


# ---------------------------------------------------------------- 模式定义
#
# 一条“段记录”= (side, flags, seq_rel, ack_rel, data_len, ts_us, class)
#   side: "A"=客户端（发起方），"B"=服务端
#   seq_rel/ack_rel: 相对各自 ISN 的序号（写样本时按“我知道发了什么”直接给）
#   class: 我们对该段的期望判定 —— in-order / retrans / reorder / gap / plain
#          plain = 不占序号空间（纯 ACK），不参与判定
#   data_len: TCP 载荷字节数（ip 载荷 = 20 + data_len）
#
# ISN：客户端 1000，服务端 5000（所有流一致；A 侧数据从 1001 起，B 侧从 5001 起）。

CL, SV = 1000, 5000

FLOW_BASE_TS = (1700000300, 0)  # 每条流起点秒 +10

FLOWS = [
    {
        "name": "baseline-in-order",
        "port": 40001,
        "rtt_us": 1500,
        "note": "按序握手 + 一段数据 + 重复 ACK：两边都必须 0/0（假阳性哨兵）。",
        "segments": [
            ("A", F_SYN, CL, 0, 0, 0, "in-order"),
            ("B", F_SYNACK, SV, CL + 1, 0, 1500, "in-order"),
            ("A", F_ACK, CL + 1, SV + 1, 0, 1600, "plain"),
            ("A", F_PSHACK, CL + 1, SV + 1, 100, 1700, "in-order"),
            ("B", F_ACK, SV + 1, CL + 101, 0, 1800, "plain"),
            ("B", F_ACK, SV + 1, CL + 101, 0, 1900, "plain"),  # 重复 ACK
        ],
        "expect": {"retr": 0, "ooo": 0, "judged": 3},  # SYN、SYN/ACK、数据段
        "tshark": {"retransmission": 0, "out_of_order": 0,
                   "lost_segment": 0, "duplicate_ack": 1, "verified": True},
    },
    {
        "name": "retransmit-acked",
        "port": 40002,
        "rtt_us": 3000,
        "note": "已被 ACK 的段原样重发：两边都判 retransmission（一致）。",
        "segments": [
            ("A", F_SYN, CL, 0, 0, 0, "in-order"),
            ("B", F_SYNACK, SV, CL + 1, 0, 3000, "in-order"),
            ("A", F_ACK, CL + 1, SV + 1, 0, 3100, "plain"),
            ("A", F_PSHACK, CL + 1, SV + 1, 100, 3200, "in-order"),
            ("B", F_ACK, SV + 1, CL + 101, 0, 3300, "plain"),
            ("A", F_PSHACK, CL + 1, SV + 1, 100, 9000, "retrans"),
        ],
        "expect": {"retr": 1, "ooo": 0, "judged": 4},
        "tshark": {"retransmission": 1, "out_of_order": 0,
                   "lost_segment": 0, "duplicate_ack": 0, "verified": True},
    },
    {
        "name": "resend-before-ack",
        "port": 40003,
        "rtt_us": 1200,
        "note": "未等 ACK 原样重发同一段：探针实测 Wireshark 也判 retransmission（一致）。",
        "segments": [
            ("A", F_SYN, CL, 0, 0, 0, "in-order"),
            ("B", F_SYNACK, SV, CL + 1, 0, 1200, "in-order"),
            ("A", F_ACK, CL + 1, SV + 1, 0, 1300, "plain"),
            ("A", F_PSHACK, CL + 1, SV + 1, 100, 1400, "in-order"),
            ("A", F_PSHACK, CL + 1, SV + 1, 100, 1500, "retrans"),
        ],
        "expect": {"retr": 1, "ooo": 0, "judged": 4},
        "tshark": {"retransmission": 1, "out_of_order": 0,
                   "lost_segment": 0, "duplicate_ack": 0, "verified": True},
    },
    {
        "name": "partial-overlap",
        "port": 40004,
        "rtt_us": 2500,
        "note": "前 50 字节旧、后 50 字节新：两边都判 out_of_order（2026-10-23 正式样本实测）。",
        "segments": [
            ("A", F_SYN, CL, 0, 0, 0, "in-order"),
            ("B", F_SYNACK, SV, CL + 1, 0, 2500, "in-order"),
            ("A", F_ACK, CL + 1, SV + 1, 0, 2600, "plain"),
            ("A", F_PSHACK, CL + 1, SV + 1, 100, 2700, "in-order"),
            ("A", F_PSHACK, CL + 51, SV + 1, 100, 2800, "reorder"),
        ],
        "expect": {"retr": 0, "ooo": 1, "judged": 4},
        "tshark": {"retransmission": 0, "out_of_order": 1,
                   "lost_segment": 0, "duplicate_ack": 0, "verified": True},
    },
    {
        "name": "forward-then-fill",
        "port": 40005,
        "rtt_us": 8000,
        "note": "先发后一段（1101）再补前一段（1001）：补洞段两边都判 out_of_order；"
                "Wireshark 给超前段 lost_segment（我们不计，口径不同）。",
        "segments": [
            ("A", F_SYN, CL, 0, 0, 0, "in-order"),
            ("B", F_SYNACK, SV, CL + 1, 0, 8000, "in-order"),
            ("A", F_ACK, CL + 1, SV + 1, 0, 8100, "plain"),
            ("A", F_PSHACK, CL + 101, SV + 1, 100, 8200, "gap"),
            ("A", F_PSHACK, CL + 1, SV + 1, 100, 8300, "reorder"),
        ],
        "expect": {"retr": 0, "ooo": 1, "judged": 4},
        "tshark": {"retransmission": 0, "out_of_order": 1,
                   "lost_segment": 1, "duplicate_ack": 0, "verified": True},
    },
    {
        "name": "gap-forever",
        "port": 40006,
        "rtt_us": 9500,
        "note": "中间段永不再来（只有 1001 和 1201）：两边 retrans/out-of-order 都是 0；"
                "这是防“把没收到数成乱序”的反向哨兵。Wireshark 给超前段 lost_segment。",
        "segments": [
            ("A", F_SYN, CL, 0, 0, 0, "in-order"),
            ("B", F_SYNACK, SV, CL + 1, 0, 9500, "in-order"),
            ("A", F_ACK, CL + 1, SV + 1, 0, 9600, "plain"),
            ("A", F_PSHACK, CL + 1, SV + 1, 100, 9700, "in-order"),
            ("A", F_PSHACK, CL + 201, SV + 1, 100, 9800, "gap"),
        ],
        "expect": {"retr": 0, "ooo": 0, "judged": 4},
        "tshark": {"retransmission": 0, "out_of_order": 0,
                   "lost_segment": 1, "duplicate_ack": 0, "verified": True},
    },
    {
        "name": "truncated-no-seq",
        "port": 40007,
        "rtt_us": None,
        "note": "三帧全部截断到 44 字节（读不到 seq/ack/flags）：会话存在但没有任何判定"
                "输入 —— 计数必须是“未观测”而不是 0，RTT/上下行必须是 None。",
        "segments": [
            ("A", F_PSHACK, CL + 1, SV + 1, 100, 0, "untruncated"),
            ("A", F_PSHACK, CL + 101, SV + 1, 100, 100, "untruncated"),
            ("A", F_PSHACK, CL + 201, SV + 1, 100, 200, "untruncated"),
        ],
        "expect": {"retr": None, "ooo": None, "judged": 0},
        "tshark": {"retransmission": 0, "out_of_order": 0,
                   "lost_segment": 0, "duplicate_ack": 0, "verified": True},
    },
]


def build_flow_segments(flow, start_sec):
    """返回 pcap 记录。每流占一个独立的起始秒，流内按 ts_us 排（<1s 不会串流）。"""
    records = []
    trunc = flow["name"] == "truncated-no-seq"
    port = flow["port"]
    for (side, flags, seq, ack, dlen, ts_us, klass) in flow["segments"]:
        if side == "A":
            seg = tcp(port, SERVER_PORT, seq, ack, flags, b"x" * dlen)
            frame = eth(ipv4(seg, CLIENT_IP, SERVER_IP))
        else:
            seg = tcp(SERVER_PORT, port, seq, ack, flags, b"x" * dlen)
            frame = eth(ipv4(seg, SERVER_IP, CLIENT_IP))
        if trunc:
            full_len = len(frame)
            frame = frame[:44]  # eth14+ip20+tcp10：读不到 flags/seq
            records.append((start_sec, ts_us, frame, full_len))
        else:
            records.append((start_sec, ts_us, frame, len(frame)))
    return records


def derive_totals():
    """由构造参数直接累加出 CLI 统计行的真值（不跑被测实现）。"""
    tot = {
        "sessions_judged": 0, "sessions_unobserved": 0,
        "judged": 0, "retr": 0, "ooo": 0,
        "rtt_measured": 0, "rtt_total_sessions": 0,
        "rtt_sum_us": 0, "rtt_min_us": None, "rtt_max_us": None,
        "up_bytes": 0, "down_bytes": 0, "ratio_sessions": 0,
        "tshark_retr": 0, "tshark_ooo": 0, "tshark_lost": 0, "tshark_dupack": 0,
    }
    rtts = []
    for fl in FLOWS:
        e = fl["expect"]
        t = fl["tshark"]
        tot["tshark_retr"] += t["retransmission"]
        tot["tshark_ooo"] += t["out_of_order"]
        tot["tshark_lost"] += t["lost_segment"]
        tot["tshark_dupack"] += t["duplicate_ack"]
        if e["judged"] == 0:
            tot["sessions_unobserved"] += 1
        else:
            tot["sessions_judged"] += 1
            tot["judged"] += e["judged"]
            tot["retr"] += e["retr"]
            tot["ooo"] += e["ooo"]
        # 握手 RTT：生成器写进 pcap 的 SYN→SYN/ACK 时间差（截断层无 SYN 也无 rtt）
        rtt = fl["rtt_us"]
        if rtt is not None:
            tot["rtt_measured"] += 1
            tot["rtt_sum_us"] += rtt
            rtts.append(rtt)
        # 上下行字节：ip 载荷 = tcp 头 20 + 载荷；发起方是 A（截断层无发起方）
        if rtt is not None:
            up = sum(TCP_HDR_LEN + d for s, _f, _q, _a, d, _t, _k in fl["segments"] if s == "A")
            down = sum(TCP_HDR_LEN + d for s, _f, _q, _a, d, _t, _k in fl["segments"] if s == "B")
            tot["up_bytes"] += up
            tot["down_bytes"] += down
            if up > 0:
                tot["ratio_sessions"] += 1
    tot["rtt_total_sessions"] = tot["sessions_judged"] + tot["sessions_unobserved"]
    if rtts:
        tot["rtt_min_us"] = min(rtts)
        tot["rtt_max_us"] = max(rtts)
    return tot


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    outdir = sys.argv[1] if len(sys.argv) > 1 else here
    os.makedirs(outdir, exist_ok=True)

    records = []
    for i, fl in enumerate(FLOWS):
        records.extend(build_flow_segments(fl, FLOW_BASE_TS[0] + i * 10))

    pcap_path = os.path.join(outdir, "sample-tcp-anomaly.pcap")
    with open(pcap_path, "wb") as fh:
        fh.write(pcap_bytes(records))

    expected = {
        "generated_by": "datasets/tcp-analysis/generate-tcp-analysis-samples.py",
        "note": "expect 由生成器按「我知道放了什么」写死；tshark 一栏是 2026-10-23 在 "
                "Wireshark 4.6.7 / macOS 上对本构造（完整握手含第三次 ACK）的实测标记，"
                "六条流全部逐格一致。verified=false 的支持机制保留给将来的口径漂移，"
                "当前没有条目使用它。RTT 只与生成器真值比：tshark 的 iRTT 量 SYN→第三次 "
                "ACK，与我们的 SYN→SYN/ACK 口径不同。",
        "probe": {"date": "2026-10-23", "tshark": "Wireshark 4.6.7 / macOS"},
        "flows": [
            {
                "name": fl["name"], "port": fl["port"], "note": fl["note"],
                "rtt_us": fl["rtt_us"],
                "expect": fl["expect"],
                "tshark": fl["tshark"],
                **({"tshark_reason": fl["tshark_reason"]} if "tshark_reason" in fl else {}),
            }
            for fl in FLOWS
        ],
        "totals": derive_totals(),
    }
    exp_path = os.path.join(outdir, "expected.json")
    with open(exp_path, "w", encoding="utf-8") as fh:
        json.dump(expected, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    print(f"生成 {pcap_path}（{len(records)} 帧）")
    print(f"生成 {exp_path}")


if __name__ == "__main__":
    main()
