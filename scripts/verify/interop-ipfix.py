#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""interop-ipfix.py —— **独立实现**的 IPFIX 导出器（按 RFC 7011 手写）+ 采集结果断言。

## 为什么需要这一份"重复实现"

仓库自己的导出关口（`check-ipfix-export.sh`）比的是"我们的编码器 vs tshark"，
采集关口（`check-ipfix-collect.sh`）比的是"我们的编码器 → 我们的采集器"。
后者有一个**结构性盲区**：编码器与采集器共用 `src/ipfix/mod.rs` 里的同一份模板定义 ——
如果那份定义本身读错了 RFC（字段顺序、长度、序列号语义），两边会**一起错，
并且互相验证通过**。tshark 能挡住"发出去的字节不合法"，但挡不住"我们把某个 IE
理解成了别的意思"。

这份脚本就是那个缺掉的第三方：一个只读 RFC 文本写出来的导出器，
**不 import、不复制仓库里的任何常量**，并且故意在每一个可能被"约定俗成"掩盖的地方
与仓库实现不同：

| 维度 | 仓库 Rust 编码器 | 本脚本（独立实现） |
| --- | --- | --- |
| 模板 ID | 256 / 257 | 4001 / 4002 / 4003 / 4004 |
| 字段顺序 | octets 在前、时间在后 | **时间在前、octets 在后** |
| 观测域 ID | 0 | 0x1234ABCD |
| 计数器长度 | 8 字节 | 也发 **4 字节**（RFC 7011 §6.2 缩减长度编码） |
| 模板字段集 | 只有已登记 IE | 夹带**未登记 IE**（9999 / 12345） |
| 模板集内容 | 只有模板 | 还发 **options template set**、**模板撤回** |
| 报文序列 | 每个报文都带模板 | **先发数据后发模板**、**中途重定义模板** |

判定用的是**手写常量**（每条流的五元组/计数/时间写死在下面的 `FLOWS_*` 里），
不是脚本自己算出来的值 —— 否则"导出"和"断言"一起错，等于没验。

## 用法

    interop-ipfix.py emit <scenario> <out.pcap> [--drop N]   # 造一份"异厂"导出产物（pcap）
    interop-ipfix.py assert <scenario> <stats.txt> <out.jsonl>
    interop-ipfix.py self-test [--collector BIN] [--workdir DIR]

scenario ∈ standard / reduced64 / v6 / foreign / gap
"""

import json
import os
import struct
import subprocess
import sys

# ---------------------------------------------------------------------------
# 独立的 IE 表（照 IANA / RFC 7011 的编号写，刻意不从仓库代码里抄）
# ---------------------------------------------------------------------------
IE_FLOW_START_MS = 152  # flowStartMilliseconds, unsigned64
IE_FLOW_END_MS = 153  # flowEndMilliseconds, unsigned64
IE_OCTETS = 1  # octetDeltaCount
IE_PACKETS = 2  # packetDeltaCount
IE_PROTO = 4  # protocolIdentifier
IE_TCP_FLAGS = 6  # tcpControlBits
IE_SRC_PORT = 7
IE_DST_PORT = 11
IE_SRC_V4 = 8
IE_DST_V4 = 12
IE_SRC_V6 = 27
IE_DST_V6 = 28
IE_FLOW_ID = 148
IE_SAMPLING = 34

VERSION = 10
SET_TEMPLATE = 2
SET_OPTIONS_TEMPLATE = 3

# 独立实现的观测域与模板 ID：与仓库实现**故意不同**。
ODID = 0x1234ABCD
TID_STD = 4001
TID_REDUCED = 4002
TID_FOREIGN = 4003
TID_V6 = 4004

EXPORT_TIME = 1_700_000_100  # 报文头的导出时刻（秒），写死以便产物可复现


def be(n, width):
    return n.to_bytes(width, "big")


def ip4(s):
    return bytes(int(x) for x in s.split("."))


def ip6(s):
    import socket

    return socket.inet_pton(socket.AF_INET6, s)


# ---------------------------------------------------------------------------
# 手写常量：期望值来自这里，不是从导出逻辑里算出来的
# ---------------------------------------------------------------------------
class Flow:
    """一条期望被采集器还原出来的流（写死的常量）。"""

    def __init__(self, src, sport, dst, dport, proto, packets, octets, start_ms, end_ms, fid,
                 expect_tup=None):
        self.src, self.sport, self.dst, self.dport = src, sport, dst, dport
        self.proto, self.packets, self.octets = proto, packets, octets
        self.start_ms, self.end_ms, self.fid = start_ms, end_ms, fid
        # 采集器把键规范化为"端点序"（`src/flow/mod.rs::canonical`：按 `(ip, port)` 排序，
        # 与"谁先发包"无关）。所以当导出方向是"客户端在前"而客户端地址更大时，
        # 期望值要写成规范形式 —— 这一条同时验证了**方向没有被假定**：
        # 我们发的是 client→server，收回来的是端点序。
        self.expect_tup = expect_tup

    def tup(self):
        t = self.expect_tup or (self.src, self.sport, self.dst, self.dport, self.proto)
        if len(t) != 5:
            # 少写一个元素时，断言会打印出"两个看起来一模一样的元组不相等"，
            # 极难读（第一版就把 proto 漏了）。在这里直接炸掉。
            raise AssertionError(f"期望五元组必须是 5 元：{t!r}")
        return t

    def __repr__(self):
        return f"Flow({self.tup()} pkt={self.packets} oct={self.octets} id={self.fid})"


FLOWS_STD = [
    Flow("10.1.2.3", 40001, "10.9.9.9", 443, 6, 12, 3456, 1_700_000_000_000, 1_700_000_001_500, 0xA1),
    Flow("10.1.2.4", 40002, "10.9.9.9", 80, 6, 3, 512, 1_700_000_000_100, 1_700_000_000_900, 0xA2),
    # 这一条刻意让**客户端地址比服务端大**（10.1.2.5 > 8.8.8.8）：导出方向是 client→server，
    # 期望按端点序写（规范形式），于是"采集器是否假定方向"这件事也被断言到了。
    Flow("10.1.2.5", 40003, "8.8.8.8", 53, 17, 1, 78, 1_700_000_000_200, 1_700_000_000_250, 0xA3,
         expect_tup=("8.8.8.8", 53, "10.1.2.5", 40003, 17)),
]

FLOWS_V6 = [
    Flow("2001:db8::1", 51000, "2001:db8::2", 443, 6, 7, 900, 1_700_000_002_000, 1_700_000_002_600, 0xB1),
    Flow("2001:db8::3", 51001, "2606:4700::1111", 53, 17, 2, 140, 1_700_000_002_100, 1_700_000_002_150, 0xB2),
]

# foreign 场景：模板里夹带未登记 IE（9999 / 12345），且计数走不同位置。
FLOWS_FOREIGN_BEFORE = [  # 先于模板发出的那两条：模板未知 ⇒ 必须计数并丢弃，不得编造
    Flow("192.0.2.1", 1234, "192.0.2.2", 80, 6, 99, 99999, 1_700_000_010_000, 1_700_000_010_500, 0xC9),
    Flow("192.0.2.3", 1235, "192.0.2.4", 80, 6, 98, 88888, 1_700_000_010_100, 1_700_000_010_600, 0xCA),
]
# 模板建立之后要发的 5 条流：**必须互不相同** —— 重发同一条记录会被采集器的去重窗口
# 正确丢掉（第一版就踩了：3 条重发全被计成 duplicate，交付数比期望少 3）。
FLOWS_FOREIGN_TAIL = [
    Flow("192.0.2.5", 1236, "192.0.2.6", 443, 6, 11, 1111, 1_700_000_011_000, 1_700_000_011_400, 0xCB),
    Flow("192.0.2.7", 1237, "192.0.2.8", 22, 6, 22, 2222, 1_700_000_011_100, 1_700_000_011_900, 0xCC),
    Flow("192.0.2.9", 1238, "192.0.2.10", 8443, 6, 33, 3333, 1_700_000_012_000, 1_700_000_012_700, 0xCD),
    Flow("192.0.2.11", 1239, "192.0.2.12", 993, 6, 44, 4444, 1_700_000_012_100, 1_700_000_012_800, 0xCE),
    Flow("192.0.2.13", 1240, "192.0.2.14", 8080, 6, 55, 5555, 1_700_000_012_200, 1_700_000_012_900, 0xCF),
]

# gap 场景：4 条报文各 1 条记录，删掉第 3 个 datagram（下标 2）。
FLOWS_GAP = [
    Flow("172.16.0.1", 1001, "172.16.0.2", 443, 6, 1, 100, 1_700_000_020_000, 1_700_000_020_100, 0xD1),
    Flow("172.16.0.3", 1002, "172.16.0.4", 443, 6, 2, 200, 1_700_000_020_200, 1_700_000_020_300, 0xD2),
    Flow("172.16.0.5", 1003, "172.16.0.6", 443, 6, 3, 300, 1_700_000_020_400, 1_700_000_020_500, 0xD3),  # 被删
    Flow("172.16.0.7", 1004, "172.16.0.8", 443, 6, 4, 400, 1_700_000_020_600, 1_700_000_020_700, 0xD4),
]
GAP_DROP_INDEX = 2


# ---------------------------------------------------------------------------
# 线路格式：报文 / 集合 / 模板 / 记录
# ---------------------------------------------------------------------------
def set_bytes(set_id, payload, pad=0):
    total = 4 + len(payload) + pad
    return be(set_id, 2) + be(total, 2) + payload + b"\x00" * pad


def message(seq, sets):
    body = b"".join(sets)
    total = 16 + len(body)
    # RFC 7011 §3.1：version / length / exportTime / sequenceNumber / observationDomainID
    return be(VERSION, 2) + be(total, 2) + be(EXPORT_TIME, 4) + be(seq, 4) + be(ODID, 4) + body


def template_set(templates):
    """templates = [(tid, [(ie, len), ...]), ...]"""
    payload = b""
    for tid, fields in templates:
        payload += be(tid, 2) + be(len(fields), 2)
        for ie, ln in fields:
            payload += be(ie, 2) + be(ln, 2)
    return set_bytes(SET_TEMPLATE, payload)


def withdrawal_set(tid):
    """RFC 7011 §8.1：字段数为 0 = 撤回该模板。UDP 上必须被忽略（§8.4）。"""
    return set_bytes(SET_TEMPLATE, be(tid, 2) + be(0, 2))


def options_template_set(tid, scope_fields, option_fields):
    payload = be(tid, 2) + be(len(scope_fields), 2) + be(len(option_fields), 2)
    for ie, ln in scope_fields + option_fields:
        payload += be(ie, 2) + be(ln, 2)
    return set_bytes(SET_OPTIONS_TEMPLATE, payload)


def record(flow, fields, ipv6=False):
    out = b""
    src = ip6(flow.src) if ipv6 else ip4(flow.src)
    dst = ip6(flow.dst) if ipv6 else ip4(flow.dst)
    values = {
        IE_FLOW_START_MS: flow.start_ms,
        IE_FLOW_END_MS: flow.end_ms,
        IE_OCTETS: flow.octets,
        IE_PACKETS: flow.packets,
        IE_PROTO: flow.proto,
        IE_TCP_FLAGS: 0x18,
        IE_SRC_PORT: flow.sport,
        IE_DST_PORT: flow.dport,
        IE_SRC_V4: src,
        IE_DST_V4: dst,
        IE_SRC_V6: src,
        IE_DST_V6: dst,
        IE_FLOW_ID: flow.fid,
        IE_SAMPLING: 1000,
        # 未登记 IE：内容刻意不参与语义，只占位（值任意但固定，保证产物可复现）
        9999: 0x5A5A,
        12345: 0x010203040506,
    }
    for ie, ln in fields:
        v = values[ie]
        out += v if isinstance(v, bytes) else be(v, ln)
    return out


def data_set(tid, records, pad=0):
    return set_bytes(tid, b"".join(records), pad=pad)


# 各场景的模板字段表（独立实现自己的顺序与长度）
TEMPLATE_STD = [
    (IE_FLOW_START_MS, 8),
    (IE_FLOW_END_MS, 8),
    (IE_OCTETS, 8),
    (IE_PACKETS, 8),
    (IE_TCP_FLAGS, 1),
    (IE_PROTO, 1),
    (IE_SRC_PORT, 2),
    (IE_DST_PORT, 2),
    (IE_SRC_V4, 4),
    (IE_DST_V4, 4),
    (IE_FLOW_ID, 8),
    (IE_SAMPLING, 4),
]
# 缩减长度编码：计数 8→4 字节、采样率 4→2 字节（RFC 7011 §6.2）
TEMPLATE_REDUCED = [
    (IE_FLOW_START_MS, 8),
    (IE_FLOW_END_MS, 8),
    (IE_OCTETS, 4),
    (IE_PACKETS, 4),
    (IE_TCP_FLAGS, 1),
    (IE_PROTO, 1),
    (IE_SRC_PORT, 2),
    (IE_DST_PORT, 2),
    (IE_SRC_V4, 4),
    (IE_DST_V4, 4),
    (IE_FLOW_ID, 4),
    (IE_SAMPLING, 2),
]
TEMPLATE_V6 = [
    (IE_FLOW_START_MS, 8),
    (IE_FLOW_END_MS, 8),
    (IE_OCTETS, 8),
    (IE_PACKETS, 8),
    (IE_PROTO, 1),
    (IE_SRC_PORT, 2),
    (IE_DST_PORT, 2),
    (IE_SRC_V6, 16),
    (IE_DST_V6, 16),
    (IE_FLOW_ID, 8),
]
TEMPLATE_FOREIGN = [
    (IE_SRC_V4, 4),
    (IE_DST_V4, 4),
    (IE_SRC_PORT, 2),
    (IE_DST_PORT, 2),
    (IE_PROTO, 1),
    (9999, 2),  # 未登记 IE（夹在中间：偏移必须按长度推进）
    (IE_OCTETS, 8),
    (12345, 6),  # 未登记 IE（6 字节，不是常规长度）
    (IE_PACKETS, 8),
    (IE_FLOW_ID, 4),
    (IE_FLOW_START_MS, 8),
    (IE_FLOW_END_MS, 8),
]
# "重定义"用的另一套字段（同 ID 不同定义）：撤回无效、重定义也必须被拒
TEMPLATE_FOREIGN_REDEFINED = [(IE_SRC_V4, 4), (IE_DST_V4, 4)]


def _clean_expect(flows, unknown_ies):
    """"无故障语料"的完整期望：每一项都写死，缺一项就算失败（不许默默跳过）。"""
    return {
        "flows": flows,
        "records": len(flows),
        "delivered": len(flows),
        "duplicates": 0,
        "gaps": 0,
        "lost_records": 0,
        "loss_ppm": 0,
        "out_of_order": 0,
        "no_template_sets": 0,
        "withdrawals_ignored": 0,
        "template_conflicts": 0,
        "options_template_sets": 0,
        "nonzero_padding": 0,
        "malformed": 0,
        "version_mismatch": 0,
        "records_missing_key": 0,
        # IE 6 = tcpControlBits：IANA 已登记、真实导出器（Cisco/softflowd）都会发，
        # 但本仓采集器的 `Ie` 枚举里**没有它** ⇒ 必须走"按长度跳过"的路径，
        # 它后面的 4 个字段一个都不许挪位。这是本关口最有价值的互操作事实。
        "unknown_ies": unknown_ies,
    }


def build(scenario):
    """返回 (datagrams, 手写期望) —— datagrams 是 IPFIX 报文字节。"""
    if scenario == "standard":
        # 报文 1：模板 + 2 条记录（seq=0，因为此前已导出 0 条记录）
        d1 = message(0, [template_set([(TID_STD, TEMPLATE_STD)]), data_set(TID_STD, [record(f, TEMPLATE_STD) for f in FLOWS_STD[:2]])])
        # 报文 2：1 条记录（seq=2）
        d2 = message(2, [data_set(TID_STD, [record(FLOWS_STD[2], TEMPLATE_STD)])])
        return [d1, d2], _clean_expect(FLOWS_STD, "6")

    if scenario == "reduced64":
        d1 = message(0, [template_set([(TID_REDUCED, TEMPLATE_REDUCED)]), data_set(TID_REDUCED, [record(f, TEMPLATE_REDUCED) for f in FLOWS_STD[:2]])])
        d2 = message(2, [data_set(TID_REDUCED, [record(FLOWS_STD[2], TEMPLATE_REDUCED)])])
        return [d1, d2], _clean_expect(FLOWS_STD, "6")

    if scenario == "v6":
        d1 = message(0, [template_set([(TID_V6, TEMPLATE_V6)]), data_set(TID_V6, [record(f, TEMPLATE_V6, ipv6=True) for f in FLOWS_V6])])
        return [d1], _clean_expect(FLOWS_V6, "-")

    if scenario == "foreign":
        # d1: 模板未知就发数据（2 条）—— 采集器**必须计数并丢弃**，不得编造流
        d1 = message(0, [data_set(TID_FOREIGN, [record(f, TEMPLATE_FOREIGN) for f in FLOWS_FOREIGN_BEFORE])])
        # d2: 模板（含两个未登记 IE）
        d2 = message(2, [template_set([(TID_FOREIGN, TEMPLATE_FOREIGN)])])
        # d3: 2 条记录（seq=2）
        d3 = message(2, [data_set(TID_FOREIGN, [record(f, TEMPLATE_FOREIGN) for f in FLOWS_FOREIGN_TAIL[:2]])])
        # d4: 模板撤回（UDP 上必须被忽略，模板仍然可用）
        d4 = message(4, [withdrawal_set(TID_FOREIGN)])
        # d5: options template set（只计数，不当数据）
        d5 = message(4, [options_template_set(5000, [(149, 4)], [(150, 8)])])
        # d6: 1 条记录 + 2 字节零填充（填充必须短于记录且全零）
        d6 = message(4, [data_set(TID_FOREIGN, [record(FLOWS_FOREIGN_TAIL[2], TEMPLATE_FOREIGN)], pad=2)])
        # d7: 同 ID 不同定义 → 必须保留旧模板并计数
        d7 = message(5, [template_set([(TID_FOREIGN, TEMPLATE_FOREIGN_REDEFINED)])])
        # d8: 再发 2 条记录（seq=5）—— 仍按**旧模板**解读
        #     注意 d1 的 2 条记录虽然交付不了，但**必须计入导出侧序列号**（RFC 7011 §3.1），
        #     所以这里 seq 从 7 起：d1=2（未解出）+ d3=2 + d6=1 + d8=2。
        # seq = 此前已导出的记录数 = d1(2) + d3(2) + d6(1) = 5（RFC 7011 §3.1）。
        # 第一版这里写了 7（沿用了三条一组的版本），采集器立刻报了第二个缺口 ——
        # 对本关口来说这是"我写错了语料"，不是"采集器错了"。
        d8 = message(5, [data_set(TID_FOREIGN, [record(f, TEMPLATE_FOREIGN) for f in FLOWS_FOREIGN_TAIL[3:]])])
        want = _clean_expect(FLOWS_FOREIGN_TAIL, "9999,12345")
        want.update({
            "unknown_ies": "9999,12345",
            "no_template_sets": 1,
            "withdrawals_ignored": 1,
            "template_conflicts": 1,
            "options_template_sets": 1,
            "nonzero_padding": 0,
            "templates": 2,          # 模板 4003 建立 1 次 + 同号不同定义 1 次（被拒但计入）
            # **这两条是本关口的重点**：d1 的 2 条记录在模板到达前发出，采集器无法知道
            # 那个 data set 里有几条记录（模板未知 ⇒ 记录长度未知），于是它不推进序列号基线；
            # 下一条报文按 RFC 7011 §3.1 报 seq=2 → 差 2 被记为 lost_records。
            # 这不是我们的 bug，而是 §11.6 明确要求的严格读法（见 HANDOFF §2.12 口径边界）：
            # 一旦有 no_template_sets>0，**loss_ppm 就不再是网络丢包率，而是它的上界** ——
            # 里面混进了"收到了但解不出"的记录。这个数由本关口钉死，防止它悄悄变。
            "gaps": 1,
            "lost_records": 2,
            "loss_ppm": 285714,      # 1e6 × 2 ÷ (5 交付 + 2 计为丢失) = 285714（整数除）
        })
        return [d1, d2, d3, d4, d5, d6, d7, d8], want

    if scenario == "gap":
        msgs = []
        seq = 0
        for i, f in enumerate(FLOWS_GAP):
            sets = []
            if i == 0:
                sets.append(template_set([(TID_STD, TEMPLATE_STD)]))
            sets.append(data_set(TID_STD, [record(f, TEMPLATE_STD)]))
            msgs.append(message(seq, sets))
            seq += 1
        want = _clean_expect([FLOWS_GAP[0], FLOWS_GAP[1], FLOWS_GAP[3]], "6")  # 第 3 条会被删掉
        # `records` 是**解出来**的条数（3），不是导出侧发了 4 条：丢的那条我们没收到，
        # 它只出现在 `lost_records` 里（1）与 loss_ppm 的分母上（1e6×1÷(3+1)）。
        want.update({"gaps": 1, "lost_records": 1, "loss_ppm": 250000})
        return msgs, want

    raise SystemExit(f"未知 scenario：{scenario}")


# ---------------------------------------------------------------------------
# 写 pcap（Ethernet / IPv4 / UDP，源口 9999 → 目的口 4739）
# ---------------------------------------------------------------------------
PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"


def frame(payload, src_ip="203.0.113.7", dst_ip="203.0.113.8", sport=9999, dport=4739):
    eth = b"\x02\x00\x5e\x00\x53\x01" + b"\x02\x00\x5e\x00\x53\x02" + b"\x08\x00"
    udp_len = 8 + len(payload)
    ip_len = 20 + udp_len
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = be(ip_len, 2)
    ip[8] = 64  # TTL
    ip[9] = 17  # UDP
    ip[12:16] = ip4(src_ip)
    ip[16:20] = ip4(dst_ip)
    ip[10:12] = be(ip_checksum(bytes(ip)), 2)
    udp = be(sport, 2) + be(dport, 2) + be(udp_len, 2) + b"\x00\x00"
    return eth + bytes(ip) + udp + payload


def ip_checksum(hdr):
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def write_pcap(path, payloads, ts_base=1_700_000_000):
    out = bytearray(PCAP_MAGIC)
    out += struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)  # LINKTYPE_ETHERNET
    for i, p in enumerate(payloads):
        data = frame(p)
        out += struct.pack("<IIII", ts_base + i, i * 1000, len(data), len(data))
        out += data
    open(path, "wb").write(bytes(out))


def cmd_emit(scenario, out_path, drop=None):
    datagrams, _want = build(scenario)
    if drop is not None:
        if not (0 <= drop < len(datagrams)):
            raise SystemExit(f"--drop {drop} 越界（共 {len(datagrams)} 个 datagram）")
        datagrams = [d for i, d in enumerate(datagrams) if i != drop]
    write_pcap(out_path, datagrams)
    print(f"    已写出 {len(datagrams)} 个 datagram（独立实现的 IPFIX 报文）→ {out_path}")
    return 0


# ---------------------------------------------------------------------------
# 断言：采集器自报的统计 + 还原出的记录，必须与手写常量一致
# ---------------------------------------------------------------------------
def parse_stats(path):
    """只认采集器自己打印的统计行。

    **刻意不 import 另一个关口（`check-ipfix-collect.py`）的同名函数**：那一个是
    被测体系的邻居，共用解析代码会把"两个关口一起读错一行输出"变成可能。
    """
    line = None
    for raw in open(path, encoding="utf-8", errors="replace"):
        if "cythsec-ipfix-collect] datagrams=" in raw:
            line = raw.strip()
    if line is None:
        raise ValueError(f"{path} 里没有采集器统计行")
    body = line.split("datagrams=", 1)[1]
    return {k: v for k, v in (kv.split("=", 1) for kv in body.split() if "=" in kv)}


def load_jsonl(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


HEAD_ONLY_KEYS = {"datagrams", "bytes", "exporters", "templates", "expired"}


def check_stats(stats, want, scenario):
    """统计行里的每一项都对手写期望；**缺项也算失败**（不许默默跳过）。"""
    bad = 0
    cli_key = {"sets_without_template": "no_template_sets", "duplicate_records": "duplicates"}
    for name, val in want.items():
        if name == "flows":
            continue
        key = cli_key.get(name, name)
        got = stats.get(key)
        if got is None:
            print(f"    ✗ 统计行里没有 {key}（期望 {val}）—— 口径被改窄了？")
            bad += 1
        elif str(got) != str(val):
            print(f"    ✗ {key}={got}，期望 {val}")
            bad += 1
    if bad:
        raise AssertionError(f"{bad} 处统计不符")
    print("    ✓ 统计行与手写期望一致：" + " ".join(f"{k}={want[k]}" for k in sorted(want) if k != "flows"))


def check_flows(rows, want_flows, scenario):
    """逐条比五元组/计数/时间 —— 期望值来自 `FLOWS_*` 常量，不是导出逻辑的输出。"""
    if len(rows) != len(want_flows):
        raise AssertionError(f"记录条数 {len(rows)}，期望 {len(want_flows)}")
    by_id = {}
    for r in rows:
        by_id[r["session_id"]] = r
    bad = 0
    for w in want_flows:
        r = by_id.get(w.fid)
        if r is None:
            print(f"    ✗ 缺少 flowId={w.fid} 的记录（采集器还原出的 id：{sorted(by_id)}）")
            bad += 1
            continue
        f = r["flow"]
        got_tup = (f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"], f["proto"])
        if got_tup != w.tup():
            print(f"    ✗ flowId={w.fid} 五元组 {got_tup} ≠ 期望 {w.tup()}")
            bad += 1
        if r["counters"]["packets"] != w.packets or r["counters"]["bytes"] != w.octets:
            print(f"    ✗ flowId={w.fid} 计数 packets={r['counters']['packets']} bytes={r['counters']['bytes']}"
                  f" ≠ 期望 {w.packets}/{w.octets}")
            bad += 1
        if r["time"]["first_seen_us"] != w.start_ms * 1000 or r["time"]["last_seen_us"] != w.end_ms * 1000:
            print(f"    ✗ flowId={w.fid} 时间 {r['time']} ≠ 期望 {w.start_ms*1000}/{w.end_ms*1000}（微秒）")
            bad += 1
    if bad:
        raise AssertionError(f"{bad} 处记录不符")
    print(f"    ✓ {len(want_flows)} 条记录逐字段相符（五元组 / 包数 / 字节数 / 流 ID / 起止时间）"
          + ("（IPv6）" if want_flows and ":" in want_flows[0].src else ""))


def cmd_assert(scenario, stats_path, jsonl_path):
    _dgrams, want = build(scenario)
    stats = parse_stats(stats_path)
    try:
        check_stats(stats, want, scenario)
        check_flows(load_jsonl(jsonl_path), want["flows"], scenario)
    except AssertionError as exc:
        print(f"  ✗ [interop:{scenario}] {exc}")
        return 1
    if scenario == "gap":
        print("    ✓ 缺口与丢包率可独立手算：gaps=1 lost_records=1 loss_ppm=250000（1e6×1÷4）")
    elif scenario == "foreign":
        print("    ✓ 模板缺失导致的序列号歧义已按 RFC 口径钉死：no_template_sets=1 ⇒ "
              "lost_records=2（收到了但解不出的那两条），loss_ppm=285714 是**上界**")
    print(f"  ✓ [interop:{scenario}] 采集器正确还原了独立实现的导出报文")
    return 0


# ---------------------------------------------------------------------------
# 自证：断言本身必须能被反向注入判死
# ---------------------------------------------------------------------------
def cmd_self_test(collector, workdir):
    os.makedirs(workdir, exist_ok=True)
    fails = 0

    def run(scenario, tag, drop=None):
        pcap = os.path.join(workdir, f"{tag}.pcap")
        out = os.path.join(workdir, f"{tag}.jsonl")
        stats = os.path.join(workdir, f"{tag}.stats")
        cmd_emit(scenario, pcap, drop)
        with open(stats, "w", encoding="utf-8") as fh:
            # **不能加 -q**：统计行就是断言的对象，安静模式下自证会退化成"没有输入"。
            r = subprocess.run([collector, "--pcap", pcap, "-o", out], stdout=fh,
                               stderr=subprocess.STDOUT)
        return r.returncode, stats, out

    # 基线：正向必须过
    rc, stats, out = run("standard", "self-std")
    if rc != 0 or cmd_assert("standard", stats, out) != 0:
        print("  ✗ [interop] 自证基线（standard）没通过")
        fails += 1
    else:
        print("  ✓ [interop] 自证基线：standard 正向通过")

    # 正向交叉：**缩减长度编码的产物必须与完整编码的产物逐字段相同**。
    #    注意这条不能用"撞期望"的方式当注入 —— 两个场景本就该解出同一批流，
    #    第一版把它当注入，结果"注入没被检出"，其实是注入选错了（断言是对的）。
    rc, stats_r, out_r = run("reduced64", "self-red")
    if cmd_assert("standard", stats_r, out_r) != 0:
        print("  ✗ [interop] 缩减长度编码（§6.2）解出的记录与完整编码不一致")
        fails += 1
    else:
        print("  ✓ [interop] 缩减长度编码与完整编码解出同一批记录（4 字节计数 / 2 字节采样率）")

    # 注入 1：拿 v6 场景的产物去撞 standard 的期望（记录与条数都不同）→ 必须判红
    rc, stats_v6, out_v6 = run("v6", "self-v6")
    if cmd_assert("standard", stats_v6, out_v6) == 0:
        print("  ✗ [interop] 注入「用 v6 的产物撞 standard 的期望」未被判死")
        fails += 1
    else:
        print("  ✓ [interop] 注入已检出：v6 的产物撞 standard 的期望被判死")

    # 注入 1b：拿 standard 的产物去撞 foreign 的期望（统计口径不同：未登记 IE / 模板缺失）
    if cmd_assert("foreign", stats, out) == 0:
        print("  ✗ [interop] 注入「用 standard 的产物撞 foreign 的统计期望」未被判死")
        fails += 1
    else:
        print("  ✓ [interop] 注入已检出：standard 的产物撞 foreign 的统计期望被判死")

    # 注入 2：篡改统计行里的一条数（delivered/records 少 1）→ 必须判红
    tampered = os.path.join(workdir, "self-tampered.stats")
    text = open(stats, encoding="utf-8").read()
    if "records=3" not in text:
        print(f"  ✗ [interop] 统计行里没有 records=3，无法做篡改注入：{text.strip()[:120]}")
        fails += 1
    else:
        open(tampered, "w", encoding="utf-8").write(text.replace("records=3", "records=2", 1))
        if cmd_assert("standard", tampered, out) == 0:
            print("  ✗ [interop] 注入「篡改统计行」未被判死")
            fails += 1
        else:
            print("  ✓ [interop] 注入已检出：统计行被篡改后判死")

    # 注入 3：篡改一条记录的时间（差 1 毫秒）→ 必须判红
    rows = load_jsonl(out)
    if not rows:
        print("  ✗ [interop] 产物为空，无法做记录篡改注入")
        fails += 1
    else:
        rows[0]["time"]["last_seen_us"] += 1000
        bad_jsonl = os.path.join(workdir, "self-bad.jsonl")
        with open(bad_jsonl, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        if cmd_assert("standard", stats, bad_jsonl) == 0:
            print("  ✗ [interop] 注入「记录时间被改 1 毫秒」未被判死")
            fails += 1
        else:
            print("  ✓ [interop] 注入已检出：记录时间被改 1 毫秒即判死")

    # 注入 4：删两个 datagram（缺口 2）→ gap 的期望（缺口 1）必须判红
    rc, stats2, out2 = run("gap", "self-gap2", drop=1)
    gap1_stats = os.path.join(workdir, "self-gap1.stats")
    rc1, s1, o1 = run("gap", "self-gap1", drop=GAP_DROP_INDEX)
    if cmd_assert("gap", s1, o1) != 0:
        print("  ✗ [interop] gap 场景（删 1 个）没通过")
        fails += 1
    else:
        print("  ✓ [interop] gap 场景通过（gaps=1 lost_records=1 loss_ppm=250000）")
    if cmd_assert("gap", stats2, out2) == 0:
        print("  ✗ [interop] 注入「删 2 个 datagram」未被判死（期望是缺口 1）")
        fails += 1
    else:
        print("  ✓ [interop] 注入已检出：删 2 个 datagram 与缺口 1 的期望不符")

    print(f"\n{'✓ interop 自证通过' if fails == 0 else '✗ interop 自证失败'}")
    return 0 if fails == 0 else 2


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "emit":
        drop = None
        if "--drop" in argv:
            drop = int(argv[argv.index("--drop") + 1])
        return cmd_emit(argv[2], argv[3], drop)
    if cmd == "assert":
        return cmd_assert(argv[2], argv[3], argv[4])
    if cmd == "self-test":
        collector = argv[argv.index("--collector") + 1] if "--collector" in argv else \
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "target", "debug", "cythsec-ipfix-collect")
        workdir = argv[argv.index("--workdir") + 1] if "--workdir" in argv else "/tmp/ipfix-interop-self-test"
        return cmd_self_test(collector, workdir)
    print(f"未知子命令：{cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
