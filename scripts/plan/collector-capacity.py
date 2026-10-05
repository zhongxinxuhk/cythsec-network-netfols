#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""collector-capacity.py —— 采集集群容量模型（CYS-INF-040，可复算）。

## 这个脚本回答什么

"省网 20 Tbps 全量抓包"是量级错误（差 3~5 个数量级，见 HANDOFF §2.11 第一张表）。
换成流级遥测之后，被问的就不再是"你们能不能抓完"，而是三个可复算的数：

    20 Tbps、1:1000 采样  ⇒  多少条记录/秒  ⇒  几台采集器  ⇒  每天多少 TB

本脚本把这串算式**固化下来**：每个参数都打印出处（实测 / 需求推导 / 规划假设），
每个中间量都打印算式，任何一步都能拿计算器复核。容量结论会随参数变，但算式不变 ——
对外沟通时挡"你们到底能扛多少 G"的，是这条算式，不是一个孤零零的数字。

## 三个必带口径（少一个，容量表就是话术）

1. **采样率**：每条链路的声明值（IPFIX `samplingInterval`(34)）。声明与执行必须一致 ——
   真采样尚未实现（`CYS-TRF-053`），故本表的三档采样率是**规划值**，不是已实现能力。
2. **导出丢包率**：由采集器按 RFC 7011 §3.1 序列号缺口算出（`CYS-TRF-054` 已落地，
   `loss_ppm`）。它不改变台数，但决定"容量表里的记录量有多少真的到了"。
3. **采集覆盖率**：被观测链路带宽 ÷ 全网带宽。**这一项只能由部署清单填**，
   缺省按 100% 规划时必须显式说明，不能默认当成事实。

## 用法

    python3 scripts/plan/collector-capacity.py                 # 省网 20 Tbps / 1:1000
    python3 scripts/plan/collector-capacity.py --bandwidth-tbps 40 --sampling 2000
    python3 scripts/plan/collector-capacity.py --from-bench build/bench.json  # 用实测每台容量
    python3 scripts/plan/collector-capacity.py --json           # 机器可读
    python3 scripts/plan/collector-capacity.py --self-test      # 算术自证 + 反向注入

`--self-test` 用**手算的期望值**校验模型（不是把脚本输出抄回来），并对模型做反向注入：
把采样率漏除、把余量系数丢掉、把比特当字节 —— 三种都必须在对应算例上被期望值判死。
一条从没被判死过的期望值，与"没写"是一样的。

退出码：0 正常；1 参数错误；2 自证失败。
"""

import argparse
import json
import math
import sys

# ---------------------------------------------------------------------------
# 缺省参数与出处。**每个数都要有出处**：没有出处的数不许写进模型。
# ---------------------------------------------------------------------------
TB = 1_000_000_000_000  # 本脚本一律用十进制 TB（10^12 B），与磁盘厂商标称一致

DEFAULTS = {
    # 省网量级（需求推导：一省出口 + 汇聚 + 接入的合计口径，见 HANDOFF §2.11）。
    "bandwidth_tbps": 20.0,
    # 核心/出口建议 1:1000（业界常见区间 1:1000~1:10000）。
    "sampling": 1000,
    # 平均包长：IMIX 混合流量的经典规划值（本仓样本落在 400~750 B 区间）。
    "avg_packet_bytes": 500.0,
    # IPFIX v4 数据记录 = 57 B（本仓模板实测，见 src/ipfix/mod.rs）；
    # 报文/集合头按"一条报文装多条记录"摊薄，此处已含摊薄后的 1~2 B。
    "record_wire_bytes": 58.0,
    # 落盘每条记录字节数：列式压缩后的**规划假设**（待实测，见 HANDOFF §6）。
    "storage_bytes_per_record": 40.0,
    # 单台采集器解码能力：本机实测（cythsec-bench 用例 ipfix-collect-decode，
    # Apple M1 Pro / macOS 26 / release，2026-10-05 实测 4.62~4.69 Mrec/s）。
    # **机器相关**，换机器请用 --from-bench 传入实测值。
    "per_box_records_per_sec": 4.7e6,
    # 余量系数：实测值是"纯内存解码上界"，现场还要收包、写盘、跑指标。
    "headroom": 0.6,
    # 采样包 → 新建流的折算（上界口径 = 1.0：每个采样包最多产生一条记录）。
    "flow_per_packet": 1.0,
    "retention_days": 1.0,
    # 三档分解（合计 20 Tbps）与各档建议采样率；来源：部署形态规划，见 §2.13。
    "tiers": [
        ("核心/出口", 8.0, 400.0, 1000),
        ("汇聚", 8.0, 100.0, 500),
        ("接入", 4.0, 10.0, 100),
    ],
}

PROVENANCE = [
    ("省网带宽 20 Tbps", "规划假设（一省出口+汇聚+接入合计）", "规划"),
    ("核心采样 1:1000 / 汇聚 1:500 / 接入 1:100", "业界常见区间；**真采样未实现**（CYS-TRF-053）", "规划"),
    ("平均包长 500 B", "IMIX 经典规划值；本仓样本实测 400~750 B", "经验"),
    ("IPFIX 记录 57 B", "本仓 v4 模板逐字段求和（src/ipfix/mod.rs）", "实测"),
    ("每台 4.7 Mrec/s", "cythsec-bench `ipfix-collect-decode`（M1 Pro release，2026-10-05）", "实测(机器相关)"),
    ("落盘 40 B/记录", "列式压缩规划假设，**尚未实测**", "待实测"),
    ("余量系数 0.6", "纯内存解码上界折到端到端（收包/写盘/指标）", "规划"),
    ("导出丢包率 loss_ppm", "采集器序列号缺口（CYS-TRF-054，已落地）", "实测(可算)"),
    ("采集覆盖率", "**只能由部署清单填**；缺省 100% 是规划口径，不是事实", "待填"),
]


def parse_tiers(spec):
    """解析 `名称:带宽Tbps:单链路Gbps:采样率;...`。

    三档分解允许外部覆盖，是因为它**是规划假设不是事实**：不同省网的层级划分、
    链路规格、采样策略都不同。把假设做成参数，别人才可能拿自己的数字替换后复算 ——
    这才是"算式可复跑"的含义。
    """
    tiers = []
    for part in spec.split(";"):
        part = part.strip()
        if not part:
            continue
        fields = part.split(":")
        if len(fields) != 4:
            raise ValueError(f"分段 {part!r} 应为 `名称:带宽Tbps:单链路Gbps:采样率`")
        name = fields[0].strip()
        try:
            tbps = float(fields[1])
            link_gbps = float(fields[2])
            sampling = int(fields[3])
        except ValueError:
            raise ValueError(f"分段 {part!r} 里的带宽/链路/采样率不是数字")
        if not name or tbps <= 0 or link_gbps <= 0 or sampling < 1:
            raise ValueError(f"分段 {part!r} 的参数必须为正（采样率 ≥ 1）")
        tiers.append((name, tbps, link_gbps, sampling))
    if not tiers:
        raise ValueError("至少要有一档")
    return tiers


def packet_rate(bps, avg_packet_bytes, inject=None):
    """链路包率（pps）= 带宽 ÷ (平均包长 × 8)。"""
    if avg_packet_bytes <= 0:
        raise ValueError("平均包长必须为正")
    if inject == "bytes-for-bits":
        # 反向注入：把比特当字节（少乘 8）—— 一个非常容易犯的错。
        return bps / avg_packet_bytes
    return bps / (avg_packet_bytes * 8.0)


def records_per_sec(bps, sampling, avg_packet_bytes, flow_per_packet=1.0, inject=None):
    """记录率上界（条/秒）= 链路包率 ÷ 采样率 × 每采样包折算记录数。

    取 1.0 是**保守**：短流居多时，每个采样包都可能新建一条流；长流（大象流）主导时
    实际记录率会明显更低。规划按上界走，才不会在突发时把采集器打爆。
    """
    if sampling < 1:
        raise ValueError("采样率必须 ≥ 1")
    pps = packet_rate(bps, avg_packet_bytes, inject)
    if inject == "drop-sampling":
        # 反向注入：漏除采样率（把全量包率当记录率）—— 差 1000 倍的量级错误。
        return pps * flow_per_packet
    return pps / sampling * flow_per_packet


def raw_capture_pb_per_day(bps):
    """逐包全量落盘的字节量（PB/天，1 PB = 10^15 B）= 带宽 ÷ 8 × 86400 ÷ 10^15。

    这是"逐包全量在省网是量级错误"这句话里那个 108 PB/天 的算式 —— 把它写进脚本
    而不是只写在文档里，是因为这类量级结论**最容易被口口相传地记错一位数**。
    """
    return bps / 8.0 * 86400.0 / 1e15


def boxes(records, per_box, headroom, inject=None):
    """采集器台数 = ceil(总记录率 ÷ (每台容量 × 余量))。

    向上取整是**刻意的**：容量规划里"差一点"就是丢记录，且丢的是导出侧的记录量，
    会直接污染丢包率口径（见 §2.13 三个必带口径）。
    """
    if per_box <= 0:
        raise ValueError("每台容量必须为正")
    if not (0 < headroom <= 1.0):
        raise ValueError("余量系数必须在 (0, 1] 内")
    eff = per_box if inject == "no-headroom" else per_box * headroom
    return int(math.ceil(records / eff)) if records > 0 else 0


def storage_tb_per_day(records, bytes_per_record, retention_days=1.0):
    """落盘量（TB/天，10^12 B）= 记录率 × 86400 × 每条字节 ÷ 10^12 ÷ 保留天数系数。"""
    if bytes_per_record <= 0:
        raise ValueError("每条记录字节数必须为正")
    return records * 86400.0 * bytes_per_record / TB / max(retention_days, 1e-9)


def model(args, inject=None):
    """跑一遍模型：主算例 + 三档分解 + 三个必带口径。"""
    bps = args.bandwidth_tbps * 1e12
    recs = records_per_sec(bps, args.sampling, args.avg_packet_bytes, args.flow_per_packet, inject)
    nbox = boxes(recs, args.per_box_records_per_sec, args.headroom, inject)
    tb_day = storage_tb_per_day(recs, args.storage_bytes_per_record, args.retention_days)
    wire_bps = recs * args.record_wire_bytes * 8.0  # 记录流占用的带宽（含 IPFIX 头摊薄）
    coverage = (
        None
        if args.observed_bandwidth_tbps is None
        else args.observed_bandwidth_tbps / args.bandwidth_tbps
    )
    tiers = []
    for name, tbps, link_gbps, sampling in args.tiers:
        t_bps = tbps * 1e12
        t_recs = records_per_sec(t_bps, sampling, args.avg_packet_bytes, args.flow_per_packet, inject)
        tiers.append(
            {
                "name": name,
                "tbps": tbps,
                "link_gbps": link_gbps,
                "link_count": int(round(tbps * 1000.0 / link_gbps)),
                "sampling": sampling,
                "records_per_sec": t_recs,
                "boxes": boxes(t_recs, args.per_box_records_per_sec, args.headroom, inject),
                "tb_per_day": storage_tb_per_day(
                    t_recs, args.storage_bytes_per_record, args.retention_days
                ),
            }
        )
    raw_pb = raw_capture_pb_per_day(bps)
    flow_pb = tb_day / 1000.0  # TB → PB（1 PB = 1000 TB）
    return {
        "raw_capture_pb_per_day": raw_pb,
        "flow_pb_per_day": flow_pb,
        # 逐包全量 ÷ 流级 = 倍数；文档里说"差 3~5 个数量级"，这里给出它自己的算法。
        "raw_over_flow_ratio": (raw_pb / flow_pb) if flow_pb > 0 else None,
        "bandwidth_tbps": args.bandwidth_tbps,
        "sampling": args.sampling,
        "records_per_sec": recs,
        "records_per_day": recs * 86400.0,
        "per_box_effective": args.per_box_records_per_sec
        * (1.0 if inject == "no-headroom" else args.headroom),
        "per_box_records_per_sec": args.per_box_records_per_sec,
        "headroom": args.headroom,
        "boxes": nbox,
        "tb_per_day": tb_day,
        "record_wire_gbps": wire_bps / 1e9,
        "export_loss_ppm": args.export_loss_ppm,
        "delivered_records_per_sec": recs * (1.0 - (args.export_loss_ppm or 0) / 1e6),
        "coverage": coverage,
        "observed_bandwidth_tbps": args.observed_bandwidth_tbps,
        "tiers": tiers,
    }


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def fmt(n, unit="", nd=2):
    if n is None:
        return "—"
    return f"{n:,.{nd}f}{unit}"


def print_report(args, m):
    print("采集集群容量模型（CYS-INF-040）—— 算式可复算，参数均有出处")
    print("=" * 78)
    print("参数与出处：")
    for name, src, kind in PROVENANCE:
        print(f"  · {name:<28} [{kind}] {src}")
    print()
    print(f"主算例：省网 {fmt(args.bandwidth_tbps, ' Tbps')}，采样 1:{args.sampling}")
    print("-" * 78)
    pps = packet_rate(args.bandwidth_tbps * 1e12, args.avg_packet_bytes)
    print(f"  1) 链路包率        = {fmt(args.bandwidth_tbps, ' Tbps')} ÷ ({args.avg_packet_bytes:g} B × 8)")
    print(f"                     = {fmt(pps / 1e9, ' Gpps')}")
    print(f"  2) 采样后包率      = 上式 ÷ {args.sampling} = {fmt(pps / args.sampling / 1e6, ' Mpps')}")
    print(
        f"  3) 记录率上界      = 采样后包率 × {args.flow_per_packet:g}（每采样包最多一条记录）"
        f" = {fmt(m['records_per_sec'] / 1e6, ' Mrec/s')}"
    )
    print(
        f"  4) 每台有效容量    = {fmt(args.per_box_records_per_sec / 1e6, ' Mrec/s')} × 余量 "
        f"{args.headroom:g} = {fmt(m['per_box_effective'] / 1e6, ' Mrec/s')}"
    )
    print(
        f"  5) 采集器台数      = ceil({fmt(m['records_per_sec'] / 1e6, ' Mrec/s')} ÷ "
        f"{fmt(m['per_box_effective'] / 1e6, ' Mrec/s')}) = **{m['boxes']} 台**"
    )
    print(
        f"  6) 落盘量/天       = {fmt(m['records_per_sec'] / 1e6, ' Mrec/s')} × 86400 × "
        f"{args.storage_bytes_per_record:g} B = **{fmt(m['tb_per_day'], ' TB/天')}**"
        f"（保留 {args.retention_days:g} 天）"
    )
    print(
        f"  7) 记录流带宽      = {fmt(m['records_per_sec'] / 1e6, ' Mrec/s')} × "
        f"{args.record_wire_bytes:g} B/条 = {fmt(m['record_wire_gbps'] / 1000.0, ' Gbps', 3)}"
        "（含 IPFIX 头摊薄，用于核对导出通道本身不是瓶颈）"
    )
    print()
    print("三档分解（同样的 20 Tbps，越靠边缘采样越密 ⇒ 记录量越大）：")
    print(
        f"  {'档位':<10} {'带宽':>8} {'单链路':>8} {'链路数':>6} {'采样':>7} "
        f"{'记录/秒':>12} {'采集器':>7} {'TB/天':>9}"
    )
    for t in m["tiers"]:
        print(
            f"  {t['name']:<10} {t['tbps']:>6.1f}T {t['link_gbps']:>6.0f}G {t['link_count']:>6} "
            f"{'1:' + str(t['sampling']):>7} {fmt(t['records_per_sec'] / 1e6, ' M'):>12} "
            f"{t['boxes']:>7} {fmt(t['tb_per_day']):>9}"
        )
    print(
        f"  {'合计':<10} {sum(t['tbps'] for t in m['tiers']):>6.1f}T {'':>15} {'':>7} "
        f"{fmt(sum(t['records_per_sec'] for t in m['tiers']) / 1e6, ' M'):>12} "
        f"{sum(t['boxes'] for t in m['tiers']):>7} {fmt(sum(t['tb_per_day'] for t in m['tiers'])):>9}"
    )
    print()
    print("逐包全量 vs 流级（这就是「省网不能靠抓包」那个量级的算式）：")
    print(
        f"  · 逐包全量落盘    = {fmt(args.bandwidth_tbps, ' Tbps')} ÷ 8 × 86400 "
        f"= **{fmt(m['raw_capture_pb_per_day'], ' PB/天')}**"
        "（1 PB = 10^15 B；不含索引/检索开销，属于下限）"
    )
    print(
        f"  · 流级落盘        = {fmt(m['tb_per_day'], ' TB/天')}"
        f" = {fmt(m['flow_pb_per_day'], ' PB/天', 4)}"
    )
    print(
        f"  · 倍数            = {fmt(m['raw_capture_pb_per_day'], ' PB')} ÷ "
        f"{fmt(m['flow_pb_per_day'], ' PB', 4)} = **{fmt(m['raw_over_flow_ratio'], ' 倍', 1)}**"
        f" ⇒ 相差 {fmt(math.log10(m['raw_over_flow_ratio']), ' 个数量级')}"
    )
    print(
        "    结论：**逐包全量在省网是量级错误**，再优化也到不了；逐包只在少数关键点位"
        "（DPI / 取证 / 单点 10~100G）保留。见 §2.11。"
    )
    print()
    print("三个必带口径（缺一个，上面这张表就是话术）：")
    print(
        f"  ① 采样率：核心 1:1000 / 汇聚 1:500 / 接入 1:100 —— **规划值**。"
        "真采样尚未实现（CYS-TRF-053），当前导出侧如实声明 IE 34 = 1（未采样）。"
    )
    if args.export_loss_ppm is None:
        print(
            "  ② 导出丢包率：**未填**。用采集器实测值填（cythsec-ipfix-collect 统计行的 loss_ppm，"
            "CYS-TRF-054 已落地）。"
        )
    else:
        print(
            f"  ② 导出丢包率：{args.export_loss_ppm} ppm ⇒ 实收 "
            f"{fmt(m['delivered_records_per_sec'] / 1e6, ' Mrec/s')}"
            f"（口径只含「导出侧链路丢失」，详见 §2.12 边界）"
        )
    if m["coverage"] is None:
        print(
            f"  ③ 采集覆盖率：**未填**（缺省按 100% 规划，这不是事实）。"
            f"实际值 = 已观测链路带宽 ÷ {fmt(args.bandwidth_tbps, ' Tbps')}。"
        )
    else:
        print(
            f"  ③ 采集覆盖率：{fmt(m['observed_bandwidth_tbps'], ' Tbps')} ÷ "
            f"{fmt(args.bandwidth_tbps, ' Tbps')} = {m['coverage'] * 100:.1f}%"
            f"（**盲区 {100 - m['coverage'] * 100:.1f}% 的链路不在观测内**）"
        )
    print()
    print("口径说明：")
    print("  · 记录率取**上界**（每个采样包折算一条记录）：规划按上界走才不会被突发打爆；")
    print("    大象流主导时实际记录率明显更低（长流只在超时/结束时出一条）。")
    print("  · 台数是**解码能力**的下限估计：现场还要收包、写盘、跑指标，故有余量系数；")
    print("    在线模式当前**无法设置 SO_RCVBUF**（std 无接口），高突发下需要更大的余量（§6）。")
    print("  · 落盘字节数是**规划假设**（列式压缩），尚未实测 —— 真做容量承诺前必须先量它。")


# ---------------------------------------------------------------------------
# 自证：手算期望值 + 反向注入
# ---------------------------------------------------------------------------
def _args_for_selftest(**over):
    base = dict(
        bandwidth_tbps=DEFAULTS["bandwidth_tbps"],
        sampling=DEFAULTS["sampling"],
        avg_packet_bytes=DEFAULTS["avg_packet_bytes"],
        record_wire_bytes=DEFAULTS["record_wire_bytes"],
        storage_bytes_per_record=DEFAULTS["storage_bytes_per_record"],
        per_box_records_per_sec=DEFAULTS["per_box_records_per_sec"],
        headroom=DEFAULTS["headroom"],
        flow_per_packet=DEFAULTS["flow_per_packet"],
        retention_days=DEFAULTS["retention_days"],
        tiers=DEFAULTS["tiers"],
        observed_bandwidth_tbps=None,
        export_loss_ppm=None,
    )
    base.update(over)
    return argparse.Namespace(**base)


def _check(label, got, want, tol=1e-9):
    """期望值来自**手算**（下面的注释给出算式），不是脚本输出。"""
    ok = (abs(got - want) <= tol * max(1.0, abs(want))) if isinstance(want, float) else got == want
    print(f"    {'✓' if ok else '✗'} {label}: {got} （手算 {want}）")
    return ok


def self_test():
    ok = True
    print("==> 模型自证（期望值全部手算，不是把输出抄回来）")

    # 算例 A：10 Tbps、500 B、1:1000 → 包率 10e12/4000 = 2.5 Gpps；
    #   采样后 2.5 Mpps；记录率上界 2.5 Mrec/s；
    #   每台有效 = 4.7e6 × 0.6 = 2.82e6 → 台数 ceil(2.5/2.82) = 1；
    #   落盘 = 2.5e6 × 86400 × 40 B = 8.64e12 B = 8.64 TB/天。
    m = model(_args_for_selftest(bandwidth_tbps=10.0))
    ok &= _check("A 记录率上界（Mrec/s）", m["records_per_sec"] / 1e6, 2.5)
    ok &= _check("A 台数", m["boxes"], 1)
    ok &= _check("A 落盘（TB/天）", m["tb_per_day"], 8.64)

    # 算例 B：采样 1:100（密 10 倍）→ 25 Mrec/s → 台数 ceil(25/2.82) = 9；
    #   落盘 2.5e6 × 10 × 86400 × 40 = 8.64e13 B = 86.4 TB/天。
    m = model(_args_for_selftest(bandwidth_tbps=10.0, sampling=100))
    ok &= _check("B 记录率（Mrec/s）", m["records_per_sec"] / 1e6, 25.0)
    ok &= _check("B 台数", m["boxes"], 9)
    ok &= _check("B 落盘（TB/天）", m["tb_per_day"], 86.4)

    # 算例 C：省网 20 Tbps / 1:1000（验收标准点名的那个）→ 5 Mrec/s；
    #   台数 ceil(5/2.82) = 2；落盘 5e6 × 86400 × 40 = 1.728e13 = 17.28 TB/天。
    m = model(_args_for_selftest())
    ok &= _check("C 记录率（Mrec/s）", m["records_per_sec"] / 1e6, 5.0)
    ok &= _check("C 台数", m["boxes"], 2)
    ok &= _check("C 落盘（TB/天）", m["tb_per_day"], 17.28)

    # 算例 D：边界（整数除法的经典错处）。每台有效容量 2.82e6 恰好用满 → 1 台；
    #   多一条记录（11.281 Tbps）→ 必须变 2 台（ceil 而不是 round/截断）。
    #   11.28 Tbps → 11.28e12/4000/1000 = 2.82e6 条/s。
    m = model(_args_for_selftest(bandwidth_tbps=11.28))
    ok &= _check("D 恰好打满 → 台数", m["boxes"], 1)
    m = model(_args_for_selftest(bandwidth_tbps=11.281))
    ok &= _check("D 超一条 → 台数", m["boxes"], 2)

    # 算例 E：平均包长翻倍 → 包率减半 → 记录率减半（相对关系与机器无关）。
    m1 = model(_args_for_selftest(bandwidth_tbps=10.0))
    m2 = model(_args_for_selftest(bandwidth_tbps=10.0, avg_packet_bytes=1000.0))
    ok &= _check("E 包长 ×2 ⇒ 记录率 ×0.5", m2["records_per_sec"] / m1["records_per_sec"], 0.5)

    # 算例 F：覆盖率（8/20）与丢包率折算。
    m = model(_args_for_selftest(observed_bandwidth_tbps=8.0, export_loss_ppm=1000))
    ok &= _check("F 覆盖率", m["coverage"], 0.4)
    ok &= _check("F 丢包 1000 ppm 后实收（Mrec/s）", m["delivered_records_per_sec"] / 1e6, 5.0 * 0.999)

    # 算例 G：逐包全量对照（§2.11 那张表里 108 PB/天 的复算）。
    #   10 Tbps ÷ 8 × 86400 = 1.08e14 B = 108 PB/天；
    #   流级 10 Tbps@1:1000 = 2.5 Mrec/s → 8.64 TB/天 = 0.00864 PB/天；
    #   倍数 = 108 ÷ 0.00864 = 12500（≈4.1 个数量级）—— 与文档"差 3~5 个数量级"一致。
    m = model(_args_for_selftest(bandwidth_tbps=10.0))
    ok &= _check("G 逐包全量（PB/天）", m["raw_capture_pb_per_day"], 108.0)
    ok &= _check("G 流级（PB/天）", m["flow_pb_per_day"], 0.00864)
    ok &= _check("G 倍数", m["raw_over_flow_ratio"], 12500.0)

    # ---- 反向注入：把模型改坏，期望值必须判死 ----
    # 这三条才是这段自证的价值：如果期望值对错误模型照样通过，它就只是个装饰品。
    print("  -- 反向注入（改坏模型，期望值必须判死）--")
    injections = [
        ("漏除采样率（把全量包率当记录率）", {"bandwidth_tbps": 10.0}, "drop-sampling", "records_per_sec", 2.5e6),
        ("丢掉余量系数（台数偏乐观）", {"bandwidth_tbps": 10.0, "sampling": 100}, "no-headroom", "boxes", 9),
        ("把比特当字节（少乘 8）", {"bandwidth_tbps": 10.0}, "bytes-for-bits", "records_per_sec", 2.5e6),
    ]
    for label, over, inject, key, want in injections:
        bad = model(_args_for_selftest(**over), inject=inject)
        got = bad[key]
        caught = abs(got - want) > 1e-9 * max(1.0, abs(want))
        print(f"    {'✓' if caught else '✗'} 注入「{label}」→ {key}={got:g}，与手算 {want:g} 不符（被判死）")
        ok &= caught

    print(f"\n{'✓ 模型自证通过' if ok else '✗ 模型自证失败'}")
    return 0 if ok else 2


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="采集集群容量模型（CYS-INF-040）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--bandwidth-tbps", type=float, default=DEFAULTS["bandwidth_tbps"])
    ap.add_argument("--sampling", type=int, default=DEFAULTS["sampling"])
    ap.add_argument("--avg-packet-bytes", type=float, default=DEFAULTS["avg_packet_bytes"])
    ap.add_argument("--record-wire-bytes", type=float, default=DEFAULTS["record_wire_bytes"])
    ap.add_argument(
        "--storage-bytes-per-record", type=float, default=DEFAULTS["storage_bytes_per_record"]
    )
    ap.add_argument(
        "--per-box-records-per-sec", type=float, default=DEFAULTS["per_box_records_per_sec"]
    )
    ap.add_argument("--headroom", type=float, default=DEFAULTS["headroom"])
    ap.add_argument("--flow-per-packet", type=float, default=DEFAULTS["flow_per_packet"])
    ap.add_argument("--retention-days", type=float, default=DEFAULTS["retention_days"])
    ap.add_argument("--observed-bandwidth-tbps", type=float, default=None)
    ap.add_argument("--export-loss-ppm", type=int, default=None)
    ap.add_argument(
        "--from-bench",
        metavar="bench.json",
        help="用 cythsec-bench --json 的实测值覆盖 --per-box-records-per-sec（用例 ipfix-collect-decode）",
    )
    ap.add_argument(
        "--tiers",
        default=None,
        help="三档分解，格式 `名称:带宽Tbps:单链路Gbps:采样率;...`（缺省用内置规划值）",
    )
    ap.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    ap.add_argument("--self-test", action="store_true", help="算术自证 + 反向注入")
    ap.add_argument("--inject", default=None, help=argparse.SUPPRESS)  # 仅供自证使用的故障注入
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.from_bench:
        try:
            with open(args.from_bench, encoding="utf-8") as fh:
                rows = [json.loads(line) for line in fh if line.strip().startswith("{")]
        except OSError as exc:
            print(f"读 --from-bench 失败：{exc}", file=sys.stderr)
            return 1
        hit = [r for r in rows if r.get("case") == "ipfix-collect-decode"]
        if not hit:
            print(
                f"--from-bench 里没有 ipfix-collect-decode 用例（{args.from_bench}）；"
                "先跑 cythsec-bench --json",
                file=sys.stderr,
            )
            return 1
        args.per_box_records_per_sec = float(hit[0]["measured"]) * 1e6
        print(
            f"（每台容量取实测：{hit[0]['measured']} Mrec/s，来自 {args.from_bench} —— "
            "该值是**机器相关**的）"
        )

    if args.tiers:
        try:
            args.tiers = parse_tiers(args.tiers)
        except ValueError as exc:
            print(f"参数错误：--tiers {exc}", file=sys.stderr)
            return 1
    else:
        args.tiers = DEFAULTS["tiers"]

    if args.bandwidth_tbps <= 0 or args.avg_packet_bytes <= 0 or args.sampling < 1:
        print("参数错误：带宽/包长必须为正，采样率 ≥ 1", file=sys.stderr)
        return 1
    if not (0 < args.headroom <= 1.0):
        print("参数错误：--headroom 必须在 (0, 1] 内", file=sys.stderr)
        return 1

    m = model(args, inject=args.inject)
    if args.json:
        print(json.dumps(m, ensure_ascii=False, indent=1))
    else:
        print_report(args, m)
    return 0


if __name__ == "__main__":
    sys.exit(main())
