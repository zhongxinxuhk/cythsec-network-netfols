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
   执行侧已有**流级采样器**（`CYS-TRF-053`，`--sample 1:N`，IE 34 取自同一份配置，见 §2.15），
   但"哪一层用哪个采样率"仍是**规划值**：本表的三档是规划口径，不是已实现能力。
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
import os
import sys

# ---------------------------------------------------------------------------
# 缺省参数与出处。**每个数都要有出处**：没有出处的数不许写进模型。
# ---------------------------------------------------------------------------
TB = 1_000_000_000_000  # 本脚本一律用十进制 TB（10^12 B），与磁盘厂商标称一致

# **已被实测否掉的旧规划假设**（列式压缩后 40 B/记录）。保留它只有一个用途：
# 反向注入 —— 让"假装读了测量产物、实际用回这个假设"的实现被自证判死。
# 不要在报告或文档里再引用这个数当规划值（实测是 84.1 B/记录 gzip / 1184 B 未压缩）。
PLANNING_ASSUMPTION_BYTES = 40.0

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
    # 落盘每条记录字节数：**已实测**（CYS-INF-041，见 docs/planning/measurements/storage-ratio.json）。
    # 实测规划值 84.1 B/记录 = gzip(JSONL) 两档测量取**较差端**（真实向量语料 84.1 / 同质压测语料 21.8）；
    # 未压缩 JSONL 的实测上界是 1184 B/记录。旧的"40 B/记录列式压缩假设"实测不成立（低估约 2~27×）。
    # 2026-10-23 记录契约 v2（`CYS-STO-002`/`007`：tcp 块 +6 个可空列）后重测：79.4→84.1（+5.9%）、
    # 1066→1184（+11.1%）。这两个数是**跟着列契约走的**，不是一劳永逸的物理常数。
    # 该值可被 --storage-measured 覆盖（默认就指向上面那份产物），也可用
    # --storage-bytes-per-record 直接给数。
    "storage_bytes_per_record": 84.1,
    "storage_measured": "docs/planning/measurements/storage-ratio.json",
    # 列式（ClickHouse MergeTree + `001_flows.sql` 的按列 CODEC）实测规划值：
    # 85.86 B/记录 = 两档**容量可用**的合成语料（20,182 / 20,000 条）取较差端
    # （同质 5.91 / 多样 85.86），产物 `measurements/columnar.json`。
    # 2026-10-23 记录契约 v2 后重测：78.50→85.86（多样档，+9.4%）、5.11→5.91（同质档，+15.7%）。
    # 同质档看着没变是假的 —— 它同样涨了 15.7%，只是绝对值小到被 part 开销掩盖。
    # 引用它必须带上两条口径：① 它依赖这份 DDL 的 CODEC/LowCardinality 选择（换 DDL 要重测）
    # ② 语料是本仓生成器造的，现场字段分布必须现场重标定。
    "columnar_bytes_per_record": 85.86,
    "columnar_measured": "docs/planning/measurements/columnar.json",
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
    ("核心采样 1:1000 / 汇聚 1:500 / 接入 1:100",
     "业界常见区间；**执行侧已实现且声明与执行一致**（CYS-TRF-053），分层取值仍是规划", "规划"),
    ("平均包长 500 B", "IMIX 经典规划值；本仓样本实测 400~750 B", "经验"),
    ("IPFIX 记录 57 B", "本仓 v4 模板逐字段求和（src/ipfix/mod.rs）", "实测"),
    ("每台 4.7 Mrec/s", "cythsec-bench `ipfix-collect-decode`（M1 Pro release，2026-10-05）", "实测(机器相关)"),
    ("落盘 84.1 B/记录", "实测（CYS-INF-041）：gzip(JSONL) 多次测量取**较差端**；产物见 measurements/"
     "（记录契约 v2 后重测；列数变了这个数就变）", "实测"),
    ("落盘 1184 B/记录（上界）", "实测：未压缩 JSONL（JSONL 就是当前真实落盘格式；v2 加列后重测）", "实测"),
    ("落盘 85.86 B/记录（列式）",
     "实测（CYS-INF-041 收尾）：ClickHouse MergeTree + 本仓 DDL 的按列 CODEC，"
     "两档合成语料取较差端；换 DDL 必须重测，语料是合成的 ⇒ 现场要重标定", "实测(合成语料)"),
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


def storage_provenance(args):
    """落盘参数的口径说明 —— 每个数都要带着"从哪来"出现在报告里。"""
    if getattr(args, "storage_measured_used", None):
        fmt_note = {"gzip": "gzip(JSONL) 多次测量取较差端",
                    "raw": "未压缩 JSONL（上界）",
                    "columnar": "列式（真实 ClickHouse + 本仓 DDL 的按列 CODEC）取较差端"}.get(
            getattr(args, "storage_format", "gzip"), args.storage_format)
        caveat = getattr(args, "storage_caveat", None)
        return (f"实测（{args.storage_measured_used}，样本 "
                f"{getattr(args, 'storage_measured_records', '?')} 条，{fmt_note}）"
                + (f"；口径：{caveat}" if caveat else ""))
    if args.storage_bytes_per_record in (DEFAULTS["storage_bytes_per_record"],
                                         DEFAULTS["columnar_bytes_per_record"]):
        return "内置实测默认值（本次**未复核**测量产物）"
    return "**命令行指定**（无出处 —— 引用这个数的人必须自己说明依据）"


def load_storage_measurement(path, fmt="gzip", inject=None):
    """读 `measure-storage.py` 的测量产物，返回 (字节/记录, 样本量)。

    **不许**在字段缺失/样本为 0 时"退回默认值继续算"：那会把一个没核验过的数
    伪装成实测值。宁可直接失败（调用方转成非零退出）。
    """
    with open(path, encoding="utf-8") as fh:
        m = json.load(fh)
    if inject == "trust-planning":
        # 注入：假装读了产物，实际用回**旧的 40 B/记录规划假设** —— 自证必须判死这种情况
        # （算例 H 的期望是 33.5664 TB/天，注入后会变成 17.28，于是主断言变红）
        return PLANNING_ASSUMPTION_BYTES, m.get("records", 0) or m.get("total_records", 0)
    key = "gzip_bytes_per_record" if fmt == "gzip" else "raw_bytes_per_record"
    if key not in m or m[key] is None:
        raise ValueError(f"{path} 里没有 {key}（用 measure-storage.py 产出？）")
    # 单次测量写 `records`，多次合并的规划产物写 `total_records`（两者都必须是正数）
    records = m.get("records", m.get("total_records"))
    if not records or int(records) <= 0:
        raise ValueError(f"{path} 的样本量为 0 —— 空语料上的平均数不能用")
    return float(m[key]), int(records)


def load_columnar_measurement(path, inject=None):
    """读 `measure-columnar.py --combine` 的产物（`columnar-plan/1`）。

    与 gzip 档同一条红线：**字段缺失就抛错，不许退回默认值继续算**。
    列式这一档额外要求每条语料都带着 `plan_bpr` —— 它意味着"这一档真的落进过
    真实 ClickHouse 并数过 part 目录的字节"。少了它，85.86 就又是一句假设。
    """
    with open(path, encoding="utf-8") as fh:
        m = json.load(fh)
    if inject == "columnar-trust-assumption":
        # 注入：假装读了产物，实际用回旧的"列式 40 B/记录"假设
        return PLANNING_ASSUMPTION_BYTES, 0
    if m.get("schema") != "columnar-plan/1":
        raise ValueError(f"{path} 的 schema 不是 columnar-plan/1（产物版本对不上，拒绝读数）")
    v = m.get("plan_bytes_per_record")
    if v is None or float(v) <= 0:
        raise ValueError(f"{path} 没有正的 plan_bytes_per_record")
    corpora = m.get("corpora") or []
    if not corpora:
        raise ValueError(f"{path} 里没有语料明细 —— 平均数没有分母，不能用")
    total = 0
    for c in corpora:
        if not c.get("plan_bpr") or not c.get("records"):
            raise ValueError(f"{path} 的语料「{c.get('label')}」没有 ClickHouse 实测档或样本为 0")
        total += int(c["records"])
    if not m.get("not_a_claim"):
        raise ValueError(f"{path} 没带「这个数依赖 DDL 的 CODEC 选择」这句口径 —— 拒绝裸引用")
    if inject == "columnar-drop-caveat":
        return float(v), total, None      # 注入：把口径丢掉
    return float(v), total, m.get("recalibrate_on_site") or "未写口径"


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
    storage_prov = storage_provenance(args)
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
        "storage_bytes_per_record": args.storage_bytes_per_record,
        "storage_provenance": storage_prov,
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
    print(f"       口径：{m['storage_provenance']}")
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
        f"  ① 采样率：核心 1:1000 / 汇聚 1:500 / 接入 1:100 —— **规划值**（分层取值未定）。"
        "执行侧已实现流级采样且 IE 34 与执行同源（CYS-TRF-053）；未开 `--sample` 时如实声明 1。"
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
    # 这一行以前写死成"落盘字节数是规划假设（列式压缩），尚未实测"，
    # 而 CYS-INF-041 / 列式实测之后两个档都已经是实测值了 —— 写死的口径句会腐烂，
    # 所以它必须由本次真正用了哪个来源来决定。
    prov = m.get("storage_provenance") or ""
    if prov.startswith("实测"):
        print(f"  · 落盘字节/记录 = {m['storage_bytes_per_record']:g} B 是**实测值**（{prov}）；"
              "不是「列式能压到几十 B」那种假设。")
    elif "命令行指定" in prov:
        print(f"  · 落盘字节/记录 = {m['storage_bytes_per_record']:g} B 由**命令行指定，无出处** —— "
              "引用这张表的人必须自己说明这个数的依据。")
    else:
        print(f"  · 落盘字节/记录 = {m['storage_bytes_per_record']:g} B 是**内置实测默认值**，"
              "但本次没有复核测量产物（要复核跑 --verify-defaults）。")


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
    m = model(_args_for_selftest(bandwidth_tbps=10.0, storage_bytes_per_record=40.0))
    ok &= _check("A 记录率上界（Mrec/s）", m["records_per_sec"] / 1e6, 2.5)
    ok &= _check("A 台数", m["boxes"], 1)
    # 落盘期望**显式钉住 40 B/记录**（不是为了沿用旧假设，而是为了让"算法"与"落盘参数"
    # 两件事分开验：这里验的是乘法，落盘参数本身由算例 H 用实测产物验）。
    ok &= _check("A 落盘（TB/天，@40 B）", m["tb_per_day"], 8.64)

    # 算例 B：采样 1:100（密 10 倍）→ 25 Mrec/s → 台数 ceil(25/2.82) = 9；
    #   落盘 2.5e6 × 10 × 86400 × 40 = 8.64e13 B = 86.4 TB/天。
    m = model(_args_for_selftest(bandwidth_tbps=10.0, sampling=100, storage_bytes_per_record=40.0))
    ok &= _check("B 记录率（Mrec/s）", m["records_per_sec"] / 1e6, 25.0)
    ok &= _check("B 台数", m["boxes"], 9)
    ok &= _check("B 落盘（TB/天，@40 B）", m["tb_per_day"], 86.4)

    # 算例 C：省网 20 Tbps / 1:1000（验收标准点名的那个）→ 5 Mrec/s；
    #   台数 ceil(5/2.82) = 2；落盘 5e6 × 86400 × 40 = 1.728e13 = 17.28 TB/天。
    m = model(_args_for_selftest(storage_bytes_per_record=40.0))
    ok &= _check("C 记录率（Mrec/s）", m["records_per_sec"] / 1e6, 5.0)
    ok &= _check("C 台数", m["boxes"], 2)
    ok &= _check("C 落盘（TB/天，@40 B）", m["tb_per_day"], 17.28)

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

    # 算例 G：逐包全量对照（§2.11 那张表里 108 PB/天 的复算），落盘取**实测规划值 84.1 B**
    #   （记录契约 v2 后重测；这里**不沿用** v1 的 79.4 —— 沿用就等于把"实测"过期成"我记得"）。
    #   10 Tbps ÷ 8 × 86400 = 1.08e14 B = 108 PB/天；
    #   流级 10 Tbps@1:1000 = 2.5 Mrec/s → 2.5e6 × 86400 × 84.1 = 1.81656e13 B
    #     = 0.0181656 PB/天；
    #   倍数 = 108 ÷ 0.0181656 = 5945.3（≈3.8 个数量级）—— 比 40 B 假设下的 12500 小一半，
    #   也**比 v1 实测的 6297 小**：字节数变大，宣传口径要跟着改小。
    m = model(_args_for_selftest(bandwidth_tbps=10.0, storage_bytes_per_record=84.1))
    ok &= _check("G 逐包全量（PB/天）", m["raw_capture_pb_per_day"], 108.0)
    ok &= _check("G 流级（PB/天，@84.1 B）", m["flow_pb_per_day"], 0.0181656)
    ok &= _check("G 倍数（@84.1 B）", m["raw_over_flow_ratio"], 5945.30, tol=0.01)

    # 算例 H：读测量产物接线（CYS-INF-041）。**自造**一份测量产物，不依赖仓库文件，
    #   于是这一条在任何 cwd 下都能跑；期望值仍然是手算：
    #   77.7 B/记录 × 5e6 记录/s × 86400 ÷ 1e12 = 33.5664 TB/天。
    import tempfile as _tf

    with _tf.TemporaryDirectory() as _d:
        art = os.path.join(_d, "measure.json")
        with open(art, "w", encoding="utf-8") as fh:
            json.dump({"label": "自造", "records": 1234,
                       "raw_bytes_per_record": 1000.0,
                       "gzip_bytes_per_record": 77.7}, fh)
        val, n = load_storage_measurement(art, "gzip")
        ok &= _check("H 读数（B/记录）", val, 77.7)
        ok &= _check("H 样本量", n, 1234)
        val_raw, _n = load_storage_measurement(art, "raw")
        ok &= _check("H raw 档（B/记录）", val_raw, 1000.0)
        args_h = _args_for_selftest(storage_bytes_per_record=val)
        m = model(args_h)
        ok &= _check("H 落盘（TB/天，@77.7 B）", m["tb_per_day"], 33.5664)
        # 注入「假装读了产物、实际用回旧的 40 B 假设」→ 必须判死
        bad, _n = load_storage_measurement(art, "gzip", inject="trust-planning")
        m_bad = model(_args_for_selftest(storage_bytes_per_record=bad))
        ok &= _check("H 注入 trust-planning 后落盘（TB/天）", m_bad["tb_per_day"], 17.28)
        # 字段缺失 / 样本为 0 的产物必须抛错（不许"退回默认值继续算"）
        for _name, _body in (("缺字段", {"records": 5}), ("零样本", {"records": 0,
                                                              "gzip_bytes_per_record": 10.0})):
            bad_art = os.path.join(_d, f"{_name}.json")
            with open(bad_art, "w", encoding="utf-8") as fh:
                json.dump(_body, fh)
            try:
                load_storage_measurement(bad_art, "gzip")
                ok &= _check(f"H {_name} 必须抛错", False, True)
            except ValueError:
                ok &= _check(f"H {_name} 抛错（不给伪数）", True, True)

    # 算例 I：列式实测产物接线（CYS-INF-041 收尾）。期望值仍是手算：
    #   85.86 B/记录 × 5e6 记录/s × 86400 ÷ 1e12 = 37.09152 TB/天。
    #   （ fixture 用的就是当前列契约 v2 的产物值，不再拿 v1 的 78.5 当例子。）
    with _tf.TemporaryDirectory() as _d:
        cart = os.path.join(_d, "columnar.json")
        with open(cart, "w", encoding="utf-8") as fh:
            json.dump({"schema": "columnar-plan/1", "plan_bytes_per_record": 85.86,
                       "not_a_claim": "依赖 DDL 的 CODEC 选择",
                       "recalibrate_on_site": "语料是合成的",
                       "corpora": [{"label": "多样", "records": 20000, "plan_bpr": 85.86},
                                  {"label": "同质", "records": 20182, "plan_bpr": 5.91}]}, fh)
        val_c, n_c, caveat = load_columnar_measurement(cart)
        ok &= _check("I 读数（B/记录）", val_c, 85.86)
        ok &= _check("I 样本量（两档合计）", n_c, 40182)
        m = model(_args_for_selftest(storage_bytes_per_record=val_c))
        ok &= _check("I 落盘（TB/天，@85.86 B 列式）", m["tb_per_day"], 37.09152)
        ok &= _check("I 口径随数一起走", 1 if caveat else 0, 1)
        # 注入 1：读了产物却用回旧的"列式 40 B"假设 → 落盘量必须偏离手算
        bad_v, _ = load_columnar_measurement(cart, inject="columnar-trust-assumption")
        m_bad = model(_args_for_selftest(storage_bytes_per_record=bad_v))
        ok &= _check("I 注入 columnar-trust-assumption 后落盘（TB/天）", m_bad["tb_per_day"], 17.28)
        # 注入 2：某一档其实没落进真实 ClickHouse（没有 plan_bpr）⇒ 必须抛错，不许静默用另一档
        no_ch = os.path.join(_d, "no-ch.json")
        with open(no_ch, "w", encoding="utf-8") as fh:
            json.dump({"schema": "columnar-plan/1", "plan_bytes_per_record": 5.91,
                       "not_a_claim": "x", "corpora": [{"label": "同质", "records": 20182,
                                                      "plan_bpr": 5.91},
                                                     {"label": "没测 CH", "records": 20000,
                                                      "plan_bpr": None}]}, fh)
        try:
            load_columnar_measurement(no_ch)
            ok &= _check("I 缺一档 ClickHouse 实测必须抛错", False, True)
        except ValueError:
            ok &= _check("I 缺一档 ClickHouse 实测 ⇒ 抛错（不给伪数）", True, True)
        # 注入 3：产物没带"这个数依赖 DDL 的 CODEC 选择"这句口径 ⇒ 拒绝裸引用
        no_caveat = os.path.join(_d, "no-caveat.json")
        with open(no_caveat, "w", encoding="utf-8") as fh:
            json.dump({"schema": "columnar-plan/1", "plan_bytes_per_record": 85.86,
                       "corpora": [{"label": "多样", "records": 20000, "plan_bpr": 85.86}]}, fh)
        try:
            load_columnar_measurement(no_caveat)
            ok &= _check("I 缺口径字段必须抛错", False, True)
        except ValueError:
            ok &= _check("I 缺「依赖 DDL 的 CODEC」口径 ⇒ 抛错", True, True)

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
        "--storage-bytes-per-record",
        type=float,
        default=None,
        help="落盘字节/记录（缺省：读 --storage-measured 的实测值；该文件缺失时退回内置实测默认值）",
    )
    ap.add_argument(
        "--storage-measured",
        metavar="measure.json",
        default=DEFAULTS["storage_measured"],
        help="落盘测量的产物（默认 docs/planning/measurements/storage-ratio.json）",
    )
    ap.add_argument(
        "--storage-format",
        choices=("gzip", "raw", "columnar"),
        default="gzip",
        help="取哪一档：gzip=JSONL+gzip 规划用（默认，取较差端）· raw=未压缩 JSONL 上界 · "
             "columnar=列式（真实 ClickHouse + 本仓 DDL，读 --columnar-measured）",
    )
    ap.add_argument(
        "--columnar-measured",
        metavar="columnar.json",
        default=DEFAULTS["columnar_measured"],
        help="列式落盘实测产物（默认 docs/planning/measurements/columnar.json）",
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
    ap.add_argument(
        "--verify-defaults",
        action="store_true",
        help="核对「内置默认落盘值」与「测量产物」是否仍然一致（两者必须一起改）",
    )
    ap.add_argument("--self-test", action="store_true", help="算术自证 + 反向注入")
    ap.add_argument("--inject", default=None, help=argparse.SUPPRESS)  # 仅供自证使用的故障注入
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.verify_defaults:
        # 这条检查是给门禁用的：容量模型的默认值来自测量产物，两者一旦漂移
        # （改了产物忘了改默认值，或反过来），报告里的"实测"口径就变成假话。
        want = DEFAULTS["storage_bytes_per_record"]
        if args.inject == "default-drift":
            want = PLANNING_ASSUMPTION_BYTES
        bad = 0
        try:
            got, n = load_storage_measurement(args.storage_measured, "gzip")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"✗ 读测量产物失败：{exc}", file=sys.stderr)
            return 1
        print(f"内置默认落盘值 {want:g} B/记录 vs 测量产物 {got:.4f} B/记录"
              f"（{args.storage_measured}，样本 {n} 条）")
        if abs(got - want) > 0.05:
            print("✗ gzip(JSONL) 档：内置默认值与测量产物不一致 —— 两者必须一起改", file=sys.stderr)
            bad += 1
        # 列式档同样要核对：它是 `--storage-format columnar` 的默认来源，
        # 只核对 gzip 会留下"一半默认值是活的、另一半早就腐烂"。
        want_c = DEFAULTS["columnar_bytes_per_record"]
        try:
            got_c, n_c, _caveat = load_columnar_measurement(args.columnar_measured)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"✗ 读列式测量产物失败：{exc}", file=sys.stderr)
            return 1
        print(f"内置默认列式值 {want_c:g} B/记录 vs 测量产物 {got_c:.4f} B/记录"
              f"（{args.columnar_measured}，语料合计 {n_c} 条）")
        if abs(got_c - want_c) > 0.05:
            print("✗ 列式档：内置默认值与测量产物不一致 —— 换 DDL 重测后必须一起改", file=sys.stderr)
            bad += 1
        if bad:
            return 1
        print("✓ 一致（gzip(JSONL) 与列式两档都核对了）")
        return 0

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

    # 落盘字节/记录：优先命令行显式给数，否则读测量产物（缺失时用内置实测默认值并明说）。
    args.storage_measured_used = None
    args.storage_measured_records = 0
    args.storage_caveat = None
    if args.storage_bytes_per_record is None and args.storage_format == "columnar":
        if args.columnar_measured and os.path.isfile(args.columnar_measured):
            try:
                val, n, caveat = load_columnar_measurement(args.columnar_measured,
                                                           inject=args.inject)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"读 --columnar-measured 失败：{exc}", file=sys.stderr)
                return 1
            args.storage_bytes_per_record = val
            args.storage_measured_used = f"{args.columnar_measured}（列式）"
            args.storage_measured_records = n
            args.storage_caveat = caveat
            print(f"（落盘 {val:g} B/记录取列式实测：{args.columnar_measured}，"
                  f"参与合并的语料共 {n} 条 —— 依赖本仓 DDL 的 CODEC 选择，语料为合成）")
        else:
            args.storage_bytes_per_record = DEFAULTS["columnar_bytes_per_record"]
            print(f"⚠ 未找到列式实测产物 {args.columnar_measured}：落盘用内置实测默认值 "
                  f"{args.storage_bytes_per_record:g} B/记录（CYS-INF-041 收尾），但**本次没有复核它**。",
                  file=sys.stderr)
    elif args.storage_bytes_per_record is None:
        if args.storage_measured and os.path.isfile(args.storage_measured):
            try:
                val, n = load_storage_measurement(args.storage_measured, args.storage_format,
                                                  inject=args.inject)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"读 --storage-measured 失败：{exc}", file=sys.stderr)
                return 1
            args.storage_bytes_per_record = val
            args.storage_measured_used = f"{args.storage_measured} 的 {args.storage_format} 档"
            args.storage_measured_records = n
            print(f"（落盘 {val:g} B/记录取实测：{args.storage_measured} 的 {args.storage_format} 档，"
                  f"样本 {n} 条；另有列式实测档 --storage-format columnar）")
        else:
            args.storage_bytes_per_record = DEFAULTS["storage_bytes_per_record"]
            print(f"⚠ 未找到测量产物 {args.storage_measured}：落盘用内置实测默认值 "
                  f"{args.storage_bytes_per_record:g} B/记录（CYS-INF-041），但**本次没有复核它**。",
                  file=sys.stderr)

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
