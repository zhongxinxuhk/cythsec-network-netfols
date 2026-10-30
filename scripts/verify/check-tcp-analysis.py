#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-tcp-analysis.py —— CYS-TRF-015 会话级 TCP 统计的三方比对器。

三方 = 我们的统计行（cythsec-analyze stderr 的 `tcp retr=... ooo=...`）
     + 生成器真值（datasets/tcp-analysis/expected.json，按构造参数手写）
     + tshark 对同一条 pcap 的独立标记（tcp.analysis.* 帧计数）。

2026-10-23 加了**第四条腿**：`FlowRecord.tcp.*` 的**逐会话列值**（记录契约 v2）。
理由不是“多一个出口多一份安心”，而是统计行与记录列可以**各自错**：汇总只校合计，
“40002 的重传记到 40003 上”在它上面完全隐形；而逐会话列不抬版就会被下游按旧列序读错。
现在两者都对同一份真值，且逐流 retr/ooo 还额外与 tshark 的逐流帧数相等。

比对口径（为什么是这几条恒等式）：
    · `我们的 retr == tshark retransmission 帧数`、`我们的 ooo == tshark out_of_order 帧数`
      —— 2026-10-23 正式样本（完整握手含第三次 ACK）实测两边逐组一致。
      同批反面探针：握手缺第三次 ACK 时同样的字节被 Wireshark 归成 retransmission ——
      分类依赖构型，所以比对只在同一条可复现 pcap 上做。
    · 每条 flow 的 lost/duplicate_ack 帧数逐格钉 tshark 侧事实（哨兵：第三方裁判
      换版本导致分类漂移时，这里先响，而不是等统计语义悄悄变）。
    · expected.json 里 `tshark.verified=false` 的条目打印为 `SKIP(已知例外)` 并计入
      统计（先例：重组关口）—— 当前没有条目使用它，机制保留给将来的口径漂移。
    · RTT **不与 tshark 比**：tshark 的 iRTT 量 SYN→第三次握手 ACK，我们的
      handshake_rtt 是 SYN→SYN/ACK，口径不同；只与生成器真值（写进 pcap 的时间戳差）
      精确比对。
    · 截断会话（truncated-no-seq）钉的是“未观测 ≠ 0”：sess_unobserved 必须为 1，
      且它的字节不得混进 up/down。

反向故障注入（--self-test）：比对器自己也可能写错（最坏是恒「通过」）。每一项
期望都被改坏一次并要求检出；检出数少一项就退出非 0。

用法（由 check-tcp-analysis.sh 调用）：
    check-tcp-analysis.py --stats <analyze-stderr> --tsv <tshark-fields> \
        --records <records.jsonl> --expected <expected.json> --self-test
TSV 列序固定为：frame.number | srcport | dstport | retr | ooo | lost | dupack

退出码：0 一致 / 1 不一致或注入未检出 / 2 输入缺失 / 3 不在此脚本使用。
"""

import argparse
import json
import sys

STATS_PREFIX = "[cythsec-analyze] tcp "
SERVER_PORT = "443"

# 记录里 `tcp` 块的会话级统计键（v2）。名字与 `record::TCP_BLOCK_COLUMNS` 同步，
# 两边不一致时 `compare_records` 会报“缺键”，而不是默默少比。
RECORD_KEYS = (
    "seq_judged",
    "retransmissions",
    "out_of_order",
    "handshake_rtt_us",
    "uplink_bytes",
    "downlink_bytes",
)

# 统计行必须齐 these 键；缺键 = 契约变了，必须显式红，不许按默认值比。
STATS_KEYS = (
    "retr", "ooo", "judged", "sess_judged", "sess_unobs",
    "sum_us", "min_us", "max_us", "up", "down", "ratio_n",
)


class Missing(Exception):
    pass


def parse_tcp_line(stats_path):
    """从 analyze 的 stderr 里取 `tcp retr=...` 行；rtt=x/y 拆成两个数。"""
    found = None
    with open(stats_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith(STATS_PREFIX):
                found = line[len("[cythsec-analyze] "):]
                break
    if found is None:
        raise Missing("统计行缺失（analyze 的 stderr 里没有 `tcp retr=` 行）")
    stats = {}
    for tok in found.split():
        if tok == "tcp":
            continue
        if "=" not in tok:
            raise Missing(f"统计行出现非 key=value 片段 `{tok}`（格式变了？）")
        k, v = tok.split("=", 1)
        if "/" in v:
            a, b = v.split("/", 1)
            stats[k] = int(a)
            stats[k + "_total"] = int(b)
            continue
        stats[k] = int(v)
    missing = [k for k in STATS_KEYS if k not in stats]
    if missing:
        raise Missing(f"统计行缺少键 {missing}（字段名是关口契约，改名字必须同步改这里）")
    if "rtt_total" not in stats:
        raise Missing("统计行缺少 rtt=x/y 的 y（分母缺失就无法钉住“没测到 ≠ 0”）")
    return stats


def parse_tshark_tsv(tsv_path):
    """按 flow 端口聚合 tshark 的 analysis 标记帧数。"""
    counts = {}
    with open(tsv_path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("|")
            if len(parts) != 7:
                continue
            _num, src, dst, retr, ooo, lost, dup = parts
            port = dst if src == SERVER_PORT else src
            if port == "":
                continue
            c = counts.setdefault(port, {"retransmission": 0, "out_of_order": 0,
                                         "lost_segment": 0, "duplicate_ack": 0})
            if retr not in ("", "0", "False"):
                c["retransmission"] += 1
            if ooo not in ("", "0", "False"):
                c["out_of_order"] += 1
            if lost not in ("", "0", "False"):
                c["lost_segment"] += 1
            if dup not in ("", "0", "False"):
                c["duplicate_ack"] += 1
    return counts


def parse_records(jsonl_path):
    """读 `cythsec-analyze` 产出的 JSONL，按端口取 `tcp.*` 六键。

    只取会话级统计这六列 + 五元组端口；其他字段是 `check-flow-records.py` 的领域。
    这里的口径：**记录里的逐会话值与统计行的汇总值是两条独立出口**，两者都要对得上
    真值 —— 只比对其中一条时，“汇总对了但逐会话错了”（或反之）会漏过去。
    缺 `tcp.*` 任一键 ⇒ 抛 `Missing`：记录契约变了必须显式红，不能默默少比。
    """
    out = {}
    with open(jsonl_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            flow = rec["flow"]
            port = str(flow["dst_port"] if str(flow["src_port"]) == SERVER_PORT
                        else flow["src_port"])
            tcpb = rec["tcp"]
            missing = [k for k in RECORD_KEYS if k not in tcpb]
            if missing:
                raise Missing(f"记录 port={port} 的 tcp 块缺键 {missing}（列契约变更必须同步改关口）")
            out[port] = {k: tcpb[k] for k in RECORD_KEYS}
            out[port]["_proto"] = str(flow.get("proto"))
    return out


def compare_records(records, tshark_counts, expected, failures, checked):
    """逐会话：记录列值 ↔ 生成器真值 ↔ tshark 逐流帧数。"""
    def chk(name, got, want):
        checked.append(name)
        if got != want:
            failures.append(f"{name}: 得到 {got!r}，期望 {want!r}")

    for fl in expected["flows"]:
        port = str(fl["port"])
        name = fl["name"]
        want = fl.get("record")
        if want is None:
            # 生成器没有记录级真值 = 样本与关口不同批，比对不能默认跳过。
            failures.append(f"record[{name}]：expected.json 缺 record 真值块")
            continue
        got = records.get(port)
        if got is None:
            failures.append(f"record[{name}]：port={port} 在记录里没出现（会话丢了）")
            continue
        missing = [k for k in RECORD_KEYS if k not in got]
        if missing:
            # 缺键不能当成"值为 None"：前者是契约变了，后者是这条会话真的没证据。
            failures.append(f"record[{name}]：tcp 块缺键 {missing}（列契约变更必须同步改关口）")
            continue
        ts = fl["tshark"]
        tc = tshark_counts.get(port, {})
        for key in RECORD_KEYS:
            chk(f"record[{name}].{key}", got[key], want[key])
        # 恒等式（逐流）：记录的重传/乱序列 == tshark 对该流的标记帧数。
        # 截断会话的 `None` 必须对 tshark 的 0 以外的口径：它没被判定过，所以只对
        # 真值对，不强求与 tshark 相等（那是 `compare()` 的全局恒等式管的）。
        if want["retransmissions"] is not None:
            chk(f"恒等式 record[{name}].retransmissions == tshark retransmission",
                want["retransmissions"], tc.get("retransmission", 0))
            chk(f"恒等式 record[{name}].out_of_order == tshark out_of_order",
                want["out_of_order"], tc.get("out_of_order", 0))
    # 会话不得多发：记录里比真值多出未知端口 = 实现在同一条 pcap 上多建了会话。
    known = {str(fl["port"]) for fl in expected["flows"]}
    extra = sorted(set(records) - known)
    chk("记录会话集与样本一致（不得多）", extra, [])


def compare(stats, tshark_counts, expected, failures, checked):
    def chk(name, got, want):
        checked.append(name)
        if got != want:
            failures.append(f"{name}: 得到 {got}，期望 {want}")

    t = expected["totals"]
    # ---- ① 我们 vs 生成器真值（逐键）----
    our_map = {
        "retr": "retr", "ooo": "ooo", "judged": "judged",
        "sess_judged": "sessions_judged", "sess_unobs": "sessions_unobserved",
        "sum_us": "rtt_sum_us", "min_us": "rtt_min_us", "max_us": "rtt_max_us",
        "up": "up_bytes", "down": "down_bytes", "ratio_n": "ratio_sessions",
    }
    for k, tk in our_map.items():
        chk(f"stats.{k}", stats[k], t[tk])
    chk("stats.rtt 分母", stats["rtt_total"], t["rtt_total_sessions"])

    # ---- ② tshark 侧逐流事实（verified 机制与重组关口同族）----
    # 总数聚合**全流**都算：恒等式③是全局口径，若某流被标成例外，恒等式会红 ——
    # 那正是想要的：例外只能例外逐格比对那一条，不能把全局恒等式也一起免掉。
    skip = []
    ts_tot = {"retransmission": 0, "out_of_order": 0, "lost_segment": 0, "duplicate_ack": 0}
    for fl in expected["flows"]:
        port = str(fl["port"])
        got = tshark_counts.get(port, {"retransmission": 0, "out_of_order": 0,
                                       "lost_segment": 0, "duplicate_ack": 0})
        for f in ts_tot:
            ts_tot[f] += got[f]
        ts = fl["tshark"]
        if not ts.get("verified", True):
            skip.append((port, fl["name"],
                         fl.get("tshark_reason", ts.get("reason", "（缺 reason）"))))
            continue
        for f in ("retransmission", "out_of_order", "lost_segment", "duplicate_ack"):
            chk(f"tshark[{fl['name']}].{f}", got[f], ts[f])
    for port, name, reason in skip:
        print(f"   SKIP(已知例外) tshark[{name}] port={port}：{reason}")

    # ---- ③ 恒等式：我们 == 第三方（总帧数口径）----
    chk("恒等式 我们的retr == tshark retransmission 总帧数", stats["retr"],
        ts_tot["retransmission"])
    chk("恒等式 我们的ooo == tshark out_of_order 总帧数", stats["ooo"],
        ts_tot["out_of_order"])
    # 生成器真值这一侧也要与 tshark 相等（三方是闭环，不是两条单边比对）
    chk("恒等式 真值retr == tshark retransmission", t["retr"], ts_tot["retransmission"])
    chk("恒等式 真值ooo == tshark out_of_order", t["ooo"], ts_tot["out_of_order"])
    chk("tshark lost_segment 总数", ts_tot["lost_segment"], t["tshark_lost"])
    chk("tshark duplicate_ack 总数", ts_tot["duplicate_ack"], t["tshark_dupack"])
    return len(skip)


def run(args):
    failures = []
    checked = []
    try:
        stats = parse_tcp_line(args.stats)
    except (Missing, ValueError) as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1
    try:
        records = parse_records(args.records)
    except (Missing, OSError, ValueError) as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1
    try:
        with open(args.expected, encoding="utf-8") as fh:
            expected = json.load(fh)
    except OSError as e:
        print(f"✗ expected.json 读取失败：{e}", file=sys.stderr)
        return 2
    if any("record" not in fl for fl in expected["flows"]):
        print("✗ expected.json 里没有逐会话真值（record 块）—— 生成器与关口不同批",
              file=sys.stderr)
        return 1
    tshark_counts = parse_tshark_tsv(args.tsv)
    skipped = compare(stats, tshark_counts, expected, failures, checked)
    compare_records(records, tshark_counts, expected, failures, checked)

    if not checked:
        print("✗ 一项都没比对（空输入不得判通过）", file=sys.stderr)
        return 1
    if failures:
        for f in failures:
            print(f"✗ {f}", file=sys.stderr)
        return 1
    print(f"✓ 三方比对 {len(checked)} 项全一致（已知例外 {skipped} 条）")

    if not args.self_test:
        return 0

    # ---- 反向故障注入：每一项都必须被检出 ----
    import copy

    def inject(desc, mutate_stats=None, mutate_counts=None, mutate_expected=None,
               mutate_records=None):
        s = copy.deepcopy(stats)
        c = copy.deepcopy(tshark_counts)
        e = copy.deepcopy(expected)
        r = copy.deepcopy(records)
        if mutate_stats:
            mutate_stats(s)
        if mutate_counts:
            mutate_counts(c)
        if mutate_expected:
            mutate_expected(e)
        if mutate_records:
            mutate_records(r)
        f2, k2 = [], []
        compare(s, c, e, f2, k2)
        compare_records(r, c, e, f2, k2)
        if f2:
            print(f"   已检出 ← 注入「{desc}」：{f2[0][:90]}")
            return 0
        print(f"   ✗ 未检出 ← 注入「{desc}」", file=sys.stderr)
        return 1

    print("==> 反向故障注入")
    missed = 0
    missed += inject("我们的 retr +1", mutate_stats=lambda s: s.__setitem__("retr", s["retr"] + 1))
    missed += inject("我们的 ooo -1", mutate_stats=lambda s: s.__setitem__("ooo", s["ooo"] - 1))
    missed += inject("我们的 judged +1", mutate_stats=lambda s: s.__setitem__("judged", s["judged"] + 1))
    missed += inject("sess_unobs +1（把未观测会话数成已判定会同时破两处）",
                     mutate_stats=lambda s: s.__setitem__("sess_unobs", s["sess_unobs"] + 1))
    missed += inject("rtt 分母 +1", mutate_stats=lambda s: s.__setitem__("rtt_total", s["rtt_total"] + 1))
    missed += inject("rtt sum +1", mutate_stats=lambda s: s.__setitem__("sum_us", s["sum_us"] + 1))
    missed += inject("rtt min 改成 max", mutate_stats=lambda s: s.__setitem__("min_us", s["max_us"]))
    missed += inject("rtt max +1", mutate_stats=lambda s: s.__setitem__("max_us", s["max_us"] + 1))
    missed += inject("up +1（截断会话字节混进上下行就会被这条抓到）",
                     mutate_stats=lambda s: s.__setitem__("up", s["up"] + 1))
    missed += inject("down +1", mutate_stats=lambda s: s.__setitem__("down", s["down"] + 1))
    missed += inject("ratio_n +1", mutate_stats=lambda s: s.__setitem__("ratio_n", s["ratio_n"] + 1))
    missed += inject("tshark 侧 40001 多一帧 retransmission",
                     mutate_counts=lambda c: c.setdefault("40001", {"retransmission": 0, "out_of_order": 0,
                                                                    "lost_segment": 0, "duplicate_ack": 0}
                                                          ).__setitem__("retransmission", 1))
    missed += inject("tshark 侧 40006 丢掉 lost_segment",
                     mutate_counts=lambda c: c["40006"].__setitem__("lost_segment", 0))
    missed += inject("tshark 侧 40001 dupack 改 0",
                     mutate_counts=lambda c: c["40001"].__setitem__("duplicate_ack", 0))
    missed += inject("真值 retr +1（期望腐烂也会被检出）",
                     mutate_expected=lambda e: e["totals"].__setitem__("retr", e["totals"]["retr"] + 1))
    missed += inject("真值里把 partial-overlap 改回旧口径（retr/ooo 对调）",
                     mutate_expected=lambda e: [e["totals"].__setitem__("retr", e["totals"]["retr"] + 1),
                                                e["totals"].__setitem__("ooo", e["totals"]["ooo"] - 1)][0])
    # ---- 逐会话记录列（v2 新列自己的注入）----
    # 统计行对不代表记录对：这两条出口可以各自错。下面的注入都只动 records。
    missed += inject("记录 40002 的 retransmissions 改 0（逐会话错了而汇总仍对）",
                     mutate_records=lambda r: r["40002"].__setitem__("retransmissions", 0))
    missed += inject("记录 40004 的 out_of_order 改成 None（乱序丢了）",
                     mutate_records=lambda r: r["40004"].__setitem__("out_of_order", None))
    missed += inject("记录 40007（未观测）的 retransmissions 从 null 改成 0 —— "
                     "“没得判”伪装成“没重传”，本项最不能错的一条",
                     mutate_records=lambda r: r["40007"].__setitem__("retransmissions", 0))
    missed += inject("记录 40007 的 uplink_bytes 从 null 改成 100（截断会话字节混进列）",
                     mutate_records=lambda r: r["40007"].__setitem__("uplink_bytes", 100))
    missed += inject("记录 40001 的 handshake_rtt_us +1",
                     mutate_records=lambda r: r["40001"].__setitem__("handshake_rtt_us",
                                                                     r["40001"]["handshake_rtt_us"] + 1))
    missed += inject("记录 40005 的 uplink/downlink 对调（发起方定方向错了）",
                     mutate_records=lambda r: (r["40005"].__setitem__(
                         "uplink_bytes", r["40005"]["downlink_bytes"]),
                         r["40005"].__setitem__("downlink_bytes", r["40005"]["uplink_bytes"]))[0])
    missed += inject("记录里丢掉 downlink_bytes 键（列契约变更必须显式报错）",
                     mutate_records=lambda r: r["40001"].pop("downlink_bytes"))
    missed += inject("真值 record 的 judged +1（逐会话期望腐烂也会被检出）",
                     mutate_expected=lambda e: e["flows"][0]["record"].__setitem__(
                         "seq_judged", e["flows"][0]["record"]["seq_judged"] + 1))
    missed += inject("记录集里多一条会话（实现多建会话不得默默过）",
                     mutate_records=lambda r: r.__setitem__(
                         "49999", {k: 0 for k in RECORD_KEYS}))
    # 缺键注入单独测（它抛 Missing，不走 compare）
    import io
    tmp = args.stats + ".tmp-missing"
    with open(args.stats, encoding="utf-8") as fh:
        content = fh.read()
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content.replace(" judged=", " judgedX="))
    try:
        parse_tcp_line(tmp)
        print("   ✗ 未检出 ← 注入「统计行缺 judged 键」", file=sys.stderr)
        missed += 1
    except Missing:
        print("   已检出 ← 注入「统计行缺 judged 键」：契约变更显式报错")
    finally:
        import os
        os.remove(tmp)

    if missed:
        print(f"✗ {missed} 项注入未被检出 —— 比对器不可信", file=sys.stderr)
        return 1
    print("✓ 反向注入全部被检出")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stats", required=True)
    ap.add_argument("--tsv", required=True)
    ap.add_argument("--records", required=True,
                    help="cythsec-analyze 产出的 JSONL（逐会话列值比对）")
    ap.add_argument("--expected", required=True)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
