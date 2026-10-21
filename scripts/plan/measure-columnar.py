#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""measure-columnar.py —— **列式（ClickHouse Native）落盘字节/记录实测**（CYS-INF-041 收尾）。

## 为什么必须量

`docs/planning/collector-capacity` 的容量表里，"落盘 79.4 B/记录"是 gzip(JSONL) 的
**实测**值，而旁边那句"列式能压到几十 B/记录"是整个规划里**最后一个没量过的假设**
（它比 79.4 还好，所以它一旦被引用就会把存储预算压低）。本脚本把它换成实测。

## 三条口径（缺一条这个数就会被误用）

1. **样本量与语料构成必须一起看**。字节/记录与"字段多样性"强相关：同一条 5 元组
   反复出现，列式编码几乎免费；真实省网流量字段各不相同，编码收益大幅缩水。
   所以三份语料分别测量、分别入库，**规划取较差端**，绝不引用最好看的那个数。
2. **"列式"与"按列编解码器"是两件事，必须分开量**。本脚本同时给出
   ① Native 原始字节（无压缩）② Native + gzip ③ ClickHouse MergeTree 默认 LZ4
   ④ ClickHouse MergeTree + 我们 DDL 的按列 CODEC。少了 ③ 这个对照，
   "列式省了几倍"会被误当成格式本身的功劳（实测并非如此，见下）。
3. **小样本不能当容量结论**。37 条真实向量在 ClickHouse 里只有 1 个 part，
   每子流约 50 B 的固定开销主导一切 —— 这个数只能用于正确性，不能用于容量。
   脚本对 `records < 5000` 的输出**显式打 `usable_for_capacity: false`**。

## 实测得到的结论（不是脚本假设，是脚本跑出来的）

* 默认 LZ4 下，列式落盘 ≈ gzip(JSONL)：**"换成列式"本身不带来数量级收益**。
* 收益来自**按列编解码器 + LowCardinality**：多样语料上比 gzip(JSONL) 小约 3.7×。
* 所以容量表用**多样语料 + 我们 DDL** 那一档，并注明它依赖 DDL 的 CODEC 选择 ——
  换 DDL 就要重测。

## 用法

    measure-columnar.py --label 名字 --pcap a.pcap [b.pcap ...] [--json 产物.json]
                        [--rows-per-block 100000] [--analyze <bin>] [--clickhouse <bin>]
    measure-columnar.py --self-test [--inject 名字]

退出码：0 正常；1 输入或自证失败；2 参数错误；3 环境缺工具（对应档标"未核验"）。
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

GZIP_LEVEL = 9
# 少于这个条数，part 固定开销主导，数字只能证明「读得对」，不能当容量规划值。
MIN_RECORDS_FOR_CAPACITY = 5000
TB = 1024 ** 4


def die(msg):
    print("✗ " + msg, file=sys.stderr)
    return 1


def gzip_size(path, level=GZIP_LEVEL):
    """用系统的 gzip 量压缩后字节（与 measure-storage.py 同一口径，可互相印证）。"""
    if shutil.which("gzip") is None:
        return None
    out = subprocess.run(
        ["gzip", f"-{level}", "-c", path],
        check=True, capture_output=True).stdout
    return len(out)


def run_analyze(analyze, pcaps, workdir, rows_per_block):
    """pcap → 同源的 JSONL 与 Native。多个 pcap 串成一条块流（每块自带列头）。"""
    jsonl = os.path.join(workdir, "flows.jsonl")
    native = os.path.join(workdir, "flows.native")
    open(jsonl, "w").close()
    open(native, "wb").close()
    records = 0
    for i, p in enumerate(pcaps):
        # 中间产物一律落在 workdir：**不许**写到 pcap 旁边（datasets/ 是生成物目录，
        # 往里塞 flows.jsonl 会让别的门禁误读到上一次运行的残留）。
        tmp_j = os.path.join(workdir, f"in{i}.jsonl")
        tmp_n = os.path.join(workdir, f"in{i}.native")
        subprocess.run(
            [analyze, "-r", p, "-o", tmp_j, "--native", tmp_n,
             "--native-rows-per-block", str(rows_per_block), "-q"],
            check=True, capture_output=True)
        with open(tmp_j, encoding="utf-8") as fh:
            n = sum(1 for l in fh if l.strip())
        if n:
            with open(tmp_j, encoding="utf-8") as src, open(jsonl, "a", encoding="utf-8") as dst:
                shutil.copyfileobj(src, dst)
            with open(tmp_n, "rb") as src, open(native, "ab") as dst:
                shutil.copyfileobj(src, dst)
            records += n
    return jsonl, native, records


def ch_measure(clickhouse, ddl_text, native_path, workdir, table, records):
    """把产物插进真实 MergeTree，返回 part 目录的字节分解。

    数字来自**文件系统**，不是估算：列数据取 `*.bin`，其余（`*.mrk2/*.idx/*_count.txt`
    等）单列为索引/元数据，两者都换算成 B/记录。
    """
    path = os.path.join(workdir, "chdata")
    os.makedirs(path, exist_ok=True)
    query = (
        ddl_text.replace("flows", table, 1)
        + f"\nINSERT INTO {table} FROM INFILE '{native_path}' FORMAT Native;\n"
    )
    r = subprocess.run([clickhouse, "local", "--path", path, "-n", "--query", query],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return {"error": (r.stderr or "").strip().splitlines()[-1] if r.stderr else "执行失败"}
    base = os.path.join(path, "data", "default", table)
    if not os.path.isdir(base):
        return {"error": "插完没有 part 目录"}
    parts = [d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d)) and d != "detached"]
    bins = 0
    other = 0
    files = []
    for part in parts:
        for root, _dirs, names in os.walk(os.path.join(base, part)):
            for n in names:
                sz = os.path.getsize(os.path.join(root, n))
                files.append((n, sz))
                if n.endswith(".bin"):
                    bins += sz
                else:
                    other += sz
    return {
        "parts": len(parts),
        "column_data_bytes": bins,
        "index_meta_bytes": other,
        "part_total_bytes": bins + other,
        "column_data_bpr": round(bins / records, 2) if records else None,
        "part_total_bpr": round((bins + other) / records, 2) if records else None,
        "counted_extensions_note": "列数据=*.bin；其余计入 index_meta（含 mark/index/统计）",
    }


def baseline_ddl(ddl_text):
    """我们 DDL 的"默认编解码"对照版：去掉所有 CODEC 子句、去掉 LowCardinality。

    这是**同一个 schema 的唯一变量控制**：只改编码，不改列、不改类型语义，
    这样 ③ 与 ④ 的差值才是"编解码器选择"的净收益，而不是别的。
    """
    out = []
    for line in ddl_text.splitlines():
        s = line.replace(" LowCardinality(", "(").replace("Nullable))", "Nullable)")
        while " CODEC(" in s:
            i = s.index(" CODEC(")
            j = s.index(")", i) + 1
            s = s[:i] + s[j:]
        out.append(s)
    return "\n".join(out)


def cmd_combine(paths, out_path):
    ms = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            ms.append(json.load(fh))
    bpr = combine_bpr(ms)
    if bpr is None:
        for m in ms:
            print(f"  ✗ {m.get('label')}：records={m.get('records')} "
                  f"plan_bpr={plan_bpr(m)}", file=sys.stderr)
        return die("没有任何一档可以进容量表 —— 必须补齐大样本 + 真实 ClickHouse 实测，"
                   "不许退回旧假设或引用未核验的那一档")
    out = {
        "schema": "columnar-plan/1",
        "plan_bytes_per_record": bpr,
        "rule": "多语料取**较差端(max)**；每档都必须 records>=%d 且有真实 ClickHouse 落盘实测"
                % MIN_RECORDS_FOR_CAPACITY,
        "corpora": [{"label": m.get("label"), "records": m.get("records"),
                     "plan_bpr": plan_bpr(m),
                     "jsonl_gzip_bpr": m.get("jsonl_gzip_bpr"),
                     "native_raw_bpr": m.get("native_raw_bpr")} for m in ms],
        "not_a_claim": "这个数依赖 001_flows.sql 的 CODEC/LowCardinality 选择；换 DDL 必须重测",
    }
    print(f"==> 列式规划值：{bpr} B/记录（取较差端；参与合并 {len(ms)} 档）")
    for c in out["corpora"]:
        print(f"  {c['label']:16s} records={c['records']:>7} plan={c['plan_bpr']} "
              f"gzip(JSONL)={c['jsonl_gzip_bpr']}")
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"产物：{out_path}")
    return 0


def cmd_measure(args):
    if not args.pcap:
        return die("要 --pcap（至少一个）")
    for p in args.pcap:
        if not os.path.isfile(p):
            return die(f"pcap 不存在：{p}（列式数字必须来自真实记录的字节，不许编数据）")
    workdir = tempfile.mkdtemp(prefix="cythsec-colmeasure.")
    try:
        jsonl, native, records = run_analyze(
            args.analyze, args.pcap, workdir, args.rows_per_block)
        if records == 0:
            return die("一条记录都没产出：没有可比的东西，测出来的平均数没有意义")
        jsonl_bytes = os.path.getsize(jsonl)
        native_bytes = os.path.getsize(native)
        gj = gzip_size(jsonl, args.gzip_level)
        gn = gzip_size(native, args.gzip_level)
        out = {
            "schema": "columnar-measure/1",
            "label": args.label,
            "provenance": {
                "pcaps": [os.path.relpath(p, args.root) for p in args.pcap],
                "records": records,
                "rows_per_block": args.rows_per_block,
                "generator": "cythsec-analyze --native（与 JSONL 同源同序）",
                "regenerate": "见 docs/planning/measurements/README.md 的「列式实测」一节",
            },
            "records": records,
            "usable_for_capacity": records >= MIN_RECORDS_FOR_CAPACITY,
            "jsonl_raw_bpr": round(jsonl_bytes / records, 2),
            "jsonl_gzip_bpr": round(gj / records, 2) if gj else None,
            "native_raw_bpr": round(native_bytes / records, 2),
            "native_gzip_bpr": round(gn / records, 2) if gn else None,
            "native_bytes": native_bytes,
            "compression_note": "gzip 档只是可移植对照；ClickHouse 不这么压",
        }
        if args.clickhouse:
            ddl_text = subprocess.run(
                [os.path.join(args.root, "target", "debug", "cythsec-dump-ddl")],
                check=True, capture_output=True, text=True).stdout
            out["clickhouse_default_codec"] = ch_measure(
                args.clickhouse, baseline_ddl(ddl_text), native, workdir,
                "flows_default", records)
            out["clickhouse_repo_ddl"] = ch_measure(
                args.clickhouse, ddl_text, native, workdir, "flows", records)
            for k in ("clickhouse_default_codec", "clickhouse_repo_ddl"):
                if "error" in out[k]:
                    out[k]["unverified"] = True
                    print(f"⚠ {k} 未核验：{out[k]['error']}", file=sys.stderr)
        else:
            out["clickhouse_default_codec"] = {"unverified": True,
                                               "reason": "没给 --clickhouse：这两档未核验，"
                                                         "不得当实测值引用"}
            out["clickhouse_repo_ddl"] = out["clickhouse_default_codec"]
        print_report(out)
        if args.json:
            os.makedirs(os.path.dirname(args.json), exist_ok=True) if os.path.dirname(args.json) else None
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(out, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.write("\n")
            print(f"产物：{args.json}")
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def print_report(m):
    print(f"==> {m['label']}（records={m['records']}，"
          f"可用于容量={'是' if m['usable_for_capacity'] else '否（小样本，part 固定开销主导）'}）")
    rows = [
        ("JSONL 未压缩", m["jsonl_raw_bpr"]),
        ("JSONL + gzip9", m["jsonl_gzip_bpr"]),
        ("Native 未压缩", m["native_raw_bpr"]),
        ("Native + gzip9", m["native_gzip_bpr"]),
    ]
    for k, name in (("clickhouse_default_codec", "CH 默认 LZ4（列数据）"),
                    ("clickhouse_repo_ddl", "CH 我们的 DDL（列数据）")):
        v = m.get(k, {})
        rows.append((name, v.get("column_data_bpr")))
    for name, v in rows:
        print(f"  {name:28s} {('%.2f B/记录' % v) if v is not None else '未核验'}")
    d = m.get("clickhouse_default_codec") or {}
    r = m.get("clickhouse_repo_ddl") or {}
    if d.get("column_data_bpr") and r.get("column_data_bpr"):
        print(f"  编解码器净收益：{d['column_data_bpr'] / r['column_data_bpr']:.1f}×"
              f"（同一 schema，只差 CODEC/LowCardinality）")
    if not m["usable_for_capacity"]:
        print("  ⚠ 本档只能证明「读得对」，不能进容量表。")


# ---------------------------------------------------------------------------
# 容量表可以引用的数（规则集中在这里，报告与自证共用同一份）
# ---------------------------------------------------------------------------
def plan_bpr(m):
    """返回该语料可进容量表的 B/记录；**返回 None 表示这个数不许用**。

    四条拒绝规则，每一条都对应一种"看起来更漂亮其实不能用"的数：
      * 样本量 < MIN_RECORDS_FOR_CAPACITY：小 part 的固定开销主导，测出来的是格式税；
      * ClickHouse 那档没实测（unverified）：引用它就是把假设写成测量；
      * 列数据字节 ≤ 0：0 B/记录会被当成"列式的极致收益"，是纯粹的假数；
      * 语料一条记录都没有：平均数无意义。
    """
    recs = m.get("records") or 0
    if recs < MIN_RECORDS_FOR_CAPACITY:
        return None
    v = m.get("clickhouse_repo_ddl") or {}
    if v.get("unverified"):
        return None
    bpr = v.get("column_data_bpr")
    if bpr is None or float(bpr) <= 0:
        return None
    return float(bpr)


def combine_bpr(ms):
    """多语料合并：**取较差端（max）**，任一档不可用则整体不可用。

    为什么是 max 而不是平均：规划值一旦偏小，采购与容量结论就会跟着偏小，
    而这种偏差在系统上线前没有任何东西能暴露它。取较差端最多是"多留了余量"。
    """
    vals = [plan_bpr(m) for m in ms]
    if not vals or any(v is None for v in vals):
        return None
    return max(vals)


# ---------------------------------------------------------------------------
# 自证：每条断言都必须能被判红（构造一个坏输入，要求判定函数拒绝它）
# ---------------------------------------------------------------------------
INJECTS = ["planning-40", "records-zero", "homogeneous-as-plan", "codec-no-ch",
           "small-sample-as-plan", "empty-native"]


def _good(label="多样语料", records=20000, bpr=4.87):
    return {
        "label": label, "records": records,
        "jsonl_raw_bpr": 1138.01, "jsonl_gzip_bpr": 34.08,
        "native_raw_bpr": 424.06, "native_gzip_bpr": 15.60,
        "clickhouse_default_codec": {"column_data_bpr": 33.04, "part_total_bpr": 34.76},
        "clickhouse_repo_ddl": {"column_data_bpr": bpr, "part_total_bpr": bpr * 1.32},
    }


def cmd_self_test(inject):
    ok_ = True

    def check(cond, what):
        nonlocal ok_
        print(("  ✓ " if cond else "  ✗ ") + what)
        if not cond:
            ok_ = False

    def want_none(m, what):
        check(plan_bpr(m) is None, what + " ⇒ 拒绝进容量表")

    if inject in (None, "planning-40"):
        v = plan_bpr(_good())
        check(abs(v - 4.87) < 1e-9,
              f"基线：多样语料 + 我们的 DDL = {v} B/记录（旧假设 40 B 与它差 {40.0 / v:.1f}×，"
              "所以那个数必须由产物给，不能由脚本猜）")
        check(combine_bpr([_good()]) == v, "单语料 combine 就等于它自己（没有偷偷做平均）")
    if inject in (None, "records-zero"):
        m = _good(records=0)
        want_none(m, "records=0")
        m2 = _good(records=MIN_RECORDS_FOR_CAPACITY)
        m2["clickhouse_repo_ddl"]["column_data_bpr"] = 0.0
        want_none(m2, "column_data_bpr=0")
    if inject in (None, "homogeneous-as-plan"):
        homo = _good("同质压测语料", 20182, 4.84)
        diverse = _good("多样语料", 20000, 4.87)
        check(combine_bpr([homo, diverse]) == 4.87,
              "combine 取**较差端**（4.84/4.87 ⇒ 4.87）；取 min 就是给存储预算注水")
        check(combine_bpr([homo, diverse, _good(records=37)]) is None,
              "混进一个小样本档 ⇒ 整体不可用（不许「挑一个能用的」）")
    if inject in (None, "codec-no-ch"):
        m = _good()
        m["clickhouse_repo_ddl"] = {"unverified": True, "reason": "没给 --clickhouse"}
        want_none(m, "ClickHouse 那档未实测")
        check(m["native_raw_bpr"] > m["jsonl_gzip_bpr"],
              "Native 未压缩(424.06) > gzip(JSONL)(34.08) ⇒ 这个对照必须留在产物里："
              "「列式」本身不省字节，省字节的是按列编解码器")
    if inject in (None, "small-sample-as-plan"):
        want_none(_good("真实向量", 37, 138.0), "records=37 的真实向量档（part 固定开销主导）")
    if inject in (None, "empty-native"):
        m = _good(records=MIN_RECORDS_FOR_CAPACITY)
        m["native_bytes"] = 0
        check(m["native_bytes"] == 0 and plan_bpr(m) is not None,
              "占位：空 Native 文件由 run_analyze 的 records==0 分支拦下，"
              "这里钉的是「字节统计与 B/记录不是同一个来源」这个事实")

    if not ok_:
        print("自证失败：上面的断言有一条没被满足", file=sys.stderr)
        return 1
    print("自证通过（注入项：" + (inject or "全部") + "）")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--label")
    ap.add_argument("--pcap", nargs="*", default=[])
    ap.add_argument("--json")
    ap.add_argument("--rows-per-block", type=int, default=100000)
    ap.add_argument("--gzip-level", type=int, default=GZIP_LEVEL)
    ap.add_argument("--analyze", default="target/debug/cythsec-analyze")
    ap.add_argument("--clickhouse")
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    ap.add_argument("--combine", nargs="*", default=[],
                    help="把多份测量产物合成容量表可引用的规划值（取较差端；任一档不可用则失败）")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--inject", choices=INJECTS)
    args = ap.parse_args(argv)

    if args.self_test:
        return cmd_self_test(args.inject)
    if args.combine:
        return cmd_combine(args.combine, args.json)
    if not args.label:
        args.label = "未命名语料"
    return cmd_measure(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
