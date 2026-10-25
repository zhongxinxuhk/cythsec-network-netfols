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

## 实测得到的结论（2026-10-22 本机跑出来的数，见 docs/planning/measurements/columnar-*.json）

两档**容量可用**（≥5,000 条）的合成语料，同一份 DDL 只差编解码器：

| 语料 | 条数 | JSONL 未压缩 | JSONL+gzip9 | Native 未压缩 | CH 默认 LZ4 | CH 我们的 DDL |
| --- | --- | --- | --- | --- | --- | --- |
| 同质压测（bench.pcap） | 20,182 | 1066.05 | 21.04 | 347.06 | 22.81 | **5.11** |
| 多样合成（bench-diverse.pcap） | 20,000 | 1082.42 | 130.16 | 346.91 | 138.32 | **78.50** |
| 真实向量（版本库内） | 37 | 1008.27 | 80.24 | 514.54 | 141.49 | 139.16 |

* **默认 LZ4 下，列式不比 gzip(JSONL) 省**：多样语料 138.32 vs 130.16 B/记录，甚至略输。
  "换成列式数据库"本身不带来数量级收益 —— 这句是本档存在的意义。
* 收益全部来自**按列编解码器 + LowCardinality**：同一 schema 只差 CODEC 时
  多样语料 1.8×（138.32→78.50）、同质语料 4.5×（22.81→5.11）。
* 规划取**较差端 = 78.5 B/记录**（多样档）。它与 gzip(JSONL) 的既有规划值 79.4 基本持平 ⇒
  容量表的 TB/天不会因为"改用列式"而改变量级。
* 三个数都依赖 `storage/clickhouse/001_flows.sql` 的 CODEC/LowCardinality 选择：**换 DDL 必须重测**；
  且两档大样本语料都是本仓生成器合成的（`generate-bench.py --profile homogeneous|diverse`），
  **现场必须用自己的流量重标定**。
* 注意反向结论也曾写错：本文件旧版写着"多样语料上比 gzip(JSONL) 小约 3.7×"，
  那是**没跑出来的预期**；实跑是 1.66×（130.16/78.50）。教训同 §2.14：先量再写。

## 用法

    measure-columnar.py --label 名字 --pcap a.pcap [b.pcap ...] [--json 产物.json]
                        [--rows-per-block 100000] [--analyze <bin>] [--clickhouse <bin>]
    measure-columnar.py --self-test [--inject 名字]

退出码：0 正常；1 输入或自证失败；2 参数错误；3 环境缺工具（对应档标"未核验"）。
"""

import argparse
import json
import os
import re
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


def rename_table(ddl_text, table):
    """把 DDL 里的表名换成 `table`，**只认 CREATE 语句那一处**。

    为什么不是 `ddl.replace("flows", table, 1)`：这份 DDL 里 "flows" 第一次出现是在
    文件头的「重新生成」注释里（`… > storage/clickhouse/001_flows.sql`），
    于是改名的那一下打在注释上，CREATE 语句还是 `flows` ——
    紧接着 `INSERT INTO flows_default` 报 UNKNOWN_TABLE。
    而这条报错在 2026-10-22 之前会被归成「未核验」，③ 档就此静默消失。
    """
    out, n = re.subn(r"CREATE TABLE IF NOT EXISTS\s+`?\w+`?",
                     "CREATE TABLE IF NOT EXISTS " + table, ddl_text, count=1)
    if n != 1:
        raise ValueError("DDL 里没有 `CREATE TABLE IF NOT EXISTS <表名>` 这一行，"
                         "改表名这件事无法安全完成 —— 拒绝猜测")
    if "CREATE TABLE IF NOT EXISTS " + table not in out:
        raise ValueError("改表名后 CREATE 语句里没有 " + table)
    return out


def ch_measure(clickhouse, ddl_text, native_path, workdir, table, records):
    """把产物插进真实 MergeTree，返回 part 目录的字节分解。

    数字来自**文件系统**，不是估算：列数据取 `*.bin`，其余（`*.mrk2/*.idx/*_count.txt`
    等）单列为索引/元数据，两者都换算成 B/记录。
    """
    path = os.path.join(workdir, "chdata")
    os.makedirs(path, exist_ok=True)
    query = (
        rename_table(ddl_text, table)
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


def _match_paren(text, open_idx):
    """从 `text[open_idx] == '('` 找到配对的 `)`（跳过单引号字符串里的括号）。

    为什么不数一行里的左右括号个数就完事：`CODEC(Delta(4), ZSTD(1))` 是**嵌套**的，
    而第一个 `)` 关的是 `Delta(4`。取第一个 `)` 会把 `, ZSTD(1))` 留在原地 ——
    这正是 2026-10-22 真实踩到的坑：baseline DDL 被 ClickHouse 以
    `Unmatched parentheses` 拒收，③ 档（没有按列 CODEC 的对照）静默变成「未核验」，
    于是「编解码器净收益 N×」这句话再也没有数字支撑，而报告照样打印得出来。
    """
    depth = 0
    in_str = False
    i = open_idx
    while i < len(text):
        c = text[i]
        if in_str:
            if c == "'":
                in_str = False
        elif c == "'":
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError(f"括号不配对（位置 {open_idx}）："
                     f"{text[max(0, open_idx - 40):open_idx + 40]!r}")


def _find_call(text, name, start=0):
    """找下一个**不在单引号字符串里**的 `name(`，返回 (起始, 右括号位置)；没有则 None。"""
    pat = name + "("
    i = text.find(pat, start)
    while i != -1:
        if text.count("'", 0, i) % 2 == 0:      # 单引号成对 ⇒ 当前位置在字符串外
            return i, _match_paren(text, i + len(name))
        i = text.find(pat, i + 1)
    return None


def _drop_clause(text, name):
    """整段删掉 `NAME(...)`（连同前面那个空格），嵌套一并算进去。"""
    while True:
        hit = _find_call(text, name)
        if hit is None:
            return text
        lo, hi = hit
        left = lo - 1 if lo > 0 and text[lo - 1] == " " else lo
        text = text[:left] + text[hi + 1:]


def _unwrap_type(text, name):
    """`LowCardinality(Nullable(String))` → `Nullable(String)`：只剥外壳，保留内部类型。"""
    while True:
        hit = _find_call(text, name)
        if hit is None:
            return text
        lo, hi = hit
        inner = text[lo + len(name) + 1:hi]
        text = text[:lo] + inner + text[hi + 1:]


def baseline_ddl(ddl_text):
    """我们 DDL 的"默认编解码"对照版：去掉所有 CODEC 子句、去掉 LowCardinality。

    这是**同一个 schema 的唯一变量控制**：只改编码，不改列、不改类型语义，
    这样 ③ 与 ④ 的差值才是"编解码器选择"的净收益，而不是别的。
    """
    out = []
    for line in ddl_text.splitlines():
        s = _unwrap_type(line, "LowCardinality")
        s = _drop_clause(s, "CODEC")
        out.append(s)
    return "\n".join(out)


def _column_names(text):
    """取列定义行的列名（首 token），用于证明 baseline 只改了编码、没动列。"""
    names = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        head = stripped.split(" ", 1)[0].rstrip("(").upper()
        if head in ("CREATE", "ENGINE", "PARTITION", "ORDER", "TTL", "SETTINGS", "SELECT"):
            continue
        first = stripped.rstrip(",").split(" ", 1)[0]
        if first[:1].isalpha() or first[:1] == "_":
            names.append(first)
    return names


def _doc_paren_balance(text):
    """整份 SQL 的括号配平检查（跳过单引号字符串）。返回错误描述或 None。"""
    depth = 0
    in_str = False
    line = 1
    for i, c in enumerate(text):
        if c == "\n":
            line += 1
        if in_str:
            if c == "'":
                in_str = False
        elif c == "'":
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return f"第 {line} 行多出一个 `)`（位置 {i}）"
    if depth:
        return f"有 {depth} 个 `(` 没有闭合"
    if in_str:
        return "有单引号没有闭合"
    return None


def check_baseline_ddl(orig, baseline):
    """baseline DDL 的**四项自检**，返回不合格项列表（空列表 = 合格）。

    这四条不是洁癖：③ 档是「同一 schema 只差 CODEC」这句话的唯一支撑。一旦 baseline
    偷偷改了列、改了类型、或写出一段 ClickHouse 根本不收的 SQL，报出来的
    「编解码器净收益 N×」就是一句没有依据的话 —— 而它看起来完全像个测量结果。
    """
    bad = []
    if len(orig.splitlines()) != len(baseline.splitlines()):
        bad.append(f"行数不同：原 {len(orig.splitlines())} vs baseline {len(baseline.splitlines())}")
    if _column_names(orig) != _column_names(baseline):
        miss = sorted(set(_column_names(orig)) ^ set(_column_names(baseline)))
        bad.append(f"列被改了（不该改）：{miss[:5]}")
    for i, line in enumerate(baseline.splitlines(), 1):
        if _find_call(line, "CODEC") or _find_call(line, "LowCardinality"):
            bad.append(f"第 {i} 行仍残留 CODEC/LowCardinality：{line.strip()[:80]}")
    # 括号按**整份文档**配平：`CREATE TABLE … (` 的左括号在列表现的上一行，
    # 逐行配平会把每一行都判成不配对（第一版就是这么写错的，68 行全红）。
    err = _doc_paren_balance(baseline)
    if err:
        bad.append(f"baseline 的括号不配平：{err}")
    return bad


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
                     "ch_default_lz4_bpr": (m.get("clickhouse_default_codec") or {}).get(
                         "column_data_bpr"),
                     "native_raw_bpr": m.get("native_raw_bpr")} for m in ms],
        "not_a_claim": "这个数依赖 001_flows.sql 的 CODEC/LowCardinality 选择；换 DDL 必须重测",
        # 这一条不是免责声明，是**口径**：两档语料都是本仓生成器造出来的，
        # 多样性由 generate-bench.py 的池子给。现场的字段分布必须现场重标定。
        "corpora_are_synthetic": True,
        "recalibrate_on_site": "两档语料都由 datasets/pcap/generate-bench.py 生成；"
                               "真实省网流量的字段重复度低于二者，这个数只能当上限参考",
    }
    print(f"==> 列式规划值：{bpr} B/记录（取较差端；参与合并 {len(ms)} 档）")
    for c in out["corpora"]:
        print(f"  {c['label'][:34]:34s} records={c['records']:>7} plan={c['plan_bpr']} "
              f"gzip(JSONL)={c['jsonl_gzip_bpr']} CH默认LZ4={c['ch_default_lz4_bpr']}")
    gj = [c["jsonl_gzip_bpr"] for c in out["corpora"] if c.get("jsonl_gzip_bpr")]
    if gj:
        print(f"  对照 gzip(JSONL) 较差端：{max(gj)} B/记录 ⇒ "
              f"列式净收益 = {max(gj) / bpr:.2f}×（这一档才是「换格式值不值」的依据）")
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"产物：{out_path}")
    return 0


def _looks_like_our_sql_defect(err):
    """把 ClickHouse 的报错分成「我们的 SQL 有问题」与「环境跑不动」两类。

    分错的代价不对称：把语法错误归成「未核验」，脚本会带着一个缺失的对照档
    正常退出 0，而读者看到的那行「CH 默认 LZ4：未核验」看起来像环境问题。
    """
    e = (err or "").lower()
    # `command not found` / `No such file or directory` 才是「这台机器跑不动 ClickHouse」；
    # 其余（含 UNKNOWN_TABLE）都是我们交出去的 SQL 本身有问题，必须判红。
    if "not found" in e or "no such file" in e:
        return False
    return any(mark in e for mark in (
        "syntax_error", "unmatched parentheses", "expected",
        "unknown identifier", "unknown_database", "unknown_table",
        "does not exist", "mismatched"))


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
            # ③ 档的前提是「同一 schema，只差编解码器」。baseline 自己就写坏时，
            # ③ 会静默变成「未核验」，报告只剩 ④ 一个数，而「净收益 N×」仍在打印。
            # 所以这里先自检再交给 ClickHouse，不合格就是硬失败（不是"未核验"）。
            problems = check_baseline_ddl(ddl_text, baseline_ddl(ddl_text))
            if problems:
                for prob in problems[:6]:
                    print(f"✗ baseline DDL 不合格：{prob}", file=sys.stderr)
                return die("baseline DDL 自检未通过：③ 档（无 CODEC 对照）无法成立，"
                            "拒绝出一个没有依据的净收益")
            out["clickhouse_default_codec"] = ch_measure(
                args.clickhouse, baseline_ddl(ddl_text), native, workdir,
                "flows_default", records)
            out["clickhouse_repo_ddl"] = ch_measure(
                args.clickhouse, ddl_text, native, workdir, "flows", records)
            for k in ("clickhouse_default_codec", "clickhouse_repo_ddl"):
                if "error" in out[k]:
                    err = out[k]["error"]
                    # 「ClickHouse 不收我们生成的 SQL」与「这台机器跑不动 ClickHouse」
                    # 是两件事。前者是缺陷，必须判红；后者才是未核验。
                    if _looks_like_our_sql_defect(err):
                        return die(f"{k}：ClickHouse 拒收我们生成的 SQL（{err}）"
                                   "—— 这是测量脚本/DDL 的缺陷，不是环境问题，不标「未核验」")
                    out[k]["unverified"] = True
                    print(f"⚠ {k} 未核验：{err}", file=sys.stderr)
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
           "small-sample-as-plan", "empty-native", "baseline-ddl", "staging-rename"]


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
    if inject in (None, "baseline-ddl"):
        # ③ 档（无按列 CODEC 的对照）完全依赖 baseline_ddl 的字符串改写。它写坏时
        # ClickHouse 只是拒收，脚本把那一档标成「未核验」继续跑 —— 于是"净收益 N×"
        # 这句话只剩一半证据。故自检本身必须可判红。
        fixture = (
            "CREATE TABLE IF NOT EXISTS flows\n(\n"
            "    schema_version UInt32 CODEC(Delta(4), ZSTD(1)) COMMENT '版本（含括号）',\n"
            "    tcp_state LowCardinality(Nullable(String)) CODEC(ZSTD(1)) COMMENT '末态',\n"
            "    app_id Nullable(UInt32) CODEC(Delta(4), ZSTD(1)) COMMENT '编号',\n"
            "    risk_score Nullable(Float64) CODEC(ZSTD(1)) COMMENT '评分'\n"
            ")\nENGINE = MergeTree\nORDER BY (schema_version);\n"
        )
        base = baseline_ddl(fixture)
        check(not check_baseline_ddl(fixture, base),
              "baseline DDL 自检合格：嵌套 CODEC 剥净、列不动、括号配平")
        check("LowCardinality" not in base and "CODEC" not in base,
              "baseline 里没有残留 LowCardinality/CODEC 字样")
        check("Nullable(String)" in base and "Nullable(UInt32)" in base and "IPv6" not in base,
              "只剥外壳：LowCardinality(Nullable(String)) → Nullable(String)，类型语义不变")
        check("COMMENT '版本（含括号）'" in base,
              "单引号里的全角括号/文字不许被动（COMMENT 也是产物的一部分）")

        def naive(t):
            out = []
            for line in t.splitlines():
                x = line.replace(" LowCardinality(", "(").replace("Nullable))", "Nullable)")
                while " CODEC(" in x:
                    i = x.index(" CODEC(")
                    j = x.index(")", i) + 1
                    x = x[:i] + x[j:]
                out.append(x)
            return "\n".join(out)

        check(bool(check_baseline_ddl(fixture, naive(fixture))),
              "反向注入：旧的「取第一个右括号」剥法必须被判红（真实踩过一次）")
        check(bool(_doc_paren_balance(naive(fixture))),
              "反向注入：旧剥法产出的 SQL 括号不配平（ClickHouse 会报 SYNTAX_ERROR）")
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        real = os.path.join(root, "storage", "clickhouse", "001_flows.sql")
        if os.path.isfile(real):
            orig = open(real, encoding="utf-8").read()
            check(not check_baseline_ddl(orig, baseline_ddl(orig)),
                  "仓库真源 DDL（56 列，记录契约 v2）的 baseline 自检同样合格")
        else:
            print("  ⚠ 仓库 DDL 不在位（生成物未产出）：这一项**未核验**，不算通过")
    if inject in (None, "staging-rename"):
        # ③ 档要把 DDL 建成另一张 staging 表。改错地方的话 INSERT 会打到一张不存在的表上，
        # 而"表不存在"看起来像环境问题 —— 所以改名这件事与报错分类都必须可判红。
        fixture = ("-- 重新生成：cargo run … > storage/clickhouse/001_flows.sql\n"
                   "CREATE TABLE IF NOT EXISTS flows\n(\n    a UInt8\n)\n"
                   "ENGINE = MergeTree ORDER BY a;\n")
        renamed = rename_table(fixture, "flows_default")
        check("CREATE TABLE IF NOT EXISTS flows_default" in renamed,
              "改表名打在了 CREATE 语句上")
        check("001_flows.sql" in renamed.splitlines()[0],
              "注释里的文件名不许被动（否则改的那一下落在注释上）")
        naive = fixture.replace("flows", "flows_default", 1)
        check("CREATE TABLE IF NOT EXISTS flows_default" not in naive,
              "反向注入：`replace(..., 1)` 那种写法必须被上面两条抓住（真实踩过）")
        check(_looks_like_our_sql_defect(
                  "Code: 60. DB::Exception: Table default.flows_default does not exist. (UNKNOWN_TABLE)"),
              "UNKNOWN_TABLE 归成「我们的 SQL 有缺陷」，不许冒充未核验")
        check(not _looks_like_our_sql_defect(
                  "FileNotFoundError: [Errno 2] No such file or directory: 'clickhouse'"),
              "ClickHouse 二进制不在 ⇒ 判为「未核验」（这条是真的没跑）")

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
