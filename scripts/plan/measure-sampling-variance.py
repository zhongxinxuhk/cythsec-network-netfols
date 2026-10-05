#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""measure-sampling-variance.py —— 采样估计量的**经验方差**实测（`CYS-TRF-053` ③ 的旁证）。

## 为什么必须实测

`ipfix/estimate.rs` 的区间按**独立伯努利抽样**推（`Var(T̂) ≈ N(N-1)·Σ样本 x²`）。但本仓
导出器用的是**确定性哈希**（同一个流每次都被选中/不被选中），它在方差上是**准系统抽样**：
比伯努利更"规整"，实际方差应当**更小**。小多少不能靠嘴说 —— 只能拿真语料跑多个种子量出来，
否则"区间保守"就成了一句没有样本量的断言。

这个实测直接决定对外话术：如果实测覆盖率只有 ~90%，说明区间**偏窄**（危险）；如果是 100%，
说明区间**偏宽**（安全但不精确），必须写明"这是上界性质"。

## 量什么

* `kept_units_sd`：各种子留存条数的标准差（同一语料 1:N 采样）→ 与伯努利理论
  `√(M·p·(1-p))` 比，得到**设计效应** `(实测/理论)²`；
* `rel_err_sd`：各种子估计值相对真值的标准差（真值来自同语料**未采样**的一次运行）；
* `reported_rel_se`：产品自报的相对标准误均值；
* `coverage`：95% 区间包含真值的次数/种子数。

## 反注入（改的是**报告出来的数**，随后断言必须判红）

* `use-bernoulli-sd`：把实测 sd 换成伯努利理论 sd（也就是"没量就写理论值"）；
* `drop-seeds`：只报前 10 个种子却在 JSON 里写 `seeds=全部`（用样本量造假）。

用法：
  python3 scripts/plan/measure-sampling-variance.py --json docs/planning/measurements/sampling-variance.json
  python3 scripts/plan/measure-sampling-variance.py --inject use-bernoulli-sd   # 必须判红
退出码：0 通过 · 1 断言失败（含注入被检出后的失败）· 2 参数/环境错
"""

import argparse
import json
import math
import os
import re
import statistics
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "verify"))
import synthpcap  # noqa: E402

FLOWS = 600
INTERVAL = 4
SEEDS = 200
# 手写判据：确定性哈希的方差**应当**小于伯努利理论（准系统抽样），但不可能小到 0。
# 比值上界取 0.9（等式情形=独立伯努利抽样），下界 0.1（小于 0.1 说明几乎固定条数，
# 那要么哈希退化要么语料退化，都该看一眼）。
SD_RATIO_MAX = 0.9
SD_RATIO_MIN = 0.1

EST_RE = re.compile(r"sampled_units=(\d+).*?est_bytes=([-\d.]+) .*?rel_se=([-\d.]+)")


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stderr


def main(argv=None):
    ap = argparse.ArgumentParser(description="采样估计量的经验方差实测（CYS-TRF-053 ③）")
    ap.add_argument("--flows", type=int, default=FLOWS)
    ap.add_argument("--interval", type=int, default=INTERVAL)
    ap.add_argument("--seeds", type=int, default=SEEDS)
    ap.add_argument("--analyze", default="./target/release/cythsec-analyze")
    ap.add_argument("--collector", default="./target/release/cythsec-ipfix-collect")
    ap.add_argument("--json", default=None, help="把实测数字写成产物")
    ap.add_argument("--label", default="核心采样 1:4（确定性哈希）")
    ap.add_argument("--inject", default=None, choices=["use-bernoulli-sd", "drop-seeds"])
    args = ap.parse_args(argv)
    for b in (args.analyze, args.collector):
        if not os.path.exists(b):
            print(f"✗ 缺被测二进制 {b}（先 cargo build --release）", file=sys.stderr)
            return 2

    tmp = tempfile.mkdtemp(prefix="cythsec-var-")
    corpus = os.path.join(tmp, "corpus.pcap")
    synthpcap.make_flow_pcap(corpus, args.flows, packets_per_flow=2)
    rc, _ = run([args.analyze, "-r", corpus, "-o", f"{tmp}/t.jsonl", "--ipfix-pcap", f"{tmp}/t.pcap"])
    if rc != 0:
        return 2
    truth = 0
    with open(f"{tmp}/t.jsonl", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                truth += json.loads(line)["counters"]["bytes"]

    units, ests, rel_ses, covered = [], [], [], 0
    for seed in range(1, args.seeds + 1):
        pcap, out = f"{tmp}/s{seed}.pcap", f"{tmp}/s{seed}.c.jsonl"
        rc, err = run([args.analyze, "-r", corpus, "-o", f"{tmp}/s{seed}.jsonl",
                       "--ipfix-pcap", pcap, "--sample", f"1:{args.interval}",
                       "--sampling-seed", str(seed)])
        if rc != 0:
            return 2
        rc, err = run([args.collector, "--pcap", pcap, "-o", out, "--estimate-volume"])
        m = EST_RE.search(err)
        lo = re.search(r"ci95_bytes=\[([-\d.]+),([-\d.]+)\]", err)
        if not m or not lo:
            print("✗ 采集器没给出估计行", file=sys.stderr)
            return 2
        units.append(int(m.group(1)))
        ests.append(float(m.group(2)))
        rel_ses.append(float(m.group(3)))
        if float(lo.group(1)) <= truth <= float(lo.group(2)):
            covered += 1

    p = 1.0 / args.interval
    theo_sd = math.sqrt(args.flows * p * (1 - p))
    kept_sd = statistics.stdev(units)
    rel_err_sd = statistics.stdev([e / truth - 1 for e in ests])
    ratio = kept_sd / theo_sd
    report = {
        "label": args.label,
        "corpus": {"flows": args.flows, "packets": args.flows * 2, "truth_bytes": truth,
                   "synthetic": True, "generator": "scripts/verify/synthpcap.py"},
        "design": {"interval": args.interval, "seeds": args.seeds, "sampler": "确定性哈希（flow 模式）"},
        "measured": {
            "kept_units_mean": statistics.mean(units),
            "kept_units_sd": kept_sd,
            "kept_units_min": min(units),
            "kept_units_max": max(units),
            "rel_err_sd": rel_err_sd,
            "reported_rel_se_mean": statistics.mean(rel_ses),
            "coverage": covered,
            "coverage_frac": covered / args.seeds,
        },
        "bernoulli_theory": {"p": p, "kept_units_sd": theo_sd},
        "design_effect": {"sd_ratio": ratio, "variance_ratio": ratio ** 2},
        "caveats": [
            "语料是脚本自造的合成流量（各流大小相近但不相同）：真实流量的大小分布更重尾，"
            "设计效应会与这里不同 —— 现场必须用**同样的多种子重放**重新标定。",
            "结论只对'哈希在真实流键分布上分布良好'成立；若键分布退化（大量键落进同一残差类），"
            "留存条数会走向全中/全不中，实际方差可超过伯努利上界，此时区间会偏窄。",
            "真值来自同语料未采样的一次运行（直接量总体），不是估计量自证。",
        ],
    }

    # ---- 反注入：改报告出来的数（不是换期望值）----
    if args.inject == "use-bernoulli-sd":
        report["measured"]["kept_units_sd"] = theo_sd
        report["design_effect"] = {"sd_ratio": 1.0, "variance_ratio": 1.0}
        print("[注入 use-bernoulli-sd] 实测 sd 被替换成伯努利理论 sd（=没量就写理论值）")
    elif args.inject == "drop-seeds":
        report["measured"]["coverage"] = min(10, covered)
        report["measured"]["coverage_frac"] = min(10, covered) / args.seeds
        report["design"]["seeds"] = args.seeds  # 样本量照写全量 —— 这就是要抓的造假
        print("[注入 drop-seeds] 覆盖率只按前 10 个种子报，样本量却写全量")

    m = report["measured"]
    print(f"  语料：{args.flows} 条流 · 真值 {truth} 字节 · 采样 1:{args.interval} · {args.seeds} 个种子")
    print(f"  留存条数：均值 {m['kept_units_mean']:.1f}（理论 {args.flows * p:.1f}）"
          f" sd {m['kept_units_sd']:.2f}（伯努利理论 {theo_sd:.2f}）")
    print(f"  估计相对误差 sd {m['rel_err_sd'] * 100:.2f}% · 产品自报相对 se 均值"
          f" {m['reported_rel_se_mean'] * 100:.2f}%")
    print(f"  95% 区间覆盖率 {m['coverage']}/{report['design']['seeds']}"
          f"（{m['coverage_frac'] * 100:.1f}%）")

    ok = True
    if not (SD_RATIO_MIN < report["design_effect"]["sd_ratio"] < SD_RATIO_MAX):
        print(f"✗ 留存条数 sd / 伯努利理论 sd = {report['design_effect']['sd_ratio']:.3f}"
              f" 不在 ({SD_RATIO_MIN}, {SD_RATIO_MAX}) 内：确定性哈希应当比独立抽样更规整，"
              f"落在这个区间外说明实测本身有问题（注入或语料退化）", file=sys.stderr)
        ok = False
    else:
        print(f"  ✓ 设计效应 {report['design_effect']['variance_ratio']:.2f}"
              f"（sd 比 {report['design_effect']['sd_ratio']:.2f}）：确定性哈希比独立伯努利更规整 ⇒"
              f" 产品区间偏保守（覆盖面 {m['coverage_frac'] * 100:.0f}% ≥ 95%）")
    # 覆盖率与样本量必须自洽：注入 drop-seeds 会在这里露出来（覆盖次数 ≠ 种子数时不允许报全量种子）
    if m["coverage"] != report["design"]["seeds"]:
        print(f"✗ 覆盖率 {m['coverage']} 与种子数 {report['design']['seeds']} 不一致："
              f"样本量必须与实际跑的次数一致（这是注入 drop-seeds 要抓的造假）", file=sys.stderr)
        ok = False
    if m["reported_rel_se_mean"] <= m["rel_err_sd"]:
        print("✗ 产品自报的相对 se 没有大于实测误差 sd：区间不是保守而是偏窄（危险方向）",
              file=sys.stderr)
        ok = False

    if args.json and ok:
        os.makedirs(os.path.dirname(args.json), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"  产物已写入 {args.json}")
    if not ok:
        return 1
    print("✓ 采样方差实测通过（实测数字自洽、方向正确）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
