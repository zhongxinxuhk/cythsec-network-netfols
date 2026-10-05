#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""采样后的量级还原（`CYS-TRF-053` 缺口③）的可证伪关口。

## 验的是什么

采集侧拿到"按 1:N 采过样的记录"，要还原全网量级。本关口验三件事：

1. **点估计对不对**：`N × Σ样本` 与**总体的真值**比。真值来自**同一语料的未采样一次运行**
   （直接量总体），不是估计量的自证 —— 估计量自己对不上总体才是要被抓住的错。
2. **区间可不可信**：方差式是手推的（见 `ipfix/estimate.rs` 文件头），推错时**点估计照样对、
   区间却会系统性偏窄**。所以只用点估计做判据是不够的：这里跑 24 个采样种子，数“95% 区间
   真的包含真值”的次数，要求 ≥ 20/24（名义 95% ⇒ 期望 22.8，二项 sd≈1.4 ⇒ 20 是约 2σ 下界）。
   方差式若漏了 `N(N-1)` 这类因子或写成样本内 i.i.d.，覆盖率会塌到 50% 上下，这里必红。
3. **该拒绝的拒绝**：记录里出现多个采样间隔时**不给数**（不同采样率的记录相加无意义）。

## 三项反向注入（都真的改变那次运行，不是换期望值）

| 注入 | 怎么改（改的是**那次运行**，不是期望值） | 该被哪条正常断言抓住 |
| --- | --- | --- |
| `under-declare` | 采过样（1:4）却在线上把 IE 34 改成 1 | ②点估计：还原不乘以 4 ⇒ 估成真值的 ~1/4 |
| `over-declare` | 没采样却在线上把 IE 34 改成 4 | ①未采样即精确和：被放大 4 倍、区间还不再为 0 |
| `replayed-new-flowid` | 重放时把 flowId 也改掉（导出侧 flowId 不稳定的真实形态） | ⑦重放不变性：去重认不出 ⇒ 估计值翻倍 |

前两项一起说明**估计量完全信任声明**这个盲区是真的（不是文档里一句免责声明）：
声明被改坏，点估计就等比例错、且毫无察觉 —— 所以"声明与执行一致"必须由导出侧自证
（`check-sampling.sh` 的那三条注入）。第三项说明去重是估计值的**前置条件**：
flowId 不稳定时重复记录会被当成新流，量级直接翻倍。

用法：
  python3 scripts/verify/check-estimate.py --check
  python3 scripts/verify/check-estimate.py --check --inject declared-lie
退出码：0 通过 · 1 失败 · 2 参数错
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import synthpcap  # noqa: E402

# ---- 手写期望值（都由下面的算式给出，不是从输出抄回来）----
FLOWS = 600           # 总体：600 条流 × 2 包
PACKETS_PER_FLOW = 2
INTERVAL = 4          # 1:4
SEEDS = 24            # 覆盖检验的种子数（默认；--seeds 可加大做一次性实测）
MIN_COVERED = 20      # 名义 95% 下允许的最低覆盖次数（≥20/24 ≈ 2σ 下界）
POINT_TOL = 0.35      # 点估计的相对误差上界：有效样本≈150 ⇒ 相对 se≈8.2%，35%≈4σ
UNSAMPLED_FLOWS = 150  # ⑤ 用更小的样本验证"样本越多相对误差越小"

EST_RE = re.compile(
    r"interval=(?P<interval>\d+) sampled_units=(?P<units>\d+) sampled_bytes=(?P<sb>\d+) "
    r"sampled_packets=(?P<sp>\d+) est_bytes=(?P<eb>[-\d.]+) est_packets=(?P<ep>[-\d.]+) "
    r"se_bytes=(?P<se>[-\d.]+) ci95_bytes=\[(?P<lo>[-\d.]+),(?P<hi>[-\d.]+)\] "
    r"rel_se=(?P<rel>[-\d.]+)"
)


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def export(binary, pcap, out, ipfix, extra):
    cmd = [binary, "-r", pcap, "-o", out, "--ipfix-pcap", ipfix] + extra
    rc, _, err = run(cmd)
    if rc != 0:
        raise RuntimeError(f"导出失败（{rc}）：{' '.join(cmd)}\n{err[-500:]}")
    return err


def collect(binary, pcap, out, extra=()):
    cmd = [binary, "--pcap", pcap, "-o", out, "--estimate-volume"] + list(extra)
    rc, _, err = run(cmd)
    m = EST_RE.search(err)
    est = None
    if m:
        est = {
            "interval": int(m.group("interval")),
            "units": int(m.group("units")),
            "sampled_bytes": int(m.group("sb")),
            "est_bytes": float(m.group("eb")),
            "se_bytes": float(m.group("se")),
            "lo": float(m.group("lo")),
            "hi": float(m.group("hi")),
            "rel_se": float(m.group("rel")),
        }
    refused = "estimate_refused" in err
    return rc, est, refused, err


def sum_bytes(path):
    total = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                total += json.loads(line)["counters"]["bytes"]
    return total


def check(results, label, got, ok, basis):
    results.append((label, got, ok, basis))
    mark = "✓" if ok else "✗"
    print(f"    {mark} {label}（{basis}）：{got}")
    return ok


def cmd_check(args):
    tmp = tempfile.mkdtemp(prefix="cythsec-estimate-")
    analyze, collector = args.analyze, args.collector
    flows, seeds, min_covered = args.flows, args.seeds, args.min_covered
    corpus = os.path.join(tmp, "corpus.pcap")
    packets = synthpcap.make_flow_pcap(corpus, flows, packets_per_flow=PACKETS_PER_FLOW)
    print(f"  语料：{flows} 条流 · {packets} 个包（脚本自造；各流大小不同 → 方差式不退化成理想情形）")

    results = []
    ok = True

    # ---- 真值：同一语料**未采样**跑一遍（直接量总体，与估计量无关）----
    truth_pcap, truth_jsonl = os.path.join(tmp, "truth.pcap"), os.path.join(tmp, "truth.jsonl")
    export(analyze, corpus, truth_jsonl, truth_pcap, [])
    truth = sum_bytes(truth_jsonl)
    print(f"  真值：未采样跑到 {truth} 字节（{flows} 条流的总体合计）")

    # ---- ① 未采样（N=1）：估计值必须等于真值，区间宽为 0 ----
    truth_src = truth_pcap
    if args.inject == "over-declare":
        truth_src = os.path.join(tmp, "over.pcap")
        synthpcap.concat_pcaps(truth_src, truth_pcap)
        n = synthpcap.patch_ie34(truth_src, INTERVAL)
        on_wire = synthpcap.tshark_ie34(truth_src)
        assert n > 0 and on_wire and set(on_wire) == {INTERVAL}, f"注入未生效：改了 {n} 条，线路 {on_wire}"
        print(f"  [注入 over-declare] 未采样的 {n} 条记录在线路上被声明成 1:{INTERVAL}（tshark 复核：{sorted(set(on_wire))}）")
    rc1, e1, _, _ = collect(collector, truth_src, os.path.join(tmp, "c1.jsonl"))
    got = None if e1 is None else (e1["est_bytes"], e1["lo"], e1["hi"], e1["se_bytes"])
    ok &= check(
        results, "①N=1 → 点估计==真值 且区间宽 0", f"est={got}",
        e1 is not None and e1["interval"] == 1 and abs(e1["est_bytes"] - truth) < 0.5
        and e1["lo"] == e1["hi"] == e1["est_bytes"] and e1["se_bytes"] == 0.0,
        "未采样即精确和：估计值=真值、se=0（p=1 时方差式为 0）",
    )

    # ---- 注入 declared-lie：把线路上的 IE 34 改成 1（导出器撒谎）----
    lie_pcap = os.path.join(tmp, "lie.pcap")
    sampled_pcap = os.path.join(tmp, "s4.pcap")
    sampled_jsonl = os.path.join(tmp, "s4.jsonl")
    export(analyze, corpus, sampled_jsonl, sampled_pcap, ["--sample", f"1:{INTERVAL}", "--sampling-seed", "7"])
    src_pcap = sampled_pcap
    if args.inject == "under-declare":
        synthpcap.concat_pcaps(lie_pcap, sampled_pcap)
        n = synthpcap.patch_ie34(lie_pcap, 1)
        # 先确认"线路真的被改了"：否则注入没生效，后面的红是无意义的红。
        on_wire = synthpcap.tshark_ie34(lie_pcap)
        assert n > 0 and on_wire and set(on_wire) == {1}, f"注入未生效：改了 {n} 条，线路值 {on_wire}"
        src_pcap = lie_pcap
        print(f"  [注入 under-declare] 1:{INTERVAL} 采样却在线上声明成 1：{n} 条记录被改（tshark 复核：{sorted(set(on_wire))}）")

    # ---- ② 1:4 点估计落在真值附近 ----
    rc2, e2, _, _ = collect(collector, src_pcap, os.path.join(tmp, "c2.jsonl"))
    if e2 is None:
        ok &= check(results, f"②1:{INTERVAL} 点估计相对误差 ≤ {POINT_TOL:.0%}", "无估计值（应当有）", False,
                    f"有效样本≈{flows // INTERVAL} ⇒ 相对 se≈1/√{flows // INTERVAL}≈8.2%")
    else:
        err = abs(e2["est_bytes"] - truth) / truth
        ok &= check(
            results, f"②1:{INTERVAL} 点估计相对误差 ≤ {POINT_TOL:.0%}", f"{err:.2%}（est={e2['est_bytes']:.0f}）",
            err <= POINT_TOL,
            f"有效样本≈{flows // INTERVAL} ⇒ 相对 se≈8.2%，上界取 4σ",
        )
        # ---- ⑤ 相对标准误应与样本量相称：1:4 时 rel_se ≈ √((N-1)/N)/√n ≤ 1/√n ----
        # 方差式若漏了 N(N-1) 因子，rel_se 会差一个数量级（这里会红）。
        n_units = max(e2["units"], 1)
        ok &= check(
            results, "⑤相对标准误与有效样本量相称", f"rel_se={e2['rel_se']:.4f} ≤ 1/√{n_units}={1 / n_units ** 0.5:.4f}",
            e2["rel_se"] <= 1.0 / n_units ** 0.5 * 1.05,
            "等概率抽样的相对标准误上界 ≈ 1/√(样本单位数)（N≥2 时系数 √((N-1)/N)<1）",
        )

    # ---- ③ 覆盖率：24 个种子，95% 区间应包含真值 ≥ 20 次 ----
    covered, widths = 0, []
    for seed in range(1, seeds + 1):
        p = os.path.join(tmp, f"seed{seed}.pcap")
        export(analyze, corpus, os.path.join(tmp, f"seed{seed}.jsonl"), p,
               ["--sample", f"1:{INTERVAL}", "--sampling-seed", str(seed)])
        rc, e, _, _ = collect(collector, p, os.path.join(tmp, f"seed{seed}.c.jsonl"))
        if e and e["lo"] <= truth <= e["hi"]:
            covered += 1
        if e:
            widths.append((e["hi"] - e["lo"]) / truth)
    ok &= check(
        results, f"③{seeds} 个种子的 95% 区间覆盖真值 ≥ {min_covered} 次", f"{covered}/{seeds}",
        covered >= min_covered,
        f"名义 95% ⇒ 期望 {seeds * 0.95:.1f} 次，二项 sd≈{((seeds * 0.95 * 0.05) ** 0.5):.1f} ⇒ {min_covered} 是约 2σ 下界（方差式推错会塌到 ~50%）",
    )

    # ---- ④ 区间宽度随采样率变粗而变大（手推 se ∝ √(N(N-1))）----
    widths_by_n = {}
    for n in (2, 8):
        p = os.path.join(tmp, f"n{n}.pcap")
        export(analyze, corpus, os.path.join(tmp, f"n{n}.jsonl"), p, ["--sample", f"1:{n}", "--sampling-seed", "7"])
        rc, e, _, _ = collect(collector, p, os.path.join(tmp, f"n{n}.c.jsonl"))
        widths_by_n[n] = None if e is None else (e["hi"] - e["lo"]) / truth
    got = {k: (None if v is None else round(v, 4)) for k, v in widths_by_n.items()}
    ok &= check(
        results, "④区间宽度随 N 增大而变宽（1:8 > 1:2）", str(got),
        None not in widths_by_n.values() and widths_by_n[8] > widths_by_n[2],
        "se ∝ √(N(N-1))：N 越大样本单位越少、每个代表的量越多 ⇒ 不确定性单调上升",
    )

    # ---- ⑥ 混合采样间隔必须拒绝（且**不给数**）----
    # 同一份 pcap 里既有 1:1 又有 1:4 的记录：网关/多导出进程混流的真实形态。
    mixed = os.path.join(tmp, "mixed.pcap")
    synthpcap.concat_pcaps(mixed, truth_pcap, sampled_pcap)
    rc6, e6, refused6, err6 = collect(collector, mixed, os.path.join(tmp, "c6.jsonl"))
    ok &= check(
        results, "⑥混合采样间隔 → 拒绝给数（退出码 3）",
        f"rc={rc6} refused={refused6} est={'有' if e6 else '无'}",
        rc6 == 3 and refused6 and e6 is None,
        "不同采样率的记录相加无意义：宁可没有数，也不给一个看起来像答案的错数",
    )

    # ---- ⑦ 重放/重传不变性：同一批 datagram 再来一遍，估计值必须不变 ----
    replay = os.path.join(tmp, "replay.pcap")
    if args.inject == "replayed-new-flowid":
        # 注入：重放的那一份连 flowId 一起改掉（导出侧 flowId 不稳定的真实形态）。
        # 去重键含 flowId，于是认不出重复 ⇒ 估计值翻倍。
        second = os.path.join(tmp, "replay2.pcap")
        synthpcap.concat_pcaps(second, sampled_pcap)
        n = synthpcap.rewrite_flow_id(second)
        assert n > 0, "注入未生效：没改到 flowId"
        synthpcap.concat_pcaps(replay, sampled_pcap, second)
        print(f"  [注入 replayed-new-flowid] 重放的一份里 {n} 条记录的 flowId 被改掉（去重认不出）")
    else:
        synthpcap.concat_pcaps(replay, sampled_pcap, sampled_pcap)
    rc7, e7, _, err7 = collect(collector, replay, os.path.join(tmp, "c7.jsonl"))
    dup = int(re.search(r"duplicates=(\d+)", err7).group(1)) if re.search(r"duplicates=(\d+)", err7) else 0
    if e2 is None:
        ok &= check(results, "⑦重放 datagram 后估计值不变", "无基准估计值", False, "需要 ② 先成立")
    else:
        same = e7 is not None and abs(e7["est_bytes"] - e2["est_bytes"]) < 0.5
        ok &= check(
            results, "⑦重放 datagram 后估计值不变（去重生效）",
            f"duplicates={dup} est={None if e7 is None else e7['est_bytes']:.0f} vs 基准 {e2['est_bytes']:.0f}",
            same and dup > 0,
            "估计量的输入是**交付出去的记录**：重放被去重吃掉 ⇒ 不能翻倍（翻倍是最经典的采样估计错误）",
        )

    print()
    if ok:
        print(
            "✓ 量级还原判定通过（点估计对总体真值、区间覆盖 ≥"
            f"{min_covered}/{seeds}、拒绝混合间隔、重放不翻倍）"
        )
        return 0
    print("✗ 量级还原判定失败（上面标 ✗ 的项）", file=sys.stderr)
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="采样后的量级还原关口（CYS-TRF-053 ③）")
    ap.add_argument("--check", action="store_true", help="运行判定")
    ap.add_argument("--analyze", default="./target/release/cythsec-analyze")
    ap.add_argument("--collector", default="./target/release/cythsec-ipfix-collect")
    ap.add_argument("--flows", type=int, default=FLOWS, help="语料流数（默认 600）")
    ap.add_argument("--seeds", type=int, default=SEEDS, help="覆盖检验的种子数（默认 24；实测覆盖率时可加大）")
    ap.add_argument("--min-covered", type=int, default=MIN_COVERED, help="覆盖次数下限（默认 20）")
    ap.add_argument(
        "--inject",
        default=None,
        choices=["under-declare", "over-declare", "replayed-new-flowid"],
        help="反向注入：改变那次运行（模拟导出器撒谎 / 采样率混流 / 去重失效），判定必须判红",
    )
    args = ap.parse_args(argv)
    if not args.check:
        ap.print_help()
        return 2
    for b in (args.analyze, args.collector):
        if not os.path.exists(b):
            print(f"✗ 缺被测二进制：{b}（先 cargo build --release）", file=sys.stderr)
            return 2
    return cmd_check(args)


if __name__ == "__main__":
    sys.exit(main())
