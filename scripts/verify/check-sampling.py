#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""流级采样（CYS-TRF-053）的判定与反向注入：**声明与执行必须一致**。

## 这个脚本要回答的三个问题（缺一个，采样就等于没有把关）

1. **执行了吗**：`--sample 1:N` 之后流数确实减少（不是"声明了 N 倍却全量导出"）。
2. **采对了吗**：`flow` 模式下留下的流是**完整**的 —— 每条被采到的流，其计数/特征与
   不采样时**逐字段相同**。逐包随机采会把一条会话撕成半条：状态机看到跳号、重组看到
   缺片，产出的记录**看起来正常**，但结论是错的（比"少几条记录"糟得多）。
3. **说的一致吗**：IPFIX 报文里的 IE 34 == 配置的 N，且**记录条数 == 实际留下的流数**；
   不采样时 IE 34 必须是 1（不能反过来虚报"采过样"）。

## 期望值都是手算的

- 语料：`--flows N` 条**互不相同的**合成流（脚本自己造 pcap，不用仓库里的向量文件，
  免得向量一改这个关口就悄悄变了判据）。每条流一进一出两个包。
- `1:4` 的保留比例期望 1/4；N=400 条流时二项分布 sd = sqrt(400·0.25·0.75) ≈ 8.7 条，
  取 **±12 条（±3%）** 已经极稳（>10 sd），不会随机变红。
- `packet` 模式每 4 个包留 1 个 ⇒ 800 个包留 200 个（包级是**精确**的：按计数决定）。

## 反向注入（这几条才是这个脚本的价值）

`--inject <名字>` **真的把被测的那次运行改坏**（不是"拿一个错值来比"），然后照常跑全部
判定；只要有一条红，脚本就以非零退出。三条注入各自对应一个真实缺陷类：

- `keep-all`：**采样器没接上**（"配置项看起来在做事，实际一个包都不丢"）—— 这正是本项
  落地前 `ExportConfig.sampling_interval` 的状态（被校验、被忽略）。问题①必须红。
- `torn-flows`：**逐包决定却自称 flow**（把采样挪到包序上）—— 记录与不采样时不同（缺包
  缺片），问题②必须红。这也是"流级随机采"最坏的那个后果。
- `no-ipfix`：**声明从未落线**（漏传 `--ipfix-pcap`）—— 问题③必须红（而不是"没得验就放行"）。

第四条轴（IE 34 被硬编码成 1）由 Rust 单测守着（`export::tests::
sampling_interval_is_written_into_records`）：那是编码器内部的回归，用 Python 改不了
二进制，所以放在离缺陷最近的地方。
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile

# ---- 手写期望值（全部由下面的算式给出，不是从输出抄回来）----
KEPT_NUM = 1  # 保留 1/N
KEPT_DEN = 4
TOLERATED_FLOWS = 12  # 400 条流 @1:4 的 ±3%（≈10 sd），见文件头

DEFAULT_FLOWS = 400


# 造语料的代码在 synthpcap.py 里与 check-estimate.py **共用一份**：各写一份的后果是两处会漂移
# （一边改了包长/时序，另一边的手算期望值就悄悄不成立），而这种失效只会让断言变成"永远通过"。
import synthpcap  # noqa: E402  （与本文件同目录）


def make_corpus(path, flows):
    """`flows` 条互不相同的 TCP 会话，每条两个包（各带载荷，保证 DPI 有东西看）。

    流键（src/dst/sport/dport）由 synthpcap 固定，本文件的手算期望值（留 1/4 ⇒ 100±12）
    依赖的正是"流的条数"与"包的总数"，与字节数无关。
    """
    return synthpcap.make_flow_pcap(path, flows, packets_per_flow=2)


def run_analyze(binary, pcap, out, extra):
    cmd = [binary, "-r", pcap, "-o", out] + extra
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} 退出码 {proc.returncode}：{proc.stderr[-600:]}")
    return proc.stderr


def parse_stats(stderr):
    """从 stderr 摘要里取采样字段（键名由 CLI 契约固定）。"""
    got = {}
    for line in stderr.splitlines():
        if "sampling_interval=" not in line:
            continue
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                got[k] = v
    return got


def flow_key(rec):
    """记录里的流键（JSON 契约：顶层 `flow` 对象）。"""
    f = rec["flow"]
    return (f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"], f["proto"])


def load_jsonl(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
    return out


def ipfix_sampling_intervals(pcap):
    """用 tshark（唯一的第三方真源）读 IE 34；tshark 缺席时返回 None。"""
    cmd = [
        "tshark", "-r", pcap, "-d", "udp.port==4739,cflow",
        "-T", "fields", "-e", "cflow.sampling_interval",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    vals = []
    for line in proc.stdout.splitlines():
        for tok in line.split(","):
            if tok.strip():
                vals.append(int(tok))
    return vals


def check(indent, label, got, ok):
    print(f"    {'✓' if ok else '✗'} {indent}{label}：{got}")
    return ok


def cmd_check(args):
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "corpus.pcap")
        packets = make_corpus(pcap, args.flows)
        print(f"  语料：{args.flows} 条互不相同的 TCP 会话 · {packets} 个包（脚本自造，手算基数）")

        # ---- 注入：真的改坏被测的那次运行（见文件头）----
        inject = args.inject
        sampled_extra = ["--sample", f"1:{KEPT_DEN}"]
        if inject == "keep-all":
            # 采样器没接上：命令行给了 1:N，实际按全量跑
            sampled_extra = []
        elif inject == "torn-flows":
            # 逐包决定却用 flow 模式的口径去判它
            sampled_extra = ["--sample", f"1:{KEPT_DEN}", "--sampling-mode", "packet"]
        want_ipfix = {"plain", "sampled"}
        if inject == "no-ipfix":
            want_ipfix = {"plain"}
        if inject:
            print(f"  **注入生效**：{inject}（这次运行按改坏后的方式跑，判定不变）")

        outs = {}
        for name, extra in (
            ("plain", []),
            ("sampled", sampled_extra),
            ("sampled_w4", list(sampled_extra) + ["--workers", "4"]),
            ("packet", ["--sample", f"1:{KEPT_DEN}", "--sampling-mode", "packet"]),
        ):
            path = os.path.join(tmp, f"{name}.jsonl")
            ipfix = os.path.join(tmp, f"{name}.pcap") if name in want_ipfix else None
            extra = list(extra) + (["--ipfix-pcap", ipfix] if ipfix else [])
            stderr = run_analyze(args.binary, pcap, path, extra)
            outs[name] = {
                "jsonl": path,
                "ipfix": ipfix,
                "records": load_jsonl(path),
                "stats": parse_stats(stderr),
                "stderr": stderr,
            }

        plain = outs["plain"]["records"]
        sampled = outs["sampled"]["records"]
        expect_kept = args.flows * KEPT_NUM // KEPT_DEN  # 手算：400×1/4 = 100

        # ---- 问题 1：执行了吗 ----
        ok &= check("①", f"不采样 → 流量 {len(plain)} 条（手算 {args.flows}）",
                    len(plain), len(plain) == args.flows)
        ok &= check("①", f"1:{KEPT_DEN} → 流量 {len(sampled)} 条（手算 {expect_kept}±{TOLERATED_FLOWS}）",
                    len(sampled), abs(len(sampled) - expect_kept) <= TOLERATED_FLOWS)
        st = outs["sampled"]["stats"]
        ok &= check("①", "CLI 自报 declared_matches_kept",
                    st.get("declared_matches_kept"),
                    st.get("declared_matches_kept") == "true")
        ok &= check("①", f"CLI 自报 observed/kept（手算 observed={packets}）",
                    f"{st.get('sampling_observed')}/{st.get('sampling_kept')}",
                    st.get("sampling_observed") == str(packets)
                    and st.get("sampling_kept") == str(len(sampled) * 2))

        # ---- 问题 2：采对了吗（流完整）----
        # 口径：`session_id` 是**每次运行的序号**（派发/单线程按"首次出现顺序"编号），
        # 采样后只给被采到的流编号，所以它本来就会变 —— 必须显式排除，而不是放宽整条断言。
        # 真正的"流完整"看的是计数/时长/特征/应用结论：逐包随机采会把这些改掉（缺包、缺片）。
        def payload(rec):
            return {k: v for k, v in rec.items() if k != "session_id"}

        plain_by_key = {flow_key(r): r for r in plain}
        mismatched = 0
        missing = 0
        first_diff = None
        for r in sampled:
            base = plain_by_key.get(flow_key(r))
            if base is None:
                missing += 1
                continue
            if json.dumps(payload(base), sort_keys=True) != json.dumps(payload(r), sort_keys=True):
                mismatched += 1
                if first_diff is None:
                    a, b = payload(base), payload(r)
                    first_diff = [k for k in a if json.dumps(a[k], sort_keys=True) != json.dumps(b[k], sort_keys=True)]
        ok &= check("②", f"被采到的流（除 session_id 外）逐字段与不采样一致（{len(sampled)} 条）",
                    f"不同 {mismatched} 条 · 不在全集 {missing} 条"
                    + (f" · 首个差异字段 {first_diff}" if first_diff else ""),
                    mismatched == 0 and missing == 0)

        # ---- 问题 3：说的一致吗 ----
        if outs["sampled"]["ipfix"] is None:
            ok &= check("③", "采样运行的 IPFIX 产物存在（IE 34 必须有地方可验）", "缺失", False)
            iv_plain = ipfix_sampling_intervals(outs["plain"]["ipfix"])
            iv_sampled = None
        else:
            iv_plain = ipfix_sampling_intervals(outs["plain"]["ipfix"])
            iv_sampled = ipfix_sampling_intervals(outs["sampled"]["ipfix"])
        if outs["sampled"]["ipfix"] is not None and (iv_plain is None or iv_sampled is None):
            print("    ⚠ tshark 不可用：IE 34 的线路校验未做（**未核验**）")
            ok &= check("③", "IE 34（tshark）", "未核验", False)
        elif outs["sampled"]["ipfix"] is not None:
            ok &= check("③", "不采样时 IE 34 全为 1",
                        sorted(set(iv_plain)), set(iv_plain) == {1})
            ok &= check("③", f"1:{KEPT_DEN} 时 IE 34 全为 {KEPT_DEN}（{len(iv_sampled)} 条记录）",
                        sorted(set(iv_sampled)), set(iv_sampled) == {KEPT_DEN})
            ok &= check("③", "记录条数 == 实际留下的流数",
                        f"{len(iv_sampled)} == {len(sampled)}", len(iv_sampled) == len(sampled))

        # ---- 并行一致性（与包序无关是 flow 模式的硬要求）----
        w4 = outs["sampled_w4"]["records"]
        same = json.dumps(w4, sort_keys=True) == json.dumps(sampled, sort_keys=True)
        ok &= check("④", f"--workers 4 与 --workers 1 采样结果逐字段相同（各 {len(sampled)}/{len(w4)} 条）",
                    "相同" if same else "不同", same)

        # ---- packet 模式：包级精确（每 N 个包留 1 个）----
        pk = outs["packet"]["records"]
        pk_packets = sum(r["counters"]["packets"] for r in pk)
        expect_pk = packets // KEPT_DEN
        ok &= check("⑤", f"packet 模式留下的包数（手算 {expect_pk}）", pk_packets, pk_packets == expect_pk)
        ok &= check("⑤", f"packet 模式流量 ≤ 全集（逐包采会撕流）", len(pk), len(pk) <= args.flows)

    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="流级采样判定（CYS-TRF-053）")
    ap.add_argument("--binary", default="target/release/cythsec-analyze")
    ap.add_argument("--flows", type=int, default=DEFAULT_FLOWS)
    ap.add_argument("--check", action="store_true", help="跑全部判定与反向注入")
    ap.add_argument(
        "--inject",
        default=None,
        choices=("keep-all", "torn-flows", "no-ipfix"),
        help="故障注入：把被测的那次运行真的改坏，判定不变（见文件头）",
    )
    args = ap.parse_args(argv)
    if not os.path.isfile(args.binary):
        print(f"未找到被测二进制 {args.binary}（先 cargo build --release）", file=sys.stderr)
        return 3
    if args.check:
        return cmd_check(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
