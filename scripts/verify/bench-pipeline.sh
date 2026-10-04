#!/usr/bin/env bash
# bench-pipeline.sh —— 量「整条离线流水线」的并行加速比，并给上限归因。
#
# 这不是门禁，**刻意不做阈值判定**：绝对吞吐是机器相关的（核数、内存带宽、页缓存、
# 是否插电），把它的数字写成阈值，换台机器就是随机红，而随机红等于没有门禁。
# 它回答三个只有测量能回答的问题：
#   1. 加 worker 到底有没有用？（`--workers N` 的加速比）
#   2. 上限在哪里？（加速比在几个 worker 上停止增长 —— 那个平台就是派发端的耗时）
#   3. 输出的正确性有没有被并行改变？（先逐字节比对，再测吞吐；不比对就只是"跑得快"）
#
# **正确性本身已经是常驻门禁**：`cargo test`（`test-all.sh --rust`）里有
# `worker_count_does_not_change_the_records`（1/2/3/4/8 个 worker 逐字节一致）
# 与 `shard_hash_is_stable_and_balanced_for_realistic_keys`（分片均衡）。
# 本脚本里那次 cmp 是"在真实规模上再核一遍"，不是唯一防线。
#
# 为什么要专门盯分片**均衡度**：分片哈希的低位若被恒定尾字节钉住，全部流会挤到少数
# worker 上 —— 输出仍然完全正确，只是并行度是零。实测第一版就是把 20000 条流全送到
# 了一个 worker（`worker_flows=[20000,0,0,0]`），而当时的单元测试是绿的。
#
# 用法：
#   bash scripts/verify/bench-pipeline.sh                # 50 万包、3 轮
#   bash scripts/verify/bench-pipeline.sh 888000 3       # 包数、轮数
#   WORKERS="1 2 4 8 16 32" bash scripts/verify/bench-pipeline.sh
#
# 产物落在 build/bench-pipeline/（gitignore）。退出码：0 测量完成；
# 1 正确性比对失败；2 参数/环境问题（缺 python3、release 未构建）。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

if [[ "${1:-}" == "--help" ]]; then
  sed -n '2,25p' "${BASH_SOURCE[0]}"
  exit 0
fi

PACKETS="${1:-500000}"
ROUNDS="${2:-3}"
WORKERS_LIST="${WORKERS:-1 2 4 8 16 32}"

OUT_DIR="build/bench-pipeline"
PCAP="${OUT_DIR}/bench.pcap"
BIN="target/release/cythsec-analyze"

if ! command -v python3 >/dev/null 2>&1; then
  echo "✗ 需要 python3（生成负载样本与计时）" >&2
  exit 2
fi
if [[ ! -x "${BIN}" ]]; then
  echo "release 二进制不存在，先构建：cargo build --release --offline" >&2
  cargo build --release --offline || exit 2
fi

# 目标包数 → 流数：每 10 条流里有 1 条 UDP（只有 3 个包），其余 TCP 每条 50 个包。
FLOWS=$(( PACKETS / 44 + 1 ))
echo "[bench-pipeline] 生成负载：${FLOWS} 条流（目标 ${PACKETS} 个包）"
GEN_OUT="$(python3 datasets/pcap/generate-bench.py "${PCAP}" "${FLOWS}" 50)" || exit 2
echo "[bench-pipeline] ${GEN_OUT}"
ACTUAL="$(printf '%s' "${GEN_OUT}" | sed -n 's/写出 \([0-9][0-9]*\) 个包.*/\1/p')"
if [[ -z "${ACTUAL}" ]]; then
  echo "✗ 没能从生成器输出里取到包数" >&2
  exit 2
fi

# ---- 第 1 步：正确性（真实规模上的逐字节比对）----
echo "[bench-pipeline] 逐字节比对：--workers 1 与其余各档"
"${BIN}" -r "${PCAP}" -o "${OUT_DIR}/w1.jsonl" -q || exit 1
for w in ${WORKERS_LIST}; do
  [[ "${w}" == "1" ]] && continue
  "${BIN}" -r "${PCAP}" -o "${OUT_DIR}/w${w}.jsonl" -q --workers "${w}" || exit 1
  if ! cmp -s "${OUT_DIR}/w1.jsonl" "${OUT_DIR}/w${w}.jsonl"; then
    echo "✗ --workers ${w} 的输出与 --workers 1 不一致（并行改变了结论）" >&2
    exit 1
  fi
done
RECORDS="$(wc -l < "${OUT_DIR}/w1.jsonl" | tr -d ' ')"
echo "✓ 一致性：${WORKERS_LIST} 各档输出逐字节一致（${RECORDS} 条记录）"

# ---- 第 2 步：吞吐扫描（python3 计时与算术；bash 3.2 没有高精度时钟）----
python3 - "${BIN}" "${PCAP}" "${ROUNDS}" "${ACTUAL}" "${WORKERS_LIST}" <<'PY'
import subprocess, sys, time

binary, pcap, rounds, packets, workers = (
    sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5].split()
)
rows = []
print()
print("%8s %9s %9s %8s  %s" % ("workers", "best_s", "Mpps", "加速比", "worker_flows"))
for w in workers:
    best, flows = None, ""
    for _ in range(rounds):
        t0 = time.perf_counter()
        p = subprocess.run(
            [binary, "-r", pcap, "-o", "/dev/null", "--workers", w],
            capture_output=True, text=True,
        )
        dt = time.perf_counter() - t0
        if p.returncode != 0:
            print("✗ --workers %s 退出码 %s：%s" % (w, p.returncode, p.stderr.strip()[:200]))
            sys.exit(1)
        best = dt if best is None else min(best, dt)
        # worker_flows 只在前 8 个 worker 上打印（32 个 worker 的行会太长）
        for line in p.stderr.splitlines():
            if "worker_flows=" in line:
                flows = ",".join(line.split("worker_flows=[")[1].split("]")[0].split(",")[:8])
    rows.append((int(w), best, flows))
    print("%8s %9.3f %9.3f %8.2f  [%s]" % (w, best, packets / best / 1e6, rows[0][1] / best, flows))

base = rows[0][1]
best_row = min(rows, key=lambda r: r[1])
dispatcher = best_row[1]
worker_work = max(0.0, base - dispatcher)
print()
print("[bench-pipeline] 上限归因（串行模型 T(N) ≈ D + W/N，D 取实测平台值）")
print("  D 派发端（读盘+解帧+分片+入队）= %.3f s → %.3f Mpps   ← 加核心不能再快的就是它"
      % (dispatcher, packets / dispatcher / 1e6))
print("  W worker 侧总工作量            = %.3f s" % worker_work)
print("  最优档位                       = %s 个 worker（%.2f×）" % (best_row[0], base / dispatcher))
print("  单核（workers=1）              = %.3f Mpps（%.3f µs/包）"
      % (packets / base / 1e6, base / packets * 1e6))
# 10G 最坏帧（64 字节线速）的覆盖率：说明"靠加核心"能不能到线速
line_64b = 14.88
print("  10G 最坏帧 64B = %.2f Mpps：本流水线整条上限覆盖 %.0f%%"
      % (line_64b, packets / dispatcher / 1e6 / line_64b * 100))
print("  ※ 本脚本不判定阈值（机器相关）。差距要排期时，看 HANDOFF §2.8 的结论。")
PY
