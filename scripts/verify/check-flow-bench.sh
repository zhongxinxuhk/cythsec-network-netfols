#!/usr/bin/env bash
# check-flow-bench.sh —— 数据面基准（CYS-TRF-037）的**回归门禁** + 反向故障注入。
#
# 这个脚本回答两个问题，且刻意不让它们互相混：
#   1. 这一版有没有把上一版跑坏？（由 `cythsec-bench` 的回归下限判定，决定退出码）
#   2. 现在距离需求目标还差多少？（只报告，不决定退出码；`--require-targets` 才改）
#
# 为什么需要反向故障注入：
#   基准的判定逻辑自己也可能写错（最坏是恒返回"正常"）。因此默认执行自检：
#   把阈值放大 1000 倍跑一次，**要求基准报出"退步"并以非零码退出**；
#   再把"每核一张独立表"换成"共享一张表 + 互斥锁"跑一次，**要求扩展性判据判出退步**
#   （后者针对的是"扩展性判据"本身 —— 一个只会说"扩展性良好"的判据等于没有判据）。
#   没有这一步，"绿色的通过"和"绿色的没跑"完全一样。
#
# 为什么要区分两套阈值（详见 bin/bench.rs 头部）：
#   需求目标由工作量需求推导（10Gbps 线速 14.88Mpps、扫描预算…），当前有若干项
#   未达成 —— 那是**要排期的差距**，不是"代码坏了"。回归下限是防倒退阈值。
#   两者混成一个退出码，只会让人分不清该修哪个。
#
# 机器相关性（**为什么不进 test-all.sh 的 ALL 集合**）：
#   回归下限标定在 Apple M1 Pro / macOS、flows=1000000、release 构建上，且实测
#   同机连跑两次能差 20~30%。换机器、换核数、开省电模式都会变，因此本项是显式
#   选择项（`--bench`）。在别的机器上先跑 `--report-only` 看真实数字再重标定。
#
# 用法：
#   bash scripts/verify/check-flow-bench.sh                 # 1M 规模 + 自检
#   bash scripts/verify/check-flow-bench.sh --quick         # 20 万规模冒烟（下限更宽松）
#   bash scripts/verify/check-flow-bench.sh --require-targets
#   bash scripts/verify/check-flow-bench.sh --report-only   # 只报告（不判定）
#
# 只读操作：只读源码，产物落在 target/。退出码：0 通过；1 退步或注入未被检出；
# 2 构建/参数错误；3 环境缺 cargo。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

# 手写的用例数清单：基准增删用例时**这里必须同步改** —— 否则"N 项全过"会因为
# 少跑了几项而依然是绿的（这正是最典型的假绿）。
# 13 = 流表 6 + 逐出 2 + 特征 1 + 重组 2 + 会话 1 + 内存 1；
# 19 = 上面 13 项 + 多实例分核实验 6 项（4 个线程档位 + 相对纯计算对照的扩展效率 + 核数预算）。
EXPECTED_CASES=19

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: check-flow-bench.sh [--quick] [--flows N] [--rounds R] [--require-targets]
                          [--report-only] [--no-self-test]

  --quick            20 万规模冒烟（判定同样跑，但下限是为 1M 标定的，必然更宽松）
  --flows N          规模（默认 1000000）
  --rounds R         内存平台期轮数（默认 5）
  --require-targets  退出码改由**需求目标**决定（默认由回归下限决定）
  --report-only      只报告不判定（人工排查用；正式验收不要用）
  --no-self-test     跳过反向故障注入（仅用于人工排查）

跑 cargo build --release --bin cythsec-bench，然后：
  1) 正常跑一次：要求退出码 0，且 19 项回归下限全部通过；
  2) 用 --target-factor 1000 跑一次：要求退出码非 0 且打印"退步"（证明判定没恒真）；
  3) 用 --report-only --target-factor 1000 跑一次：要求退出码 0（证明报告模式不判定）；
  4) 用 --inject-serialized-scaling 跑一次：把"每核一张独立表"换成"共享一张表 +
     互斥锁"，要求扩展性判据判出退步并退出非零（证明扩展性判据不是恒真）。

退出码：0 通过 / 1 退步或注入未被检出 / 2 参数或构建错误 / 3 缺 cargo
EOF
  exit 0
fi

FLOWS=1000000
ROUNDS=5
# bash 3.2（macOS 自带）在 set -u 下展开空数组会报 unbound variable，
# 因此一律用 ${EXTRA[@]+"${EXTRA[@]}"} 这个安全写法，并单独记一个布尔量。
EXTRA=()
REPORT_ONLY=0
SELF_TEST=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) FLOWS=200000; ROUNDS=2; shift ;;
    --flows) FLOWS="${2:?--flows 需要一个值}"; shift 2 ;;
    --rounds) ROUNDS="${2:?--rounds 需要一个值}"; shift 2 ;;
    --require-targets) EXTRA+=(--require-targets); shift ;;
    --report-only) EXTRA+=(--report-only); REPORT_ONLY=1; shift ;;
    --no-self-test) SELF_TEST=0; shift ;;
    *) echo "未知参数: $1（--help 查看用法）" >&2; exit 2 ;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  echo "⚠ [flow-bench] 未核验：环境缺少 cargo" >&2
  exit 3
fi

echo "==> [flow-bench] 构建 release 基准（零第三方依赖，--offline）"
if ! cargo build --offline --release --quiet --manifest-path dataplane/traffic-engine/Cargo.toml \
     --bin cythsec-bench; then
  echo "✗ [flow-bench] 基准构建失败" >&2
  exit 2
fi

BIN="target/release/cythsec-bench"
[[ -x "${BIN}" ]] || { echo "✗ [flow-bench] 找不到 ${BIN}" >&2; exit 2; }

TMPDIR_RUN="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_RUN}"' EXIT

run() { # run <输出前缀> <参数...>
  local tag="$1"; shift
  set +e
  "${BIN}" "$@" >"${TMPDIR_RUN}/${tag}.out" 2>"${TMPDIR_RUN}/${tag}.err"
  local rc=$?
  set -e
  echo "${rc}"
}

# ---------------------------------------------------------------- 1) 正常跑
echo "==> [flow-bench] 实测（flows=${FLOWS} rounds=${ROUNDS}）"

# 报告模式先跑一次并完整展示：即便判定失败，人也要能看到数字。
set +e
"${BIN}" --flows "${FLOWS}" --rounds "${ROUNDS}" ${EXTRA[@]+"${EXTRA[@]}"} --report-only \
  >"${TMPDIR_RUN}/report.out" 2>"${TMPDIR_RUN}/report.err"
set -e
cat "${TMPDIR_RUN}/report.out"
sed 's/^/    /' "${TMPDIR_RUN}/report.err"

# 用例数：报告里的每一行 case 都算一项（少跑一项就不能算全过）。
CASES=$(grep -cE '^(table-|feature-|reassembly-|session-)' "${TMPDIR_RUN}/report.out" || true)
if [[ "${CASES}" != "${EXPECTED_CASES}" ]]; then
  echo "✗ [flow-bench] 用例数不符：实际 ${CASES}，期望 ${EXPECTED_CASES}（基准改了用例？请同步本脚本）" >&2
  exit 1
fi

# 判定用的那次（不带 --report-only）。
RC=$(run judge --flows "${FLOWS}" --rounds "${ROUNDS}" ${EXTRA[@]+"${EXTRA[@]}"})
grep -E '需求目标|未达标 |REGRESSION' "${TMPDIR_RUN}/judge.err" | sed 's/^/    /' || true

if grep -q '回归下限：' "${TMPDIR_RUN}/judge.err"; then
  FLOOR_LINE=$(grep '回归下限：' "${TMPDIR_RUN}/judge.err")
  echo "    ${FLOOR_LINE}"
else
  echo "✗ [flow-bench] 判定输出里没有回归下限汇总行（判定可能没跑）" >&2
  exit 1
fi

if [[ "${RC}" != "0" ]]; then
  echo "✗ [flow-bench] 回归判定失败（退出码 ${RC}）—— 见上方 REGRESSION 行" >&2
  exit 1
fi

if [[ ${REPORT_ONLY} -eq 1 ]]; then
  echo "✓ [flow-bench] 报告模式（未判定；这不是验收通过）"
  exit 0
fi

# ---------------------------------------------------------------- 2) 反向故障注入
INJECTED=0
if [[ ${SELF_TEST} -eq 1 ]]; then
  echo "==> [flow-bench] 反向故障注入：把两个阈值都放大 1000 倍，要求基准报出退步并退出非零"
  set +e
  "${BIN}" --flows "${FLOWS}" --rounds "${ROUNDS}" --target-factor 1000 \
    >"${TMPDIR_RUN}/inject.out" 2>"${TMPDIR_RUN}/inject.err"
  IRC=$?
  set -e
  if [[ "${IRC}" == "0" ]]; then
    echo "✗ [flow-bench] 注入未被检出：阈值放大 1000 倍后基准仍报通过 —— 判定是摆设" >&2
    exit 1
  fi
  if ! grep -q 'REGRESSION' "${TMPDIR_RUN}/inject.err"; then
    echo "✗ [flow-bench] 注入虽退出非零，但没打印 REGRESSION 行（可能是别的原因失败）" >&2
    sed 's/^/    /' "${TMPDIR_RUN}/inject.err" >&2
    exit 1
  fi
  N_INJ=$(grep -c 'REGRESSION' "${TMPDIR_RUN}/inject.err" || true)
  echo "✓ [flow-bench] 注入已检出：${N_INJ} 项被标为退步，退出码 ${IRC}"
  INJECTED=$((INJECTED + 1))

  echo "==> [flow-bench] 对照：同样放大 1000 倍但加 --report-only，要求退出 0（报告模式不判定）"
  set +e
  "${BIN}" --flows "${FLOWS}" --rounds "${ROUNDS}" --target-factor 1000 --report-only \
    >"${TMPDIR_RUN}/inject_report.out" 2>/dev/null
  RRC=$?
  set -e
  if [[ "${RRC}" != "0" ]]; then
    echo "✗ [flow-bench] --report-only 竟然退出了 ${RRC} —— 报告模式不该判定" >&2
    exit 1
  fi
  echo "✓ [flow-bench] 报告模式确实不判定"
  INJECTED=$((INJECTED + 1))

  echo "==> [flow-bench] 反向注入：把 --flows 调到下限以下，要求参数校验报错（退出 2）"
  set +e
  "${BIN}" --flows 10 >/dev/null 2>&1
  BRC=$?
  set -e
  if [[ "${BRC}" != "2" ]]; then
    echo "✗ [flow-bench] --flows 10 应被参数校验拒绝（退出 2），实际 ${BRC}" >&2
    exit 1
  fi
  echo "✓ [flow-bench] 参数校验生效"
  INJECTED=$((INJECTED + 1))

  echo "==> [flow-bench] 反向注入：把多实例实验换成「共享一张表 + 互斥锁」的串行形态"
  set +e
  "${BIN}" --flows "${FLOWS}" --rounds 1 --inject-serialized-scaling \
    >"${TMPDIR_RUN}/inject_serial.out" 2>"${TMPDIR_RUN}/inject_serial.err"
  SRC=$?
  set -e
  if [[ "${SRC}" == "0" ]]; then
    echo "✗ [flow-bench] 串行注入未被检出：共享一张表 + 互斥锁竟然仍报通过 —— 扩展性判据是摆设" >&2
    exit 1
  fi
  # 必须是因为**扩展性**判出来的，而不是别的原因失败：要求出现 REGRESSION，
  # 且点名多实例用例里的至少一项（档位或比值）。
  if ! grep -q 'REGRESSION' "${TMPDIR_RUN}/inject_serial.err"; then
    echo "✗ [flow-bench] 串行注入虽退出非零，但没打印 REGRESSION 行（可能是别的原因失败）" >&2
    sed 's/^/    /' "${TMPDIR_RUN}/inject_serial.err" >&2
    exit 1
  fi
  if ! grep -qE 'REGRESSION.*(table-steady-(2|4|8)t|table-scaling-vs-ceiling)' "${TMPDIR_RUN}/inject_serial.err"; then
    echo "✗ [flow-bench] 串行注入被检出，但退步的不是多实例用例（判据可能匹配到了别的项）" >&2
    grep 'REGRESSION' "${TMPDIR_RUN}/inject_serial.err" | sed 's/^/    /' >&2
    exit 1
  fi
  S_INJ=$(grep -cE 'REGRESSION.*(table-steady-(2|4|8)t|table-scaling-vs-ceiling)' "${TMPDIR_RUN}/inject_serial.err" || true)
  echo "✓ [flow-bench] 串行注入已检出：多实例用例中 ${S_INJ} 项被判退步，退出码 ${SRC}"
  INJECTED=$((INJECTED + 1))
else
  echo "⚠ [flow-bench] 跳过反向故障注入（--no-self-test）—— 不得用于正式验收" >&2
fi

echo "✓ [flow-bench] 通过：${CASES} 项用例 · 回归下限通过 · 注入 ${INJECTED}/4 检出"
echo "    需求目标达成情况见上方「需求目标：达成 X/${CASES}」——未达成项是要排期的差距，不是本门禁的失败"
