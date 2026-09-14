#!/usr/bin/env bash
# check-channel-parity.sh —— 通道 ABI 的跨语言 parity 关口（CYS-PKT-024 第 3 层）。
#
# 用法：
#   bash scripts/verify/check-channel-parity.sh          # 校验两端 ABI 取值是否一致
#   bash scripts/verify/check-channel-parity.sh --help
#
# 行为：
#   1. 构建并运行 C++ 侧 `cythsec-dump-abi`；
#   2. 构建并运行 Rust 侧 `dump-abi`；
#   3. 逐行 diff 两者的 `key=value` 输出。
#   两端产物留在 build/parity/ 下，失败时可直接查看。
#
# 为什么必须有这一层：
#   gen-channel-abi.py 头注释描述的三层防线里，前两层各自只看**一侧** ——
#   static_assert 只验「本端结构体裁剪与真源一致」，`--check` 只验「真源与生成文本
#   一致」。三者都成立，仍可能存在「一侧改了、另一侧没改」的代码：那种情况下两端
#   各自都自洽，只有真正把两份产物放在一起比才看得出来。本脚本就是这个「放在一起」。
#
#   dump 的取值刻意全部取自**编译产物**（常量 / offsetof / sizeof / 布局函数 / 诊断样本）
#   而非真源字面量 —— 照抄真源只会让 diff 恒等，等于没验证。
#
# 退出码：0 = 一致；1 = 两端不一致；4 = 环境不满足（缺 cargo/cmake/编译器）；5 = 构建失败。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: check-channel-parity.sh

构建 C++ 侧 cythsec-dump-abi 与 Rust 侧 dump-abi，逐行 diff 两者的通道 ABI 取值。

不一致意味着两端对同一份契约的理解已经分开。修复方向二选一：
  - 若真源已变更而某端未重新生成：python3 tools/codegen/gen-channel-abi.py
  - 若生成物被手工改动：同上（生成物一律不要手改）

两端产物与 diff 报告留在 build/parity/ 下。

退出码：0 一致 / 1 不一致 / 4 缺工具链 / 5 构建失败
EOF
  exit 0
fi

for cmd in cargo cmake; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "环境检查失败：未找到 ${cmd}" >&2
    exit 4
  fi
done

OUT_DIR="${ROOT}/build/parity"
BUILD_DIR="${CYTHSEC_PARITY_BUILD_DIR:-${ROOT}/build}"
mkdir -p "${OUT_DIR}"

# ---------- Rust 侧 ----------
echo "==> [parity] 构建并运行 Rust 侧 dump-abi"
RUST_DUMP="${OUT_DIR}/dump-rust.txt"
RUST_LOG="${OUT_DIR}/cargo-rust.log"
# cargo 的编译告警走 stderr，与 dump 的 stdout 天然分开；但直接透传会把整屏告警盖住
# 结论。因此收进日志，只提示「有告警、详见何处」。
if ! cargo run --offline --quiet \
  --manifest-path "${ROOT}/dataplane/traffic-engine/Cargo.toml" \
  --bin dump-abi >"${RUST_DUMP}" 2>"${RUST_LOG}"; then
  echo "✗ [parity] Rust 侧 dump-abi 运行失败（编译日志 ${RUST_LOG}）" >&2
  tail -20 "${RUST_LOG}" >&2
  exit 5
fi
if grep -q "^warning" "${RUST_LOG}" 2>/dev/null; then
  echo "  提示: Rust 侧有编译告警，详见 ${RUST_LOG}"
fi

# ---------- C++ 侧 ----------
echo "==> [parity] 构建并运行 C++ 侧 cythsec-dump-abi"
# 必须显式重新配置一次：新增目标（如本脚本依赖的 cythsec-dump-abi）在旧构建系统里
# 不存在，直接 make 会以 "No rule to make target" 失败，而那句话完全指不到
# 「配置过期」这个真实原因。cmake -S -B 幂等，代价只有约一秒。
if [[ -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
  if ! cmake -S "${ROOT}" -B "${BUILD_DIR}" >/dev/null; then
    echo "✗ [parity] CMake 重新配置失败" >&2
    exit 5
  fi
else
  echo "  (无 CMake 缓存，首次配置 ${BUILD_DIR})"
  if ! cmake -S "${ROOT}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Debug >/dev/null; then
    echo "✗ [parity] CMake 配置失败" >&2
    exit 5
  fi
fi
if ! cmake --build "${BUILD_DIR}" --target cythsec-dump-abi >/dev/null; then
  echo "✗ [parity] C++ 侧 cythsec-dump-abi 构建失败" >&2
  exit 5
fi

CPP_DUMP="${OUT_DIR}/dump-cpp.txt"
CPP_BIN="${BUILD_DIR}/dataplane/packet-engine/cythsec-dump-abi"
if [[ ! -x "${CPP_BIN}" ]]; then
  echo "✗ [parity] 未找到可执行文件 ${CPP_BIN}" >&2
  exit 5
fi
if ! "${CPP_BIN}" >"${CPP_DUMP}"; then
  echo "✗ [parity] C++ 侧 cythsec-dump-abi 运行失败" >&2
  exit 5
fi

# ---------- 比对 ----------
echo "==> [parity] diff 两端输出（C++ ${CPP_DUMP} vs Rust ${RUST_DUMP}）"
CPP_LINES="$(wc -l <"${CPP_DUMP}" | tr -d ' ')"
RUST_LINES="$(wc -l <"${RUST_DUMP}" | tr -d ' ')"

if [[ "${CPP_LINES}" -eq 0 || "${RUST_LINES}" -eq 0 ]]; then
  echo "✗ [parity] 有一端输出为空（C++ ${CPP_LINES} 行 / Rust ${RUST_LINES} 行）：" >&2
  echo "  空输出与空输出也会「一致」，因此空必须单独判失败。" >&2
  exit 1
fi

DIFF_REPORT="${OUT_DIR}/parity.diff"
set +e
diff -u "${CPP_DUMP}" "${RUST_DUMP}" >"${DIFF_REPORT}"
rc=$?
set -e

if [[ ${rc} -eq 0 ]]; then
  echo "✓ [parity] 通道 ABI 两端一致（${CPP_LINES} 行）"
  rm -f "${DIFF_REPORT}"
  exit 0
fi

echo "" >&2
echo "✗ [parity] 通道 ABI 两端不一致：静态断言各自都过，但两份产物放在一起就分开了。" >&2
echo "  完整 diff 见 ${DIFF_REPORT}（左侧 C++，右侧 Rust）" >&2
echo "" >&2
head -40 "${DIFF_REPORT}" >&2
echo "" >&2
echo "  修复：python3 tools/codegen/gen-channel-abi.py（生成物一律不要手改）" >&2
exit 1
