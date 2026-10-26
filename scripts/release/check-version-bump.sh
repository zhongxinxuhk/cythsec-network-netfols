#!/usr/bin/env bash
# check-version-bump.sh —— 版本单一真源（CYS-INF-020）的**产物级**验收实验。
#
# 为什么需要它（`check-version.sh` 已经校验了源码级一致性）：
#   源码级检查只能回答"四处副本/派生点是否与真源一致"，
#   它无法回答"改了真源，产物报告的版本号**真的会跟着变**吗" ——
#   两者是不同的问题。历史上恰恰出现过派生点看似存在、实际从未从 VERSION 取值
#   的情况（见 web/console/version-source.ts 里记的那次三级上溯事故），
#   那种缺陷在源码级检查下完全可以全绿。
#
# 本脚本做两件事：
#   ① 把根 VERSION 改成候选值，要求 `check-version.sh` **判红** —— 证明它能在真树上
#      抓出"改了真源没同步副本"（与 `--self-test` 的合成树互补）；
#   ② 用这个候选值重新构建四端，要求**每个产物都报告候选值**，然后复原真源。
#
# 产物全部落在临时目录，仓库的 VERSION 由 trap 保证复原；不会污染 build/ 与 target/。
#
# 用法: bash scripts/release/check-version-bump.sh [--to 0.1.1] [--help]
# 耗时: 首次约 1~3 分钟（Rust 目标目录是全新的，需要编译依赖）。
# **刻意不进默认门禁**：它要重建四端，属于发版前/改版本机制后的手工验收。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

TO=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --to) TO="${2:-}"; shift 2 ;;
    --help|-h)
      echo "用法: bash scripts/release/check-version-bump.sh [--to <semver>]"
      echo "  把根 VERSION 临时改成 --to（默认 0.1.1），重建四端并核对产物版本号，然后复原。"
      echo "  耗时约 1~3 分钟（Rust 目标目录全新）；刻意不进默认门禁。"
      exit 0 ;;
    *) echo "未知参数: ${1}" >&2; exit 2 ;;
  esac
done
[[ -n "${TO}" ]] || TO="0.1.1"
if [[ ! "${TO}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "✗ --to 需要形如 1.2.3 的版本号（收到 ${TO}）" >&2
  exit 2
fi

ORIG="$(cat VERSION)"
if [[ "${TO}" == "${ORIG}" ]]; then
  echo "✗ 候选版本与当前真源相同（${TO}）：这样测不出「跟着变」" >&2
  exit 2
fi

WORK="${TMPDIR:-/tmp}/cythsec-version-bump.$$"
mkdir -p "${WORK}"
fails=0
# 复原真源 + 清理临时产物：**必须**在 trap 里，中途失败也不能把 VERSION 留在候选值上。
cleanup() {
  printf '%s\n' "${ORIG}" > "${ROOT}/VERSION"
  rm -rf "${WORK}"
}
trap cleanup EXIT

printf '%s\n' "${TO}" > VERSION
echo "==> [0/5] 临时真源 VERSION=${TO}（原值 ${ORIG}，退出时自动复原）"

# ① 真源改了、四处副本没跟 —— 检查器必须在真树上判红并点名位置。
bad_out=""
if bad_out="$(bash scripts/release/check-version.sh 2>&1)"; then
  echo "✗ [1/5] 只改真源未同步副本，check-version.sh 却通过了 —— 检查器形同虚设" >&2
  fails=$((fails+1))
else
  echo "✓ [1/5] 未同步副本时 check-version.sh 判红（真树上也能抓到）"
  printf '%s\n' "${bad_out}" | grep -q 'Cargo.toml' \
    && echo "     并在输出里点名了 Cargo.toml" \
    || { echo "✗ 判红但没指出位置（应当点名 Cargo.toml）" >&2; fails=$((fails+1)); }
fi

# 判定辅助：产物输出里必须出现候选版本号。
check() { # check <端> <实际输出>
  if printf '%s' "$2" | grep -q "${TO}"; then
    echo "✓ [$1] 产物报告 ${TO}"
  else
    echo "✗ [$1] 产物未报告 ${TO} → 实际: $2" >&2
    fails=$((fails+1))
  fi
}

echo "==> [2/5] Rust：build.rs 读 VERSION → rustc-env CYTHSEC_VERSION"
if CARGO_TARGET_DIR="${WORK}/rust-target" cargo build --offline -p traffic-engine \
     --bin cythsec-analyze -q 2>"${WORK}/rust.log"; then
  check "rust" "$("${WORK}/rust-target/debug/cythsec-analyze" --version 2>&1)"
else
  echo "✗ [rust] 构建失败" >&2; tail -5 "${WORK}/rust.log" >&2; fails=$((fails+1))
fi

echo "==> [3/5] Go：-ldflags -X（值取自构建脚本里同一句 ver=\$(cat VERSION)）"
ver="$(tr -d '[:space:]' < VERSION)"
if (cd services/policyd && GOWORK=off GOPROXY=off GOTOOLCHAIN=local \
      go build -ldflags "-X cythsec/services/pkg/versioninfo.Version=${ver}" \
      -o "${WORK}/policyd" ./cmd/policyd) 2>"${WORK}/go.log"; then
  check "go" "$("${WORK}/policyd" -version 2>&1)"
else
  echo "✗ [go] 构建失败" >&2; tail -5 "${WORK}/go.log" >&2; fails=$((fails+1))
fi

echo "==> [4/5] C++：CMake 用 configure_file 生成 version.h"
if cmake -S . -B "${WORK}/cmake" -DCMAKE_BUILD_TYPE=Release >"${WORK}/cmake.log" 2>&1 \
   && cmake --build "${WORK}/cmake" --target hello_packet --parallel >>"${WORK}/cmake.log" 2>&1; then
  check "cpp" "$("${WORK}/cmake/dataplane/packet-engine/hello_packet" --version 2>&1 | tr '\n' ' ')"
else
  echo "✗ [cpp] 构建失败" >&2; tail -5 "${WORK}/cmake.log" >&2; fails=$((fails+1))
fi

echo "==> [5/5] 前端：Umi Max 构建期 define 注入 __APP_VERSION__（产物里应有该字面量）"
if (cd web/console && CONSOLE_OUTPUT_PATH="${WORK}/dist" npx max build) >"${WORK}/frontend.log" 2>&1; then
  if grep -rq "${TO}" "${WORK}/dist"; then
    echo "✓ [frontend] 构建产物内含 ${TO}（$(grep -rl "${TO}" "${WORK}/dist" | head -1 | sed "s|${WORK}/dist/||")）"
  else
    echo "✗ [frontend] 产物里找不到 ${TO}" >&2; fails=$((fails+1))
  fi
else
  echo "✗ [frontend] 构建失败" >&2; tail -5 "${WORK}/frontend.log" >&2; fails=$((fails+1))
fi

echo "==> 复原真源并复核"
cleanup
trap - EXIT
if [[ "$(cat VERSION)" != "${ORIG}" ]]; then
  echo "✗ VERSION 未复原（当前 $(cat VERSION)，应为 ${ORIG}）" >&2; fails=$((fails+1))
else
  echo "✓ 真源已复原为 ${ORIG}"
fi
if bash scripts/release/check-version.sh >/dev/null 2>&1; then
  echo "✓ 复原后 check-version.sh 通过"
else
  echo "✗ 复原后 check-version.sh 失败" >&2; fails=$((fails+1))
fi

echo
if [[ ${fails} -eq 0 ]]; then
  echo "版本单一真源产物级验收通过：改 VERSION → 四端产物版本号同步变化 ✓"
  exit 0
fi
echo "版本单一真源产物级验收失败：${fails} 处不符预期 ✗" >&2
exit 1
