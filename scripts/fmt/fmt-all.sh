#!/usr/bin/env bash
# fmt-all.sh —— cythsec 统一格式化（自动修复）。
# 对 C++ / Rust / Go 应用格式化；前端 eslint 配置由前端负责人维护，此处不自动修改。
#
# 用法：bash scripts/fmt/fmt-all.sh [--help]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

usage() { cat <<'EOF'
用法: fmt-all.sh

  自动格式化：
    - clang-format -i（C/C++）
    - cargo fmt --all（Rust）
    - gofmt -w services/（Go）
  前端请使用其自身 eslint --fix（不在此处处理）。
EOF
}
[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && { usage; exit 0; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "✗ 工具链缺失: $1" >&2; exit 1; }; }

# clang-format 常随 Xcode CommandLineTools 安装但不在 PATH 上，裸调 `clang-format`
# 会失败；此处与 lint-all.sh 采用同一套探测顺序。
# 注：两脚本各持一份探测逻辑，后续应抽到 scripts/lib/ 共享（见 BACKLOG 待补项）。
resolve_clang_format() {
  local cand
  for cand in clang-format \
              /Library/Developer/CommandLineTools/usr/bin/clang-format \
              /opt/homebrew/bin/clang-format \
              /usr/local/bin/clang-format \
              /usr/bin/clang-format; do
    if command -v "$cand" >/dev/null 2>&1; then
      command -v "$cand"
      return 0
    fi
  done
  return 1
}

need_cmd cargo; need_cmd go
CF_BIN="$(resolve_clang_format)" || {
  echo "✗ 未找到 clang-format。安装：brew install clang-format（或安装 Xcode CommandLineTools）" >&2
  exit 1
}

# C++
cpp_files="$(find . \( -path ./build -o -path ./target -o -path ./node_modules -o -path ./.git \
  -o -path ./cmake-build-debug -o -path ./web \) -prune -o \
  \( -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.c' \
     -o -name '*.h' -o -name '*.hpp' \) -print)"
if [[ -n "$cpp_files" ]]; then
  echo "$cpp_files" | xargs "$CF_BIN" -i
  echo "✓ [cpp] 已格式化（clang-format: ${CF_BIN}）"
fi

# Rust
cargo fmt --all
echo "✓ [rust] 已格式化"

# Go
GOWORK=off gofmt -w services/
echo "✓ [go] 已格式化 services/"

echo "格式化完成。"
