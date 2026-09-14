#!/usr/bin/env bash
# lint-all.sh —— cythsec 统一静态检查（C++ clang-format / Rust cargo fmt / Go gofmt / 前端 eslint）。
# 只检查、不修改；发现问题则以非 0 退出。CI 的 lint.yml 直接调用本脚本。
#
# 用法：bash scripts/lint/lint-all.sh [--help]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

usage() { cat <<'EOF'
用法: lint-all.sh

  依次运行：
    - clang-format --dry-run --Werror（C/C++，基于仓库 .clang-format）
    - cargo fmt --all -- --check（Rust）
    - gofmt -l（Go，services/ 下）
    - npm run lint（前端 eslint，web/console）
  任一检查未通过则整体非 0 退出。
EOF
}
[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && { usage; exit 0; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "✗ 工具链缺失: $1" >&2; exit 1; }; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
need_cmd cargo; need_cmd go; need_cmd node; need_cmd npm

failed=0

# ---------- C++ : clang-format ----------
echo "==> [cpp] clang-format --dry-run --Werror"
# clang-format 常随 Xcode CommandLineTools 一同安装，但**不在 PATH 上**；仅用
# `command -v clang-format` 会把它误判为「未安装」并静默跳过门禁 —— 制造「本地绿灯、
# CI 红灯」的假象（历史事故：29/30 个 C++ 文件不合规却从未被本地检查到）。
# 故显式探测常见安装位置，并把「找不到工具」视为门禁失败而非跳过。
CF_BIN=""
for cand in clang-format \
            /Library/Developer/CommandLineTools/usr/bin/clang-format \
            /opt/homebrew/bin/clang-format \
            /usr/local/bin/clang-format \
            /usr/bin/clang-format; do
  if command -v "$cand" >/dev/null 2>&1; then
    CF_BIN="$(command -v "$cand")"
    break
  fi
done
if [[ -z "$CF_BIN" ]]; then
  echo "✗ [cpp] 未找到 clang-format，无法验证 C/C++ 格式" >&2
  echo "     安装：brew install clang-format（或安装 Xcode CommandLineTools）" >&2
  failed=$((failed+1))
else
  echo "  (clang-format: $CF_BIN)"
  cpp_files="$(find . \( -path ./build -o -path ./target -o -path ./node_modules -o -path ./.git \
    -o -path ./cmake-build-debug -o -path ./web \) -prune -o \
    \( -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.c' \
       -o -name '*.h' -o -name '*.hpp' \) -print)"
  if [[ -z "$cpp_files" ]]; then
    echo "  (无 C/C++ 源文件，跳过)"
  elif ! echo "$cpp_files" | xargs "$CF_BIN" --dry-run --Werror; then
    echo "✗ [cpp] 存在未格式化文件（见上方 diff）" >&2
    failed=$((failed+1))
  else
    echo "✓ [cpp] 格式检查通过"
  fi
fi

# ---------- Rust : cargo fmt ----------
echo "==> [rust] cargo fmt --all -- --check"
if ! cargo fmt --all -- --check; then
  echo "✗ [rust] 存在未格式化文件（运行 make fmt 修复）" >&2
  failed=$((failed+1))
else
  echo "✓ [rust] 格式检查通过"
fi

# ---------- Go : gofmt ----------
echo "==> [go] gofmt -l services/"
go_unfmt="$(GOWORK=off gofmt -l services/ || true)"
if [[ -n "$go_unfmt" ]]; then
  echo "✗ [go] 未格式化文件：" >&2
  echo "$go_unfmt" >&2
  failed=$((failed+1))
else
  echo "✓ [go] 格式检查通过"
fi

# ---------- 生成物一致性 : 属性字典 ----------
# 四语言绑定（Go/Rust/TS/Python）由 configs/registry/attributes.json 生成。
# 归入 lint 而非 test：它校验的是「提交物与真源是否一致」，即生成物新鲜度，
# 与格式检查同类；跑测试永远发现不了「生成物过期」——过期绑定照样能编译通过。
echo "==> [codegen] 属性字典生成物一致性"
if ! bash scripts/verify/check-attributes.sh; then
  echo "✗ [codegen] 属性字典生成物与真源不一致" >&2
  failed=$((failed+1))
else
  echo "✓ [codegen] 属性字典生成物一致"
fi

# ---------- 前端 : eslint ----------
echo "==> [node] npm run lint (web/console)"
if ! (cd web/console && npm run lint); then
  echo "✗ [node] eslint 检查未通过" >&2
  failed=$((failed+1))
else
  echo "✓ [node] eslint 检查通过"
fi

if [[ $failed -eq 0 ]]; then
  echo "lint 汇总：全部通过 ✓"
  exit 0
fi
echo "lint 汇总：$failed 项检查未通过 ✗" >&2
exit 1
