#!/usr/bin/env bash
# check-ignored-sources.sh —— 抓「被 .gitignore 静默吃掉、因而不在版本控制里」的源码/脚本。
#
# 为什么需要它（本仓库真实踩过三次，全部由这条规则引起）：
#   `.gitignore` 里**不带前导斜杠**的目录名（`build/`、`release/`、`target/` …）
#   按 gitignore 规则匹配**任意层级**的同名目录。这些规则本意只是忽略构建产物，
#   却会连带把同名的**源码目录**一起忽略掉：文件在磁盘上、本地跑得通、
#   `git status` 不提示，但**全新克隆里根本没有它们**。
#
#   ① `scripts/release/`：版本单一真源自检脚本 `check-version.sh` 从未入库，
#      而 `scripts/README.md` 与交接文档都在引用它；
#   ② `scripts/build/`：`build-all.sh`（四端统一构建入口）从未入库；
#   ③ `services/telemetryd/internal/target/`：telemetryd **直接 import** 的 Go 包
#      （4 个文件）从未入库 → 全新克隆里 `go build ./...` 直接失败。
#
#   三件事都不是"读代码"能发现的：代码看起来一切正常，问题只在"版本控制的事实"里。
#   所以判据必须建立在 git 的事实上，而不是人的记忆上。
#
# 判据：`git ls-files --others --ignored --exclude-standard` 中不应出现源码/脚本/文档类
# 文件，除非命中下方显式列出的白名单（体积大、机器相关或纯生成物，每条都有理由）。
#
# 用法: bash scripts/verify/check-ignored-sources.sh [--help]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
用法: check-ignored-sources.sh

  检查是否有源码/脚本被 .gitignore 规则静默忽略（因而从未入库）。
  退出码：0 = 没有；1 = 发现（逐个打印命中的规则，方便定位是哪条模式吃掉了它）。
EOF
  exit 0
fi

# 源码/脚本/文档类扩展名 —— 这些出现在"被忽略"集合里就是可疑的。
EXT='\.(sh|bash|py|rs|c|cc|h|hpp|cpp|go|ts|tsx|js|jsx|json|toml|ini|cfg|sql|proto|md|yml|yaml|txt|cmake)$'

# 白名单：**刻意的**生成物 / 依赖 / 本地工具状态。每一条都要能说出理由。
# 注意每条都用 ^ 锚定根，或显式写出"任意层级"（(^|/)…）—— 白名单自己也不能犯
# "裸目录名匹配任意层级"这个错，否则它会把要抓的东西再藏一遍。
ALLOW='(^|/)(\.mimosa|\.idea|\.vscode|node_modules)/'
ALLOW="${ALLOW}"'|^build/|^target/|^cmake-build-|^out/|^dist/|^release/'
ALLOW="${ALLOW}"'|^datasets/|^secrets/|^logs/|^web/console/dist/|^web/console/\.vite/'
ALLOW="${ALLOW}"'|^ml/.*/(runs|wandb)/'

hits="$(git ls-files --others --ignored --exclude-standard \
        | grep -E "${EXT}" \
        | grep -Ev "${ALLOW}" || true)"

if [[ -n "${hits}" ]]; then
  echo "✗ 有源码/脚本被 .gitignore 静默忽略（在磁盘上，但不在版本控制里）：" >&2
  printf '%s\n' "${hits}" | while IFS= read -r f; do
    printf '  %s\n' "${f}" >&2
    printf '     命中规则: %s\n' "$(git check-ignore -v "${f}" 2>/dev/null || echo '（未知）')" >&2
  done
  echo "" >&2
  echo "  修法：把 .gitignore 里的裸目录名锚定到根（如 build/ → /build/），" >&2
  echo "        或为白名单外的目录写精确规则；确认不需要忽略后 git add -f <path>。" >&2
  echo "  这也是「全新克隆可能缺文件」的前兆：本地全绿不代表克隆能构建。" >&2
  exit 1
fi

echo "✓ 没有被 .gitignore 吃掉的源码/脚本（已核对白名单：生成物 / 依赖 / 本地工具状态）"
