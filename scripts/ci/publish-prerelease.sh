#!/usr/bin/env bash
# publish-prerelease.sh —— 把 package-release.sh 的产物发布为 GitHub Pre-release。
#
# 每个 commit 一个标签：pre-<short-sha>。标签已存在时只更新资产与说明，不删除重建，
# 这样同一 commit 的 workflow 重跑是幂等的，也不会把旧标签指向新提交。
#
# 必需环境变量：
#   GH_TOKEN      GitHub token（contents: write）
#   HEAD_SHA      被发布 commit 的完整 SHA
# 可选：
#   HEAD_BRANCH   分支名（写入说明）
#   CI_RUN_URL    CI 运行链接（写入说明）
#
# 用法：bash scripts/ci/publish-prerelease.sh [--dry-run] [资产目录]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
  shift
fi
DIST="${1:-dist/release}"

[[ -n "${HEAD_SHA:-}" ]] || { echo "✗ 缺少 HEAD_SHA" >&2; exit 1; }
if [[ "$DRY_RUN" -eq 0 ]]; then
  [[ -n "${GH_TOKEN-}" ]] || { echo "✗ 缺少 GH_TOKEN（需要 contents: write）" >&2; exit 1; }
fi
[[ -d "$DIST" ]] || { echo "✗ 资产目录不存在：$DIST" >&2; exit 1; }
if [[ "$DRY_RUN" -eq 0 ]]; then
  command -v gh >/dev/null 2>&1 || { echo "✗ 缺少 gh（GitHub CLI）" >&2; exit 1; }
fi

TAG="pre-${HEAD_SHA:0:7}"
TITLE="CythSec 预发布 ${TAG}"
NOTES="${DIST}/RELEASE-NOTES.md"

assets=()
while IFS= read -r file; do
  assets+=("$file")
done < <(find "$DIST" -maxdepth 1 -type f ! -name 'RELEASE-NOTES.md' ! -name '.*' | sort)
[[ ${#assets[@]} -gt 0 ]] || { echo "✗ $DIST 里没有可发布资产" >&2; exit 1; }

{
  echo "# CythSec 预发布 ${TAG}"
  echo
  echo "- 版本：\`$(tr -d '[:space:]' < VERSION)\`"
  echo "- 提交：\`${HEAD_SHA}\`"
  echo "- 分支：\`${HEAD_BRANCH:-unknown}\`"
  if [[ -n "${CI_RUN_URL:-}" ]]; then
    echo "- CI：${CI_RUN_URL}"
  fi
  echo
  echo "## 资产"
  echo
  echo '```'
  cat "${DIST}/SHA256SUMS"
  echo '```'
  echo
  echo "本预发布由 CI 通过后自动生成，包含 C++ / Rust / Go / 前端 / Python 五个模块的构建包。"
  echo "每个提交对应一个 ${TAG} 标签；同一提交重跑会更新资产而不是新建标签。"
} >"$NOTES"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "==> [dry-run] 将发布 ${TAG}（${#assets[@]} 个资产）"
  printf '  %s\n' "${assets[@]}"
  echo "  说明文件：${NOTES}"
  exit 0
fi

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "==> 更新已有预发布 ${TAG}"
  gh release upload "$TAG" "${assets[@]}" --clobber
  gh release edit "$TAG" --title "$TITLE" --notes-file "$NOTES" --prerelease
else
  echo "==> 创建预发布 ${TAG}"
  gh release create "$TAG" "${assets[@]}" \
    --target "$HEAD_SHA" \
    --title "$TITLE" \
    --notes-file "$NOTES" \
    --prerelease
fi

echo "✓ 预发布已发布：${TAG}（${#assets[@]} 个资产）"
