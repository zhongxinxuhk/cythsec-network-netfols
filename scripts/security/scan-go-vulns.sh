#!/usr/bin/env bash
# 根目录只有 go.work；govulncheck 必须在每个真正的模块目录执行。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

self_test() {
  local scratch rc count
  scratch="$(mktemp -d)"
  trap 'rm -rf "$scratch"' EXIT
  # 在独立的 Git 索引中覆盖五个现有布局及未来新增的深层模块；不修改真实索引。
  mkdir -p "$scratch/repo/scripts/security"
  cp "$0" "$scratch/repo/scripts/security/scan-go-vulns.sh"
  git -C "$scratch/repo" init --quiet
  for fixture_module in services/dnsd services/pkg services/policyd services/routerd services/telemetryd components/future/new; do
    mkdir -p "$scratch/repo/$fixture_module"
    printf 'module fixture/%s\ngo 1.22\n' "$fixture_module" > "$scratch/repo/$fixture_module/go.mod"
  done
  git -C "$scratch/repo" add -- '**/go.mod'
  cat > "$scratch/scanner" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ -f go.mod && "${GOWORK:-}" == off && "${GOTOOLCHAIN:-}" == local && "$*" == './...' ]]
printf '%s\n' "${PWD##*/}" >> "$SCAN_TEST_LOG"
# pkg 排在列表中间；失败后后续模块仍应被扫描，且整体必须失败。
[[ "${SCAN_TEST_FAIL:-0}" != 1 || "${PWD##*/}" != pkg ]]
STUB
  chmod +x "$scratch/scanner"
  SCAN_TEST_LOG="$scratch/pass" GOVULNCHECK="$scratch/scanner" bash "$scratch/repo/scripts/security/scan-go-vulns.sh" > "$scratch/pass-output"
  count="$(wc -l < "$scratch/pass" | tr -d ' ')"
  [[ "$count" == 6 ]]
  printf '%s\n' new dnsd pkg policyd routerd telemetryd > "$scratch/expected"
  cmp "$scratch/expected" "$scratch/pass"
  rc=0
  SCAN_TEST_FAIL=1 SCAN_TEST_LOG="$scratch/fail" GOVULNCHECK="$scratch/scanner" bash "$scratch/repo/scripts/security/scan-go-vulns.sh" > "$scratch/fail-output" 2>&1 || rc=$?
  [[ "$rc" == 1 ]]
  cmp "$scratch/expected" "$scratch/fail"
  git -C "$scratch/repo" rm --quiet --cached -- '**/go.mod'
  rc=0
  GOVULNCHECK="$scratch/scanner" bash "$scratch/repo/scripts/security/scan-go-vulns.sh" > "$scratch/empty-output" 2>&1 || rc=$?
  [[ "$rc" == 1 ]]
  grep -q '扫描未执行' "$scratch/empty-output"
  echo '✓ Go 扫描自证：六个模块（含深层新增）/独立目录与环境/成功路径/中途失败后继续扫描/空集合拒绝'
  rm -rf "$scratch"
  trap - EXIT
}

case "${1:-}" in
  --self-test) self_test; exit 0 ;;
  '') ;;
  *) echo "用法: scan-go-vulns.sh [--self-test]" >&2; exit 2 ;;
esac

scanner="$(command -v "${GOVULNCHECK:-govulncheck}")" || {
  echo '未找到 govulncheck，请安装工作流指定的版本' >&2; exit 1;
}
modules="$(git ls-files -- 'go.mod' '**/go.mod')"
[[ -n "$modules" ]] || { echo '没有发现受版本控制的 Go 模块，扫描未执行' >&2; exit 1; }
failed=0
while IFS= read -r module_file; do
  module_dir="$(dirname "$module_file")"
  echo "==> govulncheck: $module_dir"
  if ! (cd "$module_dir" && GOWORK=off GOTOOLCHAIN=local "$scanner" ./...); then
    echo "✗ Go 漏洞扫描失败: $module_dir" >&2
    failed=$((failed+1))
  fi
done <<< "$modules"
if [[ "$failed" -ne 0 ]]; then
  echo "Go 漏洞扫描失败：$failed 个模块未通过" >&2
  exit 1
fi
echo '✓ 全部受版本控制的 Go 模块漏洞扫描完成'
