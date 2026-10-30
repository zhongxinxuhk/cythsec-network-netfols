#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/.github/workflows"
fixture="$scratch/.github/workflows/check.yml"
key="$(printf '%s%s' GITHUB_ TOKEN)"

check_case() {
  local label="$1" value="$2" expected="$3" rc=0
  printf '  %s: %s\n' "$key" "$value" > "$fixture"
  bash "$ROOT/scripts/security/scan-secrets.sh" "$scratch" > "$scratch/output" 2>&1 || rc=$?
  [[ "$rc" == "$expected" ]] || { echo "✗ secret scan self-test: $label" >&2; exit 1; }
  if [[ "$expected" == 1 ]]; then
    grep -q GENERIC_SECRET_ASSIGN "$scratch/output"
    if grep -Fq -- "$value" "$scratch/output"; then
      echo '✗ secret scan self-test: matched text exposed' >&2; exit 1
    fi
  fi
}
check_case reference '${{ secrets.GITHUB_TOKEN }}' 0
check_case context '${{ github.token }}' 0
check_case literal 'literal-value' 1
check_case suffix '${{ secrets.GITHUB_TOKEN }}-literal-value' 1
check_case conditional "\${{ secrets.GITHUB_TOKEN || 'literal-value' }}" 1
check_case comment '${{ github.token }} # literal-value' 1
# 只有明确的 OIDC 权限枚举可放行，其他 token 字段和任意值仍拒绝。
key='id-token'
check_case oidc-write write 0
check_case oidc-none none 0
check_case oidc-literal literal-value 1
check_case oidc-comment 'write # literal-value' 1
key='token'
check_case ordinary-token write 1
key="$(printf '%s%s' GITHUB_ TOKEN)"
# 相同文本在非 workflow 文件中不享受这条窄范围放行。
printf '%s: %s\n' "$key" '${{ secrets.GITHUB_TOKEN }}' > "$scratch/config.yml"
rm "$fixture"
rc=0
bash "$ROOT/scripts/security/scan-secrets.sh" "$scratch" > "$scratch/output" 2>&1 || rc=$?
[[ "$rc" == 1 ]]
printf '%s: %s\n' 'id-token' write > "$scratch/config.yml"
rc=0
bash "$ROOT/scripts/security/scan-secrets.sh" "$scratch" > "$scratch/output" 2>&1 || rc=$?
[[ "$rc" == 1 ]]
echo '✓ 密钥扫描自证：运行时引用/OIDC权限枚举/字面值与拼接拒绝/非workflow路径拒绝/原文脱敏'

# A type, runtime binding and theme object are not persisted credentials; quoted literals still are.
rm -f "$scratch/config.yml"
printf '%s\n' 'type Props = { token: string };' 'const token = localStorage.getItem("token");' "const theme = { 'token': { color: 'blue' } };" > "$scratch/source.ts" # sample fixture
bash "$ROOT/scripts/security/scan-secrets.sh" "$scratch" > "$scratch/output" 2>&1
printf '%s\n' 'const TOKEN = "literal-credential";' > "$scratch/source.ts" # sample fixture
rc=0; bash "$ROOT/scripts/security/scan-secrets.sh" "$scratch" > "$scratch/output" 2>&1 || rc=$?
[[ "$rc" == 1 ]]
! grep -q literal-credential "$scratch/output"

printf '%s\n' 'const config = {"TOKEN":"literal-credential"};' > "$scratch/source.ts" # sample fixture
rc=0; bash "$ROOT/scripts/security/scan-secrets.sh" "$scratch" > "$scratch/output" 2>&1 || rc=$?
[[ "$rc" == 1 ]]

# Compose interpolation permits only exact environment references, never literal fallback values.
rm -f "$scratch/source.ts"
mkdir -p "$scratch/deploy/docker"
fixture="$scratch/deploy/docker/compose.test.yml"
key="$(printf '%s%s' CLICKHOUSE_ PASSWORD)"
check_case compose-env '${CYTHSEC_TEST_CLICKHOUSE_PASSWORD}' 0
check_case compose-required '${CYTHSEC_TEST_CLICKHOUSE_PASSWORD:?prepare middleware test environment}' 0 # sample fixture
check_case compose-fallback '${CYTHSEC_TEST_CLICKHOUSE_PASSWORD:-literal-value}' 1 # sample fixture
check_case compose-suffix '${CYTHSEC_TEST_CLICKHOUSE_PASSWORD}-literal-value' 1
check_case compose-literal literal-value 1
rm "$fixture"
printf '%s: %s\n' "$key" '${CYTHSEC_TEST_CLICKHOUSE_PASSWORD}' > "$scratch/config.yml"
rc=0; bash "$ROOT/scripts/security/scan-secrets.sh" "$scratch" > "$scratch/output" 2>&1 || rc=$?
[[ "$rc" == 1 ]]
