#!/usr/bin/env bash
# Keep evidence and reject incomplete acceptance, including legacy exit-0 skips.
set -euo pipefail
if [[ $# -lt 2 ]]; then
  echo "usage: run-check.sh LOG COMMAND [ARG ...]" >&2
  exit 2
fi
log="$1"
shift
mkdir -p "$(dirname "$log")"
rc=0
"$@" 2>&1 | tee "$log" || rc=$?
[[ $rc -eq 0 ]] || exit "$rc"
# Match actual incomplete-result diagnostics, not self-test descriptions or the
# documented SKIP(...) field exceptions from independent protocol decoders.
if grep -aEq '⚠.*(SKIPPED|未核验|未验收|不计为通过|未找到|缺少)|^[[:space:]]*\[SKIP\]|^[[:space:]]*SKIPPED([[:space:]:（(]|$)' "$log"; then
  echo "::error::Acceptance incomplete: see $log" >&2
  exit 1
fi
