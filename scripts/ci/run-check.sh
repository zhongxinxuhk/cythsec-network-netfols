#!/usr/bin/env bash
# Privileged/integration acceptance must not turn a skipped check into green.
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
if grep -Eq 'SKIPPED|\[SKIP\]|未核验|跳过 [1-9][0-9]*' "$log"; then
  echo "Acceptance incomplete: skipped checks in $log" >&2
  exit 1
fi
