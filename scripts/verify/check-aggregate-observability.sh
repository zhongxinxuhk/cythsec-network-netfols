#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != --tshark ) ]]; then echo 'usage: check-aggregate-observability.sh [--tshark]' >&2; exit 2; fi
if [[ "${1:-}" == --tshark ]] && ! command -v tshark >/dev/null 2>&1; then echo '✗ Aggregate reference unverified: tshark missing' >&2; exit 3; fi
cargo build --frozen --bin cythsec-observe
"${PYTHON:-python3}" scripts/verify/check-aggregate-observability.py "$@"
