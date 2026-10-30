#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != --tshark ) ]]; then echo 'usage: check-dns-tcp.sh [--tshark]' >&2; exit 2; fi
if [[ "${1:-}" == --tshark ]] && ! command -v tshark >/dev/null 2>&1; then echo 'DNS/TCP reference unverified: tshark unavailable' >&2; exit 3; fi
cargo build --offline --bin cythsec-analyze
"${PYTHON:-python3}" scripts/verify/check-dns-tcp.py "$@"
