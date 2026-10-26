#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != --tshark ) ]]; then echo 'usage: check-vpn-identification.sh [--tshark]' >&2; exit 2; fi
if [[ "${1:-}" == --tshark ]] && ! command -v tshark >/dev/null 2>&1; then echo '✗ VPN tshark 未核验：工具缺失' >&2; exit 3; fi
cargo build --frozen --bin cythsec-identify
"${PYTHON:-python3}" scripts/verify/check-vpn-identification.py "$@"
