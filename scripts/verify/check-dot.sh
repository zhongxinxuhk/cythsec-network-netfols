#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != --tshark ) ]]; then echo 'usage: check-dot.sh [--tshark]' >&2; exit 2; fi
for tool in uv openssl; do
  if ! command -v "$tool" >/dev/null 2>&1; then echo "B018 DoT unverified: missing $tool" >&2; exit 3; fi
done
if [[ "${1:-}" == --tshark ]] && ! command -v tshark >/dev/null 2>&1; then echo 'B018 DoT reference unverified: tshark unavailable' >&2; exit 3; fi
cargo build --offline --bin cythsec-analyze
# Reuse the repository's pinned Python/OpenSSL runtime; system macOS Python lacks keylog support.
UV_PROJECT_ENVIRONMENT="${ROOT}/ml/training/.venv" uv run --project ml/training --locked --offline --no-python-downloads python scripts/verify/check-dot.py "$@"
