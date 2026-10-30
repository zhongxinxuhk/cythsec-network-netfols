#!/usr/bin/env bash
# CYS-TRF-028: layout freshness, independent extraction, handwritten truth and injections.
# Runs in test-all.sh --rust (including default ALL), and CI's Rust job.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
case "${1:-}" in
  --help|-h) echo 'Usage: check-features.sh [--self-test] (always includes injections)'; exit 0 ;;
  --self-test|'') ;;
  *) echo "Unknown argument: ${1}" >&2; exit 2 ;;
esac
"${PYTHON:-python3}" tools/codegen/gen-features.py --check
"${PYTHON:-python3}" scripts/verify/check-features.py
