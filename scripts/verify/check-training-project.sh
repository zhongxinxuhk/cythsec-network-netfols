#!/usr/bin/env bash
# CYS-MLT-001: frozen toolchain, lock freshness and isolated installed-wheel smoke.
# Default is offline; first bootstrap: uv sync --project ml/training --locked.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
MODE=--offline
case "${1:-}" in
  --online) MODE=; shift ;;
  --self-test|'') ;;
  --help|-h) echo 'Usage: check-training-project.sh [--online] [--self-test]'; exit 0 ;;
  *) echo "Unknown argument: ${1}" >&2; exit 2 ;;
esac
if ! command -v uv >/dev/null 2>&1; then
  echo '✗ training project: missing uv; bootstrap instructions: ml/training/README.md' >&2
  exit 1
fi
if [[ -n "${MODE}" ]]; then
  UV_PROJECT_ENVIRONMENT="${ROOT}/ml/training/.venv" uv sync --project ml/training --locked --offline --no-python-downloads
else
  UV_PROJECT_ENVIRONMENT="${ROOT}/ml/training/.venv" uv sync --project ml/training --locked
fi
if [[ -n "${MODE}" ]]; then
  ml/training/.venv/bin/python scripts/verify/check-training-project.py ${1+"$@"}
else
  ml/training/.venv/bin/python scripts/verify/check-training-project.py --online ${1+"$@"}
fi
