#!/usr/bin/env bash
# CYS-MLT-002: lock-aware quality environment; no code modifications in this gate.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
MODE=--offline
case "${1:-}" in
  --online) MODE=; shift ;;
  --self-test|'') ;;
  --help|-h) echo 'Usage: check-python-quality.sh [--online] [--self-test]'; exit 0 ;;
  *) echo "Unknown argument: ${1}" >&2; exit 2 ;;
esac
command -v uv >/dev/null 2>&1 || { echo 'Python quality requires pinned uv; see ml/training/README.md' >&2; exit 1; }
if [[ -n "${MODE}" ]]; then
  UV_PROJECT_ENVIRONMENT="${ROOT}/ml/training/.venv" uv sync --project ml/training --locked --group quality --offline --no-python-downloads
else
  UV_PROJECT_ENVIRONMENT="${ROOT}/ml/training/.venv" uv sync --project ml/training --locked --group quality
fi
ml/training/.venv/bin/python scripts/verify/check-python-quality.py ${1+"$@"}
