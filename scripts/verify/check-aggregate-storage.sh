#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
cargo build --frozen --bin cythsec-observe
mkdir -p build/aggregate-storage
(cd services/telemetryd && GOWORK=off GOPROXY=off go build -o "$ROOT/build/aggregate-storage/telemetryd" ./cmd/telemetryd)
"${PYTHON:-python3}" scripts/verify/check-aggregate-storage.py
