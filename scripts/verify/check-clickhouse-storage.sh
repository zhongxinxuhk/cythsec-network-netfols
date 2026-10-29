#!/usr/bin/env bash
# 真正执行 MergeTree 写入/重新打开/逐字段读回；缺引擎退出 3（未核验）。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
CH_BIN="${CLICKHOUSE_BIN:-clickhouse}"
if ! command -v "${CH_BIN}" >/dev/null 2>&1; then
  echo "未核验：缺少 ClickHouse（CLICKHOUSE_BIN 可指定独立二进制）" >&2
  exit 3
fi
"${PYTHON:-python3}" datasets/dpi/generate-dpi-samples.py
cargo build --release --offline --bin cythsec-analyze
"${PYTHON:-python3}" scripts/plan/measure-clickhouse.py --self-test
"${PYTHON:-python3}" scripts/plan/measure-clickhouse.py --clickhouse "${CH_BIN}" --integration-test
