#!/usr/bin/env bash
# Rust tests/examples 用 include_bytes!/include_str! 嵌入生成物；必须在首次编译之前执行。
# 与统一门禁共用入口，不依赖开发机上已有但被 gitignore 忽略的样本。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
py="${PYTHON:-python3}"
command -v "$py" >/dev/null 2>&1 || { echo "未找到 Python: $py" >&2; exit 1; }

for generator in \
  datasets/pcap/generate-samples.py \
  datasets/dpi/generate-dpi-samples.py \
  datasets/reassembly/generate-reassembly-samples.py \
  datasets/tcp-analysis/generate-tcp-analysis-samples.py; do
  "$py" "$generator"
done
