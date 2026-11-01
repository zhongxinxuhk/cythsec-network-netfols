#!/usr/bin/env bash
# check-ipfrag.sh —— B008 IPv4/IPv6 分片重组门禁。
#
# 守四件事：
#   1. 完整数据报在 IPv4/IPv6（含逐跳扩展头）上都能乱序重组，且只产出一条逻辑流；
#   2. 缺首片/缺尾/重叠/截断/重复片分别有显式统计与事件，不伪造内层流；
#   3. 主流水线的 `ipfrag` 统计行与独立 `cythsec-ipfrag` 事件流互相印证；
#   4. `--tshark` 让 Wireshark 独立重组同一份 pcap，核对 DNS 查询名与分片帧数。
#
# 用法：bash scripts/verify/check-ipfrag.sh [--tshark]
# 退出码：0 通过；1 断言失败；2 参数/前置错误；3 缺工具（未核验，不计通过）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
WANT_TSHARK=0
for arg in "$@"; do
  case "$arg" in
    --tshark) WANT_TSHARK=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "未知参数：$arg" >&2; exit 2 ;;
  esac
done

command -v cargo >/dev/null 2>&1 || { echo "⚠ 缺少 cargo：未核验" >&2; exit 3; }
command -v "$PY" >/dev/null 2>&1 || { echo "⚠ 缺少 $PY：未核验" >&2; exit 3; }
if [[ "$WANT_TSHARK" -eq 1 ]] && ! command -v tshark >/dev/null 2>&1; then
  echo "⚠ 缺少 tshark：独立对照未执行（未核验，不计通过）" >&2
  exit 3
fi

echo "==> 构建 cythsec-analyze / cythsec-ipfrag"
cargo build --offline --quiet -p traffic-engine --bin cythsec-analyze --bin cythsec-ipfrag

ARGS=()
[[ "$WANT_TSHARK" -eq 1 ]] && ARGS+=(--tshark)
"$PY" scripts/verify/check-ipfrag.py ${ARGS[@]+"${ARGS[@]}"}
