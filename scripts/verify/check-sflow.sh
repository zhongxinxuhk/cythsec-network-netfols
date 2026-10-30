#!/usr/bin/env bash
# check-sflow.sh —— sFlow v5（RFC 3176）采集回路门禁。
#
# 守三件事：
#   1. flow sample 真的能解出五元组/采样率/VLAN，不是"版本号认出来就算适配"；
#   2. counter sample 的接口计数与 VLAN 计数能落到独立 JSONL，不硬塞进 FlowRecord；
#   3. 序号是**数据报**序号，缺口报 lost_datagrams，不能复用 IPFIX/v9 的记录级口径。
#
# 语料由 scripts/verify/check-sflow.py 按 RFC 独立拼字节（不调用 Rust 编码器）；
# 加 --tshark 时由 Wireshark 的 sflow_245 解析器做第三方确认。
#
# 用法：bash scripts/verify/check-sflow.sh [--tshark]
# 退出码：0 通过；1 断言失败；2 前置条件缺失；3 缺工具（未核验，不计通过）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
WANT_TSHARK=0
for arg in "$@"; do
  case "$arg" in
    --tshark) WANT_TSHARK=1 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "未知参数：$arg" >&2; exit 2 ;;
  esac
done

command -v cargo >/dev/null 2>&1 || { echo "⚠ 缺少 cargo：未核验" >&2; exit 3; }
command -v "$PY" >/dev/null 2>&1 || { echo "⚠ 缺少 $PY：未核验" >&2; exit 3; }
if [[ "$WANT_TSHARK" -eq 1 ]] && ! command -v tshark >/dev/null 2>&1; then
  echo "⚠ 缺少 tshark：独立对照未执行（未核验，不计通过）" >&2
  exit 3
fi

echo "==> 构建 cythsec-sflow-collect"
cargo build --offline --quiet -p traffic-engine --bin cythsec-sflow-collect

ARGS=()
[[ "$WANT_TSHARK" -eq 1 ]] && ARGS+=(--tshark)
"$PY" scripts/verify/check-sflow.py ${ARGS[@]+"${ARGS[@]}"}
