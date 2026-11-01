#!/usr/bin/env bash
# check-vxlan.sh —— V014 VXLAN 有界解析门禁（RFC 7348）。
#
# 守四件事：
#   1. VXLAN 固定头的 I 位/保留位、24 位 VNI、内层以太网/VLAN/IPv4/IPv6 头
#      能按 RFC 有界解析；截断、缺 I 位、保留位、超嵌套有显式分类。
#   2. 主流水线只做报文级统计，VXLAN 内层 IP 不得另造 FlowRecord。
#   3. 独立 cythsec-vxlan 采集器输出逐事件 JSONL，且统计行可核对。
#   4. 语料由 check-vxlan.py 独立拼字节；--tshark 让 Wireshark 再解一遍同一份 pcap。
#
# 用法：bash scripts/verify/check-vxlan.sh [--tshark]
# 退出码：0 通过；1 断言失败；2 参数/前置错误；3 缺工具（未核验，不计通过）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
WANT_TSHARK=0
for arg in "$@"; do
  case "$arg" in
    --tshark) WANT_TSHARK=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "未知参数：$arg" >&2; exit 2 ;;
  esac
done

command -v cargo >/dev/null 2>&1 || { echo "⚠ 缺少 cargo：未核验" >&2; exit 3; }
command -v "$PY" >/dev/null 2>&1 || { echo "⚠ 缺少 $PY：未核验" >&2; exit 3; }
if [[ "$WANT_TSHARK" -eq 1 ]] && ! command -v tshark >/dev/null 2>&1; then
  echo "⚠ 缺少 tshark：独立对照未执行（未核验，不计通过）" >&2
  exit 3
fi

echo "==> 构建 cythsec-vxlan / cythsec-analyze"
cargo build --offline --quiet -p traffic-engine --bin cythsec-vxlan --bin cythsec-analyze

ARGS=()
[[ "$WANT_TSHARK" -eq 1 ]] && ARGS+=(--tshark)
"$PY" scripts/verify/check-vxlan.py ${ARGS[@]+"${ARGS[@]}"}
