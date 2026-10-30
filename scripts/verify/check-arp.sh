#!/usr/bin/env bash
# check-arp.sh —— B004 ARP/RARP 有界解析门禁。
#
# 守三件事：
#   1. Ethernet ARP 的 HTYPE/PTYPE/HLEN/PLEN/OPER 与地址字段能解，VLAN/QinQ、
#      gratuitous、probe、未知类型与截断有显式分类；
#   2. ARP 没有五元组，主流水线只做帧级统计，不伪造 FlowRecord；
#   3. 语料由 check-arp.py 按 RFC 独立拼字节，--tshark 由 Wireshark 再解一遍。
#
# 用法：bash scripts/verify/check-arp.sh [--tshark]
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

echo "==> 构建 cythsec-arp / cythsec-analyze"
cargo build --offline --quiet -p traffic-engine --bin cythsec-arp --bin cythsec-analyze

ARGS=()
[[ "$WANT_TSHARK" -eq 1 ]] && ARGS+=(--tshark)
"$PY" scripts/verify/check-arp.py ${ARGS[@]+"${ARGS[@]}"}
