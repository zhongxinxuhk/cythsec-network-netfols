#!/usr/bin/env bash
# check-geneve.sh —— V015 Geneve 有界解析门禁（RFC 8926）。
#
# 守四件事：
#   1. 版本 0、O/C 位、Opt Len、选项头和 24 位 VNI 能按 RFC 有界解析；
#      未知版本、选项越界、C 位不一致、内层不足、VLAN 超嵌套有显式分类。
#   2. 主流水线只做报文级统计，控制报文不解释载荷，Geneve 内层 IP 不得另造 FlowRecord。
#   3. 独立 cythsec-geneve 采集器输出逐事件 JSONL，且统计行可核对。
#   4. 语料由 check-geneve.py 独立拼字节；--tshark 让 Wireshark 再解一遍同一份 pcap。
#
# 用法：bash scripts/verify/check-geneve.sh [--tshark]
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

echo "==> 构建 cythsec-geneve / cythsec-analyze"
cargo build --offline --quiet -p traffic-engine --bin cythsec-geneve --bin cythsec-analyze

ARGS=()
[[ "$WANT_TSHARK" -eq 1 ]] && ARGS+=(--tshark)
"$PY" scripts/verify/check-geneve.py ${ARGS[@]+"${ARGS[@]}"}
