#!/usr/bin/env bash
# check-icmp-gre.sh —— B011/B012/V009 基础协议识别门禁。
#
# 守四件事：
#   1. ICMPv4/ICMPv6 的 type/code、echo 标识、错误报文内嵌原始 IP、NDP 固定字段
#      与选项能按 RFC 有界解析，截断/未知类型有显式分类；
#   2. GRE v0 的 C/R/K/S 可选头、SRE 源路由、TEB/MPLS 内层与 PPTP 增强 GRE
#      能解；版本 2、缺 K、头截断分别报错；
#   3. 主流水线只做报文级统计，GRE 内层 IP 不得另造 FlowRecord；
#   4. 语料由 check-icmp-gre.py 按 RFC 独立拼字节，--tshark 由 Wireshark 再解一遍。
#
# 用法：bash scripts/verify/check-icmp-gre.sh [--tshark]
# 退出码：0 通过；1 断言失败；2 参数/前置错误；3 缺工具（未核验，不计通过）
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

echo "==> 构建 cythsec-icmp / cythsec-gre / cythsec-analyze"
cargo build --offline --quiet -p traffic-engine --bin cythsec-icmp --bin cythsec-gre --bin cythsec-analyze

ARGS=()
[[ "$WANT_TSHARK" -eq 1 ]] && ARGS+=(--tshark)
"$PY" scripts/verify/check-icmp-gre.py ${ARGS[@]+"${ARGS[@]}"}
