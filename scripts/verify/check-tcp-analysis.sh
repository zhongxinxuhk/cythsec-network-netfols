#!/usr/bin/env bash
# check-tcp-analysis.sh —— CYS-TRF-015 会话级 TCP 统计的第三方交叉核验 + 反向故障注入。
#
# 为什么需要这一步：
#   `cythsec-analyze` 的 `tcp retr=/ooo=/rtt=` 统计行是我们自己算的。Rust 单测的期望值
#   是手写的，它只能证明"实现符合我们的定义"；定义本身是不是独立实现也认的定义，
#   要 tshark 在**同一条 pcap** 上实测。三方（我们的统计行 / 生成器真值 / tshark 标记）
#   里任意一方出错，至少有一处对不上 —— 这就是 check-tcp-analysis.py 的恒等式。
#
# 为什么样本必须是生成器而不是提交的 pcap：
#   同字节、不同 ACK 上下文会让 Wireshark 把"补洞段"归成 retransmission（2026-10-23
#   反面探针实测）；所以构型必须钉死在生成脚本里、可复现，而不是一张表格或一个
#   没人能重建的 pcap。
#
# 用法：
#   bash scripts/verify/check-tcp-analysis.sh              # 核验 + 反向注入
#   bash scripts/verify/check-tcp-analysis.sh --no-self-test  # 仅排查用，正式验收不要用
#
# 退出码：0 全部一致（且注入全部检出）/ 1 不一致或注入漏检 / 2 样本缺失 / 3 环境不满足。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: check-tcp-analysis.sh [--no-self-test]

三方比对 cythsec-analyze 的 TCP 统计行 / 生成器真值 / tshark tcp.analysis 标记，
并比对**逐会话记录列**（FlowRecord v2 的 tcp.* 六列）：
  恒等式 我们的retr == tshark retransmission 帧数（逐流 + 全局）
  恒等式 我们的ooo  == tshark out_of_order 帧数（逐流 + 全局）
  恒等式 记录逐会话 retr/ooo == tshark 对该流的帧数（列值与汇总行各自可错）
  RTT / 上下行字节 / 未观测会话数 与生成器真值逐键比对（RTT 不与 tshark iRTT 比，口径不同）
  反向故障注入 26 项必须全部被检出

退出码：0 一致 / 1 不一致或注入漏检 / 2 样本缺失 / 3 缺 python3、tshark 或 cargo
EOF
  exit 0
fi

SELF_TEST=1
if [[ "${1:-}" == "--no-self-test" ]]; then
  SELF_TEST=0
fi

PY="${PYTHON:-}"
if [[ -z "$PY" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PY="python3"
  else
    echo "环境检查失败：未找到 python3（可用 PYTHON 环境变量指定解释器）" >&2
    exit 3
  fi
fi

TSHARK="${TSHARK:-tshark}"
if ! command -v "$TSHARK" >/dev/null 2>&1; then
  echo "环境检查失败：未找到 tshark（可用 TSHARK 环境变量指定路径）" >&2
  exit 3
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "环境检查失败：未找到 cargo（需要构建 cythsec-analyze）" >&2
  exit 3
fi

PCAP="datasets/tcp-analysis/sample-tcp-anomaly.pcap"
EXPECTED="datasets/tcp-analysis/expected.json"
if [[ ! -f "$PCAP" || ! -f "$EXPECTED" ]]; then
  echo "样本缺失：$PCAP / $EXPECTED（先执行 python3 datasets/tcp-analysis/generate-tcp-analysis-samples.py）" >&2
  exit 2
fi

echo "==> 构建 cythsec-analyze"
cargo build --offline --quiet --manifest-path dataplane/traffic-engine/Cargo.toml --bin cythsec-analyze
ANALYZE="$ROOT/target/debug/cythsec-analyze"
if [[ ! -x "$ANALYZE" ]]; then
  echo "构建失败：找不到 $ANALYZE" >&2
  exit 3
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 这一行 -e 的顺序必须与 check-tcp-analysis.py 的 parse_tshark_tsv 完全一致：
# 顺序错了不会报错，只会把相邻两列对调（先例教训：重组/DPI 关口同样踩过）。
"$TSHARK" -r "$PCAP" -T fields -E separator='|' \
  -e frame.number -e tcp.srcport -e tcp.dstport \
  -e tcp.analysis.retransmission -e tcp.analysis.out_of_order \
  -e tcp.analysis.lost_segment -e tcp.analysis.duplicate_ack \
  > "$TMP/tshark.tsv" 2>/dev/null

"$ANALYZE" -r "$PCAP" -o "$TMP/records.jsonl" >/dev/null 2>"$TMP/stats.txt"
if [[ ! -s "$TMP/stats.txt" ]]; then
  echo "cythsec-analyze 没有产出 stderr 统计" >&2
  exit 1
fi

ARGS=(--stats "$TMP/stats.txt" --tsv "$TMP/tshark.tsv" --records "$TMP/records.jsonl" --expected "$EXPECTED")
if [[ "$SELF_TEST" == "1" ]]; then
  ARGS+=(--self-test)
fi

echo "==> 三方比对（我们的统计行 / 生成器真值 / tshark）+ 反向故障注入"
"$PY" scripts/verify/check-tcp-analysis.py "${ARGS[@]}"
