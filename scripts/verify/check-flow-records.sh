#!/usr/bin/env bash
# check-flow-records.sh —— FlowRecord 的**第三方交叉核验**（tshark）+ 反向故障注入。
#
# 为什么需要这一步：
#   `cythsec-analyze` 产出的 FlowRecord（包数、字节数、TCP 末态、应用识别）是我们
#   自己算的。Rust 单测里的期望值是手写的，但手写期望只能证明"实现符合我的理解"，
#   证明不了"我的理解对"。tshark 是独立实现，把它逐帧解析出的事实（IP 头长度、
#   TCP 标志位、载荷长度、协议识别）聚合成会话级结果，再与我们的记录逐项比对，
#   是这条数据链目前唯一的外部证据。
#
# 反向故障注入：
#   比对器本身也可能写错（最坏的情况是恒返回"通过"）。因此本脚本默认执行
#   `--self-test`：把每一项都改坏一次，**要求比对器报错**。没有这一步，
#   "绿色的通过"和"绿色的没跑"完全一样。
#
# 用法：
#   bash scripts/verify/check-flow-records.sh            # 核验 + 反向自检
#   bash scripts/verify/check-flow-records.sh --help
#
# 只读操作：只在临时目录里写文件（pcap 样本是生成物，需先跑 generate-samples.py）。
# 退出码：0 全部一致；1 存在不一致或未检出注入项；2 样本缺失；3 环境不满足。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: check-flow-records.sh [--no-self-test]

  --no-self-test  跳过反向故障注入（仅用于人工排查；正式验收不要用）

用 tshark 独立解析样本 pcap，与 cythsec-analyze 产出的 FlowRecord 逐项比对：
会话集合 / 包数 / 字节数 / 双向计数 / 方向切换 / 首末时间戳 / TCP 末态 /
发起方 / 中途接入标记 / 应用识别 / 解码失败计数 / 统计自证。

退出码：0 一致 / 1 不一致或注入未被检出 / 2 样本缺失 / 3 缺 python3、tshark 或 cargo
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

SAMPLES=(
  datasets/pcap/sample-session-tcp.pcap
  datasets/pcap/sample-ipv4-mixed.pcap
  datasets/pcap/sample-ipv6-tcp.pcap
  datasets/dpi/tls-vectors.pcap
  datasets/dpi/dns-vectors.pcap
  datasets/dpi/http-vectors.pcap
)
for f in "${SAMPLES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "样本缺失：$f（先执行 python3 datasets/pcap/generate-samples.py 与 datasets/dpi/generate-dpi-samples.py）" >&2
    exit 2
  fi
done

echo "==> 构建 cythsec-analyze"
cargo build --offline --quiet --manifest-path dataplane/traffic-engine/Cargo.toml --bin cythsec-analyze
ANALYZE="$ROOT/target/debug/cythsec-analyze"
if [[ ! -x "$ANALYZE" ]]; then
  echo "构建失败：找不到 $ANALYZE" >&2
  exit 3
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 这一行 -e 的顺序必须与 check-flow-records.py 里的 TSV_FIELDS 完全一致：
# 顺序错了不会报错，只会把相邻两列对调。python 侧会核对列数，但顺序仍需人保持一致。
tshark_fields() {
  "$TSHARK" -r "$1" -T fields -E separator='|' \
    -e frame.number -e frame.time_epoch \
    -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst \
    -e ip.proto -e ipv6.nxt \
    -e ip.len -e ip.hdr_len -e ipv6.plen -e ip.frag_offset \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
    -e tcp.flags -e tcp.len \
    -e frame.protocols \
    2>/dev/null
}

ARGS=()
for f in "${SAMPLES[@]}"; do
  label="$(basename "$f" .pcap)"
  out="$TMP/$label.jsonl"
  stats="$TMP/$label.stats"
  tsv="$TMP/$label.tsv"
  "$ANALYZE" -r "$f" -o "$out" >/dev/null 2>"$stats"
  tshark_fields "$f" > "$tsv"
  echo "     $label: $(wc -l < "$out" | tr -d ' ') 条记录 / $(wc -l < "$tsv" | tr -d ' ') 帧"
  ARGS+=(--pair "$label:tolerant:$out:$tsv:$stats")
done

# 严格模式也核验一遍：同一份样本、只换 TCP 判定，期望值必须由 tshark 的事实独立推出。
strict_label="session-strict"
strict_out="$TMP/$strict_label.jsonl"
strict_stats="$TMP/$strict_label.stats"
strict_tsv="$TMP/$strict_label.tsv"
"$ANALYZE" --strict -r datasets/pcap/sample-session-tcp.pcap -o "$strict_out" >/dev/null 2>"$strict_stats"
tshark_fields datasets/pcap/sample-session-tcp.pcap > "$strict_tsv"
ARGS+=(--pair "$strict_label:strict:$strict_out:$strict_tsv:$strict_stats")

echo "==> tshark 交叉核验（第三方事实）+ 反向故障注入"
if [[ "$SELF_TEST" == "1" ]]; then
  ARGS+=(--self-test)
fi
"$PY" scripts/verify/check-flow-records.py "${ARGS[@]}"
