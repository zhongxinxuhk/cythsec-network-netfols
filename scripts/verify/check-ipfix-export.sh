#!/usr/bin/env bash
# check-ipfix-export.sh —— IPFIX 导出的**第三方交叉核验**（tshark）+ 反向故障注入。
#
# 为什么需要这一步：
#   逐包采集在省网量级上不成立（单条 100G 最坏帧 148.8 Mpps；骨干 10 Tbps 全量约
#   108 PB/天），运营商的做法是让网元**采样导出**流级记录，由采集集群消费 IPFIX。
#   因此 `FlowRecord → IPFIX` 这条出口能不能用，取决于两件我们**无法自证**的事：
#     1) 字节流是不是合法 IPFIX（模板 / 长度 / 对齐 / 序列号语义）；
#     2) 字段值有没有编错（IE 编号、端序、时标单位）。
#   tshark 的上游实现是独立第三方：它能把产物解成字段值这件事，是当前唯一的外部证据。
#   （Rust 单测里的金标准字节只证明"实现符合我写下的规范理解"，证明不了理解本身对。）
#
# 反向故障注入：
#   比对器自己也会写错，最坏的情况是恒返回"通过"。故本脚本默认把产物改坏四次
#   （改计数值 / 改 setID / 改报文长度 / 截断报文），**要求比对器每次报错**。
#   注入落在产物字节上、不需要重新编译，因此它检验的是"核验链条真的在跑"。
#
# 覆盖的三条路径：
#   A. 模板与记录正确性：多个样本（TCP 会话 / 纯 v4 / 纯 v6 / DPI 样本）
#   B. 多报文与模板刷新：首样本强制 --ipfix-max-msg 220 --ipfix-template-refresh 2
#   C. UDP 真实发送：本机监听端口收包，收到的字节必须与 pcap 通道载荷逐字节相同
#
# 用法：
#   bash scripts/verify/check-ipfix-export.sh              # 核验 + 反向自检
#   bash scripts/verify/check-ipfix-export.sh --no-self-test
#
# 只读操作：只在临时目录里写文件（pcap 样本是生成物，需先跑 generate-samples.py）。
# 退出码：0 全部一致；1 存在不一致或未检出注入项；2 样本缺失；3 环境不满足。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: check-ipfix-export.sh [--no-self-test]

  --no-self-test  跳过反向故障注入（仅用于人工排查；正式验收不要用）

用 tshark 独立解析 --ipfix-pcap 产物，与 JSONL 记录逐条比对九类字段，
并核对报文级不变量（version / length / 序列号 / 模板可见性 / 刷新节奏）；
另用本机 UDP 监听验证 --ipfix-udp 通道发出的字节与 pcap 通道载荷逐字节相同。

退出码：0 一致 / 1 不一致或注入未被检出 / 2 样本缺失 / 3 缺 python3、tshark 或 cargo
EOF
  exit 0
fi

SELF_TEST=1
if [[ "${1:-}" == "--no-self-test" ]]; then
  SELF_TEST=0
fi

PY="${PYTHON:-python3}"
TSHARK="${TSHARK:-tshark}"

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "环境检查失败：未找到 $PY" >&2
  exit 3
fi
if ! command -v "$TSHARK" >/dev/null 2>&1; then
  echo "环境检查失败：未找到 ${TSHARK}（IPFIX 校验必须由第三方解码器完成）" >&2
  exit 3
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "环境检查失败：未找到 cargo" >&2
  exit 3
fi

SAMPLES=(
  datasets/pcap/sample-session-tcp.pcap
  datasets/pcap/sample-ipv4-mixed.pcap
  datasets/pcap/sample-ipv6-tcp.pcap
  datasets/dpi/tls-vectors.pcap
)
for f in "${SAMPLES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "样本缺失：${f}（先执行 python3 datasets/pcap/generate-samples.py 与 datasets/dpi/generate-dpi-samples.py）" >&2
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

count_datagrams() {
  "$PY" - "$1" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
pos, n = 24, 0
while pos + 16 <= len(d):
    incl = struct.unpack("<I", d[pos + 8 : pos + 12])[0]
    n += 1
    pos += 16 + incl
print(n)
PY
}

ARGS=()
first=1
for f in "${SAMPLES[@]}"; do
  # 第一个样本强制小报文 + 密集模板刷新：否则"多报文 / 模板重发 / 序列号跨报文"
  # 这几条逻辑在样本量下永远走不到，等于没测。
  label="$(basename "$f" .pcap)"
  jsonl="$TMP/$label.jsonl"
  pcap="$TMP/$label.ipfix.pcap"
  stats="$TMP/$label.stats"
  extra=()
  refresh=20
  if [[ $first -eq 1 ]]; then
    extra=(--ipfix-max-msg 220 --ipfix-template-refresh 2)
    refresh=2
  fi
  "$ANALYZE" -r "$f" -o "$jsonl" --ipfix-pcap "$pcap" ${extra[@]+"${extra[@]}"} >/dev/null 2>"$stats"
  if ! grep -q "ipfix domain=" "$stats"; then
    echo "统计里没有 IPFIX 行（导出可能没执行）：$stats" >&2
    cat "$stats" >&2
    exit 1
  fi
  echo "     $label: $(wc -l < "$jsonl" | tr -d ' ') 条记录 -> $(count_datagrams "$pcap") 个 IPFIX 报文（模板刷新 ${refresh}）"
  ARGS+=("$label:$jsonl:$pcap:$refresh")
  first=0
done

# ---- C：UDP 通道：本机收包，字节必须与 pcap 通道里的载荷逐字节一致 ----
# 这一步不能省：pcap 通道只证明"编码对"，证明不了"真的发出去了"。
PORT="${IPFIX_UDP_PORT:-14739}"
UDP_RX="$TMP/udp-rx.bin"
UDP_PCAP="$TMP/udp-send.ipfix.pcap"
UDP_JSONL="$TMP/udp-send.jsonl"
"$PY" - "$PORT" "$UDP_RX" <<'PY' &
import socket, sys
port, out = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
datagrams = []
# 首个 datagram 最多等 5 秒（等导出进程启动），其后 0.8 秒无新包即收工。
timeout = 5.0
while True:
    s.settimeout(timeout)
    try:
        data, _ = s.recvfrom(65535)
    except socket.timeout:
        break
    datagrams.append(data)
    timeout = 0.8
with open(out, "wb") as fh:
    for d in datagrams:
        fh.write(len(d).to_bytes(4, "big"))
        fh.write(d)
PY
LISTENER=$!
sleep 0.3
"$ANALYZE" -r datasets/pcap/sample-ipv6-tcp.pcap -o "$UDP_JSONL" \
  --ipfix-udp "127.0.0.1:$PORT" --ipfix-pcap "$UDP_PCAP" >/dev/null 2>"$TMP/udp.stats"
wait "$LISTENER" || true

"$PY" - "$UDP_RX" "$UDP_PCAP" <<'PY'
import struct, sys
rx_path, pcap_path = sys.argv[1], sys.argv[2]
blob = open(rx_path, "rb").read()
rx, pos = [], 0
while pos + 4 <= len(blob):
    n = int.from_bytes(blob[pos : pos + 4], "big")
    pos += 4
    rx.append(blob[pos : pos + n])
    pos += n
data = open(pcap_path, "rb").read()
tx, p = [], 24
while p + 16 <= len(data):
    incl = struct.unpack("<I", data[p + 8 : p + 12])[0]
    frame = data[p + 16 : p + 16 + incl]
    tx.append(frame[42:])  # 以太 14 + IPv4 20 + UDP 8
    p += 16 + incl
if not rx:
    print("✗ UDP 通道没有收到任何 datagram：--ipfix-udp 没有真的发包", file=sys.stderr)
    sys.exit(1)
if rx != tx:
    print(
        f"✗ UDP 收到的字节与 pcap 通道载荷不一致（收到 {len(rx)} 个 / 通道 {len(tx)} 个）",
        file=sys.stderr,
    )
    sys.exit(1)
print(f"  ✓ UDP 通道收到 {len(rx)} 个 datagram，与 pcap 通道载荷逐字节相同（{sum(len(d) for d in rx)} 字节）")
PY

echo "==> tshark 交叉核验（第三方实现解我们的 IPFIX 产物）"
PYARGS=()
for spec in "${ARGS[@]}"; do
  PYARGS+=(--pair "$spec")
done
if [[ "$SELF_TEST" == "1" ]]; then
  PYARGS+=(--self-test)
fi
"$PY" scripts/verify/check-ipfix-export.py ${PYARGS[@]+"${PYARGS[@]}"}
