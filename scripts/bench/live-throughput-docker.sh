#!/usr/bin/env bash
# bench/live-throughput-docker.sh —— CYS-PKT-008 验收命题的吞吐对照实测。
#
# 命题：「AF_PACKET 抓包吞吐显著高于 pcap live」。
# 之前状态：只有编译与功能证据，**没有对照数据**（见 HANDOFF §6）。
# 本脚本把对照做实：同一容器、同一接口、同一负载、同一 snaplen，三方各测一轮：
#
#   L = capture/pcap/pcap_capture.c        （libpcap live —— 命题的另一侧）
#   V = capture/af_packet/af_packet_capture.c（裸 TPACKET_V3 —— 机制参照）
#   P = cythsec-capture                     （生产后端 dataplane/packet-engine）
#
# 负载：ping -f 洪泛 lo 接口 ×3 进程（127.0.0.1/2/3），lo 上每个 echo 产生
# 2 帧（出+入），offered pps 由 ping 的 transmitted 计数与墙钟推得。
#
# 用法（macOS 宿主机）：
#   bash scripts/bench/live-throughput-docker.sh [时长秒]
# 依赖：Docker 可用；镜像 ubuntu:24.04（自动拉取）。
#
# 诚实口径：
#   * 容器为 Docker Desktop 虚拟机，**单容器 ≠ 物理省网设备**；本数据证明的是
#     三种采集机制在同一 CPU 预算下的相对吞吐，不是绝对线速能力。
#   * libpcap 的 ps_drop 各版本填充程度不同，其 drops 值只作参考不作判定。
#   * 每一轮 capture 的原始机器行都保留在输出里，结论可逐行审计。
set -euo pipefail

DUR="${1:-10}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! docker info >/dev/null 2>&1; then
  echo "✗ Docker 守护进程不可用（先启动 Docker Desktop 或 com.docker.backend）" >&2
  exit 4
fi

docker run --rm --privileged \
  -v "${ROOT}":/src:ro \
  ubuntu:24.04 \
  env BENCH_DUR="${DUR}" bash -c '
set -euo pipefail
DUR="${BENCH_DUR:-10}"
export DEBIAN_FRONTEND=noninteractive
echo "==> [1/5] 安装依赖（同一次 docker run 内完成，避免容器退出即丢失）"
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends \
  build-essential cmake libpcap-dev iputils-ping procps time tshark python3 \
  >/dev/null 2>&1 || apt-get install -y -qq build-essential cmake libpcap-dev iputils-ping procps time tshark python3
mkdir -p /work /build

echo "==> [2/5] 构建生产后端 cythsec-capture（Release）"
cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build /build --target cythsec-capture -j"$(nproc)" >/dev/null
CAP=/build/dataplane/packet-engine/cythsec-capture
[[ -x "$CAP" ]] || { echo "✗ 未找到 cythsec-capture 产物"; exit 5; }

echo "==> [3/5] 构建两个对照示例"
gcc -O2 -Wall -Wextra -o /work/pcap_capture /src/capture/pcap/pcap_capture.c -lpcap
gcc -O2 -Wall -Wextra -o /work/af_packet_capture /src/capture/af_packet/af_packet_capture.c
echo "    警告数即失败（验收口径）："
gcc -O2 -Wall -Wextra -Werror -o /dev/null /src/capture/af_packet/af_packet_capture.c \
  || echo "    （-Werror 复验未过，上方输出即告警明细）"

echo "==> [4/5] 负载生成与三轮采集（iface=lo snaplen=2048 每轮 ${DUR}s）"
start_load() {
  # 3 个洪泛进程错开 0.2s 启动，降低瞬时同相；-w 到期自停并打印 transmitted 数。
  local total=$((DUR + 3))
  for t in 127.0.0.1 127.0.0.2 127.0.0.3; do
    ping -f -w "${total}" -c 50000000 "$t" > "/work/load-${t//./_}.txt" 2>&1 &
  done
  LOAD_PIDS=$(jobs -p)
  sleep 1.5
}
stop_load() {
  for p in ${LOAD_PIDS:-}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
offered_pps() {
  # 汇总三个 ping 的 transmitted 与各自墙钟，折算 lo 上的帧速率（×2：出+入）。
  python3 - <<PYEOF
import re, glob, sys
tot_pk, tot_t = 0, 0.0
for f in glob.glob("/work/load-*.txt"):
    s = open(f, errors="ignore").read()
    m = re.search(r"(\d+) packets transmitted, .*time ([0-9.]+)ms", s)
    if m:
        tot_pk += int(m.group(1)); tot_t = max(tot_t, float(m.group(2)) / 1000.0)
if tot_t > 0:
    print(int(2 * tot_pk / tot_t))
else:
    print(0)
PYEOF
}

: > /work/results.txt
for round in L V P; do
  echo "--- 轮 ${round} ---"
  rm -f /work/load-*.txt
  case "${round}" in
    L) CMD=("/work/pcap_capture" -i lo -t "${DUR}" -s 2048 -w /work/bench-L.pcap);;
    V) CMD=("/work/af_packet_capture" -i lo -t "${DUR}" -s 2048 -w /work/bench-V.pcap);;
    P) CMD=("${CAP}" -i lo --timeout "${DUR}" -s 2048 -w /work/bench-P.pcap -q);;
  esac
  # /usr/bin/time 的 wall 与内核时间用于观察「同负载下的 CPU 差异」。
  start_load
  { /usr/bin/time -f "bench time round=${round} user=%U sys=%S wall=%e" \
      "${CMD[@]}" 2>>/work/results.txt; } >>/work/results.txt
  stop_load
  grep -h "packets transmitted" /work/load-*.txt >> /work/results.txt || true
  echo "offered=$(offered_pps) pps(frames) round=${round}" | tee -a /work/results.txt
  sleep 2
done

echo "==> [5/5] 产物可打开性（tshark 独立校验）与汇总"
for f in /work/bench-L.pcap /work/bench-V.pcap /work/bench-P.pcap; do
  if [[ -s "${f}" ]]; then
    n=$(tshark -r "${f}" -T fields -e frame.number 2>/dev/null | wc -l | tr -d " ")
    echo "  tshark ${f##*/}: frames=${n}"
  else
    echo "  tshark ${f##*/}: 文件缺失或为空"
  fi
done
echo ""
echo "================ 原始机器行 ================"
grep -E "^bench (stats|time|pcap)|offered=|packets transmitted" /work/results.txt || cat /work/results.txt
'
