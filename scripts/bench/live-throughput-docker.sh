#!/usr/bin/env bash
# bench/live-throughput-docker.sh —— CYS-PKT-008 验收命题的吞吐对照实测。
#
# 命题：「AF_PACKET mmap 环的抓包吞吐显著高于拷贝模式（pcap live 那一类）」。
# 之前状态：只有编译与功能证据，**没有对照数据**。本脚本把对照做实。
#
# 四个测量臂（同一容器、同一接口对、同一负载、同一 snaplen）：
#
#   L         = capture/pcap/pcap_capture.c        （libpcap live —— 命题的另一侧）
#   V         = capture/af_packet/af_packet_capture.c（裸 TPACKET_V3 —— 机制参照）
#   P-v3      = cythsec-capture --capture-mode v3      （生产后端，mmap 环）
#   P-copy    = cythsec-capture --capture-mode recvfrom（生产后端，拷贝模式）
#
# 负载：**veth 对 + cythsec-inject**（不是 ping 洪泛）。为什么换掉 ping：
#   ① ping 的统计只在进程正常退出时才打印，而洪泛必须被 kill 掉 → 「实际发了多少」
#      永远取不到（旧版实测 offered=0，等于没有分母）；
#   ② ping 在 lo 上每包产生 2 帧（出+入），速率口径要额外解释；
#   ③ cythsec-inject 自己报 sent/duration/pps，**自证**且零额外依赖。
#
# 记账口径（本脚本的核心，也是旧版最弱的一环）：一次测量里包的四种去向必须能对上：
#   inject 发出 → 设备 rx 计数 → 应用抓到 / socket 层丢 / 设备层丢 / 未交代
#   * socket 丢 = PACKET_STATISTICS.tp_drops（cythsec-capture 的 dropped=、V 的 drops=）
#   * 设备层丢 = /sys/class/net/<if>/statistics 的 rx_dropped+rx_missed_errors 增量
#   **实测教训**：拷贝臂少抓 40% 的包却报 socket 丢包 = 0 —— 那部分丢在设备层
#   （软中断赶不上，根本没进 packet socket 的队列）。只看 tp_drops 会得出
#   「拷贝模式不丢包」的错误结论。故本脚本把设备层计数单独列出。
#
# 诚实边界：
#   * Docker Desktop 是虚拟机，veth 是**软件设备**：本数据证明的是「同一 CPU 预算下
#     两种采集机制的能力差」，不是物理网卡的绝对线速能力。
#   * 臂与臂之间共享 CPU：抓包臂越忙，打流进程能发出去的量就越少。故每臂都记录
#     自己的 offered（inject 自报），不做「四臂同一 offered」的假设。
#   * 绝对数字随机器/容器配额变化，本脚本**不做阈值判定**。
#
# 用法（macOS 宿主机）：
#   bash scripts/bench/live-throughput-docker.sh [时长秒=8] [帧长=64] [速率pps=0]
#   速率 0 = 全速洪泛（默认）；给一个速率则另跑一轮「固定速率、零丢包」的 CPU 对照。
# 依赖：Docker 可用；镜像 ubuntu:24.04（自动拉取）。
set -euo pipefail

DUR="${1:-8}"
FRAME="${2:-64}"
RATE="${3:-0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! docker info >/dev/null 2>&1; then
  echo "✗ Docker 守护进程不可用（先启动 Docker Desktop 或 com.docker.backend）" >&2
  exit 4
fi

# 探测宿主 HTTP 代理（仅 macOS；非代理环境留空 = 容器直连）。
# 容器出网坑（本机实测）：宿主开 TUN 模式代理时，容器内 DNS 会解析到 fake-ip
# （172.19.x.x）且直连超时 —— apt 看似「网络不可达」。解法：让容器显式走宿主
# HTTP 代理（host.docker.internal:PORT，从 scutil --proxy 自动探测）。
PROXY_ENV=()
if [[ "$(uname -s)" == "Darwin" ]]; then
  P_HOST="$(scutil --proxy 2>/dev/null | awk '$1=="HTTPProxy"{print $3; exit}')"
  P_PORT="$(scutil --proxy 2>/dev/null | awk '$1=="HTTPPort"{print $3; exit}')"
  if [[ -n "${CYTHSEC_BENCH_PROXY:-}" ]]; then
    PROXY_ENV=(-e "http_proxy=${CYTHSEC_BENCH_PROXY}" -e "https_proxy=${CYTHSEC_BENCH_PROXY}")
  elif [[ "${P_HOST}" == "127.0.0.1" && -n "${P_PORT}" ]]; then
    PROXY_ENV=(-e "http_proxy=http://host.docker.internal:${P_PORT}"
               -e "https_proxy=http://host.docker.internal:${P_PORT}"
               -e "no_proxy=host.docker.internal")
    echo "（容器出网将经宿主代理 http://host.docker.internal:${P_PORT}）"
  fi
fi


# 容器脚本独立成文件（见该文件头注释：装在引号串里的语法错查不出来）。
INNER_SH="${ROOT}/scripts/bench/docker/live-throughput-inner.sh"
[[ -r "${INNER_SH}" ]] || { echo "✗ 找不到容器脚本 ${INNER_SH}" >&2; exit 3; }
bash -n "${INNER_SH}" || { echo "✗ 容器脚本语法自检未过" >&2; exit 3; }

docker run --rm --privileged -i \
  ${PROXY_ENV[@]+"${PROXY_ENV[@]}"} \
  -v "${ROOT}":/src:ro \
  ubuntu:24.04 \
  bash -s -- "${DUR}" "${FRAME}" "${RATE}" < "${INNER_SH}"
