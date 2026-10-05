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

docker run --rm --privileged \
  ${PROXY_ENV[@]+"${PROXY_ENV[@]}"} \
  -v "${ROOT}":/src:ro \
  ubuntu:24.04 \
  env BENCH_DUR="${DUR}" BENCH_FRAME="${FRAME}" BENCH_RATE="${RATE}" bash -c '
set -euo pipefail
DUR="${BENCH_DUR}"
FRAME="${BENCH_FRAME}"
RATE="${BENCH_RATE}"
export DEBIAN_FRONTEND=noninteractive
echo "==> [1/5] 安装依赖（同一次 docker run 内完成，避免容器退出即丢失）"
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends \
  build-essential cmake libpcap-dev iproute2 iputils-ping procps time tshark python3 \
  >/dev/null 2>&1 || apt-get install -y -qq build-essential cmake libpcap-dev iproute2 \
  iputils-ping procps time tshark python3
mkdir -p /work /build

echo "==> [2/5] 构建生产后端 cythsec-capture 与打流工具 cythsec-inject"
cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release -DCYTHSEC_BUILD_INFERENCE=OFF >/dev/null
cmake --build /build --target cythsec-capture cythsec-inject -j"$(nproc)" >/dev/null
CAP=/build/dataplane/packet-engine/cythsec-capture
INJ=/build/dataplane/packet-engine/cythsec-inject
[[ -x "$CAP" && -x "$INJ" ]] || { echo "✗ 未找到 cythsec-capture / cythsec-inject 产物"; exit 5; }

echo "==> [3/5] 构建两个对照示例（警告数即失败）"
gcc -O2 -Wall -Wextra -o /work/pcap_capture /src/capture/pcap/pcap_capture.c -lpcap
gcc -O2 -Wall -Wextra -o /work/af_packet_capture /src/capture/af_packet/af_packet_capture.c
gcc -O2 -Wall -Wextra -Werror -o /dev/null /src/capture/af_packet/af_packet_capture.c \
  && echo "    -Werror 复验通过" || { echo "    ✗ -Werror 复验未过"; exit 6; }

echo "==> [4/5] veth 负载对 + 四臂测量（每臂 ${DUR}s，帧长 ${FRAME}）"
ip link del va 2>/dev/null || true
ip link add va type veth peer name vb
ip link set va up
ip link set vb up

# 设备层计数（丢包在设备层时 packet socket 的 tp_drops 看不到 —— 见头注释）。
dev_stat() { # $1=接口 $2=字段
  local f="/sys/class/net/$1/statistics/$2"
  if [[ -r "${f}" ]]; then cat "${f}"; else echo 0; fi
}
# softnet backlog 丢包：高 pps 下**内核协议栈入口**的丢包只反映在这里
# （/proc/net/softnet_stat 每 CPU 一行的第 3 列，十六进制），网卡统计里看不到。
# 实测：veth 上 ~1.5 Mpps 洪泛时各臂都有 ~6% 的包「设备收到了但没人抓到」，
# 而 rx_dropped 全是 0 —— 差额就在这一列。不读它，报告的「未交代」就永远说不清。
softnet_drop() {
  awk '{s+=strtonum("0x"$3)} END{print s+0}' /proc/net/softnet_stat 2>/dev/null || echo 0
}
"tx_stat() { dev_stat vb "$1"; }"

: > /work/results.txt
run_arm() { # $1=臂名 $2=命令行（数组用 eval 展开）
  local arm="$1"; shift
  local a_rxp a_drp a_mis b_rxp b_drp b_mis
  a_rxp=$(dev_stat va rx_packets); a_drp=$(dev_stat va rx_dropped); a_mis=$(dev_stat va rx_missed_errors)
  local a_sn a_txd
  a_sn=$(softnet_drop); a_txd=$(tx_stat tx_dropped)
  # 打流进程：全速或指定速率。**不要 kill 它** —— 它的 sent/pps 只在正常退出时打印，
  # kill 掉就永远拿不到分母（旧版 ping 洪泛就是这么把 offered 变成 0 的）。
  # 所以让它跑到点自己退出，只需 wait。
  if [[ "${RATE}" == "0" ]]; then
    "${INJ}" -i vb --duration "${DUR}" --size "${FRAME}" > /work/inject-${arm}.txt 2>&1 &
  else
    "${INJ}" -i vb --duration "${DUR}" --size "${FRAME}" --rate "${RATE}" \
      > /work/inject-${arm}.txt 2>&1 &
  fi
  local inj_pid=$!
  sleep 0.4
  # CPU 用 /usr/bin/time 取（user+sys），这是「同吞吐下谁更省 CPU」的唯一硬指标。
  # 每臂输出独立成文件：混在一个 results.txt 里会让「哪个数字属于哪一臂」靠行序猜。
  /usr/bin/time -f "bench time arm=${arm} user=%U sys=%S wall=%e" \
    "$@" >/work/arm-${arm}.txt 2>>/work/arm-${arm}.txt || \
    echo "WARN arm=${arm} 采集中途非 0 退出（原始输出见 /work/arm-${arm}.txt）" | tee -a /work/results.txt
  wait "${inj_pid}" 2>/dev/null || true
  cat /work/arm-${arm}.txt >> /work/results.txt
  cat /work/inject-${arm}.txt >> /work/results.txt
  b_rxp=$(dev_stat va rx_packets); b_drp=$(dev_stat va rx_dropped); b_mis=$(dev_stat va rx_missed_errors)
  local b_sn b_txd
  b_sn=$(softnet_drop); b_txd=$(tx_stat tx_dropped)
  local sent pps_inj
  sent=$(grep -o "sent=[0-9]*" /work/inject-${arm}.txt | head -1 | cut -d= -f2 || echo 0)
  pps_inj=$(grep -o "pps=[0-9]*" /work/inject-${arm}.txt | head -1 | cut -d= -f2 || echo 0)
  echo "bench arm summary arm=${arm} offered=${sent:-0} offered_pps=${pps_inj:-0} dev_rx_delta=$((b_rxp - a_rxp)) dev_drop_delta=$((b_drp - a_drp + b_mis - a_mis)) softnet_delta=$((b_sn - a_sn)) tx_drop_delta=$((b_txd - a_txd))" \
    | tee -a /work/results.txt
  sleep 1
}

# 先探一次「打流单独能跑多快」（作为 offered 的量级参照，不带抓包）。
"${INJ}" -i vb --duration 2 --size "${FRAME}" 2>&1 | grep -E "^inject stats" \
  | sed "s/^/bench inject-only /" | tee -a /work/results.txt

run_arm L   /work/pcap_capture -i va -t "${DUR}" -s "$((FRAME + 2048))" -w /work/bench-L.pcap
run_arm V   /work/af_packet_capture -i va -t "${DUR}" -s "$((FRAME + 2048))" -w /work/bench-V.pcap
run_arm Pv3 "${CAP}" -i va --timeout "${DUR}" -s "$((FRAME + 2048))" --capture-mode v3 -q -w /work/bench-Pv3.pcap
run_arm Pcopy "${CAP}" -i va --timeout "${DUR}" -s "$((FRAME + 2048))" --capture-mode recvfrom -q \
  -w /work/bench-Pcopy.pcap

if [[ "${RATE}" != "0" ]]; then
  echo "--- 固定速率 ${RATE} pps：两档都不该丢包，比 CPU/包 ---"
  RATE_SAVE="${RATE}"; RATE="${RATE}"
  run_arm Pv3_fixed "${CAP}" -i va --timeout "${DUR}" -s "$((FRAME + 2048))" --capture-mode v3 -q -w /work/bench-Pv3f.pcap
  run_arm Pcopy_fixed "${CAP}" -i va --timeout "${DUR}" -s "$((FRAME + 2048))" --capture-mode recvfrom -q -w /work/bench-Pcopyf.pcap
  RATE="${RATE_SAVE}"
fi

echo "==> [5/5] 产物可打开性（tshark 独立校验）与汇总"
for f in /work/bench-L.pcap /work/bench-V.pcap /work/bench-Pv3.pcap /work/bench-Pcopy.pcap; do
  if [[ -s "${f}" ]]; then
    # tshark 失败（例如文件被截断）不能让整轮测量作废：把结论降级为可见的告警。
    n=$(tshark -r "${f}" -T fields -e frame.number 2>/dev/null | wc -l | tr -d " ") || n="tshark失败"
    echo "  tshark ${f##*/}: frames=${n}"
  else
    echo "  tshark ${f##*/}: 文件缺失或为空"
  fi
done

echo ""
echo "================ 汇总（本臂自报，逐行可审计）================"
python3 - <<PYEOF
import re, glob, os
def read(p):
    return open(p, errors="ignore").read() if os.path.exists(p) else ""
arms = {}
times = {}
dev = {}
inject = {}
inject_only = 0
for ln in read("/work/results.txt").splitlines():
    m = re.match(r"bench inject-only .*sent=(\d+) bytes=\d+ duration_ms=(\d+) pps=(\d+)", ln)
    if m:
        inject_only = int(m.group(3))
    m = re.match(r"bench arm summary arm=(\S+) offered=(\d+) offered_pps=(\d+) dev_rx_delta=(-?\d+) "
                 r"dev_drop_delta=(-?\d+) softnet_delta=(-?\d+) tx_drop_delta=(-?\d+)", ln)
    if m:
        dev[m.group(1)] = (int(m.group(4)), int(m.group(5)), int(m.group(6)), int(m.group(7)))
for arm in ("L", "V", "Pv3", "Pcopy", "Pv3_fixed", "Pcopy_fixed"):
    txt = read("/work/arm-%s.txt" % arm)
    if txt:
        m = re.search(r"bench stats backend=(\S+) iface=\S+ packets=(\d+) bytes=(\d+) drops=(\d+)"
                      r"(?: ifdrops=(\d+))?", txt)
        if m:
            arms[arm] = dict(packets=int(m.group(2)), drops=int(m.group(4)), impl=m.group(1))
        m2 = re.search(r"capture stats packets=(\d+) bytes=(\d+) dropped=(\d+) kernel=(\d+) errors=\d+ "
                       r"duration_ms=(\d+)", txt)
        if m2:
            arms[arm] = dict(packets=int(m2.group(1)), drops=int(m2.group(3)),
                             kernel=int(m2.group(4)), impl="cythsec-capture")
        m3 = re.search(r"bench time arm=\S+ user=([\d.]+) sys=([\d.]+) wall=([\d.]+)", txt)
        if m3:
            times[arm] = (float(m3.group(1)), float(m3.group(2)), float(m3.group(3)))
    itxt = read("/work/inject-%s.txt" % arm)
    m = re.search(r"sent=(\d+) bytes=\d+ duration_ms=\d+ pps=(\d+)", itxt)
    if m:
        inject[arm] = (int(m.group(1)), int(m.group(2)))

print()
print("打流工具单独全速（同帧长）：%d pps" % inject_only)
print()
print("---- 各臂原始自报行（逐行可审计）----")
for arm in ("L", "V", "Pv3", "Pcopy", "Pv3_fixed", "Pcopy_fixed"):
    for ln in read("/work/arm-%s.txt" % arm).splitlines():
        if ln.strip():
            print("  [%s] %s" % (arm, ln))
    for ln in read("/work/inject-%s.txt" % arm).splitlines():
        if ln.strip():
            print("  [%s 负载] %s" % (arm, ln))
print()
hdr = "%-8s %12s %12s %10s %9s %9s %9s %9s %12s" % (
    "臂", "发出", "抓到", "抓/发", "socket丢", "softnet丢", "设备丢", "未交代", "CPU(us/包)")
print(hdr)
print("-" * len(hdr))
def order():
    return [("L", "libpcap-live"), ("V", "af-packet-v3"), ("Pv3", "cythsec:TPACKET_V3"),
            ("Pcopy", "cythsec:recvfrom"), ("Pv3_fixed", "cythsec:TPACKET_V3@固定速率"),
            ("Pcopy_fixed", "cythsec:recvfrom@固定速率")]
rows = []
for arm, _key in order():
    st = arms.get(arm)
    if not st:
        # 无数据也要出现在表里：缺一行和「跑了没抓到」是两件事。
        print("%-8s %12s %12s %10s %9s %9s %9s %9s %12s" % (arm, "-", "无数据", "-", "-", "-", "-", "-", "-"))
        continue
    cap = st["packets"]
    offered, offered_pps = inject.get(arm, (0, 0))
    drx, ddrp, dsn, dtx = dev.get(arm, (0, 0, 0, 0))
    ratio = ("%.3f" % (cap / offered)) if offered else "-"
    # 未交代 = 设备收到的 − 抓到的 − socket 丢 − softnet 丢 − 发送侧丢
    unacc = drx - cap - st["drops"] - dsn - dtx
    u, s, w = times.get(arm, (0.0, 0.0, 0.0))
    cpu = (u + s) * 1e6 / cap if cap else 0.0
    print("%-8s %12d %12d %10s %9d %9d %9d %9d %12.1f" % (
        arm, offered, cap, ratio, st["drops"], dsn, ddrp, unacc, cpu))
    rows.append((arm, cap, offered, u + s, st["drops"]))
if len(rows) >= 3:
    d = {r[0]: r for r in rows}
    if "Pv3" in d and "Pcopy" in d:
        print()
        print("P-v3 / P-copy 吞吐比 = %.2fx（抓到 %d vs %d）" %
              (d["Pv3"][1] / d["Pcopy"][1] if d["Pcopy"][1] else 0, d["Pv3"][1], d["Pcopy"][1]))
        if d["Pcopy"][3] > 0:
            print("P-v3 / P-copy 每包 CPU 比 = %.1fx 省（%.2fs vs %.2fs）" %
                  ((d["Pcopy"][3] / d["Pv3"][3]) if d["Pv3"][3] else 0, d["Pv3"][3], d["Pcopy"][3]))
    if "L" in d and "V" in d:
        print("V / L 吞吐比 = %.2fx" % (d["V"][1] / d["L"][1] if d["L"][1] else 0))
print()
print("注：未交代 = 设备 rx − 抓到 − socket 丢 − softnet 丢 − 发送侧丢（含仍在环里未取走的）。")
print("    本脚本不判定阈值（机器/容器配额相关）；结论写进 HANDOFF §2.9。")
PYEOF
'
