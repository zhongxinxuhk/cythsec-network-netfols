#!/usr/bin/env bash
# 容器内的测量脚本 —— 由 scripts/bench/live-throughput-docker.sh 以
#   docker run -i ... ubuntu:24.04 bash -s -- <时长> <帧长> <速率> < inner.sh
# 的方式喂给容器执行。**单独成文件**的理由：装在引号串里的脚本，外层 bash -n 查不出
# 语法错（内层引号会与外层配平），而错误要等容器跑几分钟才炸 —— 实测为这个白等过 8 分钟。
# 独立成文件后外层脚本可以先 bash -n 一遍再进容器（见 live-throughput-docker.sh）。
set -euo pipefail
DUR="${1:?需要时长秒}"
FRAME="${2:?需要帧长}"
RATE="${3:?需要速率 pps（0 = 全速）}"
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
# 注意：本函数体处在容器脚本内，而外层是 bash -c 的单引号串 —— **这里不能出现单引号**，
# 否则会提前闭合外层字符串（这个坑真实踩过：表现为容器内莫名的语法错误）。
softnet_drop() {
  local total=0 v
  for v in $(tr -s " " < /proc/net/softnet_stat | cut -d" " -f2); do
    case "$v" in
      ""|*[!0-9a-fA-F]*) continue ;;
    esac
    total=$((total + 16#$v))
  done
  echo "$total"
}
tx_stat() { dev_stat vb "$1"; }

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
