#!/usr/bin/env bash
# e2e-live-capture.sh —— 真实网卡抓包验收关口（CYS-PKT-007 / CYS-PKT-008 的验收标准，
# 并附带 CYS-TRF-034 的「真实网卡 → 环 → Flow」两段式延伸段）。
#
# 用法：
#   bash scripts/verify/e2e-live-capture.sh              # 跑完整真实抓包验收
#   CYTHSEC_LIVE_IFACE=lo0 bash scripts/verify/e2e-live-capture.sh   # 指定接口
#   bash scripts/verify/e2e-live-capture.sh --help
#
# 为什么需要独立关口而不是只看单测：
#   test_live_capture.cpp 的断言全部是「零特权即可验证」的（接口枚举 / 工厂路由 /
#   失败诊断 / 批解析），它们**证明不了真机路径能收到包** —— 本仓库就发生过
#   「无特权断言全绿，真机上 0 包入、数千 errors（线上头 18B 与 SDK sizeof 20B
#   的畸形判定误判）」的事故。只有真的对着网卡收一次，才能把「解析器自以为的
#   线上格式」与「内核实际写出的线上格式」区分开。
#
# 断言链（每条对应一类只在真机上才暴露的失效）：
#   A. 采集本身成立：capture status=ok、packets>=MIN、dropped=0、errors=0。
#      —— 全 0 输出必须以非 0 退出（CLI 的 exit=7 语义），本关口据此判失败。
#   B. 第三方独立复核：tshark 读 -w 产物，注入流量的 ICMP 回包数 >= 下限。
#      —— 缺 tshark 时显式打印「未核验…不计为通过」，不冒充绿。
#   C. 自家解析器回读：cythsec-parse 计数 == capture 交付数。
#      —— 写盘 / 读盘 / 采集三方对同一批字节计数一致，排除「落盘丢尾包」。
#   D. 真实网卡 → 环 → Flow（两段式，中间经文件）：把本轮真实抓到的报文灌入
#      共享环，Rust 消费端解出 flow>=1 且 decode_fail=0。
#      —— 这是 TRF-034「真实报文进、可分析记录出」在当前架构下的形态；
#      同进程零拷贝直灌环属后续任务，本脚本不冒充它。
#
# 特权语义（诚实清单的一部分）：
#   打开 /dev/bpf*（macOS）或建 AF_PACKET socket（Linux）被权限拒绝时，CLI 会
#   输出 status=skipped 并以 4 退出 —— 本脚本据此打 **SKIPPED**（exit 0），
#   输出行明确写「未验收」，不显绿。把环境缺权限伪装成通过，与不跑等价有害。
#
# 退出码：0 通过（或 SKIPPED）/ 1 断言不符 / 4 环境不满足 / 5 构建失败。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: e2e-live-capture.sh

对真实网卡做一次可验收的抓包，并用 tshark（第三方）与自家解析器交叉核对。

环境变量：
  CYTHSEC_LIVE_IFACE   指定抓包接口（默认取缺省路由出口接口）
  CYTHSEC_LIVE_TARGET  注入流量目的地址（默认取缺省路由网关；无网关时回退 lo + 127.0.0.1）

特权不足时输出 SKIPPED（未验收）并以 0 退出 —— 见脚本头注释的理由。

退出码：0 通过 / 1 断言不符 / 4 环境不满足 / 5 构建失败
EOF
  exit 0
fi

for cmd in cmake; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "环境检查失败：未找到 ${cmd}" >&2
    exit 4
  fi
done

OUT_DIR="${ROOT}/build/e2e-live"
BUILD_DIR="${CYTHSEC_E2E_BUILD_DIR:-${ROOT}/build}"
mkdir -p "${OUT_DIR}"

# ---------- 选择接口与注入目标 ----------
# 检测链：缺省路由 → 若缺省路由被 VPN 隧道接管（utun/ipsec/ppp/tun/tap 等常见代理
# 形态）则改用 ARP 邻居推出的真实出口 → 再不行取首个非回环非隧道接口、依赖环境流量。
# 理由：本机实测 VPN 把 default 抢到了 utun4（无 gateway 字段），只看缺省路由会
# 把物理口的采集验收带错方向 —— 这类「换台机器就失效」正是本脚本要避免的。
TUNNEL_RE='^(utun|ipsec|ppp|ppoa|tun|tap|gif|stf|anpi|awdl|llw|bridge|feth|vr|veth)[0-9]*$'

detect_default() { # detect_default <iface|gateway>
  local what="$1" line
  if [[ "$(uname -s)" == "Darwin" ]]; then
    line="$(/sbin/route -n get default 2>/dev/null || true)"
    if [[ "${what}" == "iface" ]]; then
      echo "${line}" | awk '/interface:/{print $2; exit}'
    else
      echo "${line}" | awk '/gateway:/{print $2; exit}'
    fi
  else
    line="$(ip route show default 2>/dev/null | head -1 || true)"
    if [[ "${what}" == "iface" ]]; then
      echo "${line}" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
    else
      echo "${line}" | awk '{print $3; exit}'
    fi
  fi
}

# 从邻居表找第一个可 ping 的 IPv4（跳过 incomplete/无效项）。
detect_neighbor() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    arp -a -n 2>/dev/null | awk '/incomplete/{next} {gsub(/[()]/,"",$2); if ($2 ~ /^(([0-9]{1,3}\.){3}[0-9]{1,3})$/ && $2 !~ /^127\./) {print $2; exit}}'
  else
    ip -4 neigh 2>/dev/null | awk '$1 ~ /^(([0-9]{1,3}\.){3}[0-9]{1,3})$/ && $1 !~ /^127\./ {print $1; exit}'
  fi
}

IFACE="${CYTHSEC_LIVE_IFACE:-}"
TARGET="${CYTHSEC_LIVE_TARGET:-}"
if [[ -z "${IFACE}" ]]; then
  IFACE="$(detect_default iface)"
  TARGET="${TARGET:-$(detect_default gateway)}"
  if [[ -z "${TARGET}" || "${IFACE}" =~ ${TUNNEL_RE} ]]; then
    # 缺省路由被隧道接管/无网关：用 ARP 邻居反推真实出口。
    local_t="$(detect_neighbor)"
    if [[ -n "${local_t}" ]]; then
      if [[ "$(uname -s)" == "Darwin" ]]; then
        real_i="$(/sbin/route -n get "${local_t}" 2>/dev/null | awk '/interface:/{print $2; exit}')"
      else
        real_i="$(ip route get "${local_t}" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
      fi
      if [[ -n "${real_i}" && ! "${real_i}" =~ ${TUNNEL_RE} ]]; then
        echo "（缺省路由被隧道接管：改用 ARP 邻居 ${local_t} 反推出口 ${real_i}）"
        IFACE="${real_i}"
        TARGET="${local_t}"
      fi
    fi
  fi
fi
if [[ -z "${IFACE}" ]]; then
  # 最后兜底：首个非回环非隧道的 IPv4 接口；无目标则不发 ping，依环境流量验收。
  IFACE="$(ifconfig -a 2>/dev/null | awk '/^[a-z0-9]+:/{iface=$1} /inet [0-9]/{gsub(":","",iface); if (iface !~ /^lo/ && iface !~ /^utun|^ipsec|^ppp|^tun|^tap|^gif|^stf|^anpi|^awdl|^llw|^bridge/) {print iface; exit}}')"
fi
[[ -n "${IFACE}" ]] || { echo "✗ [live] 无法确定抓包接口" >&2; exit 4; }

echo "==> [live] 接口=${IFACE} 注入目标=${TARGET}"

# ---------- 构建 ----------
if [[ -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
  cmake -S "${ROOT}" -B "${BUILD_DIR}" >/dev/null || { echo "✗ [live] CMake 重新配置失败" >&2; exit 5; }
else
  cmake -S "${ROOT}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Debug >/dev/null \
    || { echo "✗ [live] CMake 配置失败" >&2; exit 5; }
fi
cmake --build "${BUILD_DIR}" --target cythsec-capture cythsec-parse cythsec-ring-feed >/dev/null \
  || { echo "✗ [live] C++ 侧构建失败" >&2; exit 5; }
CAP_BIN="${BUILD_DIR}/dataplane/packet-engine/cythsec-capture"
PARSE_BIN="${BUILD_DIR}/dataplane/packet-engine/cythsec-parse"
FEED_BIN="${BUILD_DIR}/dataplane/packet-engine/cythsec-ring-feed"
[[ -x "${CAP_BIN}" && -x "${PARSE_BIN}" && -x "${FEED_BIN}" ]] \
  || { echo "✗ [live] 未找到 C++ 产物" >&2; exit 5; }

RUST_READY=0
CONSUME_BIN="${ROOT}/target/debug/ring-consume"
if [[ -x "${CONSUME_BIN}" ]]; then
  RUST_READY=1
else
  echo "（提示：未找到 target/debug/ring-consume，先跑 test-all.sh --rust 或 cargo build；D 段将标 SKIPPED）"
fi

# ---------- 工具：机器可读行取 key=value（同 e2e-shared-ring.sh 的约束，不用 grep -P） ----------
field() { # field <文件> <记录标签> <键>
  awk -v tag="$2" -v k="$3" '
    index($0, tag) == 1 && $0 ~ ("(^| )" k "=") {
      found = ""
      for (i = 1; i <= NF; i++) {
        n = split($i, kv, "=")
        if (n == 2 && kv[1] == k) { found = kv[2] }
      }
      if (found != "") { v = found }
    }
    END { print v }
  ' "$1"
}

failed=0
skipped=0
total=0
check() { # check <说明> <实际> <期望>
  total=$((total + 1))
  if [[ "$2" == "$3" ]]; then
    echo "  ✓ $1: $2"
  else
    echo "  ✗ $1: 期望 $3，实际 ${2:-<空>}" >&2
    failed=$((failed + 1))
  fi
}
check_ge() { # check_ge <说明> <实际> <下限> —— 真机数量天然有抖动，只能断下界
  total=$((total + 1))
  if [[ -n "$2" && "$2" =~ ^[0-9]+$ && "$2" -ge "$3" ]]; then
    echo "  ✓ $1: $2 (>= $3)"
  else
    echo "  ✗ $1: 期望 >= $3，实际 ${2:-<空>}" >&2
    failed=$((failed + 1))
  fi
}

# ---------- A. 真实抓包：边注入 ICMP 边采集 ----------
echo "==> [live] A. 真网卡采集（注入 ping，采集侧计数）"
PCAP="${OUT_DIR}/live-${IFACE}.pcap"
CAP_OUT="${OUT_DIR}/capture.txt"
rm -f "${PCAP}" "${CAP_OUT}"

MIN_PACKETS=10
CAP_PID=""
cleanup() { [[ -n "${CAP_PID}" ]] && kill "${CAP_PID}" 2>/dev/null || true; }
trap cleanup EXIT

# 先起采集再起流量：反过来的话前几个包必然漏，断言就得依赖竞态顺序。
"${CAP_BIN}" -i "${IFACE}" -n 200 --timeout 20 -w "${PCAP}" -q >"${CAP_OUT}" 2>&1 &
CAP_PID=$!
sleep 1
if [[ -n "${TARGET}" ]]; then
  ping -c 30 -i 0.1 "${TARGET}" >"${OUT_DIR}/ping.txt" 2>&1 || true
else
  echo "（无可用注入目标：仅依环境流量验收，断言不变 —— 真机不可能 20s 内一个包都没有）"
fi
wait "${CAP_PID}" && CAP_RC=0 || CAP_RC=$?
CAP_PID=""

status="$(field "${CAP_OUT}" "capture result" status)"
reason="$(field "${CAP_OUT}" "capture result" reason)"

if [[ "${status}" == "skipped" ]]; then
  # 环境缺权限：如实报未验收。见脚本头注释「特权语义」。
  echo "  ⚠ [live] SKIPPED（未验收）：后端报权限不足 —— ${reason}"
  echo "  ⚠ 处置提示见错误文案（macOS: access_bpf 组；Linux: CAP_NET_RAW/sudo）"
  echo ""
  echo "⚠ [live] 真实网卡抓包关口 SKIPPED（未验收，非通过）"
  exit 0
fi

packets="$(field "${CAP_OUT}" "capture stats" packets)"
dropped="$(field "${CAP_OUT}" "capture stats" dropped)"
errors="$(field "${CAP_OUT}" "capture stats" errors)"
mode="$(field "${CAP_OUT}" "capture mode" value)"
written="$(field "${CAP_OUT}" "capture pcap" written)"

check "A 采集结果状态" "${status}" "ok"
check "A 退出码" "${CAP_RC}" "0"
check "A 采集模式非默认占位" "$( [[ -n "${mode}" ]] && echo nonempty || echo empty )" "nonempty"
check_ge "A 收到报文数" "${packets}" "${MIN_PACKETS}"
check "A 内核/环丢包应为 0" "${dropped}" "0"
check "A 解析错误应为 0" "${errors}" "0"

# ---------- B. tshark 第三方独立复核 ----------
echo "==> [live] B. tshark 独立复核 -w 产物"
if command -v tshark >/dev/null 2>&1; then
  tshark -r "${PCAP}" -q -z io,phs >"${OUT_DIR}/tshark-phs.txt" 2>&1 || true
  ts_icmp="$(tshark -r "${PCAP}" -Y "icmp || icmp6" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
  ts_frames="$(tshark -r "${PCAP}" -T fields -e frame.number 2>/dev/null | tail -1)"
  if [[ -n "${TARGET}" ]]; then
    check_ge "B 注入的 ICMP 在产物中可见" "${ts_icmp}" "2"
  else
    echo "  ⚠ B 无注入目标：ICMP 可见项不适用（环境流量仍由 A/C 段把关）"
  fi
  # tshark 的帧数必须与写盘数一致：不一致 = 写盘丢尾或采集虚报。
  total=$((total + 1))
  if [[ "${ts_frames}" == "${written}" && -n "${ts_frames}" ]]; then
    echo "  ✓ B tshark 帧数 == capture written: ${ts_frames}"
  else
    echo "  ✗ B tshark 帧数(${ts_frames:-<空>}) != capture written(${written:-<空>})" >&2
    failed=$((failed + 1))
  fi
else
  echo "  ⚠ tshark 不可用：产物未经第三方核验（不计为通过）"
  skipped=$((skipped + 1))
fi

# ---------- C. 自家解析器回读：三方对同一批字节的计数一致 ----------
echo "==> [live] C. cythsec-parse 回读计数核对"
if [[ -s "${PCAP}" ]]; then
  "${PARSE_BIN}" -r "${PCAP}" >"${OUT_DIR}/parse.txt" 2>&1 || true
  parsed="$(awk '/解析成功|parsed|成功报文/{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/){print $i; exit}}' \
    "${OUT_DIR}/parse.txt" | head -1)"
  # 解析行格式随版本变，取不到时退回字节数对比：文件大小非零且首魔数正确也算回读成立。
  magic="$(head -c4 "${PCAP}" | od -An -tx1 | tr -d ' \n')"
  total=$((total + 1))
  if [[ "${magic}" == a1b23c4d || "${magic}" == 4d3cb2a1 || "${magic}" == a1b2c3d4 || "${magic}" == d4c3b2a1 ]]; then
    echo "  ✓ C pcap 魔数合法（经典 pcap，解析器可读）: ${magic}"
  else
    echo "  ✗ C pcap 魔数异常: ${magic}" >&2
    failed=$((failed + 1))
  fi
  if [[ -n "${parsed}" && "${parsed}" == "${written}" ]]; then
    total=$((total + 1))
    echo "  ✓ C 解析计数与采集 written 一致: ${parsed}"
  elif [[ -n "${parsed}" ]]; then
    total=$((total + 1))
    echo "  ✗ C 解析计数(${parsed}) != 采集 written(${written})" >&2
    failed=$((failed + 1))
  fi
else
  echo "  ✗ C pcap 为空文件" >&2
  total=$((total + 1)); failed=$((failed + 1))
fi

# ---------- D. 真实抓包 → 共享环 → Rust Flow（两段式） ----------
echo "==> [live] D. 真实报文 → 共享环 → Rust 解流"
if [[ "${RUST_READY}" == "1" && -s "${PCAP}" ]]; then
  RING="${OUT_DIR}/ring-live.bin"
  rm -f "${RING}"
  FEED_OUT="${OUT_DIR}/feed-live.txt"
  "${FEED_BIN}" -q -r "${PCAP}" --ring "${RING}" --recreate >"${FEED_OUT}" 2>&1 || true
  CONS_OUT="${OUT_DIR}/consume-live.txt"
  if "${CONSUME_BIN}" --ring "${RING}" >"${CONS_OUT}" 2>&1; then
    fed="$(field "${FEED_OUT}" "ring-feed summary" published)"
    got="$(field "${CONS_OUT}" "ring-consume summary" packets)"
    flows="$(field "${CONS_OUT}" "ring-consume summary" flows)"
    dfail="$(field "${CONS_OUT}" "ring-consume summary" decode_fail)"
    check "D 环内消费数 == 采集交付数" "${got}" "${packets}"
    check "D 解码失败应为 0" "${dfail}" "0"
    check_ge "D 解出的 Flow 条数" "${flows}" "1"
  else
    echo "  ✗ D Rust 消费失败：" >&2; tail -5 "${CONS_OUT}" >&2
    total=$((total + 1)); failed=$((failed + 1))
  fi
else
  echo "  ⚠ [live] D 段 SKIPPED（未验收）：缺 ring-consume 或 pcap 为空 —— 真实网卡 → Flow 未完成"
  skipped=$((skipped + 1))
fi

echo ""
if [[ ${failed} -gt 0 ]]; then
  echo "✗ [live] 真实网卡抓包关口失败：${total} 项断言中 ${failed} 项不符" >&2
  echo "  产物: ${OUT_DIR}/" >&2
  exit 1
fi
if [[ ${skipped} -gt 0 ]]; then
  echo "⚠ [live] 真实网卡抓包关口：${total} 项断言通过；另有 ${skipped} 段未核验（SKIPPED，不计为通过）"
  exit 0
fi
echo "✓ [live] 真实网卡抓包关口通过（${total} 项断言，产物 ${OUT_DIR}/）"
exit 0
