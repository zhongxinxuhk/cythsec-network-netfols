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
#      共享环，Rust 消费端解出 flow>=1，且**非 IP 帧的判定与第三方裁判（tshark）
#      一致**（不是断言 decode_fail=0：ARP/STP 这类帧解不出五元组是正确行为，
#      要验的是两个独立实现对「哪些帧不可解」看法相同；裁判的口径见 nonip_count）。
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
  CYTHSEC_LIVE_SUDO=1  仅捕获子进程使用 sudo -n；需先经用户批准并完成 sudo 认证

特权不足时输出 SKIPPED（未验收）并以 0 退出 —— 见脚本头注释的理由。

退出码：0 通过 / 1 断言不符 / 4 环境不满足 / 5 构建失败
EOF
  exit 0
fi

PYTHON="${PYTHON:-python3}"
for cmd in cmake "$PYTHON"; do
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

# 从邻居表找第一个可 ping 的 IPv4，且它必须落在「真以太网口」上：本机实测
# bridge100/101（虚拟化桥口）的 ARP 条目排在最前，不按所在接口过滤就会把
# 采集目标选到虚拟桥上。排除回环/隧道/桥接/虚拟化接口名后再取首个。
detect_neighbor() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    arp -a -n 2>/dev/null | awk '
      /incomplete/ {next}
      {
        gsub(/[()]/, "", $2)
        onif = ""
        for (i = 1; i <= NF; i++) { if ($i == "on") { onif = $(i+1); break } }
        if ($2 ~ /^(([0-9]{1,3}\.){3}[0-9]{1,3})$/ && $2 !~ /^127\./ &&
            onif != "" && onif !~ /^(lo|utun|anpi|awdl|llw|gif|stf|bridge|vmnet|pfh|feth)/) {
          print $2; exit
        }
      }'
  else
    ip -4 neigh 2>/dev/null | awk '
      $1 ~ /^(([0-9]{1,3}\.){3}[0-9]{1,3})$/ && $1 !~ /^127\./ &&
      ($3 == "REACHABLE" || $3 == "PERMANENT" || $4 == "REACHABLE" || $4 == "PERMANENT") {
        print $1; exit
      }'
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
  # 最后兜底：首个非回环非隧道非桥接非虚拟化、且持有 IPv4 的接口；无目标则不发 ping，
  # 依环境流量验收（链路类型仍由 A 段的 link_value 硬校验把关，非以太网会明确报错）。
  IFACE="$(ifconfig -a 2>/dev/null | awk '/^[a-z0-9]+:/{iface=$1} /inet [0-9]/{gsub(":","",iface); if (iface !~ /^(lo|utun|anpi|awdl|llw|gif|stf|bridge|vmnet|pfh|feth)/) {print iface; exit}}')"
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
# 第三方裁判：同一窗口内 tshark 判定的「非 IP 帧」数。
#
# 判据选择有过一次教训（2026-10-05，本机 en0 上实测）：**不能用 `-e eth.type`**。
# 网桥/交换机周期发的 STP BPDU 是 802.3 + LLC 帧（`eth:llc:stp`），用**长度字段**而非
# EtherType，于是 `eth.type` 输出空行；而旧写法 `awk 'NF {...}'` 的 `NF` 过滤会把这
# 些行**整行丢掉** → 裁判少数 6 帧，把「我们两个实现判 6、裁判判 0」报成不一致
# （真实情况是三者一致，只是裁判瞎了）。改用 `frame.protocols`：只要协议栈里没有
# ip/ipv6 就算非 IP —— 与解析器的口径（解不出五元组）一致，且对任何封装都成立。
# 「解不出五元组」的**完整**口径 = 三类之和，每一类都由 tshark 独立给出（不自己重算，避免自证）：
#
#   ① 非 IP 链路帧：协议栈里没有 ip/ipv6（ARP / LLDP / LLDP / 802.3+LLC 等）。
#   ② IPv4 非首片：`ip.frag_offset > 0`。端口在首片里，本解码器按设计**拒绝**
#      （`DecodeError::NonInitialFragment`）—— 而 tshark 的 `frame.protocols` 仍会写成
#      `eth:ethertype:ip`（它能看到的就那么层次）。**这一条是 2026-10-05 现场踩到的**：
#      抓包窗口里恰好有 2 个非首片分片，于是 `decode_fail=58` 而「非 IP」只有 56，
#      默认关口就这么假红了一次（`ring-consume decode_fail code=decode.non_initial_fragment count=2`）。
#   ③ IPv6 非首片：`ipv6.fraghdr.offset > 0`，同理。
#
# 教训（与 §7 那批坑同类）：**"两个独立实现的判定不一致"不等于"有一方错了"** ——
# 先把"按设计拒绝"的类别逐条枚举进裁判口径，再谈一致性；否则判据里藏着一个
# 依赖现场流量的隐藏变量，表现就是"偶尔红"。
undecodable_count() { # undecodable_count <pcap> <前缀窗口帧数>
  local nonip frag4 frag6
  nonip="$(tshark -r "$1" -c "$2" -T fields -e frame.protocols 2>/dev/null |
    awk 'NF { p=tolower($0); if (p !~ /(^|:)ip(:|$)/ && p !~ /(^|:)ipv6(:|$)/) c++ } END { print c+0 }')"
  # -c 先于 -Y 生效：取的是**同一前缀窗口**里的匹配帧数（与①同窗，才能相加）。
  frag4="$(tshark -r "$1" -c "$2" -Y 'ip.frag_offset > 0' 2>/dev/null | wc -l | tr -d ' ')"
  frag6="$(tshark -r "$1" -c "$2" -Y 'ipv6.fraghdr.offset > 0' 2>/dev/null | wc -l | tr -d ' ')"
  echo $((nonip + frag4 + frag6))
}

# 分项打印，便于不一致时归因（与 undecodable_count 用的是同一批 tshark 调用口径）。
undecodable_breakdown() { # undecodable_breakdown <pcap> <窗口>
  local nonip frag4 frag6
  nonip="$(tshark -r "$1" -c "$2" -T fields -e frame.protocols 2>/dev/null |
    awk 'NF { p=tolower($0); if (p !~ /(^|:)ip(:|$)/ && p !~ /(^|:)ipv6(:|$)/) c++ } END { print c+0 }')"
  frag4="$(tshark -r "$1" -c "$2" -Y 'ip.frag_offset > 0' 2>/dev/null | wc -l | tr -d ' ')"
  frag6="$(tshark -r "$1" -c "$2" -Y 'ipv6.fraghdr.offset > 0' 2>/dev/null | wc -l | tr -d ' ')"
  echo "非IP=${nonip} + IPv4非首片=${frag4} + IPv6非首片=${frag6}"
}

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

# 先起采集再起流量：反过来的话前几个包必然漏。
# 不设 -n 上限：本机实测繁忙口上环境流量 684ms 就能凑满 200 包，采集会在注入
# 开始前结束 —— 只靠 --timeout 窗口覆盖流量注入全程。包数天然有抖动，故断言下界。
CAP_CMD=("${CAP_BIN}")
if [[ "${CYTHSEC_LIVE_SUDO:-0}" == "1" ]]; then
  # 构建、第三方解码和共享环继续使用普通用户；只有打开 BPF 的子进程提权。
  # -n 禁止脚本内索取密码，认证由调用者在用户批准后单独完成。
  CAP_CMD=(sudo -n -- "${CAP_BIN}")
fi
"${CAP_CMD[@]}" -i "${IFACE}" --timeout 15 -w "${PCAP}" -q >"${CAP_OUT}" 2>&1 &
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
link_value="$(field "${CAP_OUT}" "capture iface" link_value)"
# 丢包如实报告但不硬断言 0：繁忙真机口上单消费者边写盘边收，内核缓冲必然有
# 溢出（本机实测 15s/62k 包环境流量下 bs_drop ~2.5%）；零丢包属于吞吐关口的
# 命题（Linux AF_PACKET bench），在这里只会把环境差异误报成代码缺陷。

# 链路类型硬校验：PcapWriter 的 -w 路径固定按 DLT_EN10MB 落盘（见 capture_main.cpp
# 注释），非以太网接口写出的 pcap 是错标的：tshark/解析器会按错误链路解包。
# 与其让 B/C 段拿错标文件做无意义对比，不如在这里明确拒绝并提示换口。
if [[ "${link_value}" != "1" ]]; then
  echo "✗ [live] 接口 ${IFACE} 链路类型为 ${link_value:-<空>}（非 EN10MB=1）："\
"当前 -w 只支持以太网落盘，请用 CYTHSEC_LIVE_IFACE 指定物理/以太网接口" >&2
  exit 4
fi

check "A 采集结果状态" "${status}" "ok"
check "A 退出码" "${CAP_RC}" "0"
check "A 采集模式非默认占位" "$( [[ -n "${mode}" ]] && echo nonempty || echo empty )" "nonempty"
check_ge "A 收到报文数" "${packets}" "${MIN_PACKETS}"
if [[ "${dropped:-0}" != "0" ]]; then
  echo "  ⚠ A 内核缓冲丢包 ${dropped}（繁忙口正常现象，吞吐命题由 Linux bench 把关）"
fi
check "A 解析错误应为 0" "${errors}" "0"

# ---------- B. tshark 第三方独立复核 ----------
echo "==> [live] B. tshark 独立复核 -w 产物"
if command -v tshark >/dev/null 2>&1; then
  tshark -r "${PCAP}" -q -z io,phs >"${OUT_DIR}/tshark-phs.txt" 2>&1 || true
  # 注意：Wireshark 4.x 的 ICMPv6 显示筛选器名是 **icmpv6**；写 icmp6 会让
  # 整个表达式报错退出，表现为「一条都没匹配」——本机实测踩到。
  ts_icmp="$(tshark -r "${PCAP}" -Y "icmp || icmpv6" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ' || true)"
  ts_frames="$(tshark -r "${PCAP}" -T fields -e frame.number 2>/dev/null | tail -1 || true)"
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
  magic="$(head -c4 "${PCAP}" | od -An -tx1 | tr -d ' \n')"
  total=$((total + 1))
  if [[ "${magic}" == a1b23c4d || "${magic}" == 4d3cb2a1 || "${magic}" == a1b2c3d4 || "${magic}" == d4c3b2a1 ]]; then
    echo "  ✓ C pcap 魔数合法（经典 pcap，解析器可读）: ${magic}"
  else
    echo "  ✗ C pcap 魔数异常: ${magic}" >&2
    failed=$((failed + 1))
  fi
  # All three parser outcomes must account for the independent capture count.
  # Rejected packets remain rejected; conservation does not certify protocol accuracy.
  total=$((total + 1))
  if "$PYTHON" scripts/verify/check-pcap-readback.py --summary "${OUT_DIR}/parse.txt" --expected "${written}"; then
    echo "  ✓ C 解析成功 + 不支持 + 解析失败 == written（失败类别未改写为成功）"
  else
    echo "  ✗ C 采集与回读结果计数不闭合" >&2
    failed=$((failed + 1))
  fi
  total=$((total + 1))
  if "$PYTHON" scripts/verify/check-pcap-readback.py --self-test --parser "$PARSE_BIN"; then
    echo "  ✓ C 完整回读自证（含非首片与 5 项计数注入）"
  else
    echo "  ✗ C 回读计数自证失败" >&2
    failed=$((failed + 1))
  fi
else
  echo "  ✗ C pcap 为空文件" >&2
  total=$((total + 1)); failed=$((failed + 1))
fi

# ---------- D 前置：裁判口径自证（两段，且第二段跑**完整判定链**） ----------
# 这段存在的理由本身就是教训：
#   ① `nonip_count` 曾用 `eth.type`，802.3/LLC 帧没有 EtherType → 空行被 awk 的 NF 丢掉 →
#      裁判少数若干帧。那种错法**只在网内有 STP 之类 LLC 帧时**才显形。
#   ② 现行口径曾**只数非 IP**，漏了"非首片分片"这一类 → 抓包窗口里出现 2 个非首片分片时
#      `decode_fail=58` vs 裁判 56，默认关口**在现场假红一次**（2026-10-05）。
# 两次都是同一个病根：**判据里藏了依赖现场流量的隐藏变量**，表现是"偶尔红/偶尔绿"。
# 所以自证不再只验"裁判会不会数错"，而是**每次都用合成语料跑一遍完整判定链**：
#   合成 3 帧（LLC/STP + IPv4 + IPv4 非首片）→ 灌共享环 → ring-consume 数 decode_fail，
#   要求它 == undecodable_count() == 2。
# 这条自证对两类旧口径都会红：用 eth.type 会得 0；只数非 IP 会得 1。
if command -v python3 >/dev/null 2>&1 && command -v tshark >/dev/null 2>&1; then
  judge_dir="$(mktemp -d)"
  python3 - "${judge_dir}/mix.pcap" <<'PY'
import struct, sys
# 经典 pcap，3 帧：
#   ① 802.3/LLC/STP（用长度字段，无 EtherType）—— 旧 `eth.type` 口径在这里瞎。
#   ② Ethernet/IPv4（可解出五元组）。
#   ③ Ethernet/IPv4 **非首片**（frag_offset=185，MF=0）：tshark 的 frame.protocols 仍是
#      `eth:ethertype:ip`（它只能看到那么多层），但端口在首片里 → 本解码器按设计拒绝。
llc = bytes.fromhex("0180c2000000") + bytes.fromhex("001122334455") + struct.pack(">H", 0x0026) \
    + b"\x42\x42\x03" + b"\x00" * 35
eth = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + b"\x08\x00"
ip = eth + bytes.fromhex("4500001c0001000040110000c0a80101c0a80102") + b"\x00" * 8
# 非首片：IHL=5、total_length=28、id=1、frag 字段 = 185*8 = 1480 = 0x05C8（MF=0）、TTL=64、proto=17。
# 布局必须逐字节对齐（v4/IHL → tos → total_len → id → flags+frag → ttl → proto → csum → 地址），
# 少写/多写一个字节就会把 frag 字段顶偏 —— 本夹第一次就写错了，靠上面「裁判必须判 2」才抓到。
frag = eth + bytes.fromhex("4500001c000105c840110000c0a80101c0a80102") + b"\x00" * 8
out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
for f in (llc, ip, frag):
    out += struct.pack("<IIII", 0, 0, len(f), len(f)) + f
open(sys.argv[1], "wb").write(out)
PY
  judge_n="$(undecodable_count "${judge_dir}/mix.pcap" 3 || true)"
  judge_detail="$(undecodable_breakdown "${judge_dir}/mix.pcap" 3 || true)"
  total=$((total + 1))
  if [[ "${judge_n}" == "2" ]]; then
    echo "  ✓ D 裁判口径自证：合成 3 帧（LLC/STP + IPv4 + IPv4非首片）判「解不出五元组」= 2（${judge_detail}）"
  else
    echo "  ✗ D 裁判口径自证失败：合成样本应判 2，实际 ${judge_n:-<空>}（${judge_detail}；用 eth.type 会得 0，只数非 IP 会得 1）" >&2
    failed=$((failed + 1))
  fi

  # 第二段：同一份合成语料跑**完整判定链**（灌环 → 消费 → decode_fail），
  # 证明"裁判口径"与"我们解码器按设计拒绝的集合"在这三类上一致 —— 不靠现场流量碰运气。
  if [[ "${RUST_READY}" == "1" && -x "${FEED_BIN}" ]]; then
    jring="${judge_dir}/ring-judge.bin"
    if "${FEED_BIN}" -q -r "${judge_dir}/mix.pcap" --ring "${jring}" --recreate --limit 3 \
         >"${judge_dir}/feed.txt" 2>&1 &&
       "${CONSUME_BIN}" --ring "${jring}" >"${judge_dir}/cons.txt" 2>&1; then
      jfail="$(field "${judge_dir}/cons.txt" "ring-consume summary" decode_fail)"
      total=$((total + 1))
      if [[ "${jfail}" == "${judge_n}" ]]; then
        echo "  ✓ D 完整判定链自证：合成 3 帧 → decode_fail=${jfail} == 裁判口径 ${judge_n}"
      else
        echo "  ✗ D 完整判定链自证失败：decode_fail=${jfail:-<空>} != 裁判口径 ${judge_n:-<空>}" >&2
        grep -E '^ring-consume decode_fail code=' "${judge_dir}/cons.txt" | sed 's/^/    /' >&2 || true
        failed=$((failed + 1))
      fi
    else
      echo "  ⚠ D 完整判定链自证未核验：环工具未能运行（不计为通过）"
      skipped=$((skipped + 1))
    fi
  fi
  rm -rf "${judge_dir}"
else
  echo "  ⚠ 缺 python3 或 tshark：裁判口径自证未核验（不计为通过）"
fi

# ---------- D. 真实抓包 → 共享环 → Rust Flow（两段式） ----------
echo "==> [live] D. 真实报文 → 共享环 → Rust 解流"
if [[ "${RUST_READY}" == "1" && -s "${PCAP}" ]]; then
  RING="${OUT_DIR}/ring-live.bin"
  rm -f "${RING}"
  FEED_OUT="${OUT_DIR}/feed-live.txt"
  CONS_OUT="${OUT_DIR}/consume-live.txt"
  # 环容量 1024：全量灌入时后段必然被丢（环满属正确行为，不是验收项）。
  # 取前缀窗口 LIMIT 条，把「消费数、非 IP 帧判定」放在同一窗口内对账。
  LIMIT=500
  if [[ "${packets:-0}" -lt "${LIMIT}" ]]; then
    LIMIT="${packets}"
  fi
  "${FEED_BIN}" -q -r "${PCAP}" --ring "${RING}" --recreate --limit "${LIMIT}" >"${FEED_OUT}" 2>&1 || true
  if "${CONSUME_BIN}" --ring "${RING}" >"${CONS_OUT}" 2>&1; then
    fed="$(field "${FEED_OUT}" "ring-feed summary" published)"
    got="$(field "${CONS_OUT}" "ring-consume summary" packets)"
    flows="$(field "${CONS_OUT}" "ring-consume summary" flows)"
    dfail="$(field "${CONS_OUT}" "ring-consume summary" decode_fail)"
    check "D 灌入数 == 前缀窗口" "${fed}" "${LIMIT}"
    check "D 环内消费数 == 灌入数" "${got}" "${fed}"
    check_ge "D 解出的 Flow 条数" "${flows}" "1"
    # 解不出五元组是**正确行为**，不断言 dfail=0；要验的是两个独立实现（Rust 解码器 /
    # tshark 裁判）对「哪些帧解不出五元组」的判定一致。裁判口径见 undecodable_count()：
    # 非 IP + IPv4 非首片 + IPv6 非首片（三类都是"按设计拒绝"，不是 bug）。
    if command -v tshark >/dev/null 2>&1 && [[ "${LIMIT}" != "0" ]]; then
      prefix_bad="$(undecodable_count "${PCAP}" "${LIMIT}" || true)"
      if [[ "${dfail}" != "${prefix_bad}" ]]; then
        # 不一致要能一眼归因：把三方计数、裁判分项与错误码明细都摊开，而不是只报一个数。
        echo "  · 归因：Rust decode_fail=${dfail} / tshark 不可解=${prefix_bad}（$(undecodable_breakdown "${PCAP}" "${LIMIT}")） / C++ 分类结果见 C 段摘要" >&2
        grep -E '^ring-consume decode_fail code=' "${CONS_OUT}" | sed 's/^/    /' >&2 || true
      fi
      check "D Rust decode_fail == tshark 前缀「解不出五元组」帧数（两实现判定一致）" "${dfail}" "${prefix_bad}"
    else
      echo "  ⚠ 无 tshark：decode_fail 一致性项未核验（不计为通过）"
    fi
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
