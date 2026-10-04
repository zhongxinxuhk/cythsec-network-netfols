#!/usr/bin/env bash
# e2e-shared-ring.sh —— 跨语言共享环端到端关口（CYS-TRF-034）。
#
# 用法：
#   bash scripts/verify/e2e-shared-ring.sh          # 跑完整跨语言端到端
#   bash scripts/verify/e2e-shared-ring.sh --help
#
# 链路（这两个进程是两个语言写的、只通过一块 mmap 文件通信）：
#   C++ cythsec-ring-feed  ──写──▶  共享区域文件  ──读──▶  Rust ring-consume
#                      真实 pcap                                解成 FlowKey 并聚合
#
# 验证的不变量（每一条都对应一类「各自单测都过、连起来就错」的失效）：
#   A. 基线：C++ 灌 5 个真实报文 -> Rust 消费到 5 个、解出 5 条流、零解码失败。
#      这是「两端对同一块内存的理解一致」的最直接证据。
#   B. 消费端记账可见性：紧接着再消费一次应为 0 条。
#      若 Rust 侧的 tail 写落不到共享内存（或内存序错），第二次会重复读到全部报文 ——
#      而单看第一次的输出完全正常。
#   C. 反向 attach：C++ 侧不重建区域、以 attach 方式打开同一个环并追加 5 个报文。
#      这是「C++ 能挂到 Rust 已推进过 tail 的环上」的证明，也覆盖 attach_expect 路径。
#   D. 显式跳过：--from-head 应消费 0 条（证明该模式本身没坏，即它是「选了才跳」而非「总是跳」）。
#
# 为什么不能只靠两端各自的单测：
#   Rust 侧 tests.rs 里的 TestProducer 与 C++ 侧 test_channel_producer.cpp 都是**各自语言内**
#   对契约的复刻。两份复刻都正确，仍可能双双偏离真实对端 —— 只有真的让 C++ 进程写、Rust 进程读，
#   才能把「两端各自以为的契约」与「它们之间实际的契约」区分开。
#
# 退出码：0 通过 / 1 断言不符 / 4 环境不满足 / 5 构建失败。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: e2e-shared-ring.sh

跑 C++ 生产端 -> 共享环 -> Rust 消费端 的跨语言端到端验证。

覆盖四个不变量：基线吞吐与解码、消费端记账可见性、C++ 反向 attach 已推进的环、
--from-head 显式跳过。详见脚本头注释。

产物（dump 与摘要）留在 build/e2e/ 下，失败时可直接查看。

退出码：0 通过 / 1 断言不符 / 4 缺工具链 / 5 构建失败
EOF
  exit 0
fi

for cmd in cargo cmake; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "环境检查失败：未找到 ${cmd}" >&2
    exit 4
  fi
done

OUT_DIR="${ROOT}/build/e2e"
BUILD_DIR="${CYTHSEC_E2E_BUILD_DIR:-${ROOT}/build}"
RING="${OUT_DIR}/ring.bin"
mkdir -p "${OUT_DIR}"

# 真实样本（datasets/pcap/ 由 datasets/generate-samples.py 生成，已入库）。
SAMPLES=()
for f in "${ROOT}"/datasets/pcap/*.pcap; do
  [[ -f "$f" ]] && SAMPLES+=("$f")
done
if [[ ${#SAMPLES[@]} -eq 0 ]]; then
  echo "✗ [e2e] 未找到 datasets/pcap/*.pcap 样本" >&2
  exit 4
fi
SAMPLE_ARGS=()
for f in "${SAMPLES[@]}"; do
  SAMPLE_ARGS+=("-r" "$f")
done

# ---------- 构建两端 ----------
echo "==> [e2e] 构建 Rust 侧 ring-consume"
RUST_LOG="${OUT_DIR}/cargo.log"
if ! cargo build --offline --quiet \
  --manifest-path "${ROOT}/dataplane/traffic-engine/Cargo.toml" \
  --bin ring-consume 2>"${RUST_LOG}"; then
  echo "✗ [e2e] Rust 侧 ring-consume 构建失败（日志 ${RUST_LOG}）" >&2
  tail -20 "${RUST_LOG}" >&2
  exit 5
fi
CONSUME_BIN="${ROOT}/target/debug/ring-consume"
[[ -x "${CONSUME_BIN}" ]] || CONSUME_BIN="${ROOT}/dataplane/traffic-engine/target/debug/ring-consume"
if [[ ! -x "${CONSUME_BIN}" ]]; then
  echo "✗ [e2e] 未找到 ring-consume 可执行文件" >&2
  exit 5
fi

echo "==> [e2e] 构建 C++ 侧 cythsec-ring-feed"
# 显式重新配置：新增目标在旧构建系统里不存在，直接 make 会以 "No rule to make target"
# 失败，而那句话指不到「配置过期」这个真实原因。cmake -S -B 幂等。
if [[ -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
  cmake -S "${ROOT}" -B "${BUILD_DIR}" >/dev/null || { echo "✗ [e2e] CMake 重新配置失败" >&2; exit 5; }
else
  cmake -S "${ROOT}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Debug >/dev/null \
    || { echo "✗ [e2e] CMake 配置失败" >&2; exit 5; }
fi
cmake --build "${BUILD_DIR}" --target cythsec-ring-feed >/dev/null \
  || { echo "✗ [e2e] C++ 侧 cythsec-ring-feed 构建失败" >&2; exit 5; }
FEED_BIN="${BUILD_DIR}/dataplane/packet-engine/cythsec-ring-feed"
[[ -x "${FEED_BIN}" ]] || { echo "✗ [e2e] 未找到 ${FEED_BIN}" >&2; exit 5; }

# ---------- 工具：从机器可读行里取 key=value ----------
# 不用 grep -oP（macOS 自带 BSD grep 无 -P）。awk 先按二级标签定位唯一一类记录，
# 再在该行内按空格切分精确匹配 `key=` —— 两个条件都必要：
#   - 只按 `key=` 匹配会跨记录取错值（逐流行里也有 `packets=`）；
#   - 只按标签匹配则同一行里多个键无法区分。
# 匹配用 `(^| )` 前缀，避免 `packets=` 被 `expect_packets=` 这类后缀名误命中。
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
# 断言总数动态累计，不写死在末行汇总里：写死的数字会在增删断言时悄悄失真，
# 而「验证覆盖了 N 项」正是读汇总的人据以判断充分性的依据。
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

# 「两者应相等」不能复用 check：check 的语义是「实际 vs 一个既定期望值」，
# 而这类断言两侧都是待核对的数据，套进去会把输出说反（"期望 10，实际 5"）。
# 断言描述里带上两侧标签，使输出不需要回看脚本才能读懂。
check_same() { # check_same <说明> <标签A> <值A> <标签B> <值B>
  total=$((total + 1))
  if [[ "$3" == "$5" ]]; then
    echo "  ✓ $1: $3"
  else
    echo "  ✗ $1: $2=$3 与 $4=$5 不一致" >&2
    failed=$((failed + 1))
  fi
}

# ---------- A. 基线：C++ 写 -> Rust 读 ----------
echo "==> [e2e] A. 基线：C++ 灌入真实 pcap，Rust 消费并解流"
rm -f "${RING}"
FEED_A="${OUT_DIR}/feed-a.txt"
"${FEED_BIN}" -q "${SAMPLE_ARGS[@]}" --ring "${RING}" --recreate >"${FEED_A}"
CONS_A="${OUT_DIR}/consume-a.txt"
if ! "${CONSUME_BIN}" --ring "${RING}" >"${CONS_A}" 2>&1; then
  echo "✗ [e2e] A 阶段 Rust 消费失败：" >&2
  tail -20 "${CONS_A}" >&2
  exit 1
fi

fed_a="$(field "${FEED_A}" "ring-feed summary" published)"
got_a="$(field "${CONS_A}" "ring-consume summary" packets)"
flows_a="$(field "${CONS_A}" "ring-consume summary" flows)"
fail_a="$(field "${CONS_A}" "ring-consume summary" decode_fail)"

# 期望值由**源数据**决定，不由实现决定。当前样本集（datasets/pcap/*.pcap）：
#   sample-ipv4-mixed.pcap   4 个报文 / 4 条方向级五元组
#   sample-ipv6-tcp.pcap     1 个报文 / 1 条
#   sample-session-tcp.pcap 18 个报文 / 9 条新增方向级五元组（其中 1 个是非首片分片，
#                           解不出五元组，必须显式计入解码失败而不是悄悄消失）
# 注意 session 样本的 ICMP 与 mixed 样本的 ICMP 是**同一个五元组**（同 IP、端口均 0、
# 同协议），因此两条样本合计只有 1 条 ICMP 正向流 —— 14 = 4 + 1 + 9 正是这样来的。
#
# 【这组数字是"活的"】2026-10-04 新增 sample-session-tcp.pcap 后，下面这些断言如期
# 报红（5 → 23），说明它们真的在被数据检验。改样本集时必须同步更新，并保持上面这种
# 可逐项复核的分解注释 —— 直接改数字而不写清来源，下一次就没人知道该不该改。
EXPECTED_FRAMES=23       # 4 + 1 + 18
EXPECTED_FLOWS=14        # 4 + 1 + 9
EXPECTED_DECODE_FAIL=1   # session 样本里的非首片分片
EXPECTED_FRAMES_2X=$((EXPECTED_FRAMES * 2))
check "A 生产端发布数" "${fed_a}" "${EXPECTED_FRAMES}"
check "A 消费端收到数" "${got_a}" "${EXPECTED_FRAMES}"
check "A 解出的流条数" "${flows_a}" "${EXPECTED_FLOWS}"
check "A 解码失败数" "${fail_a}" "${EXPECTED_DECODE_FAIL}"
check_same "A 端到端记账一致" "生产端 published" "${fed_a}" "消费端 packets" "${got_a}"

# 区域共享计数与两端各自记账的交叉核对。这一组断言的理由是一次实测：往生产端注入
# 「published 双计」后，上面 5 条断言**全部通过** —— 因为两个 CLI 各自报的都是本地计数，
# 谁都没有去读区域内实际落下的计数。而那正是运维排障时唯一能看的字段。
fed_region_pub="$(field "${FEED_A}" "ring-feed region" published)"
check_same "A 生产端本地记账与区域计数一致" "本地 published" "${fed_a}" "区域 published" "${fed_region_pub}"
cons_region_pub="$(field "${CONS_A}" "ring-consume region" published)"
cons_region_con="$(field "${CONS_A}" "ring-consume region" consumed)"
cons_region_tail="$(field "${CONS_A}" "ring-consume region" tail)"
check "A 区域 published（Rust 侧读到）" "${cons_region_pub}" "${EXPECTED_FRAMES}"
check "A 区域 consumed（Rust 侧写入）" "${cons_region_con}" "${EXPECTED_FRAMES}"
check "A 区域 tail（Rust 侧写入）" "${cons_region_tail}" "${EXPECTED_FRAMES}"
check_same "A 区域 head 两端读数一致" "C++ 侧" "$(field "${FEED_A}" "ring-feed region" head)" \
  "Rust 侧" "$(field "${CONS_A}" "ring-consume region" head)"
check "A 区域 dropped 应为 0" "$(field "${CONS_A}" "ring-consume region" dropped)" "0"
check "A 区域 full_events 应为 0" "$(field "${CONS_A}" "ring-consume region" full_events)" "0"

# ---------- B. 消费端记账可见性 ----------
echo "==> [e2e] B. 再消费一次应为 0 条（tail 已落盘且对新建映射可见）"
CONS_B="${OUT_DIR}/consume-b.txt"
"${CONSUME_BIN}" --ring "${RING}" >"${CONS_B}" 2>&1 || true
got_b="$(field "${CONS_B}" "ring-consume summary" packets)"
check "B 重复消费条数" "${got_b}" "0"

# ---------- C. 反向 attach：C++ 挂到 Rust 已推进 tail 的环上 ----------
echo "==> [e2e] C. C++ 以 attach 方式追加（不重建区域）"
FEED_C="${OUT_DIR}/feed-c.txt"
if ! "${FEED_BIN}" -q "${SAMPLE_ARGS[@]}" --ring "${RING}" >"${FEED_C}" 2>&1; then
  echo "✗ [e2e] C 阶段 C++ attach 既有环失败：" >&2
  tail -20 "${FEED_C}" >&2
  exit 1
fi
head_c="$(field "${FEED_C}" "ring-feed summary" head)"
check "C 追加后 head" "${head_c}" "${EXPECTED_FRAMES_2X}"
# 第二轮灌入前，区域内 consumed 应仍停在上一轮 Rust 消费完的位置：这是「Rust 写的计数
# 对后来 attach 的 C++ 进程可见」的证据，也是「两端对同一块内存的记账一致」的直接检验。
check "C 区域 published（C++ 侧读到）" "$(field "${FEED_C}" "ring-feed region" published)" "${EXPECTED_FRAMES_2X}"
check "C 区域 consumed（Rust 上轮写入）" "$(field "${FEED_C}" "ring-feed region" consumed)" "${EXPECTED_FRAMES}"
CONS_C="${OUT_DIR}/consume-c.txt"
"${CONSUME_BIN}" --ring "${RING}" >"${CONS_C}" 2>&1 || true
got_c="$(field "${CONS_C}" "ring-consume summary" packets)"
check "C 续读到的报数（=第二轮灌入量）" "${got_c}" "${EXPECTED_FRAMES}"
check "C 第二轮后区域 consumed" "$(field "${CONS_C}" "ring-consume region" consumed)" "${EXPECTED_FRAMES_2X}"

# ---------- D. 显式跳过积压 ----------
echo "==> [e2e] D. --from-head 应跳过积压、消费 0 条"
CONS_D="${OUT_DIR}/consume-d.txt"
"${CONSUME_BIN}" --ring "${RING}" --from-head >"${CONS_D}" 2>&1 || true
got_d="$(field "${CONS_D}" "ring-consume summary" packets)"
check "D from-head 消费条数" "${got_d}" "0"

echo ""
if [[ ${failed} -eq 0 ]]; then
  echo "✓ [e2e] 跨语言共享环端到端通过（4 阶段 / ${total} 项断言）"
  echo "  产物: ${OUT_DIR}/"
  exit 0
fi
echo "✗ [e2e] 跨语言共享环端到端失败：${total} 项断言中 ${failed} 项不符" >&2
echo "  产物: ${OUT_DIR}/（feed-*.txt / consume-*.txt）" >&2
exit 1
