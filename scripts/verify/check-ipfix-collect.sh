#!/usr/bin/env bash
# check-ipfix-collect.sh —— IPFIX 采集回路门禁（M11 / CYS-TRF-054）。
#
# ## 它守的是什么
#
# 导出器（`CYS-TRF-051/052`）只管"发得出去"，`check-ipfix-export.sh` 让 tshark 证明
# "别人能读懂"。但运营商口径里真正被考核的是**"对端收到多少、丢了多少"**，这个数只有
# 采集侧能算：RFC 7011 §3.1 的序列号 = 本报文之前已发送的**数据记录**累计数，
# §11.6 要求采集进程必须靠跟踪序号发现丢包。本脚本就守这条回路。
#
# ## 三道断言（都要能被证伪）
#
#   A. **完整回路**：同一份导出产物（pcap 通道）经采集器还原后，与导出侧的 JSONL
#      记录逐条相符（五元组/包数/字节数/时标/flowId）。这证明"解码器与编码器同源"。
#   B. **丢包必须被报出来且数值正确**：从 pcap 里删掉一个**中间** datagram（不是首尾 ——
#      丢尾部没有后续报文就没有基线，丢首部则基线本身缺失），采集器必须报
#      `gaps=1`、`lost_records=该 datagram 携带的记录数`，且 `loss_ppm` 与手算一致。
#      这是"导出丢包率"这个指标唯一可证伪的证明方式。
#   C. **完整回路的丢包数必须是 0**：如果采集器无论收到什么都报缺口，A 与 B 会同时"通过"
#      （B 的正向断言被恒真满足）。故必须有一条"没有注入时必须报 0"的反向断言。
#
# 另外校验口径诚实性：采集侧还原不出 TCP 状态/DPI 结论，必须如实写
# `tcp.state = null`、`app.outcome = "not_inspected"`，不许填占位值冒充"采集到了"。
#
# 用法：bash scripts/verify/check-ipfix-collect.sh [--no-self-test]
# 退出码：0 通过；1 断言失败；2 前置条件缺失；3 环境缺工具（未核验，不计通过）
set -uo pipefail

SELF_TEST=1
for arg in "$@"; do
  case "${arg}" in
    --no-self-test) SELF_TEST=0 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "未知参数：${arg}" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}" || exit 2

PY="${PY:-python3}"
CARGO="${CARGO:-cargo}"

for tool in "${CARGO}" "${PY}"; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "⚠ 缺少 ${tool}：本关口无法执行（未核验，不计为通过）" >&2
    exit 3
  fi
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cythsec-ipfix-collect.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

echo "==> 构建（debug）"
if ! "${CARGO}" build --offline -p traffic-engine --bin cythsec-analyze --bin cythsec-ipfix-collect \
     >"${WORK}/build.log" 2>&1; then
  echo "✗ 构建失败，见 ${WORK}/build.log" >&2
  tail -20 "${WORK}/build.log" >&2
  exit 1
fi
ANALYZE="${ROOT}/target/debug/cythsec-analyze"
COLLECT="${ROOT}/target/debug/cythsec-ipfix-collect"
for bin in "${ANALYZE}" "${COLLECT}"; do
  [[ -x "${bin}" ]] || { echo "✗ 构建产物缺失：${bin}" >&2; exit 1; }
done

# 样本（与导出关口同一批，便于两处结论互相对照）。
SAMPLE="${ROOT}/datasets/dpi/tls-vectors.pcap"
[[ -f "${SAMPLE}" ]] || { echo "✗ 样本缺失：${SAMPLE}（先跑 scripts/test/test-all.sh 生成向量）" >&2; exit 2; }

# 让一条报文只装得下 2 条记录、且每条报文都带模板 → 5 个 datagram（可删中间那个）。
MAX_MSG=201
REFRESH=1

echo "==> 阶段 A：导出 → 采集（完整回路，逐字段比对）"
"${ANALYZE}" -r "${SAMPLE}" -o "${WORK}/orig.jsonl" --ipfix-pcap "${WORK}/ipfix.pcap" \
  --ipfix-max-msg "${MAX_MSG}" --ipfix-template-refresh "${REFRESH}" --quiet \
  >"${WORK}/analyze.out" 2>&1 || { echo "✗ 导出失败" >&2; cat "${WORK}/analyze.out" >&2; exit 1; }

"${COLLECT}" --pcap "${WORK}/ipfix.pcap" -o "${WORK}/col.jsonl" \
  >"${WORK}/collect.out" 2>&1 || { echo "✗ 采集失败" >&2; cat "${WORK}/collect.out" >&2; exit 1; }

# 阶段 C 与 A 合并：完整回路的统计行必须自证"没有丢包"。
if ! grep -q "gaps=0 lost_records=0 loss_ppm=0" "${WORK}/collect.out"; then
  echo "✗ 完整回路不应报出任何缺口，实际统计行为：" >&2
  grep "cythsec-ipfix-collect" "${WORK}/collect.out" >&2
  exit 1
fi
echo "  ✓ 完整回路：gaps=0 lost_records=0 loss_ppm=0（无注入时必须报 0）"

if ! "${PY}" "${ROOT}/scripts/verify/check-ipfix-collect.py" roundtrip \
     "${WORK}/orig.jsonl" "${WORK}/col.jsonl"; then
  echo "✗ 完整回路的逐字段比对失败" >&2
  exit 1
fi

echo "==> 阶段 B：反向注入「删掉中间一个 datagram」→ 缺口与丢包率必须对得上"
if ! "${PY}" "${ROOT}/scripts/verify/check-ipfix-collect.py" drop-datagram \
     "${WORK}/ipfix.pcap" "${WORK}/gap.pcap" 1 >"${WORK}/inject.out" 2>&1; then
  echo "✗ 构造丢包产物失败" >&2
  cat "${WORK}/inject.out" >&2
  exit 1
fi
sed 's/^/  /' "${WORK}/inject.out"

"${COLLECT}" --pcap "${WORK}/gap.pcap" -o "${WORK}/gap.jsonl" \
  >"${WORK}/gap.out" 2>&1 || { echo "✗ 采集（缺口语料）失败" >&2; cat "${WORK}/gap.out" >&2; exit 1; }

if ! "${PY}" "${ROOT}/scripts/verify/check-ipfix-collect.py" assert-loss \
     "${WORK}/collect.out" "${WORK}/gap.out"; then
  echo "✗ 导出丢包率断言失败" >&2
  exit 1
fi

if [[ "${SELF_TEST}" -eq 1 ]]; then
  echo "==> 阶段 D：门禁自身的反向注入（判定逻辑不能被蒙过去）"
  if ! "${PY}" "${ROOT}/scripts/verify/check-ipfix-collect.py" self-test; then
    echo "✗ 判定的反向注入未被检出（这条门禁本身不可信）" >&2
    exit 1
  fi
fi

echo "✓ IPFIX 采集回路核验通过（回路逐字段相符 + 导出丢包率可证伪 + 判定自身经反向注入）"
exit 0
