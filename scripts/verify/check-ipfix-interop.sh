#!/usr/bin/env bash
# check-ipfix-interop.sh —— **异厂导出器**互操作关口（CYS-TRF-054 未达成项 ④ 的离线替代）。
#
# 为什么必须有这一道（仓库自己的两个 IPFIX 关口挡不住的部分）：
#   · check-ipfix-export.sh：我们的编码器 vs tshark —— 挡"发出去的字节不合法"；
#   · check-ipfix-collect.sh：我们的编码器 → 我们的采集器 —— 挡"回路不一致"，
#     但两边**共用 `src/ipfix/mod.rs` 的同一份模板定义**：定义本身读错 RFC 时，
#     两边会一起错、并且互相验证通过。
# 本关口引入一个只读 RFC 写出来的**独立实现**（scripts/verify/interop-ipfix.py，
# 不 import、不复制仓库任何常量），在每一个"约定俗成"的地方故意与仓库实现不同：
# 模板 ID 4001~4004（仓库用 256/257）、字段顺序相反、观测域 0x1234ABCD（仓库用 0）、
# 计数器走**缩减长度编码**（RFC 7011 §6.2）、夹带**未登记 IE**（9999/12345）、
# 发 options template set、发模板撤回（§8.1/§8.4）、同号不同定义重定义、
# 模板到达之前先发数据、以及插入 2 字节零填充。
#
# 三个方向都验：
#   ① 我们的采集器能解异厂报文（逐条对手写常量，不是对脚本自己算的值）；
#   ② tshark 独立确认这些报文**本身是合法 IPFIX**（否则"我们解出来了"可能只是
#      "两个实现一起读错了同一个非标格式"）；
#   ③ 判定自身能被反向注入判死（换语料 / 篡改统计行 / 篡改记录 / 多删一个 datagram）。
#
# 用法: check-ipfix-interop.sh [--no-self-test]
# 只读操作：产物落在 /tmp 或 build/。退出码：0 通过；1 不一致；2 参数/构建错误；3 缺工具。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

PY="${PYTHON:-python3}"
SELF_TEST=1
SCENARIOS=(standard reduced64 v6 foreign gap)
TSHARK_CASES=(standard foreign)   # tshark 独立确认：常规模板 + 夹带未登记 IE/撤回/重定义的那份

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-self-test) SELF_TEST=0 ;;
    -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
  shift
done

if ! command -v "${PY}" >/dev/null 2>&1; then
  echo "✗ [ipfix-interop] 缺少 ${PY}" >&2
  exit 3
fi
if ! command -v tshark >/dev/null 2>&1; then
  echo "⚠ [ipfix-interop] 缺 tshark：**未核验**（异厂报文的合法性没有被第三方确认）" >&2
  exit 3
fi

COLLECT="${ROOT}/target/debug/cythsec-ipfix-collect"
[[ -x "${COLLECT}" ]] || { echo "✗ [ipfix-interop] 找不到 ${COLLECT}（先 cargo build）" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
INTEROP="${ROOT}/scripts/verify/interop-ipfix.py"

echo "==> [ipfix-interop] 造异厂导出产物（独立实现，模板 ID/字段序/长度/观测域都与仓库实现不同）"
for sc in "${SCENARIOS[@]}"; do
  extra=""
  [[ "${sc}" == "gap" ]] && extra="--drop 2"   # gap 场景：删掉中间那个 datagram
  # shellcheck disable=SC2086
  "${PY}" "${INTEROP}" emit "${sc}" "${WORK}/${sc}.pcap" ${extra} | sed 's/^/  /'
done

echo "==> [ipfix-interop] 我们的采集器解异厂报文（逐条对手写常量）"
rc=0
for sc in "${SCENARIOS[@]}"; do
  "${COLLECT}" --pcap "${WORK}/${sc}.pcap" -o "${WORK}/${sc}.jsonl" >"${WORK}/${sc}.out" 2>&1 || {
    echo "✗ [ipfix-interop] 采集器处理 ${sc} 失败" >&2; cat "${WORK}/${sc}.out" >&2; exit 1; }
  "${PY}" "${INTEROP}" assert "${sc}" "${WORK}/${sc}.out" "${WORK}/${sc}.jsonl" || rc=1
done
[[ ${rc} -eq 0 ]] || { echo "✗ [ipfix-interop] 至少一个场景未通过" >&2; exit 1; }

echo "==> [ipfix-interop] tshark 独立确认异厂报文本身是合法 IPFIX（第三实现）"
# 说明：tshark 的 NetFlow/IPFIX 解析器叫 **cflow**（字段前缀 `cflow.`），不是 `ipfix`。
# 这里只看"我们发出的那份字节是否合法、是否被解成我们声称的模板 ID"，
# 字段值比对是正向关口的事。要挡的是"我们和采集器一起读错了同一个非标格式"。
for sc in "${TSHARK_CASES[@]}"; do
  fields="$(tshark -r "${WORK}/${sc}.pcap" -T fields -e cflow.version -e cflow.template_id 2>/dev/null || true)"
  if [[ -z "${fields}" ]]; then
    echo "✗ [ipfix-interop] tshark 解不出 ${sc} 的异厂报文 —— '独立实现'可能产出了非法 IPFIX" >&2
    exit 1
  fi
  versions="$(printf '%s\n' "${fields}" | awk -F'\t' '{print $1}' | sort -u | tr '\n' ' ')"
  if [[ "${versions// /}" != "10" ]]; then
    echo "✗ [ipfix-interop] ${sc}：tshark 读到的 IPFIX 版本是「${versions}」，应为 10" >&2
    exit 1
  fi
  tids="$(printf '%s\n' "${fields}" | awk -F'\t' '{print $2}' | tr ',' '\n' | grep -E '^[0-9]+$' | sort -un | tr '\n' ' ')"
  echo "  ✓ tshark：${sc} 每条报文 version=10；出现的 templateId=「${tids}」"
done
# 模板 ID 必须是**我们自己选的** 4001/4003（模板 ID 4001 证明语料与仓库编码器无关）
for pair in "standard:4001" "foreign:4003"; do
  sc="${pair%%:*}"; want="${pair##*:}"
  if ! tshark -r "${WORK}/${sc}.pcap" -T fields -e cflow.template_id 2>/dev/null | tr ',' '\n' | grep -qx "${want}"; then
    echo "✗ [ipfix-interop] tshark 没在 ${sc} 里看到模板 ${want}（异厂语料没被解成 IPFIX）" >&2
    exit 1
  fi
  echo "  ✓ tshark 解出模板 ${want}（${sc}）"
done
# 缩减长度编码（§6.2）的语义由**第三实现**确认：两种编码必须解出同一串 octets 值。
# 只看我们自己的采集器的话，"两边一起把 4 字节当 8 字节读"仍可能对不上但互相掩盖。
oct_std="$(tshark -r "${WORK}/standard.pcap" -T fields -e cflow.octets 2>/dev/null | tr -s '\n' ' ')"
oct_red="$(tshark -r "${WORK}/reduced64.pcap" -T fields -e cflow.octets 2>/dev/null | tr -s '\n' ' ')"
if [[ -z "${oct_std}" || "${oct_std}" != "${oct_red}" ]]; then
  echo "✗ [ipfix-interop] 缩减长度编码前后 tshark 解出的 octets 不一致：「${oct_std}」vs「${oct_red}」" >&2
  exit 1
fi
echo "  ✓ tshark：8 字节与 4 字节两种编码解出同一串 octets=「${oct_std%% }」（§6.2 语义一致）"

if [[ ${SELF_TEST} -eq 1 ]]; then
  echo "==> [ipfix-interop] 判定自身的反向注入（换语料 / 篡改统计 / 篡改记录 / 多删一个 datagram）"
  if ! "${PY}" "${INTEROP}" self-test --collector "${COLLECT}" --workdir "${WORK}/self"; then
    echo "✗ [ipfix-interop] 判定的反向注入未被检出（这条门禁本身不可信）" >&2
    exit 1
  fi
else
  echo "⚠ [ipfix-interop] 跳过反向注入（--no-self-test）—— 不得用于正式验收" >&2
fi

echo "✓ [ipfix-interop] 异厂导出器互操作通过（5 个场景逐条相符 + tshark 确认报文合法 + 判定经反向注入）"
exit 0
