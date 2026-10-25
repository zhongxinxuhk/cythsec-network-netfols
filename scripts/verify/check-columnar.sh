#!/usr/bin/env bash
# check-columnar.sh —— 列式落盘（ClickHouse `Native`）门禁（CYS-STO-002 / 007，CYS-TRF-033）。
#
# ## 它守的是什么
#
# 容量表里"列式能压到几十 B/记录"是整个规划里最后一个**未经实测**的假设。
# 假设本身由 `--columnar` 测量脚本负责给数字；本脚本守的是数字成立的前提：
# **我们写出去的字节，别人按公开格式规范能读对**。
#
# 这件事为什么必须单独有一个门禁：编码器与解码器都在同一个 crate 里，
# **两边一起写错时自测永远全绿**。2026-10-19 真实发生过一次——编码器把
# "全部列头集中写完再写数据"（规范是逐列交错），产物总字节与参考实现完全相同
# （2973），我们自己的 decode_blocks 照样解得出来，而 ClickHouse 拒绝读入。
#
# ## 四道断言
#
#   A. **生成物一致**：`storage/clickhouse/001_flows.sql` 必须由 `cythsec-dump-ddl`
#      逐字节复现（改 DDL 只能改代码，不能改文件——否则列契约与建表语句会分叉）。
#      并检查列清单里没有 `unknown:` 期望规则：新增派生列而忘了登记规则时，
#      表现必须是**判红**，不是"这一列静静不比对"。
#   B. **独立解码 + 逐格比对**：`scripts/verify/check-columnar.py` 按格式规范
#      独立实现（不 import 仓库常量），把真实向量产物解成格子，与同源 JSONL
#      逐格对照 56 列（记录契约 v2；v1 时 50 列）—— 含 NULL 必须对 NULL（`risk_score` 未评分
#      绝不能被读成 0.0，`tcp_*` 未观测绝不能被读成 0）、
#      IPv4 必须按 `::ffff:a.b.c.d` 落在 IPv6 列里。
#   C. **反向故障注入必须全部被判红**：改 null 掩码 / 改值字节 / 改类型名 /
#      改行数 varint / 截断 / 交换列名 / 改字符串长度。7 种里任何一种"没被检出"
#      或"根本没改变字节"（空注入）都算失败。
#   D. **参考实现复核**（需要 clickhouse 二进制）：
#      D1 逐字节 parity：用**线路类型**建 `ENGINE = Memory` staging 表，读入我们的
#         产物后再 `SELECT <列契约顺序> FORMAT Native`，与我们的文件 `cmp`。
#         这证明字节布局与参考实现**逐字节相同**，而不是"差不多能读"。
#      D2 真实 DDL 落地：执行仓库里那份 `001_flows.sql`（MergeTree + CODEC + ALIAS），
#         `INSERT … FROM INFILE … FORMAT Native`，再把 56 列读回 TSV 与 JSONL 逐格对照。
#         IPv6 两列走 DDL 的 `src_ip_text/dst_ip_text` ALIAS 反解 —— 顺带证明
#         "地址只存一份二进制"的取舍在查询侧仍然可用。
#
# D 缺参考实现时**显式打印"未核验，不计为通过"**并整关退出码 0（与 tshark 惯例一致），
# 但绝不把 D 的结果说成已通过。
#
# 用法：bash scripts/verify/check-columnar.sh [--no-self-test] [--clickhouse <BIN>]
# 退出码：0 通过（可能含"参考实现未核验"）；1 断言失败；2 前置样本缺失；3 环境缺工具
set -uo pipefail

SELF_TEST=1
CH=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-self-test) SELF_TEST=0 ;;
    --clickhouse) shift; CH="${1:-}" ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
  shift
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

# 参考实现定位：显式参数 > 环境变量 > PATH > 本机缓存的官方二进制。
# 缓存路径**不写进仓库文档当作依赖**，只是让本机跑得到 D 组；两台复验机上
# 按各自的安装方式给 --clickhouse 或 CLICKHOUSE 即可。
if [ -z "${CH}" ]; then
  CH="${CLICKHOUSE:-}"
fi
if [ -z "${CH}" ]; then
  CH="$(command -v clickhouse 2>/dev/null || true)"
fi
if [ -z "${CH}" ] && [ -x "${HOME}/.cache/cythsec-tools/clickhouse-macos" ]; then
  CH="${HOME}/.cache/cythsec-tools/clickhouse-macos"
fi

VECS=(
  "datasets/pcap/sample-session-tcp.pcap"
  "datasets/dpi/tls-vectors.pcap"
  "datasets/dpi/dns-vectors.pcap"
  "datasets/dpi/http-vectors.pcap"
)
for f in "${VECS[@]}"; do
  if [ ! -f "${f}" ]; then
    echo "✗ 样本缺失：${f}" >&2
    echo "  先执行：python3 datasets/pcap/generate-samples.py && python3 datasets/dpi/generate-dpi-samples.py" >&2
    exit 2
  fi
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cythsec-columnar.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

echo "==> 构建（debug）"
if ! "${CARGO}" build --offline -q -p traffic-engine --bin cythsec-analyze --bin cythsec-dump-ddl \
     >"${WORK}/build.log" 2>&1; then
  echo "✗ 构建失败" >&2
  tail -20 "${WORK}/build.log" >&2
  exit 1
fi
DDL_BIN="${ROOT}/target/debug/cythsec-dump-ddl"
ANALYZE="${ROOT}/target/debug/cythsec-analyze"
TOOL="${ROOT}/scripts/verify/check-columnar.py"

echo "==> A. 生成物一致（DDL 只能由代码生成）"
"${DDL_BIN}" >"${WORK}/ddl.sql" || exit 1
if ! cmp -s "${WORK}/ddl.sql" storage/clickhouse/001_flows.sql; then
  echo "  ✗ storage/clickhouse/001_flows.sql 与 cythsec-dump-ddl 的输出不一致" >&2
  echo "    （改 DDL 请改 src/storage/mod.rs 再重新生成；两份手改必然分叉）" >&2
  diff -u storage/clickhouse/001_flows.sql "${WORK}/ddl.sql" | head -20 >&2
  exit 1
fi
echo "  ✓ 001_flows.sql 逐字节可复现"

"${DDL_BIN}" --columns-tsv >"${WORK}/cols.tsv" || exit 1
NCOLS=$(grep -c "" "${WORK}/cols.tsv")
if grep -q $'\tunknown:' "${WORK}/cols.tsv"; then
  echo "  ✗ 列清单里有没登记期望规则的派生列：" >&2
  grep $'\tunknown:' "${WORK}/cols.tsv" | cut -f1,4,5 >&2
  exit 1
fi
"${DDL_BIN}" --contract >"${WORK}/contract.txt" || exit 1
DECLARED=$("${PY}" -c "
import sys,re
m=re.search(r'columns=(\d+)', open('${WORK}/contract.txt',encoding='utf-8').read())
print(m.group(1) if m else 'NONE')")
if [ "${DECLARED}" != "${NCOLS}" ]; then
  echo "  ✗ 列契约声明 ${DECLARED} 列，TSV 却有 ${NCOLS} 行 ⇒ 有列没被比对到" >&2
  exit 1
fi
echo "  ✓ 列清单自洽：${NCOLS} 列，期望规则全部有主"

echo "==> 产出真实向量的两份出口（JSONL 与 Native 同源同序）"
: >"${WORK}/all.jsonl"
: >"${WORK}/all.native"
ROWS=0
for f in "${VECS[@]}"; do
  b="$(basename "${f}" .pcap)"
  if ! "${ANALYZE}" -r "${f}" -o "${WORK}/${b}.jsonl" --native "${WORK}/${b}.native" -q \
       >"${WORK}/${b}.stats" 2>&1; then
    echo "  ✗ 分析失败：${f}" >&2
    tail -5 "${WORK}/${b}.stats" >&2
    exit 1
  fi
  if [ -s "${WORK}/${b}.jsonl" ]; then
    cat "${WORK}/${b}.jsonl" >>"${WORK}/all.jsonl"
    # Native 是**块序列**，每块自带列头，所以多份产物可以直接串接成一条流。
    cat "${WORK}/${b}.native" >>"${WORK}/all.native"
    ROWS=$((ROWS + $(grep -c "" "${WORK}/${b}.jsonl")))
  fi
done
echo "  ✓ rows=${ROWS} native=$(wc -c <"${WORK}/all.native" | tr -d ' ') bytes"
if [ "${ROWS}" = "0" ]; then
  echo "  ✗ 真实向量一条记录都没产出：比对会空跑成"全绿"" >&2
  exit 1
fi

echo "==> B. 独立解码 + 逐格比对（规范由 check-columnar.py 单独实现一份）"
if ! "${PY}" "${TOOL}" compare \
     --native "${WORK}/all.native" --jsonl "${WORK}/all.jsonl" \
     --columns-tsv "${WORK}/cols.tsv"; then
  exit 1
fi

echo "==> B2. 块碎片化的代价（块头要重写全部列名与类型）"
"${ANALYZE}" -r "${VECS[1]}" -o "${WORK}/frag.jsonl" --native "${WORK}/frag.native" \
  --native-rows-per-block 1 -q >/dev/null 2>&1
if [ -s "${WORK}/frag.native" ]; then
  if ! "${PY}" "${TOOL}" compare \
       --native "${WORK}/frag.native" --jsonl "${WORK}/frag.jsonl" \
       --columns-tsv "${WORK}/cols.tsv"; then
    echo "  ✗ rows_per_block=1 的产物读不对 ⇒ 多块路径没被真正覆盖" >&2
    exit 1
  fi
  BIG=$(wc -c <"${WORK}/frag.native" | tr -d ' ')
  echo "  ✓ 每块 1 行时仍然逐格相符（bytes=${BIG}，这就是块头的真实代价）"
fi

echo "==> B3. 没有记录时不产出空文件（空文件会被当成"落盘成功"）"
if "${ANALYZE}" -r "${VECS[0]}" -o "${WORK}/zero.jsonl" --native "${WORK}/zero.native" \
     --limit 0 -q >"${WORK}/zero.stats" 2>&1; then
  if [ -e "${WORK}/zero.native" ] || [ -s "${WORK}/zero.jsonl" ]; then
    echo "  ✗ 零记录仍然产出了文件（下游会把空文件当成一批数据）" >&2
    exit 1
  fi
  echo "  ✓ 零记录 ⇒ 无 .native、无 JSONL 行"
else
  echo "  ✗ --limit 0 执行失败（这条断言本身没跑起来）" >&2
  tail -3 "${WORK}/zero.stats" >&2
  exit 1
fi

echo "==> C. 反向故障注入（每一种都必须被判红，且不许是空注入）"
if [ "${SELF_TEST}" = "1" ]; then
  if ! "${PY}" "${TOOL}" self-test \
       --native "${WORK}/all.native" --jsonl "${WORK}/all.jsonl" \
       --columns-tsv "${WORK}/cols.tsv"; then
    exit 1
  fi
else
  echo "  ⚠ 已按要求跳过（--no-self-test）：注入未跑，C 组**未核验**"
fi

# ---------------------------------------------------------------------------
# D 组：需要参考实现
# ---------------------------------------------------------------------------
if [ -z "${CH}" ] || [ ! -x "${CH}" ]; then
  echo "==> D. 参考实现复核：⚠ 未找到 clickhouse 二进制"
  echo "    逐字节 parity（D1）与真实 MergeTree 读回（D2）**未核验，不计为通过**。"
  echo "    补跑：bash scripts/verify/check-columnar.sh --clickhouse <路径>"
  echo "    （Linux aarch64 官方二进制：curl -O https://clickhouse.com/ && sh clickhouse.sh）"
  echo "结论：A/B/C 通过；D 未核验。"
  exit 0
fi

echo "==> D. 参考实现：${CH} ($("${CH}" local --version 2>/dev/null | tail -1))"
# 单块产物：parity 比对要求两边块边界一致，所以这里显式把 rows_per_block 抬到
# 大于行数（默认 100000 也够，但写明是为了让"为什么能 cmp"这件事有出处）。
"${ANALYZE}" -r "${VECS[1]}" -o "${WORK}/p.jsonl" --native "${WORK}/p.native" \
  --native-rows-per-block 1000000 -q >/dev/null 2>&1
PR=$(grep -c "" "${WORK}/p.jsonl")

# staging 表用**线路类型**（不是落库类型）：DDL 侧的 LowCardinality 会在读入时
# 自动转换，那样就比不出"我们的字节等于参考实现的字节"。
"${PY}" - "${WORK}/cols.tsv" "${WORK}/stage.run.sql" "${WORK}/p.native" <<'PYEOF'
import sys
cols = [l.rstrip("\n").split("\t") for l in open(sys.argv[1], encoding="utf-8")]
body = ",\n    ".join(c[0] + " " + c[1] for c in cols)
names = ", ".join(c[0] for c in cols)
open(sys.argv[2], "w", encoding="utf-8").write(
    "CREATE TABLE stage (\n    " + body + "\n) ENGINE = Memory;\n"
    "INSERT INTO stage FROM INFILE '" + sys.argv[3] + "' FORMAT Native;\n"
    # 子句顺序必须是 `INTO OUTFILE … FORMAT Native`：反过来写 ClickHouse 报
    # `Syntax error ... Expected one of: SETTINGS, ...`（2026-10-19 真实踩过）。
    "SELECT " + names + " FROM stage INTO OUTFILE 'ref.native' FORMAT Native;\n"
)
PYEOF

D1=0
if (cd "${WORK}" && "${CH}" local -n --query "$(cat "${WORK}/stage.run.sql")" \
     >"${WORK}/d1.log" 2>&1); then
  if cmp -s "${WORK}/p.native" "${WORK}/ref.native"; then
    echo "  ✓ D1 逐字节 parity：我们的产物 == 参考实现 SELECT … FORMAT Native"
    echo "    （rows=${PR} ours=$(wc -c <"${WORK}/p.native" | tr -d ' ') ref=$(wc -c <"${WORK}/ref.native" | tr -d ' ')）"
    D1=1
  else
    echo "  ✗ D1 与参考实现字节不一致：" >&2
    cmp "${WORK}/p.native" "${WORK}/ref.native" >&2
    exit 1
  fi
else
  echo "  ✗ D1 参考实现读入/输出失败（产物别人读不了）：" >&2
  tail -8 "${WORK}/d1.log" >&2
  exit 1
fi

D2=0
"${PY}" - "${WORK}/cols.tsv" "${WORK}/readback.sql" <<'PYEOF'
import sys
cols = [l.rstrip("\n").split("\t") for l in open(sys.argv[1], encoding="utf-8")]
# IPv6 两列改用 DDL 的 ALIAS 文本列：读回的是"反解出来的地址"，
# 既验证 ALIAS 可用，也验证"只存一份二进制"没有把地址读丢。
sel = []
for c in cols:
    if c[0] in ("src_ip", "dst_ip"):
        sel.append(c[0] + "_text")
    else:
        sel.append(c[0])
open(sys.argv[2], "w", encoding="utf-8").write(", ".join(sel) + "\n")
PYEOF
SELECT_LIST=$(cat "${WORK}/readback.sql")
mkdir -p "${WORK}/mtdir"
if "${CH}" local --path "${WORK}/mtdir" -n --query "
$(cat storage/clickhouse/001_flows.sql)
INSERT INTO flows FROM INFILE '${WORK}/all.native' FORMAT Native;
SELECT ${SELECT_LIST} FROM flows ORDER BY first_seen_us, session_id FORMAT TabSeparated;
" >"${WORK}/flows.tsv" 2>"${WORK}/d2.log"; then
  # compare-ch 要求行序与 JSONL 一致：JSONL 侧同样按 ORDER BY 的键排序后再比。
  "${PY}" - "${WORK}/all.jsonl" "${WORK}/all.sorted.jsonl" <<'PYEOF'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
recs.sort(key=lambda r: (int(r["time"]["first_seen_us"]), int(r["session_id"])))
with open(sys.argv[2], "w", encoding="utf-8") as fh:
    for r in recs:
        fh.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
PYEOF
  if "${PY}" "${TOOL}" compare-ch \
       --clickhouse-tsv "${WORK}/flows.tsv" --jsonl "${WORK}/all.sorted.jsonl" \
       --columns-tsv "${WORK}/cols.tsv"; then
    D2=1
    echo "  ✓ D2 真实 MergeTree（含 CODEC/LowCardinality/ALIAS/TTL）读回逐格相符"
  else
    exit 1
  fi
else
  echo "  ✗ D2 执行仓库 DDL 或读回失败：" >&2
  tail -12 "${WORK}/d2.log" >&2
  exit 1
fi

echo "结论：A/B/C/D 全部通过（D1 parity=$([ ${D1} = 1 ] && echo yes)、D2 真实库读回=$([ ${D2} = 1 ] && echo yes)）。"
