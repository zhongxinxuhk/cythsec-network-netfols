#!/usr/bin/env bash
# count-backlog.sh - 统计 docs/planning/BACKLOG.md 的任务数并写回「统计汇总」章节。
#
# 用法：
#   bash docs/planning/scripts/count-backlog.sh          # 打印统计
#   bash docs/planning/scripts/count-backlog.sh --write  # 写回 BACKLOG.md 的 <!-- STATS --> 区段
#
# 统计口径：任务行 = Markdown 表格中以 `| ⬜/◐/☑/⛔/⏸ | CYS-` 开头的行。
# 任务归属里程碑由该行所在的最近一个 "### 3.x M<数字>" 标题决定。

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BACKLOG="$REPO_ROOT/docs/planning/BACKLOG.md"

if [[ ! -f "$BACKLOG" ]]; then
  echo "错误：找不到 $BACKLOG" >&2
  exit 1
fi

python3 - "$BACKLOG" "${1:-}" <<'PY'
import re
import sys
from collections import Counter, OrderedDict

path, mode = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")

TASK_RE = re.compile(r"^\|\s*(⬜|◐|☑|✅|⛔|⏸)\s*\|\s*(CYS-([A-Z]{3})-(\d{3}))\s*\|(.*)$")
MILESTONE_RE = re.compile(r"^#{3,4}\s+3\.\d+\s+(M(\d+))\s")
# 宽容匹配：只要 ID 列是 CYS-XXX-NNN 就计入总量，用于校验严格解析是否漏行。
LOOSE_RE = re.compile(r"^\|\s*([^|]*?)\s*\|\s*CYS-[A-Z]{3}-\d{3}\s*\|")
# 状态别名：✅ 与 ☑ 同义。清单受控词汇为 ☑（见 §0 图例），此处仅作容错。
STATUS_ALIAS = {"✅": "☑"}
VALID_MARKS = ("⬜", "◐", "☑", "✅", "⛔", "⏸")

rows = []
all_lines = []
milestone = "M0"
with open(path, encoding="utf-8") as fh:
    all_lines = fh.readlines()
for line in all_lines:
    m = MILESTONE_RE.match(line)
    if m:
        milestone = m.group(1)
        continue
    t = TASK_RE.match(line)
    if not t:
        continue
    status, tid, domain, _num, rest = t.groups()
    status = STATUS_ALIAS.get(status, status)
    cells = [c.strip() for c in rest.split("|")]
    # cells[0] 已由正则消费掉任务名，剩余为 交付物/验收/依赖/P规模
    pscale = cells[-2] if len(cells) >= 2 else ""
    pm = re.match(r"\**(P[0-3])\**\s*/\s*(S|M|L|XL)", pscale)
    rows.append({
        "id": tid,
        "domain": domain,
        "milestone": milestone,
        "status": status,
        "priority": pm.group(1) if pm else "?",
        "scale": pm.group(2) if pm else "?",
    })

if not rows:
    print("未解析到任何任务行，请检查 BACKLOG.md 表格格式。", file=sys.stderr)
    sys.exit(2)

# ---- 防呆闸 ----------------------------------------------------------------
# 宽松匹配（只看 ID 列）得到的行数必须与严格解析一致。若不一致，说明表格里
# 出现了未识别的状态标记，此时严格解析会低估总量，并在 --write 时静默把错误
# 统计写回清单（历史事故：状态列误用 ✅，总量被算成 329 而非 349）。
loose_marks = Counter()
for line in all_lines:
    lm = LOOSE_RE.match(line)
    if lm:
        loose_marks[lm.group(1)] += 1
loose_total = sum(loose_marks.values())
if loose_total != len(rows):
    print(f"错误：宽匹配到 {loose_total} 个任务行，但严格解析仅得到 {len(rows)} 行。",
          file=sys.stderr)
    for mark, cnt in loose_marks.items():
        if mark not in VALID_MARKS:
            print(f"  未识别状态 {mark!r} 出现 {cnt} 次（受控词汇：⬜ ◐ ☑ ⛔ ⏸）",
                  file=sys.stderr)
    print("已拒绝写盘，请先统一状态标记。", file=sys.stderr)
    sys.exit(2)

total = len(rows)
by_domain = Counter(r["domain"] for r in rows)
by_pri = Counter(r["priority"] for r in rows)
by_scale = Counter(r["scale"] for r in rows)
by_status = Counter(r["status"] for r in rows)

MS_NAME = {
    "M0": "最小纵向切片", "M1": "工程基座加固", "M2": "数据平面真实收包",
    "M3": "流量分析深化", "M4": "控制平面补全", "M5": "控制面服务化",
    "M6": "存储与前端", "M7": "ML 与威胁情报", "M8": "平台适配与部署",
    "M9": "测试·安全·文档·发布",
}
ms_counts = OrderedDict()
for r in rows:
    ms_counts.setdefault(r["milestone"], 0)
    ms_counts[r["milestone"]] += 1

out = []
out.append(f"**任务总数：{total}**（不含 M0 已归档的 11 项）\n")

out.append("### 6.1 按里程碑\n")
out.append("| 里程碑 | 名称 | 任务数 |")
out.append("| --- | --- | --- |")
for ms in sorted(ms_counts, key=lambda x: int(x[1:])):
    out.append(f"| {ms} | {MS_NAME.get(ms, '—')} | {ms_counts[ms]} |")
out.append(f"| **合计** | — | **{total}** |\n")

out.append("### 6.2 按优先级\n")
out.append("| 优先级 | 任务数 | 占比 |")
out.append("| --- | --- | --- |")
for p in ("P0", "P1", "P2", "P3", "?"):
    if by_pri.get(p):
        out.append(f"| {p} | {by_pri[p]} | {by_pri[p] / total * 100:.1f}% |")
out.append("")

out.append("### 6.3 按规模\n")
out.append("| 规模 | 任务数 | 占比 |")
out.append("| --- | --- | --- |")
for s in ("S", "M", "L", "XL", "?"):
    if by_scale.get(s):
        out.append(f"| {s} | {by_scale[s]} | {by_scale[s] / total * 100:.1f}% |")
out.append("")

out.append("### 6.4 按域\n")
out.append("| 域码 | 任务数 |")
out.append("| --- | --- |")
for d, c in by_domain.most_common():
    out.append(f"| `{d}` | {c} |")
out.append("")

out.append("### 6.5 按状态\n")
out.append("| 状态 | 任务数 |")
out.append("| --- | --- |")
label = {"⬜": "未开始", "◐": "进行中", "☑": "已完成", "⛔": "作废", "⏸": "阻塞"}
for s in ("⬜", "◐", "☑", "⛔", "⏸"):
    if by_status.get(s):
        out.append(f"| {label[s]} | {by_status[s]} |")
out.append("")

out.append("### 6.6 里程碑完成度\n")
out.append("| 里程碑 | 已完成 | 总数 | 完成率 |")
out.append("| --- | --- | --- | --- |")
for ms in sorted(ms_counts, key=lambda x: int(x[1:])):
    done = sum(1 for r in rows if r["milestone"] == ms and r["status"] == "☑")
    n = ms_counts[ms]
    out.append(f"| {ms} | {done} | {n} | {done / n * 100:.0f}% |")
out.append("")

body = "\n".join(out).rstrip() + "\n"

if mode == "--write":
    with open(path, encoding="utf-8") as fh:
        doc = fh.read()
    new = re.sub(
        r"(<!-- STATS:START -->\n).*?(\n<!-- STATS:END -->)",
        lambda m: m.group(1) + body + m.group(2),
        doc,
        flags=re.S,
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new)
    print(f"已写回 {path}（任务总数 {total}）")
else:
    print(body)
PY
