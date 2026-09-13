#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-deps.py —— BACKLOG 依赖图完整性校验

用途：
    在按 BACKLOG 排期前，确认依赖图可用。检查四件事：
      1. 环（cycle）      —— 存在环则无法拓扑排序，排期会卡死
      2. 悬空引用         —— 依赖指向不存在的任务 ID
      3. 自依赖           —— 任务依赖自身
      4. 状态一致性       —— 已标记完成的任务，其前置依赖是否也都已完成

用法：
    python3 docs/planning/scripts/check-deps.py [BACKLOG.md]
    BACKLOG.md 缺省为 docs/planning/scripts/../BACKLOG.md

退出码：0 = 无环且无悬空引用；1 = 存在问题；2 = 用法/解析错误。
"""

import re
import sys
import os
from collections import defaultdict

ID_RE = re.compile(r"CYS-[A-Z]{3}-\d{3}")
# 任务行：| 状态 | ID | 任务 | 交付物 | 验收 | 依赖 | 优先级·规模 |
ROW_RE = re.compile(
    r"^\|\s*(\S+)\s*\|\s*(CYS-[A-Z]{3}-\d{3})\s*\|"  # 状态 | ID
)
DONE_MARKS = {"☑", "✅", "[x]", "x", "X", "完成"}  # ☑ 为清单受控词汇，✅ 仅作别名容错


def parse(path):
    """解析出 {id: (status, deps, lineno)} 与文件行列表。"""
    tasks = {}
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    for lineno, line in enumerate(lines, 1):
        m = ROW_RE.match(line)
        if not m:
            continue
        status, tid = m.group(1), m.group(2)
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 6:
            print(f"WARN  {path}:{lineno} 列数不足({len(cells)})，跳过：{tid}",
                  file=sys.stderr)
            continue
        dep_cell = cells[5]
        deps = sorted(set(ID_RE.findall(dep_cell)))
        if tid in tasks:
            print(f"WARN  {path}:{lineno} 重复任务 ID：{tid}", file=sys.stderr)
        tasks[tid] = (status, deps, lineno)
    return tasks


def find_cycles(tasks):
    """返回所有环（每个环为任务 ID 列表）。DFS + 三色标记。"""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {t: WHITE for t in tasks}
    stack, cycles = [], []

    def dfs(node):
        color[node] = GRAY
        stack.append(node)
        for nxt in tasks[node][1]:
            if nxt not in tasks:          # 悬空引用，单独报告
                continue
            if color[nxt] == GRAY:        # 回边 -> 发现环
                idx = stack.index(nxt)
                cycles.append(stack[idx:] + [nxt])
            elif color[nxt] == WHITE:
                dfs(nxt)
        stack.pop()
        color[node] = BLACK

    for t in tasks:
        if color[t] == WHITE:
            dfs(t)
    return cycles


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "BACKLOG.md")
    if not os.path.isfile(path):
        print(f"ERROR: 找不到 BACKLOG 文件：{path}", file=sys.stderr)
        return 2

    tasks = parse(path)
    print(f"解析到 {len(tasks)} 个任务（{path}）")

    failed = False

    # --- 1. 环 ---
    cycles = find_cycles(tasks)
    if cycles:
        failed = True
        print(f"\n=== 发现 {len(cycles)} 个依赖环 ===")
        for i, cyc in enumerate(cycles, 1):
            print(f"  环 {i}: " + " -> ".join(cyc))
            for tid in cyc[:-1]:
                _, deps, ln = tasks[tid]
                print(f"      {tid} (行 {ln}) deps={deps or '—'}")
    else:
        print("\n=== 依赖环：无 ===")

    # --- 2. 悬空引用 / 自依赖 ---
    dangling, selfdep = [], []
    for tid, (_, deps, ln) in sorted(tasks.items()):
        for d in deps:
            if d == tid:
                selfdep.append((tid, ln))
            elif d not in tasks:
                dangling.append((tid, d, ln))
    if dangling:
        failed = True
        print(f"\n=== 悬空引用 {len(dangling)} 处 ===")
        for tid, d, ln in dangling:
            print(f"  {tid} (行 {ln}) 依赖不存在的 {d}")
    else:
        print("=== 悬空引用：无 ===")
    if selfdep:
        failed = True
        print(f"\n=== 自依赖 {len(selfdep)} 处 ===")
        for tid, ln in selfdep:
            print(f"  {tid} (行 {ln}) 依赖自身")
    else:
        print("=== 自依赖：无 ===")

    # --- 3. 状态一致性 ---
    done = {t for t, (s, _, _) in tasks.items() if s in DONE_MARKS}
    bad = []
    for tid in sorted(done):
        for d in tasks[tid][1]:
            if d in tasks and d not in done:
                bad.append((tid, d, tasks[d][0]))
    if bad:
        print(f"\n=== 状态不一致 {len(bad)} 处（已完成任务仍有未完成前置）===")
        for tid, d, ds in bad:
            print(f"  {tid} 已完成，但前置 {d} 状态为 {ds}")
    else:
        print(f"=== 状态一致性：无问题（已完成 {len(done)} 个）===")

    # --- 4. 可直接开工的任务 ---
    ready = [t for t in sorted(tasks)
             if t not in done and all(d in done for d in tasks[t][1])]
    print(f"\n=== 当前可开工（前置全部已完成，共 {len(ready)} 个）===")
    print("  " + " ".join(ready[:40]) + (" ..." if len(ready) > 40 else ""))

    print("\n结论：" + ("存在问题，见上。" if failed else "依赖图健康。"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
