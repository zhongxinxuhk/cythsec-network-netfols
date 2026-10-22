#!/usr/bin/env bash
# guard-agent-git.sh —— 给「会自己敲 git 的 Agent」加的 PreToolUse 钩子（同 pre-commit 的规则，提前一步）。
#
# ## 为什么钩子要单独有一个 Agent 版
#
# `git commit` 只有在**真的执行**时才走 `pre-commit`。Agent 常犯的不是"提交到 master"，
# 而是"在 master 上写完一堆改动才想起该开分支"，于是顺手 `git checkout -b` 把脏树带走，
# 或者更糟：`git stash` 后再也没回来。这条钩子在命令**进入终端之前**就把它拦下，
# 让 Agent 在动手前回答"这个分支为哪个问题而存在"。
#
# ## 接线方式
#
#   - Claude Code：`.claude/settings.json` 的 `hooks.PreToolUse`（matcher = `Bash`）
#   - 其它能挂钩子的 Agent（Workbuddy / Codex / SCNet 的 hook 配置）指向同一个脚本即可
#   - 手工自检：`bash scripts/verify/check-branch-policy.sh --self-test`（含本脚本的三条断言）
#
# ## 协议
#
# stdin 收一条 JSON（`{"tool_input":{"command":"…"}}`，兼容 `tool_name`/`toolUseEvent` 变体）。
# 退出码：`0` 放行；`2` **拦截**并把 stderr 回灌给模型（Claude Code 的 PreToolUse 约定，
# 其它实现按"非 0 即拦截"处理也能用）。解析不了输入时**不假装检查过**：放行并打印未核验。
#
# ## 两条断言
#
#   1. `git commit` / `git -C <路径> commit` 落在 `master` / `main` 上 → 拦截
#      （例外同 pre-commit：`CYTHSEC_ALLOW_MAIN_COMMIT=1`；merge/rebase 等续作不在此列）
#   2. `git push` → 拦截（本仓库的既有约定：**提交仅限本地，push 需要用户明确授权**）
#      例外：`CYTHSEC_ALLOW_PUSH=1`
set -uo pipefail

INPUT="$(cat 2>/dev/null || true)"
if [ -z "${INPUT}" ]; then
  echo "[guard-agent-git] stdin 为空 → 未核验，放行（钩子没有输入时绝不假装检查过）" >&2
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[guard-agent-git] 缺 python3 → 无法解析钩子输入，未核验，放行（不计为通过）" >&2
  exit 0
fi

CMD="$(printf '%s' "${INPUT}" | python3 -c '
import json,sys
raw=sys.stdin.read()
try:
    d=json.loads(raw)
except Exception:
    print("")
    sys.exit(0)
def walk(x):
    if isinstance(x,dict):
        for k in ("command","cmd","script"):
            v=x.get(k)
            if isinstance(v,str) and v.strip():
                return v
        for v in x.values():
            r=walk(v)
            if r: return r
    if isinstance(x,list):
        for v in x:
            r=walk(v)
            if r: return r
    return ""
print(walk(d))
')"

if [ -z "${CMD}" ]; then
  echo "[guard-agent-git] 输入里没有 command 字段 → 未核验，放行（不计为通过）" >&2
  exit 0
fi

# 只看 git 的写操作，别的命令一律放行（含只读的 git status/log/diff）
case "${CMD}" in
  *git*commit*|*git*push*) ;;
  *) exit 0 ;;
esac

# 从命令里取 `-C <路径>`（git -C 会改变仓库定位，不能拿当前目录的分支糊弄过去）
REPO_DIR="$(printf '%s' "${CMD}" | python3 -c '
import re,sys
s=sys.stdin.read()
m=re.search(r"(?:^|[;&|]|\s)(?:env\s+)?git\s+(?:-\S+\s+)*?-C\s+([\"\x27]?)(\S+?)\1\s", s)
print(m.group(2) if m else "")
')"
[ -n "${REPO_DIR}" ] && TARGET="${REPO_DIR}" || TARGET="${PWD}"

# symbolic-ref 优先（"还没有提交的 master" 上 rev-parse 会返回字面量 HEAD，被误判成游离分支）
BRANCH="$(git -C "${TARGET}" symbolic-ref --short -q HEAD 2>/dev/null || echo '')"
[ -n "${BRANCH}" ] || BRANCH="$(git -C "${TARGET}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '')"
[ "${BRANCH}" = "HEAD" ] && BRANCH=""
GIT_DIR_ABS="$(cd "$(git -C "${TARGET}" rev-parse --git-dir 2>/dev/null)" 2>/dev/null && pwd || echo '')"

SENTINEL=""
if [ -n "${GIT_DIR_ABS}" ]; then
  for s in MERGE_HEAD rebase-merge rebase-apply CHERRY_PICK_HEAD REVERT_HEAD; do
    [ -e "${GIT_DIR_ABS}/${s}" ] && SENTINEL="${s}" && break
  done
fi

case "${CMD}" in
  *git*push*) # INJECT-ANCHOR:push-enforce
    if [ "${CYTHSEC_ALLOW_PUSH:-0}" = "1" ]; then
      echo "[guard-agent-git] ⚠ 越权放行 git push（CYTHSEC_ALLOW_PUSH=1）——请确认用户已明确授权" >&2
    else
      cat >&2 <<EOF
[guard-agent-git] ✗ 拦截 git push：本仓库的约定是**提交只落本地**，push 需要用户明确授权。
  如果用户这一轮就是要推，请让他明确说一句，再用 CYTHSEC_ALLOW_PUSH=1 重跑该命令。
EOF
      exit 2
    fi
    ;;
esac

case "${CMD}" in
  *git*commit*)
    case "${BRANCH}" in
      master | main)
        if [ -n "${SENTINEL}" ]; then
          exit 0   # 并入动作（merge --no-ff 等）是规则要求的步骤
        fi
        if [ "${CYTHSEC_ALLOW_MAIN_COMMIT:-0}" = "1" ]; then
          echo "[guard-agent-git] ⚠ 越权放行：直接向 ${BRANCH} 提交（CYTHSEC_ALLOW_MAIN_COMMIT=1）" >&2
          exit 0
        fi
        cat >&2 <<EOF
[guard-agent-git] ✗ 拦截：当前在 ${BRANCH}，本仓库要求**一个问题一条分支，测绿才并入**。
  先开分支再动手（脏工作树会跟着 switch 走，改动不会丢）：
    git switch -c <type>/<topic>     # 例：fix/cys-trf-015、chore/branch-policy-hook
  在分支上提交 → 跑 scripts/lint/lint-all.sh 与 scripts/test/test-all.sh（全绿）
  → 再 git switch ${BRANCH} && git merge --no-ff <type>/<topic>
  注意：只读命令（git status / log / diff / show）不受本钩子限制；merge 与 rebase 的续作也不受限。
  真有必要直落 ${BRANCH} 时用 CYTHSEC_ALLOW_MAIN_COMMIT=1，并把理由写进提交说明。
EOF
        exit 2
        ;;
    esac
    ;;
esac

exit 0
