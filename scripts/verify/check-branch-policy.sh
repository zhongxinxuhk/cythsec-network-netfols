#!/usr/bin/env bash
# check-branch-policy.sh —— 分支纪律钩子的**自证**与**安装状态**检查（把「先分支后合并」从口头约定变成可验的东西）。
#
# ## 它守的是什么
#
# 规则本身只有一句：**一个问题一条分支，测绿才并入 master**。但这句话有两种被悄悄违反的方式，
# 都不是靠文档堵住的：
#
#   ① **钩子没装**。`core.hooksPath` 是**本地 git 配置，不随克隆走** —— 换机器、新克隆，
#      或者有人跑过 `pre-commit install`（它写 `.git/hooks/`，会被 `core.hooksPath` 整体遮蔽），
#      钩子文件明明在仓库里，却一次都不会执行。这就是本仓库记过的同族教训：**注释里声称
#      「有脚本会拦下」的，该脚本必须真实存在并挂在门禁上** —— 而"存在"≠"会被调用"。
#   ② **钩子装了但拦错方向**。两个最容易写坏的方向都有真实代价：把**并入动作**一起拦掉
#      （`git merge --no-ff` 提不了 → 大家改用 `--no-verify`，连带密钥扫描一起废）；
#      或者只看当前目录的分支、没处理 `git -C <路径>` 与续作哨兵（worktree / 变基现场行为完全不同）。
#
# ## 断言
#
#   S1 master 上的普通提交必须被 `pre-commit` **拒绝**
#   S2 feature 分支上的提交必须**放行**（规则不是禁止提交）
#   S3 `git merge --no-ff` 并入 master 的合并提交必须**放行**（否则规则自己走不通）
#   S4 `CYTHSEC_ALLOW_MAIN_COMMIT=1` 必须放行**且**打印越权警告（例外口要看得见）
#   S5 摘掉钩子（`core.hooksPath` 未设）后 master 提交必须**成功** ⇒ 证明 S1 的绿来自钩子
#      而不是环境巧合
#   S6 密钥扫描桩返回非 0 时提交必须被拒；扫描脚本不存在时必须打印「未核验」而不是「通过」
#   S7 Agent 钩子（PreToolUse 协议）：master 上 `git commit` 拦截 / 分支上放行 / 只读 git 命令放行 /
#      `git push` 拦截 / `CYTHSEC_ALLOW_PUSH=1` 放行 / merge 续作放行 / `git -C <别的仓库>`
#      要按**那个仓库**的分支判定（不能拿当前目录糊弄）
#   I1 反向注入：改掉钩子里的分支判定 ⇒ S1 必须**不再拒绝**（用例不敏感就是假绿灯）
#   I2 反向注入：改掉 Agent 钩子里的 push 拦截 ⇒ S7 的 push 用例必须**不再拦截**
#
# 用法：bash scripts/verify/check-branch-policy.sh [--no-self-test]
# 退出码：0 通过；1 断言失败（含注入未被检出）；2 前置脚本缺失；
#         3 钩子未安装（本机 git 配置状态，与 tshark/ClickHouse 惯例一致 → test-all 记「未核验」）
set -uo pipefail

SELF_TEST=1
while [ $# -gt 0 ]; do
  case "$1" in
    --no-self-test)
      echo "  ⚠ 本脚本的全部内容就是自证，--no-self-test 被忽略（跳过它等于没有检查）" >&2
      ;;
    -h | --help)
      sed -n '1,42p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "未知参数：$1（--help）" >&2; exit 2 ;;
  esac
  shift
done

TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null || echo '')"
if [ -z "${TOPLEVEL}" ]; then
  echo "✗ 不在 git 仓库里，无法检查分支纪律（未核验）" >&2
  exit 2
fi

HOOK="${TOPLEVEL}/scripts/hooks/pre-commit"
GUARD="${TOPLEVEL}/scripts/hooks/guard-agent-git.sh"
for f in "${HOOK}" "${GUARD}"; do
  [ -f "${f}" ] || { echo "✗ 缺钩子脚本：${f}" >&2; exit 2; }
  [ -x "${f}" ] || { echo "✗ 钩子不可执行（git/Agent 都不会调用它）：$ chmod +x ${f}" >&2; exit 2; }
  bash -n "${f}" || { echo "✗ 钩子语法检查失败：${f}" >&2; exit 1; }
done

FAIL=0
say_ok() { echo "  ✓ $*"; }
say_no() { echo "  ✗ $*" >&2; FAIL=1; }

# ================================================================ ① 行为自证
if [ "${SELF_TEST}" = "1" ]; then
  echo "==> 行为自证（临时仓库，绝不碰真仓库）"

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/cythsec-branch-policy.XXXXXX")" || { echo "✗ mktemp 失败" >&2; exit 2; }
  trap 'rm -rf "${WORK}"' EXIT

  mk_repo() {
    local R="${1}"
    # 固定 -b master：机器上 init.defaultBranch=main 时，脚本里后面 switch -q master 会静默失败，
    # S3 / S7h 的「并入动作」场景就根本没构造出来（自测第一次跑就是这么漏掉的）
    git init -q -b master "${R}" || { say_no "git init 失败：${R}"; exit 2; }
    git -C "${R}" config user.name "self-test"
    git -C "${R}" config user.email "self@test.invalid"
    git -C "${R}" config core.hooksPath scripts/hooks
    mkdir -p "${R}/scripts/hooks" "${R}/scripts/security"
    cp "${HOOK}" "${R}/scripts/hooks/pre-commit"
    chmod +x "${R}/scripts/hooks/pre-commit"
    printf '#!/usr/bin/env bash\necho "self-test scan stub"\nexit 0\n' > "${R}/scripts/security/scan-secrets.sh"
    chmod +x "${R}/scripts/security/scan-secrets.sh"
  }

  seed_master() {
    # 造基线提交之前，先断言「还没有提交的 master」上也拦得住：
    # `git rev-parse --abbrev-ref HEAD` 在 unborn branch 上返回字面量 "HEAD"，
    # 早期版本把它当成游离分支放行 ⇒ 第一条提交可以直落 master（S1c 就是钉这个洞的）
    local R="${1}" OUT RC
    echo a > "${R}/f.txt"
    git -C "${R}" add f.txt >/dev/null 2>&1
    OUT="$(git -C "${R}" commit -m first-should-be-blocked 2>&1)"
    RC=$?
    if [ ${RC} -ne 0 ] && printf '%s' "${OUT}" | grep -q "拒绝：不能直接在 master 上提交"; then
      say_ok "S1c unborn master 上的第一条提交也被拒"
    else
      say_no "S1c unborn master 的第一条提交没被拒（rc=${RC}）：${OUT}"
    fi
    # 用规则唯一的例外口造基线提交（顺带就是 S4 的断言）
    OUT="$(CYTHSEC_ALLOW_MAIN_COMMIT=1 git -C "${R}" commit -m base 2>&1)"
    RC=$?
    if [ ${RC} -eq 0 ] && printf '%s' "${OUT}" | grep -q "越权放行"; then
      say_ok "S4 master 例外口：放行且打印越权警告"
    else
      say_no "S4 例外口行为不对（rc=${RC}）：${OUT}"
    fi
  }

  # --- S1 ~ S4 ---
  R1="${WORK}/r1"
  mk_repo "${R1}"
  seed_master "${R1}"

  echo b > "${R1}/g.txt"
  git -C "${R1}" add g.txt >/dev/null 2>&1
  S1_OUT="$(git -C "${R1}" commit -m should-be-blocked 2>&1)"
  S1_RC=$?
  if [ ${S1_RC} -ne 0 ] && printf '%s' "${S1_OUT}" | grep -q "拒绝：不能直接在 master 上提交"; then
    say_ok "S1 master 普通提交被拒绝"
  else
    say_no "S1 master 普通提交没被拒绝（rc=${S1_RC}）：${S1_OUT}"
  fi
  if printf '%s' "${S1_OUT}" | grep -q "正确做法"; then
    say_ok "S1b 拒绝时打印了正确做法（拒绝要能被照做，不是只说 no）"
  else
    say_no "S1b 拒绝信息里没有可执行的下一步"
  fi

  # --- S2 / S3 ---
  git -C "${R1}" switch -q -c feat/demo >/dev/null 2>&1
  S2_OUT="$(git -C "${R1}" commit -m on-branch 2>&1)"
  S2_RC=$?
  if [ ${S2_RC} -eq 0 ] && printf '%s' "${S2_OUT}" | grep -q "符合分支纪律"; then
    say_ok "S2 feature 分支提交放行"
  else
    say_no "S2 feature 分支被误拦（rc=${S2_RC}）：${S2_OUT}"
  fi

  git -C "${R1}" switch -q master >/dev/null 2>&1
  S3_OUT="$(git -C "${R1}" merge --no-ff -m "merge feat/demo" feat/demo 2>&1)"
  S3_RC=$?
  if [ ${S3_RC} -eq 0 ] && [ -n "$(git -C "${R1}" log --oneline -1 --grep 'merge feat/demo' 2>/dev/null)" ]; then
    say_ok "S3 git merge --no-ff 并入 master 放行（并入动作没被自己堵死）"
  else
    say_no "S3 并入动作被拦或没落地（rc=${S3_RC}）：${S3_OUT}"
  fi

  # --- S5：摘掉钩子 ⇒ S1 必须失效（证明绿来自钩子） ---
  git -C "${R1}" config --unset core.hooksPath
  echo c > "${R1}/h.txt"
  git -C "${R1}" add h.txt >/dev/null 2>&1
  S5_OUT="$(git -C "${R1}" commit -m no-hook 2>&1)"
  S5_RC=$?
  if [ ${S5_RC} -eq 0 ]; then
    say_ok "S5 未安装钩子时 master 提交畅通 → S1 的绿确实由钩子提供"
  else
    say_no "S5 摘掉钩子还是被拦（rc=${S5_RC}）：${S5_OUT}"
  fi

  # --- S6：密钥扫描必须真的串上了 ---
  git -C "${R1}" config core.hooksPath scripts/hooks
  printf '#!/usr/bin/env bash\necho "HIT 明文密钥" >&2\nexit 1\n' > "${R1}/scripts/security/scan-secrets.sh"
  git -C "${R1}" switch -q -c feat/scanfail >/dev/null 2>&1
  echo d > "${R1}/i.txt"
  git -C "${R1}" add i.txt >/dev/null 2>&1
  S6_OUT="$(git -C "${R1}" commit -m should-fail-scan 2>&1)"
  S6_RC=$?
  if [ ${S6_RC} -ne 0 ] && printf '%s' "${S6_OUT}" | grep -q "明文密钥扫描未通过"; then
    say_ok "S6 密钥命中时提交被拒（即使在合规分支上）"
  else
    say_no "S6 密钥命中没拦住（rc=${S6_RC}）：${S6_OUT}"
  fi
  rm -f "${R1}/scripts/security/scan-secrets.sh"
  S6C_OUT="$(git -C "${R1}" commit -m scan-missing 2>&1)"
  if printf '%s' "${S6C_OUT}" | grep -q "未核验"; then
    say_ok "S6b 扫描脚本缺失时打印「未核验」而不是「通过」"
  else
    say_no "S6b 扫描缺失被当成了通过（缺诚实标注）：${S6C_OUT}"
  fi

  # --- I1 反向注入：改掉分支判定 ⇒ S1 必须不再拒绝 ---
  RI="${WORK}/inject1"
  mk_repo "${RI}"
  seed_master "${RI}" >/dev/null 2>&1
  if ! python3 - "${RI}/scripts/hooks/pre-commit" <<'PY'
import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
old = "master | main) # INJECT-ANCHOR:main-branch"
new = "master___never | main___never) # INJECT-ANCHOR:main-branch"
if old not in s:
    sys.exit("注入锚点不存在（钩子改过，自证脚本要同步）")
open(p, 'w', encoding='utf-8').write(s.replace(old, new, 1))
PY
  then
    say_no "I1 注入失败"
  else
    echo b > "${RI}/g.txt"
    git -C "${RI}" add g.txt >/dev/null 2>&1
    I1_OUT="$(git -C "${RI}" commit -m gutted-should-pass 2>&1)"
    I1_RC=$?
    if [ ${I1_RC} -eq 0 ] && ! printf '%s' "${I1_OUT}" | grep -q "拒绝：不能直接在"; then
      say_ok "I1 反向注入被检出：改掉分支判定后 master 提交不再被拒（S1 敏感）"
    else
      say_no "I1 反向注入**未被检出**：钩子已改掉但 S1 仍然拒绝 → 用例是假的"
    fi
  fi

  # --- S7 Agent 钩子 ---
  GUARD_RUN() {
    # $1 命令串  $2 目标仓库（钩子必须按**这个仓库**的分支判定）  $3 额外的 env（可空）
    # 结果写全局 GUARD_RC / GUARD_OUT —— 早期版本用分隔符拼字符串回传，
    # macOS bash 3.2 的 printf 不认 \x 转义，rc 字段把整段多行输出都吞了进去。
    local payload
    payload="$(python3 -c 'import json,sys;print(json.dumps({"tool_input":{"command":sys.argv[1]}}))' "${1}")"
    GUARD_OUT="$(printf '%s' "${payload}" | (cd "${2}" && env ${3:-} bash "${GUARD}" 2>&1))"
    GUARD_RC=$?
  }

  check_guard() {
    # $1 名称 $2 期望rc $3 命令 $4 cwd $5 env $6 期望输出片段（可空）
    GUARD_RUN "${3}" "${4}" "${5}"
    if [ "${GUARD_RC}" = "${2}" ] && { [ -z "${6}" ] || printf '%s' "${GUARD_OUT}" | grep -q "${6}"; }; then
      say_ok "$1"
    else
      say_no "$1（期望 rc=${2}，实得 ${GUARD_RC}）：${GUARD_OUT}"
    fi
  }

  R2="${WORK}/r2"
  mk_repo "${R2}"
  seed_master "${R2}" >/dev/null 2>&1            # 现在 R2 在 master
  git -C "${R2}" switch -q -c feat/agent >/dev/null 2>&1   # R2 在分支

  R4="${WORK}/r4"
  mk_repo "${R4}"
  seed_master "${R4}" >/dev/null 2>&1            # R4 停在 master

  check_guard "S7a Agent 钩子在 master 上拦 git commit" 2 "git commit -m x" "${R4}" "" "一个问题一条分支"
  check_guard "S7b 分支上放行 git commit" 0 "git commit -m x" "${R2}" "" ""
  check_guard "S7c 只读 git 命令不受限" 0 "git status && git log --oneline" "${R4}" "" ""
  check_guard "S7d git push 一律先拦（本仓库：提交只落本地）" 2 "git push origin master" "${R2}" "" "提交只落本地"
  check_guard "S7e CYTHSEC_ALLOW_PUSH=1 时放行并警告" 0 "git push origin feat/agent" "${R2}" "CYTHSEC_ALLOW_PUSH=1" "越权放行"
  # S7f：cwd 在分支、但 `git -C` 指向另一个停在 master 的仓库 ⇒ 必须按那个仓库判定为拦截
  check_guard "S7f git -C 按目标仓库的分支判定（不被 cwd 骗过）" 2 \
    "git -C ${R4} commit -m x" "${R2}" "" "一个问题一条分支"
  # S7g：反向 —— cwd 在 master、`git -C` 指向分支仓库 ⇒ 放行
  check_guard "S7g git -C 指向合规仓库时放行（不被 cwd 误伤）" 0 \
    "git -C ${R2} commit -m x" "${R4}" "" ""

  # --- S7h/S7i：merge 续作不能被拦（规则会把自己堵死） ---
  R3="${WORK}/r3"
  mk_repo "${R3}"
  seed_master "${R3}" >/dev/null 2>&1
  git -C "${R3}" switch -q -c feat/conflict >/dev/null 2>&1
  echo conflict > "${R3}/f.txt"
  git -C "${R3}" add f.txt >/dev/null 2>&1
  git -C "${R3}" commit -m conflict >/dev/null 2>&1
  git -C "${R3}" switch -q master >/dev/null 2>&1
  # 两边都改同一个文件才会真冲突：只有一边改的话是 fast-forward，根本没有 MERGE_HEAD，
  # 上一版就是这么把「续作放行」的场景静默跳过的（打印未核验都比假装测过强）
  echo master-side > "${R3}/f.txt"
  git -C "${R3}" add f.txt >/dev/null 2>&1
  CYTHSEC_ALLOW_MAIN_COMMIT=1 git -C "${R3}" commit -m master-side >/dev/null 2>&1
  git -C "${R3}" merge feat/conflict >/dev/null 2>&1   # 预期冲突 → MERGE_HEAD 出现
  if [ -e "${R3}/.git/MERGE_HEAD" ]; then
    check_guard "S7h merge 续作（MERGE_HEAD）不被 Agent 钩子拦" 0 "git commit --no-edit" "${R3}" "" ""
    # 冲突要先解掉才轮得到提交（git 自己就会拦住 unmerged 文件），解完再验钩子放行
    echo resolved > "${R3}/f.txt"
    git -C "${R3}" add f.txt >/dev/null 2>&1
    S7I_OUT="$(git -C "${R3}" commit --no-edit 2>&1)"
    S7I_RC=$?
    if [ ${S7I_RC} -eq 0 ] && printf '%s' "${S7I_OUT}" | grep -q "续作中（MERGE_HEAD）"; then
      say_ok "S7i 解完冲突后的合并提交（仍在 master）被 pre-commit 放行"
    else
      say_no "S7i 并入动作被拦或没落地（rc=${S7I_RC}）：${S7I_OUT}"
    fi
  else
    echo "  ⚠ S7h/S7i 没构造出 merge 冲突 → 该场景未核验，不计为通过"
  fi

  # --- I2 反向注入：改掉 push 拦截 ⇒ S7d 必须不再拦截 ---
  if ! python3 - "${GUARD}" "${WORK}/guard-gutted.sh" <<'PYINJECT'
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding='utf-8').read()
old = "*git*push*) # INJECT-ANCHOR:push-enforce"
new = "*git*push_never*) # INJECT-ANCHOR:push-enforce"
if old not in s:
    sys.exit(1)
open(dst, 'w', encoding='utf-8').write(s.replace(old, new, 1))
PYINJECT
  then
    say_no "I2 注入失败（锚点不存在，钩子改过要同步自证脚本）"
  else
    I2_OUT="$(printf '{"tool_input":{"command":"git push origin master"}}' | (cd "${R2}" && bash "${WORK}/guard-gutted.sh" 2>&1); echo "rc=$?")"
    if printf '%s' "${I2_OUT}" | grep -q "rc=0"; then
      say_ok "I2 反向注入被检出：改掉 push 拦截后不再拦（S7d 敏感）"
    else
      say_no "I2 反向注入**未被检出**：钩子已改掉但仍在拦 → 用例是假的"
    fi
  fi
fi

# ================================================================ ② 安装状态（本机 git 配置）
echo
echo "==> 本克隆的钩子安装状态"
INSTALL_RC=0
HOOKS_PATH="$(git config --get core.hooksPath 2>/dev/null || echo '')"
if [ "${HOOKS_PATH}" = "scripts/hooks" ]; then
  say_ok "core.hooksPath = scripts/hooks（本克隆已安装）"
elif [ -n "${HOOKS_PATH}" ]; then
  say_no "core.hooksPath = ${HOOKS_PATH}，不是 scripts/hooks → 本仓库钩子**不会被执行**"
  echo "      修复：make hooks   （若是 pre-commit 框架装的：二者只留一个，本钩子已串 local 密钥扫描）" >&2
  INSTALL_RC=3
else
  echo "  ⚠ 本克隆**未安装**钩子（core.hooksPath 未设）→ 分支纪律目前无人执行"
  echo "    安装（每个克隆一次，这是本地配置、不随克隆走）：make hooks"
  echo "    —— 未核验，不计为通过"
  INSTALL_RC=3
fi
if [ -e "${TOPLEVEL}/.git/hooks/pre-commit" ]; then
  echo "  ⚠ .git/hooks/pre-commit 仍在（现被 core.hooksPath 遮蔽）；若 unset 该配置，"
  echo "    那份桩会顶替本钩子 → 只剩密钥扫描，没有分支限制。"
fi

echo
if [ ${FAIL} -ne 0 ]; then
  echo "结论：分支纪律钩子自证**未通过** ✗"
  exit 1
fi
if [ ${INSTALL_RC} -ne 0 ]; then
  echo "结论：钩子逻辑自证通过 ✓（S1–S7 + 2 项反向注入），但本克隆未安装 → 未核验"
  exit 3
fi
echo "结论：分支纪律钩子自证通过 ✓（S1–S7 + 2 项反向注入全部符合预期，钩子已安装）"
exit 0
