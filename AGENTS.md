# AGENTS.md —— 本仓库对所有 Agent 的硬指令（Codex / Claude / Workbuddy / SCNet 共用同一份真源）

> 这份文件是**流程真源**。`CLAUDE.md`、`.workbuddy/memory/MEMORY.md`、`CONTRIBUTING.md`
> 里的同一条规则都指回这里，改规则只改这里，别在四处各写一套。

## 分支纪律（不可违反）

**一个问题一条分支；测绿了才并入 `master`；只落本地，不 push。**

```bash
# 1) 动手之前先开分支（脏工作树会跟着 switch 走，改动不会丢）
git switch -c <type>/<topic>        # type ∈ feat fix chore docs refactor test
                                    # 对得上待办号就写任务号：fix/cys-trf-015

# 2) 在分支上提交该问题范围内的全部改动（状态标记与实现同批提交，别攒）

# 3) 完成 = 两条门禁全绿（不是"应该能过"，是真的跑过）
bash scripts/lint/lint-all.sh
bash scripts/test/test-all.sh       # 默认全集；缺工具的那几项会显式「未核验」，不算绿

# 4) 全绿之后才并入（必须 --no-ff，让历史上看得见这条分支对应哪个问题）
git switch master
git merge --no-ff <type>/<topic>
```

为什么值得为它写一个钩子：直接落在 `master` 上的提交，**"先测后合"这件事在历史上无法证明**
—— 测的是当时的工作树，合的是随后又改过几处的树。2026-10-22 的 `a906c81` 就是这么落上去的
（提交前确实跑了全量门禁，但历史看不出来），本规则由那次之后立起来。

### 机械层（不要只靠这份文档）

| 层 | 位置 | 拦什么 |
| --- | --- | --- |
| git `pre-commit` | `scripts/hooks/pre-commit` | 在 `master`/`main` 上的普通提交；顺带跑明文密钥兜底扫描 |
| Agent `PreToolUse` | `scripts/hooks/guard-agent-git.sh` | Agent 敲 `git commit`（落在主分支时）与 `git push` 之前先拦下 |
| 自证 + 安装状态 | `scripts/verify/check-branch-policy.sh`（门禁 `test-all.sh --branch-policy`） | 钩子逻辑坏 / **钩子根本没装** |

```bash
make hooks          # 每个克隆 / 每台机器都要跑一次：core.hooksPath 不随克隆走
make check-hooks    # 验证「真的会被执行」，没装会报「未核验」而不是通过
```

`core.hooksPath` 是**本地 git 配置**：新克隆里钩子文件在仓库里躺着、却一次都不会执行。
这正是本仓库记过三次的同族事故（检查器存在但没人调用）—— 所以才有 `--branch-policy` 这道关口。

### 例外（唯一一条，且必须看得见）

```bash
CYTHSEC_ALLOW_MAIN_COMMIT=1 git commit …    # 直落 master：会打警告，理由必须写进提交说明
CYTHSEC_ALLOW_PUSH=1 git push …             # push：只有用户明确授权时才用
```

不要用 `git commit --no-verify`：那把密钥扫描也一起绕了，而且历史上看不出你绕过了什么。

### Agent 侧的行为要求

1. 收到"改点什么"的任务，**第一个 git 动作是 `git switch -c`**，不是 `git add`。
2. 不要为了"省事"在 `master` 上提交后再补分支（`git branch` + `reset` 那种改写别随手做，
   要改写先跟用户说清楚）。
3. 并入 `master` 前必须贴出两条门禁的**实际退出码**；没跑过就说没跑过。
4. 门禁里出现「未核验 / SKIPPED」时如实转述，不许写成通过。
