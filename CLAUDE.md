# CLAUDE.md —— CythSec（Claude Code 侧）

流程规则的**真源是 `AGENTS.md`**，本文件只保证 Claude 在会话开头就拿到那条最要紧的硬约束。
细节（钩子怎么装、例外怎么留、为什么这么定）看 `AGENTS.md`；接力上下文看
`docs/planning/HANDOFF.md`；待办表看 `docs/planning/BACKLOG.md`。

## 硬规则：一个问题一条分支，测绿才并入 master

收到"改代码 / 修 bug / 加功能"的任务时，**第一个 git 动作是开分支，不是改文件**：

```bash
git switch -c <type>/<topic>          # 例：fix/cys-trf-015、feat/ipfix-template-refresh
```

改完在这个分支上提交，然后**真的跑**这两条（贴退出码，不要凭印象说"能过"）：

```bash
bash scripts/lint/lint-all.sh
bash scripts/test/test-all.sh
```

两条全绿才并入：

```bash
git switch master && git merge --no-ff <type>/<topic>
```

- **不许直接 `git commit` 在 `master`/`main` 上**：`scripts/hooks/pre-commit` 会拒。
  例外口只有 `CYTHSEC_ALLOW_MAIN_COMMIT=1`（会打警告，理由必须写进提交说明）。
  别用 `--no-verify` —— 那连明文密钥扫描一起绕了。
- **不许 `git push`**，除非用户这一轮明确说要推（`scripts/hooks/guard-agent-git.sh` 会拦，
  放行口 `CYTHSEC_ALLOW_PUSH=1`）。
- 每个新克隆跑一次 `make hooks`：`core.hooksPath` 是本地配置，不装 = 钩子一次都不执行，
  而钩子文件明明在仓库里（这类"检查器存在但没人调用"的坑本仓库踩过三次）。
  验证：`make check-hooks` 或 `bash scripts/test/test-all.sh --branch-policy`。

## 其它同族硬约束（详见 AGENTS.md / HANDOFF.md）

- 新增/修改门禁或钩子后必须做**反向注入验证**：绿色的"通过"与绿色的"没跑"长得一样。
- 注释/文档里声称"有脚本会拦下"的，该脚本必须真实存在**并挂在门禁上**。
- 状态标记与实现同批提交；刷新滞后状态时逐项核对验收标准，不凭印象批量打勾。
- 文档里的数字与结论当场复跑；`test-all.sh` 输出中的「未核验 / SKIPPED」不许写成通过。
