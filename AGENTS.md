# AGENTS.md —— 本仓库对所有 Agent 的硬指令（Codex / Claude / Workbuddy / SCNet 共用同一份真源）

> 这份文件是**流程真源**。`CLAUDE.md`、`.workbuddy/memory/MEMORY.md`、`CONTRIBUTING.md`
> 里的同一条规则都指回这里，改规则只改这里，别在四处各写一套。

## 分支纪律（不可违反）

**一个问题一条分支；测绿了才并入 `main`；只落本地，不 push。**

```bash
# 1) 动手之前先开分支（脏工作树会跟着 switch 走，改动不会丢）
git switch -c <type>/<topic>        # type ∈ feat fix chore docs refactor test
                                    # 对得上待办号就写任务号：fix/cys-trf-015

# 2) 在分支上提交该问题范围内的全部改动（状态标记与实现同批提交，别攒）

# 3) 完成 = 两条门禁全绿（不是"应该能过"，是真的跑过）
bash scripts/lint/lint-all.sh
bash scripts/test/test-all.sh       # 默认全集；缺工具的那几项会显式「未核验」，不算绿

# 4) 全绿之后才并入（必须 --no-ff，让历史上看得见这条分支对应哪个问题）
git switch main
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
CYTHSEC_ALLOW_MAIN_COMMIT=1 git commit …    # 直落 main：会打警告，理由必须写进提交说明
CYTHSEC_ALLOW_PUSH=1 git push …             # push：只有用户明确授权时才用
```

不要用 `git commit --no-verify`：那把密钥扫描也一起绕了，而且历史上看不出你绕过了什么。

### Agent 侧的行为要求

1. 收到"改点什么"的任务，**第一个 git 动作是 `git switch -c`**，不是 `git add`。
2. 不要为了"省事"在 `main` 上提交后再补分支（`git branch` + `reset` 那种改写别随手做，
   要改写先跟用户说清楚）。
3. 并入 `main` 前必须贴出两条门禁的**实际退出码**；没跑过就说没跑过。
4. 门禁里出现「未核验 / SKIPPED」时如实转述，不许写成通过。

## 协议适配状态记录（强制）

新增或修改流量协议适配，必须同批更新 `configs/registry/protocol-adaptation.json` 中对应ID的
支持范围、实现/测试/独立对照证据及未完成项，并运行 `python3 tools/codegen/gen-protocol-adaptation.py`
更新 [协议适配清单](docs/protocols/ADAPTATION-STATUS.md)。不得只手改生成表的勾选。
实现审查、本地测试、独立对照和完整适配分别记录；资料目录、候选承载、上下文接口或父协议命中
不能当作完整适配。完整适配只在本行验收范围已完成且缺口清空后勾选。

## 前端开发标准（强制）

前端控制台统一采用 **Ant Design Pro 官方工程体系**（Umi Max + React + TypeScript +
Ant Design + ProComponents），参考 <https://github.com/ant-design/ant-design-pro>。
所有新增页面和现有页面的维护均遵循此标准；禁止另建视觉体系或只用 CSS 模仿 Pro。

1. `web/console/config/routes.ts` 是路由、菜单与面包屑的唯一真源；Umi Max 负责路由与构建，
   ProLayout 负责标准中后台外壳，业务页用 PageContainer。
2. 表格、描述列表和面板优先使用 ProTable、ProDescriptions、ProCard；基础表单、日期、上传、
   按钮、反馈使用 Ant Design；图标使用 `@ant-design/icons`。不得手绘同类原生控件。
3. 主题通过 ConfigProvider / Design Token 和 Pro 布局配置修改；业务 CSS 仅负责布局，
   不覆盖 `.ant-*` 内部选择器，不添加第二套颜色、阴影和控件样式。
4. 页面必须区分加载、空数据、失败、未知、未发布与成功。请求失败不得回落成零或空列表成功；
   只呈现实际后端能力，不复制官方脚手架的演示身份、模拟数据、假权限或占位业务操作。
5. 保留键盘可用性、表单标签、错误说明、响应式布局与表格横向滚动。查询和上传必须保留
   后端约束、超时及旧响应隔离；接收确认不能冒充持久化完成。
6. 依赖版本与锁文件一同维护，遵守 peerDependencies；禁止 `--force` / `--legacy-peer-deps`
   掩盖冲突。升级 Pro 预发布组件须记录版本与兼容性验证。当前采用官方主线的 ProComponents 3。
7. 前端修改运行类型检查、ESLint、组件/接口测试及生产构建；布局或交互调整还须浏览器实测。
   两条仓库级合入门禁仍按上文执行；单项前端通过不能替代完整门禁。
8. **界面文案按企业级业务系统编写**：只呈现功能、数据、状态、操作及必要反馈。禁止自述式营销、
   开发过程说明、自我辩解和面向用户的说教文案，例如“演示模式 · 无真实身份”、
   “独立设计演示 · 全部为合成数据 · 未连接后端或实际设备”及整段“不读取、不发送、不执行”的声明。
   设计用途、样例数据、接线情况、验证范围与开发限制写入设计说明、开发文档或验收记录，
   不反复塞进页头、横幅、卡片和页脚。保留简明且与操作有关的错误、权限、数据来源、
   数据时效和风险确认；未实现能力不得因删文案而伪装为可用，禁止虚构身份、数据或成功状态。
9. **所有开发以企业级工程标准交付**：沿用真实业务模型和正式组件，落实输入校验、错误处理、
   权限边界、可访问性、可维护性及相应验证。界面说明不能替代工程实现，设计稿不能冒充已交付功能。
10. **前端统一为一套控制台**：共用 `web/console`、Umi路由、ProLayout和启动入口，默认端口15173。
    设计视图也在开发控制台内浏览，禁止另起原型静态服务、第二个React根或另一套菜单。
    后端通过同源代理接入；端口占用应报错，不得自动递增。设计数据只在开发设计路由加载，
    不进入生产业务统计和生产路由。

工程结构、页面映射、开发命令与验收清单见 [前端工程说明](docs/development/frontend-standard.md)。
