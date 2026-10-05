# cythsec 项目超级任务待办表（Master Backlog）

> 版本：v0.1.0 基线 · 生成日期：2026-09-14（AEST）
> 基线提交：`eaaa575` feat(console): add Dashboard and Traffic pages (5-page console)
> 范围：覆盖 README 蓝图全部 13 层，含工程基座、技术债、测试、安全、部署与文档。

---

## 0. 使用说明

### 0.1 编号规范

`CYS-<域代码>-<三位序号>`，全文件唯一、稳定不回收。任务作废时标记 `⛔ 作废`，序号不再复用。

### 0.2 域代码

| 域码 | 名称 | 中文 |
| --- | --- | --- |
| `INF` | Infrastructure | 工程基座 / CI / 工具链 |
| `DBT` | Debt | 技术债与现存缺陷修复 |
| `PKT` | packet-engine | C++ 高速收包 |
| `TRF` | traffic-engine | Rust 流量分析 |
| `RTD` | routerd | Go 路由控制面 |
| `POL` | policyd | Go 策略引擎 |
| `DNS` | dnsd | Go DNS 策略服务 |
| `TEL` | telemetryd | Go 遥测监控 |
| `CON` | console | React Web 控制面 |
| `MLT` | ml/training | Python 训练流水线 |
| `MLI` | ml/inference | C++ ONNX 推理 |
| `STO` | storage | PostgreSQL / ClickHouse / Redis |
| `TIP` | threat-intelligence | 威胁情报 |
| `PLT` | platform | 平台抽象层 |
| `CAP` | capture | 采集抽象 |
| `TST` | tests | 全局测试体系 |
| `TLS` | tools | 开发工具 |
| `DEP` | deploy | 部署与打包 |
| `DOC` | docs | 文档 |
| `SEC` | security | 安全与合规 |

### 0.3 优先级定义

| 级别 | 含义 | 判定标准 |
| --- | --- | --- |
| **P0** | 阻塞项 | 不做则后续任务无法开工，或存在已确认缺陷 |
| **P1** | 核心项 | 主线功能闭环所必需 |
| **P2** | 增强项 | 显著提升质量/体验，但可延后 |
| **P3** | 长期项 | 储备与优化，按需排期 |

### 0.4 规模口径（仅表示相对工作量，不作为排期承诺）

| 规模 | 含义 |
| --- | --- |
| `S` | 单一文件/单点改动，半天量级 |
| `M` | 单个模块内自洽改动 |
| `L` | 跨模块改动或需新引入依赖 |
| `XL` | 需新增子系统或跨语言契约，建议拆分后再执行 |

### 0.5 状态标记

`⬜ 未开始` · `◐ 进行中` · `☑ 已完成` · `⛔ 作废` · `⏸ 阻塞`

### 0.6 维护规则

1. 每完成一项，将状态改为 `☑ 已完成`，并在「完成记录」列追加 `Y-M-D @commit`。
2. 新增需求一律追加新编号，**禁止重排既有编号**。
3. 每个里程碑收尾时更新第 6 节统计汇总。
4. 本表与 `docs/deployment/dev-run-deploy.md` 互为补充：后者是操作手册，本表是任务台账。

---

## 1. 基线快照（2026-09-14 实测）

| 维度 | 实测值 | 证据 |
| --- | --- | --- |
| 版本 | `0.1.0` | `VERSION`、`Cargo.toml`、各 `CMakeLists.txt`、`package.json` |
| 提交数 | 11 | 全部落在 2026-09-04 02:11–03:22（约 71 分钟） |
| 有效源码 | 1,648 行 | `rs/go/cpp/h/ts/tsx`，排除 `node_modules` |
| 蓝图覆盖率 | 4 / 13 层 | 仅 `packet-engine`/`traffic-engine`/`routerd`/`console` 有实体代码 |
| 自动化测试 | 15 项，全绿 | Rust 7 · Go 4 · C++ 4 |
| C++ | ✅ 构建通过，CTest 1/1 Passed | 根 CMake → `hello_packet` / `test_packet` |
| Rust | ✅ `cargo build --offline` + 7 passed | 零第三方依赖 |
| Go | ✅ `go build ./...` + `netinfo` ok | `go vet` 通过 |
| 前端 | ✅ `tsc --noEmit` 退出码 0 · `vite build` 45 modules | gzip JS 56.55 kB |
| 工作树 | 干净 | `git status --short` 为空 |
| 远端 | `gitcode.com/zhongxinxu/CythSec.git` | 分支 `master` |

**结论**：已完成「**最小纵向切片**」——C++ → Rust → Go → React 四层链路可构建、可测试、可联通，但每层均只实现最窄路径，且 12 个模块目录仍为 `.gitkeep` 占位。

---

## 2. 里程碑总览

| 里程碑 | 名称 | 目标 | 完成判据 | 任务数 | 状态 |
| --- | --- | --- | --- | --- | --- |
| **M0** | 最小纵向切片 | 四语言工具链打通 | 四层均可构建+测试通过 | 11（已归档） | ☑ 已完成 |
| **M1** | 工程基座加固 | 可重现构建 + CI + 规范落地 | CI 四语言全绿；格式检查零差异 | 55 | ⬜ 未开始 |
| **M2** | 数据平面真实收包 | 能收到真实网卡报文并吐给分析层 | `pcap-replay` 回放可产出 Flow | 38 | ⬜ 未开始 |
| **M3** | 流量分析深化 | Flow 表 + TCP 重组 + 协议识别 | 对 `.pcap` 样本识别准确率 ≥ 阈值 | 39 | ⬜ 未开始 |
| **M4** | 控制平面补全 | 四个 Go 服务全部可运行 | `policyd`/`dnsd`/`telemetryd` 各有 API 与测试 | 45 | ⬜ 未开始 |
| **M5** | 控制面服务化 | routerd 具备写能力与生产就绪特性 | OpenAPI 覆盖 100%；鉴权生效 | 24 | ⬜ 未开始 |
| **M6** | 存储与前端 | 数据可持久化、可可视化 | 三库 schema 落地；console ≥10 页 | 38 | ⬜ 未开始 |
| **M7** | ML 与威胁情报 | 训练→导出→推理→联动闭环 | 模型 ONNX 落库并被风险引擎调用 | 37 | ⬜ 未开始 |
| **M8** | 平台适配与部署 | openEuler/openWrt/容器可交付 | 一键部署脚本在目标平台跑通 | 28 | ⬜ 未开始 |
| **M9** | 测试·安全·文档·发布 | 质量与合规闭环 | 覆盖率门槛达标；SBOM 产出 | 46 | ⬜ 未开始 |
| **M10** | 分层解耦与插件化 | 核心单体 + 契约下沉 + 插件分级 | 插件清单非法即拒；数据资产可原子热更新；新增协议检测器不改核心调度 | 17 | ⬜ 未开始 |
| **M11** | 流级遥测与采集 | 用运营商既有导出通道（IPFIX/sFlow）替代「逐包采集省网」的量级错误 | 导出产物被 tshark 独立解出且字段逐一相符；采集器能报出导出丢包（序列号缺口）；有可复算的容量模型 | 8 | ⬜ 未开始 |
| **合计** | — | — | — | **375** | — |

---

## 3. 超级任务待办表

### 3.1 M1 — 工程基座加固

#### 3.1.1 CI / 构建脚本（`INF`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ☑ | CYS-INF-001 | 创建 CI 主流水线 | `.github/workflows/ci.yml`；四语言矩阵（cpp/rust/go/node），各自 build + test | PR 触发后四个 job 全绿 | — | P0/S |
| ⬜ | CYS-INF-002 | 创建 lint 流水线 | `.github/workflows/lint.yml`；`clang-format --dry-run`、`cargo fmt --check`、`gofmt -l`、`tsc --noEmit` | 对现有代码零告警通过 | CYS-INF-001 | P0/S |
| ⬜ | CYS-INF-003 | 顶层 Makefile 入口 | `make build / test / lint / fmt / clean / ci`，内部转发到各语言脚本 | 单命令完成对应动作 | — | P0/S |
| ⬜ | CYS-INF-004 | 统一构建脚本 | `scripts/build/build-all.sh`，含工具链版本预检（cmake≥3.20、cargo、go≥1.22、node≥18） | 版本不足时给出可读报错并非 0 退出 | — | P0/S |
| ⬜ | CYS-INF-005 | 统一测试脚本 | `scripts/test/test-all.sh`，汇总四个技术栈测试结果与退出码 | 任一栈失败时整体非 0 退出 | CYS-INF-004 | P0/S |
| ⬜ | CYS-INF-006 | 环境自举脚本 | `scripts/dev/bootstrap.sh`：校验并提示安装缺失工具链 | 在干净机器上给出完整缺失清单 | CYS-INF-004 | P1/S |
| ⬜ | CYS-INF-007 | CI 复用脚本 | 将 `scripts/**` 作为 CI 唯一实现来源，workflow 只调用脚本 | workflow 内无重复构建逻辑 | CYS-INF-004 | P1/S |
| ⬜ | CYS-INF-008 | 前端构建纳入 CI | Node job：`npm ci` → `tsc --noEmit` → `vite build`，缓存 `~/.npm` | 构建产物可下载为 artifact | CYS-INF-001 | P0/S |
| ⬜ | CYS-INF-009 | 构建缓存策略 | Cargo registry/target 缓存、Go module 缓存、CMake ccache | 二次构建耗时下降可观测 | CYS-INF-001 | P2/M |
| ⬜ | CYS-INF-010 | 分支与保护规则 | `develop` 分支；`master` 要求 CI 通过 + review | 直接 push 被拒 | — | P1/S |

#### 3.1.2 代码规范与格式（`INF`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-INF-011 | `.editorconfig` | UTF-8/LF/尾随空格裁剪；`*.{ts,tsx,js,rs,go}` 2 空格，`*.{c,cpp,h}` 2 空格 | 主流编辑器自动遵从 | — | P1/S |
| ⬜ | CYS-INF-012 | `.clang-format` | 基于 LLVM 风格，2 空格缩进、100 列、`PointerAlignment: Left` | 对现有 C++ 代码 dry-run 零差异 | CYS-INF-011 | P1/S |
| ☑ | CYS-INF-013 | `rustfmt.toml` | `edition=2021`、`max_width=100`、`newline_style=Unix` | `cargo fmt --check` 通过 | — | P1/S |
| ⬜ | CYS-INF-014 | 前端 ESLint 配置 | `.eslintrc.cjs` + `@typescript-eslint`，并把 `eslint` 及其插件补入 `devDependencies` | `npm run lint` 可执行且零 error | CYS-DBT-005 | P0/S |
| ⬜ | CYS-INF-015 | Prettier 配置 | `.prettierrc`（2 空格、单引号、分号）对齐既有代码风格 | `npx prettier --check` 通过 | CYS-INF-014 | P2/S |
| ⬜ | CYS-INF-016 | 提交前钩子 | `.pre-commit-config.yaml` 或 husky：格式化 + lint + 单元测试增量 | 提交不合规代码被本地拦截 | CYS-INF-011~015 | P2/M |
| ⬜ | CYS-INF-017 | 提交信息规范 | 采用 Conventional Commits；`commitlint` 配置与 CI 校验 | 非规范 message 被拒绝 | CYS-INF-001 | P2/S |
| ⬜ | CYS-INF-018 | 代码所有权 | `.github/CODEOWNERS` 按目录划分（dataplane/services/web/ml/platform） | PR 自动请求对应 owner | — | P3/S |
| ⬜ | CYS-INF-019 | PR / Issue 模板 | `.github/PULL_REQUEST_TEMPLATE.md`、`ISSUE_TEMPLATE/bug.md`、`feature.md` | 新建 PR/Issue 自动套用 | — | P2/S |

#### 3.1.3 版本与可重现构建（`INF`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ☑ | CYS-INF-020 | 版本号单一来源 | 以 `VERSION` 为唯一真源；CMake 用 `configure_file`、Rust 用 `build.rs`、Go 用 `-ldflags -X`、前端用 `vite define` **已落地**（`64f4079`：真源定为 `0.1.0`，四端全部改为派生，根 `VERSION` 不再与 `Cargo.toml`/`package.json` 各写一份）。**每条派生链都补齐了易漏的细节**：Rust `build.rs` 声明 `cargo:rerun-if-changed=<根 VERSION>`（不声明的话改了真源产物版本号不变，正是「单一真源失效」最难察觉的表现），且**读不到真源直接 panic 而不是回落占位值**；CMake 侧 `version.h` 由 `configure_file` 生成（**不入库**，仓库里只有 `version.h.in`）；Go 侧 `-ldflags` 必须写全包路径（符号写错 Go 链接器**静默忽略**，构建成功但 `-version` 打印 `dev` —— 典型假绿）；前端 `vite define` 注入 `__APP_VERSION__`，`version.test.ts` 直接读根 `VERSION` 比对而非写死期望值。 | 改动 `VERSION` 后四个产物版本号同步变化 **已达成（产物级实测，不是看源码推断）**：`scripts/release/check-version-bump.sh` 把真源临时改成 `0.1.1` 后**重新构建四端**，`cythsec-analyze --version` / `policyd -version` / `hello_packet --version` / 前端 vite 产物各报 **0.1.1**，随后自动复原真源并复核；同一状态下 `check-version.sh` 必须**判红并点名 `Cargo.toml`**（改了真源没同步副本能被抓出）。**未达成**：`bump-version.sh`（一条命令同步四处 + 生成 CHANGELOG 占位）仍是 `CYS-INF-022` | — | P1/M |
| ☑ | CYS-INF-021 | 版本自检脚本 | `scripts/release/check-version.sh` 校验四处版本一致 **已落地且已挂门禁，并且终于真的入库了**：A 类副本（根 `Cargo.toml`、`web/console/package.json`）逐字比对真源；B 类派生点（packet-engine `CMakeLists.txt`、traffic-engine `Cargo.toml`/`build.rs`、`build-all.sh`、`vite.config.ts`）校验「既无硬编码字面量、又确实引用了真源」。**两个坑都是"检查器等于没有"的变体**：① 它此前**没有任何门禁调用** —— 于是 `2ecf512` 把真源改成 `9.9.9` 时 lint/test 全绿；② 它所在目录被 `.gitignore` 的 `release/`（无前导斜杠，匹配任意层级）整个忽略，**脚本从未入库**：README 与交接文档都在引用它，`git status` 却看不见，全新克隆里根本没有这个文件。现两处都已修（真实校验 + 自证挂成 `lint-all.sh` 第 6 条；`.gitignore` 改为 `/release/`，两份脚本入库）。 | 不一致时非 0 退出并指出位置 **已达成并加了反向注入**：`--self-test` 在临时目录里搭最小仓库树，先要求「一致 → 退出 0」（防诬告），再注入 **3 处不一致**（`Cargo.toml` 版本漂移 / `CMakeLists.txt` 硬编码 `9.9.9` / `build.rs` 注入实现被删空），要求**分别判红且输出里点名对应文件**；`scripts/release/check-version-bump.sh` 再在**真树**上把真源改成 `0.1.1` 验证判红。教训（已写进 `HANDOFF.md` §5 第 3 条）：注释/文档里声称「有脚本会拦下」的，该脚本必须真实存在、**在版本控制里、并挂在门禁上** —— 三条缺一条都等于没有 | CYS-INF-020 | P1/S |
| ⬜ | CYS-INF-022 | 版本递增脚本 | `scripts/release/bump-version.sh <semver>` | 一条命令完成四处同步 + 生成 CHANGELOG 占位 | CYS-INF-020 | P2/S |
| ☑ | CYS-INF-023 | Rust 锁文件入库 | 从 `.gitignore` 移除 `Cargo.lock` 并提交（应用类工程应锁定依赖） | `Cargo.lock` 出现在版本控制中 | — | P0/S |
| ⬜ | CYS-INF-024 | Go 依赖锁定策略 | 明确各服务是否共享 `go.sum`；为后续引入 `netlink` 等依赖预留 | `go mod verify` 通过 | — | P1/S |
| ⬜ | CYS-INF-025 | 构建产物归档 | CI 归档四语言产物并附 `SHA256SUMS` | 每次 tag 构建产出可校验压缩包 | CYS-INF-001 | P2/M |
| ⬜ | CYS-INF-026 | CHANGELOG 体系 | `CHANGELOG.md` 遵循 Keep a Changelog，按里程碑分节 | 发布 tag 时自动追加 | CYS-INF-022 | P2/S |
| ⬜ | CYS-INF-027 | 第三方许可清单 | `NOTICE` 汇总各语言依赖许可证；GO-1 专有许可边界说明 | 无 GPL 传染性依赖未经确认引入 | — | P2/M |
| ⬜ | CYS-INF-028 | 依赖漏洞扫描 | `govulncheck` / `cargo audit` / `npm audit` 纳入 CI（允许白名单） | CI 中可发现已知 CVE | CYS-INF-001 | P1/M |
| ⬜ | CYS-INF-029 | CBOM/SBOM 产出 | 使用 Syft 或 `cyclonedx` 生成 SBOM 并归档 | 每次发布附 SBOM 文件 | CYS-INF-028 | P2/M |
| ⬜ | CYS-INF-030 | 工具链版本钉扎 | `.tool-versions` 或文档化最低版本；CI 与本地一致 | 本机与 CI 构建结果一致 | CYS-INF-004 | P1/S |
| ⬜ | CYS-INF-031 | 构建可重现性验证 | 同 commit 两次构建产物哈希一致（Rust/C++ 分别验证） | 哈希一致或记录差异原因 | CYS-INF-025 | P3/M |
| ⬜ | CYS-INF-032 | release 工作流 | `.github/workflows/release.yml`：tag 触发、四语言构建、产物附件 | 打 tag 后自动产出 Release | CYS-INF-025 | P2/M |
| ⬜ | CYS-INF-033 | 本地 CMake 预设 | `CMakePresets.json` 覆盖 Debug/Release/ASan/TSan | CLion 直接选用预设即可 | — | P2/S |
| ⬜ | CYS-INF-034 | 前端包管理器钉扎 | `package.json` 增加 `packageManager` 字段并启用 `npm ci` 锁定 | 安装结果跨机器一致 | — | P2/S |
| ☑ | CYS-INF-035 | 仓库完整性自检（被 `.gitignore` 吃掉的源码） | `scripts/verify/check-ignored-sources.sh`：扫描 `git ls-files --others --ignored --exclude-standard` 里的源码/脚本类文件，命中即报错并打印是哪条 ignore 规则吃掉了它；已挂 `lint-all.sh` 的 `[repo]` 一项。**背景是本批一次踩出三处**：不带前导斜杠的 `build/` / `target/` / `release/` 会匹配**任意层级**同名目录，于是 `scripts/release/`（版本自检脚本）、`scripts/build/build-all.sh`（四端构建入口）、`services/telemetryd/internal/target/`（telemetryd 直接 import 的 Go 包，4 文件）三者被整体忽略、从未入库；本地全部跑得通、`git status` 全不提示，但全新克隆里缺文件（`go build ./...` 直接报 `package … is not in std`）。规则已全部锚定到根并把三处文件入库。 | 没有源码/脚本被静默忽略 **已达成，且判据本身经过真实反向验证**：修复前该脚本在原树上**判红并逐条打印**命中文件与命中规则（`scripts/build/build-all.sh` → `.gitignore:2:build/`；四个 Go 文件 → `.gitignore:30:target/`），修复后转绿；另有全新克隆复核（`check-version.sh` 曾报 `scripts/build/build-all.sh: No such file or directory`、`telemetryd` 编译失败，现均通过）。白名单（生成物 / 依赖 / 本地工具状态）逐条写明理由，每条都锚定到根或显式标注「任意层级」，避免白名单自己再犯同一个错 | — | P1/S |

---

#### 3.1.4 技术债与现存缺陷（`DBT`）

> 以下问题均经 2026-09-14 实测确认，非推测。

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ☑ | CYS-DBT-001 | 修复 Go 格式差异 | `gofmt -w services/`；涉及 `internal/netinfo/interfaces.go`（`PointToPoint` 字段对齐）、`internal/netinfo/routes.go` | `gofmt -l services/` 输出为空 | — | P0/S |
| ☑ | CYS-DBT-002 | 修复 Rust 格式差异 | `cargo fmt`；涉及 `src/flow/mod.rs`（`new_ipv4` 签名折行）、`src/session/mod.rs`（行尾注释对齐） | `cargo fmt --check` 零差异 | CYS-INF-013 | P0/S |
| ◐ | CYS-DBT-003 | 消除 `Proto` 死代码 | `traffic-engine/src/flow/mod.rs` 定义了 `Proto` 枚举但 `FlowKey.proto` 为裸 `u8`，枚举从未被使用 **已落地**：`Proto` 已被 `FlowKey`、解析入口与流表键真正使用（枚举不再是死代码），由 CYS-TRF-004 修复并回写。 | `Proto` 被真正使用，或删除；`cargo clippy -- -D warnings` 通过 **未达成**：`cargo clippy -- -D warnings` 全仓通过（仓库仍有既有 warning，且 clippy 尚未入门禁）。 | CYS-TRF-004 | P1/S |
| ⬜ | CYS-DBT-004 | 消除时间戳哨兵歧义 | `session/mod.rs` 用 `started_at_us == 0` 判定「未开始」，与合法时间戳 0 冲突；改用 `Option<u64>` 或显式 `Clock` | 新增测试覆盖 `timestamp_us = 0` 的包 | — | P1/S |
| ☑ | CYS-DBT-005 | 修复前端 `npm run lint` | `package.json` 声明 `lint: eslint .` 但 `eslint` 不在 `devDependencies`，命令必然失败 | `npm run lint` 可执行 | — | P0/S |
| ☑ | CYS-DBT-006 | 处理悬空 `components.json` | `web/console/components.json` 引用不存在的 `tailwind.config.js`，且 `tailwindcss` 未安装；二选一：真正接入 shadcn/ui + Tailwind，或删除该文件 | 无悬空配置引用 | — | P0/S |
| ☑ | CYS-DBT-007 | 修复 `vitest` 空跑 | `vitest` 已在 `devDependencies`，但 `web/console/tests/` 仅 `.gitkeep`，零测试文件 | `npm test` 至少跑通 1 个真实用例 | CYS-CON-005 | P1/S |
| ☑ | CYS-DBT-008 | 处理死配置文件 | `services/routerd/configs/config.yaml` 存在但代码从不读取（仅用 `-addr` flag）；接入或删除 | 配置文件生效或移除 | CYS-RTD-006 | P1/S |
| ☑ | CYS-DBT-009 | 版本号未连通 | 根 `VERSION` 文件未被任何构建系统消费，四处版本号各自硬编码 **已消除**：四端构建系统均消费根 `VERSION`（C++ `configure_file` / Rust `build.rs` / Go `-ldflags -X` / 前端 `vite define`），产物级实测见 `CYS-INF-020`。 | 由 CYS-INF-020 覆盖 **已满足**：`CYS-INF-020` 已 ☑ 并给出四端产物实测 | CYS-INF-020 | P1/S |
| ⬜ | CYS-DBT-010 | README 与实际结构漂移 | README 称 `traffic-engine` 以 `crates/`（flow/session/...）组织且有 `tests/`，实际为 `src/flow/mod.rs` + `src/session/mod.rs`，无 `tests/` | README 描述与实际目录一致 | CYS-TRF-001 | P1/S |
| ☑ | CYS-DBT-011 | README 声称 CI 但无 `.github` | README 第 179 行描述 `.github/workflows/`，实际目录不存在 | `.github/workflows` 落地 | CYS-INF-001 | P0/S |
| ☑ | CYS-DBT-012 | 非优雅关闭 | `routerd/cmd/routerd/main.go` 使用 `srv.Close()`（立即断开在途请求）而非 `srv.Shutdown(ctx)` | 关闭时在途请求正常完成 | CYS-RTD-003 | P1/S |
| ☑ | CYS-DBT-013 | 补齐 `.gitignore` 例外文件 | `!datasets/samples/README.md` 白名单指向的文件不存在。**处置：移除该行**（卡片给的第二个选项）—— `datasets/samples/` 下只有 `.gitkeep`，全仓无任何脚本/文档引用这份 README；而且它本来就**不会**被忽略（datasets 下只忽略 `*.json/*.pcap/*.pcapng/*.parquet/*.csv`），留着这行只会让人以为有份白名单在起作用。原位留注释说明，避免下次有人再补一行。 | 文件存在或移除该行 **已达成**（移除该行，并留注释写明原因） | — | P3/S |
| ⬜ | CYS-DBT-014 | CMake 全局变量污染 | 根 `CMakeLists.txt` 与子工程均设置 `CMAKE_CXX_STANDARD`；确认无 target 级覆盖需求 | 使用 `target_compile_features` 显式声明 | — | P2/S |
| ⬜ | CYS-DBT-015 | `ml/inference` 空骨架告警 | 当前无源码时退化为 INTERFACE 库并打印 message，属临时方案 | 有真实源文件后删除该分支 | CYS-MLI-001 | P2/S |
| ☑ | CYS-DBT-016 | CLion 构建目录入库风险 | `cmake-build-debug/` 已在 `.gitignore` 内，确认未被追踪。**本批复核**：规则已锚定为 `/cmake-build-*/`（原 `cmake-build-*/` 同样会匹配任意层级，属同类风险）。 | `git ls-files cmake-build-debug` 为空 **已达成**：实测输出为空（该目录里只有构建产物，且其中的产物版本号还是旧值 9.9.9，见 `HANDOFF.md` §7.6） | — | P3/S |
| ☑ | CYS-DBT-017 | Go 服务间无共享库 | `routerd`/`policyd`/`dnsd`/`telemetryd` 为独立 module，无共享 `pkg`，模型与 envelope 将重复实现 | 建立 `services/pkg` 或 `internal/shared` 共享模块 | — | P1/M |
| ☑ | CYS-DBT-018 | API 契约无版本化机制 | `envelope` 注释已提「预留 future 的 code/error 结构」但未实现；无 `code` 字段 | envelope 含 `code`，旧客户端兼容 | CYS-RTD-006 | P1/S |
| ⬜ | CYS-DBT-019 | 缺少统一错误码字典 | 各服务 `writeErr` 只传字符串，无机器可读错误码 | 建立错误码表并文档化 | CYS-DBT-018 | P2/M |
| ⬜ | CYS-DBT-020 | 无结构化日志 | `routerd` 用标准库 `log`，无级别、无字段、无 request id | 切换至 `log/slog` 并输出 JSON | CYS-RTD-002 | P1/M |

---

### 3.2 M2 — 数据平面真实收包

#### 3.2.1 packet-engine 缓冲与队列基座（`PKT`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-PKT-001 | 真实 `PacketBuffer` 类型 | `include/packet_engine/buffer.h`；替代 `struct Packet { uint8_t data[16]; }`；含 `data` 指针、`len`、`caplen`、`headroom`、`ifindex`、`timestamp`、引用计数 | 单元测试覆盖生命周期与引用计数 | — | P0/M |
| ⬜ | CYS-PKT-002 | 内存池 | `src/buffer/pool.cpp`；固定块大小、预分配、无锁 freelist（`std::atomic` CAS 或 per-CPU 池） | 10M 次 alloc/free 无泄漏（ASan 通过） | CYS-PKT-001 | P0/M |
| ⬜ | CYS-PKT-003 | 环形队列 | `src/buffer/ring.h`；SPSC 与 MPSC 两版，cache-line 对齐避免伪共享 | 单生产者单消费者压测达到预期吞吐 | CYS-PKT-002 | P0/M |
| ⬜ | CYS-PKT-004 | 批量收包 API | burst 语义：`rx_burst(void** pkts, uint32_t max)` / `tx_burst(...)` | 接口冻结并文档化 | CYS-PKT-003 | P0/S |
| ⬜ | CYS-PKT-005 | 后端接口抽象 | `include/packet_engine/backend.h`；`open/close/rx_burst/tx_burst/stats/getfd` 纯虚接口 | `pcap`/`af_packet`/`xdp` 三者均实现该接口 | CYS-PKT-004 | P0/M |

#### 3.2.2 收包后端（`PKT`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ☑ | CYS-PKT-006 | pcap 文件后端 | `src/backends/pcap_file.cpp`；libpcap 离线读取，用于回放与离线单测；支持 `-r file.pcap` CLI | 能完整读完 `datasets/pcap/` 样本且计数正确 | CYS-PKT-005 | P0/M |
| ◐ | CYS-PKT-007 | pcap 实时后端 | libpcap live capture（兼容模式，非零拷贝，作为兜底与对照基线）。**语义偏离需说明**：本机 macOS 无 libpcap（`/usr/lib/libpcap*` 与 SDK 均无），故以**原生 BPF** 实现等价能力 —— `src/backends/bpf_capture.cpp`（`/dev/bpf0..255` 逐个尝试、`BIOCSBLEN` 后**回读实际值**、`BIOCSETIF`/`BIOCIMMEDIATE`/`BIOCPROMISC`、`bpf_hdr` 20 字节与 `BPF_WORDALIGN` 步进）。Linux 侧 libpcap live 仍未开始 | 已达成：macOS 无特权环境 73 项断言全过（含权限类错误的诊断文案与 `setcap`/`sudo` 提示）。**未达成**：macOS 真实抓包（`/dev/bpf*` 属 `root:wheel 600`、本机无免密 sudo），该路径在 e2e 中显式标 `SKIPPED` 而非显绿 | CYS-PKT-006 | P1/S |
| ✅ | CYS-PKT-008 | AF_PACKET 后端 | `src/backends/af_packet.cpp`；`TPACKET_V3` + `PACKET_MMAP` 环形缓冲、block 超时。**已落地**：V3→V2→`recvfrom` 探测降级链、环参数页对齐约束、`poll` 等待可读、promisc/ignore_outgoing/allow_fallback/环参数。**2026-10-05 第四段补齐**：① 采集档位可指定（`CaptureOptions.mode` = auto/v3/v2/recvfrom，CLI `--capture-mode`，**指定即严格不降级**，不支持的后端点名拒绝并让 CLI `exit 2`）；② **丢包运行中可查**（`stats()` 现场轮询 `PACKET_STATISTICS` 并累加、`--stats-every` 周期打印、socket/设备/softnet 三类丢包分开记账）；③ 确定性打流工具 `cythsec-inject`（仅 Linux，自报 sent/pps）。**验收标准修正**：原命题「吞吐显著高于 pcap live」**被实测否定** —— libpcap 1.10 的 live 路径自己就走 mmap 环，实测 L(11,088,260 包/1.46 s) ≈ V(10,126,401/0.99 s) ≈ P-v3(10,759,233/1.27 s)，每包 CPU 均 0.10~0.13 µs。修正为「**mmap 环显著优于拷贝模式**」并已实测：零丢包同负载下每包 CPU **5.9~6.3× 更省**（0.13~0.14 vs 0.81~0.82 µs，两次独立复跑）、饱和时同机端到端速率 **1.35×**、真实网卡（`enp2s0`，放开 `rmem_max`）拷贝档把整机容量砍到 **1.74×** 之一（165,924 vs 95,450 pps）。见 HANDOFF §2.10 |已达成（2026-10-05 第四段）：四发行版编译之外，容器四臂对照 + 真实网卡两档对照全部实跑；新增常驻测试 `packet_engine_capture_modes`（Linux 7/7，**含「小环+洪泛 ⇒ 丢包必须在 `close()` 之前可读」与「close 后是累加不是覆盖」**，三条断言各配反向注入：去掉运行中轮询→红、`+=` 改 `=`→红、去掉 BPF 档位拒绝→红）；**诚实边界**：Docker Desktop 是虚拟机、veth 是软件设备；真实网卡那臂是 TX→tap（非线上收包，真收包见 HANDOFF §2.7）；2 vCPU 绝对数不可比 |CYS-PKT-005 | P0/L |
| ⬜ | CYS-PKT-009 | AF_PACKET 多队列与分流 | `PACKET_FANOUT` 按 RSS/流哈希分流；队列数与 CPU 数对齐 | 多核线性扩展（≥ 0.7 线性度）。**2026-10-05 补量化理由**：离线路径的并行接线（`CYS-TRF-006`）实测**上限是派发端**（单线程读盘+解帧+分片+入队 = 2.33 Mpps，8 核封顶 2.53×）——「每核一张独立表」能让流表扩展，但只要有单线程派发端，整条流水线就到不了线速。多队列分流的价值因此被量化：它不只是「减少锁竞争」，而是**去掉那个派发端**（每 worker 自己读自己的队列并自己解帧），这也是 10G 总核预算里唯一还缺的一块 | CYS-PKT-008 | P1/M |
| ⬜ | CYS-PKT-010 | 收包线程 CPU 亲和 | 线程绑核 + `SO_INCOMING_CPU`；避免跨 NUMA 访问 | `perf` 显示无跨核迁移热点 | CYS-PKT-009 | P1/M |
| ⬜ | CYS-PKT-011 | XDP 程序骨架 | `xdp/xdp_main.c`；`XDP_PASS`/`XDP_DROP` 分流，编译为 `.o` 供 `ip link` 挂载 | 可挂载到 veth 并观测计数 | CYS-PKT-015 | P1/M |
| ⬜ | CYS-PKT-012 | eBPF map 与用户态交互 | `src/backends/xdp.cpp`；libbpf loader + `BPF_MAP_TYPE_PERCPU_ARRAY` 统计 | 用户态可读内核计数 | CYS-PKT-011 | P1/L |
| ⬜ | CYS-PKT-013 | AF_XDP 后端 | `src/backends/af_xdp.cpp`；UMEM、FILL/COMPLETION/RX/TX 四环、`XDP_USE_NEED_WAKEUP` | 达到百万级 PPS（在可用硬件上） | CYS-PKT-012 | P2/XL |
| ⬜ | CYS-PKT-014 | DPDK 后端 | `src/backends/dpdk.cpp`；EAL 初始化、`rte_mempool`、`rte_eth_rx_burst`；由 `ENABLE_DPDK` 开关控制 | 启用开关时方可编译，默认不引入 DPDK 依赖 | CYS-PKT-005 | P3/XL |
| ☑ | CYS-PKT-015 | 后端编译开关收敛 | 现有 `ENABLE_XDP`/`ENABLE_AF_XDP`/`ENABLE_DPDK` 仅做了 `add_subdirectory` 占位，需与实际源文件联动 | 开关 ON/OFF 均可 configure 成功 | — | P0/S |

#### 3.2.3 报文解析与分发（`PKT`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-PKT-016 | L2/L3/L4 解析器 | `src/parser/`：Ethernet（含 VLAN 栈）、IPv4、IPv6（含扩展头）、TCP、UDP、ICMPv6 | 对样本集解析零错误 | CYS-PKT-001 | P0/L |
| ⬜ | CYS-PKT-017 | 零拷贝解析约束 | 解析器只返回偏移与视图，不做数据拷贝 | 代码审查确认无 `memcpy` 数据体路径 | CYS-PKT-016 | P0/S |
| ⬜ | CYS-PKT-018 | 畸形包防护 | 截断包、异常 IHL/offset、超长选项的安全处理 | 模糊测试无越界（ASan） | CYS-PKT-016 | P0/M |
| ⬜ | CYS-PKT-019 | Jumbo frame 支持 | MTU > 1500 与超长帧处理 | MTU 9000 场景测试通过 | CYS-PKT-016 | P2/S |
| ⬜ | CYS-PKT-020 | 分发器 | `src/dispatcher/`；按流哈希分发到 worker 队列，保证同流同核 | 同流同核断言测试通过 | CYS-PKT-003 | P1/M |
| ⬜ | CYS-PKT-021 | RSS 配置管理 | `src/rss/`；查询/设置 indirection table，与 `platform/linux/ethtool` 联动 | 可读写 indirection table | CYS-PKT-020 | P2/M |
| ⬜ | CYS-PKT-022 | BPF 过滤器 | 编译并挂载 tcpdump 风格过滤器，提前丢弃无关流量 | 过滤器生效后 CPU 占用下降可观测 | CYS-PKT-008 | P1/M |
| ⬜ | CYS-PKT-023 | 统计接口 | PPS/BPS/丢包/错误/队列深度，按接口与队列维度 | 统计可被 telemetryd 抓取 | CYS-PKT-022 | P1/S |
| ☑ | CYS-PKT-024 | 与 traffic-engine 的通道契约 | 真源 `configs/registry/channel-abi.json` 冻结 ABI 版本号、布局常量与全部诊断；C++ 侧 `include/packet_engine/channel/{abi_gen.h,region.h,producer.h}` + `src/channel/{region,producer}.cpp`（SPSC 生产端），Rust 侧 `src/channel/{region,consumer,decode}.rs`（消费端）。三层防线全部落地：① 编译期断言（偏移/尺寸/`descriptor_step`），② 生成物新鲜度（`check-channel-abi.sh`），③ 跨语言 parity dump（`cythsec-dump-abi` ↔ `dump-abi`，`check-channel-parity.sh`） | 双端各自单测通过（CTest 5/5：`channel_abi` + `channel_producer`；`cargo test` 48 passed）；ABI 版本不匹配时报 `chan.abi_version_mismatch`；parity 两端 89 行逐字一致；`descriptor_step == sizeof(PacketDescriptor)` 有生成期断言守护 | CYS-PKT-023 | P0/L |
| ⬜ | CYS-PKT-025 | C++ 测试框架升级 | 引入 Catch2 或 Google Test（替换裸 `check()`），同时保留零依赖构建选项 | 测试可分组、可筛选、可输出 JUnit XML | — | P1/M |
| ⬜ | CYS-PKT-026 | 静态分析接入 | `clang-tidy` 配置 + CI 强制执行 | 无 error 级告警 | CYS-INF-002 | P1/M |
| ⬜ | CYS-PKT-027 | 内存/UB 检测构建 | ASan + UBSan 构建预设，纳入 CI | 全测试在 ASan 下通过 | CYS-INF-033 | P1/M |
| ⬜ | CYS-PKT-028 | 线程检测构建 | TSan 预设（针对 dispatcher/ring 并发） | 无 data race 报告 | CYS-PKT-027 | P2/M |
| ⬜ | CYS-PKT-029 | 微基准框架 | `bench/`：收包吞吐、解析延迟、池分配延迟；输出可比较的 JSON | 基准结果可跨 commit 对比 | CYS-PKT-025 | P2/M |
| ◐ | CYS-PKT-030 | CLI 能力扩展 | 现有 `hello_packet` 保留为冒烟；新增 `cythsec-capture` CLI（`-i`、`-r`、`-f` 过滤、`-n` 计数、`-w` 落盘）。**已落地**：`--list-ifaces` / `--list-backends` / `-i` / `-n` / `--timeout` / `-w` / `--promisc` / `--quiet`，统一后端工厂按平台路由（`live` → Linux `af-packet` / macOS `bpf`）。**未落地**：`-f` 过滤（依赖 CYS-PKT-022 BPF 过滤器） | 已达成：接口枚举 27 个、CLI 各子命令实测通过、产物 `-w` 落盘可被 tshark 打开。**未达成**：`-f` 过滤；「命令可实际抓包」**Linux 侧已达成**（2026-10-05，`cythsec-capture -i enp2s0` 参与真机 e2e 采集），macOS 侧仍受 `/dev/bpf*` 权限阻塞（见 CYS-PKT-007） | CYS-PKT-006 | P1/M |
| ⬜ | CYS-PKT-031 | 文档与注释 | `docs/dataplane/packet-engine.md`：架构、后端对比、性能数据 | 文档含实测数据表 | CYS-PKT-029 | P2/M |

#### 3.2.4 采集抽象（`CAP`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-CAP-001 | pcap 采集示例 | `capture/pcap/`：libpcap 抓包最小程序 + Makefile | 可独立编译运行 | CYS-PKT-006 | P1/S |
| ✅ | CYS-CAP-002 | af_packet 采集示例 | `capture/af_packet/`：AF_PACKET 抓包至 pcap 文件 | 产物可被 Wireshark 打开 | 已达成（2026-10-05）：验收标准**此前其实不成立** —— 该示例的 pcap 全局头把 `ver_major/ver_minor` 各写成 4 字节（应各 2 字节），整块后移 4 字节导致 `network` 字段读出来是 snaplen（tshark 报 `network type 2112 unknown`），任何第三方工具都打不开。同时修掉 `tp_mac` 当块内偏移（实测 packets=8 却 bytes=6.28e9）与 `tp_next_offset` 当绝对偏移（带负载直接崩）。修后由对照脚本用 **tshark 逐臂复核**：V 臂 10,126,401 帧 == 自报落盘数。见 HANDOFF §2.10 | CYS-PKT-008 | P1/S |
| ⬜ | CYS-CAP-003 | xdp 挂载脚本 | `capture/xdp/`：`attach.sh` / `detach.sh`，含 veth 拓扑搭建 | 脚本幂等、可重复执行 | CYS-PKT-011 | P1/S |
| ⬜ | CYS-CAP-004 | af_xdp 采集示例 | `capture/af_xdp/` | 能收包并统计 | CYS-PKT-013 | P3/S |
| ⬜ | CYS-CAP-005 | dpdk 采集示例 | `capture/dpdk/` + 环境准备说明（hugepages、vfio） | 文档化前置条件 | CYS-PKT-014 | P3/M |
| ⬜ | CYS-CAP-006 | 统一采集 CLI | 一个入口按 `--backend` 选择后端 | 四个后端行为一致 | CYS-CAP-001~005 | P2/M |
| ⬜ | CYS-CAP-007 | 采集 README | 各后端适用场景、权限要求、性能对比 | 含决策树 | CYS-CAP-006 | P2/S |

---

### 3.3 M3 — 流量分析深化

#### 3.3.1 工程结构对齐（`TRF`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-TRF-001 | 重构为 cargo workspace | `dataplane/traffic-engine/crates/{common,flow,session,reassembly,protocol,dpi,feature,behavior,risk}`；根 `Cargo.toml` 的 `members` 同步更新。**【顺序决策】为何先落 DPI、暂不拆 workspace**：拆分本身不产生任何新的识别能力，只是挪目录；而 DPI 是「省网级流量分析」需求的关键路径。当前在单包内以 `src/dpi/`（与 `flow`/`session`/`channel` 同级）把算法与测试向量做实，待本任务执行时是**纯目录搬移**（模块边界已按 crate 语义划分好）。反向顺序（先拆九个空 crate 再填实现）会让跨 crate 的裁决语义长期无法统一 | 结构与 README 描述一致；`cargo build` 通过 | — | P1/L |
| ⬜ | CYS-TRF-002 | 错误类型体系 | `crates/common`：`thiserror` 定义 `TrafError`，统一 `Result`；禁止 `unwrap()` 出现在非测试路径 | `cargo clippy -D clippy::unwrap_used` 通过 | CYS-TRF-001 | P1/M |
| ⬜ | CYS-TRF-003 | 时间与时钟抽象 | `crates/common::clock`：`Clock` trait + `MonotonicClock`/`TestClock`，替换 `timestamp_us: u64` 哨兵 | 时间相关测试可确定性注入 | CYS-DBT-004 | P1/M |
| ☑ | CYS-TRF-004 | 协议number 类型化 | 用 `Proto` 枚举（或 `num_enum`）替换裸 `u8`，与 IANA 号对齐 **已落地**：`flow::Proto` 类型化枚举（`from_u8` / `number` 双向映射），解析入口、`FlowKey`、流表键全部走 `Proto` 而非裸 `u8`；`Display` 刻意打印 IANA 号（`scripts/verify/e2e-shared-ring.sh` 按该格式解析）。 | 无死代码；`Proto::from(6) == Proto::Tcp` 已达成：`Proto::from_u8(6) == Proto::Tcp` 由单测锁定（往返映射 + 未知号走 `Other`）。 | — | P1/S |
| ☑ | CYS-TRF-005 | 规范化五元组 | `canonical()` 方法：无论方向，产出稳定排序的会话键 **已落地**：`FlowKey::canonical()` 产出方向无关的会话键（先比 IP 字节序、再比端口）。 | 双向包映射到同一 canonical key（属性测试） 已达成：双向包映射到同一 canonical key（单测 + `tests/pipeline_sample.rs::canonical_keys_are_direction_independent`）；`--flows` 门禁里 tshark 侧按同一排序规则独立聚合，逐流比对（见 CYS-TRF-035）。 | CYS-TRF-004 | P0/S |

#### 3.3.2 流表与会话（`TRF`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ◐ | CYS-TRF-006 | 分片 FlowTable | `crates/flow`：按哈希分片的 `HashMap<FlowKey, FlowEntry>`，分片数与 worker 数对齐，减少锁竞争 **已落地**：`flow::table::FlowTable` 按 FNV-1a 哈希分片（分片数向上取 2 的幂且不超过 `max_flows`），每片独立 `HashMap`（FNV-1a，`BuildHasherDefault`），**确定性顺序由显式排序给出**（`sorted_keys()` / `entries_sorted()` / `into_entries_sorted()`），不依赖哈希表迭代顺序 —— 可复现是门禁前提，但**不是靠改用 BTreeMap 换来的**（早前条目写成 `BTreeMap`，与实现不符，此处更正）。**已量化（CYS-TRF-037）**：1M 条**全新进程同配置**实测 **0.97 KB/条**（槽位 448B + 键表约 50B + IAT 环形缓冲 512B），单线程 insert **2.06** Mops/s、update **5.6** Mops/s、query-hit **5.0** Mops/s、query-miss **13.8** Mops/s。**10G 差距已用实验定位并选定路线（本批）**：单实例稳态 update 6.9~8.6 Mops/s = 需求的 46~58%；**多实例分核实验**（N 张独立表各占一线程）实测 2 核聚合 13.4~15.3 Mops/s（压线）、4 核 22.6~26.2（= 需求的 1.5~1.8 倍，效率 0.71~0.95）、8 核 28.0~34.8（效率 0.42~0.63）。**结论：走"每核一张独立表"，核预算取 4 核/10G 口**；8 线程不再近线性但**不是表内共享瓶颈**（同机纯计算对照也只有 0.54~0.73，故判据用比值：实测 0.55~0.92）。**连带发现**：`FlowTable` 原先不是 `Send`（观察者 `Box<dyn FlowObserver>` + 测试里用 `Rc`），"每核一张表搬进 worker 线程"根本无法表达；已改为 `Box<dyn FlowObserver + Send>` 并加编译期断言。**2026-10-05 第二段：离线流水线已接线**（`cythsec-analyze --workers N`，详见 `CYS-TRF-035` 与 HANDOFF §2.8）：每 worker 私有流表/会话/特征/DPI 探针（零共享、无锁），`workers=1` 走就地路径保持历史行为逐字不变，`workers>1` 输出与 `workers=1` **逐字节一致**（派发端按首次出现顺序统一分配会话 id）。**整条流水线的总核预算已量出**：91.4 万包/271 MB 上单核 0.918 Mpps，4/8 worker 加速 2.47×/2.53×，**上限是派发端（读盘+解帧+分片+入队）2.33 Mpps**，worker 侧总工作量 0.603 s —— 即 **10G 最坏帧（64B/14.88 Mpps）只覆盖 16%，且这部分差距不能靠加核解决**（16 档已回落）。要线性必须让"读包+解帧"也分掉 → 每队列一环，即 `CYS-PKT-009`。**未达成**：在线路径（`ring-consume`）仍是单表单线程。**本批的结构性取舍**：为把逐出从 O(每分片容量) 降到 O(1)，条目从"内联在 1.14× 过分配的哈希桶里"改为"槽位数组 + 4B 下标"（`Shard { map: FnvMap<FlowKey, u32>, slots: Vec<Slot> }`）—— 换来逐出 O(1)（52µs → 0.34µs @每片8192）、插入快一倍、内存减半（2390 → 970 B/条），代价是命中路径多一次间接寻址（query-hit 7.68 → 5.02 Mops/s，−35%）；update 在噪声内。同机背靠背对比见 `CYS-TRF-037` 条目。 | 1M 并发流插入基准达标 **已达成**：1M 条可容纳（约 1GB）且插入速率 2.06 Mops/s 已达到「新建流速率」目标（1 Mops/s，按 1M 容量 / 60s 瞬态超时推导；**逐包速率不是新建流速率**，拿 14.88 Mpps 去要求插入属于口径错误）。**已达成（2026-10-05 第二段）**：**离线消费路径已接线** —— `cythsec-analyze --workers N`，每 worker 私有表/会话/特征，N>1 与 N=1 输出逐字节一致（`cargo test` 常驻断言）。**未达成**：① 在线消费路径 `ring-consume` 仍是单表单线程（按队列分环属 `CYS-PKT-009`）；② 整条流水线的吞吐上限已量出是**派发端**（2.33 Mpps ≈ 10G 最坏帧的 16%），**加核解决不了**。 | CYS-TRF-005 | P0/L |
| ◐ | CYS-TRF-007 | 流超时老化 | TCP established / TCP transient / UDP / ICMP / default 五档超时表（可配置） **已落地**：五档超时表（TCP established / TCP transient / UDP / ICMP / default）可配置，`expire(now)` 按档回收并触发 `on_timeout`；`TimeWait` 刻意复用 transient 档（理由在源码：TIME_WAIT 期间几乎不再有包）。**本批修掉一处真实缺陷**：`expire()` 原本把全部到期条目搬进一个 `Vec<FlowEntry>`（每条 432B）排序后派发，临时内存随条目数线性增长；250k 条的「填满→全到期」每轮让进程 RSS 抬升 99MiB 且不保证回落，直接违反本条的「无内存增长」。改为只收**键**（每条 40B）、按全局键序逐条删除并派发后，回调顺序（全局按键升序）与逐出语义不变，RSS 增量降到 +6MiB/轮、超时扫描 1.62 → 2.50 M 条/s；唯一可观察差异是「回调期间表里可能仍留有尚未派发的到期条目」（旧实现先删完再派发），已在源码注明并接受。**已量化（CYS-TRF-037）**：定容 1M 条后灌 5× 容量个包（5M 包）**RSS 增量 0 MiB**；「填满→全部到期」churn 的逐轮 RSS 增量从 **+99 MiB/轮 降到 +6 MiB/轮**（本批修掉 `expire()` 持有的 O(条目数) 临时 `Vec<FlowEntry>`，见左栏描述）。**未达成**：小时级长稳曲线 —— 本批只跑到 12 轮，残余 +6 MiB/轮（分配器不归还小块，逻辑活跃条目恒为 0，非逻辑泄漏），不足以宣称「长稳」。 | 超时流被正确回收；无内存增长 **已达成**：各档超时回收、不误杀活动流的单测；定容灌包 RSS 不增长（0 MiB）；全表到期后 RSS 不再按条目数抬升。**未达成**：小时级长稳观测。 | CYS-TRF-006 | P0/M |
| ☑ | CYS-TRF-008 | 逐出策略 | 流表容量上限 + LRU/随机逐出，逐出时触发 `on_evict` 回调 **已落地**：容量上限 + 逐出触发 `on_evict`。**本批把逐出从 O(每分片容量) 改成 O(1)（仍是精确 LRU）**：分片内用**槽位数组 + 双向链表**维护活动序（`Shard { map: FnvMap<FlowKey, u32>, slots: Vec<Slot>, free, head, tail }`）—— 插入挂尾、命中移尾、逐出摘头，全是 O(1)，不需要扫描任何候选。旧的全扫实现保留为 `EvictPolicy::LruScan`（对照 + 小表/离线复算用），`EvictPolicy::Lru`（链表）是默认。**复杂度成了可测断言**：`TableStats::evict_candidates` 累计"逐出时考察过的候选数"，单测要求链表策略**恒为 0**、扫描策略恰好 `每片容量 × 逐出次数`。**语义只差一处并已文档化**：时间戳相同时旧实现按最小键打破平局，链表按"谁更晚被访问"（链表本身即全序，且更贴近 LRU 本意）；`list_lru_and_scan_lru_choose_the_same_victims` 在时间戳严格递增的轨迹上断言两种实现的**逐出序列与存活集合完全一致**。**被实测否掉的方案**：Redis 式采样 LRU（K=8）在合成负载上只有 58.4% 热点命中率（精确 LRU 99.9%），省网里"流被逐出又重建"会把同一条会话的记录切成两段 —— 不划算，理由写进 `EvictPolicy` 注释。 | 达到上限时内存稳定 已达成：容量触发 / 逐出选择 / 回调时序单测；`--max-sessions` 生效由 `tests/pipeline_sample.rs::limit_and_session_capacity_are_honoured` 锁定（上限 2 → 逐出 3、留 2 条记录）。**本批新增 9 项单测**：默认策略 = 链表 LRU、链表逐出考察 0 候选、扫描逐出考察整片、链表与扫描逐出序列一致、大分片里逐出全局最老者（采样式会在此失败）、同时间戳按访问序、槽位复用（数组不随累计插入增长）、`clear()` 复位链表且保留容量、热点流命中率 ≥95%。 | CYS-TRF-007 | P0/M |
| ☑ | CYS-TRF-009 | 流生命周期回调 | `on_new` / `on_update` / `on_evict` / `on_timeout`，供特征与存储消费 **已落地**：`FlowObserver` 四个钩子（`on_new` / `on_update` / `on_evict` / `on_timeout`）。回调只拿 `&FlowEntry`（**不可改流表**）—— 回调里改状态会让门禁结果取决于回调实现，可复现性优先；`NoopObserver` 用来区分「没人订阅」与「显式置空」。 | 回调时序测试通过 已达成：回调时序（新建 → 更新 → 逐出/超时）单测。 | CYS-TRF-008 | P1/M |
| ☑ | CYS-TRF-010 | 会话 id 分配器 | 单调递增 + 复用池；替换 `Session::new(id, ...)` 的手工传参 **已落地**：`session::SessionIdAllocator`（单调递增 + 复用池，`release` 后最小 id 优先复用）；`Session::new` 不再手工传 id。 | 高并发下无重复 id 已达成：分配 / 释放 / 复用不重复 id 的单测。**未达成**：多线程并发分配（分配器由 `SessionManager` 单线程持有，跨线程语义尚未定义）。**2026-10-05 部分推进**：离线分片模式把 id 分配**上移到派发端**（worker 侧不需要并发分配器，id 与 worker 数无关，见 HANDOFF §2.8）；但**在线多队列**要"全局唯一 id"还是"每队列独立 id + 队列号前缀"仍未定 —— 前者需要一个跨队列分配器（回到锁），后者会让同一个 id 在不同队列上重复出现。 | CYS-TRF-006 | P1/S |
| ☑ | CYS-TRF-011 | 会话管理器 | 双向流聚合、反向 key 自动规范化、会话超时与销毁 **已落地**：`session::SessionManager` 双向流聚合成会话、反向键规范化、按 `SessionConfig` 超时销毁；**先见响应、后见 SYN** 也能正确归属（`initiator` 由 SYN 方向决定，而非由首包决定）。 | 乱序到包（先见响应）也能正确归属 已达成：乱序到包归属 / 双向合并 / 超时销毁 / id 复用单测；`--flows` 门禁用 tshark 的会话集合反向核对（多一条、少一条都红）。 | CYS-TRF-010 | P0/M |
| ☑ | CYS-TRF-012 | TCP 状态机完整版 | SYN、SYN-ACK、ACK、FIN/FIN-ACK、RST、超时、`TIME_WAIT` 简化；替换现有「双向有包即 Established」启发式 **已落地**：`tcp::TcpState` 状态机（SYN / SYN-ACK / ACK / FIN / FIN-ACK / RST / TIME_WAIT 简化），非法迁移计数而不 panic，严格与容忍两模式。**本轮修掉一个真实缺陷**：分流事件原先用 IP 载荷长度（含 20 字节 TCP 头），于是每个纯 ACK 都被判成 `Data`；容忍模式下碰巧仍能走到 `Established`/`TimeWait`（这正是旧测试全绿的原因），严格模式下则停在 `syn_received` 且 `FinWait2`/`CloseWait`/`LastAck` 不可达。已引入 `TcpObservation{flags, l4_payload_len}` 把「段载荷长度（不含头）」与「记账用的 IP 载荷长度」显式分开，并补两个回归测试（纯 ACK 的 20 字节 IP 载荷必须判 `Established`；完整关闭序列必须经 `FinWait2` 到 `TimeWait`）。**未达成**：超时驱动的状态迁移（当前只有流级超时回收）。 | 状态迁移测试覆盖全部合法路径 + 非法路径拒绝 已达成：全部合法路径 + 非法路径拒绝单测（290 个 lib 测试）；`--flows` 门禁用 tshark 的标志位序列**独立重写第二实现**核对末态 / 发起方 / 中途接入，且容忍与严格两模式各核一遍。**未达成**：超时状态迁移。 | CYS-TRF-011 | P0/L |
| ◐ | CYS-TRF-013 | TCP 状态机可配置 | 超时参数、是否严格模式（容忍丢包环境） **已落地**：`tcp::TcpConfig{strict, ...}` 与 `SessionConfig{table, tcp, max_sessions, id_start}` 全部可配置，`AnalyzeOptions::strict()` 供 CLI 切换。**未达成**：真实丢包环境下的参数标定（没有真实样本，就不给默认值之外的结论）。 | 配置化后行为可测 已达成：严格 / 容忍两模式行为可测（同一份样本，两种期望值都由 tshark 事实推出）。**未达成**：参数标定。 | CYS-TRF-012 | P2/S |
| ☑ | CYS-TRF-014 | 流统计扩展 | 现有 `packet_count`/`total_bytes` 之外：`min/max/mean` 包长、包长直方图、IAT 序列（环形缓冲） **已落地**：`flow::stats::FlowStats` 在包数 / 字节数之外增加 min / max / mean / stddev 包长、包长直方图（`HIST_BUCKETS = 12`，按 `log2(长度)` 分桶）、IAT 环形缓冲（容量 64）（在线 Welford 累加、饱和算术，合并支持分片与双向聚合）。 | 统计可导出为 FlowRecord 已达成：统计单测（含合并与溢出）；`--flows` 门禁按 tshark 逐帧事实核对双向包数、双向字节数、方向切换次数、首末时间戳。 | CYS-TRF-006 | P1/M |
| ⬜ | CYS-TRF-015 | 会话级统计聚合 | 上下行比、重传计数、乱序计数、RTT 粗估 | 单元测试断言数值 | CYS-TRF-014 | P1/M |

#### 3.3.3 重组与协议（`TRF`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ◐ | CYS-TRF-016 | TCP 乱序重组 | `crates/reassembly`：序号区间树、重叠裁剪、空洞追踪、内存上限。**【与 DPI 的关系】** 当前 DPI 刻意只做**首包判定**（纯函数、不重组）：省网要在连接建立后几百微秒内出结果，等流拼完整 SLA 已过。代价是被 TCP 分段切开的首包会判 `NeedMore`。要覆盖这类流量，必须依赖本任务提供的重组能力（重组后再喂给同一个纯函数解析器，无需改解析器）。**已落地**：`src/reassembly/`（`seq.rs` 32 位序号回绕算术 / `intervals.rs` 有序区间集 + 重叠仲裁 + 空洞追踪 / `stream.rs` 单向流 + 内存上限降级 + FIN 语义 / `tcp.rs` 头与选项解析 / `tests.rs` 向量驱动），并与 `dpi::identify` 在 `Stream::identify_app` 处衔接。**未落地**：尚未迁入 `crates/reassembly`（见 CYS-TRF-001 的顺序决策）；双向 `Reassembler`（当前只有单向 `Stream`）；超时与连接表驱逐；IP 分片重组（CYS-TRF-018） | 已达成：10 条向量（顺序/逆序/交错/重叠一致/重叠冲突/重复重传/跨零回绕/被切开的首包/内存上限/FIN 同段）全部命中手写期望值；**tshark 4.6.7 作为第三方实现复核 16 项通过**（重组字节流的长度+sha256，以及切开 ClientHello 重组后的 JA3/SNI）；「内存上限触发时降级」达成且可验证（`memory-cap` 向量：缓冲满后丢弃加深空洞的段、仍交付开头前缀）。**未达成**：双向会话级重组；真实省网流量上的重组准确率；超时/驱逐 | CYS-TRF-012 | P0/XL |
| ◐ | CYS-TRF-017 | TCP 选项解析 | MSS、窗口缩放、SACK、时间戳。**已落地**：`src/reassembly/tcp.rs` —— data offset 校验（<5 与超出缓冲区分别报 `BadDataOffset` / `HeaderExceedsBuffer`）、TLV 长度越界即置 `malformed` 并停止解析（不"跳过继续"，因为继续解析出的东西没有可信度）、MSS / 窗口缩放（`window_shift()` 按 RFC 7323 把 >14 钳到 14，原值保留以便诊断）/ SACK-permitted / SACK 块（`MAX_SACK_BLOCKS=4`，由"data offset 4 位 → 选项区 ≤40 字节 → `8n+2≤40`"推导出的协议硬上限）/ 时间戳。**未落地**：校验和验证（刻意不做：TSO/LRO/GRO 卸载后校验和字段本身不可信，验证只会产生假阳性） | 已达成：选项解析 13 项测试全过（含长度越界、SACK 长度非 8 的倍数、EOL 之后不再解析、窗口缩放 255 的钳位）。**未达成**：未见真实流量样本 | CYS-TRF-016 | P2/S |
| ⬜ | CYS-TRF-018 | IP 分片重组 | IPv4/IPv6 分片表、超时、重叠策略（BSD/Linux 语义可选） | 分片样本重组正确 | CYS-TRF-016 | P1/L |
| ◐ | CYS-TRF-019 | 协议识别（端口+启发式） | `crates/dpi::identify`；端口表 → 载荷特征 → 兜底 unknown，输出置信度。**已落地**：`src/dpi/`（`mod.rs` 三级递进框架 + 端口提示排序 + 检测器编排），裁决语义为四态 `Identified / NeedMore / Malformed / Unknown`，刻意不用 `Result`（"不是我的协议"与"我的协议解析坏了"在统计上后果相反）。**未落地**：尚未迁入 `crates/dpi`（见 CYS-TRF-001 的顺序决策）；「样本集准确率 ≥ 95%」未有样本集 | 已达成：32 条向量（9 TLS / 15 DNS / 8 HTTP）全部命中预期裁决。**未达成**：准确率指标（缺大样本集） | CYS-TRF-016 | P0/L |
| ☑ | CYS-TRF-020 | HTTP/1.1 解析器 | 方法、URI、Host、UA、状态码、Content-Type、Content-Length。**已落地**：请求侧（方法/URI/版本三元组 + Host 端口剥离与大小写归一 + UA + Content-Type）、**响应侧**（`HTTP/x.y` + 三位状态码 100~599 + 原因短语 + Content-Type，与请求侧共用「头部必须完整结束」判据）；`Content-Length` 已解析进结构体但**未产出属性**（字典未登记该属性，「只产出已登记属性」是硬约束）；判别只看「载荷是否以 `HTTP/` 开头」，请求行首 token 是方法名故不会误判；「半截 `HTTP/`」判 `NeedMore` 而非「不是 HTTP」；状态码不足三位判 `NeedMore`、三位非数字或超 1xx~5xx 判 `Malformed`（分片与坏包的下游含义相反）。**未登记**：`Content-Length` 属性（应先登记再产出） | 已达成：8 条 HTTP 向量（含响应 200/404、半截 `HTTP/` 前缀、状态码 999、头部未结束）覆盖四态裁决；tshark 三方一致（每条 6 个字段逐项比对，合计 24 项）。**未达成**：大样本覆盖率指标 | CYS-TRF-019 | P1/L |
| ◐ | CYS-TRF-021 | TLS ClientHello 解析 | 版本、SNI、密码套件、扩展；JA3 指纹计算。**已落地**：记录层/握手层逐层 checked 解析（握手长度为 **3 字节**，从偏移 6 起）、GREASE 剔除、`supported_versions` 修正 TLS 1.3 版本判定、ECH 扩展识别（真实 SNI 不可见是预期而非故障）；MD5 自实现（零第三方依赖）并用 RFC 1321 向量锁定。**未落地**：证书解析（CYS-TRF-022） | 已达成：JA3 与 **tshark 4.6.7 独立实现**逐条一致（该门禁当前共比对 92 项，含 DNS/HTTP 侧字段）。**已知例外**：ECH 向量 `tls-ech-no-outer-sni` 无法用 tshark 交叉核验（其 ECH 解析器认不出手工构造的 ECH 体，会连整包 JA3 一起抑制），已在 `expected.json` 显式标注 `tshark.verified=false` 并有测试守门，不冒充「已核验」 | CYS-TRF-019 | P1/L |
| ⬜ | CYS-TRF-022 | TLS 证书解析 | 服务端证书链中的 CN/SAN/签发者/有效期（明文可见部分） | 从样本中提取 SNI 与 CN | CYS-TRF-021 | P2/M |
| ☑ | CYS-TRF-023 | DNS 解析器 | 查询/响应、QTYPE、QNAME、RCODE、EDNS0。**已落地**：标签序列（≤63 / 总长 ≤255）、`0xC0` 压缩指针（**跳数上限 128** 破环，同时天然限制每次解析的 work 量）、指针越界判畸形、QNAME 小写归一；「查询报文 qdcount ≠ 1」判"不是 DNS"而非"解析失败"；**RCODE 只在响应上产出**（查询报文的该段是保留位，产出 0 等于凭空造出一批"正常"样本）；QCLASS 查询/响应都产出；**应答地址集合**（A/AAAA，按报文顺序，上限 8 条）+ **指针跳数**（0 = 未用压缩指针，是"确实没跳"这个测量结果而非"没测"）；**EDNS0**（OPT 的 CLASS 复用为 UDP 载荷上限，双 OPT 按 RFC 6891 §6.1.1 判畸形）。资源记录段按**尽力而为**扫描：三层 work 上限（名字跳数 / 记录条数 ≤32 / rdlength 必须落在报文内），首包被截断时仍凭 QUESTION 段判 identified —— 该段的证据强度与应答段无关。**修掉一个真实缺陷**：`parse_name` 原先把"跟随指针读完后的位置"当作"名字之后的下一个字节"，答名字用压缩指针（DNS 常态）时会让调用方错位读资源记录。 | 已达成：15 条 DNS 向量（查询/响应、压缩指针、NXDOMAIN、多应答含 AAAA、应答截断、EDNS0、双 OPT、指针成环、垃圾负例）覆盖四态裁决；tshark 三方一致（每条 6 个字段逐项比对，合计 60 项）。**未达成**：大样本覆盖率指标 | CYS-TRF-019 | P1/M |
| ⬜ | CYS-TRF-024 | QUIC 解析 | Initial 包解密后的 SNI / 版本协商（需密钥派生） | 对 QUIC 样本提取 SNI | CYS-TRF-021 | P3/XL |
| ⬜ | CYS-TRF-025 | SSH / SMTP / FTP 识别 | 版本 banner 与命令识别 | 样本验证通过 | CYS-TRF-019 | P2/M |
| ⬜ | CYS-TRF-026 | 协议解析模糊测试 | `cargo-fuzz` 对 HTTP/TLS/DNS 解析器 | 24h 无崩溃 | CYS-TRF-020 | P1/M |

#### 3.3.4 特征·行为·风险（`TRF`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ☑ | CYS-TRF-027 | 特征提取 | `crates/feature`：包长序列统计、IAT 统计、字节速率、上下行比、方向切换次数、载荷熵 **已落地**：`feature::FeatureExtractor` 21 维特征（包长序列统计、IAT 统计、字节速率、上下行比、方向切换、载荷熵）+ `FEATURE_SCHEMA_VERSION`；熵在聚合后的 256 桶直方图上算（`0` 表示「无字节」或「全部相同」，由 `bytes` 列区分）。 | 特征向量维度固定并版本化 已达成：维度固定并版本化（`idx` 常量 + 版本号）；`--flows` 门禁核对特征列与记录计数器自洽。**未达成**：与训练侧对齐（CYS-TRF-028）。 | CYS-TRF-014 | P0/L |
| ⬜ | CYS-TRF-028 | 特征与训练侧对齐 | 特征定义单一来源（YAML/JSON schema），Rust 与 Python 各自生成绑定 | 两侧对同一样本产出相同向量 | CYS-TRF-027 | P0/M |
| ⬜ | CYS-TRF-029 | 行为基线 | `crates/behavior`：滑动窗口统计、EWMA、周期基线、突增检测 | 基线在稳定流量下不误报 | CYS-TRF-027 | P1/L |
| ⬜ | CYS-TRF-030 | 异常检测接口 | 定义 `AnomalyDetector` trait，规则实现 + 预留 ML 实现（调用 `ml/inference`） | trait 可被 ML 实现替换 | CYS-TRF-029 | P1/M |
| ⬜ | CYS-TRF-031 | 风险评分引擎 | `crates/risk`：加权评分、规则命中累加、阈值分级（低/中/高/危急） | 评分可解释（含命中明细） | CYS-TRF-030 | P1/L |
| ⬜ | CYS-TRF-032 | 规则 DSL | 简洁规则语法（条件 + 动作），支持热加载 | 规则文件改动后无需重启生效 | CYS-TRF-031 | P2/L |
| ☑ | CYS-TRF-033 | 输出 FlowRecord schema | 与 `storage/clickhouse` 对齐的列式 schema，含所有特征与评分 **已落地**：`record::FlowRecord`（顶层列 + 特征列 + `schema_version = 1`，`to_json_line` / `write_jsonl`）；任何列 / Schema 变更都必须抬版本号。 | schema 冻结并版本化 已达成：schema 版本化，列名与顺序由 `include_str!` 快照锁定。**未达成**：与 `storage/clickhouse` 建表 DDL 对齐（storage 侧尚未落地）。 | CYS-TRF-027 | P0/M |
| ◐ | CYS-TRF-034 | 共享内存接入 | 从 `packet-engine` 的共享环消费真实报文（CYS-PKT-024 的消费端）。**已落地**：Rust `src/bin/ring_consume.rs`（attach 既有环 / `--from-head` 跳过积压 / `--expect-*` 断言开关）、`scripts/verify/e2e-shared-ring.sh`（C++ 进程写 → 环 → Rust 进程读并解 Flow，4 阶段 19 项断言，含两端记账与区域计数的交叉核对），已挂入 `test-all.sh --e2e`。**2026-10-05 更新**：真实网卡接入**已在 Linux 侧达成** —— Rocky Linux 10.2 aarch64 测试机上 `enp2s0` 真抓 → pcap → 环 → Rust 解出 10 条 Flow，13/13 断言，且 Rust `decode_fail` 与 tshark 判定一致（HANDOFF §2.7）；**macOS 侧仍未达成**（受 CYS-PKT-007 的 `/dev/bpf*` 权限阻塞）。`xdp/`、`af_xdp/`、`dpdk/` 三个目录仍为空占位 | 已达成：真实 pcap → 共享环 → Flow 端到端（19 项断言）+ **真实网卡 → Flow（Linux 侧，13 项断言）**。待达成：macOS 侧真实网卡 → Flow（受 CYS-PKT-007 阻塞） | CYS-PKT-024 | P0/L |
| ☑ | CYS-TRF-035 | 离线 pcap 处理 CLI | `cythsec-analyze -r x.pcap -o flows.jsonl`，输出 FlowRecord 流 **已落地**：`src/bin/analyze.rs` → `cythsec-analyze -r x.pcap -o flows.jsonl`（`--strict` / `--limit` / `--inspect-bytes` / `--max-sessions` / `--workers N`（**2026-10-05 新增**：每 worker 私有流表/会话/特征，N>1 与 N=1 逐字节一致，统计里报 `workers=` 与每 worker 承担的流数）/ `-o -`；统计走 stderr，`-o -` 时 stdout 保持纯净 JSONL）；分析逻辑抽到 `src/pipeline.rs`，CLI 与测试共用同一条路径（否则两边会各错一半）。 | 对 `datasets/pcap/` 全样本可批量处理 已达成：`datasets/pcap/` + `datasets/dpi/` 全部样本可批量处理；`tests/pipeline_sample.rs` 手写期望（18 帧 / 17 解出 / 5 会话）；**新增第三方门禁** `scripts/verify/check-flow-records.sh` —— tshark 独立解析后逐流核对 **927 项**（会话集合 / 包数字节数 / 方向切换 / 首末时间戳 / TCP 末态 / 发起方 / 应用识别 / 解码失败计数 / 统计自证；该核验也吃 DPI 的三份 pcap，故向量 21→32 条后比对项由 725 涨到 927），并默认跑**反向故障注入**（17 项篡改必须全部被检出，「一项都没比对」直接判红），已挂入 `test-all.sh --flows`。 | CYS-TRF-033 | P0/M |
| ⬜ | CYS-TRF-036 | 可观测性 | `tracing` + `metrics`：处理速率、丢包、内存占用、各阶段延迟 | 指标可被 telemetryd 抓取 | CYS-TRF-034 | P1/M |
| ☑ | CYS-TRF-037 | 自研数据面基准（**刻意不用 Criterion**） | 流表插入/查询/逐出/超时、特征更新、TCP 重组、会话归属的吞吐与内存。**已落地**：`dataplane/traffic-engine/src/bin/bench.rs`（二进制 `cythsec-bench`，`--flows/--rounds/--json/--report-only/--require-targets/--target-factor`）+ 门禁 `scripts/verify/check-flow-bench.sh`（挂 `test-all.sh --bench`，含 3 项反向故障注入）。**为什么不引 Criterion**：本工程硬约定是零第三方依赖 + `--offline` 可构建，基准工具不该成为例外；代价是**没有**离群值剔除 / 置信区间 / 跨 commit 自动比对，只报点估计（每项跑两遍、取第二遍，两遍都打印）。 | 基准可跨 commit 对比 **已达成**：目标值**由工作量需求推导**（10Gbps 最坏包速率 14.88 Mpps、1M 条扫描 ≤200ms、10Gbps 净载荷 ≥1.25GB/s），回归下限另设（≥2× 余量）且**默认不进 ALL**（机器相关）。首轮即抓出三处：`expire()` 的 O(n) 临时数组（**已修**，churn RSS +99→+6MiB/轮、扫描 1.62→2.50M 条/s）、`evict_lru` 每次逐出全扫分片 O(每分片容量)（**已修**：分片内双向链表，52µs → 0.34µs@每片8192、1.09µs → 0.21µs@每片256，容量 32× → 耗时 52× 降到 1.6~1.8×，并新增 `stats().evict_candidates` 把复杂度变成断言）、稳态查表够不上 10G。**本批又加 6 项判据（共 19 项）**：4 个线程档位（`table-steady-1/2/4/8t`，每核一张独立表，1.5 万→4 组实测 6.9/13.4~15.3/22.6~26.2/28.0~34.8 Mops/s）、`table-scaling-vs-ceiling`（流表扩展效率 ÷ **同机纯计算对照**的扩展效率，实测 0.55~0.92，目标 0.5「同量级」、下限 0.25）、`table-cores-for-10g`（最小档位使聚合 ≥1.5×14.88Mpps → 实测 **4 核**）。判据用**比值**而不是绝对效率，理由：这台机器 8 线程纯计算对照也只有 0.54~0.73，用绝对效率会把机器上限误报成代码缺陷。**新增第 4 项反向注入**：`--inject-serialized-scaling` 把并行档换成「所有线程抢一张表 + 互斥锁」，要求扩展性判据判红（实测比值 0.06~0.10）—— 单测 `serialized_table_is_flagged_as_not_scaling` 用真表真锁跑同一形态。**本批第 13 项判据**：`table-evict-scale-ratio`（容量 32× 下耗时比必须 ≈1，上限 3×）—— 这是唯一**与机器无关**的判据，换机器后依然能判"是不是又变回 O(cap)"。**另修正一处判据错误**：`table-steady-memory` 原先拿"填充后 → 灌完 5× 容量"作差，把"页第一次被触碰"（1M 条时 +206MiB）算成内存增长；现改为**预热一轮不计入判定**、逐轮记录、取预热后各轮增量的最大值（两版都判 0.00 MiB）。**未达成**：无统计显著性、无自动化跨 commit 历史对比（只能人工比数字）。 | CYS-TRF-027 | P2/M |
| ⬜ | CYS-TRF-038 | 集成测试 | `crates/*/tests/`：用固定 pcap 样本断言 Flow/Session/特征输出 | 断言快照可更新且受审 | CYS-TRF-035 | P1/M |
| ⬜ | CYS-TRF-039 | 属性测试 | `proptest` 覆盖五元组规范化、重组区间、超时逻辑 | 无反例 | CYS-TRF-016 | P2/M |

---

### 3.4 M4 — 控制平面补全

> ⚠ **本节状态已滞后于代码，动手前先读代码**（2026-10-02 核查）。
>
> `services/policyd`（4362 行源码 + 2896 行测试，含完整 `ruleir` 引擎：
> 数据模型 / 编译 / 匹配 / 求值 / 内存存储 / HTTP API）、`services/dnsd`、
> `services/telemetryd`、`services/pkg` 共享库 **均已存在且 19 个 Go 测试包全过**
> （`services/*/` 下 `go test ./...`），但本节多数任务仍标 ⬜。
> 成因：这些实现由并行协作者在 `9748175` / `8e0fb03`（2026-09-14）落库时未回写本表。
>
> **按本表去做「落地骨架」= 重复劳动。** 真实缺口在「落地侧」：
> nftables 下发（`CYS-POL-007`）、原子生效与回滚（`CYS-POL-008`）、
> PostgreSQL 持久化与版本化、命中统计、审计日志、服务间联动。
> 逐项核实与刷新状态是一项独立工作，详见 `HANDOFF.md` §1 / §3 / §8 并行线 C2。

#### 3.4.1 policyd 策略引擎（`POL`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-POL-001 | 模块骨架落地 | `services/policyd/{cmd,internal,pkg,api,configs,tests}`；替换现有仅 3 行的 `go.mod` | `go build ./...` 通过且目录结构与 routerd 一致 | CYS-DBT-017 | P0/M |
| ⬜ | CYS-POL-002 | 策略数据模型 | `Policy` / `Rule` / `Match`（五元组、域名、应用、时间窗）/ `Action`（allow/deny/log/limit/redirect）/ `Priority` | 模型通过 JSON schema 校验 | CYS-POL-001 | P0/M |
| ⬜ | CYS-POL-003 | 规则匹配 DSL | 类 Suricata/iptables 语法解析器（词法 + 语法），产出 AST | 解析器表驱动测试覆盖全部算子 | CYS-POL-002 | P0/L |
| ⬜ | CYS-POL-004 | 规则编译 | AST → 内部中间表示（IR，已归一化、已排序、已去冗余） | 冗余规则被合并，冲突规则报警 | CYS-POL-003 | P0/L |
| ⬜ | CYS-POL-005 | 策略存储 | 内存索引（按优先级的有序结构）+ PostgreSQL 持久化 | 重启后策略完整恢复 | CYS-POL-004 | P0/M |
| ⬜ | CYS-POL-006 | 策略版本化 | 每次变更产生不可变版本号 + diff 记录 | 可回滚到任意历史版本 | CYS-POL-005 | P1/M |
| ⬜ | CYS-POL-007 | nftables 下发 | 编译 IR → nftables 规则集，经 `platform/linux/nftables` 应用 | `nft list ruleset` 可见预期规则 | CYS-POL-006 | P0/L |
| ⬜ | CYS-POL-008 | 原子生效与回滚 | 事务式应用：失败自动回滚到上一版本；变更前快照现有 ruleset | 注入失败时系统状态不变 | CYS-POL-007 | P0/M |
| ⬜ | CYS-POL-009 | dry-run 模拟 | 给定报文/流特征，输出命中的规则与最终动作，不触碰内核 | 与真实下发结果一致（一致性测试） | CYS-POL-004 | P1/M |
| ⬜ | CYS-POL-010 | HTTP API | `GET/POST/PUT/DELETE /api/v1/policies`、`/api/v1/policies/{id}`、`POST /api/v1/policies/simulate` | OpenAPI 覆盖 100% | CYS-POL-005 | P0/M |
| ⬜ | CYS-POL-011 | 策略命中统计 | 每条规则的命中计数与最近命中时间，定时刷出 | 统计可从 API 查询 | CYS-POL-007 | P1/M |
| ⬜ | CYS-POL-012 | 审计日志 | 谁在何时改了哪条策略（变更前后快照） | 审计记录不可篡改（仅追加） | CYS-POL-006 | P1/M |
| ⬜ | CYS-POL-013 | 与 routerd 联动 | 策略触发路由变更（如黑洞路由、策略路由） | 联动用例端到端通过 | CYS-POL-007, CYS-RTD-008 | P1/M |
| ⬜ | CYS-POL-014 | 与 threat-intelligence 联动 | 情报命中自动生成封禁策略 | 情报更新后策略自动生成 | — | P2/M |
| ⬜ | CYS-POL-015 | 单元测试 | DSL 解析、IR 编译、优先级排序、冲突检测 | 覆盖率 ≥ 80% | CYS-POL-004 | P0/M |
| ⬜ | CYS-POL-016 | 集成测试 | 端到端：提交策略 → 下发 → 验证内核规则 | 在 Linux CI runner 上通过 | CYS-POL-007 | P1/M |

#### 3.4.2 dnsd DNS 策略服务（`DNS`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-DNS-001 | 模块骨架落地 | `services/dnsd/{cmd,internal,pkg,api,tests}` | `go build ./...` 通过 | — | P0/M |
| ⬜ | CYS-DNS-002 | DNS 报文编解码 | 自研或引入 `miekg/dns`（需评估依赖策略）；支持 A/AAAA/CNAME/MX/TXT/NS/SOA/PTR/SRV + EDNS0 | 与 `dig` 双向互操作验证 | CYS-DNS-001 | P0/L |
| ⬜ | CYS-DNS-003 | UDP 53 服务端 | 并发处理、`SO_REUSEPORT` 多队列、单包超时 | 压测 QPS 达标，无丢包 | CYS-DNS-002 | P0/M |
| ⬜ | CYS-DNS-004 | TCP 53 服务端 | 长度前缀、连接复用、超时 | `dig +tcp` 正常 | CYS-DNS-002 | P0/M |
| ⬜ | CYS-DNS-005 | 上游转发 | 并发查询、超时重试、多上游故障转移 | 单上游故障时自动切换 | CYS-DNS-003 | P0/M |
| ⬜ | CYS-DNS-006 | 缓存 | TTL 感知、负缓存（SOA minimum）、LRU + 容量上限、缓存命中指标 | 缓存命中时上游零请求 | CYS-DNS-005 | P0/M |
| ⬜ | CYS-DNS-007 | 分流规则 | 按域名/后缀、CIDR、客户端 IP、QTYPE、时间窗分流到不同上游 | 规则表单测全通过 | CYS-DNS-006 | P0/M |
| ⬜ | CYS-DNS-008 | 策略化动作 | 允许、阻断（NXDOMAIN）、重定向（A 记录替换）、限速、记录 | 动作生效可验证 | CYS-DNS-007 | P0/M |
| ⬜ | CYS-DNS-009 | DoT 上游 | 853 端口上游，连接池 + 复用 | 抓包确认加密 | CYS-DNS-005 | P2/M |
| ⬜ | CYS-DNS-010 | DoH 上游 | HTTPS 上游，HTTP/2 复用 | 抓包确认加密 | CYS-DNS-005 | P2/M |
| ⬜ | CYS-DNS-011 | DoH 服务端 | `POST /dns-query`，RFC 8484 | 浏览器可配置使用 | CYS-DNS-010 | P2/M |
| ⬜ | CYS-DNS-012 | 查询日志 | 结构化日志 + 采样控制 + 隐私脱敏开关 | 可导出至 ClickHouse | CYS-DNS-008 | P1/M |
| ⬜ | CYS-DNS-013 | HTTP 管理 API | `/api/v1/dns/rules`、`/api/v1/dns/stats`、`/api/v1/dns/cache` | 可从 console 管理 | CYS-DNS-007 | P1/M |
| ⬜ | CYS-DNS-014 | 与 policyd 联动 | 复用统一策略模型，避免重复规则语法 | 同一策略可同时作用于 DNS 与转发 | CYS-DNS-007, CYS-POL-004 | P1/M |
| ⬜ | CYS-DNS-015 | 单元测试 | 编解码（含畸形包）、缓存 TTL、规则匹配 | 覆盖率 ≥ 80% | CYS-DNS-002 | P0/M |
| ⬜ | CYS-DNS-016 | 压测与优化 | `dnsperf` 基准，目标 QPS 与 p99 延迟指标 | 达到设定目标 | CYS-DNS-006 | P1/M |

#### 3.4.3 telemetryd 遥测监控（`TEL`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-TEL-001 | 模块骨架落地 | `services/telemetryd/{cmd,internal,pkg,api,configs,tests}` | `go build ./...` 通过 | — | P0/M |
| ⬜ | CYS-TEL-002 | 指标接口约定 | 各服务统一暴露 Prometheus 文本格式 `/metrics`；定义命名规范 `cythsec_<子系>_<指标>_<单位>` | 四服务 `curl /metrics` 均返回有效格式 | CYS-RTD-004 | P0/M |
| ⬜ | CYS-TEL-003 | 抓取调度器 | 按目标列表 + 间隔抓取，含超时、重试、失败标记 | 单目标失败不影响其他目标 | CYS-TEL-002 | P0/M |
| ⬜ | CYS-TEL-004 | 本地时序缓存 | 环形缓冲保存近期样本（供快速查询），容量可配 | 内存占用有上限 | CYS-TEL-003 | P0/M |
| ⬜ | CYS-TEL-005 | 降采样与聚合 | 1s → 10s → 1m → 5m 多级聚合 | 查询任一级粒度均可 | CYS-TEL-004 | P1/M |
| ⬜ | CYS-TEL-006 | 告警规则引擎 | 阈值 / 持续时长 / 环比突增三类规则，支持表达式 | 规则命中产生告警事件 | CYS-TEL-004 | P0/L |
| ⬜ | CYS-TEL-007 | 告警抑制与聚合 | 同源告警去重、静默窗口、升级策略 | 告警风暴被有效抑制 | CYS-TEL-006 | P1/M |
| ⬜ | CYS-TEL-008 | 告警通道 | Webhook（通用）、企业微信（用户已连接 wecom）、邮件 | 各通道可独立启停并测试 | CYS-TEL-006 | P1/M |
| ⬜ | CYS-TEL-009 | 指标落库 | 写入 ClickHouse（复用 STO schema） | 历史数据可查询 | CYS-STO-002 | P1/M |
| ⬜ | CYS-TEL-010 | 查询 API | `/api/v1/metrics/query`（时间范围 + 聚合 + 过滤）、`/api/v1/alerts` | 返回格式与 console 对接 | CYS-TEL-005 | P0/M |
| ⬜ | CYS-TEL-011 | 健康检查聚合 | 汇总各服务 `/healthz` 形成整体健康视图 | Dashboard 可展示 | CYS-TEL-003 | P1/S |
| ⬜ | CYS-TEL-012 | 分布式追踪预留 | OpenTelemetry SDK 接入点定义 | 采样率可配 | CYS-TEL-002 | P3/L |
| ⬜ | CYS-TEL-013 | 单元测试 | 规则表达式、聚合正确性、通道重试 | 覆盖率 ≥ 80% | CYS-TEL-006 | P0/M |

---

### 3.5 M5 — routerd 生产就绪

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ☑ | CYS-RTD-001 | CORS 中间件 | 可配置允许源；去掉对 Vite proxy 的强依赖 | 前端直连跨域成功 | — | P0/S |
| ⬜ | CYS-RTD-002 | 结构化日志 | `log/slog`，JSON 输出、级别可配、含 request id 与耗时 | 日志可被 `jq` 解析 | — | P0/M |
| ☑ | CYS-RTD-003 | 优雅关闭 | `srv.Shutdown(ctx)` + 可配超时 + 停抓取信号 | 关闭时在途请求正常完成 | — | P0/S |
| ⬜ | CYS-RTD-004 | Prometheus 指标端点 | `GET /metrics`：请求计数、延迟直方图、各 handler 耗时、Go runtime 指标 | 指标格式合法 | — | P0/M |
| ⬜ | CYS-RTD-005 | 版本端点 | `GET /api/v1/version`：版本、commit hash、构建时间、Go 版本 | 由 `-ldflags` 注入 | CYS-INF-020 | P1/S |
| ☑ | CYS-RTD-006 | 配置文件生效 | 解析 `configs/config.yaml`；优先级 flag > 环境变量 > 文件 > 默认值 | 改文件即生效；`.env` 与 YAML 均被覆盖测试 | — | P0/M |
| ☑ | CYS-RTD-007 | envelope 加 `code` | 响应体 `{code, data, error, request_id}`，保持向后兼容 | 旧字段不破坏 | CYS-DBT-018 | P0/S |
| ⬜ | CYS-RTD-008 | 路由写 API | `POST/PUT/DELETE /api/v1/routes`，经 netlink 下发 | 可增删路由且 `ip route` 验证一致 | CYS-RTD-010 | P0/L |
| ⬜ | CYS-RTD-009 | 接口配置 API | up/down、MTU、地址增删、别名设置 | 变更后 `ip link` 一致 | CYS-RTD-010 | P1/L |
| ⬜ | CYS-RTD-010 | 引入 netlink | 以 `vishvananda/netlink` 替代 `/proc/net/route` 文本解析 | 路由/地址/链接均走 netlink | — | P0/L |
| ⬜ | CYS-RTD-011 | IPv6 路由表 | `/proc/net/ipv6_route` → netlink；API 支持按地址族过滤（v4 / v6 / all） | IPv6 路由可查可改 | CYS-RTD-010 | P0/M |
| ⬜ | CYS-RTD-012 | 路由策略模型 | rule / table / fwmark 的查询与设置 | 多路由表场景可管理 | CYS-RTD-010 | P1/L |
| ⬜ | CYS-RTD-013 | 邻居表查询 | ARP / NDP 表查询与静态项增删 | 输出与 `ip neigh` 一致 | CYS-RTD-010 | P1/M |
| ⬜ | CYS-RTD-014 | API 鉴权 | Bearer token（首版）+ mTLS（进阶）；从配置或环境读取密钥 | 无 token 请求返回 401 | CYS-RTD-006 | P0/M |
| ⬜ | CYS-RTD-015 | 速率限制 | 按 IP/Token 的令牌桶；写操作单独限额 | 超限返回 429 | CYS-RTD-014 | P1/M |
| ⬜ | CYS-RTD-016 | 请求体校验 | 所有写操作做 schema 校验与长度限制 | 畸形请求返回 400 且不落库 | CYS-RTD-008 | P0/M |
| ⬜ | CYS-RTD-017 | OpenAPI 规范 | `openapi.yaml` 手写或注解生成，覆盖全部端点 | `swagger-cli validate` 通过 | CYS-RTD-008 | P0/M |
| ⬜ | CYS-RTD-018 | handler 层测试 | `internal/api` 目前零测试，用 `httptest` 覆盖全部 handler | 覆盖率 ≥ 80% | CYS-RTD-017 | P0/M |
| ⬜ | CYS-RTD-019 | 平台 build tag 拆分 | `internal/netinfo` 按 `linux`/`darwin`/`windows` 拆分，避免运行期 `runtime.GOOS` 分支堆叠 | 三平台均可编译 | CYS-RTD-010 | P1/M |
| ⬜ | CYS-RTD-020 | 流量速率计算 | 现有 `/traffic` 只返回累计计数；增加差分采样与速率（pps/bps） | 返回速率字段且数值合理 | — | P0/M |
| ⬜ | CYS-RTD-021 | 流量历史采样环 | 内存中保留 N 个近期采样点供前端画趋势 | `/api/v1/traffic/history` 可用 | CYS-RTD-020 | P1/M |
| ⬜ | CYS-RTD-022 | WebSocket 事件流 | `/api/v1/events` 推送路由/接口/流量变更与告警 | 前端可订阅且断线重连 | CYS-RTD-021 | P1/L |
| ⬜ | CYS-RTD-023 | systemd 单元 | `deploy/openeuler/systemd/routerd.service`（含 hardening 指令） | `systemctl start routerd` 正常 | CYS-DEP-004 | P1/S |
| ⬜ | CYS-RTD-024 | 与 policyd 内部接口 | 约定 gRPC 或 HTTP 内部调用（策略查询、模拟） | 契约文档 + mock 通过 | CYS-POL-010 | P2/M |

---

### 3.6 M6 — 存储与前端

#### 3.6.1 storage 存储层（`STO`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-STO-001 | PostgreSQL schema | `storage/postgres/`：策略、规则、配置、用户、审计、情报元数据；含索引与外键 | 迁移可正反向执行 | — | P0/L |
| ⬜ | CYS-STO-002 | ClickHouse schema | `storage/clickhouse/`：`flows`、`sessions`、`events`、`metrics`、`dns_queries`；按月分区 + TTL | 大表插入与时间范围查询性能达标 | CYS-TRF-033 | P0/L |
| ⬜ | CYS-STO-003 | Redis 键空间设计 | `storage/redis/`：实时会话表、限速令牌、缓存、分布式锁；命名规范与 TTL 约定 | 键命名文档化，无裸键 | — | P0/M |
| ⬜ | CYS-STO-004 | 迁移工具 | golang-migrate（Go 服务）与 Alembic（Python ML）二选一并统一 | 空库一条命令建全表 | CYS-STO-001 | P0/M |
| ⬜ | CYS-STO-005 | 本地一键起库 | `docker-compose.datastores.yml`：PG + ClickHouse + Redis + 初始化脚本 | `docker compose up` 后三库可用 | CYS-DEP-002 | P0/M |
| ⬜ | CYS-STO-006 | Go 存储客户端 | 基于 `pgx/v5` 的连接池封装，含超时、重试、慢查询日志 | 被 policyd/routerd 复用 | CYS-STO-004 | P0/M |
| ⬜ | CYS-STO-007 | ClickHouse 写入器 | 批量写入（`native` 协议）、背压控制、失败落盘重放 | 高吞吐下无数据丢失 | CYS-STO-002 | P0/L |
| ⬜ | CYS-STO-008 | 数据保留与归档 | 按表定义热/温/冷策略与分区删除 | 过期数据自动清理 | CYS-STO-002 | P1/M |
| ⬜ | CYS-STO-009 | 备份与恢复 | 逻辑备份脚本 + 恢复演练文档 | 演练可在 30 分钟内完成恢复 | CYS-STO-006 | P1/M |
| ⬜ | CYS-STO-010 | 存储层压测 | 写入吞吐、查询 p99、连接池上限 | 有基线数据表 | CYS-STO-007 | P2/M |

#### 3.6.2 console Web 控制面（`CON`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-CON-001 | 依赖与样式栈定案 | 决策：接入 Tailwind + shadcn/ui（对齐 `components.json`）或改用手写设计令牌；同步 `tailwind.config.js` | 悬空配置消除；样式来源单一 | CYS-DBT-006 | P0/M |
| ⬜ | CYS-CON-002 | 设计令牌体系 | 把 `src/index.css` 的 339 行硬编码值抽象为 CSS 变量（颜色/间距/圆角/层级/暗色） | 改令牌即可整体换肤 | CYS-CON-001 | P0/M |
| ⬜ | CYS-CON-003 | 数据层选型 | 引入 TanStack Query 替换自研 `useApi`（缓存、重试、失效、轮询、乐观更新） | 页面切换不重复请求 | — | P0/M |
| ⬜ | CYS-CON-004 | 状态管理 | Zustand（或 Context）管理跨页状态：主题、筛选、选中项 | 状态不随路由丢失 | CYS-CON-003 | P1/M |
| ☑ | CYS-CON-005 | 测试基础设施 | `vitest.config.ts` + Testing Library + `jsdom`；首个组件用例 | `npm test` 通过 | — | P0/M |
| ⬜ | CYS-CON-006 | 图表能力 | 引入 ECharts 或 Chart.js 封装层（主题跟随暗色、懒加载） | 至少一张真实趋势图渲染 | CYS-CON-003 | P0/M |
| ⬜ | CYS-CON-007 | Traffic 页强化 | 用 `CYS-RTD-020` 的速率数据画折线/面积图，含时间窗选择与网卡多选 | 实时刷新且无内存泄漏 | CYS-CON-006, CYS-RTD-020 | P0/M |
| ⬜ | CYS-CON-008 | Dashboard 页强化 | 指标卡（总流量、活动会话、告警数、服务健康）+ 迷你趋势 + 拓扑缩略 | 首屏 3s 内可用 | CYS-CON-006 | P1/M |
| ⬜ | CYS-CON-009 | Interfaces 页强化 | 编辑能力（MTU、up/down），操作确认与结果反馈 | 变更后状态刷新正确 | CYS-RTD-009 | P1/M |
| ⬜ | CYS-CON-010 | Routes 页强化 | 新增/编辑/删除路由表单 + IPv4/IPv6 切换 + 校验 | 非法输入被前端拦截 | CYS-RTD-008 | P0/M |
| ⬜ | CYS-CON-011 | 新增 Policies 页 | 策略列表/编辑/优先级拖拽/模拟预览 | 对接 policyd API | CYS-POL-010 | P1/L |
| ⬜ | CYS-CON-012 | 新增 DNS 页 | 分流规则、缓存状态、查询统计与日志抽样 | 对接 dnsd API | CYS-DNS-013 | P1/L |
| ⬜ | CYS-CON-013 | 新增 会话/流 页 | 从 ClickHouse 查询 FlowRecord，含过滤、排序、分页、详情抽屉 | 百万行级查询可交互 | CYS-STO-002 | P1/L |
| ⬜ | CYS-CON-014 | 新增 Threat Intel 页 | 情报源状态、IOC 检索、命中趋势 | 对接 TIP API | CYS-TIP-005 | P2/L |
| ⬜ | CYS-CON-015 | 新增 ML 页 | 模型版本、指标、推理延迟、AB 对比 | 对接 model-registry | CYS-MLI-007 | P2/M |
| ⬜ | CYS-CON-016 | 新增 Alerts 页 | 告警列表、确认/静默、规则编辑 | 对接 telemetryd | CYS-TEL-010 | P1/M |
| ⬜ | CYS-CON-017 | 新增 Settings 页 | 服务地址、主题、语言、刷新间隔、API Token | 配置持久化到 localStorage | CYS-CON-004 | P1/M |
| ⬜ | CYS-CON-018 | 实时事件流 | WebSocket 客户端 + 断线重连 + 事件到 store 的映射 | 告警实时弹出 | CYS-RTD-022 | P1/M |
| ⬜ | CYS-CON-019 | 路由级代码分割 | `React.lazy` + `Suspense`，按页分包 | 首屏 JS 体积下降 | — | P1/S |
| ⬜ | CYS-CON-020 | 错误边界与统一提示 | ErrorBoundary + 全局 Toast + API 错误映射为可读文案 | 后端挂掉时页面不白屏 | — | P0/S |
| ⬜ | CYS-CON-021 | 加载与空态规范 | 骨架屏、空态插画/文案、重试按钮 | 三态（loading/empty/error）全覆盖 | CYS-CON-020 | P1/M |
| ⬜ | CYS-CON-022 | 暗色/亮色主题 | 令牌驱动的主题切换，跟随系统 + 手动覆盖 | 两主题下对比度达标 | CYS-CON-002 | P1/M |
| ⬜ | CYS-CON-023 | 国际化 | `i18next`，中英双语；术语表与后端字段对齐 | 语言切换无残留硬编码 | CYS-CON-017 | P2/L |
| ⬜ | CYS-CON-024 | 响应式与无障碍 | 移动端断点；键盘导航、焦点可见、`aria` 标注、axe 检查通过 | axe 无 serious/critical | CYS-CON-023 | P2/M |
| ⬜ | CYS-CON-025 | E2E 测试 | Playwright：5 条关键路径（登录/看板/路由增删/策略下发/告警确认） | CI 中稳定通过 | CYS-CON-005 | P1/L |
| ⬜ | CYS-CON-026 | 运行时配置注入 | 生产环境不重新构建即可改 API 地址：`config.js` 或后端注入 | 同一镜像可指向不同后端 | — | P1/S |
| ⬜ | CYS-CON-027 | 生产构建优化 | 手动分包（react/router/charts）、gzip+brotli、构建体积预算 | 首屏 gzip ≤ 200 kB | CYS-CON-019 | P2/M |
| ⬜ | CYS-CON-028 | 登录与会话（可选） | 若后端引入鉴权，前端需登录页、Token 存储与刷新 | 401 自动跳转登录 | CYS-RTD-014 | P2/L |

---

### 3.7 M7 — ML 与威胁情报

#### 3.7.1 ml/training 训练流水线（`MLT`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-MLT-001 | Python 工程化 | `ml/training/pyproject.toml`（PEP 621）、Python 版本钉扎、`uv` 或 `poetry` 锁文件 | `uv sync` 后环境可用 | — | P0/M |
| ⬜ | CYS-MLT-002 | 代码质量 | `ruff` + `black` + `mypy` 配置并纳入 CI | 三工具零告警 | CYS-MLT-001 | P1/S |
| ⬜ | CYS-MLT-003 | 数据加载框架 | `datasets/` 统一加载器：pcap/CSV/Parquet/FlowRecord JSONL | 各格式均能读入统一 DataFrame | CYS-MLT-001 | P0/M |
| ⬜ | CYS-MLT-004 | 数据切分 | 分层切分（train/val/test）+ 时间切分（防泄漏） | 切分脚本可复现（固定 seed） | CYS-MLT-003 | P0/S |
| ⬜ | CYS-MLT-005 | 预处理流水线 | 缺失值、归一化、异常样本处理，参数序列化以便推理侧复用 | 训练与推理预处理参数一致 | CYS-MLT-004 | P0/M |
| ⬜ | CYS-MLT-006 | 特征工程 | 与 `CYS-TRF-028` 的特征 schema 对齐，生成训练特征 | 同一输入 Rust/Python 特征一致 | CYS-TRF-028 | P0/M |
| ⬜ | CYS-MLT-007 | 实验管理 | MLflow（本地 file backend）记录参数/指标/产物 | 实验可对比、可复现 | CYS-MLT-001 | P1/M |
| ⬜ | CYS-MLT-008 | 基线模型 | 随机森林 / XGBoost / LightGBM，CPU 快速迭代 | 基线指标入库 | CYS-MLT-006 | P0/M |
| ⬜ | CYS-MLT-009 | 深度模型 | 1D-CNN 与 LSTM（流序列）；参数量与推理延迟受控 | 精度优于基线或延迟更优 | CYS-MLT-008 | P1/L |
| ⬜ | CYS-MLT-010 | 评估框架 | precision/recall/F1/AUC/PR-AUC/混淆矩阵，按类与按场景分解 | 报告自动生成 | CYS-MLT-008 | P0/M |
| ⬜ | CYS-MLT-011 | 统计显著性 | 交叉验证 + 配对检验（McNemar / bootstrap CI），报告 p 值与效应量 | 方法对比结论有统计支撑 | CYS-MLT-010 | P1/M |
| ⬜ | CYS-MLT-012 | 模型导出 ONNX | `torch.onnx.export` / `skl2onnx`，含 opset 与输入签名约定 | ONNX Runtime 可加载并得到一致输出 | CYS-MLT-009 | P0/M |
| ⬜ | CYS-MLT-013 | 数据集版本管理 | DVC 或 git-lfs 管理大文件；`datasets/` 与 .gitignore 策略对齐 | 指定 commit 可拉取对应数据版本 | CYS-MLT-003 | P2/L |
| ⬜ | CYS-MLT-014 | 模型卡与元数据 | 每个模型产出 Model Card（用途、限制、数据来源、指标） | 归档至 `ml/model-registry/` | CYS-MLT-012 | P1/S |
| ⬜ | CYS-MLT-015 | 训练流水线 CI | 小数据集 smoke train 纳入 CI，防回归 | CI 中 5 分钟内完成 | CYS-MLT-001 | P2/M |
| ⬜ | CYS-MLT-016 | model-registry 落地 | 目前 `ml/model-registry/` 不存在，需新建：模型版本、指标、来源、ONNX 路径 | 目录与索引文件落地 | CYS-MLT-014 | P0/S |
| ⬜ | CYS-MLT-017 | 示例 notebook | `ml/training/notebooks/`：数据探索、特征分析、结果可视化 | 可从头运行到底 | CYS-MLT-010 | P3/M |

#### 3.7.2 ml/inference 推理运行时（`MLI`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-MLI-001 | ONNX Runtime 接入 | CMake `find_package` 或 FetchContent；`ENABLE_ONNXRUNTIME` 开关真正生效 | 开关 ON 时链接成功，OFF 时零依赖构建 | CYS-MLT-012 | P0/L |
| ⬜ | CYS-MLI-002 | 会话管理 | `src/runtime/session.cpp`：多模型会话、线程数配置、内存 arena 复用 | 多模型并发加载正常 | CYS-MLI-001 | P0/M |
| ⬜ | CYS-MLI-003 | 特征张量转换 | 特征向量 → ONNX 输入张量，与 Python 侧签名严格一致 | 同输入两侧输出差 < 1e-5 | CYS-MLI-002, CYS-TRF-028 | P0/M |
| ⬜ | CYS-MLI-004 | 推理 API | 单样本低延迟路径 + 批量路径；无锁或细粒度锁 | 单样本 p99 延迟达标 | CYS-MLI-003 | P0/M |
| ⬜ | CYS-MLI-005 | 模型热更新 | 检测模型文件变更 → 原子替换会话，不中断在途推理 | 热更新期间零失败请求 | CYS-MLI-002 | P1/M |
| ⬜ | CYS-MLI-006 | 推理服务化 | HTTP（或 gRPC）接口供 traffic-engine 调用；含并发限流 | 可作为 sidecar 运行 | CYS-MLI-004 | P1/M |
| ⬜ | CYS-MLI-007 | 推理指标 | 延迟分位（p50/p95/p99）、吞吐、队列深度、错误率 | 指标可被 telemetryd 抓取 | CYS-MLI-006 | P1/M |
| ⬜ | CYS-MLI-008 | 与风险引擎对接 | 实现 `TRF` 的 `AnomalyDetector` trait：Rust 侧经 IPC/HTTP 调用推理 | 端到端风险评分含模型分项 | CYS-TRF-030, CYS-MLI-006 | P1/L |
| ⬜ | CYS-MLI-009 | 单元测试与基准 | 数值一致性测试；延迟/吞吐基准 | 有基线数据 | CYS-MLI-004 | P0/M |
| ⬜ | CYS-MLI-010 | 降级策略 | 模型缺失/加载失败时回退到规则引擎，不影响主流程 | 删掉模型文件后系统仍可用 | CYS-MLI-008 | P1/M |

#### 3.7.3 threat-intelligence 威胁情报（`TIP`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-TIP-001 | IOC 数据模型 | `ip/`、`domain/`、`hash/`、`url/` 统一模型：值、类型、来源、置信度、首次/末次观测、过期时间 | 模型可序列化并建索引 | — | P0/M |
| ⬜ | CYS-TIP-002 | 情报源接入框架 | `feeds/`：拉取（HTTP/定时）、解析（STIX/CSV/JSON/纯文本）、归一化、去重 | 新增一个源只需实现 adapter | CYS-TIP-001 | P0/L |
| ⬜ | CYS-TIP-003 | 情报源清单 | 开源源（如 AbuseCH、Spamhaus、OpenPhish）+ 商业源预留；明确许可与限速 | 清单文档化，无违规抓取 | CYS-TIP-002 | P1/M |
| ⬜ | CYS-TIP-004 | 信誉评分 | `reputation/`：多源加权、时效衰减、行为反馈修正 | 评分随观测更新 | CYS-TIP-002 | P1/M |
| ⬜ | CYS-TIP-005 | 查询 API 与缓存 | `/api/v1/intel/{ip,domain,hash,url}`，Redis 缓存 + 布隆过滤器前置 | 查询 p99 达标 | CYS-STO-003 | P0/M |
| ⬜ | CYS-TIP-006 | 与 policyd 联动 | 情报命中自动生成封禁策略（可配阈值与开关） | 情报更新后策略自动生成 | CYS-POL-014 | P1/M |
| ⬜ | CYS-TIP-007 | 与流量分析联动 | traffic-engine 命中 IOC 时产出告警事件 | 命中样本可复现 | CYS-TRF-031 | P1/M |
| ⬜ | CYS-TIP-008 | 情报时效管理 | 过期 IOC 自动降权/清理；历史留存策略 | 过期数据不参与判定 | CYS-TIP-004 | P1/M |
| ⬜ | CYS-TIP-009 | 情报落库 | PostgreSQL（结构化）+ ClickHouse（命中时序） | 可做命中趋势分析 | CYS-STO-001 | P1/M |
| ⬜ | CYS-TIP-010 | 单元测试 | 解析器（各类格式 + 畸形）、评分算法、过期逻辑 | 覆盖率 ≥ 80% | CYS-TIP-002 | P0/M |

---

### 3.8 M8 — 平台适配与部署

#### 3.8.1 platform 平台抽象层（`PLT`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-PLT-001 | 接口契约定义 | `platform/common/{network,firewall,routing,interface,system}`：纯抽象接口 + 能力探测（capability query） | 接口冻结并文档化 | — | P0/L |
| ⬜ | CYS-PLT-002 | Linux netlink 实现 | `platform/linux/netlink/`：链接/地址/路由/邻居/规则 | 与 `ip` 命令结果一致 | CYS-PLT-001 | P0/L |
| ⬜ | CYS-PLT-003 | Linux nftables 实现 | `platform/linux/nftables/`：表/链/规则/集合的增删改查与事务 | `nft` 校验通过 | CYS-PLT-001 | P0/L |
| ⬜ | CYS-PLT-004 | Linux ethtool 实现 | `platform/linux/ethtool/`：队列数、RSS 表、offload、ring 参数 | 可读可写 | CYS-PLT-001 | P1/M |
| ⬜ | CYS-PLT-005 | openEuler 适配 | `platform/openeuler/`：网络配置（NetworkManager/network-scripts 兼容）、服务单元、RPM 打包、默认配置 | 在 2403 sp4 上部署通过 | CYS-PLT-002 | P0/L |
| ⬜ | CYS-PLT-006 | OpenWrt 适配 | `platform/openwrt/{uci,ubus,netifd,service,packaging,configs}`：UCI 配置读写、ubus 暴露、netifd 集成 | 在 OpenWrt 固件上包可安装并运行 | CYS-PLT-001 | P2/XL |
| ⬜ | CYS-PLT-007 | 能力探测与降级 | 运行时探测内核版本/特性，缺失时降级并告警（如无 XDP → AF_PACKET） | 在不支持 XDP 的内核上可运行 | CYS-PLT-002 | P1/M |
| ⬜ | CYS-PLT-008 | 平台层测试 | netlink/nftables 的集成测试（需 root，CI 用 privileged runner） | 关键路径覆盖 | CYS-PLT-002 | P1/L |
| ⬜ | CYS-PLT-009 | 平台文档 | `docs/architecture/platform.md`：支持矩阵、依赖、权限要求 | 矩阵含实测内核版本 | CYS-PLT-005 | P2/M |

#### 3.8.2 deploy 部署（`DEP`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-DEP-001 | 多阶段 Dockerfile | `deploy/docker/`：每个 Go 服务一个（scratch/alpine 运行），C++/Rust 一个（含运行时依赖） | 镜像可构建且体积受控 | CYS-STO-006 | P0/L |
| ⬜ | CYS-DEP-002 | 全栈 compose | `deploy/docker/docker-compose.yml`：四服务 + 三库 + console（nginx 静态） | 一条命令起全栈 | CYS-DEP-001 | P0/M |
| ⬜ | CYS-DEP-003 | 镜像构建 CI | 多架构（amd64/arm64）构建与推送 | tag 触发自动推镜像 | CYS-DEP-001 | P1/M |
| ⬜ | CYS-DEP-004 | openEuler systemd 单元 | `deploy/openeuler/systemd/*.service`：四服务 + 依赖顺序 + 自动重启 + 沙箱加固 | 开机自启、崩溃自愈 | CYS-PLT-005 | P0/M |
| ⬜ | CYS-DEP-005 | openEuler RPM 打包 | `deploy/openeuler/rpm/*.spec` + 构建脚本，含 pre/post 脚本 | `rpm -ivh` 安装后可运行 | CYS-DEP-004 | P1/L |
| ⬜ | CYS-DEP-006 | OpenWrt 包 | `deploy/openwrt/package/Makefile` + `init.d/` 脚本 + 默认配置 | `opkg install` 后可运行 | CYS-PLT-006 | P2/L |
| ⬜ | CYS-DEP-007 | 一键部署脚本 | `deploy/openeuler/scripts/install.sh`：依赖检查、解包、建配置、起服务、自检 | 空机器上一键完成 | CYS-DEP-005 | P0/M |
| ⬜ | CYS-DEP-008 | 配置管理 | 环境变量 / YAML / 配置中心三选一定案；敏感项走 secret | 无明文密钥入库 | CYS-RTD-006 | P0/M |
| ⬜ | CYS-DEP-009 | 升级与回滚 | 版本化部署目录 + 软链切换 + 回滚脚本 | 回滚 1 分钟内完成 | CYS-DEP-007 | P1/M |
| ⬜ | CYS-DEP-010 | 部署文档 | `docs/deployment/openeuler.md`、`openwrt.md`、`docker.md`（现有 `dev-run-deploy.md` 保留为开发手册） | 三步内可照做成功 | CYS-DEP-007 | P0/M |
| ⬜ | CYS-DEP-011 | 冒烟自检 | 部署后自动健康检查脚本（各服务 `/healthz` + 关键 API） | 部署脚本末尾自动执行 | CYS-DEP-007 | P1/S |
| ⬜ | CYS-DEP-012 | VMware/Parallels 拓扑 | `deploy/vmware/`：与用户 Kali VM（10.10.10.0/24）环境对齐的测试拓扑描述 | 拓扑图 + 复现步骤 | — | P2/M |

#### 3.8.3 tools 开发工具（`TLS`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-TLS-001 | 流量生成器 | `tools/traffic-generator/`：可编排的 HTTP/DNS/TLS 混合流量，参数化速率与并发 | 可稳定产生指定 PPS | — | P1/L |
| ⬜ | CYS-TLS-002 | pcap 回放 | `tools/pcap-replay/`：按原始时间戳或加速倍率回放，支持循环与改包速 | 回放吞吐达标 | CYS-PKT-006 | P0/M |
| ⬜ | CYS-TLS-003 | 报文生成器 | `tools/packet-generator/`：构造畸形包/边界包用于解析器测试 | 可生成 CYS-PKT-018 的测试集 | CYS-PKT-016 | P1/M |
| ⬜ | CYS-TLS-004 | 基准工具 | `tools/benchmark/`：统一跑 C++/Rust/Go 各层基准并汇总对比 | 输出单一可比报告 | CYS-PKT-029 | P2/M |
| ⬜ | CYS-TLS-005 | 代码生成 | `tools/codegen/`：从统一 schema 生成跨语言类型（Go/Rust/TS/Python） | 新增字段改一处即全语言同步 | CYS-TRF-028 | P2/L |
| ⬜ | CYS-TLS-006 | 运维脚本 | `tools/scripts/`：日志采集、环境诊断、一键收集 issue 信息 | 诊断脚本输出可粘贴的清单 | — | P2/S |
| ⬜ | CYS-TLS-007 | 测试样本集构建 | `datasets/` 补充：正常/扫描/隧道/恶意流量样本，标注 ground truth | 样本集有 README 说明与出处 | CYS-TIP-003 | P0/L |

---

### 3.9 M9 — 测试·安全·文档·发布

#### 3.9.1 tests 全局测试体系（`TST`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-TST-001 | 测试策略文档 | `tests/README.md`：测试金字塔分层、各层职责、如何新增 | 新成员可据文档加测试 | — | P0/S |
| ⬜ | CYS-TST-002 | `tests/unit/` 落地 | 跨语言单元测试索引与补充（现有测试内联在各模块，此处补缺） | 目录非空且有实际内容 | CYS-TST-001 | P1/M |
| ⬜ | CYS-TST-003 | `tests/integration/` | 控制面服务间集成：routerd ↔ policyd ↔ dnsd ↔ telemetryd | CI 中可自动起停 | CYS-POL-016 | P1/L |
| ⬜ | CYS-TST-004 | `tests/e2e/` | 端到端：回放 pcap → 分析 → 策略命中 → 告警 → console 可见 | 全链路脚本化 | CYS-TST-003 | P0/XL |
| ⬜ | CYS-TST-005 | `tests/traffic/` | 流量用例集：各类协议、边界速率、突发 | 用例表驱动 | CYS-TLS-007 | P1/M |
| ⬜ | CYS-TST-006 | `tests/dpi/` | DPI 识别用例：协议矩阵 + 混淆/加密流量 + 误报样例 | 准确率与误报率有记录 | CYS-TRF-019 | P1/L |
| ⬜ | CYS-TST-007 | `tests/ml/` | 模型精度回归：固定测试集上指标不低于基线 | 指标下降时 CI 失败 | CYS-MLT-010 | P1/M |
| ⬜ | CYS-TST-008 | `tests/security/` | 认证绕过、越权、注入、反序列化、路径穿越 | 用例覆盖 OWASP Top 10 相关项 | CYS-SEC-002 | P1/L |
| ⬜ | CYS-TST-009 | `tests/performance/` | 性能基准：各层吞吐/延迟/资源占用，含回归阈值 | 超阈值 CI 报警 | CYS-TLS-004 | P1/L |
| ⬜ | CYS-TST-010 | `tests/compatibility/` | 多平台矩阵：内核版本、发行版、架构 | 支持矩阵有实测记录 | CYS-PLT-005 | P2/L |
| ⬜ | CYS-TST-011 | `tests/fixtures/` | 测试夹具：小体积 pcap、期望输出快照、生成脚本 | 夹具可再生成且体积受控 | CYS-TST-005 | P0/M |
| ⬜ | CYS-TST-012 | 覆盖率门槛 | 各语言覆盖率统计并设门槛（Go/Rust ≥ 70%，关键模块 ≥ 85%） | CI 中覆盖不达标即失败 | CYS-TST-002 | P1/M |
| ⬜ | CYS-TST-013 | 测试报告 | 汇总各语言 JUnit XML 与覆盖率，产出趋势报告 | 每次 CI 归档报告 | CYS-TST-012 | P2/M |
| ⬜ | CYS-TST-014 | 混沌与故障注入 | 网络中断、上游超时、库不可用场景下的降级验证 | 关键路径均有降级行为 | CYS-MLI-010 | P2/L |

#### 3.9.2 安全与合规（`SEC`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-SEC-001 | 威胁模型 | `docs/security/threat-model.md`：资产、信任边界、攻击面、STRIDE 分析 | 每个威胁有对应缓解措施或风险接受说明 | — | P0/M |
| ⬜ | CYS-SEC-002 | 鉴权与 RBAC | 统一认证（Token/mTLS）+ 角色（只读/运维/管理员）+ 端点级授权 | 越权用例被拒 | CYS-RTD-014 | P0/L |
| ⬜ | CYS-SEC-003 | 凭据管理 | 禁止硬编码；secret 来自环境/文件/外部 KMS；支持轮换 | 全仓扫描无明文密钥 | CYS-DEP-008 | P0/M |
| ⬜ | CYS-SEC-004 | 静态扫描 | CodeQL 或 Semgrep 纳入 CI，覆盖 Go/Rust/C++/TS/Python | 无高危未处置项 | CYS-INF-001 | P1/M |
| ⬜ | CYS-SEC-005 | 容器镜像扫描 | Trivy/Grype 扫描镜像，阻断高危 | 镜像无高危 CVE 未处置 | CYS-DEP-001 | P1/M |
| ⬜ | CYS-SEC-006 | 密钥泄漏防护 | `gitleaks` pre-commit + CI | 提交含密钥被拦截 | CYS-INF-016 | P0/S |
| ⬜ | CYS-SEC-007 | 审计日志 | 关键操作（策略变更、路由变更、配置修改）全量留痕 | 可回答「谁在何时改了什么」 | CYS-POL-012 | P1/M |
| ⬜ | CYS-SEC-008 | 许可合规声明 | 明确本项目 LICENSE（现为「仅授权安全研究使用，保留所有权利」）的边界与部署方义务 | 文档化且无歧义 | CYS-INF-027 | P0/M |
| ⬜ | CYS-SEC-009 | 权限最小化 | 服务以最小 capability 运行（CAP_NET_ADMIN 等按需）；systemd 沙箱 | `systemd-analyze security` 评分改善 | CYS-DEP-004 | P1/M |
| ⬜ | CYS-SEC-010 | 输入加固 | 所有外部输入（HTTP、DNS、报文）的边界与长度校验 | 模糊测试无崩溃 | CYS-PKT-018 | P1/M |
| ⬜ | CYS-SEC-011 | 安全响应流程 | 漏洞上报渠道与处置 SLA 文档（`SECURITY.md`） | 文件落地 | — | P2/S |
| ⬜ | CYS-SEC-012 | 渗透验证闭环 | 对自有部署做一次渗透测试并修复 | 高危项清零 | CYS-SEC-002 | P2/L |

#### 3.9.3 文档（`DOC`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-DOC-001 | 架构总览 | `docs/architecture/overview.md`：分层、数据流、进程模型、部署形态 | 含端到端数据流图 | — | P0/M |
| ⬜ | CYS-DOC-002 | 数据平面文档 | `docs/dataplane/`：packet-engine 与 traffic-engine 设计（含 CYS-PKT-031） | 覆盖实现选型与性能数据 | CYS-PKT-031 | P1/M |
| ⬜ | CYS-DOC-003 | 控制平面文档 | `docs/controlplane/`：四服务职责、API、交互时序 | 含时序图 | CYS-POL-016 | P0/M |
| ⬜ | CYS-DOC-004 | DPI 文档 | `docs/dpi/`：协议识别策略、特征、准确率与误报 | 含评测数据 | CYS-TST-006 | P1/M |
| ⬜ | CYS-DOC-005 | ML 文档 | `docs/ml/`：特征定义、模型、训练流程、推理部署、模型卡 | 可复现训练与部署 | CYS-MLT-014 | P1/M |
| ⬜ | CYS-DOC-006 | API 文档 | `docs/api/`：OpenAPI 规范渲染 + 各服务端点索引 + 错误码字典 | 在线可查、示例可运行 | CYS-RTD-017 | P0/M |
| ⬜ | CYS-DOC-007 | 性能文档 | `docs/performance/`：基准方法、硬件环境、结果表、瓶颈分析 | 结果可复现 | CYS-TST-009 | P1/M |
| ⬜ | CYS-DOC-008 | 安全文档 | `docs/security/`：威胁模型、加固基线、合规说明 | 与 CYS-SEC-001 对齐 | CYS-SEC-001 | P1/M |
| ⬜ | CYS-DOC-009 | 部署文档补全 | 见 CYS-DEP-010 | — | CYS-DEP-010 | P0/M |
| ⬜ | CYS-DOC-010 | README 校准 | 修正与实际的漂移（见 CYS-DBT-010/011）；补 CI 徽章与快速上手 | README 与实际目录逐项一致 | CYS-DBT-011 | P0/S |
| ⬜ | CYS-DOC-011 | 贡献指南 | `CONTRIBUTING.md`：分支模型、提交规范、评审清单、DCO | 新成员可依此提 PR | CYS-INF-017 | P1/S |
| ⬜ | CYS-DOC-012 | 开发者上手 | `docs/guides/getting-started.md`：环境准备到跑通第一条链路 | 照做 30 分钟内跑通 | CYS-INF-006 | P0/M |
| ⬜ | CYS-DOC-013 | 运维手册 | `docs/guides/operations.md`：日常运维、排障、常见故障速查 | 含故障树 | CYS-DEP-009 | P1/M |
| ⬜ | CYS-DOC-014 | 术语表 | `docs/guides/glossary.md`：中英双语术语对齐（Flow/Session/DPI/IOC 等） | 全文术语一致 | — | P2/S |
| ⬜ | CYS-DOC-015 | 文档站点 | 以 MkDocs 或 VitePress 汇总 `docs/` 并可本地预览 | 一条命令起站点 | CYS-DOC-001 | P2/M |
| ⬜ | CYS-DOC-016 | 文档校验 | CI 检查 Markdown 链接有效性与代码块语言标注 | 死链检查通过 | CYS-DOC-015 | P2/S |

#### 3.9.4 发布（`DOC`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-DOC-017 | 版本发布流程 | `docs/guides/release.md`：冻结、验证、打 tag、归档、公告 | 流程可照做 | CYS-INF-032 | P1/S |
| ⬜ | CYS-DOC-018 | 发布清单 | Release Checklist（含回滚触发条件） | 每次发布勾选留痕 | CYS-DOC-017 | P1/S |
| ⬜ | CYS-DOC-019 | v0.2.0 发布 | 完成 M1–M5 后发布首个具备控制面写能力的版本 | tag + Release + 产物 + SBOM | CYS-DOC-018 | P0/M |
| ⬜ | CYS-DOC-020 | v1.0.0 里程碑定义 | 明确 1.0 的功能边界与质量门槛（覆盖率、性能、文档完备度） | 定义文档评审通过 | CYS-DOC-019 | P2/S |

---

### 3.10 M10 — 分层解耦与插件化

> **来源**：`docs/architecture/layered-plugin-architecture.md`（**v1.0.0 正式方案**，2026-10-05 审核通过）
> 与 `docs/architecture/tsg-tech-transfer.md` §3.1 的 A1/A2/A4 引入项。
> **完成判据**：① 插件清单非法时**启动即失败并点名条目**；② 数据资产可原子热更新，且**换版失败保持旧版本生效**；
> ③ 新增一个 DPI 协议检测器**不需要改核心调度代码**；④ 本里程碑每道新增门禁都**有反向注入并挂在 CI 上**。
>
> ⚠ **本里程碑刻意只登记「现有待办表未覆盖」的工作。** 下列工作由**既有任务承接，不重复编号**——
> 同一件事发两个号，或把已落地的能力再排一次期，都是治理债：
>
> - `CYS-PLT-001`/`007`（接口契约定义 / 能力探测与降级）承接「平台实现按清单装配 + 能力声明」。
> - `CYS-STO-003`/`006`/`007`（Redis 键空间 / Go 存储客户端 / CH 写入器）承接存储实现。
> - `CYS-POL-005`/`006`/`007`/`008`/`009`（策略存储 / 版本化 / nftables 下发 / 原子回滚 / dry-run）承接处置侧执行。
> - `CYS-TIP-001`/`002`/`003`/`008`（IOC 模型 / 情报源接入 / 清单 / 时效）承接情报 feed 与 TTL。
> - `CYS-MLT-016`（model-registry 落地）承接模型注册表与版本化。
> - `CYS-TRF-001`（cargo workspace 拆分）是 `CYS-TRF-040`/`048` 的**前置**。
>
> **已知偏差（务必先读）**：§3.4 M4 的状态标记**滞后于代码**（见该节顶部提示与 `HANDOFF.md` §8 并行线 C2）。
> 因此上表按**实际缺口**而非「表内标记」判断；按仓库既有决定，**不逐项批量改状态**——
> 那属独立工作，不在本里程碑内。TSG §8.5 预留的 `CYS-POL-017`/`019` 与 `CYS-TIP-012`、`CYS-PLT-010`
> 经核对**与既有任务重复或已落地**（`CYS-POL-004`/`evaluate.go` 的 `excludes`、`CYS-TIP-002~003`、`CYS-PLT-001/007`），
> 故**不启用这些编号**；`CYS-TRF-043` 只登记其未落地的治理部分。

#### 3.10.1 契约与地基（`INF` / `TRF` / `DOC`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-INF-037 | 架构依赖方向门禁 | `scripts/lint/check-architecture.sh`：核心库不得 `use` 具体插件（白名单制）、L2 插件之间不得互调、新增 L0 真源必须同时有 `--check` 门禁；挂 `lint-all.sh` | 注入「核心 use 某插件」与「插件调插件」两例**均判红并点名文件行**；正向全绿 | — | P0/M |
| ⬜ | CYS-INF-038 | 契约门禁的自证与 CI 接入补齐 | 给 `check-attributes.sh` / `check-channel-abi.sh` / `check-channel-parity.sh` 补反向注入（改真源不重跑 / 改生成物 / ABI 字段增减）；新门禁挂 `.github/workflows/ci.yml`。**并清理「有检查器但无人调用」的既有孤例**：`scripts/verify/bench-pipeline.sh` 与 `docs/planning/scripts/check-deps.py` 都已入库却**不在任何门禁或 CI 上** —— 二者要么挂入门禁，要么显式标注为「手动工具」并写进文档，**不允许留在「看起来有把关、实际从不运行」的状态** | 三道注入各自判红且退出非零；`ci.yml` 上可见新门禁 job；两个孤例各有明确归属（挂上或标注），无「未接线的检查器」 | — | P0/M |
| ⬜ | CYS-TRF-040 | 插件清单真源、静态注册表与装配调度 | 新真源 `configs/registry/plugins.json`（`name`/`kind`/`form`/`version`/`requires_host_abi`/`capabilities`/`priority`/`enabled`/`source`/`license`）+ `tools/codegen/gen-plugins.py` 出宿主绑定 + 清单驱动装配；**刻意不用 `dlopen`** | 清单非法（缺字段 / 重名 / 未知 kind / ABI 不兼容）→ **启动即失败并点名条目**；`--check` 守门 | CYS-TRF-001 | P0/L |
| ⬜ | CYS-TRF-048 | 核心库与宿主切分 | 把 `pipeline.rs` 的编排、默认策略、统计汇总上移到宿主（`bin/*`），库只暴露稳定 API；重新划分 `AnalyzeOptions` 默认值的归属 | 核心库不再出现「读环境变量 / 配置文件挑实现」；`--workers N` 与单表行为**逐字节一致不回归** | CYS-TRF-040 | P0/M |
| ☑ | CYS-DOC-021 | 上游技术移植方案（TSG）文档 | `docs/architecture/tsg-tech-transfer.md`：A1~A6 架构级引入清单、落地记录与引用索引 | 已落地（见该文档 §9） | — | P1/M |
| ☑ | CYS-DOC-022 | 分层解耦与插件化正式方案 | `docs/architecture/layered-plugin-architecture.md`：L0~L4 分层、三类 × 三形态插件、六条准入判据、逐模块裁决、分阶段路线 | 审核通过并合并进本表（见本小节与 §7） | — | P0/M |

#### 3.10.2 数据资产通道（形态 A）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-INF-039 | 数据资产热更新通道与原子换版语义 | 统一触发通道（`SIGHUP` / 文件监听 / 控制面下发三选一）+ 校验 → 原子换版 → **失败保持旧版本并告警**；复用 `ruleir.Registry` 的 revision / checksum / rollback | 换版失败时**旧版本仍生效**且指标可见；注入「坏版本」必须判红而不是静默生效 | CYS-TRF-040 | P1/M |
| ⬜ | CYS-TIP-011 | 签名注册表与格式双向转换 | 签名 IR + 内部与外部格式**双向无损**转换 + Git 版本化 + 校验和 | 往返 diff 为空；坏签名在**装载期**即被拒 | — | P1/L |
| ⬜ | CYS-TRF-043 | 属性字典扩展治理（owner / 弃用周期 / 插件命名空间） | `attributes.json` 增 `owner` 与弃用标记；插件属性走命名空间；旧名保留一个版本并告警 | 引用已弃用属性时**告警且可定位到来源插件**；四语言 codegen 一致 | — | P1/M |

#### 3.10.3 宿主观测与装配

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-TEL-014 | 组件与插件版本上报 | 每个插件版本可查询（Prometheus gauge + `/api/v1/version` 扩展）；规则健康度；**降级必须进指标** | 「**指纹到一个插件不代表另一个存在**」可被证实：每个插件版本能独立查询 | CYS-TEL-001 | P1/M |
| ⬜ | CYS-STO-012 | 存储后端抽象与按清单装配 | 在 `services/pkg` 定义 Store 契约，实现（PG / CH / Redis）按清单装配；现无任何 DB driver 导入 | 换后端**不改上层**；契约有同一套一致性测试 | CYS-STO-001 | P2/L |

#### 3.10.4 DPI 检测器注册表（形态 B，**唯一需要改核心**）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-TRF-049 | DPI 检测器注册表改造 | `order()` 的定长 `[fn(&[u8]) -> Detect; 3]` → 检测器注册表；`AppId` 枚举 → 命名空间内动态分配；端口提示表数据化。**四条不可退让**：四态语义不变、检测器仍是**纯函数**、每包**零分配**、每条检测器自带向量 | 新增一个协议检测器**不需要改核心调度代码**；四态语义与零分配有测试钉住 | CYS-TRF-040 | P1/L |
| ⬜ | CYS-TRF-050 | 检测器插件验收门禁 | 每条检测器必须带**自己的向量**并过 tshark 核验；未核验的必须显式标 `verified=false` | 注入「新检测器无向量」判红；`verified=false` 在报告里**可见**而非默认绿 | CYS-TRF-049 | P1/M |

#### 3.10.5 进程外插件（形态 C，**只用于隔离与许可**）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-TRF-042 | 会话级事件总线与判定聚合点 | `DetectionEvent{session_id, source_engine, attrs, confidence}` + topic 订阅；**检测器之间不得互相调用**，各自发布、聚合点统一裁决 | 新增一路判定**只订阅即可接入**；同一会话多源判定可回放 | CYS-TRF-040 | P1/L |
| ⬜ | CYS-TRF-044 | 外部 DPI 引擎适配与进程隔离 | 进程外引擎宿主：IPC（Unix socket + 手写 JSON，**不引 gRPC / protobuf**）+ 心跳 + 熔断 + **显式降级** + 许可清单 | 引擎崩溃或超时**不得拖垮数据面**；降级进指标；许可与分发边界记录在案 | CYS-TRF-042 | P2/XL |
| ⬜ | CYS-MLI-011 | 推理进程外挂载 | ONNX Runtime 走**独立进程**，与「Rust 数据面零第三方依赖」的硬约定隔离；模型版本 + 校验和。**与 `CYS-MLI-001` 的关系**：MLI-001 允许把 ORT 链进数据面，本条要求改为进程外，**二者需二选一**（决策依据见 `DOC-022` §4.4） | 数据面二进制仍**零第三方依赖**；模型可独立换版 | CYS-MLT-016, CYS-TRF-044 | P2/L |

#### 3.10.6 治理

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-DBT-021 | 修正上游方案的编号冲突 | `tsg-tech-transfer.md` §8.5 把 `CYS-INF-035` 分配给「可重现构建与 SBOM」，但该号在本表中**已是已完成的**「仓库完整性自检」（§3.1.4），实际应为 `CYS-INF-036`；同时把该表标注为「已并入本表」并逐条指向 §3.10 | 两张文档中**同一编号含义唯一、无重号**；`check-deps.py` 无悬空引用 | — | P0/S |

### 3.11 M11 — 流级遥测与采集

> **来源**：2026-10-05 第五段。用户质询「运营商级 netflow 技术栈不用吗？这种抓包怎么可能扛得住省网」——
> 复核后确认这是**量级错误**而非优化空间：单条 100G 链路最坏 64 B 帧 = 148.8 Mpps；省网骨干 10 Tbps
> 全量逐包 = 2.5 Gpps / 1.25 TB/s / 约 108 PB/天。仓库实测的单箱能力是 1.5 Mpps（容器）～0.17 Mpps（2 vCPU 测试机），
> 离线派发端封顶 2.33 Mpps（10G 最坏帧的 16%）——**逐包全量在省网上不存在**。
> 运营商的做法是**网元侧采样导出 + 流级采集集群**：同一条 10 Tbps 经 1:1000 采样后是 2.5 Mpps / 折合 2~10 M 记录/秒，
> 存储从 108 PB/天 降到 2~4 TB/天（三到四个数量级）。本里程碑补的就是这条缺失的链路。
>
> **完成判据**：① `FlowRecord` 能按 RFC 7011 导出为 IPFIX，且**产物被 tshark 独立解出、字段逐一相符**（不是"我们自己解得开"）；
> ② 采集侧能报出**导出丢包**（序列号缺口）——这是"看不见的丢包"在流级路径上的对应物；
> ③ 采样率**如实声明**（`samplingInterval`/`samplingAlgorithm`），不声明就等于让下游把采样流量当全量算；
> ④ 给出可复算的**容量模型**（链路带宽 × 采样率 → 记录/秒 → 采集器台数 → 存储/天）；
> ⑤ 本里程碑新增门禁全部**有反向注入**（把模板改坏必须判红），并挂在 `test-all.sh` 上。
>
> ⚠ **只登记「现有待办表未覆盖」的工作**（与 M10 同一纪律）。下列由既有任务承接，**不重复编号**：
> - `CYS-STO-002`/`007`（ClickHouse schema / 写入器）、`CYS-TEL-009`（指标落库）、`CYS-CON-013`（流/会话页）
>   承接**存储与展示**——本里程碑只负责把记录**送到**它们的门口（并因此让 `CYS-CON-013` 第一次有了真实数据来源）。
> - `CYS-PKT-009`~`014`（FANOUT 分流 / CPU 亲和 / XDP / AF_XDP / DPDK）是**单点包级能力**，
>   与流级**不是替代关系**：包级负责"少数点位的深度"（DPI/取证），流级负责"全网面的广度"。
>   本里程碑据此**修正 `CYS-PKT-008` 之后那一段的对外口径**（见 `CYS-DOC-023`）。
> - `CYS-TRF-035`（无真实省网 pcap）仍是独立缺口，不因本里程碑关闭。
>
> **明确不做**：不做"逐包全量覆盖省网"的任何尝试——包括继续调优 AF_PACKET 环、加机器堆吞吐。
> 这是量级问题（差 3~5 个数量级），不是工程问题。

#### 3.11.1 导出侧（`TRF`：编码与通道）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ◐ | CYS-TRF-051 | IPFIX 编码器（RFC 7011） | `src/export/mod.rs`（v1 已落地）：消息头（version=10 / length / exportTime / sequenceNumber / observationDomainID）、模板集（Set ID 2）与数据集（Set ID ≥256）、IPv4/IPv6 两套模板**分族按需携带**、`FlowRecord` → 信息元素映射（8/12/27/28 地址、7/11 端口、4 协议、1/2 计数、152/153 毫秒时标、148 flowId=session_id、34 samplingInterval=1 如实声明「未采样」）。**零第三方依赖**（手写编码，与 `record/mod.rs` 手写 JSON 同一红线）。**v1 刻意不含**：RFC 5103 双方向（反转 IE = 企业位 + PEN 29305，而 `FlowRecord` 只有总量计数，硬做只能编造方向归属）与 DPI `applicationName`(96)（变长字段与「定长无歧义」目标冲突）；两者待分方向计数/变长编码落地后作增量 | tshark 独立解出导出的 IPFIX，**九类字段逐一相符**（含 IPv6 与超 32 位计数）；模板/数据集 4 字节对齐；字段号取自 IANA 注册表**而非记忆**。门禁 `scripts/verify/check-ipfix-export.sh`（tshark 逐字段 + 5 项产物级反向注入） | — | P0/M |
| ◐ | CYS-TRF-052 | 导出通道与模板生命周期 | `src/export/sink.rs`（v1 已落地）：UDP 导出（`--ipfix-udp host:port`，std 实现，含失败计数与最近错误）+ **落盘成 pcap**（`--ipfix-pcap`，手写以太/IPv4/UDP 且校验和真算，供 tshark 独立校验与 `tcpreplay` 回放）；`--ipfix-domain` / `--ipfix-max-msg` / `--ipfix-template-refresh`。模板分族首报文携带并按报文数刷新（UDP 无连接、采集器会重启）、序列号只计数据记录（RFC 7011 §3.1）。**已闭环**：导出丢包的可观测性已由采集器 `CYS-TRF-054` 落地（序列号缺口 → `loss_ppm`） | 导出报文数/记录数/字节数/失败数 CLI 可见；门禁验证 UDP 收到的字节与 pcap 通道载荷**逐字节相同**；产物能被 tshark 读懂 | CYS-TRF-051 | P0/M |
| ◐ | CYS-TRF-053 | 采样口径（声明与执行一致） | **流级采样落地**：`--sample 1:N` + `--sampling-mode flow\|packet` + `--sampling-seed`；`flow`（默认）按**流键哈希**决定（同一条流全采或全不采、与包序无关），`packet` 按包计数；采样决定在**派发端**做（放 worker 会让实际采样率放大 N×）；IE 34 取自**同一份 `SamplingConfig`**（没有单独的 `--ipfix-sampling` 开关，于是"只声明不执行"在 CLI 上无法表达）；CLI 自报 `sampling_observed/kept/dropped/kept_ppm/declared_matches_kept`；**导出计数不放大**（×N 还原量级是采集侧的事）。顺手修掉一个真实缺陷：`ExportConfig.sampling_interval` 此前被硬编码为 1（配置项只被校验、从不生效）。**未达成**：① 采样点在流键上，在线"收包环上采"需 `CYS-PKT-032`（AF_PACKET/XDP）；② 分层采样率取值仍是规划；③ 采样后的量级还原/置信区间未做；④ `samplingAlgorithm`(35) 未声明 | ① 自造 400 条流语料：1:4 → 留存 107 条（手算 100±12）且 CLI 自报 `declared_matches_kept=true`；② **流完整**：被采到的流除 `session_id` 外与不采样**逐字段相同**；③ **线路校验**（tshark）：不采样 IE 34 全 1、1:4 全 4，且记录条数 == 实际留存流数；④ `--workers 4` 与 `--workers 1` 结果逐字段相同；⑤ `packet` 模式 800 包留 200 包（手算）；⑥ 3 项**真实故障注入**（`keep-all` 采样器没接上 / `torn-flows` 逐包却自称 flow / `no-ipfix` 声明未落线）全部判红；⑦ Rust 单测钉住 IE 34 来自配置（1000 与默认 1 两个方向） | CYS-TRF-051 | P1/M |

#### 3.11.2 采集侧（采集器与容量模型）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ◐ | CYS-TRF-054 | IPFIX 采集器（序列号缺口可观测） | `src/ipfix/collector.rs` + `src/bin/ipfix_collect.rs`（v1 已落地）：解模板集/数据集（含**缩减长度编码** RFC 7011 §6.2、未登记 IE **按长度跳过**而不是删掉）、按 `(导出进程, ODID)` 各自维护序列号基线与模板表；**序列号缺口 = 导出丢包条数**（§3.1 / §11.6），只在前进方向记账、界外一律按乱序计且**不重置基线**（防 §11.6 点名的注入蒙蔽）；模板生存期按 §8.4 取「观测到的重传间隔 × 3」（可配置），UDP 上的模板撤回按 §8.4 **忽略**；同模板号不同定义按 §8.1 保留旧模板并计数；有界窗口去重；`--pcap`（离线，时间取抓包时间戳 → 可复现）与 `--udp`（在线）。**异厂互操作（2026-10-05 落地）**：`scripts/verify/check-ipfix-interop.sh` + `interop-ipfix.py` —— 一个**只读 RFC 7011 写出来的独立实现**（不 import/不复制仓库常量：模板 ID 4001~4004、字段序相反、观测域 `0x1234ABCD`、计数器**缩减长度编码**、夹带**未登记 IE**、发 options template set、发**模板撤回**、同号不同定义**重定义**、**先数据后模板**、零填充），5 个场景逐条对手写常量；tshark 再独立确认这份报文本身合法（防"我们和采集器一起读错同一个非标格式"）；统计行补印 6 个联调字段（`template_conflicts` / `withdrawals_ignored` / `options_template_sets` / `nonzero_padding` / `records_missing_key` / `templates_refreshed`）。**未落地**：TCP/SCTP 语义（传输会话结束隐式撤回模板）、Options Template 解码、**IE 6（tcpControlBits）等常见字段只按长度跳过、不取值**（v1 能力边界，真实导出器都会发）、**真实网元未联调**（离线替代已覆盖缩减长度/未登记 IE/撤回/重定义/先数据后模板/IPv6，硬件导出器的字段子集与刷新节奏仍未见过）、在线模式**无法设置 `SO_RCVBUF`**（std 无接口且仓库不引第三方依赖 → 高突发下内核丢弃会混进缺口，口径污染已在 HANDOFF §6 记明） | **人为丢一个 datagram 必须报出缺口且计数正确**（可证伪，已做：门禁删**中间**那个 datagram，要求 `gaps=1` 且 `lost_records = 完整记录数 − 实收记录数`，`loss_ppm` 独立手算一致）；**模板换版不产生整段解析失败**（已做：生存期到期后重传即恢复，单测钉住）；**重放同一段导出可复现同一结果**（已做：回路逐字段比对 9/9 相符）；无注入时必须报 0 缺口（反向断言），判定本身另有 6 项反向注入（含 1 项"必须通过"） | CYS-TRF-052 | P0/L |
| ⬜ | CYS-TEL-015 | sFlow v5 收集（RFC 3176） | 覆盖只支持 sFlow 的交换设备：datagram 解析、样本（flow/packet/counter sample）、**datagram 序列号缺口同样计入丢包** | sFlow 样本能解析并与接口计数对齐；序列号缺口可观测 | CYS-TEL-001 | P1/L |
| ◐ | CYS-INF-040 | 采集集群容量模型与部署形态 | 文档（HANDOFF §2.13）+ 可复算脚本 `scripts/plan/collector-capacity.py`（挂 `test-all.sh --plan`，纯 python3、秒级）：链路带宽 × 采样率 × 平均包长 → 记录/秒（**上界口径**：每采样包折算一条记录）→ 采集器台数（每台容量取 `cythsec-bench` 新增用例 `ipfix-collect-decode` 的**实测值**，本例 4.7 Mrec/s）× 余量 → 存储/天；给出核心 1:1000 / 汇聚 1:500 / 接入 1:100 三档分解（同一 20 Tbps 在三档下记录率差 2~5 倍）；`--json`、`--from-bench`（直接吃实测值）、`--tiers`（替换层级/链路/采样假设）；**三个必带口径**每次打印：① 采样率（规划值；真采样待 `CYS-TRF-053`）② 导出丢包率（`CYS-TRF-054` 的 `loss_ppm`）③ 采集覆盖率（**待部署清单填**，缺省 100% 是规划口径不是事实） | 给定「省网 20 Tbps、采样 1:1000」⇒ **5 Mrec/s → 2 台 → 34.29 TB/天**（手算可复现；落盘取 `CYS-INF-041` 实测 79.4 B/记录）；`--self-test` 用**手算期望值**校验（A/B/C 三算例 + 台数边界"恰好打满=1 台、多一条=2 台" + 包长×2⇒记录率×0.5 + 覆盖率/丢包折算），并对模型做 3 项反向注入（漏除采样率 / 丢掉余量系数 / 比特当字节）**均被判死**；参数出处逐条打印（实测/经验/规划/待实测，四类分开） | CYS-TRF-054 | P1/M |
| ◐ | CYS-INF-041 | 落盘字节/记录实测（把容量表最后一个假设换成数） | `scripts/plan/measure-storage.py`（挂 `test-all.sh --plan`，纯 python3）：吃 `cythsec-analyze` 产出的真实 `FlowRecord` JSONL，给**未压缩 / gzip** 两档字节数与"字节花在哪"的顶层键诊断；`--combine` 把多次测量合成规划值并**两档各取较差端**（不是平均、不是最小）；产物固化在 `docs/planning/measurements/`（记输入、样本量、`gzip_tool`、`gzip_method`）。接线：`collector-capacity.py` 默认读产物 gzip 档，新增 `--verify-defaults` 核对"内置默认值 ↔ 产物"一致。**未落地**：真实列式/数据库（ClickHouse）落盘未实测——21~79.4 B 都是 **gzip(JSONL)**；跨平台只对照 Apple gzip 487.0.1 | ① 两档语料实测：真实向量语料 37 条 ⇒ 1008.3 / **79.4 B/记录**（gzip）、同质压测语料 20,182 条 ⇒ 1066.0 / 21.0，规划取较差端 ⇒ **1066 B 上界 / 79.4 B 规划值**；② **旧「40 B/记录」实测不成立**（低估 2~27×），容量表随之重算：20 Tbps×1:1000 落盘 17.28 → **34.29 TB/天**、三档合计 55.3 → **109.73 TB/天**、逐包全量/流级倍数 12,500 → **6,297**；③ `--self-test` 手算字节数 + 末行无换行计数 + **gzip 往返校验**（解压==原文，截断输入不算压缩）+ TB/天 手算 + 空语料抛错，5 项反向注入（漏算换行/压缩档上报未压缩/字节当比特/条数多 1/合并取最好看一端）**均被判死**；④ 容量模型算例 H + 注入 `trust-planning`（假装读了产物、用回旧 40 B）⇒ 33.5664 变 17.28 判死；⑤ `--verify-defaults` 注入 `default-drift` 判死 | CYS-INF-040 | P1/M |

#### 3.11.3 数据面采样与对外口径（`PKT` / `DOC`）

| 状态 | ID | 任务 | 交付物与实现要点 | 验收标准 | 依赖 | P/规模 |
| --- | --- | --- | --- | --- | --- | --- |
| ⬜ | CYS-PKT-032 | 数据面采样率控制 | AF_PACKET 侧采样（`PACKET_FANOUT` 之外按 1/n 丢弃）+ XDP 侧 `bpf_get_prandom_u32` 采样；采样发生在**喂给流表之前**，否则流表仍按全量算 | 采样率配置生效；采样分布有**上下界**断言（不是"看起来均匀"）；采样率 =1 时与全量逐字节一致 | CYS-PKT-009 | P1/M |
| ☑ | CYS-DOC-023 | 「包级 vs 流级」分工与省网容量模型 | 修正对外口径：`M2`/`CYS-PKT-008` = **单点包级能力**（DPI/取证，10~100G/点），**不是**省网采集手段；流级路径（流表 → IPFIX → 采集集群）写清采样/采集/存储链路与三口径。落地：README 新增「两条流量路径的边界（可判定）」表 + HANDOFF §2.11 两条边界判定句 + §2.13 容量模型与三口径；**算式改为可复跑**：`scripts/plan/collector-capacity.py` 同时打印逐包全量与流级两条口径（自证算例 G） | ① 文档中不再出现"靠抓包扛省网"的暗示（README/HANDOFF 逐处核对，代码注释里的"省网"均为时延/规模语义，非承载暗示）；② **10 Tbps = 108 PB/天** 与 20 Tbps×1:1000 = 5 Mrec/s → 2~3 台 → **34.29 TB/天**（落盘 79.4 B/记录为实测，见 `CYS-INF-041`）均由脚本复算并挂 `--plan` 门禁；③ 两条路径各有一句可判定的表述：包级「要求逐包全量留存 ≥ 1 Tbps 即量级不成立」、流级「三个口径（采样率/导出丢包率/采集覆盖率）都能给出数字即可算并可复算」 | — | P0/S |

---

## 4. 关键路径与依赖链

```
M1 工程基座（CI/格式/版本/脚本）
  └─ 解锁：所有后续任务的验证手段

CYS-DBT-001/002（格式修复）──► CYS-INF-002（lint CI）
CYS-INF-020（版本单一来源）──► CYS-INF-021 ──► CYS-RTD-005（版本端点）

CYS-PKT-001（PacketBuffer）
  └─► CYS-PKT-003（ring）──► CYS-PKT-004（burst API）──► CYS-PKT-005（后端抽象）
        ├─► CYS-PKT-006（pcap 文件后端）──► CYS-TLS-002（回放）──► CYS-TST-004（e2e）
        ├─► CYS-PKT-008（AF_PACKET）──► CYS-PKT-009（多队列）
        └─► CYS-PKT-024（共享内存契约）──► CYS-TRF-034（Rust 消费端）

CYS-TRF-001（workspace 重构）──► CYS-TRF-006（FlowTable）
  └─► CYS-TRF-012（TCP 状态机）──► CYS-TRF-016（重组）──► CYS-TRF-019（协议识别）
        └─► CYS-TRF-027（特征）──► CYS-TRF-028（特征对齐）
              ├─► CYS-MLT-006（训练特征）──► CYS-MLT-012（ONNX）──► CYS-MLI-001（ORT 接入）
              └─► CYS-TRF-031（风险引擎）◄── CYS-MLI-008（推理对接）

CYS-DBT-017（共享 Go 库）──► CYS-POL-001 / CYS-DNS-001 / CYS-TEL-001（三服务骨架）
CYS-POL-004（规则 IR）──► CYS-POL-007（nftables 下发）──► CYS-PLT-003（nftables 实现）
CYS-RTD-010（netlink）──► CYS-RTD-008（路由写 API）──► CYS-CON-010（前端路由编辑）

CYS-STO-001/002（schema）──► CYS-TEL-009（指标落库）/ CYS-TIP-009（情报落库）
CYS-TRF-051（IPFIX 编码）──► CYS-TRF-052（导出通道）──► CYS-TRF-054（采集器 ◐）──► CYS-STO-007（CH 写入器）──► CYS-CON-013（流/会话页）
CYS-CON-003（TanStack Query）──► 所有前端数据页

CYS-PLT-005（openEuler 适配）──► CYS-DEP-007（一键部署）──► CYS-DEP-011（部署自检）

M10 分层解耦与插件化（横切，不占 M1~M9 关键路径，为数据面/控制面提供装配缝隙）
CYS-INF-037/038（依赖方向门禁 + 契约门禁自证）──► M10 全部任务的前置
CYS-TRF-001（workspace 拆分）──► CYS-TRF-040（插件清单、静态注册表与装配调度）
  ├─► CYS-TRF-048（核心库/宿主切分）──► CYS-INF-039（数据资产热更新通道）
  ├─► CYS-TRF-049（DPI 检测器注册表）──► CYS-TRF-050（检测器必须自带向量）
  ├─► CYS-TRF-042（会话级事件总线）──► CYS-TRF-044（进程外引擎与隔离）──► CYS-MLI-011（推理进程外挂载）
  └─► CYS-TEL-014（组件与插件版本上报）
CYS-TRF-043（属性字典 owner/弃用周期）与 CYS-TIP-011（签名注册表）为形态 A 数据资产的独立支线
```

**关键路径（决定最早可交付时间）**：
`CYS-INF-001/003/004` → `CYS-PKT-001→005→006` → `CYS-TRF-001→006→012→016→019→027` → `CYS-TRF-028` → `CYS-MLT-012` → `CYS-MLI-001→008` → `CYS-TST-004`（端到端）

**并行的独立支线**（不占关键路径，可提前启动）：
- 前端数据页改造（`CYS-CON-003` 起）仅依赖现有只读 API，可立即开工。
- 文档体系（`CYS-DOC-001/003/010/012`）仅依赖现状，可立即开工。
- 安全基线（`CYS-SEC-001/003/006/008`）不依赖功能完成，可立即开工。
- **插件契约地基**（`CYS-INF-037/038`、`CYS-TRF-040/048`、`CYS-DBT-021`）不依赖 M2~M9 的功能完成，可立即开工；
  且它越早做越省 —— `platform`/`storage`/`threat-intelligence` 等 0 LOC 模块**出生即插件**的改造成本几乎为零。

---

## 5. 建议的开工批次

| 批次 | 目标 | 包含任务 | 说明 |
| --- | --- | --- | --- |
| **第 1 批**（P0 清障） | 仓库健康化 | `CYS-DBT-001/002/005/006/011`、`CYS-INF-001/003/004/005/008/023` | 纯清理，无新功能，风险最低 |
| **第 2 批**（验证能力） | 具备 CI 与统一验证 | `CYS-INF-002/007/020/021/028`、`CYS-RTD-018` | 为后续所有改动提供回归保护 |
| **第 3 批**（数据面开路） | 真实收包 | `CYS-PKT-001/002/003/004/005/006/015/016/030`、`CYS-TLS-002` | 打通「真实报文」第一步 |
| **第 4 批**（分析闭环） | Flow/会话/特征 | `CYS-TRF-001/004/005/006/007/011/012/027/033/035` | 产出可存储的 FlowRecord |
| **第 5 批**（控制面补全） | 三服务落地 | `CYS-DBT-017`、`CYS-POL-001~004/010/015`、`CYS-DNS-001~008/015`、`CYS-TEL-001~013` | 控制平面成形 |
| **第 6 批**（生产就绪） | routerd 写能力 + 前端 | `CYS-RTD-001~008/010/014/016/017/020`、`CYS-CON-001~007/010/020` | 端到端可操作 |
| **第 7 批**（数据与智能） | 存储 + ML + 情报 | `CYS-STO-001~007`、`CYS-MLT-001~016`、`CYS-MLI-001~010`、`CYS-TIP-001~010` | 引入持久化与模型能力 |
| **第 8 批**（交付） | 平台与部署 | `CYS-PLT-001~005`、`CYS-DEP-001~011`、`CYS-TST-001~014` | 可交付到目标平台 |
| **第 9 批**（收口） | 安全、文档、发布 | `CYS-SEC-001~012`、`CYS-DOC-001~020` | 发布 v0.2.0 / v1.0.0 |
| **第 10 批**（插件化地基，可**立即并行开工**） | 契约下沉与装配缝隙 | `CYS-INF-037/038`、`CYS-TRF-040/048`、`CYS-DBT-021` | 不改行为、纯地基；越早做越省（0 LOC 模块出生即插件）。详见 §3.10 |
| **第 11 批**（省网量级，可**立即开工**） | 流级遥测与采集 | `CYS-DOC-023`、`CYS-TRF-051/052/053/054`、`CYS-PKT-032`、`CYS-TEL-015`、`CYS-INF-040` | 逐包全量在省网是量级错误（差 3~5 个数量级）；先把记录送进运营商既有的流级通道，再谈规模。详见 §3.11 |

---

## 6. 统计汇总

<!-- STATS:START -->
**任务总数：376**（不含 M0 已归档的 11 项）

### 6.1 按里程碑

| 里程碑 | 名称 | 任务数 |
| --- | --- | --- |
| M1 | 工程基座加固 | 55 |
| M2 | 数据平面真实收包 | 38 |
| M3 | 流量分析深化 | 39 |
| M4 | 控制平面补全 | 45 |
| M5 | 控制面服务化 | 24 |
| M6 | 存储与前端 | 38 |
| M7 | ML 与威胁情报 | 37 |
| M8 | 平台适配与部署 | 28 |
| M9 | 测试·安全·文档·发布 | 46 |
| M10 | 分层解耦与插件化 | 17 |
| M11 | 流级遥测与采集 | 9 |
| **合计** | — | **376** |

### 6.2 按优先级

| 优先级 | 任务数 | 占比 |
| --- | --- | --- |
| P0 | 147 | 39.1% |
| P1 | 155 | 41.2% |
| P2 | 64 | 17.0% |
| P3 | 10 | 2.7% |

### 6.3 按规模

| 规模 | 任务数 | 占比 |
| --- | --- | --- |
| S | 86 | 22.9% |
| M | 214 | 56.9% |
| L | 69 | 18.4% |
| XL | 7 | 1.9% |

### 6.4 按域

| 域码 | 任务数 |
| --- | --- |
| `TRF` | 50 |
| `INF` | 40 |
| `PKT` | 32 |
| `CON` | 28 |
| `RTD` | 24 |
| `DOC` | 23 |
| `DBT` | 21 |
| `MLT` | 17 |
| `POL` | 16 |
| `DNS` | 16 |
| `TEL` | 15 |
| `TST` | 14 |
| `DEP` | 12 |
| `SEC` | 12 |
| `STO` | 11 |
| `MLI` | 11 |
| `TIP` | 11 |
| `PLT` | 9 |
| `CAP` | 7 |
| `TLS` | 7 |

### 6.5 按状态

| 状态 | 任务数 |
| --- | --- |
| 未开始 | 313 |
| 进行中 | 17 |
| 已完成 | 46 |

### 6.6 里程碑完成度

| 里程碑 | 已完成 | 总数 | 完成率 |
| --- | --- | --- | --- |
| M1 | 19 | 55 | 35% |
| M2 | 5 | 38 | 13% |
| M3 | 14 | 39 | 36% |
| M4 | 0 | 45 | 0% |
| M5 | 4 | 24 | 17% |
| M6 | 1 | 38 | 3% |
| M7 | 0 | 37 | 0% |
| M8 | 0 | 28 | 0% |
| M9 | 0 | 46 | 0% |
| M10 | 2 | 17 | 12% |
| M11 | 1 | 9 | 11% |

<!-- STATS:END -->

---

## 7. 变更记录

| 日期 | 变更 | 说明 |
| --- | --- | --- |
| 2026-10-05（第四段） | **采集侧收口：mmap 环 vs 拷贝模式对照实测（`CYS-PKT-008` → ✅ 且**修正验收标准**、`CYS-CAP-002` → ✅）** | ① **为什么**：`CYS-PKT-008` 的验收命题「抓包吞吐显著高于 pcap live」从立项起**没有任何数据**，此前证据全是「能编译、能抓包」；上一批刚证明离线路径上限在**派发端**，捕获侧正是缺证据的一段。② **做了什么**：`BackendStats.rx_kernel_packets` + `af_packet::stats()` **现场轮询 `PACKET_STATISTICS` 并累加**（原先只在 `close()` 读一次 → 长跑期间丢包不可见、被信号杀掉就永远丢；与 macOS BPF 的 `stats()` 语义对齐）+ CLI `--stats-every`；`CaptureOptions.mode`（auto/v3/v2/recvfrom）**指定即严格、失败不降级**，不支持档位的后端**点名拒绝**且 CLI `exit 2`；新增 Linux 确定性打流工具 `cythsec-inject`（自报 sent/pps，不再依赖 pktgen 之类）；对照脚本改为 veth 负载 + 四臂（libpcap / 裸 TPACKET_V3 / 生产 v3 / 生产 recvfrom）+ **三类丢包分开记账**（socket / 设备 / softnet backlog）。③ **结论（含一条否定自己的）**：容器内同负载实测 L(11,088,260 包/1.46 s) ≈ V(10,126,401/0.99 s) ≈ P-v3(10,759,233/1.27 s)，每包 CPU 均 0.10~0.13 µs —— **libpcap 1.10 的 live 路径自己就走 mmap 环，原命题「显著高于 pcap live」不成立，是设错了对照轴**。成立的命题是「mmap 环显著优于拷贝模式」：零丢包同负载（1.0 Mpps）下每包 CPU **5.9~6.3× 更省**（0.13~0.14 vs 0.81~0.82 µs，两次独立复跑）；饱和时同机端到端速率 **1.35×**（10.76 M vs 7.96 M 包/同窗口）；真实网卡（`enp2s0`）上拷贝档把整机容量砍到 **1.74×** 之一（165,924 vs 95,450 pps）。④ **顺带修掉 4 个真 bug**（共同点：从未被独立工具检验过）：参照程序 `af_packet_capture.c` 的 `tp_mac` 当块内偏移（实测 packets=8 却 bytes=6.28e9）、`tp_next_offset` 当绝对偏移（带负载直接崩）、pcap 全局头 `ver_major/ver_minor` 写成 4 字节（应各 2 字节 → `network` 读出来是 snaplen，tshark 报 `network type 2112 unknown`，**即 `CYS-CAP-002` 的「产物可被 Wireshark 打开」此前其实不成立**）；对照脚本的 ping 洪泛分母取不到、打流被 kill 就没有自报、以及**测量顺序**（先打流后抓包 → 头 0.5 s 落在无监听窗口，凭空 5% 残差）——修完残差归零（抓/发 = 1.000）。⑤ **反向注入（三条，均实测）**：去掉 `stats()` 的运行中轮询 → 「close 前可读」两条断言红；`+=` 改 `=` → 「close 后是累加」断言红（close 前 429,900 → close 后 2）；去掉 BPF 的档位拒绝 → 跨平台不变量红。⑥ **验证**：Linux 测试机 `--cpp` **7/7**（新增 `packet_engine_capture_modes`）、`--rust` 342 全过、`--live` 真机真网卡 **14/14**；macOS `--cpp` 6/6；lint 全部通过（本轮先漏跑 lint 就提交了一次格式债，已修并记进 §7）。**未达成**：物理网卡上的**线速**对照（本轮真实网卡那臂是 TX→tap、且是 2 vCPU 虚机，绝对数不可比）；macOS 侧真抓包仍需一次免密 sudo 现场 |
| 2026-10-05（第三段） | **新增里程碑 M10「分层解耦与插件化」：把架构方案从「评估稿」升为正式方案并合并进本表（350 → 367 任务，9 → 10 里程碑）** | ① **来源与授权**：`docs/architecture/layered-plugin-architecture.md` 经审核通过，由 v0.1.0 评估稿升为 **v1.0.0 正式方案**；本表新增 §3.10 与之逐条对应（每个任务都能在方案的 P0~P4 里找到出处）。② **为什么单独立一个里程碑而不是塞进 M1~M9**：这批工作是**横切**的——门禁在 M1、数据面在 M3、控制面在 M4、存储与情报在 M6/M7、ML 在 M7、文档在 M9；散着放会让「插件化」在待办表里失去可见性，也没有统一的完成判据。③ **只登记「现有待办表未覆盖」的工作（本次合并最关键的一条纪律）**：逐一核对 TSG §8.5 预留的 24 个编号后，**`CYS-POL-017`（规则 IR 结构化）与 `CYS-POL-019`（白名单/排除集）已由 `CYS-POL-004` 与 `evaluate.go` 的 `excludes` 落地**（TSG §9.1 记为 A5/B5 ✅）、**`CYS-TIP-012` 与 `CYS-TIP-002/003/008` 重复**、**`CYS-PLT-010` 与 `CYS-PLT-001/007` 重复**、**`CYS-POL-018/020` 与 `CYS-POL-005/006/007/008/009` 重复**、`CYS-MLT-016`（model-registry）**本表已有**——这些**一律不启用新编号**，改为在 §3.10 顶部以「承接既有任务」清单显式挂钩。理由很实在：同一件事发两个号会把完成率算错，也会让后人重复排期。④ **单独登记 `CYS-DBT-021`**：TSG §8.5 声称编号「均从各域现有上限顺延」，但它把 `CYS-INF-035` 分配给「可重现构建与 SBOM」，而**本表 `CYS-INF-035` 早已是已完成的「仓库完整性自检」**（§3.1.4）——上游方案存在一处重号，实际应为 `CYS-INF-036`。本次不改上游文档正文（两份文档同时改容易冲突），而是**把它登记成可追踪、可验收的任务**。⑤ **不借这次合并刷绿 M4**：§3.4 的状态滞后是**已知且已定处置**的问题（§7 2026-10-02 记录 + `HANDOFF.md` §8 并行线 C2，理由是对每项验收标准须逐条核实，明确「不逐项批量改状态」）；M10 因此按**实际缺口**判断依赖，并已写在 §3.10 顶部。⑥ **顺带修正本表两处自身漂移**：§2 里程碑总览的 M1 计数与合计（写 54 / 349，而脚本实际读到 55 / 350）已对齐脚本口径；`count-backlog.sh` 的 `MS_NAME` 补 M10（否则 §6.1 会把 M10 的名字打成 `—`）。⑦ **验证**：`count-backlog.sh` 防呆闸未触发（宽匹配行数 == 严格解析行数），写回后总数 **367**、M10 = **17**；§6 全表由脚本重新生成而非手改。**未达成**：M10 的 17 项里除 `CYS-DOC-021/022` 两项文档外**尚无一行代码**；插件清单真源、依赖方向门禁、热更新触发通道、检测器注册表**均为待建**。 |
| 2026-10-05（第二段） | **把「每核一张独立表」接进消费路径：`cythsec-analyze --workers N`（N>1 与 N=1 输出逐字节一致），并量出整条流水线的上限是派发端** | ① **做了什么**：抽出 `PipelineState`（私有流表+会话+特征+DPI 探针），**每包路径只有一份实现**、就地与分片两条驱动共用；`analyze_pcap_with(reader, opts, workers)` 中 `workers=1` 走就地路径（与历史行为逐字一致、零额外开销）；CLI 加 `--workers N`，统计报 `workers= / worker_flows= / evicted=`。两条关键设计：**分片按 `key.canonical()`**（按原始五元组分片会把一条会话的两个方向拆到两个 worker，各建一套状态 → 记录数翻倍且不报错）、**会话 id 由派发端按首次出现顺序统一分配**（worker 各自编号会冲突且随分片变化）—— 后者是"逐字节一致"的来源。② **量出来**（`bash scripts/verify/bench-pipeline.sh 888000 3`，91.4 万包/271MB，脚本**不做阈值判定**）：单核 0.918 Mpps；2/4/8/16 worker 加速 1.49×/2.47×/**2.53×（上限）**/2.49×。**上限归因**：平台值 0.393 s 就是派发端（读盘+解帧+分片+入队）→ **派发端上限 2.33 Mpps**，worker 侧总工作量 0.603 s ⇒ **离线路径的并行上限是派发端而不是流表**，即 10G 最坏帧（64B/14.88 Mpps）只覆盖 **16%**，且**加核解决不了**；要线性必须让"读包+解帧"也分掉（每队列一环，`CYS-PKT-009`）。③ **一个只有测量才暴露的缺陷**：分片哈希原为 FNV-1a 后直接 `% workers`，而 FNV 的**低位只由最后几个字节决定**、真实流键尾部（目的端口 443、协议号 6）又完全相同 → 低位恒定：20000 条流在 8 个 worker 上只用到 0/4 号，2/4 个 worker 时**全部**落 0 号（`worker_flows=[20000,0,0,0]`）—— **输出完全正确、单测全绿、并行度为零**。修法：取模前加 splitmix64 雪崩混合；测试改为按**真实流量字节布局**（变化在前部）断言**均衡度上下界**（旧测试只断言"8 个分片都被用到"，而它用的键恰好把变化放在别的字节上，所以漏了）。④ **顺带修掉测试自身的一个盲区**：不变量测试原先只做"两条路互相比"，**把同一个错犯在两条路上就看不见**（实测：删掉统计合并整行后仍然相等）→ 补**绝对口径**断言（每个解码成功的包恰好被 observe 一次 = `session.packets == packets_decoded`、会话数 = 记录数、应用分布总数 = 记录数）。⑤ **反向注入**：分片改原始五元组 → 红；去掉派发端定序 → 红；删统计合并一项 → 红（补绝对口径之前是绿的）；三条都实测后还原复核全绿。**跨机对照**（Linux aarch64 / Rocky 10.2 / **2 vCPU** / 同脚本 / 30.9 万包）：单核 0.883 Mpps（与 M1 Pro 单核 0.918 基本持平，单线程不受核数影响），但 2 个 worker **1.00×**、4 个 1.11× —— 派发端在 2 核机上把收益全吃掉（`workers=2` 已是 3 线程抢 2 核）；同时注意脚本的 `D=最优档位耗时` 归因**要求 worker 数 ≥ 核数**，否则会把线程争抢误算成派发端。**已知限制**：分片模式每 worker 各持 `--max-sessions` 额度（总容量 = N×额度），一旦发生逐出各 worker 存活集合本就不同 → 此时"与 `--workers 1` 一致"不再成立（CLI 每次都打印 `evicted=`）；**只是离线路径**接线，在线 `ring-consume` 仍是单表；测量是页缓存热+独占核的单机数字，不能当在线能力 |
| 2026-10-05 | **接入 Linux aarch64 测试机当"第二台机器"：真机真网卡 13/13 验收，并修掉 3 处换机器才暴露的假红** | ① **为什么做**：此前所有验证只在 macOS/M1 Pro 上跑过，而仓库宣称支持的发行版里有 Rocky Linux ——「本机全绿 ≠ 别的机器能过」是 HANDOFF §7 第 7 条已经吃过一次的亏。把 VMware Fusion 上的 **Rocky Linux 10.2 aarch64 虚机（2 vCPU / 3 GB / `CONFIG_ARM64_4K_PAGES=y`）**接进回路，源码用 `git archive` 同步（**不用** `tar --exclude`：bsdtar 会匹配任意层级同名目录，实测静默丢掉 `scripts/build/build-all.sh` 与 `services/telemetryd/internal/target/*.go`），工具链装成与本机**逐位相同**的 `rustc 1.97.1`。② **结果**：`--rust` **337 项全过**（与本机计数一致）、`--cpp` **6/6**、`--live` **13/13 真实网卡断言**（`enp2s0` 采 74 包、tshark 复核 74 帧 = 落盘数、环内消费 74 = 灌入数、解出 10 条 Flow、Rust `decode_fail` 与 tshark 前缀非 IP 帧数同为 0）→ `CYS-PKT-008` 的证据从"容器内"升级为"真机真网卡"，`CYS-TRF-034` 的 **Linux 侧达成**；`--bench --report-only` 取到跨机数据（1/2/4/8 线程 6.73 / 7.41 / 12.85 / 13.20 Mops/s，比值判据 0.94 仍成立）。③ **修掉 3 处"把本机/平台假设当普遍事实"的假红**（全部加/扩了自证）：`test-all.sh` 的工具链预检不看所选分组（`--rust` 也要求 cmake/go/node，在只有 cargo 的机器上先卡 cmake、装完又卡 go）→ 改为按分组取工具链的纯函数 `required_tools()` + `--self-test` 反向注入（PATH 无 cmake 时 `--rust` 必须通过、`--cpp` 必须点名判红）；`bench.rs` 的串行档断言「效率 < 下限 0.25」在 2 核上是 **0.33**（核太少表达不出抢锁）→ 改为机器无关形态（永远断言串行 < 并行；`ap ≥ 4` 才断言比值下限；另加与核数无关的兜底「串行档顶档聚合 < 该档下限」），两机复验各 13/13；`test_live_capture.cpp` 写死两个平台常量（`0xFFFF` 在 Linux 是具名的 `ARPHRD_VOID`、`kNoSuchIface` 32 字符 > `IF_NAMESIZE`=16 会先命中"接口名过长"分支）→ 改用 `0x10000`（超出 16 位编号空间，期望值由常量算出）与短接口名，两机复验各 6/6。④ **修正一处记错的事实**：该机是 **4 KiB 页**而非 64 KiB，`af_packet.h` 的 PAGE_SIZE 运行时假设仍有覆盖价值，但 **64 KiB 页路径仍无覆盖环境**。④ **顺带修掉一处默认门禁的潜伏假红**：`--live` 的 D 项用 `tshark -e eth.type` 当裁判，而 STP BPDU 是 802.3+LLC 帧（没有 EtherType）→ `eth.type` 为空 → 旧 awk 的 `NF` 过滤把空行整行丢掉 → 裁判少数 6 帧、把「两实现一致判 6、裁判判 0」报成不一致；**只要网内有交换机发 STP，这道默认门禁就长期假红**（本机 en0 实测 6 帧；此前各批「13 项全过」只是因为抓包窗口里恰好没有 LLC 帧，虚拟机那次是 0==0 空过）。改裁判口径为 `frame.protocols`（无 ip/ipv6 即非 IP，抽成 `nonip_count()`），不一致时摊开三方计数与错误码；修后本机 8==8、虚拟机 0==0。并把它做成**每次都会跑的自证**（合成「1 帧 LLC/STP + 1 帧 IPv4」样本，断言裁判只数 1 帧非 IP；反向注入旧口径立刻红 0 != 1），该关口由 13 项变 14 项。**未达成**：该机 2 vCPU 上吞吐类结论不可用（`--bench` 只能 `--report-only`，照阈值跑必红且**不得据其判红**）；macOS 侧真抓包仍需一次免密 sudo 现场 |
| 2026-10-04 | **稳态吞吐与 10G 的差距：先量再决定 —— 走「每核一张独立表」，核预算 4 核/10G 口（`CYS-TRF-006` 路线定案、`CYS-TRF-037` 加 6 项判据与第 4 项注入）** | ① **先做便宜实验，再决定**（HANDOFF §8 第一梯队第 1 项明确要求「别在没有实验数据的情况下直接重构流表」）：新增「多实例分核实验」—— N 张**完全独立**的 `FlowTable` 各占一线程跑稳态 update，外加两条对照：**纯计算对照**（同线程数、同操作次数、只做寄存器运算，量出**机器本身**的多线程上限）与**小工作集对照**（每实例 2000 条 ≈3MB，能进每核 L2）。实测（M1 Pro / 10 逻辑核 / release / 每实例 12.5 万条）：1 线程 6.9~8.6、2 线程 13.4~15.3（效率 0.82~0.96）、4 线程 22.6~26.2（0.71~0.95）、8 线程 28.0~34.8 Mops/s（0.42~0.63）。② **结论：2 核即压线达标、4 核留 1.5~1.8 倍余量 → 核预算 4 核/10G 口**（判据项 `table-cores-for-10g` 取「最小档位使聚合 ≥1.5×14.88Mpps」，余量留给同核上的特征/会话等环节）；**热/冷字段拆分暂不做**，它是「省核」才需要的优化，而核预算远小于常见机型核数，触发条件（目标机型核预算 < 所需核数，或单表规模再涨一个数量级）已写进 HANDOFF §2.6。③ **8 线程不再近线性，但不是表内的共享瓶颈**：同机纯计算对照同样上不去（0.54~0.73），小工作集对照每线程吞吐只比大工作集高 34~67% 且仍只有自身单线程的 0.4~0.5 倍 → 机器级并发上限是主因、访存是次要因素。判据因此改成**比值**（流表效率 ÷ 对照效率）；把目标贴着实测均值设（0.7~0.8）会让判定在抖动区间里随机翻转，故目标取 0.5（拦的是塌到 0.1 量级的共享瓶颈）、下限 0.25。④ **顺带发现一个结构性前提**：`FlowTable` 原先**不是 `Send`**（观察者 `Box<dyn FlowObserver>`、测试实现用 `Rc`）——「每核一张表搬进 worker 线程」这条路**根本无法表达**（bench 直接编译失败）。改为 `Box<dyn FlowObserver + Send>`（只要 `Send`、不要 `Sync`：表不需要被多线程共享引用），并加编译期断言 `table_is_send_so_it_can_move_to_a_worker_thread`；测试观察者随之从 `Rc<RefCell>` 换成 `Arc<Mutex>`。⑤ **判据的判据**：新增反向注入 `--inject-serialized-scaling`（门禁第 4 项，要求判红且退出非零）+ 单测（真表真锁、真线程）；同时修掉一处我自己引入的阈值错误 —— 8 线程档的回归下限按线性算是 16，**比需求目标 14.88 还严**，会让「未达标」同时被报成「退步」（仓库硬规则：两类阈值不可混用），已把每档下限封顶到需求目标，并由 `floors_are_never_stricter_than_targets` 守住。⑥ **判据总数 13 → 19**（门禁的手写用例数清单同步更新，否则「N 项全过」会因为少跑几项而依然是绿的）；另修一处**测量口径错误**：纯计算对照原先只做与流表同样**次数**的运算（约 0.15ms），与线程启动开销同量级 → 放大 32 倍到同一量级（约 5ms/线程）。⑦ **顺带修正前一批遗留的文档漂移**：HANDOFF §6 里「HTTP 的 UA/状态码/… 未做」「DNS 的 RCODE/EDNS0 未做」两行与「21 条向量」在上一批完成后未回写，已改为已完成（并写明 Content-Length 未登记属性、`dns-negative-garbage` 的 tshark 分歧）。**未达成**：① 多实例尚未接进实际消费路径（`analyze`/`ring-consume` 仍是单表）；② 整条每包流水线的**总**核预算未核算（特征/会话等环节各有 14.88 Mpps 目标，实测 4~7 Mops/s）；③ 2 线程档在压线附近抖动（13.4~15.3 vs 需求 14.88），达标判定会随运行摆动 —— 这是**实测事实**，也是「推荐 3~4 个 worker」的理由。 |
| 2026-09-14 | 初版建立 | 基于 `eaaa575` 全量代码审查生成；含 20 个域、9 个里程碑、全部任务编号 |
| 2026-09-14 | 依赖图断环（8 处） | 新增 `docs/planning/scripts/check-deps.py` 做环检测，查出 8 处双向依赖。根因：`CYS-DBT-*` 为「审计发现项」，被误填成依赖其相关任务，形成反向边。修正原则：**执行修复的域任务无前置依赖（填 `—`），发现项依赖该修复任务以确认关闭**。涉及 `CYS-CON-005`/`CYS-RTD-006`/`CYS-TRF-001`/`CYS-RTD-003`/`CYS-DBT-017`/`CYS-RTD-002`/`CYS-POL-014`/`CYS-RTD-004` 的依赖列。断环后依赖图：0 环、0 悬空引用、0 自依赖 |
| 2026-09-14 | 状态标记规范化 | 状态列误用 `✅`（非受控词汇），导致 `count-backlog.sh` 漏计 20 行、`--write` 静默把总量 349 写成 329。已统一为受控词汇 `☑`，并为 `count-backlog.sh` 增加防呆闸：宽匹配行数与严格解析不一致时**拒绝写盘**并列出未识别标记（已用注入非法标记 `🔵` 的方式验证闸门生效） |
| 2026-09-14 | 首批 20 项完成 | 见 §6.6：M1 13/54、M2 2/38、M5 4/24、M6 1/38。含 CI 四语言矩阵、共享包 `services/pkg`、routerd 配置生效/优雅关闭/envelope `code`/CORS、pcap 文件后端、`rustfmt.toml`、Rust 锁文件入库等 |
| 2026-09-14 | 已知遗留：`CYS-PKT-006` 前置未闭环 | `CYS-PKT-006`（pcap 后端）已验收通过，但其声明的前置 `CYS-PKT-005` 仍为未开始。原因：`CYS-PKT-005` 的验收要求 `pcap`/`af_packet`/`xdp` **三者**均实现后端接口，而供 `CYS-PKT-006` 消费的接口部分（`backend.h`）已交付并完成对接；`af_packet`/`xdp` 属独立后续任务。故保留 `CYS-PKT-005` 未开始，待三者齐备后关闭。此项由 `check-deps.py` 的状态一致性检查报告，属**预期内的语义重叠**，非数据错误 |
| 2026-09-14 | **修复 `fmt-all.sh` 从未可执行** | `scripts/fmt/fmt-all.sh:23` 调用了 `need_cmd`，但该函数只定义在 `lint-all.sh`/`build-all.sh` 中，本文件内**从未定义**，脚本在第 23 行即中断（`exit=127`），`make fmt` 这条路径实际不可用。修复：补齐 `need_cmd`，并引入与 `lint-all.sh` 同一套 `clang-format` 位置探测（原用裸 `clang-format`，同样会踩 PATH 问题）。修复后实测跑通 C++/Rust/Go 三段并 `exit=0`。**遗留**：两脚本各持一份探测逻辑，应抽到 `scripts/lib/toolchain.sh` 共享（待补项） |
| 2026-09-14 | **修复 macOS bash 3.2 多字节变量名解析缺陷（全仓 5 处）** | macOS 自带 `bash 3.2.57` 会把**紧跟在 `$VAR` 后面的多字节字符并入变量名**。在启用 `set -u` 的脚本中会直接报 `unbound variable` 并中断。全仓扫描定位 5 处：`scripts/build/build-all.sh:62-64`（`$cmake_ver（`、`$go_ver（`、`$node_ver（`）—— 该项最危险，仅在工具链版本过低的**错误路径**触发，本应打印清晰提示却会中断；`scripts/security/scan-secrets.sh:91`（`$REPO）`）—— 表现为输出首行路径被截断成乱码 `��`（长期未能定位的疑团，本次确认根因）；`scripts/fmt/fmt-all.sh:56`（`$CF_BIN）`）。统一改为花括号写法 `${VAR}`。验证：`fmt-all.sh` 跑通、`scan-secrets.sh` 正确打印仓库根路径、`build-all.sh` 保持 `exit=0`，全仓残留为 0。**约定**：本仓库 shell 中变量引用一律使用 `${VAR}` 花括号形式 |
| 2026-09-14 | 新增仓库级校验脚本 | ① `docs/planning/scripts/check-deps.py` —— 依赖图环检测 / 悬空引用 / 自依赖 / 状态一致性 / 可开工任务；本次据此修掉 8 处环。② `docs/planning/scripts/count-backlog.sh` 增加防呆闸（见上）。两脚本均纳入日常维护流程 |
| 2026-09-14 | 修复 `cythsec-parse` 无参崩溃 | `cli/parse_main.cpp` 中 `strcmp(argv[1], "-r")` 早于 `argc < 2` 判断，`argc==1` 时 `argv[1]` 为 `NULL`，属未定义行为。实测 `exit=139`（SIGSEGV），修复后 `exit=2` 并正常打印用法（同时补上此前缺失的 `-r` 用法说明）。关联 `CYS-PKT-006` |
| 2026-09-14 | 新增 pcap 样本集（补 `CYS-PKT-006` 验收缺口） | `datasets/pcap/` 此前**仅有 `.gitkeep`（空目录）**，导致 `CYS-PKT-006` 的验收标准「能完整读完 `datasets/pcap/` 样本且计数正确」实际无法满足（55 个断言全用自构造字节流，覆盖边界但未验证真实样本端到端）。处置：新增 `datasets/pcap/generate-samples.py`（确定性生成器，不塞来历不明的二进制 blob）+ 2 个样本（`sample-ipv4-mixed.pcap` 4 包含 1 个截断包 / `sample-ipv6-tcp.pcap` 1 包）。验证：`cythsec-parse -r` 端到端 **4/4 解析成功**，截断包（caplen=54/wirelen=66）准确识别，L3/L4 分布精确匹配 |
| 2026-09-14 | **修复 C++ lint 门禁假绿灯（重要）** | `scripts/lint/lint-all.sh` 用 `command -v clang-format` 探测工具，而 macOS 上 `clang-format` 随 Xcode CommandLineTools 安装却**不在 PATH**（实际位于 `/Library/Developer/CommandLineTools/usr/bin/clang-format`，版本 21.0.0），导致该门禁被静默跳过，从未真正执行过。补测发现 **29/30 个 C++ 文件不通过** `--dry-run --Werror`（含本次开发之前已提交的 `main.cpp`/`packet.h`/`packet.cpp`），即 CI 的 C++ lint job 必然失败。处置：① 脚本改为探测多个常见安装位置，并把「找不到工具」计为门禁失败而非跳过；② `.clang-format` 原先 `BasedOnStyle: LLVM` 的默认 `PointerAlignment: Right` 与代码库一致使用的**左对齐指针**冲突，且多项 LLVM 默认值在 clang-format 18 后已改为结构体形式 —— 按「配置适配既有代码」原则重写配置（显式声明 `PointerAlignment: Left`、`SortIncludes.Enabled: false`、`AlignTrailingComments.Kind: Always`、`ReflowComments: false` 以保护中文注释等）；③ 对 28 个文件执行 `clang-format -i` 消除残余差异（改动前已备份至 `/tmp/cpp-backup/`，改动前记录 30 个文件的 SHA-256）。**行为中性已验证**：重建 0 错误 0 警告，CTest 3/3，`test_packet` 5 + `test_parser` 64 + `test_pcap` 55 = **124 个断言与格式化前完全一致** |
| 2026-09-14 | **修复 master 主干 Rust 端编译失败（重要）** | `dataplane/traffic-engine/src/channel/region.rs` 引用了 `AttachError::SlotCountMismatch` / `SlotSizeMismatch`，但真源 `configs/registry/channel-abi.json` 中这两条诊断已被删除、生成枚举里也无对应变体，`cargo build` 报 2 个 E0599 —— 即**主干处于无法编译状态**。核实为依据误删（`channel/tests.rs` 明确断言这两个码，`attach_expect` 的语义也需要它们），故在真源恢复两条诊断（字段 `local`/`remote`，severity `error`）并重新生成双端契约。验证：`cargo build` 0 错 0 警、`cargo test` 48 passed、C++ 构建通过 |
| 2026-09-14 | **修复诊断可达性检测器的成片误报** | `tools/codegen/gen-channel-abi.py` 的 `_is_constructed` 只认 `diag::ChanX` 形态，不认识 `AttachError::X` 这类**枚举变体构造**，导致 15 条诊断中 9 条已实现的被误报为「死诊断」。修正为按 `construct_idents()` 给出的多条候选标识逐个判定，并为唯一的命名例外（`chan.io_error` → `ChanIoError`）在真源登记 `impl_ident`。**关键**：修完做注入验证——往真源塞一条真死诊断 `chan.__probe_never_implemented`，确认检测器仍能捕获，避免「把检测器改瞎」；验证后恢复现场并核对生成物字节一致、探针残留为 0 |
| 2026-09-14 | 补齐 `check-channel-abi.sh` 并挂入门禁 | 生成器注释与两个生成物头注释共 4 处写着「改动会被 `scripts/verify/check-channel-abi.sh` 拦下」，而**该脚本此前并不存在**，lint 门禁也没挂它 —— 于是通道 ABI 的漂移检查长期无人执行。新增该脚本（只读校验，退出码区分「生成物过期 1 / 诊断不可达 2 / 真源非法 3 / 缺 python3 4」，好让调用方给出精确修复指引），并在生成器中把三类失败拆成不同退出码；挂入 `scripts/lint/lint-all.sh`，与 `check-attributes.sh` 对称。**约定**：注释里声称「有脚本会拦下」的，该脚本必须真实存在并挂在门禁上 |
| 2026-09-14 | 修复 `attach_expect` 的校验顺序缺陷 | `Channel::attach_with` 把「配置期望值 vs 区域值」的比对放在了 `validate()` 的根基校验**之前**，违反 `validate` 自身声明的「先粗后细」原则：对未初始化区域（全零头部）会误报 `chan.slot_count_mismatch` 而非 `chan.uninitialized`，把排障人引向错误方向。已移到 `validate()` 之后，并加单测锁定该顺序行为 |
| 2026-09-14 | **通道 ABI 三层防线补全第 3 层：跨语言 parity（`CYS-PKT-024`）** | 此前三层中只有前两层落地，且第 1 层在 C++ 侧**从未生效**：`abi_gen.h` 是 header-only，其中的 35 条 `static_assert` 只在有人 include 时才会被编译，而全仓**没有任何翻译单元引用它**（Rust 侧因 `pub mod abi_gen;` 正常生效）。本轮：① 新增 `dataplane/packet-engine/cli/dump_abi_main.cpp` 与 `tests/test_channel_abi.cpp`，使那些断言真正进入编译（注入违背断言验证：编译期如期报错）；② 由**生成器单点生成**双端 parity dump（C++ `dump::AbiDump()` / Rust `abi_dump()`，取值一律取编译产物表达式——常量 / `offsetof` / `sizeof` / 生成的布局函数 / 诊断样本，共 89 行），避免「两侧各写一遍」重蹈漂移；③ 新增 `scripts/verify/check-channel-parity.sh`（构建两端可执行产物后逐行 diff）并挂入 `scripts/test/test-all.sh`（新增 `--parity`）。注入验证：只手改 Rust 侧 `MIN_SLOT_SIZE` 64→65，关口如期报 `exit=1` 并同时抓到派生出的 `layout.probe.min_x_min.required` 差异；恢复后两端 89 行完全一致。④ 新增真源级不变量 `descriptor_step == sizeof(PacketDescriptor)` 的编译期断言（此前无人守：step 大于描述符尺寸会读到槽间空隙，字段都有值但全部错位） |
| 2026-09-14 | 修复 `test-all.sh` C++ 栈「用旧产物验收」 | 该脚本仅在 `build/` **不存在**时才配置与构建，之后只跑 `ctest` —— 后果有二：新增目标后不重新配置，ctest 报 `Unable to find executable` / `Not Run`（那句话指不到「配置过期」这个真实原因）；更严重的是**拿上一次构建的产物去验当前源码**，本地绿灯而实际验的是旧二进制。已改为每次重新配置 + 增量构建 + ctest。修复后 CTest 恢复 4/4（新增 `packet_engine_channel_abi`） |
| 2026-09-14 | **修复前端版本号注入链路从未生效（`CYS-INF-020` 相关）** | `web/console/vite.config.ts` 与 `vitest.config.ts` 各持一份版本读取逻辑且路径不一致：后者上溯三级（`../../../VERSION`）实际解析到**仓库外**的 `CLionProjects/VERSION`，`readFileSync` 抛异常后被 `catch` 静默吞掉、回落 `'dev'` —— 版本号看起来「有值」，实际从未来自 `VERSION`。处置：抽出单一真源 `web/console/version-source.ts`（**去掉静默兜底**，读不到直接让构建失败，避免同类问题再次隐身），两份配置改为引用它，并纳入 `tsconfig.node.json`。验证：`version.test.ts` 7 项通过（此前 2 项失败） |
| 2026-09-14 | **修复 `attributes.gen.ts` 生成物编译不过（前端 `typecheck`/`build` 双红）** | `tools/codegen/gen-attributes.py` 生成的三个说明表（`ATTR_VALUE_TYPE_DESC` / `ATTR_SCOPE_DESC` / `ATTR_STAGE_DESC`）用了 PascalCase 派生名作键，而它们的类型是 `Record<AttrValueType, string>` —— 键须取自枚举映射的**值**联合（`"string"` / `"l2"` / `"packet"`），故 TS 报 6 处 TS2561。修生成器（键改用规范标识），并在 `TS_HEADER` 中写明「两类对象的键取法刻意不同」的理由，把这条踩过的坑留在生成物注释里。同时补装 `@types/node`（构建配置需要）、把 `tsc --noEmit -p tsconfig.node.json` 纳入 `lint-all.sh`、清理未入库的 `*.tsbuildinfo`。验证：前端 typecheck 0 错、测试 25/25、生产构建通过 |
| 2026-09-14 | **`CYS-PKT-024` 转 ☑：补齐 C++ 生产端并打通跨语言端到端（`CYS-TRF-034` → ◐）** | 此前该契约**只有 Rust 侧有实现**，C++ 侧仅有一份从未被 include 的 header，所谓「跨语言」实际从未跑起来过。本轮：① 新增 C++ 共享区域层 `include/packet_engine/channel/region.h` + `src/channel/region.cpp`（普通文件 `open`/`ftruncate`/`mmap(MAP_SHARED)`，与 Rust 侧 `Region::map` 同机制；attach 期全部诊断复用生成物的 `diag` 命名空间，保证两端报错逐字一致）；② 新增 C++ 生产端 `producer.h/.cpp`（SPSC 语义严格对齐 Rust `tests.rs` 的 `TestProducer`：先数据后描述符、release 序发布 head、超长帧只计 `dropped` 不计 `full_events`、环满同时计两者并丢新帧、绝不触碰消费端专属字段）；③ 新增 `cli/ring_feed_main.cpp`（pcap → 环，支持多源）与 Rust `src/bin/ring_consume.rs`（attach 既有环 / `--from-head` / `--expect-*` 断言）；④ 新增 `scripts/verify/e2e-shared-ring.sh`（**C++ 进程写 → mmap 文件 → Rust 进程读并解 Flow**，4 阶段 19 项断言）并挂入 `test-all.sh --e2e`。**注入验证抓到两处真实缺口**：一是注入「`desc.data_off` 误用区域相对偏移」后诊断如期报错，但输出里暴露出诊断文案含一长串游离空格（行连接符展开后的残留，仅出现在面向排障者的文案里，已全仓扫描修净）；二是注入「生产端 `published` 双计」时 **19 项断言全部通过 —— 关口存在漏洞**：两端 CLI 各自报的都是本地计数，无人核对区域内实际落下的计数器，而那正是运维排障唯一能看的字段。据此补上「区域共享计数」记录与本地/区域交叉核对断言，重做同一注入后如期被抓。另修正 e2e 汇总行**写死的断言数**（原写 17、实为 19）为动态累计。`CYS-TRF-034` 只转 ◐ 而非 ☑：其验收标准含「真实网卡 → Flow」，而网卡侧依赖 `CYS-PKT-007`/`008`（均未开始，`xdp/`、`af_xdp/`、`dpdk/` 仍为空占位），本轮达成的是「真实 pcap → 环 → Flow」，已在条目中显式标注，不含糊成已完成 |
| 2026-10-02 | **网卡通用版：Linux AF_PACKET + macOS 原生 BPF 双后端落地（`CYS-PKT-007`→◐ / `CYS-PKT-008`→◐ / `CYS-PKT-030`→◐）** | 需求为「openEuler / Ubuntu / Rocky Linux 通用 + 开发机 macOS 也能抓」。① `iface_list.{h,cpp}` 跨平台接口枚举（`getifaddrs`；Linux `SIOCGIFHWADDR` / macOS `AF_LINK`），实测 macOS 上 `getifaddrs` 与 `sysctl(NET_RT_IFLIST)` **两条路径都返回占位 MAC** `02:00:00:00:00:00`（`ifconfig` 显示真值），故加 `mac_hidden` 标志把「平台隐藏」与「本就无 MAC」分开显示，避免全列 `-` 被误认为枚举 bug。② `af_packet.{h,cpp}`：运行时 `setsockopt(PACKET_VERSION)` 探测的 **V3→V2→`recvfrom` 降级链**，`PACKET_RX_RING` 页对齐与整除约束修正。③ `bpf_capture.{h,cpp}`：macOS 原生 BPF（**本机无 libpcap**，故不走 libpcap），`/dev/bpf0..255` 逐个尝试、`BIOCSBLEN` 后回读实际值、`bpf_hdr` 20 字节 + `BPF_WORDALIGN` 步进。④ 统一后端工厂按平台路由 `live`（Linux→`af-packet` / macOS→`bpf`），平台不匹配时返回明确错误而非静默 `nullptr`；新增 `wait_readable` 虚接口避免忙等。⑤ `cythsec-capture` CLI + `pcap_writer`（`-w` 落盘）。**验证**：Ubuntu 24.04(6.8) / Rocky 9(5.14) / openEuler 24.03(6.6) 三发行版 Docker 容器内**零错误零警告**编译并真实抓包（容器内 `apt`/`dnf` 装依赖须与编译在**同一次 `docker run`** 内完成，否则容器退出即丢失）；macOS 侧新增 `test_live_capture.cpp` **73 项断言**全过，CTest 6/6。**诚实标注**：macOS 真抓包未达成（`/dev/bpf*` 属 `root:wheel 600` 且本机无免密 sudo），该路径在 e2e 中显式标 `SKIPPED` 不显绿；`CYS-PKT-008` 只转 ◐ 是因为验收标准要求的「吞吐显著高于 pcap live」**尚无实测对照数据**。另修 CLI 三处缺陷：`--list-ifaces`/`--list-backends` 污染输出 `capture result`（会让 e2e 抓取误判）、`--list-backends` 自指（输出「live 路由到 live」，实际应为 `bpf`）、MAC 全显示 `-` |
| 2026-10-02 | **DPI 深度包检测落地：TLS/JA3（CYS-TRF-021）、DNS QNAME（CYS-TRF-023）、HTTP Host（CYS-TRF-020）、识别框架（CYS-TRF-019）** | 起因：「pcap 这个流量一大就不行了」—— 实测 `pcap_file.cpp` 在 open 时把**整个文件**读进 `std::vector<PacketBuffer>`，非流式、无界内存且不报丢包，省网 100G 物理上走不通。本轮补的是**识别能力**这一侧：① 新增 `datasets/dpi/` 测试向量体系（`generate-dpi-samples.py` 确定性生成器 + 21 个 `payloads/*.bin` + 3 个 pcap + `expected.json`），期望值由**构造参数**推出而非解析产出，避免"自己解析自己"的循环论证；② 新增 `scripts/verify/check-dpi-vectors.sh` 用 **tshark 4.6.7 独立实现**作第三方互证（22 项 SNI/JA3/QNAME/Host 逐条一致），挂入 `test-all.sh --dpi`。③ Rust `src/dpi/`：`mod.rs` 三级递进框架、`tls.rs`（ClientHello + JA3）、`dns.rs`、`http.rs`、`attributes.rs`、`md5.rs`（自实现，零第三方依赖）。**修复的六个真实缺陷**：MD5 的 B 初值 `0xEFCD89AB` 应为 `0xEFCDAB89`；MD5 摘要逐 u32 输出时字节序写反；MD5 第 3 轮 G 表抄错一格（`3i+5` 应得 `5,8,11,14…`）；握手长度是 **3 字节且从偏移 6 起**（按 2 字节从偏移 5 读会整体错位）；`Cursor` 忘了跳到握手体起点偏移 9；SNI 与 `supported_groups` 扩展体的**长度头**被当成列表元素（表现为指纹里多出一个来路不明的小数字）。**修生成器自身一处缺陷**：`tls-bad-inner-len` 的偏移写成 `5+2+32+1=40`，漏算 4 字节握手头，实际改坏的是 random 而非 cipher_suites 长度 —— 这条「畸形」样本其实完全合法，是测试期望 `malformed` 才把它暴露出来（畸形样本必须真的畸形，否则测的是空气）。**注入验证**：改坏期望值 → 脚本与 Rust 测试双双报错；去掉 GREASE 过滤 → `tls-grease` 如期失败；两次均恢复现场并做字节级 `cmp` 比对。**已知例外不冒充通过**：ECH 向量 `tls-ech-no-outer-sni` 无法用 tshark 交叉核验（tshark 对手工构造的 ECH 体一律判畸形并抑制整包 JA3），已在 `expected.json` 显式标 `tshark.verified=false` + 原因，并由测试守门防止该标记被悄悄改回 `true`。④ **闭合「契约层已有、实现层为零」的缺口**：`attributes.rs` 首次真正产出 `ATTR_TLS_SNI`/`ATTR_TLS_JA3`/`ATTR_DNS_QNAME`/`ATTR_APP_ID` 等属性（此前它们只存在于字典、生成物与示例规则里，没有任何生产者），约束为「只产出已登记属性 + 常量引用 `attributes_gen` 不手写 + 未识别**不产出**空串属性」 |
| 2026-10-02 | **TCP 乱序重组落地（`CYS-TRF-016`→◐ / `CYS-TRF-017`→◐）** | 承接上一批：DPI 只做首包判定，被 TCP 分段切开的首包只能判 `NeedMore`，补字节的人就是重组层。新增 `src/reassembly/`：`seq.rs`（32 位序号回绕算术 —— 10G 链路跑满约 3.4 秒就绕一圈，回绕**不是边界情况而是必现**；并把"恰好相距半个序号空间时双向都成立"这一循环空间固有退化点写成测试固化）、`intervals.rs`（有序区间集，三条不变式：按 start 严格递增 / 互不相交 / 互不相邻；重叠仲裁 `KeepOld`（Linux 语义，先到者胜 —— 旁路要复现的是**接收端真实收到的字节流**，而不是攻击者最后重发的版本）与 `KeepNew`（BSD）双策略）、`stream.rs`（单向流：SYN 锚 ISN+1、中途接入时标 `anchored_by_syn=false` 让"开头完整性未知"可被下游看见、内存上限按**保连续弃乱序**降级）、`tcp.rs`（头与选项解析，顺带完成 CYS-TRF-017）。**向量体系**：`datasets/reassembly/` 10 条向量（顺序/逆序/交错/重叠一致/重叠冲突/重复重传/跨零回绕/被切开的首包/内存上限/FIN 同段），期望值**手写**而非"跑一遍实现记下来"—— 后者等于让被测实现给自己的答案打分。`scripts/verify/check-reassembly-vectors.sh` 用 tshark 独立复核 **16 项**（重组字节流的长度+sha256；切开 ClientHello 重组后的 JA3/SNI 与 `datasets/dpi/expected.json` 跨集一致），挂入 `test-all.sh --reassembly`。**注入验证三处**：① 改坏 `expected.json` → tshark 门禁与 Rust 测试双双报错（`exit=1`），恢复后字节级 `cmp` 一致；② 把 FIN 序号写成 `seq`（漏算载荷长度）→ 2 项测试如期失败；③ **把 `feed` 里"先数据后 FIN"对调 → 76 项测试全绿**，据此证实该顺序对最终状态实际无影响（`on_fin` 只记序号，与插入互不干扰），已把源码里那句"顺序必须如此"的夸大注释改成真实约束（真正敏感的是 FIN 的**序号**），避免留下一条"看起来很重要其实无所谓"的规则。**已知例外 2 条**（`overlap-conflict` 因 tshark 重叠仲裁策略不同且不可配置、`memory-cap` 因 tshark 无内存上限）显式标 `verified=false` + 原因并由测试守门，不冒充已核验。另把 dpi 测试里的 JSON 解析器抽成共享的 `src/testjson.rs`（两份解析器行为差异会变成"字段被读成 null 而测试仍报绿"的假绿灯） |
| 2026-10-02 | 修复 C++ lint 门禁复发的成片不合规 | 上一批新增的 C++ 文件（`iface_list` / `af_packet` / `bpf_capture` / `backend` / `capture_main` / `pcap_writer` 等）未执行 `clang-format`，`lint-all.sh` 的 C++ 段持续报红（历史同类事故：29/30 文件不合规却被静默跳过）。已对全仓 50 个 C/C++ 文件执行 `clang-format -i` 并复检 0 违规，**行为中性已验证**：cmake 重建 0 错、CTest **6/6 通过**（`packet_engine_unit` / `parser` / `pcap` / `channel_abi` / `channel_producer` / `live_capture`） |
| 2026-10-02 | **核查发现：§3.4 M4 控制平面小节状态已滞后于代码** | 接力文档编写期间逐项复跑门禁时发现：`services/policyd`（4362 行源码 + 2896 行测试，含完整 `ruleir` 引擎）、`services/dnsd`（621+860）、`services/telemetryd`（687+984）、`services/pkg`（2689+1735）**均已存在，19 个 Go 测试包全部通过**（`services/*/` 下 `go test ./...`），而本表 `CYS-POL-001` / `CYS-DNS-001` / `CYS-TEL-001` 及 M4 里程碑仍标 ⬜。成因：实现由并行协作者在 `9748175` / `8e0fb03`（2026-09-14）落库，该批提交未回写本表。**处置**：① 本表 §3.4 顶部加显眼提示，说明真实缺口在「落地侧」（nftables 下发 / 原子回滚 / PG 持久化 / 版本化 / 命中统计 / 审计日志 / 服务间联动），避免后人照表做重复劳动；② **不逐项批量改状态** —— 刷新需对每项验收标准逐条核实（例如 `CYS-POL-005` 要求「重启后策略完整恢复」，而现存储为纯内存，实际**未达成**），已列为 `HANDOFF.md` §8 并行线 C2，属独立工作。教训：**并行开发的仓库里，实现跑在待办表前面是常态；状态标记的更新必须与实现同批提交** |
| 2026-10-03 | **数据面主干落地（流表/超时/逐出/回调 + TCP 状态机 + 会话管理器，`CYS-TRF-006`→◐ / `007`→◐ / `008`→☑ / `009`→☑ / `010`→☑ / `011`→☑ / `012`→☑ / `013`→◐）** | 承 `64f4079`：`flow/table.rs` 按 FNV-1a 分片（分片数向上取 2 的幂、每片 `HashMap`，确定性顺序由显式排序给出（**顺序不确定就谈不上可复现的门禁**））、五档超时表（`TimeWait` 刻意复用 transient 档）、容量 + LRU 逐出（最小键打破平局）、`FlowObserver{on_new,on_update,on_evict,on_timeout}`（回调只拿 `&FlowEntry`，**不可改流表**）；`session/` 会话 id 复用池、双向聚合与反向键规范化、「先见响应后见 SYN」也能正确归属；`tcp/` 完整状态机 + 非法迁移计数（不 panic）+ 严格/容忍双模式。**定调**：`fwd`/`rev` 是**规范端点序**而不是「发起方/响应方」—— 发起方单列 `initiator` 字段，两者混用会让下游把方向当角色用。验证：`cargo test -p traffic-engine` 全绿；`--e2e`/`--parity` 无回归。 |
| 2026-10-04 | **从「能识别」到「能产出记录」（`CYS-TRF-004/005/014/027/033/035`→☑，新增 `--flows` 第三方门禁）** | 补齐 `Packet → FlowTable → Session → FlowRecord` 的后半段：`flow::Proto` 类型化、`FlowKey::canonical()` 方向无关会话键、`FlowStats` 扩展（min/max/mean/stddev 包长 + 12 桶 log2 包长直方图 + 容量 64 的 IAT 环形缓冲，在线 Welford、饱和算术）、`feature::FeatureExtractor` 21 维特征（含载荷熵，熵在聚合直方图上算，`0` 用 `bytes` 列消歧）、`record::FlowRecord`（`schema_version=1`，列名与顺序由快照锁定）、CLI `cythsec-analyze -r x.pcap -o flows.jsonl`（`--strict/--limit/--inspect-bytes/--max-sessions/-o -`，统计走 stderr 以保证 `-o -` 的 stdout 是纯净 JSONL）。**本轮修掉一个真实缺陷**：会话层用 IP 载荷长度（含 20 字节 TCP 头）判定 TCP 事件，于是每个纯 ACK 都被当成 `Data`；容忍模式下碰巧仍能走到 `Established`/`TimeWait`（**旧测试全绿的原因**），严格模式下则卡在 `syn_received`、`FinWait2`/`CloseWait`/`LastAck` 永不可达。修法是把「段载荷长度」与「记账用 IP 载荷长度」显式分成两个量（`TcpObservation`）而不是在调用处随手换算，并补 2 个回归测试。**新增第三方门禁** `scripts/verify/check-flow-records.sh`（挂 `test-all.sh --flows`）：tshark 独立解析样本后逐流核对 **725 项**（会话集合 / 包数字节数 / 双向计数 / 方向切换 / 首末时间戳 / TCP 末态 / 发起方 / 中途接入 / 应用识别 / 解码失败计数 / 统计自证），TCP 末态的判定规则是**照着 tshark 的标志位序列重写的第二实现**（不是抄 Rust 迁移表），覆盖不到的组合打印 `SKIP` 且不计入通过（共 7 项跳过，全部有理由）；并默认执行**反向故障注入**：17 项篡改（含改 tshark 事实、改自家 stderr 摘要、空输入）必须全部被检出，否则判红 —— 否则「核验器恒返回成功」也会一路绿灯，而绿色的「通过」与绿色的「没跑」长得一模一样。**顺带修正一处过期期望**：`--e2e` 硬编码「5 个报文」，新增 `sample-session-tcp.pcap` 后该断言如期报红（5→23），已把期望值改成可逐项复核的分解式（4+1+18 帧 / 4+1+9 流 / 1 个非首片分片），并把「这组数字是活的」写进注释。验证：`--cpp --rust --dpi --reassembly --flows --parity --e2e` 全绿 + `lint-all.sh` 7 项全绿。 |
| 2026-10-04 | **仓库完整性：`.gitignore` 的裸目录名吃掉三处源码（新增并落地 `CYS-INF-035`，`CYS-DBT-013`/`016`→☑）** | ① **现象**：`scripts/release/check-version.sh` 在上一批被挂进门禁后，**全新克隆里跑不通** —— 因为 `scripts/release/` 整个不在版本控制里。顺着查下去发现这不是孤例：`.gitignore` 里 `build/`、`target/`、`release/` 都**不带前导斜杠**，按 gitignore 规则匹配**任意层级**的同名目录，于是 `scripts/build/build-all.sh`（四端统一构建入口）与 `services/telemetryd/internal/target/`（telemetryd 直接 import 的 Go 包，4 个文件）也从未入库。三处在本地都完全正常：文件在、权限对、脚本跑得通、`git status` 不提示。 ② **后果是「发版必红」级的**：全新克隆缺 `scripts/build/build-all.sh`（`check-version.sh` 直接报它不存在），且 `cd services/telemetryd && go build ./...` 报 `package cythsec/services/telemetryd/internal/target is not in std` —— 即 telemetryd 根本编译不过。**「本地全绿」与「克隆能构建」是两件事，靠真的 clone 一次才发现。** ③ **修法**：目录类 ignore 模式一律锚定到根（`/build/`、`/cmake-build-*/`、`/target/`、`/out/`、`/dist/`、`/release/`，并把原因写进 `.gitignore` 注释），三处文件按原有权限入库（`build-all.sh` 755）。 ④ **系统性防线（`CYS-INF-035`）**：新增 `scripts/verify/check-ignored-sources.sh`，在「版本控制的事实」上扫描 `git ls-files --others --ignored --exclude-standard` 里的源码/脚本类文件，命中即报错并打印是哪条 ignore 规则吃掉了它（白名单只留刻意的生成物/依赖/本地工具状态，每条锚定到根）。**它的判据经过真实反向验证**：修复前在原树上判红并逐条点名 5 个文件与对应规则，修复后转绿 —— 不是「写完就绿」的空检查器。已挂成 `lint-all.sh` 的 `[repo]` 一项（lint 8 → 9 项）。 ⑤ **顺带核实两张相邻卡片**：`CYS-DBT-016`（`git ls-files cmake-build-debug` 为空）实测成立；`CYS-DBT-013` 的白名单行指向不存在的文件且本身多余，按卡片给出的选项**移除该行**并留注释。 验证：`lint-all.sh` **9 项**全绿；全新克隆里 `check-version.sh`、`check-version.sh --self-test`、`test-all.sh --self-test` 全绿且 `telemetryd` 可编译；`--go` 全部测试包通过。 |
| 2026-10-04 | **版本单一真源收口：检查器挂门禁 + 反向注入自证 + 产物级四端验收（`CYS-INF-020`/`021`→☑、`CYS-DBT-009`→☑，`--node` 假红灯消除）** | ① **一个没人执行的检查器等于没有检查器**：`scripts/release/check-version.sh` 早已存在、内容也正确，但**没有任何门禁调用它** —— 于是 `2ecf512` 把根 `VERSION` 改成 `9.9.9` 时 lint/test 全绿，只有「发版前手动跑一次」才会发现四端版本号已经不一致。现挂成 `lint-all.sh` **第 6 条**（真实校验 + 检查器自证两步）。② **更狠的一层：那个检查器根本没入库**。`.gitignore` 里写的是不带前导斜杠的 `release/`，按 gitignore 规则它匹配**任意层级**名为 `release` 的目录 —— 于是 `scripts/release/` 整个被忽略，两份脚本从未进入版本控制：`scripts/README.md` 与交接文档都在引用它，`git status` 却看不见它，**全新克隆里根本没有这个文件**（这也解释了为何第 ① 条长期没被发现：不是没人跑，是跑不了）。已改为 `/release/`（只忽略根目录打包输出，并在 `.gitignore` 里写明原因），两份脚本以 755 入库；全仓复查确认再无其它被忽略的源码/脚本（只剩 `datasets/**/expected.json` 这类刻意的生成物）。③ **给检查器加反向注入（`--self-test`）**：在临时目录搭一份最小仓库树（8 个文件），先要求「一致 → 退出 0」（防自证诬告），再注入 3 处不一致 —— `Cargo.toml` 版本漂移、`CMakeLists.txt` 回退成硬编码 `9.9.9`、`build.rs` 注入实现被删空 —— 要求**分别判红并且在输出里点名对应文件**。绿色的「通过」与绿色的「没跑」必须能区分开。④ **产物级验收（不是看源码推断）**：新增 `scripts/release/check-version-bump.sh`，把真源临时改成 `0.1.1` 后**重建四端**，要求 `cythsec-analyze --version`、`policyd -version`、`hello_packet --version`、前端 vite 产物**各报 0.1.1**，并在同一状态下要求 `check-version.sh` 判红（真源改了没同步副本能被抓出），最后自动复原真源 + 复核。实测四端全部通过；产物全部落在临时目录、`VERSION` 由 `trap` 保证复原（改真源做实验必须防「中断后留在实验值上」）。⑤ **`--node` 的假红灯消除**：`test_node()` 改成「`node_modules/.bin/vitest` 在位就直接 `npm test`，不在位才 `npm ci`」，并把失败分类抽成 `classify_npm_ci_failure()`（含 `SAFE_DELETE_BULK_CONFIRM_REQUIRED` 才报「环境拦截，不是网络问题」，其余一律「真失败」）—— 抽成函数是为了能自证：写在 `if` 里就只能靠「真的触发一次批量删除保护」来验证。`test-all.sh --self-test` 用 stub `npm` + `CYTHSEC_FORCE_NPM_CI=1` 把此前**从未执行过**的拦截分支真正跑一遍（4 场景：分类×2 / 拦截 / 真失败 / 成功），挂在 `--node` 前自动执行。⑥ **顺手记下两个环境坑**：`cmake-build-debug/` 是 IDE 的陈旧离树缓存（配置于 `VERSION=9.9.9` 时期），它的 `hello_packet --version` 至今打印 `9.9.9`，拿它验收会以为修复没生效（验收一律用 `build/`）；产物版本号是构建期烙进去的，改了 `VERSION` 必须重新构建才能看到变化。验证：`lint-all.sh` **8 项**全绿（含新的版本真源 + 自证）；`test-all.sh --node` 自证 4 场景 + 前端 25 项全绿；`check-version-bump.sh` 四端产物级验收通过；`--rust` 320 项、`--dpi` 22 项、`--reassembly` 16 项、`--flows` 725 项/17 注入全绿。 |
| 2026-10-04 | **逐出从 O(每分片容量) 压到 O(1)，语义不变（`CYS-TRF-008` 加厚、`CYS-TRF-037` 加第 13 项判据）** | ① **先估后改，结论与预判相反**：`evict_lru` 原来是 `shard.map.iter().min_by(...)` 全扫分片，表满后**每次新建流都要付一次**（1.09µs@每片256、**52.2µs**@每片8192，容量 32× → 耗时 52×）。两条候选路线都评估了：**采样 LRU**（Redis 式，K=8）与**链表 LRU**。采样先在原语上量了质量 —— 在「400 条流 / 128 槽位 / 90% 热点」负载上，采样 K=8 的热点流命中率只有 **58.4%**，精确 LRU 是 **99.9%**（复现方式见 `flow/table.rs` 的 `lru_keeps_hot_flows`）；省网里「流被逐出又重建」不是缓存 miss，而是**同一条会话的记录被切成两段**，所以采样被否掉，理由与数字一并写进 `EvictPolicy` 注释。② **改法是纯性能改动、不动语义**：分片从 `HashMap<FlowKey, FlowEntry>`（条目内联在桶里）改为 `Shard { map: FnvMap<FlowKey, u32>, slots: Vec<Slot>, free, head, tail }` —— 槽位数组承载条目，`prev/next` 下标串成双向链表，插入挂尾、命中移尾、逐出摘头，全是 O(1)；旧实现保留为 `EvictPolicy::LruScan` 作对照兼小表/离线复算用。③ **复杂度变成可测断言**（不是注释里的声明）：新增 `TableStats::evict_candidates`（逐出时考察过的候选数），单测要求链表策略**恒为 0**、扫描策略**恰好 = 每片容量 × 逐出次数**；另补 9 项：默认策略 = 链表 LRU、链表与扫描的逐出序列+存活集合在时间戳严格递增轨迹上**完全一致**（等价性）、大分片里必须逐出全局最老者（采样式会在此失败）、同时间戳按访问序而非键序（唯一一处语义差异，已文档化）、槽位复用（数组不随累计插入增长）、`clear()` 复位链表且保留容量、热点命中率 ≥95%。④ **同机背靠背前后对比**（不是隔几天各跑一次）：逐出 1.09µs→**0.21µs**@每片256、52.2µs→**0.34µs**@每片8192，容量 32× 的耗时比 52×→**1.6~1.8×**；insert 0.98→**2.06** Mops/s（快一倍）、单表内存 2390→**970 B/条**（全新进程同配置）；代价是命中路径多一次间接寻址，query-hit 7.68→**5.02** Mops/s（−35%），update/query-miss 在噪声内 —— 这笔账写在 `CYS-TRF-006` 与 §2.5 里，不遮。⑤ **顺带修掉一处判据自身的错误**：`table-steady-memory` 原先拿「填充后 → 灌完 5× 容量」作差，把「IAT 环形缓冲后 63 个槽位的页第一次被触碰」（1M 条时 **+206MiB**，第 2 轮起完全平）算成内存增长；改为**预热一轮不计入判定**、逐轮记录 RSS、取预热后各轮增量最大值，并整条打印原始序列（不藏）。修正后新实现判 **0.00 MiB**。⑥ **新增一项与机器无关的判据** `table-evict-scale-ratio`：容量 32× 下耗时比必须 ≈1（上限 3×）—— 换机器后依然能判「是不是又变回 O(cap)」。验证：`--rust` **320** 项全绿（301 lib + 8 基准 + 6 bin + 5 集成）；`--flows` 725 项比对 / 7 跳过 / **17 项注入全检出**（换掉分片结构后无回归）；`--bench` 13 项回归下限全过 + 3/3 注入检出，需求目标 4/12 → **8/13**；`lint-all.sh` 7 项全绿；`cargo fmt --check` 通过。 |
| 2026-10-04 | 修正一处**方向反了**的依赖边（`CYS-TRF-004` ↔ `CYS-DBT-003`） | `CYS-TRF-004`（修复任务：协议号类型化）原本声明前置为 `CYS-DBT-003`（审计发现项），而 §2026-09-14 那条已确立的原则是「**执行修复的域任务无前置依赖，发现项依赖该修复任务以确认关闭**」。本轮把 `CYS-TRF-004` 的状态改成 ☑ 后，`check-deps.py` 才把它暴露出来（已完成任务的未完成前置从 5 处变 6 处）。已改正方向：`CYS-TRF-004` 依赖置 `—`，`CYS-DBT-003` 改为依赖 `CYS-TRF-004` 并标 ◐（`Proto` 死代码确实已消除；但它的另一条验收标准 `cargo clippy -- -D warnings` 未达成 —— 仓库仍有既有 warning，clippy 也尚未入门禁，不冒充通过）。**教训**：状态标记的刷新会顺带暴露依赖图的陈年错误，所以刷新时不能只看状态列。 |
| 2026-10-04 | **数据面基准落地，首轮就抓出三处问题并修掉一处（`CYS-TRF-037`→☑，`006`/`007` 补上量化证据）** | ① 新增自研基准 `dataplane/traffic-engine/src/bin/bench.rs`（二进制 `cythsec-bench`）：流表插入 / 更新 / 命中查询 / 未命中查询 / 超时扫描 / 两种每片容量的逐出、特征更新、TCP 重组（顺序 / 乱序）、短连接会话归属，共 **12 项**。**刻意不引 Criterion**：本工程硬约定是零第三方依赖 + `--offline` 可构建，基准工具不该是例外；代价是**只报点估计**（每项跑两遍、取第二遍，两遍都打印），没有离群值剔除与置信区间 —— 这一点写进条目，不含糊过去。 ② **两类阈值必须分开**，这是本批最重要的设计：`需求目标`由工作量需求推导（10Gbps 最坏包速率 10e9/(84×8) = **14.88 Mpps**、1M 条扫描 ≤200ms、10Gbps 净载荷 ≥1.25GB/s、新建流速率 ≈ 1M 容量/60s 超时），`回归下限`只回答「这版有没有把上一版跑坏」（≥2× 余量：实测同机连跑两次能差 20~30%，5% 余量只会变成随机假红）。两者混成一个退出码，人就分不清该修哪个；默认退出码只看回归下限，`--require-targets` 才按目标判定。 ③ **反向故障注入**（判定的判定）：`--target-factor 1000` 必须报出「退步」并退出非零；同样放大但加 `--report-only` 必须退出 0（证明报告模式真的不判定）；`--flows 10` 必须被参数校验拒绝。门禁 `scripts/verify/check-flow-bench.sh` 挂 `test-all.sh --bench`，并**刻意不进 ALL 集合**（阈值带机器属性，进默认集合只会变成「随机红的门禁 = 没有门禁」）。 ④ **首轮就抓出三处**：`expire()` 把全部到期条目搬进 `Vec<FlowEntry>`（每条 432B）排序后再派发 → 250k 条「填满→全到期」每轮 RSS **+99MiB** 且不保证回落（**这直接违反 007 的「无内存增长」**）；`evict_lru` 每次逐出全扫分片、成本 O(每分片容量) → 1.0µs/次 @每片256、55µs/次 @每片8192（容量 32× → 耗时 52×）；稳态查表 5.7~7.6 Mops/s，只有 10Gbps@64B 需求（14.88 Mpps）的一半。 ⑤ **修掉第一处**：`expire()` 改为只收**键**（40B/条）、按全局键序逐条删除并派发，回调顺序与逐出语义不变，RSS 增量 **+99 → +6 MiB/轮**、超时扫描 **1.62 → 2.50 M 条/s**；唯一可观察差异是「回调期间表里可能仍留有尚未派发的到期条目」（旧实现先删完再派发），已在源码注明并明确接受。补 2 个测试（回调顺序 = 全局键升序、只回收该回收的那几条）钉住新行为。另两处**未修**且在条目里写清：`evict_lru` 的修法要改动「精确 LRU + 最小键打破平局」这一已文档化语义，属于需要显式决策的事，不在基准批次里顺手改。 ⑥ **顺带修正两处我自己上一批写错的事实**：分片容器写成 `BTreeMap`（实为 `HashMap` + FNV-1a，确定性顺序来自显式排序）、`FlowStats` 包长直方图写成「256 桶」（实为 **12 个 log2 桶**；256 桶是 `feature::ENTROPY_BINS`，两者不是同一个东西）。 验证：`--rust` 292 项单测 + 基准 8 项单测全绿；`--flows` 725 项比对 / 7 跳过 / 17 项注入全检出（`expire` 改动无回归）；`--bench` 全绿（12 项回归下限 + 3/3 注入检出）；`lint-all.sh` 7 项全绿。 |
| 2026-10-04 | **HTTP 响应侧与 DNS RCODE/EDNS0/应答地址补齐（`CYS-TRF-020`/`023`→☑），顺带抓出「入库字节 ≠ 测试读到的字节」** | ① **HTTP（`CYS-TRF-020`）**：请求侧补 URI / User-Agent / Content-Type；新增**响应侧解析**（`HTTP/x.y` + 三位状态码 + 原因短语 + Content-Type），与请求侧共用同一条「头部必须真的以空行结束」判据。判别只看一个字节级事实——载荷是否以 `HTTP/` 开头（请求行首 token 是方法名，不可能叫 HTTP），并把**半截 `HTTP/`**（`H`/`HT`/`HTT`/`HTTP`）判 `NeedMore`：交给请求解析器会因「方法后没有空格」判 `Rejected`，于是**分片被记成「不是 HTTP」**。状态码不足三位判 `NeedMore`、三位非数字或超 1xx~5xx 判 `Malformed`（分片与坏包的下游含义相反，混作一谈就是把分片算进失败率）。`Content-Length` 已解析进结构体但**不产出属性**——字典未登记它，「只产出已登记属性」是硬约束，宁可留缺口也不塞进别的属性。 ② **DNS（`CYS-TRF-023`）**：RCODE **只在响应上产出**（查询报文该段是保留位恒 0，产出它等于凭空造出一批「查询没出错」的样本）；补 QCLASS、**应答地址集合**（A/AAAA 按报文顺序，上限 8 条）、**指针跳数**（0 = 未用压缩指针，是「确实没跳」这个测量结果而非「没测」，故不做 `>0` 过滤）、**EDNS0**（OPT 的 CLASS 被复用为请求方声明的 UDP 载荷上限）。资源记录段**尽力而为**扫描（三层 work 上限：名字跳数 ≤128 / 记录条数 ≤32 / rdlength 必须落在报文内）：首包常被截断，而 QUESTION 段的证据强度与应答段无关，判 `NeedMore` 会把已拿到域名强证据的流量推回未识别。双 OPT 按 RFC 6891 §6.1.1 判畸形。 ③ **修掉一个真实缺陷**：`parse_name` 原先把「跟随指针读完后的位置」当作「名字之后的下一个字节」。QUESTION 段的名字不用压缩指针，所以这个错一直没暴露；一旦用于**应答记录名**（DNS 常态：`C0 0C` 指回 QUESTION），调用方就会从报文中间继续读 TYPE/CLASS/RDLENGTH——报文完全合法而资源记录全部错位。修法是记下**原始位置上指针字段结束**的位置并补一条针对性单测（把「压缩指针之后的位置」钉死）。 ④ **向量 21 → 32 条**（TLS 9 / DNS 15 / HTTP 8），期望值全部由**构造参数**推出（地址来自我写进报文的那几个字节），不是跑一遍实现记下来。tshark 三方互证 **22 → 92 项**：DNS 侧加 QTYPE/RCODE/QCLASS/应答地址/EDNS0，HTTP 侧加 URI/UA/状态码/Content-Type；`dns.flags.rcode` 在查询上报空、响应上报数值，正好与「查询不产出 RCODE」互证。**两处会让第三方核验「静默少比」的坑**：其一，响应报文原先发往 80 端口，tshark 按目的端口判方向、干脆不解析，于是 404 向量的状态码/Content-Type **一个字段都没比**（假绿的一种），改成响应从 80 端口发出后才真的比上；其二，`dns.opt.udp_size` 这个字段名**不存在**（猜到第三个才试对 `dns.rr.udp_payload_size`）——字段名一律先探再写。另：应答地址按**集合**比对而非逐位（tshark 把 A 与 AAAA 分在两个字段，字段序 ≠ 报文序，逐位比会得到一个假的失败），Content-Type 两边都做大小写归一（我们的实现按策略归一，不能把 tshark 的原始大小写当成它错了）。 ⑤ **属性字典 v1 → v2**：新增 `ATTR_DNS_EDNS0_UDP_SIZE`（98 → **99** 条），四端绑定重新生成（`--check` 通过）；`attributes.rs` 新增 9 个生产者（HTTP URI/UA/状态码/Content-Type、DNS QCLASS/RCODE/ANSWER_IP/PTR_DEPTH/EDNS0_UDP_SIZE），集合型属性**每个成员一条 `Attr`**（拼成逗号串会让规则只能做全串相等，集合语义就没了）。**结构体字段与产出属性都做「有值 / 恰好为空」的区分**：请求侧的状态码、查询侧的 RCODE 都是 `None` 而不是 `0`。 ⑥ **本批最贵的一课：`core.autocrlf=input` 把入库的二进制向量改掉了行尾**。`git add` 把 HTTP 向量载荷里的 `\r\n` 归一成 `\n`（而 `http.rs` 正是用 `\r\n\r\n` 判头部结束），实测索引 blob 的 CRLF 计数 **0**、磁盘 **5** —— 文件在版本控制里、`git status` 不提示，但**入库那份与测试读的那份不是同一份字节**（与上一批「文件不在版本控制里」同族，只是更隐蔽）。修法：新增 `.gitattributes` 声明 `datasets/**/*.bin -text` + `git add --renormalize`。**两个反直觉点都写进了 HANDOFF §7**：`git diff` **看不见**这种损坏（它比对「过了 clean 过滤之后」的内容，归一恰恰发生在过滤这一步，实测 `git diff --quiet` 报干净），必须比 `git ls-files -s` 的 blob 哈希与 `git hash-object --no-filters`；`.gitattributes` 会被**缓存在索引里**（删掉文件后 `git check-attr` 仍报 `text: unset`，我第一轮实验就被它骗过，得先重写索引才能让实验成立）。守门落在 `check-dpi-vectors.sh`：正常执行先跑**自证**（临时仓库里真造一次归一 → 断言判红；加 `-text` → 断言判绿，防「比对恒等于通过」），再逐文件比对 32 个入库向量与生成物字节，`--self-test` 可单独跑，挂在 `--dpi`（默认全量门禁含该项）。 ⑦ **反向注入三次**：改坏期望值（404→500、漏一个应答地址）→ Rust 测试与 tshark 双双报错并点名向量；把 `parse_name` 退回旧语义 → 向量测试与针对性单测双双报红；**真的做一次行尾归一**（先重写索引使属性缓存失效，否则实验结论是假的）→ 新门禁如期报红，恢复后转绿。 ⑧ **连带增益**：`--flows` 的 tshark 交叉核验也吃这三份 pcap，向量变多后比对项从 725 涨到 **927**（跳过 8 项，各有理由）。验证：`lint-all.sh` **9 项**全绿；`--rust` **331** 项；`--dpi` **92** 项 + 字节保真自证；`--reassembly` 16 项；`--flows` 927 项 + 17 项注入全检出。 |
