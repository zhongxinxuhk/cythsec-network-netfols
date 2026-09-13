# SPRINT-01 编排方案与执行记录

> 日期：2026-09-14（AEST）
> 基线：`eaaa575` · v0.1.0
> 依据：`docs/planning/BACKLOG.md`（349 任务 / 9 里程碑）
> 团队：`cythsec-dev` —— 3 位领域专家 + 1 位技术负责人（team-lead）

---

## 1. 编排思路

BACKLOG 的 349 个任务无法一次做完，也不应盲目平铺。本轮编排遵循三条原则：

**原则一：先清障，再开工。** 若带着已确认的 P0 缺陷启动并行开发，三位专家会各自踩到同一批坑，且修复动作会与他们的改动产生文件级冲突。因此 team-lead 在派发前**先独立完成 P0 清障**，为专家建立干净基线。

**原则二：按文件区域切分职责，而非按任务类型。** 并行 agent 最大的风险是同一文件的写冲突。因此每位专家被分配**独占的文件区域**，边界在任务简报中显式声明（含「绝对不要改」清单），使并行改动在物理上互斥。

**原则三：每条工作流必须有可执行的验证关口。** 不接受「我改好了」这类自述。每位专家的验收标准都是**具体命令 + 期望输出**（例如 `ctest` 全绿、`gofmt -l` 为空、`go test ./...` 通过），由专家本人跑通并提交证据，team-lead 再复核。

---

## 2. 阶段划分

### 阶段 0：P0 清障（team-lead 独立完成，已完成）

在派发专家之前完成，因为以下改动会与专家的文件区域重叠：

| 任务 ID | 内容 | 处置 | 结果 |
| --- | --- | --- | --- |
| `CYS-DBT-001` | Go 格式差异 | `gofmt -w services/` | ☑ `gofmt -l services/` 输出为空 |
| `CYS-DBT-002` | Rust 格式差异 | `cargo fmt` | ☑ `cargo fmt --check` 零差异，`cargo test` 7 passed |
| `CYS-DBT-005` | `npm run lint` 必然失败（缺 `eslint` 依赖） | 补 `eslint` / `@typescript-eslint/*` / `eslint-plugin-react-hooks` / `eslint-plugin-react-refresh` 到 `devDependencies`，新增 `.eslintrc.cjs` | ☑ 19 文件扫描、0 问题 |
| `CYS-DBT-006` | `components.json` 引用不存在的 `tailwind.config.js` | 判定为死配置（项目用手写 CSS，无 `@tailwind` 指令、无 `tailwindcss` 依赖），移入回收站 | ☑ 悬空引用消除，可从 git 历史恢复 |
| `CYS-INF-023` | `Cargo.lock` 被 `.gitignore` 忽略 | 改为保留入库（应用类工程需锁定依赖） | ☑ 根 `Cargo.lock` 已在工作区 |

> **决策记录（CYS-CON-001）**：样式栈定案为**手写 CSS + 设计令牌**，不引入 Tailwind / shadcn/ui。
> 依据：现有 `src/index.css` 已累积 339 行自洽样式，UI 类名（`shell` / `side` / `topbar` / `stat` / `iface`）自成体系；
> 引入 Tailwind 意味着全量重写且与「Apple 极简 + iOS 毛玻璃」的既定视觉方向无收益。`components.json` 因此判定为死配置。

### 阶段 1：四路并行（本阶段）

三位专家 + team-lead 各自推进一条工作流。下图是本轮的**并发拓扑**：

```
                        team-lead（阶段 0 清障 ✅）
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
   telecom-expert          software-expert          security-expert
   任务 #1                 任务 #2                  任务 #3
        │                         │                         │
   dataplane/**             .github/workflows/         docs/security/**
   capture/**               {ci,lint}.yml              SECURITY.md
   docs/dataplane/**        scripts/**（除 security/）   .gitleaks.toml
                            services/**                .pre-commit-config.yaml
                            Makefile                    .github/workflows/security.yml
                            VERSION/go.work             scripts/security/**
                            docs/controlplane/**        docs/security/AUDIT-*.md
        │                         │                         │
   验证关口：                验证关口：                验证关口：
   根 CMake configure        go build/test/vet        scan-secrets.sh 实跑
   + build + ctest 全绿      gofmt -l 为空              YAML 语法可解析
                            脚本可执行                 风险条目引用真实行号
        │                         │                         │
        └─────────────────────────┴─────────────────────────┘
                                  │
                    team-lead 复核 + 汇总（阶段 2）
```

---

## 3. 职责矩阵

### 3.1 通信行业专家 · `telecom-expert` · 任务 #1

**角色定位**：计算机网络 / 高速数据平面方向。

**为什么由他负责**：这批任务的本质是**协议语义正确性**（IPv4 IHL 的单位是 4 字节、IPv6 扩展头链的遍历与成环防护、TCP 数据偏移的单位、VLAN 栈的嵌套深度上限）。这些是通信领域的专业知识，不是通用编程能力能覆盖的。

**承接口径**：把 `packet-engine` 从「工具链验证级」提升到「真实可用」，并冻结与下游 Rust 侧对接的解析 API。

| 任务 ID | 内容 | 关键风险点 |
| --- | --- | --- |
| `CYS-PKT-015` | 修复后端编译开关 | 已确认缺陷：`ENABLE_XDP`/`ENABLE_AF_XDP`/`ENABLE_DPDK` 指向**不存在的目录** `xdp/` `af_xdp/` `dpdk/`，任一开关置 ON 则 configure 立即失败 |
| `CYS-PKT-005` | 后端抽象接口 + 真实 PacketBuffer | 要求零拷贝：缓冲视图持有指针而非数据副本 |
| `CYS-PKT-016` | L2/L3/L4 解析器 | VLAN 栈（QinQ）、IPv6 扩展头链、TCP 选项区偏移 |
| `CYS-PKT-017` | 零拷贝约束 | 解析只返回偏移与视图，禁止 memcpy 数据体 |
| `CYS-PKT-018` | 畸形包防护 | 截断包、IHL<5、`total_length` 大于 caplen、扩展头成环、长度算术溢出 |
| `CYS-PKT-030` | CLI 演示 | 保留 `hello_packet` 作冒烟，新增可接收十六进制/二进制输入的解析 CLI |

**验证关口**：
```bash
cmake -S dataplane/packet-engine -B /tmp/pkt-off
cmake -S dataplane/packet-engine -B /tmp/pkt-on -DENABLE_XDP=ON -DENABLE_AF_XDP=ON -DENABLE_DPDK=ON
cmake -S . -B /tmp/cythsec-build && cmake --build /tmp/cythsec-build
ctest --test-dir /tmp/cythsec-build --output-on-failure
```
硬门槛：构建零错误、CTest 全绿、原有 `packet_engine_unit` 不退化。

### 3.2 软件行业专家 · `software-expert` · 任务 #2

**角色定位**：工程效能 / 分布式系统架构方向。

**为什么由他负责**：需要判断「版本号单一来源」在不同构建系统（CMake `configure_file` / Rust `build.rs` / Go `-ldflags -X` / Vite `define`）中的落地方式，以及跨语言 CI 矩阵的缓存与依赖顺序。这是工程架构判断，不是逐个语言照抄模板。

**承接口径**：把工程基座补齐到「任何改动都有自动化回归保护」的程度，并让 `routerd` 达到生产就绪基线。

| 任务 ID | 内容 | 设计要点 |
| --- | --- | --- |
| `CYS-DBT-017` | services 共享库 | 四服务各自独立 module 且无共享代码，`envelope` 必然重复实现。先落地 `apiresp`（响应结构 + 工具 + 错误码），再让 routerd 复用 |
| `CYS-INF-020/021` | 版本号单一来源 + 自检 | 以根 `VERSION` 为唯一真源，四端消费；`check-version.sh` 不一致时非 0 退出并**指出具体哪处不一致** |
| `CYS-INF-004/005/003` | 统一构建/测试脚本 + Makefile | 工具链版本预检（cmake≥3.20 / cargo / go≥1.22 / node≥18）；任一栈失败整体非 0 退出；脚本幂等且有 `--help` |
| `CYS-INF-001/002/008` | CI 流水线 | 四语言矩阵 + lint 矩阵；**workflow 只调用 `scripts/**`，不重复写构建逻辑** |
| `CYS-RTD-007/003/001` | envelope 加 `code` / 优雅关闭 / CORS | `srv.Close()` 改为 `srv.Shutdown(ctx)`；`request_id` 生成与透传 |
| `CYS-RTD-018` | handler 层测试 | `internal/api` 目前**零测试文件**，用 `httptest` 覆盖全部端点 |
| `CYS-DBT-008` | 配置文件生效 | 死文件 `configs/config.yaml` 接入，优先级 flag > env > YAML > 默认 |

**验证关口**：
```bash
bash scripts/build/build-all.sh --help
bash scripts/test/test-all.sh
bash scripts/release/check-version.sh
cd services/routerd && GOWORK=off GOPROXY=off GOTOOLCHAIN=local go build ./... && ... go test ./... && ... go vet ./...
GOWORK=off gofmt -l services/     # 必须为空
```

> **已知并发干扰**：专家 #1 正在改 `dataplane/`，因此 `build-all.sh` 的 C++ 环节可能因对方半成品失败。这是**预期内**的，简报中已要求脚本在这种情况下清晰报错并指明失败栈。

### 3.3 安全行业专家 · `security-expert` · 任务 #3

**角色定位**：网络攻防 / 应用安全 / 合规方向。

**为什么由他负责**：cythsec 本身是安全产品，其威胁模型与普通业务系统不同（要抓包、要改路由、要下发防火墙规则）。这类判断需要攻防视角，且必须基于真实攻击面而非泛泛而谈。

**承接口径**：建立安全基线，并对现存代码做一次**引用真实行号**的审计。

| 任务 ID | 内容 |
| --- | --- |
| `CYS-SEC-001` | 威胁模型：资产 / 信任边界 / 攻击面（引用真实文件行号）/ STRIDE 六类分析 |
| `CYS-SEC-003/006` | 凭据防泄漏：`scan-secrets.sh`（零外部依赖）+ `.gitleaks.toml` + pre-commit + `security.yml` |
| `CYS-SEC-002` | 鉴权方案设计（只出设计，不改代码）—— 交给 `software-expert` 实现 |
| `CYS-SEC-009` | 最小权限加固指引（systemd 沙箱、capability 按需、**数据面与控制面权限分离**） |
| `CYS-SEC-008/011` | 许可合规边界 / `SECURITY.md` 漏洞上报流程 |
| `CYS-SEC-007` | 审计日志字段规范（规范，不实现） |
| — | 现存代码安全审计报告 `docs/security/AUDIT-2026-09-14.md` |

**已移交他核实的初步观察**（要求独立核实、不得照抄）：
1. 全部 5 个 API 端点**零鉴权** —— `/api/v1/interfaces` + `/api/v1/routes` 等于把内网拓扑白送。
2. **无 CORS 配置** —— 存在跨站读取与 DNS rebinding 风险。
3. **纯 HTTP 无 TLS**。
4. `writeErr` 直接回显 `err.Error()` —— 可能泄露路径与系统细节。
5. 未来规划的高危点：`policyd` 要下发 nftables、`routerd` 要改路由表、`dnsd` 要做 DNS 重定向 —— **均为 root 权限操作，命令注入与策略绕过的后果是整机失陷**。

**验证关口**：`scan-secrets.sh` 实际运行并产出结果；三个 YAML 文件可被 `yaml.safe_load` 解析；威胁模型覆盖 STRIDE 六类且每类至少 2 条；每条风险引用真实文件与行号。

> **权限约束**：该专家被明确禁止修改任何源码。产出为文档、配置与扫描脚本。发现的问题写入报告并由对应专家修复 —— 这保证了「审计独立性」。

### 3.4 技术负责人 · `team-lead` · 阶段 0 + 前端

**角色定位**：工程编排 + 前端门户。

**为什么前端归 team-lead**：`web/**` 与三位专家的区域均不重叠，且前端仅依赖已稳定的 `routerd` 只读端点，不阻塞任何专家。

| 任务 ID | 内容 | 结果 |
| --- | --- | --- |
| `CYS-DBT-005` | 修复 `npm run lint` | ☑ |
| `CYS-DBT-007` | 修复 `vitest` 空跑（`tests/` 仅 `.gitkeep`） | ☑ 18 个用例 |
| `CYS-CON-001` | 依赖与样式栈定案 | ☑ 手写 CSS + 令牌，移除 `components.json` |
| `CYS-CON-005` | 测试基础设施 | ☑ `vitest.config.ts` + jsdom + Testing Library + jest-dom setup |
| — | **额外发现并修复**：`fmtBytes` 展示缺陷 | ☑ 见下 |

**额外发现（前端测试捕获的真实缺陷）**：
`src/utils/format.ts` 的 `fmtBytes()` 对 `n < 1024` 的输入走了通用小数分支，导致 `fmtBytes(1)` 输出 `1.00 B`。
字节是离散计数，小数位无有效信息。已修复为「kB 以下固定取整」，并补充边界用例锁定行为
（`0` / 负数 → `0 B`；`1023` → `1023 B`；`1024` → `1.00 KB`；`1024**5` → `1024 TB`，即超出 TB 后不再进位）。

**前端四项关口实测**：
| 关口 | 命令 | 结果 |
| --- | --- | --- |
| Lint | `npm run lint` | ☑ 19 文件扫描、0 问题（已用 `-f json` 反查确认非空跑） |
| Test | `npm test` | ☑ 3 文件 / 18 用例全通过 |
| Typecheck | `npm run typecheck` | ☑ 退出码 0（`tsconfig.json` 的 `include` 已扩展到 `tests`） |
| Build | `npm run build` | ☑ 45 modules，JS gzip 56.56 kB |

---

## 4. 并发安全规则

本轮为避免并行写冲突，施加以下约束：

1. **文件区域独占**：每位专家的简报中都有一份显式的「绝对不要改」清单。
2. **共享文件的单一归属**：`.github/workflows/` 下 `ci.yml` / `lint.yml` 归 `software-expert`，`security.yml` 归 `security-expert` —— 按**文件名**而非目录切分。
3. **`scripts/` 的例外处理**：`scripts/` 整体归 `software-expert`，但 `scripts/security/` 明确划给 `security-expert`。
4. **只读审计原则**：`security-expert` 不得修改任何源码，只产出文档、配置与扫描脚本。这既避免冲突，也保证了审计独立性（审计者不审计自己的代码）。
5. **不提交**：所有专家被禁止执行 `git commit` / `git push`，改动全部留在工作区，由 team-lead 统一复核后决定提交策略。
6. **非破坏性**：禁止删除现有文件；如需废弃先与 team-lead 确认。

---

## 5. 里程碑映射

本轮覆盖 BACKLOG 的子集，并推进以下里程碑：

| 里程碑 | 名称 | 本轮推进 |
| --- | --- | --- |
| **M1** | 工程基座加固 | `INF` 域主体 + `DBT` 域 P0 项 —— 本轮主要目标 |
| **M2** | 数据平面真实收包 | `PKT` 域解析与抽象层（收包后端留待下轮） |
| **M3** | 流量分析深化 | 未启动（依赖 `PKT` 产出的解析 API） |
| **M4** | 控制平面补全 | 未启动（本轮先落地 `DBT-017` 共享库，为其铺路） |
| **M5** | 控制面服务化 | `RTD` 域 P0 项（CORS / 优雅关闭 / envelope / handler 测试） |
| **M6** | 存储与前端 | 前端工程化基座（非功能页） |
| **M7** | ML 与威胁情报 | 未启动 |
| **M8** | 平台适配与部署 | 未启动 |
| **M9** | 测试·安全·文档·发布 | `SEC` 域主体（威胁模型 / 防泄漏 / 合规） |

---

## 6. 下一轮建议优先级

按「解锁下游能力最多」排序：

1. **`CYS-PKT-006` pcap 文件后端 + `CYS-TLS-002` pcap 回放** —— 有了真实解析器却无报文来源，应立即补上离线回放，才能用真实样本验证解析器。这是当前最短的闭环缺口。
2. **`CYS-PKT-024` 共享内存契约** —— C++ 生产 / Rust 消费的 ABI 需尽早冻结，否则 `traffic-engine` 无法接入真实报文。
3. **`CYS-MLT-016` model-registry + `CYS-STO-001/002` 存储 schema** —— 三项均不依赖其他工作流，可并行启动。
4. **`policyd` 骨架落地** —— 已有 `DBT-017` 共享库作为地基；**但必须先落实 `security-expert` 对 nftables 下发的强制性安全要求**（策略即 root 权限操作）。
5. **`CYS-RTD-014` routerd 鉴权实现** —— 设计由 `security-expert` 出，实现由 `software-expert` 做，是 `security.yml` 之外唯一能实质降低当前风险的动作。

---

## 7. 变更记录

| 时间 | 变更 |
| --- | --- |
| 2026-09-14 | 建立 `cythsec-dev` 团队；阶段 0 完成 5 项 P0 清障；派发 3 位领域专家并行开工；team-lead 完成前端工程化基座与 `fmtBytes` 缺陷修复 |
