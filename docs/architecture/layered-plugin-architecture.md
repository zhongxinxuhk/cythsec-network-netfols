# CythSec 分层解耦与插件化方案（正式版）

> 文档域：ARC ／ 关联 DOC、TRF、PKT、POL、TIP、TEL、DEP、INF
> **版本：v1.0.0（正式方案，2026-10-05 审核通过）** ｜ 前身：v0.1.0 评估稿（同日）
> 适用基线：`cythsec` v0.1.0（`VERSION`=0.1.0，`docs/planning/BACKLOG.md` **367 任务 / 10 里程碑**）
> 基线事实核对于：`10175e8`（2026-10-05，工作树干净）
> 上游依据：`docs/architecture/tsg-tech-transfer.md`（A1/A2/A3/A4/A5/A6 架构级引入清单）
> **落地载体：`docs/planning/BACKLOG.md` §3.10（里程碑 M10「分层解耦与插件化」）—— 本方案已合并进开发计划**
>
> **本文档的性质**：正式实施方案。**只立契约、判边界、定顺序与验收，本身不含实现代码**；
> 逐条可执行的任务登记在 `BACKLOG.md` §3.10，本文与该节**双向可追溯**（§9 给出编号映射）。
> 全文所有结论都带 `file:line` 证据；凡未核实的一律标注「未核实」。
> 方案与代码之间最容易出现的偏差，是把「计划」读成「已有」——本文刻意把两者分列（§1 vs §2）。
>
> ⚠ **基线口径**：所有 `file:line` 均对 `10175e8` 的实际文件核实。
> v0.1.0 评估稿撰写期间，工作树曾含两处未提交的源码改动
> （`dataplane/traffic-engine/src/{pipeline.rs,bin/analyze.rs}`，即 `--workers N` 那一批）；
> 该批已随 `9561d69` 落地，**本文所有行号已按落地后的文件复核**——
> 复核结果：`pipeline.rs:29-36` 的 8 条 `use`、`dpi/mod.rs:57` 的定长数组、
> `session/mod.rs:310` 的 `clear_observer()` 均未位移，结论不受影响。
> 另有一处**行号之外**的事实更新：`--workers N`（每核一张独立表）现已接进消费路径，
> 故「核预算已定案」的表述在 §1.1/§7.2 已按新事实改写。

---

## 0. 结论摘要（TL;DR）

**一句话结论**：分层解耦**可行且高收益**；「功能模块**全部**拆成插件」**不可行也不必要**。
正确形态是 **「契约下沉 · 核心单体 · 插件分级 · 第三方进程隔离」**：
90% 的「分开升级」诉求由**数据插件**（签名/规则/情报/模型）满足，代码插件只该出现在少数**粗粒度边界**上，
而每包热路径必须留在核心里保持单体。

四条判断（每条都在后文给出证据与判据）：

| # | 判断 | 依据一句话 |
| --- | --- | --- |
| J1 | **「核心引擎 vs 运行框架」的分离成本很低，且已经开始** | `traffic-engine` 已是 `lib` + 4 个 `bin`、`packet-engine` 已是库 + 5 个 CLI；真正要做的是把「装配与策略」从库挪到宿主 |
| J2 | **「特征库」必须一分为二，否则一定做错** | 特征**提取器**是每包热路径 + 定长向量契约（`FEATURE_COUNT=21`），**不可**插件；特征/属性/签名**定义**是数据真源（`attributes.json` 99 条），**必须**做成分版本资产 |
| J3 | **收益最大的插件形态是「数据插件」，不是「代码插件」** | 变化频率最高的东西（签名、规则、IOC、模型）恰好**无需任何 ABI**；而本仓已有 `ruleir.Registry` 的 revision/checksum/rollback 与 `attributes.json` 的四语言 codegen 作先例 |
| J4 | **进程外插件只该用在两个地方** | 第三方/商用引擎（许可 + 崩溃隔离，TSG F43 实证）与 ML 推理（ONNX Runtime 是第三方依赖，与「Rust 零第三方依赖」硬约定冲突）；其余场景进程内足矣 |

**明确否决的形态**：把每包路径上的算法（流表、会话、TCP 状态机、重组、特征提取、协议基础解析）
做成 `dlopen` 动态插件。理由见 §7.2 的三条硬约束（性能预算 14.88 Mpps / 4 核每 10G 口、
零第三方依赖与离线可构建、以及本仓明文写死的语义单一性要求）。

**推荐路线**：§7.4 的**方案甲 → 方案乙**；方案丙（全动态插件）**只在「引入第三方引擎」这一条上局部采用**。

### 0.1 批准与落地（2026-10-05）

| 项 | 内容 |
| --- | --- |
| 审核结论 | **通过**。本方案由 v0.1.0 评估稿升为 **v1.0.0 正式方案** |
| 落地里程碑 | `BACKLOG.md` 新增 **M10「分层解耦与插件化」**，共 **17** 项任务 |
| 待办表总数 | 350 → **367**（里程碑 9 → 10） |
| 编号映射 | 见本文 **§8.5**；逐条任务与验收标准见 `BACKLOG.md` **§3.10** |
| 已完成项 | `CYS-DOC-021`（TSG 上游方案）、`CYS-DOC-022`（本文档） |
| 首个可开工批次 | `CYS-INF-037/038` + `CYS-TRF-040/048` + `CYS-DBT-021`（不改行为、纯地基，**不依赖 M2~M9**）；编排与区域切分见 `docs/planning/SPRINT-02.md` |

> **本次合并最关键的一条纪律：只登记「现有待办表未覆盖」的工作。**
> 逐一核对 TSG §8.5 预留的 24 个编号后有 6 类重复或已落地
> （`CYS-POL-017/018/019/020`、`CYS-TIP-012`、`CYS-PLT-010`，另有 `CYS-MLT-016` 本表已有），
> 因此**不启用这些新编号**，改为在 `BACKLOG.md` §3.10 顶部以「承接既有任务」清单挂钩。
> 理由：同一件事发两个号会把完成率算错，也会让后人重复排期。
> 另有 1 处**上游方案自身**的重号（`CYS-INF-035`）已登记为 `CYS-DBT-021` 待修。

---

## 1. 现状基线（实测，2026-10-05）

### 1.1 代码分布与真实成熟度

「蓝图有 13 层」与「代码有多少」是两件完全不同的事。实测（`git ls-files` + `wc -l`，仅统计 `.rs/.go/.cpp/.h/.ts/.tsx/.py`）：

| 模块 | 源文件 | 源码行数 | 成熟度 | 证据 |
| --- | --- | --- | --- | --- |
| `dataplane/traffic-engine`（Rust） | 39 | **21,793** | ★★★ 真实、有门禁 | 流表/会话/TCP/重组/DPI/特征/记录全在单包内；`--workers N` 已接进消费路径（`10175e8`） |
| `dataplane/packet-engine`（C++） | 50 | **9,403** | ★★★ 真实、有门禁 | 后端 + 共享环生产端 + 解析器 + 5 个 CLI |
| `services/policyd`（Go） | 23 | **7,258** | ★★★ 引擎内核完整，落地侧全空 | `ruleir/` 3354 行源码 + 1933 行测试；`nftables`/`pgx`/`audit` 零命中 |
| `services/pkg`（Go 共享库） | 22 | **4,426** | ★★★ 真实 | `controlplane`/`metrics`/`logging`/`attributes(生成)` |
| `services/telemetryd` | 9 | 1,671 | ★★ 有领域模型与 API | 无真实后端 |
| `services/dnsd` | 9 | 1,481 | ★★ 同上 | zone/load/api/config |
| `services/routerd` | 11 | 1,342 | ★★ 只读网卡/路由 API | 无写能力 |
| `web/console/src` | 20 | 1,093 | ★★ 5 个页面 | React + Vite |
| `ml/training` | 1 | 1,061 | ☆ **只有 1 个生成物** | 该文件是 `features/attributes_gen.py`（codegen 产物） |
| `ml/inference` | 0 | 0 | ☆ 占位 | 仅 `CMakeLists.txt` |
| `platform/` | 0 | 0 | ☆ **纯占位** | 19 个目录全是 `.gitkeep` + 1 个 README |
| `storage/` | 0 | 0 | ☆ **纯占位** | README + `.gitkeep` |
| `threat-intelligence/` | 0 | 0 | ☆ **纯占位** | README + `.gitkeep` |
| `dataplane/traffic-engine/crates/*` | 0 | 0 | ☆ **9 个空 `.gitkeep`** | `behavior/common/dpi/feature/flow/protocol/reassembly/risk/session` 全部为空 |

**这条基线决定了本方案的第一条现实约束**：
`platform`、`storage`、`threat-intelligence`、`ml/inference`、`crates/behavior`、`crates/risk`
**没有代码可「拆」**——它们只能「**出生即插件**」。这反而是最省事的时机：接口设计成本几乎为零，
而改造既有热路径的成本极高。

> **计数口径与一个真实的坑**：上表由
> `find <dir> -type f \( -name '*.rs' -o -name '*.go' ... \)` + `wc -l` 得到，
> 排除各自的 `target/`、`node_modules/`、`dist/`。
> ⚠ 写这条命令时**我自己踩了仓库在 `HANDOFF.md` §7 第 7 条记录过的同一个坑**：
> 用 `-not -path '*/target/*'` 会把 `services/telemetryd/internal/target/` 这个
> **名字叫 target 的 Go 包**一起排除，telemetryd 被算成 5 文件 / 809 行（实为 **9 文件 / 1,671 行**，
> 少算 4 个文件 / 862 行）——**恰好就是那个 `.gitignore` 裸目录名吃源码的同一形状**。
> 计数必须把排除路径锚定到具体目录（`-not -path "$d/target/*"`），不能写裸的 `*/target/*`。

### 1.2 已有的「半插件化」基础设施（这是可行性的最强论据）

本仓**已经在五个地方**做出了插件缝隙，只是没有统一的插件框架把它们串起来：

| # | 既有缝隙 | 形态 | 证据 |
| --- | --- | --- | --- |
| E1 | `PacketBackend` 纯虚接口 + 名字工厂 + 自省列表 | 编译期注册 + 运行期按名创建 | `packet-engine/include/packet_engine/backend.h:45-118`（纯虚）、`src/backend.cpp:85-146`（工厂）、`backend.cpp:200-214`（`available_backends()`）；注释明确「调用方不该为了打印一行状态而知道自己跑在哪个后端上」（`backend.h:79-84`） |
| E2 | `FlowObserver` trait object | 运行期可装可卸的观察者 | `traffic-engine/src/flow/table.rs:260-278`、`table.rs:573`（`Box<dyn FlowObserver + Send>`）；**注意**：`session/mod.rs:310-311` 会把观察者清空，生产路径实际没有观察者 |
| E3 | `controlplane.NewHandler(opts, register)` 注册回调 | 控制面装配缝隙 | `services/pkg/controlplane/controlplane.go:64`；四个服务全部经它装配（如 `services/policyd/internal/api/server.go:80-88`） |
| E4 | `ruleir.Store` 接口 + 4 实现 + `Registry` 原子换版 | **数据插件**先例 | `services/policyd/internal/ruleir/store.go:51`（接口）、`:80/:106/:144/:221`（memory / json-file / index+datatable / redis 四实现）、`:294`（Registry）、`:324`（Install）、`:403`（Rollback）、`:430`（checksum） |
| E5 | telemetryd 采集目标：**纯 JSON 数据，改数据不改代码** | 全仓**最接近真插件**的一处 | `services/telemetryd/internal/target/load.go:11-45`（`{"targets":[...]}`）、`store.go:139`；加一个目标只需改数据文件 |

> 补充两个定量事实，用于校准「半插件化」的真实程度：
> ① 整个 `services/` 里**只有 2 个 Go 接口**（`ruleir.Store`、`metrics.Collector`，`services/pkg/metrics/metrics.go:30`）；
> `policy.Store` / `dns.Store` / `target.Store` 都是**具体结构体**（名字叫 Store 但没有缝），
> 这正是形态 B 要补的地方。
> ② 全仓**没有 per-component / per-plugin 版本标识**：`VERSION`=0.1.0 是唯一版本，
> 四个 Go 服务共用一个版本（`go.work:3-9`）、Rust 工作区只有一个 member（`Cargo.toml:3-5`）；
> 唯一带独立版本号的是共享环 ABI（`abi_version=1`）。

再加两条**契约层**的既有能力，它们是插件 ABI 治理的「预演」：

- **真源 → codegen → 多语言绑定**：`configs/registry/attributes.json`（version=2，**99 条属性**）与
  `configs/registry/channel-abi.json`（`abi_version=1`）→ `tools/codegen/*.py` → 生成物共 **5,086 行**
  （Go 389 / Rust 1165 / TS 328 / Python 1061 / C++ 942 / Rust-ABI 1201），由 `--check` 与
  `scripts/verify/check-attributes.sh`、`check-channel-abi.sh`、`check-channel-parity.sh` 三道关口守门。
- **属性注册表已经在声明「谁生产什么能力」**：99 条属性的 `source` 字段分布为
  **packet-engine 30 · traffic-engine 57 · threat-intelligence 7 · risk-engine 3 · ml-inference 2**
  ——也就是说，**5 个生产者的能力边界已经在真源里显式声明了**，其中 3 个生产者（后三者）**尚无一行代码**。
  这是「能力清单先于实现存在」的现成范式，正是插件化最需要的治理姿势。

### 1.3 缺失项（诚实清单）

| 缺失 | 证据 | 影响 |
| --- | --- | --- |
| **没有任何动态加载** | 全仓 `grep -rn "dlopen\|dlsym\|plugin\|Plugin"`（`*.cpp/*.h/*.rs/*.go`）**零命中** | 动态插件形态需从零建 |
| 无插件清单 / 无清单 schema | `configs/registry/` 只有 `attributes.json`、`channel-abi.json` | 缺「声明式注册」的载体 |
| 无插件 ABI 版本协商 | 唯一有版本的是通道 ABI（`channel-abi.json` 的 `abi_version`）与记录/特征 schema 版本 | 插件与宿主不兼容时无法显式拒绝 |
| 无进程外 IPC 基础设施 | 全仓无 socket/RPC 服务端代码；`e2e-control-plane.sh` 只做 HTTP 探测 | 进程外插件形态需从零建 |
| 无隔离 / 降级机制 | 无 panic 边界、无 supervisor、无熔断 | 「插件挂了核心继续」无法表达 |
| **无热更新通道** | 全仓无 `SIGHUP`/`fsnotify`/`inotify`；配置一律**启动时加载一次**（`configutil.go:77-113`、`policy/load.go:8-40`） | 形态 A 的「原子换版语义」已有（`Registry.Install/Rollback`），但**触发通道**要新建 |
| 无 per-component 版本 | 唯一版本是根 `VERSION`；仅通道 ABI 有独立 `abi_version` | 插件版本矩阵无载体（C6 要补） |
| `deploy/` 是空骨架 | 10 个 `.gitkeep` + README（`deploy/README.md:5`）；`docs/deployment/dev-run-deploy.md:10-55` 假定**单仓单构建** | 「分开升级」还缺**按组件交付的产物**（属 M8） |
| 门禁自证覆盖不均 | 有反向注入的只有 `--dpi`/`--flows`/`--bench`/`--node`/`check-version`；`check-attributes`/`check-channel-abi`/`check-channel-parity`/`check-ignored-sources`/`--reassembly`/`--e2e` **一个都没有** | **恰好是守契约的那几道没有自证** —— 插件契约若建在它们之上，先补自证 |
| CI 比 `make test` 窄 | `ci.yml:22/35/57/76` 只跑 `--cpp`/`--rust`/`--go` + `e2e-control-plane`；**不跑** `--parity`/`--dpi`/`--reassembly`/`--flows`/`--live`/`--bench`/`npm test` | 新插件门禁若只挂 `test-all.sh`，在 CI 上等于没挂 |
| **热路径硬编码** | `dpi/mod.rs:57-67` `order()` 返回**定长** `[fn(&[u8]) -> Detect; 3]`；`types.rs:17-24` `AppId` 枚举手写；`parser/parser.cpp:35-52` `switch(proto)` | 新增协议必须改核心 |
| 核心**直接依赖**具体模块 | `pipeline.rs:29-36` 一次 `use` 8 个模块；`lib.rs:16-26` 模块硬声明 | 无注入缝隙，「核心不依赖插件」这条规则目前**不成立** |
| 治理债：待办表滞后于代码 | `HANDOFF.md:34-40` 明确「控制平面部分已明显滞后」 | 再引入插件版本矩阵会加剧版本漂移 |

---

## 2. 目标架构：四层 + 契约地基（三横一纵）

### 2.1 分层图

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ L4 产品面      web/console 页面 · 运维脚本 · 控制台展示                        │
├──────────────────────────────────────────────────────────────────────────────┤
│ L3 运行框架（宿主 Host）—— 稳定，插件围着它升级                                │
│    清单加载与校验 · 能力/版本协商 · 生命周期 · 隔离与降级 · 观测 · 原子热更新   │
│    ├ 数据面宿主：ring-consume / cythsec-analyze / cythsec-capture            │
│    └ 控制面宿主：controlplane.NewHandler(register 回调)                      │
├──────────────────────────────────────────────────────────────────────────────┤
│ L2 插件面（3 类 × 3 形态）                                                    │
│    platform 插件：收包后端 · OS 适配(netlink/nftables/uci) · 处置后端 ·       │
│                   存储后端 · 遥测导出                                        │
│    protocol 插件：DPI 检测器 · 隧道解封装 · 外部引擎适配                      │
│    business 插件：签名/规则/IOC/模型【数据资产】· 判定聚合引擎 · 动作映射     │
│    形态 A 数据插件   │   形态 B 同进程静态插件   │   形态 C 进程外引擎         │
├──────────────────────────────────────────────────────────────────────────────┤
│ L1 核心引擎（单体 · 确定性 · 不可插件）                                       │
│    channel 解码 → flow 流表 → session/TCP 状态机 → reassembly →              │
│    feature 特征向量 → record 记录                                             │
├──────────────────────────────────────────────────────────────────────────────┤
│ L0 真源与契约层（地基）                                                       │
│    configs/registry/*.json → tools/codegen → 四语言绑定                       │
│    attributes(99) · channel-abi(abi=1) · 【新增】插件清单 · 各类 schema 版本  │
│    scripts/verify/* 门禁（13 个脚本；仅 3 个含反向注入，见 §1.3）              │
└──────────────────────────────────────────────────────────────────────────────┘

依赖方向（单向，禁止回边）：
  L4 → L3 → L2 → L1 → L0        L2 亦可直接依赖 L0（只见契约，不见核心内部）
  铁律：L1 **绝不**依赖任何具体插件；L2 之间**绝不**互相调用
```

### 2.2 分层解耦的两处「真问题」，与它们的正确切法

用户的两个提法需要先各拆成两件事，否则一定会做错：

**(a) 「核心引擎 vs 运行框架」——这是「库 vs 宿主」的分离，不是插件化**

| 概念 | 定义 | 现状 | 该动什么 |
| --- | --- | --- | --- |
| 核心引擎 | 无策略、无 I/O、无装配的纯能力库 | `traffic-engine` 有 `[lib]`（`Cargo.toml`）+ 4 个 `[[bin]]`；`packet-engine` 有库 + 5 个 CLI | 把 `pipeline.rs` 里的**编排与默认策略**上移到宿主，库只暴露稳定 API |
| 运行框架 | 装配、调度、策略、生命周期、配置 | `pipeline.rs:40-68`（`AnalyzeOptions` 默认容忍模式）、`bin/*`、Go 的 `controlplane` | 宿主负责「选哪些插件、怎么配、失败怎么办」 |

> 这一步**不需要插件框架**，成本是 `S`~`M`，收益是后面所有插件化的前提。
> 判据：核心库里不允许出现「从环境变量/配置文件读取实现选择」的代码——一处出现，分层即破。

**(b) 「特征库」——必须一分为二**

| 子概念 | 内容 | 归属 | 理由（证据） |
| --- | --- | --- | --- |
| 特征**提取器** | 单遍增量算法、`[f64; 21]` 定长向量、`idx` 常量下标 | **L1 核心，不可插件** | `feature/mod.rs:6-11`：「用 map 时漏掉一个特征只是少一个键，不会报错，而模型会静默地把第 k 维当成 0」；`feature/mod.rs:18-20`：必须单遍以便在线复用 |
| 特征/属性**定义** | `ATTR_*` 名称、类型、scope、stage、cost、生产者 | **L0 契约 + L2 数据插件** | 已有真源 `attributes.json`（99 条 / 14 类型 / 8 scope / 5 stage / 3 级 cost），四语言 codegen 已成 |
| 特征**扩展**（派生特征、窗口特征） | 需要新增维度时 | **L2 同进程插件 + 升版** | 必须走 `FEATURE_SCHEMA_VERSION` 显式升版；不允许「悄悄变长」（`feature/mod.rs:9-10`） |

### 2.3 插件的三种形态（按成本/收益排序，这是全案的骨架）

| 形态 | 是什么 | 升级方式 | 成本 | 适用 |
| --- | --- | --- | --- | --- |
| **A 数据插件** | 纯数据资产 + 清单：签名包、规则表、IOC/情报、ML 模型、端口/启发式表、白名单、属性扩展 | 原子热更新（不重启） | **M** | 变化频率最高的一切；**收益最大** |
| **B 同进程静态插件** | trait/纯虚接口 + 声明式清单 + **静态链接**（不用 dlopen）；编译期枚举、运行期按清单装配 | 重新链接宿主 → 滚动/蓝绿升级 | **L** | 收包后端、OS 适配、处置后端、存储后端、遥测导出、**DPI 检测器**、隧道解封装 |
| **C 进程外插件** | 独立进程 + IPC；宿主经事件总线投递，结果异步汇入判定点 | **只重启该进程** | **XL** | 第三方/商用引擎（许可 + 崩溃隔离）、ML 推理（第三方运行时依赖） |

> 「B 不用 dlopen」是刻意的：本仓核心每包预算为 **14.88 Mpps**（10Gbps 最坏包速率，`bin/bench.rs` 口径），
> 核预算 **4 核/10G 口**（`HANDOFF.md` §2.6 实测）；每包一次 `dlsym` 间接调用既不可内联、也不可预测。
> 静态注册表可以做到**零间接成本**（单态化/monomorphization），清单与实现分离已足够满足
> 「新增能力不改核心调度代码」这一唯一实质诉求（对齐 TSG A1 验收口径）。

### 2.4 「分开做系统升级」的通道矩阵（用户核心诉求的直接回答）

| 升级对象 | 通道 | 是否重启数据面 | 回滚手段 | 今日可行性 |
| --- | --- | --- | --- | --- |
| 签名 / 规则表 / IOC 情报 / 白名单 | A 数据插件 | 否 | revision + checksum + 原子切换 | **部分可行**：`ruleir.Registry` 已有 Install/Rollback（`store.go:324/403`）；签名与情报无 |
| ML 模型 | A 数据插件 | 否（推理侧） | 模型版本 + 校验和 | 未开始：`ml/model-registry` 空 |
| 属性字典扩展 | A 数据插件 + 契约升版 | 否（重新生成绑定并重链接宿主） | 版本 + 弃用周期 | **可行**：真源 + codegen + `--check` 已在 |
| 协议检测器（新增协议） | B 同进程插件 | 需重链接宿主（滚动升级） | 版本回退 + 清单禁用 | **需先改核心**：`order()`/`AppId` 硬编码 |
| 收包后端（XDP/AF_XDP/DPDK） | B 同进程插件 | 重链接宿主 | 清单切换后端 | 接口已在（E1），实现未做 |
| OS 适配（Linux/openEuler/OpenWrt） | B 同进程插件 | 按部署单元 | 包版本回退 | **出生即插件**：当前 0 LOC |
| 处置后端（nftables/inline/pcap/dry-run） | B 同进程插件 | 按部署单元 | 能力矩阵 + 灰度 | **出生即插件**：方案已有（TSG A4） |
| 存储后端（PG/CH/Redis） | B 同进程插件 | 按部署单元 | 双写/回滚 | **出生即插件**：当前 0 LOC |
| 第三方 DPI 引擎 / ML 推理 | C 进程外引擎 | 否（只重启该进程） | 进程版本切换 + 熔断降级 | **需新建框架** |
| 核心引擎（流表/会话/重组/特征） | 整体版本升级 | 是（停机/蓝绿） | 整体回退 | 现状即可 |

---

## 3. 拆分准入判据（先立规矩，再谈清单）

「哪些能拆」不应靠感觉，应有可复算的判据。**六条判据**，拆一个模块前逐条打分：

| # | 判据 | 反例（不满足会怎样） |
| --- | --- | --- |
| K1 | **变化频率与核心不同频**：它半年一变，核心三年一变 | 把流表做成插件：每次核心优化都要同步插件 ABI，成本翻倍 |
| K2 | **故障域应当隔离 / 需要独立许可边界** | 第三方 `.so` 段错误拖垮主进程（TSG F43 实证） |
| K3 | **可独立验证**：有第三方真相来源，或纯数据可离线回放 | 没有判据的插件 = 无法证明它真的生效（见 R2 假绿） |
| K4 | **边界可用稳定契约表达**：类型有限、可生成、可版本协商 | 边界上出现 `void*` / 共享可变状态 → ABI 必然腐化 |
| K5 | **不引入每包间接跳转或跨进程往返**（或该路径本身非每包） | 每包 `dlsym`：14.88 Mpps 预算下不可接受 |
| K6 | **缺席可降级**：插件不可用时核心仍能跑，且降级**显式可见** | 静默降级 = 「绿色的通过和绿色的没跑长得一样」 |

**裁决规则**：满足 ≥5 条 → 拆；满足 3~4 条 → **有条件拆**（先补契约与门禁）；≤2 条 → **留在核心**。

对主要候选的打分（`●`=满足，`○`=部分，`—`=不满足）：

| 候选 | K1 | K2 | K3 | K4 | K5 | K6 | 得分 | 结论 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 签名/规则/IOC/模型（数据） | ● | ○ | ● | ● | ● | ● | 5.5 | **形态 A** |
| 收包后端 | ● | ○ | ● | ● | ● | ● | 5.5 | **形态 B** |
| OS 平台适配 | ● | ○ | ○ | ● | ● | ● | 5 | **形态 B** |
| 处置后端 | ● | ○ | ● | ● | ● | ● | 5.5 | **形态 B** |
| 存储后端 | ● | ○ | ○ | ● | ● | ● | 5 | **形态 B** |
| 遥测导出 | ● | ○ | ● | ● | ● | ● | 5.5 | **形态 B** |
| DPI 检测器 | ● | ○ | ● | ● | ○ | ● | 5 | **形态 B（须改造核心）** |
| 隧道解封装 | ○ | — | ● | ● | ○ | ● | 4 | **有条件**（形态 B，晚做） |
| 第三方 DPI 引擎 | ● | ● | ○ | ○ | ○ | ● | 4.5 | **形态 C** |
| ML 推理 | ● | ● | ○ | ● | — | ● | 4.5 | **形态 C** |
| 会话级判定/聚合引擎 | ● | ○ | ● | ● | ● | ● | 5.5 | 形态 B 或 C（看性能结论） |
| **流表 / 会话 / TCP / 重组** | — | — | ○ | ○ | — | — | 1 | **不可拆** |
| **特征提取器（21 维向量）** | — | — | ● | — | — | — | 1 | **不可拆** |
| **记录 schema（FlowRecord）** | ○ | — | ● | ● | ● | ● | 3.5 | **不可拆**（它是契约本身，不是插件） |
| **通道解码（共享环）** | — | — | ● | ● | — | — | 2 | **不可拆**（它**是**契约的实现侧，拆出去只是把 ABI 挪个位置） |
| **policyd match/evaluate 内核** | — | — | ● | ● | ● | — | 3 | **不可拆** |
| web console 页面 | ● | — | ○ | — | ● | ● | 3.5 | 不是插件（表现层，模块懒加载即可） |
| 测试/门禁/CI/版本真源 | — | — | ● | ● | ● | — | 3 | 不是插件（治理，宿主的一部分） |

---

## 4. 模块可拆性总表（逐模块裁决）

### 4.1 不可拆：核心引擎（L1）

| 模块 | 为什么不能插件化（证据） |
| --- | --- |
| `channel/`（C++ 生产端 + Rust 消费端 + `decode`） | 它**就是**共享环 ABI 的两侧实现。`channel-abi.json` 已冻结（`abi_version=1`，注释：「一经发布不得修改语义；增减字段必须同时提升 abi_version」），并有 89 行 parity 门禁。把它做成「插件」等于凭空造**第二个**版本面，而收益为零 |
| `flow/`（`FlowKey`/`FlowTable`/`FlowStats`/`IatRing`） | 每包热路径；条目内存 0.97KB/条与 4 核/10G 口的核预算是实测标定的（`HANDOFF.md` §2.6）。跨插件传条目会同时破坏内存布局与核预算 |
| `session/` + `tcp/`（会话聚合、TCP 双模状态机） | 刻意语义：`FlowTable` 被专门改成可移动进 worker 线程（观察者是 `Box<dyn FlowObserver + Send>`——**只要 `Send`、不要 `Sync`**，因为「共享一张表 + 加锁」恰是要避免的形态，`table.rs:573`）；TCP 事件区分「IP 载荷」与「段载荷」是为修正真实缺陷而立的（`HANDOFF.md` §2.4-2）。插件化会让「一个判据只有一处」失效 |
| `reassembly/`（序号回绕/区间集/重叠仲裁/内存上限降级） | 刻意语义：默认 `KeepOld`（Linux `tcp_trim_head`）、`anchored_by_syn` 必须保留、内存上限降级方向是「保连续弃乱序」（`HANDOFF.md` §2.2）。**注意**：该模块目前**尚未接入主管线**（只在 `bench.rs` 与测试中使用）——先接进核心，再谈别的 |
| `feature/`（21 维向量 + `idx` + `FEATURE_SCHEMA_VERSION`） | 它是**模型与规则的输入 ABI**。第 k 维含义若随插件而变，模型会静默把缺失维度当 0（`feature/mod.rs:6-11`） |
| `record/`（`FlowRecord` + `RECORD_SCHEMA_VERSION=1`） | 对外交付契约，每行自带版本（`record/mod.rs:9-12`）。它是**契约本体**，把它变成插件等于让下游解析方式随部署而变 |
| `parser/`（C++ L2–L4 基础解析 + `decode.rs` 的 ethertype/proto 判定） | 基础 L2–L4 定义 `Packet`/`FlowKey` 的形状，是所有上游的公共前置；`parser.cpp:35-52/64-82` 的 `switch` 是固定协议族，不是能力扩展点 |
| `pipeline`（编排） | 编排属于**宿主**职责；把它插件化没有意义（见 §2.2a），该做的是把它从库里上移 |
| `policyd` 的 `ruleir` 匹配/求值内核 | `match.go`（1118 行）+ `evaluate.go` 的「allow 优先」是刻意的**可用性**决策（`HANDOFF.md` §8-C1：「不要改回去」）。判定内核不可插件；**规则表、动作、白名单、加载后端可以** |

### 4.2 可拆 · 形态 A：数据插件（**最高优先级**）

| 插件 | 当前状态 | 已有基础 | 需要补什么 |
| --- | --- | --- | --- |
| 规则表 | 已有内存 + json-file 两种后端 | `ruleir.Store` 接口 + `Registry`（revision/checksum/rollback，`store.go:294-403`） | redis 后端、插件版本/来源元数据、命中统计 |
| 签名包（协议/应用签名） | **无** | 属性字典已有 `AppId` 命名空间约定（`types.rs:28-31`：高 16 位命名空间，**不用魔数边界**） | 签名 IR + 双向格式转换 + Git 版本化 + 校验和（TSG B4 / `CYS-TIP-011`） |
| IOC / 情报 feed | **无**（目录纯占位） | 真源里已声明 7 个 `source=threat-intelligence` 的属性 | feed 接入、归一化、TTL、大规模匹配（十万级） |
| 白名单 / 排除集 | **无** | `evaluate.go` 已有 `excludes` 一等公民（TSG B5 已落地） | 独立版本化 + 高效匹配（TSG 案例：1023 个 CDN 段 + 排除 56396 个 FQDN） |
| ML 模型 | **无**（`ml/model-registry` 空） | 真源已声明 2 个 `source=ml-inference` 的属性 | 模型注册表（版本/指标/来源）+ 校验和 + 热切换 |
| 属性字典扩展 | **已有真源**（99 条，version=2） | `attributes.json` + 四语言 codegen + `--check` 门禁 | **弃用周期**（旧名保留一个版本并告警）；插件的属性需带 `owner` |
| 端口/启发式表 | **硬编码** | `dpi/mod.rs:47-50` 四个 `PORT_*` 常量 | 把端口提示表移入真源（数据化），检测器只读表 |

> **形态 A 的落地范式已经存在**：`attributes.json` 的治理流程
> （改真源 → 重跑 codegen → 跑 verify → 提交）就是数据插件的标准模板；
> 把它复制到签名/规则/情报/模型上，**不需要发明任何新机制**。

### 4.3 可拆 · 形态 B：同进程静态插件

| 插件 | 当前状态 | 已有基础 | 改造要点 |
| --- | --- | --- | --- |
| 收包后端 | 3 个实现（pcap-file / af-packet / bpf） | **已经是纯虚接口 + 工厂 + 自省列表**（E1） | 工厂的 `if/std::strcmp` 链与 `available_backends()` 手写列表 → 清单驱动；把 `#if CYTHSEC_HAVE_*` 的编译期分支变成「清单里的平台适用性声明」 |
| OS 平台适配 | **0 LOC** | `platform/README.md` 已画好 common/linux/openeuler/openwrt 结构 | **出生即插件**：`platform/common` 定义契约，三个平台实现按清单装配；nftables 只在 Linux 可用这件事必须做成**能力声明**（对齐 `SubActionAvailable` 的做法） |
| 处置后端 | **0 LOC** | 判定层已完整：`SubActionAvailable(sub, mode)`、4 种 `DeployMode`、11 种 `SubAction`（`ruleir/action.go:29-104`） | **出生即插件**：`EnforcementBackend` trait + 4 实现（DryRun / Nftables / Inline / Pcap）；**DryRun 必须先做**，它是唯一能离线证明「判定→动作」闭环的形态 |
| 存储后端 | **0 LOC**（无任何 DB driver 导入） | `ruleir.Store` 四后端是同类先例 | `services/pkg` 里定义 Store 契约，PG/CH/Redis 三个实现插件化 |
| 遥测导出 | telemetryd 有 API 无后端 | `metrics` 包已有 Prometheus 文本格式 + 校验器（`check-prometheus-format.py`） | exporter 插件（Prometheus / ClickHouse / Kafka）；非热路径，风险低 |
| **DPI 检测器** | 3 个检测器（tls/dns/http），**硬编码编排** | `Detect`/`Outcome` 四态契约已冻结（`dpi/types.rs:187-199`）；32 条向量 + tshark 92 项核验 | **本案技术难度最高的一步**：`order()` 的定长 `[fn;3]` 数组 → 检测器注册表；`AppId` 枚举 → 命名空间内动态分配（**命名空间机制已预留**，`types.rs:28-31`）；端口提示表数据化。今天新增一个协议要**同时改三处核心**：枚举（`types.rs:17-24`）、数组**元数**（`mod.rs:57-67` 写死为 3）、以及每个 `match` 臂——而且枚举里的 `Quic`/`Ssh` **至今没有对应检测器**，正是「枚举先行、实现未到」的静态缺口。**四条不可退让**：① 四态语义不变；② 检测器仍是**纯函数**；③ 每包**零分配**；④ 每条检测器必须带自己的向量且过 tshark 核验（否则新增协议无法证明「真的识别了」） |
| 隧道/封装解析 | **0 LOC**（规划 `CYS-PKT-032`） | 基础 L2–L4 在核心里 | 作为**核心内的可选管段集合**（形态 B）：VLAN/VXLAN/GRE/PPPoE 各自成段，但**必须**过向量门禁；它改的是 `FlowKey` 提取，属热路径，先做完基础 L2–L4 再动 |
| 会话级判定/聚合引擎 | `crates/{behavior,risk}` 空；`record.risk_score` 恒为 `None` | TSG A2 已给出 `DetectionEvent` + 事件总线的设计 | 形态 B 或 C 取决于实测：若判定发生在**会话级**（非每包），进程内够用；若引入第三方模型，转 C |

### 4.4 可拆 · 形态 C：进程外插件（**只用在两处**）

| 插件 | 为什么必须进程外 | 代价 |
| --- | --- | --- |
| 第三方 / 商用 DPI 引擎（nDPI、Qosmos 类） | **双理由**：① 许可（nDPI 是 GPL，直接拷贝源码会污染；TSG 的实证做法正是「直接拷贝源码」`F23`）；② 崩溃隔离（TSG 的 `libqmbundle` 段错误拖垮 SAPP，`F43`） | IPC 序列化 + 部署复杂度 + 一次额外进程往返。**必须**做熔断与显式降级（对齐 `tsg-tech-transfer.md` §6 的 G6 崩溃隔离） |
| ML 推理 | ONNX Runtime 是第三方依赖，与「Rust 数据面零第三方依赖、离线可构建」的硬约定**直接冲突**（`Cargo.toml`：`[dependencies]` 为空；`build.rs`：只用 std；`bench.rs` 明确拒绝 Criterion） | 同上。且推理是**会话级**而非每包，往返成本可接受 |

> **形态 C 不是「更好的插件」，而是「为隔离与许可不得不付的代价」。**
> 能进程内解决的一律不要进程外——本仓当前**没有任何 IPC 基础设施**（§1.3）。

### 4.5 不属于插件范畴

| 对象 | 归属 | 理由 |
| --- | --- | --- |
| web console 的页面/组件 | 产品表现层 | 用路由懒加载即可；做成插件只会增加一个无收益的 ABI |
| `tests/`、`scripts/verify/*`、CI | 治理 / 宿主 | 「检查器本身」不该是可替换的插件——否则「谁验检查器」无解 |
| `VERSION`、codegen、schema 真源 | 契约地基（L0） | 单一真源是全仓前提，不可插件化 |
| `datasets/`、向量生成器 | 测试资产 | 向量必须编进二进制（`include_bytes!`）才是硬断言 |

---

## 5. 关键契约（只定边界，不写实现）

| 契约 | 现状 | 冻结策略 |
| --- | --- | --- |
| **C1 属性/能力注册表** | ✅ 已有：99 属性 / 14 类型 / 8 scope / 5 stage / 3 cost / 5 生产者 | 只增不删；改名走弃用周期（旧名保留一个版本并告警） |
| **C2 通道 ABI** | ✅ 已有：`abi_version=1`、冻结规则写在真源注释里、89 行 parity 门禁 | 增减字段必须升 `abi_version`；旧版本 attach 期**明确报错**而非静默错读 |
| **C3 检测裁决四态** | ✅ 已有：`Detect{Hit,NeedMore,Rejected,Malformed}` + `Outcome{Identified,NeedMore,Malformed,Unknown}` | **必须冻结为插件 ABI 的一部分**。四态刻意不用 `Result`（`types.rs:187-189`），插件接口若把它退化成 `Result`，省网 unknown 率会立刻虚高 |
| **C4 特征向量** | ✅ 已有：`[f64; 21]` + `idx` 常量 + `FEATURE_SCHEMA_VERSION=1` | **不是插件边界**，是插件的**输入契约**；任何维度/含义变化必须升版 |
| **C5 记录 schema** | ✅ 已有：`RECORD_SCHEMA_VERSION=1`，每行自带版本 | 同上；`null` 与 `0.0` 必须可区分（`record/mod.rs:14-18`） |
| **C6 插件清单 + 能力协商** | ❌ **缺，本案新增** | 新真源 `configs/registry/plugins.json` → codegen 出宿主绑定 → `--check` 门禁。字段建议：`{name, kind(platform/protocol/business), form(A/B/C), version, requires_host_abi, capabilities[], priority, enabled, source, license}`。**注意**：全仓当前**没有任何 per-component 版本**（唯一版本是根 `VERSION`），所以 `version` 与 `requires_host_abi` 是**从零建立**的字段，必须同时定义「不兼容时的行为」（装载期拒绝，不允许尽力而为） |
| **C7 会话级事件** | ❌ 缺（TSG A2 已设计） | `DetectionEvent { session_id, source_engine, attrs, confidence }` + topic 订阅；**检测器之间不得互相调用**，各自发布、由聚合点统一裁决 |
| **C8 处置可用性矩阵** | ✅ 已有：`SubActionAvailable(11 原语 × 4 模式)` | 部署模式必须显式声明；不可用原语在装载期即拦截（启用规则→阻塞级错误；停用规则→提示级） |

**契约设计的三条硬规则**：

1. **契约下沉，实现上浮**：凡跨边界的数据类型，必须在 `configs/registry/` 有真源、由 codegen 产出，**禁止各语言手写**（已有惨痛先例：`.gitignore` 与版本副本漂移，`HANDOFF.md` §7 第 7 条）。
2. **边界只允许两种形状**：**纯函数**（无状态、可内联、向量可测）或**消息**（有版本、可序列化、可回放）。**禁止共享可变状态跨边界**。
3. **每个插件必须自证「干没干」**：只报「成功」而不报处理量，就是「绿色的通过和绿色的没跑长得一样」（`pipeline.rs:70-71` 的原话）。插件的最小契约里应包含 counters。

---

## 6. 运行框架（宿主）职责清单

| 职责 | 要求 | 已有先例 |
| --- | --- | --- |
| 清单加载与校验 | 清单非法 → **启动即失败并点名条目**（不是跳过） | TSG A1 验收口径 |
| 能力 / 版本协商 | 宿主 ABI 与插件 `requires_host_abi` 不兼容 → **显式拒绝**，不静默降级 | 通道 ABI attach 期强校验 |
| 生命周期 | init → start → drain → stop / reload，各阶段幂等 | Go `controlplane` 的优雅关闭 |
| 隔离与降级 | 插件 panic/崩溃 → 隔离到该插件，核心继续；降级**必须**进指标与日志 | 缺（须新建） |
| 观测 | 每个插件的 counters + 版本 + 生效状态可查 | `available_backends()`、`capture_mode_name()`、`fallback_reason()` |
| 原子热更新 | 新版本校验 → 原子切换 → 失败保持旧版本并告警 | `ruleir.Registry` Install/Rollback（`store.go:324/403`） |
| **部署清单与版本上报** | 每个插件版本可查询 | **TSG 实证教训**（`tsg-tech-transfer.md` §4 的 S5/S6 附注）：论文指出「一个部署可能跑同版本 SAPP 但不同版本 SSL 插件」，故「指纹到一个插件不代表另一个存在」 |

---

## 7. 可行性评估

### 7.1 有利因素（强）

| 因素 | 证据与含义 |
| --- | --- |
| **契约治理体系已成型** | 真源 → codegen → 四语言绑定 → `--check` 门禁，另加 9 项 lint 与 13 个 `scripts/verify/*` 脚本。插件 ABI 治理**最难的部分已被预演过** |
| **已有 5 个半插件缝隙** | E1 收包后端纯虚接口、E2 观察者 trait object、E3 控制面注册回调、E4 `ruleir.Store` 四实现 + 原子换版、E5 telemetryd 纯数据目标 |
| **能力清单先于实现存在** | `attributes.json` 的 `source` 字段已声明 5 个生产者的能力边界（30/57/7/3/2），其中 3 个尚无代码——正是「先契约后实现」的范式 |
| **零第三方依赖 + 离线可构建** | 形态 B（静态插件）天然契合；形态 C 的必要性反而因此更清楚（第三方运行时只能进程外） |
| **反向注入已是硬规矩** | 「新增或修改门禁后必须注入必然违规的输入确认它会报错」（`HANDOFF.md` §4.2）。插件化最大的风险（假绿、静默降级）**已有方法论兜底** |
| **大部分目标模块是 0 LOC** | `platform`/`storage`/`threat-intelligence`/`ml/inference` 出生即插件，改造阻力最小 |

### 7.2 不利因素与硬约束（必须承认）

| 约束 | 后果 |
| --- | --- |
| **无任何动态加载/清单/协商/隔离/IPC 基础设施** | 形态 C 是**从零建**，属 XL |
| **热路径硬编码** | DPI 插件化（唯一的形态 B 改造项）**必须先动核心**：`order()` 定长数组、`AppId` 枚举、`parser.cpp` 的 `switch` |
| **核心直接依赖具体模块** | `pipeline.rs:29-36` 一次性 `use` 8 个模块；`lib.rs:16-26` 硬声明。「核心不依赖插件」这条规则**当前不成立**，需先建注入缝隙 |
| **性能预算是硬约束** | 每包 14.88 Mpps 目标、4 核/10G 口核预算（`HANDOFF.md` §2.6）；任何触及每包路径的改动都必须给出**同机前后对比**（本仓硬约定 `HANDOFF.md` §5 第 11 条） |
| **Rust 零依赖** | 无 `libloading`/`abi_stable` 等成熟插件库可引入；C 形态只能靠 socket/共享内存自研 |
| **治理债** | `BACKLOG.md` 控制平面部分已滞后于代码（`HANDOFF.md` §1 顶部警告）。再叠加插件版本矩阵会加剧漂移 → 插件清单必须**进版本控制并挂门禁** |
| **规模现实** | 约 5.0 万行有效源码、以单人 + 并行协作者为主的工程。插件框架的维护成本必须用收益自证，不能默认「更灵活 = 更好」 |
| **门禁自证与 CI 覆盖都不齐** | 守契约的三道（`check-attributes`/`check-channel-abi`/`check-channel-parity`）**都没有反向注入**；`ci.yml` 又只跑 `--cpp`/`--rust`/`--go`。插件契约若直接建在这三道之上，会同时继承「没有自证」与「CI 不跑」两个缺口 |
| **没有按组件的交付物** | `deploy/` 是空骨架，`docs/deployment/dev-run-deploy.md` 假定单仓单构建。**插件能分开升级 ≠ 能分开交付**；后者属 M8，需并行推进否则 P1/P2 的成果无法上线 |

### 7.3 成本量级（按本仓 S/M/L/XL 口径）

| 工作项 | 规模 | 说明 |
| --- | --- | --- |
| 核心库 / 宿主职责切分（§2.2a） | **S~M** | 纯重组，不改行为；`traffic-engine` 已有 lib+bin 结构 |
| 契约显式化（清单 schema + 去硬编码依赖 + 「核心不得依赖插件」门禁） | **M** | 新增真源 + codegen + 一条静态检查 |
| 形态 A 数据插件通道（签名/规则/情报/模型） | **M~L** | 复用 `ruleir.Registry` 与 `attributes.json` 治理流程 |
| 形态 B 空模块「出生即插件」（platform/处置/存储/遥测） | **L** | 4 个新子系统，但都是新代码，无改造风险 |
| 形态 B 改造：DPI 检测器注册表 | **L** | 技术难度最高；需保四态语义 + 纯函数 + 零分配 + 每条带向量 |
| 形态 C 进程外框架（IPC + 隔离 + 生命周期 + 熔断降级） | **XL** | 本仓无 IPC 基础，建议拆成 3~4 个子任务 |

### 7.4 三档方案对比

| | 方案甲（最小可行） | 方案乙（推荐目标） | 方案丙（激进，不建议现在做） |
| --- | --- | --- | --- |
| 内容 | 契约先行 + 核心/宿主切分 + 形态 A 数据插件 + 空模块「出生即插件」 | 甲 + DPI 检测器注册表（形态 B）+ 会话事件总线 | 全模块 `dlopen` 动态插件 + 全引擎进程外 |
| 覆盖面 | 「分开升级」诉求的 **~70%**（签名/规则/情报/模型/平台/处置/存储） | ~90% | 100% |
| 成本 | M~L | L | XL×N |
| 对热路径的影响 | **零** | 小（需 benchmark 前后对比） | 大（每包间接跳转） |
| 主要风险 | 低 | 中（DPI 语义与性能回归） | 高（版本矩阵爆炸、性能、许可、故障面） |
| 结论 | **立即做** | **甲之后做** | **仅在「第三方引擎」一条上局部采用（形态 C）** |

**推荐**：**甲 → 乙** 分阶段；丙只保留其中的形态 C。

---

## 8. 分阶段实施路线

> 每阶段的验收都必须包含三件事：① **反向注入**（证明门禁真的会拦）；② **降级可见性断言**（插件缺席时必须能看见）；③ 若触及热路径，**同机前后性能对比**。

### P0 — 契约地基（不改任何行为）

| # | 工作 | 待办编号 |
| --- | --- | --- |
| 1 | 核心库 / 宿主切分：把 `pipeline.rs` 的默认策略与编排上移到宿主，库只留 API | `CYS-TRF-048` |
| 2 | 新增真源 `configs/registry/plugins.json` + codegen 出宿主绑定 + `check-plugins.sh` 门禁 | `CYS-TRF-040` |
| 3 | 新增门禁：**核心不得依赖具体插件**（静态检查 `lib.rs`/`pipeline.rs` 的 `use` 白名单）与**插件间不得互调** | `CYS-INF-037` |
| 4 | 对齐 `CYS-TRF-001`（cargo workspace 拆分）：目录边界已按 crate 语义画好（9 个空目录），此时拆是**纯目录搬移** | 前置：`CYS-TRF-001` |
| 5 | **补门禁自身的短板**（前置动作，否则后面所有插件门禁都不可信）：给 `check-attributes` / `check-channel-abi` / `check-channel-parity` 加反向注入；新门禁同时挂 `ci.yml`（不能只挂 `test-all.sh`） | `CYS-INF-038` |
| 6 | 修掉上游方案自身的一处重号（`CYS-INF-035` 与已完成的仓库完整性自检冲突） | `CYS-DBT-021` |

**验收**：清单非法时启动即失败并点名条目；注入一条「核心 use 了某个插件」→ 门禁判红；契约门禁在注入下判红；`ci.yml` 上能看见新门禁的 job。

### P1 — 形态 A 数据插件通道（**收益最快**）

| # | 工作 | 待办编号 |
| --- | --- | --- |
| 1 | **热更新触发通道**（当前全仓没有）：控制面下发 / `SIGHUP` / 文件监听三选一，配合已有的 `Registry.Install/Rollback` 原子语义；**失败必须保持旧版本并告警** | `CYS-INF-039` |
| 2 | 规则表补 `redis` 后端（`RedisStore` 现在是刻意留的错误桩，`store.go:216-233`）+ 插件元数据；命中统计 | 承接 `CYS-POL-005`/`006` |
| 3 | 签名包：IR + 格式双向转换 + Git 版本化 + 校验和 | `CYS-TIP-011` |
| 4 | IOC/情报 feed 接入 + 归一化 + TTL；白名单独立版本化 | 承接 `CYS-TIP-001`/`002`/`003`/`008` |
| 5 | 模型注册表（版本/指标/来源）+ 校验和；与 `ml/training` 的导出契约对齐 | 承接 `CYS-MLT-016`（对齐 `CYS-TRF-028`/`CYS-MLI-003`） |
| 6 | 属性字典加 `owner` 字段 + 弃用周期（旧名保留一个版本并告警）+ 插件属性命名空间 | `CYS-TRF-043` |

**验收**：热更新失败时**保持旧版本生效并告警**；每个数据插件都能回答「当前生效版本 / 条目数 / 上次更新」。

### P2 — 空模块「出生即插件」（形态 B）

| # | 工作 | 待办编号 |
| --- | --- | --- |
| 1 | `platform/common` 契约 → `linux`（netlink/nftables/ethtool）、`openeuler`、`openwrt` 实现；nftables 的 Linux 专属做成**能力声明** | 承接 `CYS-PLT-001`/`007` |
| 2 | 处置后端：**先做 `DryRun`**（离线证明「判定→动作」闭环）→ `Pcap` → `Nftables`（参数化构造，防注入）→ `Inline` | 承接 `CYS-POL-007`/`008`/`009` |
| 3 | 存储后端：Store 契约 + PG/CH/Redis 实现按清单装配 | `CYS-STO-012`（实现承接 `CYS-STO-003`/`006`/`007`） |
| 4 | 遥测导出与**每插件版本上报**（「指纹到一个插件不代表另一个存在」可被证实） | `CYS-TEL-014` |

**验收**：切后端不改任何匹配/判定逻辑；`DryRun` 在离线 pcap 回放上产出完整「判定 vs 实际动作」日志；每个插件版本可独立查询。

### P3 — DPI 检测器注册表（形态 B，本案最难一步）

| # | 工作 | 待办编号 |
| --- | --- | --- |
| 1 | `order()` 的定长 `[fn;3]` → 检测器注册表（端口提示表数据化） | `CYS-TRF-049` |
| 2 | `AppId` 枚举 → 命名空间内动态分配（机制已预留，`types.rs:28-31`） | `CYS-TRF-049` |
| 3 | 检测器接口 = 纯函数 + 四态输出 + **零分配** + 声明的端口/topic 提示 | `CYS-TRF-049` |
| 4 | 每条检测器自带向量，且必须过 tshark 核验（**找不到第三方参照就显式标 `verified=false` + 原因**，不许默认通过） | `CYS-TRF-050` |

**验收**：新增一个协议检测器 = 新增模块 + 清单条目，**零改动**核心调度；四态语义逐条不变；`cythsec-bench` 同机前后对比无回归。

### P4 — 进程外引擎 + 会话事件总线（形态 C）

| # | 工作 | 待办编号 |
| --- | --- | --- |
| 1 | `DetectionEvent` + 会话级事件总线（topic 订阅，检测器之间不互相调用） | `CYS-TRF-042` |
| 2 | 进程外引擎框架：IPC + 心跳 + **熔断降级**（引擎不可用 → 降级为该引擎本轮不可用，核心继续）+ 许可清单 | `CYS-TRF-044` |
| 3 | 首批接入：第三方 DPI 引擎适配、ML 推理（**与 `CYS-MLI-001` 二选一**：链进数据面 vs 进程外） | `CYS-MLI-011` |

**验收**：`SIGKILL` 外部引擎后主流程继续运行，且指标明确暴露「引擎降级」；许可清单标注各引擎许可与分发边界。

### 8.5 与待办表的编号映射（本方案 ←→ `BACKLOG.md` §3.10 / M10）

> **双向可追溯**：下表的每个编号都能在 `BACKLOG.md` §3.10 找到任务行与验收标准；
> §3.10 的每个任务也都归属本方案的一个阶段。**本文改边界，待办表管执行。**

| 阶段 | 新增编号（M10 内，共 17 项） | 承接的既有编号（**不重复发号**） |
| --- | --- | --- |
| **P0** 契约地基 | `CYS-INF-037`、`CYS-INF-038`、`CYS-TRF-040`、`CYS-TRF-048`、`CYS-DBT-021` | 前置 `CYS-TRF-001` |
| **P1** 数据插件通道 | `CYS-INF-039`、`CYS-TIP-011`、`CYS-TRF-043` | `CYS-POL-005`/`006`、`CYS-TIP-001`/`002`/`003`/`008`、`CYS-MLT-016` |
| **P2** 出生即插件 | `CYS-STO-012`、`CYS-TEL-014` | `CYS-PLT-001`/`007`、`CYS-POL-007`/`008`/`009`、`CYS-STO-003`/`006`/`007` |
| **P3** DPI 注册表 | `CYS-TRF-049`、`CYS-TRF-050` | — |
| **P4** 进程外 | `CYS-TRF-042`、`CYS-TRF-044`、`CYS-MLI-011` | — |
| **文档** | `CYS-DOC-021`（上游 TSG 方案）、`CYS-DOC-022`（本文档） | — |

**刻意不启用的 TSG 预留编号**（核对后与既有任务重复或已落地）：

| 预留编号 | 不启用原因 |
| --- | --- |
| `CYS-POL-017` 规则 IR 结构化 | 已由 `CYS-POL-004` 落地（TSG §9.1 A5 ✅：`match.go` 8 方法 × 5 格式） |
| `CYS-POL-019` 白名单/排除集 | 已由 `evaluate.go` 的 `excludes` 落地（TSG §9.1 B5 ✅） |
| `CYS-POL-018` 装载后端与热更新 | 抽象与原子换版已落地（A5′/A6 ✅，后端 2/3）；剩余「redis + 触发通道」归 `CYS-POL-005`/`006` 与 `CYS-INF-039` |
| `CYS-POL-020` 处置动作全集与参数化 | 判定层已落地（D2 ✅ 4 模式 × 11 原语）；执行侧归 `CYS-POL-007`/`008`/`009` |
| `CYS-TIP-012` 情报 feed 与 TTL | 与 `CYS-TIP-002`/`003`/`008` 重复 |
| `CYS-PLT-010` 平台按清单装配 | 与 `CYS-PLT-001`/`007` 重复 |

---

## 9. 风险、反模式与对冲

| # | 风险 | 对冲 |
| --- | --- | --- |
| R1 | **版本矩阵爆炸**（插件数 × 版本数） | 部署清单 + 版本上报 + 能力协商（C6 + §6）；「指纹到一个插件不代表另一个存在」是 TSG 的实证教训 |
| R2 | **假绿**：插件「加载了但没跑」 | 每个插件必须有「干没干」的 counters；新门禁一律反向注入（本仓既有硬规矩） |
| R3 | **热路径性能回归** | 任何触及每包路径的改动必须给同机背靠背前后对比 + 复杂度可测证据（`HANDOFF.md` §5 第 11 条的三件套） |
| R4 | **静默降级** | 降级必须进指标/日志/记录。反例参照：`app.outcome="not_inspected"` 不能并进 `"unknown"`；`risk_score` 未实现就写 `null` 而非 `0.0` |
| R5 | **契约漂移** | 真源单一 + codegen `--check` + 弃用周期 + 挂门禁（三条缺一条都等于没有） |
| R6 | **过度拆分**（为插件而插件） | 六条准入判据（§3）+ 明确非目标（§10）。反例：把每个小函数抽成一个 trait，只会让调用链无法内联 |
| R7 | **治理债加剧** | 插件清单与 BACKLOG 同步；新增目录后立刻 `git check-ignore -v`（`HANDOFF.md` §7 第 7 条：三处被 `.gitignore` 吃掉的教训） |
| R8 | **许可污染** | 外部引擎一律形态 C（进程隔离）；许可清单（`CYS-INF-027`）+ `docs/security/` 记录分发边界 |
| R9 | **插件间耦合** | 检测器之间**不得互相调用**（TSG F37 的核心洞见：多条并行判定路径汇入同一判定点） |
| R10 | **「有检查器」≠「检查器会跑」** | 三条缺一不可：在版本控制里、有反向注入、挂在 CI 上。**当前仓库里就有两个活例**：① `scripts/verify/bench-pipeline.sh` **已入库（`git ls-files` 可见）但仍未被任何门禁调用**，它是本批 `--workers N` 测量的唯一工具，却不在任何关口上 → 「流水线并行度回归」目前**无人看守**；② `docs/planning/scripts/check-deps.py`（消费待办表依赖图）同样不在任何门禁或 CI 上 —— 而它本次恰好被用来核对 M10 的 17 条新依赖（0 环 / 0 悬空 / 0 自依赖）。**两个都只满足三条里的第一条**，都已登记进 `CYS-INF-038` 的交付物。插件门禁必须一次性挂齐三处 |
| R11 | **热更新只做了一半** | 「原子换版」已有（`Registry.Install/Rollback`），但**触发通道没有**（全仓无 `SIGHUP`/`fsnotify`）。只补换版不补通道，数据插件就退化成「要重启才生效的配置文件」 |

**必须写进代码注释的反模式清单**（供实现时逐条拒绝）：
1. 为插件而插件——接口粒度小于「一次完整能力」的不要拆。
2. 每包路径 `dlopen` / 虚函数间接调用。
3. 插件直接读全局变量/环境变量/配置文件（应经宿主注入）。
4. 插件之间直接调用（应经总线/聚合点）。
5. 「插件未加载」与「插件加载了但没命中」在日志里长得一样。
6. 降级路径返回成功。

---

## 10. 非目标（明确不做什么）

1. **不做**数据面每包路径上的 `dlopen` 任意代码热加载。
2. **不做**跨语言统一插件内核（Rust/C++/Go/Python 各自的边界不同，不追求一个万能 ABI）。
3. **不把** web 页面、测试、门禁、版本真源插件化。
4. **不在本案中实现** XDP/AF_XDP/DPDK（属 `CYS-PKT-006/009/010`）——只规定它们进来时应遵循的插件形态。
5. **不引入**第三方插件框架依赖（与「零第三方依赖、离线可构建」冲突）。
6. **不追求**「一次到位」——P0~P4 每阶段都可独立交付与回退。

---

## 11. 待决策项（Open Questions）

| # | 决策点 | 建议 |
| --- | --- | --- |
| Q1 | 形态 B 是否允许 `dlopen`？ | **不建议**（至少不在每包路径）。静态注册表已满足「不改核心调度」这一唯一实质诉求 |
| Q2 | 形态 C 的 IPC 载体 | 复用现有能力最省：Unix socket + 手写 JSON（与 `record` 的手写 JSON 同风格），或直接复用共享环。**不建议**引入 gRPC/protobuf（第三方依赖） |
| Q3 | 插件清单：集中真源 vs 每插件自带 manifest | **集中真源**（`configs/registry/plugins.json`）。理由：本仓唯一的治理范式就是集中真源 + codegen，分散清单会让「全量能力」无法被一次性校验 |
| Q4 | 插件 ABI 版本语义 | 宿主声明 `host_abi`；插件声明 `requires_host_abi`；不兼容**装载期拒绝**，不允许「尽力而为」 |
| Q5 | `CYS-TRF-001`（拆 workspace）与插件化的先后 | 先做 P0-4（它是纯目录搬移，且能让「核心不依赖插件」的门禁在编译期可表达） |
| Q6 | `crates/behavior`、`crates/risk` 是 B 还是 C？ | 先做 B（进程内），**触发条件**：若判定需引入第三方模型运行时 → 转 C |
| Q7 | 用户提法中的「特征库」是否包含「签名库」？ | 按本文 §2.2b 拆为「提取器（核心）/ 定义（契约）/ 扩展（插件）」，三者分别处理 |

---

## 12. 一句话交给下一棒

**分层解耦该做，但要按「契约先下沉、核心保持单体、插件按六条判据分级」来做**：
`platform`/`storage`/`threat-intelligence` 这些 0 LOC 的层**出生即插件**（最省）；
`attributes.json`/`ruleir.Registry` 已经给出了数据插件的**现成范式**，直接复制即可（收益最快）；
唯一需要动核心的是 **DPI 检测器注册表**（`order()` 定长数组 + `AppId` 枚举），
而它必须付三笔账：四态语义不变、每包零分配、同机性能前后对比。
**不要把流表/会话/重组/特征向量/记录 schema 插件化**——它们是契约与热路径本体，
拆出去的代价（性能、语义漂移、版本矩阵）远大于收益。

**立刻可以开工的第一步（不依赖 M2~M9 任何功能完成）**：
`CYS-INF-037`（依赖方向门禁）+ `CYS-INF-038`（契约门禁自证与 CI 接入）+ `CYS-TRF-040`（插件清单真源）
+ `CYS-TRF-048`（核心库/宿主切分）+ `CYS-DBT-021`（修上游重号）。
这五项**不改任何行为**，却是后面所有插件化工作的前置——**门禁不可信，后面的插件契约就都不可信**。

---

## 附录 A：证据索引（关键 file:line）

| 主题 | 位置 |
| --- | --- |
| 收包后端纯虚接口 | `dataplane/packet-engine/include/packet_engine/backend.h:45-118` |
| 后端工厂（硬编码 if 链） | `dataplane/packet-engine/src/backend.cpp:85-146`、`:200-214` |
| DPI 硬编码编排（定长 fn 数组） | `dataplane/traffic-engine/src/dpi/mod.rs:47-67`、`:76-99` |
| 四态裁决语义（刻意不用 Result） | `dataplane/traffic-engine/src/dpi/types.rs:187-199` |
| `AppId` 命名空间（预留自定义段） | `dataplane/traffic-engine/src/dpi/types.rs:17-58` |
| 特征向量契约 | `dataplane/traffic-engine/src/feature/mod.rs:6-11`、`:18-25`、`:29-97` |
| 记录 schema 契约 | `dataplane/traffic-engine/src/record/mod.rs:9-18`、`:31` |
| 流水线（核心→8 模块硬依赖） | `dataplane/traffic-engine/src/pipeline.rs:29-36`、`:40-68` |
| 观察者 trait object | `dataplane/traffic-engine/src/flow/table.rs:260-278`、`:573` |
| 生产路径清空观察者 | `dataplane/traffic-engine/src/session/mod.rs:310-311` |
| 通道 ABI 冻结规则 | `configs/registry/channel-abi.json`（`_comment`）；`configs/README.md` |
| 属性真源与生产者 | `configs/registry/attributes.json`；`configs/README.md`（99 条 / 四语言绑定） |
| 规则 Store 接口与四实现 | `services/policyd/internal/ruleir/store.go:51`、`:80/:106/:144/:221` |
| Registry 原子换版与回滚 | `services/policyd/internal/ruleir/store.go:294`、`:324`、`:403`、`:430` |
| 处置可用性矩阵 | `services/policyd/internal/ruleir/action.go:29-104` |
| 控制面注册回调 | `services/pkg/controlplane/controlplane.go:64`；`services/policyd/internal/api/server.go:80-88` |
| 门禁与反向注入规矩 | `docs/planning/HANDOFF.md` §4、§4.2、§5 第 11 条 |
| 性能预算与核预算 | `docs/planning/HANDOFF.md` §2.5、§2.6 |
| 待办表滞后提醒 | `docs/planning/HANDOFF.md` §1 顶部、§6 末两条 |
| TSG 架构级引入清单 | `docs/architecture/tsg-tech-transfer.md` §3.1（A1~A6）、§9.1（落地状态） |
| 形态 A 最接近真插件的先例 | `services/telemetryd/internal/target/load.go:11-45`、`store.go:139` |
| Go 侧仅有的两个接口 | `services/policyd/internal/ruleir/store.go:51`、`services/pkg/metrics/metrics.go:30` |
| Redis 后端是刻意留的桩 | `services/policyd/internal/ruleir/store.go:216-233` |
| 无热更新通道 | `services/pkg/configutil/configutil.go:77-113`、`services/policyd/internal/policy/load.go:8-40` |
| `deploy/` 空骨架 | `deploy/README.md:5`；`docs/deployment/dev-run-deploy.md:10-55`（单仓单构建） |
| CI 比 `make test` 窄 | `.github/workflows/ci.yml:22,35,57,76` |
| 门禁自证覆盖 | `scripts/verify/`：仅 `check-dpi-vectors.sh`、`check-flow-records.sh`、`check-flow-bench.sh` 含反向注入 |
| 活例：有脚本但无人调用 | `scripts/verify/bench-pipeline.sh`（未入库、未被任何门禁引用） |
| 文档漂移实例（同类风险） | `tools/README.md:22` 写「98 条属性」，实际 99 条（`configs/README.md:16`） |

## 附录 B：术语表

| 术语 | 含义 |
| --- | --- |
| L0 契约层 | 真源 JSON + codegen + 门禁；全仓唯一事实来源 |
| L1 核心引擎 | 每包/每流快路径的单体实现；确定性、无策略、不依赖插件 |
| L2 插件面 | 三类（platform/protocol/business）× 三形态（A 数据 / B 同进程静态 / C 进程外） |
| L3 运行框架 | 宿主：清单、协商、生命周期、隔离、观测、热更新 |
| 形态 A | 数据插件：纯数据资产 + 清单，无 ABI，可热更新 |
| 形态 B | 同进程静态插件：trait/纯虚 + 清单，**不用 dlopen** |
| 形态 C | 进程外插件：独立进程 + IPC，用于隔离与许可边界 |
| 四态裁决 | `Identified / NeedMore / Malformed / Unknown`（`Detect`/`Outcome`） |
| 反向注入 | 注入必然违规的输入，确认门禁会报错——防「绿色=没跑」 |

---

## 附录 C：变更记录

| 日期 | 版本 | 变更 |
| --- | --- | --- |
| 2026-10-05 | **v1.0.0** | **审核通过，升为正式方案并合并进开发计划**：① 新增 §0.1「批准与落地」；② §8 的 P0~P4 每项工作**逐条挂上待办编号**，并新增 **§8.5 编号映射**（含「刻意不启用的 TSG 预留编号」及原因）；③ 落地载体 = `BACKLOG.md` 新增里程碑 **M10「分层解耦与插件化」**（17 项，待办表 350 → **367**，里程碑 9 → 10）；④ 按 `10175e8` 复核并刷新全部基线事实与行号（`traffic-engine` 21,759 → **21,793**、`packet-engine` 9,226 → **9,403**、规模口径 47k → 约 5.0 万行），并在 §1.1 记录**计数时踩到的 `*/target/*` 排除陷阱**（telemetryd 被少算 862 行）；⑤ R10 的活例按新事实改写：`bench-pipeline.sh` **已入库但仍未被任何门禁调用**（三条只满足一条）；⑥ §12 补「立刻可开工的第一步」 |
| 2026-10-05 | v0.1.0 | 初版评估稿：分层模型（L0~L4）、三类 × 三形态插件、六条准入判据与逐模块裁决、可行性评估、分阶段路线、风险与待决策项。**性质为评估稿，未落地任何代码** |
