# SPRINT-02 编排方案 —— M10「分层解耦与插件化」第一批（P0 契约地基）

> 日期：2026-10-05
> 基线：`10175e8` · v0.1.0
> 依据：`docs/architecture/layered-plugin-architecture.md`（**正式方案 v1.0.0**）与
> `docs/planning/BACKLOG.md` **§3.10 / 里程碑 M10**
> **本文件的性质：编排方案（尚未执行）。** 与 `SPRINT-01.md` 的区别是那份含执行记录，
> 本份只定范围、区域切分与验证关口；执行后应像 SPRINT-01 那样补「结果」列。

---

## 1. 为什么第一批只做这五项

M10 有 17 项，但**只有 5 项可以立刻开工且不必等任何功能完成**：

| 编号 | 任务 | 为什么排在最前 |
| --- | --- | --- |
| `CYS-INF-037` | 架构依赖方向门禁 | 「核心不得依赖具体插件」这条规则**现在无法表达**（`pipeline.rs:29-36` 一次 `use` 8 个模块）。规则先能被检查，才谈得上遵守 |
| `CYS-INF-038` | 契约门禁自证与 CI 接入补齐 | 守契约的三道门禁（attributes / channel-abi / parity）**一道都没有反向注入**，且**都不在 `ci.yml` 上**。插件契约若建在它们之上，会同时继承两个缺口 —— **这道不做，后面的插件门禁都不可信** |
| `CYS-TRF-040` | 插件清单真源、静态注册表与装配调度 | 整个 M10 的**唯一契约载体**。没有它，后面每一项都会自己发明一套装配方式 |
| `CYS-TRF-048` | 核心库与宿主切分 | 把编排与默认策略从库里上移到宿主。**纯重组、不改行为**，是 `CYS-TRF-040` 的落地侧 |
| `CYS-DBT-021` | 修正上游方案编号重号 | 纯文档、几分钟的事，但**放着不管会让两份文档对同一编号有两种含义** |

**本批刻意不做**：P1 数据资产通道、P3 DPI 检测器注册表、P4 进程外引擎。
理由：P3 要改核心热路径（必须先付三笔账：四态语义不变、每包零分配、同机性能前后对比），
P1/P4 都依赖 `CYS-TRF-040` 的清单产物。**先把地基和门禁立稳，再动有性能风险的部分。**

---

## 2. 编排三原则（沿用 SPRINT-01，并补一条）

1. **先立门禁，再改结构。** 与 SPRINT-01 的「先清障」同源，但更强：本批的产物是**规则本身**，
   规则若不能自证，后面所有插件化都建在沙子上。
2. **按文件区域切分职责，而非按任务类型。** 并行改动必须在物理上互斥（见 §3 的独占区域表）。
3. **每条工作流必须有可执行的验证关口。** 不接受「我改好了」；验收标准是**具体命令 + 期望输出**。
4. **（本批新增）新门禁必须同时挂三处**：**入库**、**有反向注入**、**挂在 `ci.yml`**。
   三条缺一条就等于没有 —— 仓库里已有活例：`scripts/verify/bench-pipeline.sh`
   已入库却**未被任何门禁调用**（见 HANDOFF §2.9 与方案 §9 的 R10）。

---

## 3. 文件区域切分（独占，避免写冲突）

| 工作流 | 独占区域（可写） | **绝对不要碰** |
| --- | --- | --- |
| **W1** `CYS-INF-037`<br>依赖方向门禁 | `scripts/lint/check-architecture.sh`（新建）<br>`scripts/lint/lint-all.sh`（仅追加一项） | `scripts/verify/*`、`.github/workflows/*`、`configs/**`、`dataplane/**` |
| **W2** `CYS-INF-038`<br>契约门禁自证 + CI | `scripts/verify/check-attributes.sh`<br>`scripts/verify/check-channel-abi.sh`<br>`scripts/verify/check-channel-parity.sh`<br>`.github/workflows/ci.yml` | `scripts/lint/*`、`tools/codegen/**`、`configs/registry/*.json`（**真源不可为通过测试而改**） |
| **W3** `CYS-TRF-040`<br>插件清单真源与注册表 | `configs/registry/plugins.json`（新建）<br>`tools/codegen/gen-plugins.py`（新建）<br>`scripts/verify/check-plugins.sh`（新建）<br>`configs/README.md` | `dataplane/traffic-engine/src/lib.rs`、`pipeline.rs`、`src/bin/**`（**归 W4**）、`scripts/lint/*` |
| **W4** `CYS-TRF-048`<br>核心库/宿主切分 | `dataplane/traffic-engine/src/{lib.rs,pipeline.rs}`<br>`dataplane/traffic-engine/src/bin/**`<br>`dataplane/traffic-engine/tests/**` | `configs/**`、`tools/**`、`scripts/**` |
| **W5** `CYS-DBT-021`<br>修上游重号 | `docs/architecture/tsg-tech-transfer.md` §8.5 | 其他一切（含 `BACKLOG.md` —— 本批不新增编号） |

**并发拓扑**：

```
        W1 依赖方向门禁 ─┐
        W2 契约门禁自证 ─┤ 三者完全独立，可同时开工
        W5 修上游重号  ─┘
                          W3 插件清单真源 ──► W4 核心库/宿主切分
                                              （W4 依赖 W3 的清单产物；
                                               两者共享 lib.rs 表面，必须串行）
```

> **W3 → W4 必须串行**：两者都会碰到 `traffic-engine` 的模块声明面。
> 若强行并行，`lib.rs` 的 `pub mod` 行必然冲突。**W3 先交付清单产物，W4 再动核心表面。**

---

## 4. 各工作流的验证关口

### W1 `CYS-INF-037` 依赖方向门禁

```bash
bash scripts/lint/check-architecture.sh --self-test   # 必须先是「1 绿 + N 注入全红」
bash scripts/lint/lint-all.sh                         # 全绿（项数由 9 增至 10）
```

**反向注入（至少两条，必须实测）**：
1. 在 `lib.rs` 里加一句 `use crate::plugin_demo::Thing;`（假插件）→ **必须判红并点名文件与行**。
2. 在两个「插件」模块之间加一条互调用 → **必须判红**。

**期望输出**：注入时退出码非零且打印**具体文件:行**；还原后全绿。
**「绿色的通过和绿色的没跑长得一样」**：若注入后仍然全绿，本项视为**未达成**。

### W2 `CYS-INF-038` 契约门禁自证与 CI

```bash
bash scripts/verify/check-attributes.sh --self-test
bash scripts/verify/check-channel-abi.sh --self-test
bash scripts/verify/check-channel-parity.sh --self-test
bash scripts/lint/lint-all.sh
```

**三道各自的反向注入**（针对各自的失效模式，不能只做一道）：

| 门禁 | 注入什么 | 期望 |
| --- | --- | --- |
| `check-attributes` | 改真源 `attributes.json` 而不重跑 codegen | 判红（「生成物过期」） |
| `check-channel-abi` | 只改生成物、不动真源 | 判红；另注入一条「有诊断码但无构造点」→ 判红（走 `check_reachability`） |
| `check-channel-parity` | 让 C++/Rust 一方的 dump 输出多一行 | 判红并 `diff -u` 摊开差异 |

**并把新门禁挂上 `ci.yml`**：验收 = 在 `.github/workflows/ci.yml` 里**能找到**这些 job 的名字。
（现状：`ci.yml` 只跑 `--cpp`/`--rust`/`--go` + `e2e-control-plane`，**parity/dpi/reassembly/flows/live/bench 都不跑**。）

### W3 `CYS-TRF-040` 插件清单真源与注册表

```bash
python3 tools/codegen/gen-plugins.py --check     # 幂等：不重跑则判红
bash scripts/verify/check-plugins.sh --self-test
```

**必须覆盖的四类非法清单**（每类都要有注入用例）：
缺字段 / 重名 / 未知 `kind` / `requires_host_abi` 与宿主不兼容。
**期望**：**启动即失败并点名条目**，不是跳过、不是 warning。

### W4 `CYS-TRF-048` 核心库/宿主切分

```bash
cd dataplane/traffic-engine && cargo test --workspace
bash scripts/test/test-all.sh --rust
bash scripts/verify/bench-pipeline.sh 888000 3    # 同机前后对比
```

**验收**：
1. **行为零变化**：`--workers N`（N>1）与单表输出**逐字节一致**（该断言已存在，不许放宽）。
2. **分层可检查**：核心库内不再出现「读环境变量 / 配置文件挑实现」的代码（由 W1 的门禁守）。
3. 触及每包路径 → 必须给**同机前后性能对比**（仓库硬规则：`HANDOFF.md` §5 第 11 条三件套）。

### W5 `CYS-DBT-021` 修上游重号

```bash
python3 docs/planning/scripts/check-deps.py       # 0 环、0 悬空引用
grep -rn "CYS-INF-035" docs/ | wc -l              # 语义唯一，不再有两种含义
```
纯文档，无门禁可挂；验收 = **同一编号在两份文档里含义唯一**。

---

## 5. 全批统一验收（Definition of Done）

在给出「本批完成」之前，以下每一条都要**跑过并留证据**：

| # | 判据 | 命令 |
| --- | --- | --- |
| 1 | lint 全绿且**项数增加**（新增门禁真的挂上了） | `bash scripts/lint/lint-all.sh` |
| 2 | 每道新门禁**都做过反向注入**且**都判红** | 见 §4 各条 |
| 3 | 新门禁在 `ci.yml` 上**可见** | `grep -n "check-architecture\|check-plugins" .github/workflows/ci.yml` |
| 4 | 行为零回归 | `bash scripts/test/test-all.sh --rust`（+ `--cpp`/`--go` 若触及） |
| 5 | 待办表状态已回写 | `CYS-INF-037/038`、`CYS-TRF-040/048`、`CYS-DBT-021` 置 ☑ 并写完成记录 |
| 6 | 数字口径一致 | `bash docs/planning/scripts/count-backlog.sh` |

---

## 6. 风险与注意事项（本批特有）

| 风险 | 说明与对冲 |
| --- | --- |
| **把「加了门禁」当成「门禁生效」** | 本批最可能的失败模式。对冲：§5 第 2/3 条**分开**判，注入红 + CI 可见，缺一不算完成 |
| **为通过测试而改真源** | W2 明令禁止改 `configs/registry/*.json`。若代码gen 与真源不一致，**改代码或改生成器，不改真源** |
| **`CYS-TRF-048` 顺手「优化」行为** | 本批是**纯重组**。任何行为变化都应拆到单独提交并给出性能对比 |
| **`.gitignore` 裸目录名吃源码** | 新增目录（尤其 `src/plugins/` 一类）后**立刻** `git check-ignore -v <path>`。仓库已因此丢过三处源码（`CYS-INF-035`），并已挂 `check-ignored-sources.sh` 兜底 |
| **计数/排除写裸 `*/target/*`** | 会把 `services/telemetryd/internal/target/` 这个**名字叫 target 的 Go 包**排除掉（实测少算 862 行）。排除路径必须锚定到具体目录 |
| **W3/W4 并行改 `lib.rs`** | 已按 §3 串行化。**不要为了并行而把清单逻辑塞进 `pipeline.rs`** |
| **插件清单过早膨胀** | 清单字段只加**会被门禁或宿主用到**的。现在没有的能力不要预留字段（否则就是「为插件而插件」） |

---

## 7. 变更记录

| 时间 | 变更 |
| --- | --- |
| 2026-10-05 | 建立本编排方案：确定 M10 第一批为 5 项 P0 地基工作；按 5 个工作流切分独占文件区域；W3→W4 串行、其余三路并行；每项给出可执行验证关口与反向注入要求；补「新门禁必须同时挂三处」原则 |
