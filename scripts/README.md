# scripts/ — 项目级脚本

> 构建 / 测试 / 质量关口的统一入口。根 `Makefile` 是薄转发层：`build` `test` `lint` `fmt` `clean` `ci`（`ci: lint build test`）全部转发到这里。

## build/

| 脚本 | 用途 |
| --- | --- |
| `build-all.sh` | 统一构建 C++/Rust/Go/前端四栈；工具链版本预检；失败栈数作为退出码 |

## test/

| 脚本 | 用途 |
| --- | --- |
| `test-all.sh` | 四栈测试 + 通道 ABI parity + 跨语言 e2e + 三道 tshark 核验 + 数据面基准（`--bench` 需显式开），逐栈汇总 |

## lint/ 与 fmt/

| 脚本 | 用途 |
| --- | --- |
| `lint-all.sh` | clang-format / cargo fmt / gofmt / eslint **只查不改**；CI `lint.yml` 直接调用 |
| `fmt-all.sh` | C++/Rust/Go 自动格式化修复 |

## release/

> **这两份脚本此前不在版本控制里**：`.gitignore` 曾写不带前导斜杠的 `release/`，
> 按 gitignore 规则会匹配**任意层级**名为 `release` 的目录，于是 `scripts/release/`
> 被整体忽略 —— README 与本目录都在引用它，`git status` 却看不见，全新克隆里没有它。
> 规则已改为 `/release/`。新增目录后请 `git check-ignore -v <path>` 自查。

| 脚本 | 用途 |
| --- | --- |
| `check-version.sh` | 校验版本单一真源：`Cargo.toml` 与 `package.json` 必须等于根 `VERSION`；`--self-test` 反向注入自证（临时最小仓库树 + 3 处不一致必须判红）。已挂在 `lint-all.sh` 第 6 条 |
| `check-version-bump.sh` | **产物级**验收：把根 `VERSION` 临时改成候选值并重建四端，要求四个产物各报该值、且 `check-version.sh` 在该状态下判红，随后自动复原真源。约 1~3 分钟，刻意不进默认门禁（发版前 / 改版本机制后手跑） |

## security/

| 脚本 | 用途 |
| --- | --- |
| `scan-secrets.sh` | 零依赖 grep 明文凭据扫描（CYS-SEC-003/006）；不打印密钥原文；兼容 BSD/GNU grep |

## verify/ — 语义关口（本项目质量体系核心）

| 脚本 | 用途 |
| --- | --- |
| `check-attributes.sh` | 属性字典四语言绑定 vs 真源一致性 |
| `check-channel-abi.sh` | 通道 ABI 生成物一致性 + 诊断码可达性 |
| `check-channel-parity.sh` | C++ `cythsec-dump-abi` 与 Rust `dump-abi` 输出逐行 diff（产物留 `build/parity/`） |
| `check-prometheus-format.py` | Python 独立重实现的 Prometheus 文本格式（0.0.4）严格校验器 |
| `check-dpi-vectors.sh` | **tshark 独立复核** DPI 向量（92 项：TLS/DNS/HTTP 字段）+ 32 个入库向量的**字节保真**比对与自证（挂 `test-all.sh --dpi`，默认全量门禁含该项；`--self-test` 可单独跑） |
| `check-reassembly-vectors.sh` | **tshark 独立复核** TCP 重组向量（挂 `--reassembly`） |
| `check-flow-records.sh` | **tshark 独立复核** FlowRecord（会话/计数/状态/应用）+ 17 项反向故障注入（挂 `--flows`） |
| `check-ipfix-export.sh` | **tshark 独立复核** IPFIX 导出（九类字段逐条 vs JSONL、IE 152/153 原始字节、报文头/序列号/模板可见性）+ UDP 通道字节比对 + 5 项产物级注入（挂 `--ipfix`） |
| `check-ipfix-collect.sh` | **采集回路**（导出→采集逐字段 9/9 相符）+ **导出丢包率可证伪**（删中间 datagram → `gaps=1 lost_records=2`，`loss_ppm` 独立手算一致）+ 无注入必须报 0 + 判定自身 6 项注入（挂 `--ipfix`） |
| `check-ipfix-interop.sh` + `interop-ipfix.py` | **异厂导出器互操作**（`CYS-TRF-054` ④ 的离线替代）：一个**只读 RFC 写出来的独立实现**（模板 ID 4001~4004、字段序相反、观测域 `0x1234ABCD`、计数器缩减长度编码、夹带未登记 IE、发模板撤回/重定义/options、先数据后模板、零填充）→ 我们的采集器逐条对手写常量；**tshark 再确认这份报文本身合法**（防"两个实现一起读错同一个非标格式"）；5 场景 + 判定自身 6 项反向注入（挂 `--ipfix`） |
| `check-estimate.sh` + `check-estimate.py` | **采样后的量级还原关口**（`CYS-TRF-053` ③）：1:4 的点估计对**总体真值**（未采样一次运行直接量总体）· 24 个种子的 95% 区间覆盖率 ≥20/24（**唯一能抓"点估计对、区间错"的判据**）· 混合采样间隔必须**拒绝给数**（退出 3）· 重放整批 datagram 估计值不变（去重生效）；3 项真实故障注入（线上 IE 34 两个方向被改坏 · 重放时 flowId 被改掉让去重失效）。共用 `synthpcap.py` 造语料与改线路字节。挂 `test-all.sh --sampling` |
| `check-sampling.sh` + `check-sampling.py` | **流级采样关口**（`CYS-TRF-053`）：`--sample 1:N` 是否**真的丢包**、`flow` 模式留下的流是否**完整**、IPFIX 的 `samplingInterval`(IE 34) 是否等于配置值（tshark 读线路）、`--workers` 是否一致、逐包模式包级是否精确；3 项**真实故障注入**（采样器没接上 / 逐包却自称 flow / 声明未落线）必须判红。挂 `test-all.sh --sampling` |
| `check-ignored-sources.sh` | 抓「被 `.gitignore` 静默吃掉、因而不在版本控制里」的源码/脚本（挂 `lint-all.sh`；本仓库靠它抓出了 `scripts/release/`、`scripts/build/`、`services/telemetryd/internal/target/` 三处） |
| `check-flow-bench.sh` | 数据面基准（CYS-TRF-037）的**回归下限**门禁（**20 项**用例，含 `ipfix-collect-decode` —— 容量模型的"每台 N 记录/秒"出处）+ 4 项反向注入（阈值放大 / 报告模式不判定 / 参数校验 / **串行化扩展性**）；需求目标只报告（挂 `--bench`，**默认不在 ALL 里**：阈值带机器属性） |
| `e2e-control-plane.sh` | 四服务端到端验收：启动 routerd/policyd/dnsd/telemetryd → 探测端点 → 校验 metrics → jq 验证结构化日志 → 优雅关闭 |
| `e2e-shared-ring.sh` | 跨语言共享环 e2e（CYS-TRF-034）：C++ ring-feed 写 mmap → Rust ring-consume 读并聚合 FlowKey |

## plan/ — 容量与规划（可复算）

> 这一目录放的是"对外承诺依据"的算式。它们不是测试，但**算法会腐烂**（改一个系数、把 ceil 写成
> round，报告照样打印得出来），故都有手算期望值 + 反向注入，并挂进 `test-all.sh --plan`（纯 python3、秒级）。

| 脚本 | 用途 |
| --- | --- |
| `collector-capacity.py` | 采集集群容量模型（`CYS-INF-040`）：带宽 × 采样率 × 平均包长 → 记录/秒 → 采集器台数（每台容量取 `cythsec-bench ipfix-collect-decode` 实测值）→ 存储/天（**落盘字节/记录默认读实测产物**）；三档分解；**三个必带口径**（采样率 / 导出丢包率 / 采集覆盖率）；`--self-test` 手算期望值 + 3 项反向注入 + 算例 H（测量产物接线 + `trust-planning` 注入）；`--verify-defaults` 核对「内置默认值 ↔ 测量产物」是否一致（只改一处时"实测"就成了假话） |
| `measure-sampling-variance.py` | **采样估计量的经验方差实测**（`CYS-TRF-053` ③）：600 条流 × 200 个种子量留存条数 sd 与估计值波动，得到**设计效应 0.26**（sd 比 0.51）⇒ 产品报告的伯努利区间**偏保守**（实测覆盖 200/200）；产物 `docs/planning/measurements/sampling-variance.json`。含 2 项注入（没量就写理论值 / 只报前 10 个种子却写全量样本量） |
| `measure-storage.py` | **落盘字节/记录实测**（`CYS-INF-041`）：吃 `cythsec-analyze` 产出的真实 `FlowRecord` JSONL，给未压缩/gzip 两档字节数 + 字节去向诊断；`--combine` 把多次测量合成规划值（**两档各取较差端**，规则可被判死）；`--self-test` 手算字节数 + gzip 往返校验 + 5 项反向注入。产物见 `docs/planning/measurements/`（含样本量、gzip 工具版本与方法） |

## dev/

`clion.sh` 为共享 CLion 配置入口，复用真实构建与测试门禁；`monitor-local.sh` 提供本机四服务健康监测。
配置、端口、证据与停止方式见 [CLion 开发说明](../docs/development/clion.md)。

---

## 常用入口速查

```bash
make ci                  # lint + build + test（CI 等价物）
make build               # 四栈构建
make test                # 四栈测试 + parity + e2e
scripts/security/scan-secrets.sh    # 提交前自查
scripts/release/check-version.sh    # 版本一致性自查
```

## 相关

- 生成器与真源：`tools/README.md`、`configs/README.md`
- 构建产物去向：`build/README.md`
