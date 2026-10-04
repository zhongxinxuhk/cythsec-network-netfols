# CythSec 接力文档（HANDOFF）

> 状态点：`4d62530` · 2026-10-02（AEST）
> 上一检查点：`fb031ef`（DPI 批次）、`d3c2b3a`（远端 master 基线）
> 主待办表：`docs/planning/BACKLOG.md`（349 任务 / 9 里程碑）
> ⚠ **待办表的控制平面部分已滞后于代码**，直接照它做会重复劳动 —— 见 §1 顶部。
> 本文件回答一个具体问题：**下一棒接手时，哪些事必须知道，否则会踩重复的坑。**

**本文件的三条硬约束**（其余内容都是解释）：

1. §8 里标了「理由」的，理由比结论重要——**先读理由再决定是否推翻**。
2. §6 是**诚实清单**。往报告或演示里抹平它，等于把已知风险藏起来。
3. §4.2 的**反向注入**是新增门禁的必做动作。绿色的「通过」和绿色的「没跑」长得一样。

---

## 1. 三十秒版本

数据平面（C++ 收包 → 共享内存环 → Rust 分析）已打通往返链路；Rust 侧「流量分析」
已经走完**从「能识别」到「能产出记录」**这一段：单包识别 → 流表/会话 → 特征 → JSONL 记录。
链路是 `Packet → FlowTable → Session → FeatureExtractor → FlowRecord`。

| 能力 | 状态 | 落地位置 |
| --- | --- | --- |
| 深度包检测（TLS/JA3、DNS、HTTP） | ◐ 已落地（`CYS-TRF-020`/`023`→☑）：32 条向量 + tshark **92 项**三方互证；HTTP 响应侧与 DNS RCODE/EDNS0/应答地址已补齐 | `dataplane/traffic-engine/src/dpi/` |
| TCP 乱序重组 + TCP 选项解析 | ◐ 已落地，三方互证通过 | `dataplane/traffic-engine/src/reassembly/` |
| 流表 / 超时 / 逐出 / 回调 + TCP 状态机 + 会话管理 | ☑ 已落地（CYS-TRF-006→◐ / 007→◐ / 008/009/010/011/012→☑） | `dataplane/traffic-engine/src/{flow,session,tcp}/` |
| 特征提取 + FlowRecord + 离线 pcap CLI | ☑ 已落地（CYS-TRF-004/005/014/027/033/035） | `src/{feature,record,pipeline,bin/analyze}.rs` |
| 真实网卡抓包（Linux AF_PACKET / macOS BPF） | **Linux 侧真抓包已验收（2026-10-05，见 §2.7）**：2 vCPU Rocky Linux 10.2 aarch64 测试机、真实网卡 `enp2s0`、13/13 断言（74 包 / tshark 74 帧一致 / 环 74=74 / 10 条 Flow）；macOS BPF 侧仍受 `/dev/bpf*` 权限阻塞（e2e 内显式 `SKIPPED`，不显绿） | `dataplane/packet-engine/src/backends/` |
| 数据面基准（吞吐/内存 + 多实例扩展 + 反向注入门禁） | ☑ 19 项 · 回归下限全过 · 需求目标 11~14/19（差距已列明）· **多实例分核实验已定路线：4 核/10G 口** | `src/bin/bench.rs` + `scripts/verify/check-flow-bench.sh` |
| 跨语言共享环端到端 | ☑ 19 项断言通过 | `scripts/verify/e2e-shared-ring.sh` |
| 控制平面（Go 四服务） | ◐ 引擎内核已落地（约 9000 行源码 / 7000 行测试），**但待办表未同步** | `services/` |

> ⚠ **接手前必读的一条偏差**：`docs/planning/BACKLOG.md` 的**控制平面部分已明显滞后于代码**。
> 待办表把 `CYS-POL-001`（policyd 骨架）、`CYS-DNS-001`、`CYS-TEL-001`、整个 M4
> 里程碑都标着「⬜ 未开始」，但仓库里这些服务**已经存在且测试全过**（19 个 Go 测试包）。
> 成因已定位：这些实现由**并行协作者**在 `9748175` / `8e0fb03`（2026-09-14，16661 行）
> 落库，而那批提交**没有回写待办表**。
> **照 BACKLOG 去「落地 policyd 骨架」= 重复劳动。** 做控制平面前先读代码
> （见 §3），真实缺口见 §8。

**门禁实测状态**（2026-10-04 逐项复跑）：

| 门禁 | 结果 | 跑法 |
| --- | --- | --- |
| CTest | 6/6 通过 | `--cpp` |
| Rust 单测 | 331 项通过（312 lib + 8 基准 bin + 6 bin + 5 集成） | `--rust` |
| Go | 通过 | `--go` |
| 前端 vitest | 25 项通过（4 文件） | `cd web/console && npm test` ⚠ 见下 |
| 通道 ABI parity | 89 行一致 | `--parity`（须同时选 `--cpp --rust`） |
| DPI 的 tshark 核验 + 向量字节保真 | **92 项一致**（跳过 14 项，全部有理由；另比对 32 个入库向量与生成物逐字节一致） | `--dpi` |
| 重组的 tshark 核验 | 16 项一致（跳过 2 项已知例外） | `--reassembly` |
| 流记录的 tshark 核验 + 反向故障注入 | **927 项一致**（跳过 8 项，全部有理由；17 项注入全部被检出） | `--flows` |
| 跨语言 e2e | 4 阶段 / 19 项断言通过 | `--e2e`（须同时选 `--cpp --rust`） |
| 数据面基准回归门禁 + 反向故障注入 | 12 项回归下限全过；注入 3/3 检出；需求目标 4/12 | `--bench`（**默认不跑**，见 §4） |
| lint（格式 + 生成物一致性 + 版本真源 + 仓库完整性） | 9 项全过 | `scripts/lint/lint-all.sh` |

> ⚠ **本机唯一必红的一项**：`test-all.sh --node` 里的 `npm ci` 会被环境的
> `safe-delete` 钩子拦下（它要删 `node_modules/.bin`，7884 个目标 > 阈值 50），
> 脚本把它包装成「npm ci 失败（可能需要网络）」——**这个提示是误导，不是网络问题**。
> 前端代码本身是绿的：`cd web/console && npm test` → 25 项通过。
> 详见 §7.1。**除这一项外，其余各栈单独跑均全绿**（含不带参数跑时的其余部分）。

待办表状态（`count-backlog.sh`）：350 任务 / 9 里程碑 —— 未开始 297 · 进行中 12 · 已完成 41（M3 14/39）。

---

## 2. 本批做了什么（含「为什么这么做」，避免下一棒改回去）

### 2.1 DPI 深度包检测（`fb031ef`）

**动因是用户的一句话**：「pcap 这个流量一大就不行了」。实测证据：
`src/backends/pcap_file.cpp` 在 open 时把**整个文件**读进
`std::vector<PacketBuffer>` —— 非流式、无界内存、不报丢包，省网 100G 物理上走不通。
本轮补的是**识别能力**这一侧（真正的流式采集属另一个任务）。

新增 `src/dpi/`，核心是**三级递进识别框架**：
端口给候选顺序（成本 0）→ 载荷特征逐个确认 → 兜底 unknown。

**四个必须延续的设计决定：**

1. **裁决语义用四态枚举，刻意不用 `Result`**
   `Identified / NeedMore / Malformed / Unknown`。
   理由：「不是我的协议（Rejected）」与「我的协议解析坏了（Malformed）」
   在 `Result` 里都只是 `Err`，下游无法区分该**等分片**还是该**丢弃**——
   这正是省网 unknown 率虚高的主因（坏包被计入"再等等就能识别"的桶里，
   而它永远等不出结果）。框架层 `Malformed` 优先于 `NeedMore`。

2. **只看首包、不重组**（本层是纯函数）
   省网要在连接建立后几百微秒内出结果，等流拼完整 SLA 已过。
   代价是被切开的首包判 `NeedMore` —— 由重组层补（见 2.2），**不改解析器**。

3. **GREASE 必须剔除**（RFC 8701，`0x0a0a` 等 16 个值）
   否则 JA3 对同一客户端产出不同指纹，指纹库直接失效。数值段用**十进制**
   （`0x1301` → `4865`），空段留空（`771,,,,`）。

4. **零第三方依赖**：MD5 自实现（JA3 需要）。
   不是为了洁癖 —— 是为了保持「离线可构建、工具链可验证」。

### 2.2 TCP 乱序重组（`4d62530`）

**动因**：DPI 的 `NeedMore` 需要有价值，「补字节的人」就是这一层。

新增 `src/reassembly/`，五个文件各担一件事：

| 文件 | 职责 | 关键约束 |
| --- | --- | --- |
| `seq.rs` | 32 位序号回绕算术 | 10G 链路跑满约 **3.4 秒**就绕一圈——回绕不是边界情况而是必现 |
| `intervals.rs` | 有序区间集 | 三条不变式：按 start 严格递增 / 互不相交 / 互不相邻 |
| `stream.rs` | 单向流 | 内存上限按**保连续弃乱序**降级 |
| `tcp.rs` | 头与选项解析 | TLV 长度越界即**停止**解析，不"跳过继续" |
| `tests.rs` | 向量驱动断言 | 向量 `include_bytes!` 编进二进制 |

**四个必须延续的设计决定：**

1. **重叠仲裁默认 `KeepOld`（Linux `tcp_trim_head` 语义）**
   含义是「流的内容一旦定下就不再被后续报文改写」。旁路设备要复现的是
   **接收端真实收到的字节流**，而不是攻击者最后重发的那个版本。
   代码里同时提供 `KeepNew`（BSD），因为两种语义真实存在且**行为相反**，
   必须显式选择而不是隐式固定。

2. **`anchored_by_syn` 标志必须保留**
   抓到 SYN 才锚 ISN+1；旁路中途接入时以首个数据段锚定，此时该标志为 `false`。
   用途是让下游能看见「这条流的开头完整性未知」——若抹掉这个区别，
   「开头不完整」会被静默当成「开头就是这个字节」。

3. **内存上限的降级方向是「保连续、弃乱序」**
   上限触发时，能推进连续前缀的段照收（马上会被交付并释放），
   只会加深空洞的段丢弃。这样即便在攻击流量下，DPI 依然能在流的开头拿到
   完整前缀并出结果——退化了但没瞎，比"整体停摆"有用得多。

4. **与 DPI 的衔接只有一处**：`Stream::identify_app()`
   把重组后的连续前缀喂给同一个纯函数 `dpi::identify`。
   若发现需要为重组改 DPI，说明分层串了。

### 2.3 顺带修掉的真实缺陷

| 缺陷 | 表现 | 根因 |
| --- | --- | --- |
| MD5 初值 B 写错 | 全部 JA3 指纹错误 | `0xEFCD89AB` 应为 `0xEFCDAB89`（**三个独立实现都错在同一处**，靠移植到 Python 与 `hashlib` 逐步比对才定位） |
| MD5 摘要字节序反 | 32 字符、外观合法、每两字符都反 | 应逐 u32 按小端字节输出 |
| MD5 第 3 轮 G 表抄错 | 摘要全错 | 正确为 `5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2` |
| TLS 握手长度位置错 | 得出荒谬的 `0x010000` | 是 **3 字节**且从**偏移 6** 起（不是 2 字节从偏移 5） |
| `Cursor` 起始偏移漏 9 | 每个字段都错位 | 握手体起点偏移 9 |
| 扩展体长度头被当列表元素 | JA3 里多出来路不明的小数字 | SNI / `supported_groups` 有 2 字节长度头；`supported_versions` 是 **1 字节** |
| 生成器畸形样本其实合法 | 测的是空气 | `tls-bad-inner-len` 偏移漏算 4 字节握手头，改坏的是 random |
| SACK 选项长度算成 `8n` | SACK 块解析不出 | 应为 `8n+2`（含 kind 与 len 两字节） |

### 2.4 从「能识别」到「能产出记录」（本批）

链路补齐为 `Packet → FlowTable → Session → FeatureExtractor → FlowRecord`，
新增离线 CLI `cythsec-analyze -r x.pcap -o flows.jsonl`（CYS-TRF-035）。

**几个刻意定下来的语义，别改回去：**

1. **`fwd`/`rev` 是「规范端点序」，不是「发起方/响应方」。** 规范序保证同一会话
   无论方向都落到同一个键（CYS-TRF-005）；「谁是发起方」是**另一个**字段
   (`tcp.initiator`，取 SYN 的方向)。把两者混用，下游就会把「方向」当「角色」用。
2. **TCP 事件判定要吃「段载荷长度」，不是 IP 载荷长度。**
   `Packet::payload_len` 是 IP 载荷（含 20 字节 TCP 头），`TcpEvent::classify`
   要的是**去掉头之后的**字节数。本批修掉的真实缺陷就在这里：用含头长度判定，
   每个纯 ACK（IP 载荷 20、数据 0）都被算成 `Data`；容忍模式下碰巧仍能走到
   `Established`/`TimeWait`（**所以旧测试全绿**），严格模式下则卡在 `syn_received`
   且 `FinWait2`/`CloseWait`/`LastAck` 永不可达。修法是把两个量**显式分成两个参数**
   (`TcpObservation{flags, l4_payload_len}`)，而不是在调用处随手减 20 —— 后者下一个人
   一定会漏。
3. **`app.outcome = "not_inspected"` 不能并进 `"unknown"`。** 「没看」和「看了不认识」
   在统计上后果相反：前者是我们没覆盖，后者是流量本身不成形。
4. **熵在聚合直方图上算，`0` 有两种含义**（无字节 / 全部相同），用 `bytes` 列消歧。
5. **`schema_version` 随任何列变更抬版本**；`risk_score` 在 CYS-TRF-031 之前恒为 `null`
   （宁可留空，也不要先填一个假分数进存储）。

**新增的第三方门禁（`--flows`）**：`scripts/verify/check-flow-records.sh` 用 tshark
独立解析样本，逐流核对 **927 项**（会话集合 / 包数字节数 / 双向计数 / 方向切换 /
首末时间戳 / TCP 末态 / 发起方 / 中途接入 / 应用识别 / 解码失败计数 / 统计自证）。
两个关键设计：

- **TCP 末态用第二实现判定**：拿着 tshark 给的标志位序列，按规则表**重新推**一个末态，
  而不是去抄 Rust 的迁移表 —— 抄表等于让实现给自己打分。规则覆盖不到的组合打印
  `SKIP` 并**不计入通过**（当前 7 项，全部附理由）。
- **反向故障注入是默认行为**：17 项篡改（改包数、改状态、翻转发起方、改 tshark 事实、
  改自家 stderr 摘要、删/重复会话、空输入……）必须**全部被检出**，否则判红。
  理由见 §4.2：核验器自己写错时，「绿色的通过」和「绿色的没跑」完全一样。

**顺带修正一处过期期望**：`--e2e` 里硬编码「5 个报文」，新增
`datasets/pcap/sample-session-tcp.pcap`（18 帧）后如期报红（5 → 23）。
已改成可逐项复核的分解式（`4+1+18` 帧 / `4+1+9` 流 / 1 个非首片分片），
并把「这组数字是活的、改样本集必须同步改」写进注释 —— 期望值过期就该红，
不该顺手删掉那条断言。

---

### 2.5 数据面基准：先用需求推导出目标值，再量（本批）

`CYS-TRF-006/007` 此前卡在两条**指标**上（「1M 并发流插入基准达标」「无内存增长」）。
本批补上基准，但**没有**按原计划引 Criterion —— 本工程硬约定是零第三方依赖 +
`--offline` 可构建，基准工具不该是例外。代价写清楚：**只报点估计**（每项跑两遍、
取第二遍，两遍都打印），没有离群值剔除、置信区间与自动跨 commit 比对。

**`src/bin/bench.rs`（二进制 `cythsec-bench`）的四个设计决定**：

1. **目标值由工作量需求推导，不是"跑一遍记下来"**：
   10Gbps 最坏包速率 = `10e9 / (84×8)` = **14.88 Mpps**（84B = 64B 最小帧 + 7B 前导 +
   1B SFD + 12B 帧间隙；按 64B 算会得到 19.53 Mpps，那是自己给自己放宽要求）；
   1M 条超时扫描 ≤200ms（秒级节拍留 5 倍余量）；TCP 重组 ≥1.25 GB/s（10Gbps 净载荷）；
   **新建流速率单独算**：1M 容量 / 60s 瞬态超时 ≈ 17k 次/s，取 1 Mops/s 作 60 倍余量 ——
   拿包速率（14.88 Mpps）去要求"插入新流"是口径错误，会把正常的东西判成不合格。
2. **两类阈值分开**（本批最重要的设计）：`需求目标`回答"够不够用"，`回归下限`回答
   "这版有没有把上一版跑坏"。默认退出码只看后者，`--require-targets` 才按目标判定。
   混成一个码，人会分不清该修哪个；而且当前有 8 项未达目标，若它们都让门禁变红，
   门禁会天天红，红到没人看。
3. **回归下限余量刻意留大（≥2×）**：实测同机连跑两次，稳态查表类能差 20~30%
   （散热 / 其它负载 / 内存布局）。5% 余量的门禁只会变成随机假红，而随机红等于没有门禁。
4. **判定逻辑只有一处**（`Case::passed/regressed`）：表格显示、汇总行、退出码都调它，
   避免"表格说达标、退出码按另一套规则算"这种最隐蔽的自相矛盾。

**首轮就抓出三处，其中一处当场修掉**：

| # | 发现 | 证据 | 处置 |
| --- | --- | --- | --- |
| 1 | `expire()` 把全部到期条目搬进 `Vec<FlowEntry>`（每条 432B）排序后派发 | 250k 条「填满→全到期」每轮 RSS **+99MiB** 且不保证回落（逻辑活跃条目恒为 0）；对照实验（只 insert+drop / insert+`clear()`）RSS 平稳，`HashMap` 自身 churn 也平稳，故不是分配器通病 | **已修**：只收**键**（40B/条），按全局键序逐条删除并派发。回调顺序（全局按键升序）与逐出语义不变；RSS +99→**+6MiB/轮**，扫描 **1.62→2.50M 条/s**。唯一可观察差异：回调期间表里可能仍留有尚未派发的到期条目（旧实现先删完再派发）—— 已在源码注明并接受，补 2 个测试钉住 |
| 2 | `evict_lru` 每次逐出**全扫分片**，成本 O(每分片容量) | 每片容量 256 → **1.09µs/次**；8192 → **52.2µs/次**；容量 32× → 耗时 52× | **已修（2026-10-04 第二段）**：分片内改用**槽位数组 + 双向链表**维护活动序（插入挂尾、命中移尾、逐出摘头），语义仍是**精确 LRU**、仍确定性，代价 O(1)：256 → **0.21µs/次**、8192 → **0.34µs/次**，容量 32× → 耗时 **1.6~1.8×**。旧路径保留为 `EvictPolicy::LruScan` 作对照，并新增 `stats().evict_candidates`（链表策略恒 0、扫描策略 = 每片容量 × 逐出次数）把复杂度变成**可测断言**。**先评估并实测否掉了采样 LRU**：Redis 式 K=8 采样在「400 流 / 128 槽位 / 90% 热点」负载上热点命中率只有 **58.4%**，精确 LRU 是 **99.9%** —— 流被逐出又重建意味着同一条会话的记录被切成两段，这个代价换不来那点 CPU |
| 3 | 稳态查表够不上 10G 最坏情况 | update **5.6~8.6** / query-hit **5.0~6.9** / query-miss **13.8** Mops/s，需求 14.88（达成 34~58%）；每流实测 **0.97KB**（槽位 448B + 键表约 50B + IAT 环形 512B） | **已定位并选定路线**（2026-10-04 第三段，见 **§2.6**）：多实例分核实测 **2 核压线、4 核留 1.5~1.8 倍余量** → 核预算 **4 核/10G 口**；热/冷字段拆分**暂不做**（触发条件写在 §2.6）。**连带发现**：`FlowTable` 原先不是 `Send`（观察者 `Box<dyn FlowObserver>` + 测试用 `Rc`），"每核一张表搬进 worker 线程"根本无法表达 —— 已改为 `Box<dyn FlowObserver + Send>` 并加编译期断言。**本批的副作用**：O(1) LRU 让插入快一倍（0.98→2.06 Mops/s）、逐出快 5~150 倍、单表内存减半（2390→970 B/条，全新进程同配置实测），代价是命中路径多一次间接寻址 —— query-hit 7.68→5.02 Mops/s（−35%），update 在噪声内（5.71→5.59） |

**顺带修正两处我自己上一批写错的事实**：分片容器写成 `BTreeMap`（实为
`HashMap` + FNV-1a，确定性顺序来自显式排序）；`FlowStats` 包长直方图写成"256 桶"
（实为 **12 个 log2 桶**；256 桶是 `feature::ENTROPY_BINS`，两者不是同一个东西）。

**第二段（2026-10-04 收口批次）还改掉了一处**判据本身**的错误**：`table-steady-memory`
原先拿「填充后 → 灌完 5× 容量」作差。条目内嵌的 IAT 环形缓冲是 512B/条，填充时每条只写过
第一个元素，剩下 63 个槽位的**页**要等后续包才被触碰 —— 第 1 轮的 RSS 会一次性抬高一个与
容量成正比的量（1M 条时 **+206MiB**），第 2 轮起完全平；那是"页第一次被触碰"，不是"内存随
流量增长"。旧写法把这个一次性项算成增长，判据本身是错的（旧实现凑巧为 0，只因它前面的用例
刚好触碰过同尺寸的页）。现在**预热一轮不计入判定**、逐轮记录 RSS、取"预热后各轮增量最大值"，
并整条打印原始序列（含预热轮，不藏）。修正后两版都判 0.00 MiB。

### 2.6 稳态吞吐与 10G 的差距：先量再决定（2026-10-04 第三段）

`CYS-TRF-006` 卡在「每包路径吞吐只有 14.88 Mpps 需求的 34~38%」。HANDOFF §8 第一梯队第 1 项
的要求是：**先做便宜实验（每核一张独立表，证明近线性扩展），再决定走「多实例分核」还是
「条目拆热/冷字段」—— 不要在没有数据的情况下重构流表**。

**实验**（`cythsec-bench` 新增 6 个判据项，细节见 `bin/bench.rs` 头部「多实例分核实验」）：
N 张**完全独立**的 `FlowTable` 各占一个线程跑稳态 update；外加两条对照 ——
**纯计算对照**（同线程数、同操作次数，只做寄存器运算）用来量出「**这台机器本身**的多线程
上限」，**小工作集对照**（每实例 2000 条 ≈ 3MB，能进每核 L2）把「访存/工作集」这个因素单独
拎出来。

实测（Apple M1 Pro / 10 逻辑核 / release / 每实例 12.5 万条 / 多次运行）：

| 线程数 | 聚合吞吐 | 每线程 | 扩展效率 |
| --- | --- | --- | --- |
| 1 | 6.9~8.6 Mops/s | 6.9~8.6 | 1.00 |
| 2 | 13.4~15.3 | 6.7~7.6 | 0.82~0.96 |
| 4 | 22.6~26.2 | 5.6~6.5 | 0.71~0.95 |
| 8 | 28.0~34.8 | 3.5~4.4 | 0.42~0.63 |

**决定：走「每核一张独立表」（多实例分核），热/冷字段拆分暂不做。**

- **2 核压线达标，4 核留 1.5~1.8 倍余量** → 核预算 = **4 核/10G 口**
  （判据项 `table-cores-for-10g`：取「最小档位使聚合 ≥1.5×14.88Mpps」，1.5× 是留给同核上
  其它环节的工程余量）。
- **8 线程不再近线性，但不是表内的共享瓶颈**：同一台机器上的纯计算对照也只有 0.54~0.73；
  小工作集对照的每线程吞吐比大工作集高 34~67%，但仍只有它自己单线程的 0.4~0.5 倍。
  即**机器级并发上限是主因、访存是次要因素**。判据因此用**比值**（流表扩展效率 ÷ 纯计算
  对照扩展效率）：实测 0.55~0.92，目标 0.5（要求「同量级」，判据要拦的是塌到 0.1 量级的
  共享瓶颈）、下限 0.25；串行注入档实测 0.06~0.10，判红。
- **热/冷字段拆分不作当前路线**：核预算（4）远小于常见机型核数，拆条目是「省核」才需要的
  优化，却要动条目内存布局、分片、超时与回调一整套。**触发条件**：目标机型核预算 < 所需
  核数，或单表规模再涨一个数量级、cache miss 成为主导。
- **前提是顺带发现的**：`FlowTable` 原先**不是 `Send`**（观察者是 `Box<dyn FlowObserver>`，
  测试实现还用 `Rc`）—— 「每核一张表 + 把表搬进 worker 线程」这条路**根本无法表达**
  （bench 直接编译失败）。已改为 `Box<dyn FlowObserver + Send>`（只要 `Send`、**不要**
  `Sync`：表不需要被多线程共享引用，「共享一张表 + 加锁」恰是要避免的形态），并加编译期断言
  `table_is_send_so_it_can_move_to_a_worker_thread` 守住。

**本实验不回答的**：整条每包流水线的核预算 —— 特征更新、会话归属等环节各有自己的
14.88 Mpps 目标（实测 4~7 Mops/s），要各自核算之后才能给出一个 10G 口的**总**核预算。

**反向注入（判据的判据）**：`--inject-serialized-scaling` 把并行档换成「所有线程抢一张表 +
互斥锁」，要求扩展性判据判出退步并退出非零。单测 `serialized_table_is_flagged_as_not_scaling`
（真表真锁、真线程）与门禁 `check-flow-bench.sh` 的第 4 项注入都跑它 ——
**一个只会说「扩展性良好」的判据等于没有判据**。

---

### 2.7 换机器验证：Linux aarch64 测试机（2026-10-05）

**为什么做**：此前所有验证都只在 macOS/M1 Pro 上跑过。仓库宣称支持的发行版里有
Rocky Linux，而「本机全绿 ≠ 别的机器能构建/能过」是 §7 第 7 条已经吃过一次的亏。
本批把开发机（VMware Fusion 上的 Rocky Linux 10.2 aarch64 虚拟机，2 vCPU / 3 GB /
4 KiB 页）接进回路，用它当**第二台机器**。（机器信息与接入方式见
`.workbuddy/memory/MEMORY.md` 的「测试环境」；凭据不入仓库。）

**做法**：`git archive HEAD` 同步源码（**不用** `tar --exclude`，见 §7 第 9 条），
装上与本机**逐位相同**的 `rustc 1.97.1`（+ gcc 14.3.1 / tshark 4.4.2）后跑同一套脚本。

**结果（全部通过）**：

| 关口 | 结果 |
| --- | --- |
| `test-all.sh --rust` | **337 项全过**，与本机计数一致 |
| `test-all.sh --cpp` | **6/6 通过** |
| `test-all.sh --live` | **13/13 断言**（该关口此后加了「裁判口径自证」，现为 **14 项**）：真实网卡 `enp2s0` 采集 74 包、`tshark` 复核帧数 74 = 落盘数、环内消费 74 = 灌入数、解出 10 条 Flow、Rust `decode_fail` 与 tshark 前缀非 IP 帧数同为 0（三实现判定一致） |
| `cythsec-bench --flows 200000 --rounds 2 --report-only` | 1 线程 6.73 / 2 线程 7.41 / 4 线程 12.85 / 8 线程 13.20 Mops/s；**比值判据 `table-scaling-vs-ceiling` = 0.94 仍成立**（该机核数不足，比值口径正是为此设计的）；按单核折算 10G 口需 3 核，含工程余量取实测档位外推 **14 核** > `ap=2` → 该机**跑不满 10G**（机器属性，不是代码问题） |

**换机器才暴露的 3 处「把本机/平台假设当成普遍事实」（全部已修 + 已加自证）**：

1. **`test-all.sh` 的工具链预检不看选了哪些分组** —— `--rust` 也要求 cmake/go/node，
   在只有 cargo 的机器上直接报「工具链缺失: cmake」而**本次运行根本不需要它**
   （在虚拟机上是实测撞到的：先卡 cmake，装完 cmake 又卡 go）。改为按所选分组取工具链
   （纯函数 `required_tools()`，便于自证），并在 `--self-test` 里加**反向注入**：
   PATH 中没有 cmake 时 `--rust` 必须通过、`--cpp` 必须点名判红。
2. **`bench.rs` 的串行档断言带机器属性** —— `serialized_table_is_flagged_as_not_scaling`
   断言「串行效率 < 回归下限 0.25」，10 核实测 0.05~0.10 成立，**2 核上是 0.33**（核太少，
   表达不出抢锁），于是这条判据自己变成假红。改为机器无关形态：**永远**断言
   `串行效率 < 并行效率`；只有 `ap ≥ 4` 才断言比值低于下限；另加与核数无关的兜底
   （串行档**顶档聚合**必须低于该档下限 —— 共享锁的特征就是"多核也上不去"）。
   两机复验：10 核 13/13、2 核 13/13。
3. **C++ 实时采集测试里写死了两处平台常量** —— ① 用 `0xFFFF` 当「未知链路类型」：
   macOS 上确实未知，**Linux 上它是具名的 `ARPHRD_VOID`**（相邻 `0xFFFE` = `ARPHRD_NONE`），
   于是实现照实返回 `VOID`、断言判红；改用 `0x10000`（超出 16 位 `ARPHRD_*`/`DLT_` 空间），
   且期望的十六进制回显**由常量算出**。② `kNoSuchIface` 是 32 字符，而 `IF_NAMESIZE`=16，
   Linux 的 `open()` 会**先命中「接口名过长」分支**，报的不是「不存在」，于是
   「诊断必须给出可操作线索」这条断言在 aarch64 上红；改用短名（"超长名字不崩溃"本就有专门用例）。
   两机复验：macOS 6/6、Linux 6/6。

**这三条都不是「Linux 有 bug」，而是测试里写死的机器/平台假设** —— 换一台机器跑一次全暴露，
且**全都是假红**（把机器属性报成代码缺陷），正是本仓库最反对的那类红。教训与本仓库一贯口径一致：
**阈值与常量一旦带平台或机器属性，判据要么改成相对量，要么显式限定适用条件。**

**顺带修掉一处默认门禁的潜伏假红（同样是换环境才暴露）**：`--live` 的 D 项断言「Rust 的 `decode_fail` == tshark 判定的前缀非 IP 帧数」原先用 `tshark -e eth.type` 取数，而**网桥周期发的 STP BPDU 是 802.3 + LLC 帧**（`eth:llc:stp`，用长度字段而非 EtherType）→ `eth.type` 输出空行 → 旧写法 `awk 'NF {...}'` 把空行**整行丢掉** → 裁判少数 6 帧，把「两个实现一致判 6、裁判判 0」报成不一致。**只要网络里有交换机在发 STP，这道默认门禁就会长期假红**（本机 en0 上实测 6 帧；此前各批「13 项全过」只是因为抓包窗口里恰好没有 LLC 帧，虚拟机那次是 0==0 空过）。修法：裁判改用 `frame.protocols`（协议栈里没有 ip/ipv6 即非 IP，与解析器口径一致且对任何封装都成立，抽成 `nonip_count()` 并写明为什么不用 `eth.type`），不一致时把三方计数与错误码明细一起摊开便于归因。修后本机 8==8、虚拟机 0==0。并且**把这条口径做成每次都会跑的自证**：合成一个「1 帧 LLC/STP + 1 帧 IPv4」的两帧 pcap，断言裁判只数出 1 帧非 IP（旧口径在此立刻红：0 != 1，已用反向注入实测确认），python3/tshark 缺席时显式打印「未核验（不计为通过）」。这道关口因此从 13 项变为 **14 项断言**。

**能力边界（诚实）**：该机 2 vCPU，**吞吐类结论不可用**（`--bench` 只 `--report-only`，
照门禁阈值跑会红 —— 阈值是机器相对的，不得据其判红）；页大小是 **4 KiB**
（`CONFIG_ARM64_4K_PAGES=y`），与 macOS 的 16 KiB 不同、对 `af_packet.h` 的 PAGE_SIZE
运行时假设仍有覆盖价值，但**「64 KiB 页路径」至今没有覆盖环境**（早前文档把它写成 64 KiB 是错的，已改）。

---

## 3. 代码地图

```
dataplane/
  packet-engine/          C/C++17 采集与解析
    include/packet_engine/
      backends/           后端接口与 iface_list
      channel/            共享环区域（C++ 侧实现）
    src/backends/         pcap_file / af_packet / bpf_capture / iface_list
    src/channel/          region（mmap）/ producer（SPSC）
    cli/                  cythsec-parse / cythsec-capture / cythsec-ring-feed / cythsec-dump-abi
    tests/                packet / parser / pcap / channel_abi / channel_producer / live_capture
  traffic-engine/         Rust 分析
    src/channel/          共享环消费端（region / consumer / decode / abi_gen）
    src/dpi/              tls / dns / http / attributes / types / md5（+ tests）
    src/reassembly/       seq / intervals / stream / tcp（+ tests）
    src/flow/             ★ 本批：五元组 + canonical() / 分片流表（超时·LRU 逐出·回调）/ FlowStats
    src/session/          ★ 本批：会话管理器（双向聚合 / 反向键规范化 / 超时销毁）+ 会话 id 复用池
    src/tcp/              ★ 本批：TCP 状态机（严格 / 容忍双模式）+ TcpObservation
    src/feature/          ★ 本批：21 维特征提取（包长/IAT/速率/上下行比/方向切换/载荷熵）
    src/record/           ★ 本批：FlowRecord（schema_version=1，JSONL 写出）
    src/pipeline.rs       ★ 本批：pcap → 记录 的库函数（CLI 与测试共用，防两边各错一半）
    src/pcapfile.rs       ★ 本批：零依赖 pcap 读取（含字节序与截断包判定）
    src/attributes_gen.rs 由 configs/registry/attributes.json 生成
    src/testjson.rs       测试共用最小 JSON 解析器
    src/bin/              dump_abi / ring_consume / analyze（cythsec-analyze）/ ★ 本批：bench（cythsec-bench）
    tests/pipeline_sample.rs ★ 本批：用手写期望值锁定 5 个会话的记录内容

configs/registry/         ★ 真源：attributes.json / channel-abi.json
tools/codegen/            真源 → 四语言绑定生成器
datasets/                 测试向量（pcap 与 expected.json 是生成物，不入库）
scripts/verify/           check-attributes / check-channel-abi / check-channel-parity /
                          check-dpi-vectors / check-reassembly-vectors /
                          check-flow-records（.sh 采集 + .py 比对，自带反向故障注入）/
                          check-flow-bench（数据面基准回归门禁 + 3 项反向注入）/
                          e2e-shared-ring / e2e-control-plane

services/                 Go 控制平面（约 9000 行源码 / 7000 行测试，19 个测试包全过）
  pkg/                    共享库：attributes(生成) / controlplane / httpx / logging /
                          metrics / configutil / versioninfo
  routerd/                网卡与路由信息只读 API（netinfo: interfaces/routes/system/traffic）
  policyd/                ★ 策略引擎内核（见下），4362 行源码
  dnsd/                   DNS 策略服务（zone / load / api / config）
  telemetryd/             遥测监控（target / load / store / api / config）

web/console/              React 控制台（5 页：Dashboard / Interfaces / Routes / System / Traffic）
```

**`policyd/internal/ruleir/` 是控制平面里最厚的一块**，做前必须先读懂它的设计意图：

| 文件 | 内容 |
| --- | --- |
| `ir.go` | 规则中间表示（已归一化） |
| `compile.go` | 源规则 → IR 编译 |
| `match.go` | 条件匹配（1118 行，最厚） |
| `evaluate.go` | 判定求值引擎：**allow 优先**、条件级 Trace 可解释 |
| `store.go` / `action.go` | 内存索引与动作模型 |
| `api/rules.go` | HTTP API（含试算） |

**已做 / 未做的分界**（决定下一棒从哪里接）：引擎内核（解析、编译、匹配、求值、
API、内存存储、测试）**已做**；**落地侧全未做**——nftables 下发、原子生效与回滚、
PostgreSQL 持久化、策略版本化、命中统计、审计日志、服务间联动
（搜 `nftables` / `pgx` / `audit` 在 `services/policyd/` 下零命中，可自行复核）。

**核心体系（全仓贯穿）**：真源 JSON → codegen 四语言绑定 → verify 脚本关口。
任何一层的常量都不允许在任何语言里手写字面量。

---

## 4. 验证体系：怎么跑，每道关口拦什么

```bash
bash scripts/test/test-all.sh            # 全部（含向量自动生成）
bash scripts/test/test-all.sh --rust --dpi --reassembly --flows   # 日常快速回路
bash scripts/lint/lint-all.sh            # 八项：格式 / 生成物一致性 / 版本真源 + 检查器自证
```

| 开关 | 拦什么 | 当前结果 |
| --- | --- | --- |
| `--cpp` | C++ 单元与集成（ctest） | 6/6 通过 |
| `--rust` | Rust 全部单测 | 320 项通过（301 lib + 8 基准 + 6 bin + 5 集成） |
| `--go` | Go 控制面测试 | 通过 |
| `--node` | 前端 vitest（`npm ci` + `npm test`） | 测试 25 项通过，但 `npm ci` 被环境拦 → 见 §7.1 |
| `--parity` | 通道 ABI 跨语言取值一致性（逐行 diff） | 89 行一致（需配 `--cpp --rust`） |
| `--dpi` | **tshark 独立复核** DPI 向量 + 入库字节保真 | **92 项一致**（跳过 14 项，全部有理由） |
| `--reassembly` | **tshark 独立复核** 重组向量 | 16 项一致（跳过 2 项已知例外） |
| `--flows` | **tshark 独立复核 FlowRecord**（会话/计数/状态/应用）+ 反向故障注入 | 927 项一致，跳过 8 项；17 项注入全部被检出 |
| `--e2e` | C++ 进程写 → 共享环 → Rust 进程读并解 Flow | 4 阶段 / 19 项通过（需配 `--cpp --rust`） |
| `--bench` | 数据面吞吐/内存的**回归下限** + 判定自身的反向注入 | 12 项回归下限全过、注入 3/3 检出（需求目标 4/12，只报告） |

**两条用法约束**（踩过：单独选会被脚本直接拒绝并 `exit 2`）：

- `--parity` 与 `--e2e` **必须与 `--cpp --rust` 同时选** —— 它们校验的对象是
  编译出来的两端产物/进程，缺一侧就无法成立。脚本拒绝是刻意的：
  *静默跳过会让人以为验过了*。
- 前端**类型检查不在这里**，在 `lint-all.sh` 里（静态检查不依赖运行时）。
  分开的理由：`test-all.sh` 需要真实构建产物，`lint-all.sh` 只看源码文本。
- `--bench` **刻意不在"全部"里**（`ALL` 集合不含它）：它的回归下限标定在特定机器上
  （Apple M1 Pro / macOS / 1M 条规模），换机器、换核数、开省电模式都会变。
  进默认集合只会变成"随机红的门禁"，而随机红等于没有门禁。换机器后先
  `--report-only` 看真实数字再重标定。

**lint 九项明细**：`[cpp] clang-format` · `[rust] cargo fmt` · `[go] gofmt` ·
`[codegen] 属性字典生成物一致性` · `[codegen] 通道 ABI 双端契约一致性` ·
`[version] 版本单一真源一致性`（这一项跑两步：真实校验 + 检查器自证）·
`[repo] 有没有源码被 .gitignore 静默忽略` ·
`[node] 前端类型检查（vue-tsc / tsc --noEmit）` · `[node] eslint`。

**`test-all.sh` 现在会先自动生成向量**（`gen_datasets`）。
理由：`datasets/**/*.pcap` 与 `*.json` 都在 `.gitignore` 里（字节级可复现，
不该占 diff），而 Rust 刻意用 `include_bytes!` 把向量**编进二进制**
（路径错 = 编译失败，而不是运行时静默什么都不测）——
所以全新克隆里缺文件是**硬失败**，必须有人补齐。

### 4.1 三方互证方法论（本项目最重要的方法论）

```
生成器（知道放了什么，自算期望值）
      ↓ 同一份 expected.json
Rust 实现（读期望值断言）
      ↕ 独立比对
tshark（第三方独立实现）
```

**为什么必须有第三方**：一致性本身证明不了正确性。只要生成器和实现犯**同一个**
理解错误（比如都把 GREASE 算进 JA3、都把握手长度当 2 字节），两边依然会完美一致。
tshark 是唯一能发现「一致地错」的手段。

**已知例外必须显式标注**，不能默认通过。目前共 3 条：

| 例外 | 原因 |
| --- | --- |
| `tls-ech-no-outer-sni` | tshark 4.6.7 的 ECH 解析器认不出手工构造的 ECH 体，会连整包 JA3 一起抑制 |
| `overlap-conflict` | 重叠仲裁策略与 tshark 不同且不可配置，两边期望值必然不同 |
| `memory-cap` | tshark 没有内存上限，会把被本实现丢弃的段也算进重组结果 |

三条都在 `expected.json` 里标 `tshark.verified=false` + 写明原因，
**并有测试守门**（`ech_vector_is_marked_as_not_tshark_verified`、
`known_exceptions_are_explicitly_marked`）防止被悄悄改回 `true`。

### 4.2 改动后必须做的反向注入验证

「检查通过」与「检查根本没跑」的输出都是绿色。因此**新增或修改门禁后**，
必须注入一个必然违规的输入确认它会报错，再恢复现场并做字节级比对。

本批三次注入的实际结果（都写进了提交信息）：

| 注入 | 结果 |
| --- | --- |
| 改坏 `expected.json` 的 sha256/len/memory_drops | ✓ 两道门禁双双报错（`exit=1`） |
| FIN 序号写成 `seq`（漏算载荷长度） | ✓ 2 项测试失败 |
| 把 `feed` 里「先数据后 FIN」对调 | ✗ **76 项测试全绿** |

第三次是**有价值的失败**：它证明了该顺序对最终状态实际无影响
（`on_fin` 只记序号，与插入互不干扰），于是把源码里那句
「顺序**必须**是先数据后 FIN」的夸大注释改成了真实约束
（真正敏感的是 FIN 的**序号**）。教训：注释里写的因果关系也要被验证。

---

## 5. 项目约定（必须延续）

1. **C++ 新增文件必须跑 `clang-format -i`**
   工具在 `/Library/Developer/CommandLineTools/usr/bin/clang-format`（**不在 PATH**）。
   历史事故：29/30 文件不合规却因检测不到工具而被静默跳过，
   本地绿灯、CI 必红。本轮又复发一次（新文件未格式化），已全仓修净。
   → **建议把 `clang-format -i` 变成保存钩子或 pre-commit**。

2. **shell 中变量引用一律用 `${VAR}` 花括号形式**
   macOS 自带 `bash 3.2.57` 会把紧跟 `$VAR` 后的多字节字符**并入变量名**，
   在 `set -u` 下直接 `unbound variable` 中断。历史 6 处事故 —— **本批又踩了第 6 次**
   （新写的 `check-flow-bench.sh` 里 `$ROUNDS）` 直接把右括号并进变量名）。
   新脚本一律先按 `\$([A-Za-z_][A-Za-z0-9_]*)` → `${...}` 批量加花括号，再 `bash -n` 验证。

3. **注释里声称「有脚本会拦下」的，该脚本必须真实存在、在版本控制里、并挂在门禁上**（三条缺一条都等于没有）
   历史事故：4 处注释这么写，而那个脚本**并不存在**。

4. **真源单一**：`configs/registry/*.json` 是唯一真源。
   四语言侧只允许**引用生成物**（`attributes_gen` / `abi_gen`），
   禁止手写 `"ATTR_..."` 之类字面量。

   **本批给出这条约定的三个真实反例**（同一天、同一条 ignore 规则家族）：
   `scripts/release/check-version.sh` 正确且存在，却 ① 没有任何门禁调用它，
   ② 它所在的 `scripts/release/` 被 `.gitignore` 的裸 `release/` 规则整个忽略、
   **从未入库**；③ 同一条规则家族还吞掉了 `scripts/build/build-all.sh`（四端构建入口）
   与 `services/telemetryd/internal/target/`（telemetryd 直接 import 的 Go 包，
   全新克隆里 `go build ./...` 直接失败）。
   「有检查器」和「检查器会跑」和「检查器在仓库里」是三件事，任何一件缺失，
   绿色的门禁都与「没检查」无法区分。现由 `[repo]` 那道 lint 专门守这一类（见 §7.7）。

5. **未识别 ≠ 识别为无**：SNI 为 `None` 时**不产出** `ATTR_TLS_SNI`，
   而不是产出一个空串属性。空串在下游会被当成「确实没有」，语义相反。

6. **测试向量必须编进二进制**，不许运行时读文件。运行读文件的话，
   路径写错或工作目录不对时测试会「安静地什么都测不到」——输出全绿，
   实际一条断言都没跑。这是本项目反复踩过的假绿灯。

7. **期望值手写，不许「跑一遍实现记下来」**。后者等于让被测实现给自己的
   答案打分，两边一起错的时候看不出来。

8. **性能门禁的阈值必须分成"需求目标"与"回归下限"两套**（见 §2.5）。
   需求目标由工作量需求推导（公式写在源码注释里），回归下限才允许是"本机实测"。
   把实测值当验收标准，等于用实现给自己打分；把需求目标当退出码，则会在差距
   还没排期时让门禁天天红。两者都不能省。

9. **报告与判定分离，且判定逻辑只有一处**。同一个判据被复制到"打印"和"退出码"
   两处，迟早会分叉成"表格说达标、脚本说失败"。基准的 `--report-only` 与
   `--require-targets` 就是这条约定的产物。

10. **量出来的问题，要么修，要么带数字进 §6**。基准首轮抓出三处，两批共修掉两处；
    剩下的一处（10G 吞吐）带着实测数字写进清单 —— 语义/架构级变更需要显式决策，
    不能藏在性能提交里。

11. **性能改造必须给出三样东西，缺一不可**：① 同机、同参数、背靠背的**前后对比**
    （不是各跑一次隔几天比）；② 复杂度的**可测证据**（本批是 `stats().evict_candidates`：
    链表策略必须恒为 0，扫描策略必须是"每片容量 × 逐出次数"，谁把 O(1) 改回 O(容量)
    测试立刻红）；③ 被否掉的方案也要带数字（采样 LRU 被 58.4% vs 99.9% 的热点命中率
    否掉，写进 `EvictPolicy` 的注释）。只有挂钟时间的前后对比会被负载漂移骗过去。

---

## 6. 已知未达成（诚实清单，不要在报告里抹平）

| 项 | 缺口 | 阻塞原因 |
| --- | --- | --- |
| `CYS-PKT-007` | macOS 真抓包未验收 | `/dev/bpf*` 属 `root:wheel 600`，本机无免密 sudo。e2e 中显式标 `SKIPPED`，**不显绿** |
| `CYS-PKT-008` | 「吞吐显著高于 pcap live」无实测对照数据 | 证据已升级（2026-10-05）：除三发行版容器内编译外，**真实主机 + 真实网卡**上 13/13 断言通过（Rocky 10.2 aarch64 虚机 `enp2s0`，见 §2.7）；仍缺的是**与 pcap live 的吞吐对照** |
| `CYS-TRF-019` | 「样本集准确率 ≥ 95%」无样本集 | 现有 **32 条**向量只证明**边界正确**，不构成准确率指标 |
| `CYS-TRF-016` | 双向 `Reassembler` / 超时 / 连接表驱逐未做 | 当前只有单向 `Stream` |
| `CYS-TRF-034` | 「真实网卡 → Flow」**Linux 侧已达成**（2026-10-05）：`enp2s0` 真抓 → pcap → 环 → Rust 解出 10 条 Flow，且 Rust `decode_fail` 与 tshark 判定一致 | **macOS 侧仍未达成**（受 `CYS-PKT-007` 的 `/dev/bpf*` 权限阻塞）；「真实 pcap → 环 → Flow」早已达成 |
| `CYS-TRF-001` | 未拆 cargo workspace | **刻意延后**，见 §2 顺序决策；模块边界已按 crate 语义划分好，将来是纯目录搬移 |
| ~~HTTP 的 UA/状态码/Content-Type 与响应侧~~ | **已做**（2026-10-04 第四段，`CYS-TRF-020`→☑）：请求侧 URI/UA/Content-Type + 响应侧状态码/原因/Content-Type；**未登记**：`Content-Length`（已解析但字典未登记该属性，按「只产出已登记属性」的硬约束不产出） | — |
| ~~DNS 的 RCODE/EDNS0 与 ANSWER 解析~~ | **已做**（2026-10-04 第四段，`CYS-TRF-023`→☑）：RCODE（仅响应）/QCLASS/应答地址集合/指针跳数/EDNS0 UDP 上限；**已知分歧**：`dns-negative-garbage` 上 tshark 报 rcode=15 而我们判「不是 DNS」（rcode>11），已在 `expected.json` 显式标注 `tshark.verified=false` | — |
| `CYS-TRF-006` | 1M 并发流**可容纳**（全新进程同配置实测 **0.97KB/条** → 约 1GB）且插入速率 **2.06 Mops/s** 已达"新建流速率"目标（1 Mops/s）。单实例每包路径 update 6.9~8.6 / query-hit 5.0~6.9 Mops/s = 需求的 46~58%；**多实例分核已验证可行（2 核压线、4 核留 1.5~1.8 倍余量，见 §2.6）**，但**流水线尚未接线**（bench 里是独立表实例，`analyze`/`ring-consume` 仍是单表） | **路线已定（§2.6），接线未做**：把「每 worker 一张表」接进实际消费路径（含 DPI/特征/会话的每线程私有化）是下一步；`CYS-TRF-010`（会话 id 分配器的跨线程语义）会一起被牵动。**未达成**：整条每包流水线的**总**核预算（特征/会话等环节各有 14.88 Mpps 目标，实测 4~7 Mops/s，需各自核算） |
| `CYS-TRF-007` | 定容 1M 条持续灌 6× 容量个包：**预热后逐轮 RSS 增量最大 0.00 MiB**（首轮 +206MiB 是页第一次被触碰，不计入，见 §2.5 末段）；全表到期 churn 的 RSS 增量已从 +99 降到 **+6~7 MiB/轮**（`expire()` 的 O(n) 临时数组已修）。**未达成**：小时级长稳曲线 —— 只跑到 12 轮，残余 +6MiB/轮来自分配器不归还小块（逻辑活跃条目恒为 0，非逻辑泄漏） | 需要小时级 soak 观测（本批为控制时长只跑到 12 轮）；这条不写"已达成"是刻意的 |
| ~~`evict_lru` 的 O(每分片容量)~~ | **已修**（见 §2.5 发现 2）：0.21µs@每片256 / 0.34µs@每片8192（需求 ≤500ns/次），容量 32× → 耗时 1.6~1.8× | 语义未变（精确 LRU），只剩一处**已文档化的可观察差异**：时间戳相同时旧实现按键序、新实现按"谁更晚被访问"（链表本身就是全序）。已在源码写明并用测试钉住 |
| `CYS-TRF-012`/`013` | 超时驱动的状态迁移与真实丢包环境参数标定未做 | 当前只有流级超时回收；没有真实丢包样本，就不给默认值之外的结论 |
| `CYS-TRF-010` | 多线程并发 id 分配未定义 | 分配器由 `SessionManager` 单线程持有；跨线程语义要先定锁边界 |
| `CYS-TRF-028` | 特征定义仍是「Rust 代码里一份」 | 与训练侧对齐（单一来源 + 双端生成）未做，Python 侧一旦手抄就会各自漂移 |
| `CYS-TRF-033` | 与 `storage/clickhouse` 建表 DDL 未对齐 | storage 侧尚未落地；现在只保证列名 + `schema_version` |
| `CYS-TRF-035` | 无真实省网 pcap 上的批量验证 | 现有样本是确定性生成的合成流量，只覆盖已知边界 |
| — | ~~`VERSION=9.9.9` 与 `Cargo.toml`/`package.json` 的 `0.1.0` 不一致~~ | **已修**（`64f4079` 定真源 `VERSION=0.1.0`，四端全部改为派生）。**本批补齐了"它不会再悄悄坏掉"这一步，而且挖出比"没人跑"更深的一层**：`scripts/release/check-version.sh` 此前**没有任何门禁调用它**（检查器存在但没人跑，等于没有；现已挂成 `lint-all.sh` 第 6 条），更糟的是**它自己从未入库** —— `.gitignore` 里不带前导斜杠的 `release/` 会匹配任意层级同名目录，把 `scripts/release/` 整个忽略了：`scripts/README.md` 与本文件都在引用它，`git status` 却看不见它，**全新克隆里根本没有这个文件**。已把规则改为 `/release/`（只忽略根目录打包输出）并让两份脚本入库；同类规则还吞掉了 `scripts/build/` 与 `services/telemetryd/internal/target/`（见 §7.7），一并修掉并加了 `[repo]` 门禁。挂门禁 + 加 `--self-test`（临时最小仓库树 + 注入 3 处不一致，要求分别判红并指出位置）+ `check-version-bump.sh`（真改真源重建四端）。四端已逐个**以产物级证据**复核：`cythsec-analyze --version` → `version=0.1.0`；`build/dataplane/packet-engine/hello_packet --version` → `version : 0.1.0`；`policyd -version` → `policyd 0.1.0 (commit …, go1.26.2 darwin/arm64)`；前端 `version.test.ts` 直接读根 `VERSION` 比对（经构建期 `define` 注入）。**踩到的坑**：`cmake-build-debug/` 是 IDE 的陈旧构建树（配置于 `VERSION=9.9.9` 时期），它的 `hello_packet --version` 仍打印 `9.9.9` —— 拿它验收会以为修复没生效，见 §7.6 |
| policyd 落地侧 | nftables 下发 / 原子生效与回滚 / PostgreSQL 持久化 / 策略版本化 / 命中统计 / 审计日志 / 服务间联动 **全部未做** | 引擎内核已就绪（§3），缺口在「把判定结果落到内核与库」这一段 |
| `dnsd` / `telemetryd` | 领域模型与 API 在，但与 policyd 的策略模型未统一、无真实后端 | 见 BACKLOG `CYS-DNS-014` / `CYS-TEL-010` 一类联动任务 |
| **待办表本身** | `BACKLOG.md` 的控制平面部分滞后于代码（见 §1 顶部提醒） | `8e0fb03` 等并行提交未回写状态；刷新时需**逐项对代码核实**，不要凭印象批量打勾 |
| 基准工具能力 | 只报点估计：无离群值剔除、无置信区间、无自动跨 commit 历史比对（人工比数字） | 刻意不引 Criterion（零第三方依赖硬约定），用两遍取第二遍 + 大余量下限替代；要统计显著性就得先解决依赖策略 |

---

## 7. 本机环境坑（踩过的，别再踩）

1. **批量删除保护会拦 `npm ci`，且报错信息误导**
   环境有 `safe-delete` 钩子：单轮删除 ≥50 个目标时拒绝并报
   `SAFE_DELETE_BULK_CONFIRM_REQUIRED`。`test-all.sh --node` 里的 `npm ci`
   要清掉整个 `node_modules/.bin`，实测 **7884 个目标**——必然中招，
   于是脚本打印 `✗ [node] npm ci 失败（可能需要网络）`。

   **这句话是误导**：不是网络问题，装包并不需要联网（依赖已缓存）。
   更糟的是它会让人去查网络、查 registry，而真正的原因在删除阶段。

   **已修（2026-10-04）**，三处改动：
   - `test_node()` 先看 `web/console/node_modules/.bin/vitest`：在位就直接 `npm test`，
     不在位才 `npm ci`（本机常态是前者，于是根本不会碰到删除阶段）。
   - 失败分类独立成函数 `classify_npm_ci_failure()`（stdin 吃 npm 输出 →
     `ENV_INTERCEPTED` / `REAL_FAILURE`）：含 `SAFE_DELETE_BULK_CONFIRM_REQUIRED`
     才报「环境拦截（不是网络问题）」，其余一律报「真失败」—— **不许拿环境当挡箭牌**。
     抽成函数是为了能自证：写在 `if` 里就只能靠"真的触发一次批量删除保护"来验证。
   - `test-all.sh --self-test`（挂在 `--node` 前自动跑）：用一个 stub `npm` +
     `CYTHSEC_FORCE_NPM_CI=1` 把**此前从未执行过**的那条分支真正跑一遍，4 个场景
     （分类×2、拦截、真失败、成功）必须全部符合预期。
   - 仍然可用的退路：只想验前端就 `cd web/console && npm test`；需要重装依赖就手动
     `npm ci --no-audit --no-fund`。**已被拦的 `npm ci` 不会破坏现场**：拦截发生在
     删除阶段之前，`node_modules/.bin` 实测 23 个文件完好。

   > 历史记录：早先 e2e 也曾在全量跑时报红，曾被一并归入此项。**2026-10-02 复测
   > 已不成立**：`bash scripts/test/test-all.sh --cpp --rust --e2e` → `全部通过 ✓`。
   > **2026-10-04 复测**：`bash scripts/test/test-all.sh --node` → 自证 4 场景 +
   > 前端 25 项全绿，`测试汇总：全部通过 ✓`。即全量门禁（含 `--node`）现在真的能全绿。

2. **`rm -rf` 与批量操作优先走回收站**，且逐批确认。

3. **`sed -i ''` 在 macOS 上易被误当成文件名**。改文件用编辑工具逐处改。

4. **三发行版容器验证必须在同一次 `docker run` 内完成安装与编译**，
   否则容器退出即丢失（apt/dnf 装的依赖随容器消失）。

5. **`datasets/` 下的 pcap 与 json 是生成物**（`.gitignore` 覆盖）。
   改动向量定义后要重新跑生成器，并把 `expected.json` 的变化与实现改动一起提交。

6. **陈旧构建树会让你以为修复没生效**。`cmake-build-debug/` 是 IDE 的离树缓存，
   配置于 `VERSION=9.9.9` 时期；里面的 `hello_packet --version` 至今打印 `9.9.9`，
   而源码与门禁用的 `build/` 树都是 `0.1.0`。**验收一律用 `build/`**（`test_cpp`
   每轮重新 `cmake -S . -B build` 并重建，正是为了避免「拿上一次的产物验当前源码」
   这种假绿）。同类坑：产物版本号是**构建期**烙进去的，改了 `VERSION` 必须重新构建
   才能看到变化 —— 看到旧版本号时先问一句「这个二进制是什么时候构建的」。

7. **`.gitignore` 里的裸目录名会吃掉同名的源码目录**（本批最贵的一课，一次踩出三处）。
   `build/` / `target/` / `release/` 这类**不带前导斜杠**的目录名，按 gitignore 规则匹配
   **任意层级**的同名目录，于是同名源码目录被整体忽略 —— 文件在磁盘上、执行权限正常、
   本地跑得通，但不在版本控制里，**全新克隆里没有它**，`git status` 也永远不提示：

   | 被吃掉的东西 | 后果 |
   | --- | --- |
   | `scripts/release/`（`check-version.sh`） | 版本自检脚本从未入库，README 与交接文档却在引用 |
   | `scripts/build/`（`build-all.sh`） | 四端统一构建入口从未入库 |
   | `services/telemetryd/internal/target/`（Go 包，4 文件） | telemetryd **直接 import** 它 → 全新克隆 `go build ./...` 直接失败 |

   规则已全部锚定到根（`/build/`、`/cmake-build-*/`、`/target/`、`/out/`、`/dist/`、`/release/`），
   三处文件已入库，并新增门禁 `scripts/verify/check-ignored-sources.sh`（`lint-all.sh`
   的 `[repo]` 一项）在**版本控制的事实**上守这一类回归 —— 它扫描
   `git ls-files --others --ignored --exclude-standard` 里的源码/脚本类文件，
   命中即报错并打印是哪条 ignore 规则吃掉了它。
   **新增目录后请立刻 `git check-ignore -v <path>`**；`git status --short` 看不见
   某个自己刚写的文件时，先怀疑 ignore 规则而不是编辑器。
   **更要紧的是「怎么发现的」**：三处都不是读代码看出来的，而是**在全新克隆里跑门禁**
   才暴露的（`check-version.sh` 报 `scripts/build/build-all.sh` 不存在、Go 编译报缺包）。
   本地全绿 ≠ 克隆能构建；发布/交接前请真的 clone 一次再跑。

8. **`core.autocrlf=input` 会把入库的二进制向量改掉行尾**（与第 7 条同属「磁盘上有 ≠ 版本控制里是那份」，
   但更难发现，因为这次文件**在**版本控制里，只是内容被悄悄改了）。
   本机 `core.autocrlf=input`（全局也是），`git add` 会把 HTTP 向量载荷里的 `\r\n`
   归一成 `\n` —— 而 `http.rs` 正是用 `\r\n\r\n` 判头部结束。实测表现：
   `git add datasets/dpi/payloads/http-response-200.bin` 打印
   `CRLF will be replaced by LF`，索引 blob 的 CRLF 计数变成 **0**，磁盘上仍是 **5**。
   修复：`.gitattributes` 声明 `datasets/**/*.bin -text`（向量载荷是不透明字节）+
   `git add --renormalize datasets/dpi/payloads/`。

   **两个反直觉点，别绕过去**：
   - **`git diff` 看不见这种损坏**。它比对的是"过了 clean 过滤之后"的内容，而行尾归一
     恰恰发生在过滤这一步，于是"索引 LF / 磁盘 CRLF"在它眼里毫无差别（实测 `git diff --quiet`
     报干净）。必须逐文件比对**未经过滤**的字节：`git ls-files -s` 的 blob 哈希 vs
     `git hash-object --no-filters`。
   - **`.gitattributes` 会被缓存在索引里**。把文件删掉后 `git check-attr` 仍报 `text: unset`，
     于是"去掉属性验证会不会复发"这种实验会得出**假的结论**（我第一轮就被它骗过一次）。
     要让改动生效需重写索引（如 `git rm --cached .gitattributes` 后再看 `check-attr`）。

   守门：`scripts/verify/check-dpi-vectors.sh` 的正常执行会先跑一遍**自证**
   （在临时仓库里真的制造一次行尾归一 → 断言能判红；加 `-text` → 断言判绿），
   再逐文件比对 32 个入库向量与生成物字节；`--self-test` 可单独跑。
   挂在 `test-all.sh --dpi`（默认全量门禁含该项）上。

9. **跨机同步代码：`tar --exclude` 会静默吃掉源码，`git archive` 才是对的**（2026-10-05）
   macOS 自带的 `tar` 是 bsdtar：`--exclude=./target` / `--exclude=./build` 匹配的是
   **任意层级**的同名目录，实测静默丢掉了 `scripts/build/build-all.sh` 与
   `services/telemetryd/internal/target/*.go`（共 5 个文件）—— 正是第 7 条那类
   「磁盘上有 ≠ 版本控制里有」，而且这次连目标机上都是缺的。正确姿势：

   ```bash
   git archive --format=tar HEAD | ssh <host> 'mkdir -p <dst> && tar -xf - -C <dst> --no-same-owner'
   COPYFILE_DISABLE=1 tar -cf - .git | ssh <host> 'tar -xf - -C <dst> --no-same-owner'
   ```

   另外三个坑：① 以 root 解包会保留 macOS 的 uid → git 报「可疑的所有权」，需
   `chown -R root:root`（或 `safe.directory`）；② 不加 `COPYFILE_DISABLE=1` 会带进
   AppleDouble `._*`，`.git/objects/pack/._*.idx` 会让 git 报 `index file ... is too small`；
   ③ bsdtar 的 `LIBARCHIVE.xattr.com.apple.provenance` 警告是噪声（`--no-xattrs` 或丢给 `/dev/null`）。
   **自证**：同步后目标机上 `git status --short` 必须 **0 行**。
   相关：**干净克隆里直接 `cargo test` 也会失败** —— `datasets/**/*.pcap|json` 是被
   `.gitignore` 忽略的生成物，而测试用 `include_bytes!/include_str!` 引用它们，
   必须走 `scripts/test/test-all.sh --rust`（会先生成向量）。

10. **测试里写死的「平台常识」换机器就是假红**（2026-10-05 一次抓到 3 处，详见 §2.7）
   - `0xFFFF` 当「未知链路类型」：Linux 上是具名的 `ARPHRD_VOID`（`0xFFFE` = `ARPHRD_NONE`）。
   - `kNoSuchIface` 用 32 字符：`IF_NAMESIZE`=16 → `open()` 先报「接口名过长」而非「不存在」。
   - 串行档断言「效率 < 下限 0.25」：2 核机器表达不出抢锁（实测 0.33）。
   **共同的修法**：取值/阈值不要凭"在 macOS/本机上看起来合理"来定 —— 要么改成相对量
   （比值、与核数无关的兜底），要么显式限定适用条件（`ap >= 4` 才断言），
   并把期望值由常量算出而不是抄一份字面量。**假红与假绿同样有害**：假红会让人干脆关掉门禁。

---

## 8. 下一棒建议顺序（含理由，可据实际情况调整）

### 第一梯队：把已落地的东西收口（低风险、高收益）

| 顺序 | 任务 | 理由 |
| --- | --- | --- |
| ~~1~~ | ~~**`evict_lru` 的 O(每分片容量)**~~ **已于 2026-10-04 第二段落地** | 结论与预期相反：**不需要语义决策** —— 分片内改成"槽位数组 + 双向链表"后仍是精确 LRU、仍确定性，逐出摘表头即 O(1)（0.21µs@256 / 0.34µs@8192）。而真正会改语义的**采样 LRU 被实测否掉**（热点命中率 58.4% vs 99.9%）。教训：先量再决定，别把"看起来最省事的近似"当成默认选项 |
| ~~1~~ | ~~**稳态吞吐与 10G 的差距**~~ **已于 2026-10-04 第三段落地**（见 §2.6） | 便宜实验做完了，结论比预期干脆：**2 核即压线、4 核留 1.5~1.8 倍余量 → 走"每核一张独立表"**，热/冷拆分不作当前路线（触发条件已写明）。8 线程不再近线性**不是表内共享瓶颈**（同机纯计算对照同样上不去），判据因此改成「相对纯计算对照的比值」。顺带发现 `FlowTable` 原先不是 `Send`，这条路本来**根本无法表达**。**剩下的**：把多实例接进实际消费路径 + 核算整条流水线的总核预算 |
| 2 | `CYS-PKT-007/008` 收尾：**Linux 侧已于 2026-10-05 验收**（真机真网卡 13/13，见 §2.7，`CYS-TRF-034` 的 Linux 侧随之达成）；**剩下**：① macOS 侧真抓包（需一次免密 sudo 现场，`/dev/bpf*`）；② `af_packet` 与 pcap live 的**吞吐对照**实测 | 吞吐对照是省网需求的核心论据；macOS 侧不解决则「两平台都验过」始终是半句真话 |
| ~~3~~ | ~~`VERSION` 不一致~~ **已落地**（`64f4079` 定真源 + 2026-10-04 挂进门禁 + 自证） | 真源 `VERSION=0.1.0`，四端全部派生；`check-version.sh` 成为 `lint-all.sh` 第 6 条并带 `--self-test`（3 处注入必须判红）。教训：**检查器不挂门禁等于没有检查器** —— 它当时已存在且能跑，但没有任何脚本调用它 |
| 4 | `CYS-TRF-020/023` 补全（HTTP 响应侧与 UA、DNS RCODE/EDNS0） | 已落地部分的自然延伸，向量体系现成，加样本成本低 |
| ~~5~~ | ~~修 `test_node()` 的 `npm ci` 拦截（见 §7.1）~~ **已落地**（2026-10-04） | 见 §7.1：改成"依赖在位就跳过 `npm ci`"，并把失败分类抽成可自证函数 + `--self-test` 4 场景（含此前从未执行过的拦截分支）。`--node` 现在全绿 |

> 建议把 `clang-format` 与 `cargo fmt` 装成 pre-commit 钩子。本批已是第二次
> 因忘记格式化导致 lint 成片报红。

### 第二梯队：分析闭环（**已于 2026-10-04 落地**，下面剩的是延伸项）

原计划 5–9 项（`CYS-TRF-005/006/007/008/012/027/033/035`）**已全部落地**，
链路 `Packet → FlowTable → Session → FeatureExtractor → FlowRecord` 已打通，
并新增 `--flows` 第三方门禁（见 §2.4）。剩下的是延伸项：

| 顺序 | 任务 | 理由 |
| --- | --- | --- |
| 5 | ~~`CYS-TRF-037` Criterion 基准~~ **已于本批落地**（改为自研基准，不引 Criterion；含 `--bench` 门禁 + 反向注入） | 它已经回答了两条指标：1M 条可容纳（1.55KB/条）且插入达标；无内存增长在定容灌包路径成立。**它同时抓出了三处真问题**，见 §2.5 |
| ~~5b~~ | ~~稳态吞吐够不上 10G~~ **已提为第一梯队第 1 项** | 见上 |
| 6 | `CYS-TRF-028` 特征定义单一来源 + 与训练侧对齐 | 现在特征定义在 Rust 代码里；一旦 Python 侧用手抄一份，两边就会各自漂移，且**两边都会自认为对** |
| 7 | `CYS-TRF-020/023` 补全（HTTP 响应侧/UA、DNS RCODE/EDNS0） | 已落地部分的自然延伸，向量体系现成，加样本成本低 |
| 8 | `CYS-TRF-015` 会话级统计（重传/乱序计数、RTT 粗估） | 记录已经在产出，补列即可；重传与乱序要用到序号，重组层已有 |
| 9 | `CYS-TRF-033` 与 `storage/clickhouse` 建表 DDL 对齐 | `FlowRecord` 现在只保证「列名+版本号」，存储侧尚未落地；这是分析闭环真正出库的口子 |

### 第三梯队：结构化重构（有明确前置时才做）

- `CYS-TRF-001` 拆 workspace：现在做是**纯目录搬移**。建议在第二梯队
  （尤其是流表与特征）落地后再做 —— 那时才会真正出现跨 crate 的依赖，
  提前拆只会让裁决语义长期无法统一。
- `CYS-TRF-016` 双向 `Reassembler` + 超时驱逐：需要会话层先有流表。

### 并行线：控制平面（Go，与上面那条线互不阻塞）

这条线由**另一个协作者**推进（实现全部来自 `9748175` / `8e0fb03`）。若由你接手：

| 顺序 | 任务 | 理由 |
| --- | --- | --- |
| C1 | **先读 `policyd/internal/ruleir/`，再决定做什么** | 引擎已完整（约 3700 行源码 + 2896 行测试）。先读能避免重写；`evaluate.go` 里写明了「allow 优先」是**可用性理由**而非偏好，不要改回去 |
| C2 | 刷新 `BACKLOG.md` 的控制平面部分 | 现表与代码差得最多的一段。刷新时逐项对代码核实（`go test ./...` + 搜包名），别批量打勾 |
| C3 | `CYS-POL-007` nftables 下发 | 引擎唯一缺的「出口」：IR 目前只能判定，不能生效。这是把 policyd 从「可试算」变成「可管控」的分界 |
| C4 | `CYS-POL-008` 原子生效与回滚 | 必须在 007 之后：没有快照就谈不上回滚，而防火墙类设备最怕半生效 |
| C5 | `CYS-POL-005` 的 PG 持久化 + 版本化/审计 | 现存储是纯内存（`store.go`），重启即丢；审计是合规硬需求 |

> **平台注意**：nftables 只在 Linux 生效，本机是 macOS。验证要在
> Parallels 的 Kali VM 或容器里做，且容器内安装+测试必须放在**同一次** `docker run`
> 中（见 §7.4）。

### 可选增强（P2/P3）

- `CYS-TRF-022` TLS 证书解析（明文可见部分）
- `CYS-TRF-026` `cargo-fuzz` 对 HTTP/TLS/DNS 解析器做模糊测试 ——
  解析器已在处理**敌意输入**（省网必然遇到畸形包），这是当前最值得补的一道防守
- `CYS-TRF-024` QUIC（需密钥派生，XL）
- `CYS-TRF-018` IP 分片重组（与 TCP 重组同源，可复用 `intervals.rs`）

---

## 9. 交接检查清单

接手后按此顺序确认环境可用（约 2 分钟）：

```bash
# 1. 工作区干净、状态点正确
git log --oneline -3                      # 期望看到本次交接的 HEAD
git status --short                        # 期望为空

# 2. 关键门禁全绿（会自动生成测试向量）
bash scripts/test/test-all.sh --rust --dpi --reassembly --flows
#    期望：Rust 331 项通过 + 三道 tshark 核验（92 / 16 / 927 项）通过
#          + --flows 的反向故障注入全部被检出 + 测试汇总全部通过

# 2b. 数据面基准（显式开关，默认不在 ALL 里；约 15 秒）
bash scripts/test/test-all.sh --bench
#    期望：13 项回归下限全过 + 3 项反向注入全部被检出；
#          需求目标"达成 8/13"（未达成的是每包路径吞吐与小时级长稳）是**已知差距**，
#          不构成本步失败（见 §2.5、§6）
#    换机器/换核数后先跑：bash scripts/verify/check-flow-bench.sh --report-only 看真实数字

# 3. 格式与真源一致性（前端类型检查也在这里）
bash scripts/lint/lint-all.sh             # 期望：九项全过（含版本真源 + 仓库完整性 + node）

# 4. 端到端 + ABI parity（两者都必须带上 --cpp --rust）
bash scripts/test/test-all.sh --cpp --rust --parity --e2e
#    期望：parity 89 行一致 + e2e 4 阶段 / 19 项断言 + 测试汇总全部通过

# 5. 前端单测（--node 现在可直接用：自证 4 场景 + 前端 25 项）
bash scripts/test/test-all.sh --node

# 6. 待办表状态
bash docs/planning/scripts/count-backlog.sh | tail -20
#    期望：未开始 297 · 进行中 12 · 已完成 41
python3 docs/planning/scripts/check-deps.py
#    期望：无环、无悬空、无自依赖；7 处状态不一致全部是**已记录**项：
#      - CYS-PKT-006 / CYS-PKT-024：既有项（前置的接口部分已交付，属语义重叠）
#      - CYS-TRF-008 / 010 / 014：前置 CYS-TRF-006/007 为 ◐ —— 依赖的是分片流表与超时的
#        **功能**（已可用）；`CYS-TRF-037` 已落地并给出数字，只是 006/007 仍有未达成项
#        （每包路径吞吐、小时级长稳），故仍标 ◐ 而不是批量打勾
#      - CYS-TRF-020 / 023（本批转 ☑）：前置 `CYS-TRF-019` 仍 ◐，因为 019 的另一条验收
#        标准是「样本集准确率 ≥95%」而仓库尚无大样本集 —— 那是**前置自己的**独立未达成项，
#        与这两项的解析功能无关（它们的字段与四态裁决已逐条三方互证），故不把它拖成 ◐；
#        这也是本仓库既有做法（008/010/014 同理）。若将来 019 落地大样本集，这三条一起清零

# 7. 反查「文件真的在仓库里」（本批的教训：磁盘上有 ≠ 版本控制里有）
bash scripts/verify/check-ignored-sources.sh        # 期望：没有源码被 .gitignore 吃掉
git ls-files scripts/release/ scripts/build/ services/telemetryd/internal/target/ \
            # 期望：四个脚本 + 四份 Go 文件都在（它们曾被 ignore 规则吞掉过）
bash scripts/release/check-version.sh --self-test   # 期望：自证通过（4 场景）

# 8. 反查「入库的字节就是测试读的字节」（同族教训：入库这份 ≠ 磁盘那份）
bash scripts/verify/check-dpi-vectors.sh --self-test
#    期望：字节保真比对自证通过（临时仓库内注入行尾归一→判红；加 -text→判绿）
#    正常跑 --dpi 时会先自证再逐文件比对 32 个入库向量与生成物；
#    若报「入库字节与生成物不一致」，见 §7 第 8 条（core.autocrlf=input 吃掉了 CRLF）
```

**若看到 `✗ [node] npm ci 被环境拦截（ENV_INTERCEPTED…）`**：那是 §7.1 的批量删除
保护，不是网络问题也不是代码缺陷（这条文案已经被修成明确指向环境；看到 `REAL_FAILURE`
才是真失败）。依赖在位时脚本会自动跳过 `npm ci`，所以本机常态下不会出现。

**环境依赖**：`cmake` / `cargo` / `go` / `node` / `npm` / `python3` / `tshark`（4.6.7）。
缺 `tshark` 时三道核验会明确打印「未核验…不计为通过」并返回 0 ——
**这是刻意的**：装不装 tshark 是环境问题，但绝不能把它显示成"通过"。

---

## 10. 一句话交给下一棒

「从报文到可存储记录」这一段**已经通了**：`Packet → FlowTable → Session →
FeatureExtractor → FlowRecord`，有离线路径 `cythsec-analyze -r x.pcap -o flows.jsonl`，
有带反向注入的 tshark 门禁（`--flows`），现在**还有了数字**（`--bench`）：
1M 条流可容纳（0.97KB/条）、插入达标（2.06 Mops/s）、稳态无内存增长成立；
基准量出的三处问题**已修两处**：`expire()` 的 O(n) 临时数组、`evict_lru` 的 O(每分片容量)
（后者改成分片内双向链表，仍是精确 LRU、逐出 O(1)：52µs → 0.34µs@每片8192，并给出
"每次逐出考察 0 个候选"的可测断言）；剩下的是稳态查表只有 10G 需求的 34~38%。

下一棒最有价值的三件事，按性价比排序：

1. **稳态吞吐与 10G 的差距**：update 5.6 / query-hit 5.0 / query-miss 13.8 Mops/s vs 需求
   14.88 Mpps。先做一个便宜实验（每核一个独立流表实例，证明近线性扩展），再决定是走
   "多实例分核"还是"把 432B 条目拆成热/冷两段"。别在没有实验数据的情况下直接重构流表。
   （本批已交出一次可比对的教训：O(1) LRU 让插入快一倍、逐出快 100 倍，但命中路径多一次
   间接寻址就吃掉 35% —— 结构改动必须前后同机量。）
3. **特征定义单一来源**（`CYS-TRF-028`）+ **控制平面落地侧**（`CYS-POL-007/008/005`）：
   前者防"两边手抄各自漂移且都自认为对"，后者是把 policyd 从「可试算」变成「可管控」。

**另请留意**：`tshark` 交叉核验是这套代码唯一的"外部真相来源"。
新增任何协议解析器时，如果找不到第三方参照，宁可显式标注
`verified=false` + 原因，也不要让它默认通过 ——
**「未被核验」冒充「已核验通过」是本项目最需要防的事**。
