//! cythsec-bench —— 自研微型基准（CYS-TRF-037）。
//!
//! ## 为什么不用 Criterion
//!
//! Criterion 是第三方 crate，而本工程有一条硬约定：**零第三方依赖、离线可构建**
//! （见 `Cargo.toml` 与 `docs/planning/HANDOFF.md` §5）。基准工具本身不该成为这条
//! 约定的例外 —— 一旦为了跑基准引入依赖，「全新克隆必须能 `--offline` 构建」就不再
//! 成立，而基准恰恰是最不该破坏可构建性的东西。因此这里用 `std::time::Instant` 自实现：
//! 统计能力弱得多（没有离群值剔除、没有置信区间），但**只报告事实**，不假装有统计显著性。
//!
//! ## 目标值从哪来（这一节是基准的灵魂）
//!
//! 目标值**不是**「跑一遍实现记下来」—— 那是让被测实现给自己打分。
//! 全部由**工作量需求**推导，写在每个 case 的 `derivation` 里，可逐条复核：
//!
//! - **每包处理路径**（流表更新 / 查询、特征更新、会话归属）：省网 10Gbps 线速、最坏情况
//!   （线上 84 字节的最小帧）要求 10e9 / (84*8) = **14.88 Mpps**。每个报文至少要过一次
//!   这些环节，故目标统一为 14.88 Mops/s。
//! - **超时扫描**：`expire()` 由调用方按秒级节拍驱动，单次扫描成本必须远小于节拍。
//!   取「1M 条目扫描 ≤ 200ms」即 **5 M 条目/s**（对秒级节拍留 5 倍余量）。
//! - **重组**：要跟上 10Gbps，净载荷吞吐须 ≥ 1.25 GB/s（10e9/8）。
//! - **内存**：判据是**不随包数增长**而不是绝对值 —— 定容 N 条之后灌 5×N 个包，
//!   RSS 增量必须 < 16MiB。单次测量只能说「用了多少」，说不了「会不会一直涨」；
//!   另外打印一条**参考诊断**（「每轮填满 → 全部到期」的 RSS 序列）用于定位分配器行为，
//!   它不参与判定（实测残余 +6MiB/轮，来自分配器不归还小块，逻辑活跃条目恒为 0）。
//!
//! 这些是**我们自己的工程预算**，不是第三方事实：它们回答「够不够用」，不回答「写得对不对」。
//! 正确性由单测与 `--flows` 的 tshark 门禁负责，两者不要混为一谈。
//!
//! ## 两类阈值：需求目标 vs 回归下限
//!
//! 一项实测值同时对照两个数，二者**不可混用**：
//!
//! - `target`（需求目标）：由上面那些推导得出，回答"够不够用"。**当前有一批未达成**，
//!   这正是基准存在的意义：把"没有基准就只能写未达成"变成"有一个具体差了 12 倍的数"。
//! - `floor`（回归下限）：在本机（Apple M1 Pro / macOS，2026-10-04，release）实测基线上
//!   留 **≥2×（逐出类 ≥4×）** 余量得出的**防倒退**阈值，回答"这一版有没有把上一版跑坏"。
//!   余量刻意留大：同机连跑两次，稳态查表类就能差 20~30%，5% 余量只会变成随机假红。
//!   它**不是**验收标准，也**不跨机器成立** —— 换机器需要重标定，因此 `--bench` 门禁
//!   默认不进 `test-all.sh` 的 ALL 集合。
//!
//! 默认退出码由 `floor` 决定（防倒退）；加 `--require-targets` 才由 `target` 决定
//! （回答"现在到底达没达到需求"）。把两件事合成一个退出码，只会让人分不清
//! "这版变慢了"和"这版不达标"。
//!
//! ## 本机实测揭示的问题（详见 docs/planning/HANDOFF.md §6）
//!
//! 1. **稳态查表够不上 10G 最坏情况**（已定位，路线已定）：单实例 update 6.9~8.6 Mops/s，
//!    只有 14.88 Mpps 需求的 46%~58%。**多实例分核实验（见下一节）给出了结论：
//!    每核一张独立表，2 核压线、4 核留 1.5~1.8 倍余量**；热/冷字段拆分不作当前路线。
//! 2. **逐出成本 O(每分片容量)**（本批已修）：旧实现每次逐出全扫分片找最小，
//!    容量 32× → 耗时 52×，实测 1.0 µs/次（每片 256）与 55 µs/次（每片 8192）；
//!    表满后每一次新建流都要付这个代价，而表满恰恰是稳态。改为分片内双向链表维护
//!    活动序（摘表头即逐出）后：两种容量的耗时都降到与容量无关，每次逐出**考察 0 个候选**
//!    （`stats().evict_candidates` 恒为 0，单测与基准都断言这一点）。
//!    旧路径保留为 `EvictPolicy::LruScan`，既是同机对照，也是逐出序列等价性的参照。
//! 3. **`expire()` 的 O(n) 临时数组**（本批已修）：旧实现把全部到期条目搬进
//!    `Vec<FlowEntry>`（每条 432B）再派发，实测每轮「填满→全部到期」让 RSS 抬升
//!    `条目数 × 432B`（250k 条 → +99MiB/轮）且不保证回落，违反 007 的"内存稳定"。
//!    改为只收键、按键序逐条删除并派发后：RSS 增量降到 +6MiB/轮，
//!    超时扫描吞吐 1.62 → 2.50 M entries/s。回调顺序（全局按键升序）不变。
//!
//! ## 多实例分核实验：稳态吞吐与 10G 的差距（HANDOFF §8 第一梯队第 1 项）
//!
//! **问题**：10G 最坏帧（线上 84 字节）要求 14.88 Mpps，即**每个报文**都要过一次流表；
//! 而单实例流表稳态 update 只有 6.9~8.6 Mops/s。候选路线两条：
//! **(a) 每核一张独立表**（多实例分核）；**(b) 拆条目热/冷字段**（缩小每条目内存，
//! 实测约 1.5KB/条）。HANDOFF 的要求是：**先做便宜实验，再决定** ——
//! 不要在没有数据的情况下重构流表。
//!
//! **方法**：N 个**完全独立**的 `FlowTable`（每核一张），各自在自己的线程里跑稳态
//! update（表与键都在计时区之外预建，测的是稳态而不是建表成本）。两条对照：
//!
//! - **纯计算对照**：同样线程数、同样操作次数，但只做寄存器运算 —— 用来量出
//!   "**这台机器本身**的多线程上限"。没有它，"8 线程效率 0.5"无法区分
//!   "表里有共享瓶颈"与"这台机器全核就这个水平"。
//! - **小工作集对照**：每实例 2000 条（约 3MB，能进每核 L2）—— 把"访存/工作集"
//!   这个因素单独拎出来，看它占多少。
//!
//! **数据**（Apple M1 Pro / 10 个逻辑核 / release / 每实例 12.5 万条 / 四次运行）：
//!
//! | 线程数 | 聚合吞吐 | 每线程 | 扩展效率 |
//! | --- | --- | --- | --- |
//! | 1 | 6.9~8.6 Mops/s | 6.9~8.6 | 1.00 |
//! | 2 | 13.4~15.3 | 6.7~7.6 | 0.82~0.96 |
//! | 4 | 22.6~26.2 | 5.6~6.5 | 0.71~0.95 |
//! | 8 | 28.0~34.8 | 3.5~4.4 | 0.42~0.63 |
//!
//! **结论：走路线 (a)，热/冷拆分暂不做。**
//!
//! - **2 核已经压线达标**（13.4~15.3 vs 需求 14.88），**4 核有 1.5~1.8 倍工程余量**
//!   （22.6~26.2 Mops/s），且 4 核内扩展效率仍有 0.71~0.95。核预算按
//!   "最小达标档位 + 1.5× 余量"给出 = **4 核/10G 口**（判据项 `table-cores-for-10g`）。
//! - **8 线程不再近线性（0.42~0.63），但不是因为表里有共享瓶颈**：同一台机器上的
//!   纯计算对照也只有 0.54~0.73；小工作集对照每线程吞吐只比大工作集高 34%~67%，
//!   但仍只有它自己单线程的 0.4~0.5 倍。即：**机器级并发上限是主因，访存是次要因素**。
//!   因此判据用**比值**（流表扩展效率 ÷ 纯计算对照效率，`table-scaling-vs-ceiling`），
//!   实测 **0.55~0.92**（目标 0.5 = "同量级"，下限 0.25）；用绝对效率当验收标准会把
//!   机器上限误报成代码缺陷，把目标贴着实测均值设（0.7~0.8）又会让判定在抖动区间里
//!   随机翻转 —— 阈值该拦"塌掉"（共享瓶颈让它掉到 0.1 量级），不该拦"抖动"。
//! - **热/冷字段拆分不作当前路线**：核预算（4）远小于常见机型核数，拆条目是"省核"
//!   才需要的优化，而它要动条目内存布局、分片、超时与回调一整套。**触发条件**：
//!   目标机型核预算 < 所需核数，或单表规模再涨一个数量级、cache miss 成为主导。
//! - **前提是被实验顺带发现的**：`FlowTable` 原先**不是 `Send`**（观察者是
//!   `Box<dyn FlowObserver>`，测试实现还用 `Rc`），"每核一张表 + 把表搬进 worker 线程"
//!   这条路**根本无法表达**。已改为 `Box<dyn FlowObserver + Send>`（只要 `Send`、
//!   不要 `Sync`：表不需要被多线程共享引用），并有编译期断言守住。
//!
//! **本实验不回答的**：整条每包流水线的核预算。特征更新、会话归属等环节各有自己的
//! 14.88 Mpps 目标（实测 4~7 Mpps，见各 case），它们各自需要自己的核 ——
//! 一个 10G 口的总核预算要在每个环节都达标之后才算得出来，属于后续项。
//!
//! ## 用法
//!
//! ```text
//! cythsec-bench [--flows N] [--rounds R] [--json] [--report-only] [--target-factor F]
//!               [--inject-serialized-scaling]
//! ```
//!
//! - 默认 `--flows 1000000`；机器慢或只做冒烟时用 `--flows 100000`。
//! - 每个 case 跑两遍，**只把第二遍计入判定**（第一遍含页分配、分支预测与 `HashMap`
//!   扩容的冷启动；两遍都打印，便于人工判断抖动）。
//! - `--target-factor F` 把全部目标值乘以 F：**仅供反向故障注入使用** ——
//!   `check-flow-bench.sh --self-test` 用它把目标抬到不可能达到的高度，要求本程序
//!   **必须退出非零**。若一次"不可能达标"的运行仍然报通过，就说明这里的判定是摆设。
//! - `--inject-serialized-scaling` 把多实例实验换成「所有线程抢一张表 + 互斥锁」的
//!   串行形态：**仅供反向故障注入** —— 扩展性判据必须判出退步并退出非零
//!   （`check-flow-bench.sh` 的第 4 项注入）。一个只会说"扩展性良好"的判据等于没有判据。
//! - `--report-only` 只报告不判定（排查用；正式验收不要用）。
//!
//! 退出码：0 全部达标；1 有未达标项；2 参数错误。

use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;

use traffic_engine::export::{Encoder, ExportConfig};
use traffic_engine::feature::FEATURE_SCHEMA_VERSION;
use traffic_engine::feature::{FeatureExtractor, FeatureVector, FlowSample, FEATURE_COUNT};
use traffic_engine::flow::stats::DEFAULT_IAT_CAPACITY;
use traffic_engine::flow::table::{EvictPolicy, FlowEntry, FlowTable, FlowTableConfig};
use traffic_engine::flow::{FlowKey, Packet, IPPROTO_TCP};
use traffic_engine::ipfix::collector::{Collector, CollectorConfig, ExporterId};
use traffic_engine::reassembly::stream::{Stream, StreamConfig};
use traffic_engine::reassembly::tcp::TcpFlags;
use traffic_engine::record::{AppInfo, FlowRecord, RECORD_SCHEMA_VERSION};
use traffic_engine::session::{SessionConfig, SessionManager};
use traffic_engine::tcp::{Side, TcpObservation};

/// 10Gbps 线速下的最坏包速率（pps）。
///
/// 最小以太帧是 64 字节，但**线上**还要加 7B 前导 + 1B SFD + 12B 帧间隙，共 84 字节：
/// 10e9 / (84×8) = **14,880,952 pps**。这就是业界常说的"10G 最坏情况 14.88 Mpps"。
/// 若按 64 字节算会得到 19.53 Mpps —— 那是把线开销当成不存在，属于自己给自己放宽要求。
const LINE_RATE_10G_64B_PPS: f64 = 10_000_000_000.0 / (84.0 * 8.0);
/// 每包路径的目标值，单位 Mops/s（与上报单位一致，避免"目标 14880952 对 14.88"这种口径错）。
const PER_PACKET_TARGET_MOPS: f64 = LINE_RATE_10G_64B_PPS / 1e6;
/// 新建流速率的目标值（Mops/s）。
///
/// **不能用每包速率当新建流速率的目标**：一个连接只在建立时新建一次条目，之后每个包都
/// 走 update。按 1M 并发流、瞬态超时 60s 估算稳态替换率约 17k 次/s；取 1 Mops/s
/// （约 60 倍余量，覆盖扫描型突发的新建潮）作为目标。用 14.88 Mpps 去要求插入，
/// 是拿包速率当流速率，会把一个正常的东西判成不合格。
const NEW_FLOW_TARGET_MOPS: f64 = 1.0;
/// 10Gbps 的净载荷字节速率。
const LINE_RATE_10G_GBPS: f64 = 10_000_000_000.0 / 8.0 / 1e9;
/// 超时扫描预算：1M 条目 ≤ 200ms（单位 M entries/s）。
const EXPIRE_TARGET_M_ENTRIES: f64 = 5.0;
/// 单次逐出预算：表满后每次新建流都要逐出一条，目标 ≥ 2M 次/s（线速下新建流速率
/// 的 100 倍余量）；换算成纳秒即 ≤ 500ns。
const EVICT_TARGET_NS: f64 = 500.0;

// ---------------------------------------------------------------- 回归下限
//
// 本机基线（Apple M1 Pro / macOS 26，2026-10-04，release 构建，flows=1000000）。
// 含义只有一句：**这一版别比上一版差**。换机器请重标定（`--report-only` 打印实测值），
// 不要拿它当验收标准。
//
// 余量刻意留得大（≥2×，逐出类 ≥4×）：实测同一台机器上连跑两次，稳态查表类能差 20~30%
// （散热/其它负载/内存布局），5% 的余量只会变成随机的假红。所以这些数只用来抓
// "坏了一个数量级"，不是用来抓"慢了 10%"——后者需要固定频率的测试机才有意义。

/// 单条流插入（新建条目）下限。
const FLOOR_INSERT_MOPS: f64 = 0.5;
/// 稳态更新 / 命中查询下限。
const FLOOR_LOOKUP_MOPS: f64 = 3.0;
/// 未命中查询下限。
const FLOOR_MISS_MOPS: f64 = 8.0;
/// 超时扫描下限（M entries/s）。
const FLOOR_EXPIRE_M_ENTRIES: f64 = 1.0;
/// 逐出上限（ns/次）——越大越差的指标，floor 是"不许超过"。
///
/// 采样 LRU 落地后，两种容量的逐出成本都只由 K=8 次哈希桶访问决定，**与容量无关**，
/// 因此两者共用同一个下限（这正是本批修掉的东西：修之前每片 8192 要 55µs，
/// 比每片 256 慢 52 倍）。
const FLOOR_EVICT_NS: f64 = 1_500.0;
/// 大步长（每片 8192）逐出的下限，取同一个值 —— 若它又比 cap256 慢一个数量级，
/// 说明 O(每分片容量) 回来了，而这比"绝对值慢一点"重要得多。
const FLOOR_EVICT_BIG_NS: f64 = 1_500.0;

/// 逐出成本对容量的**伸缩比**上界。
///
/// 这是本批唯一"与机器无关"的判据：采样 K=8 ⇒ 成本与每分片容量无关 ⇒ 比值 ≈ 1。
/// 容量比 32× 下留 3 倍余量覆盖 cache 效应的波动；修之前实测是 52×（精确 LRU，O(cap)）。
/// 绝对值会随机器漂，这个比值不会 —— 换机器后它依然是判断"是不是又变成 O(cap)"的哨兵。
const EVICT_SCALE_RATIO_MAX: f64 = 3.0;
/// 特征更新下限。
const FLOOR_FEATURE_MOPS: f64 = 14.0;
/// 顺序重组下限（GB/s）。
const FLOOR_REASSEMBLY_GBPS: f64 = 1.0;
/// 乱序重组下限（GB/s）。
const FLOOR_REASSEMBLY_OOO_GBPS: f64 = 0.8;
/// 会话归属下限（Mpps）。
const FLOOR_SESSION_MPPS: f64 = 1.5;
/// 稳态内存增长上限（MiB）：这一条就是 007 的验收标准本身，不设"回归下限"之外的宽容。
const STEADY_MEMORY_LIMIT_MIB: f64 = 16.0;

/// IPFIX 采集解码的目标吞吐（Mrec/s）。
///
/// **出处是容量模型本身，不是"越大越好"**：省网量级 20 Tbps、1:1000 采样、平均包长
/// 500 B 时，采样后是 5 Gpps/1000 = **5 M 采样包/秒**；按"每个采样包最多产生一条记录"
/// 的上界（保守口径，见 §2.13）即 **5 M 记录/秒**。单台采集器至少要吃下 1 M 记录/秒，
/// 全省才可能落在个位数台设备的量级（容量模型用它算台数）。
const COLLECTOR_TARGET_MREC_S: f64 = 1.0;

/// 采集解码吞吐的回归下限（Mrec/s）。
///
/// 与其它下限同源：**本机基线**（Apple M1 Pro / macOS 26，release，flows=1M，
/// 2026-10-05 实测 4.62 Mrec/s）留 2.3× 余量，只为抓"坏了一个数量级"，
/// 不抓"慢了 10%"。换机器请用 `--report-only` 重标定后再改这个数。
///
/// 注意它**低于目标值 1.0 之上不多**：这一条不是产能承诺，是防倒退。
const FLOOR_COLLECTOR_MREC_S: f64 = 2.0;

// ------------------------------------------------- 多实例分核实验（CYS-TRF-006/037）
//
// 稳态单实例查表只有 14.88Mpps 需求的 46%~58%，而省网 10G 口是硬需求。
// 候选路线有两条：**每核一张独立流表**（多实例分核）或**拆热/冷字段缩小条目**。
// 本组用例只回答一个问题：**多实例到底能不能近线性地扩展**。能，则路线一成立，
// 剩下的只是核数预算；不能，说明有共享瓶颈，得先找出来（而不是先重构流表）。
//
// 判据只用一个比值，不用绝对吞吐：`N 线程聚合 ÷ (可用核数 × 单线程)`。
// 绝对吞吐随机器漂，这个比值回答的是"设计里有没有共享瓶颈"，与机器无关。

/// 标准线程档位（名字静态，便于门禁用例数清单固定）。
///
/// **新增/删除档位必须同步 `scripts/verify/check-flow-bench.sh` 的 `EXPECTED_CASES`**：
/// 少了档位而门禁仍然绿，就是最典型的假绿。
const MULTI_INSTANCE_TIERS: [(usize, &str); 4] = [
    (1, "table-steady-1t"),
    (2, "table-steady-2t"),
    (4, "table-steady-4t"),
    (8, "table-steady-8t"),
];
/// 每个线程的规模 = `flows / 这个数`：默认 1M 总量摊到 8 个实例，
/// 于是 8 线程实验的**总内存占用与单实例用例同级**（否则 8×1M 条会吃掉十几 GB）。
const MULTI_INSTANCE_SPLIT: usize = 8;
/// 流表扩展效率相对**纯计算对照**的下限（需求目标）。
///
/// 为什么不直接要求"8 线程绝对效率 ≥0.8"：那会把**机器本身**的上限算成表的缺陷。
/// 实测（M1 Pro）8 线程绝对效率只有 0.46~0.63，而同一台机器上纯计算对照也上不去 ——
/// 多线程吞吐在这个平台上有天花板（全核频率/核间异构），与流表无关。
/// 因此判据必须是**比值**：流表的扩展效率 ÷ 同一台机器纯计算对照的扩展效率。
/// 比值接近 1 = 表里没有共享瓶颈（有锁/假共享/全局计数器时它必然塌下来）。
/// 取 **0.5**：要求流表的多线程扩展与机器的纯计算上限**同量级**（允许差 2 倍）。
///
/// 为什么是"同量级"而不是某个更紧的数：这个判据要拦的是**共享瓶颈**（锁、全局计数器、
/// 假共享），它会让比值塌到 0.1 量级（串行注入档实测 **0.10**）；而流表走 DRAM 随机
/// 访问、对照只做寄存器运算，两者相差一倍以内属于访问模式的固有成本，不是缺陷。
/// 实测（两种估计量口径共 10 次）落在 **0.55~0.92**；把目标贴着实测均值设（0.7~0.8）
/// 会让判定在抖动区间里随机翻转 —— 阈值应当拦"塌掉"，不该拦"抖动"。
const SCALING_VS_CEILING_MIN: f64 = 0.5;
/// 「相对纯计算对照」这个比值的回归下限。
///
/// 标定依据：十次实测比值 0.55~0.92（两种估计量口径）。下限取 0.25 ——
/// 约为实测最小值的 0.45 倍；串行注入档实测 0.10 仍在其下，注入依然被判红。
const FLOOR_SCALING_VS_CEILING: f64 = 0.25;
/// **每核**稳态吞吐的回归下限（Mops/s）。
///
/// 聚合下限按 `档位 × 这个数` 算：这样"8 个线程却只有单线程的吞吐"（共享锁、
/// 假共享、全局计数器）会直接撞在回归下限上被判红，而不是靠效率比值单独兜底。
/// 实测（1M 规模，三次）：单线程 6.89~8.60、8 线程 31.98~34.66 Mops/s，
/// 即每核 2.0~8.6；下限取 2.0。
/// **每个档位的下限再封顶到需求目标**（`min(档位 × 2.0, 14.88)`）：8 档按线性算是 16，
/// 比需求目标还严 —— 那会让"未达标"同时被报成"退步"。两类阈值不可混用，
/// 由 `floors_are_never_stricter_than_targets` 守住。串行注入档实测 8 线程
/// 2.10~2.35 Mops/s → 远低于封顶后的 14.88，仍被判红。
const FLOOR_STEADY_PER_CORE_MOPS: f64 = 2.0;
/// 纯计算对照的操作次数倍数。
///
/// 流表档位里每个线程做 12.5 万次 update，耗时约 15~20ms —— 与线程启动开销
/// （数十微秒）相比可以忽略。对照如果只做同样**次数**的寄存器运算（约 0.15ms），
/// 就会被线程启动/回收的开销污染，量到的不是机器上限而是 spawn 成本。
/// 因此把对照的次数放大到同一量级（约 5ms/线程）。
const CEILING_OPS_MULTIPLE: usize = 32;

/// 归因对照用的每实例规模。
///
/// 2000 条 ×（实测 ~1.5KB/条）≈ **3MB/实例**，正好落在 M1 Pro 每个性能核 12MB 的
/// L2 里（每核自己的 L2 装自己那张表）。用它做对照才能把"工作集超出 cache"这个
/// 因素真正排除掉 —— 取 2 万条（约 30MB/实例）虽然更小，但仍远大于 L2，
/// 对照组本身就还是 DRAM 负载，等于没做对照。
const CACHE_FIT_PER_THREAD: usize = 2_000;

/// 一个被测项。
struct Case {
    name: &'static str,
    /// 第一遍（冷启动）实测值。
    first: f64,
    /// 第二遍实测值 —— **判定用这一遍**。
    measured: f64,
    unit: &'static str,
    /// 需求目标（由工作量需求推导）。
    target: f64,
    /// 回归下限（本机基线留余量，只用于防倒退）。
    floor: f64,
    /// 目标是否为"越小越好"（内存类指标）。
    lower_is_better: bool,
    derivation: &'static str,
}

impl Case {
    /// 达到**需求目标**了吗（回答"够不够用"）。
    ///
    /// `factor` 只用于反向故障注入（把阈值整体放大，要求判定必须翻转）。
    /// 判定逻辑只有这一处 —— 输出、汇总、退出码都调它，避免"表格显示达标、
    /// 退出码按另一套规则算"这种最隐蔽的自相矛盾。
    fn passed(&self, factor: f64) -> bool {
        let target = self.target * factor;
        if self.lower_is_better {
            self.measured <= target
        } else {
            self.measured >= target
        }
    }

    /// 相对**回归下限**退步了吗（回答"这版有没有跑坏"）。
    fn regressed(&self, factor: f64) -> bool {
        let floor = self.floor * factor;
        if self.lower_is_better {
            self.measured > floor
        } else {
            self.measured < floor
        }
    }
}

/// 极简确定性 PRNG（xorshift64*）：基准必须可复现，不能用每次运行都不同的熵源 ——
/// 那样两次测的就不是同一份工作。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
}

/// 本进程的常驻内存（物理 RSS）。零第三方依赖下拿不到平台 API，于是走系统工具：
/// Linux 读 `/proc/self/statm`，其它平台退回 `ps -o rss=`。拿不到返回 `None`
/// （**不猜**一个数出来）。
fn rss_bytes() -> Option<u64> {
    if let Ok(text) = std::fs::read_to_string("/proc/self/statm") {
        let pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
        return Some(pages * 4096);
    }
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let kb: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    Some(kb * 1024)
}

fn mib(v: u64) -> f64 {
    v as f64 / (1024.0 * 1024.0)
}

/// 跑两遍，返回 (第一遍秒数, 第二遍秒数)。
fn twice(mut f: impl FnMut()) -> (f64, f64) {
    let t0 = Instant::now();
    f();
    let first = t0.elapsed().as_secs_f64();
    let t1 = Instant::now();
    f();
    (first, t1.elapsed().as_secs_f64())
}

/// 造 n 个互不相同的 IPv4/TCP 五元组。地址用自增（保证不重复），端口用 PRNG
/// （避免端口恰好顺序而在哈希上过于友好）。
fn keys(n: usize, seed: u64) -> Vec<FlowKey> {
    keys_to(n, seed, [10, 0, 0, 2])
}

/// 同 `keys`，但指定目的地址。
///
/// "查不到"的键集必须与"查得到"的键集**在地址上就分开**：若只换端口，两地
/// 60000 个端口值在百万级规模下必然碰撞（生日问题），于是 miss 集里混进真命中的键，
/// 测出来的就不是纯 miss 路径 —— 这类错误不会报错，只会让数字偏乐观。
fn keys_to(n: usize, seed: u64, dst: [u8; 4]) -> Vec<FlowKey> {
    let mut rng = Rng::new(seed);
    (0..n)
        .map(|i| {
            let a = ((i >> 16) & 0xff) as u8;
            let b = ((i >> 8) & 0xff) as u8;
            let c = (i & 0xff) as u8;
            let port = 1024 + (rng.below(60000) as u16);
            FlowKey::new_ipv4([10, a, b, c], port, dst, 443, IPPROTO_TCP)
        })
        .collect()
}

fn packet(key: FlowKey, ts_us: u64) -> Packet {
    let mut p = Packet::new(key, 64);
    p.timestamp_us = ts_us;
    p
}

// ---------------------------------------------------------------- 各被测项

fn case_table(flows: usize, report: &mut Vec<Case>) {
    let ks = keys(flows, 0x5eed_1234);

    // 插入：N 个新键各一个包。
    //
    // 容量取 2N 而不是 N：容量按分片均分（`max_flows / shard_count`），而哈希分布
    // 并不均匀，`max_flows = N` 时会有约 0.5% 的键落在"已经满了"的分片上而被逐出
    // （实测 N=100k/16 分片逐出 458 条，`len()` 只剩 99542）。那不是插入路径的
    // 特性，而是容量模型的特性 —— 测吞吐时要把逐出**排除**掉，并在下面断言
    // `evictions == 0`，否则这个 case 会悄悄变成"插入 + 逐出"的混合测量。
    let cfg = FlowTableConfig {
        max_flows: flows * 2,
        shard_count: 16,
        // 容量取 2×，插入阶段根本不会逐出；策略写默认值是为了让这条 case
        // 与线上配置一致（默认 = 分片内双向链表的精确 LRU，见 EvictPolicy）。
        policy: EvictPolicy::default(),
        ..Default::default()
    };
    let mut full: Option<FlowTable> = None;
    let (first, measured) = twice(|| {
        let mut t = FlowTable::new(cfg);
        for (i, k) in ks.iter().enumerate() {
            t.observe(&packet(*k, i as u64));
        }
        assert_eq!(
            t.stats().evictions,
            0,
            "本 case 必须排除逐出（见上方容量说明）"
        );
        assert_eq!(t.len(), flows, "无逐出时条数应等于键数");
        full = Some(t);
    });
    report.push(Case {
        name: "table-insert",
        first: flows as f64 / first / 1e6,
        measured: flows as f64 / measured / 1e6,
        unit: "Mops/s",
        target: NEW_FLOW_TARGET_MOPS,
        lower_is_better: false,
        floor: FLOOR_INSERT_MOPS,
        derivation: "新建流速率：1M 容量/60s 超时≈17k 次/s，取 1Mops/s 作 60 倍余量",
    });
    let mut table = full.expect("插入用例必须产出一张满表");

    // 更新：同一批键各再来一个包 → 全部走"已存在"分支。
    let (first, measured) = twice(|| {
        for (i, k) in ks.iter().enumerate() {
            table.observe(&packet(*k, 1_000_000 + i as u64));
        }
    });
    report.push(Case {
        name: "table-update",
        first: flows as f64 / first / 1e6,
        measured: flows as f64 / measured / 1e6,
        unit: "Mops/s",
        target: PER_PACKET_TARGET_MOPS,
        lower_is_better: false,
        floor: FLOOR_LOOKUP_MOPS,
        derivation: "同 table-insert：稳态流量绝大多数包落在 update 分支",
    });

    // 查询命中：随机顺序（顺序访问会被预取器美化）。
    let mut rng = Rng::new(0xabcd_ef01);
    let order: Vec<usize> = (0..flows)
        .map(|_| rng.below(flows as u64) as usize)
        .collect();
    let (first, measured) = twice(|| {
        let mut hits = 0usize;
        for &i in &order {
            if table.get(&ks[i]).is_some() {
                hits += 1;
            }
        }
        assert_eq!(hits, flows, "查询必须先是真的命中，否则测的是 miss 分支");
    });
    report.push(Case {
        name: "table-query-hit",
        first: flows as f64 / first / 1e6,
        measured: flows as f64 / measured / 1e6,
        unit: "Mops/s",
        target: PER_PACKET_TARGET_MOPS,
        lower_is_better: false,
        floor: FLOOR_LOOKUP_MOPS,
        derivation: "同 table-insert；命中率按 100% 算是乐观上界",
    });

    // 查询未命中：目的地址换掉，确保与命中的键集**在地址上**就不同。
    let miss = keys_to(flows, 0x9999_0001, [10, 0, 0, 3]);
    let mut rng = Rng::new(0x1357_9bdf);
    let morder: Vec<usize> = (0..flows)
        .map(|_| rng.below(flows as u64) as usize)
        .collect();
    let (first, measured) = twice(|| {
        for &i in &morder {
            assert!(table.get(&miss[i]).is_none(), "miss 集必须真的不在表里");
        }
    });
    report.push(Case {
        name: "table-query-miss",
        first: flows as f64 / first / 1e6,
        measured: flows as f64 / measured / 1e6,
        unit: "Mops/s",
        target: PER_PACKET_TARGET_MOPS,
        lower_is_better: false,
        floor: FLOOR_MISS_MOPS,
        derivation: "回溯型扫描大量走 miss 分支",
    });

    // 超时扫描：全部条目一次性到期。
    let far = 1_000_000_000_000u64; // 1e12 µs ≈ 11.6 天，远超任一档超时
    let expire_once = || {
        let mut t = FlowTable::new(cfg);
        for (i, k) in ks.iter().enumerate() {
            t.observe(&packet(*k, i as u64));
        }
        let a = Instant::now();
        let expired = t.expire(far);
        let secs = a.elapsed().as_secs_f64();
        assert_eq!(expired, flows, "全部条目都应被回收");
        assert_eq!(t.len(), 0, "回收后表必须为空");
        secs
    };
    let first = expire_once();
    let measured = expire_once();
    report.push(Case {
        name: "table-expire",
        first: flows as f64 / first / 1e6,
        measured: flows as f64 / measured / 1e6,
        unit: "M entries/s",
        target: EXPIRE_TARGET_M_ENTRIES,
        lower_is_better: false,
        floor: FLOOR_EXPIRE_M_ENTRIES,
        derivation: "1M 条目扫描 ≤200ms（秒级节拍留 5 倍余量）",
    });
}

/// 一个"核"的负载：**预建好的**独立表 + 待重放的键序列。
///
/// 预建在计时区之外：要测的是稳态 update 路径，不是建表成本（否则量到的是
/// 分配器与哈希扩容，与扩展性无关）。
struct Instance {
    table: FlowTable,
    ks: Vec<FlowKey>,
}

/// 多实例分核实验的原始数据（打印诊断用；判定走 `Case`）。
struct ScalingReport {
    /// 本机可用并行度（`available_parallelism`）。
    ap: usize,
    /// 每个实例的规模。
    per_thread: usize,
    /// (线程数, 聚合 Mops/s, 扩展效率)。
    tiers: Vec<(usize, f64, f64)>,
    /// 按单核实测吞吐折算：顶住一个 10G 口需要的核数。
    cores_for_10g: f64,
    /// 本次是否走了串行档（仅反向故障注入时为真）。
    serialized: bool,
    /// 8 线程扩展效率 ÷ 纯计算对照的 8 线程扩展效率（机器无关的判据）。
    ceiling_ratio: f64,
    /// 纯计算对照自身的 8 线程扩展效率（绝对值，用于解释比值）。
    ceiling_eff: f64,
    /// 归因对照：(每实例条数, 8 线程聚合 Mops/s, 8 线程效率, 小工作集的单线程吞吐)。
    ///
    /// 同一批 8 线程、但每实例的表小到能进 cache。若它的效率明显高于大工作集，
    /// 就说明大工作集下的效率掉落来自**内存/工作集**，而不是锁或共享状态
    /// —— 这两者对部署的含义相反（前者靠控制每核流数，后者只能靠改设计）。
    cache_fit: Option<(usize, f64, f64, f64)>,
}

/// 扩展效率：`聚合 ÷ (可用核数 × 单线程)`。
///
/// 分母用 `min(线程数, 本机并行度)` 而不是线程数：在核数少于线程数的机器上，
/// 效率低反映的是**机器核数不够**，不是设计里有共享瓶颈 —— 两者混在一起，
/// 换台机器就会把机器限制误报成代码退步。
fn scaling_efficiency(aggregate_mops: f64, single_mops: f64, threads: usize, ap: usize) -> f64 {
    let usable = threads.min(ap.max(1)) as f64;
    aggregate_mops / (usable * single_mops)
}

/// 核数预算里的**工程余量**。
///
/// 线速 14.88Mpps 是"最坏帧"下的均值要求，而一个 worker 通常还要同时做特征、会话、
/// 记录等环节（每个环节都有自己的 14.88 目标，见 HANDOFF §2.5）。流表把余量吃光，
/// 后面的环节就没有空间了，因此取 1.5× —— 与 `NEW_FLOW_TARGET_MOPS` 的 60×、
/// 回归下限的 2× 同属"把工程判断写成可复核的数字"，不是拍脑袋。
const CORES_ENGINEERING_MARGIN: f64 = 1.5;

/// 顶住一个 10G 口需要的**最小达标档位**（核数）。
///
/// 直接取"第一个聚合吞吐 ≥ 1.5×目标的线程档位"，而不是拿单核吞吐外推：
/// 档位表里已经有 2/4/8 核的**实测**聚合值，用实测值回答"几个核够"最不容易骗人。
/// 所有档位都不够时才外推，并按最高档的每线程吞吐算（并发效率只会更差，故这是乐观下界）。
fn cores_for_line_rate(tiers: &[(usize, f64, f64)]) -> f64 {
    let need = PER_PACKET_TARGET_MOPS * CORES_ENGINEERING_MARGIN;
    for (n, agg, _) in tiers {
        if *agg >= need {
            return *n as f64;
        }
    }
    let (top_n, top_agg, _) = *tiers.last().expect("至少一个档位");
    (need / (top_agg / top_n as f64)).ceil()
}

/// 造一个"核"：独立表 + 键序列，并把键全部插入（计时区外的预建）。
fn build_instance(per_thread: usize, seed: u64) -> Instance {
    let ks = keys(per_thread, seed);
    let mut table = FlowTable::new(FlowTableConfig {
        // 与 `table-*` 系列同样的 2× 余量：把逐出排除掉（哈希分布不均会让少数分片先满）。
        max_flows: per_thread * 2,
        shard_count: 16,
        ..Default::default()
    });
    for (i, k) in ks.iter().enumerate() {
        table.observe(&packet(*k, i as u64));
    }
    // 预建阶段的正确性直接断言：否则"扩展性很好"可能只是有一半线程没干活。
    assert_eq!(table.stats().evictions, 0, "预建阶段不应发生逐出");
    assert_eq!(table.len(), per_thread, "预建后条数应等于键数");
    Instance { table, ks }
}

/// 并行档：N 个独立实例各在自己的线程里处理自己的键。返回耗时（秒）。
fn parallel_duration(instances: &mut [Instance], n: usize) -> f64 {
    let start = Instant::now();
    std::thread::scope(|s| {
        for inst in instances[..n].iter_mut() {
            s.spawn(move || {
                // 解构出两个不相交的可变/不可变借用，否则闭包里借不了 self 的两个字段。
                let Instance { table, ks } = inst;
                for (i, k) in ks.iter().enumerate() {
                    table.observe(&packet(*k, 1_000_000 + i as u64));
                }
            });
        }
    });
    start.elapsed().as_secs_f64()
}

/// 串行档：线程数照旧，但**所有线程抢同一把锁、共用一张表**。
///
/// 只用于反向故障注入 —— 这正是"多实例分核"要避免的形态（共享状态 + 串行化）。
/// 它让扩展效率判据有一个已知会失败的输入：若判据连这个都判不出来，那它就是摆设。
fn serialized_duration(instances: &[Instance], n: usize, shared: &Mutex<FlowTable>) -> f64 {
    let start = Instant::now();
    std::thread::scope(|s| {
        for inst in instances[..n].iter() {
            // 只把**键切片**搬进线程，不搬 `&Instance`：后者会让 `FlowTable` 需要
            // `Sync`（多线程共享同一张表），而这条路线刻意只要求 `Send`。
            let ks = inst.ks.as_slice();
            s.spawn(move || {
                for (i, k) in ks.iter().enumerate() {
                    shared
                        .lock()
                        .expect("串行档的锁不该中毒")
                        .observe(&packet(*k, 1_000_000 + i as u64));
                }
            });
        }
    });
    start.elapsed().as_secs_f64()
}

/// 纯计算对照：同样的线程数与操作次数，但只做寄存器运算 —— 不建表、不访存、
/// 不共享任何状态。返回耗时（秒）。
///
/// 它的唯一用途是把**机器本身**的多线程吞吐上限量出来。没有这个对照，
/// "8 线程效率 0.53"就无法区分"表里有共享瓶颈"与"这台机器全核就这个水平"。
fn ceiling_duration(ops: usize, threads: usize) -> f64 {
    let start = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(move || {
                // 依赖链 + black_box：防止编译器把整个循环优化掉（那样"对照"会快得离谱）。
                let mut x = 0x9e37_79b9_7f4a_7c15u64;
                for i in 0..ops {
                    x = x.rotate_left(7) ^ (i as u64).wrapping_mul(0x2545_f491_4f6c_dd1d);
                    x = x.wrapping_add(x >> 17);
                }
                std::hint::black_box(x);
            });
        }
    });
    start.elapsed().as_secs_f64()
}

/// 多实例分核实验（HANDOFF §8 第一梯队第 1 项）。
///
/// `serialized` 仅供反向故障注入：把并行档换成"共享一张表 + 互斥锁"，
/// 要求本实验判出扩展失败（见 `check-flow-bench.sh` 的第 4 项注入）。
fn case_multi_instance(flows: usize, report: &mut Vec<Case>, serialized: bool) -> ScalingReport {
    let ap = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let per_thread = (flows / MULTI_INSTANCE_SPLIT).max(2000);
    let max_threads = MULTI_INSTANCE_TIERS
        .iter()
        .map(|(n, _)| *n)
        .max()
        .expect("档位表不能为空");
    let mut instances: Vec<Instance> = (0..max_threads)
        .map(|i| build_instance(per_thread, 0x2701_0000 + i as u64))
        .collect();

    // 串行档的表要在计时前预建到"全部键都在"的状态，否则量到的是插入路径，
    // 与并行档（update 路径）不可比。
    let shared = if serialized {
        let mut t = FlowTable::new(FlowTableConfig {
            max_flows: per_thread * max_threads * 2,
            shard_count: 16,
            ..Default::default()
        });
        for inst in &instances {
            for (i, k) in inst.ks.iter().enumerate() {
                t.observe(&packet(*k, i as u64));
            }
        }
        Some(Mutex::new(t))
    } else {
        None
    };

    let mut tiers = Vec::new();
    let mut single = 0.0f64;
    for (n, name) in MULTI_INSTANCE_TIERS {
        let ops: usize = instances[..n].iter().map(|i| i.ks.len()).sum();
        let (first, measured) = match shared.as_ref() {
            Some(shared) => twice(|| {
                serialized_duration(&instances, n, shared);
            }),
            None => twice(|| {
                parallel_duration(&mut instances, n);
            }),
        };
        let to_mops = |secs: f64| ops as f64 / secs / 1e6;
        // 多线程项的判定值取**两遍里较快的那一遍**（= 吞吐的较大值）：
        // 8 线程的抖动主要来自调度与外部干扰（实测同一构建最多差 20%），
        // "这台机器能做到多少"的标准估计量是较快的那遍；单线程项仍按惯例取第二遍
        // （那里第一遍含页分配与分支预测的冷启动，是真实的一次性成本）。
        // 两遍都照常打印，人工复核时看得到原始数据。
        let aggregate = to_mops(first.min(measured));
        if n == 1 {
            single = aggregate;
        }
        let eff = scaling_efficiency(aggregate, single, n, ap);
        tiers.push((n, aggregate, eff));
        report.push(Case {
            name,
            first: to_mops(first),
            measured: aggregate,
            unit: "Mops/s",
            target: PER_PACKET_TARGET_MOPS,
            lower_is_better: false,
            // 聚合下限 = min(档位 × 每核下限, 需求目标)：8 线程却只有单线程吞吐会被
            // 直接判红，但下限不得比需求目标更严（否则"未达标"会被同时报成"退步"）。
            floor: (FLOOR_STEADY_PER_CORE_MOPS * n as f64).min(PER_PACKET_TARGET_MOPS),
            derivation: if n == 1 {
                "每核一张独立 FlowTable，稳态 update；1 档 = 单实例（与 table-update 同负载）"
            } else {
                "同 1 档，N 个实例各占一个线程；目标仍是 10G 的 14.88Mpps"
            },
        });
    }

    // 每个实例都必须真的活着（并发跑完之后逐个体检）：否则"扩展性好"可能是
    // 有的线程压根没干活 —— 并发基准最常见的假绿。
    if shared.is_none() {
        for (i, inst) in instances.iter().enumerate() {
            assert_eq!(
                inst.table.len(),
                per_thread,
                "实例 {i} 的条目数不对，说明该线程没跑完"
            );
            assert_eq!(inst.table.stats().evictions, 0, "稳态不该逐出");
        }
    }

    // 扩展效率：取最高档（8t），再除以**同一台机器纯计算对照**的效率。
    //
    // 判据刻意不用绝对效率：绝对效率里混着"机器能并行到什么程度"这个与代码无关的量，
    // 拿它当验收标准会把机器上限误报成表的缺陷。比值才是"表里有没有共享瓶颈"的答案。
    let (top_n, _, top_eff) = *tiers.last().expect("至少有一个档位");
    let ceiling_ops = per_thread * CEILING_OPS_MULTIPLE;
    let (c1a, c1b) = twice(|| {
        ceiling_duration(ceiling_ops, 1);
    });
    let (cta, ctb) = twice(|| {
        ceiling_duration(ceiling_ops, top_n);
    });
    // **与流表档位对称**：两边都取较快的一遍。只在一侧取较快值会让比值偏向任意一边
    // （实测比值会因此从 0.8 掉到 0.35~0.55，那是口径错误，不是机器变慢）。
    let ceiling_single = ceiling_ops as f64 / c1a.min(c1b) / 1e6;
    let ceiling_agg = (ceiling_ops * top_n) as f64 / cta.min(ctb) / 1e6;
    let ceiling_eff = scaling_efficiency(ceiling_agg, ceiling_single, top_n, ap);
    let ceiling_ratio = top_eff / ceiling_eff;
    report.push(Case {
        name: "table-scaling-vs-ceiling",
        first: ceiling_ratio,
        measured: ceiling_ratio,
        unit: "×",
        target: SCALING_VS_CEILING_MIN,
        lower_is_better: false,
        floor: FLOOR_SCALING_VS_CEILING,
        derivation: "流表扩展效率 ÷ 纯计算对照效率（同为 8 线程）；≈1 即表内无共享瓶颈",
    });
    // 归因对照：同样 8 线程，但每实例的表小到能进 cache。
    // 只在自然档（非注入档）且大工作集时才跑 —— 小规模本来就没有"工作集"这个问题。
    let cache_fit = if shared.is_none() && per_thread > CACHE_FIT_PER_THREAD {
        let small = CACHE_FIT_PER_THREAD;
        let mut insts: Vec<Instance> = (0..max_threads)
            .map(|i| build_instance(small, 0x2a01_0000 + i as u64))
            .collect();
        let ops_one = insts[0].ks.len();
        let (_, d1) = twice(|| {
            parallel_duration(&mut insts, 1);
        });
        let (_, d8) = twice(|| {
            parallel_duration(&mut insts, max_threads);
        });
        let small_single = ops_one as f64 / d1 / 1e6;
        let small_agg = (ops_one * max_threads) as f64 / d8 / 1e6;
        Some((
            small,
            small_agg,
            scaling_efficiency(small_agg, small_single, max_threads, ap),
            small_single,
        ))
    } else {
        None
    };

    let cores = cores_for_line_rate(&tiers);
    report.push(Case {
        name: "table-cores-for-10g",
        first: cores,
        measured: cores,
        unit: "cores",
        // 目标 = 本机可用并行度：问的是"这台机器用满核能不能顶住一个 10G 口"。
        // 这是**机器相对**的目标（与回归下限同性质），不是跨机器的验收标准。
        target: ap as f64,
        lower_is_better: true,
        floor: ap as f64,
        derivation: "最小档位使聚合 ≥1.5×14.88Mpps（余量留给同核上的其它环节）",
    });
    ScalingReport {
        ap,
        per_thread,
        tiers,
        cores_for_10g: cores,
        serialized,
        ceiling_ratio,
        ceiling_eff,
        cache_fit,
    }
}

/// 007 的验收标准本身：**内存不随包数增长**。
///
/// 做法是「定容 + 灌包」：把表填到容量上限，再对同一批流持续观测若干倍于容量的包数
/// （全部走 update 分支，不新建条目、不逐出）。update 路径不分配任何内存，因此
/// 任何一个真实的泄漏都会在这里表现为 RSS 增长，而正常的实现应当纹丝不动。
///
/// **为什么不用「填满 → 全部到期」的 churn 来判**：那条路径每次调用 `expire()` 都要
/// 申请一个与被回收条目数成正比的临时数组（每条目 432B，见 HANDOFF §6），macOS 在释放
/// 后不把 RSS 还回来 —— 量到的是分配器行为，不是流表泄漏。churn 仍有价值：作为**参考值**
/// 连诊断一起打印（逻辑活跃条目始终为 0，说明不是逻辑泄漏，但进程 RSS 确实一直涨，
/// 这条同样是 007 要面对的事实）。
fn case_memory(flows: usize, rounds: usize, report: &mut Vec<Case>, per_flow: &mut Option<f64>) {
    let cap = flows;
    let cfg = FlowTableConfig {
        max_flows: cap * 2,
        shard_count: 16,
        policy: EvictPolicy::default(),
        ..Default::default()
    };
    let ks = keys(cap, 0x2468_ace0);
    let mut table = FlowTable::new(cfg);
    let rss_before = rss_bytes();
    for (i, k) in ks.iter().enumerate() {
        table.observe(&packet(*k, i as u64));
    }
    assert_eq!(table.stats().evictions, 0, "容量取 2×，填充阶段不该逐出");
    assert_eq!(table.len(), cap);
    let rss_full = rss_bytes();
    if let (Some(a), Some(b)) = (rss_before, rss_full) {
        // 每流常驻内存：填充后的 RSS 增量 ÷ 条目数。除条目本身，还含条目内嵌的
        // IAT 环形缓冲（Vec，容量 64×8B）与哈希桶开销 —— 这是选容量上限的依据。
        //
        // 结构下限是算得出来的：sizeof(FlowEntry) + IAT 容量 × 8B。实测值若低于它，
        // 说明这段 RSS 增量里有早前阶段释放后被复用的页，**这个实测值不可用**，
        // 必须显式标出来而不是照抄。
        let per_flow_lower = (std::mem::size_of::<FlowEntry>() + DEFAULT_IAT_CAPACITY * 8) as f64;
        let measured = (b.saturating_sub(a)) as f64 / cap as f64;
        if measured >= per_flow_lower * 0.5 {
            *per_flow = Some(measured);
        } else {
            eprintln!(
                "    [steady] 每流 RSS 增量 {measured:.0}B 低于结构下限 {per_flow_lower:.0}B \
                 （分配器复用了早前释放的页），该实测值不可用，已丢弃",
            );
        }
    }

    // 灌包：每轮把**每个**已有条目再打一次，共 rounds×容量 个包，全部命中已有条目。
    //
    // **判据是"逐轮增量"，不是"首尾差"**（本批修正）：条目内部的 IAT 环形缓冲是
    // 512B/条，填充阶段每条只写过第一个元素，剩下 63 个槽位的页要等到后续包才被触碰 ——
    // 于是第 1 轮的 RSS 会一次性抬高一个与容量成正比的量（实测 1M 条时 +182MiB），
    // 第 2 轮起就完全平了。那是"页第一次被触碰"，不是"内存随流量增长"；
    // 旧写法拿"填充后 → 灌完"作差，把这个一次性项算成增长，判据本身是错的
    // （旧实现凑巧为 0，是因为它前面的用例刚好把同尺寸的页都触碰过）。
    // 现在**预热一轮不计入判定**，再逐轮记录 RSS，判据取"预热后各轮增量的最大值"。
    // 原始序列整条打印出来，不藏。
    const BURST: u64 = 6;
    let mut series: Vec<u64> = Vec::new();
    let mut secs_total = 0.0f64;
    for round in 0..BURST {
        let t = Instant::now();
        for k in ks.iter() {
            table.observe(&packet(*k, (round + 1) * 1_000_000));
        }
        secs_total += t.elapsed().as_secs_f64();
        assert_eq!(table.len(), cap, "灌包阶段不该改变条目数");
        assert_eq!(table.stats().evictions, 0, "灌包阶段不该逐出");
        if let Some(r) = rss_bytes() {
            series.push(r);
        }
    }
    assert!(
        series.len() >= 3,
        "RSS 取不到时无法判定稳态（至少要有 3 个观测点）"
    );
    // series[0] 是预热轮的落点：它一次性包含了"首次触碰未触碰页"的量，不参与判定。
    let warm: Vec<u64> = series[1..].to_vec();
    let measured = warm
        .windows(2)
        .map(|w| mib(w[1].saturating_sub(w[0])))
        .fold(0.0f64, f64::max);
    let (measured, note) = if let Some(a) = rss_full {
        (
            measured,
            format!(
                "定容 {cap} 条后灌 {} 个包（{:.1} Mpps）；RSS 序列 {} ｜ 预热轮（第 1 轮，含首次触页）\
                 增量 +{:.0} MiB，**不计入判定**；预热后各轮增量最大 {measured:.0} MiB",
                cap as u64 * BURST,
                (cap as u64 * BURST) as f64 / secs_total / 1e6,
                series
                    .iter()
                    .map(|v| format!("{:.0}", mib(*v)))
                    .collect::<Vec<_>>()
                    .join(" "),
                mib(series[1].saturating_sub(a)),
            ),
        )
    } else {
        (
            table.len() as f64,
            format!("拿不到 RSS，退化为逻辑判据：灌包后条目数={}", table.len()),
        )
    };
    let packets = cap as u64 * BURST;
    eprintln!("    [steady] {note}");
    report.push(Case {
        name: "table-steady-memory",
        first: measured,
        measured,
        unit: "MiB Δ",
        target: STEADY_MEMORY_LIMIT_MIB,
        lower_is_better: true,
        floor: STEADY_MEMORY_LIMIT_MIB,
        derivation: "007 验收：定容后持续灌包，**预热后逐轮 RSS 增量** <16MiB（不随流量增长）",
    });

    let _ = packets;
    // ---- 参考值（不判定）：churn 的 RSS 序列与诊断。
    drop(table);
    let churn_cap = (cap / 4).max(1024);
    let churn_ks = keys(churn_cap, 0x1357_2468);
    let churn_cfg = FlowTableConfig {
        max_flows: churn_cap * 2,
        shard_count: 16,
        policy: EvictPolicy::default(),
        ..Default::default()
    };
    let mut churn = FlowTable::new(churn_cfg);
    let mut series = Vec::new();
    for round in 0..rounds.max(1) {
        for (i, k) in churn_ks.iter().enumerate() {
            churn.observe(&packet(*k, i as u64));
        }
        let expired = churn.expire(1_000_000_000_000);
        assert_eq!(expired, churn_cap, "第 {round} 轮：全部条目都该到期");
        assert_eq!(churn.len(), 0, "第 {round} 轮：逻辑活跃条目必须归零");
        if let Some(r) = rss_bytes() {
            series.push(r);
        }
    }
    if series.len() >= 2 {
        // 逐轮增量而不是平均：这个序列**不是**单调的（分配器会偶尔归还一批），
        // 拿首尾差算平均会把回落也平均进去，看着像"没涨"。
        let deltas: Vec<String> = series
            .windows(2)
            .map(|w| {
                // 直接算带符号的 MiB 差，别绕道 mib()（它收 u64，会把符号吃掉）。
                let d = (w[1] as f64 - w[0] as f64) / (1024.0 * 1024.0);
                format!("{d:+.0}")
            })
            .collect();
        eprintln!(
            "    [churn ] 每轮 {} 条「填满→全部到期」的 RSS(MiB): {} ｜ 逐轮增量: {}；\
             逻辑活跃条目始终为 0 → 不是逻辑泄漏（残余增量是分配器不归还小块内存）",
            churn_cap,
            series
                .iter()
                .map(|v| format!("{:.0}", mib(*v)))
                .collect::<Vec<_>>()
                .join(" "),
            deltas.join(" ")
        );
    }
}

/// 一次逐出探测：按分片填满到上限（填充阶段零逐出）→ 溢出 `n` 次
/// （每次必须**恰好**逐出一条）→ 返回（每次逐出的纳秒数，每次逐出考察的候选数）。
///
/// 填满之后才溢出，是为了让每条溢出插入都真的走逐出分支；填充阶段若发生逐出，
/// 测出来的就是"插入 + 逐出"的混合值。用公开的 `shard_of()` 按分片分组填充：
/// 容量是按分片均分的，随便插 `cap` 条会让部分分片超限、部分分片有空位。
fn evict_probe(per_shard_cap: usize, n_evict: usize, policy: EvictPolicy, seed: u64) -> (f64, f64) {
    let cap = per_shard_cap * 16;
    let cfg = FlowTableConfig {
        max_flows: cap,
        shard_count: 16,
        policy,
        ..Default::default()
    };
    let mut table = FlowTable::new(cfg);
    // 填充键与溢出键用不同的目的地址：保证溢出阶段的每个包都是**真插入**
    // （端口碰撞会把它变成 update，逐出就不会发生）。
    let mut per_shard: Vec<Vec<FlowKey>> = vec![Vec::new(); table.shard_count()];
    let mut filled = 0usize;
    for k in keys_to(cap * 4, seed, [10, 0, 0, 2]) {
        let sidx = table.shard_of(&k);
        if per_shard[sidx].len() < per_shard_cap {
            per_shard[sidx].push(k);
            filled += 1;
        }
        if filled == cap {
            break;
        }
    }
    assert_eq!(filled, cap, "每个分片都该被填到上限（填充键集不够用？）");
    let mut ts = 0u64;
    for ks in &per_shard {
        for k in ks {
            table.observe(&packet(*k, ts));
            ts += 1;
        }
    }
    assert_eq!(table.len(), cap);
    assert_eq!(
        table.stats().evictions,
        0,
        "填充阶段不该发生逐出（各分片恰好装满）"
    );

    let mut over: Vec<FlowKey> = Vec::new();
    for k in keys_to(n_evict * 4, seed ^ 0x5555_5555, [10, 9, 9, 9]) {
        over.push(k);
        if over.len() == n_evict {
            break;
        }
    }
    assert_eq!(over.len(), n_evict);
    let before = table.stats();
    let t = Instant::now();
    for (i, k) in over.iter().enumerate() {
        table.observe(&packet(*k, 1_000_000 + i as u64));
    }
    let secs = t.elapsed().as_secs_f64();
    debug_assert_eq!(table.len(), cap, "逐出后表仍应保持满");
    let after = table.stats();
    assert_eq!(
        after.evictions - before.evictions,
        n_evict as u64,
        "溢出阶段的每一次插入都必须触发恰好一次逐出"
    );
    let ns_per_evict = secs * 1e9 / n_evict as f64;
    let candidates_per_evict =
        (after.evict_candidates - before.evict_candidates) as f64 / n_evict as f64;
    (ns_per_evict, candidates_per_evict)
}

/// 逐出成本：两种「每分片容量」× 两种策略。
///
/// **为什么要专门测它**：表满之后**每一次新流插入都要逐出一条**，而表满恰恰是省网的
/// 稳态（1M 容量 / 60s 超时 ≈ 17k 次/s 的新建流）。所以逐出必须是常数代价。
/// 早先的实现用 `iter().min_by()` 全扫分片取全局最久未活动者（精确 LRU），
/// 每片 8192 时 55µs/次 —— 只够 18k 次/s，把整张表的吞吐上限钉死在新流速率的水平上。
///
/// 本 case 同时量**采样 LRU（默认，参与判定）**与**精确 LRU（对照，只报告）**：
/// 有了对照，"采样把成本降到与容量无关"这句话才是可核对的，而不是一句自我声明。
/// 另加一条与机器无关的判据 `table-evict-scale-ratio`：容量比 32× 下耗时比必须 ≈1。
fn case_evict(flows: usize, report: &mut Vec<Case>) {
    let n_evict = (flows / 50).clamp(2_000, 50_000);
    let mut sampled_pair = Vec::new();
    let mut exact_pair = Vec::new();
    for (label, per_shard_cap) in [("cap256", 256usize), ("cap8192", 8192usize)] {
        let (ns, cands) = evict_probe(per_shard_cap, n_evict, EvictPolicy::default(), 0x1111_0001);
        eprintln!(
            "    [evict] 链表 LRU {label}: 每分片容量 {per_shard_cap} → {ns:.0} ns/次逐出\
             （{:.2} M 次/s；每次考察 {cands:.1} 个候选）",
            1000.0 / ns
        );
        assert_eq!(
            cands, 0.0,
            "链表策略摘表头即可，**不该考察任何候选** —— 这就是 O(1) 的硬证据"
        );
        sampled_pair.push(ns);
        report.push(Case {
            name: if label == "cap256" {
                "table-evict-cap256"
            } else {
                "table-evict-cap8192"
            },
            first: ns,
            measured: ns,
            unit: "ns/evict",
            target: EVICT_TARGET_NS,
            lower_is_better: true,
            floor: if label == "cap256" {
                FLOOR_EVICT_NS
            } else {
                FLOOR_EVICT_BIG_NS
            },
            derivation: "表满后每次新建流都要逐出一条；目标 ≤500ns/次（≥2M 次/s）",
        });

        // 对照：精确 LRU 只在 cap256 上跑，8192 时它要 55µs/次 × n_evict ≈ 1 分钟，
        // 而它的结论（O(容量)）在 cap256 与 cap8192 的比值里已经很清楚。
        if per_shard_cap == 256 {
            let (ns_exact, cands_exact) =
                evict_probe(per_shard_cap, n_evict, EvictPolicy::LruScan, 0x3333_0003);
            eprintln!(
                "    [evict] 对照·扫描 LRU {label}: {ns_exact:.0} ns/次逐出（每次考察 \
                 {cands_exact:.0} 个候选）—— 这就是被替换掉的那条路径"
            );
            assert_eq!(
                cands_exact, per_shard_cap as f64,
                "扫描策略每次逐出要考察整片，这正是它的代价"
            );
            exact_pair.push(ns_exact);
        }
    }
    if sampled_pair.len() == 2 && sampled_pair[0] > 0.0 {
        let ratio = sampled_pair[1] / sampled_pair[0];
        eprintln!(
            "    [evict] 链表 LRU（默认）：容量比 32× → 耗时比 {ratio:.2}×\
             （与容量无关；扫描 LRU 会随容量线性增长，修前实测 52×）"
        );
        report.push(Case {
            name: "table-evict-scale-ratio",
            first: ratio,
            measured: ratio,
            unit: "×",
            target: EVICT_SCALE_RATIO_MAX,
            floor: EVICT_SCALE_RATIO_MAX,
            lower_is_better: true,
            derivation: "链表 LRU 摘表头即 O(1) ⇒ 逐出成本与每分片容量无关；容量 32× 下耗时比应 ≈1（修前 52×）",
        });
    }
    if exact_pair.len() == 1 && sampled_pair.len() == 1 && sampled_pair[0] > 0.0 {
        eprintln!(
            "    [evict] 对照结论：扫描 LRU {:.0} ns vs 链表 LRU {:.0} ns → 快 {:.0}×（每片 256）",
            exact_pair[0],
            sampled_pair[0],
            exact_pair[0] / sampled_pair[0]
        );
    }
}

fn case_feature(flows: usize, report: &mut Vec<Case>) {
    let mut rng = Rng::new(0x0f0f_0f0f);
    let lens: Vec<u32> = (0..flows).map(|_| 64 + rng.below(1400) as u32).collect();
    let (first, measured) = twice(|| {
        let mut fx = FeatureExtractor::new(64);
        for (i, len) in lens.iter().enumerate() {
            let side = if i % 2 == 0 { Side::A } else { Side::B };
            fx.observe(&FlowSample::len_only(side, *len, i as u64 * 100));
        }
        assert_eq!(fx.packets(), flows as u64);
        assert!(
            fx.vector().is_finite(),
            "特征向量必须有限，否则测的是 NaN 传播"
        );
    });
    report.push(Case {
        name: "feature-observe",
        first: flows as f64 / first / 1e6,
        measured: flows as f64 / measured / 1e6,
        unit: "Mops/s",
        target: PER_PACKET_TARGET_MOPS,
        lower_is_better: false,
        floor: FLOOR_FEATURE_MOPS,
        derivation: "特征更新在每包路径上，目标与流表同源（14.88Mpps）",
    });
}

fn case_reassembly(streams: usize, report: &mut Vec<Case>) {
    const SEG: usize = 32;
    const PAYLOAD: usize = 1400;
    let buf = vec![b'a'; PAYLOAD];

    // 顺序到达（稳态常见路径）。缓冲区提到循环外：段内容不影响被测逻辑，
    // 而每段新建一个 Vec 会把分配器成本算进重组吞吐里。
    let (first, measured) = twice(|| {
        let mut delivered = 0usize;
        for _ in 0..streams {
            let mut st = Stream::new(StreamConfig::default());
            st.on_syn(1000);
            for k in 0..SEG {
                let seq = 1001 + (k * PAYLOAD) as u32;
                st.feed(seq, &buf, false);
            }
            delivered += st.take_all().len();
        }
        assert_eq!(delivered, streams * SEG * PAYLOAD, "顺序流应全部交付");
    });

    // 逆序到达（乱序最坏情况）：段数受 max_buffered=64KiB 约束（16×1400=22.4KB）。
    const OOO_SEG: usize = 16;
    let (first_ooo, measured_ooo) = twice(|| {
        let mut delivered = 0usize;
        for _ in 0..streams {
            let mut st = Stream::new(StreamConfig::default());
            st.on_syn(1000);
            for k in (0..OOO_SEG).rev() {
                let seq = 1001 + (k * PAYLOAD) as u32;
                st.feed(seq, &buf, false);
            }
            delivered += st.take_all().len();
        }
        assert_eq!(
            delivered,
            streams * OOO_SEG * PAYLOAD,
            "乱序流在缓冲上限内应全部交付"
        );
    });

    report.push(Case {
        name: "reassembly-inorder",
        first: (streams * SEG * PAYLOAD) as f64 / first / 1e9,
        measured: (streams * SEG * PAYLOAD) as f64 / measured / 1e9,
        unit: "GB/s",
        target: LINE_RATE_10G_GBPS,
        lower_is_better: false,
        floor: FLOOR_REASSEMBLY_GBPS,
        derivation: "跟上 10Gbps 需净载荷 ≥1.25GB/s（顺序到达）",
    });
    report.push(Case {
        name: "reassembly-outoforder",
        first: (streams * OOO_SEG * PAYLOAD) as f64 / first_ooo / 1e9,
        measured: (streams * OOO_SEG * PAYLOAD) as f64 / measured_ooo / 1e9,
        unit: "GB/s",
        target: LINE_RATE_10G_GBPS,
        lower_is_better: false,
        floor: FLOOR_REASSEMBLY_OOO_GBPS,
        derivation: "同上；乱序 16 段/流（受 max_buffered 约束）",
    });
}

fn case_session(sessions: usize, report: &mut Vec<Case>) {
    // 每个会话 5 个包：SYN / SYN+ACK / ACK / DATA / FIN。这是建连密集场景的
    // 最坏形态（短连接），比长连接更能暴露每会话的固定开销。
    let packets = (sessions * 5) as f64;
    let (first, measured) = twice(|| {
        let mut mgr = SessionManager::new(SessionConfig {
            max_sessions: sessions + 16,
            ..Default::default()
        });
        let syn = TcpObservation::no_payload(TcpFlags {
            syn: true,
            ..Default::default()
        });
        let synack = TcpObservation::no_payload(TcpFlags {
            syn: true,
            ack: true,
            ..Default::default()
        });
        let ack = TcpObservation::no_payload(TcpFlags {
            ack: true,
            ..Default::default()
        });
        let data = TcpObservation::new(
            TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            300,
        );
        let fin = TcpObservation::no_payload(TcpFlags {
            ack: true,
            fin: true,
            ..Default::default()
        });
        for s in 0..sessions {
            let a = ((s >> 16) & 0xff) as u8;
            let b = ((s >> 8) & 0xff) as u8;
            let c = (s & 0xff) as u8;
            let port = 40000 + (s % 20000) as u16;
            let fwd = FlowKey::new_ipv4([10, a, b, c], port, [10, 0, 0, 2], 80, IPPROTO_TCP);
            let rev = FlowKey::new_ipv4([10, 0, 0, 2], 80, [10, a, b, c], port, IPPROTO_TCP);
            let t = s as u64 * 1000;
            mgr.observe(&packet(fwd, t), Some(&syn));
            mgr.observe(&packet(rev, t + 100), Some(&synack));
            mgr.observe(&packet(fwd, t + 200), Some(&ack));
            mgr.observe(&packet(fwd, t + 300), Some(&data));
            mgr.observe(&packet(fwd, t + 400), Some(&fin));
        }
        assert_eq!(mgr.stats().packets, packets as u64);
        assert_eq!(mgr.session_count(), sessions, "每一个会话都必须被建出来");
    });
    report.push(Case {
        name: "session-tcp-short",
        first: packets / first / 1e6,
        measured: packets / measured / 1e6,
        unit: "Mpps",
        target: PER_PACKET_TARGET_MOPS,
        lower_is_better: false,
        floor: FLOOR_SESSION_MPPS,
        derivation: "会话层在每包路径上；5 包/会话为短连接最坏形态",
    });
}

// ------------------------------------------- IPFIX 采集解码（CYS-INF-040 的"每台 N 记录/秒"）

/// 造一条 IPv4 流记录（基准语料，不走数据面）。
fn bench_record(i: usize) -> FlowRecord {
    let a = ((i >> 16) & 0xff) as u8;
    let b = ((i >> 8) & 0xff) as u8;
    let c = (i & 0xff) as u8;
    FlowRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        session_id: i as u64 + 1,
        key: FlowKey::new_ipv4(
            [10, a, b, c],
            1024 + (i % 60000) as u16,
            [10, 0, 0, 2],
            80,
            6,
        ),
        tcp_state: None,
        initiator: None,
        adopted_midstream: false,
        illegal_tcp_events: 0,
        first_seen_us: 1_700_000_000_000_000 + i as u64 * 1000,
        last_seen_us: 1_700_000_000_001_000 + i as u64 * 1000,
        packets: 10,
        bytes: 1500,
        direction_switches: 0,
        features: FeatureVector {
            schema_version: FEATURE_SCHEMA_VERSION,
            values: [0f64; FEATURE_COUNT],
        },
        app: AppInfo::not_inspected(),
        risk_score: None,
    }
}

/// 采集解码吞吐：把**生产编码器**产出的真实 IPFIX 报文喂给采集器，只对解码计时。
///
/// 两个口径必须说清，否则这个数会被误用：
/// ① 语料构造（`encode_batch`）放在计时之外 —— 线上导出在**另一个进程**里，
///    把它计进来等于把导出成本算两遍；
/// ② 这是**纯内存**解码吞吐（无 socket、无 pcap 读盘、无 dedup 命中之外的系统调用），
///    是"每台采集器解码能力的上界"，不是端到端吞吐。端到端要另减收包/写盘成本，
///    容量模型里用余量系数把它折下来（见 §2.13）。
fn case_ipfix_collector(records: usize, report: &mut Vec<Case>) {
    let cfg = ExportConfig {
        max_msg_bytes: 1400,
        template_refresh_msgs: 64,
        sampling_interval: 1,
        ..Default::default()
    };
    let mut enc = Encoder::new(cfg).expect("基准：导出器配置必须合法");
    let recs: Vec<FlowRecord> = (0..records).map(bench_record).collect();
    // 分批发：一次 4096 条，避免单报文超过 max_msg_bytes（编码器自己会切）。
    let messages: Vec<Vec<u8>> = recs
        .chunks(4096)
        .flat_map(|chunk| enc.encode_batch(chunk, 1_700_000_000).expect("基准：编码"))
        .collect();
    let exporter = ExporterId {
        ip: "10.0.0.1".parse().expect("基准：固定地址"),
        port: 4739,
    };
    assert!(!messages.is_empty(), "基准：必须真的产生报文");

    let (first, measured) = twice(|| {
        let mut c = Collector::new(CollectorConfig::default());
        let mut t = 0u64;
        for m in &messages {
            t += 1;
            c.on_datagram(exporter, m, t);
        }
        // 断言不能省：解码吞吐只有在"记录真的被解出来"时才有意义，
        // 否则一个把记录全丢掉的实现会跑出最好看的数字。
        let st = c.stats();
        assert_eq!(
            st.delivered_records as usize, records,
            "基准：必须所有记录都被交付（data_records={} duplicates={} malformed={}）",
            st.data_records, st.duplicate_records, st.malformed_datagrams
        );
        assert_eq!(st.loss_ppm(), 0, "基准：同一条流连续投递，不应报出缺口");
    });
    report.push(Case {
        name: "ipfix-collect-decode",
        first: records as f64 / first / 1e6,
        measured: records as f64 / measured / 1e6,
        unit: "Mrec/s",
        target: COLLECTOR_TARGET_MREC_S,
        lower_is_better: false,
        floor: FLOOR_COLLECTOR_MREC_S,
        derivation: "容量模型：20Tbps×1:1000 ⇒ 5 M记录/s（上界），单台需 ≥1 M",
    });
}

// ---------------------------------------------------------------- 输出

fn print_table(cases: &[Case], factor: f64, report_only: bool) {
    println!(
        "{:<24} {:>10} {:<13} {:>10} {:<13} {:>7} {:>6}  {}",
        "case", "measured", "unit", "target", "unit", "需求", "回归", "derivation"
    );
    for c in cases {
        // factor 只用于反向故障注入：把两个阈值一起抬高。
        let target = c.target * factor;
        let (meets, holds) = (c.passed(factor), !c.regressed(factor));
        let (req, base) = if report_only {
            ("REPORT", "REPORT")
        } else {
            (
                if meets { "达标" } else { "未达标" },
                if holds { "正常" } else { "退步" },
            )
        };
        println!(
            "{:<24} {:>10.2} {:<13} {:>10.2} {:<13} {:>7} {:>6}  {}",
            c.name, c.measured, c.unit, target, c.unit, req, base, c.derivation
        );
    }
}

fn print_json(cases: &[Case], factor: f64, report_only: bool) {
    for c in cases {
        let target = c.target * factor;
        let floor = c.floor * factor;
        let (meets, holds) = (c.passed(factor), !c.regressed(factor));
        println!(
            "{{\"case\":\"{}\",\"first\":{:.3},\"measured\":{:.3},\"unit\":\"{}\",\"target\":{:.3},\"floor\":{:.3},\"lower_is_better\":{},\"meets_target\":{},\"holds_floor\":{}}}",
            c.name,
            c.first,
            c.measured,
            c.unit,
            target,
            floor,
            c.lower_is_better,
            if report_only { "null" } else if meets { "true" } else { "false" },
            if report_only { "null" } else if holds { "true" } else { "false" }
        );
    }
}

/// 多实例分核实验的原始数据。
///
/// 表格里已经有每个档位的判定，这里补的是**过程**：聚合怎么随线程数长、
/// 效率比值、以及"按单核吞吐折算需要几个核才能顶住一个 10G 口"。
fn print_scaling(r: &ScalingReport, per_flow: Option<f64>) {
    println!(
        "\n多实例分核实验：每核一张独立 FlowTable，负载 = 稳态 update（每实例 {} 条{}）",
        r.per_thread,
        if r.serialized {
            "；**串行档（共享一张表 + 互斥锁，仅供反向故障注入）**"
        } else {
            ""
        }
    );
    println!(
        "  {:<8} {:>14} {:>16} {:>12}",
        "线程数", "聚合吞吐", "每线程吞吐", "扩展效率"
    );
    for (n, aggregate, eff) in &r.tiers {
        println!(
            "  {:<8} {:>10.2} Mops/s {:>12.2} Mops/s {:>10.2}×",
            n,
            aggregate,
            aggregate / *n as f64,
            eff
        );
    }
    let single = r.tiers.first().map(|(_, a, _)| *a).unwrap_or(f64::NAN);
    println!(
        "  本机可用并行度 {}；顶住一个 10G 口：按单核实测折算 {} 核，\
         含 1.5× 工程余量后取实测档位 {} 核",
        r.ap,
        (PER_PACKET_TARGET_MOPS / single).ceil().max(1.0),
        r.cores_for_10g
    );
    println!("  扩展效率的分母用 min(线程数, 可用并行度)：核数不足时报的是机器限制，不是设计缺陷");
    let (top_n, top_agg, top_eff) = *r.tiers.last().expect("至少一个档位");
    println!(
        "  纯计算对照（同样 {top_n} 线程、同样操作次数，只做寄存器运算）：扩展效率 {:.2}×；\
         流表 {:.2}× → 比值 {:.2}×（判据项 table-scaling-vs-ceiling）",
        r.ceiling_eff, top_eff, r.ceiling_ratio
    );
    if let Some((small, agg, eff, small_single)) = r.cache_fit {
        let threads = r.tiers.last().map(|(n, _, _)| *n).unwrap_or(1);
        let scale = match per_flow {
            Some(b) => format!(
                "总工作集约 {:.0} MB",
                small as f64 * threads as f64 * b / 1e6
            ),
            // 每流内存实测值在某些运行中会被判为不可用（分配器复用页面），此时不编数字。
            None => "工作集远小于 L2".to_string(),
        };
        let small_per = agg / threads as f64;
        let large_per = top_agg / threads as f64;
        println!(
            "  对照（归因）：同样 {threads} 线程、但每实例仅 {small} 条（{scale}）：\
             聚合 {agg:.2} Mops/s、每线程 {small_per:.2} Mops/s、效率 {eff:.2}×",
        );
        // 只报事实，不给因果结论：两个因素（机器级并发上限、工作集/访存）都在，
        // 各自占多少需要更细的实验，这里把可复核的数字摆出来即可。
        println!(
            "    → 每线程吞吐：大工作集 {large_per:.2} vs 小工作集 {small_per:.2} Mops/s（{:+.0}%）；\
             各自相对**自身**单线程：大 {:.2}×、小 {:.2}×",
            (small_per - large_per) / large_per * 100.0,
            large_per / single,
            small_per / small_single
        );
    }
}

/// 未达需求目标的项（`factor` 只用于故障注入，与 `Case::passed` 同源）。
fn unmet<'a>(cases: &'a [Case], factor: f64) -> Vec<&'a Case> {
    cases.iter().filter(|c| !c.passed(factor)).collect()
}

/// 相对回归下限退步的项（与 `Case::regressed` 同源）。
fn regressions<'a>(cases: &'a [Case], factor: f64) -> Vec<&'a Case> {
    cases.iter().filter(|c| c.regressed(factor)).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut flows = 1_000_000usize;
    let mut rounds = 5usize;
    let mut json = false;
    let mut report_only = false;
    let mut require_targets = false;
    let mut factor = 1.0f64;
    // 仅供反向故障注入：把多实例实验换成"共享一张表 + 锁"的串行形态。
    let mut inject_serialized = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!("用法: cythsec-bench [--flows N] [--rounds R] [--json] [--report-only] [--target-factor F]");
                println!("  --flows N          规模（默认 1000000；冒烟用 100000）");
                println!("  --rounds R         内存平台期轮数（默认 5）");
                println!("  --json             逐行 JSON 输出");
                println!("  --report-only      只报告不判定");
                println!("  --require-targets  退出码由**需求目标**决定（默认由回归下限决定）");
                println!("  --target-factor F  两个阈值都乘以 F（仅供反向故障注入）");
                println!(
                    "  --inject-serialized-scaling\n                     \
                     把多实例实验换成「所有线程抢一张表 + 互斥锁」，\n                     \
                     要求扩展性判据判出失败（仅供反向故障注入）"
                );
                return;
            }
            "--flows" => flows = next_usize(&args, &mut i),
            "--rounds" => rounds = next_usize(&args, &mut i),
            "--json" => json = true,
            "--report-only" => report_only = true,
            "--require-targets" => require_targets = true,
            "--target-factor" => factor = next_f64(&args, &mut i),
            "--inject-serialized-scaling" => inject_serialized = true,
            other => {
                eprintln!("未知参数: {other}（--help 查看用法）");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    if flows < 1000 {
        eprintln!("--flows 至少 1000（否则测的是计时器噪声）");
        std::process::exit(2);
    }
    if factor <= 0.0 {
        eprintln!("--target-factor 必须为正");
        std::process::exit(2);
    }

    let t0 = Instant::now();
    let mut cases = Vec::new();
    let mut per_flow = None;
    eprintln!("cythsec-bench flows={flows} rounds={rounds}（每项跑两遍，判定用第二遍）");
    // 未优化的构建会把每个操作放大 10~50 倍，此时报出来的"未达标"毫无意义 ——
    // 明确警告，而不是让人拿 debug 数字去写结论。
    if cfg!(debug_assertions) {
        eprintln!(
            "⚠ 这是 debug 构建：数字被放大 10~50 倍，判定不具参考价值。\
             请用 cargo build --release，或 bash scripts/verify/check-flow-bench.sh"
        );
    }
    case_table(flows, &mut cases);
    case_feature(flows, &mut cases);
    case_reassembly((flows / 100).max(1000), &mut cases);
    case_session((flows / 10).max(1000), &mut cases);
    // 采集解码：容量模型（§2.13）里"每台 N 记录/秒"的实测出处。
    case_ipfix_collector((flows / 2).clamp(200_000, 4_000_000), &mut cases);
    case_evict(flows, &mut cases);
    case_memory(flows, rounds, &mut cases, &mut per_flow);
    // 放在内存用例**之后**：多实例实验会一次性申请 ~1.5GB 表，跑在前面会让
    // `table-steady-memory` 的每流 RSS 增量被分配器复用污染（实测值直接不可用）。
    // 顺序在这里是有语义的，不是排版问题。
    let scaling = case_multi_instance(flows, &mut cases, inject_serialized);

    if json {
        print_json(&cases, factor, report_only);
        if let Some(v) = per_flow {
            println!("{{\"case\":\"residency\",\"bytes_per_flow\":{v:.1}}}");
        }
    } else {
        print_table(&cases, factor, report_only);
        print_scaling(&scaling, per_flow);
        if let Some(v) = per_flow {
            let lower = (std::mem::size_of::<FlowEntry>() + DEFAULT_IAT_CAPACITY * 8) as f64;
            println!(
                "\n每条流常驻内存：结构下限 {lower:.0} B（条目 {entry}B + IAT 环形 {iat}B），\
                 实测含哈希桶 {v:.0} B/条（RSS 增量 ÷ 条数；规模越大越准）",
                entry = std::mem::size_of::<FlowEntry>(),
                iat = DEFAULT_IAT_CAPACITY * 8
            );
        }
        println!(
            "总耗时 {:.1}s；目标值为**需求推导**（10Gbps 线速 / 扫描预算），非第三方核验事实",
            t0.elapsed().as_secs_f64()
        );
    }

    if report_only {
        return;
    }
    let missed = unmet(&cases, factor);
    let regressed = regressions(&cases, factor);
    eprintln!(
        "cythsec-bench 需求目标：达成 {}/{}（未达成 {} 项 —— 这是当前真实水平，用于排优先级，不代表代码坏了）",
        cases.len() - missed.len(),
        cases.len(),
        missed.len()
    );
    for c in &missed {
        eprintln!(
            "cythsec-bench 未达标 case={} measured={:.2}{} target={:.2}{}（{}）",
            c.name,
            c.measured,
            c.unit,
            c.target * factor,
            c.unit,
            c.derivation
        );
    }
    if regressed.is_empty() {
        eprintln!(
            "cythsec-bench 回归下限：{}/{} 全部通过",
            cases.len(),
            cases.len()
        );
    } else {
        for c in &regressed {
            eprintln!(
                "cythsec-bench REGRESSION case={} measured={:.2}{} floor={:.2}{}",
                c.name,
                c.measured,
                c.unit,
                c.floor * factor,
                c.unit
            );
        }
        eprintln!(
            "cythsec-bench 回归下限：退步 {}/{}",
            regressed.len(),
            cases.len()
        );
    }
    // 默认退出码只看"有没有退步"：把"这版变慢了"和"这版不达标"混成一个码，
    // 只会让人分不清该修哪个。要拿需求目标当门禁就显式加 --require-targets。
    let hard = if require_targets { &missed } else { &regressed };
    if !hard.is_empty() {
        std::process::exit(1);
    }
}

fn next_usize(args: &[String], i: &mut usize) -> usize {
    *i += 1;
    let v = args.get(*i).unwrap_or_else(|| {
        eprintln!("缺少参数值");
        std::process::exit(2);
    });
    v.parse().unwrap_or_else(|_| {
        eprintln!("不是合法整数: {v}");
        std::process::exit(2);
    })
}

fn next_f64(args: &[String], i: &mut usize) -> f64 {
    *i += 1;
    let v = args.get(*i).unwrap_or_else(|| {
        eprintln!("缺少参数值");
        std::process::exit(2);
    });
    v.parse().unwrap_or_else(|_| {
        eprintln!("不是合法小数: {v}");
        std::process::exit(2);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_is_deterministic_and_not_constant() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        let xs: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let ys: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        assert_eq!(xs, ys, "同种子必须同序列，否则基准不可复现");
        assert!(xs.windows(2).all(|w| w[0] != w[1]), "序列不能是常量");
    }

    #[test]
    fn keys_are_unique_and_deterministic() {
        let a = keys(10_000, 7);
        let b = keys(10_000, 7);
        assert_eq!(a, b);
        let mut set = std::collections::HashSet::new();
        for k in &a {
            assert!(set.insert(*k), "生成的键必须互不相同，否则插入数会被高估");
        }
        // 目的地址不同 ⇒ 两个键集不相交（miss 用例就是靠这一点保证"真的查不到"）
        let other = keys_to(10_000, 7, [10, 0, 0, 3]);
        assert!(set.is_disjoint(&other.iter().copied().collect()));
    }

    #[test]
    fn targets_match_their_derivation() {
        // 10Gbps / (64*8) = 14,880,952 pps。把这两个数写死，是为了让"改目标值"
        // 必须连着改推导一起改 —— 目标值是这个基准唯一的"期望"，不能随手改。
        assert!((LINE_RATE_10G_64B_PPS - 14_880_952.38).abs() < 1.0);
        assert!((PER_PACKET_TARGET_MOPS - 14.880_952).abs() < 0.001);
        assert!((LINE_RATE_10G_GBPS - 1.25).abs() < 1e-9);
        // 新建流速率目标必须明显低于每包速率，否则就是把包速率当流速率用。
        assert!(NEW_FLOW_TARGET_MOPS < PER_PACKET_TARGET_MOPS / 10.0);
    }

    #[test]
    fn floors_are_never_stricter_than_targets() {
        // 回归下限只能比需求目标宽松，否则"未达标"会被报成"退步"，
        // 门禁就会天天红，红到没人看。
        let higher_better = [
            ("insert", NEW_FLOW_TARGET_MOPS, FLOOR_INSERT_MOPS),
            ("update", PER_PACKET_TARGET_MOPS, FLOOR_LOOKUP_MOPS),
            ("miss", PER_PACKET_TARGET_MOPS, FLOOR_MISS_MOPS),
            ("expire", EXPIRE_TARGET_M_ENTRIES, FLOOR_EXPIRE_M_ENTRIES),
            ("feature", PER_PACKET_TARGET_MOPS, FLOOR_FEATURE_MOPS),
            ("reassembly", LINE_RATE_10G_GBPS, FLOOR_REASSEMBLY_GBPS),
            (
                "reassembly-ooo",
                LINE_RATE_10G_GBPS,
                FLOOR_REASSEMBLY_OOO_GBPS,
            ),
            ("session", PER_PACKET_TARGET_MOPS, FLOOR_SESSION_MPPS),
            (
                "steady-memory",
                STEADY_MEMORY_LIMIT_MIB,
                STEADY_MEMORY_LIMIT_MIB,
            ),
            (
                "scaling-vs-ceiling",
                SCALING_VS_CEILING_MIN,
                FLOOR_SCALING_VS_CEILING,
            ),
        ];
        for (name, target, floor) in higher_better {
            assert!(
                floor <= target,
                "{name}: floor={floor} 应 ≤ target={target}"
            );
        }
        // 每个线程档位的聚合下限（封顶到需求目标后）必须 ≤ 需求目标，
        // 否则"未达标"会被同时报成"退步"（同一条红线）。
        for (n, name) in MULTI_INSTANCE_TIERS {
            let floor = (FLOOR_STEADY_PER_CORE_MOPS * n as f64).min(PER_PACKET_TARGET_MOPS);
            assert!(
                floor <= PER_PACKET_TARGET_MOPS,
                "{name}: floor={floor} 应 ≤ target={PER_PACKET_TARGET_MOPS}"
            );
        }
        let lower_better = [
            ("evict", EVICT_TARGET_NS, FLOOR_EVICT_NS),
            ("evict-big", EVICT_TARGET_NS, FLOOR_EVICT_BIG_NS),
        ];
        for (name, target, floor) in lower_better {
            assert!(
                floor >= target,
                "{name}: 越小越好的项 floor={floor} 应 ≥ target={target}"
            );
        }
    }

    #[test]
    fn rss_is_available_on_this_platform() {
        // 拿不到会退化为逻辑判据（不算失败），但这台机器上应该有。
        assert!(rss_bytes().unwrap_or(0) > 0, "应能读到本进程 RSS");
    }

    #[test]
    fn two_tiers_are_judged_independently() {
        let base = Case {
            name: "x",
            first: 1.0,
            measured: 9.0,
            unit: "Mops/s",
            target: 10.0,
            floor: 4.0,
            lower_is_better: false,
            derivation: "t",
        };
        // 未达目标但高于回归下限：达标判定为假、退步判定也为假 —— 两者必须分得开。
        assert!(!base.passed(1.0));
        assert!(!base.regressed(1.0));
        assert_eq!(unmet(std::slice::from_ref(&base), 1.0).len(), 1);
        assert!(regressions(std::slice::from_ref(&base), 1.0).is_empty());
        let at_target = Case {
            measured: 10.0,
            ..base
        };
        assert!(
            at_target.passed(1.0),
            "等于目标值算达标（用 >= / <= 而不是 > / <）"
        );
        assert!(unmet(std::slice::from_ref(&at_target), 1.0).is_empty());
        let slow = Case {
            measured: 3.9,
            ..base
        };
        assert!(slow.regressed(1.0), "低于回归下限就是退步");
        assert_eq!(regressions(std::slice::from_ref(&slow), 1.0).len(), 1);
        // 越小越好的方向必须反过来判
        let mem_ok = Case {
            measured: 3.0,
            target: 16.0,
            floor: 16.0,
            lower_is_better: true,
            ..at_target
        };
        assert!(mem_ok.passed(1.0));
        assert!(!mem_ok.regressed(1.0));
        let mem_bad = Case {
            measured: 40.0,
            ..mem_ok
        };
        assert!(!mem_bad.passed(1.0));
        assert!(mem_bad.regressed(1.0));
        // 故障注入用的放大系数必须真的能把"正常"变成"退步"
        assert_eq!(regressions(std::slice::from_ref(&base), 1000.0).len(), 1);
    }

    #[test]
    fn twice_measures_the_second_run() {
        let mut n = 0;
        let (_first, _second) = twice(|| n += 1);
        assert_eq!(n, 2, "twice 必须真的跑两遍");
    }

    /// 扩展效率的算法本身：分母是 `min(线程数, 可用并行度)`，不是线程数。
    #[test]
    fn scaling_efficiency_normalizes_by_usable_cores() {
        // 8 线程跑在 10 核上 → 分母 8；聚合 8× 单线程 = 完美线性 = 1.0
        assert!((scaling_efficiency(8.0 * 5.0, 5.0, 8, 10) - 1.0).abs() < 1e-9);
        // 4 核机器上跑 8 线程 → 分母是 4（核数不足是机器限制，不该算成设计缺陷）
        assert!((scaling_efficiency(4.0 * 5.0, 5.0, 8, 4) - 1.0).abs() < 1e-9);
        // 共享锁形态：8 线程却只有单线程吞吐 → 0.125，必须低于回归下限
        let serialized = scaling_efficiency(5.0, 5.0, 8, 10);
        assert!((serialized - 0.125).abs() < 1e-9);
        assert!(
            serialized < FLOOR_SCALING_VS_CEILING,
            "串行化的效率必须落在回归下限之下，否则判据抓不住它"
        );
        // 可用并行度取不到时按 1 处理，不能除零
        assert!(scaling_efficiency(1.0, 1.0, 4, 0).is_finite());
    }

    /// 核数预算：取**最小达标档位**（含 1.5× 工程余量），不够时才外推。
    #[test]
    fn cores_for_line_rate_picks_the_smallest_tier_with_margin() {
        let need = PER_PACKET_TARGET_MOPS * CORES_ENGINEERING_MARGIN;
        assert!(need > PER_PACKET_TARGET_MOPS, "工程余量必须真的放大预算");
        // 2 核已达 14.88 但不足 1.5×余量 → 应取 4 核
        let tiers = vec![
            (1, 8.0, 1.0),
            (2, 15.0, 0.9),
            (4, 24.0, 0.8),
            (8, 34.0, 0.5),
        ];
        assert_eq!(cores_for_line_rate(&tiers), 4.0);
        // 2 核就超过余量 → 取 2
        let fast = vec![
            (1, 20.0, 1.0),
            (2, 40.0, 1.0),
            (4, 70.0, 0.9),
            (8, 90.0, 0.6),
        ];
        assert_eq!(cores_for_line_rate(&fast), 2.0);
        // 所有档位都不够 → 按最高档每线程吞吐外推（乐观下界），且必须是有限正数
        let slow = vec![(1, 1.0, 1.0), (2, 1.5, 0.8), (4, 2.0, 0.5), (8, 2.4, 0.3)];
        let c = cores_for_line_rate(&slow);
        assert!(c.is_finite() && c > 8.0, "外推结果 {c} 应大于最大档位");
    }

    /// **判据的判据**：把流表实验换成"共享一张表 + 互斥锁"的形态，
    /// 扩展性判据必须判出失败。没有这一步，绿色的"扩展性良好"与绿色的"压根没测"
    /// 无法区分 —— 这也是 `check-flow-bench.sh --inject-serialized-scaling` 的单元级对应物。
    #[test]
    fn serialized_table_is_flagged_as_not_scaling() {
        let ap = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if ap < 2 {
            return; // 单核机器上"串行"与"并行"本来就同速，测不了
        }
        const PER: usize = 20_000;
        let n = 4.min(ap);
        let mut parallel: Vec<Instance> = (0..n)
            .map(|i| build_instance(PER, 0x5a01_0000 + i as u64))
            .collect();
        // 并行档：N 个独立表
        let ops = PER * n;
        let (_, d_par) = twice(|| {
            parallel_duration(&mut parallel, n);
        });
        let par_agg = ops as f64 / d_par / 1e6;
        let par_eff = scaling_efficiency(par_agg, par_agg / n as f64, n, ap);
        // 串行档：同一批键，但共用一张表 + 互斥锁。
        // 容量按**顶档**给：否则顶档那一段会因为表太小而付逐出代价，把"锁竞争"
        // 与"容量不足"混在一起 —— 那是两件不同的事。
        let mut shared = FlowTable::new(FlowTableConfig {
            max_flows: PER * 8 * 2,
            shard_count: 16,
            ..Default::default()
        });
        for inst in &parallel {
            for (i, k) in inst.ks.iter().enumerate() {
                shared.observe(&packet(*k, i as u64));
            }
        }
        let shared = Mutex::new(shared);
        let (_, d_ser) = twice(|| {
            serialized_duration(&parallel, n, &shared);
        });
        let ser_agg = ops as f64 / d_ser / 1e6;
        // 串行档的单线程基准：用 1 线程跑同一把锁
        let (_, d_ser1) = twice(|| {
            serialized_duration(&parallel, 1, &shared);
        });
        let ser_single = PER as f64 / d_ser1 / 1e6;
        let ser_eff = scaling_efficiency(ser_agg, ser_single, n, ap);
        // **机器无关**的断言：竞争必须让它变差（任何核数都成立）。
        assert!(
            ser_eff < par_eff,
            "串行形态的效率（{ser_eff:.2}）必须低于并行形态（{par_eff:.2}）"
        );
        // 「效率比值跌到回归下限之下」**只在核数足够时**才成立：竞争要在多个核上
        // 同时抢锁才会把比值压垮，2 核机器根本表达不出来（2026-10-05 在 2 vCPU 的
        // Rocky aarch64 虚机上实测：10 核上比值 0.05~0.10，2 核上 0.33 > 下限 0.25）。
        // 硬断言会把"机器小"报成"判据坏" —— 那正是本仓库反复强调的假红。
        if ap >= 4 {
            assert!(
                ser_eff < FLOOR_SCALING_VS_CEILING,
                "核数充足（ap={ap}）时串行形态的效率 {ser_eff:.2} 必须低于回归下限 \
                 {FLOOR_SCALING_VS_CEILING}；否则判据无法把它与「有共享瓶颈」区分开"
            );
        }
        // 兜底判据（与门禁实际用的一致）：串行档在**顶档**的聚合吞吐必须低于该档下限。
        // 这条与核数无关 —— 下限按 `档位 × 每核下限` 线性给，核数不足时它只会更宽松，
        // 而共享锁是"多核也上不去"，所以各档聚合下限才是拦得住的那种判据。
        const TOP: usize = 8;
        let mut top_insts: Vec<Instance> = (0..TOP)
            .map(|i| build_instance(PER, 0x7c01_0000 + i as u64))
            .collect();
        let top_ops = PER * TOP;
        let (_, d_top) = twice(|| {
            serialized_duration(&top_insts, TOP, &shared);
        });
        let top_agg = top_ops as f64 / d_top / 1e6;
        let top_floor = (FLOOR_STEADY_PER_CORE_MOPS * TOP as f64).min(PER_PACKET_TARGET_MOPS);
        assert!(
            top_agg < top_floor,
            "串行档在 {TOP} 线程的聚合 {top_agg:.2} Mops/s 必须低于该档回归下限 {top_floor:.2}\
             （共享锁的特征就是多核也上不去）"
        );
    }

    /// 纯计算对照必须真的做满那么多次运算（否则它可以被优化成空循环，
    /// "机器上限"就会被高估，比值随之失真）。
    #[test]
    fn ceiling_control_does_real_work() {
        let small = ceiling_duration(200_000, 1);
        let large = ceiling_duration(4_000_000, 1);
        assert!(
            large > small,
            "运算量 ×20 后耗时应明显更长（{small:.6}s → {large:.6}s），说明循环没被优化掉"
        );
    }

    /// 档位表与门禁用例数清单的耦合：新增档位必须同步 `EXPECTED_CASES`。
    #[test]
    fn tier_count_matches_the_gate_expectation() {
        assert_eq!(
            MULTI_INSTANCE_TIERS.len(),
            4,
            "档位数变了 → 必须同步 scripts/verify/check-flow-bench.sh 的 EXPECTED_CASES"
        );
        for (n, name) in MULTI_INSTANCE_TIERS {
            assert!(
                name.starts_with("table-"),
                "档位名 {name} 必须被门禁的计数规则匹配"
            );
            assert!(n >= 1);
        }
    }

    #[test]
    fn packet_builder_sets_timestamp() {
        let k = keys(1, 1)[0];
        let p = packet(k, 12345);
        assert_eq!(p.timestamp_us, 12345);
        assert_eq!(p.payload_len, 64);
    }
}
