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
//! 1. **稳态查表够不上 10G 最坏情况**（未修）：1M 条规模下 update 约 5.7 Mops/s、
//!    query-hit 约 7.6 Mops/s，只有 14.88 Mpps 需求的一半。单实例流表要跑到 10G
//!    最小帧线速，需要多实例分核（每核独立表）或缩小每条目内存（实测 1.5KB/条）。
//! 2. **逐出成本 O(每分片容量)**（未修）：`evict_lru` 每次逐出全扫分片，
//!    容量 32× → 耗时 55×，实测 1.0 µs/次（每片 256）与 55 µs/次（每片 8192）。
//!    表满后每一次新建流都要付这个代价，而表满恰恰是稳态。
//! 3. **`expire()` 的 O(n) 临时数组**（本批已修）：旧实现把全部到期条目搬进
//!    `Vec<FlowEntry>`（每条 432B）再派发，实测每轮「填满→全部到期」让 RSS 抬升
//!    `条目数 × 432B`（250k 条 → +99MiB/轮）且不保证回落，违反 007 的"内存稳定"。
//!    改为只收键、按键序逐条删除并派发后：RSS 增量降到 +6MiB/轮，
//!    超时扫描吞吐 1.62 → 2.50 M entries/s。回调顺序（全局按键升序）不变。
//!
//! ## 用法
//!
//! ```text
//! cythsec-bench [--flows N] [--rounds R] [--json] [--report-only] [--target-factor F]
//! ```
//!
//! - 默认 `--flows 1000000`；机器慢或只做冒烟时用 `--flows 100000`。
//! - 每个 case 跑两遍，**只把第二遍计入判定**（第一遍含页分配、分支预测与 `HashMap`
//!   扩容的冷启动；两遍都打印，便于人工判断抖动）。
//! - `--target-factor F` 把全部目标值乘以 F：**仅供反向故障注入使用** ——
//!   `check-flow-bench.sh --self-test` 用它把目标抬到不可能达到的高度，要求本程序
//!   **必须退出非零**。若一次"不可能达标"的运行仍然报通过，就说明这里的判定是摆设。
//! - `--report-only` 只报告不判定（排查用；正式验收不要用）。
//!
//! 退出码：0 全部达标；1 有未达标项；2 参数错误。

use std::process::Command;
use std::time::Instant;

use traffic_engine::feature::{FeatureExtractor, FlowSample};
use traffic_engine::flow::stats::DEFAULT_IAT_CAPACITY;
use traffic_engine::flow::table::{EvictPolicy, FlowEntry, FlowTable, FlowTableConfig};
use traffic_engine::flow::{FlowKey, Packet, IPPROTO_TCP};
use traffic_engine::reassembly::stream::{Stream, StreamConfig};
use traffic_engine::reassembly::tcp::TcpFlags;
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
/// 这两项的 floor 留得特别松（实测 1.1µs / 57µs）：它们本来就已经比需求差 2~100 倍，
/// 门禁在这里只回答"有没有再坏一个数量级"，不回答"够不够用"（后者由 target 回答）。
const FLOOR_EVICT_NS: f64 = 5_000.0;
/// 大步长逐出上限（ns/次），每片容量 8192 时实测 40.7~57µs。
const FLOOR_EVICT_BIG_NS: f64 = 250_000.0;
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
        policy: EvictPolicy::Lru,
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
        policy: EvictPolicy::Lru,
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

    // 灌包：每流再来 5 个包（共 5×容量 个包），全部命中已有条目。
    const BURST: u64 = 5;
    let t = Instant::now();
    for round in 1..=BURST {
        for k in ks.iter() {
            table.observe(&packet(*k, round * 1_000_000));
        }
    }
    let secs = t.elapsed().as_secs_f64();
    assert_eq!(table.len(), cap, "灌包阶段不该改变条目数");
    assert_eq!(table.stats().evictions, 0, "灌包阶段不该逐出");
    let rss_after = rss_bytes();
    let packets = cap as u64 * BURST;
    let (measured, note) = match (rss_full, rss_after) {
        (Some(a), Some(b)) => (
            mib(b.saturating_sub(a)),
            format!(
                "定容 {cap} 条后灌入 {packets} 个包（{:.1} Mpps）→ RSS {:.0} → {:.0} MiB",
                packets as f64 / secs / 1e6,
                mib(a),
                mib(b)
            ),
        ),
        _ => (
            table.len() as f64,
            format!("拿不到 RSS，退化为逻辑判据：灌包后条目数={}", table.len()),
        ),
    };
    eprintln!("    [steady] {note}");
    report.push(Case {
        name: "table-steady-memory",
        first: measured,
        measured,
        unit: "MiB Δ",
        target: STEADY_MEMORY_LIMIT_MIB,
        lower_is_better: true,
        floor: STEADY_MEMORY_LIMIT_MIB,
        derivation: "007 验收：定容后灌 5× 容量个包，RSS 不增长（<16MiB）",
    });

    // ---- 参考值（不判定）：churn 的 RSS 序列与诊断。
    drop(table);
    let churn_cap = (cap / 4).max(1024);
    let churn_ks = keys(churn_cap, 0x1357_2468);
    let churn_cfg = FlowTableConfig {
        max_flows: churn_cap * 2,
        shard_count: 16,
        policy: EvictPolicy::Lru,
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

/// 逐出成本，两个「每分片容量」各测一次。
///
/// **为什么要专门测它**：`flow/table.rs::evict_lru` 用 `iter().min_by()` 全扫分片找
/// 最久未活动者，即每次逐出 O(每分片容量)。表满之后**每一次新流插入都要付这个代价**，
/// 而表满恰恰是省网的稳态。容量翻 32 倍、每次逐出耗时也大致翻 32 倍 —— 这一项就是用
/// 数字把这句话钉住，免得它只活在注释里。
fn case_evict(flows: usize, report: &mut Vec<Case>) {
    let n_evict = (flows / 50).clamp(2_000, 50_000);
    let mut measured_pair = Vec::new();
    for (label, per_shard_cap) in [("cap256", 256usize), ("cap8192", 8192usize)] {
        let cap = per_shard_cap * 16;
        let cfg = FlowTableConfig {
            max_flows: cap,
            shard_count: 16,
            policy: EvictPolicy::Lru,
            ..Default::default()
        };
        // 填满用一套目的地址，溢出用另一套：保证溢出阶段的每个包都是**真插入**
        // （否则端口碰撞会把它变成 update，逐出就不会发生）。
        //
        // 填充阶段必须**按分片**装到上限：容量是按分片均分的，若只是随便插 cap 条，
        // 分布不均会让部分分片超限（填充阶段自己先逐出）、部分分片还有空位
        // （溢出阶段插进去也不逐出）。那样测出来的不是"每次插入都逐出一条"。
        // 用公开的 `shard_of()` 分组填充，两个阶段都变得确定。
        let mut table = FlowTable::new(cfg);
        let mut per_shard: Vec<Vec<FlowKey>> = vec![Vec::new(); table.shard_count()];
        let mut filled = 0usize;
        for k in keys_to(cap * 4, 0x1111_0001, [10, 0, 0, 2]) {
            let s = table.shard_of(&k);
            if per_shard[s].len() < per_shard_cap {
                per_shard[s].push(k);
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

        // 溢出键同样按分片分组：保证每个包落在一个已满的分片上。
        let mut over: Vec<FlowKey> = Vec::new();
        for k in keys_to(n_evict * 4, 0x2222_0002, [10, 9, 9, 9]) {
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
        debug_assert_eq!(table.len(), cap, "逐出后表仍应保持满");
        let secs = t.elapsed().as_secs_f64();
        let after = table.stats();
        assert_eq!(
            after.evictions - before.evictions,
            n_evict as u64,
            "溢出阶段的每一次插入都必须触发恰好一次逐出"
        );
        let ns_per_evict = secs * 1e9 / n_evict as f64;
        eprintln!(
            "    [evict] {label}: 每分片容量 {per_shard_cap} → {ns_per_evict:.0} ns/次逐出（{:.2} M 次/s）",
            n_evict as f64 / secs / 1e6
        );
        measured_pair.push(ns_per_evict);
        report.push(Case {
            name: if label == "cap256" {
                "table-evict-cap256"
            } else {
                "table-evict-cap8192"
            },
            first: ns_per_evict,
            measured: ns_per_evict,
            unit: "ns/evict",
            target: EVICT_TARGET_NS,
            lower_is_better: true,
            // 每片容量 8192 时实测 40.7µs/次；与 cap256 共用一个 floor 等于没测。
            floor: if label == "cap256" {
                FLOOR_EVICT_NS
            } else {
                FLOOR_EVICT_BIG_NS
            },
            derivation: "表满后每次新建流都要逐出一条；目标 ≤500ns/次（≥2M 次/s）",
        });
    }
    if measured_pair.len() == 2 && measured_pair[0] > 0.0 {
        eprintln!(
            "    [evict] 容量比 32×，耗时比 {:.1}× → 逐出成本随每分片容量线性增长（O(cap)）",
            measured_pair[1] / measured_pair[0]
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
                return;
            }
            "--flows" => flows = next_usize(&args, &mut i),
            "--rounds" => rounds = next_usize(&args, &mut i),
            "--json" => json = true,
            "--report-only" => report_only = true,
            "--require-targets" => require_targets = true,
            "--target-factor" => factor = next_f64(&args, &mut i),
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
    case_evict(flows, &mut cases);
    case_memory(flows, rounds, &mut cases, &mut per_flow);

    if json {
        print_json(&cases, factor, report_only);
        if let Some(v) = per_flow {
            println!("{{\"case\":\"residency\",\"bytes_per_flow\":{v:.1}}}");
        }
    } else {
        print_table(&cases, factor, report_only);
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
        ];
        for (name, target, floor) in higher_better {
            assert!(
                floor <= target,
                "{name}: floor={floor} 应 ≤ target={target}"
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

    #[test]
    fn packet_builder_sets_timestamp() {
        let k = keys(1, 1)[0];
        let p = packet(k, 12345);
        assert_eq!(p.timestamp_us, 12345);
        assert_eq!(p.payload_len, 64);
    }
}
