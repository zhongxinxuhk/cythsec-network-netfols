// feature/mod.rs —— 流特征提取（CYS-TRF-027）。
//
// 职责边界只有一句：**把一条流/会话的包序列压成一个定长、定序、可比较的数值向量。**
//
// 为什么必须是定长数组而不是 `HashMap<String, f64>`：
//   下游是规则引擎与模型推理，两者都要求"第 k 维永远是同一个含义"。用 map 时
//   漏掉一个特征只是少一个键，不会报错，而模型会静默地把第 k 维当成 0 —— 这类错误
//   在离线评估里看不出来，只在线上表现为"某类流量识别率莫名偏低"。
//   维度变化则必须靠 `FEATURE_SCHEMA_VERSION` 显式升版，而不是悄悄变长。
//
// 三条设计约束：
//
// 1. **单遍增量**：每个包只看一次、只做常数级运算，不在最后回扫包序列。
//    离线分析可以容忍回扫，但同一份特征代码要被在线路径复用，所以从一开始就按单遍写。
//
// 2. **方向用规范端点序（fwd/rev），不叫"上/下行"**。谁才是"上行"要看
//    `Session::initiator()`，而中途接入时发起方是未知的。把 A→B 直接叫下行，
//    在只看到单向流量的场景里会得到一张方向完全反过来的特征表。
//
// 3. **熵按聚合直方图算**（256 桶），不保留载荷。省网级不得为了算熵把负载留在内存里。
//    代价是熵定义在"该流全部字节的分布"上，而不是"逐包熵再平均"——后者对
//    定长加密流更敏感，但需要逐包保留字节，这里的选择在注释里写清即可。

use crate::flow::stats::{FlowStats, IatRing};
use crate::tcp::Side;

// 布局、版本与阈值由唯一真源 configs/registry/features.json 生成。
mod schema_gen;
pub use schema_gen::{
    idx, FEATURE_COUNT, FEATURE_NAMES, FEATURE_SCHEMA_VERSION, IDX_LAYOUT_CHECK,
    SMALL_PACKET_MAX_LEN,
};

/// 载荷字节直方图的桶数（一个字节的全部取值）。
pub const ENTROPY_BINS: usize = 256;

/// 一个包的观测输入。
#[derive(Debug, Clone, Copy)]
pub struct FlowSample<'a> {
    /// 该包所属侧（规范端点序）。
    pub side: Side,
    /// 四层载荷长度（线上的量，不是捕获到的字节数）。
    pub payload_len: u32,
    /// 到达时间（微秒）。
    pub timestamp_us: u64,
    /// 实际抓到的载荷字节（用于算熵；可能为空 —— 空载荷包不参与熵统计）。
    pub payload: &'a [u8],
}

impl<'a> FlowSample<'a> {
    /// 只带长度与时间的样本（不算熵，用于负载不可得的场景）。
    pub fn len_only(side: Side, payload_len: u32, timestamp_us: u64) -> Self {
        Self {
            side,
            payload_len,
            timestamp_us,
            payload: &[],
        }
    }
}

/// 流特征提取器。
#[derive(Debug, Clone)]
pub struct FeatureExtractor {
    /// 两个方向各自的包长/IAT 摘要（复用 `flow::stats`，避免第二套统计逻辑）。
    fwd: FlowStats,
    rev: FlowStats,
    /// 跨方向的**流级** IAT（两个方向交替活跃时，这才是"包的到达节奏"）。
    iat: IatRing,
    packets: u64,
    first_ts_us: Option<u64>,
    /// 见过的**最大**时间戳（用于算时长；乱序时不能被小时间戳拖回去）。
    last_ts_us: Option<u64>,
    /// 上一个包的到达时间（按到达顺序，用于算 IAT）。
    ///
    /// 与 `last_ts_us` 分开是必须的：时长要的是极值，IAT 要的是相邻性。
    /// 用一个字段兼任两者，要么时长被乱序拖小，要么 IAT 变成"到最大值的距离"。
    prev_ts_us: Option<u64>,
    dir_switches: u64,
    last_side: Option<Side>,
    entropy_hist: [u64; ENTROPY_BINS],
    entropy_bytes: u64,
    small_packets: u64,
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new(crate::flow::stats::DEFAULT_IAT_CAPACITY)
    }
}

impl FeatureExtractor {
    pub fn new(iat_capacity: usize) -> Self {
        Self {
            fwd: FlowStats::with_iat_capacity(iat_capacity),
            rev: FlowStats::with_iat_capacity(iat_capacity),
            iat: IatRing::new(iat_capacity),
            packets: 0,
            first_ts_us: None,
            last_ts_us: None,
            prev_ts_us: None,
            dir_switches: 0,
            last_side: None,
            entropy_hist: [0; ENTROPY_BINS],
            entropy_bytes: 0,
            small_packets: 0,
        }
    }

    /// 观测一个包。
    pub fn observe(&mut self, sample: &FlowSample<'_>) {
        match sample.side {
            Side::A => self.fwd.observe(sample.payload_len, sample.timestamp_us),
            Side::B => self.rev.observe(sample.payload_len, sample.timestamp_us),
        }
        match self.first_ts_us {
            None => self.first_ts_us = Some(sample.timestamp_us),
            Some(_) => {
                // 首包时间用 Option 记录而不是拿 0 当哨兵：pcap 相对时间可以从 0 开始。
            }
        }
        self.last_ts_us = Some(match self.last_ts_us {
            Some(l) => l.max(sample.timestamp_us),
            None => sample.timestamp_us,
        });
        if let Some(prev) = self.prev_ts_us {
            // 乱序（多队列汇聚时真实存在）按 0 记：一个错误的巨大 IAT 会毁掉均值与极值。
            self.iat.push(sample.timestamp_us.saturating_sub(prev));
        }
        self.prev_ts_us = Some(sample.timestamp_us);

        if let Some(prev) = self.last_side {
            if prev != sample.side {
                self.dir_switches += 1;
            }
        }
        self.last_side = Some(sample.side);

        self.packets += 1;
        if sample.payload_len <= SMALL_PACKET_MAX_LEN {
            self.small_packets += 1;
        }
        for &b in sample.payload {
            self.entropy_hist[b as usize] += 1;
            self.entropy_bytes += 1;
        }
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }

    pub fn is_empty(&self) -> bool {
        self.packets == 0
    }

    pub fn fwd_stats(&self) -> &FlowStats {
        &self.fwd
    }

    pub fn rev_stats(&self) -> &FlowStats {
        &self.rev
    }

    /// 两个方向合并后的包长摘要（均值/方差都必须按计数合并，不能各自算完再平均）。
    pub fn payload_stats(&self) -> FlowStats {
        let mut total = self.fwd.clone();
        total.merge(&self.rev);
        total
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.iat.capacity());
    }

    /// 载荷字节的香农熵，单位 bit/byte（0..=8）。
    ///
    /// 值 0 有两种来源：没有载荷字节，或全部字节相同。二者都表示"没有不确定性"，
    /// 因此都映射到 0，不会混淆下游判断 —— 需要区分时看 `bytes` 特征即可。
    pub fn payload_entropy_bits(&self) -> f64 {
        if self.entropy_bytes == 0 {
            return 0.0;
        }
        let total = self.entropy_bytes as f64;
        let mut h = 0.0;
        for &c in self.entropy_hist.iter() {
            if c > 0 {
                let p = c as f64 / total;
                h -= p * p.log2();
            }
        }
        h
    }

    /// 产出特征向量。
    pub fn vector(&self) -> FeatureVector {
        let mut values = [0f64; FEATURE_COUNT];
        let payload = self.payload_stats();
        let bytes = payload.bytes;
        let packets = self.packets;
        let fwd_bytes = self.fwd.bytes;
        let rev_bytes = self.rev.bytes;

        let duration_us = match (self.first_ts_us, self.last_ts_us) {
            (Some(f), Some(l)) => l.saturating_sub(f),
            _ => 0,
        };
        let seconds = duration_us as f64 / 1_000_000.0;
        // 时长为 0（单包流 / 同微秒到达）时速率定义为 0，而不是除以 0 得到 inf：
        // inf 不是合法 JSON，也不是合法特征值，落库时会被悄悄写成 NULL。
        let (byte_rate, packet_rate) = if seconds > 0.0 {
            (bytes as f64 * 8.0 / seconds, packets as f64 / seconds)
        } else {
            (0.0, 0.0)
        };

        values[idx::PACKETS] = packets as f64;
        values[idx::BYTES] = bytes as f64;
        values[idx::FWD_PACKETS] = self.fwd.packets as f64;
        values[idx::FWD_BYTES] = fwd_bytes as f64;
        values[idx::REV_PACKETS] = self.rev.packets as f64;
        values[idx::REV_BYTES] = rev_bytes as f64;
        // 占比而不是 fwd/rev 比值：比值上界无限，落库与画图都不好用；
        // 占比有界、信息等价（配合 bytes 可完全还原）。
        values[idx::FWD_BYTE_RATIO] = if bytes == 0 {
            0.0
        } else {
            fwd_bytes as f64 / bytes as f64
        };
        values[idx::DURATION_US] = duration_us as f64;
        values[idx::BYTE_RATE_BPS] = byte_rate;
        values[idx::PACKET_RATE_PPS] = packet_rate;
        values[idx::MEAN_PAYLOAD_LEN] = if packets == 0 {
            0.0
        } else {
            bytes as f64 / packets as f64
        };
        values[idx::MIN_PAYLOAD_LEN] = payload.min_payload_len.unwrap_or(0) as f64;
        values[idx::MAX_PAYLOAD_LEN] = payload.max_payload_len.unwrap_or(0) as f64;
        values[idx::STDDEV_PAYLOAD_LEN] = payload.stddev_payload_len();
        values[idx::MEAN_IAT_US] = self.iat.mean_us() as f64;
        let (min_iat, max_iat) = self.iat.extremes_us().unwrap_or((0, 0));
        values[idx::MIN_IAT_US] = min_iat as f64;
        values[idx::MAX_IAT_US] = max_iat as f64;
        values[idx::STDDEV_IAT_US] = self.iat.stddev_us();
        values[idx::DIRECTION_SWITCHES] = self.dir_switches as f64;
        values[idx::SMALL_PACKET_RATIO] = if packets == 0 {
            0.0
        } else {
            self.small_packets as f64 / packets as f64
        };
        values[idx::PAYLOAD_ENTROPY_BITS] = self.payload_entropy_bits();

        FeatureVector {
            schema_version: FEATURE_SCHEMA_VERSION,
            values,
        }
    }
}

/// 定长特征向量。
#[derive(Debug, Clone, PartialEq)]
pub struct FeatureVector {
    pub schema_version: u32,
    pub values: [f64; FEATURE_COUNT],
}

impl FeatureVector {
    pub fn get(&self, index: usize) -> f64 {
        self.values[index]
    }

    pub fn by_name(&self, name: &str) -> Option<f64> {
        FEATURE_NAMES
            .iter()
            .position(|n| *n == name)
            .map(|i| self.values[i])
    }

    /// 名字与取值按布局顺序配对（供控制台表格与 CSV 表头共用）。
    pub fn zip(&self) -> impl Iterator<Item = (&'static str, f64)> + '_ {
        FEATURE_NAMES.iter().copied().zip(self.values)
    }

    /// 全部取值都是有限数。
    ///
    /// 这条必须能检查，因为 NaN/inf 不是合法 JSON，写进 JSONL 会让整行失效；
    /// 而"某个特征偶尔是 inf"在离线看单个文件时几乎发现不了。
    pub fn is_finite(&self) -> bool {
        self.values.iter().all(|v| v.is_finite())
    }

    pub fn approx_eq(&self, other: &Self, eps: f64) -> bool {
        self.schema_version == other.schema_version
            && self
                .values
                .iter()
                .zip(other.values)
                .all(|(a, b)| (a - b).abs() <= eps)
    }

    /// 把取值按 `"name":value` 追加到 JSON 对象体内（调用方负责大括号与逗号）。
    pub fn json_pairs_into(&self, out: &mut String) {
        for (i, (name, v)) in self.zip().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(name);
            out.push_str("\":");
            out.push_str(&json_number(v));
        }
    }
}

/// f64 → JSON 数字字面量。
///
/// 非有限值输出 `null`：JSON 没有 NaN/Infinity，直接写 `NaN` 会让解析器整行报错，
/// 而 `null` 至少能被读取方看见"这里缺一个值"。
pub fn json_number(v: f64) -> String {
    if !v.is_finite() {
        return "null".to_string();
    }
    // Rust 的 f64 Display 输出最短往返表示，且不会用指数记法（JSON 合法但
    // 部分消费方不认），故直接用它。
    let mut s = format!("{v}");
    if s.contains(['e', 'E']) {
        // 兜底：真的出现指数记法时展开成普通小数。
        s = format!("{v:.6}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(side: Side, len: u32, ts: u64) -> FlowSample<'static> {
        FlowSample {
            side,
            payload_len: len,
            timestamp_us: ts,
            payload: &[],
        }
    }

    #[test]
    fn empty_extractor_yields_all_zeros_and_stays_finite() {
        let v = FeatureExtractor::default().vector();
        assert_eq!(v.schema_version, FEATURE_SCHEMA_VERSION);
        assert!(v.values.iter().all(|x| *x == 0.0));
        assert!(v.is_finite());
    }

    #[test]
    fn layout_is_self_consistent() {
        assert_eq!(FEATURE_NAMES.len(), FEATURE_COUNT);
        // 名字不许重复：重复意味着两个下标被同一个规则命中，取值会互相顶掉。
        let mut names: Vec<&str> = FEATURE_NAMES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), FEATURE_COUNT, "特征名必须互不重复");
        assert_eq!(idx::PACKETS, 0);
        assert_eq!(IDX_LAYOUT_CHECK.len(), FEATURE_COUNT);
    }

    #[test]
    fn single_packet_has_no_rate_and_no_duration() {
        let mut e = FeatureExtractor::default();
        e.observe(&sample(Side::A, 200, 5_000));
        let v = e.vector();
        assert_eq!(v.get(idx::PACKETS), 1.0);
        assert_eq!(v.get(idx::BYTES), 200.0);
        assert_eq!(v.get(idx::DURATION_US), 0.0);
        assert_eq!(v.get(idx::BYTE_RATE_BPS), 0.0, "不能除以 0 得到 inf");
        assert_eq!(v.get(idx::MEAN_PAYLOAD_LEN), 200.0);
        assert_eq!(v.get(idx::MIN_PAYLOAD_LEN), 200.0);
        assert_eq!(v.get(idx::MAX_PAYLOAD_LEN), 200.0);
        assert_eq!(v.get(idx::STDDEV_PAYLOAD_LEN), 0.0);
        assert_eq!(v.get(idx::MEAN_IAT_US), 0.0);
        assert!(v.is_finite());
    }

    #[test]
    fn rates_use_the_hand_computed_formula() {
        // 1000 字节 / 1 秒 = 8000 bit/s；2 包 / 1 秒 = 2 pps。
        let mut e = FeatureExtractor::default();
        e.observe(&sample(Side::A, 600, 0));
        e.observe(&sample(Side::A, 400, 1_000_000));
        let v = e.vector();
        assert_eq!(v.get(idx::DURATION_US), 1_000_000.0);
        assert!((v.get(idx::BYTE_RATE_BPS) - 8000.0).abs() < 1e-9);
        assert!((v.get(idx::PACKET_RATE_PPS) - 2.0).abs() < 1e-9);
        // IAT = 1_000_000 微秒
        assert_eq!(v.get(idx::MEAN_IAT_US), 1_000_000.0);
        assert_eq!(v.get(idx::MIN_IAT_US), 1_000_000.0);
        assert_eq!(v.get(idx::MAX_IAT_US), 1_000_000.0);
    }

    #[test]
    fn direction_attribution_and_switches() {
        let mut e = FeatureExtractor::default();
        e.observe(&sample(Side::A, 100, 1)); // A
        e.observe(&sample(Side::A, 100, 2)); // A（不切换）
        e.observe(&sample(Side::B, 300, 3)); // 切换 1
        e.observe(&sample(Side::A, 100, 4)); // 切换 2
        let v = e.vector();
        assert_eq!(v.get(idx::FWD_PACKETS), 3.0);
        assert_eq!(v.get(idx::REV_PACKETS), 1.0);
        assert_eq!(v.get(idx::FWD_BYTES), 300.0);
        assert_eq!(v.get(idx::REV_BYTES), 300.0);
        assert_eq!(v.get(idx::DIRECTION_SWITCHES), 2.0);
        assert!((v.get(idx::FWD_BYTE_RATIO) - 0.5).abs() < 1e-12);
        // 合并方向的 min/max/mean 必须跨两侧取
        assert_eq!(v.get(idx::MIN_PAYLOAD_LEN), 100.0);
        assert_eq!(v.get(idx::MAX_PAYLOAD_LEN), 300.0);
        assert!((v.get(idx::MEAN_PAYLOAD_LEN) - 150.0).abs() < 1e-12);
    }

    #[test]
    fn stddev_merges_directions_instead_of_averaging_them() {
        // A 侧定长 100，B 侧 [100, 300]：合并后 4 个样本是 [100,100,100,300]，
        // 均值 150，方差 (2500*3 + 22500)/4 = 7500。
        let mut e = FeatureExtractor::default();
        e.observe(&sample(Side::A, 100, 1));
        e.observe(&sample(Side::A, 100, 2));
        e.observe(&sample(Side::B, 100, 3));
        e.observe(&sample(Side::B, 300, 4));
        let v = e.vector();
        assert!((v.get(idx::STDDEV_PAYLOAD_LEN) - 7500f64.sqrt()).abs() < 1e-9);
    }

    #[test]
    fn small_packet_ratio_uses_the_inclusive_threshold() {
        let mut e = FeatureExtractor::default();
        // 128 恰好算小包（阈值含义是"≤"），129 不算。
        for len in [0u32, 64, 128, 129] {
            e.observe(&sample(Side::A, len, 1));
        }
        let v = e.vector();
        assert!((v.get(idx::SMALL_PACKET_RATIO) - 0.75).abs() < 1e-12);
    }

    #[test]
    fn entropy_is_zero_for_uniform_bytes_and_eight_for_all_distinct() {
        let mut flat = FeatureExtractor::default();
        let payload = vec![0xABu8; 1000];
        flat.observe(&FlowSample {
            side: Side::A,
            payload_len: 1000,
            timestamp_us: 1,
            payload: &payload,
        });
        assert_eq!(flat.payload_entropy_bits(), 0.0);

        let mut full = FeatureExtractor::default();
        let distinct: Vec<u8> = (0..=255u8).collect();
        full.observe(&FlowSample {
            side: Side::A,
            payload_len: 256,
            timestamp_us: 1,
            payload: &distinct,
        });
        // 256 种字节各一次 → 每个 p = 1/256 → H = log2(256) = 8。
        assert!((full.payload_entropy_bits() - 8.0).abs() < 1e-12);

        let mut two = FeatureExtractor::default();
        let mix = vec![0u8, 0, 1, 1];
        two.observe(&FlowSample {
            side: Side::A,
            payload_len: 4,
            timestamp_us: 1,
            payload: &mix,
        });
        // 两种符号等概率 → 1 bit/byte。
        assert!((two.payload_entropy_bits() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn entropy_counts_bytes_not_len_only_samples() {
        // 只给长度、不给字节时熵为 0 —— 这是"没有证据"，不是"熵真的是 0"。
        // 因此下游必须结合 `bytes` 特征判断，这一点写进注释并由本用例锁住。
        let mut e = FeatureExtractor::default();
        e.observe(&FlowSample::len_only(Side::A, 1000, 1));
        assert_eq!(e.vector().get(idx::PAYLOAD_ENTROPY_BITS), 0.0);
        assert_eq!(e.vector().get(idx::BYTES), 1000.0);
    }

    #[test]
    fn timestamps_may_start_at_zero() {
        // pcap 相对时间从 0 开始是常态。首包时间用 Option 记录，
        // 不用 0 当哨兵，否则第一条样例会把自己的时间戳丢掉。
        let mut e = FeatureExtractor::default();
        e.observe(&sample(Side::A, 10, 0));
        e.observe(&sample(Side::A, 10, 500));
        assert_eq!(e.vector().get(idx::DURATION_US), 500.0);
    }

    #[test]
    fn out_of_order_timestamps_do_not_produce_a_huge_iat() {
        let mut e = FeatureExtractor::default();
        e.observe(&sample(Side::A, 10, 1_000));
        e.observe(&sample(Side::A, 10, 400)); // 乱序
        e.observe(&sample(Side::A, 10, 1_500));
        let v = e.vector();
        assert_eq!(v.get(idx::MAX_IAT_US), 1_100.0);
        assert!(v.is_finite());
    }

    #[test]
    fn iat_is_measured_across_directions_not_per_direction() {
        // 两个方向交替活跃时，"包的到达节奏"是跨方向的；若按方向各算一份，
        // 交互型流量（请求-响应-请求）的 IAT 会被系统性放大一倍。
        let mut e = FeatureExtractor::default();
        e.observe(&sample(Side::A, 10, 0));
        e.observe(&sample(Side::B, 10, 100));
        e.observe(&sample(Side::A, 10, 250));
        assert_eq!(e.vector().get(idx::MEAN_IAT_US), 125.0, "(100+150)/2");
    }

    #[test]
    fn vector_is_deterministic_for_the_same_input() {
        let run = || {
            let mut e = FeatureExtractor::default();
            for (i, len) in [64u32, 1500, 40, 900].iter().enumerate() {
                e.observe(&FlowSample {
                    side: if i % 2 == 0 { Side::A } else { Side::B },
                    payload_len: *len,
                    timestamp_us: 1_000 * i as u64,
                    payload: b"abcdef",
                });
            }
            e.vector()
        };
        // 逐位相等：特征是要拿去比对的，任何非确定性（迭代顺序、浮点求和顺序）
        // 都会让"同一份 pcap 跑两次结果不同"。
        assert_eq!(run().values, run().values);
    }

    #[test]
    fn reset_clears_every_accumulator() {
        let mut e = FeatureExtractor::default();
        e.observe(&FlowSample {
            side: Side::A,
            payload_len: 500,
            timestamp_us: 7,
            payload: b"xyz",
        });
        assert!(!e.is_empty());
        e.reset();
        assert!(e.is_empty());
        assert!(e.vector().values.iter().all(|v| *v == 0.0));
    }

    #[test]
    fn json_pairs_are_valid_and_versioned() {
        let mut e = FeatureExtractor::default();
        e.observe(&sample(Side::A, 500, 0));
        let v = e.vector();
        let mut out = String::new();
        v.json_pairs_into(&mut out);
        assert!(out.starts_with("\"packets\":1"));
        assert!(
            out.contains("\"schema_version\"") == false,
            "版本号单独由记录层写"
        );
        assert_eq!(
            out.matches(':').count(),
            FEATURE_COUNT,
            "每个特征恰好一个冒号"
        );
        assert!(!out.contains("NaN") && !out.contains("inf"));
        assert!(v.by_name("bytes") == Some(500.0));
        assert_eq!(v.by_name("no_such_feature"), None);
    }

    #[test]
    fn json_number_maps_non_finite_to_null() {
        assert_eq!(json_number(f64::NAN), "null");
        assert_eq!(json_number(f64::INFINITY), "null");
        assert_eq!(json_number(1.5), "1.5");
        assert_eq!(json_number(0.0), "0");
    }
}
