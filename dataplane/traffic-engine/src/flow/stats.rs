// flow/stats.rs —— 流级统计扩展（CYS-TRF-014）。
//
// 为什么这些统计要在这里、而不是"等做特征时再算"：
//
//   * **包长与 IAT 是"只有在线时才拿得到"的量**。流表逐包推进，天然能看到每一个
//     包长与到达间隔；而"落库后再统计"意味着必须把每个包的元数据都存下来。
//     省网上这是数量级的存储差异。所以在线只保留**可合并的摘要**（min/max/mean/直方图）
//     与**固定容量的样本**（IAT 环形缓冲），需要精确序列的场景另行采样。
//
//   * **摘要必须可合并**：将来做分片/多 worker 时会需要把两份摘要合并成一份。
//     故 `merge()` 是显式实现并测试的，而不是"看起来能加就加"。均值尤其容易错：
//     不能把两个均值再平均，必须按计数加权。
//
//   * **IAT 环形缓冲只留最近 N 个**。理由是内存上界可预测：一条百万包的流不可能
//     把全部间隔留在内存里。代价是"最老的间隔会被覆盖"——这个代价必须写进字段名
//     （`retained()` vs `count()`），否则下游会把"样本均值"当成"全体均值"。

/// 包长直方图桶数。
///
/// 分桶按 **2 的幂**，不是拍脑袋的固定区间：以太网上包长分布高度集中在
/// 64 / 128 / 256 / 512 / 1518 这些量级，2 的幂分桶让每个数量级都有独立桶，
/// 且**桶边界不随协议/链路变化**（写成固定字节区间，换了链路类型就要重定）。
pub const HIST_BUCKETS: usize = 12;

/// 默认 IAT 环形缓冲容量（个）。
pub const DEFAULT_IAT_CAPACITY: usize = 64;

/// 包长所属的直方图桶。
///
/// 语义（写清楚，避免下游各自理解）：
///   * 桶 `i` 覆盖 `[2^i, 2^(i+1))`；
///   * **桶 0 额外包含长度为 0 的包**（纯 ACK / 无载荷），因此 0 与 1 同桶；
///   * 长度 ≥ `2^(HIST_BUCKETS-1)` 的一律进最后一个桶（以太网 MTU 远小于此，
///     出现就意味着抓的是巨型帧或链路层拼接）。
pub fn len_bucket(payload_len: u32) -> usize {
    if payload_len <= 1 {
        return 0;
    }
    let floor_log2 = (u32::BITS - 1 - payload_len.leading_zeros()) as usize;
    floor_log2.min(HIST_BUCKETS - 1)
}

/// 桶 `i` 的下界（含）。
pub fn bucket_lower(i: usize) -> u64 {
    if i == 0 {
        0
    } else {
        1u64 << i
    }
}

/// 桶 `i` 的上界（不含）；最后一桶为 `None` 表示开区间。
pub fn bucket_upper(i: usize) -> Option<u64> {
    if i + 1 >= HIST_BUCKETS {
        None
    } else {
        Some(1u64 << (i + 1))
    }
}

/// IAT（到达间隔）固定容量环形缓冲。
///
/// 存的是**相邻包的时间差**（微秒）。第一个包不产生 IAT（没有前驱），这一点很重要：
/// 若把首个包的到达时间本身当成一个 IAT，样本里就会混进一个"距开机多久"的巨值，
/// 均值与最大值会被系统性污染。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatRing {
    buf: Vec<u64>,
    /// 下一个写入位置。
    next: usize,
    /// 当前有效元素数（≤ 容量）。
    len: usize,
    /// 累计推入过的 IAT 个数（含已被覆盖的）。
    count: u64,
    sum_us: u64,
    /// 平方和的低 128 位与高 64 位（精确 192 位，无逐样本分配）。
    /// 一个 u64 的平方放得下 u128，两个 u64::MAX 的平方之和就放不下。
    /// count ≤ u64::MAX 时，总和 ≤ (2^64-1)^3 < 2^192，因此三字足够。
    /// 不能饱和平方和：它会把溢出藏成偏小的标准差。
    sum_sq_us: u128,
    sum_sq_us_high: u64,
    min_us: u64,
    max_us: u64,
}

impl IatRing {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            buf: vec![0; cap],
            next: 0,
            len: 0,
            count: 0,
            sum_us: 0,
            sum_sq_us: 0,
            sum_sq_us_high: 0,
            min_us: 0,
            max_us: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    // 仅维护保留窗口，不更新全历史摘要。merge 复制窗口也走这里，避免重复计数。
    fn retain(&mut self, delta_us: u64) {
        let cap = self.buf.len();
        self.buf[self.next] = delta_us;
        self.next = (self.next + 1) % cap;
        if self.len < cap {
            self.len += 1;
        }
    }

    pub fn push(&mut self, delta_us: u64) {
        self.retain(delta_us);
        if self.count == 0 {
            self.min_us = delta_us;
            self.max_us = delta_us;
        } else {
            self.min_us = self.min_us.min(delta_us);
            self.max_us = self.max_us.max(delta_us);
        }
        // sum 用 saturating：一条跑满 10G 的长流其 IAT 总和在 u64 下仍然安全，
        // 但饱和加法保证任何输入都不会回绕成一个小值（回绕会把均值算成 0）。
        self.sum_us = self.sum_us.saturating_add(delta_us);
        let square = u128::from(delta_us) * u128::from(delta_us);
        let (low, carry) = self.sum_sq_us.overflowing_add(square);
        self.sum_sq_us = low;
        self.sum_sq_us_high += u64::from(carry);
        self.count += 1;
    }

    /// 累计 IAT 个数（含已覆盖的样本）。
    pub fn count(&self) -> u64 {
        self.count
    }

    /// 当前仍可读取的样本数。
    pub fn retained(&self) -> usize {
        self.len
    }

    /// 全体样本的均值（含已覆盖样本），微秒；无样本时为 0。
    pub fn mean_us(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.sum_us / self.count
        }
    }

    /// 全体样本的极值，微秒；无样本时 `None`。
    ///
    /// 用 `Option` 而不是 0：0 是合法的 IAT（同一微秒内到达两个包），
    /// 用 0 表示"没有样本"会让"极快突发"与"还没收到第二个包"混为一谈。
    pub fn extremes_us(&self) -> Option<(u64, u64)> {
        if self.count == 0 {
            None
        } else {
            Some((self.min_us, self.max_us))
        }
    }

    /// 全体样本的**总体**标准差，微秒；样本数 < 2 时为 0。
    ///
    /// 用总体标准差（除以 n）而非样本标准差（除以 n-1）：这里的样本就是"这条流
    /// 实际发生的全部包间隔"，不是从更大总体里抽的样，所以没有自由度损失可言。
    /// 方差用 `E[x²] - E[x]²` 展开式直接算，避免为了求均值再遍历一遍缓冲 ——
    /// 但要注意该式在数值上可能给出极小负数（浮点误差），故钳到 0。
    /// 兼容限制：一阶矩 sum_us 保留 v1 的 u64 饱和规则；饱和后这里只能解释为
    /// “以饱和一阶矩计算的离散度”，不再等于精确总体标准差。平方和仍保持精确。
    pub fn stddev_us(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        let n = self.count as f64;
        let mean = self.sum_us as f64 / n;
        // 2^128 is exactly representable in f64. Convert only when rendering;
        // the increment/merge paths retain the full integer second moment.
        const HIGH_SCALE: f64 = 340282366920938463463374607431768211456.0;
        let mean_sq = (self.sum_sq_us as f64 + self.sum_sq_us_high as f64 * HIGH_SCALE) / n;
        let var = mean_sq - mean * mean;
        if var <= 0.0 {
            0.0
        } else {
            var.sqrt()
        }
    }

    /// 按最旧→最新遍历仍保留的样本。
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        let cap = self.buf.len();
        let start = (self.next + cap - self.len) % cap;
        (0..self.len).map(move |i| self.buf[(start + i) % cap])
    }

    /// 合并另一份摘要（全员合并语义：计数、和、极值都并入）。
    ///
    /// 注意**不能**只合并环形缓冲：被覆盖的样本已经不在缓冲里，但仍计入 `count/sum`。
    /// 若只合并缓冲内容，合并结果的均值会偏向"最近 N 个"，而调用方无法察觉。
    pub fn merge(&mut self, other: &IatRing) {
        if other.count == 0 {
            return;
        }
        if self.count == 0 {
            self.min_us = other.min_us;
            self.max_us = other.max_us;
        } else {
            self.min_us = self.min_us.min(other.min_us);
            self.max_us = self.max_us.max(other.max_us);
        }
        self.sum_us = self.sum_us.saturating_add(other.sum_us);
        let (low, carry) = self.sum_sq_us.overflowing_add(other.sum_sq_us);
        self.sum_sq_us = low;
        self.sum_sq_us_high += other.sum_sq_us_high + u64::from(carry);
        self.count += other.count;
        // 环形缓冲只保留"最近"的语义：合并时以本对象的最近样本为准，
        // 仅在本对象为空时采纳对方的缓冲。
        if self.len == 0 {
            for v in other.iter() {
                self.retain(v);
            }
        }
    }
}

/// 单条流的扩展统计。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStats {
    /// 包数（与 `Flow::packet_count` 同源，重复保留是为了让摘要可独立合并）。
    pub packets: u64,
    /// 载荷字节合计。
    pub bytes: u64,
    /// 最小 / 最大载荷长度；无包时为 `None`。
    pub min_payload_len: Option<u32>,
    pub max_payload_len: Option<u32>,
    /// 零载荷包数（纯 ACK / 空数据报，单独计数而不是混进 min）。
    pub zero_len_packets: u64,
    /// 包长直方图。
    pub hist: [u64; HIST_BUCKETS],
    /// 最近若干 IAT。
    pub iat: IatRing,
    /// 上一个包的到达时间（`None` 表示还没见过包）。
    last_ts_us: Option<u64>,
    /// 载荷长度平方和。u32 长度的平方 × u64 包数至多需要 128 位，与 u64 IAT 不同。
    sum_payload_sq: u128,
}

impl Default for FlowStats {
    fn default() -> Self {
        Self {
            packets: 0,
            bytes: 0,
            min_payload_len: None,
            max_payload_len: None,
            zero_len_packets: 0,
            hist: [0; HIST_BUCKETS],
            iat: IatRing::new(DEFAULT_IAT_CAPACITY),
            last_ts_us: None,
            sum_payload_sq: 0,
        }
    }
}

impl FlowStats {
    pub fn with_iat_capacity(capacity: usize) -> Self {
        Self {
            iat: IatRing::new(capacity),
            ..Self::default()
        }
    }

    /// 观测一个包。`ts_us` 是到达时间（微秒）。
    pub fn observe(&mut self, payload_len: u32, ts_us: u64) {
        self.packets += 1;
        self.bytes += u64::from(payload_len);
        self.sum_payload_sq += u128::from(payload_len) * u128::from(payload_len);
        match self.min_payload_len {
            Some(m) => self.min_payload_len = Some(m.min(payload_len)),
            None => self.min_payload_len = Some(payload_len),
        }
        match self.max_payload_len {
            Some(m) => self.max_payload_len = Some(m.max(payload_len)),
            None => self.max_payload_len = Some(payload_len),
        }
        if payload_len == 0 {
            self.zero_len_packets += 1;
        }
        self.hist[len_bucket(payload_len)] += 1;
        if let Some(prev) = self.last_ts_us {
            // 时间戳乱序（多队列/多源合并时会真实发生）时按 0 记，而不是让 u64
            // 减法下溢成天文数字：一个错误的巨大 IAT 会直接毁掉均值与最大值。
            self.iat.push(ts_us.saturating_sub(prev));
        }
        self.last_ts_us = Some(ts_us);
    }

    /// 平均载荷长度（整数除法）。无包时返回 0。
    pub fn mean_payload_len(&self) -> u64 {
        if self.packets == 0 {
            0
        } else {
            self.bytes / self.packets
        }
    }

    /// 载荷长度的**总体**标准差；包数 < 2 时为 0。
    ///
    /// 为什么值得单独留一个方差累加器：均值相同、方差截然不同的两条流
    /// （定长心跳 vs 大小包混合）在只看均值的规则里完全无法区分，
    /// 而这正是"是不是隧道/是不是扫描"的关键差别。
    pub fn stddev_payload_len(&self) -> f64 {
        if self.packets < 2 {
            return 0.0;
        }
        let n = self.packets as f64;
        let mean = self.bytes as f64 / n;
        let mean_sq = self.sum_payload_sq as f64 / n;
        let var = mean_sq - mean * mean;
        if var <= 0.0 {
            0.0
        } else {
            var.sqrt()
        }
    }

    /// 合并另一份摘要（多分片/多 worker 场景）。
    ///
    /// 均值的合并必须按计数加权 —— 直接平均两个均值在两侧包数不同时是错的，
    /// 而错得很难看出来（数值仍在合理范围内）。这里只合并可合并量，
    /// 均值由 `mean_payload_len()` 在合并后的 `bytes/packets` 上重新算出。
    pub fn merge(&mut self, other: &FlowStats) {
        if other.packets == 0 {
            return;
        }
        self.packets += other.packets;
        self.bytes += other.bytes;
        self.sum_payload_sq += other.sum_payload_sq;
        self.zero_len_packets += other.zero_len_packets;
        for i in 0..HIST_BUCKETS {
            self.hist[i] += other.hist[i];
        }
        self.min_payload_len = match (self.min_payload_len, other.min_payload_len) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.max_payload_len = match (self.max_payload_len, other.max_payload_len) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        self.iat.merge(&other.iat);
        // last_ts 取较晚者，否则合并后的下一个 IAT 会算出负数（被 saturating 成 0，
        // 表现为"合并后 IAT 里凭空多出一堆 0"）。
        self.last_ts_us = match (self.last_ts_us, other.last_ts_us) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_boundaries_are_powers_of_two() {
        assert_eq!(len_bucket(0), 0, "零长包进桶 0");
        assert_eq!(len_bucket(1), 0);
        assert_eq!(len_bucket(2), 1);
        assert_eq!(len_bucket(3), 1);
        assert_eq!(len_bucket(4), 2);
        assert_eq!(len_bucket(1024), 10);
        assert_eq!(len_bucket(2047), 10);
        assert_eq!(len_bucket(2048), 11);
        assert_eq!(len_bucket(u32::MAX), HIST_BUCKETS - 1, "超出范围进最后桶");
    }

    #[test]
    fn bucket_ranges_are_consistent_with_the_indexer() {
        // 分桶函数与"桶边界描述"必须是同一件事：两处各写一套的话，
        // 报告里标着 [64,128) 的桶可能实际装的是别的长度。
        for i in 0..HIST_BUCKETS {
            let lo = bucket_lower(i);
            let hi = bucket_upper(i);
            assert_eq!(len_bucket(lo as u32), i, "桶 {i} 下界落入本桶");
            if let Some(hi) = hi {
                assert_eq!(
                    len_bucket((hi - 1) as u32),
                    i,
                    "桶 {i} 上界前一字节仍在桶内"
                );
                assert!(hi > lo);
            } else {
                assert_eq!(bucket_upper(i), None, "最后一桶是开区间");
            }
        }
    }

    #[test]
    fn iat_ring_first_packet_produces_no_sample() {
        let mut s = FlowStats::default();
        s.observe(100, 1000);
        assert_eq!(s.iat.count(), 0, "首包没有前驱，不产生 IAT");
        s.observe(100, 1030);
        assert_eq!(s.iat.count(), 1);
        assert_eq!(s.iat.mean_us(), 30);
    }

    #[test]
    fn iat_ring_keeps_only_the_most_recent_samples_but_stats_stay_global() {
        let mut ring = IatRing::new(2);
        for v in [10u64, 20, 30] {
            ring.push(v);
        }
        assert_eq!(ring.retained(), 2, "只留最近 2 个");
        assert_eq!(ring.iter().collect::<Vec<_>>(), vec![20, 30], "最旧→最新");
        assert_eq!(ring.count(), 3, "计数含被覆盖样本");
        assert_eq!(ring.mean_us(), 20, "(10+20+30)/3");
        assert_eq!(ring.extremes_us(), Some((10, 30)), "极值覆盖被覆盖样本");
    }

    #[test]
    fn iat_ring_empty_extremes_are_none_not_zero() {
        let ring = IatRing::new(4);
        assert_eq!(ring.extremes_us(), None);
        assert_eq!(ring.mean_us(), 0);
        assert_eq!(ring.iter().count(), 0);
    }

    #[test]
    fn iat_ring_zero_delta_is_a_real_sample() {
        // 同一微秒内到达两个包：IAT = 0 是合法观测，不得与"没有样本"混淆。
        let mut ring = IatRing::new(4);
        ring.push(0);
        assert_eq!(ring.extremes_us(), Some((0, 0)));
        assert_eq!(ring.count(), 1);
    }

    #[test]
    fn iat_merge_is_weighted_not_a_second_average() {
        let mut a = IatRing::new(8);
        a.push(10);
        let mut b = IatRing::new(8);
        for v in [100u64, 100, 100] {
            b.push(v);
        }
        a.merge(&b);
        assert_eq!(a.count(), 4);
        assert_eq!(a.mean_us(), (10 + 300) / 4, "按计数加权，不是 (10+100)/2");
        assert_eq!(a.extremes_us(), Some((10, 100)));
    }

    #[test]
    fn flow_stats_summary_matches_hand_computed_values() {
        let mut s = FlowStats::default();
        // 包长：0, 100, 200, 2000；时间戳：0, 10, 30, 130
        for (len, ts) in [(0u32, 0u64), (100, 10), (200, 30), (2000, 130)] {
            s.observe(len, ts);
        }
        assert_eq!(s.packets, 4);
        assert_eq!(s.bytes, 2300);
        assert_eq!(s.min_payload_len, Some(0));
        assert_eq!(s.max_payload_len, Some(2000));
        assert_eq!(s.zero_len_packets, 1);
        assert_eq!(s.mean_payload_len(), 575, "2300/4");
        assert_eq!(s.iat.count(), 3);
        assert_eq!(s.iat.iter().collect::<Vec<_>>(), vec![10, 20, 100]);
        // 直方图：0→桶0，100→桶6（[64,128)），200→桶7，2000→桶10
        assert_eq!(s.hist[0], 1);
        assert_eq!(s.hist[6], 1);
        assert_eq!(s.hist[7], 1);
        assert_eq!(s.hist[10], 1);
        assert_eq!(s.hist.iter().sum::<u64>(), 4, "每包必落一个桶");
    }

    #[test]
    fn out_of_order_timestamps_do_not_underflow_into_huge_iat() {
        let mut s = FlowStats::default();
        s.observe(10, 1000);
        s.observe(10, 500); // 时间倒流（多源合并时真实存在）
        assert_eq!(
            s.iat.iter().collect::<Vec<_>>(),
            vec![0],
            "按 0 记，不得回绕"
        );
        assert_eq!(s.iat.extremes_us(), Some((0, 0)));
    }

    #[test]
    fn merge_preserves_global_counters_and_never_averages_averages() {
        let mut a = FlowStats::default();
        a.observe(100, 0);
        a.observe(100, 10);
        let mut b = FlowStats::default();
        for (len, ts) in [(300u32, 0u64), (300, 10), (300, 20), (300, 30)] {
            b.observe(len, ts);
        }
        let mean_a = a.mean_payload_len();
        let mean_b = b.mean_payload_len();
        a.merge(&b);
        assert_eq!(a.packets, 6);
        assert_eq!(a.bytes, 1400);
        assert_eq!(a.mean_payload_len(), 1400 / 6);
        assert_ne!(
            a.mean_payload_len(),
            (mean_a + mean_b) / 2,
            "直接平均两个均值在包数不等时是错的"
        );
        assert_eq!(a.min_payload_len, Some(100));
        assert_eq!(a.max_payload_len, Some(300));
        assert_eq!(a.iat.count(), 4, "1 + 3 个 IAT");
    }

    #[test]
    fn merge_with_empty_side_is_identity() {
        let mut a = FlowStats::default();
        a.observe(64, 5);
        let before = a.clone();
        a.merge(&FlowStats::default());
        assert_eq!(a, before, "合并空摘要不得改变任何字段");
    }

    #[test]
    fn merge_keeps_the_later_last_timestamp() {
        let mut a = FlowStats::default();
        a.observe(10, 400);
        a.observe(10, 500);
        let mut b = FlowStats::default();
        b.observe(10, 100); // 更早的时间戳（乱序合并的真实情形）
        a.merge(&b);
        a.observe(10, 600);
        // 若合并时把 last_ts 取成了较小的 100，这里会算出 500 并把 0 混进样本。
        assert_eq!(a.iat.iter().collect::<Vec<_>>(), vec![100, 100]);
    }

    // ---- 离散度（手算期望值；不用实现输出当期望） ----

    #[test]
    fn stddev_payload_len_needs_two_packets_and_matches_hand_computation() {
        let mut s = FlowStats::default();
        assert_eq!(s.stddev_payload_len(), 0.0, "没有样本时离散度为 0");
        s.observe(100, 1);
        assert_eq!(s.stddev_payload_len(), 0.0, "单样本没有离散度可言");
        s.observe(300, 2);
        // 手算：均值 200，方差 ((100-200)² + (300-200)²)/2 = 10000，标准差 100。
        assert!((s.stddev_payload_len() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn stddev_distinguishes_a_heartbeat_from_a_mixed_flow() {
        // 均值相同、标准差不同：这正是"只看均值"会漏掉的情形。
        let mut steady = FlowStats::default();
        let mut mixed = FlowStats::default();
        for _ in 0..4 {
            steady.observe(500, 1);
        }
        for len in [0u32, 1000, 400, 600] {
            mixed.observe(len, 1);
        }
        assert_eq!(steady.mean_payload_len(), mixed.mean_payload_len());
        assert_eq!(steady.stddev_payload_len(), 0.0);
        // 手算：均值 500，偏差平方 250000+250000+10000+10000 = 520000，/4 = 130000。
        assert!((mixed.stddev_payload_len() - 130000f64.sqrt()).abs() < 1e-6);
    }

    #[test]
    fn merge_sums_variances_instead_of_averaging_them() {
        let mut a = FlowStats::default();
        a.observe(100, 1);
        a.observe(300, 2);
        let mut b = FlowStats::default();
        b.observe(400, 3);
        b.observe(400, 4);
        assert_eq!(b.stddev_payload_len(), 0.0, "定长流的离散度为 0");
        a.merge(&b);
        // 手算：[100,300,400,400] 均值 300，偏差平方 40000+0+10000+10000=60000，
        // /4 = 15000，标准差 ≈ 122.47448713915891。
        assert_eq!(a.mean_payload_len(), 300);
        assert!((a.stddev_payload_len() - 15000f64.sqrt()).abs() < 1e-9);
        assert!(
            a.stddev_payload_len() > 0.0,
            "把两条流的方差各自算完后取平均会得到 0，但合并后的样本确实更离散"
        );
    }

    #[test]
    fn iat_stddev_matches_hand_computation_and_merges() {
        let mut r = IatRing::new(8);
        assert_eq!(r.stddev_us(), 0.0);
        r.push(0);
        assert_eq!(r.stddev_us(), 0.0, "单样本无离散度");
        r.push(200);
        // 手算：均值 100，方差 (100² + 100²)/2 = 10000，标准差 100。
        assert!((r.stddev_us() - 100.0).abs() < 1e-9);

        let mut other = IatRing::new(8);
        other.push(1000);
        r.merge(&other);
        // 手算：[0,200,1000] 均值 400，方差 (160000+40000+360000)/3 = 186666.67。
        assert_eq!(r.count(), 3);
        assert_eq!(r.mean_us(), 400);
        assert!((r.stddev_us() - (560000f64 / 3.0).sqrt()).abs() < 1e-9);
        assert!(r.stddev_us() > 100.0, "合并必须把方差并进来而不是取平均");
    }

    #[test]
    fn iat_square_sum_push_carries_past_u128_without_wrapping() {
        let mut ring = IatRing::new(1);
        ring.push(u64::MAX);
        ring.push(u64::MAX);
        assert_eq!(ring.count(), 2);
        assert_eq!(ring.retained(), 1);
        // The legacy first moment saturates at u64::MAX. Preserve that contract;
        // exact second moment is 2*M², so variance = M² - (M/2)² = 3*M²/4.
        let expected = u64::MAX as f64 * 3f64.sqrt() / 2.0;
        assert!((ring.stddev_us() / expected - 1.0).abs() < 1e-12);
    }

    #[test]
    fn iat_square_sum_merge_carries_past_u128_without_wrapping() {
        let mut left = IatRing::new(1);
        left.push(u64::MAX);
        let right = left.clone();
        left.merge(&right);
        assert_eq!(left.count(), 2);
        let expected = u64::MAX as f64 * 3f64.sqrt() / 2.0;
        assert!((left.stddev_us() / expected - 1.0).abs() < 1e-12);
    }

    #[test]
    fn iat_merge_into_empty_does_not_replay_retained_samples_into_summary() {
        let mut source = IatRing::new(2);
        for delta in [10, 20, 30, 40] {
            source.push(delta);
        }
        let mut target = IatRing::new(1);
        target.merge(&source);
        assert_eq!(target.capacity(), 1);
        assert_eq!(target.iter().collect::<Vec<_>>(), vec![40]);
        assert_eq!(
            target.count(),
            4,
            "adopting the buffer must not count it twice"
        );
        assert_eq!(target.mean_us(), 25);
        assert_eq!(target.extremes_us(), Some((10, 40)));
        assert!((target.stddev_us() - 125f64.sqrt()).abs() < 1e-12);
        target.push(50);
        assert_eq!(target.count(), 5);
        assert_eq!(target.mean_us(), 30);
        assert!((target.stddev_us() - 200f64.sqrt()).abs() < 1e-12);
    }

    #[test]
    fn iat_square_sum_is_exact_through_the_full_u64_count_range() {
        let mut total = IatRing::new(1);
        let mut block = IatRing::new(1);
        block.push(u64::MAX);
        // Build 1+2+4+...+2^63 samples in 64 merges, without storing the samples.
        for bit in 0..64 {
            total.merge(&block);
            if bit < 63 {
                let copy = block.clone();
                block.merge(&copy);
            }
        }
        assert_eq!(total.count(), u64::MAX);
        // Hand algebra: (2^64-1)^3 = 2^192 - 3*2^128 + 3*2^64 - 1.
        assert_eq!(total.sum_sq_us_high, u64::MAX - 2);
        assert_eq!(total.sum_sq_us, 3 * (1u128 << 64) - 1);
        assert!(total.stddev_us().is_finite());
        assert_eq!(
            total.retained(),
            1,
            "aggregate capacity is independent of count"
        );
    }
}
