//! estimate.rs —— 采样后的量级还原（`CYS-TRF-053` 缺口③）。
//!
//! ## 问题
//!
//! 导出器按 1:N 采了样，采集侧看到的只是"留下来的一部分"。要回答"全网多少字节"，
//! 必须把它还原回全量 —— 而且**只能给区间，不能给一个光溜溜的数**：
//! 采样本身带来的不确定性是这部分估计的固有属性，抹掉它就是在编精度。
//!
//! ## 估计量（手算可复算，不是"调个库"）
//!
//! 抽样设计：每个"单位"以等概率 `p = 1/N` 入样（N 来自 IE 34）。单位是什么取决于
//! 导出侧的采样模式：
//!
//! * `flow` 模式（本仓默认）：单位 = **整条流**（哈希选中就全采），单位取值 = 该流的
//!   真实字节/包数（是**实测值**，不是被缩小过的计数）；
//! * `packet` 模式：单位 = 包（每 N 个留 1 个），单位取值 = 被留下的那些包。
//!
//! 两种模式下 Horvitz–Thompson 估计量的形式完全一样：
//!
//! ```text
//! T̂ = Σ_{i∈S} x_i / p = N · Σ_{i∈S} x_i
//! ```
//!
//! 也就是说：**把留下的记录求和再乘 N**。这条式子对"整条流被选中（计数是实测值）"与
//! "逐包被选中（计数已经小了 N 倍）"都成立 —— 因为它们说的是同一件事：样本里的一个单位
//! 代表总体里的 N 个单位。
//!
//! 方差（同样手推，见文件尾的单测给出数值）：
//!
//! ```text
//! Var(T̂) = Σ_pop x_i² · (1-p)/p   ≈  N(N-1) · Σ_{i∈S} x_i²
//! ```
//!
//! 第二式用 `(1/p)·Σ_S x_i²` 估计总体的 `Σ x_i²`。等大小时退化为熟悉的
//! `相对误差 ≈ 1/√|S|`（单测里对这条退化做了断言）。
//!
//! ## 三条刻意的约束
//!
//! 1. **混合 N 直接拒绝**：不同 N 的记录**不能相加**（"1:4 采到的 1000 字节"与
//!    "1:1 采到的 1000 字节"代表完全不同的量级）。混在一起算出一个数，比不算是更糟的
//!    结果 —— 因为它看起来像个答案。
//! 2. **N = 1 时区间宽为 0**：没采样就没有抽样误差，此时估计值就是精确和。这不是特例，
//!    而是同一套式子在 p = 1 时的自然退化（se = 0）。
//! 3. **不猜导出侧的采样模式**：IE 34 只有间隔，没有模式。两种模式共用同一个点估计式，
//!    但方差在"流被撕开"时（`packet` 模式）会略被低估 —— 这一点写在
//!    `EstimateNote` 里由调用方打印出去，而不是假装区间一定准。
//!
//! ## 这个估计量**不能**回答什么（别越界引用）
//!
//! * 它**完全信任声明**：导出器若在 IE 34 上撒谎（声明 1:1000 却全量导出），
//!   估计值就会错 N 倍且毫无察觉 —— 所以"声明与执行一致"必须由导出侧自证
//!   （见 `sampling::SamplingStats::matches_declaration` 与 `check-sampling.sh`）。
//! * 它不给"丢了多少"的修正：导出丢包（`loss_ppm`）是另一条口径，两者**不能相乘混用**
//!   而不说明。

use crate::ipfix::collector::CollectedFlow;

/// 估计结果的说明性字段：调用方必须把它们打印出来，否则"一个数"会被当成事实。
#[derive(Debug, Clone, PartialEq)]
pub struct VolumeEstimate {
    /// 声明并实际用于还原的采样间隔（来自 IE 34）。
    pub interval: u32,
    /// 参与估计的记录条数。
    pub sampled_units: usize,
    /// 样本内的字节/包合计（**未放大**）。
    pub sampled_bytes: u64,
    pub sampled_packets: u64,
    /// 全量估计（点估计）。
    pub est_bytes: f64,
    pub est_packets: f64,
    /// 标准误（见文件头的方差式）。
    pub se_bytes: f64,
    pub se_packets: f64,
    /// 95% 正态近似区间。
    pub ci95_bytes: (f64, f64),
    pub ci95_packets: (f64, f64),
}

impl VolumeEstimate {
    /// 相对标准误（se / 估计值）；估计值为 0 时返回 0。
    pub fn rel_se_bytes(&self) -> f64 {
        if self.est_bytes <= 0.0 {
            0.0
        } else {
            self.se_bytes / self.est_bytes
        }
    }

    /// 一条必须由调用方打出去的口径说明。
    pub fn note(&self) -> String {
        format!(
            "口径：等概率 1:{} 抽样的 HT 估计（把样本求和 × {}）；区间为 95% 正态近似\
             （相对标准误 {:.2}%）。三点边界：① 它**信任 IE 34 的声明**——导出侧声明造假时\
             估计值会等比例错，故声明与执行一致必须由导出侧自证（check-sampling.sh）；\
             ② 区间按**独立伯努利**抽样算，而本仓导出器用**确定性哈希**（准系统抽样）：实测方差\
             更小 ⇒ 区间**保守**（200 种子实测覆盖率 200/200、设计效应 0.26，见\
             docs/planning/measurements/sampling-variance.json）；若真实流键分布退化到某个\
             残差类，方差会向该模型靠拢甚至超过，此时区间偏窄，须现场多种子重标定；\
             ③ 采样是**逐包**语义（IE 34 说的是包），按流聚合的样本用它算区间只是近似。",
            self.interval,
            self.interval,
            self.rel_se_bytes() * 100.0
        )
    }
}

/// 估计失败的原因。**全部是"拒绝给数"而不是"给个近似数"**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstimateError {
    /// 没有任何可用的记录。
    NoRecords,
    /// 记录里出现了多个不同的采样间隔 —— 相加没有意义。
    MixedIntervals(Vec<u32>),
}

impl std::fmt::Display for EstimateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EstimateError::NoRecords => write!(f, "没有可用记录，无法估计量级"),
            EstimateError::MixedIntervals(ns) => write!(
                f,
                "记录里出现多个采样间隔 {ns:?}：不同采样率的记录**不能相加**\
                 （同一批字节在不同采样率下代表的量级不同）。请按 IE 34 分组分别估计"
            ),
        }
    }
}

/// 正态近似的 95% 分位（1.959964）。
const Z95: f64 = 1.959_963_984_540_054;

/// 从采集到的记录还原全量。
///
/// 与顺序无关（求和与平方和都可交换），故分片/多导出进程下结果一致。
pub fn estimate_volume(flows: &[CollectedFlow]) -> Result<VolumeEstimate, EstimateError> {
    if flows.is_empty() {
        return Err(EstimateError::NoRecords);
    }
    // ① 采样间隔必须唯一：这是"能不能相加"的前提，不是统计细节。
    let mut intervals: Vec<u32> = flows.iter().map(|f| f.sampling_interval).collect();
    intervals.sort_unstable();
    intervals.dedup();
    if intervals.len() > 1 {
        return Err(EstimateError::MixedIntervals(intervals));
    }
    let n = intervals[0].max(1); // interval=0 不该出现（导出侧拒绝），保守按 1 处理
    let nf = f64::from(n);

    let sampled_bytes: u64 = flows.iter().map(|f| f.bytes).sum();
    let sampled_packets: u64 = flows.iter().map(|f| f.packets).sum();
    let sum_sq_bytes: f64 = flows.iter().map(|f| (f.bytes as f64).powi(2)).sum();
    let sum_sq_packets: f64 = flows.iter().map(|f| (f.packets as f64).powi(2)).sum();

    let est_bytes = nf * sampled_bytes as f64;
    let est_packets = nf * sampled_packets as f64;
    // Var(T̂) ≈ N(N-1)·Σ_S x_i²；N=1 时系数为 0 ⇒ 区间宽 0（未采样即精确和）。
    let var_factor = nf * (nf - 1.0);
    let se_bytes = (var_factor * sum_sq_bytes).sqrt();
    let se_packets = (var_factor * sum_sq_packets).sqrt();

    Ok(VolumeEstimate {
        interval: n,
        sampled_units: flows.len(),
        sampled_bytes,
        sampled_packets,
        est_bytes,
        est_packets,
        se_bytes,
        se_packets,
        ci95_bytes: (
            (est_bytes - Z95 * se_bytes).max(0.0),
            est_bytes + Z95 * se_bytes,
        ),
        ci95_packets: (
            (est_packets - Z95 * se_packets).max(0.0),
            est_packets + Z95 * se_packets,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Proto;
    use crate::ipfix::collector::CollectedFlow;
    use std::net::{IpAddr, Ipv4Addr};

    fn flow(i: u8, bytes: u64, packets: u64, interval: u32) -> CollectedFlow {
        CollectedFlow {
            exporter: crate::ipfix::collector::ExporterId {
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                port: 4739,
            },
            odid: 1,
            template_id: 4001,
            key: crate::flow::FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                src_port: 1024 + u16::from(i),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 128, 0, 1)),
                dst_port: 443,
                proto: Proto::Tcp,
            },
            packets,
            bytes,
            first_seen_ms: 1,
            last_seen_ms: 2,
            flow_id: u64::from(i),
            sampling_interval: interval,
        }
    }

    /// 手算：4 条记录 100/200/300/400 字节，声明 1:4。
    ///   Σx = 1000 ⇒ T̂ = 4 × 1000 = **4000**
    ///   Σx² = 10000+40000+90000+160000 = 300000
    ///   Var ≈ N(N-1)·Σx² = 4×3×300000 = 3.6e6 ⇒ se = 1897.3666…
    ///   ci95 = 4000 ± 1.959964×1897.3666 = [281.22…, 7718.77…]
    #[test]
    fn hand_computed_point_estimate_and_interval() {
        let flows = vec![
            flow(1, 100, 10, 4),
            flow(2, 200, 20, 4),
            flow(3, 300, 30, 4),
            flow(4, 400, 40, 4),
        ];
        let e = estimate_volume(&flows).unwrap();
        assert_eq!(e.interval, 4);
        assert_eq!(e.sampled_units, 4);
        assert_eq!(e.sampled_bytes, 1000);
        assert!(
            (e.est_bytes - 4000.0).abs() < 1e-9,
            "点估计 {:?}",
            e.est_bytes
        );
        assert!(
            (e.se_bytes - 1897.366_599_5).abs() < 1e-3,
            "se {:?}",
            e.se_bytes
        );
        assert!(
            (e.ci95_bytes.0 - 281.223_6).abs() < 0.01,
            "{:?}",
            e.ci95_bytes
        );
        assert!(
            (e.ci95_bytes.1 - 7718.776_4).abs() < 0.01,
            "{:?}",
            e.ci95_bytes
        );
        // 包数同式（10/20/30/40）：Σ=100 ⇒ T̂ = 400；Σx²=100+400+900+1600=3000
        //   se = sqrt(4×3×3000) = sqrt(36000) = 189.7366…
        assert!((e.est_packets - 400.0).abs() < 1e-9);
        assert!((e.se_packets - 189.736_659_0).abs() < 1e-3);
    }

    /// 未采样（N=1）⇒ 估计值就是精确和，区间宽 0：没有抽样误差可言。
    #[test]
    fn interval_one_is_exact_with_zero_width() {
        let flows = vec![flow(1, 100, 10, 1), flow(2, 250, 25, 1)];
        let e = estimate_volume(&flows).unwrap();
        assert_eq!(e.est_bytes, 350.0);
        assert_eq!(e.est_packets, 35.0);
        assert_eq!(e.se_bytes, 0.0);
        assert_eq!(e.se_packets, 0.0);
        assert_eq!(e.ci95_bytes, (350.0, 350.0));
        assert_eq!(e.rel_se_bytes(), 0.0);
    }

    /// 混合采样间隔必须**拒绝**（宁可没有数，也不给一个看起来像答案的错数）。
    #[test]
    fn mixed_intervals_are_refused() {
        let flows = vec![flow(1, 100, 10, 4), flow(2, 100, 10, 1)];
        match estimate_volume(&flows) {
            Err(EstimateError::MixedIntervals(ns)) => assert_eq!(ns, vec![1, 4]),
            other => panic!("混合间隔必须报错，得到 {other:?}"),
        }
        assert!(estimate_volume(&[]).is_err());
    }

    /// 退化校验：单位大小都相等时，相对标准误应 ≈ 1/√|S| —— 这是抽样估计的常识，
    /// 对不上说明方差式推错了（而不是"数值有点差异"）。
    #[test]
    fn relative_error_degenerates_to_one_over_sqrt_n() {
        // 100 条记录、每条 1000 字节、声明 1:10 ⇒ 总体 1000 条、真值 1_000_000。
        let flows: Vec<CollectedFlow> = (1..=100u8).map(|i| flow(i, 1000, 100, 10)).collect();
        let e = estimate_volume(&flows).unwrap();
        assert_eq!(e.est_bytes, 1_000_000.0);
        // se = sqrt(10×9×100×1000²) = sqrt(90×1e8) = 94868.3 ; 相对 = 9.4868% ≈ 1/√111
        assert!(
            (e.rel_se_bytes() - 0.094_868_3).abs() < 1e-6,
            "{}",
            e.rel_se_bytes()
        );
        assert!(
            (e.rel_se_bytes() - 1.0 / (111f64).sqrt()).abs() < 0.001,
            "相对标准误应≈1/√(有效样本量)：{}",
            e.rel_se_bytes()
        );
    }

    /// 口径说明必须把三条边界都带上（尤其"区间偏保守"与"信任声明"）：
    /// 少写一条，运维就会把保守区间当精确区间、或以为采集侧能自己发现导出器撒谎。
    #[test]
    fn note_states_the_three_boundaries() {
        let e = estimate_volume(&[flow(1, 100, 1, 4)]).unwrap();
        let n = e.note();
        for needle in ["信任 IE 34", "确定性哈希", "保守", "逐包"] {
            assert!(n.contains(needle), "口径说明缺少「{needle}」：{n}");
        }
    }

    /// 与记录顺序无关（多导出进程/乱序到达下结果必须一致）。
    #[test]
    fn estimate_is_order_independent() {
        let mut a = vec![flow(1, 100, 1, 4), flow(2, 700, 7, 4), flow(3, 300, 3, 4)];
        let mut b = a.clone();
        b.reverse();
        a.rotate_left(1);
        let (ea, eb) = (estimate_volume(&a).unwrap(), estimate_volume(&b).unwrap());
        assert_eq!(ea, eb);
    }
}
