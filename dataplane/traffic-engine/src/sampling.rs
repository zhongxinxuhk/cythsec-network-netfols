//! sampling.rs - 流级采样：**声明与执行必须一致**（`CYS-TRF-053`）。
//!
//! ## 为什么这件事非做不可
//!
//! IPFIX 的 IE 34（`samplingInterval`）是一句**声明**：*"我导出的计数是每 N 个包采 1 个
//! 得到的结果，你要还原量级就乘 N"*。如果导出器把 IE 34 写成 1000、实际一个包都没丢，
//! 那么这句声明就是假的 —— 而它会被采集侧、容量模型、乃至对外的"省网 20 Tbps"
//! 结论一路引用下去。**声明与执行之间没有任何东西会自动把它们对齐**，所以要在这里对齐：
//!
//! * `Sampler` 是唯一做丢弃决定的地方；
//! * `SamplingStats` 记录"实际观测了多少包 / 实际留了多少"；
//! * 导出侧的 IE 34 取自同一份 `SamplingConfig`（**单一来源**），而不是另有一个开关 ——
//!   一个开关能声明，另一个开关决定执行，就是把撒谎的入口留在代码里。
//!
//! ## 两种模式，语义不同（别混用）
//!
//! | 模式 | 决定依据 | 留下的流 | 适用 |
//! | --- | --- | --- | --- |
//! | `FlowConsistent` | **流键哈希**（与包序无关） | 完整（一条流全采或全不采） | 默认。流表/会话/TCP 状态机需要完整包序，逐包随机采会把一条会话撕成半条：状态机看到"跳号"，重组层看到"缺片"，结论是**错误的**而不是"少一点的" |
//! | `PerPacket` | 包计数（每 N 个留 1 个） | 可能被撕裂 | 只需要大致量级、且不关心流完整性的场景（对照/压测） |
//!
//! `FlowConsistent` 的"与包序无关"这一点是**硬要求**而不是巧合：`--workers N` 时
//! 采样决定必须在派发端做（否则各 worker 的计数各自为政），而哈希决定与顺序无关，
//! 于是"多线程采出来的流集合"与"单线程采出来的"逐字节相同。
//!
//! ## 计数不放大（刻意的）
//!
//! 导出的 `packetDeltaCount` / `octetDeltaCount` 是**实测计数**，`Sampler` 不做 ×N。
//! 理由与仓库其它地方一致：乘一个系数等于用一个假设伪造测量值。还原量级是**采集侧**
//! 的事（它知道 IE 34 = N），不是导出侧偷偷把数改大。IE 34 的语义本来就是为此设计的。

use crate::flow::FlowKey;
use crate::hash::key_hash_mixed;

/// 采样模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingMode {
    /// 按流键哈希决定（默认）：同一条流全采或全不采，且与包序无关。
    FlowConsistent,
    /// 每 N 个包留 1 个（按输入顺序计数）。
    PerPacket,
}

impl SamplingMode {
    pub fn name(self) -> &'static str {
        match self {
            SamplingMode::FlowConsistent => "flow",
            SamplingMode::PerPacket => "packet",
        }
    }
}

/// 采样配置。`interval = 1` 表示不采样（合法且是默认值：**没要求采样就别丢包**）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingConfig {
    /// 每 `interval` 个包留 1 个（1 = 全留）。
    pub interval: u32,
    pub mode: SamplingMode,
    /// 哈希种子：换种子 = 换一批被采到的流（同一 interval 下）。
    pub seed: u64,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            interval: 1,
            mode: SamplingMode::FlowConsistent,
            seed: 0,
        }
    }
}

impl SamplingConfig {
    pub fn new(interval: u32, mode: SamplingMode, seed: u64) -> Result<Self, String> {
        if interval == 0 {
            return Err("采样间隔必须 ≥ 1（1 = 不采样）".to_string());
        }
        Ok(Self {
            interval,
            mode,
            seed,
        })
    }

    /// 是否真的会丢包。`interval == 1` 是恒等变换，此时**不得**声明 IE 34 > 1。
    pub fn is_noop(&self) -> bool {
        self.interval == 1
    }
}

/// 采样执行统计。`declared_interval` 与 `observed`/`kept` 必须自洽 —— 这是
/// "声明与执行一致"唯一可被外部检查的地方。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingStats {
    pub interval: u32,
    pub mode: SamplingMode,
    /// 到达采样器的包数（= 采样前）。
    pub observed: u64,
    /// 通过采样器、进入流表的包数。
    pub kept: u64,
}

impl SamplingStats {
    pub fn dropped(&self) -> u64 {
        self.observed.saturating_sub(self.kept)
    }

    /// 实际保留率（ppm）。`observed == 0` 时返回 0。
    pub fn kept_ppm(&self) -> u64 {
        if self.observed == 0 {
            0
        } else {
            self.kept.saturating_mul(1_000_000) / self.observed
        }
    }

    /// 是否满足"声明与执行一致"：这是导出侧写 IE 34 之前**唯一**该问的问题。
    ///
    /// 判定规则（刻意宽松到只挡住"根本没执行"这一类）：
    /// * `interval == 1` ⇒ 必须一个都没丢（`kept == observed`）—— 声明 1 却丢包，同样是假话；
    /// * `interval > 1` ⇒ 必须**确实丢了包**（`kept < observed`）。
    ///
    /// 不做"保留率是否精确等于 1/N"的统计判定：小样本上方差本来就大（10 个包采 1:4
    /// 可能一条都没采到），拿它当判据只会得到一个随机变红/变绿的门禁。**精确比例**由
    /// 门禁用足够大的语料 + 手写上下界来验（见 `scripts/verify/check-sampling.sh`）。
    pub fn matches_declaration(&self) -> bool {
        if self.interval == 1 {
            self.kept == self.observed
        } else {
            self.observed > 0 && self.kept < self.observed
        }
    }
}

/// 采样器。**每条包路径只有一个实例**：就地路径一个、分片路径在派发端一个
/// （放 worker 里会让每个 worker 各采一遍，等于采样率被放大到 N×workers）。
#[derive(Debug, Clone)]
pub struct Sampler {
    cfg: SamplingConfig,
    observed: u64,
    kept: u64,
}

impl Sampler {
    pub fn new(cfg: SamplingConfig) -> Result<Self, String> {
        SamplingConfig::new(cfg.interval, cfg.mode, cfg.seed)?;
        Ok(Self {
            cfg,
            observed: 0,
            kept: 0,
        })
    }

    pub fn config(&self) -> SamplingConfig {
        self.cfg
    }

    /// 每包路径的唯一入口：返回 `true` 表示这个包**进入流表**。
    ///
    /// 参数是**已 `canonical()` 过的键**：TCP 的两个方向必须得到同一个决定，
    /// 否则半条会话进表 —— 比不采样更糟（记录看起来正常，只是少了一半包）。
    pub fn keep(&mut self, key: &FlowKey) -> bool {
        self.observed += 1;
        let keep = if self.cfg.interval <= 1 {
            true
        } else {
            match self.cfg.mode {
                SamplingMode::FlowConsistent => {
                    key_hash_mixed(key).wrapping_add(self.cfg.seed) % u64::from(self.cfg.interval)
                        == 0
                }
                SamplingMode::PerPacket => self.observed % u64::from(self.cfg.interval) == 0,
            }
        };
        if keep {
            self.kept += 1;
        }
        keep
    }

    pub fn stats(&self) -> SamplingStats {
        SamplingStats {
            interval: self.cfg.interval,
            mode: self.cfg.mode,
            observed: self.observed,
            kept: self.kept,
        }
    }
}

impl Default for Sampler {
    fn default() -> Self {
        Self {
            cfg: SamplingConfig::default(),
            observed: 0,
            kept: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Proto;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(i: u32) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i)),
            src_port: 1024 + (i as u16 % 40000),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 128, 0, 1)),
            dst_port: 443,
            proto: Proto::Tcp,
        }
    }

    #[test]
    fn interval_one_keeps_everything() {
        let mut s = Sampler::new(SamplingConfig::default()).unwrap();
        for i in 0..1000 {
            assert!(s.keep(&key(i)), "interval=1 必须全留");
        }
        let st = s.stats();
        assert_eq!(st.observed, 1000);
        assert_eq!(st.kept, 1000);
        assert!(st.matches_declaration(), "interval=1 且一个没丢 ⇒ 自洽");
    }

    #[test]
    fn zero_interval_is_rejected() {
        assert!(SamplingConfig::new(0, SamplingMode::FlowConsistent, 0).is_err());
        assert!(Sampler::new(SamplingConfig {
            interval: 0,
            mode: SamplingMode::FlowConsistent,
            seed: 0
        })
        .is_err());
    }

    #[test]
    fn flow_consistent_decision_is_per_key_and_order_independent() {
        let mut a =
            Sampler::new(SamplingConfig::new(4, SamplingMode::FlowConsistent, 0).unwrap()).unwrap();
        let mut b =
            Sampler::new(SamplingConfig::new(4, SamplingMode::FlowConsistent, 0).unwrap()).unwrap();
        // 同一个键问两次，答案必须一样（否则同一条流会被采成"半条"）
        for i in 0..200u32 {
            let k = key(i);
            assert_eq!(a.keep(&k), a.keep(&k), "同一个键的决定必须稳定");
        }
        // 逆序喂入：留下的是同一批键（与包序无关）
        let mut kept_fwd = Vec::new();
        for i in 0..500u32 {
            if b.keep(&key(i)) {
                kept_fwd.push(i);
            }
        }
        let mut c =
            Sampler::new(SamplingConfig::new(4, SamplingMode::FlowConsistent, 0).unwrap()).unwrap();
        let mut kept_rev = Vec::new();
        for i in (0..500u32).rev() {
            if c.keep(&key(i)) {
                kept_rev.push(i);
            }
        }
        kept_rev.reverse();
        assert_eq!(
            kept_fwd, kept_rev,
            "决定必须与包序无关（--workers N 一致性的前提）"
        );
        assert!(!kept_fwd.is_empty(), "500 条流采 1:4 不可能一条都没有");
    }

    #[test]
    fn flow_consistent_rate_is_near_one_in_n() {
        let mut s =
            Sampler::new(SamplingConfig::new(4, SamplingMode::FlowConsistent, 0).unwrap()).unwrap();
        let n = 20_000u32;
        let kept = (0..n).filter(|i| s.keep(&key(*i))).count();
        // 手算期望 20000/4 = 5000；二项分布 sd = sqrt(20000·0.25·0.75) ≈ 61，
        // 取 ±4×sd ≈ ±244（≈±5%）已经极稳，不会随机变红。
        assert!(
            (4756..=5244).contains(&kept),
            "1:4 采到 {kept} 条，期望 5000±244"
        );
        assert!(s.stats().matches_declaration());
    }

    #[test]
    fn different_seeds_pick_different_flows() {
        // 换种子 = 换一批被采到的流；否则"种子"这个参数就是装饰品。
        let mut a =
            Sampler::new(SamplingConfig::new(8, SamplingMode::FlowConsistent, 1).unwrap()).unwrap();
        let mut b =
            Sampler::new(SamplingConfig::new(8, SamplingMode::FlowConsistent, 2).unwrap()).unwrap();
        let sa: Vec<bool> = (0..400u32).map(|i| a.keep(&key(i))).collect();
        let sb: Vec<bool> = (0..400u32).map(|i| b.keep(&key(i))).collect();
        assert_ne!(sa, sb, "换种子必须换一批流");
    }

    #[test]
    fn per_packet_keeps_every_nth_and_can_tear_flows() {
        let mut s =
            Sampler::new(SamplingConfig::new(4, SamplingMode::PerPacket, 0).unwrap()).unwrap();
        let mut kept = 0;
        for _ in 0..100 {
            if s.keep(&key(7)) {
                kept += 1;
            }
        }
        assert_eq!(kept, 25, "每 4 个留 1 个：100 个包留 25 个");
        assert_eq!(s.stats().kept_ppm(), 250_000);
    }

    #[test]
    fn declaring_without_dropping_is_detected() {
        // "声明 1:N 但一个都没丢"必须能被判出来 —— 这是本模块存在的理由。
        let st = SamplingStats {
            interval: 1000,
            mode: SamplingMode::FlowConsistent,
            observed: 10_000,
            kept: 10_000,
        };
        assert!(!st.matches_declaration(), "声明 1:1000 却全留 ⇒ 不一致");
        let ok = SamplingStats {
            interval: 1000,
            mode: SamplingMode::FlowConsistent,
            observed: 10_000,
            kept: 10,
        };
        assert!(ok.matches_declaration(), "真丢了才算一致");
        // 反过来：声明不采样却丢了包，也是假话
        let bad_noop = SamplingStats {
            interval: 1,
            mode: SamplingMode::FlowConsistent,
            observed: 10_000,
            kept: 9_999,
        };
        assert!(!bad_noop.matches_declaration(), "声明 1:1 却丢包 ⇒ 不一致");
    }
}
