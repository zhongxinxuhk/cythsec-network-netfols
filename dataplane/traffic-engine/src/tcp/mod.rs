// tcp/mod.rs —— TCP 连接状态机（CYS-TRF-012）。
//
// 为什么需要它：会话层原先用「双向都有包即 Established」这条启发式。它的代价是
// **把"看不见的部分"和"不存在"混为一谈**：
//   * 一个被拒绝的连接（SYN → RST）在启发式下只要两侧各有一个包就算"已建立"；
//   * 一个只抓到了半程的流（旁路中途接入）与一条完整握手的流得到完全相同的状态；
//   * 单向扫描（大量 SYN、无回应）根本进不了会话表，因为它等不到反向包。
// 这三种情况在省网流量里都是常态，而它们的处置（计费/告警/阻断）完全不同。
//
// 三条设计约束：
//
// 1. **事件源是 `reassembly::tcp::TcpFlags`，不另写一套标志位**。
//    （HANDOFF §8 第 7 条：重组层已提供 FIN/RST 语义与 SYN 锚定，状态机应复用。）
//    两套标志位定义只要有一处把 FIN/FIN-ACK 的判定写反，就会得出相反的关闭方向，
//    而两边各自的测试都还是绿的。
//
// 2. **非法迁移是显式错误，不是"容忍并继续"**（`strict` 默认开）。
//    状态机的价值一半在于拒绝："RST 之后又来数据"不是"连接继续"，是**抓到了
//    不该出现的字节**（重放、注入、或抓包点乱序）。静默接受会让这类事件从统计里消失。
//
// 3. **但旁路设备必须能中途接入**（`strict = false`）。没抓到 SYN 是常态而非异常，
//    此时把数据当成"非法"会让绝大多数真实流量判不出状态。容忍模式下**不伪造证据**：
//    状态变 Established，但 `adopted_midstream` 为真，且 `initiator()` 保持 `None`
//    —— "谁先发起"这件事没看到就是没看到，不能猜一个填上。

use crate::reassembly::tcp::TcpFlags;

/// 连接端点标识。
///
/// A/B 的**具体含义由调用方定义**（会话层用 canonical 端点序），本模块只保证
/// 同一端点在整条连接的生命周期内始终用同一个符号表示。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    A,
    B,
}

impl Side {
    pub const fn other(self) -> Side {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Side::A => "a",
            Side::B => "b",
        }
    }
}

/// 简化的 TCP 连接状态。
///
/// 与 RFC 9293 的差异（刻意，写在这里以免被当成实现不全）：
///   * 没有 `CLOSING`：同时关闭（双方 FIN 交叉且未互相确认）直接进 `TimeWait`。
///     本状态机的用途是**判定与统计**，不是复现协议栈；多一个只在交叉场景出现的
///     中间态只会增加迁移表里没人验证的分支。
///   * `TimeWait` 不区分主动/被动方，统一在超时后进 `Closed`。
///   * `Reset` 与 `Closed` 分开：`Reset` 说明"这条连接是被打断的"，与"正常关闭"
///     在告警与计费上语义相反，合并会让 RST 洪水看起来像正常收尾。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
    Reset,
}

impl TcpState {
    /// 是否处于数据可双向传输的正常状态。
    pub const fn is_established(self) -> bool {
        matches!(self, TcpState::Established)
    }

    /// 是否已有数据面活动（含半关闭：半关闭状态下数据仍可单向传输）。
    pub const fn has_data_flow(self) -> bool {
        matches!(
            self,
            TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::LastAck
        )
    }

    /// 是否已终结（不再期望任何报文，除重传外）。
    pub const fn is_terminal(self) -> bool {
        matches!(self, TcpState::Closed | TcpState::Reset)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            TcpState::Closed => "closed",
            TcpState::SynSent => "syn_sent",
            TcpState::SynReceived => "syn_received",
            TcpState::Established => "established",
            TcpState::FinWait1 => "fin_wait1",
            TcpState::FinWait2 => "fin_wait2",
            TcpState::CloseWait => "close_wait",
            TcpState::LastAck => "last_ack",
            TcpState::TimeWait => "time_wait",
            TcpState::Reset => "reset",
        }
    }
}

/// 一次 TCP 观测：状态机唯一需要知道的两件事 —— 标志位与**段载荷长度**。
///
/// 为什么不复用 `flow::Packet::payload_len`：那是 **IP 载荷长度（含四层头）**，
/// 用于字节统计；而事件判定问的是"这个段带数据了吗"。用含头的长度去判，
/// 一个 20 字节的纯 ACK 会被判成 `Data` —— 握手最后一个 ACK 因此不再走 `Ack`
/// 分支，`FinWait2`/`CloseWait`/`LastAck` 在真实流量里永远到不了；而最终状态
/// **看起来仍然正常**（容忍模式下 `Data` 恰好也把连接推到 Established）。
/// 这类错误不会自己暴露，所以单位由类型 + 参数名钉死，且必须显式构造。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpObservation {
    pub flags: TcpFlags,
    /// 四层载荷长度，**不含**四层头（TCP 头不算数据）。
    pub l4_payload_len: u32,
    /// 序号。`None` = 帧被截断到读不到序号。
    ///
    /// 必须是 `Option` 而不是 0：`0` 是一个合法序号，拿它当“没读到”会把截断包
    /// 数成重传（`CYS-TRF-015` 的判定完全建立在这个区分上）。
    pub seq: Option<u32>,
    /// 确认号。`None` = 读不到（目前只用于诊断，不参与判定）。
    pub ack: Option<u32>,
}

impl TcpObservation {
    /// 只有标志位与段长、**没有序号信息**的观测。
    ///
    /// 用它的调用方（合成脚本、只看标志位的旧路径）不能产出重传/乱序计数：
    /// 会话侧会把该会话的计数置为“未观测”而不是 0。
    pub const fn new(flags: TcpFlags, l4_payload_len: u32) -> Self {
        Self {
            flags,
            l4_payload_len,
            seq: None,
            ack: None,
        }
    }

    /// 带序号的观测（真实抓包/共享环路径用这个）。
    pub const fn with_seq(flags: TcpFlags, l4_payload_len: u32, seq: u32, ack: u32) -> Self {
        Self {
            flags,
            l4_payload_len,
            seq: Some(seq),
            ack: Some(ack),
        }
    }

    /// 只有标志位、没有数据的段：纯 ACK / SYN / FIN 都属于这一类。
    pub const fn no_payload(flags: TcpFlags) -> Self {
        Self::new(flags, 0)
    }
}

/// 状态机输入事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpEvent {
    /// SYN（不含 ACK）。
    Syn,
    /// SYN + ACK。
    SynAck,
    /// 纯 ACK（无载荷、无 SYN/FIN/RST）。
    Ack,
    /// 带载荷的报文（不含 SYN/FIN/RST）。
    Data,
    /// FIN（可能同时带载荷；载荷记账由重组层负责）。
    Fin,
    /// RST。
    Rst,
    /// 超时（由超时表驱动，不是从报文里读出来的）。
    Timeout,
}

impl TcpEvent {
    /// 由标志位与**四层载荷长度**判定事件类型。
    ///
    /// `l4_payload_len` 是四层载荷长度，**不含四层头** —— 也就是"这个段带数据了吗"。
    /// 传含头的 IP 载荷长度（纯 ACK 也有 20 字节）会把纯 ACK 判成 `Data`，
    /// 于是握手最后一个 ACK 不走 `Ack` 分支、`FinWait2`/`CloseWait`/`LastAck`
    /// 在真实流量里永远到不了，而状态看起来仍然"挺正常"。故参数名里带单位。
    ///
    /// 优先级是**刻意的**，且必须写下来，否则"SYN+FIN 同置"这种畸形/探测报文
    /// 会在不同实现里归到不同事件上：
    ///   RST > SYN+ACK > SYN > FIN > Data > ACK。
    /// RST 最高：RST 的语义是"立即终止"，同置其它位不改变这个事实。
    /// SYN 高于 FIN：`SYN+FIN` 不是合法握手，但当 SYN 处理能保证它不会把状态机
    /// 推进到一个"已关闭"的假终态（真正要防的是攻击者用一个同置包把连接判死）。
    pub fn classify(flags: &TcpFlags, l4_payload_len: u32) -> Self {
        if flags.rst {
            TcpEvent::Rst
        } else if flags.syn && flags.ack {
            TcpEvent::SynAck
        } else if flags.syn {
            TcpEvent::Syn
        } else if flags.fin {
            TcpEvent::Fin
        } else if l4_payload_len > 0 {
            TcpEvent::Data
        } else if flags.ack {
            TcpEvent::Ack
        } else {
            // 无标志、无载荷：畸形或截断。按 Data 处理而不是丢弃 —— 丢弃会让
            // "收到过一个看不懂的包"这个事实从统计里消失。状态机对 Data 的处置
            // 在各状态下都是显式定义的。
            TcpEvent::Data
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            TcpEvent::Syn => "syn",
            TcpEvent::SynAck => "syn_ack",
            TcpEvent::Ack => "ack",
            TcpEvent::Data => "data",
            TcpEvent::Fin => "fin",
            TcpEvent::Rst => "rst",
            TcpEvent::Timeout => "timeout",
        }
    }
}

/// 状态机配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConfig {
    /// 严格模式：非法迁移返回错误且**不改状态**。
    ///
    /// 默认开。关掉它意味着"旁路中途接入"这一类常态流量能被接受 ——
    /// 但同时也意味着"RST 之后又来数据"会被静默忽略。两者是同一个开关的两面，
    /// 所以它必须是一个**显式的部署选择**，不能有"顺便宽松一点"的默认值。
    pub strict: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self { strict: true }
    }
}

impl TcpConfig {
    /// 旁路中途接入用的容忍配置。
    pub const fn tolerant() -> Self {
        Self { strict: false }
    }
}

/// 一次迁移的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    pub from: TcpState,
    pub to: TcpState,
}

impl Transition {
    pub fn changed(&self) -> bool {
        self.from != self.to
    }
}

fn same_state(a: TcpState, b: TcpState) -> bool {
    a == b
}

/// 状态机错误：非法迁移。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IllegalTransition {
    pub from: TcpState,
    pub event: TcpEvent,
    pub side: Side,
}

impl std::fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "非法 TCP 迁移：状态 {} 收到来自 {} 的 {}（严格模式下拒绝）",
            self.from.as_str(),
            self.side.as_str(),
            self.event.as_str()
        )
    }
}

impl std::error::Error for IllegalTransition {}

/// TCP 连接状态机。
#[derive(Debug, Clone)]
pub struct TcpStateMachine {
    cfg: TcpConfig,
    state: TcpState,
    /// 发起方（见过 SYN 才有值）。没见过就是 `None`，**不猜**。
    initiator: Option<Side>,
    /// 先发 FIN 的一方。
    first_fin_side: Option<Side>,
    /// 是否因中途接入而被"采纳"为 Established。
    adopted_midstream: bool,
    transitions: u64,
    illegal_events: u64,
}

impl TcpStateMachine {
    pub fn new(cfg: TcpConfig) -> Self {
        Self {
            cfg,
            state: TcpState::Closed,
            initiator: None,
            first_fin_side: None,
            adopted_midstream: false,
            transitions: 0,
            illegal_events: 0,
        }
    }

    pub fn cfg(&self) -> TcpConfig {
        self.cfg
    }

    pub fn state(&self) -> TcpState {
        self.state
    }

    /// 发起方；未观察到 SYN 时为 `None`。
    pub fn initiator(&self) -> Option<Side> {
        self.initiator
    }

    /// 是否在中途接入时被采纳（开头握手未见）。
    pub fn adopted_midstream(&self) -> bool {
        self.adopted_midstream
    }

    /// 已发生的状态迁移次数（不含自环）。
    pub fn transitions(&self) -> u64 {
        self.transitions
    }

    /// 被判定为非法的事件次数。语义要分清：
    ///   * **严格模式**：返回 `Err` 的那些事件；
    ///   * **容忍模式**：被**忽略**（状态不变）的那些事件；
    ///   * 容忍模式中被**采纳**的事件（中途接入的 Data/FIN）**不计入**这里 ——
    ///     它们不是"被拒绝"，而是按显式规则接受，特征记在 `adopted_midstream()`。
    /// 容忍模式下这个计数仍必须累加：忽略不等于没发生。
    pub fn illegal_events(&self) -> u64 {
        self.illegal_events
    }

    pub fn first_fin_side(&self) -> Option<Side> {
        self.first_fin_side
    }

    /// 应用一个事件。
    ///
    /// 严格模式返回 `Err` 时状态**不变**（拒绝即拒绝，不做"尽力而为"的推进）；
    /// 容忍模式返回 `Ok` 且状态不变，同时 `illegal_events` 仍会累加。
    pub fn apply(&mut self, event: TcpEvent, side: Side) -> Result<Transition, IllegalTransition> {
        let from = self.state;
        let next = match event {
            TcpEvent::Rst => Ok(TcpState::Reset),
            TcpEvent::Timeout => Ok(TcpState::Closed),
            TcpEvent::Syn => self.apply_syn(side, from),
            TcpEvent::SynAck => self.apply_syn_ack(side, from),
            TcpEvent::Ack => self.apply_ack(side, from),
            TcpEvent::Data => self.apply_data(side, from),
            TcpEvent::Fin => self.apply_fin(side, from),
        }?;
        if !same_state(next, from) {
            self.transitions += 1;
            self.state = next;
        }
        Ok(Transition { from, to: next })
    }

    /// 用一批标志位驱动状态机（便捷入口，等价于 `apply(TcpEvent::classify(..), side)`）。
    ///
    /// `l4_payload_len` 同样**不含四层头**，见 `TcpEvent::classify`。
    pub fn apply_flags(
        &mut self,
        flags: &TcpFlags,
        l4_payload_len: u32,
        side: Side,
    ) -> Result<Transition, IllegalTransition> {
        self.apply(TcpEvent::classify(flags, l4_payload_len), side)
    }

    fn illegal(
        &mut self,
        from: TcpState,
        event: TcpEvent,
        side: Side,
    ) -> Result<TcpState, IllegalTransition> {
        self.illegal_events += 1;
        if self.cfg.strict {
            Err(IllegalTransition { from, event, side })
        } else {
            Ok(from)
        }
    }

    fn apply_syn(&mut self, side: Side, from: TcpState) -> Result<TcpState, IllegalTransition> {
        match from {
            TcpState::Closed => {
                self.initiator = Some(side);
                Ok(TcpState::SynSent)
            }
            // SYN 重传：同侧再发不改变状态（也不改发起方）。
            TcpState::SynSent if self.initiator == Some(side) => Ok(TcpState::SynSent),
            // 同时打开：另一侧也发 SYN。
            TcpState::SynSent => {
                self.initiator.get_or_insert(side);
                Ok(TcpState::SynReceived)
            }
            TcpState::SynReceived => Ok(TcpState::SynReceived), // 重传
            _ => self.illegal(from, TcpEvent::Syn, side),
        }
    }

    fn apply_syn_ack(&mut self, side: Side, from: TcpState) -> Result<TcpState, IllegalTransition> {
        match from {
            // 正常握手：发起方收到对方的 SYN-ACK。
            TcpState::SynSent if self.initiator != Some(side) => Ok(TcpState::SynReceived),
            // 同时打开：发起方自己也发 SYN-ACK，握手就此完成。
            TcpState::SynReceived if self.initiator == Some(side) => Ok(TcpState::Established),
            // 对端重传 SYN-ACK。
            TcpState::SynReceived => Ok(TcpState::SynReceived),
            _ => self.illegal(from, TcpEvent::SynAck, side),
        }
    }

    fn apply_ack(&mut self, side: Side, from: TcpState) -> Result<TcpState, IllegalTransition> {
        match from {
            TcpState::SynReceived if self.initiator == Some(side) => Ok(TcpState::Established),
            TcpState::SynReceived => self.illegal(from, TcpEvent::Ack, side),
            // 主动关闭方收到对方的 ACK：FIN 已被确认。
            TcpState::FinWait1 if self.first_fin_side != Some(side) => Ok(TcpState::FinWait2),
            TcpState::FinWait1 => Ok(TcpState::FinWait1), // 自己重传 ACK / 迟到的 ACK
            // 被动关闭方发出的 FIN 被对方确认（确认来自先发 FIN 的一方）。
            TcpState::LastAck if self.first_fin_side == Some(side) => Ok(TcpState::Closed),
            TcpState::Established
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::LastAck
            | TcpState::TimeWait => Ok(from),
            // SYN-SENT 上收到纯 ACK：没有任何东西可确认（SYN-ACK 会走 SynAck 分支）。
            _ => self.illegal(from, TcpEvent::Ack, side),
        }
    }

    fn apply_data(&mut self, side: Side, from: TcpState) -> Result<TcpState, IllegalTransition> {
        match from {
            // 半关闭状态下仍可单向传数据，这是合法行为而不是"连接已结束"。
            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::LastAck
            | TcpState::TimeWait => Ok(from),
            // TFO（TCP Fast Open）：SYN 自带数据，此时还谈不上"已建立"。
            TcpState::SynSent => Ok(from),
            // SYN-RECEIVED 上出现数据：多半是**最终 ACK 丢了**而不是没建立。
            // 严格模式仍判非法（以免把"抓包点漏包"伪装成正常连接）；
            // 容忍模式采纳为 Established，但不置 adopted_midstream（握手前两段确实看到了）。
            TcpState::SynReceived => {
                if self.cfg.strict {
                    self.illegal(from, TcpEvent::Data, side)
                } else {
                    Ok(TcpState::Established)
                }
            }
            // 完全没握手的流：旁路中途接入。容忍模式下采纳，并**标记出来**。
            TcpState::Closed => {
                if self.cfg.strict {
                    self.illegal(from, TcpEvent::Data, side)
                } else {
                    self.adopted_midstream = true;
                    Ok(TcpState::Established)
                }
            }
            TcpState::Reset => self.illegal(from, TcpEvent::Data, side),
        }
    }

    fn apply_fin(&mut self, side: Side, from: TcpState) -> Result<TcpState, IllegalTransition> {
        match from {
            TcpState::Established => {
                self.first_fin_side = Some(side);
                match self.initiator {
                    // 主动关闭：先发 FIN 的是发起方。
                    Some(init) if init == side => Ok(TcpState::FinWait1),
                    // 被动关闭：对方先关，本端进入 CLOSE-WAIT。
                    Some(_) => Ok(TcpState::CloseWait),
                    // 发起方未知（中途接入）：只能按"主动关闭"记，
                    // 差异由 `initiator() == None` 暴露给下游。
                    None => Ok(TcpState::FinWait1),
                }
            }
            TcpState::FinWait1 => {
                if self.first_fin_side != Some(side) {
                    Ok(TcpState::TimeWait)
                } else {
                    Ok(TcpState::FinWait1) // 自己重传 FIN
                }
            }
            TcpState::FinWait2 => {
                if self.first_fin_side != Some(side) {
                    Ok(TcpState::TimeWait)
                } else {
                    Ok(TcpState::FinWait2)
                }
            }
            TcpState::CloseWait => {
                if self.first_fin_side != Some(side) {
                    Ok(TcpState::LastAck)
                } else {
                    Ok(TcpState::CloseWait)
                }
            }
            TcpState::LastAck => Ok(TcpState::LastAck), // FIN 重传
            TcpState::TimeWait => Ok(TcpState::TimeWait), // 对端 FIN 重传
            // 没握手就见到 FIN：容忍模式下采纳为"正在关闭"，且标记中途接入。
            TcpState::Closed => {
                if self.cfg.strict {
                    self.illegal(from, TcpEvent::Fin, side)
                } else {
                    self.adopted_midstream = true;
                    self.first_fin_side = Some(side);
                    Ok(TcpState::FinWait1)
                }
            }
            TcpState::SynSent | TcpState::SynReceived | TcpState::Reset => {
                self.illegal(from, TcpEvent::Fin, side)
            }
        }
    }
}

impl Default for TcpStateMachine {
    fn default() -> Self {
        Self::new(TcpConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags_ack() -> TcpFlags {
        TcpFlags {
            ack: true,
            ..TcpFlags::default()
        }
    }

    fn flags_syn() -> TcpFlags {
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        }
    }

    fn flags_syn_ack() -> TcpFlags {
        TcpFlags {
            syn: true,
            ack: true,
            ..TcpFlags::default()
        }
    }

    fn flags_fin_ack() -> TcpFlags {
        TcpFlags {
            fin: true,
            ack: true,
            ..TcpFlags::default()
        }
    }

    fn flags_rst() -> TcpFlags {
        TcpFlags {
            rst: true,
            ack: true,
            ..TcpFlags::default()
        }
    }

    fn machine() -> TcpStateMachine {
        TcpStateMachine::default()
    }

    fn tolerant() -> TcpStateMachine {
        TcpStateMachine::new(TcpConfig::tolerant())
    }

    fn step(m: &mut TcpStateMachine, f: &TcpFlags, payload: u32, side: Side) -> TcpState {
        m.apply_flags(f, payload, side).expect("应为合法迁移").to
    }

    // ---- 事件分类 ----

    #[test]
    fn classify_priority_is_rst_syn_fin_data_ack() {
        let mut all = TcpFlags {
            rst: true,
            syn: true,
            fin: true,
            ack: true,
            ..TcpFlags::default()
        };
        assert_eq!(TcpEvent::classify(&all, 100), TcpEvent::Rst);
        all.rst = false;
        assert_eq!(TcpEvent::classify(&all, 100), TcpEvent::SynAck);
        all.ack = false;
        assert_eq!(TcpEvent::classify(&all, 100), TcpEvent::Syn);
        all.syn = false;
        assert_eq!(
            TcpEvent::classify(&all, 100),
            TcpEvent::Fin,
            "FIN 优先于载荷"
        );
        all.fin = false;
        assert_eq!(TcpEvent::classify(&all, 100), TcpEvent::Data);
        assert_eq!(
            TcpEvent::classify(&all, 0),
            TcpEvent::Data,
            "无标志无载荷也归类为 Data"
        );
        assert_eq!(TcpEvent::classify(&TcpFlags::default(), 0), TcpEvent::Data);
        assert_eq!(TcpEvent::classify(&flags_ack(), 0), TcpEvent::Ack);
        assert_eq!(
            TcpEvent::classify(&flags_ack(), 1400),
            TcpEvent::Data,
            "带载荷的 ACK 是 Data"
        );
    }

    // ---- 合法路径全覆盖 ----

    #[test]
    fn full_three_way_handshake() {
        let mut m = machine();
        assert_eq!(step(&mut m, &flags_syn(), 0, Side::A), TcpState::SynSent);
        assert_eq!(m.initiator(), Some(Side::A));
        assert_eq!(
            step(&mut m, &flags_syn_ack(), 0, Side::B),
            TcpState::SynReceived
        );
        assert_eq!(
            step(&mut m, &flags_ack(), 0, Side::A),
            TcpState::Established
        );
        assert!(m.state().is_established());
        assert!(!m.adopted_midstream());
        assert_eq!(m.transitions(), 3);
        assert_eq!(m.illegal_events(), 0);
    }

    #[test]
    fn syn_retransmission_keeps_state_and_initiator() {
        let mut m = machine();
        step(&mut m, &flags_syn(), 0, Side::A);
        step(&mut m, &flags_syn(), 0, Side::A);
        assert_eq!(m.state(), TcpState::SynSent);
        assert_eq!(m.initiator(), Some(Side::A));
        assert_eq!(m.transitions(), 1, "自环不计入迁移次数");
    }

    #[test]
    fn simultaneous_open_reaches_established() {
        let mut m = machine();
        step(&mut m, &flags_syn(), 0, Side::A); // A 发起
        step(&mut m, &flags_syn(), 0, Side::B); // B 也发起
        assert_eq!(m.state(), TcpState::SynReceived);
        assert_eq!(m.initiator(), Some(Side::A), "先见到的 SYN 定为发起方");
        step(&mut m, &flags_syn_ack(), 0, Side::A); // A 的 SYN-ACK
        assert!(m.state().is_established());
    }

    #[test]
    fn syn_ack_retransmission_is_absorbed() {
        let mut m = machine();
        step(&mut m, &flags_syn(), 0, Side::A);
        step(&mut m, &flags_syn_ack(), 0, Side::B);
        step(&mut m, &flags_syn_ack(), 0, Side::B);
        assert_eq!(m.state(), TcpState::SynReceived);
    }

    #[test]
    fn connection_refused_by_rst() {
        let mut m = machine();
        step(&mut m, &flags_syn(), 0, Side::A);
        assert_eq!(step(&mut m, &flags_rst(), 0, Side::B), TcpState::Reset);
        assert!(m.state().is_terminal());
        assert!(!m.state().is_established(), "被拒绝的连接不得判为已建立");
    }

    #[test]
    fn active_close_path_by_initiator() {
        let mut m = machine();
        step(&mut m, &flags_syn(), 0, Side::A);
        step(&mut m, &flags_syn_ack(), 0, Side::B);
        step(&mut m, &flags_ack(), 0, Side::A);
        assert_eq!(
            step(&mut m, &flags_fin_ack(), 0, Side::A),
            TcpState::FinWait1
        );
        assert_eq!(step(&mut m, &flags_ack(), 0, Side::B), TcpState::FinWait2);
        assert_eq!(
            step(&mut m, &flags_fin_ack(), 0, Side::B),
            TcpState::TimeWait
        );
        assert_eq!(step(&mut m, &flags_ack(), 0, Side::A), TcpState::TimeWait);
        assert_eq!(
            step(&mut m, &TcpFlags::default(), 0, Side::A),
            TcpState::TimeWait
        );
        // TIME_WAIT 靠超时终结。
        assert_eq!(
            m.apply(TcpEvent::Timeout, Side::A).unwrap().to,
            TcpState::Closed
        );
    }

    #[test]
    fn passive_close_path_by_responder() {
        let mut m = machine();
        step(&mut m, &flags_syn(), 0, Side::A);
        step(&mut m, &flags_syn_ack(), 0, Side::B);
        step(&mut m, &flags_ack(), 0, Side::A);
        assert_eq!(
            step(&mut m, &flags_fin_ack(), 0, Side::B),
            TcpState::CloseWait,
            "对端先关，本端应进 CLOSE-WAIT 而不是 FIN-WAIT"
        );
        assert_eq!(step(&mut m, &flags_ack(), 0, Side::A), TcpState::CloseWait);
        assert_eq!(
            step(&mut m, &flags_fin_ack(), 0, Side::A),
            TcpState::LastAck
        );
        assert_eq!(step(&mut m, &flags_ack(), 0, Side::B), TcpState::Closed);
    }

    #[test]
    fn fin_retransmission_is_absorbed_in_every_closing_state() {
        let mut m = machine();
        step(&mut m, &flags_syn(), 0, Side::A);
        step(&mut m, &flags_syn_ack(), 0, Side::B);
        step(&mut m, &flags_ack(), 0, Side::A);
        step(&mut m, &flags_fin_ack(), 0, Side::A); // FinWait1
        step(&mut m, &flags_fin_ack(), 0, Side::A);
        assert_eq!(m.state(), TcpState::FinWait1);
        step(&mut m, &flags_ack(), 0, Side::B); // FinWait2
        step(&mut m, &flags_fin_ack(), 0, Side::A);
        assert_eq!(
            m.state(),
            TcpState::FinWait2,
            "先发 FIN 的一侧重传 FIN 不改状态"
        );
    }

    #[test]
    fn data_is_allowed_in_all_half_closed_states() {
        for pre in [
            TcpState::Established,
            TcpState::FinWait1,
            TcpState::FinWait2,
            TcpState::CloseWait,
            TcpState::LastAck,
        ] {
            let mut m = machine();
            // 用合法路径把状态机推到目标状态。
            match pre {
                TcpState::Established => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_syn_ack(), 0, Side::B);
                    step(&mut m, &flags_ack(), 0, Side::A);
                }
                TcpState::FinWait1 => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_syn_ack(), 0, Side::B);
                    step(&mut m, &flags_ack(), 0, Side::A);
                    step(&mut m, &flags_fin_ack(), 0, Side::A);
                }
                TcpState::FinWait2 => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_syn_ack(), 0, Side::B);
                    step(&mut m, &flags_ack(), 0, Side::A);
                    step(&mut m, &flags_fin_ack(), 0, Side::A);
                    step(&mut m, &flags_ack(), 0, Side::B);
                }
                TcpState::CloseWait => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_syn_ack(), 0, Side::B);
                    step(&mut m, &flags_ack(), 0, Side::A);
                    step(&mut m, &flags_fin_ack(), 0, Side::B);
                }
                TcpState::LastAck => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_syn_ack(), 0, Side::B);
                    step(&mut m, &flags_ack(), 0, Side::A);
                    step(&mut m, &flags_fin_ack(), 0, Side::B);
                    step(&mut m, &flags_fin_ack(), 0, Side::A);
                }
                other => panic!("用例未覆盖状态 {other:?}"),
            }
            assert_eq!(m.state(), pre);
            step(&mut m, &flags_ack(), 1400, Side::A);
            assert_eq!(m.state(), pre, "半关闭状态下仍可传数据：{pre:?}");
            assert_eq!(m.illegal_events(), 0);
        }
    }

    #[test]
    fn tfo_syn_with_payload_stays_in_syn_sent() {
        let mut m = machine();
        m.apply(TcpEvent::Syn, Side::A).unwrap();
        m.apply(TcpEvent::Data, Side::A).unwrap();
        assert_eq!(m.state(), TcpState::SynSent, "SYN 带数据不得直接判成立");
    }

    #[test]
    fn timeout_closes_from_any_state() {
        for pre in [
            TcpState::Closed,
            TcpState::SynSent,
            TcpState::SynReceived,
            TcpState::Established,
            TcpState::TimeWait,
            TcpState::Reset,
        ] {
            let mut m = machine();
            match pre {
                TcpState::Closed => {}
                TcpState::SynSent => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                }
                TcpState::SynReceived => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_syn_ack(), 0, Side::B);
                }
                TcpState::Established => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_syn_ack(), 0, Side::B);
                    step(&mut m, &flags_ack(), 0, Side::A);
                }
                TcpState::Reset => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_rst(), 0, Side::B);
                }
                TcpState::TimeWait => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_syn_ack(), 0, Side::B);
                    step(&mut m, &flags_ack(), 0, Side::A);
                    step(&mut m, &flags_fin_ack(), 0, Side::A);
                    step(&mut m, &flags_fin_ack(), 0, Side::B);
                }
                other => panic!("用例未覆盖状态 {other:?}"),
            }
            let t = m.apply(TcpEvent::Timeout, Side::A).expect("超时始终合法");
            assert_eq!(t.to, TcpState::Closed, "{pre:?} 超时应收敛到 Closed");
        }
    }

    // ---- 非法路径拒绝 ----

    #[test]
    fn illegal_paths_are_rejected_and_state_is_unchanged() {
        let cases: Vec<(&str, TcpState, TcpEvent, Side)> = vec![
            (
                "Closed 上收到 ACK",
                TcpState::Closed,
                TcpEvent::Ack,
                Side::A,
            ),
            (
                "Closed 上收到 SYN-ACK",
                TcpState::Closed,
                TcpEvent::SynAck,
                Side::B,
            ),
            (
                "Closed 上收到数据",
                TcpState::Closed,
                TcpEvent::Data,
                Side::A,
            ),
            (
                "Closed 上收到 FIN",
                TcpState::Closed,
                TcpEvent::Fin,
                Side::A,
            ),
            (
                "SynSent 上收到纯 ACK",
                TcpState::SynSent,
                TcpEvent::Ack,
                Side::A,
            ),
            (
                "SynReceived 上收到数据",
                TcpState::SynReceived,
                TcpEvent::Data,
                Side::A,
            ),
            ("Reset 上收到数据", TcpState::Reset, TcpEvent::Data, Side::A),
            ("Reset 上收到 FIN", TcpState::Reset, TcpEvent::Fin, Side::A),
            (
                "Established 上收到第二个 SYN",
                TcpState::Established,
                TcpEvent::Syn,
                Side::A,
            ),
        ];
        for (desc, pre, event, side) in cases {
            let mut m = machine();
            match pre {
                TcpState::Closed => {}
                TcpState::SynSent => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                }
                TcpState::SynReceived => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_syn_ack(), 0, Side::B);
                }
                TcpState::Established => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_syn_ack(), 0, Side::B);
                    step(&mut m, &flags_ack(), 0, Side::A);
                }
                TcpState::Reset => {
                    step(&mut m, &flags_syn(), 0, Side::A);
                    step(&mut m, &flags_rst(), 0, Side::B);
                }
                other => panic!("用例未覆盖前置状态 {other:?}"),
            }
            assert_eq!(m.state(), pre, "{desc}：前置状态应就位");
            let err = m.apply(event, side).unwrap_err();
            assert_eq!(err.from, pre, "{desc}");
            assert_eq!(err.event, event, "{desc}");
            assert_eq!(m.state(), pre, "{desc}：拒绝后状态必须不变");
            assert_eq!(m.illegal_events(), 1, "{desc}");
        }
    }

    #[test]
    fn error_display_mentions_state_and_event() {
        let err = IllegalTransition {
            from: TcpState::Closed,
            event: TcpEvent::Data,
            side: Side::B,
        };
        let s = err.to_string();
        assert!(s.contains("closed"), "{s}");
        assert!(s.contains("data"), "{s}");
        assert!(s.contains('b'), "{s}");
    }

    // ---- 容忍模式（旁路中途接入）----

    #[test]
    fn tolerant_mode_adopts_midstream_data_but_marks_it() {
        let mut m = tolerant();
        m.apply(TcpEvent::Data, Side::B).unwrap();
        assert_eq!(m.state(), TcpState::Established);
        assert!(m.adopted_midstream(), "中途接入必须可辨认");
        assert_eq!(m.initiator(), None, "没看到 SYN 就不许猜发起方");
        // 采纳是"按规则接受"，不是"拒绝"：不计入 illegal_events。
        // 真正被忽略的事件（状态不变）才计入，见下一条用例。
        assert_eq!(m.illegal_events(), 0);
        assert!(m.transitions() > 0, "采纳必然伴随一次状态迁移");
    }

    #[test]
    fn tolerant_mode_ignores_but_counts_illegal_events() {
        let mut m = tolerant();
        // Closed 上收到 ACK：没有可采纳的语义，状态不变但计数增加。
        let t = m.apply(TcpEvent::Ack, Side::A).unwrap();
        assert_eq!(t.from, TcpState::Closed);
        assert_eq!(t.to, TcpState::Closed);
        assert_eq!(m.illegal_events(), 1);
    }

    #[test]
    fn tolerant_mode_completes_handshake_when_final_ack_is_lost() {
        let mut m = tolerant();
        m.apply(TcpEvent::Syn, Side::A).unwrap();
        m.apply(TcpEvent::SynAck, Side::B).unwrap();
        assert_eq!(m.state(), TcpState::SynReceived);
        m.apply(TcpEvent::Data, Side::B).unwrap();
        assert_eq!(
            m.state(),
            TcpState::Established,
            "最终 ACK 丢失不应让连接判不出"
        );
        assert!(!m.adopted_midstream(), "握手前两段看到了，不算中途接入");
    }

    #[test]
    fn tolerant_mode_midstream_fin_is_attributed() {
        let mut m = tolerant();
        m.apply(TcpEvent::Fin, Side::A).unwrap();
        assert_eq!(m.state(), TcpState::FinWait1);
        assert!(m.adopted_midstream());
        assert_eq!(m.first_fin_side(), Some(Side::A));
    }

    #[test]
    fn strict_mode_never_adopts_and_tolerant_never_errors() {
        // 同一串事件在两种模式下必须给出"可判定的不同结果"，而不是碰巧一样。
        let events = [
            (TcpEvent::Data, Side::A),
            (TcpEvent::Rst, Side::B),
            (TcpEvent::Data, Side::A),
            (TcpEvent::Syn, Side::A),
            (TcpEvent::SynAck, Side::B),
            (TcpEvent::Ack, Side::A),
        ];
        let mut strict = machine();
        let mut lenient = tolerant();
        let mut strict_errors = 0;
        for (e, s) in events {
            if strict.apply(e, s).is_err() {
                strict_errors += 1;
            }
            assert!(lenient.apply(e, s).is_ok(), "容忍模式不得对任何事件报错");
        }
        assert!(strict_errors > 0, "严格模式必须拒绝其中的非法事件");
        assert!(lenient.illegal_events() > 0);
        assert!(!strict.adopted_midstream());
    }
}
