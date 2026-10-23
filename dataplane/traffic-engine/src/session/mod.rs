// session/mod.rs —— 会话层：id 分配、双向聚合法、超时销毁（CYS-TRF-010/011）。
//
// 会话与流的关系（这条不能含糊，否则统计会重复计数或漏计）：
//   * **流**（`flow::Flow`）是方向敏感的，一条双向通信有两条流（上行、下行）；
//   * **会话**（`Session`）把同一双向通信聚合为一条，主键是 `FlowKey::canonical()`；
//   * 字节/包数只存在**流**里，会话的合计由两条流相加 —— 不另存一份。
//     另存一份必然出现"改了流没改会话"的静默不一致。
//
// 三条设计约束：
//
// 1. **方向归属由规范端点序决定，不由到达顺序决定**（CYS-TRF-005）。
//    这样"先看到响应"（旁路中途接入）与"先看到请求"得到同一个会话键，
//    不会把一条通信劈成两条。至于"谁先发起"，那是另一件事，由状态机回答
//    （`Session::initiator()`，没见过 SYN 就是 `None`）。
//
// 2. **会话超时按 TCP 状态分档**：会话建立后进度条变长，靠 `TimeoutClass` 升级，
//    而不是靠"所有会话一个超时"。见 `SessionManager::expire`。
//
// 3. **单个畸形包不得中断流水线**。非法 TCP 迁移被**计数并记录**，
//    但 `observe()` 不返回错误：一个 RST 之后的乱序数据包不该让整个分析进程停下。
//    "拒绝"的语义体现在状态没有推进上，这一点必须能从计数看出来。

use std::collections::HashSet;

use crate::flow::table::{
    new_fnv_map, FlowEntry, FlowTable, FlowTableConfig, FnvMap, TimeoutClass, TimeoutTable,
};
use crate::flow::{FlowKey, Packet};
use crate::tcp::{
    IllegalTransition, Side, TcpConfig, TcpEvent, TcpObservation, TcpState, TcpStateMachine,
};

/// 默认最大会话数。
pub const DEFAULT_MAX_SESSIONS: usize = 1 << 16;

/// 会话 id 分配器（CYS-TRF-010）。
///
/// 两条性质：
///   * **单调递增**：新 id 永远大于此前发出过的所有 id，便于按 id 排序即得到创建顺序；
///   * **空闲 id 复用**：会话销毁后 id 回到池中，避免长跑进程把 id 空间烧穿。
///
/// 复用带来的唯一风险是"同一 id 前后指向两个不同会话"。因此 `live` 集合是必需的：
/// 释放过的 id 才会进空闲池，且在再次分配前会校验它已不在 live 里。
/// 没有这个校验时，一次重复释放就会让两个会话共用一个 id，而下游按 id 关联时无法察觉。
#[derive(Debug, Clone)]
pub struct SessionIdAllocator {
    next: u64,
    free: Vec<u64>,
    live: HashSet<u64>,
    issued: u64,
    reused: u64,
}

impl SessionIdAllocator {
    pub fn new(start: u64) -> Self {
        Self {
            next: start,
            free: Vec::new(),
            live: HashSet::new(),
            issued: 0,
            reused: 0,
        }
    }

    /// 分配一个 id；空间耗尽（u64 上限）时返回 `None`。
    ///
    /// `u64::MAX` **保留不发放**：它作为"有效 id"的上边界，让"下一号会溢出"这件事
    /// 在分配那一刻就被判定（而不是发出去之后才发现游标无法推进）。
    pub fn alloc(&mut self) -> Option<u64> {
        // 先尝试空闲池；池里可能混入重复项（重复释放），拿之前必须校验。
        while let Some(id) = self.free.pop() {
            if self.live.insert(id) {
                self.issued += 1;
                self.reused += 1;
                return Some(id);
            }
        }
        let id = self.next;
        let next = self.next.checked_add(1)?;
        self.next = next;
        self.live.insert(id);
        self.issued += 1;
        Some(id)
    }

    /// 释放一个 id；返回它此前是否处于在用状态（`false` 表示重复释放或从未发出）。
    pub fn release(&mut self, id: u64) -> bool {
        if self.live.remove(&id) {
            self.free.push(id);
            true
        } else {
            false
        }
    }

    /// 当前在用 id 数。
    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    pub fn is_live(&self, id: u64) -> bool {
        self.live.contains(&id)
    }

    /// 累计发出次数（含复用）。
    pub fn issued(&self) -> u64 {
        self.issued
    }

    /// 其中来自复用的次数。
    pub fn reused(&self) -> u64 {
        self.reused
    }

    pub fn next_id(&self) -> u64 {
        self.next
    }
}

/// 一个方向的包数与字节数（字节口径同 `Session::bytes`：IP 载荷长度，含四层头）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SideCounters {
    pub packets: u64,
    pub bytes: u64,
}

/// 一个方向的序列号轨迹（`CYS-TRF-015`）。
///
/// 定义拿 tshark 当裁判做过探针。两次探针（同字节、不同 ACK 上下文给过不同分类）
/// 说明定义必须钉在**可复现样本**上，而不是一句“tshark 实测如何”的表格：
/// 可复现样本 = `datasets/tcp-analysis/` + `check-tcp-analysis.py`（2026-10-23，
/// Wireshark 4.6.7 / macOS，完整握手（含第三次 ACK）的六模式探针）：
///
/// | 模式 | Wireshark 实测标记 | 本实现的判定 |
/// | --- | --- | --- |
/// | 正常按序 + 握手 + 重复 ACK | 只有 `duplicate_ack` | 0/0 |
/// | 已 ACK 的段原样重发 | `retransmission` | `retransmissions` |
/// | 未 ACK 就重发同一段（seq==cursor） | `retransmission` | `retransmissions` |
/// | 段部分重叠（前旧后新） | `out_of_order` | `out_of_order` |
/// | 先发后一段再补前一段 | 补洞段 `out_of_order`，超前段 `lost_segment` | `out_of_order`（补洞段） |
/// | 中间段永不再来（只有超前段） | 只有 `lost_segment`，无 retr/ooo | 两者都不计 |
///
/// 关口钉的恒等式：`本实现 retr == tshark retransmission 帧数`、
/// `本实现 ooo == tshark out_of_order 帧数`；`lost_segment` 是“丢包/未捕获”口径，
/// 与本项两个计数器无关，样本里钉住其帧数防止将来两边默默漂移。
/// 反面教训（同批 2026-10-22 探针的教训）：握手缺第三次 ACK 时，同样的重叠/补洞
/// 字节被 Wireshark 归成 retransmission —— “拿实现去对表格”会因构型不同而假绿或假红，
/// 所以只有“生成器真值 ↔ 实现 ↔ tshark”在同一条 pcap 上同场比对才算数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeqTrack {
    /// 已按序收到的右端点（下一个期望序号）。用 `u64` 避免 32 位序号回绕把判定打转。
    ///
    /// **序号回绕本身不处理**（那是另一个特性：要区分“回绕”与“倒退”必须有窗口语义），
    /// 这里只是不让它在 `u32` 加法上静默变成错误计数。
    cursor: Option<u64>,
    /// 见过的最高段右端点（含乱序到达的）：用来判断“这洞是不是被后面的段暴露过”。
    max_end: u64,
    retransmissions: u64,
    out_of_order: u64,
    /// 参与过判定的段数（没序号的段不计入，也**不能**把没判定过的会话报成 0）。
    judged: u64,
}

impl Default for SeqTrack {
    fn default() -> Self {
        Self {
            cursor: None,
            max_end: 0,
            retransmissions: 0,
            out_of_order: 0,
            judged: 0,
        }
    }
}

impl SeqTrack {
    /// 吃掉一个段。`consume` 是该段占用的序号空间（载荷 + SYN/FIN 各算 1）。
    ///
    /// 0 长度的纯 ACK 不走这里：它们不占序号空间，拿“序号比期望小”去数它们会把
    /// 每个重复 ACK 都数成重传（探针里 baseline 模式假阳 0 靠的就是这一步）。
    fn observe_segment(&mut self, seq: u64, consume: u64) {
        if consume == 0 {
            return;
        }
        self.judged += 1;
        let end = seq.saturating_add(consume);
        let cursor = match self.cursor {
            None => {
                // 中途接入的首段：无法知道它之前收过什么，只建立基准，不判定。
                self.cursor = Some(end);
                self.max_end = end;
                return;
            }
            Some(c) => c,
        };
        if end <= cursor {
            // 全部字节此前已按序收到（无论是否被 ACK）→ 重传
            self.retransmissions += 1;
        } else if seq < cursor {
            // 既有旧字节又有新字节 → 乱序。2026-10-23 正式样本探针：完整握手下
            // Wireshark 同样给 out_of_order（早期无第三次 ACK 的探针里它曾归
            // retransmission —— 分类依赖 ACK 上下文，所以比对只钉在同一条 pcap 上）。
            self.out_of_order += 1;
            self.max_end = self.max_end.max(end);
        } else if seq == cursor {
            // 按序推进；但如果之前已经有更高序号的段到达过（洞被暴露过），
            // 这一补洞段就是乱序（探针实测 Wireshark 对补洞段同样报 out_of_order）。
            if end < self.max_end {
                self.out_of_order += 1;
            }
            self.cursor = Some(end);
            self.max_end = self.max_end.max(end);
        } else {
            // seq > cursor：前面缺了一段。本段不判定：探针实测 Wireshark 给它的是
            // `lost_segment`（丢包/未捕获口径），retrans/out-of-order 两列都不计 ——
            // 把“没收到”数成乱序，下游两个指标就都假了。记下右端点，等补洞段再判。
            self.max_end = self.max_end.max(end);
        }
    }
}

/// 一条双向会话。
#[derive(Debug, Clone)]
pub struct Session {
    pub id: u64,
    /// 规范（方向无关）五元组，会话主键。
    pub key: FlowKey,
    /// 规范端点 A→B 方向的流键（等于 `key`）。
    pub forward: FlowKey,
    /// 规范端点 B→A 方向的流键。
    pub backward: FlowKey,
    /// TCP 状态机（非 TCP 协议不推进，恒为 `Closed`）。
    pub tcp: TcpStateMachine,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub packets: u64,
    pub bytes: u64,
    /// 方向切换次数（上下行交替的频度，是交互型/批处理型流量的区分特征之一）。
    pub direction_switches: u64,
    /// 按**规范方向**（A = `forward` 键，B = `backward` 键）分别计的包数与字节数。
    ///
    /// 存 A/B 而不是"上/下行"：规范方向与会话是谁发起无关，同一个会话在两个
    /// 方向键上拿到的是同一个数；"上/下行"必须再过一道 `initiator` 才能说（见
    /// [`Session::uplink_bytes`]），中途接入的会话发起方未知 ⇒ 那是 `None` 而不是 0。
    pub side_counters: [SideCounters; 2],
    last_side: Option<Side>,
    /// 按方向的序列号轨迹（`CYS-TRF-015`：重传 / 乱序）。
    seq_track: [SeqTrack; 2],
    /// 首次看到 SYN 的那一侧与时间（握手 RTT 的起点）。
    syn_at: Option<(Side, u64)>,
    /// 握手 RTT（SYN → 对侧 SYN/ACK），微秒。没测到是 `None`，不是 0。
    handshake_rtt_us: Option<u64>,
}

impl Session {
    fn new(id: u64, key: FlowKey, cfg: TcpConfig) -> Self {
        Self {
            id,
            key,
            forward: key,
            backward: key.reverse(),
            tcp: TcpStateMachine::new(cfg),
            first_seen_us: 0,
            last_seen_us: 0,
            packets: 0,
            bytes: 0,
            direction_switches: 0,
            side_counters: [SideCounters::default(), SideCounters::default()],
            last_side: None,
            seq_track: [SeqTrack::default(), SeqTrack::default()],
            syn_at: None,
            handshake_rtt_us: None,
        }
    }

    /// 某个方向键属于哪一侧；与本会话无关时返回 `None`。
    pub fn side_of(&self, key: &FlowKey) -> Option<Side> {
        if *key == self.forward {
            Some(Side::A)
        } else if *key == self.backward {
            Some(Side::B)
        } else {
            None
        }
    }

    pub fn is_tcp(&self) -> bool {
        self.key.proto.is_tcp()
    }

    pub fn tcp_state(&self) -> TcpState {
        self.tcp.state()
    }

    /// 发起方；没见过 SYN 时为 `None`（不猜）。
    pub fn initiator(&self) -> Option<Side> {
        self.tcp.initiator()
    }

    /// 是否因中途接入而被采纳（开头握手未见）。
    pub fn adopted_midstream(&self) -> bool {
        self.tcp.adopted_midstream()
    }

    /// 当前适用的超时档位。
    pub fn timeout_class(&self) -> TimeoutClass {
        if self.is_tcp() {
            TimeoutClass::for_tcp_state(self.tcp.state())
        } else {
            TimeoutClass::for_proto(self.key.proto)
        }
    }

    pub fn idle_us(&self, now_us: u64) -> u64 {
        now_us.saturating_sub(self.last_seen_us)
    }

    fn observe(
        &mut self,
        pkt: &Packet,
        side: Side,
        tcp: Option<&TcpObservation>,
    ) -> Option<IllegalTransition> {
        if self.packets == 0 {
            self.first_seen_us = pkt.timestamp_us;
        }
        if pkt.timestamp_us > self.last_seen_us {
            self.last_seen_us = pkt.timestamp_us;
        }
        self.packets += 1;
        self.bytes += u64::from(pkt.payload_len);
        {
            let idx = match side {
                Side::A => 0,
                Side::B => 1,
            };
            self.side_counters[idx].packets += 1;
            self.side_counters[idx].bytes += u64::from(pkt.payload_len);
        }
        if let Some(prev) = self.last_side {
            if prev != side {
                self.direction_switches += 1;
            }
        }
        self.last_side = Some(side);

        // 只有 TCP 跑状态机。非 TCP 的包进来只记账 —— 给 UDP 造一个"连接状态"
        // 是凭空发明协议语义，下游会当真。
        if !self.is_tcp() {
            return None;
        }
        let Some(tcp) = tcp else {
            // TCP 包但调用方没给出可解释的段信息（标志位读不到，或帧在四层头之前被
            // 截断）：只记账，不推进状态机。不"猜一个 ACK"，因为猜错会把状态推到
            // Established，而那个错误之后再也看不出来（状态机自身不会报错）。
            return None;
        };
        // 注意用的是段载荷长度，**不是** pkt.payload_len（后者含四层头，
        // 会把每个纯 ACK 都判成 Data），见 TcpObservation 的说明。
        let event = TcpEvent::classify(&tcp.flags, tcp.l4_payload_len);
        self.track_tcp_anomalies(side, tcp, pkt.timestamp_us);
        self.tcp.apply(event, side).err()
    }

    /// 重传 / 乱序 / 握手 RTT（`CYS-TRF-015`）。
    ///
    /// 与状态机完全分开：状态机只吃事件类型，这里吃序号与时间。**不能因为
    /// 判定失败就影响状态机**（一个乱序段不该把会话推成错误状态），也不能反过来。
    fn track_tcp_anomalies(&mut self, side: Side, tcp: &TcpObservation, ts_us: u64) {
        // —— 握手 RTT：第一个 SYN 到对侧第一个 SYN/ACK ——
        if tcp.flags.is_syn() && !tcp.flags.is_syn_ack() {
            if self.syn_at.is_none() {
                self.syn_at = Some((side, ts_us));
            }
        } else if tcp.flags.is_syn_ack() {
            if let Some((syn_side, syn_ts)) = self.syn_at {
                if syn_side != side && self.handshake_rtt_us.is_none() {
                    self.handshake_rtt_us = Some(ts_us.saturating_sub(syn_ts));
                }
            }
        }

        // —— 重传 / 乱序：没序号就什么都不动（计入“未观测”而不是 0）——
        let Some(seq) = tcp.seq else { return };
        let consume =
            u64::from(tcp.l4_payload_len) + u64::from(tcp.flags.syn) + u64::from(tcp.flags.fin);
        let idx = Self::side_index(side);
        self.seq_track[idx].observe_segment(u64::from(seq), consume);
    }

    /// 会话两侧重传计数之和。**全程读不到序号时返回 `None`**：
    /// 截断采集 / 只看标志位的调用路径下，报 0 会被下游读成“这条会话没有重传”，
    /// 而实情是“本会话没有任何判定输入”（项内约定：“未识别 ≠ 识别为无”）。
    pub fn retransmissions(&self) -> Option<u64> {
        let judged = self.seq_track[0].judged + self.seq_track[1].judged;
        if judged == 0 {
            None
        } else {
            Some(self.seq_track[0].retransmissions + self.seq_track[1].retransmissions)
        }
    }

    /// 同上语义的乱序计数。
    pub fn out_of_order(&self) -> Option<u64> {
        let judged = self.seq_track[0].judged + self.seq_track[1].judged;
        if judged == 0 {
            None
        } else {
            Some(self.seq_track[0].out_of_order + self.seq_track[1].out_of_order)
        }
    }

    /// 参与过重传/乱序判定的段数（两侧合计）。`0` 表示本会话**没有任何判定输入**
    /// （截断采集 / 调用方没给序号），而不是“判定完发现没重传”。
    pub fn seq_judged(&self) -> u64 {
        self.seq_track[0].judged + self.seq_track[1].judged
    }

    /// 一个方向的包数与字节数（供端到端统计出口用；口径同 `Session::bytes`）。
    pub fn side_counters(&self) -> [SideCounters; 2] {
        self.side_counters
    }

    /// 握手 RTT（微秒）。没见到完整 SYN → SYN/ACK 时为 `None`（中途接入不猜）。
    pub fn handshake_rtt_us(&self) -> Option<u64> {
        self.handshake_rtt_us
    }

    /// 发起方方向的字节（“上行”）。**发起方未知 ⇒ `None`**，不拿 A 当发起方兜底：
    /// 中途接入的会话里 A 只是字典序更小的一侧，把它叫上行会让下游把随机数当成指标。
    pub fn uplink_bytes(&self) -> Option<u64> {
        let side = self.initiator()?;
        Some(self.side_counters[Self::side_index(side)].bytes)
    }

    /// 对侧（应答方）字节。同样：发起方未知 ⇒ `None`。
    pub fn downlink_bytes(&self) -> Option<u64> {
        let side = self.initiator()?.other();
        Some(self.side_counters[Self::side_index(side)].bytes)
    }

    /// 下行/上行字节比。任一侧为 0 或发起方未知 ⇒ `None`（比 0 或 inf 诚实）。
    pub fn down_up_ratio(&self) -> Option<f64> {
        let up = self.uplink_bytes()?;
        let down = self.downlink_bytes()?;
        if up == 0 {
            return None;
        }
        Some(down as f64 / up as f64)
    }

    const fn side_index(side: Side) -> usize {
        match side {
            Side::A => 0,
            Side::B => 1,
        }
    }
}

/// 会话管理器配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfig {
    /// 流表配置（含五档超时）。
    pub table: FlowTableConfig,
    /// TCP 状态机配置（严格 / 容忍）。
    pub tcp: TcpConfig,
    /// 最大会话数；超出时逐出最久未活动的会话。
    pub max_sessions: usize,
    /// 会话 id 起始值。
    pub id_start: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            table: FlowTableConfig::default(),
            tcp: TcpConfig::default(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            id_start: 1,
        }
    }
}

impl SessionConfig {
    /// 旁路中途接入用的配置：TCP 容忍模式 + 较小容量（单机分析离线 pcap 够用）。
    pub fn bypass() -> Self {
        Self {
            tcp: TcpConfig::tolerant(),
            ..Self::default()
        }
    }
}

/// 一次观测的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub session_id: u64,
    pub key: FlowKey,
    pub is_new: bool,
    pub side: Side,
    pub state: TcpState,
    /// 本次包触发的非法 TCP 迁移（若有）。**不中断处理**，但必须可被统计。
    pub illegal: Option<IllegalTransition>,
}

/// 管理器计数。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ManagerStats {
    pub packets: u64,
    pub sessions_created: u64,
    pub sessions_expired: u64,
    pub sessions_evicted: u64,
    /// 非法 TCP 迁移次数（严格模式下会被计数；容忍模式下也计数）。
    pub illegal_tcp_events: u64,
    /// 会话 id 空间耗尽导致无法新建的会话数（正常配置下恒为 0）。
    pub dropped_no_id: u64,
}

/// 会话管理器。
pub struct SessionManager {
    cfg: SessionConfig,
    table: FlowTable,
    sessions: FnvMap<FlowKey, Session>,
    alloc: SessionIdAllocator,
    stats: ManagerStats,
}

impl SessionManager {
    pub fn new(cfg: SessionConfig) -> Self {
        let mut table = FlowTable::new(cfg.table);
        table.clear_observer();
        Self {
            cfg,
            table,
            sessions: new_fnv_map(),
            alloc: SessionIdAllocator::new(cfg.id_start),
            stats: ManagerStats::default(),
        }
    }

    pub fn cfg(&self) -> SessionConfig {
        self.cfg
    }

    pub fn stats(&self) -> ManagerStats {
        self.stats
    }

    /// 底层流表（方向敏感的方向级数据在这里）。
    pub fn flows(&self) -> &FlowTable {
        &self.table
    }

    pub fn flows_mut(&mut self) -> &mut FlowTable {
        &mut self.table
    }

    /// 方向级条目。
    pub fn flow_entry(&self, key: &FlowKey) -> Option<&FlowEntry> {
        self.table.get(key)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn flow_count(&self) -> usize {
        self.table.len()
    }

    /// 按规范键查会话（传入任方向的键都可以）。
    pub fn session(&self, key: &FlowKey) -> Option<&Session> {
        self.sessions.get(&key.canonical())
    }

    pub fn session_by_id(&self, id: u64) -> Option<&Session> {
        self.sessions.values().find(|s| s.id == id)
    }

    /// 以确定顺序遍历会话（按规范键排序）。
    pub fn sessions_sorted(&self) -> Vec<&Session> {
        let mut v: Vec<&Session> = self.sessions.values().collect();
        v.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        v
    }

    /// 观测一个包。`tcp` 只有 TCP 包才需要（其它协议、或四层头读不到的帧传 `None`）。
    ///
    /// 传进来的 `TcpObservation` 里的载荷长度是**段载荷长度**；字节统计仍然
    /// 使用 `pkt.payload_len`（IP 载荷长度，含四层头），两者口径不同、不可互换。
    pub fn observe(&mut self, pkt: &Packet, tcp: Option<&TcpObservation>) -> Observation {
        self.stats.packets += 1;
        let key = pkt.key.canonical();
        let side = if pkt.key == key { Side::A } else { Side::B };

        // 1. 先喂方向级流表：字节/包数只在这里记一份。
        self.table.observe(pkt);

        // 2. 会话：存在则更新，不存在则（可能先逐出一条）新建。
        let tcp_cfg = self.cfg.tcp;
        let (id, is_new, illegal) = if let Some(s) = self.sessions.get_mut(&key) {
            let illegal = s.observe(pkt, side, tcp);
            (s.id, false, illegal)
        } else {
            if self.sessions.len() >= self.cfg.max_sessions.max(1) {
                self.evict_lru_session();
            }
            match self.alloc.alloc() {
                Some(id) => {
                    let mut s = Session::new(id, key, tcp_cfg);
                    let illegal = s.observe(pkt, side, tcp);
                    self.sessions.insert(key, s);
                    self.stats.sessions_created += 1;
                    (id, true, illegal)
                }
                None => {
                    // id 空间耗尽：只保留方向级统计，不建会话。
                    // 这是显式的降级（并计数），而不是静默丢弃整条包。
                    self.stats.dropped_no_id += 1;
                    let state = TcpState::Closed;
                    return Observation {
                        session_id: 0,
                        key,
                        is_new: false,
                        side,
                        state,
                        illegal: None,
                    };
                }
            }
        };

        if illegal.is_some() {
            self.stats.illegal_tcp_events += 1;
        }

        // 3. 会话状态变化会改变超时档位：建立后走长超时。
        //
        // **两个方向都要更新**。只更新当前包的方向会留下一个滞后档位的反向流：
        // 握手时反向流（SYN-ACK）到达那一刻会话还在 SYN-RECEIVED，档位是 transient；
        // 若之后没有反向包，这条反向流就会按 30 秒超时被回收 —— 而它的会话还在，
        // 结果是"上下行只剩一条流"，字节统计静默少一半。
        let class = self
            .sessions
            .get(&key)
            .map_or(TimeoutClass::TcpTransient, |s| s.timeout_class());
        self.table.set_class(&key, class);
        self.table.set_class(&key.reverse(), class);

        let state = self
            .sessions
            .get(&key)
            .map_or(TcpState::Closed, |s| s.tcp_state());
        Observation {
            session_id: id,
            key,
            is_new,
            side,
            state,
            illegal,
        }
    }

    /// 回收超时的会话与流。返回 `(会话数, 流数)`。
    ///
    /// 会话超时判据用**会话自己的档位**（由 TCP 状态决定），流超时判据用流表档位。
    /// 两者共用同一张 `TimeoutTable`：分开配置会让"会话还在、它的流已被删"变成
    /// 常规状态，而那种状态下统计必然自相矛盾。
    pub fn expire(&mut self, now_us: u64) -> (usize, usize) {
        let timeouts: TimeoutTable = self.cfg.table.timeouts;
        let mut expired: Vec<FlowKey> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.idle_us(now_us) >= timeouts.timeout_us(s.timeout_class()))
            .map(|(k, _)| *k)
            .collect();
        // 排序后回收：HashMap 迭代顺序不定，顺序不定的副作用是"哪条会话先被销毁"
        // 随运行变化，进而让输出（与未来的落库动作）不可复现。
        expired.sort_unstable();
        let n = expired.len();
        for k in expired {
            if let Some(s) = self.sessions.remove(&k) {
                self.alloc.release(s.id);
                self.stats.sessions_expired += 1;
            }
        }
        let flows = self.table.expire(now_us);
        (n, flows)
    }

    /// 取出并清空全部会话（按规范键排序）。用于产出记录后释放内存。
    pub fn drain_sessions_sorted(&mut self) -> Vec<Session> {
        let mut v: Vec<Session> = self.sessions.drain().map(|(_, s)| s).collect();
        v.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        for s in &v {
            self.alloc.release(s.id);
        }
        v
    }

    /// 当前在用会话 id 数（与 `session_count()` 对照可发现 id 泄漏）。
    pub fn live_ids(&self) -> usize {
        self.alloc.live_count()
    }

    pub fn id_allocator(&self) -> &SessionIdAllocator {
        &self.alloc
    }

    /// 逐出最久未活动的会话（容量上限保护）。
    fn evict_lru_session(&mut self) {
        let victim = self
            .sessions
            .iter()
            .min_by(|(ka, a), (kb, b)| a.last_seen_us.cmp(&b.last_seen_us).then_with(|| ka.cmp(kb)))
            .map(|(k, _)| *k);
        if let Some(k) = victim {
            if let Some(s) = self.sessions.remove(&k) {
                self.alloc.release(s.id);
                self.stats.sessions_evicted += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Proto, IPPROTO_TCP, IPPROTO_UDP};
    use crate::reassembly::tcp::TcpFlags;

    fn key(a: u8, sport: u16, b: u8, dport: u16, proto: u8) -> FlowKey {
        FlowKey::new_ipv4([10, 0, 0, a], sport, [10, 0, 0, b], dport, proto)
    }

    fn tcp_key() -> FlowKey {
        key(1, 40000, 2, 443, IPPROTO_TCP)
    }

    fn pkt(k: FlowKey, ts: u64, len: u32) -> Packet {
        Packet {
            key: k,
            payload_len: len,
            timestamp_us: ts,
        }
    }

    fn syn() -> TcpFlags {
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        }
    }

    fn syn_ack() -> TcpFlags {
        TcpFlags {
            syn: true,
            ack: true,
            ..TcpFlags::default()
        }
    }

    /// 测试用段观测。测试里不构造四层头，因此把"IP 载荷长度"与"段载荷长度"
    /// 取同一个值；生产路径由解码器分别给出这两个值（见 pipeline::analyze_pcap）。
    fn seg(flags: TcpFlags, l4_payload_len: u32) -> TcpObservation {
        TcpObservation::new(flags, l4_payload_len)
    }

    fn ack() -> TcpFlags {
        TcpFlags {
            ack: true,
            ..TcpFlags::default()
        }
    }

    // ---- CYS-TRF-015 会话级重传 / 乱序 / RTT / 上下行 ----
    //
    // 六组模式的期望值由构造参数手写；与 tshark 的分类在 2026-10-23 的正式样本
    // 探针上逐组对齐（完整握手电报含第三次 ACK）：baseline 0/0、已 ACK 重发→retr、
    // 未 ACK 重发→retr、部分重叠→ooo、补洞段→ooo（超前段 lost）、
    // 中间段永不再来→两边 retr/ooo 都 0。最后一条是防“把没收到数成乱序”的
    // 关键反向断言；逐组比对由 `check-tcp-analysis.py` 在同一条 pcap 上守门。

    /// 带序号的段观测（生产路径由 `tcp_seq_ack` 从四层头读出）。
    fn segq(flags: TcpFlags, len: u32, seq: u32, ackno: u32) -> TcpObservation {
        TcpObservation::with_seq(flags, len, seq, ackno)
    }

    fn mgr1() -> SessionManager {
        SessionManager::new(SessionConfig::default())
    }

    /// 跑一段脚本（side, ts, flags, len, seq, ack），返回会话引用所需的一切已喂入。
    fn feed(m: &mut SessionManager, script: &[(bool, u64, TcpFlags, u32, u32, u32)]) {
        for (from_a, ts, fl, len, seq, ackno) in script.iter() {
            let k = if *from_a {
                tcp_key()
            } else {
                tcp_key().reverse()
            };
            m.observe(&pkt(k, *ts, *len), Some(&segq(*fl, *len, *seq, *ackno)));
        }
    }

    fn session_of(m: &SessionManager) -> &Session {
        m.session(&tcp_key()).expect("会话应存在")
    }

    #[test]
    fn cys_trf_015_clean_handshake_yields_zero_counts_and_measured_rtt() {
        let mut m = mgr1();
        feed(
            &mut m,
            &[
                (true, 0, syn(), 0, 1000, 0),
                (false, 1500, syn_ack(), 0, 5000, 1001),
                (true, 1510, ack(), 0, 1001, 5001),
                (true, 1520, data_flags(), 100, 1001, 5001),
                (false, 1530, ack(), 0, 5001, 1101),
                (true, 1540, data_flags(), 100, 1101, 5001),
            ],
        );
        let s = session_of(&m);
        assert_eq!(s.retransmissions(), Some(0), "干净会话不得产出重传");
        assert_eq!(s.out_of_order(), Some(0), "干净会话不得产出乱序");
        assert_eq!(
            s.handshake_rtt_us(),
            Some(1500),
            "RTT = SYN → SYN/ACK 的实测间隔（不是 0，也不是猜）"
        );
    }

    #[test]
    fn cys_trf_015_retransmission_of_acked_data_is_counted() {
        let mut m = mgr1();
        feed(
            &mut m,
            &[
                (true, 0, syn(), 0, 1000, 0),
                (false, 100, syn_ack(), 0, 5000, 1001),
                (true, 110, data_flags(), 100, 1001, 5001),
                (false, 120, ack(), 0, 5001, 1101),
                (true, 130, data_flags(), 100, 1101, 5001),
                (false, 140, ack(), 0, 5001, 1201),
                (true, 900, data_flags(), 100, 1101, 5001), // 已被 ACK 的那段原样重发
            ],
        );
        let s = session_of(&m);
        assert_eq!(s.retransmissions(), Some(1));
        assert_eq!(s.out_of_order(), Some(0), "重发已收到的字节不是乱序");
    }

    #[test]
    fn cys_trf_015_resend_before_ack_is_also_a_retransmission() {
        // 探针实测：未等 ACK 就重发同一段，Wireshark 给的是 retransmission（不是乱序）。
        let mut m = mgr1();
        feed(
            &mut m,
            &[
                (true, 0, syn(), 0, 1000, 0),
                (false, 100, syn_ack(), 0, 5000, 1001),
                (true, 110, data_flags(), 100, 1001, 5001),
                (true, 120, data_flags(), 100, 1001, 5001),
            ],
        );
        let s = session_of(&m);
        assert_eq!(s.retransmissions(), Some(1));
        assert_eq!(s.out_of_order(), Some(0));
    }

    #[test]
    fn cys_trf_015_reorder_counts_out_of_order_not_retransmission() {
        // 先发后一段（seq 1101），再补前一段（1001）：补上的那个是乱序。
        let mut m = mgr1();
        feed(
            &mut m,
            &[
                (true, 0, syn(), 0, 1000, 0),
                (false, 100, syn_ack(), 0, 5000, 1001),
                (true, 110, data_flags(), 100, 1101, 5001),
                (true, 120, data_flags(), 100, 1001, 5001),
            ],
        );
        let s = session_of(&m);
        assert_eq!(s.out_of_order(), Some(1));
        assert_eq!(
            s.retransmissions(),
            Some(0),
            "补洞的字节此前根本没收到，不是重传"
        );
    }

    #[test]
    fn cys_trf_015_missing_segment_is_neither_retransmission_nor_out_of_order() {
        // 关键反向断言：中间一段永不再来。探针实测 tshark 只给它 `lost_segment`，
        // retrans/out-of-order 两列都不计；把它数成乱序会把“丢包/未捕获”混进“乱序”，
        // 下游两个指标就都假了。
        let mut m = mgr1();
        feed(
            &mut m,
            &[
                (true, 0, syn(), 0, 1000, 0),
                (false, 100, syn_ack(), 0, 5000, 1001),
                (true, 110, data_flags(), 100, 1001, 5001),
                (true, 120, data_flags(), 100, 1201, 5001),
            ],
        );
        let s = session_of(&m);
        assert_eq!(s.retransmissions(), Some(0));
        assert_eq!(s.out_of_order(), Some(0), "缺段不得被数成乱序");
    }

    #[test]
    fn cys_trf_015_partially_overlapping_segment_is_out_of_order() {
        // 前 50 字节旧、后 50 字节新：探针实测（含第三次 ACK 的正式样本）tshark 给
        // 的是 out_of_order，不是 retransmission；早期无完整握手的探针曾把它归成
        // retransmission —— 分类依赖 ACK 上下文，所以本行只钉在可复现样本上。
        let mut m = mgr1();
        feed(
            &mut m,
            &[
                (true, 0, syn(), 0, 1000, 0),
                (false, 100, syn_ack(), 0, 5000, 1001),
                (true, 110, data_flags(), 100, 1001, 5001),
                (true, 120, data_flags(), 100, 1051, 5001),
            ],
        );
        let s = session_of(&m);
        assert_eq!(s.out_of_order(), Some(1));
        assert_eq!(s.retransmissions(), Some(0));
    }

    #[test]
    fn cys_trf_015_without_sequence_numbers_the_counts_are_unknown_not_zero() {
        // “读不到序号”与“没有重传”必须能分开：截断采集下报 0 等于向下游谎报全网零重传。
        let mut m = mgr1();
        let script = [
            (tcp_key(), syn(), 0u64),
            (tcp_key().reverse(), syn_ack(), 0),
            (tcp_key(), data_flags(), 100),
            (tcp_key(), data_flags(), 100),
        ];
        for (i, (k, fl, len)) in script.iter().enumerate() {
            m.observe(
                &pkt(*k, (i as u64) * 10, *len as u32),
                Some(&seg(*fl, *len as u32)),
            );
        }
        let s = session_of(&m);
        assert_eq!(s.retransmissions(), None, "没判定输入时不得报 Some(0)");
        assert_eq!(s.out_of_order(), None);
        assert_eq!(
            s.handshake_rtt_us(),
            Some(10),
            "RTT 只依赖时间戳，没序号也能测到"
        );
    }

    #[test]
    fn cys_trf_015_updown_bytes_are_keyed_by_initiator_and_refuse_midstream() {
        let mut m = mgr1();
        feed(
            &mut m,
            &[
                (true, 0, syn(), 0, 1000, 0),
                (false, 100, syn_ack(), 0, 5000, 1001),
                (true, 110, data_flags(), 120, 1001, 5001), // 上行：IP 载荷 120B
                (false, 120, data_flags(), 480, 5001, 1101), // 下行：IP 载荷 480B
            ],
        );
        let s = session_of(&m);
        assert_eq!(s.uplink_bytes(), Some(120));
        assert_eq!(s.downlink_bytes(), Some(480));
        assert_eq!(
            s.down_up_ratio(),
            Some(4.0),
            "上下行比 = 下行/上行，由发起方定方向"
        );

        // 中途接入（没见过 SYN）：发起方未知 ⇒ 上下行必须是 None。
        let mut m2 = mgr1();
        feed(
            &mut m2,
            &[
                (true, 0, data_flags(), 120, 1001, 5001),
                (false, 10, data_flags(), 480, 5001, 1101),
            ],
        );
        let s2 = session_of(&m2);
        assert!(s2.initiator().is_none());
        assert_eq!(
            s2.uplink_bytes(),
            None,
            "中途接入不猜谁发起，也就不报上下行"
        );
        assert_eq!(s2.down_up_ratio(), None);
        // 而重传/乱序计数仍然可用（它们不依赖发起方）。
        assert_eq!(s2.retransmissions(), Some(0));
    }

    #[test]
    fn cys_trf_015_zero_length_segments_never_count_as_retransmission() {
        // 重复 ACK（不占序号空间）是最容易误判成重传的一类：探针里 baseline 假阳 0
        // 靠的就是这一步。断言它不会因为“序号比期望小”而被数成重传。
        let mut m = mgr1();
        feed(
            &mut m,
            &[
                (true, 0, syn(), 0, 1000, 0),
                (false, 100, syn_ack(), 0, 5000, 1001),
                (true, 110, data_flags(), 100, 1001, 5001),
                (false, 120, ack(), 0, 5001, 1101),
                (false, 130, ack(), 0, 5001, 1101),
                (false, 140, ack(), 0, 5001, 1101),
            ],
        );
        let s = session_of(&m);
        assert_eq!(s.retransmissions(), Some(0), "重复 ACK 不得数成重传");
        assert_eq!(s.out_of_order(), Some(0));
    }

    fn data_flags() -> TcpFlags {
        TcpFlags {
            psh: true,
            ack: true,
            ..TcpFlags::default()
        }
    }

    // ---- CYS-TRF-010 id 分配器 ----

    #[test]
    fn ids_are_monotonic_and_unique() {
        let mut a = SessionIdAllocator::new(1);
        let ids: Vec<u64> = (0..5).map(|_| a.alloc().unwrap()).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
        assert_eq!(a.live_count(), 5);
        assert_eq!(a.issued(), 5);
        assert_eq!(a.reused(), 0);
    }

    #[test]
    fn released_ids_are_reused_and_never_collide_with_live_ones() {
        let mut a = SessionIdAllocator::new(1);
        let a1 = a.alloc().unwrap();
        let b1 = a.alloc().unwrap();
        assert!(a.release(a1));
        let c1 = a.alloc().unwrap();
        assert_eq!(c1, a1, "空闲池中的 id 应被复用");
        assert_eq!(a.reused(), 1);
        let live: Vec<u64> = [b1, c1].into_iter().filter(|id| a.is_live(*id)).collect();
        assert_eq!(live.len(), 2, "复用的 id 不得与在用的重名");
    }

    #[test]
    fn double_release_is_reported_and_does_not_duplicate_the_pool_entry() {
        let mut a = SessionIdAllocator::new(7);
        let id = a.alloc().unwrap();
        assert!(a.release(id));
        assert!(!a.release(id), "重复释放必须被识别");
        // 池中只有一份：连续两次分配拿到 7 之后应回到单调递增序列。
        assert_eq!(a.alloc().unwrap(), 7);
        assert_eq!(a.alloc().unwrap(), 8);
        assert_eq!(a.live_count(), 2);
    }

    #[test]
    fn allocator_exhaustion_returns_none() {
        // u64::MAX 保留不发放，因此从 MAX-1 起只能发出一个。
        let mut a = SessionIdAllocator::new(u64::MAX - 1);
        assert_eq!(a.alloc(), Some(u64::MAX - 1));
        assert_eq!(a.alloc(), None, "id 空间耗尽必须是显式的 None");
        assert_eq!(a.live_count(), 1);
    }

    // ---- CYS-TRF-011 会话聚合 ----

    #[test]
    fn both_directions_land_in_one_session() {
        let mut m = SessionManager::new(SessionConfig::default());
        let f = tcp_key();
        let b = f.reverse();
        let o1 = m.observe(&pkt(f, 1, 100), Some(&seg(ack(), 100)));
        let o2 = m.observe(&pkt(b, 2, 200), Some(&seg(ack(), 200)));
        assert_eq!(o1.session_id, o2.session_id, "双向必须归同一条会话");
        assert!(o1.is_new && !o2.is_new);
        assert_eq!(m.session_count(), 1);
        assert_eq!(m.flow_count(), 2, "方向级流表保留两条流");
        assert_eq!(o1.side, Side::A);
        assert_eq!(o2.side, Side::B);

        let s = m.session(&f).expect("会话在");
        assert_eq!(s.packets, 2);
        assert_eq!(s.bytes, 300);
        assert_eq!(s.direction_switches, 1);
        assert_eq!(s.forward, f);
        assert_eq!(s.backward, b);
    }

    #[test]
    fn response_first_still_attaches_to_the_same_session() {
        // 旁路中途接入：先看到响应，后看到请求。
        let mut m = SessionManager::new(SessionConfig::bypass());
        let f = tcp_key();
        let b = f.reverse();
        let first = m.observe(&pkt(b, 100, 500), Some(&seg(ack(), 500)));
        let second = m.observe(&pkt(f, 200, 100), Some(&seg(ack(), 100)));
        assert_eq!(
            first.session_id, second.session_id,
            "先见响应也必须归同一条会话"
        );
        assert_eq!(m.session_count(), 1);
        assert!(!second.is_new);
        // 方向归属由规范端点序决定：后到的 f 仍是 A 侧。
        assert_eq!(first.side, Side::B);
        assert_eq!(second.side, Side::A);
        let s = m.session(&f).expect("会话在");
        assert!(s.adopted_midstream(), "没看到握手必须可辨认");
    }

    #[test]
    fn different_ports_or_protocols_are_different_sessions() {
        let mut m = SessionManager::new(SessionConfig::default());
        m.observe(
            &pkt(key(1, 1, 2, 80, IPPROTO_TCP), 1, 1),
            Some(&seg(ack(), 1)),
        );
        m.observe(
            &pkt(key(1, 1, 2, 443, IPPROTO_TCP), 1, 1),
            Some(&seg(ack(), 1)),
        );
        m.observe(&pkt(key(1, 1, 2, 80, IPPROTO_UDP), 1, 1), None);
        assert_eq!(m.session_count(), 3);
    }

    // ---- 状态机接入 ----

    #[test]
    fn handshake_drives_state_and_upgrades_the_timeout_class() {
        let mut m = SessionManager::new(SessionConfig::default());
        let f = tcp_key();
        let b = f.reverse();
        m.observe(&pkt(f, 1, 0), Some(&seg(syn(), 0)));
        assert_eq!(m.session(&f).unwrap().tcp_state(), TcpState::SynSent);
        assert_eq!(
            m.flow_entry(&f).map(|e| e.class),
            Some(TimeoutClass::TcpTransient),
            "握手未完成时走短超时"
        );
        m.observe(&pkt(b, 2, 0), Some(&seg(syn_ack(), 0)));
        let o = m.observe(&pkt(f, 3, 0), Some(&seg(ack(), 0)));
        assert_eq!(o.state, TcpState::Established);
        assert_eq!(
            m.flow_entry(&f).map(|e| e.class),
            Some(TimeoutClass::TcpEstablished),
            "建立后必须升级为长超时档"
        );
        assert_eq!(m.session(&f).unwrap().initiator(), Some(Side::A));
        assert!(!m.session(&f).unwrap().adopted_midstream());
    }

    #[test]
    fn non_tcp_packets_never_drive_the_state_machine() {
        let mut m = SessionManager::new(SessionConfig::default());
        let k = key(1, 53, 2, 53, IPPROTO_UDP);
        let o = m.observe(&pkt(k, 1, 100), None);
        assert_eq!(o.state, TcpState::Closed);
        let s = m.session(&k).unwrap();
        assert!(!s.is_tcp());
        assert_eq!(s.tcp_state(), TcpState::Closed);
        assert_eq!(s.timeout_class(), TimeoutClass::Udp);
    }

    #[test]
    fn illegal_tcp_transitions_are_counted_but_do_not_stop_processing() {
        let mut m = SessionManager::new(SessionConfig::default());
        let f = tcp_key();
        // 严格模式下 Closed 上收到纯 ACK 是非法迁移。
        let o1 = m.observe(&pkt(f, 1, 0), Some(&seg(ack(), 0)));
        assert!(o1.illegal.is_some(), "非法迁移必须被记录");
        assert_eq!(o1.state, TcpState::Closed, "拒绝的语义是状态不推进");
        assert_eq!(m.stats().illegal_tcp_events, 1);
        // 后续正常握手仍能推进：单个畸形包不得让流水线停摆。
        m.observe(&pkt(f, 2, 0), Some(&seg(syn(), 0)));
        m.observe(&pkt(f.reverse(), 3, 0), Some(&seg(syn_ack(), 0)));
        let o = m.observe(&pkt(f, 4, 0), Some(&seg(ack(), 0)));
        assert_eq!(o.state, TcpState::Established);
        assert_eq!(m.stats().illegal_tcp_events, 1, "正常迁移不计入非法");
    }

    #[test]
    fn tcp_packet_without_flags_is_counted_but_not_interpreted() {
        let mut m = SessionManager::new(SessionConfig::default());
        let f = tcp_key();
        let o = m.observe(&pkt(f, 1, 100), None);
        assert_eq!(o.state, TcpState::Closed, "没有标志位就不许猜状态");
        assert_eq!(m.session(&f).unwrap().packets, 1);
        assert_eq!(m.flow_entry(&f).unwrap().flow.total_bytes, 100);
    }

    // ---- 超时与逐出 ----

    #[test]
    fn expire_uses_the_state_dependent_timeout() {
        let mut cfg = SessionConfig::default();
        cfg.table.timeouts = TimeoutTable {
            tcp_established_us: 1000,
            tcp_transient_us: 10,
            udp_us: 20,
            icmp_us: 5,
            default_us: 30,
        };
        let mut m = SessionManager::new(cfg);
        let f = tcp_key();
        // 一条已建立，一条停在 SYN（transient）。
        m.observe(&pkt(f, 0, 0), Some(&seg(syn(), 0)));
        m.observe(&pkt(f.reverse(), 0, 0), Some(&seg(syn_ack(), 0)));
        m.observe(&pkt(f, 0, 0), Some(&seg(ack(), 0)));
        let slow = key(3, 50000, 4, 80, IPPROTO_TCP);
        m.observe(&pkt(slow, 0, 0), Some(&seg(syn(), 0)));
        assert_eq!(m.session_count(), 2);

        let (sessions, flows) = m.expire(50);
        assert_eq!(sessions, 1, "只有 transient 会话到期");
        assert_eq!(flows, 1);
        assert!(m.session(&f).is_some(), "已建立的会话不应被短超时误伤");
        assert!(m.session(&slow).is_none());

        let (sessions2, _) = m.expire(1000);
        assert_eq!(sessions2, 1, "长超时档到期后回收");
        assert_eq!(m.session_count(), 0);
        assert_eq!(m.live_ids(), 0, "会话销毁必须归还 id");
        assert_eq!(m.stats().sessions_expired, 2);
    }

    #[test]
    fn expired_ids_are_reused_by_later_sessions() {
        let mut cfg = SessionConfig::default();
        cfg.table.timeouts = TimeoutTable {
            tcp_transient_us: 10,
            ..TimeoutTable::default()
        };
        let mut m = SessionManager::new(cfg);
        let first = m
            .observe(&pkt(tcp_key(), 0, 0), Some(&seg(syn(), 0)))
            .session_id;
        m.expire(100);
        let second = m
            .observe(
                &pkt(key(9, 999, 8, 80, IPPROTO_TCP), 200, 0),
                Some(&seg(syn(), 0)),
            )
            .session_id;
        assert_eq!(
            second, first,
            "回收的 id 应被复用（long-running 进程不能烧穿 id）"
        );
    }

    #[test]
    fn session_capacity_evicts_least_recently_seen() {
        let mut cfg = SessionConfig::default();
        cfg.max_sessions = 2;
        let mut m = SessionManager::new(cfg);
        let k1 = key(1, 1, 2, 80, IPPROTO_TCP);
        let k2 = key(1, 2, 2, 80, IPPROTO_TCP);
        let k3 = key(1, 3, 2, 80, IPPROTO_TCP);
        m.observe(&pkt(k1, 10, 1), Some(&seg(syn(), 1)));
        m.observe(&pkt(k2, 20, 1), Some(&seg(syn(), 1)));
        m.observe(&pkt(k1, 30, 1), Some(&seg(ack(), 1))); // k1 重新活跃
        m.observe(&pkt(k3, 40, 1), Some(&seg(syn(), 1))); // 触发逐出
        assert_eq!(m.session_count(), 2);
        assert!(m.session(&k1).is_some(), "最近活跃的会话不得被逐出");
        assert!(m.session(&k2).is_none());
        assert!(m.session(&k3).is_some());
        assert_eq!(m.stats().sessions_evicted, 1);
        assert_eq!(m.live_ids(), 2, "逐出必须归还 id");
    }

    #[test]
    fn sessions_sorted_is_deterministic_and_drain_releases_ids() {
        let mut m = SessionManager::new(SessionConfig::default());
        for p in [443u16, 80, 22] {
            m.observe(
                &pkt(key(1, 1000 + p, 2, p, IPPROTO_TCP), 1, 1),
                Some(&seg(ack(), 1)),
            );
        }
        let keys: Vec<FlowKey> = m.sessions_sorted().iter().map(|s| s.key).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "遍历顺序必须确定");

        let drained = m.drain_sessions_sorted();
        assert_eq!(drained.len(), 3);
        assert_eq!(m.session_count(), 0);
        assert_eq!(m.live_ids(), 0, "取走会话后 id 必须归还");
    }

    #[test]
    fn dropped_no_id_is_reported_instead_of_silently_lost() {
        let mut cfg = SessionConfig::default();
        cfg.id_start = u64::MAX - 1;
        cfg.max_sessions = 8;
        let mut m = SessionManager::new(cfg);
        let ok = m.observe(
            &pkt(key(1, 1, 2, 80, IPPROTO_TCP), 1, 1),
            Some(&seg(syn(), 1)),
        );
        assert_eq!(ok.session_id, u64::MAX - 1);
        let fail = m.observe(
            &pkt(key(1, 2, 2, 80, IPPROTO_TCP), 1, 1),
            Some(&seg(syn(), 1)),
        );
        assert_eq!(fail.session_id, 0, "无法分配 id 时必须显式暴露");
        assert_eq!(m.stats().dropped_no_id, 1);
        assert_eq!(m.session_count(), 1);
        assert_eq!(m.flow_count(), 2, "方向级统计不受影响");
    }

    #[test]
    fn observation_reports_side_and_new_flag_consistently() {
        let mut m = SessionManager::new(SessionConfig::default());
        let f = tcp_key();
        let o1 = m.observe(&pkt(f, 1, 0), Some(&seg(syn(), 0)));
        assert!(o1.is_new);
        assert_eq!(o1.key, f.canonical());
        assert_eq!(o1.side, Side::A);
        let o2 = m.observe(&pkt(f.reverse(), 2, 0), Some(&seg(syn_ack(), 0)));
        assert!(!o2.is_new);
        assert_eq!(o2.key, o1.key, "会话键与方向无关");
        assert_eq!(o2.side, Side::B);
    }

    #[test]
    fn proto_is_part_of_session_identity() {
        let mut m = SessionManager::new(SessionConfig::default());
        let tcp = key(1, 53, 2, 53, IPPROTO_TCP);
        let udp = key(1, 53, 2, 53, IPPROTO_UDP);
        m.observe(&pkt(tcp, 1, 1), Some(&seg(ack(), 1)));
        m.observe(&pkt(udp, 1, 1), None);
        assert_eq!(m.session_count(), 2);
        assert_eq!(m.session(&tcp).unwrap().key.proto, Proto::Tcp);
        assert_eq!(m.session(&udp).unwrap().key.proto, Proto::Udp);
    }

    // ---- 单位口径回归（曾经的真实缺陷）----

    #[test]
    fn a_bare_ack_has_a_twenty_byte_ip_payload_but_no_tcp_data() {
        // 回归：真实报文里纯 ACK 的 **IP 载荷长度**是 20（一个 TCP 头），
        // 而**段载荷长度**是 0。曾把 pkt.payload_len 直接当段载荷长度用，
        // 于是握手的最后一个 ACK 被当成 Data：容忍模式下"看起来正常"
        // （Data 恰好也把连接推到 Established），严格模式下连接永远停在
        // SynReceived，且 FinWait2/CloseWait/LastAck 全都到不了。
        let mut m = SessionManager::new(SessionConfig::default());
        let f = tcp_key();
        let bare = |k: FlowKey, ts: u64| Packet {
            key: k,
            payload_len: 20,
            timestamp_us: ts,
        };
        m.observe(&bare(f, 1), Some(&TcpObservation::no_payload(syn())));
        assert_eq!(m.session(&f).unwrap().tcp_state(), TcpState::SynSent);
        m.observe(
            &bare(f.reverse(), 2),
            Some(&TcpObservation::no_payload(syn_ack())),
        );
        assert_eq!(m.session(&f).unwrap().tcp_state(), TcpState::SynReceived);
        let o = m.observe(&bare(f, 3), Some(&TcpObservation::no_payload(ack())));
        assert_eq!(o.state, TcpState::Established, "纯 ACK 必须走 Ack 分支");
        assert!(o.illegal.is_none());
        assert_eq!(m.stats().illegal_tcp_events, 0);
        // 字节统计仍按 IP 载荷长度记（含头的 20 字节/包）：两个口径并存但绝不混用。
        assert_eq!(m.session(&f).unwrap().bytes, 60);
    }

    #[test]
    fn close_sequence_passes_through_fin_wait2_and_reaches_time_wait() {
        // 同样的单位问题会让 FinWait2 在真实流量里不可达 —— 因此这里逐步断言，
        // 而不是只看最后一个状态（"结果对了"不等于"路径对了"）。
        let mut m = SessionManager::new(SessionConfig::default());
        let f = tcp_key();
        let b = f.reverse();
        let bare = |k: FlowKey, ts: u64| Packet {
            key: k,
            payload_len: 20,
            timestamp_us: ts,
        };
        let step = |m: &mut SessionManager, k: FlowKey, ts: u64, o: TcpObservation| {
            m.observe(&bare(k, ts), Some(&o)).state
        };
        assert_eq!(
            step(&mut m, f, 1, TcpObservation::no_payload(syn())),
            TcpState::SynSent
        );
        assert_eq!(
            step(&mut m, b, 2, TcpObservation::no_payload(syn_ack())),
            TcpState::SynReceived
        );
        assert_eq!(
            step(&mut m, f, 3, TcpObservation::no_payload(ack())),
            TcpState::Established
        );
        let mut fin = ack();
        fin.fin = true;
        assert_eq!(
            step(&mut m, f, 4, TcpObservation::no_payload(fin)),
            TcpState::FinWait1,
            "先发 FIN 的一方进入 FinWait1"
        );
        assert_eq!(
            step(&mut m, b, 5, TcpObservation::no_payload(ack())),
            TcpState::FinWait2,
            "FIN 被确认后进入 FinWait2（这一步曾经不可达）"
        );
        assert_eq!(
            step(&mut m, b, 6, TcpObservation::no_payload(fin)),
            TcpState::TimeWait
        );
        assert_eq!(
            step(&mut m, f, 7, TcpObservation::no_payload(ack())),
            TcpState::TimeWait
        );
        assert_eq!(m.stats().illegal_tcp_events, 0, "正常关闭不含非法迁移");
    }
}
