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
use crate::reassembly::tcp::TcpFlags;
use crate::tcp::{IllegalTransition, Side, TcpConfig, TcpEvent, TcpState, TcpStateMachine};

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
    last_side: Option<Side>,
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
            last_side: None,
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
        flags: Option<&TcpFlags>,
    ) -> Option<IllegalTransition> {
        if self.packets == 0 {
            self.first_seen_us = pkt.timestamp_us;
        }
        if pkt.timestamp_us > self.last_seen_us {
            self.last_seen_us = pkt.timestamp_us;
        }
        self.packets += 1;
        self.bytes += u64::from(pkt.payload_len);
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
        let Some(flags) = flags else {
            // TCP 包但调用方没给标志位：只记账，不推进状态机。
            // 不"猜一个 ACK"，因为猜错会把状态推到 Established，而那个错误
            // 之后再也看不出来（状态机自身不会报错）。
            return None;
        };
        let event = TcpEvent::classify(flags, pkt.payload_len);
        self.tcp.apply(event, side).err()
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

    /// 观测一个包。`flags` 只有 TCP 包才需要（其它协议传 `None`）。
    pub fn observe(&mut self, pkt: &Packet, flags: Option<&TcpFlags>) -> Observation {
        self.stats.packets += 1;
        let key = pkt.key.canonical();
        let side = if pkt.key == key { Side::A } else { Side::B };

        // 1. 先喂方向级流表：字节/包数只在这里记一份。
        self.table.observe(pkt);

        // 2. 会话：存在则更新，不存在则（可能先逐出一条）新建。
        let tcp_cfg = self.cfg.tcp;
        let (id, is_new, illegal) = if let Some(s) = self.sessions.get_mut(&key) {
            let illegal = s.observe(pkt, side, flags);
            (s.id, false, illegal)
        } else {
            if self.sessions.len() >= self.cfg.max_sessions.max(1) {
                self.evict_lru_session();
            }
            match self.alloc.alloc() {
                Some(id) => {
                    let mut s = Session::new(id, key, tcp_cfg);
                    let illegal = s.observe(pkt, side, flags);
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

    fn ack() -> TcpFlags {
        TcpFlags {
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
        let o1 = m.observe(&pkt(f, 1, 100), Some(&ack()));
        let o2 = m.observe(&pkt(b, 2, 200), Some(&ack()));
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
        let first = m.observe(&pkt(b, 100, 500), Some(&ack()));
        let second = m.observe(&pkt(f, 200, 100), Some(&ack()));
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
        m.observe(&pkt(key(1, 1, 2, 80, IPPROTO_TCP), 1, 1), Some(&ack()));
        m.observe(&pkt(key(1, 1, 2, 443, IPPROTO_TCP), 1, 1), Some(&ack()));
        m.observe(&pkt(key(1, 1, 2, 80, IPPROTO_UDP), 1, 1), None);
        assert_eq!(m.session_count(), 3);
    }

    // ---- 状态机接入 ----

    #[test]
    fn handshake_drives_state_and_upgrades_the_timeout_class() {
        let mut m = SessionManager::new(SessionConfig::default());
        let f = tcp_key();
        let b = f.reverse();
        m.observe(&pkt(f, 1, 0), Some(&syn()));
        assert_eq!(m.session(&f).unwrap().tcp_state(), TcpState::SynSent);
        assert_eq!(
            m.flow_entry(&f).map(|e| e.class),
            Some(TimeoutClass::TcpTransient),
            "握手未完成时走短超时"
        );
        m.observe(&pkt(b, 2, 0), Some(&syn_ack()));
        let o = m.observe(&pkt(f, 3, 0), Some(&ack()));
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
        let o1 = m.observe(&pkt(f, 1, 0), Some(&ack()));
        assert!(o1.illegal.is_some(), "非法迁移必须被记录");
        assert_eq!(o1.state, TcpState::Closed, "拒绝的语义是状态不推进");
        assert_eq!(m.stats().illegal_tcp_events, 1);
        // 后续正常握手仍能推进：单个畸形包不得让流水线停摆。
        m.observe(&pkt(f, 2, 0), Some(&syn()));
        m.observe(&pkt(f.reverse(), 3, 0), Some(&syn_ack()));
        let o = m.observe(&pkt(f, 4, 0), Some(&ack()));
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
        m.observe(&pkt(f, 0, 0), Some(&syn()));
        m.observe(&pkt(f.reverse(), 0, 0), Some(&syn_ack()));
        m.observe(&pkt(f, 0, 0), Some(&ack()));
        let slow = key(3, 50000, 4, 80, IPPROTO_TCP);
        m.observe(&pkt(slow, 0, 0), Some(&syn()));
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
        let first = m.observe(&pkt(tcp_key(), 0, 0), Some(&syn())).session_id;
        m.expire(100);
        let second = m
            .observe(&pkt(key(9, 999, 8, 80, IPPROTO_TCP), 200, 0), Some(&syn()))
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
        m.observe(&pkt(k1, 10, 1), Some(&syn()));
        m.observe(&pkt(k2, 20, 1), Some(&syn()));
        m.observe(&pkt(k1, 30, 1), Some(&ack())); // k1 重新活跃
        m.observe(&pkt(k3, 40, 1), Some(&syn())); // 触发逐出
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
                Some(&ack()),
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
        let ok = m.observe(&pkt(key(1, 1, 2, 80, IPPROTO_TCP), 1, 1), Some(&syn()));
        assert_eq!(ok.session_id, u64::MAX - 1);
        let fail = m.observe(&pkt(key(1, 2, 2, 80, IPPROTO_TCP), 1, 1), Some(&syn()));
        assert_eq!(fail.session_id, 0, "无法分配 id 时必须显式暴露");
        assert_eq!(m.stats().dropped_no_id, 1);
        assert_eq!(m.session_count(), 1);
        assert_eq!(m.flow_count(), 2, "方向级统计不受影响");
    }

    #[test]
    fn observation_reports_side_and_new_flag_consistently() {
        let mut m = SessionManager::new(SessionConfig::default());
        let f = tcp_key();
        let o1 = m.observe(&pkt(f, 1, 0), Some(&syn()));
        assert!(o1.is_new);
        assert_eq!(o1.key, f.canonical());
        assert_eq!(o1.side, Side::A);
        let o2 = m.observe(&pkt(f.reverse(), 2, 0), Some(&syn_ack()));
        assert!(!o2.is_new);
        assert_eq!(o2.key, o1.key, "会话键与方向无关");
        assert_eq!(o2.side, Side::B);
    }

    #[test]
    fn proto_is_part_of_session_identity() {
        let mut m = SessionManager::new(SessionConfig::default());
        let tcp = key(1, 53, 2, 53, IPPROTO_TCP);
        let udp = key(1, 53, 2, 53, IPPROTO_UDP);
        m.observe(&pkt(tcp, 1, 1), Some(&ack()));
        m.observe(&pkt(udp, 1, 1), None);
        assert_eq!(m.session_count(), 2);
        assert_eq!(m.session(&tcp).unwrap().key.proto, Proto::Tcp);
        assert_eq!(m.session(&udp).unwrap().key.proto, Proto::Udp);
    }
}
