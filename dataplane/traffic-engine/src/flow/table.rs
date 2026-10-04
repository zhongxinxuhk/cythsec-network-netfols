// flow/table.rs —— 分片流表：容量、超时老化、逐出与生命周期回调（CYS-TRF-006/007/008/009）。
//
// 三个必须分开回答的问题（混在一起会得到一个既不能测也不能解释的表）：
//
// 1. **放哪**（分片）：按五元组哈希分片，分片内独立哈希表。分片的意义不是"更快"，
//    而是**把锁的粒度提前定下来**：将来多 worker 时按分片加锁即可，数据布局不用动。
//    现在单线程运行，分片只体现为"同一分片容量满时只影响该分片"。
//
// 2. **什么时候丢**（超时）：判据是"距最后一次活动多久"，**按协议与连接状态分档**。
//    用一个统一超时会同时犯两个错：把 UDP 的 30 秒与 TCP 已建立的 5 分钟拉平，
//    要么过早回收长连接（统计断成两截），要么让扫描流量在表里堆积成内存泄漏。
//
// 3. **放不下时丢谁**（逐出）：表满时的选择是 LRU（详见 `evict_lru` 的代价说明）。
//    刻意不做随机逐出：输出必须可复现，随机逐出会让同一份 pcap 两次运行得到
//    不同的流表内容，快照回归直接失效。
//
// 生命周期回调（`FlowObserver`）只观察、不参与决策：表本身不依赖任何回调的副作用。
// 回调里能拿到的是一条完整条目，拿不到"表"——想改表必须回到表的方法上排队，
// 这样回调不可能在遍历中途改坏表结构。

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

use super::stats::FlowStats;
use super::{Flow, FlowKey, Packet, Proto};
use crate::tcp::TcpState;

/// 默认分片数。必须是 2 的幂（用掩码代替取模）。
pub const DEFAULT_SHARD_COUNT: usize = 16;

/// 默认流表容量上限（条）。约 1M 并发流。
pub const DEFAULT_MAX_FLOWS: usize = 1 << 20;

/// FNV-1a 64 位哈希。
///
/// 为什么不用标准库默认的 `RandomState`（SipHash + 随机密钥）：
///   * 每个 `HashMap` 都会向系统熵池取随机密钥，建表本身有成本；
///   * **分片结果随机化后，同一个键在不同进程里落到不同分片**。分片当前不影响
///     输出（输出前会排序），但会让"分片分布是否均匀"这类排查无法复现。
/// FNV 在这里足够：键是定长短字节串，且我们会先把键编码成规范字节序列再喂进去。
#[derive(Debug, Clone, Copy)]
pub struct FnvHasher(u64);

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

impl Default for FnvHasher {
    fn default() -> Self {
        // 起点由 `Default` 给出，而不是在 `write` 里用 "0 就是没初始化" 判断：
        // 后者会让一个**恰好算成 0** 的中间哈希被当成未初始化而重新起头，
        // 概率极低但一旦发生就是"同一个键偶尔落到另一个分片"。
        Self(FNV_OFFSET_BASIS)
    }
}

impl Hasher for FnvHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(FNV_PRIME);
        }
    }
}

/// 以 FNV 为哈希的映射类型（分片内部与流表索引共用）。
pub type FnvMap<K, V> = HashMap<K, V, BuildHasherDefault<FnvHasher>>;

/// 建一个空的 FNV 映射。
pub fn new_fnv_map<K, V>() -> FnvMap<K, V> {
    FnvMap::default()
}

/// 超时档位（CYS-TRF-007 的五档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TimeoutClass {
    /// TCP 已建立（含半关闭）。
    TcpEstablished,
    /// TCP 未建立（SYN 阶段、TIME_WAIT、已重置）。
    TcpTransient,
    Udp,
    Icmp,
    /// 其余协议（ESP/GRE/SCTP 等）。
    Default,
}

impl TimeoutClass {
    /// 由协议推导默认档位。
    ///
    /// TCP 默认为 `TcpTransient`：**在没看到握手结论之前不许假设连接已建立**。
    /// 会话层在状态机进入 Established 后会显式升级为 `TcpEstablished`
    /// （`FlowTable::set_class`）。默认给 5 分钟会让大量半开连接赖在表里。
    pub const fn for_proto(proto: Proto) -> Self {
        match proto {
            Proto::Tcp => TimeoutClass::TcpTransient,
            Proto::Udp => TimeoutClass::Udp,
            Proto::Icmp | Proto::Icmpv6 => TimeoutClass::Icmp,
            Proto::Other(_) => TimeoutClass::Default,
        }
    }

    /// 由 TCP 状态推导档位。
    ///
    /// 只有 `Established` 走长超时；其余（含 `TimeWait`）都走短超时。
    /// 关于 TIME_WAIT：RFC 9293 的 2MSL 通常是 120 秒，这里刻意**不**为它单开一档 ——
    /// 本表是"什么时候可以回收内存"的策略表，不是协议栈计时器；多一档就多一个
    /// 需要单独验证的边界，而收益只是让观测到的 TIME_WAIT 多留 90 秒。
    pub const fn for_tcp_state(state: TcpState) -> Self {
        match state {
            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::LastAck => TimeoutClass::TcpEstablished,
            _ => TimeoutClass::TcpTransient,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            TimeoutClass::TcpEstablished => "tcp_established",
            TimeoutClass::TcpTransient => "tcp_transient",
            TimeoutClass::Udp => "udp",
            TimeoutClass::Icmp => "icmp",
            TimeoutClass::Default => "default",
        }
    }
}

/// 五档超时表（微秒）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutTable {
    pub tcp_established_us: u64,
    pub tcp_transient_us: u64,
    pub udp_us: u64,
    pub icmp_us: u64,
    pub default_us: u64,
}

impl Default for TimeoutTable {
    fn default() -> Self {
        Self {
            tcp_established_us: 300 * 1_000_000,
            tcp_transient_us: 30 * 1_000_000,
            udp_us: 30 * 1_000_000,
            icmp_us: 10 * 1_000_000,
            default_us: 120 * 1_000_000,
        }
    }
}

impl TimeoutTable {
    pub const fn timeout_us(&self, class: TimeoutClass) -> u64 {
        match class {
            TimeoutClass::TcpEstablished => self.tcp_established_us,
            TimeoutClass::TcpTransient => self.tcp_transient_us,
            TimeoutClass::Udp => self.udp_us,
            TimeoutClass::Icmp => self.icmp_us,
            TimeoutClass::Default => self.default_us,
        }
    }
}

/// 逐出策略。
///
/// 目前只有 LRU 一种可用取值，保留枚举是为了让"策略"成为**显式的构造参数**：
/// 将来若加入时钟/随机策略，调用方必须重新审视自己的假设（比如"逐出顺序确定"）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvictPolicy {
    /// 逐出最久未活动的条目。
    #[default]
    Lru,
}

/// 流表条目。
#[derive(Debug, Clone)]
pub struct FlowEntry {
    /// 方向敏感的五元组（与 `FlowKey::canonical()` 无关）。
    pub key: FlowKey,
    pub flow: Flow,
    /// 当前超时档位；会话层可随 TCP 状态变化升级。
    pub class: TimeoutClass,
    pub created_us: u64,
    pub last_active_us: u64,
    /// 更新次数（不含首次插入）。
    pub updates: u64,
}

impl FlowEntry {
    pub fn new(key: FlowKey, class: TimeoutClass, now_us: u64) -> Self {
        Self {
            key,
            flow: Flow::new(key),
            class,
            created_us: now_us,
            last_active_us: now_us,
            updates: 0,
        }
    }

    pub fn observe(&mut self, pkt: &Packet) {
        self.flow.observe(pkt);
        self.updates += 1;
        if pkt.timestamp_us > self.last_active_us {
            self.last_active_us = pkt.timestamp_us;
        }
    }

    pub fn timeout_us(&self, table: &TimeoutTable) -> u64 {
        table.timeout_us(self.class)
    }

    /// 距 `now_us` 的空闲时长；`now_us` 早于最后活动时为 0。
    pub fn idle_us(&self, now_us: u64) -> u64 {
        now_us.saturating_sub(self.last_active_us)
    }

    /// 是否已超时。
    pub fn is_expired(&self, now_us: u64, table: &TimeoutTable) -> bool {
        self.idle_us(now_us) >= self.timeout_us(table)
    }

    pub fn stats(&self) -> &FlowStats {
        &self.flow.stats
    }
}

/// 生命周期回调（CYS-TRF-009）。
///
/// 全部方法都有空实现，因此实现者只需覆盖真正关心的那几个。
/// 回调**不得**尝试修改流表：它拿到的是 `&FlowEntry`，没有表的句柄。
#[allow(unused_variables)]
pub trait FlowObserver {
    /// 新条目插入后。
    fn on_new(&mut self, entry: &FlowEntry) {}
    /// 已有条目被更新后。
    fn on_update(&mut self, entry: &FlowEntry) {}
    /// 因容量上限被逐出（条目已不在表中）。
    fn on_evict(&mut self, entry: &FlowEntry) {}
    /// 因超时被回收（条目已不在表中）。
    fn on_timeout(&mut self, entry: &FlowEntry) {}
}

/// 什么都不做的观察者，用于把"没有观察者"与"观察者被显式置空"区分开。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl FlowObserver for NoopObserver {}

/// 流表配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTableConfig {
    /// 分片数；构造时向上取到 2 的幂，且不超过 `max_flows`。
    pub shard_count: usize,
    /// 总容量上限（条）。
    pub max_flows: usize,
    pub timeouts: TimeoutTable,
    pub policy: EvictPolicy,
}

impl Default for FlowTableConfig {
    fn default() -> Self {
        Self {
            shard_count: DEFAULT_SHARD_COUNT,
            max_flows: DEFAULT_MAX_FLOWS,
            timeouts: TimeoutTable::default(),
            policy: EvictPolicy::default(),
        }
    }
}

/// 表级计数（用于回答"表在干什么"，不是"流量是什么"）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TableStats {
    /// 观测到的包数（含所有分支）。
    pub packets: u64,
    /// 新建条目数。
    pub inserts: u64,
    /// 更新既有条目数。
    pub updates: u64,
    /// 因容量被逐出的条目数。
    pub evictions: u64,
    /// 因超时被回收的条目数。
    pub timeouts: u64,
    /// `expire()` 被调用的次数。
    pub expire_runs: u64,
}

#[derive(Debug)]
struct Shard {
    map: FnvMap<FlowKey, FlowEntry>,
}

impl Shard {
    fn new() -> Self {
        Self { map: new_fnv_map() }
    }
}

/// 事件种类（内部用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowEvent {
    New,
    Update,
    Evict,
    Timeout,
}

/// 待派发的事件。
///
/// 为什么要"先记录、后派发"：回调需要 `&FlowEntry`，而更新路径上条目正被
/// `&mut` 借用。若在借用区内直接调回调，编译器会拒绝；若为此改成
/// `RefCell`/内部可变性，回调就可能在表遍历中途改表。分两步是最省事且最安全的做法。
enum Pending {
    /// 条目仍在表中，按 key 回查。
    Keyed(FlowEvent, FlowKey),
    /// 条目已被移出，随事件一起携带。
    Removed(FlowEvent, FlowEntry),
}

/// 分片流表。
pub struct FlowTable {
    cfg: FlowTableConfig,
    shards: Vec<Shard>,
    /// 每分片容量（`max_flows / shard_count` 向上取整）。
    per_shard_cap: usize,
    observer: Option<Box<dyn FlowObserver>>,
    stats: TableStats,
}

impl FlowTable {
    pub fn new(cfg: FlowTableConfig) -> Self {
        let max_flows = cfg.max_flows.max(1);
        let mut shard_count = cfg.shard_count.max(1).next_power_of_two();
        // 分片数不得超过容量：否则大量分片的容量上限为 0，"插入即逐出"。
        shard_count = shard_count.min(max_flows);
        let per_shard_cap = max_flows.div_ceil(shard_count);
        let cfg = FlowTableConfig {
            shard_count,
            max_flows,
            ..cfg
        };
        Self {
            cfg,
            shards: (0..shard_count).map(|_| Shard::new()).collect(),
            per_shard_cap,
            observer: None,
            stats: TableStats::default(),
        }
    }

    pub fn cfg(&self) -> FlowTableConfig {
        self.cfg
    }

    pub fn stats(&self) -> TableStats {
        self.stats
    }

    pub fn shard_count(&self) -> usize {
        self.cfg.shard_count
    }

    /// 每分片容量上限。
    pub fn per_shard_capacity(&self) -> usize {
        self.per_shard_cap
    }

    pub fn set_observer(&mut self, observer: Box<dyn FlowObserver>) {
        self.observer = Some(observer);
    }

    pub fn clear_observer(&mut self) {
        self.observer = None;
    }

    pub fn has_observer(&self) -> bool {
        self.observer.is_some()
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.map.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.map.is_empty())
    }

    /// 条目所在分片下标。
    fn shard_index(&self, key: &FlowKey) -> usize {
        let mut h = FnvHasher::default();
        key.hash_with(&mut h);
        (h.finish() as usize) & (self.cfg.shard_count - 1)
    }

    /// 某个键会落在哪个分片（供测试与分片分布排查）。
    pub fn shard_of(&self, key: &FlowKey) -> usize {
        self.shard_index(key)
    }

    pub fn get(&self, key: &FlowKey) -> Option<&FlowEntry> {
        lookup(&self.shards, key)
    }

    pub fn get_mut(&mut self, key: &FlowKey) -> Option<&mut FlowEntry> {
        let idx = self.shard_index(key);
        self.shards[idx].map.get_mut(key)
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.get(key).is_some()
    }

    /// 修改条目的超时档位；返回是否命中。
    pub fn set_class(&mut self, key: &FlowKey, class: TimeoutClass) -> bool {
        match self.get_mut(key) {
            Some(e) => {
                e.class = class;
                true
            }
            None => false,
        }
    }

    /// 观测一个包：新建或更新条目。返回 `true` 表示新建。
    pub fn observe(&mut self, pkt: &Packet) -> bool {
        self.stats.packets += 1;
        let key = pkt.key;
        let idx = self.shard_index(&key);
        let mut pending: Option<Pending>;
        let mut evicted: Option<FlowEntry> = None;

        {
            let shard = &mut self.shards[idx];
            if let Some(entry) = shard.map.get_mut(&key) {
                entry.observe(pkt);
                self.stats.updates += 1;
                pending = Some(Pending::Keyed(FlowEvent::Update, key));
            } else {
                if shard.map.len() >= self.per_shard_cap {
                    evicted = match self.cfg.policy {
                        EvictPolicy::Lru => evict_lru(shard),
                    };
                }
                let class = TimeoutClass::for_proto(key.proto);
                let mut entry = FlowEntry::new(key, class, pkt.timestamp_us);
                entry.observe(pkt);
                // 上面的 observe 会把 updates 记成 1；首次插入不计入更新次数。
                entry.updates = 0;
                shard.map.insert(key, entry);
                self.stats.inserts += 1;
                pending = Some(Pending::Keyed(FlowEvent::New, key));
            }
        }

        // 先派发逐出（先离开的条目先上报），再派发本次的 New/Update。
        if let Some(entry) = evicted {
            self.stats.evictions += 1;
            self.notify(Pending::Removed(FlowEvent::Evict, entry));
        }
        let is_new = matches!(pending, Some(Pending::Keyed(FlowEvent::New, _)));
        if let Some(p) = pending.take() {
            self.notify(p);
        }
        is_new
    }

    /// 回收所有空闲超时的条目，返回回收条数。
    ///
    /// 由调用方显式驱动（不内置时钟/定时器）：这样超时行为在测试里是**完全确定性**的，
    /// 而不是"跑够 300 秒看看会不会回收"。
    pub fn expire(&mut self, now_us: u64) -> usize {
        self.stats.expire_runs += 1;
        let timeouts = self.cfg.timeouts;
        let mut removed: Vec<FlowEntry> = Vec::new();

        for shard in &mut self.shards {
            if shard.map.is_empty() {
                continue;
            }
            let mut expired: Vec<FlowKey> = shard
                .map
                .iter()
                .filter(|(_, e)| e.is_expired(now_us, &timeouts))
                .map(|(k, _)| *k)
                .collect();
            // 排序后再删：HashMap 迭代顺序不定，不排序会让回调顺序随运行变化。
            expired.sort_unstable();
            for k in expired {
                if let Some(e) = shard.map.remove(&k) {
                    removed.push(e);
                }
            }
        }

        removed.sort_by(|a, b| a.key.cmp(&b.key));
        let n = removed.len();
        for e in removed {
            self.stats.timeouts += 1;
            self.notify(Pending::Removed(FlowEvent::Timeout, e));
        }
        n
    }

    /// 以确定顺序输出全部键（调用方据此产出稳定报告/快照）。
    pub fn sorted_keys(&self) -> Vec<FlowKey> {
        let mut keys: Vec<FlowKey> = self
            .shards
            .iter()
            .flat_map(|s| s.map.keys().copied())
            .collect();
        keys.sort_unstable();
        keys
    }

    /// 以确定顺序输出全部条目（借用）。
    pub fn entries_sorted(&self) -> Vec<&FlowEntry> {
        let mut entries: Vec<&FlowEntry> =
            self.shards.iter().flat_map(|s| s.map.values()).collect();
        entries.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        entries
    }

    /// 以确定顺序取出全部条目（消费表）。
    pub fn into_entries_sorted(self) -> Vec<FlowEntry> {
        let mut entries: Vec<FlowEntry> = self
            .shards
            .into_iter()
            .flat_map(|s| s.map.into_values())
            .collect();
        entries.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        entries
    }

    /// 清空全表（不发回调：清空是调用方的显式动作，不是"条目自己超时了"）。
    pub fn clear(&mut self) {
        for shard in &mut self.shards {
            shard.map.clear();
        }
    }

    /// 派发一个事件给观察者。
    fn notify(&mut self, pending: Pending) {
        // 字段级拆分借用：`observer` 可变借用与 `shards` 不可变借用互不重叠。
        let Some(observer) = self.observer.as_mut() else {
            return;
        };
        match pending {
            Pending::Keyed(kind, key) => {
                let Some(entry) = lookup(&self.shards, &key) else {
                    // 条目在派发前被删掉（同一次调用内不会发生，但接口上可能）。
                    // 静默忽略而不是 panic：回调缺失是观测缺失，不是数据损坏。
                    return;
                };
                match kind {
                    FlowEvent::New => observer.on_new(entry),
                    FlowEvent::Update => observer.on_update(entry),
                    FlowEvent::Evict => observer.on_evict(entry),
                    FlowEvent::Timeout => observer.on_timeout(entry),
                }
            }
            Pending::Removed(kind, entry) => match kind {
                FlowEvent::Evict => observer.on_evict(&entry),
                FlowEvent::Timeout => observer.on_timeout(&entry),
                FlowEvent::New | FlowEvent::Update => {}
            },
        }
    }
}

/// 在分片集合里查一个键。
fn lookup<'a>(shards: &'a [Shard], key: &FlowKey) -> Option<&'a FlowEntry> {
    // 分片下标与表实例绑定，这里无法复用 `FlowTable::shard_index`（需要 &self）。
    // 用同一把哈希函数重算，代价是一次 FNV；换来的是借用拆分（见 `notify`）。
    let mut h = FnvHasher::default();
    key.hash_with(&mut h);
    let mask = shards.len().next_power_of_two() - 1;
    let idx = (h.finish() as usize) & mask;
    shards.get(idx)?.map.get(key)
}

/// 取并移除分片里最久未活动的条目。
///
/// **已知代价（刻意接受，不是疏忽）**：这是一次 O(分片容量) 的线性扫描。
/// 默认配置下分片容量为 65536，即表满时每插入一条新流约需 6.5 万次比较。
/// 之所以接受：逐出只在表满时发生，且正确性与确定性优先于峰值插入速率。
/// 将来若基准显示这是瓶颈，把本函数换成基于双向链表或最小堆的 O(1)/O(log n) LRU
/// 即可 —— 它是私有函数，替换不影响任何调用方。
///
/// 平局规则：`last_active_us` 相同时取键最小的那条。没有这条规则时，
/// HashMap 迭代顺序会让"同一次逐出丢谁"随运行变化，输出便不可复现。
fn evict_lru(shard: &mut Shard) -> Option<FlowEntry> {
    let victim = shard
        .map
        .iter()
        .min_by(|(ka, a), (kb, b)| {
            a.last_active_us
                .cmp(&b.last_active_us)
                .then_with(|| ka.cmp(kb))
        })
        .map(|(k, _)| *k)?;
    shard.map.remove(&victim)
}

/// 供 `FlowKey` 计算分片哈希的辅助 trait。
///
/// 显式逐字段写入，而不是依赖 `derive(Hash)` 的编码：派生实现会先写枚举判别式
/// （`Proto`）再写字段，编码细节随编译器版本可能变化，而分片映射一旦变化，
/// "同一分片"的假设在跨版本对比时就不成立了。这里自己定编码，永远稳定。
pub trait FlowKeyHashExt {
    fn hash_with(&self, hasher: &mut FnvHasher);
}

impl FlowKeyHashExt for FlowKey {
    fn hash_with(&self, hasher: &mut FnvHasher) {
        // 地址：先写族标记，再写 16 字节（v4 只占前 4 字节，其余为 0）。
        match self.src_ip {
            std::net::IpAddr::V4(v4) => {
                hasher.write(&[4]);
                hasher.write(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                hasher.write(&[6]);
                hasher.write(&v6.octets());
            }
        }
        hasher.write(&self.src_port.to_be_bytes());
        match self.dst_ip {
            std::net::IpAddr::V4(v4) => {
                hasher.write(&[4]);
                hasher.write(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                hasher.write(&[6]);
                hasher.write(&v6.octets());
            }
        }
        hasher.write(&self.dst_port.to_be_bytes());
        hasher.write(&[self.proto.number()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::IPPROTO_TCP;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn key(a: u8, sport: u16, b: u8, dport: u16) -> FlowKey {
        FlowKey::new_ipv4([10, 0, 0, a], sport, [10, 0, 0, b], dport, IPPROTO_TCP)
    }

    fn pkt(k: FlowKey, ts: u64, len: u32) -> Packet {
        Packet {
            key: k,
            payload_len: len,
            timestamp_us: ts,
        }
    }

    fn small_table(max: usize) -> FlowTable {
        FlowTable::new(FlowTableConfig {
            shard_count: 1,
            max_flows: max,
            ..FlowTableConfig::default()
        })
    }

    /// 记录事件的观察者（用 Rc<RefCell<..>> 以便断言后仍能读取）。
    #[derive(Clone, Default)]
    struct Recorder {
        events: Rc<RefCell<Vec<String>>>,
    }

    impl Recorder {
        fn new() -> Self {
            Self::default()
        }
        fn push(&self, s: String) {
            self.events.borrow_mut().push(s);
        }
        fn take(&self) -> Vec<String> {
            self.events.borrow().clone()
        }
    }

    impl FlowObserver for Recorder {
        fn on_new(&mut self, e: &FlowEntry) {
            self.push(format!("new {}", e.key.dst_port));
        }
        fn on_update(&mut self, e: &FlowEntry) {
            self.push(format!("update {}", e.key.dst_port));
        }
        fn on_evict(&mut self, e: &FlowEntry) {
            self.push(format!("evict {}", e.key.dst_port));
        }
        fn on_timeout(&mut self, e: &FlowEntry) {
            self.push(format!("timeout {}", e.key.dst_port));
        }
    }

    // ---- 基本插入与更新 ----

    #[test]
    fn insert_then_update_keeps_one_entry() {
        let mut t = small_table(16);
        let k = key(1, 1000, 2, 80);
        assert!(t.observe(&pkt(k, 100, 10)), "首次应报新建");
        assert_eq!(t.len(), 1);
        assert!(!t.observe(&pkt(k, 200, 20)), "第二次应报更新");
        assert_eq!(t.len(), 1, "同键不得产生第二条");

        let e = t.get(&k).expect("条目在");
        assert_eq!(e.flow.packet_count, 2);
        assert_eq!(e.flow.total_bytes, 30);
        assert_eq!(e.updates, 1, "首次插入不计入更新次数");
        assert_eq!(e.created_us, 100);
        assert_eq!(e.last_active_us, 200);
        assert_eq!(t.stats().inserts, 1);
        assert_eq!(t.stats().updates, 1);
        assert_eq!(t.stats().packets, 2);
    }

    #[test]
    fn table_is_direction_sensitive() {
        let mut t = small_table(16);
        let fwd = key(1, 1000, 2, 80);
        let rev = fwd.reverse();
        t.observe(&pkt(fwd, 1, 10));
        t.observe(&pkt(rev, 2, 20));
        assert_eq!(t.len(), 2, "上下行是两条流（否则上下行比恒为 1）");
    }

    #[test]
    fn same_key_always_lands_in_the_same_shard() {
        let t = FlowTable::new(FlowTableConfig {
            shard_count: 16,
            ..FlowTableConfig::default()
        });
        let k = key(1, 1000, 2, 80);
        let a = t.shard_of(&k);
        let b = t.shard_of(&k.reverse());
        assert_eq!(t.shard_of(&k), a, "分片下标必须是纯函数");
        assert!(a < 16 && b < 16);
    }

    #[test]
    fn shards_are_bounded_individually() {
        // 16 个分片、容量 16 → 每分片 1 条；总条数不会超过 16。
        let mut t = FlowTable::new(FlowTableConfig {
            shard_count: 16,
            max_flows: 16,
            ..FlowTableConfig::default()
        });
        for i in 0..200u16 {
            t.observe(&pkt(key(1, i, 2, 80), u64::from(i), 10));
        }
        assert!(t.len() <= 16, "总容量必须被守住，实际 {}", t.len());
        assert_eq!(t.per_shard_capacity(), 1);
        assert!(t.stats().evictions > 0, "超出容量必须走逐出而不是无限增长");
    }

    // ---- 容量与 LRU 逐出 ----

    #[test]
    fn eviction_keeps_size_stable_and_fires_on_evict() {
        let mut t = small_table(2);
        let rec = Recorder::new();
        t.set_observer(Box::new(rec.clone()));

        t.observe(&pkt(key(1, 1000, 2, 80), 10, 1));
        t.observe(&pkt(key(1, 1001, 2, 80), 20, 1));
        t.observe(&pkt(key(1, 1002, 2, 80), 30, 1)); // 触发逐出

        assert_eq!(t.len(), 2, "达到上限后内存稳定");
        assert_eq!(t.stats().evictions, 1);
        let events = rec.take();
        assert_eq!(events, vec!["new 80", "new 80", "evict 80", "new 80"]);
        // 逐出的是最久未活动的 1000。
        assert!(!t.contains(&key(1, 1000, 2, 80)), "最久未活动者应被逐出");
        assert!(t.contains(&key(1, 1001, 2, 80)));
        assert!(t.contains(&key(1, 1002, 2, 80)));
    }

    #[test]
    fn lru_uses_recent_activity_not_creation_order() {
        let mut t = small_table(2);
        let oldest = key(1, 1000, 2, 80);
        let middle = key(1, 1001, 2, 80);
        let newest = key(1, 1002, 2, 80);

        t.observe(&pkt(oldest, 10, 1));
        t.observe(&pkt(middle, 20, 1));
        // 让 oldest 重新活跃：它不再是"最久未活动"。
        t.observe(&pkt(oldest, 30, 1));
        t.observe(&pkt(newest, 40, 1)); // 触发逐出

        assert!(t.contains(&oldest), "刚活跃过的流不得被逐出");
        assert!(!t.contains(&middle), "被逐出的应是 middle");
    }

    #[test]
    fn eviction_never_removes_the_entry_being_inserted() {
        let mut t = small_table(1);
        for i in 0..5u16 {
            t.observe(&pkt(key(1, i, 2, 80), u64::from(i) + 1, 1));
        }
        assert_eq!(t.len(), 1);
        assert_eq!(t.stats().evictions, 4);
        assert!(t.contains(&key(1, 4, 2, 80)), "最后插入的必须在表里");
    }

    // ---- 超时 ----

    #[test]
    fn expire_removes_only_idle_entries_per_class() {
        let mut t = FlowTable::new(FlowTableConfig {
            shard_count: 1,
            max_flows: 64,
            timeouts: TimeoutTable {
                tcp_established_us: 100,
                tcp_transient_us: 50,
                udp_us: 20,
                icmp_us: 10,
                default_us: 5,
            },
            ..FlowTableConfig::default()
        });

        let established = key(1, 1000, 2, 80);
        let transient = key(1, 1001, 2, 80);
        t.observe(&pkt(established, 0, 1));
        t.observe(&pkt(transient, 0, 1));
        t.set_class(&established, TimeoutClass::TcpEstablished);

        // now = 60：transient（50）已超时，established（100）还没有。
        assert_eq!(t.expire(60), 1);
        assert!(t.contains(&established), "长超时档不得被短超时误伤");
        assert!(!t.contains(&transient));
        assert_eq!(
            t.get(&established).map(|e| e.class),
            Some(TimeoutClass::TcpEstablished)
        );

        // now = 100：established 也到期。
        assert_eq!(t.expire(100), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn expire_fires_on_timeout_with_stable_order() {
        let mut t = FlowTable::new(FlowTableConfig {
            shard_count: 3,
            max_flows: 64,
            timeouts: TimeoutTable {
                tcp_transient_us: 1,
                ..TimeoutTable::default()
            },
            ..FlowTableConfig::default()
        });
        let rec = Recorder::new();
        t.set_observer(Box::new(rec.clone()));
        for p in [80u16, 443, 53, 22] {
            t.observe(&pkt(key(1, 1000 + p, 2, p), 10, 1));
        }
        let n = t.expire(1_000);
        assert_eq!(n, 4);
        let events = rec.take();
        let mut ports: Vec<u16> = events
            .iter()
            .filter_map(|e| e.strip_prefix("timeout "))
            .filter_map(|p| p.parse::<u16>().ok())
            .collect();
        assert_eq!(ports.len(), 4);
        ports.sort_unstable();
        assert_eq!(ports, vec![22, 53, 80, 443], "回收顺序必须确定（按会话键）");
    }

    #[test]
    fn expire_is_a_no_op_when_nothing_is_idle_forever() {
        let mut t = small_table(8);
        t.observe(&pkt(key(1, 1, 2, 80), 0, 1));
        assert_eq!(t.expire(0), 0, "零空闲不得被回收");
        assert_eq!(t.expire(1), 0, "空闲 1 微秒远未到档位");
        assert_eq!(t.len(), 1);
        assert_eq!(t.stats().expire_runs, 2);
    }

    #[test]
    fn expire_updates_the_timeout_counter() {
        let mut t = FlowTable::new(FlowTableConfig {
            shard_count: 1,
            max_flows: 8,
            timeouts: TimeoutTable {
                tcp_transient_us: 5,
                ..TimeoutTable::default()
            },
            ..FlowTableConfig::default()
        });
        t.observe(&pkt(key(1, 1, 2, 80), 0, 1));
        assert_eq!(t.expire(5), 1, "恰好等于超时阈值即到期（>= 语义）");
        assert_eq!(t.stats().timeouts, 1);
    }

    // ---- 回调时序 ----

    #[test]
    fn observer_event_sequence_is_new_update_new() {
        let mut t = small_table(8);
        let rec = Recorder::new();
        t.set_observer(Box::new(rec.clone()));
        let k = key(1, 1000, 2, 80);
        t.observe(&pkt(k, 1, 1));
        t.observe(&pkt(k, 2, 1));
        t.observe(&pkt(k, 3, 1));
        assert_eq!(rec.take(), vec!["new 80", "update 80", "update 80"]);
    }

    #[test]
    fn observer_sees_the_updated_counters() {
        struct Counting(Rc<RefCell<Vec<u64>>>);
        impl FlowObserver for Counting {
            fn on_update(&mut self, e: &FlowEntry) {
                self.0.borrow_mut().push(e.flow.packet_count);
            }
        }
        let mut t = small_table(8);
        let seen = Rc::new(RefCell::new(Vec::new()));
        t.set_observer(Box::new(Counting(seen.clone())));
        let k = key(1, 1000, 2, 80);
        for i in 1..=3u64 {
            t.observe(&pkt(k, i, 1));
        }
        assert_eq!(&*seen.borrow(), &[2, 3], "回调必须看到已更新的计数");
    }

    #[test]
    fn table_works_without_an_observer() {
        let mut t = small_table(2);
        assert!(!t.has_observer());
        t.observe(&pkt(key(1, 1, 2, 80), 1, 1));
        // 默认 TCP transient 档 30 秒；空闲 60 秒后应被回收。
        assert_eq!(t.expire(60_000_000), 1);
        assert!(t.is_empty(), "无观察者时功能不受影响");
    }

    #[test]
    fn clearing_the_observer_stops_events() {
        let mut t = small_table(8);
        let rec = Recorder::new();
        t.set_observer(Box::new(rec.clone()));
        t.observe(&pkt(key(1, 1, 2, 80), 1, 1));
        t.clear_observer();
        t.observe(&pkt(key(1, 1, 2, 80), 2, 1));
        assert_eq!(rec.take(), vec!["new 80"], "置空后不再派发");
    }

    // ---- 确定性输出 ----

    #[test]
    fn sorted_output_is_independent_of_insertion_order() {
        let mut a = small_table(64);
        let mut b = small_table(64);
        let keys = [
            key(1, 1000, 2, 443),
            key(2, 2000, 3, 80),
            key(1, 1000, 2, 80),
            key(3, 3000, 1, 22),
        ];
        for (i, k) in keys.iter().enumerate() {
            a.observe(&pkt(*k, i as u64, 1));
        }
        for (i, k) in keys.iter().rev().enumerate() {
            b.observe(&pkt(*k, i as u64, 1));
        }
        let sa: Vec<FlowKey> = a.sorted_keys();
        let sb: Vec<FlowKey> = b.sorted_keys();
        assert_eq!(sa, sb, "输出顺序必须与插入顺序无关");
        let mut sorted = sa.clone();
        sorted.sort_unstable();
        assert_eq!(sa, sorted);
        let e = a.into_entries_sorted();
        assert_eq!(e.len(), 4);
        assert_eq!(e[0].key, sa[0]);
    }

    // ---- 配置归一化 ----

    #[test]
    fn config_is_normalized_to_power_of_two_shards_within_capacity() {
        let t = FlowTable::new(FlowTableConfig {
            shard_count: 3, // 非 2 的幂
            max_flows: 100,
            ..FlowTableConfig::default()
        });
        assert_eq!(t.shard_count(), 4, "向上取到 2 的幂");
        assert_eq!(t.per_shard_capacity(), 25);
        // 分片数不得超过容量。
        let t2 = FlowTable::new(FlowTableConfig {
            shard_count: 32,
            max_flows: 8,
            ..FlowTableConfig::default()
        });
        assert_eq!(t2.shard_count(), 8);
        assert_eq!(t2.per_shard_capacity(), 1);
        // 容量至少 1。
        let t3 = FlowTable::new(FlowTableConfig {
            shard_count: 0,
            max_flows: 0,
            ..FlowTableConfig::default()
        });
        assert_eq!(t3.shard_count(), 1);
        assert_eq!(t3.per_shard_capacity(), 1);
    }

    #[test]
    fn timeout_class_maps_protocols_and_tcp_states() {
        assert_eq!(
            TimeoutClass::for_proto(Proto::Tcp),
            TimeoutClass::TcpTransient,
            "没看到握手结论前不得假设已建立"
        );
        assert_eq!(TimeoutClass::for_proto(Proto::Udp), TimeoutClass::Udp);
        assert_eq!(TimeoutClass::for_proto(Proto::Icmp), TimeoutClass::Icmp);
        assert_eq!(TimeoutClass::for_proto(Proto::Icmpv6), TimeoutClass::Icmp);
        assert_eq!(
            TimeoutClass::for_proto(Proto::Other(47)),
            TimeoutClass::Default
        );
        assert_eq!(
            TimeoutClass::for_tcp_state(TcpState::Established),
            TimeoutClass::TcpEstablished
        );
        assert_eq!(
            TimeoutClass::for_tcp_state(TcpState::CloseWait),
            TimeoutClass::TcpEstablished,
            "半关闭仍属已建立档"
        );
        assert_eq!(
            TimeoutClass::for_tcp_state(TcpState::TimeWait),
            TimeoutClass::TcpTransient
        );
        assert_eq!(
            TimeoutClass::for_tcp_state(TcpState::Reset),
            TimeoutClass::TcpTransient
        );
        let t = TimeoutTable::default();
        assert!(
            t.timeout_us(TimeoutClass::TcpEstablished) > t.timeout_us(TimeoutClass::TcpTransient)
        );
        assert!(t.timeout_us(TimeoutClass::TcpTransient) > t.timeout_us(TimeoutClass::Icmp));
    }

    #[test]
    fn stats_are_consistent_with_operations() {
        let mut t = small_table(4);
        let k1 = key(1, 1, 2, 80);
        let k2 = key(1, 2, 2, 80);
        t.observe(&pkt(k1, 1, 1));
        t.observe(&pkt(k1, 2, 1));
        t.observe(&pkt(k2, 3, 1));
        let s = t.stats();
        assert_eq!(s.packets, 3);
        assert_eq!(s.inserts, 2);
        assert_eq!(s.updates, 1);
        assert_eq!(s.inserts + s.updates, s.packets);
    }
}
