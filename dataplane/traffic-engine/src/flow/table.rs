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
// 3. **放不下时丢谁**（逐出）：表满时逐出最久未活动的那条（精确 LRU），**O(1)**。
//    条目存在分片自己的槽位数组里，并用 `prev/next` 下标串成双向链表：
//    插入挂到表尾、命中移到表尾、逐出摘表头。之所以不用 `HashMap` 迭代找最小
//    （早先的做法），是因为那样每次逐出要 O(每分片容量)：实测每片 8192 时 55µs/次，
//    而表满之后**每来一条新流都要付一次** —— 那等于把整张表的吞吐上限钉在 18k 新流/s。
//    语义没有变：仍然是精确 LRU、仍然确定性（同一输入 ⇒ 同一逐出序列），
//    只是把代价从 O(容量) 降到 O(1)。
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
/// **两种取值择一，语义相同（都是精确 LRU），代价差一个数量级**：
/// 差别只在"怎么找到最久未活动的那条"。
///
/// 默认是 `Lru`：分片内用双向链表维护活动序，逐出摘表头，**O(1)**。
/// 表满之后每次新建流都要逐出一条，而表满恰恰是省网的稳态
/// （1M 容量 / 60s 超时 ≈ 17k 次/s 的新建流速率），所以逐出必须是常数代价。
///
/// `LruScan` 是**对照实现**：扫描整片取 `last_active_us` 最小者，O(每分片容量)。
/// 实测每片 8192 时 55µs/次 —— 只够 18k 次/s，把整张表的吞吐上限钉死在新流速率上，
/// 扫描型流量会直接把它打崩。保留它有三个用处：单测用它做**等价性对照**
/// （链表策略的逐出序列必须与它一致）、基准用它给出改造前后的同机对比、
/// 以及小容量/离线复算场景仍可用。
///
/// 另外两条被评估过但没有采用的方案：
/// - **采样 LRU**（Redis `allkeys-lru` 式：随机取 K 条、淘汰其中最早）：
///   代价也是 O(K)，但实测在"400 条流 / 128 槽位 / 90% 热点"的负载上，
///   热点流命中率只有 58.4%，而精确 LRU 是 99.9% —— 省网里"流被逐出又重建"
///   意味着**同一条会话的记录被切成两段**，这个代价换不来那点 CPU。放弃。
/// - **时钟算法**：能 O(1)，但要在条目上维护引用位、引入第二个时间维度，
///   与"按 `last_active_us` 分档超时"重复，解释成本高于收益。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvictPolicy {
    /// 精确 LRU，分片内双向链表，代价 **O(1)**。
    #[default]
    Lru,
    /// 精确 LRU，扫描整片找最小者，代价 O(每分片容量)。对照/小表用。
    LruScan,
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
    /// 逐出时**考察过的候选条目数**（累计）。
    ///
    /// 存在的唯一目的：把"逐出是 O(1) 还是 O(容量)"从注释里的声明变成**可测的上界**。
    /// 链表策略（默认）恒为 **0** —— 摘表头不需要考察任何候选，这就是 O(1) 的直接证据；
    /// 扫描策略为 `每分片容量 × 逐出次数`。没有这个计数，复杂度回归只能靠基准的挂钟
    /// 时间去发现，而挂钟时间会随机器与负载漂移 20~30%。
    pub evict_candidates: u64,
    /// 因超时被回收的条目数。
    pub timeouts: u64,
    /// `expire()` 被调用的次数。
    pub expire_runs: u64,
}

/// 链表哨兵：`prev`/`next` 用它表示"没有前驱/后继"。
const NIL: u32 = u32::MAX;

/// 分片里的一个槽位：条目本体 + 双向链表的两个下标。
///
/// 条目用 `Option` 包着，是为了让 `remove`/逐出能把值**移出**（`take()`）而不是
/// 克隆一条 432 字节的 `FlowEntry`；空槽位下 `Option` 不占额外空间
/// （`FlowEntry` 无 niche，`Option<FlowEntry>` 比 `FlowEntry` 多 8 字节对齐填充）。
#[derive(Debug)]
struct Slot {
    entry: Option<FlowEntry>,
    prev: u32,
    next: u32,
}

/// 分片：`键 → 槽位下标` + 槽位数组（同时是双向链表的 LRU 序）。
///
/// **为什么不是 `HashMap<FlowKey, FlowEntry>`**：表满后每次新建流都要逐出一条，
/// 而"最久未活动的是谁"必须 O(1) 拿到。`HashMap` 既不能随机寻址、也不能 O(1)
/// 删除链表中部元素，所以把条目放进数组、用下标串成链表：
/// - 插入：追加到表尾（最近使用）；
/// - 命中：移到表尾；
/// - 逐出：摘表头（最久未活动）——**不需要考察任何候选**。
///
/// `free` 是复用槽位的空闲表：删除留下空洞时把下标还回来，数组不会无限增长。
/// 链表是**活动序**（同一次插入序/访问序），不是键序：这与旧实现的
/// "同时间戳取最小键"略有不同 —— 旧规则是为了让"时间戳无法区分时"仍可复现，
/// 而链表序本身就是一个全序，天然可复现，且更贴近 LRU 的本意
/// （刚被访问过的流即使时间戳相同也不该被淘汰）。
#[derive(Debug)]
struct Shard {
    map: FnvMap<FlowKey, u32>,
    slots: Vec<Slot>,
    free: Vec<u32>,
    /// 最久未活动（逐出从这里摘）。
    head: u32,
    /// 最近活动（新条目与命中都挂/移到这里）。
    tail: u32,
}

impl Shard {
    fn new() -> Self {
        Self {
            map: new_fnv_map(),
            slots: Vec::new(),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn get(&self, key: &FlowKey) -> Option<&FlowEntry> {
        let i = *self.map.get(key)?;
        self.slots[i as usize].entry.as_ref()
    }

    /// 只改内容、**不动 LRU 顺序**（顺序由 `hit`/`insert` 维护）。
    /// `get_mut` 的调用方是"改档位"这类管理操作，不是流量路径。
    fn get_mut(&mut self, key: &FlowKey) -> Option<&mut FlowEntry> {
        let i = *self.map.get(key)?;
        self.slots[i as usize].entry.as_mut()
    }

    /// 把槽位 `i` 移到表尾（标记为最近使用）。
    fn move_to_tail(&mut self, i: u32) {
        if self.tail == i {
            return;
        }
        let (prev, next) = {
            let s = &self.slots[i as usize];
            (s.prev, s.next)
        };
        // 先从原位置摘下。
        if prev == NIL {
            self.head = next;
        } else {
            self.slots[prev as usize].next = next;
        }
        if next != NIL {
            self.slots[next as usize].prev = prev;
        }
        // 再挂到表尾。
        let tail = self.tail;
        {
            let s = &mut self.slots[i as usize];
            s.prev = tail;
            s.next = NIL;
        }
        if tail == NIL {
            self.head = i;
        } else {
            self.slots[tail as usize].next = i;
        }
        self.tail = i;
    }

    /// 命中：更新条目并移到表尾。返回 `false` 表示键不在表里。
    ///
    /// 一次哈希查找完成"更新 + 维护 LRU 序"两件事，避免调用方查两遍。
    fn hit(&mut self, key: &FlowKey, pkt: &Packet) -> bool {
        let Some(&i) = self.map.get(key) else {
            return false;
        };
        if let Some(e) = self.slots[i as usize].entry.as_mut() {
            e.observe(pkt);
        }
        self.move_to_tail(i);
        true
    }

    /// 新建条目并挂到表尾。调用方负责容量检查。
    fn insert(&mut self, key: FlowKey, entry: FlowEntry) -> u32 {
        let i = match self.free.pop() {
            Some(i) => {
                let s = &mut self.slots[i as usize];
                s.entry = Some(entry);
                s.prev = self.tail;
                s.next = NIL;
                i
            }
            None => {
                let i = u32::try_from(self.slots.len()).expect("分片槽位下标溢出 u32");
                self.slots.push(Slot {
                    entry: Some(entry),
                    prev: self.tail,
                    next: NIL,
                });
                i
            }
        };
        if self.tail == NIL {
            self.head = i;
        } else {
            self.slots[self.tail as usize].next = i;
        }
        self.tail = i;
        self.map.insert(key, i);
        i
    }

    /// 删除键：摘链、还槽位、把条目移出返回。
    fn remove(&mut self, key: &FlowKey) -> Option<FlowEntry> {
        let i = self.map.remove(key)?;
        let (prev, next) = {
            let s = &self.slots[i as usize];
            (s.prev, s.next)
        };
        if prev == NIL {
            self.head = next;
        } else {
            self.slots[prev as usize].next = next;
        }
        if next == NIL {
            self.tail = prev;
        } else {
            self.slots[next as usize].prev = prev;
        }
        let slot = &mut self.slots[i as usize];
        slot.prev = NIL;
        slot.next = NIL;
        let entry = slot.entry.take();
        self.free.push(i);
        entry
    }

    /// 摘表头（最久未活动）。**不考察任何候选**，这是 O(1) 的来源。
    fn evict_head(&mut self) -> Option<FlowEntry> {
        if self.head == NIL {
            return None;
        }
        let i = self.head;
        let key = *self
            .slots
            .get(i as usize)
            .and_then(|s| s.entry.as_ref())
            .map(|e| &e.key)
            .expect("表头槽位必然在用");
        self.remove(&key)
    }

    /// 清空但**保留容量**（与 `HashMap::clear` 的语义一致：清条目、不还内存）。
    fn clear(&mut self) {
        self.tail = NIL;
        for i in 0..self.slots.len() as u32 {
            if let Some(e) = self.slots[i as usize].entry.take() {
                drop(e);
                self.slots[i as usize].prev = NIL;
                self.slots[i as usize].next = NIL;
                self.free.push(i);
            }
        }
        self.head = NIL;
        self.map.clear();
    }

    fn keys(&self) -> impl Iterator<Item = &FlowKey> {
        self.map.keys()
    }

    fn entries(&self) -> impl Iterator<Item = &FlowEntry> {
        self.slots.iter().filter_map(|s| s.entry.as_ref())
    }

    fn into_entries(self) -> impl Iterator<Item = FlowEntry> {
        self.slots.into_iter().filter_map(|s| s.entry)
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
        self.shards.iter().map(Shard::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(Shard::is_empty)
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
        self.shards[idx].get_mut(key)
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
            // 命中即"最近使用"：`hit` 同时完成统计更新与 LRU 序维护。
            if shard.hit(&key, pkt) {
                self.stats.updates += 1;
                pending = Some(Pending::Keyed(FlowEvent::Update, key));
            } else {
                if shard.len() >= self.per_shard_cap {
                    let (victim, examined) = evict_victim(shard, self.cfg.policy);
                    evicted = victim;
                    self.stats.evict_candidates += examined;
                }
                let class = TimeoutClass::for_proto(key.proto);
                let mut entry = FlowEntry::new(key, class, pkt.timestamp_us);
                entry.observe(pkt);
                // 上面的 observe 会把 updates 记成 1；首次插入不计入更新次数。
                entry.updates = 0;
                shard.insert(key, entry);
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

        // 只收集**键**（每条 40B），不收集条目（每条 432B）。
        //
        // 早先的实现把所有到期条目搬进一个 `Vec<FlowEntry>`，排序后逐条派发回调。
        // 那样临时内存是 `条目数 × sizeof(FlowEntry)`，500k 条即 216MiB 的一次性大块；
        // macOS 在释放后不把 RSS 还回来，实测「填满→全部到期」每轮让进程 RSS 抬升
        // 约 `条目数 × 432B`（250k 条 → +99MiB/轮），并且不保证回落 ——
        // 这直接违反 CYS-TRF-007「达到上限时内存稳定」的验收标准。
        //
        // 现在改成"先按键序收齐键、再逐条删并派发"：回调顺序（全局按键升序）与逐出
        // 语义完全不变，临时内存降到 `条目数 × sizeof(FlowKey)`。
        //
        // 唯一的可观察差异：回调期间表里可能仍留着**尚未派发**的到期条目（旧实现是先
        // 全删完再派发）。这个差异被明确接受：回调是只读观察，不该依赖"表此刻已清空"
        // 这种时序细节；而 RSS 不回落是硬伤。
        let mut expired_keys: Vec<FlowKey> = Vec::new();
        for shard in &self.shards {
            if shard.is_empty() {
                continue;
            }
            // 哈希表迭代顺序不定 → 统一排序，保证回调顺序随运行稳定。
            expired_keys.extend(
                shard
                    .keys()
                    .filter(|k| {
                        shard
                            .get(k)
                            .is_some_and(|e| e.is_expired(now_us, &timeouts))
                    })
                    .copied(),
            );
        }
        // 键不可能重复（一个键只存在于一个分片里），故无需去重。
        expired_keys.sort_unstable();

        let mut n = 0usize;
        for k in expired_keys {
            let idx = self.shard_index(&k);
            if let Some(e) = self.shards[idx].remove(&k) {
                n += 1;
                self.stats.timeouts += 1;
                self.notify(Pending::Removed(FlowEvent::Timeout, e));
            }
        }
        n
    }

    /// 以确定顺序输出全部键（调用方据此产出稳定报告/快照）。
    pub fn sorted_keys(&self) -> Vec<FlowKey> {
        let mut keys: Vec<FlowKey> = self.shards.iter().flat_map(|s| s.keys().copied()).collect();
        keys.sort_unstable();
        keys
    }

    /// 以确定顺序输出全部条目（借用）。
    pub fn entries_sorted(&self) -> Vec<&FlowEntry> {
        let mut entries: Vec<&FlowEntry> = self.shards.iter().flat_map(Shard::entries).collect();
        entries.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        entries
    }

    /// 以确定顺序取出全部条目（消费表）。
    pub fn into_entries_sorted(self) -> Vec<FlowEntry> {
        let mut entries: Vec<FlowEntry> = self
            .shards
            .into_iter()
            .flat_map(Shard::into_entries)
            .collect();
        entries.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        entries
    }

    /// 清空全表（不发回调：清空是调用方的显式动作，不是"条目自己超时了"）。
    pub fn clear(&mut self) {
        for shard in &mut self.shards {
            shard.clear();
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
    shards.get(idx)?.get(key)
}

/// 选出一个牺牲者并从分片里移除，返回（被逐出的条目，考察过的候选条目数）。
///
/// 两个分支的**语义完全相同**（都是精确 LRU：淘汰最久未活动的那条），区别只在代价：
/// - `Lru`：摘双向链表表头，**不考察任何候选** ⇒ 返回 0 个候选；
/// - `LruScan`：扫描整片比较 `last_active_us` ⇒ 返回每分片容量。
///
/// `evict_candidates` 因此成了复杂度的**可测证据**：单测断言链表策略恒为 0、
/// 扫描策略恰好是"容量 × 逐出次数"，谁把 O(1) 改回 O(容量)，测试立刻红。
fn evict_victim(shard: &mut Shard, policy: EvictPolicy) -> (Option<FlowEntry>, u64) {
    match policy {
        EvictPolicy::Lru => (shard.evict_head(), 0),
        EvictPolicy::LruScan => {
            let victim = shard
                .slots
                .iter()
                .filter_map(|s| s.entry.as_ref())
                .min_by(|a, b| {
                    a.last_active_us
                        .cmp(&b.last_active_us)
                        .then_with(|| a.key.cmp(&b.key))
                })
                .map(|e| e.key);
            let examined = shard.len() as u64;
            (victim.and_then(|k| shard.remove(&k)), examined)
        }
    }
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

    // ---- LRU 的代价与等价性（本批的 O(容量) → O(1)）----

    /// 单分片表：便于把"每分片容量"当成"容量"来算复杂度。
    fn one_shard(cap: usize, policy: EvictPolicy) -> FlowTable {
        FlowTable::new(FlowTableConfig {
            shard_count: 1,
            max_flows: cap,
            policy,
            ..FlowTableConfig::default()
        })
    }

    /// 填满单分片表（填充阶段零逐出）。
    fn fill_one_shard(t: &mut FlowTable, cap: usize, base: u16) -> Vec<FlowKey> {
        let mut ks = Vec::new();
        for i in 0..cap {
            let k = key(1, base + i as u16, 2, 80);
            t.observe(&pkt(k, i as u64 + 1, 10));
            ks.push(k);
        }
        assert_eq!(t.len(), cap, "填充阶段应恰好装满");
        assert_eq!(t.stats().evictions, 0, "填充阶段不该逐出");
        ks
    }

    #[test]
    fn default_policy_is_the_o1_list_lru() {
        assert_eq!(EvictPolicy::default(), EvictPolicy::Lru);
        assert_eq!(FlowTableConfig::default().policy, EvictPolicy::Lru);
        // 默认策略必须是"不考察任何候选"的那一个。谁把默认值换成扫描版，
        // 就该先看到基准里 55µs/次 的数字，再读 `EvictPolicy` 上的说明。
        let mut t = one_shard(64, EvictPolicy::default());
        fill_one_shard(&mut t, 64, 1000);
        t.observe(&pkt(key(3, 9000, 4, 90), 1_000_000, 10));
        assert_eq!(t.stats().evictions, 1);
        assert_eq!(t.stats().evict_candidates, 0, "默认策略不该扫描候选");
    }

    #[test]
    fn list_lru_evicts_without_examining_any_candidate() {
        // 把"逐出是 O(1)"变成**可测的硬证据**：链表策略恒不考察候选。
        // 这条断言就是本批改造的验收标准 —— 它一旦失败，说明逐出又回到了扫描。
        let cap = 4096usize;
        let mut t = one_shard(cap, EvictPolicy::Lru);
        fill_one_shard(&mut t, cap, 1000);
        let n_evict = 200u64;
        for i in 0..n_evict {
            t.observe(&pkt(key(3, 5000 + i as u16, 4, 90), 10_000 + i, 10));
        }
        let st = t.stats();
        assert_eq!(st.evictions, n_evict, "满表后每次插入都该逐出一条");
        assert_eq!(st.evict_candidates, 0, "链表 LRU 每次逐出考察 0 个候选");
        assert_eq!(t.len(), cap, "逐出后表仍应恰好装满");
    }

    #[test]
    fn scan_lru_examines_the_whole_shard() {
        // 对照实现：扫描版的代价就是整片容量 —— 留着它是为了让"为什么必须改"可复核。
        let cap = 512usize;
        let mut t = one_shard(cap, EvictPolicy::LruScan);
        fill_one_shard(&mut t, cap, 1000);
        let n_evict = 20u64;
        for i in 0..n_evict {
            t.observe(&pkt(key(3, 5000 + i as u16, 4, 90), 10_000 + i, 10));
        }
        let st = t.stats();
        assert_eq!(st.evictions, n_evict);
        assert_eq!(
            st.evict_candidates,
            n_evict * cap as u64,
            "扫描策略每次逐出都要考察整片（这正是它被换掉的原因）"
        );
    }

    /// 在给定策略下跑一段固定流量，返回被逐出的键序列与最终存活键。
    fn run_eviction_trace(policy: EvictPolicy, cap: usize) -> (Vec<FlowKey>, Vec<FlowKey>) {
        let mut t = one_shard(cap, policy);
        let evicted = Rc::new(RefCell::new(Vec::new()));
        t.set_observer(Box::new(EvictRecorder {
            evicted: evicted.clone(),
        }));
        // 时间戳严格递增：让"最小 last_active_us"没有平局，两种实现必须给出同一答案。
        for i in 0..900u64 {
            let k = key(5, 2000 + (i % 400) as u16, 6, 443 + (i % 7) as u16);
            t.observe(&pkt(k, i * 10 + 1, 10));
        }
        let mut survivors = t.sorted_keys();
        survivors.sort_unstable();
        let out = evicted.borrow().clone();
        (out, survivors)
    }

    /// 只录逐出事件的观察者（`Recorder` 记的是字符串，这里需要键）。
    #[derive(Clone, Default)]
    struct EvictRecorder {
        evicted: Rc<RefCell<Vec<FlowKey>>>,
    }

    impl FlowObserver for EvictRecorder {
        fn on_new(&mut self, _e: &FlowEntry) {}
        fn on_update(&mut self, _e: &FlowEntry) {}
        fn on_evict(&mut self, e: &FlowEntry) {
            self.evicted.borrow_mut().push(e.key);
        }
        fn on_timeout(&mut self, _e: &FlowEntry) {}
    }

    #[test]
    fn list_lru_and_scan_lru_choose_the_same_victims() {
        // 语义等价性：链表维护的是"活动序"，扫描比的是 (last_active_us, key)。
        // 时间戳严格递增时两者必须逐次给出**同一个**牺牲者 —— 否则"换成链表"
        // 就成了一次悄悄的语义变更，而不是纯性能改造。
        let (list_evicted, list_survivors) = run_eviction_trace(EvictPolicy::Lru, 512);
        let (scan_evicted, scan_survivors) = run_eviction_trace(EvictPolicy::LruScan, 512);
        assert!(!list_evicted.is_empty(), "这段流量应该产生逐出");
        assert_eq!(list_evicted, scan_evicted, "两种实现的逐出序列必须一致");
        assert_eq!(list_survivors, scan_survivors, "存活集合也必须一致");
    }

    #[test]
    fn list_lru_evicts_the_globally_oldest_in_a_large_shard() {
        // 精确 LRU 的定义性质：片内最老的那条先出，**不管它排在哪里**。
        // （采样式逐出会在这里失败：窗口里没有它就永远不会被选中。）
        let cap = 4096usize;
        let mut t = one_shard(cap, EvictPolicy::Lru);
        let ancient = key(1, 1111, 2, 80);
        t.observe(&pkt(ancient, 1, 10));
        for i in 0..cap - 1 {
            t.observe(&pkt(key(1, 2000 + i as u16, 2, 80), 10_000 + i as u64, 10));
        }
        assert_eq!(t.len(), cap);
        assert_eq!(t.stats().evictions, 0);
        // 再来一条新流 → 必须淘汰那条最老的。
        t.observe(&pkt(key(1, 9999, 2, 81), 1_000_000, 10));
        assert_eq!(t.stats().evictions, 1);
        assert!(!t.contains(&ancient), "片内最老的那条必须先被淘汰");
    }

    #[test]
    fn list_lru_orders_equal_timestamps_by_recency() {
        // 与旧实现的**唯一语义差异**，必须写清楚并被测试钉住：
        // 时间戳相同时，旧实现按"最小键"打破平局；链表按"谁更晚被访问"。
        // 后者更贴近 LRU 本意（刚访问过的流即使时间戳相同也不该被淘汰），
        // 且同样是全序、同样可复现。
        let mut t = one_shard(2, EvictPolicy::Lru);
        let a = key(1, 1000, 2, 80);
        let b = key(1, 2000, 2, 80);
        t.observe(&pkt(a, 100, 10));
        t.observe(&pkt(b, 100, 10));
        // b 刚被访问过（时间戳相同但更晚进入表尾）→ 再来一条时该淘汰 a。
        let c = key(1, 3000, 2, 80);
        t.observe(&pkt(c, 100, 10));
        assert_eq!(t.stats().evictions, 1);
        assert!(!t.contains(&a), "更早被访问的那条先出（键序不影响结果）");
        assert!(t.contains(&b) && t.contains(&c));
    }

    #[test]
    fn removed_slots_are_reused_instead_of_growing_the_arena() {
        // 槽位复用是这套结构的前提：逐出/到期都在"删"，若不复用，槽位数组会随
        // 累计插入量无限增长 —— 那就等于把内存泄漏藏进了 LRU 改造里。
        let cap = 64usize;
        let mut t = one_shard(cap, EvictPolicy::Lru);
        for round in 0..50u64 {
            for i in 0..cap {
                t.observe(&pkt(
                    key(1, (round as u16) * 200 + i as u16, 2, 80),
                    round * 1000 + i as u64,
                    10,
                ));
            }
            // 全部到期回收，把槽位还回空闲表。
            let n = t.expire(u64::MAX / 2);
            assert!(n > 0, "每轮都该有到期条目");
        }
        assert!(t.is_empty(), "每轮结束都该清空");
        let slots = t.shards[0].slots.len();
        assert_eq!(slots, cap, "槽位数组必须停在容量上限（复用），实际 {slots}");
        // 还能继续正常插入。
        t.observe(&pkt(key(9, 1, 9, 1), 1, 10));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn clear_resets_the_lru_list_and_keeps_capacity() {
        let cap = 128usize;
        let mut t = one_shard(cap, EvictPolicy::Lru);
        fill_one_shard(&mut t, cap, 1000);
        let slots_before = t.shards[0].slots.len();
        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.shards[0].head, NIL, "清空后链表头应复位");
        assert_eq!(t.shards[0].tail, NIL, "清空后链表尾应复位");
        assert_eq!(
            t.shards[0].slots.len(),
            slots_before,
            "clear 只清条目、不还内存（与 HashMap::clear 语义一致）"
        );
        // 清空后再填满，仍应零逐出（说明链表与空闲表都复位干净了）。
        fill_one_shard(&mut t, cap, 2000);
        assert_eq!(t.len(), cap);
    }

    #[test]
    fn lru_keeps_hot_flows() {
        // 语义要求（手写，不是"跑一遍记下来"）：在"少量热点流 + 大量冷流"的负载下，
        // 热点流的访问命中率不得低于 95%。这是"LRU 真的像 LRU"的量化底线 ——
        // 采样式逐出（K=8）在这里只有 58%，正因如此才没有采用它。
        fn hit_rate(policy: EvictPolicy, cap: usize) -> (u64, u64) {
            let mut t = one_shard(cap, policy);
            let mut state = 0x1234_5678u64;
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let (mut hot_hit, mut hot_tot) = (0u64, 0u64);
            for i in 0..40_000u64 {
                let hot = next() % 100 < 90;
                let idx = if hot { next() % 40 } else { 40 + next() % 360 };
                let k = key(7, 100 + idx as u16, 8, 8080);
                if hot {
                    hot_tot += 1;
                    if t.contains(&k) {
                        hot_hit += 1;
                    }
                }
                t.observe(&pkt(k, i * 100, 10));
            }
            (hot_hit, hot_tot)
        }

        let (hot_hit, hot_tot) = hit_rate(EvictPolicy::Lru, 128);
        assert!(
            hot_hit * 100 >= hot_tot * 95,
            "热点流命中率 {hot_hit}/{hot_tot} 低于 95%（这不再是 LRU 了）"
        );
        let (scan_hit, scan_tot) = hit_rate(EvictPolicy::LruScan, 128);
        assert_eq!(
            (hot_hit, hot_tot),
            (scan_hit, scan_tot),
            "链表 LRU 与扫描 LRU 的行为必须一致"
        );
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
    fn expire_dispatches_callbacks_in_global_key_order() {
        // 旧实现是"先收齐再全局排序派发"，新实现是"按键序逐条删除并派发"。
        // 两条路径都必须给出同一个顺序，否则"回调顺序稳定"就成了空话。
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
        for p in [443u16, 22, 80, 53] {
            t.observe(&pkt(key(1, 1000 + p, 2, p), 10, 1));
        }
        assert_eq!(t.expire(1_000), 4);
        let ports: Vec<u16> = rec
            .take()
            .iter()
            .filter_map(|e| e.strip_prefix("timeout "))
            .filter_map(|p| p.parse::<u16>().ok())
            .collect();
        // 端口升序 = 会话键升序（源地址与目的地址都固定，只有源端口在变）。
        assert_eq!(ports, vec![22, 53, 80, 443], "回调必须按全局会话键升序派发");
    }

    #[test]
    fn expire_keeps_the_non_expired_entries() {
        // 新实现逐条删除，最容易犯的错是删错分片/删过头 —— 这里按两类超时分层核对。
        let mut t = FlowTable::new(FlowTableConfig {
            shard_count: 4,
            max_flows: 64,
            timeouts: TimeoutTable::default(),
            ..FlowTableConfig::default()
        });
        for i in 0..8u16 {
            t.observe(&pkt(key(1, 1000 + i, 2, 80), u64::from(i) * 1000, 1));
        }
        // 只让前 3 条老到「空闲 ≥ 瞬态超时」：第 3 条（时间戳 2000）恰好等于阈值即到期，
        // 第 4 条（时间戳 3000）差 1µs，必须留下 —— 顺带把 >= 边界钉住。
        let transient = t.cfg().timeouts.tcp_transient_us;
        let n = t.expire(2_000 + transient);
        assert_eq!(n, 3, "恰好前 3 条到期");
        assert_eq!(t.len(), 5);
        assert_eq!(t.stats().timeouts, 3);
        for i in 0..3u16 {
            assert!(!t.contains(&key(1, 1000 + i, 2, 80)), "第 {i} 条应被回收");
        }
        for i in 3..8u16 {
            assert!(t.contains(&key(1, 1000 + i, 2, 80)), "第 {i} 条不该被回收");
        }
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
