// flow/mod.rs - Packet / Flow / FlowKey 模型与流表入口（CYS-TRF-004/005/006-009/014）
// 数据链：Packet -> FlowTable -> Session -> FlowRecord
//
// 本模块的职责边界是刻意划的，三条都不能含糊：
//
// 1. **`FlowKey` 是方向敏感的**：一条双向会话对应两个 `FlowKey`。`canonical()`
//    给出"与方向无关"的会话键，但那是**上层聚合的输入**，不是流表的键 ——
//    流表若把双向合并成一条，上下行就再也分不开了（而"上下行比"是特征之一）。
//
// 2. **`Flow` 只负责记账**，超时与逐出不在它这里。原因：超时判据是"多久没新包"
//    （需要时钟），逐出判据是"表满时丢谁"（需要全局视角），两者都是**表级**决策。
//    把它们塞进 `Flow` 会让同一个 Flow 在两张表里的行为不同。
//
// 3. **协议号是类型不是裸 `u8`**（CYS-TRF-004）。裸 `u8` 的代价不是难看，而是
//    `proto == 6` 这类比较会散落在各处，且拼错（比如写成 `proto == 17` 却当成 TCP）
//    时编译器一句话都不说。

pub mod stats;
pub mod table;

pub use stats::{FlowStats, IatRing, HIST_BUCKETS};
pub use table::{
    EvictPolicy, FlowEntry, FlowObserver, FlowTable, FlowTableConfig, NoopObserver, TableStats,
    TimeoutClass, TimeoutTable, DEFAULT_MAX_FLOWS, DEFAULT_SHARD_COUNT,
};

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IANA 协议号。**唯一真源在 `configs/registry/attributes.json` 之外的代码侧常量**，
/// 因此只允许在这里出现一次；解码器与状态机都从这里取，避免多处各写一份 6/17。
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

/// 四层协议（类型化；CYS-TRF-004）。
///
/// `Other` 保留原始协议号而不是"归入未知"：ESP(50)/GRE(47)/SCTP(132) 这类协议
/// 虽然拿不到端口，但**协议号本身是流键的一部分**。把它们塌缩成一个 `Unknown`，
/// 所有非 TCP/UDP 的流会合并统计，而输出上看不出任何异常。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    /// 6
    Tcp,
    /// 17
    Udp,
    /// 1
    Icmp,
    /// 58
    Icmpv6,
    /// 其余（含 ESP/GRE/SCTP 等）；端口恒为 0。
    Other(u8),
}

impl Proto {
    pub const fn from_u8(v: u8) -> Self {
        match v {
            IPPROTO_TCP => Proto::Tcp,
            IPPROTO_UDP => Proto::Udp,
            IPPROTO_ICMP => Proto::Icmp,
            IPPROTO_ICMPV6 => Proto::Icmpv6,
            other => Proto::Other(other),
        }
    }

    /// IANA 协议号（`FlowKey` 与 wire 上的取值）。
    pub const fn number(self) -> u8 {
        match self {
            Proto::Tcp => IPPROTO_TCP,
            Proto::Udp => IPPROTO_UDP,
            Proto::Icmp => IPPROTO_ICMP,
            Proto::Icmpv6 => IPPROTO_ICMPV6,
            Proto::Other(v) => v,
        }
    }

    /// 该协议的头里是否有端口字段。
    ///
    /// 只有 TCP/UDP 有。这不是"不知道就填 0"的兜底，而是**协议本身没有端口**：
    /// ICMP 的两个"端口"恒为 0 是正确表示，不是缺失。
    pub const fn has_ports(self) -> bool {
        matches!(self, Proto::Tcp | Proto::Udp)
    }

    pub const fn is_tcp(self) -> bool {
        matches!(self, Proto::Tcp)
    }

    pub const fn is_udp(self) -> bool {
        matches!(self, Proto::Udp)
    }

    /// 是否有连接状态（决定超时档与状态机是否适用）。
    pub const fn is_connection_oriented(self) -> bool {
        matches!(self, Proto::Tcp)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Icmpv6 => "icmpv6",
            Proto::Other(_) => "other",
        }
    }
}

impl From<u8> for Proto {
    fn from(v: u8) -> Self {
        Proto::from_u8(v)
    }
}

impl From<Proto> for u8 {
    fn from(p: Proto) -> Self {
        p.number()
    }
}

/// 以协议号输出。
///
/// 刻意**不是** `as_str()`：这条 `Display` 是给 `ring-consume`/`cythsec-analyze`
/// 的机器可读输出用的（`proto=6`），改动它会静默破坏 e2e 脚本的字段抓取。
/// 要人读的名字请显式调用 `as_str()`。
impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.number())
    }
}

/// 五元组：源/目的地址与端口 + 协议，用于唯一标识**一个方向**的流。
///
/// 除 `Hash`/`Eq`（流表用）外还实现 `Ord`：**输出需要确定性顺序**。以 HashMap 遍历流表
/// 输出的报告每次顺序都不同，使跨次比对（e2e 逐行 diff、快照回归）失去意义 ——
/// 排序规则本身不重要，稳定才重要。`IpAddr` 的 `Ord` 先按 v4/v6 分族再按地址，
/// 因此同族地址的先后与数值大小一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub proto: Proto,
}

impl FlowKey {
    /// 简易 IPv4 三元组构造（测试与演示常用）。
    ///
    /// 参数仍是裸 `u8` 协议号：调用点（测试、e2e 向量）写的是 IANA 号，
    /// 让它们先转 `Proto` 只会增加噪音。转换只在这一处发生。
    pub fn new_ipv4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, proto: u8) -> Self {
        Self {
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
            src_port: sport,
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
            dst_port: dport,
            proto: Proto::from_u8(proto),
        }
    }

    /// IPv6 版本。decode 层本来就在手写结构体字面量，把它收成一个构造器：
    /// 两处都手写时，任何一次字段增删都容易只改一边（另一边仍能编译）。
    pub fn new_ipv6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, proto: u8) -> Self {
        Self {
            src_ip: IpAddr::V6(src),
            src_port: sport,
            dst_ip: IpAddr::V6(dst),
            dst_port: dport,
            proto: Proto::from_u8(proto),
        }
    }

    /// 交换源与目的（反向流键）。
    pub const fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
            proto: self.proto,
        }
    }

    /// 会话键：与方向无关的稳定规范形式（CYS-TRF-005）。
    ///
    /// 规则：把两端点按 `(地址, 端口)` 排序，端点小的一方作源。于是
    /// `canonical(a→b) == canonical(b→a)`，双向包必落入同一条会话。
    ///
    /// 为什么按端点排序而不是"以发起方为准"：**方向并不总是已知的**。旁路设备
    /// 中途接入时，先看到的可能是响应；若规范形式依赖"谁先发包"，同一条会话在
    /// 补看到 SYN 之前与之后会得到两个不同的键，会话被劈成两条。
    /// 端点序是纯函数，永远算得出来。
    ///
    /// 退化点（必须知道，不是 bug）：两端点完全相同时（例如 ICMP 自环、
    /// 同机同端口），`canonical()` 等于原键，两个方向本来也就是同一串字节。
    pub fn canonical(&self) -> Self {
        let a = (self.src_ip, self.src_port);
        let b = (self.dst_ip, self.dst_port);
        if a <= b {
            *self
        } else {
            self.reverse()
        }
    }

    /// 本键是否已是规范形式（`canonical()` 的不动点）。
    pub fn is_canonical(&self) -> bool {
        self.canonical() == *self
    }
}

/// 最小数据包：携带五元组与负载长度。高速场景将由零拷贝缓冲承载。
#[derive(Debug, Clone)]
pub struct Packet {
    pub key: FlowKey,
    pub payload_len: u32,
    pub timestamp_us: u64, // 到达时间（微秒，测试用单调时钟雏形）
}

impl Packet {
    pub fn new(key: FlowKey, payload_len: u32) -> Self {
        Self {
            key,
            payload_len,
            timestamp_us: 0,
        }
    }
}

/// 一条流：以 FlowKey 为主键，聚合属于它的包与统计。
#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FlowKey,
    pub packet_count: u64,
    pub total_bytes: u64,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    /// 扩展统计（CYS-TRF-014）：包长分布、IAT 环形缓冲。
    pub stats: FlowStats,
}

impl Flow {
    pub fn new(key: FlowKey) -> Self {
        Self {
            key,
            packet_count: 0,
            total_bytes: 0,
            first_seen_us: 0,
            last_seen_us: 0,
            stats: FlowStats::default(),
        }
    }

    /// 吞入一个包：更新包数与字节统计。
    pub fn observe(&mut self, pkt: &Packet) {
        // "首个包"的判据用 **包数**，不用 `first_seen_us == 0`。
        // 后者是历史缺陷：真实时间戳可以为 0（pcap 相对时间、内核单调钟起点），
        // 那样第一个包会把 first_seen 置 0，第二个包又因"first_seen == 0"把它改成
        // 自己的时间 —— 结果是首包时间被静默丢掉，而输出上完全看不出来。
        if self.packet_count == 0 {
            self.first_seen_us = pkt.timestamp_us;
        } else if pkt.timestamp_us < self.first_seen_us {
            self.first_seen_us = pkt.timestamp_us;
        }
        if pkt.timestamp_us > self.last_seen_us {
            self.last_seen_us = pkt.timestamp_us;
        }
        self.packet_count += 1;
        self.total_bytes += u64::from(pkt.payload_len);
        self.stats.observe(pkt.payload_len, pkt.timestamp_us);
    }

    /// 判断该流是否为空（尚未吞入任何包）。
    pub fn is_idle(&self) -> bool {
        self.packet_count == 0
    }

    /// 平均包长（整数微秒无关，这里按字节）。空流返回 0。
    pub fn mean_bytes(&self) -> u64 {
        self.stats.mean_payload_len()
    }

    /// 持续时间（微秒）。只有一个包时为 0。
    pub fn duration_us(&self) -> u64 {
        self.last_seen_us.saturating_sub(self.first_seen_us)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> FlowKey {
        FlowKey::new_ipv4([10, 0, 0, 1], 12345, [93, 184, 216, 34], 443, IPPROTO_TCP)
    }

    #[test]
    fn flow_key_equality() {
        let a = sample_key();
        let b = FlowKey::new_ipv4([10, 0, 0, 1], 12345, [93, 184, 216, 34], 443, IPPROTO_TCP);
        let c = FlowKey::new_ipv4([10, 0, 0, 1], 12345, [93, 184, 216, 34], 80, IPPROTO_TCP);
        assert_eq!(a, b);
        assert_ne!(a, c, "目的端口不同应视为不同流");
    }

    #[test]
    fn packet_carries_key() {
        let p = Packet::new(sample_key(), 1400);
        assert_eq!(p.payload_len, 1400);
        assert_eq!(p.key.dst_port, 443);
    }

    #[test]
    fn flow_observe_accumulates() {
        let mut f = Flow::new(sample_key());
        assert!(f.is_idle());

        f.observe(&Packet {
            key: sample_key(),
            payload_len: 100,
            timestamp_us: 1,
        });
        f.observe(&Packet {
            key: sample_key(),
            payload_len: 200,
            timestamp_us: 5,
        });

        assert_eq!(f.packet_count, 2);
        assert_eq!(f.total_bytes, 300);
        assert_eq!(f.first_seen_us, 1);
        assert_eq!(f.last_seen_us, 5);
        assert!(!f.is_idle());
    }

    #[test]
    fn first_seen_is_not_lost_when_timestamp_is_zero() {
        // 回归用例：timestamp_us = 0 是合法取值（pcap 相对时间），
        // 不得被当成"还没见过包"的哨兵。
        let mut f = Flow::new(sample_key());
        f.observe(&Packet {
            key: sample_key(),
            payload_len: 10,
            timestamp_us: 0,
        });
        f.observe(&Packet {
            key: sample_key(),
            payload_len: 10,
            timestamp_us: 50,
        });
        assert_eq!(f.first_seen_us, 0, "首包时间戳 0 必须被保留");
        assert_eq!(f.duration_us(), 50);
    }

    #[test]
    fn reverse_direction_is_distinct_flow() {
        // 反方向（客户端<-服务器）的五元组应视为另一条流 —— 流表按方向存，
        // 否则上下行统计会合并，特征里的"上下行比"永远是 1。
        let forward = sample_key();
        let backward =
            FlowKey::new_ipv4([93, 184, 216, 34], 443, [10, 0, 0, 1], 12345, IPPROTO_TCP);
        assert_ne!(forward, backward);
    }

    // ---- CYS-TRF-005 规范化五元组 ----

    #[test]
    fn canonical_maps_both_directions_to_one_key() {
        let forward = sample_key();
        let backward =
            FlowKey::new_ipv4([93, 184, 216, 34], 443, [10, 0, 0, 1], 12345, IPPROTO_TCP);
        assert_eq!(forward.canonical(), backward.canonical());
        assert_eq!(forward.canonical(), forward, "10.0.0.1 小于 93.184.216.34");
        assert!(forward.is_canonical());
        assert!(!backward.is_canonical());
    }

    #[test]
    fn canonical_is_an_involution_and_idempotent() {
        let k = FlowKey::new_ipv4([192, 168, 1, 1], 5555, [10, 0, 0, 1], 80, IPPROTO_TCP);
        assert_eq!(k.canonical().canonical(), k.canonical(), "幂等");
        assert_eq!(k.reverse().reverse(), k, "两次反向回到原键");
        assert_eq!(k.canonical(), k.reverse().canonical(), "与方向无关");
    }

    #[test]
    fn canonical_covers_all_three_address_families_and_protocols() {
        // 三种组合：v4/v4、v6/v6、以及与方向无关性的交叉检查。
        let v6a: IpAddr = "2001:db8::1".parse().expect("字面量合法");
        let v6b: IpAddr = "2001:db8::2".parse().expect("字面量合法");
        let k = FlowKey {
            src_ip: v6b,
            src_port: 5000,
            dst_ip: v6a,
            dst_port: 443,
            proto: Proto::Tcp,
        };
        let c = k.canonical();
        assert_eq!(c.src_ip, v6a, "v6 端点排序同样成立");
        assert_eq!(c.canonical(), c);
        assert_eq!(c.proto, Proto::Tcp, "规范化不得改变协议");

        // 端口参与比较：地址相同、端口不同时必须仍能区分方向。
        let same_addr_diff_port = FlowKey {
            src_ip: v6a,
            src_port: 5000,
            dst_ip: v6a,
            dst_port: 443,
            proto: Proto::Udp,
        };
        assert_eq!(
            same_addr_diff_port.canonical().src_port,
            443,
            "地址相同则由端口决定端点序"
        );
    }

    #[test]
    fn canonical_of_identical_endpoints_is_a_fixed_point() {
        // 退化点：两端点完全相同（ICMP 自环等）。两个方向本来就是同一串字节，
        // 规范形式等于原键是正确行为，而不是"没能规范化"。
        let k = FlowKey::new_ipv4([127, 0, 0, 1], 0, [127, 0, 0, 1], 0, IPPROTO_ICMP);
        assert_eq!(k.canonical(), k);
        assert_eq!(k.canonical(), k.reverse());
    }

    #[test]
    fn canonical_survives_exhaustive_port_direction_matrix() {
        // 属性型穷举（无第三方依赖，自己枚举）：对 0/1/65535 等边界端口组合，
        // 双向必须始终收敛到同一个键，且该键必是二者的不动点。
        let ports = [0u16, 1, 80, 1024, 65535];
        for &a in &ports {
            for &b in &ports {
                let f = FlowKey::new_ipv4([10, 0, 0, 1], a, [10, 0, 0, 2], b, IPPROTO_TCP);
                let r = f.reverse();
                assert_eq!(f.canonical(), r.canonical(), "端口 {a}/{b} 方向未收敛");
                assert_eq!(f.canonical().canonical(), f.canonical());
            }
        }
    }

    // ---- CYS-TRF-004 类型化协议 ----

    #[test]
    fn proto_roundtrips_through_iana_number() {
        for v in [0u8, 1, 6, 17, 47, 50, 58, 132, 255] {
            assert_eq!(Proto::from_u8(v).number(), v, "协议号往返应无损");
        }
    }

    #[test]
    fn proto_classifies_ports_and_connection_orientation() {
        assert!(Proto::Tcp.has_ports());
        assert!(Proto::Udp.has_ports());
        assert!(!Proto::Icmp.has_ports());
        assert!(!Proto::Icmpv6.has_ports());
        assert!(!Proto::Other(47).has_ports());
        assert!(Proto::Tcp.is_connection_oriented());
        assert!(!Proto::Udp.is_connection_oriented());
        assert_eq!(Proto::Icmpv6.as_str(), "icmpv6");
    }

    #[test]
    fn proto_display_is_the_iana_number_not_the_name() {
        // 这条 Display 被 e2e 脚本按 `proto=6` 抓取，改成 "tcp" 会静默破坏门禁。
        assert_eq!(Proto::Tcp.to_string(), "6");
        assert_eq!(Proto::Udp.to_string(), "17");
        assert_eq!(Proto::Other(132).to_string(), "132");
    }

    #[test]
    fn proto_is_part_of_the_flow_key() {
        let tcp = FlowKey::new_ipv4([10, 0, 0, 1], 53, [10, 0, 0, 2], 53, IPPROTO_TCP);
        let udp = FlowKey::new_ipv4([10, 0, 0, 1], 53, [10, 0, 0, 2], 53, IPPROTO_UDP);
        assert_ne!(tcp, udp, "同端口不同协议必须是两条流");
        assert_ne!(tcp.canonical(), udp.canonical());
    }
}
