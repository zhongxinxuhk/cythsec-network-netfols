// flow/mod.rs - Packet 与 Flow 最小模型
// 数据链：Packet -> Flow -> Session
// 本阶段仅表达五元组流的核心概念，用于验证 traffic-engine 的 Rust 工具链，
// 不做高速收包、重组、DPI 等（后续在各自 crate 实现）。
use std::net::{IpAddr, Ipv4Addr};

/// 网络协议号（最小子集；真实实现将对照 IANA / IPPROTO_*）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

/// 最小五元组：源/目的地址与端口 + 协议，用于唯一标识一条流。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
}

impl FlowKey {
    /// 简易 IPv4 三元组构造（测试与演示常用）。
    pub fn new_ipv4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, proto: u8) -> Self {
        Self {
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
            src_port: sport,
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
            dst_port: dport,
            proto,
        }
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
}

impl Flow {
    pub fn new(key: FlowKey) -> Self {
        Self {
            key,
            packet_count: 0,
            total_bytes: 0,
            first_seen_us: 0,
            last_seen_us: 0,
        }
    }

    /// 吞入一个包：更新包数与字节统计。
    pub fn observe(&mut self, pkt: &Packet) {
        self.packet_count += 1;
        self.total_bytes += u64::from(pkt.payload_len);
        if self.first_seen_us == 0 || pkt.timestamp_us < self.first_seen_us {
            self.first_seen_us = pkt.timestamp_us;
        }
        if pkt.timestamp_us > self.last_seen_us {
            self.last_seen_us = pkt.timestamp_us;
        }
    }

    /// 判断该流是否为空（尚未吞入任何包）。
    pub fn is_idle(&self) -> bool {
        self.packet_count == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> FlowKey {
        FlowKey::new_ipv4([10, 0, 0, 1], 12345, [93, 184, 216, 34], 443, 6)
    }

    #[test]
    fn flow_key_equality() {
        let a = sample_key();
        let b = FlowKey::new_ipv4([10, 0, 0, 1], 12345, [93, 184, 216, 34], 443, 6);
        let c = FlowKey::new_ipv4([10, 0, 0, 1], 12345, [93, 184, 216, 34], 80, 6);
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
    fn reverse_direction_is_distinct_flow() {
        // 反方向（客户端<-服务器）的五元组应视为另一条流
        let forward = sample_key();
        let backward = FlowKey::new_ipv4([93, 184, 216, 34], 443, [10, 0, 0, 1], 12345, 6);
        assert_ne!(forward, backward);
    }
}
