// session/mod.rs - Session 最小模型
// 会话：将同一通信的双向流(forward/backward)聚合为一个逻辑连接，
// 以便后续做连接状态、超时、重组等分析。
use crate::flow::{Flow, FlowKey, Packet};

/// 会话阶段（TCP 雏形：SYN->ESTABLISHED->FIN）。非 TCP 直接 Established。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    SynSent,
    Established,
    Closing,
    Closed,
}

/// 一条双向会话：由两条方向的流构成。
#[derive(Debug, Clone)]
pub struct Session {
    pub id: u64,
    /// 会话主键采用"发起方方向"的五元组作为稳定标识。
    pub key: FlowKey,
    pub forward: Flow,   // 发起方 -> 响应方
    pub backward: Flow,  // 响应方 -> 发起方
    pub state: SessionState,
    /// 会话首包方向作为 forward 的判定依据（演示：这里假设 forward 先出现）。
    pub started_at_us: u64,
}

impl Session {
    pub fn new(id: u64, forward_key: FlowKey) -> Self {
        // 反向 key：交换源/目的。
        let backward_key = FlowKey {
            src_ip: forward_key.dst_ip,
            src_port: forward_key.dst_port,
            dst_ip: forward_key.src_ip,
            dst_port: forward_key.src_port,
            proto: forward_key.proto,
        };
        Self {
            id,
            key: forward_key,
            forward: Flow::new(forward_key),
            backward: Flow::new(backward_key),
            state: SessionState::SynSent,
            started_at_us: 0,
        }
    }

    /// 依据五元组匹配方向并把包计入对应方向的流。
    pub fn ingest(&mut self, pkt: &Packet) {
        if self.started_at_us == 0 {
            self.started_at_us = pkt.timestamp_us;
        }
        // forward.key 即会话 key；若五元组等于 forward -> forward，等于反向 -> backward。
        if pkt.key == self.forward.key {
            self.forward.observe(pkt);
        } else if pkt.key == self.backward.key {
            self.backward.observe(pkt);
        }
        // 一旦两端都开始出现，视为连接建立（最小启发式）。
        if !self.forward.is_idle() && !self.backward.is_idle() {
            self.state = SessionState::Established;
        }
    }

    pub fn total_packets(&self) -> u64 {
        self.forward.packet_count + self.backward.packet_count
    }

    pub fn total_bytes(&self) -> u64 {
        self.forward.total_bytes + self.backward.total_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowKey, Packet};

    fn keys() -> (FlowKey, FlowKey) {
        let f = FlowKey::new_ipv4([10, 0, 0, 1], 40000, [93, 184, 216, 34], 443, 6);
        let b = FlowKey {
            src_ip: f.dst_ip,
            src_port: f.dst_port,
            dst_ip: f.src_ip,
            dst_port: f.src_port,
            proto: f.proto,
        };
        (f, b)
    }

    fn pkt(key: FlowKey, len: u32, ts: u64) -> Packet {
        Packet {
            key,
            payload_len: len,
            timestamp_us: ts,
        }
    }

    #[test]
    fn session_initial_state() {
        let (f, _b) = keys();
        let s = Session::new(1, f);
        assert_eq!(s.state, SessionState::SynSent);
        assert_eq!(s.total_packets(), 0);
    }

    #[test]
    fn session_routes_forward_and_backward() {
        let (f, b) = keys();
        let mut s = Session::new(1, f);

        s.ingest(&pkt(f, 1200, 1)); // 请求
        s.ingest(&pkt(f, 800, 2));  // 第二个请求
        s.ingest(&pkt(b, 500, 3));  // 响应

        assert_eq!(s.forward.packet_count, 2);
        assert_eq!(s.backward.packet_count, 1);
        assert_eq!(s.total_packets(), 3);
        assert_eq!(s.total_bytes(), 2500);
        assert_eq!(s.state, SessionState::Established);
    }

    #[test]
    fn session_ignores_unrelated_flow() {
        let (f, _b) = keys();
        let mut s = Session::new(1, f);
        let other = FlowKey::new_ipv4([1, 1, 1, 1], 53, [8, 8, 8, 8], 53, 17);
        s.ingest(&pkt(other, 100, 0));
        assert_eq!(s.total_packets(), 0, "无关五元组的包应被忽略");
    }
}
