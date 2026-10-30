//! sFlow v5（RFC 3176 / sFlow.org v5）采集侧：flow/counter sample 与**数据报**级丢包。
//!
//! ## 为什么单独一个模块
//!
//! sFlow 与 NetFlow v9/IPFIX 都是"网元把采样结果发出来"，但线格式和语义完全不同：
//! sFlow 是**自描述 TLV**（sample type + length，record type + length），没有模板；
//! 序号是**数据报序号**，不是记录数，也不是 v9 的导出报文序号。把它塞进 IPFIX/v9
//! 的模板状态机里，只会得到"能跑但口径错"的第二套实现。故这里从 XDR 读取器开始独立写。
//!
//! ## 本版实际覆盖
//!
//! - 数据报头：version 5、IPv4/IPv6 agent address、sub-agent、sequence、uptime、num_samples。
//! - sample：flow sample（1）、counter sample（2）、expanded flow sample（3）、
//!   expanded counter sample（4）；其他 enterprise/format 显式跳过并计数。
//! - flow record：raw packet header（1，Ethernet/IPv4/IPv6）、Ethernet frame（2）、
//!   IPv4 data（3）、IPv6 data（4）、extended switch（1001）。
//! - counter record：generic interface（1）、Ethernet interface（2）、VLAN（5）。
//!
//! ## 刻意不做
//!
//! - 不把 sFlow 采样记录**还原成全网总量**：一条 flow sample 只代表一个被采到的包，
//!   采样率单独输出；拿 `packets=1` 去乘采样率是估计，不是观测，不能冒充统计值。
//! - 不解 MPLS/AS/URL/NAT/socket/host 等扩展记录：未知类型按长度跳过并登记，
//!   不猜字段布局。
//! - 不做 sFlow over TCP/SCTP：本仓采集入口只有 UDP/pcap。
//! - 不把 counter sample 硬塞进 `FlowRecord`：接口计数没有五元组，单独输出。

use crate::flow::FlowKey;
use crate::ipfix::collector::ExporterId;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// sFlow v5 版本号。
pub const SFLOW_VERSION: u32 = 5;
/// IANA 为 sFlow 登记的 UDP 端口。
pub const SFLOW_PORT: u16 = 6343;
/// IPv4 agent 的数据报头长度：version/agent_type/agent/sub_agent/sequence/uptime/num_samples。
pub const DATAGRAM_HEADER_LEN_V4: usize = 28;
/// IPv6 agent 的数据报头长度。
pub const DATAGRAM_HEADER_LEN_V6: usize = 40;
/// sample 头：sample_type + sample_length。
pub const SAMPLE_HEADER_LEN: usize = 8;
/// record 头：record_type + record_length。
pub const RECORD_HEADER_LEN: usize = 8;
/// flow sample 固定部分长度。
pub const FLOW_SAMPLE_LEN: usize = 32;
/// expanded flow sample 固定部分长度。
pub const EXPANDED_FLOW_SAMPLE_LEN: usize = 44;
/// counter sample 固定部分长度。
pub const COUNTER_SAMPLE_LEN: usize = 12;
/// expanded counter sample 固定部分长度。
pub const EXPANDED_COUNTER_SAMPLE_LEN: usize = 16;
/// 单个数据报最多接受的 sample 数（防御性上限）。
pub const DEFAULT_MAX_SAMPLES_PER_DATAGRAM: usize = 4096;
/// 单个 sample 最多接受的 record 数（防御性上限）。
pub const DEFAULT_MAX_RECORDS_PER_SAMPLE: usize = 4096;
/// 去重窗口（sample 条数）。
pub const DEFAULT_DEDUP_WINDOW: usize = 4096;

const FLOW_SAMPLE: u32 = 1;
const COUNTER_SAMPLE: u32 = 2;
const EXPANDED_FLOW_SAMPLE: u32 = 3;
const EXPANDED_COUNTER_SAMPLE: u32 = 4;

const RAW_PACKET_HEADER: u32 = 1;
const ETHERNET_FRAME_DATA: u32 = 2;
const IPV4_DATA: u32 = 3;
const IPV6_DATA: u32 = 4;
const EXTENDED_SWITCH_DATA: u32 = 1001;

const GENERIC_INTERFACE_COUNTERS: u32 = 1;
const ETHERNET_INTERFACE_COUNTERS: u32 = 2;
const VLAN_COUNTERS: u32 = 5;

const HEADER_PROTOCOL_ETHERNET: u32 = 1;
const HEADER_PROTOCOL_IPV4: u32 = 11;
const HEADER_PROTOCOL_IPV6: u32 = 12;

/// 采集器配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SflowConfig {
    pub max_samples_per_datagram: usize,
    pub max_records_per_sample: usize,
    /// 0 = 不去重。
    pub dedup_window: usize,
}

impl Default for SflowConfig {
    fn default() -> Self {
        Self {
            max_samples_per_datagram: DEFAULT_MAX_SAMPLES_PER_DATAGRAM,
            max_records_per_sample: DEFAULT_MAX_RECORDS_PER_SAMPLE,
            dedup_window: DEFAULT_DEDUP_WINDOW,
        }
    }
}

/// 采集统计。每个字段都能从 CLI 打出来；算得出但看不见的指标等于没有。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SflowStats {
    pub datagrams: u64,
    pub bytes: u64,
    pub version_mismatch: u64,
    pub malformed_datagrams: u64,
    /// 见过的 (agent, sub_agent_id) 组合数。
    pub agents: u64,
    /// 通过版本/头检查、参与序号记账的 v5 数据报数。
    pub sequence_tracked: u64,
    pub sequence_gaps: u64,
    /// 缺口合计丢失的**数据报**数。
    pub datagrams_lost: u64,
    pub duplicate_datagrams: u64,
    /// 序号倒退/乱序/agent 重启：不算丢包。
    pub out_of_order: u64,
    /// 所有 sample（含未知类型、重复、畸形）。
    pub samples: u64,
    pub flow_samples: u64,
    pub counter_samples: u64,
    /// expanded 子集，不重复计入 `flow_samples`/`counter_samples`。
    pub expanded_flow_samples: u64,
    pub expanded_counter_samples: u64,
    pub unknown_sample_types: u64,
    /// 已识别的 flow/counter record 数（不含未知类型）。
    pub flow_records: u64,
    pub counter_records: u64,
    pub raw_header_records: u64,
    pub ethernet_records: u64,
    pub ipv4_records: u64,
    pub ipv6_records: u64,
    pub extended_switch_records: u64,
    pub generic_interface_counters: u64,
    pub ethernet_counters: u64,
    pub vlan_counters: u64,
    /// 真正交付的 flow/counter 记录数。
    pub delivered_flows: u64,
    pub delivered_counters: u64,
    /// 窗口内重复的 sample 数（整段跳过）。
    pub duplicate_samples: u64,
    /// flow sample 里的 record 都解不出五元组。
    pub flow_records_missing_key: u64,
    /// 同一 flow sample 内多个 record 给出不同五元组（保留首个）。
    pub flow_record_conflicts: u64,
    pub unknown_flow_record_types: BTreeSet<u32>,
    pub unknown_counter_record_types: BTreeSet<u32>,
    /// sample/record 尾部填充非零。
    pub nonzero_padding: u64,
    /// record/sample 固定头或长度越界（尽量跳过剩余部分，不伪造记录）。
    pub record_truncations: u64,
    /// sample 固定部分不足或 record 数超上限。
    pub malformed_samples: u64,
    /// 数据报尾部未被 sample 覆盖的字节（只允许全零）。
    pub trailing_bytes: u64,
}

impl SflowStats {
    /// 数据报丢包率（ppm）。分母 = 实收 v5 数据报 + 推定丢失数据报。
    pub fn loss_ppm(&self) -> u64 {
        let denom = self.sequence_tracked + self.datagrams_lost;
        if denom == 0 {
            return 0;
        }
        self.datagrams_lost.saturating_mul(1_000_000) / denom
    }

    /// 是否解出过至少一条可交付记录。
    pub fn delivered_records(&self) -> u64 {
        self.delivered_flows + self.delivered_counters
    }
}

/// 通配的接口来源标识（source_id 的高 8 位类型 + 低 24 位索引）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceId {
    pub id_type: u32,
    pub index: u32,
}

/// 一条 sFlow flow sample（采样包），不是还原后的总量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SflowFlow {
    /// UDP 源（谁把数据报发给采集器）。
    pub exporter: ExporterId,
    /// 数据报头里的 agent address。
    pub agent: IpAddr,
    pub sub_agent_id: u32,
    pub datagram_sequence: u32,
    pub sample_sequence: u32,
    pub source_id: SourceId,
    pub sampling_rate: u32,
    pub sample_pool: u32,
    pub drops: u32,
    pub input_format: u32,
    pub input_value: u32,
    pub output_format: u32,
    pub output_value: u32,
    pub key: FlowKey,
    /// record 给出的长度：raw header/Ethernet 是帧长，IPv4/IPv6 data 是 IP 包长。
    pub frame_length: u64,
    pub header_length: u32,
    pub tcp_flags: Option<u8>,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub ether_type: Option<u16>,
    pub src_vlan: Option<u32>,
    pub dst_vlan: Option<u32>,
    pub src_priority: Option<u32>,
    pub dst_priority: Option<u32>,
    pub timestamp_ms: u64,
}

impl SflowFlow {
    /// 一行 JSON。字段名固定，供采集器/验证脚本消费。
    pub fn to_json_line(&self) -> String {
        let mut s = String::with_capacity(512);
        write!(
            s,
            "{{\"type\":\"flow\",\"agent\":\"{}\",\"exporter\":\"{}\",\"sub_agent_id\":{},\
             \"datagram_sequence\":{},\"sample_sequence\":{},\"source_id_type\":{},\
             \"source_id_index\":{},\"sampling_rate\":{},\"sample_pool\":{},\"drops\":{},\
             \"input_format\":{},\"input\":{},\"output_format\":{},\"output\":{},\
             \"timestamp_ms\":{},\"frame_length\":{},\"header_length\":{},\"tcp_flags\":{},\
             \"src_mac\":{},\"dst_mac\":{},\"ether_type\":{},\
             \"src_vlan\":{},\"dst_vlan\":{},\"src_priority\":{},\"dst_priority\":{},\
             \"flow\":{{\"src_ip\":\"{}\",\"src_port\":{},\"dst_ip\":\"{}\",\"dst_port\":{},\
             \"proto\":{},\"proto_name\":\"{}\"}}}}",
            self.agent,
            self.exporter,
            self.sub_agent_id,
            self.datagram_sequence,
            self.sample_sequence,
            self.source_id.id_type,
            self.source_id.index,
            self.sampling_rate,
            self.sample_pool,
            self.drops,
            self.input_format,
            self.input_value,
            self.output_format,
            self.output_value,
            self.timestamp_ms,
            self.frame_length,
            self.header_length,
            json_opt_u64(self.tcp_flags.map(u64::from)),
            json_opt_mac(self.src_mac),
            json_opt_mac(self.dst_mac),
            json_opt_u64(self.ether_type.map(u64::from)),
            json_opt_u64(self.src_vlan.map(u64::from)),
            json_opt_u64(self.dst_vlan.map(u64::from)),
            json_opt_u64(self.src_priority.map(u64::from)),
            json_opt_u64(self.dst_priority.map(u64::from)),
            self.key.src_ip,
            self.key.src_port,
            self.key.dst_ip,
            self.key.dst_port,
            self.key.proto.number(),
            self.key.proto.as_str(),
        )
        .expect("write to String cannot fail");
        s
    }
}

/// 通用接口计数器（sFlow counter record format 1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GenericInterfaceCounters {
    pub if_index: u32,
    pub if_type: u32,
    pub if_speed: u64,
    pub if_direction: u32,
    pub if_status: u32,
    pub in_octets: u64,
    pub in_ucast_pkts: u32,
    pub in_multicast_pkts: u32,
    pub in_broadcast_pkts: u32,
    pub in_discards: u32,
    pub in_errors: u32,
    pub in_unknown_protos: u32,
    pub out_octets: u64,
    pub out_ucast_pkts: u32,
    pub out_multicast_pkts: u32,
    pub out_broadcast_pkts: u32,
    pub out_discards: u32,
    pub out_errors: u32,
    pub promiscuous_mode: u32,
}

/// 以太网接口计数器（format 2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EthernetCounters {
    pub alignment_errors: u32,
    pub fcs_errors: u32,
    pub single_collision_frames: u32,
    pub multiple_collision_frames: u32,
    pub sqe_test_errors: u32,
    pub deferred_transmissions: u32,
    pub late_collisions: u32,
    pub excessive_collisions: u32,
    pub internal_mac_transmit_errors: u32,
    pub carrier_sense_errors: u32,
    pub frame_too_longs: u32,
    pub internal_mac_receive_errors: u32,
    pub symbol_errors: u32,
}

/// VLAN 计数器（format 5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VlanCounters {
    pub vlan_id: u32,
    pub octets: u64,
    pub ucast_pkts: u32,
    pub multicast_pkts: u32,
    pub broadcast_pkts: u32,
    pub discards: u32,
}

/// counter record 的具体载荷。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SflowCounterData {
    GenericInterface(GenericInterfaceCounters),
    Ethernet(EthernetCounters),
    Vlan(VlanCounters),
}

/// 一条 sFlow counter sample 里的一个计数器 record。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SflowCounter {
    pub exporter: ExporterId,
    pub agent: IpAddr,
    pub sub_agent_id: u32,
    pub datagram_sequence: u32,
    pub sample_sequence: u32,
    pub source_id: SourceId,
    /// 记录类型：1/2/5。
    pub format: u32,
    pub data: SflowCounterData,
    pub timestamp_ms: u64,
}

impl SflowCounter {
    pub fn to_json_line(&self) -> String {
        let mut s = String::with_capacity(512);
        write!(
            s,
            "{{\"type\":\"counter\",\"agent\":\"{}\",\"exporter\":\"{}\",\"sub_agent_id\":{},\
             \"datagram_sequence\":{},\"sample_sequence\":{},\"source_id_type\":{},\
             \"source_id_index\":{},\"record_format\":{},\"timestamp_ms\":{}",
            self.agent,
            self.exporter,
            self.sub_agent_id,
            self.datagram_sequence,
            self.sample_sequence,
            self.source_id.id_type,
            self.source_id.index,
            self.format,
            self.timestamp_ms,
        )
        .expect("write to String cannot fail");
        match self.data {
            SflowCounterData::GenericInterface(c) => {
                write!(
                    s,
                    ",\"record\":\"generic_interface\",\"if_index\":{},\"if_type\":{},\
                     \"if_speed\":{},\"if_direction\":{},\"if_status\":{},\"in_octets\":{},\
                     \"in_ucast_pkts\":{},\"in_multicast_pkts\":{},\"in_broadcast_pkts\":{},\
                     \"in_discards\":{},\"in_errors\":{},\"in_unknown_protos\":{},\
                     \"out_octets\":{},\"out_ucast_pkts\":{},\"out_multicast_pkts\":{},\
                     \"out_broadcast_pkts\":{},\"out_discards\":{},\"out_errors\":{},\
                     \"promiscuous_mode\":{}}}",
                    c.if_index,
                    c.if_type,
                    c.if_speed,
                    c.if_direction,
                    c.if_status,
                    c.in_octets,
                    c.in_ucast_pkts,
                    c.in_multicast_pkts,
                    c.in_broadcast_pkts,
                    c.in_discards,
                    c.in_errors,
                    c.in_unknown_protos,
                    c.out_octets,
                    c.out_ucast_pkts,
                    c.out_multicast_pkts,
                    c.out_broadcast_pkts,
                    c.out_discards,
                    c.out_errors,
                    c.promiscuous_mode,
                )
                .expect("write to String cannot fail");
            }
            SflowCounterData::Ethernet(c) => {
                write!(
                    s,
                    ",\"record\":\"ethernet\",\"alignment_errors\":{},\"fcs_errors\":{},\
                     \"single_collision_frames\":{},\"multiple_collision_frames\":{},\
                     \"sqe_test_errors\":{},\"deferred_transmissions\":{},\"late_collisions\":{},\
                     \"excessive_collisions\":{},\"internal_mac_transmit_errors\":{},\
                     \"carrier_sense_errors\":{},\"frame_too_longs\":{},\
                     \"internal_mac_receive_errors\":{},\"symbol_errors\":{}}}",
                    c.alignment_errors,
                    c.fcs_errors,
                    c.single_collision_frames,
                    c.multiple_collision_frames,
                    c.sqe_test_errors,
                    c.deferred_transmissions,
                    c.late_collisions,
                    c.excessive_collisions,
                    c.internal_mac_transmit_errors,
                    c.carrier_sense_errors,
                    c.frame_too_longs,
                    c.internal_mac_receive_errors,
                    c.symbol_errors,
                )
                .expect("write to String cannot fail");
            }
            SflowCounterData::Vlan(c) => {
                write!(
                    s,
                    ",\"record\":\"vlan\",\"vlan_id\":{},\"octets\":{},\"ucast_pkts\":{},\
                     \"multicast_pkts\":{},\"broadcast_pkts\":{},\"discards\":{}}}",
                    c.vlan_id,
                    c.octets,
                    c.ucast_pkts,
                    c.multicast_pkts,
                    c.broadcast_pkts,
                    c.discards,
                )
                .expect("write to String cannot fail");
            }
        }
        s
    }
}

fn json_opt_u64(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

fn json_opt_mac(v: Option<[u8; 6]>) -> String {
    match v {
        Some(m) => format!(
            "\"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\"",
            m[0], m[1], m[2], m[3], m[4], m[5]
        ),
        None => "null".to_string(),
    }
}

/// 数据报处理结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SflowOutcome {
    Accepted {
        flows: usize,
        counters: usize,
        lost_datagrams: u32,
    },
    VersionMismatch {
        got: u32,
    },
    Malformed,
}

#[derive(Debug)]
struct AgentState {
    next_expected: Option<u32>,
    last_sequence: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DedupKey {
    agent: IpAddr,
    sub_agent_id: u32,
    datagram_sequence: u32,
    sample_sequence: u32,
    sample_format: u32,
}

/// sFlow v5 采集器。
#[derive(Debug)]
pub struct SflowCollector {
    cfg: SflowConfig,
    agents: HashMap<(IpAddr, u32), AgentState>,
    stats: SflowStats,
    flows: Vec<SflowFlow>,
    counters: Vec<SflowCounter>,
    dedup_seen: HashSet<DedupKey>,
    dedup_order: VecDeque<DedupKey>,
}

impl SflowCollector {
    pub fn new(cfg: SflowConfig) -> Self {
        Self {
            cfg,
            agents: HashMap::new(),
            stats: SflowStats::default(),
            flows: Vec::new(),
            counters: Vec::new(),
            dedup_seen: HashSet::new(),
            dedup_order: VecDeque::new(),
        }
    }

    pub fn stats(&self) -> &SflowStats {
        &self.stats
    }

    pub fn take_flows(&mut self) -> Vec<SflowFlow> {
        std::mem::take(&mut self.flows)
    }

    pub fn take_counters(&mut self) -> Vec<SflowCounter> {
        std::mem::take(&mut self.counters)
    }

    pub fn pending_flows(&self) -> usize {
        self.flows.len()
    }

    pub fn pending_counters(&self) -> usize {
        self.counters.len()
    }

    /// 处理一个 UDP 载荷。`now_ms` 由调用方提供（pcap 重放取抓包时间戳）。
    pub fn on_datagram(&mut self, exporter: ExporterId, bytes: &[u8], now_ms: u64) -> SflowOutcome {
        self.stats.datagrams += 1;
        self.stats.bytes += bytes.len() as u64;

        if bytes.len() < 8 {
            self.stats.malformed_datagrams += 1;
            return SflowOutcome::Malformed;
        }
        let version = be32(&bytes[0..4]);
        if version != SFLOW_VERSION {
            self.stats.version_mismatch += 1;
            return SflowOutcome::VersionMismatch { got: version };
        }
        let agent_type = be32(&bytes[4..8]);
        let (agent, alen) = match agent_type {
            1 => {
                if bytes.len() < DATAGRAM_HEADER_LEN_V4 {
                    self.stats.malformed_datagrams += 1;
                    return SflowOutcome::Malformed;
                }
                let mut a = [0u8; 4];
                a.copy_from_slice(&bytes[8..12]);
                (IpAddr::V4(Ipv4Addr::from(a)), 4usize)
            }
            2 => {
                if bytes.len() < DATAGRAM_HEADER_LEN_V6 {
                    self.stats.malformed_datagrams += 1;
                    return SflowOutcome::Malformed;
                }
                let mut a = [0u8; 16];
                a.copy_from_slice(&bytes[8..24]);
                (IpAddr::V6(Ipv6Addr::from(a)), 16usize)
            }
            _ => {
                self.stats.malformed_datagrams += 1;
                return SflowOutcome::Malformed;
            }
        };
        let header_len = 24 + alen;
        if bytes.len() < header_len {
            self.stats.malformed_datagrams += 1;
            return SflowOutcome::Malformed;
        }
        let sub_agent_id = be32(&bytes[8 + alen..12 + alen]);
        let sequence = be32(&bytes[12 + alen..16 + alen]);
        let _uptime = be32(&bytes[16 + alen..20 + alen]);
        let num_samples = be32(&bytes[20 + alen..24 + alen]) as usize;
        if num_samples > self.cfg.max_samples_per_datagram {
            self.stats.malformed_datagrams += 1;
            return SflowOutcome::Malformed;
        }

        let seq_agent = if agent.is_unspecified() {
            exporter.ip
        } else {
            agent
        };
        self.stats.sequence_tracked += 1;
        self.agents
            .entry((seq_agent, sub_agent_id))
            .or_insert(AgentState {
                next_expected: None,
                last_sequence: None,
            });
        self.stats.agents = self.agents.len() as u64;
        let lost = self.account_sequence(seq_agent, sub_agent_id, sequence);

        let mut off = header_len;
        let mut flows = 0usize;
        let mut counters = 0usize;
        for _ in 0..num_samples {
            if off + SAMPLE_HEADER_LEN > bytes.len() {
                self.stats.malformed_datagrams += 1;
                return SflowOutcome::Malformed;
            }
            let sample_type = be32(&bytes[off..off + 4]);
            let sample_len = be32(&bytes[off + 4..off + 8]) as usize;
            off += SAMPLE_HEADER_LEN;
            if sample_len > bytes.len().saturating_sub(off) {
                self.stats.malformed_datagrams += 1;
                return SflowOutcome::Malformed;
            }
            let body = &bytes[off..off + sample_len];
            self.stats.samples += 1;
            let (f, c) = self.parse_sample(
                exporter,
                seq_agent,
                sub_agent_id,
                sequence,
                sample_type,
                body,
                now_ms,
            );
            flows += f;
            counters += c;
            off += sample_len;
            if off % 4 != 0 {
                let aligned = (off + 3) & !3;
                if aligned > bytes.len() {
                    self.stats.malformed_datagrams += 1;
                    return SflowOutcome::Malformed;
                }
                if bytes[off..aligned].iter().any(|b| *b != 0) {
                    self.stats.nonzero_padding += 1;
                }
                off = aligned;
            }
        }
        if off < bytes.len() {
            if bytes[off..].iter().all(|b| *b == 0) {
                self.stats.trailing_bytes += (bytes.len() - off) as u64;
            } else {
                self.stats.malformed_datagrams += 1;
                return SflowOutcome::Malformed;
            }
        }
        SflowOutcome::Accepted {
            flows,
            counters,
            lost_datagrams: lost,
        }
    }

    /// sFlow 数据报序号是**数据报**序号；`delta - 1` 才是丢失的数据报数。
    fn account_sequence(&mut self, agent: IpAddr, sub_agent_id: u32, sequence: u32) -> u32 {
        let Some(st) = self.agents.get_mut(&(agent, sub_agent_id)) else {
            return 0;
        };
        if let Some(last) = st.last_sequence {
            if last == sequence {
                self.stats.duplicate_datagrams += 1;
                return 0;
            }
        }
        if let Some(expected) = st.next_expected {
            let delta = sequence.wrapping_sub(expected);
            if delta == 0 {
                // 正常的下一个数据报。
            } else if delta < (1u32 << 31) {
                self.stats.sequence_gaps += 1;
                self.stats.datagrams_lost += u64::from(delta);
            } else {
                self.stats.out_of_order += 1;
                return 0;
            }
        }
        st.last_sequence = Some(sequence);
        st.next_expected = Some(sequence.wrapping_add(1));
        0
    }

    fn parse_sample(
        &mut self,
        exporter: ExporterId,
        agent: IpAddr,
        sub_agent_id: u32,
        datagram_sequence: u32,
        sample_type: u32,
        body: &[u8],
        now_ms: u64,
    ) -> (usize, usize) {
        let enterprise = sample_type >> 12;
        let format = sample_type & 0x0fff;
        if enterprise != 0 {
            self.stats.unknown_sample_types += 1;
            return (0, 0);
        }
        let expanded = match format {
            FLOW_SAMPLE => false,
            EXPANDED_FLOW_SAMPLE => true,
            COUNTER_SAMPLE | EXPANDED_COUNTER_SAMPLE => false,
            _ => {
                self.stats.unknown_sample_types += 1;
                return (0, 0);
            }
        };
        let fixed = match format {
            FLOW_SAMPLE => FLOW_SAMPLE_LEN,
            EXPANDED_FLOW_SAMPLE => EXPANDED_FLOW_SAMPLE_LEN,
            COUNTER_SAMPLE => COUNTER_SAMPLE_LEN,
            EXPANDED_COUNTER_SAMPLE => EXPANDED_COUNTER_SAMPLE_LEN,
            _ => 0,
        };
        if body.len() < fixed.max(4) {
            self.stats.malformed_samples += 1;
            return (0, 0);
        }
        let sample_sequence = be32(&body[0..4]);
        if self.is_duplicate(
            agent,
            sub_agent_id,
            datagram_sequence,
            sample_sequence,
            format,
        ) {
            self.stats.duplicate_samples += 1;
            return (0, 0);
        }
        match format {
            FLOW_SAMPLE | EXPANDED_FLOW_SAMPLE => {
                self.stats.flow_samples += 1;
                if expanded {
                    self.stats.expanded_flow_samples += 1;
                }
                self.parse_flow_sample(
                    exporter,
                    agent,
                    sub_agent_id,
                    datagram_sequence,
                    sample_sequence,
                    expanded,
                    body,
                    now_ms,
                )
            }
            COUNTER_SAMPLE | EXPANDED_COUNTER_SAMPLE => {
                self.stats.counter_samples += 1;
                if format == EXPANDED_COUNTER_SAMPLE {
                    self.stats.expanded_counter_samples += 1;
                }
                self.parse_counter_sample(
                    exporter,
                    agent,
                    sub_agent_id,
                    datagram_sequence,
                    sample_sequence,
                    format == EXPANDED_COUNTER_SAMPLE,
                    body,
                    now_ms,
                )
            }
            _ => (0, 0),
        }
    }

    fn is_duplicate(
        &mut self,
        agent: IpAddr,
        sub_agent_id: u32,
        datagram_sequence: u32,
        sample_sequence: u32,
        sample_format: u32,
    ) -> bool {
        if self.cfg.dedup_window == 0 {
            return false;
        }
        let key = DedupKey {
            agent,
            sub_agent_id,
            datagram_sequence,
            sample_sequence,
            sample_format,
        };
        if self.dedup_seen.contains(&key) {
            return true;
        }
        self.dedup_seen.insert(key);
        self.dedup_order.push_back(key);
        while self.dedup_order.len() > self.cfg.dedup_window {
            if let Some(old) = self.dedup_order.pop_front() {
                self.dedup_seen.remove(&old);
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_flow_sample(
        &mut self,
        exporter: ExporterId,
        agent: IpAddr,
        sub_agent_id: u32,
        datagram_sequence: u32,
        sample_sequence: u32,
        expanded: bool,
        body: &[u8],
        now_ms: u64,
    ) -> (usize, usize) {
        let fixed = if expanded {
            EXPANDED_FLOW_SAMPLE_LEN
        } else {
            FLOW_SAMPLE_LEN
        };
        if body.len() < fixed {
            self.stats.malformed_samples += 1;
            return (0, 0);
        }
        let (
            source_id,
            sampling_rate,
            sample_pool,
            drops,
            input_format,
            input_value,
            output_format,
            output_value,
            nrec,
        ) = if expanded {
            (
                SourceId {
                    id_type: be32(&body[4..8]),
                    index: be32(&body[8..12]),
                },
                be32(&body[12..16]),
                be32(&body[16..20]),
                be32(&body[20..24]),
                be32(&body[24..28]),
                be32(&body[28..32]),
                be32(&body[32..36]),
                be32(&body[36..40]),
                be32(&body[40..44]) as usize,
            )
        } else {
            let src = be32(&body[4..8]);
            let input = be32(&body[20..24]);
            let output = be32(&body[24..28]);
            (
                SourceId {
                    id_type: src >> 24,
                    index: src & 0x00ff_ffff,
                },
                be32(&body[8..12]),
                be32(&body[12..16]),
                be32(&body[16..20]),
                input >> 30,
                input & 0x3fff_ffff,
                output >> 30,
                output & 0x3fff_ffff,
                be32(&body[28..32]) as usize,
            )
        };
        if nrec > self.cfg.max_records_per_sample {
            self.stats.malformed_samples += 1;
            return (0, 0);
        }

        let mut acc = FlowAccum::default();
        let mut off = fixed;
        for _ in 0..nrec {
            if off + RECORD_HEADER_LEN > body.len() {
                self.stats.record_truncations += 1;
                self.stats.malformed_samples += 1;
                break;
            }
            let rtype = be32(&body[off..off + 4]);
            let rlen = be32(&body[off + 4..off + 8]) as usize;
            off += RECORD_HEADER_LEN;
            if rlen > body.len().saturating_sub(off) {
                self.stats.record_truncations += 1;
                self.stats.malformed_samples += 1;
                break;
            }
            let rb = &body[off..off + rlen];
            let enterprise = rtype >> 12;
            let format = rtype & 0x0fff;
            if enterprise != 0 {
                self.stats.unknown_flow_record_types.insert(rtype);
            } else {
                match format {
                    RAW_PACKET_HEADER => {
                        self.stats.raw_header_records += 1;
                        self.stats.flow_records += 1;
                        self.parse_raw_header(rb, &mut acc);
                    }
                    ETHERNET_FRAME_DATA => {
                        self.stats.ethernet_records += 1;
                        self.stats.flow_records += 1;
                        self.parse_ethernet_record(rb, &mut acc);
                    }
                    IPV4_DATA => {
                        self.stats.ipv4_records += 1;
                        self.stats.flow_records += 1;
                        self.parse_ipv4_record(rb, &mut acc);
                    }
                    IPV6_DATA => {
                        self.stats.ipv6_records += 1;
                        self.stats.flow_records += 1;
                        self.parse_ipv6_record(rb, &mut acc);
                    }
                    EXTENDED_SWITCH_DATA => {
                        self.stats.extended_switch_records += 1;
                        self.stats.flow_records += 1;
                        self.parse_extended_switch(rb, &mut acc);
                    }
                    _ => {
                        self.stats.unknown_flow_record_types.insert(rtype);
                    }
                }
            }
            off += rlen;
            if off % 4 != 0 {
                let aligned = (off + 3) & !3;
                if aligned > body.len() {
                    self.stats.record_truncations += 1;
                    self.stats.malformed_samples += 1;
                    break;
                }
                if body[off..aligned].iter().any(|b| *b != 0) {
                    self.stats.nonzero_padding += 1;
                }
                off = aligned;
            }
        }

        let Some(key) = acc.key else {
            self.stats.flow_records_missing_key += 1;
            return (0, 0);
        };
        let flow = SflowFlow {
            exporter,
            agent,
            sub_agent_id,
            datagram_sequence,
            sample_sequence,
            source_id,
            sampling_rate,
            sample_pool,
            drops,
            input_format,
            input_value,
            output_format,
            output_value,
            key,
            frame_length: acc.frame_length.unwrap_or(0),
            header_length: acc.header_length.unwrap_or(0),
            tcp_flags: acc.tcp_flags,
            src_mac: acc.src_mac,
            dst_mac: acc.dst_mac,
            ether_type: acc.ether_type,
            src_vlan: acc.src_vlan,
            dst_vlan: acc.dst_vlan,
            src_priority: acc.src_priority,
            dst_priority: acc.dst_priority,
            timestamp_ms: now_ms,
        };
        self.stats.delivered_flows += 1;
        self.flows.push(flow);
        (1, 0)
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_counter_sample(
        &mut self,
        exporter: ExporterId,
        agent: IpAddr,
        sub_agent_id: u32,
        datagram_sequence: u32,
        sample_sequence: u32,
        expanded: bool,
        body: &[u8],
        now_ms: u64,
    ) -> (usize, usize) {
        let fixed = if expanded {
            EXPANDED_COUNTER_SAMPLE_LEN
        } else {
            COUNTER_SAMPLE_LEN
        };
        if body.len() < fixed {
            self.stats.malformed_samples += 1;
            return (0, 0);
        }
        let (source_id, nrec) = if expanded {
            (
                SourceId {
                    id_type: be32(&body[4..8]),
                    index: be32(&body[8..12]),
                },
                be32(&body[12..16]) as usize,
            )
        } else {
            let src = be32(&body[4..8]);
            (
                SourceId {
                    id_type: src >> 24,
                    index: src & 0x00ff_ffff,
                },
                be32(&body[8..12]) as usize,
            )
        };
        if nrec > self.cfg.max_records_per_sample {
            self.stats.malformed_samples += 1;
            return (0, 0);
        }
        let mut delivered = 0usize;
        let mut off = fixed;
        for _ in 0..nrec {
            if off + RECORD_HEADER_LEN > body.len() {
                self.stats.record_truncations += 1;
                self.stats.malformed_samples += 1;
                break;
            }
            let rtype = be32(&body[off..off + 4]);
            let rlen = be32(&body[off + 4..off + 8]) as usize;
            off += RECORD_HEADER_LEN;
            if rlen > body.len().saturating_sub(off) {
                self.stats.record_truncations += 1;
                self.stats.malformed_samples += 1;
                break;
            }
            let rb = &body[off..off + rlen];
            let enterprise = rtype >> 12;
            let format = rtype & 0x0fff;
            if enterprise != 0 {
                self.stats.unknown_counter_record_types.insert(rtype);
            } else {
                match format {
                    GENERIC_INTERFACE_COUNTERS => {
                        if let Some(c) = parse_generic_interface(rb) {
                            self.stats.generic_interface_counters += 1;
                            self.stats.counter_records += 1;
                            self.push_counter(
                                exporter,
                                agent,
                                sub_agent_id,
                                datagram_sequence,
                                sample_sequence,
                                source_id,
                                format,
                                SflowCounterData::GenericInterface(c),
                                now_ms,
                            );
                            delivered += 1;
                        } else {
                            self.stats.record_truncations += 1;
                        }
                    }
                    ETHERNET_INTERFACE_COUNTERS => {
                        if let Some(c) = parse_ethernet_counters(rb) {
                            self.stats.ethernet_counters += 1;
                            self.stats.counter_records += 1;
                            self.push_counter(
                                exporter,
                                agent,
                                sub_agent_id,
                                datagram_sequence,
                                sample_sequence,
                                source_id,
                                format,
                                SflowCounterData::Ethernet(c),
                                now_ms,
                            );
                            delivered += 1;
                        } else {
                            self.stats.record_truncations += 1;
                        }
                    }
                    VLAN_COUNTERS => {
                        if let Some(c) = parse_vlan_counters(rb) {
                            self.stats.vlan_counters += 1;
                            self.stats.counter_records += 1;
                            self.push_counter(
                                exporter,
                                agent,
                                sub_agent_id,
                                datagram_sequence,
                                sample_sequence,
                                source_id,
                                format,
                                SflowCounterData::Vlan(c),
                                now_ms,
                            );
                            delivered += 1;
                        } else {
                            self.stats.record_truncations += 1;
                        }
                    }
                    _ => {
                        self.stats.unknown_counter_record_types.insert(rtype);
                    }
                }
            }
            off += rlen;
            if off % 4 != 0 {
                let aligned = (off + 3) & !3;
                if aligned > body.len() {
                    self.stats.record_truncations += 1;
                    self.stats.malformed_samples += 1;
                    break;
                }
                if body[off..aligned].iter().any(|b| *b != 0) {
                    self.stats.nonzero_padding += 1;
                }
                off = aligned;
            }
        }
        (0, delivered)
    }

    #[allow(clippy::too_many_arguments)]
    fn push_counter(
        &mut self,
        exporter: ExporterId,
        agent: IpAddr,
        sub_agent_id: u32,
        datagram_sequence: u32,
        sample_sequence: u32,
        source_id: SourceId,
        format: u32,
        data: SflowCounterData,
        now_ms: u64,
    ) {
        self.stats.delivered_counters += 1;
        self.counters.push(SflowCounter {
            exporter,
            agent,
            sub_agent_id,
            datagram_sequence,
            sample_sequence,
            source_id,
            format,
            data,
            timestamp_ms: now_ms,
        });
    }

    fn parse_raw_header(&mut self, rb: &[u8], acc: &mut FlowAccum) {
        if rb.len() < 16 {
            self.stats.record_truncations += 1;
            return;
        }
        let protocol = be32(&rb[0..4]);
        let frame_length = be32(&rb[4..8]);
        let header_length = be32(&rb[12..16]) as usize;
        if 16 + header_length > rb.len() {
            self.stats.record_truncations += 1;
            return;
        }
        acc.frame_length.get_or_insert(u64::from(frame_length));
        acc.header_length.get_or_insert(header_length as u32);
        // `stripped`（rb[8..12]）是发送前剥离的字节数；本版不参与五元组。
        if let Some((key, tcp_flags)) = parse_sampled_header(protocol, &rb[16..16 + header_length])
        {
            if let Some(flags) = tcp_flags {
                acc.tcp_flags.get_or_insert(flags);
            }
            if acc.offer_key(key) {
                self.stats.flow_record_conflicts += 1;
            }
        }
    }

    fn parse_ethernet_record(&mut self, rb: &[u8], acc: &mut FlowAccum) {
        if rb.len() < 24 {
            self.stats.record_truncations += 1;
            return;
        }
        let length = be32(&rb[0..4]);
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&rb[4..10]);
        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&rb[12..18]);
        acc.frame_length.get_or_insert(u64::from(length));
        acc.src_mac.get_or_insert(src_mac);
        acc.dst_mac.get_or_insert(dst_mac);
        acc.ether_type.get_or_insert(be16(&rb[22..24]));
    }

    fn parse_ipv4_record(&mut self, rb: &[u8], acc: &mut FlowAccum) {
        if rb.len() < 32 {
            self.stats.record_truncations += 1;
            return;
        }
        let length = be32(&rb[0..4]);
        let proto = be32(&rb[4..8]);
        let mut src = [0u8; 4];
        src.copy_from_slice(&rb[8..12]);
        let mut dst = [0u8; 4];
        dst.copy_from_slice(&rb[12..16]);
        let sport = be32(&rb[16..20]);
        let dport = be32(&rb[20..24]);
        let flags = be32(&rb[24..28]);
        if let Some(key) = key_from_v4(src, dst, proto, sport, dport) {
            acc.frame_length.get_or_insert(u64::from(length));
            if proto == 6 {
                acc.tcp_flags.get_or_insert(flags as u8);
            }
            if acc.offer_key(key) {
                self.stats.flow_record_conflicts += 1;
            }
        }
    }

    fn parse_ipv6_record(&mut self, rb: &[u8], acc: &mut FlowAccum) {
        if rb.len() < 56 {
            self.stats.record_truncations += 1;
            return;
        }
        let length = be32(&rb[0..4]);
        let proto = be32(&rb[4..8]);
        let mut src = [0u8; 16];
        src.copy_from_slice(&rb[8..24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&rb[24..40]);
        let sport = be32(&rb[40..44]);
        let dport = be32(&rb[44..48]);
        let flags = be32(&rb[48..52]);
        if let Some(key) = key_from_v6(src, dst, proto, sport, dport) {
            acc.frame_length.get_or_insert(u64::from(length));
            if proto == 6 {
                acc.tcp_flags.get_or_insert(flags as u8);
            }
            if acc.offer_key(key) {
                self.stats.flow_record_conflicts += 1;
            }
        }
    }

    fn parse_extended_switch(&mut self, rb: &[u8], acc: &mut FlowAccum) {
        if rb.len() < 16 {
            self.stats.record_truncations += 1;
            return;
        }
        acc.src_vlan = Some(be32(&rb[0..4]));
        acc.src_priority = Some(be32(&rb[4..8]));
        acc.dst_vlan = Some(be32(&rb[8..12]));
        acc.dst_priority = Some(be32(&rb[12..16]));
    }
}

#[derive(Debug, Default)]
struct FlowAccum {
    key: Option<FlowKey>,
    frame_length: Option<u64>,
    header_length: Option<u32>,
    tcp_flags: Option<u8>,
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
    ether_type: Option<u16>,
    src_vlan: Option<u32>,
    dst_vlan: Option<u32>,
    src_priority: Option<u32>,
    dst_priority: Option<u32>,
}

impl FlowAccum {
    /// 返回 true 表示已有不同的五元组，保留首个并让调用方计冲突。
    fn offer_key(&mut self, key: FlowKey) -> bool {
        match self.key {
            None => {
                self.key = Some(key);
                false
            }
            Some(existing) => existing != key,
        }
    }
}

fn key_from_v4(src: [u8; 4], dst: [u8; 4], proto: u32, sport: u32, dport: u32) -> Option<FlowKey> {
    if proto > u32::from(u8::MAX) || sport > u32::from(u16::MAX) || dport > u32::from(u16::MAX) {
        return None;
    }
    Some(FlowKey::new_ipv4(
        src,
        sport as u16,
        dst,
        dport as u16,
        proto as u8,
    ))
}

fn key_from_v6(
    src: [u8; 16],
    dst: [u8; 16],
    proto: u32,
    sport: u32,
    dport: u32,
) -> Option<FlowKey> {
    if proto > u32::from(u8::MAX) || sport > u32::from(u16::MAX) || dport > u32::from(u16::MAX) {
        return None;
    }
    Some(FlowKey::new_ipv6(
        Ipv6Addr::from(src),
        sport as u16,
        Ipv6Addr::from(dst),
        dport as u16,
        proto as u8,
    ))
}

fn parse_sampled_header(protocol: u32, header: &[u8]) -> Option<(FlowKey, Option<u8>)> {
    match protocol {
        HEADER_PROTOCOL_ETHERNET => parse_ethernet_header(header),
        HEADER_PROTOCOL_IPV4 => parse_ipv4_header(header, 0),
        HEADER_PROTOCOL_IPV6 => parse_ipv6_header(header, 0),
        _ => None,
    }
}

fn parse_ethernet_header(header: &[u8]) -> Option<(FlowKey, Option<u8>)> {
    if header.len() < 14 {
        return None;
    }
    let mut off = 12usize;
    let mut ethertype = be16(&header[off..off + 2]);
    off += 2;
    // 0x8100/0x88a8/0x9100 都是 VLAN tag；最多剥两层，防畸形报文无限循环。
    for _ in 0..2 {
        if ethertype != 0x8100 && ethertype != 0x88a8 && ethertype != 0x9100 {
            break;
        }
        if header.len() < off + 4 {
            return None;
        }
        ethertype = be16(&header[off + 2..off + 4]);
        off += 4;
    }
    match ethertype {
        0x0800 => parse_ipv4_header(header, off),
        0x86dd => parse_ipv6_header(header, off),
        _ => None,
    }
}

fn parse_ipv4_header(header: &[u8], off: usize) -> Option<(FlowKey, Option<u8>)> {
    if header.len() < off + 20 {
        return None;
    }
    if header[off] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(header[off] & 0x0f) * 4;
    if ihl < 20 || header.len() < off + ihl {
        return None;
    }
    let proto = header[off + 9];
    let frag = be16(&header[off + 6..off + 8]);
    let frag_offset = frag & 0x1fff;
    let mut src = [0u8; 4];
    src.copy_from_slice(&header[off + 12..off + 16]);
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&header[off + 16..off + 20]);
    let ports = if proto == 6 || proto == 17 {
        // 非首片没有 L4 头；此时无法给出端口，不能拿 0 冒充真实端口。
        if frag_offset != 0 || header.len() < off + ihl + 4 {
            return None;
        }
        Some((
            be16(&header[off + ihl..off + ihl + 2]),
            be16(&header[off + ihl + 2..off + ihl + 4]),
        ))
    } else {
        Some((0, 0))
    };
    let (sport, dport) = ports?;
    let tcp_flags = if proto == 6 && header.len() >= off + ihl + 14 {
        Some(header[off + ihl + 13])
    } else {
        None
    };
    Some((FlowKey::new_ipv4(src, sport, dst, dport, proto), tcp_flags))
}

fn parse_ipv6_header(header: &[u8], off: usize) -> Option<(FlowKey, Option<u8>)> {
    if header.len() < off + 40 {
        return None;
    }
    if header[off] >> 4 != 6 {
        return None;
    }
    let mut next = header[off + 6];
    let mut src = [0u8; 16];
    src.copy_from_slice(&header[off + 8..off + 24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&header[off + 24..off + 40]);
    let mut l4 = off + 40;
    // 只走最常见的扩展头；遇到 ESP/AH 等无法安全定位 L4，直接放弃五元组。
    for _ in 0..4 {
        match next {
            0 | 43 | 60 => {
                if header.len() < l4 + 2 {
                    return None;
                }
                let hdr_len = (usize::from(header[l4 + 1]) + 1) * 8;
                if header.len() < l4 + hdr_len {
                    return None;
                }
                next = header[l4];
                l4 += hdr_len;
            }
            44 => {
                // Fragment header：非首片没有 L4 头。
                if header.len() < l4 + 8 {
                    return None;
                }
                let frag_off = be16(&header[l4 + 2..l4 + 4]) >> 3;
                if frag_off != 0 {
                    return None;
                }
                next = header[l4];
                l4 += 8;
            }
            _ => break,
        }
    }
    let (sport, dport, tcp_flags) = if next == 6 || next == 17 {
        if header.len() < l4 + 4 {
            return None;
        }
        let flags = if next == 6 && header.len() >= l4 + 14 {
            Some(header[l4 + 13])
        } else {
            None
        };
        (
            be16(&header[l4..l4 + 2]),
            be16(&header[l4 + 2..l4 + 4]),
            flags,
        )
    } else {
        (0, 0, None)
    };
    Some((
        FlowKey::new_ipv6(Ipv6Addr::from(src), sport, Ipv6Addr::from(dst), dport, next),
        tcp_flags,
    ))
}

fn parse_generic_interface(rb: &[u8]) -> Option<GenericInterfaceCounters> {
    if rb.len() < 88 {
        return None;
    }
    Some(GenericInterfaceCounters {
        if_index: be32(&rb[0..4]),
        if_type: be32(&rb[4..8]),
        if_speed: be64(&rb[8..16]),
        if_direction: be32(&rb[16..20]),
        if_status: be32(&rb[20..24]),
        in_octets: be64(&rb[24..32]),
        in_ucast_pkts: be32(&rb[32..36]),
        in_multicast_pkts: be32(&rb[36..40]),
        in_broadcast_pkts: be32(&rb[40..44]),
        in_discards: be32(&rb[44..48]),
        in_errors: be32(&rb[48..52]),
        in_unknown_protos: be32(&rb[52..56]),
        out_octets: be64(&rb[56..64]),
        out_ucast_pkts: be32(&rb[64..68]),
        out_multicast_pkts: be32(&rb[68..72]),
        out_broadcast_pkts: be32(&rb[72..76]),
        out_discards: be32(&rb[76..80]),
        out_errors: be32(&rb[80..84]),
        promiscuous_mode: be32(&rb[84..88]),
    })
}

fn parse_ethernet_counters(rb: &[u8]) -> Option<EthernetCounters> {
    if rb.len() < 52 {
        return None;
    }
    Some(EthernetCounters {
        alignment_errors: be32(&rb[0..4]),
        fcs_errors: be32(&rb[4..8]),
        single_collision_frames: be32(&rb[8..12]),
        multiple_collision_frames: be32(&rb[12..16]),
        sqe_test_errors: be32(&rb[16..20]),
        deferred_transmissions: be32(&rb[20..24]),
        late_collisions: be32(&rb[24..28]),
        excessive_collisions: be32(&rb[28..32]),
        internal_mac_transmit_errors: be32(&rb[32..36]),
        carrier_sense_errors: be32(&rb[36..40]),
        frame_too_longs: be32(&rb[40..44]),
        internal_mac_receive_errors: be32(&rb[44..48]),
        symbol_errors: be32(&rb[48..52]),
    })
}

fn parse_vlan_counters(rb: &[u8]) -> Option<VlanCounters> {
    if rb.len() < 28 {
        return None;
    }
    Some(VlanCounters {
        vlan_id: be32(&rb[0..4]),
        octets: be64(&rb[4..12]),
        ucast_pkts: be32(&rb[12..16]),
        multicast_pkts: be32(&rb[16..20]),
        broadcast_pkts: be32(&rb[20..24]),
        discards: be32(&rb[24..28]),
    })
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXP: ExporterId = ExporterId {
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        port: 40000,
    };

    fn pad4(b: &[u8]) -> Vec<u8> {
        let mut out = b.to_vec();
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn record(rtype: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn flow_sample(seq: u32, records: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&seq.to_be_bytes());
        body.extend_from_slice(&((0u32 << 24) | 5).to_be_bytes());
        body.extend_from_slice(&1000u32.to_be_bytes());
        body.extend_from_slice(&123_456u32.to_be_bytes());
        body.extend_from_slice(&2u32.to_be_bytes());
        body.extend_from_slice(&3u32.to_be_bytes());
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for r in records {
            body.extend_from_slice(r);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&FLOW_SAMPLE.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn expanded_flow_sample(seq: u32, records: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&seq.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&5u32.to_be_bytes());
        body.extend_from_slice(&1000u32.to_be_bytes());
        body.extend_from_slice(&123_456u32.to_be_bytes());
        body.extend_from_slice(&2u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&3u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for r in records {
            body.extend_from_slice(r);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&EXPANDED_FLOW_SAMPLE.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn counter_sample(seq: u32, records: &[Vec<u8>], expanded: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&seq.to_be_bytes());
        if expanded {
            body.extend_from_slice(&0u32.to_be_bytes());
            body.extend_from_slice(&3u32.to_be_bytes());
        } else {
            body.extend_from_slice(&3u32.to_be_bytes());
        }
        body.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for r in records {
            body.extend_from_slice(r);
        }
        let mut out = Vec::new();
        out.extend_from_slice(
            &(if expanded {
                EXPANDED_COUNTER_SAMPLE
            } else {
                COUNTER_SAMPLE
            })
            .to_be_bytes(),
        );
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn sample(sample_type: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&sample_type.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn datagram(sequence: u32, samples: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for s in samples {
            body.extend_from_slice(s);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&SFLOW_VERSION.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&[192, 0, 2, 10]);
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&1_234_567u32.to_be_bytes());
        out.extend_from_slice(&(samples.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn datagram_v6(sequence: u32, samples: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for s in samples {
            body.extend_from_slice(s);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&SFLOW_VERSION.to_be_bytes());
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&1_234_567u32.to_be_bytes());
        out.extend_from_slice(&(samples.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn ipv4_header() -> Vec<u8> {
        let mut ip = Vec::new();
        ip.extend_from_slice(&[0x45, 0]);
        ip.extend_from_slice(&40u16.to_be_bytes());
        ip.extend_from_slice(&1u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.push(64);
        ip.push(6);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&1234u16.to_be_bytes());
        tcp.extend_from_slice(&80u16.to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(0x50);
        tcp.push(0x18);
        tcp.extend_from_slice(&65535u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&tcp);
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    fn raw_record() -> Vec<u8> {
        let h = ipv4_header();
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&1500u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&(h.len() as u32).to_be_bytes());
        body.extend_from_slice(&pad4(&h));
        record(RAW_PACKET_HEADER, &body)
    }

    fn ipv6_packet() -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&1234u16.to_be_bytes());
        tcp.extend_from_slice(&443u16.to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(0x50);
        tcp.push(0x18);
        tcp.extend_from_slice(&65535u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        let mut ip = Vec::new();
        ip.extend_from_slice(&[0x60, 0, 0, 0]);
        ip.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        ip.push(6);
        ip.push(64);
        ip.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        ip.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        ip.extend_from_slice(&tcp);
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&0x86ddu16.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    fn raw_ipv6_record() -> Vec<u8> {
        let h = ipv6_packet()[14..].to_vec();
        let mut body = Vec::new();
        body.extend_from_slice(&12u32.to_be_bytes());
        body.extend_from_slice(&1500u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&(h.len() as u32).to_be_bytes());
        body.extend_from_slice(&pad4(&h));
        record(RAW_PACKET_HEADER, &body)
    }

    fn ethernet_frame_record() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1500u32.to_be_bytes());
        body.extend_from_slice(&[0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&0x0800u32.to_be_bytes());
        assert_eq!(body.len(), 24);
        record(ETHERNET_FRAME_DATA, &body)
    }

    fn ipv4_record() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1500u32.to_be_bytes());
        body.extend_from_slice(&6u32.to_be_bytes());
        body.extend_from_slice(&[10, 0, 0, 1]);
        body.extend_from_slice(&[10, 0, 0, 2]);
        body.extend_from_slice(&1234u32.to_be_bytes());
        body.extend_from_slice(&80u32.to_be_bytes());
        body.extend_from_slice(&0x18u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        record(IPV4_DATA, &body)
    }

    fn ipv6_record() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1500u32.to_be_bytes());
        body.extend_from_slice(&17u32.to_be_bytes());
        body.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        body.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        body.extend_from_slice(&5353u32.to_be_bytes());
        body.extend_from_slice(&53u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        record(IPV6_DATA, &body)
    }

    fn switch_record() -> Vec<u8> {
        let mut body = Vec::new();
        for v in [100u32, 3, 200, 4] {
            body.extend_from_slice(&v.to_be_bytes());
        }
        record(EXTENDED_SWITCH_DATA, &body)
    }

    fn generic_record() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&3u32.to_be_bytes());
        b.extend_from_slice(&6u32.to_be_bytes());
        b.extend_from_slice(&1_000_000_000u64.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&3u32.to_be_bytes());
        b.extend_from_slice(&123_456_789u64.to_be_bytes());
        for v in [1000u32, 2, 3, 4, 5, 6] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b.extend_from_slice(&987_654_321u64.to_be_bytes());
        for v in [2000u32, 7, 8, 9, 10, 0] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        assert_eq!(b.len(), 88);
        record(GENERIC_INTERFACE_COUNTERS, &b)
    }

    fn ethernet_record() -> Vec<u8> {
        let mut b = Vec::new();
        for v in 1u32..=13 {
            b.extend_from_slice(&v.to_be_bytes());
        }
        record(ETHERNET_INTERFACE_COUNTERS, &b)
    }

    fn vlan_record() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&100u32.to_be_bytes());
        b.extend_from_slice(&5555u64.to_be_bytes());
        for v in [10u32, 20, 30, 40] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        record(VLAN_COUNTERS, &b)
    }

    fn collect(msgs: &[(u64, Vec<u8>)]) -> (SflowCollector, Vec<SflowFlow>, Vec<SflowCounter>) {
        let mut c = SflowCollector::new(SflowConfig::default());
        for (t, m) in msgs {
            c.on_datagram(EXP, m, *t);
        }
        let flows = c.take_flows();
        let counters = c.take_counters();
        (c, flows, counters)
    }

    #[test]
    fn decodes_flow_sample_with_raw_header_and_extended_switch() {
        let d = datagram(
            100,
            &[flow_sample(
                7,
                &[
                    raw_record(),
                    ethernet_frame_record(),
                    ipv4_record(),
                    switch_record(),
                ],
            )],
        );
        let (c, flows, _) = collect(&[(1000, d)]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].key.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(flows[0].key.dst_port, 80);
        assert_eq!(flows[0].sampling_rate, 1000);
        assert_eq!(flows[0].frame_length, 1500);
        assert_eq!(flows[0].tcp_flags, Some(0x18));
        assert_eq!(flows[0].src_mac, Some([0, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(flows[0].dst_mac, Some([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]));
        assert_eq!(flows[0].ether_type, Some(0x0800));
        assert_eq!(flows[0].src_vlan, Some(100));
        assert_eq!(flows[0].dst_vlan, Some(200));
        assert_eq!(c.stats().flow_records, 4);
        assert_eq!(c.stats().delivered_flows, 1);
        assert_eq!(c.stats().flow_record_conflicts, 0);
    }

    #[test]
    fn decodes_expanded_flow_sample_with_ipv6() {
        let d = datagram(101, &[expanded_flow_sample(8, &[ipv6_record()])]);
        let (c, flows, _) = collect(&[(2000, d)]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].key.src_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(flows[0].key.dst_port, 53);
        assert_eq!(flows[0].sampling_rate, 1000);
        assert_eq!(c.stats().expanded_flow_samples, 1);
    }

    #[test]
    fn decodes_counter_samples_in_both_formats() {
        let d = datagram(
            102,
            &[
                counter_sample(
                    9,
                    &[generic_record(), ethernet_record(), vlan_record()],
                    false,
                ),
                counter_sample(10, &[generic_record()], true),
            ],
        );
        let (c, _, counters) = collect(&[(3000, d)]);
        assert_eq!(counters.len(), 4);
        assert_eq!(c.stats().generic_interface_counters, 2);
        assert_eq!(c.stats().ethernet_counters, 1);
        assert_eq!(c.stats().vlan_counters, 1);
        match counters[0].data {
            SflowCounterData::GenericInterface(g) => {
                assert_eq!(g.if_index, 3);
                assert_eq!(g.in_octets, 123_456_789);
                assert_eq!(g.out_octets, 987_654_321);
            }
            _ => panic!("expected generic interface"),
        }
        match counters[2].data {
            SflowCounterData::Vlan(v) => {
                assert_eq!(v.vlan_id, 100);
                assert_eq!(v.octets, 5555);
            }
            _ => panic!("expected vlan"),
        }
    }

    #[test]
    fn sequence_gap_counts_lost_datagrams() {
        let d1 = datagram(10, &[flow_sample(1, &[ipv4_record()])]);
        let d2 = datagram(12, &[flow_sample(2, &[ipv4_record()])]);
        let (c, flows, _) = collect(&[(1000, d1), (2000, d2)]);
        assert_eq!(flows.len(), 2);
        assert_eq!(c.stats().sequence_gaps, 1);
        assert_eq!(c.stats().datagrams_lost, 1);
        assert_eq!(c.stats().loss_ppm(), 333_333); // 1 / (2 + 1)
    }

    #[test]
    fn duplicate_datagram_is_not_loss_and_sample_dedup_holds() {
        let d = datagram(10, &[flow_sample(1, &[ipv4_record()])]);
        let (c, flows, _) = collect(&[(1000, d.clone()), (2000, d)]);
        assert_eq!(flows.len(), 1);
        assert_eq!(c.stats().duplicate_datagrams, 1);
        assert_eq!(c.stats().duplicate_samples, 1);
        assert_eq!(c.stats().datagrams_lost, 0);
    }

    #[test]
    fn backward_sequence_is_out_of_order_not_loss() {
        let (c, _, _) = collect(&[(1000, datagram(10, &[])), (2000, datagram(8, &[]))]);
        assert_eq!(c.stats().out_of_order, 1);
        assert_eq!(c.stats().sequence_gaps, 0);
        assert_eq!(c.stats().datagrams_lost, 0);
    }

    #[test]
    fn sequence_wraps_without_false_loss() {
        let (c, _, _) = collect(&[(1000, datagram(u32::MAX, &[])), (2000, datagram(0, &[]))]);
        assert_eq!(c.stats().datagrams_lost, 0);
        assert_eq!(c.stats().out_of_order, 0);
    }

    #[test]
    fn sub_agents_do_not_share_sequence_state() {
        let a = datagram(1, &[]);
        let mut b = datagram(100, &[]);
        // 改第二个数据报的 sub_agent_id；位置 = 8 + 4。
        b[12..16].copy_from_slice(&2u32.to_be_bytes());
        let (c, _, _) = collect(&[(1000, a), (2000, b)]);
        assert_eq!(c.stats().agents, 2);
        assert_eq!(c.stats().datagrams_lost, 0);
    }

    #[test]
    fn unknown_sample_and_record_types_are_skipped() {
        let unknown_sample = sample((1 << 12) | 99, &[0u8; 8]);
        let unknown_record = record((1 << 12) | 77, &[0u8; 8]);
        let d = datagram(1, &[unknown_sample, flow_sample(1, &[unknown_record])]);
        let (c, flows, _) = collect(&[(1000, d)]);
        assert!(flows.is_empty());
        assert_eq!(c.stats().unknown_sample_types, 1);
        assert!(c
            .stats()
            .unknown_flow_record_types
            .contains(&((1 << 12) | 77)));
        assert_eq!(c.stats().flow_records_missing_key, 1);
    }

    #[test]
    fn truncated_record_is_counted_not_invented() {
        let mut r = ipv4_record();
        r.truncate(12);
        let d = datagram(1, &[flow_sample(1, &[r])]);
        let (c, flows, _) = collect(&[(1000, d)]);
        assert!(flows.is_empty());
        assert_eq!(c.stats().record_truncations, 1);
        assert_eq!(c.stats().malformed_samples, 1);
    }

    #[test]
    fn version_and_agent_type_mismatch_are_rejected() {
        let mut v4 = datagram(1, &[]);
        v4[0..4].copy_from_slice(&4u32.to_be_bytes());
        let mut bad_agent = datagram(1, &[]);
        bad_agent[4..8].copy_from_slice(&9u32.to_be_bytes());
        let (c, _, _) = collect(&[(1000, v4), (2000, bad_agent)]);
        assert_eq!(c.stats().version_mismatch, 1);
        assert_eq!(c.stats().malformed_datagrams, 1);
        assert_eq!(c.stats().sequence_tracked, 0);
    }

    #[test]
    fn malformed_sample_length_does_not_panic() {
        let mut d = datagram(1, &[]);
        d.extend_from_slice(&FLOW_SAMPLE.to_be_bytes());
        d.extend_from_slice(&999u32.to_be_bytes());
        let (c, _, _) = collect(&[(1000, d)]);
        assert_eq!(c.stats().malformed_datagrams, 1);
    }

    #[test]
    fn nonzero_trailing_bytes_are_malformed() {
        let mut d = datagram(1, &[]);
        d.push(0xff);
        let (c, _, _) = collect(&[(1000, d)]);
        assert_eq!(c.stats().malformed_datagrams, 1);
    }

    #[test]
    fn conflicting_flow_records_keep_first_key() {
        let mut other = ipv4_record();
        other[16..20].copy_from_slice(&[10, 0, 0, 99]);
        let d = datagram(1, &[flow_sample(1, &[ipv4_record(), other])]);
        let (c, flows, _) = collect(&[(1000, d)]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].key.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(c.stats().flow_record_conflicts, 1);
    }

    #[test]
    fn decodes_ipv6_agent_and_raw_ipv6_header() {
        let d = datagram_v6(102, &[flow_sample(10, &[raw_ipv6_record()])]);
        let (c, flows, _) = collect(&[(4000, d)]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].agent, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(flows[0].key.src_port, 1234);
        assert_eq!(flows[0].key.dst_port, 443);
        assert_eq!(flows[0].tcp_flags, Some(0x18));
        assert_eq!(c.stats().agents, 1);
    }

    #[test]
    fn json_lines_are_stable_and_typed() {
        let d = datagram(1, &[flow_sample(1, &[ipv4_record(), switch_record()])]);
        let (_, flows, _) = collect(&[(1000, d)]);
        let line = flows[0].to_json_line();
        assert!(line.contains("\"type\":\"flow\""));
        assert!(line.contains("\"src_ip\":\"10.0.0.1\""));
        assert!(line.contains("\"sampling_rate\":1000"));
        assert!(line.contains("\"src_vlan\":100"));

        let d = datagram(2, &[counter_sample(2, &[generic_record()], false)]);
        let (_, _, counters) = collect(&[(2000, d)]);
        let line = counters[0].to_json_line();
        assert!(line.contains("\"record\":\"generic_interface\""));
        assert!(line.contains("\"in_octets\":123456789"));
    }
}
