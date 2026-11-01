// pipeline.rs —— 离线分析流水线：pcap → FlowRecord（CYS-TRF-035 的核心）。
//
// 为什么把它从 CLI 里抽出来：同一条链要同时被**命令行**和**测试**驱动。
// 若各自写一份"读包→解码→喂流表→喂特征→产出记录"的循环，两份必然漂移，
// 而漂移的表现是"测试全绿、命令行产出的记录却是另一回事"——最难发现的那种错。
//
// 这条链上依次用到：channel::decode（解帧）→ flow（流表/五档超时/逐出）→
// session（双向会话 + TCP 状态机）→ feature（定长特征）→ record（JSONL 契约）。
// 因此它同时是**整条数据链的回归载体**：任何一环改坏了，这个函数的输出会变。
//
// 三个刻意的默认值：
//
// 1. **默认容忍模式（tolerant）**。离线 pcap 的抓包起点几乎必然切在某条会话中间，
//    严格模式会把"没看到握手"一律判成非法迁移，产出的状态全是 Closed ——
//    那不是协议栈的真实状态，而是"我们只看到后半段"这一事实。
//
// 2. **EOF 不做过期裁剪**。抓包结束时仍打开的会话照常产出记录，因为**它们承载了
//    全部数据**；丢掉"没有 FIN 的会话"会让一整条大流量的记录消失，而统计上看不出
//    少了什么。在线路径相反：那里靠 `SessionManager::expire` 按超时回收。
//
// 3. Most classifiers inspect one payload per direction. DNS/TCP on service
//    port 53 additionally uses bounded SYN-anchored first-frame reassembly.

mod dns_tcp;

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::mpsc;
use std::thread;

use crate::arp::{self, ArpStats};
use crate::channel::{
    decode_frame_with_link, l4_payload, tcp_flags, tcp_seq_ack, DecodedFrame, LinkLayer,
};
use crate::dpi::{self, DpiPolicy, Outcome};
use crate::feature::{FeatureExtractor, FlowSample};
use crate::flow::{FlowKey, Packet};
use crate::gre::{self, GreStats};
use crate::icmp::{self, IcmpFamily, IcmpStats};
use crate::pcapfile::{PcapReader, PcapRecord};
use crate::reassembly::ip::{IpFragConfig, IpFragStats, IpReassembler, PushOutcome};
use crate::record::{AppInfo, FlowRecord, TcpSessionStats, RECORD_SCHEMA_VERSION};
use crate::session::{ManagerStats, SessionConfig, SessionManager};
use crate::tcp::{Side, TcpConfig, TcpObservation};
use crate::vxlan::{self, VxlanStats};

/// 流水线参数。
#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    /// 会话管理器配置（含 TCP 严格/容忍模式与容量）。
    pub session: SessionConfig,
    /// 喂给 DPI 的首包字节数上限（调用方上限；最终值还受 `dpi` 强度约束）。
    pub inspect_bytes: usize,
    /// DPI 模块开关、检测强度与 TLS 解密配置。
    pub dpi: DpiPolicy,
    /// 流级采样（`CYS-TRF-053`）。`None` 或 `interval == 1` ⇒ **一个包都不丢**。
    ///
    /// 采样器只在这里配置一次，导出侧的 IE 34 也从这份配置取（单一来源）：
    /// 分成"一个开关声明、另一个开关执行"就是把撒谎的入口留在代码里。
    pub sampling: Option<crate::sampling::SamplingConfig>,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        let mut session = SessionConfig::default();
        session.tcp = TcpConfig::tolerant();
        Self {
            session,
            inspect_bytes: dpi::DEFAULT_INSPECT_BYTES,
            dpi: DpiPolicy::default(),
            sampling: None,
        }
    }
}

impl AnalyzeOptions {
    /// 严格模式：未见到握手的会话不采纳（审计"完整握手"场景才需要）。
    pub fn strict() -> Self {
        let mut session = SessionConfig::default();
        session.tcp = TcpConfig::default();
        Self {
            session,
            ..Self::default()
        }
    }
}

/// 运行统计。**每一项都要能回答"干没干"**：只报"成功"而不报处理了多少，
/// 就是"绿色的通过和绿色的没跑长得一样"。
#[derive(Debug, Clone, Default)]
pub struct AnalyzeStats {
    pub packets_read: u64,
    pub packets_decoded: u64,
    pub truncated_captures: u64,
    /// 连四层头长度都读不到、因而载荷起点未知的包数。
    pub payload_start_unknown: u64,
    /// 解码失败按错误码分桶（`DecodeError::code()`）。
    pub decode_errors: BTreeMap<&'static str, u64>,
    pub records: usize,
    /// 特征向量含非有限值的记录数（正常恒为 0）。
    pub non_finite_vectors: usize,
    /// 会话计数与特征计数不一致的记录数（正常恒为 0）。
    pub counter_mismatches: u64,
    pub sorted_by_key: bool,
    /// 消费侧并行度（1 = 就地单线程）。
    pub workers: usize,
    /// 每个 worker 承担的**记录数**。只报总数看不出「分片有没有倾斜」，
    /// 而倾斜会让并行度变成摆设（一个 worker 干完所有活）。
    pub worker_flows: Vec<usize>,
    /// 应用识别结论分布。
    pub app_outcomes: BTreeMap<&'static str, u64>,
    pub session: ManagerStats,
    pub linktype: u32,
    pub linktype_name: &'static str,
    /// 采样统计（未启用时为 `None`）。**"声明与执行一致"唯一可被外部检查的地方**：
    /// `observed`/`kept` 由采样器自己记，导出侧的 IE 34 由同一份配置给。
    pub sampling: Option<crate::sampling::SamplingStats>,
    /// ARP/RARP 帧级统计（B004）。ARP 没有 IP 五元组，不产生 `FlowRecord`；
    /// 这里只记录“看到并解析了什么”，不从 reply 推断主机在线或地址归属。
    pub arp: ArpStats,
    /// ICMPv4/ICMPv6 报文级统计（B011/B012）。ICMP 有五元组、会进流表，
    /// 类型/代码/内嵌原始数据报只在统计行与独立采集器里展开。
    pub icmp: IcmpStats,
    /// GRE/PPTP GRE 报文级统计（V009）。内层 IP 不会被当成第二条流：
    /// 单包可见的只是一个封装头，拆开内层会凭空制造会话。
    pub gre: GreStats,
    /// IPv4/IPv6 分片重组统计（B008）。完整数据报才进入流表；缺片/重叠/
    /// 截断/超预算只在这里计数，不会伪造内层流。
    pub ipfrag: IpFragStats,
    /// VXLAN 报文级统计（V014）。只展开外层 UDP + VXLAN 头/可见内层以太网头，
    /// 内层 IP 不回到流水线，不产生第二条 FlowRecord。
    pub vxlan: VxlanStats,
    /// 会话级 TCP 统计（`CYS-TRF-015`）。走**统计行**这个已有出口而不是记录字段：
    /// 给 JSONL 加键会改变已实测的落盘字节/记录（gzip 79.4 / 列式 78.5），
    /// 那必须是一个“改契约 + 重测”的专门批次，不能混在这里静默偷掉。
    pub tcp: TcpAnomalyStats,
    /// DPI 策略快照。**报告"关了多少"和"开了什么强度"必须来自同一份对象**，
    /// 否则统计行会与记录里的 `not_inspected` 互相矛盾。
    pub dpi_enabled: bool,
    pub dpi_intensity: &'static str,
    pub dpi_modules_disabled: usize,
}

/// 会话级 TCP 统计的合计（跨 worker 相加；RTT 取 min/max/sum 而不是均值，
/// 因为均值在合并时会需要额外的样本量字段，而 min/max/sum 本身就是可结合量）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpAnomalyStats {
    /// 有过判定输入的会话数与完全没有的会话数。两者分开报，“没重传”与
    /// “读不到序号”在输出上必须长得不一样。
    pub sessions_judged: u64,
    pub sessions_unobserved: u64,
    pub judged_segments: u64,
    pub retransmissions: u64,
    pub out_of_order: u64,
    pub rtt_measured: u64,
    pub rtt_sum_us: u64,
    pub rtt_min_us: u64,
    pub rtt_max_us: u64,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    /// 上下行都已知且上行>0 的会话数（报比例时的样本量；没样本量就不报比例）。
    pub ratio_sessions: u64,
}

impl TcpAnomalyStats {
    /// 把一条会话的统计累加进来。调用方必须只对 TCP 会话调用（非 TCP 没有这些语义）。
    fn add_session(&mut self, s: &crate::session::Session) {
        if s.seq_judged() == 0 {
            self.sessions_unobserved += 1;
        } else {
            self.sessions_judged += 1;
            self.judged_segments += s.seq_judged();
            self.retransmissions += s.retransmissions().unwrap_or(0);
            self.out_of_order += s.out_of_order().unwrap_or(0);
        }
        if let Some(r) = s.handshake_rtt_us() {
            self.rtt_measured += 1;
            self.rtt_sum_us += r;
            self.rtt_min_us = if self.rtt_measured == 1 {
                r
            } else {
                self.rtt_min_us.min(r)
            };
            self.rtt_max_us = self.rtt_max_us.max(r);
        }
        if let (Some(up), Some(down)) = (s.uplink_bytes(), s.downlink_bytes()) {
            self.uplink_bytes += up;
            self.downlink_bytes += down;
            if up > 0 {
                self.ratio_sessions += 1;
            }
        }
    }

    fn merge(&mut self, src: &Self) {
        self.sessions_judged += src.sessions_judged;
        self.sessions_unobserved += src.sessions_unobserved;
        self.judged_segments += src.judged_segments;
        self.retransmissions += src.retransmissions;
        self.out_of_order += src.out_of_order;
        self.rtt_measured += src.rtt_measured;
        self.rtt_sum_us += src.rtt_sum_us;
        self.rtt_min_us = match (self.rtt_measured, src.rtt_measured) {
            (0, _) => src.rtt_min_us,
            (_, 0) => self.rtt_min_us,
            _ => self.rtt_min_us.min(src.rtt_min_us),
        };
        self.rtt_max_us = self.rtt_max_us.max(src.rtt_max_us);
        self.uplink_bytes += src.uplink_bytes;
        self.downlink_bytes += src.downlink_bytes;
        self.ratio_sessions += src.ratio_sessions;
    }

    /// 单行渲染（给 CLI 统计行；字段名是关口对着比的契约，改名字必须同时改关口）。
    pub fn render_line(&self) -> String {
        format!(
            "tcp retr={} ooo={} judged={} sess_judged={} sess_unobs={} rtt={}/{} sum_us={} min_us={} max_us={} up={} down={} ratio_n={}",
            self.retransmissions,
            self.out_of_order,
            self.judged_segments,
            self.sessions_judged,
            self.sessions_unobserved,
            self.rtt_measured,
            self.sessions_judged + self.sessions_unobserved,
            self.rtt_sum_us,
            self.rtt_min_us,
            self.rtt_max_us,
            self.uplink_bytes,
            self.downlink_bytes,
            self.ratio_sessions,
        )
    }
}

impl AnalyzeStats {
    pub fn decode_error_count(&self) -> u64 {
        self.decode_errors.values().sum()
    }
}

/// 分片队列长度：够深以吸收派发抖动，够浅以免整份 pcap 的负载都堆在内存里。
/// 队列满时派发端会阻塞 —— 这正是我们想要的背压，而不是无界堆积。
const SHARD_QUEUE_LEN: usize = 256;

/// 已解码的一条记录：派发端解一次帧，worker 直接消费。
///
/// 为什么把 `DecodedFrame` 一起带过去：worker 若自己再解一遍，每个包就付两次
/// 解帧开销 —— 那不是并行，是把同一件活干两遍。
struct DecodedPacket {
    data: Vec<u8>,
    decoded: DecodedFrame,
    timestamp_us: u64,
}

/// 每个 worker **私有**的流水线状态。
///
/// 静态分片保证同一条会话（双向）只落在一个 worker 上，于是这里不需要任何锁 ——
/// 「每核一张独立表」（HANDOFF §2.6 定下的路线）要的正是这个形态：流表、会话、
/// 特征、DPI 探针全部私有，worker 之间零共享。
struct PipelineState {
    mgr: SessionManager,
    features: BTreeMap<FlowKey, FeatureExtractor>,
    probes: BTreeMap<FlowKey, Probe>,
    payload_start_unknown: u64,
    dns_tcp: dns_tcp::DnsTcpStreams,
}

impl PipelineState {
    fn new(opts: &AnalyzeOptions) -> Self {
        Self {
            mgr: SessionManager::new(opts.session),
            features: BTreeMap::new(),
            probes: BTreeMap::new(),
            payload_start_unknown: 0,
            dns_tcp: dns_tcp::DnsTcpStreams::new(opts.inspect_bytes, opts.session.max_sessions),
        }
    }

    /// 喂一个包。**就地模式与分片模式共用这一条每包路径**：各写一份必然漂移，
    /// 而漂移的表现是「单线程跑出来的记录与多线程不是一回事」—— 最难发现的那种错。
    fn observe(&mut self, pkt: &DecodedPacket, opts: &AnalyzeOptions) {
        let d = &pkt.decoded;
        let key = d.key.canonical();
        let payload_view = l4_payload(&pkt.data, d);
        if payload_view.is_none() {
            self.payload_start_unknown += 1;
        }
        // 状态机要的是**段载荷长度**（不含四层头），字节统计要的是 IP 载荷长度
        // （含四层头）。这两个数必须分别传：混用会把每个纯 ACK 判成 Data。
        let seg = match (tcp_flags(&pkt.data, d), payload_view) {
            // 有序号就带上序号（`CYS-TRF-015` 的重传/乱序判定要它）；帧被截断到读不到
            // 序号时**不拿 0 兜底**，走 `new()` ⇒ 该会话的重传/乱序报"未观测"而不是 0。
            (Some(f), Some(p)) => {
                let len = u32::try_from(p.declared_len).unwrap_or(u32::MAX);
                match tcp_seq_ack(&pkt.data, d) {
                    Some((seq, ack)) => Some(TcpObservation::with_seq(f, len, seq, ack)),
                    None => Some(TcpObservation::new(f, len)),
                }
            }
            _ => None,
        };

        let obs = self.mgr.observe(
            &Packet {
                key: d.key,
                payload_len: d.ip_payload_len,
                timestamp_us: pkt.timestamp_us,
            },
            seg.as_ref(),
        );

        let payload_bytes: &[u8] = payload_view.map(|p| p.bytes).unwrap_or(&[]);
        self.features.entry(key).or_default().observe(&FlowSample {
            side: obs.side,
            payload_len: d.ip_payload_len,
            timestamp_us: pkt.timestamp_us,
            payload: payload_bytes,
        });

        // For native tunnels the IP payload starts at l4_offset; there is no TCP/UDP header.
        // Keep feature bytes unchanged: this is only the protocol inspection view.
        let native_tunnel = matches!(d.key.proto.number(), 4 | 41 | 47 | 50 | 51 | 97);
        let inspect_payload = if native_tunnel {
            let end = d
                .l4_offset
                .saturating_add(d.ip_payload_len as usize)
                .min(pkt.data.len());
            pkt.data.get(d.l4_offset..end).unwrap_or(&[])
        } else {
            payload_bytes
        };
        let truncated = payload_view.map(|p| p.is_truncated()).unwrap_or(false)
            || native_tunnel && inspect_payload.len() < d.ip_payload_len as usize;
        // 全局/强度为 off 时连 DNS/TCP 重组器都不喂：关闭必须真的不解析，
        // 而不是"解析完再把结论丢掉"。
        if opts.dpi.is_off() {
            return;
        }
        if d.key.proto.number() == dpi::IPPROTO_TCP
            && (d.key.src_port == 53 || d.key.dst_port == 53)
        {
            let end = d
                .l4_offset
                .saturating_add(d.ip_payload_len as usize)
                .min(pkt.data.len());
            let segment = pkt
                .data
                .get(d.l4_offset..end)
                .and_then(|bytes| crate::reassembly::tcp::parse(bytes).ok());
            let seen = self.probes.get(&key).is_some_and(|p| p.is_done(obs.side));
            if let Some(segment) = segment {
                let update =
                    self.dns_tcp
                        .observe(&obs, &segment, pkt.timestamp_us, seen, d.is_fragmented);
                let probe = self.probes.entry(key).or_default();
                if update.reset {
                    *probe = Probe::default();
                }
                if let Some(info) = update.info {
                    *probe.slot(obs.side) = Some(info);
                }
            }
            return;
        }
        let probe = self.probes.entry(key).or_default();
        let udp = d.key.proto.number() == dpi::IPPROTO_UDP;
        let inspect_limit = opts.dpi.effective_inspect_bytes(opts.inspect_bytes);
        if !probe.is_done(obs.side) && !inspect_payload.is_empty() && inspect_limit > 0 {
            let mut n = inspect_payload.len().min(inspect_limit);
            let preliminary = dpi::identify_with_policy(
                &inspect_payload[..n],
                d.key.proto.number(),
                d.key.src_port,
                d.key.dst_port,
                &opts.dpi,
            );
            let dhcpv6 = udp
                && opts.dpi.module_enabled("dhcpv6")
                && (matches!(&preliminary, Outcome::Identified(info) if info.app == dpi::AppId::Dhcpv6)
                    || matches!(d.key.dst_port, 546 | 547)
                        && dpi::dhcpv6::is_message_type(inspect_payload));
            let dhcp = udp
                && opts.dpi.module_enabled("dhcpv4")
                && (dpi::dhcp::has_cookie(inspect_payload) || dhcpv6);
            let mdns = udp
                && opts.dpi.module_enabled("mdns")
                && dpi::mdns::transport(inspect_payload, d.key.src_port, d.key.dst_port);
            let outcome = if (dhcp || mdns) && (d.is_fragmented || truncated) {
                Outcome::NeedMore
            } else if dhcp || mdns {
                // Keep datagram boundaries: IP/Ethernet padding is not application data.
                let udp_len = pkt
                    .data
                    .get(d.l4_offset + 4..d.l4_offset + 6)
                    .map(|v| usize::from(u16::from_be_bytes([v[0], v[1]])));
                match udp_len {
                    Some(len) if len >= 8 && len <= d.ip_payload_len as usize => {
                        n = n.min(len - 8);
                        if (dhcpv6 || mdns) && n < len - 8 {
                            Outcome::NeedMore // The complete datagram has not been inspected.
                        } else {
                            dpi::identify_with_policy(
                                &inspect_payload[..n],
                                d.key.proto.number(),
                                d.key.src_port,
                                d.key.dst_port,
                                &opts.dpi,
                            )
                        }
                    }
                    _ => Outcome::Malformed,
                }
            } else {
                preliminary
            };
            // 截断捕获必须导向「还需要更多字节」：我们自己少拷了字节，不能算「不认识」。
            let info = if truncated && matches!(outcome, Outcome::Unknown) {
                AppInfo::from_outcome(&Outcome::NeedMore, n)
            } else {
                AppInfo::from_outcome(&outcome, n)
            };
            *probe.slot(obs.side) = Some(info);
        }
    }

    /// 产出记录，并把**属于本 worker** 的统计（会话/特征/应用分布）累加进 `stats`。
    /// 派发端的统计（读包数、解帧数、截断数、解码错误）不在这里，由派发循环直接记。
    fn finish(self, stats: &mut AnalyzeStats) -> Vec<FlowRecord> {
        let sessions = self.mgr.sessions_sorted();
        let mut records: Vec<FlowRecord> = Vec::with_capacity(sessions.len());
        for s in sessions {
            let fv = self
                .features
                .get(&s.key)
                .map(|e| e.vector())
                .unwrap_or_else(|| FeatureExtractor::default().vector());
            // 内部互证：会话计数与特征计数必须一致（两条路径喂的是同一串包）。
            if fv.get(crate::feature::idx::PACKETS) != s.packets as f64
                || fv.get(crate::feature::idx::BYTES) != s.bytes as f64
            {
                stats.counter_mismatches += 1;
            }
            if !fv.is_finite() {
                stats.non_finite_vectors += 1;
            }
            let app = self
                .probes
                .get(&s.key)
                .map(|p| p.resolve())
                .unwrap_or_else(AppInfo::not_inspected);
            *stats.app_outcomes.entry(app.outcome).or_insert(0) += 1;
            if s.is_tcp() {
                stats.tcp.add_session(s);
            }
            records.push(FlowRecord {
                schema_version: RECORD_SCHEMA_VERSION,
                session_id: s.id,
                key: s.key,
                tcp_state: if s.is_tcp() {
                    Some(s.tcp_state())
                } else {
                    None
                },
                initiator: s.initiator(),
                adopted_midstream: s.adopted_midstream(),
                illegal_tcp_events: s.tcp.illegal_events(),
                // 会话级 TCP 统计（`CYS-TRF-015`）。非 TCP 会话整块 `None` ⇒ 六列全 NULL；
                // TCP 但读不到序号（截断采集）⇒ `seq_judged = 0` 而计数为 NULL。
                // 下游拿到的记录里“没重传”与“没得判”永远不共用一个字节。
                tcp_stats: if s.is_tcp() {
                    Some(TcpSessionStats {
                        seq_judged: s.seq_judged(),
                        retransmissions: s.retransmissions(),
                        out_of_order: s.out_of_order(),
                        handshake_rtt_us: s.handshake_rtt_us(),
                        uplink_bytes: s.uplink_bytes(),
                        downlink_bytes: s.downlink_bytes(),
                    })
                } else {
                    None
                },
                first_seen_us: s.first_seen_us,
                last_seen_us: s.last_seen_us,
                packets: s.packets,
                bytes: s.bytes,
                direction_switches: s.direction_switches,
                features: fv,
                app,
                risk_score: None,
            });
        }
        stats.payload_start_unknown += self.payload_start_unknown;
        add_manager_stats(&mut stats.session, &self.mgr.stats());
        stats.records = records.len();
        records
    }
}

/// 流键 → 分片号。**必须传 `canonical()` 过的键**：按原始五元组算，会把一条会话的
/// 两个方向分到不同 worker，于是各自只看到半条会话 —— 记录数翻倍而没有任何报错。
fn shard_of(key: &FlowKey, workers: usize) -> usize {
    // 哈希构造在 `hash` 模块（采样也用它）：两处各写一份必然漂移，
    // 而漂移的表现是"采样采到的流集合与分片结果对不上号"。
    (crate::hash::key_hash_mixed(key) % workers as u64) as usize
}

/// 会话统计逐项相加。**必须逐项**：漏一项的表现是那项指标悄悄比单线程运行小
/// （例如 12 次非法 TCP 迁移只报了 3 次），而总数看起来完全正常。
fn add_manager_stats(dst: &mut ManagerStats, src: &ManagerStats) {
    dst.packets += src.packets;
    dst.sessions_created += src.sessions_created;
    dst.sessions_expired += src.sessions_expired;
    dst.sessions_evicted += src.sessions_evicted;
    dst.illegal_tcp_events += src.illegal_tcp_events;
    dst.dropped_no_id += src.dropped_no_id;
}

/// 把 worker 的局部统计并入总统计（派发端自己的那几项不在这里）。
fn merge_worker_stats(dst: &mut AnalyzeStats, src: &AnalyzeStats) {
    dst.payload_start_unknown += src.payload_start_unknown;
    dst.non_finite_vectors += src.non_finite_vectors;
    dst.counter_mismatches += src.counter_mismatches;
    for (k, v) in &src.app_outcomes {
        *dst.app_outcomes.entry(*k).or_insert(0) += *v;
    }
    add_manager_stats(&mut dst.session, &src.session);
    dst.tcp.merge(&src.tcp);
}

fn new_stats<R: Read>(
    reader: &PcapReader<R>,
    workers: usize,
    opts: &AnalyzeOptions,
) -> AnalyzeStats {
    AnalyzeStats {
        linktype: reader.linktype(),
        linktype_name: reader.header().linktype_name(),
        workers,
        dpi_enabled: !opts.dpi.is_off(),
        dpi_intensity: opts.dpi.intensity.as_str(),
        dpi_modules_disabled: opts.dpi.disabled_module_count(),
        ..Default::default()
    }
}

/// 收尾：定 `records`/`sorted_by_key`，并跑那几条「输出不可信」的硬条件。
/// 单线程与分片两条路都走这里 —— 自检只有一份，才不会被绕过。
fn finalize(
    records: Vec<FlowRecord>,
    mut stats: AnalyzeStats,
) -> Result<(Vec<FlowRecord>, AnalyzeStats), String> {
    stats.records = records.len();
    stats.sorted_by_key = records.windows(2).all(|w| w[0].key <= w[1].key);

    let mut problems: Vec<String> = Vec::new();
    if stats.non_finite_vectors != 0 {
        problems.push(format!(
            "{} 条记录的特征向量含非有限值",
            stats.non_finite_vectors
        ));
    }
    if stats.counter_mismatches != 0 {
        problems.push(format!(
            "{} 条记录的会话计数与特征计数不一致",
            stats.counter_mismatches
        ));
    }
    if !stats.sorted_by_key {
        problems.push("输出未按会话键排序（不可复现）".to_string());
    }
    if !problems.is_empty() {
        return Err(problems.join("；"));
    }
    Ok((records, stats))
}

/// 当解码失败的原因是“非 IP 帧”时，再尝试一次 ARP 解析。
///
/// 为什么不把 ARP 塞进 `decode_frame`：那条路返回的是 `DecodedFrame`，必须有
/// IP 五元组；ARP 没有端口，硬造一个键会污染流表。这里只在**已确定不是 IP**
/// 的分支上旁路解析，ARP 统计与流统计因此不会互相冒充。
///
/// 只对 EtherType=ARP/RARP 尝试：普通 IPv4 解码失败（如坏 IHL）不应被记成
/// “坏 ARP”，否则 `non_arp` 会变成一个没有意义的垃圾桶。
fn note_arp_frame(
    stats: &mut ArpStats,
    e: crate::channel::DecodeError,
    frame: &[u8],
    capture_truncated: bool,
    link: LinkLayer,
) {
    let is_arp =
        |ether_type: u16| ether_type == arp::ETHERTYPE_ARP || ether_type == arp::ETHERTYPE_RARP;
    let looks_like_arp = match link {
        LinkLayer::Ethernet => match e {
            crate::channel::DecodeError::NonIpEtherType { ether_type } => is_arp(ether_type),
            // VLAN 层数超限时 decode 只报“超限”，不给出内层 EtherType；这里再扫一遍
            // 标签链确认里面是不是 ARP，避免把超嵌套的 IPv4 误记成坏 ARP。
            crate::channel::DecodeError::TooManyVlanTags { .. } => arp::is_arp_ethertype(frame),
            _ => false,
        },
        LinkLayer::LinuxSll | LinkLayer::LinuxSll2 => {
            arp::linux_sll_ethertype(frame, link == LinkLayer::LinuxSll2).is_some_and(is_arp)
        }
    };
    if !looks_like_arp {
        return;
    }
    let parsed = match link {
        LinkLayer::Ethernet => arp::parse_ethernet(frame),
        LinkLayer::LinuxSll => arp::parse_linux_sll(frame, false),
        LinkLayer::LinuxSll2 => arp::parse_linux_sll(frame, true),
    };
    match parsed {
        Ok(mut f) => {
            f.capture_truncated = capture_truncated;
            stats.observe(&f);
        }
        Err(ae) => stats.record_error(ae),
    }
}

/// 当解码成功且协议号是 ICMP/ICMPv6 时，展开报文级统计。
///
/// 不把 type/code 写进 `FlowRecord`：加键会改变已实测的落盘字节与列式契约，
/// 那必须是一个单独批次；ARP 已经确立了“基础协议走统计行 + 独立事件流”的先例。
/// 切片按 `ip_payload_len` 截取，抓包少了字节时只解析实有部分并记 capture_truncated。
fn note_icmp_frame(stats: &mut IcmpStats, d: &DecodedFrame, frame: &[u8], capture_truncated: bool) {
    let family = match d.key.proto.number() {
        icmp::IPPROTO_ICMP => IcmpFamily::V4,
        icmp::IPPROTO_ICMPV6 => IcmpFamily::V6,
        _ => return,
    };
    let want = d.ip_payload_len as usize;
    let available = frame.get(d.l4_offset..).unwrap_or(&[]);
    let payload = &available[..available.len().min(want)];
    let context = icmp::ChecksumContext {
        source: d.key.src_ip,
        destination: d.key.dst_ip,
        complete: !capture_truncated && payload.len() == want,
    };
    match icmp::parse_with_context(payload, family, Some(context)) {
        Ok(mut f) => {
            f.capture_truncated = capture_truncated || payload.len() < want;
            stats.observe(&f);
        }
        Err(e) => stats.record_error(e),
    }
}

/// 当解码成功且协议号是 GRE 时，展开报文级统计。内层协议只记录类型与头字段，
/// **不**把内层 IP 塞回流水线：一个 GRE 包只能证明封装存在，不能证明内层会话。
fn note_gre_frame(stats: &mut GreStats, d: &DecodedFrame, frame: &[u8], capture_truncated: bool) {
    if d.key.proto.number() != gre::IPPROTO_GRE {
        return;
    }
    let want = d.ip_payload_len as usize;
    let available = frame.get(d.l4_offset..).unwrap_or(&[]);
    let payload = &available[..available.len().min(want)];
    let complete = !capture_truncated && payload.len() == want;
    match gre::parse_with_complete(payload, complete) {
        Ok(mut f) => {
            f.capture_truncated = capture_truncated || payload.len() < want;
            stats.observe(&f);
        }
        Err(e) => stats.record_error(e),
    }
}

/// 当解码成功且外层是 VXLAN 的 UDP 端口时，展开报文级统计。
///
/// 端口只是触发条件，结构判定仍由 `vxlan::parse_with_complete` 完成；内层
/// 以太网/IP 头只记录可见字段，**不**把内层 IP 塞回流水线。
fn note_vxlan_frame(
    stats: &mut VxlanStats,
    d: &DecodedFrame,
    frame: &[u8],
    capture_truncated: bool,
) {
    if d.key.proto.number() != 17
        || (!vxlan::is_vxlan_port(d.key.src_port) && !vxlan::is_vxlan_port(d.key.dst_port))
    {
        return;
    }
    let Some(payload) = l4_payload(frame, d) else {
        stats.record_error(vxlan::VxlanError::TruncatedHeader { need: 8, got: 0 });
        return;
    };
    let complete = !capture_truncated && !payload.is_truncated();
    match vxlan::parse_with_complete(payload.bytes, complete) {
        Ok(mut f) => {
            f.capture_truncated = capture_truncated || payload.is_truncated();
            stats.observe(&f);
        }
        Err(e) => stats.record_error(e),
    }
}

/// 解码一条 pcap 记录，必要时先做 IP 分片重组。
///
/// 返回 `None` 表示这条记录已被分片表吸收/拒绝，不能进入流表。这里把
/// “先重组、再解帧”的顺序写在一个地方：单线程与多 worker 的派发端必须完全一致，
/// 否则同一条分片在两条路径上会得到不同的记录。
fn decode_record(
    ipfrag: &mut IpReassembler,
    stats: &mut AnalyzeStats,
    rec: PcapRecord,
    link: LinkLayer,
) -> Option<DecodedPacket> {
    let truncated = rec.is_truncated();
    match ipfrag.push(&rec.data, link, rec.timestamp_us, truncated) {
        PushOutcome::Pending(_) => None,
        PushOutcome::Dropped { error, .. } => {
            *stats.decode_errors.entry(error.code()).or_insert(0) += 1;
            None
        }
        PushOutcome::Complete(d) => {
            let decoded = match decode_frame_with_link(&d.frame, link) {
                Ok(v) => v,
                Err(e) => {
                    *stats.decode_errors.entry(e.code()).or_insert(0) += 1;
                    note_arp_frame(&mut stats.arp, e, &d.frame, false, link);
                    return None;
                }
            };
            stats.packets_decoded += 1;
            note_icmp_frame(&mut stats.icmp, &decoded, &d.frame, false);
            note_gre_frame(&mut stats.gre, &decoded, &d.frame, false);
            note_vxlan_frame(&mut stats.vxlan, &decoded, &d.frame, false);
            Some(DecodedPacket {
                data: d.frame,
                decoded,
                timestamp_us: d.timestamp_us,
            })
        }
        PushOutcome::NotFragment => {
            let decoded = match decode_frame_with_link(&rec.data, link) {
                Ok(v) => v,
                Err(e) => {
                    // 解码失败**不中断**：省网抓包里畸形帧是常态。
                    *stats.decode_errors.entry(e.code()).or_insert(0) += 1;
                    note_arp_frame(&mut stats.arp, e, &rec.data, truncated, link);
                    return None;
                }
            };
            stats.packets_decoded += 1;
            note_icmp_frame(&mut stats.icmp, &decoded, &rec.data, truncated);
            note_gre_frame(&mut stats.gre, &decoded, &rec.data, truncated);
            note_vxlan_frame(&mut stats.vxlan, &decoded, &rec.data, truncated);
            Some(DecodedPacket {
                data: rec.data,
                decoded,
                timestamp_us: rec.timestamp_us,
            })
        }
    }
}

/// 把收尾时的未完成分片计入统计。非首片仍然单独记到既有的
/// `decode.non_initial_fragment`：它单独看确实没有四层头，不能因为“曾经尝试
/// 重组”就假装它被解码过。完整数据报不会产生这个错误。
fn finish_ipfrag(stats: &mut AnalyzeStats, ipfrag: &mut IpReassembler) {
    let fin = ipfrag.finish();
    stats.ipfrag = ipfrag.stats().clone();
    if fin.non_initial_fragments > 0 {
        *stats
            .decode_errors
            .entry("decode.non_initial_fragment")
            .or_insert(0) += fin.non_initial_fragments;
    }
}

/// 就地（单线程）驱动：与历史行为**逐字一致** —— 顺序、会话 id、统计口径都不变。
fn drive_inline<R: Read>(
    mut reader: PcapReader<R>,
    opts: &AnalyzeOptions,
    link: LinkLayer,
) -> Result<(Vec<FlowRecord>, AnalyzeStats), String> {
    let mut stats = new_stats(&reader, 1, opts);
    let mut state = PipelineState::new(opts);
    let mut ipfrag = IpReassembler::new(IpFragConfig::default());
    // 采样器在**每包路径之前**、且只有这一个实例：放进 worker 会让 N 个 worker 各采一遍。
    let mut sampler = match opts.sampling {
        Some(cfg) => Some(crate::sampling::Sampler::new(cfg)?),
        None => None,
    };
    loop {
        let rec = match reader.next_record() {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => return Err(format!("读第 {} 条记录失败：{e}", stats.packets_read + 1)),
        };
        stats.packets_read += 1;
        if rec.is_truncated() {
            stats.truncated_captures += 1;
        }
        let Some(pkt) = decode_record(&mut ipfrag, &mut stats, rec, link) else {
            continue;
        };
        if let Some(sp) = sampler.as_mut() {
            // 传 `canonical()` 键：TCP 两个方向必须得到同一个决定，否则进表的是半条会话。
            if !sp.keep(&pkt.decoded.key.canonical()) {
                continue;
            }
        }
        state.observe(&pkt, opts);
    }
    finish_ipfrag(&mut stats, &mut ipfrag);
    let records = state.finish(&mut stats);
    stats.sampling = sampler.map(|s| s.stats());
    stats.worker_flows = vec![records.len()];
    finalize(records, stats)
}

/// 分片驱动：派发端（本线程）读盘 + 解帧 + **定序** + 按流键分片，
/// `workers` 个 worker 各自持有私有状态、彼此零共享。
fn drive_sharded<R: Read>(
    mut reader: PcapReader<R>,
    opts: &AnalyzeOptions,
    workers: usize,
    link: LinkLayer,
) -> Result<(Vec<FlowRecord>, AnalyzeStats), String> {
    let mut stats = new_stats(&reader, workers, opts);
    let mut senders = Vec::with_capacity(workers);
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let (tx, rx) = mpsc::sync_channel::<DecodedPacket>(SHARD_QUEUE_LEN);
        senders.push(tx);
        let opts = opts.clone();
        handles.push(thread::spawn(move || {
            let mut state = PipelineState::new(&opts);
            while let Ok(pkt) = rx.recv() {
                state.observe(&pkt, &opts);
            }
            let mut wstats = AnalyzeStats::default();
            let records = state.finish(&mut wstats);
            (records, wstats)
        }));
    }

    // ---- 派发 ----
    // 会话 id 在这里分配（按**首次出现顺序**），而不是让各 worker 自己编号：
    // worker 各自的计数器会互相冲突，编号还会随分片结果变化。派发端看到的是
    // 同一个包流，所以它分出来的 id 与 worker 数无关。
    let mut ids: HashMap<FlowKey, u64> = HashMap::new();
    let mut next_id: u64 = 1;
    let mut ipfrag = IpReassembler::new(IpFragConfig::default());
    // 采样决定**必须在派发端做**：放进 worker 就是每个 worker 各采一遍（实际采样率
    // 被放大 N×），而且各 worker 只看到自己那部分包序，`PerPacket` 模式还会不一致。
    // 又因为 `FlowConsistent` 的决定只依赖流键（与包序无关），所以"多线程采到的流集合"
    // 与"单线程采到的"逐字节相同 —— 这是 `--workers` 一致性不变量的前提。
    let mut sampler = match opts.sampling {
        Some(cfg) => Some(crate::sampling::Sampler::new(cfg)?),
        None => None,
    };
    loop {
        let rec = match reader.next_record() {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => return Err(format!("读第 {} 条记录失败：{e}", stats.packets_read + 1)),
        };
        stats.packets_read += 1;
        if rec.is_truncated() {
            stats.truncated_captures += 1;
        }
        let Some(pkt) = decode_record(&mut ipfrag, &mut stats, rec, link) else {
            continue;
        };
        let key = pkt.decoded.key.canonical();
        if let Some(sp) = sampler.as_mut() {
            if !sp.keep(&key) {
                continue; // 未采到的包**不登记会话 id、不入分片**：id 顺序只看采样后的流集合
            }
        }
        if !ids.contains_key(&key) {
            ids.insert(key, next_id);
            next_id += 1;
        }
        let shard = shard_of(&key, workers);
        senders[shard]
            .send(pkt)
            .map_err(|_| "内部错误：分片 worker 在派发完成前退出".to_string())?;
    }
    finish_ipfrag(&mut stats, &mut ipfrag);
    drop(senders);

    // ---- 收拢 ----
    let mut records: Vec<FlowRecord> = Vec::new();
    for h in handles {
        let (mut rs, wstats) = h
            .join()
            .map_err(|_| "内部错误：分片 worker panic".to_string())?;
        stats.worker_flows.push(wstats.records);
        merge_worker_stats(&mut stats, &wstats);
        records.append(&mut rs);
    }
    stats.sampling = sampler.map(|s| s.stats());
    // 与单线程同一个排序口径：按规范键升序（`sessions_sorted` 用的也是它）。
    records.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    for r in records.iter_mut() {
        match ids.get(&r.key) {
            Some(id) => r.session_id = *id,
            None => {
                return Err(format!(
                    "内部错误：会话键 {:?} 没有在派发端登记（分片与记录装配不一致）",
                    r.key
                ))
            }
        }
    }
    finalize(records, stats)
}

/// 每个会话的 DPI 探针：只对每个方向的**第一个非空载荷**做一次识别。
#[derive(Debug, Default, Clone)]
pub struct Probe {
    fwd: Option<AppInfo>,
    rev: Option<AppInfo>,
}

impl Probe {
    fn slot(&mut self, side: Side) -> &mut Option<AppInfo> {
        match side {
            Side::A => &mut self.fwd,
            Side::B => &mut self.rev,
        }
    }

    fn is_done(&self, side: Side) -> bool {
        match side {
            Side::A => self.fwd.is_some(),
            Side::B => self.rev.is_some(),
        }
    }

    /// 取一个结论。顺序是明确写定的（不是"哪个先到算哪个"）：
    /// 先看正向是否已识别，再看反向；两侧都没有"已识别"时，再看哪一侧至少被检查过
    /// （正向优先）。同一份 pcap 跑两次必须得到同一条记录，因此不能依赖到达顺序。
    pub fn resolve(&self) -> AppInfo {
        for slot in [&self.fwd, &self.rev] {
            if let Some(info) = slot {
                if info.is_identified() {
                    return info.clone();
                }
            }
        }
        for slot in [&self.fwd, &self.rev] {
            if let Some(info) = slot {
                return info.clone();
            }
        }
        AppInfo::not_inspected()
    }
}

/// 跑完整条流水线。`reader` 必须是经典 pcap。
///
/// 返回 `(按会话键排序的记录, 统计)`。以下情况直接返回 `Err`（都是"输出不可信"
/// 的硬条件，不是警告）：输入不可读、链路层不是以太网、特征含非有限值、
/// 会话计数与特征计数不一致。
pub fn analyze_pcap<R: Read>(
    reader: R,
    opts: &AnalyzeOptions,
) -> Result<(Vec<FlowRecord>, AnalyzeStats), String> {
    analyze_pcap_with(reader, opts, 1)
}

/// 带并行度的入口。
///
/// `workers <= 1` 走**就地**路径（与历史行为逐字一致）；`workers > 1` 走静态分片
/// 路径：派发端单线程读盘/解帧，worker 各自持有私有的流表、会话、特征与 DPI 探针。
///
/// 两条必须写下来的约束（否则下一个人会把它们当成实现细节而改回去）：
///
/// 1. **分片按 `key.canonical()`**（方向无关）。按原始五元组分片会把一条会话的
///    两个方向分到不同 worker，于是各自只看到半条会话 —— 记录数翻倍而没人报错。
/// 2. **`workers > 1` 时会话 id 由派发端按「首次出现顺序」统一分配**，与 worker 数
///    无关；本模式**每个 worker 各自持有 `max_sessions` 额度**（总容量 = N × 上限）。
///    因此前提是容量充足：一旦发生逐出或 id 耗尽，各 worker 的存活集合本就会不同，
///    此时「与 `--workers 1` 输出一致」不再成立（`workers = 1` 保持历史语义不变）。
///
/// 派发端是这条路的**上限**：读盘 + 解帧 + 分片 + 入队都在它身上，因此离线路径的
/// 加速比不可能等于核数。真正要线性的是按队列分环（每个 worker 一个环，CYS-PKT-009），
/// 那时连派发端都不需要。
pub fn analyze_pcap_with<R: Read>(
    reader: R,
    opts: &AnalyzeOptions,
    workers: usize,
) -> Result<(Vec<FlowRecord>, AnalyzeStats), String> {
    let workers = workers.max(1);
    let reader = PcapReader::new(reader).map_err(|e| format!("解析 pcap 头失败：{e}"))?;
    let link = LinkLayer::from_linktype(reader.linktype()).ok_or_else(|| {
        format!(
            "链路层类型 {}（{}）暂不支持；本流水线只解 Ethernet/Linux SLL/SLL2。\
             可先转换：`tshark -F pcap -r in -w out.pcap`（或 editcap -T ether）",
            reader.linktype(),
            reader.header().linktype_name()
        )
    })?;
    if workers == 1 {
        drive_inline(reader, opts, link)
    } else {
        drive_sharded(reader, opts, workers, link)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcapfile::LINKTYPE_ETHERNET;

    /// 构造一个最小 pcap（小端、微秒），只用来测错误路径与参数传递。
    fn tiny_pcap(linktype: u32, frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&linktype.to_le_bytes());
        for (i, f) in frames.iter().enumerate() {
            out.extend_from_slice(&1_700_000_000u32.to_le_bytes());
            out.extend_from_slice(&(i as u32 * 1000).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    /// 一条 IPv4/TCP 帧（20 字节 TCP 头，无选项）。IP 校验和不参与解码，留 0。
    fn tcp_frame(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 1]); // seq
        tcp.extend_from_slice(&[0, 0, 0, 0]); // ack
        tcp.push(5 << 4); // data offset = 5 words
        tcp.push(flags);
        tcp.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]); // window / checksum / urgent
        tcp.extend_from_slice(payload);
        l3_frame(src, dst, 6, &tcp)
    }

    /// 一条带显式序号/确认号的 IPv4/TCP 帧（用于重组类用例）。
    fn tcp_frame_seq(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&ack.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(flags);
        tcp.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        tcp.extend_from_slice(payload);
        l3_frame(src, dst, 6, &tcp)
    }

    /// 一条 IPv4/UDP 帧。
    fn udp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum
        udp.extend_from_slice(payload);
        l3_frame(src, dst, 17, &udp)
    }

    /// 一条 Ethernet ARP 请求/应答（无 VLAN）。
    fn arp_frame(op: u16, sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4]) -> Vec<u8> {
        let mut f = vec![0xffu8; 12]; // broadcast dst + arbitrary src
        f.extend_from_slice(&0x0806u16.to_be_bytes());
        f.extend_from_slice(&1u16.to_be_bytes()); // HTYPE Ethernet
        f.extend_from_slice(&0x0800u16.to_be_bytes()); // PTYPE IPv4
        f.push(6);
        f.push(4);
        f.extend_from_slice(&op.to_be_bytes());
        f.extend_from_slice(&sha);
        f.extend_from_slice(&spa);
        f.extend_from_slice(&tha);
        f.extend_from_slice(&tpa);
        f
    }

    /// 一条 IPv4/ICMP 帧；`body` 是公共头之后的字节。
    fn icmp_v4(
        src: [u8; 4],
        dst: [u8; 4],
        ty: u8,
        code: u8,
        rest: [u8; 4],
        body: &[u8],
    ) -> Vec<u8> {
        let mut p = vec![ty, code, 0, 0];
        p.extend_from_slice(&rest);
        p.extend_from_slice(body);
        l3_frame(src, dst, 1, &p)
    }

    /// 一条 IPv4/GRE 帧，内层带一个 IPv4 头。
    fn gre_v4(inner_src: [u8; 4], inner_dst: [u8; 4], proto: u8) -> Vec<u8> {
        let mut gre = vec![0, 0, 0x08, 0x00]; // flags=0, protocol=IPv4
        gre.push(0x45);
        gre.push(0x00);
        gre.extend_from_slice(&40u16.to_be_bytes());
        gre.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
        gre.extend_from_slice(&inner_src);
        gre.extend_from_slice(&inner_dst);
        l3_frame([192, 0, 2, 1], [192, 0, 2, 2], 47, &gre)
    }

    /// 一条外层 IPv4/UDP 4789 的 VXLAN 帧，内层是 IPv4/ICMP 头。
    ///
    /// 三个内层地址由调用方给，用来证明“不同内层 IP 仍只有一条外层流”。
    fn vxlan_v4(vni: u32, inner_src: [u8; 4], inner_dst: [u8; 4]) -> Vec<u8> {
        let mut inner = vec![0u8; 12]; // 内层 MAC
        inner.extend_from_slice(&0x0800u16.to_be_bytes());
        inner.push(0x45);
        inner.push(0);
        inner.extend_from_slice(&28u16.to_be_bytes()); // 20 + 8
        inner.extend_from_slice(&[0, 0, 0x40, 0, 64, 1, 0, 0]);
        inner.extend_from_slice(&inner_src);
        inner.extend_from_slice(&inner_dst);
        inner.extend_from_slice(&[8, 0, 0, 0, 0, 1, 0, 1]); // ICMP echo
        let mut payload = vec![0x08, 0, 0, 0];
        payload.extend_from_slice(&vni.to_be_bytes()[1..]);
        payload.push(0);
        payload.extend_from_slice(&inner);
        udp_frame([192, 0, 2, 1], [192, 0, 2, 2], 55555, 4789, &payload)
    }

    /// 非法 VXLAN：I 位为 0，但外层五元组仍然可解。
    fn vxlan_missing_i() -> Vec<u8> {
        let mut payload = vec![0x00, 0, 0, 0, 0, 0, 0, 1];
        payload.extend_from_slice(&[0u8; 14]); // 一个最短内层以太头，避免被内层截断抢先
        udp_frame([192, 0, 2, 1], [192, 0, 2, 2], 55555, 4789, &payload)
    }

    fn l3_frame(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
        let total = 20 + l4.len();
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, proto, 0x00, 0x00]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(l4);
        let mut frame = vec![0u8; 12]; // MAC
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame
    }

    /// `flows` 条完整握手的 TCP 流 + 1 条中途接入的 TCP 流 + 1 条 UDP 流 + 1 个畸形帧。
    ///
    /// 为什么要这么多流：分片并行只在「有活可分」时才被真正检验 ——
    /// 一个两包的 pcap 无论几个 worker 都会得出同一条记录，那样的测试什么都没验。
    fn multi_flow_pcap(flows: u16) -> Vec<u8> {
        let mut frames: Vec<Vec<u8>> = Vec::new();
        for i in 0..flows {
            let c = [10, 0, (i / 256) as u8, (i % 256) as u8];
            let srv = [10, 1, 0, 1];
            let sport = 20_000 + i;
            frames.push(tcp_frame(c, srv, sport, 443, 0x02, &[])); // SYN
            frames.push(tcp_frame(srv, c, 443, sport, 0x12, &[])); // SYN-ACK
            frames.push(tcp_frame(
                c,
                srv,
                sport,
                443,
                0x18,
                b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            ));
            frames.push(tcp_frame(
                srv,
                c,
                443,
                sport,
                0x18,
                b"HTTP/1.1 200 OK\r\n\r\n",
            ));
            frames.push(tcp_frame(c, srv, sport, 443, 0x11, &[])); // FIN
        }
        // 中途接入（没见过握手）：产出 adopted_midstream 的记录
        frames.push(tcp_frame(
            [10, 2, 0, 1],
            [10, 1, 0, 2],
            33_333,
            80,
            0x18,
            b"mid",
        ));
        // 非 TCP：会话状态必须是 None 而不是 Closed
        frames.push(udp_frame(
            [10, 3, 0, 1],
            [10, 3, 0, 2],
            5_000,
            53,
            b"\x00\x01\x01\x00",
        ));
        // 解不出帧的垃圾：解码失败要计入派发端统计，且不能打断派发
        frames.push(vec![0u8; 10]);
        tiny_pcap(LINKTYPE_ETHERNET, &frames)
    }

    /// DNS/TCP 的**主流水线重组**：长度帧被拆到两个乱序段里，仍必须在记录上
    /// 得到 `dns`/`identified`，而不是退回单包弱判定或 unknown。
    ///
    /// 这条测试与 `pipeline::dns_tcp` 的单元测试分工不同：单元测试直接喂
    /// `TcpSegment`，这里验证的是真实 pcap 路径上的序号解析、双向会话、
    /// probe 落位与记录输出是否接对 —— 接错时单测可以全绿而 CLI 仍是 need_more。
    #[test]
    fn segmented_dns_tcp_is_reassembled_before_identification() {
        let query: &[u8] = &[
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        let mut body = (query.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(query);

        let response: &[u8] = &[
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0,
            1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 42,
        ];
        let mut resp = (response.len() as u16).to_be_bytes().to_vec();
        resp.extend_from_slice(response);

        let (c, s) = ([192, 0, 2, 1], [198, 51, 100, 2]);
        let frames = vec![
            tcp_frame_seq(c, s, 40_000, 53, 1_000, 0, 0x02, &[]),
            tcp_frame_seq(s, c, 53, 40_000, 5_000, 1_001, 0x12, &[]),
            tcp_frame_seq(c, s, 40_000, 53, 1_001, 5_001, 0x10, &[]),
            // 先到尾部、后到头部：覆盖"洞被填上"的路径。
            tcp_frame_seq(c, s, 40_000, 53, 1_001 + 9, 5_001, 0x18, &body[9..]),
            tcp_frame_seq(c, s, 40_000, 53, 1_001, 5_001, 0x18, &body[..9]),
            tcp_frame_seq(
                s,
                c,
                53,
                40_000,
                5_001,
                1_001 + body.len() as u32,
                0x18,
                &resp[..10],
            ),
            tcp_frame_seq(
                s,
                c,
                53,
                40_000,
                5_011,
                1_001 + body.len() as u32,
                0x18,
                &resp[10..],
            ),
        ];
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &frames);
        let (records, stats) = analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 1)
            .expect("流水线应能处理 DNS/TCP");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.app.outcome, "identified", "{:?}", record.app);
        assert_eq!(record.app.app, Some(crate::dpi::AppId::Dns));
        assert_eq!(record.app.confidence, Some(crate::dpi::Confidence::High));
        assert_eq!(record.app.bytes_inspected, body.len());
        assert_eq!(stats.counter_mismatches, 0);

        // 分片不能改变结论；这条流只有一个会话，2 个 worker 也必须逐字节一致。
        let (sharded, _) =
            analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 2).expect("分片");
        assert_eq!(sharded, records);
        assert_eq!(jsonl(&sharded), jsonl(&records));
    }

    /// 全局关闭必须产出 `not_inspected`，而不是把"没看"混进 `unknown`。
    /// 这条同时验证关闭后仍能正常出记录（DPI 是增强项，不是流水线的前置条件）。
    #[test]
    fn dpi_off_writes_not_inspected_instead_of_unknown() {
        let bytes = multi_flow_pcap(3);
        let mut opts = AnalyzeOptions::default();
        opts.dpi.intensity = crate::dpi::Intensity::Off;
        let (records, stats) = analyze_pcap_with(&bytes[..], &opts, 1).expect("off 模式应能分析");
        assert!(!records.is_empty());
        assert!(records.iter().all(|r| r.app.outcome == "not_inspected"));
        assert_eq!(stats.dpi_enabled, false);
        assert_eq!(stats.dpi_intensity, "off");
        assert_eq!(
            stats.app_outcomes.get("not_inspected").copied(),
            Some(records.len() as u64)
        );
        assert!(stats.app_outcomes.get("unknown").is_none());
    }

    /// 逐协议开关必须真的拦住对应检测器，而不是"识别完再过滤"。
    #[test]
    fn dpi_module_switch_suppresses_that_protocol() {
        let bytes = multi_flow_pcap(1);
        let mut opts = AnalyzeOptions::default();
        opts.dpi.modules.insert("http".to_string(), false);
        let (records, _) = analyze_pcap_with(&bytes[..], &opts, 1).expect("策略分析");
        assert!(
            records
                .iter()
                .all(|r| r.app.app != Some(crate::dpi::AppId::Http)),
            "HTTP 模块关闭后仍产出了 HTTP 结论: {:?}",
            records.iter().map(|r| &r.app).collect::<Vec<_>>()
        );
        let mut opts = AnalyzeOptions::default();
        opts.dpi.modules.insert("dns".to_string(), false);
        let (records, _) = analyze_pcap_with(&bytes[..], &opts, 1).expect("策略分析");
        assert!(records
            .iter()
            .all(|r| r.app.app != Some(crate::dpi::AppId::Dns)));
    }

    /// 强度必须改变真实拷贝窗口：basic 128 / standard 512 / deep ≥4096。
    #[test]
    fn dpi_intensity_changes_inspect_window() {
        let mut payload = b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: ".to_vec();
        payload.extend(std::iter::repeat(b'a').take(600 - payload.len()));
        payload.extend_from_slice(b"\r\n\r\n");
        let frames = vec![
            tcp_frame_seq(
                [10, 9, 0, 1],
                [10, 9, 0, 2],
                40_000,
                80,
                1_000,
                0,
                0x02,
                &[],
            ),
            tcp_frame_seq(
                [10, 9, 0, 2],
                [10, 9, 0, 1],
                80,
                40_000,
                2_000,
                1_001,
                0x12,
                &[],
            ),
            tcp_frame_seq(
                [10, 9, 0, 1],
                [10, 9, 0, 2],
                40_000,
                80,
                3_000,
                1_001,
                0x18,
                &payload,
            ),
        ];
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &frames);
        let mut basic = AnalyzeOptions::default();
        basic.dpi.intensity = crate::dpi::Intensity::Basic;
        let (records, stats) = analyze_pcap_with(&bytes[..], &basic, 1).expect("basic");
        assert_eq!(stats.dpi_intensity, "basic");
        assert_eq!(records[0].app.bytes_inspected, 128);
        let (records, _) =
            analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 1).expect("standard");
        assert_eq!(records[0].app.bytes_inspected, 512);
        let mut deep = AnalyzeOptions::default();
        deep.dpi.intensity = crate::dpi::Intensity::Deep;
        let (records, _) = analyze_pcap_with(&bytes[..], &deep, 1).expect("deep");
        assert_eq!(records[0].app.bytes_inspected, payload.len());
        assert_eq!(records[0].app.outcome, "identified");
    }

    fn jsonl(records: &[FlowRecord]) -> String {
        let mut out = Vec::new();
        crate::record::write_jsonl(&mut out, records).expect("写 JSONL 失败");
        String::from_utf8(out).expect("JSONL 必须是 UTF-8")
    }

    /// **本轮改动的核心不变量**：worker 数不改变输出 —— 一条记录、一个字节都不变。
    ///
    /// 这条测试是「每核一张独立表」敢接进消费路径的前提：分片只允许改变**谁算的**，
    /// 不允许改变**算出来的东西**。它同时覆盖了方向分片（一条流的两个方向必须同分片）、
    /// 畸形帧（派发端计数）、非 TCP 会话（状态 None）、DPI 首包识别（应用分布合并）。
    #[test]
    fn worker_count_does_not_change_the_records() {
        let bytes = multi_flow_pcap(12);
        let opts = AnalyzeOptions::default();
        let (base, base_stats) = analyze_pcap_with(&bytes[..], &opts, 1).expect("单线程");
        assert!(
            base.len() > 4,
            "样本必须产出足够多的记录，否则这条测试什么都没验：{} 条",
            base.len()
        );
        assert_eq!(base_stats.workers, 1);
        assert_eq!(base_stats.worker_flows, vec![base.len()]);
        assert_eq!(
            base_stats.decode_error_count(),
            1,
            "垃圾帧要被计入派发端统计"
        );
        // **绝对口径**：只有「两条路互相比」是不够的 —— 同一个错犯在两条路上就看不见
        // （实测：把统计合并整行删掉后，互比仍然相等）。这三条断言的是「应该是什么」：
        //   1. 每个解码成功的包恰好被 observe 一次（漏合并会让它比 packets_decoded 小）；
        //   2. 每条记录背后恰好一条会话（记录只能来自会话）；
        //   3. 应用识别分布的总数等于记录数（漏合并 app_outcomes 会让它偏小）。
        assert_eq!(
            base_stats.session.packets, base_stats.packets_decoded,
            "单线程：有包没被喂进流水线（会话统计与解帧数对不上）"
        );
        assert_eq!(
            base_stats.session.sessions_created,
            base.len() as u64,
            "单线程：会话数与记录数对不上"
        );
        assert_eq!(
            base_stats.app_outcomes.values().sum::<u64>(),
            base.len() as u64,
            "单线程：应用识别分布的总数不等于记录数"
        );
        let want = jsonl(&base);

        for workers in [2usize, 3, 4, 8] {
            let (got, stats) = analyze_pcap_with(&bytes[..], &opts, workers).expect("分片");
            assert_eq!(got, base, "{workers} 个 worker 的记录与单线程不一致");
            assert_eq!(
                jsonl(&got),
                want,
                "{workers} 个 worker 的 JSONL 与单线程不逐字节一致"
            );
            assert_eq!(stats.workers, workers);
            assert_eq!(stats.worker_flows.len(), workers, "每个 worker 都要有账");
            assert_eq!(
                stats.worker_flows.iter().sum::<usize>(),
                got.len(),
                "各 worker 记录数之和必须等于总记录数"
            );
            // 派发端统计与合并后的统计都不能被分片改变
            assert_eq!(stats.packets_read, base_stats.packets_read);
            assert_eq!(stats.packets_decoded, base_stats.packets_decoded);
            assert_eq!(stats.decode_error_count(), base_stats.decode_error_count());
            assert_eq!(stats.session.packets, base_stats.session.packets);
            assert_eq!(
                stats.session.sessions_created,
                base_stats.session.sessions_created
            );
            assert_eq!(stats.app_outcomes, base_stats.app_outcomes);
            assert_eq!(stats.counter_mismatches, 0);
            assert_eq!(stats.non_finite_vectors, 0);
            assert!(stats.sorted_by_key);
            // 分片路径同样按绝对口径核一遍（合并漏项在这里现形）
            assert_eq!(
                stats.session.packets, stats.packets_decoded,
                "{workers} 个 worker：有包没被喂进流水线（统计合并漏项）"
            );
            assert_eq!(
                stats.session.sessions_created,
                got.len() as u64,
                "{workers} 个 worker：会话数与记录数对不上"
            );
            assert_eq!(
                stats.app_outcomes.values().sum::<u64>(),
                got.len() as u64,
                "{workers} 个 worker：应用识别分布的总数不等于记录数"
            );
        }
    }

    /// 分片必须**均衡**，而且要用「像真实流量那样的键」来测。
    ///
    /// 这条测试的键刻意复刻真实流量的形态：变化的字节在**前部**（源 IP、源端口），
    /// 尾部（目的端口 443 + 协议号 6）在一批流里完全相同。早期版本只验证「8 个分片
    /// 都被用到」，而它用的键把变化放在别的字节上，于是**漏掉了**「低位被恒定尾字节
    /// 钉死」这个缺陷：实测 20000 条真实流在 8 个 worker 上只用到 2 个，
    /// 2/4 个 worker 时全部挤在 0 号。因此这里必须同时断言均衡度，不能只断言「用到过」。
    #[test]
    fn shard_hash_is_stable_and_balanced_for_realistic_keys() {
        const FLOWS: u64 = 4_096;
        for workers in [2usize, 4, 8] {
            let mut counts = vec![0u64; workers];
            for f in 0..FLOWS as u64 {
                let src = [
                    10,
                    ((f >> 16) & 0xff) as u8,
                    ((f >> 8) & 0xff) as u8,
                    (f & 0xff) as u8,
                ];
                let k = FlowKey::new_ipv4(src, 1_024 + (f as u16), [10, 128, 0, 1], 443, 6);
                let shard = shard_of(&k, workers);
                assert_eq!(shard, shard_of(&k, workers), "同一键必须稳定落同一分片");
                counts[shard] += 1;
            }
            let fair = FLOWS / workers as u64;
            let min = *counts.iter().min().unwrap();
            let max = *counts.iter().max().unwrap();
            assert!(
                min >= fair / 2,
                "{workers} 个 worker 分片严重倾斜：最少的只有 {min} 条（公平值 {fair}），分布 {counts:?}"
            );
            assert!(
                max <= fair * 2,
                "{workers} 个 worker 分片严重倾斜：最多的有 {max} 条（公平值 {fair}），分布 {counts:?}"
            );
            assert_eq!(
                counts.iter().filter(|n| **n > 0).count(),
                workers,
                "{workers} 个 worker 里有分片一条流都没拿到：{counts:?}"
            );
        }
    }

    /// 一条会话的两个方向必须落同一分片：否则两边各建一套状态，
    /// 记录的包数会各算一半，而两边都不会报错（这正是不变量测试要拦的事）。
    #[test]
    fn both_directions_of_a_flow_share_one_shard() {
        let k = FlowKey::new_ipv4([10, 0, 0, 1], 1234, [10, 0, 0, 2], 443, 6);
        let rev = k.reverse();
        for n in [2usize, 3, 5, 8] {
            assert_eq!(
                shard_of(&k.canonical(), n),
                shard_of(&rev.canonical(), n),
                "{n} 个分片时两个方向落到了不同 worker"
            );
        }
    }

    /// 空抓包 + 多 worker：线程要能正常收尾（不能挂住），并且账要平。
    #[test]
    fn empty_capture_with_workers_terminates() {
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[]);
        let (records, stats) =
            analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 4).expect("空文件");
        assert!(records.is_empty());
        assert_eq!(stats.workers, 4);
        assert_eq!(stats.worker_flows, vec![0, 0, 0, 0]);
        assert_eq!(stats.packets_read, 0);
    }

    /// 所有包都解不出帧时，worker 一条记录也产不出，但派发端仍要如实计数。
    #[test]
    fn all_garbage_frames_are_counted_on_the_dispatch_side() {
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[vec![0u8; 10], vec![0u8; 12]]);
        let (records, stats) =
            analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 3).expect("垃圾帧");
        assert!(records.is_empty());
        assert_eq!(stats.packets_read, 2);
        assert_eq!(stats.packets_decoded, 0);
        assert_eq!(stats.decode_error_count(), 2);
        assert_eq!(stats.worker_flows, vec![0, 0, 0]);
    }

    #[test]
    fn linux_cooked_capture_is_decoded_as_ip_not_rejected() {
        let eth = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 0x02, &[]);
        let mut sll = Vec::new();
        sll.extend_from_slice(&0u16.to_be_bytes());
        sll.extend_from_slice(&1u16.to_be_bytes());
        sll.extend_from_slice(&6u16.to_be_bytes());
        sll.extend_from_slice(&[0u8; 8]);
        sll.extend_from_slice(&0x0800u16.to_be_bytes());
        sll.extend_from_slice(&eth[14..]);
        let bytes = tiny_pcap(crate::pcapfile::LINKTYPE_LINUX_SLL, &[sll]);
        let (records, stats) = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key.proto.number(), 6);
        assert_eq!(stats.packets_decoded, 1);
        assert_eq!(stats.linktype, crate::pcapfile::LINKTYPE_LINUX_SLL);
    }

    #[test]
    fn non_ethernet_linktype_is_rejected_with_a_conversion_hint() {
        let bytes = tiny_pcap(101, &[]); // LINKTYPE_RAW_IP
        let err = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap_err();
        assert!(err.contains("101"), "{err}");
        assert!(err.contains("tshark"), "必须给出可执行的转换办法：{err}");
    }

    #[test]
    fn empty_capture_yields_no_records_and_no_error() {
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[]);
        let (records, stats) =
            analyze_pcap(&bytes[..], &AnalyzeOptions::default()).expect("空文件");
        assert!(records.is_empty());
        assert_eq!(stats.packets_read, 0);
        assert_eq!(stats.records, 0);
        assert!(stats.sorted_by_key, "空序列视为有序");
        assert_eq!(stats.decode_error_count(), 0);
    }

    #[test]
    fn garbage_frame_is_counted_as_a_decode_error_and_does_not_abort() {
        // 10 字节的垃圾帧：解不出以太头，但流水线必须继续并如实计数。
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[vec![0u8; 10]]);
        let (records, stats) = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap();
        assert!(records.is_empty());
        assert_eq!(stats.packets_read, 1);
        assert_eq!(stats.packets_decoded, 0);
        assert_eq!(stats.decode_error_count(), 1);
        assert!(stats.decode_errors.contains_key("decode.truncated"));
    }

    #[test]
    fn arp_frames_are_counted_but_do_not_enter_the_flow_table() {
        let req = arp_frame(
            1,
            [0x02, 0, 0, 0, 0, 1],
            [192, 0, 2, 10],
            [0; 6],
            [192, 0, 2, 1],
        );
        let rep = arp_frame(
            2,
            [0x02, 0, 0, 0, 0, 2],
            [192, 0, 2, 1],
            [0x02, 0, 0, 0, 0, 1],
            [192, 0, 2, 10],
        );
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[req, rep]);
        let (records, stats) = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap();
        assert!(records.is_empty(), "ARP 没有五元组，不得伪造 FlowRecord");
        assert_eq!(stats.packets_read, 2);
        assert_eq!(stats.packets_decoded, 0);
        assert_eq!(stats.decode_error_count(), 2);
        assert_eq!(stats.arp.arp_frames, 2);
        assert_eq!(stats.arp.requests, 1);
        assert_eq!(stats.arp.replies, 1);
        assert_eq!(stats.arp.non_arp, 0, "ARP 帧不能被记成非 ARP");
        assert_eq!(stats.arp.malformed, 0);
        assert_eq!(stats.arp.truncated, 0);
    }

    #[test]
    fn arp_stats_are_identical_with_multiple_workers() {
        let req = arp_frame(
            1,
            [0x02, 0, 0, 0, 0, 1],
            [192, 0, 2, 10],
            [0; 6],
            [192, 0, 2, 1],
        );
        let tcp = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 0x02, &[]);
        let rep = arp_frame(
            2,
            [0x02, 0, 0, 0, 0, 2],
            [192, 0, 2, 1],
            [0x02, 0, 0, 0, 0, 1],
            [192, 0, 2, 10],
        );
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[req, tcp, rep]);
        let (one, s1) = analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 1).unwrap();
        let (three, s3) = analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 3).unwrap();
        assert_eq!(one, three, "worker 数不得改变 FlowRecord");
        assert_eq!(s1.arp, s3.arp, "ARP 统计必须与 worker 数无关");
        assert_eq!(s3.arp.arp_frames, 2);
        assert_eq!(s3.arp.requests, 1);
        assert_eq!(s3.arp.replies, 1);
    }

    #[test]
    fn icmp_frames_are_counted_and_keep_one_real_flow() {
        let req = icmp_v4(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            8,
            0,
            [0x12, 0x34, 0, 1],
            &[0xaa; 8],
        );
        let rep = icmp_v4(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            0,
            0,
            [0x12, 0x34, 0, 1],
            &[0xaa; 8],
        );
        let mut embedded = vec![0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 17, 0, 0];
        embedded.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        let unreachable = icmp_v4([10, 0, 0, 2], [10, 0, 0, 1], 3, 3, [0; 4], &embedded);
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[req, rep, unreachable]);
        let (records, stats) = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap();
        assert_eq!(records.len(), 1, "三个包属于同一条 ICMP 会话");
        assert_eq!(records[0].key.proto.number(), 1);
        assert_eq!(stats.icmp.icmp_frames, 3);
        assert_eq!(stats.icmp.v4, 3);
        assert_eq!(stats.icmp.echo_requests, 1);
        assert_eq!(stats.icmp.echo_replies, 1);
        assert_eq!(stats.icmp.destination_unreachable, 1);
        assert_eq!(stats.icmp.errors, 1);
        assert_eq!(stats.icmp.with_embedded, 1);
        assert_eq!(stats.icmp.truncated, 0);
        assert_eq!(stats.gre.gre_frames, 0);
    }

    #[test]
    fn gre_inner_ip_is_not_a_second_flow() {
        let frame = gre_v4([10, 0, 0, 1], [10, 0, 0, 2], 6);
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[frame]);
        let (records, stats) = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap();
        assert_eq!(records.len(), 1, "外层 GRE 一条流，内层 IP 不得另造会话");
        assert_eq!(records[0].key.proto.number(), 47);
        assert_eq!(stats.gre.gre_frames, 1);
        assert_eq!(stats.gre.version0, 1);
        assert_eq!(stats.gre.unkeyed, 1);
        assert_eq!(stats.gre.protocol_ipv4, 1);
        assert_eq!(stats.gre.inner_complete, 1);
        assert_eq!(stats.icmp.icmp_frames, 0);
    }

    #[test]
    fn vxlan_inner_ip_is_not_a_second_flow() {
        let a = vxlan_v4(100, [10, 0, 0, 1], [10, 0, 0, 2]);
        let b = vxlan_v4(200, [10, 0, 0, 3], [10, 0, 0, 4]);
        let bad = vxlan_missing_i();
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[a, b, bad]);
        let (records, stats) = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap();
        assert_eq!(records.len(), 1, "VXLAN 内层 IP 不得另造会话");
        assert_eq!(records[0].key.proto.number(), 17);
        assert_eq!(records[0].key.dst_port, 4789);
        assert_eq!(stats.vxlan.vxlan_frames, 2);
        assert_eq!(stats.vxlan.inner_ipv4, 2);
        assert_eq!(stats.vxlan.inner_complete, 2);
        assert_eq!(stats.vxlan.malformed, 1);
        assert_eq!(stats.vxlan.missing_i_flag, 1);
        assert_eq!(stats.vxlan.vni_zero, 0);
    }

    #[test]
    fn vxlan_stats_are_identical_with_multiple_workers() {
        let a = vxlan_v4(100, [10, 0, 0, 1], [10, 0, 0, 2]);
        let b = vxlan_v4(200, [10, 0, 0, 3], [10, 0, 0, 4]);
        let tcp = tcp_frame([10, 2, 0, 1], [10, 2, 0, 2], 40000, 80, 0x02, &[]);
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[a, b, tcp]);
        let (one, s1) = analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 1).unwrap();
        let (three, s3) = analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 3).unwrap();
        assert_eq!(one, three, "worker 数不得改变 FlowRecord");
        assert_eq!(s1.vxlan, s3.vxlan, "VXLAN 统计必须与 worker 数无关");
        assert_eq!(s3.vxlan.vxlan_frames, 2);
        assert_eq!(s3.vxlan.inner_ipv4, 2);
    }

    #[test]
    fn icmp_and_gre_stats_are_identical_with_multiple_workers() {
        let icmp = icmp_v4([10, 0, 0, 1], [10, 0, 0, 2], 8, 0, [0, 1, 0, 1], &[]);
        let gre = gre_v4([10, 1, 0, 1], [10, 1, 0, 2], 6);
        let tcp = tcp_frame([10, 2, 0, 1], [10, 2, 0, 2], 40000, 80, 0x02, &[]);
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[icmp, gre, tcp]);
        let (one, s1) = analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 1).unwrap();
        let (three, s3) = analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 3).unwrap();
        assert_eq!(one, three, "worker 数不得改变 FlowRecord");
        assert_eq!(s1.icmp, s3.icmp, "ICMP 统计必须与 worker 数无关");
        assert_eq!(s1.gre, s3.gre, "GRE 统计必须与 worker 数无关");
        assert_eq!(s3.icmp.icmp_frames, 1);
        assert_eq!(s3.gre.gre_frames, 1);
    }

    /// 一条 IPv4 分片帧。`offset` 单位是 8 字节；`more=true` 表示后面还有片。
    fn ipv4_frag_frame(
        src: [u8; 4],
        dst: [u8; 4],
        id: u16,
        proto: u8,
        offset: u16,
        more: bool,
        l4: &[u8],
    ) -> Vec<u8> {
        let total = 20 + l4.len();
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&id.to_be_bytes());
        let mut frag = offset & 0x1fff;
        if more {
            frag |= 0x2000;
        }
        ip.extend_from_slice(&frag.to_be_bytes());
        ip.extend_from_slice(&[64, proto, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(l4);
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame
    }

    fn udp_l4(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&sport.to_be_bytes());
        out.extend_from_slice(&dport.to_be_bytes());
        out.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(payload);
        out
    }

    /// 一条最小 DNS 查询（QDCOUNT=1），足以让 DPI 走 DNS 解析器。
    fn dns_query_l4(name: &str) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]);
        q
    }

    #[test]
    fn fragmented_udp_is_reassembled_into_one_dns_flow() {
        let query = dns_query_l4("example.com");
        let l4 = udp_l4(53000, 53, &query);
        // 故意逆序：尾片先到，首片后到；完成时必须只产生一条逻辑包。
        let last = ipv4_frag_frame([10, 0, 0, 1], [10, 0, 0, 2], 77, 17, 1, false, &l4[8..]);
        let first = ipv4_frag_frame([10, 0, 0, 1], [10, 0, 0, 2], 77, 17, 0, true, &l4[..8]);
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[last, first]);
        let (records, stats) = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap();
        assert_eq!(records.len(), 1, "两片合起来才是 1 条 DNS 流");
        let r = &records[0];
        assert_eq!(r.key.src_port, 53000);
        assert_eq!(r.key.dst_port, 53);
        assert_eq!(r.packets, 1, "两个分片只算一个逻辑包");
        assert_eq!(r.bytes as usize, l4.len(), "字节口径是完整 IP 载荷");
        assert_eq!(r.app.app.map(|a| a.as_str()), Some("dns"));
        assert_eq!(stats.packets_read, 2);
        assert_eq!(stats.packets_decoded, 1, "只有完整数据报进入解码");
        assert_eq!(stats.ipfrag.fragments_seen, 2);
        assert_eq!(stats.ipfrag.ipv4_fragments, 2);
        assert_eq!(stats.ipfrag.datagrams_completed, 1);
        assert_eq!(stats.ipfrag.datagrams_incomplete, 0);
        assert_eq!(stats.ipfrag.bytes_reassembled as usize, l4.len());
        assert!(stats.decode_errors.is_empty(), "完整重组不应报解码错误");
    }

    #[test]
    fn orphan_non_initial_fragment_does_not_create_a_fake_flow() {
        let orphan = ipv4_frag_frame([10, 0, 0, 1], [10, 0, 0, 2], 78, 17, 1, false, &[0xaa; 16]);
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[orphan]);
        let (records, stats) = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap();
        assert!(records.is_empty(), "缺首片不能合成一条端口为 0 的流");
        assert_eq!(stats.packets_decoded, 0);
        assert_eq!(stats.ipfrag.datagrams_incomplete, 1);
        assert_eq!(stats.ipfrag.pending_fragments_at_eof, 1);
        assert_eq!(
            stats.decode_errors.get("decode.non_initial_fragment"),
            Some(&1),
            "非首片单独看仍然解不出四层头，必须保留显式计数"
        );
    }

    #[test]
    fn overlapping_fragments_are_rejected_and_never_enter_the_flow_table() {
        let a = ipv4_frag_frame([10, 0, 0, 1], [10, 0, 0, 2], 79, 17, 0, true, &[1u8; 16]);
        let b = ipv4_frag_frame([10, 0, 0, 1], [10, 0, 0, 2], 79, 17, 1, false, &[2u8; 16]);
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[a, b]);
        let (records, stats) = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap();
        assert!(records.is_empty(), "重叠分片不得选择先到/后到语义");
        assert_eq!(stats.ipfrag.overlap_fragments, 1);
        assert_eq!(stats.ipfrag.datagrams_malformed, 1);
        assert_eq!(stats.decode_errors.get("ipfrag.overlap"), Some(&1));
    }

    #[test]
    fn ipfrag_stats_and_records_are_identical_with_multiple_workers() {
        let query = dns_query_l4("example.com");
        let l4 = udp_l4(53001, 53, &query);
        let last = ipv4_frag_frame([10, 0, 0, 1], [10, 0, 0, 2], 80, 17, 1, false, &l4[8..]);
        let first = ipv4_frag_frame([10, 0, 0, 1], [10, 0, 0, 2], 80, 17, 0, true, &l4[..8]);
        let normal = udp_frame([10, 0, 0, 3], [10, 0, 0, 4], 53002, 53, &query);
        let orphan = ipv4_frag_frame([10, 0, 0, 5], [10, 0, 0, 6], 81, 17, 1, false, &[0xbb; 8]);
        let bytes = tiny_pcap(LINKTYPE_ETHERNET, &[last, first, normal, orphan]);
        let (one, s1) = analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 1).unwrap();
        let (three, s3) = analyze_pcap_with(&bytes[..], &AnalyzeOptions::default(), 3).unwrap();
        assert_eq!(one, three, "worker 数不得改变分片重组后的 FlowRecord");
        assert_eq!(s1.ipfrag, s3.ipfrag, "分片统计必须与 worker 数无关");
        assert_eq!(s3.ipfrag.datagrams_completed, 1);
        assert_eq!(s3.ipfrag.datagrams_incomplete, 1);
        assert_eq!(s3.records, 2);
    }

    #[test]
    fn malformed_pcap_is_an_error_not_an_empty_result() {
        // 半截文件必须报错：报"0 条记录"会让调用方以为"这个 pcap 里确实没有流"。
        let mut bytes = tiny_pcap(LINKTYPE_ETHERNET, &[vec![0u8; 60]]);
        bytes.truncate(bytes.len() - 10);
        let err = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap_err();
        assert!(err.contains("截断"), "{err}");
    }
}
