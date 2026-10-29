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
// 3. **DTO 只跑首包**，每个方向第一个非空载荷各一次，与 DPI 的定位一致
//    （不等重组，见 dpi/mod.rs）。把重组结果喂给 DPI 是后续步骤。

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::mpsc;
use std::thread;

use crate::channel::{decode_frame, l4_payload, tcp_flags, tcp_seq_ack, DecodedFrame};
use crate::dpi::{self, Outcome};
use crate::feature::{FeatureExtractor, FlowSample};
use crate::flow::{FlowKey, Packet};
use crate::pcapfile::{PcapReader, LINKTYPE_ETHERNET};
use crate::record::{AppInfo, FlowRecord, TcpSessionStats, RECORD_SCHEMA_VERSION};
use crate::session::{ManagerStats, SessionConfig, SessionManager};
use crate::tcp::{Side, TcpConfig, TcpObservation};

/// 流水线参数。
#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    /// 会话管理器配置（含 TCP 严格/容忍模式与容量）。
    pub session: SessionConfig,
    /// 喂给 DPI 的首包字节数上限。
    pub inspect_bytes: usize,
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
    /// 会话级 TCP 统计（`CYS-TRF-015`）。走**统计行**这个已有出口而不是记录字段：
    /// 给 JSONL 加键会改变已实测的落盘字节/记录（gzip 79.4 / 列式 78.5），
    /// 那必须是一个“改契约 + 重测”的专门批次，不能混在这里静默偷掉。
    pub tcp: TcpAnomalyStats,
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
}

impl PipelineState {
    fn new(opts: &AnalyzeOptions) -> Self {
        Self {
            mgr: SessionManager::new(opts.session),
            features: BTreeMap::new(),
            probes: BTreeMap::new(),
            payload_start_unknown: 0,
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
        let probe = self.probes.entry(key).or_default();
        if !probe.is_done(obs.side) && !inspect_payload.is_empty() {
            let mut n = inspect_payload.len().min(opts.inspect_bytes);
            let dhcp =
                d.key.proto.number() == dpi::IPPROTO_UDP && dpi::dhcp::has_cookie(inspect_payload);
            let outcome = if dhcp && (d.is_fragmented || truncated) {
                Outcome::NeedMore
            } else if dhcp {
                // Keep the datagram boundary: IP/Ethernet padding is not DHCP options.
                let udp_len = pkt
                    .data
                    .get(d.l4_offset + 4..d.l4_offset + 6)
                    .map(|v| usize::from(u16::from_be_bytes([v[0], v[1]])));
                match udp_len {
                    Some(len) if len >= 8 && len <= d.ip_payload_len as usize => {
                        n = n.min(len - 8);
                        dpi::identify(&inspect_payload[..n], d.key.proto.number(), d.key.dst_port)
                    }
                    _ => Outcome::Malformed,
                }
            } else {
                dpi::identify(&inspect_payload[..n], d.key.proto.number(), d.key.dst_port)
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

fn new_stats<R: Read>(reader: &PcapReader<R>, workers: usize) -> AnalyzeStats {
    AnalyzeStats {
        linktype: reader.linktype(),
        linktype_name: reader.header().linktype_name(),
        workers,
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

/// 就地（单线程）驱动：与历史行为**逐字一致** —— 顺序、会话 id、统计口径都不变。
fn drive_inline<R: Read>(
    mut reader: PcapReader<R>,
    opts: &AnalyzeOptions,
) -> Result<(Vec<FlowRecord>, AnalyzeStats), String> {
    let mut stats = new_stats(&reader, 1);
    let mut state = PipelineState::new(opts);
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
        let decoded = match decode_frame(&rec.data) {
            Ok(d) => d,
            Err(e) => {
                // 解码失败**不中断**：省网抓包里畸形帧与非首片分片是常态。
                *stats.decode_errors.entry(e.code()).or_insert(0) += 1;
                continue;
            }
        };
        stats.packets_decoded += 1;
        if let Some(sp) = sampler.as_mut() {
            // 传 `canonical()` 键：TCP 两个方向必须得到同一个决定，否则进表的是半条会话。
            if !sp.keep(&decoded.key.canonical()) {
                continue;
            }
        }
        state.observe(
            &DecodedPacket {
                data: rec.data,
                decoded,
                timestamp_us: rec.timestamp_us,
            },
            opts,
        );
    }
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
) -> Result<(Vec<FlowRecord>, AnalyzeStats), String> {
    let mut stats = new_stats(&reader, workers);
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
        let decoded = match decode_frame(&rec.data) {
            Ok(d) => d,
            Err(e) => {
                *stats.decode_errors.entry(e.code()).or_insert(0) += 1;
                continue;
            }
        };
        stats.packets_decoded += 1;
        let key = decoded.key.canonical();
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
            .send(DecodedPacket {
                data: rec.data,
                decoded,
                timestamp_us: rec.timestamp_us,
            })
            .map_err(|_| "内部错误：分片 worker 在派发完成前退出".to_string())?;
    }
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
    if reader.linktype() != LINKTYPE_ETHERNET {
        return Err(format!(
            "链路层类型 {}（{}）暂不支持，本流水线按以太帧解码；\
             可先转换：`tshark -F pcap -r in -w out.pcap`（或 editcap -T ether）",
            reader.linktype(),
            reader.header().linktype_name()
        ));
    }
    if workers == 1 {
        drive_inline(reader, opts)
    } else {
        drive_sharded(reader, opts, workers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn malformed_pcap_is_an_error_not_an_empty_result() {
        // 半截文件必须报错：报"0 条记录"会让调用方以为"这个 pcap 里确实没有流"。
        let mut bytes = tiny_pcap(LINKTYPE_ETHERNET, &[vec![0u8; 60]]);
        bytes.truncate(bytes.len() - 10);
        let err = analyze_pcap(&bytes[..], &AnalyzeOptions::default()).unwrap_err();
        assert!(err.contains("截断"), "{err}");
    }
}
