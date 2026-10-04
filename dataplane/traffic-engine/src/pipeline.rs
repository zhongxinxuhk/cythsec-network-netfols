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

use std::collections::BTreeMap;
use std::io::Read;

use crate::channel::{decode_frame, l4_payload, tcp_flags};
use crate::dpi::{self, Outcome};
use crate::feature::{FeatureExtractor, FlowSample};
use crate::flow::{FlowKey, Packet};
use crate::pcapfile::{PcapReader, LINKTYPE_ETHERNET};
use crate::record::{AppInfo, FlowRecord, RECORD_SCHEMA_VERSION};
use crate::session::{ManagerStats, SessionConfig, SessionManager};
use crate::tcp::{Side, TcpConfig, TcpObservation};

/// 流水线参数。
#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    /// 会话管理器配置（含 TCP 严格/容忍模式与容量）。
    pub session: SessionConfig,
    /// 喂给 DPI 的首包字节数上限。
    pub inspect_bytes: usize,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        let mut session = SessionConfig::default();
        session.tcp = TcpConfig::tolerant();
        Self {
            session,
            inspect_bytes: dpi::DEFAULT_INSPECT_BYTES,
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
    /// 应用识别结论分布。
    pub app_outcomes: BTreeMap<&'static str, u64>,
    pub session: ManagerStats,
    pub linktype: u32,
    pub linktype_name: &'static str,
}

impl AnalyzeStats {
    pub fn decode_error_count(&self) -> u64 {
        self.decode_errors.values().sum()
    }
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
    let mut reader = PcapReader::new(reader).map_err(|e| format!("解析 pcap 头失败：{e}"))?;
    let mut stats = AnalyzeStats {
        linktype: reader.linktype(),
        linktype_name: reader.header().linktype_name(),
        ..Default::default()
    };
    if reader.linktype() != LINKTYPE_ETHERNET {
        return Err(format!(
            "链路层类型 {}（{}）暂不支持，本流水线按以太帧解码；\
             可先转换：`tshark -F pcap -r in -w out.pcap`（或 editcap -T ether）",
            stats.linktype, stats.linktype_name
        ));
    }

    let mut mgr = SessionManager::new(opts.session);
    let mut features: BTreeMap<FlowKey, FeatureExtractor> = BTreeMap::new();
    let mut probes: BTreeMap<FlowKey, Probe> = BTreeMap::new();

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
        let d = match decode_frame(&rec.data) {
            Ok(d) => d,
            Err(e) => {
                // 解码失败**不中断**：省网抓包里畸形帧与非首片分片是常态，
                // 一个坏帧就让整份分析停摆，等于把"能分析"降级成"不能分析"。
                *stats.decode_errors.entry(e.code()).or_insert(0) += 1;
                continue;
            }
        };
        stats.packets_decoded += 1;

        let key = d.key.canonical();
        let payload_view = l4_payload(&rec.data, &d);
        if payload_view.is_none() {
            stats.payload_start_unknown += 1;
        }
        // 状态机要的是**段载荷长度**（不含四层头），字节统计要的是 IP 载荷长度
        // （含四层头）。这两个数必须分别传：混用会把每个纯 ACK 判成 Data，
        // 于是握手最后一个 ACK 不再走 Ack 分支（见 TcpObservation 的说明）。
        // 用 declared_len（线上声明的长度）而不是捕获到的字节数：载荷被 snaplen
        // 截断的包在线上仍然带了数据，不能因为自己少拷了字节就当成空的。
        let seg = tcp_flags(&rec.data, &d).zip(payload_view).map(|(f, p)| {
            TcpObservation::new(f, u32::try_from(p.declared_len).unwrap_or(u32::MAX))
        });

        let obs = mgr.observe(
            &Packet {
                key: d.key,
                payload_len: d.ip_payload_len,
                timestamp_us: rec.timestamp_us,
            },
            seg.as_ref(),
        );

        let payload_bytes: &[u8] = payload_view.map(|p| p.bytes).unwrap_or(&[]);
        features.entry(key).or_default().observe(&FlowSample {
            side: obs.side,
            payload_len: d.ip_payload_len,
            timestamp_us: rec.timestamp_us,
            payload: payload_bytes,
        });

        let probe = probes.entry(key).or_default();
        if !probe.is_done(obs.side) && !payload_bytes.is_empty() {
            let n = payload_bytes.len().min(opts.inspect_bytes);
            let outcome = dpi::identify(&payload_bytes[..n], d.key.proto.number(), d.key.dst_port);
            // 截断捕获必须导向"还需要更多字节"：我们自己少拷了字节，不能算"不认识"。
            let info = if payload_view.map(|p| p.is_truncated()).unwrap_or(false)
                && matches!(outcome, Outcome::Unknown)
            {
                AppInfo::from_outcome(&Outcome::NeedMore, n)
            } else {
                AppInfo::from_outcome(&outcome, n)
            };
            *probe.slot(obs.side) = Some(info);
        }
    }

    // ---- 产出记录 ----
    let sessions = mgr.sessions_sorted();
    let mut records: Vec<FlowRecord> = Vec::with_capacity(sessions.len());
    for s in sessions {
        let fv = features
            .get(&s.key)
            .map(|e| e.vector())
            .unwrap_or_else(|| FeatureExtractor::default().vector());
        // 内部互证：会话计数与特征计数必须一致（两条路径喂的是同一串包）。
        // 不一致说明有包只进了其中一条路 —— 这种错不会自己冒出来，必须显式检查。
        if fv.get(crate::feature::idx::PACKETS) != s.packets as f64
            || fv.get(crate::feature::idx::BYTES) != s.bytes as f64
        {
            stats.counter_mismatches += 1;
        }
        if !fv.is_finite() {
            stats.non_finite_vectors += 1;
        }
        let app = probes
            .get(&s.key)
            .map(|p| p.resolve())
            .unwrap_or_else(AppInfo::not_inspected);
        *stats.app_outcomes.entry(app.outcome).or_insert(0) += 1;
        records.push(FlowRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            session_id: s.id,
            key: s.key,
            // 非 TCP 没有连接状态：写 None，而不是拿 Closed 冒充。
            tcp_state: if s.is_tcp() {
                Some(s.tcp_state())
            } else {
                None
            },
            initiator: s.initiator(),
            adopted_midstream: s.adopted_midstream(),
            illegal_tcp_events: s.tcp.illegal_events(),
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
    stats.records = records.len();
    stats.sorted_by_key = records.windows(2).all(|w| w[0].key <= w[1].key);
    stats.session = mgr.stats();

    // ---- 自检：不满足就让调用方看到失败，而不是给出一份"看起来成功"的输出 ----
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
