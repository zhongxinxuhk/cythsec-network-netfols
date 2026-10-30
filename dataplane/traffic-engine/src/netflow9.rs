//! NetFlow v9（RFC 3954）采集侧：模板/数据流集解码与**导出报文**丢包率。
//!
//! ## 与 IPFIX 采集器为什么分开
//!
//! 两者共享"模板 + 数据流集"的形状，但 RFC 3954 的**序列号语义不同**：
//! v9 的 `sequence` 是导出报文的序号（每发一个报文 +1），不是"此前已发送的数据记录数"。
//! 若复用 IPFIX 的记账，`gap = 序号差` 会被当成丢失的**记录条数**，把一次丢包
//! 放大成报文里记录数倍 —— 数字看起来合理，口径却完全错了。故本模块单独存在，
//! 只复用 `CollectedFlow`/`ExporterId` 这类与协议无关的窄类型。
//!
//! ## 刻意不做
//!
//! - 不把 v9 字段类型直接当成 IPFIX IE 全集：只映射本仓下游真正消费的那组
//!   （1/2/4/7/8/11/12/27/28/34/148/152/153），其余按长度跳过并登记类型号。
//! - 不解码 Options Template 的选项字段：只按 RFC 的形状跳过并计数；
//!   用选项模板发的数据流集也显式跳过，不按普通记录硬解。
//! - 不做 TCP/SCTP 传输语义（本仓导出/回放只有 UDP/pcap）。
//! - 不从 `sysUpTime` 反推"设备启动时刻"：只把 21/22 号字段换算成绝对毫秒，
//!   换算依赖报文头里的 `unixSecs` 与 `sysUpTime`，不读本机时钟。

use crate::flow::FlowKey;
use crate::ipfix::collector::{
    CollectedFlow, ExporterId, DEFAULT_DEDUP_WINDOW, DEFAULT_MAX_RECORDS_PER_MESSAGE,
    DEFAULT_TEMPLATE_LIFETIME_MS,
};
use crate::ipfix::Ie;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// NetFlow v9 版本号（RFC 3954 §5.1）。
pub const NETFLOW9_VERSION: u16 = 9;
/// IANA 为 NetFlow v9 登记的常用端口（RFC 3954 本身不分配端口；2055 是事实标准）。
pub const NETFLOW9_PORT: u16 = 2055;
/// v9 报文头长度：version/count/sysUpTime/unixSecs/sequence/sourceID。
pub const MSG_HEADER_LEN: usize = 20;
/// FlowSet 头长度（flowsetID + length）。
pub const FLOWSET_HEADER_LEN: usize = 4;
/// 模板流集 ID。
pub const TEMPLATE_FLOWSET_ID: u16 = 0;
/// 选项模板流集 ID。
pub const OPTIONS_TEMPLATE_FLOWSET_ID: u16 = 1;
/// 数据流集 ID 下界（模板 ID 必须 ≥ 256）。
pub const FIRST_DATA_FLOWSET_ID: u16 = 256;

/// v9 的 21/22 号字段：相对 `sysUpTime` 的毫秒数。
const FIELD_LAST_SWITCHED: u16 = 21;
const FIELD_FIRST_SWITCHED: u16 = 22;

/// 采集器配置。默认值与 IPFIX 侧保持一致，避免同一套运维参数出现两套口径。
#[derive(Debug, Clone, Copy)]
pub struct Netflow9Config {
    /// 模板生存期（毫秒）；`None` = 观测到重传间隔 × 3，尚未观测到则用默认下限。
    pub template_lifetime_ms: Option<u64>,
    /// 去重窗口（条数）；0 = 不去重。
    pub dedup_window: usize,
    /// 单报文最多接受的数据记录数（防御性上限）。
    pub max_records_per_message: usize,
}

impl Default for Netflow9Config {
    fn default() -> Self {
        Self {
            template_lifetime_ms: None,
            dedup_window: DEFAULT_DEDUP_WINDOW,
            max_records_per_message: DEFAULT_MAX_RECORDS_PER_MESSAGE,
        }
    }
}

/// 采集统计。
///
/// `export_packets_lost` 的单位是**导出报文**，不是流记录。字段名刻意不叫
/// `lost_records`：v9 的序号只告诉我们"哪几个报文没到"，无法知道每个丢失报文里
/// 原本有几条记录。把它叫成记录数会让下游误以为拿到了精确的记录级丢包率。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Netflow9Stats {
    pub datagrams: u64,
    pub bytes: u64,
    /// 通过版本/头检查、参与序号记账的 v9 报文数。
    pub export_packets: u64,
    pub exporters: u64,
    /// 解出的数据记录数（含缺关键字段被丢弃的）。
    pub data_records: u64,
    /// 真正交付出去的数据记录数（去重后）。
    pub delivered_records: u64,
    pub duplicate_records: u64,
    /// 序号缺口次数。
    pub sequence_gaps: u64,
    /// 缺口合计丢失的**导出报文**数。
    pub export_packets_lost: u64,
    /// 同一序号重复到达的报文数。
    pub duplicate_datagrams: u64,
    /// 序号倒退（重复/乱序/导出侧重启），不算丢包。
    pub out_of_order: u64,
    pub template_flowsets: u64,
    pub templates_received: u64,
    pub template_refresh: u64,
    pub template_conflicts: u64,
    pub templates_expired: u64,
    pub sets_without_template: u64,
    pub options_template_records: u64,
    /// 引用了选项模板的数据流集：本版不解码选项记录，只计数。
    pub options_data_sets_skipped: u64,
    pub unknown_set_ids: u64,
    pub records_missing_key: u64,
    pub nonzero_padding: u64,
    pub malformed_datagrams: u64,
    pub version_mismatch: u64,
    /// 报文头 `count` 与实际解析出的记录数不符的次数（RFC 3954 §5.1）。
    pub count_mismatches: u64,
    /// 出现过的未映射字段类型（去重后升序）。
    pub unknown_field_types: BTreeSet<u16>,
}

impl Netflow9Stats {
    /// 导出**报文**丢包率（ppm）。分母 = 实收 v9 报文 + 推定丢失报文。
    pub fn loss_ppm(&self) -> u64 {
        let denom = self.export_packets + self.export_packets_lost;
        if denom == 0 {
            return 0;
        }
        self.export_packets_lost.saturating_mul(1_000_000) / denom
    }
}

#[derive(Debug)]
struct ExporterState {
    /// 期望的下一个**报文**序号；`None` = 还没见过任何报文。
    next_expected: Option<u32>,
    /// 上一个到达的报文序号，用来区分"重复"与"倒退"。
    last_sequence: Option<u32>,
}

/// v9 模板字段：保留原始类型号，21/22 这类不在 `Ie` 里的字段仍可解释。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct V9Field {
    code: u16,
    ie: Option<Ie>,
    len: u16,
}

#[derive(Debug)]
struct TemplateEntry {
    fields: Vec<V9Field>,
    record_len: usize,
    last_refresh_ms: u64,
    observed_interval_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DedupKey {
    exporter: ExporterId,
    source_id: u32,
    flow_id: u64,
    first_ms: u64,
    last_ms: u64,
    bytes: u64,
    packets: u64,
}

/// 一个报文的处理结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Netflow9Outcome {
    /// 解析成功；`lost_export_packets` 是本次发现的缺口报文数。
    Accepted {
        records: usize,
        lost_export_packets: u32,
    },
    /// 版本不是 9（例如 IPFIX 打到了同一个端口）。
    VersionMismatch { got: u16 },
    /// 畸形报文。
    Malformed,
}

/// NetFlow v9 采集器。
#[derive(Debug)]
pub struct Netflow9Collector {
    cfg: Netflow9Config,
    exporters: HashMap<(ExporterId, u32), ExporterState>,
    templates: HashMap<(ExporterId, u32, u16), TemplateEntry>,
    /// 选项模板 ID 只用于"这个数据集不是普通流记录"的判定，不保存字段布局。
    option_templates: HashSet<(ExporterId, u32, u16)>,
    stats: Netflow9Stats,
    flows: Vec<CollectedFlow>,
    dedup_seen: HashSet<DedupKey>,
    dedup_order: VecDeque<DedupKey>,
    now_ms: u64,
}

impl Netflow9Collector {
    pub fn new(cfg: Netflow9Config) -> Self {
        Self {
            cfg,
            exporters: HashMap::new(),
            templates: HashMap::new(),
            option_templates: HashSet::new(),
            stats: Netflow9Stats::default(),
            flows: Vec::new(),
            dedup_seen: HashSet::new(),
            dedup_order: VecDeque::new(),
            now_ms: 0,
        }
    }

    pub fn stats(&self) -> &Netflow9Stats {
        &self.stats
    }

    pub fn take_flows(&mut self) -> Vec<CollectedFlow> {
        std::mem::take(&mut self.flows)
    }

    pub fn pending_flows(&self) -> usize {
        self.flows.len()
    }

    pub fn live_templates(&self) -> usize {
        self.templates.len()
    }

    /// 处理一个 UDP 载荷。`now_ms` 由调用方提供，pcap 重放必须可复现。
    pub fn on_datagram(
        &mut self,
        exporter: ExporterId,
        bytes: &[u8],
        now_ms: u64,
    ) -> Netflow9Outcome {
        self.stats.datagrams += 1;
        self.stats.bytes += bytes.len() as u64;
        self.now_ms = now_ms;
        self.expire_templates(now_ms);

        if bytes.len() < MSG_HEADER_LEN {
            self.stats.malformed_datagrams += 1;
            return Netflow9Outcome::Malformed;
        }
        let version = be16(&bytes[0..2]);
        if version != NETFLOW9_VERSION {
            self.stats.version_mismatch += 1;
            return Netflow9Outcome::VersionMismatch { got: version };
        }
        let count = be16(&bytes[2..4]);
        let sys_uptime = be32(&bytes[4..8]);
        let unix_secs = be32(&bytes[8..12]);
        let sequence = be32(&bytes[12..16]);
        let source_id = be32(&bytes[16..20]);
        self.stats.export_packets += 1;
        self.exporters
            .entry((exporter, source_id))
            .or_insert(ExporterState {
                next_expected: None,
                last_sequence: None,
            });
        self.stats.exporters = self.exporters.len() as u64;

        let mut off = MSG_HEADER_LEN;
        let mut record_count: u32 = 0;
        let mut data_records: u32 = 0;
        while off + FLOWSET_HEADER_LEN <= bytes.len() {
            let set_id = be16(&bytes[off..off + 2]);
            let set_len = be16(&bytes[off + 2..off + 4]) as usize;
            if set_len < FLOWSET_HEADER_LEN || off + set_len > bytes.len() {
                self.stats.malformed_datagrams += 1;
                return Netflow9Outcome::Malformed;
            }
            let body = &bytes[off + FLOWSET_HEADER_LEN..off + set_len];
            match set_id {
                TEMPLATE_FLOWSET_ID => {
                    match self.parse_template_flowset(exporter, source_id, body, now_ms) {
                        Ok(n) => record_count += n,
                        Err(()) => {
                            self.stats.malformed_datagrams += 1;
                            return Netflow9Outcome::Malformed;
                        }
                    }
                }
                OPTIONS_TEMPLATE_FLOWSET_ID => {
                    self.stats.template_flowsets += 1;
                    match self.parse_options_template_flowset(exporter, source_id, body) {
                        Ok(n) => record_count += n,
                        Err(()) => {
                            self.stats.malformed_datagrams += 1;
                            return Netflow9Outcome::Malformed;
                        }
                    }
                }
                id if id >= FIRST_DATA_FLOWSET_ID => {
                    match self.parse_data_flowset(
                        exporter, source_id, id, body, sys_uptime, unix_secs, now_ms,
                    ) {
                        Ok(n) => {
                            record_count += n;
                            data_records += n;
                        }
                        Err(()) => {
                            self.stats.malformed_datagrams += 1;
                            return Netflow9Outcome::Malformed;
                        }
                    }
                }
                _ => self.stats.unknown_set_ids += 1,
            }
            off += set_len;
        }
        if off != bytes.len() {
            // 尾部剩余 1~3 字节：v9 的 FlowSet 必须 4 字节对齐，这里明确判畸形。
            self.stats.malformed_datagrams += 1;
            return Netflow9Outcome::Malformed;
        }
        if u32::from(count) != record_count {
            // count 包含模板/选项模板/数据记录（RFC 3954 §5.1）。不因此丢数据：
            // 有些导出器的 count 口径并不严格，报出来让运维定位，比静默相信更诚实。
            self.stats.count_mismatches += 1;
        }
        self.stats.data_records += u64::from(data_records);
        let lost = self.account_sequence(exporter, source_id, sequence);
        Netflow9Outcome::Accepted {
            records: data_records as usize,
            lost_export_packets: lost,
        }
    }

    /// v9 序号 = 导出报文序号。`delta - 1` 才是丢失的报文数。
    fn account_sequence(&mut self, exporter: ExporterId, source_id: u32, sequence: u32) -> u32 {
        let Some(st) = self.exporters.get_mut(&(exporter, source_id)) else {
            return 0;
        };
        if let Some(last) = st.last_sequence {
            if last == sequence {
                // 同一序号重复到达：可能是网络重复，也可能是导出侧重传。
                self.stats.duplicate_datagrams += 1;
                return 0;
            }
        }
        if let Some(expected) = st.next_expected {
            let delta = sequence.wrapping_sub(expected);
            if delta == 0 {
                // 正常的下一个报文。
            } else if delta < (1u32 << 31) {
                // 期望的是 11、收到 12 ⇒ 11 号报文丢失；delta 就是丢失的报文数。
                self.stats.sequence_gaps += 1;
                self.stats.export_packets_lost += u64::from(delta);
            } else {
                self.stats.out_of_order += 1;
                return 0;
            }
        }
        st.last_sequence = Some(sequence);
        st.next_expected = Some(sequence.wrapping_add(1));
        0
    }

    /// 解析模板流集（flowsetID=0）。返回模板记录数。
    fn parse_template_flowset(
        &mut self,
        exporter: ExporterId,
        source_id: u32,
        body: &[u8],
        now_ms: u64,
    ) -> Result<u32, ()> {
        self.stats.template_flowsets += 1;
        let mut off = 0usize;
        let mut records = 0u32;
        while off < body.len() {
            if off + 4 > body.len() {
                if body[off..].iter().all(|b| *b == 0) {
                    break;
                }
                return Err(());
            }
            let tid = be16(&body[off..off + 2]);
            let field_count = be16(&body[off + 2..off + 4]) as usize;
            off += 4;
            if tid < FIRST_DATA_FLOWSET_ID || field_count == 0 {
                return Err(());
            }
            let need = field_count * 4;
            if off + need > body.len() {
                return Err(());
            }
            let mut fields = Vec::with_capacity(field_count);
            let mut record_len = 0usize;
            for i in 0..field_count {
                let base = off + i * 4;
                let code = be16(&body[base..base + 2]);
                let len = be16(&body[base + 2..base + 4]);
                if len == 0 {
                    return Err(());
                }
                let ie = Ie::from_code(code);
                if ie.is_none() && code != FIELD_LAST_SWITCHED && code != FIELD_FIRST_SWITCHED {
                    self.stats.unknown_field_types.insert(code);
                }
                fields.push(V9Field { code, ie, len });
                record_len += len as usize;
            }
            off += need;
            self.store_template(exporter, source_id, tid, fields, record_len, now_ms);
            records += 1;
        }
        Ok(records)
    }

    /// 选项模板流集（flowsetID=1）：只校验形状并登记模板号，不解释字段。
    fn parse_options_template_flowset(
        &mut self,
        exporter: ExporterId,
        source_id: u32,
        body: &[u8],
    ) -> Result<u32, ()> {
        let mut off = 0usize;
        let mut records = 0u32;
        while off < body.len() {
            if off + 6 > body.len() {
                if body[off..].iter().all(|b| *b == 0) {
                    break;
                }
                return Err(());
            }
            let tid = be16(&body[off..off + 2]);
            let scope_len = be16(&body[off + 2..off + 4]) as usize;
            let option_len = be16(&body[off + 4..off + 6]) as usize;
            off += 6;
            if tid < FIRST_DATA_FLOWSET_ID
                || scope_len % 4 != 0
                || option_len % 4 != 0
                || off + scope_len + option_len > body.len()
            {
                return Err(());
            }
            off += scope_len + option_len;
            self.option_templates.insert((exporter, source_id, tid));
            self.stats.options_template_records += 1;
            records += 1;
        }
        Ok(records)
    }

    fn store_template(
        &mut self,
        exporter: ExporterId,
        source_id: u32,
        tid: u16,
        fields: Vec<V9Field>,
        record_len: usize,
        now_ms: u64,
    ) {
        self.stats.templates_received += 1;
        let key = (exporter, source_id, tid);
        match self.templates.get_mut(&key) {
            Some(entry) => {
                let same = entry.fields.len() == fields.len()
                    && entry.fields.iter().zip(fields.iter()).all(|(a, b)| a == b);
                if same {
                    self.stats.template_refresh += 1;
                } else {
                    // 同号不同定义：保留旧模板，不用新定义解释后续数据。
                    self.stats.template_conflicts += 1;
                    entry.last_refresh_ms = now_ms;
                    return;
                }
                let gap = now_ms.saturating_sub(entry.last_refresh_ms);
                if gap > 0 {
                    entry.observed_interval_ms = Some(gap);
                }
                entry.last_refresh_ms = now_ms;
            }
            None => {
                self.templates.insert(
                    key,
                    TemplateEntry {
                        fields,
                        record_len,
                        last_refresh_ms: now_ms,
                        observed_interval_ms: None,
                    },
                );
            }
        }
    }

    fn expire_templates(&mut self, now_ms: u64) {
        let cfg_ms = self.cfg.template_lifetime_ms;
        let mut expired = Vec::new();
        for (key, entry) in self.templates.iter() {
            let life = cfg_ms.unwrap_or_else(|| match entry.observed_interval_ms {
                Some(iv) => iv.saturating_mul(3).max(1),
                None => DEFAULT_TEMPLATE_LIFETIME_MS,
            });
            if now_ms.saturating_sub(entry.last_refresh_ms) > life {
                expired.push(*key);
            }
        }
        for key in &expired {
            self.templates.remove(key);
        }
        self.stats.templates_expired += expired.len() as u64;
    }

    /// 解析数据流集。返回记录条数。
    fn parse_data_flowset(
        &mut self,
        exporter: ExporterId,
        source_id: u32,
        set_id: u16,
        body: &[u8],
        sys_uptime: u32,
        unix_secs: u32,
        now_ms: u64,
    ) -> Result<u32, ()> {
        if self
            .option_templates
            .contains(&(exporter, source_id, set_id))
        {
            self.stats.options_data_sets_skipped += 1;
            return Ok(0);
        }
        let Some(entry) = self.templates.get(&(exporter, source_id, set_id)) else {
            self.stats.sets_without_template += 1;
            return Ok(0);
        };
        let record_len = entry.record_len;
        if record_len == 0 {
            self.stats.sets_without_template += 1;
            return Ok(0);
        }
        let fields = entry.fields.clone();
        let n = body.len() / record_len;
        if n > self.cfg.max_records_per_message {
            return Err(());
        }
        let pad = body.len() % record_len;
        if pad > 0 {
            if body[body.len() - pad..].iter().any(|b| *b != 0) {
                self.stats.nonzero_padding += 1;
            }
        }
        for i in 0..n {
            let rec = &body[i * record_len..(i + 1) * record_len];
            self.decode_record(
                exporter, source_id, set_id, &fields, rec, sys_uptime, unix_secs, now_ms,
            );
        }
        Ok(n as u32)
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_record(
        &mut self,
        exporter: ExporterId,
        source_id: u32,
        template_id: u16,
        fields: &[V9Field],
        rec: &[u8],
        sys_uptime: u32,
        unix_secs: u32,
        _now_ms: u64,
    ) {
        let mut v4_src: Option<[u8; 4]> = None;
        let mut v4_dst: Option<[u8; 4]> = None;
        let mut v6_src: Option<[u8; 16]> = None;
        let mut v6_dst: Option<[u8; 16]> = None;
        let mut sport: Option<u16> = None;
        let mut dport: Option<u16> = None;
        let mut proto: Option<u8> = None;
        let mut bytes: Option<u64> = None;
        let mut packets: Option<u64> = None;
        let mut start_ms: Option<u64> = None;
        let mut end_ms: Option<u64> = None;
        let mut first_switched: Option<u32> = None;
        let mut last_switched: Option<u32> = None;
        let mut flow_id: Option<u64> = None;
        let mut sampling: Option<u32> = None;

        let mut off = 0usize;
        for f in fields {
            let len = f.len as usize;
            if off + len > rec.len() {
                self.stats.malformed_datagrams += 1;
                return;
            }
            let raw = &rec[off..off + len];
            off += len;
            if let Some(ie) = f.ie {
                match ie {
                    Ie::SourceIPv4Address => v4_src = read_ipv4(raw),
                    Ie::DestinationIPv4Address => v4_dst = read_ipv4(raw),
                    Ie::SourceIPv6Address => v6_src = read_ipv6(raw),
                    Ie::DestinationIPv6Address => v6_dst = read_ipv6(raw),
                    Ie::SourceTransportPort => sport = read_uint(raw).map(|v| v as u16),
                    Ie::DestinationTransportPort => dport = read_uint(raw).map(|v| v as u16),
                    Ie::ProtocolIdentifier => proto = read_uint(raw).map(|v| v as u8),
                    Ie::OctetDeltaCount => bytes = read_uint(raw),
                    Ie::PacketDeltaCount => packets = read_uint(raw),
                    Ie::FlowStartMilliseconds => start_ms = read_uint(raw),
                    Ie::FlowEndMilliseconds => end_ms = read_uint(raw),
                    Ie::FlowId => flow_id = read_uint(raw),
                    Ie::SamplingInterval => sampling = read_uint(raw).map(|v| v as u32),
                }
            } else {
                match f.code {
                    FIELD_FIRST_SWITCHED => first_switched = read_uint(raw).map(|v| v as u32),
                    FIELD_LAST_SWITCHED => last_switched = read_uint(raw).map(|v| v as u32),
                    _ => {}
                }
            }
        }

        // 152/153 是绝对毫秒；没有时用 21/22 的 sysUpTime 相对值换算。
        let unix_ms = u64::from(unix_secs).saturating_mul(1000);
        let first_seen_ms = start_ms.unwrap_or_else(|| {
            first_switched
                .map(|v| unix_ms.saturating_sub(u64::from(sys_uptime.saturating_sub(v))))
                .unwrap_or(0)
        });
        let last_seen_ms = end_ms.unwrap_or_else(|| {
            last_switched
                .map(|v| unix_ms.saturating_sub(u64::from(sys_uptime.saturating_sub(v))))
                .unwrap_or(0)
        });

        let key = build_key(v4_src, v4_dst, v6_src, v6_dst, sport, dport, proto);
        let Some(key) = key else {
            self.stats.records_missing_key += 1;
            return;
        };
        let (bytes, packets) = (bytes.unwrap_or(0), packets.unwrap_or(0));
        let flow_id = flow_id.unwrap_or(0);
        let sampling_interval = sampling.unwrap_or(1);
        let flow = CollectedFlow {
            exporter,
            odid: source_id,
            template_id,
            key,
            packets,
            bytes,
            first_seen_ms,
            last_seen_ms,
            flow_id,
            sampling_interval,
        };

        if self.cfg.dedup_window > 0 {
            let dk = DedupKey {
                exporter,
                source_id,
                flow_id,
                first_ms: first_seen_ms,
                last_ms: last_seen_ms,
                bytes,
                packets,
            };
            if self.dedup_seen.contains(&dk) {
                self.stats.duplicate_records += 1;
                return;
            }
            self.dedup_seen.insert(dk);
            self.dedup_order.push_back(dk);
            while self.dedup_order.len() > self.cfg.dedup_window {
                if let Some(old) = self.dedup_order.pop_front() {
                    self.dedup_seen.remove(&old);
                }
            }
        }
        self.stats.delivered_records += 1;
        self.flows.push(flow);
    }
}

fn build_key(
    v4_src: Option<[u8; 4]>,
    v4_dst: Option<[u8; 4]>,
    v6_src: Option<[u8; 16]>,
    v6_dst: Option<[u8; 16]>,
    sport: Option<u16>,
    dport: Option<u16>,
    proto: Option<u8>,
) -> Option<FlowKey> {
    let (sport, dport, proto) = (sport?, dport?, proto?);
    if let (Some(s), Some(d)) = (v4_src, v4_dst) {
        return Some(FlowKey::new_ipv4(s, sport, d, dport, proto));
    }
    if let (Some(s), Some(d)) = (v6_src, v6_dst) {
        return Some(FlowKey::new_ipv6(
            std::net::Ipv6Addr::from(s),
            sport,
            std::net::Ipv6Addr::from(d),
            dport,
            proto,
        ));
    }
    None
}

fn read_uint(raw: &[u8]) -> Option<u64> {
    if raw.is_empty() || raw.len() > 8 {
        return None;
    }
    let mut v: u64 = 0;
    for b in raw {
        v = (v << 8) | u64::from(*b);
    }
    Some(v)
}

fn read_ipv4(raw: &[u8]) -> Option<[u8; 4]> {
    raw.try_into().ok()
}

fn read_ipv6(raw: &[u8]) -> Option<[u8; 16]> {
    raw.try_into().ok()
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const EXP: ExporterId = ExporterId {
        ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        port: 2055,
    };

    fn template_flowset(tid: u16, fields: &[(u16, u16)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TEMPLATE_FLOWSET_ID.to_be_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&tid.to_be_bytes());
        body.extend_from_slice(&(fields.len() as u16).to_be_bytes());
        for (code, len) in fields {
            body.extend_from_slice(&code.to_be_bytes());
            body.extend_from_slice(&len.to_be_bytes());
        }
        out.extend_from_slice(&((FLOWSET_HEADER_LEN + body.len()) as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn data_flowset(tid: u16, body: &[u8], pad: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tid.to_be_bytes());
        out.extend_from_slice(
            &((FLOWSET_HEADER_LEN + body.len() + pad.len()) as u16).to_be_bytes(),
        );
        out.extend_from_slice(body);
        out.extend_from_slice(pad);
        out
    }

    fn message(sequence: u32, source_id: u32, count: u16, sets: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for s in sets {
            body.extend_from_slice(s);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&NETFLOW9_VERSION.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&1_000_000u32.to_be_bytes()); // sysUpTime
        out.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // unixSecs
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&source_id.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn v4_fields() -> Vec<(u16, u16)> {
        vec![
            (8, 4),
            (12, 4),
            (7, 2),
            (11, 2),
            (4, 1),
            (1, 4),
            (2, 4),
            (152, 8),
            (153, 8),
            (148, 4),
            (34, 2),
        ]
    }

    fn v4_record(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, proto: u8, flow_id: u32) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&src);
        r.extend_from_slice(&dst);
        r.extend_from_slice(&sp.to_be_bytes());
        r.extend_from_slice(&dp.to_be_bytes());
        r.push(proto);
        r.extend_from_slice(&1500u32.to_be_bytes());
        r.extend_from_slice(&10u32.to_be_bytes());
        r.extend_from_slice(&1_700_000_000_000u64.to_be_bytes());
        r.extend_from_slice(&1_700_000_001_000u64.to_be_bytes());
        r.extend_from_slice(&flow_id.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r
    }

    fn collect(msgs: &[(u64, Vec<u8>)]) -> (Netflow9Collector, Vec<CollectedFlow>) {
        let mut c = Netflow9Collector::new(Netflow9Config::default());
        for (t, m) in msgs {
            c.on_datagram(EXP, m, *t);
        }
        let flows = c.take_flows();
        (c, flows)
    }

    #[test]
    fn decodes_template_then_records() {
        let t = template_flowset(256, &v4_fields());
        let r1 = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 6, 7);
        let r2 = v4_record([10, 0, 0, 3], [10, 0, 0, 4], 53, 53, 17, 8);
        let d = data_flowset(256, &[r1, r2].concat(), &[]);
        let (c, flows) = collect(&[(1000, message(0, 1, 3, &[t, d]))]);
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].key.src_port, 1234);
        assert_eq!(flows[0].bytes, 1500);
        assert_eq!(flows[0].flow_id, 7);
        assert_eq!(flows[0].first_seen_ms, 1_700_000_000_000);
        assert_eq!(flows[0].sampling_interval, 1);
        assert_eq!(c.stats().templates_received, 1);
        assert_eq!(c.stats().count_mismatches, 0);
        assert_eq!(c.stats().export_packets_lost, 0);
    }

    #[test]
    fn sequence_gap_counts_lost_export_packets() {
        let t = template_flowset(256, &v4_fields());
        let r = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6, 1);
        let d = data_flowset(256, &r, &[]);
        let (c, _) = collect(&[
            (1000, message(10, 1, 2, &[t.clone(), d.clone()])),
            (2000, message(12, 1, 1, &[d])), // 11 号报文丢失
        ]);
        assert_eq!(c.stats().sequence_gaps, 1);
        assert_eq!(c.stats().export_packets_lost, 1);
        assert_eq!(c.stats().loss_ppm(), 333_333); // 1 / (2 + 1)
    }

    #[test]
    fn duplicate_sequence_is_not_loss() {
        let t = template_flowset(256, &v4_fields());
        let r = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6, 1);
        let d = data_flowset(256, &r, &[]);
        let (c, _) = collect(&[
            (1000, message(5, 1, 2, &[t, d.clone()])),
            (2000, message(5, 1, 1, &[d])),
        ]);
        assert_eq!(c.stats().duplicate_datagrams, 1);
        assert_eq!(c.stats().export_packets_lost, 0);
        assert_eq!(c.stats().out_of_order, 0);
    }

    #[test]
    fn backward_sequence_is_out_of_order_not_loss() {
        let (c, _) = collect(&[(1000, message(5, 1, 0, &[])), (2000, message(3, 1, 0, &[]))]);
        assert_eq!(c.stats().out_of_order, 1);
        assert_eq!(c.stats().export_packets_lost, 0);
        assert_eq!(c.stats().sequence_gaps, 0);
    }

    #[test]
    fn sequence_wraps_at_32_bits_without_false_loss() {
        let (c, _) = collect(&[
            (1000, message(u32::MAX, 1, 0, &[])),
            (2000, message(0, 1, 0, &[])),
        ]);
        assert_eq!(c.stats().export_packets_lost, 0);
        assert_eq!(c.stats().out_of_order, 0);
    }

    #[test]
    fn different_source_ids_do_not_share_sequence_state() {
        let (c, _) = collect(&[
            (1000, message(1, 1, 0, &[])),
            (2000, message(100, 2, 0, &[])),
        ]);
        assert_eq!(c.stats().export_packets_lost, 0);
        assert_eq!(c.stats().exporters, 2);
    }

    #[test]
    fn template_refresh_and_conflict_keep_old_definition() {
        let t = template_flowset(256, &v4_fields());
        let mut changed = v4_fields();
        changed[0] = (27, 16); // 换成 IPv6 源地址，同号不同定义
        let t2 = template_flowset(256, &changed);
        let (c, _) = collect(&[
            (1000, message(0, 1, 1, &[t.clone()])),
            (2000, message(1, 1, 1, &[t])),
            (3000, message(2, 1, 1, &[t2])),
        ]);
        assert_eq!(c.stats().template_refresh, 1);
        assert_eq!(c.stats().template_conflicts, 1);
        assert_eq!(c.live_templates(), 1);
    }

    #[test]
    fn data_without_template_is_counted_not_invented() {
        let r = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6, 1);
        let d = data_flowset(256, &r, &[]);
        let (c, flows) = collect(&[(1000, message(0, 1, 1, &[d]))]);
        assert!(flows.is_empty());
        assert_eq!(c.stats().sets_without_template, 1);
    }

    #[test]
    fn unknown_field_type_is_skipped_without_shifting() {
        let mut fields = vec![(9999, 3)];
        fields.extend(v4_fields());
        let t = template_flowset(256, &fields);
        let mut r = vec![0xaa, 0xbb, 0xcc];
        r.extend(v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6, 1));
        let d = data_flowset(256, &r, &[]);
        let (c, flows) = collect(&[(1000, message(0, 1, 2, &[t, d]))]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].key.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(flows[0].bytes, 1500);
        assert!(c.stats().unknown_field_types.contains(&9999));
    }

    #[test]
    fn sysuptime_fields_become_absolute_milliseconds() {
        // sysUpTime=1_000_000ms，unixSecs=1_700_000_000 → 启动时刻 1_699_999_000_000ms。
        // FIRST/LAST_SWITCHED=999_000/1_000_000 → 绝对 1_699_999_999_000/1_700_000_000_000。
        let fields = vec![(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (22, 4), (21, 4)];
        let t = template_flowset(256, &fields);
        let mut r = Vec::new();
        r.extend_from_slice(&[10, 0, 0, 1]);
        r.extend_from_slice(&[10, 0, 0, 2]);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&2u16.to_be_bytes());
        r.push(6);
        r.extend_from_slice(&999_000u32.to_be_bytes());
        r.extend_from_slice(&1_000_000u32.to_be_bytes());
        let d = data_flowset(256, &r, &[]);
        let (_, flows) = collect(&[(1000, message(0, 1, 2, &[t, d]))]);
        assert_eq!(flows[0].first_seen_ms, 1_699_999_999_000);
        assert_eq!(flows[0].last_seen_ms, 1_700_000_000_000);
    }

    #[test]
    fn v6_template_and_reduced_length_encoding() {
        let fields = vec![(27, 16), (28, 16), (7, 2), (11, 2), (4, 1), (1, 4), (2, 2)];
        let t = template_flowset(257, &fields);
        let mut r = Vec::new();
        r.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        r.extend_from_slice(&std::net::Ipv6Addr::UNSPECIFIED.octets());
        r.extend_from_slice(&1234u16.to_be_bytes());
        r.extend_from_slice(&443u16.to_be_bytes());
        r.push(6);
        r.extend_from_slice(&900u32.to_be_bytes());
        r.extend_from_slice(&3u16.to_be_bytes());
        let d = data_flowset(257, &r, &[]);
        let (_, flows) = collect(&[(1000, message(0, 1, 2, &[t, d]))]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].bytes, 900);
        assert_eq!(flows[0].packets, 3);
        assert_eq!(
            flows[0].key.dst_ip,
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn count_mismatch_and_truncated_flowset_are_reported() {
        let t = template_flowset(256, &v4_fields());
        let (c, _) = collect(&[(1000, message(0, 1, 99, &[t]))]);
        assert_eq!(c.stats().count_mismatches, 1);
        assert_eq!(c.stats().malformed_datagrams, 0);

        let mut bad = message(1, 1, 0, &[]);
        bad.extend_from_slice(&TEMPLATE_FLOWSET_ID.to_be_bytes());
        bad.extend_from_slice(&100u16.to_be_bytes());
        let (c, _) = collect(&[(1000, message(1, 1, 0, &[bad[MSG_HEADER_LEN..].to_vec()]))]);
        assert!(c.stats().malformed_datagrams >= 1);
    }

    #[test]
    fn template_expires_and_recovers_on_refresh() {
        let t = template_flowset(256, &v4_fields());
        let r = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6, 1);
        let d = data_flowset(256, &r, &[]);
        let mut c = Netflow9Collector::new(Netflow9Config {
            template_lifetime_ms: Some(100),
            ..Default::default()
        });
        c.on_datagram(EXP, &message(0, 1, 2, &[t.clone(), d.clone()]), 1000);
        assert_eq!(c.live_templates(), 1);
        c.on_datagram(EXP, &message(1, 1, 1, &[d.clone()]), 1200);
        assert_eq!(c.live_templates(), 0);
        assert_eq!(c.stats().templates_expired, 1);
        c.on_datagram(EXP, &message(2, 1, 2, &[t, d]), 1300);
        assert_eq!(c.live_templates(), 1);
    }

    #[test]
    fn duplicate_record_within_window_is_dropped_and_counted() {
        let t = template_flowset(256, &v4_fields());
        let r = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6, 1);
        let d = data_flowset(256, &r, &[]);
        let (c, flows) = collect(&[
            (1000, message(0, 1, 2, &[t.clone(), d.clone()])),
            (2000, message(1, 1, 1, &[d])),
        ]);
        assert_eq!(flows.len(), 1);
        assert_eq!(c.stats().duplicate_records, 1);
    }

    #[test]
    fn options_template_data_is_skipped_not_forced_into_flows() {
        let mut opts = Vec::new();
        opts.extend_from_slice(&OPTIONS_TEMPLATE_FLOWSET_ID.to_be_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&300u16.to_be_bytes());
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&8u16.to_be_bytes());
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes());
        opts.extend_from_slice(&((FLOWSET_HEADER_LEN + body.len()) as u16).to_be_bytes());
        opts.extend_from_slice(&body);
        let data = data_flowset(300, &[0u8; 8], &[]);
        let (c, flows) = collect(&[(1000, message(0, 1, 2, &[opts, data]))]);
        assert!(flows.is_empty());
        assert_eq!(c.stats().options_template_records, 1);
        assert_eq!(c.stats().options_data_sets_skipped, 1);
    }
}
