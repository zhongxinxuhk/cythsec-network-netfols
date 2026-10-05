// ipfix/collector.rs —— IPFIX 采集侧（M11 / CYS-TRF-054）。
//
// ## 为什么采集器是"必须自己做"的一环
//
// 导出器（`export/mod.rs`）只解决"发得出去"。而运营商口径里真正被考核的是**三个数**：
// ① 采样率（声明与执行一致）② **导出丢包率**（这段流量到底丢了没有、丢了多少）
// ③ 采集覆盖率（哪些网元在报、哪些没报）。其中 ② 只有采集侧能算：
// RFC 7011 §3.1 把 Sequence Number 定义为「本报文**之前**该 Observation Domain 已发送的
// **数据记录**累计数」，于是 `本报文序号 - 上次期望序号` 就是**中间丢了多少条记录**；
// 而 §11.6 明确要求采集进程**必须**靠跟踪序号来发现插入/丢失。没有采集器，
// 这个数就只能靠"我们发了 N 条"自说自话 —— 那是导出侧的自证，不是可观测的丢包率。
//
// ## 四条按 RFC 落地的硬语义（写错都不会崩，只会把丢包读成正常）
//
// 1. **序列号缺口 = 导出丢包**（§3.1 / §11.6），且**前进方向才算丢包**：
//    序号落后于期望值是重复/乱序/导出侧重启，不能算丢包。这里还必须防住 §11.6 点名的
//    攻击面 —— "收到一个更大的序号就重置期望值"会被**故意注入的大序号**蒙蔽，
//    使自己在一段时间内看不见真实丢包。故本实现：只在**合理界内**记账并把期望值推进，
//    界外的（差值 ≥ 2^31）一律按乱序计，**不重置基线**。
// 2. **首报文不算丢包**：没有基线就没有缺口可言。这是刻意的诚实边界 ——
//    "采集器启动之前丢了什么"不可知，只能靠"采集覆盖率"这个另一维度的口径去说。
// 3. **UDP 上的模板撤回必须被忽略**（§8.4：UDP 传输的导出进程 MUST NOT 发撤回，
//    采集进程 MUST 忽略）。UDP 上模板靠**周期重传**续命，故采集侧给模板设**生存期**，
//    未刷新即丢弃（§8.4：生存期 SHOULD 默认 ≥ 观测到的重传间隔的 3 倍）。
// 4. **同一模板号收到不同定义 = 明确的错误**（§8.1）：采集器 SHOULD 记录并告警。
//    本实现**保留旧模板**并计数，不去用新定义解释后续数据 ——
//    RFC 说此时"已无法无歧义解释"，那就不要假装能解释。
//
// ## v1 刻意不做
//
// - 只做 **UDP 语义**（本仓导出器只有 UDP/pcap 两条路）。TCP/SCTP 传输下的
//   "传输会话结束时隐式撤回全部模板"（§8.1）不适用，故未实现。
// - **不做 Options Template 解码**（IE 直方图/中间流统计等）：只解析长度以便跳过，
//   并计数。做了但不给下游用，比没做更糟（看起来支持了）。
// - **不做解密/DTLS**（§11.5：UDP 无 DTLS 时应靠网络隔离）。

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use crate::feature::{FeatureVector, FEATURE_SCHEMA_VERSION};
use crate::flow::FlowKey;
use crate::ipfix::{
    Ie, WireField, FIRST_DATA_SET_ID, IPFIX_VERSION, MSG_HEADER_LEN, OPTIONS_TEMPLATE_SET_ID,
    SET_HEADER_LEN, TEMPLATE_SET_ID,
};
use crate::record::{AppInfo, FlowRecord, RECORD_SCHEMA_VERSION};

/// 模板默认生存期（毫秒）。
///
/// RFC 7011 §8.4 说默认值是"部署与应用相关"的，只要求"SHOULD 至少是观测到的
/// 重传间隔的 3 倍"。故这里给一个保守的**下限**默认（10 分钟），
/// 一旦观测到该模板的重传间隔，就用 `3 × 间隔` 取而代之（见 `lifetime_ms`）。
pub const DEFAULT_TEMPLATE_LIFETIME_MS: u64 = 600_000;

/// 送到采集器的数据记录与"窗口内重复"判定的默认窗口大小。
///
/// 去重只在**有界窗口**内成立：IPFIX 是持续流，没有"会话结束"的边界，
/// 无限去重表会随运行时长无界增长。窗口大小如实暴露在配置里，
/// 因为"窗口外的重复计不进去"是使用方必须知道的口径。
pub const DEFAULT_DEDUP_WINDOW: usize = 4096;

/// 单个报文最多接受的数据记录数（防御性上限）。
///
/// 模板可以声明 `record_len = 1`（合法），于是一个 1500 字节的报文能"解出"1400 条记录。
/// 这是对**畸形/恶意**报文的必要防御，不是性能优化：没有它，一条伪造报文就能让我们
/// 按模板声明的粒度无限地往结果里塞记录。
pub const DEFAULT_MAX_RECORDS_PER_MESSAGE: usize = 4096;

/// 导出进程（Exporter）的身份。
///
/// 按 RFC 7011 §3.1，"序列号 + 模板"的作用域是**传输会话 × Observation Domain**。
/// UDP 无连接，故用 (源地址, 源端口) 近似一个传输会话 —— 这一点必须写明：
/// 导出进程换源端口重启，对采集器而言就是一个**新的**会话（序号基线重来），
/// 而不是"序号倒退"。把这两者混为一谈会把重启记成乱序，反之会把乱序记成重启。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExporterId {
    pub ip: IpAddr,
    pub port: u16,
}

impl std::fmt::Display for ExporterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

/// 采集器配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorConfig {
    /// 模板生存期（毫秒）。`None` = 按 §8.4 用"观测到的重传间隔 × 3"，
    /// 观测不到时退回 [`DEFAULT_TEMPLATE_LIFETIME_MS`]。
    pub template_lifetime_ms: Option<u64>,
    /// 去重窗口（按记录条数）。0 表示不去重（口径上等价于"重复一律计入"）。
    pub dedup_window: usize,
    /// 单报文记录数上限。
    pub max_records_per_message: usize,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            template_lifetime_ms: None,
            dedup_window: DEFAULT_DEDUP_WINDOW,
            max_records_per_message: DEFAULT_MAX_RECORDS_PER_MESSAGE,
        }
    }
}

/// 采集统计。**每一个字段都要能被 CLI 打出来**：算得出但看不见的指标等于没有。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectorStats {
    pub datagrams: u64,
    pub bytes: u64,
    pub exporters: u64,
    /// 数据记录总数（**已成功解码、含被判为重复的**）。
    pub data_records: u64,
    /// 因窗口内重复而被丢弃的记录数。
    pub duplicate_records: u64,
    /// 真正交付出去的记录数（= data_records - duplicate_records）。
    pub delivered_records: u64,
    /// 序列号缺口的**次数**。
    pub sequence_gaps: u64,
    /// 缺口合计**丢了多少条记录**。
    pub lost_records: u64,
    /// 序号落后于期望值：重复/乱序/导出侧重启（**不算丢包**）。
    pub out_of_order: u64,
    /// 模板集数量 / 收到的模板定义数（含重传）。
    pub template_sets: u64,
    pub templates_received: u64,
    /// 模板重传（定义完全相同）—— UDP 上这是**正常操作**（§8.4），不计错误。
    pub template_refresh: u64,
    /// 同一模板号收到**不同**定义（§8.1 的明确错误）。
    pub template_conflicts: u64,
    /// 因生存期到期被丢弃的模板数（§8.4）。
    pub templates_expired: u64,
    /// UDP 上收到模板撤回并**按 §8.4 忽略**的次数。
    pub withdrawals_ignored: u64,
    /// 数据集引用了未知模板 → 整段无法解释（记录条数**不可知**，故只计段数）。
    pub sets_without_template: u64,
    /// Options Template 集（本版只跳过不解码）。
    pub options_template_sets: u64,
    /// 保留/未定义 setID 的集数。
    pub unknown_set_ids: u64,
    /// 解码出记录但**缺关键字段**（地址/端口/协议不全）而被丢弃的条数。
    pub records_missing_key: u64,
    /// 填充字节非零（RFC 7011 §3.3.1 要求填充必须为 0）的次数。
    pub nonzero_padding: u64,
    /// 畸形报文（长度不符/Set 越界/字段越界等）。
    pub malformed_datagrams: u64,
    /// 版本不是 10 的报文（例如 NetFlow v9 打到了同一个端口）。
    pub version_mismatch: u64,
    /// 记录里出现过的**未登记 IE 编号**（去重后升序）。
    pub unknown_ies: BTreeSet<u16>,
}

impl CollectorStats {
    /// 导出丢包率（以**百万分之一**为单位，整数）。
    ///
    /// 用 ppm 而不是浮点：这个数会进报告与门禁断言，浮点格式化在不同平台上
    /// 会出现末位差异，而"丢包率"这种口径不允许因为格式而抖动。
    /// 分母是"应该收到的记录数" = 实收 + 丢失。
    pub fn loss_ppm(&self) -> u64 {
        let denom = self.data_records + self.lost_records;
        if denom == 0 {
            return 0;
        }
        // 先乘后除，避免整数除法把小缺口直接抹成 0。
        self.lost_records.saturating_mul(1_000_000) / denom
    }
}

/// 一个导出进程 + 一个 Observation Domain 的状态。
#[derive(Debug)]
struct ExporterState {
    /// 期望的下一个序号；`None` = 还没见过任何报文（无基线，谈不上缺口）。
    next_expected: Option<u32>,
}

/// 已存下的模板及其刷新状态。
#[derive(Debug)]
struct TemplateEntry {
    fields: Vec<WireField>,
    record_len: usize,
    last_refresh_ms: u64,
    /// 观测到的重传间隔（毫秒）。用最近一次间隔，不用平均值 ——
    /// 平均值会被"首次两次刷新挨得很近"永久拉低，让生存期偏短、模板被误删。
    observed_interval_ms: Option<u64>,
}

/// 一条从 IPFIX 记录还原出来的流。
///
/// 刻意**不是** `FlowRecord`：IPFIX 只承载了部分字段（地址/端口/协议/计数/时标/flowId），
/// TCP 状态、特征、DPI 结论都不在线上。把它们填成默认值再叫 `FlowRecord`，
/// 就等于把"没采集到"伪装成"采集到了且值为空"。故这里是一个显式的窄类型，
/// 需要 `FlowRecord` 形态时由 `to_flow_record()` 显式转换（并在文档里写明丢了什么）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedFlow {
    pub exporter: ExporterId,
    pub odid: u32,
    pub template_id: u16,
    pub key: FlowKey,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub flow_id: u64,
    pub sampling_interval: u32,
}

impl CollectedFlow {
    /// 转成 `FlowRecord` 形态（便于复用 JSONL 写出与下游）。
    ///
    /// **明确丢失**：TCP 状态、发起方、方向切换、非法迁移、特征向量、DPI 结论 ——
    /// 这些字段 IPFIX v1 的模板里没有（见 `export/mod.rs` 的模板定义）。
    /// 故 `tcp_state = None`、`app = not_inspected()`、特征全 0：
    /// 报告里的 `not_inspected` 与 `None` 是**真话**（"没采集到"），不是"值为空"。
    pub fn to_flow_record(&self) -> FlowRecord {
        FlowRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            session_id: self.flow_id,
            key: self.key.canonical(),
            tcp_state: None,
            initiator: None,
            adopted_midstream: false,
            illegal_tcp_events: 0,
            first_seen_us: self.first_seen_ms.saturating_mul(1000),
            last_seen_us: self.last_seen_ms.saturating_mul(1000),
            packets: self.packets,
            bytes: self.bytes,
            direction_switches: 0,
            features: FeatureVector {
                schema_version: FEATURE_SCHEMA_VERSION,
                values: [0f64; crate::feature::FEATURE_COUNT],
            },
            app: AppInfo::not_inspected(),
            risk_score: None,
        }
    }
}

/// 一个报文的处理结果（给调用方留日志用的最小信息）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramOutcome {
    /// 解析成功，交付 `records` 条记录（`lost` 是本次发现的缺口条数）。
    Accepted { records: usize, lost: u32 },
    /// 版本不是 10（例如 NetFlow v9 打到了同一端口）。
    VersionMismatch { got: u16 },
    /// 畸形报文。
    Malformed,
}

/// IPFIX 采集器。
#[derive(Debug)]
pub struct Collector {
    cfg: CollectorConfig,
    exporters: HashMap<(ExporterId, u32), ExporterState>,
    /// key = (导出进程, ODID, 模板号)。模板作用域含 ODID —— 两个 ODID 可以各有 256 号模板。
    templates: HashMap<(ExporterId, u32, u16), TemplateEntry>,
    stats: CollectorStats,
    flows: Vec<CollectedFlow>,
    dedup_seen: HashSet<DedupKey>,
    dedup_order: VecDeque<DedupKey>,
    /// 已处理报文的"当前时间"，供模板生存期判定使用。
    now_ms: u64,
}

/// 去重键。
///
/// 选 (flowId, 起止时标, 字节数) 而不是整个五元组：同一导出进程把同一条记录
/// 重复发出来（网络重复、导出侧重传）时，这四项必然相同；而**两条真正不同的
/// 记录不可能在同样的 flowId、同样的起止毫秒、同样的字节数上重合**
/// （flowId 由导出侧保证唯一，见 `FlowRecord.session_id`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DedupKey {
    exporter: ExporterId,
    odid: u32,
    flow_id: u64,
    first_ms: u64,
    last_ms: u64,
    bytes: u64,
    packets: u64,
}

impl Collector {
    pub fn new(cfg: CollectorConfig) -> Self {
        Self {
            cfg,
            exporters: HashMap::new(),
            templates: HashMap::new(),
            stats: CollectorStats::default(),
            flows: Vec::new(),
            dedup_seen: HashSet::new(),
            dedup_order: VecDeque::new(),
            now_ms: 0,
        }
    }

    pub fn stats(&self) -> &CollectorStats {
        &self.stats
    }

    /// 取走已交付的记录（调用后清空内部缓冲）。
    pub fn take_flows(&mut self) -> Vec<CollectedFlow> {
        std::mem::take(&mut self.flows)
    }

    /// 当前缓存的记录数。
    pub fn pending_flows(&self) -> usize {
        self.flows.len()
    }

    /// 当前存活模板数（门禁用它证明"模板生存期真的在跑"）。
    pub fn live_templates(&self) -> usize {
        self.templates.len()
    }

    /// 处理一个 UDP 载荷（一个 IPFIX 报文）。
    ///
    /// `now_ms` 由调用方给出（pcap 用抓包时间戳、实时用系统时钟）——
    /// **不在这里读时钟**：生存期与重传间隔的判定必须可复现，
    /// 否则同一段 pcap 重放两次会得到不同结果。
    pub fn on_datagram(
        &mut self,
        exporter: ExporterId,
        bytes: &[u8],
        now_ms: u64,
    ) -> DatagramOutcome {
        self.stats.datagrams += 1;
        self.stats.bytes += bytes.len() as u64;
        self.now_ms = now_ms;
        self.expire_templates(now_ms);

        if bytes.len() < MSG_HEADER_LEN {
            self.stats.malformed_datagrams += 1;
            return DatagramOutcome::Malformed;
        }
        let version = be16(&bytes[0..2]);
        if version != IPFIX_VERSION {
            self.stats.version_mismatch += 1;
            return DatagramOutcome::VersionMismatch { got: version };
        }
        let msg_len = be16(&bytes[2..4]) as usize;
        if msg_len < MSG_HEADER_LEN || msg_len > bytes.len() {
            // length 大于实际载荷 = 报文被截断；小于 = 尾部有多余字节。
            // 两者都必须报出来：静默按实际长度解析会把一次截断读成"记录就是少了几条"。
            self.stats.malformed_datagrams += 1;
            return DatagramOutcome::Malformed;
        }
        let sequence = be32(&bytes[8..12]);
        let odid = be32(&bytes[12..16]);
        self.exporters
            .entry((exporter, odid))
            .or_insert(ExporterState {
                next_expected: None,
            });
        self.stats.exporters = self.exporters.len() as u64;

        // ---- 报文体：逐个 Set ----
        let mut off = MSG_HEADER_LEN;
        let mut records_in_msg: u32 = 0;
        while off + SET_HEADER_LEN <= msg_len {
            let set_id = be16(&bytes[off..off + 2]);
            let set_len = be16(&bytes[off + 2..off + 4]) as usize;
            if set_len < SET_HEADER_LEN || off + set_len > msg_len {
                // Set 越界：整报文判定畸形。**不"尽力而为地解到哪儿算哪儿"** ——
                // 那会把一次协议错读成"这段流量只有这几条记录"。
                self.stats.malformed_datagrams += 1;
                return DatagramOutcome::Malformed;
            }
            let body = &bytes[off + SET_HEADER_LEN..off + set_len];
            match set_id {
                TEMPLATE_SET_ID => self.parse_template_set(exporter, odid, body, now_ms),
                OPTIONS_TEMPLATE_SET_ID => self.stats.options_template_sets += 1,
                id if id >= FIRST_DATA_SET_ID => {
                    match self.parse_data_set(exporter, odid, id, body, now_ms) {
                        Ok(n) => records_in_msg += n,
                        Err(()) => {
                            self.stats.malformed_datagrams += 1;
                            return DatagramOutcome::Malformed;
                        }
                    }
                }
                _ => self.stats.unknown_set_ids += 1,
            }
            off += set_len;
        }

        // ---- 序列号记账（RFC 7011 §3.1 / §11.6）----
        let lost = self.account_sequence(exporter, odid, sequence, records_in_msg);
        self.stats.data_records += records_in_msg as u64;
        DatagramOutcome::Accepted {
            records: records_in_msg as usize,
            lost,
        }
    }

    /// 序列号记账。返回本次发现的缺口条数（0 = 无缺口，包括首报文与乱序）。
    fn account_sequence(
        &mut self,
        exporter: ExporterId,
        odid: u32,
        sequence: u32,
        records_in_msg: u32,
    ) -> u32 {
        let Some(st) = self.exporters.get_mut(&(exporter, odid)) else {
            return 0;
        };
        let mut lost = 0u32;
        if let Some(expected) = st.next_expected {
            let delta = sequence.wrapping_sub(expected);
            if delta == 0 {
                // 正常。
            } else if delta < (1u32 << 31) {
                // 前进方向 = 中间丢了 delta 条数据记录。
                lost = delta;
                self.stats.sequence_gaps += 1;
                self.stats.lost_records += delta as u64;
            } else {
                // 序号落后 = 重复/乱序/导出侧重启。**不推进期望值**：
                // §11.6 点名过"见到更大的序号就重置"会被注入蒙蔽，
                // 反过来"见到更小的序号就把基线拉回去"同样会被重放攻击利用。
                self.stats.out_of_order += 1;
                return 0;
            }
        }
        st.next_expected = Some(sequence.wrapping_add(records_in_msg));
        lost
    }

    /// 解析模板集（setID = 2）。
    fn parse_template_set(&mut self, exporter: ExporterId, odid: u32, body: &[u8], now_ms: u64) {
        self.stats.template_sets += 1;
        let mut off = 0usize;
        while off + 4 <= body.len() {
            let tid = be16(&body[off..off + 2]);
            let field_count = be16(&body[off + 2..off + 4]) as usize;
            off += 4;
            if field_count == 0 {
                // 模板撤回。**UDP 上必须忽略**（RFC 7011 §8.4）。
                // 本仓导出器只有 UDP（+ pcap 落盘），故这里一律忽略并计数。
                self.stats.withdrawals_ignored += 1;
                continue;
            }
            let need = field_count * 4;
            if off + need > body.len() {
                self.stats.malformed_datagrams += 1;
                return;
            }
            let mut fields = Vec::with_capacity(field_count);
            let mut record_len = 0usize;
            for i in 0..field_count {
                let base = off + i * 4;
                let code = be16(&body[base..base + 2]);
                let len = be16(&body[base + 2..base + 4]);
                if len == 0 {
                    // 长度为 0 的字段会让 record_len 与记录边界全部失真。
                    self.stats.malformed_datagrams += 1;
                    return;
                }
                // 未登记编号：保留长度、不赋语义（见 `WireField` 的说明）。
                // 绝不能"猜一个已知 IE"——猜错会让后续字段偏移整体错位，
                // 而错位读出来的往往仍是"合法"的字节。
                let ie = Ie::from_code(code);
                if ie.is_none() {
                    self.stats.unknown_ies.insert(code);
                }
                fields.push(WireField { ie, len });
                record_len += len as usize;
            }
            off += need;
            self.store_template(exporter, odid, tid, fields, record_len, now_ms);
        }
    }

    /// 存下一个模板，并处理"刷新"与"冲突重定义"（RFC 7011 §8.1 / §8.4）。
    fn store_template(
        &mut self,
        exporter: ExporterId,
        odid: u32,
        tid: u16,
        fields: Vec<WireField>,
        record_len: usize,
        now_ms: u64,
    ) {
        self.stats.templates_received += 1;
        let key = (exporter, odid, tid);
        match self.templates.get_mut(&key) {
            Some(entry) => {
                let same = entry.fields.len() == fields.len()
                    && entry.fields.iter().zip(fields.iter()).all(|(a, b)| a == b);
                if same {
                    // UDP 上重传同一模板是**正常操作**，不是错误（§8.4）。
                    self.stats.template_refresh += 1;
                } else {
                    // §8.1：同一模板号给了不同定义 = 明确的错误。
                    // 保留旧模板：RFC 说此时"已无法无歧义解释后续数据"，
                    // 那就不要用新定义去假装能解释。
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

    /// 模板生存期（毫秒）：显式配置 > 观测到的重传间隔 × 3 > 默认下限（RFC 7011 §8.4）。
    fn lifetime_ms(&self, entry: &TemplateEntry) -> u64 {
        if let Some(ms) = self.cfg.template_lifetime_ms {
            return ms;
        }
        match entry.observed_interval_ms {
            Some(iv) => iv.saturating_mul(3).max(1),
            None => DEFAULT_TEMPLATE_LIFETIME_MS,
        }
    }

    /// 清掉到期未刷新的模板（§8.4）。
    fn expire_templates(&mut self, now_ms: u64) {
        let cfg_ms = self.cfg.template_lifetime_ms;
        // 先算出到期键，再统一删除：避免在遍历 `self.templates` 时借用 `self`。
        let mut expired = Vec::new();
        for (key, entry) in self.templates.iter() {
            let life = cfg_ms.unwrap_or(match entry.observed_interval_ms {
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

    /// 解析数据集（setID ≥ 256）。返回记录条数；`Err` = 结构越界（整报文判畸形）。
    fn parse_data_set(
        &mut self,
        exporter: ExporterId,
        odid: u32,
        set_id: u16,
        body: &[u8],
        now_ms: u64,
    ) -> Result<u32, ()> {
        let Some(entry) = self.templates.get(&(exporter, odid, set_id)) else {
            // 模板未知 → 记录条数**不可知**（不知道记录长度），故只计"段"，不计条数。
            // 把它折算成"0 条"会让覆盖率虚高；折算成"1 条"是编造。
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
            // 填充必须全零（RFC 7011 §3.3.1）。非零填充是明确的协议违规，
            // 且它往往意味着"记录长度算错了"—— 报出来比默默忽略有用得多。
            if body[body.len() - pad..].iter().any(|b| *b != 0) {
                self.stats.nonzero_padding += 1;
            }
        }
        for i in 0..n {
            let rec = &body[i * record_len..(i + 1) * record_len];
            self.decode_record(exporter, odid, set_id, &fields, rec, now_ms);
        }
        Ok(n as u32)
    }

    /// 解一条记录，按需交付（含去重）。
    fn decode_record(
        &mut self,
        exporter: ExporterId,
        odid: u32,
        template_id: u16,
        fields: &[WireField],
        rec: &[u8],
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
        let mut flow_id: Option<u64> = None;
        let mut sampling: Option<u32> = None;

        let mut off = 0usize;
        for f in fields {
            let len = f.len as usize;
            if off + len > rec.len() {
                // 字段越界：这条记录不可解。整报文已被长度检查保护，
                // 走到这里说明模板与记录长度不一致 → 计数并丢弃这一条。
                self.stats.malformed_datagrams += 1;
                return;
            }
            let raw = &rec[off..off + len];
            // **先推进偏移，再决定解不解**：未登记 IE 虽然不赋语义，但它占的字节
            // 必须计进去，否则后面所有字段整体前移 3 个字节，读出来的仍是"合法"数值
            // （本测试就是用这条抓到的：octets 读成了 0xAABBCC0000000000）。
            off += len;
            let Some(ie) = f.ie else {
                continue;
            };
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
                // IE 34 是 unsigned32，但 RFC 7011 §6.2 允许**缩减长度编码**
                // （导出侧可只发 1~2 字节），故按字节数读，不假定 4 字节。
                Ie::SamplingInterval => sampling = read_uint(raw).map(|v| v as u32),
            }
        }

        let key = build_key(v4_src, v4_dst, v6_src, v6_dst, sport, dport, proto);
        let Some(key) = key else {
            self.stats.records_missing_key += 1;
            return;
        };
        let (bytes, packets) = (bytes.unwrap_or(0), packets.unwrap_or(0));
        let (first_seen_ms, last_seen_ms) = (start_ms.unwrap_or(0), end_ms.unwrap_or(0));
        let flow_id = flow_id.unwrap_or(0);
        let sampling_interval = sampling.unwrap_or(1);

        let flow = CollectedFlow {
            exporter,
            odid,
            template_id,
            key,
            packets,
            bytes,
            first_seen_ms,
            last_seen_ms,
            flow_id,
            sampling_interval,
        };

        // ---- 有界窗口去重 ----
        if self.cfg.dedup_window > 0 {
            let dk = DedupKey {
                exporter,
                odid,
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

/// 按模板字段拼出五元组。地址/端口/协议**缺一不可**：缺任何一个都不猜。
///
/// 返回 `None` 表示这条记录无法归属到一条流 —— 调用方必须把它计成
/// "缺关键字段"并丢弃，绝不能拿 0.0.0.0:0 之类的占位值凑一条流出来：
/// 那会在统计里造出大量不存在的流，且看起来完全正常。
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
        let s = std::net::Ipv6Addr::from(s);
        let d = std::net::Ipv6Addr::from(d);
        return Some(FlowKey::new_ipv6(s, sport, d, dport, proto));
    }
    // 混用 v4/v6 地址（模板里同时有 v4 与 v6 字段）→ 无歧义可言，丢弃。
    None
}

/// 按**实际字节数**读无符号整数（允许 RFC 7011 §6.2 的缩减长度编码）。
///
/// 长度 ≥ 9 字节不是任何已登记 IE 的合法编码（最大 unsigned64），返回 `None`：
/// 宁可判"这条记录不可解"，也不要截断成 64 位后继续算。
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

/// 只在测试/夹具里用到的类型：放模块级会让非测试构建（CLI）报未使用 import。
#[cfg(test)]
use crate::ipfix::FieldSpec;

/// 把我们的模板编成模板集字节（**仅测试与夹具用**）。
///
/// 生产方向的编码在 `export/mod.rs`。这里刻意再写一遍的理由：门禁需要构造
/// **导出器不会产出**的报文（未知模板、未登记 IE、缩减长度编码、模板撤回、
/// 序号倒退），这些用导出器造不出来。它与生产编码器共用 `Template`/`Ie` 定义，
/// 不共用字节拼接顺序 —— 顺序写错会被测试抓出来（而不是两边一起错）。
#[cfg(test)]
fn template_set_bytes(tid: u16, fields: &[FieldSpec]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TEMPLATE_SET_ID.to_be_bytes());
    let len = SET_HEADER_LEN + 4 + 4 * fields.len();
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&tid.to_be_bytes());
    out.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for f in fields {
        out.extend_from_slice(&f.ie.code().to_be_bytes());
        out.extend_from_slice(&f.len.to_be_bytes());
    }
    out
}

/// 拼一个 IPFIX 报文（**仅测试与夹具用**）。
#[cfg(test)]
fn message_bytes(sequence: u32, odid: u32, export_time: u32, sets: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for s in sets {
        body.extend_from_slice(s);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&IPFIX_VERSION.to_be_bytes());
    out.extend_from_slice(&((MSG_HEADER_LEN + body.len()) as u16).to_be_bytes());
    out.extend_from_slice(&export_time.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&odid.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipfix::{FieldSpec, Template, TEMPLATE_ID_V4, TEMPLATE_ID_V6};

    const EXP: ExporterId = ExporterId {
        ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 9)),
        port: 4739,
    };

    /// 手写一条 v4 记录（**不用生产编码器**，否则"两端一起错"就测不出来）。
    fn v4_record(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, proto: u8) -> Vec<u8> {
        v4_record_id(src, dst, sp, dp, proto, 7)
    }

    /// 带 flowId 的版本。去重按 (flowId, 起止时标, 计数) 判定，
    /// 所以"想造两条不同的记录"就必须换 flowId —— 这正是线上导出进程的行为
    /// （flowId 唯一标识一条流）。
    fn v4_record_id(
        src: [u8; 4],
        dst: [u8; 4],
        sp: u16,
        dp: u16,
        proto: u8,
        flow_id: u64,
    ) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&src);
        r.extend_from_slice(&dst);
        r.extend_from_slice(&sp.to_be_bytes());
        r.extend_from_slice(&dp.to_be_bytes());
        r.push(proto);
        r.extend_from_slice(&1500u64.to_be_bytes()); // octets
        r.extend_from_slice(&10u64.to_be_bytes()); // packets
        r.extend_from_slice(&1_700_000_000_000u64.to_be_bytes()); // start ms
        r.extend_from_slice(&1_700_000_001_000u64.to_be_bytes()); // end ms
        r.extend_from_slice(&flow_id.to_be_bytes()); // flowId
        r.extend_from_slice(&1u32.to_be_bytes()); // samplingInterval
        r
    }

    /// 数据集（补零到 4 字节；调用方可传非零字节来构造违规填充）。
    fn data_set(tid: u16, body: &[u8], pad: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tid.to_be_bytes());
        out.extend_from_slice(&((SET_HEADER_LEN + body.len() + pad.len()) as u16).to_be_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(pad);
        out
    }

    fn collect_raw(msgs: &[(u64, Vec<u8>)]) -> (Collector, Vec<CollectedFlow>) {
        let mut c = Collector::new(CollectorConfig::default());
        for (t, m) in msgs {
            c.on_datagram(EXP, m, *t);
        }
        let flows = c.take_flows();
        (c, flows)
    }

    fn v4_template() -> Template {
        Template::ipv4()
    }

    // ---- 1. 基本解码：模板 + 一条记录 ----
    #[test]
    fn decodes_template_then_record() {
        let t = v4_template();
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 6);
        assert_eq!(rec.len(), t.record_len());
        let msg = message_bytes(
            0,
            1,
            0,
            &[
                template_set_bytes(TEMPLATE_ID_V4, &t.fields),
                data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0]),
            ],
        );
        let (c, flows) = collect_raw(&[(1000, msg)]);
        assert_eq!(flows.len(), 1, "应解出 1 条记录");
        let f = &flows[0];
        assert_eq!(f.key.src_port, 1234);
        assert_eq!(f.key.dst_port, 80);
        assert_eq!(f.bytes, 1500);
        assert_eq!(f.packets, 10);
        assert_eq!(f.first_seen_ms, 1_700_000_000_000);
        assert_eq!(f.last_seen_ms, 1_700_000_001_000);
        assert_eq!(f.flow_id, 7);
        assert_eq!(f.sampling_interval, 1);
        assert_eq!(f.odid, 1);
        assert_eq!(f.template_id, TEMPLATE_ID_V4);
        let st = c.stats();
        assert_eq!(st.data_records, 1);
        assert_eq!(st.delivered_records, 1);
        assert_eq!(st.lost_records, 0, "首报文没有基线，不能算丢包");
        assert_eq!(st.malformed_datagrams, 0);
        assert_eq!(st.nonzero_padding, 0);
    }

    // ---- 2. 序列号缺口 = 导出丢包（本任务的核心断言）----
    #[test]
    fn sequence_gap_counts_lost_records() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let r1 = v4_record_id([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6, 1);
        let r2 = v4_record_id([10, 0, 0, 1], [10, 0, 0, 2], 1, 3, 6, 2);
        let r3 = v4_record_id([10, 0, 0, 1], [10, 0, 0, 2], 1, 4, 6, 3);
        // 第 1 个报文：序号 0，2 条记录 → 期望下一个是 2
        let m1 = message_bytes(
            0,
            1,
            0,
            &[
                ts.clone(),
                data_set(TEMPLATE_ID_V4, &[r1, r2].concat(), &[0, 0]),
            ],
        );
        // 第 2 个报文：序号 5（丢了 3 条），1 条记录
        let m2 = message_bytes(
            5,
            1,
            0,
            &[ts.clone(), data_set(TEMPLATE_ID_V4, &r3, &[0, 0, 0])],
        );
        let (c, flows) = collect_raw(&[(1000, m1), (2000, m2)]);
        assert_eq!(flows.len(), 3);
        let st = c.stats();
        assert_eq!(st.sequence_gaps, 1);
        assert_eq!(st.lost_records, 3, "序号 2→5 = 丢 3 条数据记录");
        assert_eq!(st.data_records, 3);
        // 丢包率 = 3 / (3 + 3) = 50% = 500000 ppm
        assert_eq!(st.loss_ppm(), 500_000);
    }

    #[test]
    fn in_order_sequence_has_no_gap_and_counts_records_not_messages() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        // 序号推进只按**数据记录数**：报文只带模板时序号不动（RFC 7011 §3.1）
        let only_ts = message_bytes(0, 1, 0, &[ts.clone()]);
        let m2 = message_bytes(
            0,
            1,
            0,
            &[ts.clone(), data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0])],
        );
        let m3 = message_bytes(
            1,
            1,
            0,
            &[ts.clone(), data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0])],
        );
        let (c, _) = collect_raw(&[(1000, only_ts), (2000, m2), (3000, m3)]);
        let st = c.stats();
        assert_eq!(
            st.sequence_gaps, 0,
            "只带模板的报文不推进序号，不得误报缺口"
        );
        assert_eq!(st.lost_records, 0);
        assert_eq!(st.loss_ppm(), 0);
    }

    #[test]
    fn backward_sequence_is_out_of_order_not_loss() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        let set = data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0]);
        let m1 = message_bytes(10, 1, 0, &[ts.clone(), set.clone()]);
        let m2 = message_bytes(11, 1, 0, &[ts.clone(), set.clone()]);
        // 序号倒回 5（重复/乱序/重启）
        let m3 = message_bytes(5, 1, 0, &[ts.clone(), set.clone()]);
        let (c, _) = collect_raw(&[(1000, m1), (2000, m2), (3000, m3)]);
        let st = c.stats();
        assert_eq!(st.out_of_order, 1);
        assert_eq!(st.lost_records, 0, "序号倒退不是丢包");
        assert_eq!(st.sequence_gaps, 0);
    }

    #[test]
    fn sequence_wraps_at_32_bits_without_false_loss() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        let set = data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0]);
        // 序号 2^32-1 + 1 条记录 → 期望下一个是 0（回绕）
        let m1 = message_bytes(u32::MAX, 1, 0, &[ts.clone(), set.clone()]);
        let m2 = message_bytes(0, 1, 0, &[ts.clone(), set.clone()]);
        let (c, _) = collect_raw(&[(1000, m1), (2000, m2)]);
        let st = c.stats();
        assert_eq!(st.lost_records, 0, "2^32 回绕不得误报丢包");
        assert_eq!(st.out_of_order, 0);
        assert_eq!(st.loss_ppm(), 0);
    }

    #[test]
    fn each_observation_domain_has_its_own_sequence_baseline() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        let set = data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0]);
        // ODID 1 用序号 0；ODID 2 用序号 100。两者各自独立，不得互相算成缺口。
        let (c, _) = collect_raw(&[
            (1000, message_bytes(0, 1, 0, &[ts.clone(), set.clone()])),
            (2000, message_bytes(100, 2, 0, &[ts.clone(), set.clone()])),
            (3000, message_bytes(1, 1, 0, &[ts.clone(), set.clone()])),
            (4000, message_bytes(101, 2, 0, &[ts.clone(), set.clone()])),
        ]);
        let st = c.stats();
        assert_eq!(st.lost_records, 0);
        assert_eq!(st.exporters, 2, "两个 ODID 是两套独立状态");
    }

    #[test]
    fn different_exporters_do_not_share_sequence_state() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        let set = data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0]);
        let other = ExporterId {
            ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 10)),
            port: 4739,
        };
        let mut c = Collector::new(CollectorConfig::default());
        c.on_datagram(
            EXP,
            &message_bytes(0, 1, 0, &[ts.clone(), set.clone()]),
            1000,
        );
        // 另一台导出进程从序号 500 开始：对它而言这是首报文，不构成缺口
        c.on_datagram(
            other,
            &message_bytes(500, 1, 0, &[ts.clone(), set.clone()]),
            2000,
        );
        let st = c.stats();
        assert_eq!(st.lost_records, 0, "不同导出进程各有各的序号基线");
        assert_eq!(st.exporters, 2);
    }

    // ---- 3. 模板管理 ----
    #[test]
    fn refresh_of_identical_template_is_not_an_error() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let (c, _) = collect_raw(&[
            (1000, message_bytes(0, 1, 0, &[ts.clone()])),
            (2000, message_bytes(0, 1, 0, &[ts.clone()])),
        ]);
        let st = c.stats();
        assert_eq!(st.templates_received, 2);
        assert_eq!(st.template_refresh, 1);
        assert_eq!(st.template_conflicts, 0);
        assert_eq!(st.malformed_datagrams, 0);
    }

    #[test]
    fn conflicting_redefinition_keeps_old_template_and_counts_conflict() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        // 同一模板号，字段数不同 → §8.1 的明确错误
        let mut changed = t.fields.clone();
        changed.pop();
        let ts2 = template_set_bytes(TEMPLATE_ID_V4, &changed);
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        let (c, flows) = collect_raw(&[
            (1000, message_bytes(0, 1, 0, &[ts.clone()])),
            (2000, message_bytes(0, 1, 0, &[ts2.clone()])),
            (
                3000,
                message_bytes(
                    0,
                    1,
                    0,
                    &[ts.clone(), data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0])],
                ),
            ),
        ]);
        let st = c.stats();
        assert_eq!(st.template_conflicts, 1);
        assert_eq!(flows.len(), 1, "旧模板仍然可用（按旧定义解）");
        assert_eq!(flows[0].bytes, 1500);
    }

    #[test]
    fn data_without_template_is_counted_as_set_not_invented_records() {
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        let (c, flows) = collect_raw(&[(
            1000,
            message_bytes(0, 1, 0, &[data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0])]),
        )]);
        assert!(flows.is_empty());
        let st = c.stats();
        assert_eq!(st.sets_without_template, 1);
        assert_eq!(st.data_records, 0, "记录条数不可知时不许编造条数");
    }

    #[test]
    fn template_expires_after_lifetime_then_recovers_on_refresh() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        let set = data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0]);
        // 生存期显式设 1000 ms：1000ms 时定义，4000ms 时已过期 → 数据集不可解
        let cfg = CollectorConfig {
            template_lifetime_ms: Some(1000),
            ..Default::default()
        };
        let mut c = Collector::new(cfg);
        let set2 = data_set(
            TEMPLATE_ID_V4,
            &v4_record_id([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6, 2),
            &[0, 0, 0],
        );
        c.on_datagram(EXP, &message_bytes(0, 1, 0, &[ts.clone()]), 1000);
        c.on_datagram(EXP, &message_bytes(0, 1, 0, &[set.clone()]), 1500);
        assert_eq!(c.take_flows().len(), 1, "生存期内可用");
        c.on_datagram(EXP, &message_bytes(1, 1, 0, &[set.clone()]), 4000);
        assert!(c.take_flows().is_empty(), "过期后不得再按旧模板解释");
        assert_eq!(c.stats().templates_expired, 1);
        assert_eq!(c.stats().sets_without_template, 1);
        // 导出侧重传模板 → 立刻恢复（这正是 UDP 上必须周期重传的理由）
        c.on_datagram(EXP, &message_bytes(1, 1, 0, &[ts.clone()]), 5000);
        c.on_datagram(EXP, &message_bytes(1, 1, 0, &[set2]), 5100);
        assert_eq!(c.take_flows().len(), 1, "重传后恢复解码");
        assert_eq!(c.live_templates(), 1);
    }

    #[test]
    fn observed_refresh_interval_sets_lifetime_to_three_times() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        let set = data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0]);
        // 观测到重传间隔 2000 ms → 生存期 = 6000 ms（RFC 7011 §8.4）
        let mut c = Collector::new(CollectorConfig::default());
        c.on_datagram(EXP, &message_bytes(0, 1, 0, &[ts.clone()]), 0);
        c.on_datagram(EXP, &message_bytes(0, 1, 0, &[ts.clone()]), 2000);
        // 5000ms：距上次刷新 3000ms < 6000ms → 仍存活
        c.on_datagram(EXP, &message_bytes(0, 1, 0, &[set.clone()]), 5000);
        assert_eq!(c.take_flows().len(), 1, "生存期应为观测间隔的 3 倍");
        // 10000ms：距上次刷新 8000ms > 6000ms → 过期
        c.on_datagram(EXP, &message_bytes(1, 1, 0, &[set.clone()]), 10_000);
        assert!(c.take_flows().is_empty());
        assert_eq!(c.stats().templates_expired, 1);
    }

    #[test]
    fn template_withdrawal_over_udp_is_ignored() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        // 撤回报文：模板号 + 字段数 0
        let mut wd = Vec::new();
        wd.extend_from_slice(&TEMPLATE_SET_ID.to_be_bytes());
        wd.extend_from_slice(&8u16.to_be_bytes());
        wd.extend_from_slice(&TEMPLATE_ID_V4.to_be_bytes());
        wd.extend_from_slice(&0u16.to_be_bytes());
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        let (c, flows) = collect_raw(&[
            (1000, message_bytes(0, 1, 0, &[ts.clone()])),
            (2000, message_bytes(0, 1, 0, &[wd])),
            (
                3000,
                message_bytes(0, 1, 0, &[data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0])]),
            ),
        ]);
        let st = c.stats();
        assert_eq!(st.withdrawals_ignored, 1);
        assert_eq!(flows.len(), 1, "UDP 上撤回必须被忽略（RFC 7011 §8.4）");
        assert_eq!(c.live_templates(), 1);
    }

    // ---- 4. 编码细节：缩减长度、未登记 IE、填充 ----
    #[test]
    fn reduced_size_encoding_is_accepted() {
        // RFC 7011 §6.2 允许 unsigned64 用更少字节编码：这里 octets 用 4 字节、packets 用 2 字节
        let fields = vec![
            FieldSpec {
                ie: Ie::SourceIPv4Address,
                len: 4,
            },
            FieldSpec {
                ie: Ie::DestinationIPv4Address,
                len: 4,
            },
            FieldSpec {
                ie: Ie::SourceTransportPort,
                len: 2,
            },
            FieldSpec {
                ie: Ie::DestinationTransportPort,
                len: 2,
            },
            FieldSpec {
                ie: Ie::ProtocolIdentifier,
                len: 1,
            },
            FieldSpec {
                ie: Ie::OctetDeltaCount,
                len: 4,
            },
            FieldSpec {
                ie: Ie::PacketDeltaCount,
                len: 2,
            },
            FieldSpec {
                ie: Ie::FlowId,
                len: 4,
            },
            FieldSpec {
                ie: Ie::SamplingInterval,
                len: 2,
            },
        ];
        let mut rec = Vec::new();
        rec.extend_from_slice(&[10, 0, 0, 1]);
        rec.extend_from_slice(&[10, 0, 0, 2]);
        rec.extend_from_slice(&1234u16.to_be_bytes());
        rec.extend_from_slice(&80u16.to_be_bytes());
        rec.push(6);
        rec.extend_from_slice(&4_000_000_000u32.to_be_bytes()); // octets > u32::MAX? 不，恰好 u32 上限内
        rec.extend_from_slice(&1000u16.to_be_bytes());
        rec.extend_from_slice(&9u32.to_be_bytes());
        rec.extend_from_slice(&100u16.to_be_bytes());
        let ts = template_set_bytes(TEMPLATE_ID_V4, &fields);
        let pad = vec![0u8; (4 - rec.len() % 4) % 4];
        let (c, flows) = collect_raw(&[(
            1000,
            message_bytes(0, 1, 0, &[ts, data_set(TEMPLATE_ID_V4, &rec, &pad)]),
        )]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].bytes, 4_000_000_000);
        assert_eq!(flows[0].packets, 1000);
        assert_eq!(flows[0].flow_id, 9);
        assert_eq!(
            flows[0].sampling_interval, 100,
            "2 字节采样间隔也要如实读出"
        );
        assert_eq!(c.stats().malformed_datagrams, 0);
    }

    #[test]
    fn unknown_ie_is_skipped_without_shifting_other_fields() {
        // 模板里插一个未登记编号 9999（长度 3）→ 后面字段的偏移必须仍然正确
        let fields = vec![
            FieldSpec {
                ie: Ie::SourceIPv4Address,
                len: 4,
            },
            FieldSpec {
                ie: Ie::DestinationIPv4Address,
                len: 4,
            },
            FieldSpec {
                ie: Ie::SourceTransportPort,
                len: 2,
            },
            FieldSpec {
                ie: Ie::DestinationTransportPort,
                len: 2,
            },
            FieldSpec {
                ie: Ie::ProtocolIdentifier,
                len: 1,
            },
            FieldSpec {
                ie: Ie::OctetDeltaCount,
                len: 8,
            },
            FieldSpec {
                ie: Ie::PacketDeltaCount,
                len: 8,
            },
            FieldSpec {
                ie: Ie::FlowId,
                len: 8,
            },
        ];
        // 手拼模板集：把 IE 9999 塞在协议号之后
        // 实际字段条目 = 已知字段 + 1 个未登记 IE（夹具里手写，故总数要 +1：
        // 声明的 field_count 与实际条目数不一致 = 自己造了个畸形报文）
        let mut set = Vec::new();
        set.extend_from_slice(&TEMPLATE_SET_ID.to_be_bytes());
        let len = SET_HEADER_LEN + 4 + 4 * (fields.len() + 1);
        set.extend_from_slice(&(len as u16).to_be_bytes());
        set.extend_from_slice(&TEMPLATE_ID_V4.to_be_bytes());
        set.extend_from_slice(&((fields.len() + 1) as u16).to_be_bytes());
        for f in &fields {
            set.extend_from_slice(&f.ie.code().to_be_bytes());
            set.extend_from_slice(&f.len.to_be_bytes());
            if f.ie == Ie::ProtocolIdentifier {
                set.extend_from_slice(&9999u16.to_be_bytes());
                set.extend_from_slice(&3u16.to_be_bytes());
            }
        }
        let mut rec = Vec::new();
        rec.extend_from_slice(&[10, 0, 0, 1]);
        rec.extend_from_slice(&[10, 0, 0, 2]);
        rec.extend_from_slice(&1234u16.to_be_bytes());
        rec.extend_from_slice(&80u16.to_be_bytes());
        rec.push(6);
        rec.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // 未登记 IE 的 3 字节
        rec.extend_from_slice(&1500u64.to_be_bytes());
        rec.extend_from_slice(&10u64.to_be_bytes());
        rec.extend_from_slice(&7u64.to_be_bytes());
        let pad = vec![0u8; (4 - rec.len() % 4) % 4];
        let (c, flows) = collect_raw(&[(
            1000,
            message_bytes(0, 1, 0, &[set, data_set(TEMPLATE_ID_V4, &rec, &pad)]),
        )]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].bytes, 1500, "未登记 IE 不能把后续字段顶偏");
        assert_eq!(flows[0].packets, 10);
        assert_eq!(flows[0].flow_id, 7);
        assert_eq!(
            c.stats().unknown_ies.iter().copied().collect::<Vec<_>>(),
            vec![9999]
        );
    }

    #[test]
    fn nonzero_padding_is_reported() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        // 记录 57 字节 → 补 3 字节；故意填非零（RFC 7011 §3.3.1 要求全零）
        let (c, flows) = collect_raw(&[(
            1000,
            message_bytes(0, 1, 0, &[ts, data_set(TEMPLATE_ID_V4, &rec, &[1, 2, 3])]),
        )]);
        assert_eq!(flows.len(), 1);
        assert_eq!(c.stats().nonzero_padding, 1);
    }

    #[test]
    fn record_with_missing_key_fields_is_not_invented() {
        // 模板缺端口/协议 → 记录无法归属到流
        let fields = vec![
            FieldSpec {
                ie: Ie::SourceIPv4Address,
                len: 4,
            },
            FieldSpec {
                ie: Ie::DestinationIPv4Address,
                len: 4,
            },
            FieldSpec {
                ie: Ie::OctetDeltaCount,
                len: 8,
            },
        ];
        let ts = template_set_bytes(TEMPLATE_ID_V4, &fields);
        let mut rec = Vec::new();
        rec.extend_from_slice(&[10, 0, 0, 1]);
        rec.extend_from_slice(&[10, 0, 0, 2]);
        rec.extend_from_slice(&1500u64.to_be_bytes());
        let (c, flows) = collect_raw(&[(
            1000,
            message_bytes(0, 1, 0, &[ts, data_set(TEMPLATE_ID_V4, &rec, &[])]),
        )]);
        assert!(flows.is_empty(), "缺关键字段不得伪造一条流");
        assert_eq!(c.stats().records_missing_key, 1);
    }

    // ---- 5. IPv6 与去重 ----
    #[test]
    fn ipv6_template_decodes_and_lengths_match() {
        let t = Template::ipv6();
        let ts = template_set_bytes(TEMPLATE_ID_V6, &t.fields);
        let mut rec = Vec::new();
        rec.extend_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        rec.extend_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        rec.extend_from_slice(&443u16.to_be_bytes());
        rec.extend_from_slice(&50000u16.to_be_bytes());
        rec.push(6);
        rec.extend_from_slice(&999u64.to_be_bytes());
        rec.extend_from_slice(&3u64.to_be_bytes());
        rec.extend_from_slice(&1u64.to_be_bytes());
        rec.extend_from_slice(&2u64.to_be_bytes());
        rec.extend_from_slice(&42u64.to_be_bytes());
        rec.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(rec.len(), t.record_len());
        let pad = vec![0u8; (4 - rec.len() % 4) % 4];
        let (c, flows) = collect_raw(&[(
            1000,
            message_bytes(0, 1, 0, &[ts, data_set(TEMPLATE_ID_V6, &rec, &pad)]),
        )]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].key.src_port, 443);
        assert_eq!(flows[0].flow_id, 42);
        assert!(matches!(flows[0].key.src_ip, IpAddr::V6(_)));
        assert_eq!(c.stats().malformed_datagrams, 0);
    }

    #[test]
    fn duplicate_record_within_window_is_dropped_and_counted() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
        let set = data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0]);
        // 同一记录重复发：网络重复或导出侧重传
        let (c, flows) = collect_raw(&[
            (1000, message_bytes(0, 1, 0, &[ts.clone(), set.clone()])),
            (2000, message_bytes(1, 1, 0, &[ts.clone(), set.clone()])),
        ]);
        let st = c.stats();
        assert_eq!(st.data_records, 2);
        assert_eq!(st.duplicate_records, 1);
        assert_eq!(st.delivered_records, 1);
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn dedup_window_is_bounded() {
        let t = v4_template();
        let ts = template_set_bytes(TEMPLATE_ID_V4, &t.fields);
        let cfg = CollectorConfig {
            dedup_window: 1,
            ..Default::default()
        };
        let mut c = Collector::new(cfg);
        let mk = |fid: u64| {
            let mut rec = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 6);
            let n = rec.len();
            rec[n - 12..n - 4].copy_from_slice(&fid.to_be_bytes());
            rec
        };
        // 窗口 = 1：A、B 之后 A 已经在窗口外 → 再收到 A 不算重复（口径如此）
        c.on_datagram(
            EXP,
            &message_bytes(
                0,
                1,
                0,
                &[ts.clone(), data_set(TEMPLATE_ID_V4, &mk(1), &[0, 0, 0])],
            ),
            1000,
        );
        c.on_datagram(
            EXP,
            &message_bytes(
                1,
                1,
                0,
                &[ts.clone(), data_set(TEMPLATE_ID_V4, &mk(2), &[0, 0, 0])],
            ),
            2000,
        );
        c.on_datagram(
            EXP,
            &message_bytes(
                2,
                1,
                0,
                &[ts.clone(), data_set(TEMPLATE_ID_V4, &mk(1), &[0, 0, 0])],
            ),
            3000,
        );
        assert_eq!(c.stats().duplicate_records, 0);
        assert_eq!(c.take_flows().len(), 3);
    }

    // ---- 6. 畸形报文防御 ----
    #[test]
    fn version_mismatch_is_reported_not_parsed() {
        let t = v4_template();
        let mut msg = message_bytes(0, 1, 0, &[template_set_bytes(TEMPLATE_ID_V4, &t.fields)]);
        msg[0..2].copy_from_slice(&9u16.to_be_bytes()); // NetFlow v9 打到同一端口
        let (c, flows) = collect_raw(&[(1000, msg)]);
        assert!(flows.is_empty());
        assert_eq!(c.stats().version_mismatch, 1);
        assert_eq!(c.stats().malformed_datagrams, 0);
    }

    #[test]
    fn short_and_overlong_messages_are_malformed() {
        let t = v4_template();
        let good = message_bytes(0, 1, 0, &[template_set_bytes(TEMPLATE_ID_V4, &t.fields)]);
        // 只剩 10 字节
        let (c1, _) = collect_raw(&[(1000, good[..10].to_vec())]);
        assert_eq!(c1.stats().malformed_datagrams, 1);
        // length 字段大于实际载荷（被截断）
        let mut cut = good.clone();
        cut[2..4].copy_from_slice(&((good.len() + 8) as u16).to_be_bytes());
        let (c2, _) = collect_raw(&[(1000, cut)]);
        assert_eq!(c2.stats().malformed_datagrams, 1);
        // Set 长度越界
        let mut bad = good.clone();
        let set_len_at = MSG_HEADER_LEN + 2;
        bad[set_len_at..set_len_at + 2].copy_from_slice(&4096u16.to_be_bytes());
        let (c3, _) = collect_raw(&[(1000, bad)]);
        assert_eq!(c3.stats().malformed_datagrams, 1);
    }

    #[test]
    fn template_declaring_record_len_one_cannot_flood_records() {
        // 模板把 record_len 压到 1 字节：一个 1400 字节的报文能"解出"1400 条记录，
        // 超过上限即判畸形（防注入，不是性能优化）。
        let fields = vec![FieldSpec {
            ie: Ie::ProtocolIdentifier,
            len: 1,
        }];
        let ts = template_set_bytes(TEMPLATE_ID_V4, &fields);
        let cfg = CollectorConfig {
            max_records_per_message: 16,
            ..Default::default()
        };
        let mut c = Collector::new(cfg);
        c.on_datagram(EXP, &message_bytes(0, 1, 0, &[ts.clone()]), 1000);
        let body = vec![6u8; 64];
        let out = c.on_datagram(
            EXP,
            &message_bytes(0, 1, 0, &[ts, data_set(TEMPLATE_ID_V4, &body, &[])]),
            2000,
        );
        assert_eq!(out, DatagramOutcome::Malformed);
        assert_eq!(c.stats().malformed_datagrams, 1);
    }

    // ---- 7. 与 FlowRecord 的转换口径 ----
    #[test]
    fn collected_flow_to_record_is_honest_about_what_is_missing() {
        let t = v4_template();
        let rec = v4_record([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, 6);
        let (_, flows) = collect_raw(&[(
            1000,
            message_bytes(
                0,
                1,
                0,
                &[
                    template_set_bytes(TEMPLATE_ID_V4, &t.fields),
                    data_set(TEMPLATE_ID_V4, &rec, &[0, 0, 0]),
                ],
            ),
        )]);
        let r = flows[0].to_flow_record();
        assert_eq!(r.session_id, 7);
        assert_eq!(r.packets, 10);
        assert_eq!(r.bytes, 1500);
        assert_eq!(r.first_seen_us, 1_700_000_000_000_000);
        assert_eq!(r.tcp_state, None, "IPFIX v1 不承载 TCP 状态，不许填占位值");
        assert_eq!(r.app.outcome, "not_inspected");
        assert_eq!(r.risk_score, None);
        // 规范五元组：反向后应与正向不同，且自身规范
        assert!(r.key.is_canonical());
    }

    #[test]
    fn loss_ppm_is_zero_when_nothing_received() {
        let c = Collector::new(CollectorConfig::default());
        assert_eq!(
            c.stats().loss_ppm(),
            0,
            "没收到任何记录时分母为 0，不许算成 100% 丢包"
        );
    }
}
