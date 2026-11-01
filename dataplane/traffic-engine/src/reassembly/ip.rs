// reassembly/ip.rs —— IPv4/IPv6 分片重组（CYS-TRF-018 / B008）。
//
// 这一层的存在理由只有一个：**四层端口只在首片里**。首片之前的非首片没有
// TCP/UDP 头，解码层拒绝它是正确的；但拒绝不等于完整适配 —— 分片数据报只有
// 在重组之后才能得到与未分片数据报相同的五元组、载荷长度和应用视图。
//
// 三条刻意写死的边界：
//
// 1. **完整数据报才产出逻辑包**。缺首片、缺尾、超时、超预算、重叠或长度矛盾
//    都只增加显式统计，不合成任何内层流。把不完整的字节交给解码器，就等于
//    让一个端口为 0 的假流去污染会话表。
// 2. **重叠一律拒绝**（RFC 5722 对 IPv6 的语义）。IPv4 的 BSD/Linux 两种
//    先到/后到策略在旁路设备上都会让“看到的字节”与接收端可能不一致；这里不
//    选边，直接报 `ipfrag.overlap`。完全相同的重复片是例外：它不改变字节，
//    只记 `duplicate`。
// 3. **所有上限都同时约束内存和队列**：单数据报载荷 ≤ 65535、片数、队列数、
//    空闲超时。随机 identification 的扫描流量因此不能把重组表撑成内存放大器。
//
// 本模块不主动探测、不推断主机是否在线；它只处理 pcap/采集面已经给出的帧。

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::channel::LinkLayer;

/// 单个数据报的 IP 载荷上限。IPv4 total length 与 IPv6 payload length 都是
/// 16 位字段；IPv6 jumbogram 不在这里假装支持。
pub const MAX_DATAGRAM_PAYLOAD: usize = 65_535;

/// 默认同时跟踪的分片数据报数。按 64 KiB/条的最坏情况，内存上界约 16 MiB。
pub const DEFAULT_MAX_DATAGRAMS: usize = 256;

/// 默认单数据报最多接受的唯一分片数。64 KiB 以 8 字节为界需要 8192 片；
/// 这里取 1024，覆盖常见 MTU 下的极端分片，同时给随机片数一个明确上限。
pub const DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM: usize = 1024;

/// 默认空闲超时。与 Linux 的 `ipfrag_time` 默认值一致（30 秒）。
pub const DEFAULT_TIMEOUT_US: u64 = 30_000_000;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const IPV6_FRAGMENT_HEADER: usize = 8;
const MAX_IPV6_EXT_HEADERS: u8 = 8;

/// 重组表的上限。`max_datagram_payload` 会被夹到协议字段允许的最大值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpFragConfig {
    pub max_datagrams: usize,
    pub max_fragments_per_datagram: usize,
    pub timeout_us: u64,
    pub max_datagram_payload: usize,
}

impl Default for IpFragConfig {
    fn default() -> Self {
        Self {
            max_datagrams: DEFAULT_MAX_DATAGRAMS,
            max_fragments_per_datagram: DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM,
            timeout_us: DEFAULT_TIMEOUT_US,
            max_datagram_payload: MAX_DATAGRAM_PAYLOAD,
        }
    }
}

impl IpFragConfig {
    fn normalized(self) -> Self {
        Self {
            max_datagrams: self.max_datagrams.max(1),
            max_fragments_per_datagram: self.max_fragments_per_datagram.max(1),
            timeout_us: self.timeout_us.max(1),
            max_datagram_payload: self.max_datagram_payload.clamp(1, MAX_DATAGRAM_PAYLOAD),
        }
    }
}

/// IP 版本。分片键必须带版本，否则同地址同 identification 的 IPv4/IPv6
/// 数据报会互相污染。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }
}

/// 重组失败的原因。每个值都是一个稳定的统计/事件码，不从 `Display` 文本反推。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFragError {
    /// 抓包被 snaplen 截断，或实有字节少于 IP 声明长度。不能补零冒充完整。
    TruncatedCapture,
    /// 载荷为 0 的分片。它既不能推进覆盖，也不可能是合法的最后一片。
    EmptyFragment,
    /// 非最后一片的载荷不是 8 字节的整数倍（RFC 791 / RFC 8200）。
    MisalignedFragment,
    /// 偏移 + 载荷超过单数据报上限。
    TooLarge,
    /// 单数据报分片数超过配置上限。
    TooManyFragments,
    /// 与已收分片重叠且不是完全相同的重复片。
    Overlap,
    /// 最后一片给出的总长与已有分片/此前最后一片矛盾。
    InconsistentLength,
    /// 同一偏移的重复首片携带了不同的 IP 头。
    InconsistentHeader,
    /// IP 头字段自相矛盾（如 total length < header length）。
    MalformedIpHeader,
    /// IPv6 jumbogram（payload length = 0）不支持分片重组。
    UnsupportedJumbogram,
}

impl IpFragError {
    /// 流水线 `decode_errors` 使用的稳定错误码。
    pub fn code(self) -> &'static str {
        match self {
            Self::TruncatedCapture => "ipfrag.truncated_capture",
            Self::EmptyFragment => "ipfrag.empty_fragment",
            Self::MisalignedFragment => "ipfrag.misaligned_fragment",
            Self::TooLarge => "ipfrag.too_large",
            Self::TooManyFragments => "ipfrag.too_many_fragments",
            Self::Overlap => "ipfrag.overlap",
            Self::InconsistentLength => "ipfrag.inconsistent_length",
            Self::InconsistentHeader => "ipfrag.inconsistent_header",
            Self::MalformedIpHeader => "ipfrag.malformed_ip_header",
            Self::UnsupportedJumbogram => "ipfrag.unsupported_jumbogram",
        }
    }
}

/// 一个已解析分片的摘要。事件流和统计都从这里取字段，避免两处各算一份。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentSummary {
    pub version: IpVersion,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub identification: u32,
    pub offset: usize,
    pub payload_len: usize,
    pub more_fragments: bool,
    /// 当前数据报已收的唯一分片数（不含完全重复片）。
    pub datagram_fragments: usize,
    /// 当前数据报已缓冲的唯一字节数。
    pub buffered_bytes: usize,
}

/// 重组完成的数据报。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledDatagram {
    /// 完整帧：原链路头/ VLAN + 首片 IP 头（已改写为未分片）+ 重组后的 IP 载荷。
    pub frame: Vec<u8>,
    /// 最后一片到达的时间。重组数据报只有在完整时才可交付，时间戳取完成时刻。
    pub timestamp_us: u64,
    pub version: IpVersion,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub identification: u32,
    pub fragments: usize,
    pub payload_bytes: usize,
}

/// `push` 的结果。`NotFragment` 必须原样交给普通解码器，不能在这里吞掉。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    NotFragment,
    Pending(FragmentSummary),
    Complete(ReassembledDatagram),
    Dropped {
        /// 解析成功但重组失败时有摘要；IP 头都无法解析时为 `None`。
        summary: Option<FragmentSummary>,
        error: IpFragError,
    },
}

/// 收尾结果。`non_initial_fragments` 只用于兼容既有的
/// `decode.non_initial_fragment` 统计口径：这些帧单独看仍然无法解出四层头。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpFragFinish {
    pub pending_datagrams: usize,
    pub pending_fragments: usize,
    pub non_initial_fragments: u64,
}

/// 重组统计。字段是 CLI 统计行的契约，改名必须同时改门禁脚本。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpFragStats {
    pub fragments_seen: u64,
    pub ipv4_fragments: u64,
    pub ipv6_fragments: u64,
    pub datagrams_seen: u64,
    pub datagrams_completed: u64,
    pub datagrams_incomplete: u64,
    pub datagrams_malformed: u64,
    pub duplicate_fragments: u64,
    pub overlap_fragments: u64,
    pub truncated_fragments: u64,
    pub oversized_fragments: u64,
    pub evicted_datagrams: u64,
    pub expired_datagrams: u64,
    pub bytes_reassembled: u64,
    pub pending_fragments_at_eof: usize,
}

impl IpFragStats {
    /// 单行渲染。未完成/畸形必须与成功分开报，否则“没重组”会被读成“重组了 0 条”。
    pub fn render_line(&self) -> String {
        format!(
            "ipfrag frags={} v4={} v6={} datagrams={} complete={} incomplete={} malformed={} dup={} overlap={} truncated={} oversize={} evicted={} expired={} bytes={} pending_at_eof={}",
            self.fragments_seen,
            self.ipv4_fragments,
            self.ipv6_fragments,
            self.datagrams_seen,
            self.datagrams_completed,
            self.datagrams_incomplete,
            self.datagrams_malformed,
            self.duplicate_fragments,
            self.overlap_fragments,
            self.truncated_fragments,
            self.oversized_fragments,
            self.evicted_datagrams,
            self.expired_datagrams,
            self.bytes_reassembled,
            self.pending_fragments_at_eof,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FragKey {
    V4 {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        id: u16,
        proto: u8,
    },
    V6 {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        id: u32,
    },
}

#[derive(Debug)]
struct ParsedFragment<'a> {
    key: FragKey,
    version: IpVersion,
    src: IpAddr,
    dst: IpAddr,
    identification: u32,
    offset: usize,
    more: bool,
    data: &'a [u8],
    l3_offset: usize,
    header: &'a [u8],
    /// 四层协议号。IPv4 取协议字段，IPv6 取分片头里的 Next Header。
    /// 同一个数据报的所有分片必须一致，但不参与 `FragKey`（IPv6 的键按
    /// RFC 8200 只有源/目的/Identification；不一致要显式拒绝，不能另起一条流）。
    next_header: u8,
}

impl ParsedFragment<'_> {
    fn summary(&self, datagram_fragments: usize, buffered_bytes: usize) -> FragmentSummary {
        FragmentSummary {
            version: self.version,
            src: self.src,
            dst: self.dst,
            identification: self.identification,
            offset: self.offset,
            payload_len: self.data.len(),
            more_fragments: self.more,
            datagram_fragments,
            buffered_bytes,
        }
    }
}

#[derive(Debug, Clone)]
struct Part {
    offset: usize,
    data: Vec<u8>,
}

impl Part {
    fn end(&self) -> usize {
        self.offset.saturating_add(self.data.len())
    }
}

#[derive(Debug)]
struct Entry {
    header: Option<Vec<u8>>,
    next_header: Option<u8>,
    l3_offset: usize,
    parts: Vec<Part>,
    total_payload: Option<usize>,
    fragments: usize,
    buffered_bytes: usize,
    non_initial_fragments: u64,
    last_seen_us: u64,
    version: IpVersion,
    src: IpAddr,
    dst: IpAddr,
    identification: u32,
}

impl Entry {
    fn new(f: &ParsedFragment<'_>, ts: u64) -> Self {
        Self {
            header: None,
            next_header: None,
            l3_offset: f.l3_offset,
            parts: Vec::new(),
            total_payload: None,
            fragments: 0,
            buffered_bytes: 0,
            non_initial_fragments: 0,
            last_seen_us: ts,
            version: f.version,
            src: f.src,
            dst: f.dst,
            identification: f.identification,
        }
    }

    fn summary(&self, f: &ParsedFragment<'_>) -> FragmentSummary {
        f.summary(self.fragments, self.buffered_bytes)
    }

    /// 插入一片。调用方已经检查过队列和配置；这里只处理覆盖关系。
    fn insert(
        &mut self,
        f: &ParsedFragment<'_>,
        cfg: &IpFragConfig,
    ) -> Result<InsertKind, IpFragError> {
        let offset = f.offset;
        let end = offset
            .checked_add(f.data.len())
            .ok_or(IpFragError::TooLarge)?;
        if f.data.is_empty() {
            return Err(IpFragError::EmptyFragment);
        }
        if end > cfg.max_datagram_payload {
            return Err(IpFragError::TooLarge);
        }
        if f.more && f.data.len() % 8 != 0 {
            return Err(IpFragError::MisalignedFragment);
        }
        match self.next_header {
            Some(old) if old != f.next_header => return Err(IpFragError::InconsistentHeader),
            Some(_) => {}
            None => self.next_header = Some(f.next_header),
        }

        // 统计口径按“帧”计：重复的非首片也仍然是一帧无法单独解码的片，
        // 与 tshark 的 `ip.frag_offset > 0` 计数保持一致。
        if offset != 0 {
            self.non_initial_fragments += 1;
        }

        // 首片携带重建所需的 IP 头。重复首片若头不同，不能拿“后到的头”替换：
        // 端口、地址和扩展头都可能被改写，必须显式拒绝。
        if offset == 0 {
            match &self.header {
                Some(old) if old.as_slice() != f.header => {
                    return Err(IpFragError::InconsistentHeader)
                }
                Some(_) => {}
                None => {}
            }
        }

        for p in &self.parts {
            let overlap_start = offset.max(p.offset);
            let overlap_end = end.min(p.end());
            if overlap_start >= overlap_end {
                continue;
            }
            // 完全相同的重复片是唯一允许的“重叠”。只要有一个字节不同，
            // 就不能选择先到/后到语义：那会让旁路看到的载荷与接收端不一致。
            if p.offset == offset && p.data.len() == f.data.len() && p.data == f.data {
                return Ok(InsertKind::Duplicate);
            }
            return Err(IpFragError::Overlap);
        }

        if self.fragments >= cfg.max_fragments_per_datagram {
            return Err(IpFragError::TooManyFragments);
        }

        if offset == 0 {
            self.header = Some(f.header.to_vec());
        }

        if !f.more {
            match self.total_payload {
                Some(old) if old != end => return Err(IpFragError::InconsistentLength),
                Some(_) => {}
                None => self.total_payload = Some(end),
            }
        } else if self.total_payload.is_some_and(|total| end > total) {
            return Err(IpFragError::InconsistentLength);
        }

        self.parts.push(Part {
            offset,
            data: f.data.to_vec(),
        });
        self.fragments += 1;
        self.buffered_bytes += f.data.len();
        Ok(InsertKind::Accepted)
    }

    /// 只在“最后一片已到 + 首片已到 + 覆盖 0..total 连续”时交付。
    fn try_build(&self) -> Option<Result<BuiltDatagram, IpFragError>> {
        let total = self.total_payload?;
        let header = self.header.as_ref()?;
        let mut parts: Vec<&Part> = self.parts.iter().collect();
        parts.sort_by_key(|p| p.offset);
        let mut cursor = 0usize;
        for p in &parts {
            if p.offset != cursor {
                // 有空洞就继续等；空洞不是“可以猜一段”的理由。
                return None;
            }
            let end = p.end();
            if end < cursor {
                return Some(Err(IpFragError::Overlap));
            }
            cursor = end;
            if cursor > total {
                return Some(Err(IpFragError::InconsistentLength));
            }
        }
        if cursor != total {
            return None;
        }
        Some(build_datagram(
            header,
            self.l3_offset,
            self.version,
            &parts,
            total,
            self.src,
            self.dst,
            self.identification,
            self.fragments,
        ))
    }
}

enum InsertKind {
    Accepted,
    Duplicate,
}

/// 分片重组器。单线程使用；流水线的派发端在分片前串行调用它。
#[derive(Debug)]
pub struct IpReassembler {
    cfg: IpFragConfig,
    entries: BTreeMap<FragKey, Entry>,
    stats: IpFragStats,
}

impl Default for IpReassembler {
    fn default() -> Self {
        Self::new(IpFragConfig::default())
    }
}

impl IpReassembler {
    pub fn new(cfg: IpFragConfig) -> Self {
        Self {
            cfg: cfg.normalized(),
            entries: BTreeMap::new(),
            stats: IpFragStats::default(),
        }
    }

    pub fn stats(&self) -> &IpFragStats {
        &self.stats
    }

    /// 当前等待中的数据报数（测试与诊断用）。
    pub fn pending_datagrams(&self) -> usize {
        self.entries.len()
    }

    /// 处理一帧。非分片返回 `NotFragment`，调用方必须继续走普通解码。
    pub fn push(
        &mut self,
        frame: &[u8],
        link: LinkLayer,
        timestamp_us: u64,
        capture_truncated: bool,
    ) -> PushOutcome {
        let parsed = match parse_fragment(frame, link) {
            Ok(None) => return PushOutcome::NotFragment,
            Ok(Some(f)) => f,
            Err(e) => {
                self.bump_error(e);
                self.stats.datagrams_malformed += 1;
                return PushOutcome::Dropped {
                    summary: None,
                    error: e,
                };
            }
        };

        self.stats.fragments_seen += 1;
        match parsed.version {
            IpVersion::V4 => self.stats.ipv4_fragments += 1,
            IpVersion::V6 => self.stats.ipv6_fragments += 1,
        }
        self.evict_expired(timestamp_us);

        if capture_truncated {
            self.stats.truncated_fragments += 1;
            self.stats.datagrams_malformed += 1;
            return PushOutcome::Dropped {
                summary: Some(parsed.summary(0, 0)),
                error: IpFragError::TruncatedCapture,
            };
        }

        let key = parsed.key;
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= self.cfg.max_datagrams {
                self.evict_oldest();
            }
            self.entries.insert(key, Entry::new(&parsed, timestamp_us));
            self.stats.datagrams_seen += 1;
        }
        let Some(entry) = self.entries.get_mut(&key) else {
            // `contains_key` 与 `insert` 之间没有并发入口；走到这里只可能是
            // 内部状态被破坏，显式报错而不是继续读一个不存在的条目。
            return PushOutcome::Dropped {
                summary: None,
                error: IpFragError::MalformedIpHeader,
            };
        };
        entry.last_seen_us = entry.last_seen_us.max(timestamp_us);

        let insert = entry.insert(&parsed, &self.cfg);
        let summary = entry.summary(&parsed);
        match insert {
            Ok(InsertKind::Duplicate) => {
                self.stats.duplicate_fragments += 1;
                PushOutcome::Pending(summary)
            }
            Ok(InsertKind::Accepted) => match entry.try_build() {
                Some(Ok(d)) => {
                    self.entries.remove(&key);
                    self.stats.datagrams_completed += 1;
                    self.stats.bytes_reassembled += d.payload_bytes as u64;
                    PushOutcome::Complete(ReassembledDatagram {
                        frame: d.frame,
                        timestamp_us,
                        version: parsed.version,
                        src: d.src,
                        dst: d.dst,
                        identification: d.identification,
                        fragments: d.fragments,
                        payload_bytes: d.payload_bytes,
                    })
                }
                Some(Err(e)) => {
                    self.entries.remove(&key);
                    self.bump_error(e);
                    self.stats.datagrams_malformed += 1;
                    PushOutcome::Dropped {
                        summary: Some(summary),
                        error: e,
                    }
                }
                None => PushOutcome::Pending(summary),
            },
            Err(e) => {
                self.entries.remove(&key);
                self.bump_error(e);
                self.stats.datagrams_malformed += 1;
                PushOutcome::Dropped {
                    summary: Some(summary),
                    error: e,
                }
            }
        }
    }

    /// 收尾：所有仍在等片的数据报都是**未完成**，不是“已重组但没输出”。
    pub fn finish(&mut self) -> IpFragFinish {
        let mut out = IpFragFinish::default();
        for (_, e) in std::mem::take(&mut self.entries) {
            out.pending_datagrams += 1;
            out.pending_fragments += e.fragments;
            out.non_initial_fragments += e.non_initial_fragments;
        }
        self.stats.datagrams_incomplete += out.pending_datagrams as u64;
        self.stats.pending_fragments_at_eof = out.pending_fragments;
        out
    }

    fn bump_error(&mut self, e: IpFragError) {
        match e {
            IpFragError::Overlap | IpFragError::InconsistentHeader => {
                self.stats.overlap_fragments += 1;
            }
            IpFragError::TooLarge => self.stats.oversized_fragments += 1,
            IpFragError::TruncatedCapture => self.stats.truncated_fragments += 1,
            _ => {}
        }
    }

    fn evict_expired(&mut self, now_us: u64) {
        let timeout = self.cfg.timeout_us;
        let expired: Vec<FragKey> = self
            .entries
            .iter()
            .filter(|(_, e)| now_us.saturating_sub(e.last_seen_us) >= timeout)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            self.entries.remove(&k);
            self.stats.expired_datagrams += 1;
            self.stats.datagrams_incomplete += 1;
        }
    }

    fn evict_oldest(&mut self) {
        let victim = self
            .entries
            .iter()
            .min_by_key(|(k, e)| (e.last_seen_us, **k))
            .map(|(k, _)| *k);
        if let Some(k) = victim {
            self.entries.remove(&k);
            self.stats.evicted_datagrams += 1;
            self.stats.datagrams_incomplete += 1;
        }
    }
}

struct BuiltDatagram {
    frame: Vec<u8>,
    src: IpAddr,
    dst: IpAddr,
    identification: u32,
    fragments: usize,
    payload_bytes: usize,
}

#[allow(clippy::too_many_arguments)]
fn build_datagram(
    header: &[u8],
    l3_offset: usize,
    version: IpVersion,
    parts: &[&Part],
    total: usize,
    src: IpAddr,
    dst: IpAddr,
    identification: u32,
    fragments: usize,
) -> Result<BuiltDatagram, IpFragError> {
    if l3_offset > header.len() || total > MAX_DATAGRAM_PAYLOAD {
        return Err(IpFragError::TooLarge);
    }
    let mut frame = Vec::with_capacity(header.len().saturating_add(total));
    frame.extend_from_slice(header);
    for p in parts {
        frame.extend_from_slice(&p.data);
    }

    match version {
        IpVersion::V4 => {
            let ip_header_len = header.len() - l3_offset;
            let total_len = ip_header_len
                .checked_add(total)
                .ok_or(IpFragError::TooLarge)?;
            if total_len > u16::MAX as usize || total_len < IPV4_MIN_HEADER {
                return Err(IpFragError::TooLarge);
            }
            frame[l3_offset + 2..l3_offset + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
            // 重组后不再是分片：清掉 MF/offset，也清掉 DF（数据报已经完整）。
            frame[l3_offset + 6..l3_offset + 8].copy_from_slice(&[0, 0]);
            recompute_ipv4_checksum(&mut frame, l3_offset, ip_header_len)?;
        }
        IpVersion::V6 => {
            let prefix_len = header.len() - l3_offset;
            if prefix_len < IPV6_HEADER + IPV6_FRAGMENT_HEADER {
                return Err(IpFragError::MalformedIpHeader);
            }
            let payload_len = (prefix_len - IPV6_HEADER)
                .checked_add(total)
                .ok_or(IpFragError::TooLarge)?;
            if payload_len > u16::MAX as usize {
                return Err(IpFragError::TooLarge);
            }
            frame[l3_offset + 4..l3_offset + 6]
                .copy_from_slice(&(payload_len as u16).to_be_bytes());
            let frag_header = header.len() - IPV6_FRAGMENT_HEADER;
            // 只清 offset/M/保留位，保留 next header 与 identification。
            frame[frag_header + 2..frag_header + 4].copy_from_slice(&[0, 0]);
        }
    }

    Ok(BuiltDatagram {
        frame,
        src,
        dst,
        identification,
        fragments,
        payload_bytes: total,
    })
}

fn recompute_ipv4_checksum(
    frame: &mut [u8],
    l3_offset: usize,
    header_len: usize,
) -> Result<(), IpFragError> {
    let end = l3_offset
        .checked_add(header_len)
        .ok_or(IpFragError::MalformedIpHeader)?;
    let header = frame
        .get_mut(l3_offset..end)
        .ok_or(IpFragError::MalformedIpHeader)?;
    if header.len() < IPV4_MIN_HEADER {
        return Err(IpFragError::MalformedIpHeader);
    }
    header[10] = 0;
    header[11] = 0;
    let c = internet_checksum(header);
    header[10..12].copy_from_slice(&c.to_be_bytes());
    Ok(())
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// 解析分片；`Ok(None)` 表示“不是需要重组的分片”，必须交给普通解码器。
fn parse_fragment<'a>(
    frame: &'a [u8],
    link: LinkLayer,
) -> Result<Option<ParsedFragment<'a>>, IpFragError> {
    let (ether_type, l3_offset, _) = match crate::channel::link_payload(frame, link) {
        Ok(v) => v,
        // 链路头/标签本身不完整：普通解码器会给出更精确的 `decode.*` 错误。
        Err(_) => return Ok(None),
    };
    match ether_type {
        ETHERTYPE_IPV4 => parse_ipv4(frame, l3_offset),
        ETHERTYPE_IPV6 => parse_ipv6(frame, l3_offset),
        _ => Ok(None),
    }
}

fn parse_ipv4<'a>(frame: &'a [u8], l3: usize) -> Result<Option<ParsedFragment<'a>>, IpFragError> {
    if frame.len() < l3 + IPV4_MIN_HEADER {
        return Ok(None);
    }
    let vihl = frame[l3];
    if vihl >> 4 != 4 {
        return Ok(None);
    }
    let ihl = usize::from(vihl & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER {
        return Ok(None);
    }
    if frame.len() < l3 + ihl {
        return Ok(None);
    }
    let frag_field = be16(&frame[l3 + 6..l3 + 8]);
    let offset_units = usize::from(frag_field & 0x1fff);
    let more = frag_field & 0x2000 != 0;
    // 首片且没有 MF 只是普通 IP 数据报；DF 也不产生分片。
    if offset_units == 0 && !more {
        return Ok(None);
    }
    let total_len = usize::from(be16(&frame[l3 + 2..l3 + 4]));
    if total_len < ihl {
        return Err(IpFragError::MalformedIpHeader);
    }
    if frame.len() < l3 + total_len {
        return Err(IpFragError::TruncatedCapture);
    }
    let offset = offset_units.checked_mul(8).ok_or(IpFragError::TooLarge)?;
    let data = &frame[l3 + ihl..l3 + total_len];
    let mut src = [0u8; 4];
    src.copy_from_slice(&frame[l3 + 12..l3 + 16]);
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&frame[l3 + 16..l3 + 20]);
    let src = Ipv4Addr::from(src);
    let dst = Ipv4Addr::from(dst);
    let identification = be16(&frame[l3 + 4..l3 + 6]);
    let proto = frame[l3 + 9];

    Ok(Some(ParsedFragment {
        key: FragKey::V4 {
            src,
            dst,
            id: identification,
            proto,
        },
        version: IpVersion::V4,
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        identification: u32::from(identification),
        offset,
        more,
        data,
        l3_offset: l3,
        header: &frame[..l3 + ihl],
        next_header: proto,
    }))
}

fn parse_ipv6<'a>(frame: &'a [u8], l3: usize) -> Result<Option<ParsedFragment<'a>>, IpFragError> {
    if frame.len() < l3 + IPV6_HEADER {
        return Ok(None);
    }
    if frame[l3] >> 4 != 6 {
        return Ok(None);
    }
    let payload_len = usize::from(be16(&frame[l3 + 4..l3 + 6]));
    let mut next = frame[l3 + 6];
    let mut cursor = l3 + IPV6_HEADER;
    let mut hops = 0u8;
    let declared_end = l3 + IPV6_HEADER + payload_len;

    loop {
        if next == 44 {
            // 分片头 8 字节固定；偏移字段占前 2 字节的高 13 位。
            if payload_len == 0 {
                return Err(IpFragError::UnsupportedJumbogram);
            }
            if cursor + IPV6_FRAGMENT_HEADER > frame.len() {
                return Err(IpFragError::TruncatedCapture);
            }
            if cursor + IPV6_FRAGMENT_HEADER > declared_end {
                return Err(IpFragError::MalformedIpHeader);
            }
            let frag_field = be16(&frame[cursor + 2..cursor + 4]);
            let offset_units = usize::from(frag_field >> 3);
            let more = frag_field & 1 != 0;
            if offset_units == 0 && !more {
                // 原子分片（RFC 6946）：不是实际分片，普通解码器能直接处理。
                return Ok(None);
            }
            if declared_end > frame.len() {
                return Err(IpFragError::TruncatedCapture);
            }
            let offset = offset_units.checked_mul(8).ok_or(IpFragError::TooLarge)?;
            let header_end = cursor + IPV6_FRAGMENT_HEADER;
            let data = &frame[header_end..declared_end];
            let mut src = [0u8; 16];
            src.copy_from_slice(&frame[l3 + 8..l3 + 24]);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&frame[l3 + 24..l3 + 40]);
            let src = Ipv6Addr::from(src);
            let dst = Ipv6Addr::from(dst);
            let identification = be32(&frame[cursor + 4..cursor + 8]);

            return Ok(Some(ParsedFragment {
                key: FragKey::V6 {
                    src,
                    dst,
                    id: identification,
                },
                version: IpVersion::V6,
                src: IpAddr::V6(src),
                dst: IpAddr::V6(dst),
                identification,
                offset,
                more,
                data,
                l3_offset: l3,
                header: &frame[..header_end],
                next_header: frame[cursor],
            }));
        }

        // 逐跳选项 / 路由头 / 目的选项：长度单位 8 字节，不含首 8 字节。
        if matches!(next, 0 | 43 | 60) {
            if hops == MAX_IPV6_EXT_HEADERS {
                return Ok(None);
            }
            if cursor + 8 > frame.len() || cursor + 8 > declared_end {
                return Ok(None);
            }
            let ext_len = (usize::from(frame[cursor + 1]) + 1) * 8;
            let next_cursor = cursor
                .checked_add(ext_len)
                .ok_or(IpFragError::MalformedIpHeader)?;
            if next_cursor > frame.len() || next_cursor > declared_end {
                return Ok(None);
            }
            next = frame[cursor];
            cursor = next_cursor;
            hops += 1;
            continue;
        }
        // 认证头：长度单位 4 字节，不含首 8 字节（len + 2）。
        if next == 51 {
            if hops == MAX_IPV6_EXT_HEADERS {
                return Ok(None);
            }
            if cursor + 8 > frame.len() || cursor + 8 > declared_end {
                return Ok(None);
            }
            let ext_len = (usize::from(frame[cursor + 1]) + 2) * 4;
            let next_cursor = cursor
                .checked_add(ext_len)
                .ok_or(IpFragError::MalformedIpHeader)?;
            if next_cursor > frame.len() || next_cursor > declared_end {
                return Ok(None);
            }
            next = frame[cursor];
            cursor = next_cursor;
            hops += 1;
            continue;
        }
        // 不是分片（TCP/UDP/ICMP/ESP/未知），交给普通解码器。
        return Ok(None);
    }
}

#[cfg(test)]
mod tests;
