// gre.rs —— GRE / PPTP GRE 有界解析（RFC 2784 / RFC 2890 / RFC 2637）。
//
// 定位：基础隧道协议识别只回答“这一条 IP 载荷是不是结构完整的 GRE，以及
// 它带了什么头字段、里面是什么协议”。GRE 没有端口，不能进应用识别；
// 本模块输出报文级事件与流水线计数。
//
// 四个刻意的边界：
//
// 1. **版本只认 0 和 1**。版本 0 是 RFC 2784/2890 的 GRE，版本 1 是 RFC 2637
//    的 PPTP 增强 GRE；2..7 未定义，直接报错而不是当版本 0 解析。
// 2. **可选头按位逐个走**。C/R/K/S 位决定 checksum+offset、key、sequence 是否
//    存在；SRE 路由列表按 4 字节头 + 数据长度遍历，并设 64 条上限。任何一步
//    越界都是明确的 `TruncatedHeader`/`BadRouting`，不跳着猜下一个字段。
// 3. **PPTP 只接受它自己的形状**：version=1、protocol=0x880B、K 必须置位，
//    R/s/Recur/保留位必须为 0。载荷长度大于实有字节时记截断，不把短包当完整。
// 4. **“无 key”不等于 mGRE**。mGRE 是点对多点部署形态，单包上没有可判定的
//    标志；这里只输出 `key_present=false`，不推断拓扑，也不把无 key 的 GRE
//    直接命名为 mGRE。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// GRE 的 IP 协议号。
pub const IPPROTO_GRE: u8 = 47;
/// PPTP 增强 GRE 的 protocol type（RFC 2637）。
pub const PPTP_PROTOCOL_TYPE: u16 = 0x880B;
/// ERSPAN 的 protocol type（Cisco 私有扩展，只做有界标注，不展开镜像头）。
pub const ERSPAN_PROTOCOL_TYPE: u16 = 0x88BE;

const BASE_HEADER_LEN: usize = 4;
const PPTP_BASE_HEADER_LEN: usize = 8;
const PPTP_MIN_PAYLOAD_LEN: usize = 2;
const MAX_SRE: usize = 64;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_TEB: u16 = 0x6558;
const ETHERTYPE_MPLS_UNICAST: u16 = 0x8847;
const ETHERTYPE_MPLS_MULTICAST: u16 = 0x8848;

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// 解析失败的具体位置。与 `channel::DecodeError` 分开：GRE 头坏掉不是 IP 解码失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreError {
    /// 固定头或某个可选头字段不足。
    TruncatedHeader { need: usize, got: usize },
    /// 版本 2..7 未定义。
    UnsupportedVersion { version: u8 },
    /// PPTP 增强 GRE 的形状不符合 RFC 2637。
    BadPptp { reason: &'static str },
    /// 源路由 SRE 列表越界或长度字段不成立。
    BadRouting { at: usize, need: usize, got: usize },
    /// SRE 数量超过上限。
    TooManySre { limit: usize },
}

impl GreError {
    /// 稳定错误码，供统计/日志按原因聚合。
    pub fn code(self) -> &'static str {
        match self {
            GreError::TruncatedHeader { .. } => "gre.truncated_header",
            GreError::UnsupportedVersion { .. } => "gre.unsupported_version",
            GreError::BadPptp { .. } => "gre.bad_pptp",
            GreError::BadRouting { .. } => "gre.bad_routing",
            GreError::TooManySre { .. } => "gre.too_many_sre",
        }
    }
}

impl fmt::Display for GreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GreError::TruncatedHeader { need, got } => {
                write!(f, "GRE 头不完整：需要 {need} 字节，实有 {got} 字节")
            }
            GreError::UnsupportedVersion { version } => {
                write!(f, "不支持的 GRE 版本 {version}（只认 0/1）")
            }
            GreError::BadPptp { reason } => write!(f, "PPTP 增强 GRE 形状不成立：{reason}"),
            GreError::BadRouting { at, need, got } => {
                write!(
                    f,
                    "GRE 源路由 SRE 越界：偏移 {at} 需要 {need} 字节，实有 {got} 字节"
                )
            }
            GreError::TooManySre { limit } => write!(f, "GRE 源路由 SRE 超过 {limit} 条"),
        }
    }
}

impl std::error::Error for GreError {}

/// GRE 内层协议的 bounded 视图。
///
/// `complete_header` 表示“按该协议自身的头长度，字节够且版本/IHL 自洽”；
/// 不够时字段能读多少写多少，**不把缺失的地址补成 0.0.0.0/::**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerProtocol {
    pub kind: &'static str,
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub protocol: Option<u8>,
    pub declared_len: Option<u16>,
    pub header_len: Option<usize>,
    pub captured_len: usize,
    pub complete_header: bool,
    /// 透明以太网桥接（0x6558）时的内层 EtherType。
    pub inner_ether_type: Option<u16>,
    /// 透明以太网桥接时从外到内的 VLAN ID（最多两层）。
    pub inner_vlan_ids: Vec<u16>,
}

impl InnerProtocol {
    fn new(kind: &'static str, captured_len: usize) -> Self {
        Self {
            kind,
            source: None,
            destination: None,
            protocol: None,
            declared_len: None,
            header_len: None,
            captured_len,
            complete_header: false,
            inner_ether_type: None,
            inner_vlan_ids: Vec::new(),
        }
    }
}

/// 一条结构可解析的 GRE 报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GreFrame {
    pub version: u8,
    pub checksum_present: bool,
    pub routing_present: bool,
    pub key_present: bool,
    pub sequence_present: bool,
    pub ack_present: bool,
    pub strict_source_route: bool,
    pub recursion_control: u8,
    /// 未定义/保留位置位；原样保留，不从单个包推断发送端实现。
    pub reserved_flags: u16,
    pub protocol_type: u16,
    pub checksum: Option<u16>,
    pub routing_offset: Option<u16>,
    pub key: Option<u32>,
    pub sequence: Option<u32>,
    pub ack: Option<u32>,
    pub sre_count: u32,
    /// 固定头 + 可选头 + SRE 的总长度。
    pub header_len: usize,
    /// PPTP 增强 GRE 的载荷长度字段（不含 GRE 头）。
    pub pptp_payload_len: Option<u16>,
    pub pptp_call_id: Option<u16>,
    pub inner: Option<InnerProtocol>,
    /// PPTP 载荷长度声明大于实有字节；或 GRE 头之后没有可解析的内层头。
    pub truncated: bool,
    /// 采集侧 `orig_len > caplen`。
    pub capture_truncated: bool,
}

impl GreFrame {
    /// `gre` 或 `pptp`：只由 version 决定，不根据端口/地址猜。
    pub fn mode(&self) -> &'static str {
        if self.version == 1 {
            "pptp"
        } else {
            "gre"
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        protocol_name(self.protocol_type)
    }

    /// 一行稳定 JSON（字段顺序固定；未知值用 `null`，不缺席）。
    pub fn to_json_line(&self, timestamp_us: u64, frame: u64, frame_len: usize) -> String {
        let inner = match &self.inner {
            None => "null".to_string(),
            Some(i) => {
                let vlans = i
                    .inner_vlan_ids
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "{{\"kind\":\"{}\",\"source\":{},\"destination\":{},\"protocol\":{},\
                     \"declared_len\":{},\"header_len\":{},\"captured_len\":{},\
                     \"complete_header\":{},\"inner_ether_type\":{},\"inner_vlan_ids\":[{}]}}",
                    i.kind,
                    json_string_opt(i.source.map(|v| v.to_string())),
                    json_string_opt(i.destination.map(|v| v.to_string())),
                    json_opt_num(i.protocol.map(u64::from)),
                    json_opt_num(i.declared_len.map(u64::from)),
                    json_opt_num(i.header_len.map(|v| v as u64)),
                    i.captured_len,
                    i.complete_header,
                    json_opt_num(i.inner_ether_type.map(u64::from)),
                    vlans,
                )
            }
        };
        format!(
            "{{\"timestamp_us\":{timestamp_us},\"frame\":{frame},\"frame_len\":{frame_len},\
             \"capture_truncated\":{},\"version\":{},\"mode\":\"{}\",\
             \"checksum_present\":{},\"routing_present\":{},\"key_present\":{},\
             \"sequence_present\":{},\"ack_present\":{},\"strict_source_route\":{},\
             \"recursion_control\":{},\"reserved_flags\":{},\
             \"protocol_type\":{},\"protocol_name\":\"{}\",\
             \"checksum\":{},\"routing_offset\":{},\"key\":{},\"sequence\":{},\"ack\":{},\
             \"sre_count\":{},\"header_len\":{},\
             \"pptp_payload_len\":{},\"pptp_call_id\":{},\
             \"truncated\":{},\"inner\":{inner}}}",
            self.capture_truncated,
            self.version,
            self.mode(),
            self.checksum_present,
            self.routing_present,
            self.key_present,
            self.sequence_present,
            self.ack_present,
            self.strict_source_route,
            self.recursion_control,
            self.reserved_flags,
            self.protocol_type,
            self.protocol_name(),
            json_opt_num(self.checksum.map(u64::from)),
            json_opt_num(self.routing_offset.map(u64::from)),
            json_opt_num(self.key.map(u64::from)),
            json_opt_num(self.sequence.map(u64::from)),
            json_opt_num(self.ack.map(u64::from)),
            self.sre_count,
            self.header_len,
            json_opt_num(self.pptp_payload_len.map(u64::from)),
            json_opt_num(self.pptp_call_id.map(u64::from)),
            self.truncated,
        )
    }
}

/// 解析一段从 GRE 固定头开始的 IP 载荷（IP protocol = 47）。
pub fn parse(payload: &[u8]) -> Result<GreFrame, GreError> {
    if payload.len() < BASE_HEADER_LEN {
        return Err(GreError::TruncatedHeader {
            need: BASE_HEADER_LEN,
            got: payload.len(),
        });
    }
    let flags = be16(payload, 0);
    let version = (flags & 0x0007) as u8;
    match version {
        0 => parse_v0(payload, flags),
        1 => parse_pptp(payload, flags),
        _ => Err(GreError::UnsupportedVersion { version }),
    }
}

fn parse_v0(payload: &[u8], flags: u16) -> Result<GreFrame, GreError> {
    let protocol_type = be16(payload, 2);
    let checksum_present = flags & 0x8000 != 0;
    let routing_present = flags & 0x4000 != 0;
    let key_present = flags & 0x2000 != 0;
    let sequence_present = flags & 0x1000 != 0;
    let strict_source_route = flags & 0x0800 != 0;
    let recursion_control = ((flags >> 8) & 0x07) as u8;
    let reserved_flags = flags & 0x00f8;
    let mut off = BASE_HEADER_LEN;
    let mut checksum = None;
    let mut routing_offset = None;
    if checksum_present || routing_present {
        ensure(payload, off + 4)?;
        if checksum_present {
            checksum = Some(be16(payload, off));
        }
        routing_offset = Some(be16(payload, off + 2));
        off += 4;
    }
    let mut key = None;
    if key_present {
        ensure(payload, off + 4)?;
        key = Some(be32(payload, off));
        off += 4;
    }
    let mut sequence = None;
    if sequence_present {
        ensure(payload, off + 4)?;
        sequence = Some(be32(payload, off));
        off += 4;
    }
    let mut sre_count = 0u32;
    if routing_present {
        // RFC 1701：SRE Length == 0 的那一项是列表结束标记（它自身仍占 4 字节头）。
        loop {
            // 至少要能读出 AF(2) + offset(1) + length(1)。
            ensure(payload, off + 4)?;
            let length = usize::from(payload[off + 3]);
            if length == 0 {
                off += 4;
                break;
            }
            if sre_count as usize >= MAX_SRE {
                return Err(GreError::TooManySre { limit: MAX_SRE });
            }
            let need = off + 4 + length;
            if need > payload.len() {
                return Err(GreError::BadRouting {
                    at: off,
                    need: 4 + length,
                    got: payload.len() - off,
                });
            }
            sre_count += 1;
            off = need;
        }
    }
    let mut frame = GreFrame {
        version: 0,
        checksum_present,
        routing_present,
        key_present,
        sequence_present,
        ack_present: false,
        strict_source_route,
        recursion_control,
        reserved_flags,
        protocol_type,
        checksum,
        routing_offset,
        key,
        sequence,
        ack: None,
        sre_count,
        header_len: off,
        pptp_payload_len: None,
        pptp_call_id: None,
        inner: None,
        truncated: false,
        capture_truncated: false,
    };
    let rest = &payload[off..];
    frame.inner = Some(parse_inner(protocol_type, rest));
    // 未知 protocol type 是“不知道内层怎么解”，不是“字节被截断”。
    frame.truncated = matches!(
        protocol_type,
        ETHERTYPE_IPV4
            | ETHERTYPE_IPV6
            | ETHERTYPE_TEB
            | PPTP_PROTOCOL_TYPE
            | ERSPAN_PROTOCOL_TYPE
            | ETHERTYPE_MPLS_UNICAST
            | ETHERTYPE_MPLS_MULTICAST
    ) && frame
        .inner
        .as_ref()
        .map(|i| !i.complete_header)
        .unwrap_or(false);
    Ok(frame)
}

fn parse_pptp(payload: &[u8], flags: u16) -> Result<GreFrame, GreError> {
    // RFC 2637：只有 K/S/A 与 version=1 允许出现。
    const ALLOWED: u16 = 0x2000 | 0x1000 | 0x0080 | 0x0007;
    if flags & !ALLOWED != 0 {
        return Err(GreError::BadPptp {
            reason: "R/s/Recur/保留位必须为 0",
        });
    }
    if flags & 0x2000 == 0 {
        return Err(GreError::BadPptp {
            reason: "K（key present）必须置位",
        });
    }
    if payload.len() < PPTP_BASE_HEADER_LEN {
        return Err(GreError::TruncatedHeader {
            need: PPTP_BASE_HEADER_LEN,
            got: payload.len(),
        });
    }
    let protocol_type = be16(payload, 2);
    if protocol_type != PPTP_PROTOCOL_TYPE {
        return Err(GreError::BadPptp {
            reason: "protocol type 必须是 0x880B",
        });
    }
    // PPTP 的 Key 就是基础头 offset 4 的 4 字节：高 16 位载荷长度，低 16 位 Call ID。
    // 它不是“Key Present 之后额外 4 字节”；RFC 2637 的增强 GRE 没有那个字段。
    let key = Some(be32(payload, 4));
    let pptp_payload_len = be16(payload, 4);
    let pptp_call_id = be16(payload, 6);
    let sequence_present = flags & 0x1000 != 0;
    let ack_present = flags & 0x0080 != 0;
    let mut off = PPTP_BASE_HEADER_LEN;
    let mut sequence = None;
    if sequence_present {
        ensure(payload, off + 4)?;
        sequence = Some(be32(payload, off));
        off += 4;
    }
    let mut ack = None;
    if ack_present {
        ensure(payload, off + 4)?;
        ack = Some(be32(payload, off));
        off += 4;
    }
    let available = payload.len().saturating_sub(off);
    let declared = usize::from(pptp_payload_len);
    let mut frame = GreFrame {
        version: 1,
        checksum_present: false,
        routing_present: false,
        key_present: true,
        sequence_present,
        ack_present,
        strict_source_route: false,
        recursion_control: 0,
        reserved_flags: 0,
        protocol_type,
        checksum: None,
        routing_offset: None,
        key,
        sequence,
        ack,
        sre_count: 0,
        header_len: off,
        pptp_payload_len: Some(pptp_payload_len),
        pptp_call_id: Some(pptp_call_id),
        inner: None,
        truncated: declared > available,
        capture_truncated: false,
    };
    if declared != 0 || available != 0 {
        let mut inner = InnerProtocol::new("ppp", available.min(declared));
        // PPP 载荷前两个字节是协议字段（0x0021 IPv4 / 0x0057 IPv6 / 0xC021 LCP），
        // 但 ACFC/PFC 协商不在单包可见范围内；只要求至少 2 字节，不据此判 IP。
        inner.header_len = Some(2);
        inner.complete_header = available.min(declared) >= PPTP_MIN_PAYLOAD_LEN;
        frame.inner = Some(inner);
    }
    Ok(frame)
}

fn ensure(payload: &[u8], need: usize) -> Result<(), GreError> {
    if payload.len() < need {
        return Err(GreError::TruncatedHeader {
            need,
            got: payload.len(),
        });
    }
    Ok(())
}

fn parse_inner(protocol_type: u16, bytes: &[u8]) -> InnerProtocol {
    match protocol_type {
        ETHERTYPE_IPV4 => parse_inner_ipv4(bytes),
        ETHERTYPE_IPV6 => parse_inner_ipv6(bytes),
        ETHERTYPE_TEB => parse_inner_ethernet(bytes),
        PPTP_PROTOCOL_TYPE => {
            let mut i = InnerProtocol::new("ppp", bytes.len());
            i.header_len = Some(2);
            i.complete_header = bytes.len() >= 2;
            i
        }
        ERSPAN_PROTOCOL_TYPE => {
            let mut i = InnerProtocol::new("erspan", bytes.len());
            i.header_len = Some(8);
            i.complete_header = bytes.len() >= 8;
            i
        }
        ETHERTYPE_MPLS_UNICAST | ETHERTYPE_MPLS_MULTICAST => {
            let mut i = InnerProtocol::new("mpls", bytes.len());
            i.header_len = Some(4);
            i.complete_header = bytes.len() >= 4;
            i
        }
        _ => InnerProtocol::new("unknown", bytes.len()),
    }
}

fn parse_inner_ipv4(bytes: &[u8]) -> InnerProtocol {
    let mut i = InnerProtocol::new("ipv4", bytes.len());
    if bytes.len() < 20 {
        return i;
    }
    let version = bytes[0] >> 4;
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    let declared = be16(bytes, 2);
    i.declared_len = Some(declared);
    i.header_len = Some(ihl);
    if version != 4 || ihl < 20 {
        return i;
    }
    i.protocol = Some(bytes[9]);
    i.source = Some(IpAddr::V4(Ipv4Addr::new(
        bytes[12], bytes[13], bytes[14], bytes[15],
    )));
    i.destination = Some(IpAddr::V4(Ipv4Addr::new(
        bytes[16], bytes[17], bytes[18], bytes[19],
    )));
    i.complete_header = bytes.len() >= ihl && usize::from(declared) >= ihl;
    i
}

fn parse_inner_ipv6(bytes: &[u8]) -> InnerProtocol {
    let mut i = InnerProtocol::new("ipv6", bytes.len());
    if bytes.len() < 40 {
        return i;
    }
    let version = bytes[0] >> 4;
    i.declared_len = Some(be16(bytes, 4).saturating_add(40));
    i.header_len = Some(40);
    if version != 6 {
        return i;
    }
    i.protocol = Some(bytes[6]);
    let mut src = [0u8; 16];
    src.copy_from_slice(&bytes[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&bytes[24..40]);
    i.source = Some(IpAddr::V6(Ipv6Addr::from(src)));
    i.destination = Some(IpAddr::V6(Ipv6Addr::from(dst)));
    i.complete_header = true;
    i
}

fn parse_inner_ethernet(bytes: &[u8]) -> InnerProtocol {
    let mut i = InnerProtocol::new("ethernet", bytes.len());
    if bytes.len() < 14 {
        return i;
    }
    let mut ether_type = be16(bytes, 12);
    let mut off = 14;
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) && i.inner_vlan_ids.len() < 2 {
        if bytes.len() < off + 4 {
            break;
        }
        i.inner_vlan_ids.push(be16(bytes, off) & 0x0fff);
        ether_type = be16(bytes, off + 2);
        off += 4;
    }
    i.inner_ether_type = Some(ether_type);
    i.complete_header = !matches!(ether_type, 0x8100 | 0x88a8 | 0x9100);
    i
}

fn protocol_name(protocol_type: u16) -> &'static str {
    match protocol_type {
        ETHERTYPE_IPV4 => "ipv4",
        ETHERTYPE_IPV6 => "ipv6",
        ETHERTYPE_TEB => "transparent_ethernet_bridging",
        PPTP_PROTOCOL_TYPE => "ppp",
        ETHERTYPE_MPLS_UNICAST => "mpls_unicast",
        ETHERTYPE_MPLS_MULTICAST => "mpls_multicast",
        ERSPAN_PROTOCOL_TYPE => "erspan",
        _ => "unknown",
    }
}

fn json_opt_num(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "null".into())
}

fn json_string_opt(v: Option<String>) -> String {
    match v {
        None => "null".into(),
        Some(s) => format!("\"{s}\""),
    }
}

/// GRE 报文级统计。**没有“隧道建立/对端在线”的计数**：单包只能说明结构。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GreStats {
    pub gre_frames: u64,
    pub version0: u64,
    pub version1: u64,
    pub keyed: u64,
    pub unkeyed: u64,
    pub checksum_present: u64,
    pub routing_present: u64,
    pub sequence_present: u64,
    pub ack_present: u64,
    pub protocol_ipv4: u64,
    pub protocol_ipv6: u64,
    pub protocol_ethernet: u64,
    pub protocol_ppp: u64,
    pub protocol_mpls: u64,
    pub protocol_erspan: u64,
    pub protocol_other: u64,
    pub inner_complete: u64,
    pub inner_incomplete: u64,
    pub capture_truncated: u64,
    pub truncated: u64,
    pub malformed: u64,
}

impl GreStats {
    pub fn observe(&mut self, f: &GreFrame) {
        self.gre_frames += 1;
        match f.version {
            0 => self.version0 += 1,
            1 => self.version1 += 1,
            _ => {}
        }
        if f.key_present {
            self.keyed += 1;
        } else {
            self.unkeyed += 1;
        }
        if f.checksum_present {
            self.checksum_present += 1;
        }
        if f.routing_present {
            self.routing_present += 1;
        }
        if f.sequence_present {
            self.sequence_present += 1;
        }
        if f.ack_present {
            self.ack_present += 1;
        }
        match f.protocol_type {
            ETHERTYPE_IPV4 => self.protocol_ipv4 += 1,
            ETHERTYPE_IPV6 => self.protocol_ipv6 += 1,
            ETHERTYPE_TEB => self.protocol_ethernet += 1,
            PPTP_PROTOCOL_TYPE => self.protocol_ppp += 1,
            ETHERTYPE_MPLS_UNICAST | ETHERTYPE_MPLS_MULTICAST => self.protocol_mpls += 1,
            ERSPAN_PROTOCOL_TYPE => self.protocol_erspan += 1,
            _ => self.protocol_other += 1,
        }
        if let Some(i) = &f.inner {
            if i.complete_header {
                self.inner_complete += 1;
            } else if i.kind != "unknown" {
                // 未知 protocol type 没有可对照的头长度，不记“截断”。
                self.inner_incomplete += 1;
            }
        }
        if f.truncated {
            self.truncated += 1;
        }
        if f.capture_truncated {
            self.capture_truncated += 1;
        }
    }

    pub fn record_error(&mut self, e: GreError) {
        match e {
            GreError::TruncatedHeader { .. } => self.truncated += 1,
            GreError::UnsupportedVersion { .. }
            | GreError::BadPptp { .. }
            | GreError::BadRouting { .. }
            | GreError::TooManySre { .. } => self.malformed += 1,
        }
    }

    /// 统计行是关口比对的契约：字段名改了必须同时改
    /// `scripts/verify/check-icmp-gre.py`。
    pub fn render_line(&self) -> String {
        format!(
            "gre gre_frames={} version0={} version1={} keyed={} unkeyed={} \
             checksum_present={} routing_present={} sequence_present={} ack_present={} \
             protocol_ipv4={} protocol_ipv6={} protocol_ethernet={} protocol_ppp={} \
             protocol_mpls={} protocol_erspan={} protocol_other={} \
             inner_complete={} inner_incomplete={} capture_truncated={} \
             truncated={} malformed={}",
            self.gre_frames,
            self.version0,
            self.version1,
            self.keyed,
            self.unkeyed,
            self.checksum_present,
            self.routing_present,
            self.sequence_present,
            self.ack_present,
            self.protocol_ipv4,
            self.protocol_ipv6,
            self.protocol_ethernet,
            self.protocol_ppp,
            self.protocol_mpls,
            self.protocol_erspan,
            self.protocol_other,
            self.inner_complete,
            self.inner_incomplete,
            self.capture_truncated,
            self.truncated,
            self.malformed,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_header(src: [u8; 4], dst: [u8; 4], proto: u8, total: u16) -> Vec<u8> {
        let mut v = vec![0x45, 0x00];
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v
    }

    fn ipv6_header(src: u16, dst: u16) -> Vec<u8> {
        let mut v = vec![0x60, 0, 0, 0];
        v.extend_from_slice(&0u16.to_be_bytes());
        v.push(59);
        v.push(64);
        v.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&src.to_be_bytes());
        v.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&dst.to_be_bytes());
        v
    }

    fn gre_v0(flags: u16, proto: u16, inner: &[u8]) -> Vec<u8> {
        let mut v = flags.to_be_bytes().to_vec();
        v.extend_from_slice(&proto.to_be_bytes());
        v.extend_from_slice(inner);
        v
    }

    /// 带可选头的 GRE v0：按 C/R/K/S 的顺序拼 checksum+offset、key、sequence。
    fn gre_v0_with(
        flags: u16,
        proto: u16,
        checksum: Option<(u16, u16)>,
        key: Option<u32>,
        sequence: Option<u32>,
        tail: &[u8],
    ) -> Vec<u8> {
        let mut v = gre_v0(flags, proto, &[]);
        if let Some((c, off)) = checksum {
            v.extend_from_slice(&c.to_be_bytes());
            v.extend_from_slice(&off.to_be_bytes());
        }
        if let Some(k) = key {
            v.extend_from_slice(&k.to_be_bytes());
        }
        if let Some(s) = sequence {
            v.extend_from_slice(&s.to_be_bytes());
        }
        v.extend_from_slice(tail);
        v
    }

    fn pptp(flags: u16, payload_len: u16, call_id: u16, tail: &[u8]) -> Vec<u8> {
        let mut v = flags.to_be_bytes().to_vec();
        v.extend_from_slice(&PPTP_PROTOCOL_TYPE.to_be_bytes());
        v.extend_from_slice(&payload_len.to_be_bytes());
        v.extend_from_slice(&call_id.to_be_bytes());
        v.extend_from_slice(tail);
        v
    }

    #[test]
    fn plain_gre_carries_ipv4_without_key() {
        let inner = ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 6, 40);
        let f = parse(&gre_v0(0, 0x0800, &inner)).unwrap();
        assert_eq!(f.version, 0);
        assert_eq!(f.mode(), "gre");
        assert!(!f.key_present && !f.sequence_present);
        assert_eq!(f.header_len, 4);
        assert_eq!(f.protocol_name(), "ipv4");
        let i = f.inner.expect("应有内层");
        assert_eq!(i.source, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(i.destination, Some("10.0.0.2".parse().unwrap()));
        assert_eq!(i.protocol, Some(6));
        assert!(i.complete_header);
    }

    #[test]
    fn key_sequence_and_checksum_are_walked_in_order() {
        let mut inner = ipv6_header(1, 2);
        inner.extend_from_slice(&[0; 8]);
        let p = gre_v0_with(
            0xb000,
            0x86dd,
            Some((0xbeef, 0)),
            Some(0xdead_beef),
            Some(7),
            &inner,
        );
        let f = parse(&p).unwrap();
        assert!(f.checksum_present && f.key_present && f.sequence_present);
        assert_eq!(f.checksum, Some(0xbeef));
        assert_eq!(f.key, Some(0xdead_beef));
        assert_eq!(f.sequence, Some(7));
        assert_eq!(f.header_len, 16);
        assert_eq!(f.protocol_name(), "ipv6");
        let i = f.inner.expect("应有内层");
        assert_eq!(i.protocol, Some(59));
        assert!(i.complete_header);
    }

    #[test]
    fn source_route_sre_list_is_counted_and_bounded() {
        let inner = ipv4_header([192, 0, 2, 1], [192, 0, 2, 2], 17, 28);
        let mut p = gre_v0_with(0x4000, 0x0800, Some((0, 0)), None, None, &[]);
        p.extend_from_slice(&[0x08, 0x00, 0, 4]); // AF=IPv4, offset=0, length=4
        p.extend_from_slice(&[10, 0, 0, 9]); // SRE data
        p.extend_from_slice(&[0, 0, 0, 0]); // 结束标记：length=0
        p.extend_from_slice(&inner);
        let f = parse(&p).unwrap();
        assert_eq!(f.sre_count, 1);
        assert_eq!(f.header_len, 20);
        assert_eq!(f.protocol_name(), "ipv4");
        assert!(f.inner.expect("内层").complete_header);
    }

    #[test]
    fn routing_sre_without_terminator_is_bad_routing() {
        // R 位 + 一条完整 SRE，但后面直接跟内层 IP（没有 Length=0 的结束标记）。
        let inner = ipv4_header([192, 0, 2, 1], [192, 0, 2, 2], 17, 28);
        let mut p = gre_v0_with(0x4000, 0x0800, Some((0, 0)), None, None, &[]);
        p.extend_from_slice(&[0x08, 0x00, 0, 4]);
        p.extend_from_slice(&[10, 0, 0, 9]);
        p.extend_from_slice(&inner);
        assert!(matches!(parse(&p), Err(GreError::BadRouting { .. })));
    }

    #[test]
    fn transparent_ethernet_bridging_reads_inner_ethertype_and_vlan() {
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&0x8100u16.to_be_bytes());
        eth.extend_from_slice(&0x0064u16.to_be_bytes());
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&[0u8; 20]);
        let f = parse(&gre_v0(0, 0x6558, &eth)).unwrap();
        assert_eq!(f.protocol_name(), "transparent_ethernet_bridging");
        let i = f.inner.expect("应有内层");
        assert_eq!(i.kind, "ethernet");
        assert_eq!(i.inner_ether_type, Some(0x0800));
        assert_eq!(i.inner_vlan_ids, vec![100]);
        assert!(i.complete_header);
    }

    #[test]
    fn pptp_enhanced_gre_with_key_only_is_accepted() {
        let p = pptp(0x2001, 8, 1, &[0, 0x21, 0x45, 0, 0, 20, 0, 0]);
        let f = parse(&p).unwrap();
        assert_eq!(f.mode(), "pptp");
        assert_eq!(f.pptp_call_id, Some(1));
        assert_eq!(f.pptp_payload_len, Some(8));
        assert_eq!(f.key, Some(0x0008_0001));
        assert_eq!(f.header_len, 8);
        assert_eq!(f.protocol_name(), "ppp");
        assert!(f.inner.expect("PPP 内层").complete_header);
    }

    #[test]
    fn pptp_sequence_and_ack_extend_the_header() {
        let mut tail = 0x0a0b_0c0du32.to_be_bytes().to_vec();
        tail.extend_from_slice(&0x1122_3344u32.to_be_bytes());
        tail.extend_from_slice(&[0, 0x21, 0, 0, 0, 20, 0, 0]);
        let p = pptp(0x3081, 0, 3, &tail);
        let f = parse(&p).unwrap();
        assert_eq!(f.sequence, Some(0x0a0b_0c0d));
        assert_eq!(f.ack, Some(0x1122_3344));
        assert_eq!(f.header_len, 16);
        assert!(f.sequence_present && f.ack_present);
    }

    #[test]
    fn pptp_without_key_is_malformed_with_a_reason() {
        let p = pptp(0x0001, 8, 1, &[0; 4]);
        assert_eq!(
            parse(&p).unwrap_err(),
            GreError::BadPptp {
                reason: "K（key present）必须置位"
            }
        );
    }

    #[test]
    fn pptp_reserved_bits_are_rejected() {
        let p = pptp(0x2009, 8, 1, &[0; 8]);
        assert!(matches!(parse(&p), Err(GreError::BadPptp { .. })));
    }

    #[test]
    fn unsupported_gre_version_is_not_treated_as_v0() {
        let e = parse(&gre_v0(2, 0x0800, &[])).unwrap_err();
        assert_eq!(e, GreError::UnsupportedVersion { version: 2 });
        assert_eq!(e.code(), "gre.unsupported_version");
    }

    #[test]
    fn truncated_optional_header_is_typed() {
        let mut p = gre_v0(0x2000, 0x0800, &[]);
        p.extend_from_slice(&[0, 1]); // key 只给 2 字节
        let e = parse(&p).unwrap_err();
        assert!(matches!(e, GreError::TruncatedHeader { need: 8, got: 6 }));
    }

    #[test]
    fn truncated_inner_ipv4_is_not_reported_complete() {
        let inner = ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 6, 40);
        let f = parse(&gre_v0(0, 0x0800, &inner[..12])).unwrap();
        let i = f.inner.expect("内层应有结构");
        assert!(!i.complete_header);
        assert_eq!(i.source, None, "版本/IHL 不完整时不能编出地址");
        assert!(f.truncated);
    }

    #[test]
    fn unknown_inner_protocol_keeps_its_number() {
        let f = parse(&gre_v0(0, 0x1234, &[0; 8])).unwrap();
        assert_eq!(f.protocol_type, 0x1234);
        assert_eq!(f.protocol_name(), "unknown");
        let i = f.inner.expect("未知协议也应有内层视图");
        assert_eq!(i.kind, "unknown");
        assert!(!i.complete_header);
    }

    #[test]
    fn stats_and_json_are_stable() {
        let inner = ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 6, 40);
        let mut s = GreStats::default();
        s.observe(&parse(&gre_v0(0, 0x0800, &inner)).unwrap());
        s.observe(&parse(&pptp(0x2001, 8, 1, &[0; 8])).unwrap());
        s.record_error(GreError::UnsupportedVersion { version: 2 });
        assert_eq!(s.gre_frames, 2);
        assert_eq!(s.version0, 1);
        assert_eq!(s.version1, 1);
        assert_eq!(s.keyed, 1);
        assert_eq!(s.unkeyed, 1);
        assert_eq!(s.protocol_ipv4, 1);
        assert_eq!(s.protocol_ppp, 1);
        assert_eq!(s.malformed, 1);
        let line = s.render_line();
        assert!(line.starts_with("gre gre_frames=2"), "{line}");
        assert!(line.contains("version1=1"), "{line}");

        let f = parse(&gre_v0(0, 0x0800, &inner)).unwrap();
        let json = f.to_json_line(1_700_000_000_000_000, 9, 60);
        assert!(
            json.starts_with("{\"timestamp_us\":1700000000000000,\"frame\":9"),
            "{json}"
        );
        assert!(json.contains("\"mode\":\"gre\""), "{json}");
        assert!(json.contains("\"key\":null"), "{json}");
        assert!(json.contains("\"kind\":\"ipv4\""), "{json}");
        assert!(json.contains("\"source\":\"10.0.0.1\""), "{json}");
    }
}
