// icmp.rs —— ICMPv4 / ICMPv6 有界解析（RFC 792 / RFC 4443 / RFC 4861）。
//
// 定位：基础协议识别只回答“这条 ICMP 报文的结构是什么”，不根据 type/code
// 推断主机状态、路径可达性或攻击意图。ICMP 没有端口，不能像 TCP/UDP 那样
// 归入应用识别；本模块输出的是**报文级事件**与流水线计数。
//
// 三个刻意的边界：
//
// 1. **公共头固定 8 字节**。RFC 792/4443 的每条 ICMP 报文都含 type/code/checksum
//    与 4 字节“rest of header”；不足 8 字节就是截断，不拿 0 兜底。
// 2. **错误报文里的原始数据报按声明长度解析，但不要求抓全**。ICMP 错误只承诺
//    携带原始 IP 头 + 至少 8 字节；抓包截断时保留“已抓到多少”，不把缺失字节
//    当成 0，也不把没抓到的内层地址编出来。
// 3. **不校验 checksum**。抓包截断、网卡校验和卸载与分片都会让校验失败，
//    把它当成“坏包”会把大量合法报文判错；checksum 字段原样保留供独立核对。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// ICMPv4 的 IP 协议号。
pub const IPPROTO_ICMP: u8 = 1;
/// ICMPv6 的 IP 协议号。
pub const IPPROTO_ICMPV6: u8 = 58;
/// 所有 ICMP 报文共有的最小头长度。
pub const HEADER_LEN: usize = 8;
/// NDP 选项的解析上限。现实中一条 RA 很少超过十来个选项；超过这个量
/// 更像是解析位置偏了，继续循环只会把畸形包变成 CPU 消耗。
const MAX_NDP_OPTIONS: usize = 16;

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// ICMP 所属的 IP 版本。类型/代码空间不同，必须显式带上而不是靠猜。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpFamily {
    V4,
    V6,
}

impl IcmpFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            IcmpFamily::V4 => "ipv4",
            IcmpFamily::V6 => "ipv6",
        }
    }

    pub fn ip_protocol(self) -> u8 {
        match self {
            IcmpFamily::V4 => IPPROTO_ICMP,
            IcmpFamily::V6 => IPPROTO_ICMPV6,
        }
    }
}

/// 解析失败的位置。与 `channel::DecodeError` 分开：ICMP 头截断不是 IP 解码失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpError {
    /// 不足 8 字节公共头。
    TruncatedHeader { need: usize, got: usize },
}

impl IcmpError {
    /// 稳定错误码，供统计/日志按原因聚合。
    pub fn code(self) -> &'static str {
        match self {
            IcmpError::TruncatedHeader { .. } => "icmp.truncated_header",
        }
    }
}

impl fmt::Display for IcmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpError::TruncatedHeader { need, got } => {
                write!(f, "ICMP 公共头不完整：需要 {need} 字节，实有 {got} 字节")
            }
        }
    }
}

impl std::error::Error for IcmpError {}

/// ICMP 错误报文里携带的原始数据报。
///
/// 每个字段都是 `Option`：抓包只截到一部分时，能解析多少写多少，
/// **不把没有的字节补成 0.0.0.0/0**。`declared_len` 是内层 IP 头声明的总长，
/// `captured_len` 是本次实际可用的字节数；两者不等说明原始数据报被截断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedDatagram {
    pub version: u8,
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub protocol: Option<u8>,
    pub declared_len: Option<u16>,
    pub header_len: Option<usize>,
    pub captured_len: usize,
    /// 内层 IP 头（按自身 IHL 或固定 40 字节）是否完整可读。
    pub header_complete: bool,
}

/// 一个 NDP 选项的 bounded 视图。`len` 是 RFC 4861 的 8 字节为单位长度；
/// Pad1 没有长度字节，记为 `len=0`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdpOption {
    pub kind: u8,
    pub len: u8,
}

/// 邻居发现（NDP）固定字段 + 选项。只对 ICMPv6 的类型 133..=137 填充。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NdpInfo {
    pub target: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub cur_hop_limit: Option<u8>,
    pub ra_flags: Option<u8>,
    pub router_lifetime: Option<u16>,
    pub reachable_time: Option<u32>,
    pub retrans_timer: Option<u32>,
    pub na_flags: Option<u32>,
    pub options: Vec<NdpOption>,
    pub options_truncated: bool,
    pub options_malformed: bool,
}

/// 一条结构可解析的 ICMPv4/ICMPv6 报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpFrame {
    pub family: IcmpFamily,
    pub type_code: u8,
    pub code: u8,
    pub checksum: u16,
    /// Echo/Timestamp 的 identifier/sequence；其他类型为 `None`。
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
    /// 公共头的 4 字节 rest-of-header 原值（按大端读）。
    pub rest_of_header: u32,
    /// ICMPv4 分片需要（type 3 code 4）的下一跳 MTU。
    pub mtu: Option<u32>,
    /// ICMPv4/v6 参数问题的指针。
    pub pointer: Option<u32>,
    /// 错误报文携带的原始数据报；非错误类型为 `None`。
    pub embedded: Option<EmbeddedDatagram>,
    /// ICMPv6 NDP 字段；其他类型为 `None`。
    pub ndp: Option<NdpInfo>,
    /// 公共头之后的实际可用字节数。
    pub payload_len: usize,
    /// 已知类型的固定字段是否被截断（NDP 的固定部分、选项不完整分别记在 NdpInfo）。
    pub truncated: bool,
    /// 采集侧 `orig_len > caplen`。与 `truncated` 分开：前者是抓包少了字节，
    /// 后者是报文自身的固定结构没读全。
    pub capture_truncated: bool,
}

impl IcmpFrame {
    pub fn is_error(&self) -> bool {
        is_error(self.family, self.type_code)
    }

    pub fn type_name(&self) -> &'static str {
        type_name(self.family, self.type_code)
    }

    /// 一行稳定 JSON（字段顺序固定；未知值用 `null`，不缺席）。
    pub fn to_json_line(&self, timestamp_us: u64, frame: u64, frame_len: usize) -> String {
        let embedded = match &self.embedded {
            None => "null".to_string(),
            Some(e) => format!(
                "{{\"version\":{},\"source\":{},\"destination\":{},\"protocol\":{},\
                 \"declared_len\":{},\"header_len\":{},\"captured_len\":{},\"header_complete\":{}}}",
                e.version,
                json_string_opt(e.source.map(|v| v.to_string())),
                json_string_opt(e.destination.map(|v| v.to_string())),
                json_opt_num(e.protocol.map(u64::from)),
                json_opt_num(e.declared_len.map(u64::from)),
                json_opt_num(e.header_len.map(|v| v as u64)),
                e.captured_len,
                e.header_complete,
            ),
        };
        let ndp = match &self.ndp {
            None => "null".to_string(),
            Some(n) => {
                let options = n
                    .options
                    .iter()
                    .map(|o| format!("{{\"kind\":{},\"len\":{}}}", o.kind, o.len))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "{{\"target\":{},\"destination\":{},\"cur_hop_limit\":{},\"ra_flags\":{},\
                     \"router_lifetime\":{},\"reachable_time\":{},\"retrans_timer\":{},\
                     \"na_flags\":{},\"options\":[{}],\"options_truncated\":{},\
                     \"options_malformed\":{}}}",
                    json_string_opt(n.target.map(|v| v.to_string())),
                    json_string_opt(n.destination.map(|v| v.to_string())),
                    json_opt_num(n.cur_hop_limit.map(u64::from)),
                    json_opt_num(n.ra_flags.map(u64::from)),
                    json_opt_num(n.router_lifetime.map(u64::from)),
                    json_opt_num(n.reachable_time.map(u64::from)),
                    json_opt_num(n.retrans_timer.map(u64::from)),
                    json_opt_num(n.na_flags.map(u64::from)),
                    options,
                    n.options_truncated,
                    n.options_malformed,
                )
            }
        };
        format!(
            "{{\"timestamp_us\":{timestamp_us},\"frame\":{frame},\"frame_len\":{frame_len},\
             \"capture_truncated\":{},\"family\":\"{}\",\"ip_proto\":{},\
             \"type\":{},\"type_name\":\"{}\",\"code\":{},\"checksum\":{},\
             \"is_error\":{},\"identifier\":{},\"sequence\":{},\"rest_of_header\":{},\
             \"mtu\":{},\"pointer\":{},\"payload_len\":{},\"truncated\":{},\
             \"embedded\":{embedded},\"ndp\":{ndp}}}",
            self.capture_truncated,
            self.family.as_str(),
            self.family.ip_protocol(),
            self.type_code,
            self.type_name(),
            self.code,
            self.checksum,
            self.is_error(),
            json_opt_num(self.identifier.map(u64::from)),
            json_opt_num(self.sequence.map(u64::from)),
            self.rest_of_header,
            json_opt_num(self.mtu.map(u64::from)),
            json_opt_num(self.pointer.map(u64::from)),
            self.payload_len,
            self.truncated,
        )
    }
}

/// 解析一段从 ICMP 公共头开始的 IP 载荷。
pub fn parse(payload: &[u8], family: IcmpFamily) -> Result<IcmpFrame, IcmpError> {
    if payload.len() < HEADER_LEN {
        return Err(IcmpError::TruncatedHeader {
            need: HEADER_LEN,
            got: payload.len(),
        });
    }
    let type_code = payload[0];
    let code = payload[1];
    let checksum = be16(payload, 2);
    let rest = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let message = &payload[HEADER_LEN..];

    let mut frame = IcmpFrame {
        family,
        type_code,
        code,
        checksum,
        identifier: None,
        sequence: None,
        rest_of_header: rest,
        mtu: None,
        pointer: None,
        embedded: None,
        ndp: None,
        payload_len: message.len(),
        truncated: false,
        capture_truncated: false,
    };

    match family {
        IcmpFamily::V4 => parse_v4(&mut frame, payload, message),
        IcmpFamily::V6 => parse_v6(&mut frame, payload, message),
    }
    Ok(frame)
}

fn parse_v4(frame: &mut IcmpFrame, payload: &[u8], message: &[u8]) {
    match frame.type_code {
        // Echo Reply / Echo Request 以及 Timestamp 系：identifier/sequence 固定在前 4 字节。
        0 | 8 | 13 | 14 | 15 | 16 | 17 | 18 => {
            frame.identifier = Some(be16(payload, 4));
            frame.sequence = Some(be16(payload, 6));
        }
        // Destination Unreachable：code 4 的 rest-of-header 低 16 位是下一跳 MTU。
        3 => {
            if frame.code == 4 {
                frame.mtu = Some(u32::from(be16(payload, 6)));
            }
        }
        // Parameter Problem：指针是 rest-of-header 的第一个字节。
        12 => {
            frame.pointer = Some(u32::from(payload[4]));
        }
        _ => {}
    }
    if is_error(IcmpFamily::V4, frame.type_code) {
        frame.embedded = parse_embedded(message);
    }
}

fn parse_v6(frame: &mut IcmpFrame, payload: &[u8], message: &[u8]) {
    match frame.type_code {
        128 | 129 => {
            frame.identifier = Some(be16(payload, 4));
            frame.sequence = Some(be16(payload, 6));
        }
        // Packet Too Big：rest-of-header 整体是 MTU。
        2 => frame.mtu = Some(frame.rest_of_header),
        // Parameter Problem：rest-of-header 整体是指针。
        4 => frame.pointer = Some(frame.rest_of_header),
        _ => {}
    }
    if is_error(IcmpFamily::V6, frame.type_code) {
        frame.embedded = parse_embedded(message);
    }
    if (133..=137).contains(&frame.type_code) {
        frame.ndp = Some(parse_ndp(frame.type_code, message, &mut frame.truncated));
    }
}

fn is_error(family: IcmpFamily, type_code: u8) -> bool {
    match family {
        IcmpFamily::V4 => matches!(type_code, 3 | 4 | 5 | 11 | 12),
        IcmpFamily::V6 => matches!(type_code, 1 | 2 | 3 | 4),
    }
}

/// 类型名是稳定的展示值，不随本地语言变化；未知类型一律 `unknown`。
pub fn type_name(family: IcmpFamily, type_code: u8) -> &'static str {
    match (family, type_code) {
        (IcmpFamily::V4, 0) => "echo_reply",
        (IcmpFamily::V4, 3) => "destination_unreachable",
        (IcmpFamily::V4, 4) => "source_quench",
        (IcmpFamily::V4, 5) => "redirect",
        (IcmpFamily::V4, 8) => "echo_request",
        (IcmpFamily::V4, 11) => "time_exceeded",
        (IcmpFamily::V4, 12) => "parameter_problem",
        (IcmpFamily::V4, 13) => "timestamp_request",
        (IcmpFamily::V4, 14) => "timestamp_reply",
        (IcmpFamily::V4, 15) => "information_request",
        (IcmpFamily::V4, 16) => "information_reply",
        (IcmpFamily::V4, 17) => "address_mask_request",
        (IcmpFamily::V4, 18) => "address_mask_reply",
        (IcmpFamily::V6, 1) => "destination_unreachable",
        (IcmpFamily::V6, 2) => "packet_too_big",
        (IcmpFamily::V6, 3) => "time_exceeded",
        (IcmpFamily::V6, 4) => "parameter_problem",
        (IcmpFamily::V6, 128) => "echo_request",
        (IcmpFamily::V6, 129) => "echo_reply",
        (IcmpFamily::V6, 130) => "mld_query",
        (IcmpFamily::V6, 131) => "mld_report_v1",
        (IcmpFamily::V6, 132) => "mld_done_v1",
        (IcmpFamily::V6, 133) => "router_solicitation",
        (IcmpFamily::V6, 134) => "router_advertisement",
        (IcmpFamily::V6, 135) => "neighbor_solicitation",
        (IcmpFamily::V6, 136) => "neighbor_advertisement",
        (IcmpFamily::V6, 137) => "redirect",
        (IcmpFamily::V6, 138) => "router_renumbering",
        (IcmpFamily::V6, 139) => "node_information_query",
        (IcmpFamily::V6, 140) => "node_information_response",
        (IcmpFamily::V6, 141) => "inverse_nd_solicitation",
        (IcmpFamily::V6, 142) => "inverse_nd_advertisement",
        (IcmpFamily::V6, 143) => "mld_report_v2",
        (IcmpFamily::V6, 144) => "ha_discovery_request",
        (IcmpFamily::V6, 145) => "ha_discovery_reply",
        (IcmpFamily::V6, 146) => "mobile_prefix_solicitation",
        (IcmpFamily::V6, 147) => "mobile_prefix_advertisement",
        (IcmpFamily::V6, 151) => "multicast_router_advertisement",
        (IcmpFamily::V6, 152) => "multicast_router_solicitation",
        (IcmpFamily::V6, 153) => "multicast_router_termination",
        _ => "unknown",
    }
}

/// 解析 ICMP 错误报文携带的原始数据报头。只读头，不把内层载荷当成新的一层流。
fn parse_embedded(bytes: &[u8]) -> Option<EmbeddedDatagram> {
    let first = *bytes.first()?;
    let version = first >> 4;
    let mut e = EmbeddedDatagram {
        version,
        source: None,
        destination: None,
        protocol: None,
        declared_len: None,
        header_len: None,
        captured_len: bytes.len(),
        header_complete: false,
    };
    match version {
        4 => {
            if bytes.len() < 20 {
                return Some(e);
            }
            let ihl = usize::from(first & 0x0f) * 4;
            if ihl < 20 {
                return Some(e);
            }
            e.declared_len = Some(be16(bytes, 2));
            e.protocol = Some(bytes[9]);
            e.source = Some(IpAddr::V4(Ipv4Addr::new(
                bytes[12], bytes[13], bytes[14], bytes[15],
            )));
            e.destination = Some(IpAddr::V4(Ipv4Addr::new(
                bytes[16], bytes[17], bytes[18], bytes[19],
            )));
            e.header_len = Some(ihl);
            e.header_complete = bytes.len() >= ihl;
        }
        6 => {
            if bytes.len() < 40 {
                return Some(e);
            }
            e.declared_len = Some(be16(bytes, 4).saturating_add(40));
            e.protocol = Some(bytes[6]);
            let mut src = [0u8; 16];
            src.copy_from_slice(&bytes[8..24]);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&bytes[24..40]);
            e.source = Some(IpAddr::V6(Ipv6Addr::from(src)));
            e.destination = Some(IpAddr::V6(Ipv6Addr::from(dst)));
            e.header_len = Some(40);
            e.header_complete = true;
        }
        _ => {}
    }
    Some(e)
}

/// 解析 NDP 固定字段与其后的选项。
fn parse_ndp(type_code: u8, message: &[u8], truncated: &mut bool) -> NdpInfo {
    let mut n = NdpInfo::default();
    let fixed_end = match type_code {
        133 => 4,  // Router Solicitation: reserved 4
        134 => 12, // Router Advertisement: 12 字节固定字段
        135 => 20, // Neighbor Solicitation: reserved 4 + target 16
        136 => 20, // Neighbor Advertisement: flags 4 + target 16
        137 => 36, // Redirect: reserved 4 + target 16 + destination 16
        _ => 0,
    };
    if message.len() < fixed_end {
        *truncated = true;
        return n;
    }
    match type_code {
        134 => {
            n.cur_hop_limit = Some(message[0]);
            n.ra_flags = Some(message[1]);
            n.router_lifetime = Some(be16(message, 2));
            n.reachable_time = Some(be32(message, 4));
            n.retrans_timer = Some(be32(message, 8));
        }
        135 => {
            let mut target = [0u8; 16];
            target.copy_from_slice(&message[4..20]);
            n.target = Some(IpAddr::V6(Ipv6Addr::from(target)));
        }
        136 => {
            n.na_flags = Some(be32(message, 0));
            let mut target = [0u8; 16];
            target.copy_from_slice(&message[4..20]);
            n.target = Some(IpAddr::V6(Ipv6Addr::from(target)));
        }
        137 => {
            let mut target = [0u8; 16];
            target.copy_from_slice(&message[4..20]);
            n.target = Some(IpAddr::V6(Ipv6Addr::from(target)));
            let mut destination = [0u8; 16];
            destination.copy_from_slice(&message[20..36]);
            n.destination = Some(IpAddr::V6(Ipv6Addr::from(destination)));
        }
        _ => {}
    }
    let (options, options_truncated, options_malformed) = parse_ndp_options(message, fixed_end);
    n.options = options;
    n.options_truncated = options_truncated;
    n.options_malformed = options_malformed;
    n
}

/// 选项格式：Type(1) + Length(1，单位 8 字节) + Data。Pad1 只有 Type 一个字节。
fn parse_ndp_options(message: &[u8], start: usize) -> (Vec<NdpOption>, bool, bool) {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut malformed = false;
    let mut pos = start;
    while pos < message.len() {
        if out.len() == MAX_NDP_OPTIONS {
            truncated = true;
            break;
        }
        let kind = message[pos];
        let option_start = pos;
        pos += 1;
        if kind == 0 {
            out.push(NdpOption { kind, len: 0 });
            continue;
        }
        let Some(&units) = message.get(pos) else {
            truncated = true;
            break;
        };
        if units == 0 {
            malformed = true;
            break;
        }
        let bytes = usize::from(units) * 8;
        // Length 含 Type/Length 自身；从 option_start 起算，而不是从读完后起算。
        if option_start + bytes > message.len() {
            truncated = true;
            break;
        }
        out.push(NdpOption { kind, len: units });
        pos = option_start + bytes;
    }
    (out, truncated, malformed)
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

/// ICMP 报文级统计。**没有“主机存活”的计数**：echo reply 只说明收到一个 reply。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IcmpStats {
    pub icmp_frames: u64,
    pub v4: u64,
    pub v6: u64,
    pub echo_requests: u64,
    pub echo_replies: u64,
    pub destination_unreachable: u64,
    pub packet_too_big: u64,
    pub time_exceeded: u64,
    pub parameter_problem: u64,
    pub redirects: u64,
    pub ndp: u64,
    pub mld: u64,
    pub other: u64,
    pub errors: u64,
    pub with_embedded: u64,
    pub truncated: u64,
    pub malformed: u64,
    pub ndp_options_truncated: u64,
    pub ndp_options_malformed: u64,
    pub capture_truncated: u64,
}

impl IcmpStats {
    pub fn observe(&mut self, f: &IcmpFrame) {
        self.icmp_frames += 1;
        match f.family {
            IcmpFamily::V4 => self.v4 += 1,
            IcmpFamily::V6 => self.v6 += 1,
        }
        match (f.family, f.type_code) {
            (IcmpFamily::V4, 8) | (IcmpFamily::V6, 128) => self.echo_requests += 1,
            (IcmpFamily::V4, 0) | (IcmpFamily::V6, 129) => self.echo_replies += 1,
            (IcmpFamily::V4, 3) | (IcmpFamily::V6, 1) => self.destination_unreachable += 1,
            (IcmpFamily::V6, 2) => self.packet_too_big += 1,
            (IcmpFamily::V4, 11) | (IcmpFamily::V6, 3) => self.time_exceeded += 1,
            (IcmpFamily::V4, 12) | (IcmpFamily::V6, 4) => self.parameter_problem += 1,
            (IcmpFamily::V4, 5) => self.redirects += 1,
            (IcmpFamily::V6, 133..=137) => self.ndp += 1,
            (IcmpFamily::V6, 130..=132) | (IcmpFamily::V6, 143) => self.mld += 1,
            _ => self.other += 1,
        }
        if f.is_error() {
            self.errors += 1;
        }
        if f.embedded.is_some() {
            self.with_embedded += 1;
        }
        if f.truncated {
            self.truncated += 1;
        }
        if let Some(n) = &f.ndp {
            if n.options_truncated {
                self.ndp_options_truncated += 1;
            }
            if n.options_malformed {
                self.malformed += 1;
                self.ndp_options_malformed += 1;
            }
        }
        if f.capture_truncated {
            self.capture_truncated += 1;
        }
    }

    pub fn record_error(&mut self, e: IcmpError) {
        match e {
            IcmpError::TruncatedHeader { .. } => self.truncated += 1,
        }
    }

    /// 统计行是关口比对的契约：字段名改了必须同时改
    /// `scripts/verify/check-icmp-gre.py`，否则关口会报「缺键」而不是默默少比。
    pub fn render_line(&self) -> String {
        format!(
            "icmp icmp_frames={} v4={} v6={} echo_requests={} echo_replies={} \
             destination_unreachable={} packet_too_big={} time_exceeded={} \
             parameter_problem={} redirects={} ndp={} mld={} other={} errors={} \
             with_embedded={} truncated={} malformed={} ndp_options_truncated={} \
             ndp_options_malformed={} capture_truncated={}",
            self.icmp_frames,
            self.v4,
            self.v6,
            self.echo_requests,
            self.echo_replies,
            self.destination_unreachable,
            self.packet_too_big,
            self.time_exceeded,
            self.parameter_problem,
            self.redirects,
            self.ndp,
            self.mld,
            self.other,
            self.errors,
            self.with_embedded,
            self.truncated,
            self.malformed,
            self.ndp_options_truncated,
            self.ndp_options_malformed,
            self.capture_truncated,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(ty: u8, code: u8, rest: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = vec![ty, code, 0, 0];
        v.extend_from_slice(&rest);
        v.extend_from_slice(body);
        v
    }

    fn v6(ty: u8, code: u8, rest: [u8; 4], body: &[u8]) -> Vec<u8> {
        v4(ty, code, rest, body)
    }

    fn ipv4_header(src: [u8; 4], dst: [u8; 4], proto: u8, total: u16) -> Vec<u8> {
        let mut v = vec![0x45, 0x00];
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v
    }

    #[test]
    fn echo_request_and_reply_carry_identifier_and_sequence() {
        let req = parse(&v4(8, 0, [0x12, 0x34, 0, 7], &[0xaa; 16]), IcmpFamily::V4).unwrap();
        assert_eq!(req.type_name(), "echo_request");
        assert_eq!(req.identifier, Some(0x1234));
        assert_eq!(req.sequence, Some(7));
        assert_eq!(req.payload_len, 16);
        assert!(!req.is_error());
        assert!(req.embedded.is_none());

        let rep = parse(&v4(0, 0, [0x12, 0x34, 0, 7], &[]), IcmpFamily::V4).unwrap();
        assert_eq!(rep.type_name(), "echo_reply");
        assert_eq!(rep.identifier, Some(0x1234));
    }

    #[test]
    fn destination_unreachable_parses_fragmentation_mtu() {
        let p = v4(
            3,
            4,
            [0, 0, 0x05, 0xdc],
            &ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 17, 28),
        );
        let f = parse(&p, IcmpFamily::V4).unwrap();
        assert_eq!(f.type_name(), "destination_unreachable");
        assert_eq!(f.mtu, Some(1500));
        let e = f.embedded.expect("错误报文应带内嵌数据报");
        assert_eq!(e.source, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(e.destination, Some("10.0.0.2".parse().unwrap()));
        assert_eq!(e.protocol, Some(17));
        assert_eq!(e.declared_len, Some(28));
        assert!(e.header_complete);
    }

    #[test]
    fn truncated_embedded_header_keeps_captured_length_and_no_invented_addresses() {
        let mut inner = ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 6, 40);
        inner.truncate(12);
        let f = parse(&v4(11, 0, [0; 4], &inner), IcmpFamily::V4).unwrap();
        let e = f.embedded.expect("有内层字节就应给出结构");
        assert_eq!(e.captured_len, 12);
        assert_eq!(e.source, None);
        assert_eq!(e.destination, None);
        assert!(!e.header_complete);
    }

    #[test]
    fn parameter_problem_pointer_is_read_per_family() {
        let f4 = parse(&v4(12, 0, [9, 0, 0, 0], &[]), IcmpFamily::V4).unwrap();
        assert_eq!(f4.pointer, Some(9));
        let f6 = parse(&v6(4, 0, [0, 0, 0, 9], &[]), IcmpFamily::V6).unwrap();
        assert_eq!(f6.pointer, Some(9));
    }

    #[test]
    fn icmpv6_packet_too_big_reads_full_rest_of_header() {
        let f = parse(&v6(2, 0, [0, 0, 0x05, 0xdc], &[]), IcmpFamily::V6).unwrap();
        assert_eq!(f.type_name(), "packet_too_big");
        assert_eq!(f.mtu, Some(1500));
        assert!(f.is_error());
    }

    #[test]
    fn icmpv6_echo_has_its_own_type_space() {
        let f = parse(&v6(128, 0, [0, 1, 0, 2], &[]), IcmpFamily::V6).unwrap();
        assert_eq!(f.type_name(), "echo_request");
        assert_eq!(f.identifier, Some(1));
        assert_eq!(f.sequence, Some(2));
        let v4_same = parse(&v4(128, 0, [0, 1, 0, 2], &[]), IcmpFamily::V4).unwrap();
        assert_eq!(v4_same.type_name(), "unknown", "v4 的 128 不是 echo");
        assert_eq!(v4_same.identifier, None);
    }

    #[test]
    fn neighbor_solicitation_parses_target_and_options() {
        let mut body = vec![0u8; 4];
        body.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        body.extend_from_slice(&[1, 1, 0x02, 0, 0, 0, 0, 1]);
        let f = parse(&v6(135, 0, [0; 4], &body), IcmpFamily::V6).unwrap();
        assert_eq!(f.type_name(), "neighbor_solicitation");
        let n = f.ndp.expect("NS 应有 NDP 字段");
        assert_eq!(n.target, Some("fe80::1".parse().unwrap()));
        assert_eq!(n.options, vec![NdpOption { kind: 1, len: 1 }]);
        assert!(!n.options_truncated);
    }

    #[test]
    fn router_advertisement_parses_fixed_fields_and_prefix_option() {
        let mut body = vec![64, 0xc0];
        body.extend_from_slice(&1800u16.to_be_bytes());
        body.extend_from_slice(&30_000u32.to_be_bytes());
        body.extend_from_slice(&1000u32.to_be_bytes());
        body.extend_from_slice(&[3, 4, 64, 0xc0, 0, 0, 0x0e, 0x10, 0, 0, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let f = parse(&v6(134, 0, [0; 4], &body), IcmpFamily::V6).unwrap();
        let n = f.ndp.expect("RA 应有 NDP 字段");
        assert_eq!(n.cur_hop_limit, Some(64));
        assert_eq!(n.ra_flags, Some(0xc0));
        assert_eq!(n.router_lifetime, Some(1800));
        assert_eq!(n.reachable_time, Some(30_000));
        assert_eq!(n.retrans_timer, Some(1000));
        assert_eq!(n.options, vec![NdpOption { kind: 3, len: 4 }]);
    }

    #[test]
    fn neighbor_advertisement_flags_and_target_are_kept() {
        let mut body = vec![0xe0, 0, 0, 0];
        body.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let f = parse(&v6(136, 0, [0; 4], &body), IcmpFamily::V6).unwrap();
        let n = f.ndp.expect("NA 应有 NDP 字段");
        assert_eq!(n.na_flags, Some(0xe000_0000));
        assert_eq!(n.target, Some("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn pad1_option_consumes_one_byte_and_continues() {
        let mut body = vec![0u8; 4];
        body.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        body.push(0); // Pad1
        body.extend_from_slice(&[1, 1, 0x02, 0, 0, 0, 0, 1]);
        let f = parse(&v6(135, 0, [0; 4], &body), IcmpFamily::V6).unwrap();
        let n = f.ndp.expect("NS");
        assert_eq!(
            n.options,
            vec![NdpOption { kind: 0, len: 0 }, NdpOption { kind: 1, len: 1 }]
        );
        assert!(!n.options_truncated && !n.options_malformed);
    }

    #[test]
    fn truncated_ndp_option_is_flagged_not_parsed() {
        let mut body = vec![0u8; 4];
        body.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        body.extend_from_slice(&[1, 1, 0x02, 0]); // 声明 8 字节，只给 4 字节
        let f = parse(&v6(135, 0, [0; 4], &body), IcmpFamily::V6).unwrap();
        let n = f.ndp.expect("NS");
        assert!(n.options.is_empty(), "不完整选项不得被当成已解析");
        assert!(n.options_truncated);
        assert!(!n.options_malformed);
    }

    #[test]
    fn zero_length_option_is_malformed_but_does_not_panic() {
        let mut body = vec![0u8; 4];
        body.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        body.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        let f = parse(&v6(135, 0, [0; 4], &body), IcmpFamily::V6).unwrap();
        assert!(f.ndp.expect("NS").options_malformed);
    }

    #[test]
    fn header_shorter_than_eight_bytes_is_a_typed_error() {
        let e = parse(&[8, 0, 0, 0, 0, 1, 0], IcmpFamily::V4).unwrap_err();
        assert_eq!(e, IcmpError::TruncatedHeader { need: 8, got: 7 });
        assert_eq!(e.code(), "icmp.truncated_header");
    }

    #[test]
    fn stats_count_families_types_and_embedded_payloads() {
        let mut s = IcmpStats::default();
        s.observe(&parse(&v4(8, 0, [0, 1, 0, 1], &[]), IcmpFamily::V4).unwrap());
        s.observe(&parse(&v4(0, 0, [0, 1, 0, 1], &[]), IcmpFamily::V4).unwrap());
        s.observe(&parse(&v6(128, 0, [0, 1, 0, 2], &[]), IcmpFamily::V6).unwrap());
        let mut ns = vec![0u8; 4];
        ns.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        s.observe(&parse(&v6(135, 0, [0; 4], &ns), IcmpFamily::V6).unwrap());
        s.observe(
            &parse(
                &v4(
                    3,
                    3,
                    [0; 4],
                    &ipv4_header([1, 1, 1, 1], [2, 2, 2, 2], 17, 28),
                ),
                IcmpFamily::V4,
            )
            .unwrap(),
        );
        s.record_error(IcmpError::TruncatedHeader { need: 8, got: 4 });
        assert_eq!(s.icmp_frames, 5);
        assert_eq!(s.v4, 3);
        assert_eq!(s.v6, 2);
        assert_eq!(s.echo_requests, 2);
        assert_eq!(s.echo_replies, 1);
        assert_eq!(s.destination_unreachable, 1);
        assert_eq!(s.ndp, 1);
        assert_eq!(s.errors, 1);
        assert_eq!(s.with_embedded, 1);
        assert_eq!(s.truncated, 1, "不足 8 字节的报文计入截断");
        let line = s.render_line();
        assert!(line.starts_with("icmp icmp_frames=5"), "{line}");
        assert!(line.contains("with_embedded=1"), "{line}");
    }

    #[test]
    fn json_line_is_stable_and_typed() {
        let p = v4(
            3,
            4,
            [0, 0, 0x05, 0xdc],
            &ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 17, 28),
        );
        let f = parse(&p, IcmpFamily::V4).unwrap();
        let line = f.to_json_line(1_700_000_000_000_000, 7, 42);
        assert!(
            line.starts_with("{\"timestamp_us\":1700000000000000,\"frame\":7"),
            "{line}"
        );
        assert!(line.contains("\"family\":\"ipv4\""), "{line}");
        assert!(
            line.contains("\"type_name\":\"destination_unreachable\""),
            "{line}"
        );
        assert!(line.contains("\"mtu\":1500"), "{line}");
        assert!(line.contains("\"source\":\"10.0.0.1\""), "{line}");
        assert!(line.contains("\"ndp\":null"), "{line}");
    }
}
