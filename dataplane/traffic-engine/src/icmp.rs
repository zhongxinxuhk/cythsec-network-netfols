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
// 3. **校验和只在“完整且可计算”时判定**。抓包截断、网卡校验和卸载与分片都会
//    让校验和看起来不对，因此不能把“没算”写成“坏包”：字段完整时输出
//    valid/invalid，否则输出 unavailable；checksum 原值始终保留。

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
/// MLDv2 记录条数上限。合法报告通常只有个位数；上限只防构造报文。
const MAX_MLD_RECORDS: usize = 64;
/// 单条 MLD 记录的源地址上限。RFC 不设小上限，这里只做内存边界。
const MAX_MLD_SOURCES: usize = 256;

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

/// 校验和判定结果。`Unavailable` 不是“坏包”，而是本轮没有足够上下文：
/// 抓包截断、分片未重组、ICMPv6 缺外层地址或调用方未提供完整标志。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumStatus {
    Valid,
    Invalid,
    Unavailable,
}

impl ChecksumStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ChecksumStatus::Valid => "valid",
            ChecksumStatus::Invalid => "invalid",
            ChecksumStatus::Unavailable => "unavailable",
        }
    }
}

/// ICMPv6 校验和需要外层 IPv6 源/目的；ICMPv4 只用报文自身。
/// `complete` 表示调用方确认 `payload` 是完整的 ICMP 报文（不是 snaplen 截断）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumContext {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub complete: bool,
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

/// 源/目标链路层地址选项（Type 1/2）。地址长度按选项保留，不硬套 6 字节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpLinkLayerAddress {
    pub kind: u8,
    pub address: Vec<u8>,
}

/// Prefix Information 选项（Type 3，RFC 4861 4.6.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpPrefixInfo {
    pub kind: u8,
    pub prefix_len: u8,
    /// 原始 L/A/Reserved1 字节；L=0x80、A=0x40。
    pub flags: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub prefix: Ipv6Addr,
}

/// MTU 选项（Type 5，RFC 4861 4.6.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdpMtu {
    pub kind: u8,
    pub mtu: u32,
}

/// Route Information 选项（Type 24，RFC 4191 2.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpRouteInfo {
    pub kind: u8,
    pub prefix_len: u8,
    /// 2 位 Prf；0=medium、1=high、2=low、3=保留。
    pub preference: u8,
    pub lifetime: u32,
    /// Length=1 时没有 Prefix 字段，保留 `None`；不补 `::`。
    pub prefix: Option<Ipv6Addr>,
}

/// RDNSS 选项（Type 25，RFC 6106 5.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpRdnss {
    pub kind: u8,
    pub lifetime: u32,
    pub servers: Vec<Ipv6Addr>,
}

/// DNSSL 选项（Type 31，RFC 6106 5.2）。域名按 DNS 无压缩 label 解码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpDnssl {
    pub kind: u8,
    pub lifetime: u32,
    pub domains: Vec<String>,
}

/// Redirected Header 选项（Type 4，RFC 4861 4.6.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpRedirectedHeader {
    pub kind: u8,
    pub packet: EmbeddedDatagram,
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
    /// 选项内容明细；未知选项只保留 Type/Length。
    pub link_layer_addresses: Vec<NdpLinkLayerAddress>,
    pub prefixes: Vec<NdpPrefixInfo>,
    pub mtu_options: Vec<NdpMtu>,
    pub route_info: Vec<NdpRouteInfo>,
    pub rdnss: Vec<NdpRdnss>,
    pub dnssl: Vec<NdpDnssl>,
    pub redirected_header: Option<NdpRedirectedHeader>,
    pub options_truncated: bool,
    pub options_malformed: bool,
}

/// MLDv2 的一条 Multicast Address Record（RFC 3810 5.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MldRecord {
    pub record_type: u8,
    pub aux_data_len: u8,
    pub multicast_address: Ipv6Addr,
    pub sources: Vec<Ipv6Addr>,
}

/// MLD/MLDv2 的可解析字段。只描述报文，不推断组播成员状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MldInfo {
    /// `query` / `report_v1` / `done_v1` / `report_v2`。
    pub kind: &'static str,
    /// 原始 Maximum Response Code / Delay 字段。
    pub max_response_code: u16,
    /// 按 RFC 3810 解码后的毫秒值；v1 时等于 max_response_code。
    pub max_response_delay_ms: u32,
    pub multicast_address: Option<Ipv6Addr>,
    pub s_flag: Option<bool>,
    pub qrv: Option<u8>,
    pub qqic: Option<u8>,
    pub sources: Vec<Ipv6Addr>,
    pub records: Vec<MldRecord>,
    pub truncated: bool,
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
    /// ICMPv6 MLD 字段；其他类型为 `None`。
    pub mld: Option<MldInfo>,
    /// 校验和判定；没有完整报文或外层上下文时为 `Unavailable`。
    pub checksum_status: ChecksumStatus,
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
        let embedded = embedded_json(self.embedded.as_ref());
        let ndp = ndp_json(self.ndp.as_ref());
        let mld = mld_json(self.mld.as_ref());
        format!(
            "{{\"timestamp_us\":{timestamp_us},\"frame\":{frame},\"frame_len\":{frame_len},\
             \"capture_truncated\":{},\"family\":\"{}\",\"ip_proto\":{},\
             \"type\":{},\"type_name\":\"{}\",\"code\":{},\"checksum\":{},\
             \"checksum_status\":\"{}\",\
             \"is_error\":{},\"identifier\":{},\"sequence\":{},\"rest_of_header\":{},\
             \"mtu\":{},\"pointer\":{},\"payload_len\":{},\"truncated\":{},\
             \"embedded\":{embedded},\"ndp\":{ndp},\"mld\":{mld}}}",
            self.capture_truncated,
            self.family.as_str(),
            self.family.ip_protocol(),
            self.type_code,
            self.type_name(),
            self.code,
            self.checksum,
            self.checksum_status.as_str(),
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
///
/// 不带外层上下文：ICMPv6 校验和无法计算，`checksum_status` 为 `unavailable`；
/// ICMPv4 同样不假定载荷完整。需要校验时用 [`parse_with_context`]。
pub fn parse(payload: &[u8], family: IcmpFamily) -> Result<IcmpFrame, IcmpError> {
    parse_with_context(payload, family, None)
}

/// 带外层上下文解析。`context.complete` 为真才计算校验和：
/// ICMPv4 覆盖整条 ICMP 报文；ICMPv6 还要外层 IPv6 源/目的与伪头。
pub fn parse_with_context(
    payload: &[u8],
    family: IcmpFamily,
    context: Option<ChecksumContext>,
) -> Result<IcmpFrame, IcmpError> {
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
        mld: None,
        checksum_status: ChecksumStatus::Unavailable,
        payload_len: message.len(),
        truncated: false,
        capture_truncated: false,
    };

    match family {
        IcmpFamily::V4 => parse_v4(&mut frame, payload, message),
        IcmpFamily::V6 => parse_v6(&mut frame, payload, message),
    }
    frame.checksum_status = verify_checksum(payload, family, context);
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
    if matches!(frame.type_code, 130..=132 | 143) {
        frame.mld = Some(parse_mld(frame.type_code, frame.rest_of_header, message));
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
    let (options_truncated, options_malformed) = parse_ndp_options(message, fixed_end, &mut n);
    n.options_truncated = options_truncated;
    n.options_malformed = options_malformed;
    n
}

/// 选项格式：Type(1) + Length(1，单位 8 字节) + Data。Pad1 只有 Type 一个字节。
fn parse_ndp_options(message: &[u8], start: usize, n: &mut NdpInfo) -> (bool, bool) {
    let mut truncated = false;
    let mut malformed = false;
    let mut pos = start;
    while pos < message.len() {
        if n.options.len() == MAX_NDP_OPTIONS {
            truncated = true;
            break;
        }
        let kind = message[pos];
        let option_start = pos;
        pos += 1;
        if kind == 0 {
            n.options.push(NdpOption { kind, len: 0 });
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
        let option = &message[option_start..option_start + bytes];
        parse_ndp_option_data(kind, option, n, &mut malformed);
        n.options.push(NdpOption { kind, len: units });
        pos = option_start + bytes;
    }
    (truncated, malformed)
}

fn parse_ndp_option_data(kind: u8, bytes: &[u8], n: &mut NdpInfo, malformed: &mut bool) {
    match kind {
        // Source/Target Link-Layer Address：Length 必须为 1（8 字节）。
        1 | 2 => {
            if bytes.len() < 8 {
                *malformed = true;
                return;
            }
            if bytes.len() != 8 {
                *malformed = true;
            }
            n.link_layer_addresses.push(NdpLinkLayerAddress {
                kind,
                address: bytes[2..8].to_vec(),
            });
        }
        // Prefix Information：固定 32 字节。
        3 => {
            if bytes.len() < 32 {
                *malformed = true;
                return;
            }
            let mut prefix = [0u8; 16];
            prefix.copy_from_slice(&bytes[16..32]);
            n.prefixes.push(NdpPrefixInfo {
                kind,
                prefix_len: bytes[2],
                flags: bytes[3],
                valid_lifetime: be32(bytes, 4),
                preferred_lifetime: be32(bytes, 8),
                prefix: Ipv6Addr::from(prefix),
            });
        }
        // Redirected Header：6 字节保留 + 原始 IP 头/数据。
        4 => {
            if bytes.len() <= 8 {
                *malformed = true;
                return;
            }
            if let Some(packet) = parse_embedded(&bytes[8..]) {
                n.redirected_header = Some(NdpRedirectedHeader { kind, packet });
            }
        }
        // MTU：固定 8 字节。
        5 => {
            if bytes.len() < 8 {
                *malformed = true;
                return;
            }
            n.mtu_options.push(NdpMtu {
                kind,
                mtu: be32(bytes, 4),
            });
        }
        // Route Information：Length 1/2/3，Prefix 0/8/16 字节。
        24 => {
            if bytes.len() < 8 {
                *malformed = true;
                return;
            }
            let prefix = if bytes.len() >= 24 {
                let mut p = [0u8; 16];
                p.copy_from_slice(&bytes[8..24]);
                Some(Ipv6Addr::from(p))
            } else if bytes.len() >= 16 {
                let mut p = [0u8; 16];
                p[..8].copy_from_slice(&bytes[8..16]);
                Some(Ipv6Addr::from(p))
            } else {
                None
            };
            n.route_info.push(NdpRouteInfo {
                kind,
                prefix_len: bytes[2],
                preference: (bytes[3] >> 3) & 0x03,
                lifetime: be32(bytes, 4),
                prefix,
            });
        }
        // RDNSS：2 字节保留 + 4 字节 lifetime + N 个 16 字节地址。
        25 => {
            if bytes.len() < 8 || (bytes.len() - 8) % 16 != 0 {
                *malformed = true;
                return;
            }
            let mut servers = Vec::new();
            for chunk in bytes[8..].chunks_exact(16) {
                let mut a = [0u8; 16];
                a.copy_from_slice(chunk);
                servers.push(Ipv6Addr::from(a));
            }
            n.rdnss.push(NdpRdnss {
                kind,
                lifetime: be32(bytes, 4),
                servers,
            });
        }
        // DNSSL：2 字节保留 + 4 字节 lifetime + DNS 无压缩域名列表。
        31 => {
            if bytes.len() < 8 {
                *malformed = true;
                return;
            }
            let (domains, bad) = parse_dns_names(&bytes[8..]);
            if bad {
                *malformed = true;
            }
            n.dnssl.push(NdpDnssl {
                kind,
                lifetime: be32(bytes, 4),
                domains,
            });
        }
        _ => {}
    }
}

/// DNS 搜索列表里的域名：label 长度 + label，0 结尾；不允许压缩指针。
/// 返回空列表不算错（选项可能只带填充），但截断/非法 label 要显式标记。
fn parse_dns_names(mut bytes: &[u8]) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    let mut bad = false;
    while !bytes.is_empty() && out.len() < 16 {
        if bytes[0] == 0 {
            break;
        }
        let mut name = String::new();
        let mut pos = 0usize;
        loop {
            if pos >= bytes.len() {
                bad = true;
                break;
            }
            let len = usize::from(bytes[pos]);
            pos += 1;
            if len == 0 {
                break;
            }
            if len & 0xc0 != 0 || pos + len > bytes.len() {
                bad = true;
                break;
            }
            let Ok(label) = std::str::from_utf8(&bytes[pos..pos + len]) else {
                bad = true;
                break;
            };
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(label);
            pos += len;
        }
        if bad {
            break;
        }
        if !name.is_empty() {
            out.push(name);
        }
        bytes = &bytes[pos..];
    }
    (out, bad)
}

/// MLD 查询的 Maximum Response Code 解码（RFC 3810 5.1.3）。
fn mld_delay(code: u16) -> u32 {
    if code < 0x8000 {
        u32::from(code)
    } else {
        let exp = u32::from((code >> 12) & 0x7);
        let mant = u32::from(code & 0x0fff);
        (mant | 0x1000) << (exp + 3)
    }
}

fn parse_mld(type_code: u8, rest: u32, message: &[u8]) -> MldInfo {
    let max_response_code = (rest >> 16) as u16;
    let mut m = MldInfo {
        kind: match type_code {
            130 => "query",
            131 => "report_v1",
            132 => "done_v1",
            _ => "report_v2",
        },
        max_response_code,
        max_response_delay_ms: mld_delay(max_response_code),
        multicast_address: None,
        s_flag: None,
        qrv: None,
        qqic: None,
        sources: Vec::new(),
        records: Vec::new(),
        truncated: false,
    };
    if message.len() < 16 {
        m.truncated = true;
        return m;
    }
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&message[..16]);
    m.multicast_address = Some(Ipv6Addr::from(addr));
    match type_code {
        130 => {
            // MLDv2 查询在组播地址后还有 flags/QQIC/源数量；MLDv1 到地址为止。
            if message.len() >= 20 {
                let flags = message[16];
                m.s_flag = Some(flags & 0x08 != 0);
                m.qrv = Some(flags & 0x07);
                m.qqic = Some(message[17]);
                let count = usize::from(be16(message, 18));
                let need = 20 + count * 16;
                if message.len() < need {
                    m.truncated = true;
                }
                let n = count
                    .min(MAX_MLD_SOURCES)
                    .min(message.len().saturating_sub(20) / 16);
                for chunk in message[20..20 + n * 16].chunks_exact(16) {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(chunk);
                    m.sources.push(Ipv6Addr::from(a));
                }
                if count > MAX_MLD_SOURCES {
                    m.truncated = true;
                }
            }
        }
        131 | 132 => {}
        _ => {
            // MLDv2 Report：rest 的低 16 位是记录数，记录从 message[0] 开始。
            let count = usize::from((rest & 0xffff) as u16);
            let mut pos = 0usize;
            for _ in 0..count.min(MAX_MLD_RECORDS) {
                if message.len() < pos + 20 {
                    m.truncated = true;
                    break;
                }
                let record_type = message[pos];
                let aux_data_len = message[pos + 1];
                let sources = usize::from(be16(message, pos + 2));
                let mut mcast = [0u8; 16];
                mcast.copy_from_slice(&message[pos + 4..pos + 20]);
                let src_start = pos + 20;
                let src_need = sources * 16;
                let aux_need = usize::from(aux_data_len) * 4;
                if message.len() < src_start + src_need + aux_need {
                    m.truncated = true;
                    break;
                }
                let mut srcs = Vec::new();
                for chunk in message[src_start..src_start + src_need].chunks_exact(16) {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(chunk);
                    srcs.push(Ipv6Addr::from(a));
                }
                m.records.push(MldRecord {
                    record_type,
                    aux_data_len,
                    multicast_address: Ipv6Addr::from(mcast),
                    sources: srcs,
                });
                pos = src_start + src_need + aux_need;
            }
            if count > MAX_MLD_RECORDS {
                m.truncated = true;
            }
        }
    }
    m
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn add_bytes(sum: &mut u32, bytes: &[u8]) {
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        *sum += u32::from(be16(c, 0));
    }
    if let [last] = chunks.remainder() {
        *sum += u32::from(*last) << 8;
    }
}

/// ICMPv4 校验和：只覆盖 ICMP 报文自身。
fn checksum_v4(payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    add_bytes(&mut sum, payload);
    !fold_checksum(sum)
}

/// ICMPv6 校验和：外层 IPv6 伪头 + ICMPv6 报文。
fn checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    add_bytes(&mut sum, &src.octets());
    add_bytes(&mut sum, &dst.octets());
    let len = payload.len() as u32;
    sum += len >> 16;
    sum += len & 0xffff;
    sum += u32::from(IPPROTO_ICMPV6);
    add_bytes(&mut sum, payload);
    !fold_checksum(sum)
}

fn verify_checksum(
    payload: &[u8],
    family: IcmpFamily,
    context: Option<ChecksumContext>,
) -> ChecksumStatus {
    let Some(ctx) = context else {
        return ChecksumStatus::Unavailable;
    };
    if !ctx.complete {
        return ChecksumStatus::Unavailable;
    }
    let valid = match family {
        IcmpFamily::V4 => checksum_v4(payload) == 0,
        IcmpFamily::V6 => match (ctx.source, ctx.destination) {
            (IpAddr::V6(src), IpAddr::V6(dst)) => checksum_v6(src, dst, payload) == 0,
            _ => return ChecksumStatus::Unavailable,
        },
    };
    if valid {
        ChecksumStatus::Valid
    } else {
        ChecksumStatus::Invalid
    }
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_bool_opt(v: Option<bool>) -> String {
    v.map(|b| b.to_string()).unwrap_or_else(|| "null".into())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn format_link_address(bytes: &[u8]) -> String {
    if bytes.len() == 6 {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    } else {
        hex_bytes(bytes)
    }
}

fn json_ipv6_array(values: &[Ipv6Addr]) -> String {
    let items = values
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

fn embedded_json(e: Option<&EmbeddedDatagram>) -> String {
    match e {
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
    }
}

fn ndp_json(n: Option<&NdpInfo>) -> String {
    let Some(n) = n else {
        return "null".to_string();
    };
    let options = n
        .options
        .iter()
        .map(|o| format!("{{\"kind\":{},\"len\":{}}}", o.kind, o.len))
        .collect::<Vec<_>>()
        .join(",");
    let link = n
        .link_layer_addresses
        .iter()
        .map(|a| {
            format!(
                "{{\"kind\":{},\"address\":\"{}\"}}",
                a.kind,
                format_link_address(&a.address)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let prefixes = n
        .prefixes
        .iter()
        .map(|p| {
            format!(
                "{{\"kind\":{},\"prefix_len\":{},\"flags\":{},\"valid_lifetime\":{},\
                 \"preferred_lifetime\":{},\"prefix\":\"{}\"}}",
                p.kind, p.prefix_len, p.flags, p.valid_lifetime, p.preferred_lifetime, p.prefix
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let mtu_options = n
        .mtu_options
        .iter()
        .map(|m| format!("{{\"kind\":{},\"mtu\":{}}}", m.kind, m.mtu))
        .collect::<Vec<_>>()
        .join(",");
    let routes = n
        .route_info
        .iter()
        .map(|r| {
            format!(
                "{{\"kind\":{},\"prefix_len\":{},\"preference\":{},\"lifetime\":{},\
                 \"prefix\":{}}}",
                r.kind,
                r.prefix_len,
                r.preference,
                r.lifetime,
                json_string_opt(r.prefix.map(|p| p.to_string()))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let rdnss = n
        .rdnss
        .iter()
        .map(|r| {
            format!(
                "{{\"kind\":{},\"lifetime\":{},\"servers\":{}}}",
                r.kind,
                r.lifetime,
                json_ipv6_array(&r.servers)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let dnssl = n
        .dnssl
        .iter()
        .map(|d| {
            let domains = d
                .domains
                .iter()
                .map(|s| json_string(s))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"kind\":{},\"lifetime\":{},\"domains\":[{}]}}",
                d.kind, d.lifetime, domains
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let redirected = match &n.redirected_header {
        None => "null".to_string(),
        Some(r) => format!(
            "{{\"kind\":{},\"packet\":{}}}",
            r.kind,
            embedded_json(Some(&r.packet))
        ),
    };
    format!(
        "{{\"target\":{},\"destination\":{},\"cur_hop_limit\":{},\"ra_flags\":{},\
         \"router_lifetime\":{},\"reachable_time\":{},\"retrans_timer\":{},\
         \"na_flags\":{},\"options\":[{}],\
         \"link_layer_addresses\":[{}],\"prefixes\":[{}],\"mtu_options\":[{}],\
         \"route_info\":[{}],\"rdnss\":[{}],\"dnssl\":[{}],\"redirected_header\":{redirected},\
         \"options_truncated\":{},\"options_malformed\":{}}}",
        json_string_opt(n.target.map(|v| v.to_string())),
        json_string_opt(n.destination.map(|v| v.to_string())),
        json_opt_num(n.cur_hop_limit.map(u64::from)),
        json_opt_num(n.ra_flags.map(u64::from)),
        json_opt_num(n.router_lifetime.map(u64::from)),
        json_opt_num(n.reachable_time.map(u64::from)),
        json_opt_num(n.retrans_timer.map(u64::from)),
        json_opt_num(n.na_flags.map(u64::from)),
        options,
        link,
        prefixes,
        mtu_options,
        routes,
        rdnss,
        dnssl,
        n.options_truncated,
        n.options_malformed,
    )
}

fn mld_json(m: Option<&MldInfo>) -> String {
    let Some(m) = m else {
        return "null".to_string();
    };
    let records = m
        .records
        .iter()
        .map(|r| {
            format!(
                "{{\"record_type\":{},\"aux_data_len\":{},\"multicast_address\":\"{}\",\
                 \"sources\":{}}}",
                r.record_type,
                r.aux_data_len,
                r.multicast_address,
                json_ipv6_array(&r.sources)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"kind\":\"{}\",\"max_response_code\":{},\"max_response_delay_ms\":{},\
         \"multicast_address\":{},\"s_flag\":{},\"qrv\":{},\"qqic\":{},\
         \"sources\":{},\"records\":[{}],\"truncated\":{}}}",
        m.kind,
        m.max_response_code,
        m.max_response_delay_ms,
        json_string_opt(m.multicast_address.map(|v| v.to_string())),
        json_bool_opt(m.s_flag),
        json_opt_num(m.qrv.map(u64::from)),
        json_opt_num(m.qqic.map(u64::from)),
        json_ipv6_array(&m.sources),
        records,
        m.truncated,
    )
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
    pub checksum_valid: u64,
    pub checksum_invalid: u64,
    pub checksum_unavailable: u64,
    pub mld_queries: u64,
    pub mld_reports: u64,
    pub mld_sources: u64,
    pub mld_records: u64,
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
        match f.checksum_status {
            ChecksumStatus::Valid => self.checksum_valid += 1,
            ChecksumStatus::Invalid => self.checksum_invalid += 1,
            ChecksumStatus::Unavailable => self.checksum_unavailable += 1,
        }
        if let Some(m) = &f.mld {
            if m.kind == "query" {
                self.mld_queries += 1;
            } else {
                self.mld_reports += 1;
            }
            self.mld_sources += m.sources.len() as u64;
            self.mld_records += m.records.len() as u64;
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
             ndp_options_malformed={} capture_truncated={} \
             checksum_valid={} checksum_invalid={} checksum_unavailable={} \
             mld_queries={} mld_reports={} mld_sources={} mld_records={}",
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
            self.checksum_valid,
            self.checksum_invalid,
            self.checksum_unavailable,
            self.mld_queries,
            self.mld_reports,
            self.mld_sources,
            self.mld_records,
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
    fn checksum_is_validated_only_with_complete_context() {
        let mut p = v4(8, 0, [0x12, 0x34, 0, 7], b"abcdefgh");
        let c = checksum_v4(&p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
        let ctx = ChecksumContext {
            source: "10.0.0.1".parse().unwrap(),
            destination: "10.0.0.2".parse().unwrap(),
            complete: true,
        };
        let f = parse_with_context(&p, IcmpFamily::V4, Some(ctx)).unwrap();
        assert_eq!(f.checksum_status, ChecksumStatus::Valid);

        let mut bad = p.clone();
        bad[8] ^= 0xff;
        let f = parse_with_context(&bad, IcmpFamily::V4, Some(ctx)).unwrap();
        assert_eq!(f.checksum_status, ChecksumStatus::Invalid);

        let f = parse_with_context(&p, IcmpFamily::V4, None).unwrap();
        assert_eq!(f.checksum_status, ChecksumStatus::Unavailable);
        let f = parse_with_context(
            &p,
            IcmpFamily::V4,
            Some(ChecksumContext {
                complete: false,
                ..ctx
            }),
        )
        .unwrap();
        assert_eq!(f.checksum_status, ChecksumStatus::Unavailable);
    }

    #[test]
    fn icmpv6_checksum_uses_outer_addresses_and_pseudo_header() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut p = v6(128, 0, [0x12, 0x34, 0, 7], b"abcdefgh");
        let c = checksum_v6(src, dst, &p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
        let ctx = ChecksumContext {
            source: IpAddr::V6(src),
            destination: IpAddr::V6(dst),
            complete: true,
        };
        let f = parse_with_context(&p, IcmpFamily::V6, Some(ctx)).unwrap();
        assert_eq!(f.checksum_status, ChecksumStatus::Valid);
        // 换成别的源地址，伪头不同，必须判 invalid 而不是继续 valid。
        let wrong = ChecksumContext {
            source: IpAddr::V6("2001:db8::9".parse().unwrap()),
            ..ctx
        };
        let f = parse_with_context(&p, IcmpFamily::V6, Some(wrong)).unwrap();
        assert_eq!(f.checksum_status, ChecksumStatus::Invalid);
        let f = parse_with_context(&p, IcmpFamily::V6, None).unwrap();
        assert_eq!(f.checksum_status, ChecksumStatus::Unavailable);
    }

    #[test]
    fn ndp_option_contents_are_decoded_with_bounded_lengths() {
        // Router Advertisement 固定字段 12 字节；选项从 offset 12 开始。
        let mut body = vec![64, 0xc0];
        body.extend_from_slice(&1800u16.to_be_bytes());
        body.extend_from_slice(&30_000u32.to_be_bytes());
        body.extend_from_slice(&1000u32.to_be_bytes());
        // Source Link-Layer Address (type 1, len 1)
        body.extend_from_slice(&[1, 1, 2, 0, 0, 0, 0, 1]);
        // Prefix Information (type 3, len 4): /64, L+A, valid 3600, preferred 1800
        body.extend_from_slice(&[3, 4, 64, 0xc0]);
        body.extend_from_slice(&3600u32.to_be_bytes());
        body.extend_from_slice(&1800u32.to_be_bytes());
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // MTU (type 5, len 1)
        body.extend_from_slice(&[5, 1, 0, 0]);
        body.extend_from_slice(&1500u32.to_be_bytes());
        // Route Information (type 24, len 3): /64, preference high, lifetime 600
        body.extend_from_slice(&[24, 3, 64, 0x08]);
        body.extend_from_slice(&600u32.to_be_bytes());
        body.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // RDNSS (type 25, len 3): lifetime 300, one server
        body.extend_from_slice(&[25, 3, 0, 0]);
        body.extend_from_slice(&300u32.to_be_bytes());
        body.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
        ]);
        // DNSSL (type 31, len 3): lifetime 300, "example.com"
        body.extend_from_slice(&[31, 3, 0, 0]);
        body.extend_from_slice(&300u32.to_be_bytes());
        body.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        body.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, 0, 0]);
        // Redirected Header (type 4, len 4): reserved 6 + IPv4 header + padding
        body.extend_from_slice(&[4, 4, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&ipv4_header([10, 0, 0, 1], [10, 0, 0, 2], 17, 28));
        body.extend_from_slice(&[0; 4]);

        let f = parse(&v6(134, 0, [0; 4], &body), IcmpFamily::V6).unwrap();
        let n = f.ndp.as_ref().expect("RA");
        assert_eq!(n.link_layer_addresses.len(), 1);
        assert_eq!(n.link_layer_addresses[0].address, vec![2, 0, 0, 0, 0, 1]);
        assert_eq!(n.prefixes.len(), 1);
        assert_eq!(n.prefixes[0].prefix_len, 64);
        assert_eq!(n.prefixes[0].flags, 0xc0);
        assert_eq!(n.prefixes[0].valid_lifetime, 3600);
        assert_eq!(
            n.prefixes[0].prefix,
            "2001:db8::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(n.mtu_options, vec![NdpMtu { kind: 5, mtu: 1500 }]);
        assert_eq!(n.route_info.len(), 1);
        assert_eq!(n.route_info[0].preference, 1);
        assert_eq!(n.route_info[0].lifetime, 600);
        assert_eq!(n.rdnss.len(), 1);
        assert_eq!(n.rdnss[0].servers.len(), 1);
        assert_eq!(n.dnssl.len(), 1);
        assert_eq!(n.dnssl[0].domains, vec!["example.com"]);
        let redirected = n.redirected_header.as_ref().expect("redirected header");
        assert_eq!(redirected.packet.source, Some("10.0.0.1".parse().unwrap()));
        let line = f.to_json_line(1, 1, 1);
        assert!(line.contains("\"prefixes\":[{\"kind\":3"), "{line}");
        assert!(line.contains("\"domains\":[\"example.com\"]"), "{line}");
    }

    #[test]
    fn mld_query_v2_and_report_v2_are_bounded() {
        let mut query = vec![0u8; 16];
        query[0] = 0xff;
        query[1] = 0x02;
        query.extend_from_slice(&[0x0f, 10]); // S=1, QRV=7, QQIC=10
        query.extend_from_slice(&2u16.to_be_bytes());
        query.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        query.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let f = parse(&v6(130, 0, [0x03, 0xe8, 0, 0], &query), IcmpFamily::V6).unwrap();
        let m = f.mld.expect("MLD query");
        assert_eq!(m.kind, "query");
        assert_eq!(m.max_response_delay_ms, 1000);
        assert_eq!(m.s_flag, Some(true));
        assert_eq!(m.qrv, Some(7));
        assert_eq!(m.qqic, Some(10));
        assert_eq!(m.sources.len(), 2);
        assert!(m.multicast_address.is_some());

        let mut report = Vec::new();
        report.push(1); // MODE_IS_INCLUDE
        report.push(0); // aux data len
        report.extend_from_slice(&1u16.to_be_bytes());
        report.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        report.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        let f = parse(&v6(143, 0, [0, 0, 0, 1], &report), IcmpFamily::V6).unwrap();
        let m = f.mld.expect("MLD report");
        assert_eq!(m.kind, "report_v2");
        assert_eq!(m.records.len(), 1);
        assert_eq!(m.records[0].record_type, 1);
        assert_eq!(m.records[0].sources.len(), 1);
        assert_eq!(
            m.records[0].multicast_address,
            "ff02::1".parse::<Ipv6Addr>().unwrap()
        );
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
        assert!(line.contains("\"mld\":null"), "{line}");
        assert!(
            line.contains("\"checksum_status\":\"unavailable\""),
            "{line}"
        );
    }
}
