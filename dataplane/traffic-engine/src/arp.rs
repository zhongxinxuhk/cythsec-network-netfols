// arp.rs —— Ethernet ARP/RARP 有界解析（RFC 826 / RFC 903）。
//
// 定位：ARP 没有 IP 五元组，不能塞进 `FlowRecord`。本模块只回答“这一帧是不是
// 一个结构完整的 ARP/RARP，以及它的字段是什么”，供独立采集器输出事件、
// 供主流水线做帧级计数。**不从 ARP 推断设备身份、在线状态或缓存表**：
// 收到一个 reply 不等于目标真的在使用该地址，未经请求的 reply 也不等于冲突。
//
// 三个刻意的边界：
//
// 1. **只处理 Ethernet 链路上的 ARP**（含最多两层 802.1Q/QinQ）。Linux cooked
//    capture、raw IP、pcapng 不在这里猜，交给调用方显式报不支持。
// 2. **长度字段可以不是常见的 6/4**。HTYPE/PTYPE/HLEN/PLEN 原样保留；只有
//    Ethernet/IPv4 或 Ethernet/IPv6 的组合才额外给出格式化地址，其余给十六进制
//    原始字节，绝不把 6 字节硬件地址硬套成 MAC、也不把任意 4 字节协议地址
//    当成 IPv4。
// 3. **Ethernet 尾部填充不算错误**。ARP 体长度由 HLEN/PLEN 唯一决定，之后多出的
//    字节是 60 字节最小帧填充；把填充当畸形会拒绝大量合法请求。

use std::fmt;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

/// ARP 的 EtherType。
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// RARP 的 EtherType（RFC 903）。
pub const ETHERTYPE_RARP: u16 = 0x8035;

const ETH_HEADER_LEN: usize = 14;
const VLAN_TAG_LEN: usize = 4;
/// 与 `channel::decode` 的上限一致：QinQ 是现实上限，更多层一定是解析位置偏了。
const MAX_VLAN_TAGS: u8 = 2;
const ARP_HEADER_LEN: usize = 8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const HARDWARE_ETHERNET: u16 = 1;
const HARDWARE_IEEE802: u16 = 6;

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn is_vlan(ether_type: u16) -> bool {
    matches!(ether_type, 0x8100 | 0x88A8 | 0x9100)
}

/// 解析失败的具体位置。与 `channel::DecodeError` 分开：ARP 不是 IP 解码失败，
/// 它的错误不该被计入 `decode.non_ip` 之外的地方。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpError {
    /// 连以太头都不完整。
    TruncatedEthernet { need: usize, got: usize },
    /// EtherType 不是 ARP。
    NonArpEtherType { ether_type: u16 },
    /// VLAN 嵌套超过上限。
    TooManyVlanTags { limit: u8 },
    /// 8 字节固定 ARP 头不完整。
    TruncatedArpHeader { need: usize, got: usize },
    /// 按 HLEN/PLEN 算出的地址区不完整（抓包截断或坏包）。
    TruncatedArpBody { need: usize, got: usize },
}

impl ArpError {
    /// 稳定错误码，供统计/日志按原因聚合。
    pub fn code(self) -> &'static str {
        match self {
            ArpError::TruncatedEthernet { .. } => "arp.truncated_ethernet",
            ArpError::NonArpEtherType { .. } => "arp.non_arp",
            ArpError::TooManyVlanTags { .. } => "arp.vlan_nesting",
            ArpError::TruncatedArpHeader { .. } => "arp.truncated_header",
            ArpError::TruncatedArpBody { .. } => "arp.truncated_body",
        }
    }
}

impl fmt::Display for ArpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpError::TruncatedEthernet { need, got } => {
                write!(f, "以太头不完整：需要 {need} 字节，实有 {got} 字节")
            }
            ArpError::NonArpEtherType { ether_type } => {
                write!(f, "EtherType=0x{ether_type:04X}，不是 ARP")
            }
            ArpError::TooManyVlanTags { limit } => {
                write!(f, "VLAN 标签超过 {limit} 层")
            }
            ArpError::TruncatedArpHeader { need, got } => {
                write!(f, "ARP 固定头不完整：需要 {need} 字节，实有 {got} 字节")
            }
            ArpError::TruncatedArpBody { need, got } => {
                write!(
                    f,
                    "ARP 地址区不完整：按 HLEN/PLEN 需要 {need} 字节，实有 {got} 字节"
                )
            }
        }
    }
}

impl std::error::Error for ArpError {}

/// 一条结构完整的 ARP/RARP 帧。
///
/// `sender_*` / `target_*` 都是**原始字节**；格式化只在明确的 Ethernet/IPv4 或
/// Ethernet/IPv6 组合下发生（见 `sender_ipv4` 等方法）。这样未知硬件类型不会
/// 被错误地展示成 MAC 地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpFrame {
    /// 从外到内的 VLAN ID（最多两层）。空表示未打标。
    pub vlan_ids: Vec<u16>,
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_len: u8,
    pub protocol_len: u8,
    pub operation: u16,
    pub sender_hardware: Vec<u8>,
    pub sender_protocol: Vec<u8>,
    pub target_hardware: Vec<u8>,
    pub target_protocol: Vec<u8>,
    /// 采集侧 `orig_len > caplen`。ARP 体可能仍完整，故它与 `TruncatedArpBody`
    /// 是两件事：前者是“抓少了”，后者是“按字段算根本不够”。
    pub capture_truncated: bool,
}

impl ArpFrame {
    pub fn hardware_type_name(&self) -> &'static str {
        match self.hardware_type {
            HARDWARE_ETHERNET => "ethernet",
            HARDWARE_IEEE802 => "ieee802",
            _ => "unknown",
        }
    }

    pub fn protocol_type_name(&self) -> &'static str {
        match self.protocol_type {
            ETHERTYPE_IPV4 => "ipv4",
            ETHERTYPE_IPV6 => "ipv6",
            ETHERTYPE_RARP => "rarp",
            _ => "unknown",
        }
    }

    pub fn operation_name(&self) -> &'static str {
        match self.operation {
            1 => "request",
            2 => "reply",
            3 => "rarp_request",
            4 => "rarp_reply",
            _ => "unknown",
        }
    }

    /// 仅当 HTYPE=1（Ethernet）且 HLEN=6 时给出 MAC；否则 `None`，
    /// 不把任意 6 字节硬件地址叫成 MAC。
    pub fn sender_mac(&self) -> Option<[u8; 6]> {
        mac_if_ethernet(self.hardware_type, self.hardware_len, &self.sender_hardware)
    }

    pub fn target_mac(&self) -> Option<[u8; 6]> {
        mac_if_ethernet(self.hardware_type, self.hardware_len, &self.target_hardware)
    }

    /// 仅当 PTYPE=IPv4 且 PLEN=4 时给出地址。
    pub fn sender_ipv4(&self) -> Option<Ipv4Addr> {
        ipv4_if(self.protocol_type, self.protocol_len, &self.sender_protocol)
    }

    pub fn target_ipv4(&self) -> Option<Ipv4Addr> {
        ipv4_if(self.protocol_type, self.protocol_len, &self.target_protocol)
    }

    /// 仅当 PTYPE=IPv6 且 PLEN=16 时给出地址。
    pub fn sender_ipv6(&self) -> Option<Ipv6Addr> {
        ipv6_if(self.protocol_type, self.protocol_len, &self.sender_protocol)
    }

    pub fn target_ipv6(&self) -> Option<Ipv6Addr> {
        ipv6_if(self.protocol_type, self.protocol_len, &self.target_protocol)
    }

    /// Gratuitous ARP：请求或应答中 sender IP == target IP 且非 0.0.0.0。
    /// 只对 Ethernet/IPv4 判定；其他组合返回 `None`（“判不了”，不是“不是”）。
    pub fn is_gratuitous(&self) -> Option<bool> {
        let s = self.sender_ipv4()?;
        let t = self.target_ipv4()?;
        Some(s == t && !s.is_unspecified())
    }

    /// ARP probe（RFC 5227）：请求且 sender IP 为 0.0.0.0。
    /// 仍然只是报文事实，不推断地址最终是否被占用。
    pub fn is_probe(&self) -> Option<bool> {
        if self.operation != 1 {
            return None;
        }
        Some(self.sender_ipv4()?.is_unspecified())
    }

    /// 一行稳定 JSON（字段顺序固定；未知值用 `null`，不缺席）。
    pub fn to_json_line(&self, timestamp_us: u64, frame: u64, frame_len: usize) -> String {
        let vlan_ids = self
            .vlan_ids
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let sender_mac = json_string_opt(self.sender_mac().map(format_mac));
        let target_mac = json_string_opt(self.target_mac().map(format_mac));
        let sender_ipv4 = json_string_opt(self.sender_ipv4().map(|v| v.to_string()));
        let target_ipv4 = json_string_opt(self.target_ipv4().map(|v| v.to_string()));
        let sender_ipv6 = json_string_opt(self.sender_ipv6().map(|v| v.to_string()));
        let target_ipv6 = json_string_opt(self.target_ipv6().map(|v| v.to_string()));
        format!(
            "{{\"timestamp_us\":{timestamp_us},\"frame\":{frame},\"frame_len\":{frame_len},\
             \"capture_truncated\":{},\"vlan_ids\":[{vlan_ids}],\
             \"hardware_type\":{},\"hardware_type_name\":\"{}\",\
             \"protocol_type\":{},\"protocol_type_name\":\"{}\",\
             \"hardware_len\":{},\"protocol_len\":{},\
             \"operation\":{},\"operation_name\":\"{}\",\
             \"sender_hardware\":\"{}\",\"sender_mac\":{sender_mac},\
             \"sender_protocol\":\"{}\",\"sender_ipv4\":{sender_ipv4},\"sender_ipv6\":{sender_ipv6},\
             \"target_hardware\":\"{}\",\"target_mac\":{target_mac},\
             \"target_protocol\":\"{}\",\"target_ipv4\":{target_ipv4},\"target_ipv6\":{target_ipv6},\
             \"gratuitous\":{},\"probe\":{}}}",
            self.capture_truncated,
            self.hardware_type,
            self.hardware_type_name(),
            self.protocol_type,
            self.protocol_type_name(),
            self.hardware_len,
            self.protocol_len,
            self.operation,
            self.operation_name(),
            hex(&self.sender_hardware),
            hex(&self.sender_protocol),
            hex(&self.target_hardware),
            hex(&self.target_protocol),
            json_bool_opt(self.is_gratuitous()),
            json_bool_opt(self.is_probe()),
        )
    }
}

fn mac_if_ethernet(hardware_type: u16, hardware_len: u8, bytes: &[u8]) -> Option<[u8; 6]> {
    if hardware_type != HARDWARE_ETHERNET || hardware_len != 6 || bytes.len() != 6 {
        return None;
    }
    Some([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
}

fn ipv4_if(protocol_type: u16, protocol_len: u8, bytes: &[u8]) -> Option<Ipv4Addr> {
    if protocol_type != ETHERTYPE_IPV4 || protocol_len != 4 || bytes.len() != 4 {
        return None;
    }
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn ipv6_if(protocol_type: u16, protocol_len: u8, bytes: &[u8]) -> Option<Ipv6Addr> {
    if protocol_type != ETHERTYPE_IPV6 || protocol_len != 16 || bytes.len() != 16 {
        return None;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(bytes);
    Some(Ipv6Addr::from(a))
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn json_string_opt(v: Option<String>) -> String {
    match v {
        Some(s) => format!("\"{s}\""),
        None => "null".to_string(),
    }
}

fn json_bool_opt(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

/// 只判断 EtherType（含最多 8 层 VLAN），不解析 ARP 体。
///
/// 用于主流水线：`decode_frame` 在 VLAN 层数超限时只报 `TooManyVlanTags`，
/// 此时仍要先确认“里面到底是不是 ARP”，否则会把超嵌套的 IPv4 帧误记成坏 ARP。
/// 8 层是纯防御性上限，正常 QinQ 只需 2 层。
pub fn is_arp_ethertype(frame: &[u8]) -> bool {
    if frame.len() < ETH_HEADER_LEN {
        return false;
    }
    let mut off = 12usize;
    for _ in 0..8 {
        if frame.len() < off + 2 {
            return false;
        }
        let ether_type = be16(frame, off);
        if !is_vlan(ether_type) {
            return ether_type == ETHERTYPE_ARP || ether_type == ETHERTYPE_RARP;
        }
        if frame.len() < off + 4 {
            return false;
        }
        off += VLAN_TAG_LEN;
    }
    false
}

/// 解析一条 Ethernet ARP/RARP 帧。
///
/// 只读取 `frame` 的已捕获字节；`orig_len` 由调用方另行标到 `capture_truncated`。
pub fn parse_ethernet(frame: &[u8]) -> Result<ArpFrame, ArpError> {
    if frame.len() < ETH_HEADER_LEN {
        return Err(ArpError::TruncatedEthernet {
            need: ETH_HEADER_LEN,
            got: frame.len(),
        });
    }
    let mut off = 12usize;
    let mut ether_type = be16(frame, off);
    let mut vlan_ids = Vec::new();
    while is_vlan(ether_type) {
        if vlan_ids.len() >= MAX_VLAN_TAGS as usize {
            return Err(ArpError::TooManyVlanTags {
                limit: MAX_VLAN_TAGS,
            });
        }
        // off 指向本层 TPID；其后依次是 2 字节 TCI 与 2 字节内层 EtherType。
        // 必须把这三段都算进 need：只按 VLAN_TAG_LEN 检查会把“缺内层 EtherType”
        // 当成“没有标签”，然后在错误的位置读 ARP 头。
        let need = off + VLAN_TAG_LEN + 2;
        if frame.len() < need {
            return Err(ArpError::TruncatedEthernet {
                need,
                got: frame.len(),
            });
        }
        vlan_ids.push(be16(frame, off + 2) & 0x0fff);
        ether_type = be16(frame, off + 4);
        off += VLAN_TAG_LEN;
    }
    if ether_type != ETHERTYPE_ARP && ether_type != ETHERTYPE_RARP {
        return Err(ArpError::NonArpEtherType { ether_type });
    }

    // 无 VLAN 时 off 停在 EtherType 字段起点（12），ARP 体从 14 开始；
    // 有 VLAN 时每层已把 off 推过「TCI + 内层 EtherType」，off 就是 ARP 体起点。
    let body_off = if vlan_ids.is_empty() {
        ETH_HEADER_LEN
    } else {
        off + 2
    };
    let body = &frame[body_off..];
    if body.len() < ARP_HEADER_LEN {
        return Err(ArpError::TruncatedArpHeader {
            need: ARP_HEADER_LEN,
            got: body.len(),
        });
    }
    let hardware_type = be16(body, 0);
    let protocol_type = be16(body, 2);
    let hardware_len = body[4];
    let protocol_len = body[5];
    let operation = be16(body, 6);
    let hlen = hardware_len as usize;
    let plen = protocol_len as usize;
    // 8 固定头 + 两组 (HLEN+PLEN)。u8 上限 255，算术不会溢出 usize。
    let need = ARP_HEADER_LEN + 2 * (hlen + plen);
    if body.len() < need {
        return Err(ArpError::TruncatedArpBody {
            need,
            got: body.len(),
        });
    }
    let mut p = ARP_HEADER_LEN;
    let sender_hardware = body[p..p + hlen].to_vec();
    p += hlen;
    let sender_protocol = body[p..p + plen].to_vec();
    p += plen;
    let target_hardware = body[p..p + hlen].to_vec();
    p += hlen;
    let target_protocol = body[p..p + plen].to_vec();

    Ok(ArpFrame {
        vlan_ids,
        hardware_type,
        protocol_type,
        hardware_len,
        protocol_len,
        operation,
        sender_hardware,
        sender_protocol,
        target_hardware,
        target_protocol,
        capture_truncated: false,
    })
}

/// ARP 帧级统计。**不把“收到的 reply”算成“地址在线”**：这里只有报文计数。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArpStats {
    pub arp_frames: u64,
    pub requests: u64,
    pub replies: u64,
    pub rarp_requests: u64,
    pub rarp_replies: u64,
    pub other_operations: u64,
    pub probes: u64,
    pub gratuitous: u64,
    pub vlan_tagged: u64,
    pub unknown_hardware: u64,
    pub unknown_protocol: u64,
    pub malformed: u64,
    pub truncated: u64,
    pub non_arp: u64,
    pub capture_truncated: u64,
}

impl ArpStats {
    pub fn observe(&mut self, f: &ArpFrame) {
        self.arp_frames += 1;
        match f.operation {
            1 => self.requests += 1,
            2 => self.replies += 1,
            3 => self.rarp_requests += 1,
            4 => self.rarp_replies += 1,
            _ => self.other_operations += 1,
        }
        if f.is_probe() == Some(true) {
            self.probes += 1;
        }
        if f.is_gratuitous() == Some(true) {
            self.gratuitous += 1;
        }
        if !f.vlan_ids.is_empty() {
            self.vlan_tagged += 1;
        }
        if !matches!(f.hardware_type, HARDWARE_ETHERNET | HARDWARE_IEEE802) {
            self.unknown_hardware += 1;
        }
        if !matches!(
            f.protocol_type,
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 | ETHERTYPE_RARP
        ) {
            self.unknown_protocol += 1;
        }
        if f.capture_truncated {
            self.capture_truncated += 1;
        }
    }

    /// 记一次解析失败。`NonArpEtherType` 单独计，不能把普通 IPv4/LLDP 帧算成坏 ARP。
    pub fn record_error(&mut self, e: ArpError) {
        match e {
            ArpError::NonArpEtherType { .. } => self.non_arp += 1,
            ArpError::TruncatedEthernet { .. }
            | ArpError::TruncatedArpHeader { .. }
            | ArpError::TruncatedArpBody { .. } => self.truncated += 1,
            ArpError::TooManyVlanTags { .. } => self.malformed += 1,
        }
    }

    pub fn render_line(&self) -> String {
        format!(
            "arp arp_frames={} requests={} replies={} rarp_requests={} rarp_replies={} \
             other_operations={} probes={} gratuitous={} vlan_tagged={} unknown_hardware={} \
             unknown_protocol={} malformed={} truncated={} non_arp={} capture_truncated={}",
            self.arp_frames,
            self.requests,
            self.replies,
            self.rarp_requests,
            self.rarp_replies,
            self.other_operations,
            self.probes,
            self.gratuitous,
            self.vlan_tagged,
            self.unknown_hardware,
            self.unknown_protocol,
            self.malformed,
            self.truncated,
            self.non_arp,
            self.capture_truncated,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(ether_type: u16, payload: &[u8], vlans: &[u16]) -> Vec<u8> {
        let mut v = vec![0u8; 12];
        for (i, id) in vlans.iter().enumerate() {
            let tpid: u16 = if i + 1 == vlans.len() { 0x8100 } else { 0x88A8 };
            v.extend_from_slice(&tpid.to_be_bytes());
            v.extend_from_slice(&(id & 0x0fff).to_be_bytes());
        }
        v.extend_from_slice(&ether_type.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[allow(clippy::too_many_arguments)]
    fn body(
        htype: u16,
        ptype: u16,
        hlen: u8,
        plen: u8,
        op: u16,
        sha: &[u8],
        spa: &[u8],
        tha: &[u8],
        tpa: &[u8],
    ) -> Vec<u8> {
        assert_eq!(sha.len(), hlen as usize);
        assert_eq!(tha.len(), hlen as usize);
        assert_eq!(spa.len(), plen as usize);
        assert_eq!(tpa.len(), plen as usize);
        let mut v = Vec::new();
        v.extend_from_slice(&htype.to_be_bytes());
        v.extend_from_slice(&ptype.to_be_bytes());
        v.push(hlen);
        v.push(plen);
        v.extend_from_slice(&op.to_be_bytes());
        v.extend_from_slice(sha);
        v.extend_from_slice(spa);
        v.extend_from_slice(tha);
        v.extend_from_slice(tpa);
        v
    }

    const SHA: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const THA: [u8; 6] = [0, 0, 0, 0, 0, 0];
    const SPA: [u8; 4] = [192, 0, 2, 10];
    const TPA: [u8; 4] = [192, 0, 2, 1];

    fn request(op: u16, spa: &[u8; 4], tpa: &[u8; 4]) -> ArpFrame {
        let b = body(1, ETHERTYPE_IPV4, 6, 4, op, &SHA, spa, &THA, tpa);
        parse_ethernet(&eth(ETHERTYPE_ARP, &b, &[])).unwrap()
    }

    #[test]
    fn parses_request_with_fields() {
        let a = request(1, &SPA, &TPA);
        assert_eq!(a.hardware_type, HARDWARE_ETHERNET);
        assert_eq!(a.protocol_type, ETHERTYPE_IPV4);
        assert_eq!(a.operation, 1);
        assert_eq!(a.operation_name(), "request");
        assert_eq!(a.sender_mac(), Some(SHA));
        assert_eq!(a.target_mac(), Some(THA));
        assert_eq!(a.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(a.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(a.is_gratuitous(), Some(false));
        assert_eq!(a.is_probe(), Some(false));
        assert!(a.vlan_ids.is_empty());
    }

    #[test]
    fn parses_reply_and_vlan_stack() {
        let b = body(1, ETHERTYPE_IPV4, 6, 4, 2, &SHA, &TPA, &THA, &SPA);
        let a = parse_ethernet(&eth(ETHERTYPE_ARP, &b, &[200, 300])).unwrap();
        assert_eq!(a.vlan_ids, vec![200, 300]);
        assert_eq!(a.operation_name(), "reply");
        assert_eq!(a.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(a.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[test]
    fn detects_gratuitous_and_probe_only_for_ipv4() {
        let g = request(1, &SPA, &SPA);
        assert_eq!(g.is_gratuitous(), Some(true));
        assert_eq!(g.is_probe(), Some(false));
        let p = request(1, &[0, 0, 0, 0], &TPA);
        assert_eq!(p.is_gratuitous(), Some(false));
        assert_eq!(p.is_probe(), Some(true));
        // 应答里的 0.0.0.0 不是 probe：probe 语义只属于请求。
        let r = request(2, &[0, 0, 0, 0], &TPA);
        assert_eq!(r.is_probe(), None);
    }

    #[test]
    fn rarp_and_unknown_operations_keep_their_numbers() {
        let b = body(1, ETHERTYPE_RARP, 6, 4, 3, &SHA, &SPA, &THA, &TPA);
        let a = parse_ethernet(&eth(ETHERTYPE_RARP, &b, &[])).unwrap();
        assert_eq!(a.protocol_type_name(), "rarp");
        assert_eq!(a.operation_name(), "rarp_request");
        // RARP 的 PTYPE 不是 IPv4，不能给出 IPv4 地址。
        assert_eq!(a.sender_ipv4(), None);
        let u = request(99, &SPA, &TPA);
        assert_eq!(u.operation_name(), "unknown");
        assert_eq!(u.operation, 99);
    }

    #[test]
    fn parses_ipv6_protocol_addresses() {
        let spa = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let tpa = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let b = body(1, ETHERTYPE_IPV6, 6, 16, 1, &SHA, &spa, &THA, &tpa);
        let a = parse_ethernet(&eth(ETHERTYPE_ARP, &b, &[])).unwrap();
        assert_eq!(a.protocol_type_name(), "ipv6");
        assert_eq!(a.sender_ipv6(), Some(Ipv6Addr::from(spa)));
        assert_eq!(a.target_ipv6(), Some(Ipv6Addr::from(tpa)));
        assert_eq!(a.sender_ipv4(), None);
        assert_eq!(a.is_gratuitous(), None);
        assert_eq!(a.is_probe(), None);
    }

    #[test]
    fn unknown_hardware_and_protocol_are_preserved_not_guessed() {
        let b = body(99, 0x1234, 6, 4, 1, &SHA, &SPA, &THA, &TPA);
        let a = parse_ethernet(&eth(ETHERTYPE_ARP, &b, &[])).unwrap();
        assert_eq!(a.hardware_type_name(), "unknown");
        assert_eq!(a.protocol_type_name(), "unknown");
        assert_eq!(a.sender_hardware, SHA);
        // HTYPE 未知 ⇒ 即使长度是 6 也不叫 MAC。
        assert_eq!(a.sender_mac(), None);
        assert_eq!(a.sender_ipv4(), None);
    }

    #[test]
    fn rejects_non_arp_and_truncated_frames() {
        assert_eq!(
            parse_ethernet(&eth(ETHERTYPE_IPV4, &[0; 20], &[])).unwrap_err(),
            ArpError::NonArpEtherType {
                ether_type: ETHERTYPE_IPV4
            }
        );
        assert!(matches!(
            parse_ethernet(&[0u8; 10]).unwrap_err(),
            ArpError::TruncatedEthernet { .. }
        ));
        let short = eth(ETHERTYPE_ARP, &[0u8; 5], &[]);
        assert_eq!(
            parse_ethernet(&short).unwrap_err(),
            ArpError::TruncatedArpHeader { need: 8, got: 5 }
        );
        let b = body(1, ETHERTYPE_IPV4, 6, 4, 1, &SHA, &SPA, &THA, &TPA);
        let full = eth(ETHERTYPE_ARP, &b, &[]);
        let truncated = &full[..full.len() - 2];
        assert_eq!(
            parse_ethernet(truncated).unwrap_err(),
            ArpError::TruncatedArpBody { need: 28, got: 26 }
        );
    }

    #[test]
    fn rejects_too_many_vlan_tags_but_accepts_two() {
        let b = body(1, ETHERTYPE_IPV4, 6, 4, 1, &SHA, &SPA, &THA, &TPA);
        let f = eth(ETHERTYPE_ARP, &b, &[1, 2, 3]);
        assert_eq!(
            parse_ethernet(&f).unwrap_err(),
            ArpError::TooManyVlanTags { limit: 2 }
        );
    }

    #[test]
    fn ignores_ethernet_padding_after_the_arp_body() {
        let b = body(1, ETHERTYPE_IPV4, 6, 4, 1, &SHA, &SPA, &THA, &TPA);
        let mut f = eth(ETHERTYPE_ARP, &b, &[]);
        f.extend_from_slice(&[0u8; 18]);
        let a = parse_ethernet(&f).unwrap();
        assert_eq!(a.operation, 1);
        assert_eq!(a.sender_protocol, SPA);
    }

    #[test]
    fn stats_count_operations_anomalies_and_errors() {
        let mut st = ArpStats::default();
        st.observe(&request(1, &SPA, &TPA));
        st.observe(&request(2, &TPA, &SPA));
        st.observe(&request(1, &SPA, &SPA)); // gratuitous
        st.observe(&request(1, &[0, 0, 0, 0], &TPA)); // probe
        st.record_error(ArpError::NonArpEtherType {
            ether_type: ETHERTYPE_IPV4,
        });
        st.record_error(ArpError::TruncatedArpBody { need: 28, got: 26 });
        st.record_error(ArpError::TooManyVlanTags { limit: 2 });
        assert_eq!(st.arp_frames, 4);
        assert_eq!(st.requests, 3);
        assert_eq!(st.replies, 1);
        assert_eq!(st.gratuitous, 1);
        assert_eq!(st.probes, 1);
        assert_eq!(st.non_arp, 1);
        assert_eq!(st.truncated, 1);
        assert_eq!(st.malformed, 1);
        let line = st.render_line();
        assert!(line.contains("arp_frames=4"), "{line}");
        assert!(line.contains("requests=3"), "{line}");
        assert!(line.contains("non_arp=1"), "{line}");
    }

    #[test]
    fn json_line_is_stable_and_typed() {
        let a = request(1, &SPA, &TPA);
        let line = a.to_json_line(1_700_000_000_000_000, 7, 42);
        assert!(
            line.starts_with("{\"timestamp_us\":1700000000000000,\"frame\":7"),
            "{line}"
        );
        assert!(line.contains("\"vlan_ids\":[]"), "{line}");
        assert!(line.contains("\"operation_name\":\"request\""), "{line}");
        assert!(
            line.contains("\"sender_mac\":\"02:00:00:00:00:01\""),
            "{line}"
        );
        assert!(line.contains("\"sender_ipv4\":\"192.0.2.10\""), "{line}");
        assert!(line.contains("\"target_ipv4\":\"192.0.2.1\""), "{line}");
        assert!(line.contains("\"gratuitous\":false"), "{line}");
        assert!(line.contains("\"probe\":false"), "{line}");
        // 未知值必须是 null，而不是省略键；否则下游无法区分“没有”与“没判”。
        let b = body(1, ETHERTYPE_RARP, 6, 4, 3, &SHA, &SPA, &THA, &TPA);
        let r = parse_ethernet(&eth(ETHERTYPE_RARP, &b, &[])).unwrap();
        let line = r.to_json_line(1, 1, 42);
        assert!(line.contains("\"sender_ipv4\":null"), "{line}");
        assert!(line.contains("\"gratuitous\":null"), "{line}");
    }

    #[test]
    fn zero_length_addresses_are_bounded_and_not_invented() {
        let b = body(1, ETHERTYPE_IPV4, 0, 0, 1, &[], &[], &[], &[]);
        let a = parse_ethernet(&eth(ETHERTYPE_ARP, &b, &[])).unwrap();
        assert_eq!(a.hardware_len, 0);
        assert_eq!(a.protocol_len, 0);
        assert!(a.sender_hardware.is_empty());
        assert_eq!(a.sender_mac(), None);
        assert_eq!(a.sender_ipv4(), None);
        assert_eq!(
            a.to_json_line(0, 1, 0).contains("\"sender_hardware\":\"\""),
            true
        );
    }
}
