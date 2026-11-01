// inner.rs —— 隧道内层以太网/IP 头的有界视图。
//
// VXLAN 与 Geneve 都会在隧道头之后携带“内层以太网帧”或“裸 IP”。两种封装
// 需要同一套截断语义、VLAN 上限和“不补 0 地址”的规则；把这段逻辑放在这里，
// 避免两个解析器各自解释内层头，导致同一个字节序列在两条统计行里给出不同结论。
//
// 本模块只读取可见头：不重组、不建立内层流、不推断邻居/租户/隧道对端状态。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ETH_HEADER_LEN: usize = 14;
pub const VLAN_TAG_LEN: usize = 4;
/// 与 `channel::decode` 保持一致：QinQ 是现实上限。
pub const MAX_VLAN_TAGS: usize = 2;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// 内层以太头/ VLAN 的结构错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerError {
    /// 完整抓包下内层以太头不足 14 字节。
    TruncatedEthernet { need: usize, got: usize },
    /// 内层 VLAN 嵌套超过两层。
    TooManyVlanTags { limit: usize },
}

impl InnerError {
    pub fn code(self) -> &'static str {
        match self {
            InnerError::TruncatedEthernet { .. } => "inner.truncated_ethernet",
            InnerError::TooManyVlanTags { .. } => "inner.vlan_nesting",
        }
    }
}

impl std::fmt::Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerError::TruncatedEthernet { need, got } => {
                write!(f, "内层以太头不完整：需要 {need} 字节，实有 {got} 字节")
            }
            InnerError::TooManyVlanTags { limit } => {
                write!(f, "内层 VLAN 标签超过 {limit} 层")
            }
        }
    }
}

impl std::error::Error for InnerError {}

/// 内层 IPv4/IPv6 头的可见部分。
///
/// 地址只在版本/长度自洽时给出；否则为 `None`，**不拿 0.0.0.0/:: 兜底**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InnerIp {
    pub version: u8,
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub protocol: Option<u8>,
    /// IPv4 total length 或 IPv6 40 + payload length；只按已捕获头字段读。
    pub declared_len: Option<u16>,
    /// IPv4 IHL 或 IPv6 固定 40。
    pub header_len: Option<usize>,
    /// 版本、头长与最小头字节都自洽。
    pub complete_header: bool,
}

/// 内层以太网帧的可见头。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerEthernet {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    /// 从外到内的 VLAN ID（最多两层）。空表示未打标。
    pub vlan_ids: Vec<u16>,
    pub ether_type: u16,
    /// 从内层以太头起点到内层载荷起点的字节数（含 VLAN 标签）。
    pub header_len: usize,
    /// 内层载荷实际捕获到的字节数。
    pub captured_len: usize,
    pub ip: Option<InnerIp>,
}

impl InnerEthernet {
    pub fn destination_mac(&self) -> String {
        format_mac(self.destination)
    }

    pub fn source_mac(&self) -> String {
        format_mac(self.source)
    }

    pub fn ether_type_name(&self) -> &'static str {
        ether_type_name(self.ether_type)
    }

    /// 内层 IP 头是否完整；非 IP 内层只要以太头成立就算完整。
    pub fn ip_header_complete(&self) -> bool {
        match &self.ip {
            Some(ip) => ip.complete_header,
            None => true,
        }
    }
}

pub fn ether_type_name(ether_type: u16) -> &'static str {
    match ether_type {
        ETHERTYPE_IPV4 => "ipv4",
        ETHERTYPE_IPV6 => "ipv6",
        ETHERTYPE_ARP => "arp",
        _ => "unknown",
    }
}

pub fn is_vlan(ether_type: u16) -> bool {
    matches!(ether_type, 0x8100 | 0x88A8 | 0x9100)
}

/// 解析隧道内层的以太网头。`p` 从内层目的 MAC 开始。
pub fn parse_ethernet(p: &[u8]) -> Result<InnerEthernet, InnerError> {
    if p.len() < ETH_HEADER_LEN {
        return Err(InnerError::TruncatedEthernet {
            need: ETH_HEADER_LEN,
            got: p.len(),
        });
    }
    let mut destination = [0u8; 6];
    destination.copy_from_slice(&p[0..6]);
    let mut source = [0u8; 6];
    source.copy_from_slice(&p[6..12]);

    let mut cursor = 12usize; // 当前 EtherType 字段的偏移
    let mut ether_type = be16(p, cursor);
    let mut vlan_ids = Vec::new();
    while is_vlan(ether_type) {
        if vlan_ids.len() >= MAX_VLAN_TAGS {
            return Err(InnerError::TooManyVlanTags {
                limit: MAX_VLAN_TAGS,
            });
        }
        // TPID(2) + TCI(2) + 内层 EtherType(2)
        let need = cursor + 6;
        if p.len() < need {
            return Err(InnerError::TruncatedEthernet { need, got: p.len() });
        }
        vlan_ids.push(be16(p, cursor + 2) & 0x0fff);
        ether_type = be16(p, cursor + 4);
        cursor += VLAN_TAG_LEN;
    }
    let header_len = cursor + 2;
    let payload = p.get(header_len..).unwrap_or(&[]);
    let ip = parse_ip_for_ether_type(ether_type, payload);
    Ok(InnerEthernet {
        destination,
        source,
        vlan_ids,
        ether_type,
        header_len,
        captured_len: payload.len(),
        ip,
    })
}

/// 按 EtherType 解析可见内层 IP；非 IPv4/IPv6 返回 `None`。
pub fn parse_ip_for_ether_type(ether_type: u16, p: &[u8]) -> Option<InnerIp> {
    match ether_type {
        ETHERTYPE_IPV4 => Some(parse_ipv4(p)),
        ETHERTYPE_IPV6 => Some(parse_ipv6(p)),
        _ => None,
    }
}

pub fn parse_ipv4(p: &[u8]) -> InnerIp {
    let version = p.first().map(|b| b >> 4).unwrap_or(0);
    if p.len() < 20 || version != 4 {
        return InnerIp {
            version,
            source: None,
            destination: None,
            protocol: None,
            declared_len: None,
            header_len: None,
            complete_header: false,
        };
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let total = be16(p, 2);
    if ihl < 20 || usize::from(total) < ihl || p.len() < ihl {
        return InnerIp {
            version,
            source: None,
            destination: None,
            protocol: None,
            declared_len: Some(total),
            header_len: Some(ihl),
            complete_header: false,
        };
    }
    let mut src = [0u8; 4];
    src.copy_from_slice(&p[12..16]);
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&p[16..20]);
    InnerIp {
        version,
        source: Some(IpAddr::V4(Ipv4Addr::from(src))),
        destination: Some(IpAddr::V4(Ipv4Addr::from(dst))),
        protocol: Some(p[9]),
        declared_len: Some(total),
        header_len: Some(ihl),
        complete_header: true,
    }
}

pub fn parse_ipv6(p: &[u8]) -> InnerIp {
    let version = p.first().map(|b| b >> 4).unwrap_or(0);
    if p.len() < 40 || version != 6 {
        return InnerIp {
            version,
            source: None,
            destination: None,
            protocol: None,
            declared_len: None,
            header_len: None,
            complete_header: false,
        };
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&p[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&p[24..40]);
    let payload_len = be16(p, 4);
    InnerIp {
        version,
        source: Some(IpAddr::V6(Ipv6Addr::from(src))),
        destination: Some(IpAddr::V6(Ipv6Addr::from(dst))),
        protocol: Some(p[6]),
        declared_len: Some(40u16.saturating_add(payload_len)),
        header_len: Some(40),
        complete_header: true,
    }
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
