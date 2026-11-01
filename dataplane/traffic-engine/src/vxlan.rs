// vxlan.rs —— VXLAN 有界解析（RFC 7348）。
//
// 定位：VXLAN 是“UDP 里的以太网帧”。本模块只回答“这一段 UDP 载荷是不是一个
// 结构成立的 VXLAN 头，VNI 是多少，内层以太网头能看到什么”。它**不**把内层
// IP 重新送回流水线：一个 VXLAN 包只能证明外层隧道与可见的内层头存在，不能
// 证明内层会话、VTEP 对端或租户拓扑。
//
// 五个刻意的边界：
//
// 1. **I 位必须置位，其余基础保留位必须为 0**。RFC 7348 的 VXLAN 头只有 I 位；
//    GBP/GPE 等扩展有自己的位语义，混进基础解析会把“另一种封装”误报成 VXLAN。
// 2. **VNI 原样保留，0 单独计数**。VNI 是 24 位网络标识，不拿端口或 MAC 反推
//    租户；VNI=0 按保留值单独记账，不据此宣称隧道有效。
// 3. **内层只解析到可见的以太网/IP 头**。VLAN 最多两层（与 channel::decode
//    的上限一致）；IPv4/IPv6 只取源/目的/协议与声明长度，不重组、不建流。
// 4. **抓包截断与结构截断分开**：`capture_truncated` 是采集侧抓少了；
//    `TruncatedInner` 是完整抓包下 VXLAN 内层本来就不够一个以太头。前者不能
//    被记成畸形，后者不能伪装成成功。
// 5. **端口只做触发条件，不做身份结论**。主流水线按 4789/8472 触发；独立采集器
//    可以对任意 UDP 载荷调用解析，但只有结构成立才输出事件。

use std::fmt;
use std::net::IpAddr;

use crate::inner as inner_mod;
pub use crate::inner::{InnerEthernet as VxlanInner, InnerIp};
use crate::inner::{ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6};

/// IANA 分配的 VXLAN UDP 目的端口（RFC 7348）。
pub const UDP_PORT: u16 = 4789;
/// 早期 Linux 实现使用的 VXLAN UDP 目的端口。
pub const UDP_PORT_LEGACY: u16 = 8472;

/// VXLAN 固定头长度：flags(1) + reserved(3) + VNI(3) + reserved(1)。
pub const VXLAN_HEADER_LEN: usize = 8;

/// 是否为主流水线应当尝试 VXLAN 解析的 UDP 端口。
///
/// 端口只是触发条件，**不是**协议证据：真正的判定在 `parse*` 里按头结构完成。
pub fn is_vxlan_port(port: u16) -> bool {
    matches!(port, UDP_PORT | UDP_PORT_LEGACY)
}

/// VXLAN 头/内层以太头的结构错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VxlanError {
    /// 连 8 字节 VXLAN 固定头都不完整。
    TruncatedHeader { need: usize, got: usize },
    /// I 位没有置位；这不是 VXLAN 基础封装。
    MissingIFlag { flags: u8 },
    /// 基础保留位非零（flags 低 7 位、bytes 1..4、byte 7）。
    ReservedNonZero { offset: usize, value: u8 },
    /// 完整抓包下内层以太头不足 14 字节。
    TruncatedInner { need: usize, got: usize },
    /// 内层 VLAN 嵌套超过两层。
    TooManyVlanTags { limit: usize },
}

impl VxlanError {
    /// 稳定错误码，供统计/日志按原因聚合（文案会改，码不该改）。
    pub fn code(self) -> &'static str {
        match self {
            VxlanError::TruncatedHeader { .. } => "vxlan.truncated_header",
            VxlanError::MissingIFlag { .. } => "vxlan.missing_i_flag",
            VxlanError::ReservedNonZero { .. } => "vxlan.reserved_nonzero",
            VxlanError::TruncatedInner { .. } => "vxlan.truncated_inner",
            VxlanError::TooManyVlanTags { .. } => "vxlan.vlan_nesting",
        }
    }
}

impl fmt::Display for VxlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VxlanError::TruncatedHeader { need, got } => {
                write!(f, "VXLAN 头不完整：需要 {need} 字节，实有 {got} 字节")
            }
            VxlanError::MissingIFlag { flags } => {
                write!(f, "VXLAN I 位未置位（flags=0x{flags:02X}）")
            }
            VxlanError::ReservedNonZero { offset, value } => {
                write!(f, "VXLAN 保留位非零：偏移 {offset} 值 0x{value:02X}")
            }
            VxlanError::TruncatedInner { need, got } => {
                write!(
                    f,
                    "VXLAN 内层以太头不完整：需要 {need} 字节，实有 {got} 字节"
                )
            }
            VxlanError::TooManyVlanTags { limit } => {
                write!(f, "VXLAN 内层 VLAN 标签超过 {limit} 层")
            }
        }
    }
}

impl std::error::Error for VxlanError {}

/// 一条结构成立的 VXLAN 报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VxlanFrame {
    pub flags: u8,
    pub vni: u32,
    /// 内层以太头；抓包截断到读不出完整以太头时为 `None`。
    pub inner: Option<VxlanInner>,
    /// 因抓包截断而不能解析内层（不是结构畸形）。
    pub inner_truncated: bool,
    /// 采集侧 `orig_len > caplen`。
    pub capture_truncated: bool,
}

impl VxlanFrame {
    /// 一行稳定 JSON（字段顺序固定；未知值用 `null`，不缺席）。
    ///
    /// 字段名是 `scripts/verify/check-vxlan.py` 的契约，改名必须同批改脚本。
    pub fn to_json_line(
        &self,
        timestamp_us: u64,
        frame: u64,
        frame_len: usize,
        outer_src: IpAddr,
        outer_dst: IpAddr,
        outer_src_port: u16,
        outer_dst_port: u16,
    ) -> String {
        let (dst_mac, src_mac, vlan_ids, ether_type, ether_type_name, header_len, captured_len, ip) =
            match &self.inner {
                Some(i) => (
                    json_string_opt(Some(i.destination_mac())),
                    json_string_opt(Some(i.source_mac())),
                    i.vlan_ids
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                    i.ether_type.to_string(),
                    format!("\"{}\"", i.ether_type_name()),
                    i.header_len.to_string(),
                    i.captured_len.to_string(),
                    i.ip,
                ),
                None => (
                    "null".to_string(),
                    "null".to_string(),
                    String::new(),
                    "null".to_string(),
                    "null".to_string(),
                    "null".to_string(),
                    "null".to_string(),
                    None,
                ),
            };
        let (ip_version, ip_src, ip_dst, ip_proto, ip_declared, ip_header, ip_complete) = match ip {
            Some(i) => (
                i.version.to_string(),
                json_string_opt(i.source.map(|v| v.to_string())),
                json_string_opt(i.destination.map(|v| v.to_string())),
                json_num_opt(i.protocol.map(u64::from)),
                json_num_opt(i.declared_len.map(u64::from)),
                json_num_opt(i.header_len.map(|v| v as u64)),
                i.complete_header.to_string(),
            ),
            None => (
                "null".to_string(),
                "null".to_string(),
                "null".to_string(),
                "null".to_string(),
                "null".to_string(),
                "null".to_string(),
                "null".to_string(),
            ),
        };
        format!(
            "{{\"timestamp_us\":{timestamp_us},\"frame\":{frame},\"frame_len\":{frame_len},\
             \"capture_truncated\":{},\"outer_src\":\"{outer_src}\",\"outer_dst\":\"{outer_dst}\",\
             \"outer_src_port\":{outer_src_port},\"outer_dst_port\":{outer_dst_port},\
             \"vni\":{},\"flags\":{},\"inner_truncated\":{},\"inner_complete\":{},\
             \"inner_dst_mac\":{dst_mac},\"inner_src_mac\":{src_mac},\
             \"inner_vlan_ids\":[{vlan_ids}],\"inner_ether_type\":{ether_type},\
             \"inner_ether_type_name\":{ether_type_name},\"inner_header_len\":{header_len},\
             \"inner_captured_len\":{captured_len},\"inner_ip_version\":{ip_version},\
             \"inner_src_ip\":{ip_src},\"inner_dst_ip\":{ip_dst},\
             \"inner_ip_protocol\":{ip_proto},\"inner_ip_declared_len\":{ip_declared},\
             \"inner_ip_header_len\":{ip_header},\"inner_ip_complete\":{ip_complete}}}",
            self.capture_truncated,
            self.vni,
            self.flags,
            self.inner_truncated,
            self.inner
                .as_ref()
                .map(VxlanInner::ip_header_complete)
                .unwrap_or(false),
        )
    }
}

/// 解析一段完整的 VXLAN 载荷（要求内层以太头完整）。
pub fn parse(payload: &[u8]) -> Result<VxlanFrame, VxlanError> {
    parse_with_complete(payload, true)
}

/// 解析一段 VXLAN 载荷。
///
/// `complete=false` 表示采集侧已声明字节不齐：此时内层以太头不足只记
/// `inner_truncated`，不记结构畸形；VXLAN 固定头本身不足仍然是错误。
pub fn parse_with_complete(payload: &[u8], complete: bool) -> Result<VxlanFrame, VxlanError> {
    if payload.len() < VXLAN_HEADER_LEN {
        return Err(VxlanError::TruncatedHeader {
            need: VXLAN_HEADER_LEN,
            got: payload.len(),
        });
    }
    let flags = payload[0];
    if flags & 0x08 == 0 {
        return Err(VxlanError::MissingIFlag { flags });
    }
    if flags != 0x08 {
        return Err(VxlanError::ReservedNonZero {
            offset: 0,
            value: flags,
        });
    }
    for (offset, value) in payload.iter().enumerate().take(4).skip(1) {
        if *value != 0 {
            return Err(VxlanError::ReservedNonZero {
                offset,
                value: *value,
            });
        }
    }
    if payload[7] != 0 {
        return Err(VxlanError::ReservedNonZero {
            offset: 7,
            value: payload[7],
        });
    }
    let vni = (u32::from(payload[4]) << 16) | (u32::from(payload[5]) << 8) | u32::from(payload[6]);

    let inner = match parse_inner(&payload[VXLAN_HEADER_LEN..]) {
        Ok(inner) => Some(inner),
        Err(VxlanError::TruncatedInner { .. }) if !complete => None,
        Err(e) => return Err(e),
    };
    let inner_truncated = inner.is_none();
    Ok(VxlanFrame {
        flags,
        vni,
        inner,
        inner_truncated,
        capture_truncated: false,
    })
}

fn parse_inner(p: &[u8]) -> Result<VxlanInner, VxlanError> {
    match inner_mod::parse_ethernet(p) {
        Ok(inner) => Ok(inner),
        Err(inner_mod::InnerError::TruncatedEthernet { need, got }) => {
            Err(VxlanError::TruncatedInner { need, got })
        }
        Err(inner_mod::InnerError::TooManyVlanTags { limit }) => {
            Err(VxlanError::TooManyVlanTags { limit })
        }
    }
}

/// VXLAN 报文级统计。**没有“隧道建立/租户在线”的计数**：单包只能说明结构。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VxlanStats {
    pub vxlan_frames: u64,
    pub vni_zero: u64,
    pub vlan_tagged: u64,
    pub inner_ipv4: u64,
    pub inner_ipv6: u64,
    pub inner_arp: u64,
    pub inner_other: u64,
    pub inner_complete: u64,
    pub inner_incomplete: u64,
    pub capture_truncated: u64,
    pub truncated: u64,
    pub malformed: u64,
    pub missing_i_flag: u64,
    pub reserved_nonzero: u64,
    pub too_many_vlans: u64,
}

impl VxlanStats {
    pub fn observe(&mut self, f: &VxlanFrame) {
        self.vxlan_frames += 1;
        if f.vni == 0 {
            self.vni_zero += 1;
        }
        if let Some(inner) = &f.inner {
            if !inner.vlan_ids.is_empty() {
                self.vlan_tagged += 1;
            }
            match inner.ether_type {
                ETHERTYPE_IPV4 => self.inner_ipv4 += 1,
                ETHERTYPE_IPV6 => self.inner_ipv6 += 1,
                ETHERTYPE_ARP => self.inner_arp += 1,
                _ => self.inner_other += 1,
            }
            if inner.ip_header_complete() {
                self.inner_complete += 1;
            } else {
                self.inner_incomplete += 1;
            }
        } else {
            self.inner_incomplete += 1;
        }
        if f.inner_truncated || f.capture_truncated {
            self.capture_truncated += 1;
        }
    }

    pub fn record_error(&mut self, e: VxlanError) {
        match e {
            VxlanError::TruncatedHeader { .. } | VxlanError::TruncatedInner { .. } => {
                self.truncated += 1;
            }
            VxlanError::MissingIFlag { .. } => {
                self.malformed += 1;
                self.missing_i_flag += 1;
            }
            VxlanError::ReservedNonZero { .. } => {
                self.malformed += 1;
                self.reserved_nonzero += 1;
            }
            VxlanError::TooManyVlanTags { .. } => {
                self.malformed += 1;
                self.too_many_vlans += 1;
            }
        }
    }

    /// 统计行是关口比对的契约：字段名改了必须同时改 `check-vxlan.py`。
    pub fn render_line(&self) -> String {
        format!(
            "vxlan vxlan_frames={} vni_zero={} vlan_tagged={} inner_ipv4={} inner_ipv6={} \
             inner_arp={} inner_other={} inner_complete={} inner_incomplete={} \
             capture_truncated={} truncated={} malformed={} missing_i_flag={} \
             reserved_nonzero={} too_many_vlans={}",
            self.vxlan_frames,
            self.vni_zero,
            self.vlan_tagged,
            self.inner_ipv4,
            self.inner_ipv6,
            self.inner_arp,
            self.inner_other,
            self.inner_complete,
            self.inner_incomplete,
            self.capture_truncated,
            self.truncated,
            self.malformed,
            self.missing_i_flag,
            self.reserved_nonzero,
            self.too_many_vlans,
        )
    }
}

fn json_string_opt(v: Option<String>) -> String {
    match v {
        Some(s) => format!("\"{s}\""),
        None => "null".to_string(),
    }
}

fn json_num_opt(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

#[cfg(test)]
mod tests;
