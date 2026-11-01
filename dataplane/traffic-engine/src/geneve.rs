// geneve.rs —— Geneve 有界解析（RFC 8926）。
//
// 定位与 VXLAN 相同：只回答“这段 UDP 载荷是不是结构成立的 Geneve 头，VNI 是多少，
// 可见内层头是什么”。基因不同之处在于 Geneve 有可变长选项、裸 IP 载荷、控制位 O
// 和关键位 C；这些差异不能用 VXLAN 的固定 8 字节头直接套。
//
// 四条刻意写死的边界：
//
// 1. **只接受 version 0**。未知版本按 RFC 8926 交给“未知 UDP 载荷”，不猜字段。
// 2. **选项按 4 字节单位有界遍历**。Opt Len 最大 63，总头最长 260 字节；每个选项的
//    长度必须落在 Opt Len 内，不读越过头部。选项内容只保留 class/type/关键位/数据长度，
//    不解释厂商语义，也不因未知关键选项替调用方做丢弃决定。
// 3. **O=1 是控制报文**。RFC 要求中转设备不得解释其载荷；这里只记录 O/C、VNI 和选项，
//    `inner` 留空，不把控制载荷伪装成可解码的以太网/IP。
// 4. **保留位按 RFC“收到时忽略”**。非零保留位不判畸形，只记 `reserved_nonzero`；
//    version、选项越界、C 位与关键选项不一致等结构矛盾仍然显式拒绝。

use std::fmt;
use std::net::IpAddr;

use crate::inner as inner_mod;
use crate::inner::{InnerEthernet, InnerIp, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6};

/// IANA 分配的 Geneve UDP 目的端口（RFC 8926）。
pub const UDP_PORT: u16 = 6081;
/// Geneve 固定头：ver/optlen(2) + flags(1) + protocol type(2) + VNI(3) + reserved(1)。
pub const GENEVE_HEADER_LEN: usize = 8;
/// Opt Len 为 6 位，单位 4 字节；最大选项区 252 字节，总头 260 字节。
pub const MAX_HEADER_LEN: usize = GENEVE_HEADER_LEN + 63 * 4;

const ETHERTYPE_TEB: u16 = 0x6558;
const O_BIT: u8 = 0x80;
const C_BIT: u8 = 0x40;
const OPTION_CRITICAL: u8 = 0x80;
const OPTION_LENGTH_MASK: u8 = 0x1f;
const OPTION_RESERVED_MASK: u8 = 0xe0;

/// 是否为主流水线应当尝试 Geneve 解析的 UDP 端口。
///
/// 端口只是触发条件，**不是**协议证据：真正的判定在 `parse*` 里按头结构完成。
pub fn is_geneve_port(port: u16) -> bool {
    port == UDP_PORT
}

/// Geneve 头/选项/内层的结构错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneveError {
    /// 连 8 字节固定头都不完整。
    TruncatedHeader { need: usize, got: usize },
    /// version != 0；按未知 UDP 载荷处理，不猜字段。
    UnsupportedVersion { version: u8 },
    /// Opt Len 声明的选项区超过已捕获字节。
    TruncatedOptions { need: usize, got: usize },
    /// 选项自身长度越过 Opt Len 边界。
    OptionOverrun {
        offset: usize,
        length: usize,
        header_len: usize,
    },
    /// C 位与任一选项的关键位不一致。
    CriticalMismatch { c_bit: bool, option_critical: bool },
    /// 完整抓包下内层载荷不足该协议的最小头。
    TruncatedInner {
        need: usize,
        got: usize,
        protocol_type: u16,
    },
    /// 内层 VLAN 嵌套超过两层。
    TooManyVlanTags { limit: usize },
}

impl GeneveError {
    pub fn code(self) -> &'static str {
        match self {
            GeneveError::TruncatedHeader { .. } => "geneve.truncated_header",
            GeneveError::UnsupportedVersion { .. } => "geneve.unsupported_version",
            GeneveError::TruncatedOptions { .. } => "geneve.truncated_options",
            GeneveError::OptionOverrun { .. } => "geneve.option_overrun",
            GeneveError::CriticalMismatch { .. } => "geneve.critical_mismatch",
            GeneveError::TruncatedInner { .. } => "geneve.truncated_inner",
            GeneveError::TooManyVlanTags { .. } => "geneve.vlan_nesting",
        }
    }
}

impl fmt::Display for GeneveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeneveError::TruncatedHeader { need, got } => {
                write!(f, "Geneve 头不完整：需要 {need} 字节，实有 {got} 字节")
            }
            GeneveError::UnsupportedVersion { version } => {
                write!(f, "Geneve version {version} 不受支持")
            }
            GeneveError::TruncatedOptions { need, got } => {
                write!(f, "Geneve 选项区不完整：需要 {need} 字节，实有 {got} 字节")
            }
            GeneveError::OptionOverrun {
                offset,
                length,
                header_len,
            } => write!(
                f,
                "Geneve 选项越界：偏移 {offset} 长度 {length}，选项区止于 {header_len}"
            ),
            GeneveError::CriticalMismatch {
                c_bit,
                option_critical,
            } => write!(
                f,
                "Geneve C 位={c_bit} 与选项关键位={option_critical} 不一致"
            ),
            GeneveError::TruncatedInner {
                need,
                got,
                protocol_type,
            } => write!(
                f,
                "Geneve 内层载荷不完整：protocol type 0x{protocol_type:04X} 需要 {need} 字节，实有 {got} 字节"
            ),
            GeneveError::TooManyVlanTags { limit } => {
                write!(f, "Geneve 内层 VLAN 标签超过 {limit} 层")
            }
        }
    }
}

impl std::error::Error for GeneveError {}

/// 一个可见的 Geneve 选项头。**不保存选项数据**，避免把厂商私有载荷带进事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneveOption {
    pub class: u16,
    pub type_: u8,
    pub critical: bool,
    /// 选项长度字段的高 3 位；RFC 要求发送时置 0、接收时忽略。
    pub reserved: u8,
    /// 选项数据长度（字节，不含 4 字节选项头）。
    pub data_len: usize,
}

/// Geneve 内层的可见部分。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneveInner {
    /// Protocol Type=0x6558：透明以太网桥接。
    Ethernet(InnerEthernet),
    /// Protocol Type=0x0800/0x86DD：裸 IP。
    Ip { ip: InnerIp, captured_len: usize },
}

/// 一条结构成立的 Geneve 报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneveFrame {
    pub version: u8,
    pub opt_len: u8,
    pub flags: u8,
    pub control: bool,
    pub critical: bool,
    pub protocol_type: u16,
    pub vni: u32,
    /// 基础头或任一选项的保留位非零；按 RFC 忽略，不判畸形。
    pub reserved_nonzero: bool,
    pub options: Vec<GeneveOption>,
    /// 抓包截断到不足以覆盖 Opt Len 声明的选项区。
    pub options_truncated: bool,
    /// 可解析的内层视图；控制报文、未知 protocol type 或抓包截断时为 None。
    pub inner: Option<GeneveInner>,
    /// 抓包截断导致内层头不完整（不是结构畸形）。
    pub inner_truncated: bool,
    /// 采集侧 `orig_len > caplen`。
    pub capture_truncated: bool,
}

impl GeneveFrame {
    pub fn protocol_type_name(&self) -> &'static str {
        match self.protocol_type {
            ETHERTYPE_TEB => "ethernet",
            ETHERTYPE_IPV4 => "ipv4",
            ETHERTYPE_IPV6 => "ipv6",
            _ => "unknown",
        }
    }

    pub fn inner_kind(&self) -> &'static str {
        if self.control {
            "control"
        } else if self.options_truncated {
            "options_truncated"
        } else if self.inner_truncated {
            "truncated"
        } else {
            match &self.inner {
                Some(GeneveInner::Ethernet(_)) => "ethernet",
                Some(GeneveInner::Ip { ip, .. }) => match ip.version {
                    4 => "ipv4",
                    6 => "ipv6",
                    _ => "other",
                },
                None => "other",
            }
        }
    }

    /// 内层 IP 头是否完整；控制/未知/截断时为 `None`（不冒充成功或失败）。
    pub fn inner_complete(&self) -> Option<bool> {
        if self.control || self.options_truncated {
            return None;
        }
        match &self.inner {
            Some(GeneveInner::Ethernet(e)) => Some(e.ip_header_complete()),
            Some(GeneveInner::Ip { ip, .. }) => Some(ip.complete_header),
            None => None,
        }
    }

    #[cfg(test)]
    fn inner_ethernet(&self) -> Option<&InnerEthernet> {
        match &self.inner {
            Some(GeneveInner::Ethernet(e)) => Some(e),
            _ => None,
        }
    }

    fn inner_ip(&self) -> Option<&InnerIp> {
        match &self.inner {
            Some(GeneveInner::Ethernet(e)) => e.ip.as_ref(),
            Some(GeneveInner::Ip { ip, .. }) => Some(ip),
            None => None,
        }
    }

    /// 一行稳定 JSON（字段顺序固定；未知值用 `null`，不缺席）。
    ///
    /// 字段名是 `scripts/verify/check-geneve.py` 的契约，改名必须同批改脚本。
    #[allow(clippy::too_many_arguments)]
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
        let options = self
            .options
            .iter()
            .map(|o| {
                format!(
                    "{{\"class\":{},\"type\":{},\"critical\":{},\"data_len\":{}}}",
                    o.class, o.type_, o.critical, o.data_len
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        let ip = self.inner_ip();
        let (inner_dst_mac, inner_src_mac, inner_vlan_ids, inner_ether_type, inner_eth_name) =
            match &self.inner {
                Some(GeneveInner::Ethernet(e)) => (
                    json_string(Some(e.destination_mac())),
                    json_string(Some(e.source_mac())),
                    e.vlan_ids
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                    e.ether_type.to_string(),
                    json_string(Some(e.ether_type_name().to_string())),
                ),
                Some(GeneveInner::Ip { .. }) => (
                    "null".to_string(),
                    "null".to_string(),
                    String::new(),
                    self.protocol_type.to_string(),
                    json_string(Some(self.protocol_type_name().to_string())),
                ),
                None => (
                    "null".to_string(),
                    "null".to_string(),
                    String::new(),
                    "null".to_string(),
                    "null".to_string(),
                ),
            };
        let (inner_header_len, inner_captured_len) = match &self.inner {
            Some(GeneveInner::Ethernet(e)) => {
                (e.header_len.to_string(), e.captured_len.to_string())
            }
            Some(GeneveInner::Ip { ip, captured_len }) => (
                json_num_opt(ip.header_len.map(|v| v as u64)),
                captured_len.to_string(),
            ),
            None => ("null".to_string(), "null".to_string()),
        };
        let (ip_version, ip_src, ip_dst, ip_proto, ip_declared, ip_header, ip_complete) = match ip {
            Some(i) => (
                i.version.to_string(),
                json_string(i.source.map(|v| v.to_string())),
                json_string(i.destination.map(|v| v.to_string())),
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
        let inner_complete = json_bool_opt(self.inner_complete());
        format!(
            "{{\"timestamp_us\":{timestamp_us},\"frame\":{frame},\"frame_len\":{frame_len},\
             \"capture_truncated\":{},\"outer_src\":\"{outer_src}\",\"outer_dst\":\"{outer_dst}\",\
             \"outer_src_port\":{outer_src_port},\"outer_dst_port\":{outer_dst_port},\
             \"version\":{},\"opt_len\":{},\"header_len\":{},\"flags\":{},\"control\":{},\
             \"critical\":{},\"protocol_type\":{},\"protocol_type_name\":\"{}\",\"vni\":{},\
             \"reserved_nonzero\":{},\"options\":[{options}],\"options_truncated\":{},\
             \"inner_kind\":\"{}\",\"inner_truncated\":{},\"inner_complete\":{inner_complete},\
             \"inner_dst_mac\":{inner_dst_mac},\"inner_src_mac\":{inner_src_mac},\
             \"inner_vlan_ids\":[{inner_vlan_ids}],\"inner_ether_type\":{inner_ether_type},\
             \"inner_ether_type_name\":{inner_eth_name},\"inner_header_len\":{inner_header_len},\
             \"inner_captured_len\":{inner_captured_len},\"inner_ip_version\":{ip_version},\
             \"inner_src_ip\":{ip_src},\"inner_dst_ip\":{ip_dst},\
             \"inner_ip_protocol\":{ip_proto},\"inner_ip_declared_len\":{ip_declared},\
             \"inner_ip_header_len\":{ip_header},\"inner_ip_complete\":{ip_complete}}}",
            self.capture_truncated,
            self.version,
            self.opt_len,
            GENEVE_HEADER_LEN + usize::from(self.opt_len) * 4,
            self.flags,
            self.control,
            self.critical,
            self.protocol_type,
            self.protocol_type_name(),
            self.vni,
            self.reserved_nonzero,
            self.options_truncated,
            self.inner_kind(),
            self.inner_truncated,
        )
    }
}

/// 解析一段完整的 Geneve 载荷（要求选项区与内层头完整）。
pub fn parse(payload: &[u8]) -> Result<GeneveFrame, GeneveError> {
    parse_with_complete(payload, true)
}

/// 解析一段 Geneve 载荷。
///
/// `complete=false` 表示采集侧已声明字节不齐：选项区或内层头不足只记
/// `options_truncated`/`inner_truncated`，不记结构畸形；固定头/版本仍按结构校验。
pub fn parse_with_complete(payload: &[u8], complete: bool) -> Result<GeneveFrame, GeneveError> {
    if payload.len() < GENEVE_HEADER_LEN {
        return Err(GeneveError::TruncatedHeader {
            need: GENEVE_HEADER_LEN,
            got: payload.len(),
        });
    }
    let version = payload[0] >> 6;
    if version != 0 {
        return Err(GeneveError::UnsupportedVersion { version });
    }
    let opt_len = payload[0] & 0x3f;
    let header_len = GENEVE_HEADER_LEN + usize::from(opt_len) * 4;
    if header_len > MAX_HEADER_LEN {
        // opt_len 是 6 位，这里只为常量约束保留；正常不可达。
        return Err(GeneveError::TruncatedOptions {
            need: header_len,
            got: payload.len(),
        });
    }
    let flags = payload[1];
    let control = flags & O_BIT != 0;
    let critical = flags & C_BIT != 0;
    let mut reserved_nonzero = flags & !(O_BIT | C_BIT) != 0 || payload[7] != 0;
    let protocol_type = be16(payload, 2);
    let vni = (u32::from(payload[4]) << 16) | (u32::from(payload[5]) << 8) | u32::from(payload[6]);

    if payload.len() < header_len {
        if complete {
            return Err(GeneveError::TruncatedOptions {
                need: header_len,
                got: payload.len(),
            });
        }
        return Ok(GeneveFrame {
            version,
            opt_len,
            flags,
            control,
            critical,
            protocol_type,
            vni,
            reserved_nonzero,
            options: Vec::new(),
            options_truncated: true,
            inner: None,
            inner_truncated: false,
            capture_truncated: false,
        });
    }

    let mut options = Vec::new();
    let mut saw_critical = false;
    let mut off = GENEVE_HEADER_LEN;
    while off < header_len {
        if off + 4 > header_len {
            return Err(GeneveError::TruncatedOptions {
                need: header_len,
                got: off + 4,
            });
        }
        let class = be16(payload, off);
        let type_ = payload[off + 2];
        let len_byte = payload[off + 3];
        let reserved = len_byte & OPTION_RESERVED_MASK;
        if reserved != 0 {
            reserved_nonzero = true;
        }
        let option_critical = type_ & OPTION_CRITICAL != 0;
        saw_critical |= option_critical;
        let data_len = usize::from(len_byte & OPTION_LENGTH_MASK) * 4;
        let end = off + 4 + data_len;
        if end > header_len {
            return Err(GeneveError::OptionOverrun {
                offset: off,
                length: data_len,
                header_len,
            });
        }
        options.push(GeneveOption {
            class,
            type_,
            critical: option_critical,
            reserved,
            data_len,
        });
        off = end;
    }
    if saw_critical != critical {
        return Err(GeneveError::CriticalMismatch {
            c_bit: critical,
            option_critical: saw_critical,
        });
    }

    if control {
        return Ok(GeneveFrame {
            version,
            opt_len,
            flags,
            control,
            critical,
            protocol_type,
            vni,
            reserved_nonzero,
            options,
            options_truncated: false,
            inner: None,
            inner_truncated: false,
            capture_truncated: false,
        });
    }

    let body = &payload[header_len..];
    let (inner, inner_truncated) = match protocol_type {
        ETHERTYPE_TEB => match inner_mod::parse_ethernet(body) {
            Ok(e) => (Some(GeneveInner::Ethernet(e)), false),
            Err(inner_mod::InnerError::TruncatedEthernet { .. }) if !complete => (None, true),
            Err(inner_mod::InnerError::TruncatedEthernet { need, got }) => {
                return Err(GeneveError::TruncatedInner {
                    need,
                    got,
                    protocol_type,
                })
            }
            Err(inner_mod::InnerError::TooManyVlanTags { limit }) => {
                return Err(GeneveError::TooManyVlanTags { limit })
            }
        },
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
            if body.is_empty() {
                if complete {
                    return Err(GeneveError::TruncatedInner {
                        need: 1,
                        got: 0,
                        protocol_type,
                    });
                }
                (None, true)
            } else {
                let ip = if protocol_type == ETHERTYPE_IPV4 {
                    inner_mod::parse_ipv4(body)
                } else {
                    inner_mod::parse_ipv6(body)
                };
                (
                    Some(GeneveInner::Ip {
                        ip,
                        captured_len: body.len(),
                    }),
                    false,
                )
            }
        }
        _ => (None, false),
    };

    Ok(GeneveFrame {
        version,
        opt_len,
        flags,
        control,
        critical,
        protocol_type,
        vni,
        reserved_nonzero,
        options,
        options_truncated: false,
        inner,
        inner_truncated,
        capture_truncated: false,
    })
}

/// Geneve 报文级统计。**没有“隧道建立/租户在线”的计数**：单包只能说明结构。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GeneveStats {
    pub geneve_frames: u64,
    pub vni_zero: u64,
    pub control: u64,
    pub critical: u64,
    pub options: u64,
    pub options_critical: u64,
    pub inner_ethernet: u64,
    pub inner_ipv4: u64,
    pub inner_ipv6: u64,
    pub inner_arp: u64,
    pub inner_other: u64,
    pub inner_complete: u64,
    pub inner_incomplete: u64,
    pub capture_truncated: u64,
    pub options_truncated: u64,
    pub truncated: u64,
    pub malformed: u64,
    pub unsupported_version: u64,
    pub critical_mismatch: u64,
    pub option_overrun: u64,
    pub too_many_vlans: u64,
    pub reserved_nonzero: u64,
}

impl GeneveStats {
    pub fn observe(&mut self, f: &GeneveFrame) {
        self.geneve_frames += 1;
        if f.vni == 0 {
            self.vni_zero += 1;
        }
        if f.control {
            self.control += 1;
        }
        if f.critical {
            self.critical += 1;
        }
        self.options += f.options.len() as u64;
        self.options_critical += f.options.iter().filter(|o| o.critical).count() as u64;
        if f.reserved_nonzero {
            self.reserved_nonzero += 1;
        }
        if f.options_truncated {
            self.options_truncated += 1;
        }
        if let Some(inner) = &f.inner {
            match inner {
                GeneveInner::Ethernet(e) => {
                    self.inner_ethernet += 1;
                    match e.ether_type {
                        ETHERTYPE_IPV4 => self.inner_ipv4 += 1,
                        ETHERTYPE_IPV6 => self.inner_ipv6 += 1,
                        ETHERTYPE_ARP => self.inner_arp += 1,
                        _ => self.inner_other += 1,
                    }
                    if e.ip_header_complete() {
                        self.inner_complete += 1;
                    } else {
                        self.inner_incomplete += 1;
                    }
                }
                GeneveInner::Ip { ip, .. } => {
                    match f.protocol_type {
                        ETHERTYPE_IPV4 => self.inner_ipv4 += 1,
                        ETHERTYPE_IPV6 => self.inner_ipv6 += 1,
                        _ => self.inner_other += 1,
                    }
                    if ip.complete_header {
                        self.inner_complete += 1;
                    } else {
                        self.inner_incomplete += 1;
                    }
                }
            }
        } else if !f.control && !f.options_truncated {
            if f.inner_truncated {
                self.inner_incomplete += 1;
            } else {
                self.inner_other += 1;
            }
        }
        if f.inner_truncated || f.options_truncated || f.capture_truncated {
            self.capture_truncated += 1;
        }
    }

    pub fn record_error(&mut self, e: GeneveError) {
        match e {
            GeneveError::TruncatedHeader { .. }
            | GeneveError::TruncatedOptions { .. }
            | GeneveError::TruncatedInner { .. } => self.truncated += 1,
            GeneveError::UnsupportedVersion { .. } => {
                self.malformed += 1;
                self.unsupported_version += 1;
            }
            GeneveError::OptionOverrun { .. } => {
                self.malformed += 1;
                self.option_overrun += 1;
            }
            GeneveError::CriticalMismatch { .. } => {
                self.malformed += 1;
                self.critical_mismatch += 1;
            }
            GeneveError::TooManyVlanTags { .. } => {
                self.malformed += 1;
                self.too_many_vlans += 1;
            }
        }
    }

    /// 统计行是关口比对的契约：字段名改了必须同时改 `check-geneve.py`。
    pub fn render_line(&self) -> String {
        format!(
            "geneve geneve_frames={} vni_zero={} control={} critical={} options={} \
             options_critical={} inner_ethernet={} inner_ipv4={} inner_ipv6={} inner_arp={} \
             inner_other={} inner_complete={} inner_incomplete={} capture_truncated={} \
             options_truncated={} truncated={} malformed={} unsupported_version={} \
             critical_mismatch={} option_overrun={} too_many_vlans={} reserved_nonzero={}",
            self.geneve_frames,
            self.vni_zero,
            self.control,
            self.critical,
            self.options,
            self.options_critical,
            self.inner_ethernet,
            self.inner_ipv4,
            self.inner_ipv6,
            self.inner_arp,
            self.inner_other,
            self.inner_complete,
            self.inner_incomplete,
            self.capture_truncated,
            self.options_truncated,
            self.truncated,
            self.malformed,
            self.unsupported_version,
            self.critical_mismatch,
            self.option_overrun,
            self.too_many_vlans,
            self.reserved_nonzero,
        )
    }
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn json_string(v: Option<String>) -> String {
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

fn json_bool_opt(v: Option<bool>) -> String {
    match v {
        Some(b) => b.to_string(),
        None => "null".to_string(),
    }
}

#[cfg(test)]
mod tests;
