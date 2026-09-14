// channel/decode.rs —— 以太帧 → 五元组解码（CYS-PKT-024 的下游第一步）。
//
// 定位：把消费端取到的裸帧变成 `flow::FlowKey`，从而接入既有 Packet → Flow → Session 数据链。
// 本文件只做「无状态的一帧解码」，不维护任何流表——流表属于上层。
//
// 三条刻意的设计决定，每一条都对应一类「静默错读」：
//
// 1. **解不出来就报错，绝不兜底成端口 0**。分片非首片、ESP 负载、截断捕获都拿不到四层头。
//    若一律退化成 `(0, 0)`，所有这些帧会塌缩进同一个假流，看上去只是「有一条奇怪的流」，
//    而真实的流统计已经悄悄错了。故 `DecodeError` 逐情形给码，让调用方能按原因计数。
//
// 2. **不校验校验和**。IPv4 头校验和与 TCP/UDP 校验和在大量抓包环境下因校验和卸载
//    （checksum offload）而**本来就是错的**——宿主发出的包在网卡里才算校验和。若在此处
//    校验，会把大量正常流量判为损坏。校验和属于「抓包点配置是否正确」的问题，
//    应在采集环节而非解码环节发现。
//
// 3. **解码只看字节，不看 `PacketMeta.flags`**。flags 是生产端给的元数据，字节才是事实。
//    让解码依赖元数据，等于把「生产端标错」这类缺陷变成解码器的一部分。需要交叉验证
//    标记时由调用方显式比对（`frame_has_vlan_tag` 就是为此准备的）。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::flow::FlowKey;

/// 以太网头部长度（不含 VLAN 标签）。
const ETH_HEADER_LEN: usize = 14;
/// 单个 802.1Q 标签的长度：2 字节 TCI + 2 字节内层 EtherType。
const VLAN_TAG_LEN: usize = 4;
/// 支持的最大 VLAN 标签层数。QinQ（0x88A8 外 + 0x8100 内）是现实上限，
/// 再多的嵌套在实际网络中不存在，多出来的一定是解析走错了位置。
const MAX_VLAN_TAGS: u8 = 2;

/// EtherType。
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// 802.1Q / 802.1ad / 部分厂商的私有 VLAN EtherType。
const ETHERTYPE_VLAN: [u16; 3] = [0x8100, 0x88A8, 0x9100];

/// IPv4 协议号。
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;
/// ESP：负载整体加密，四层头不可见。
const IPPROTO_ESP: u8 = 50;
/// AH：认证头，本身不加密，走完它仍能看到四层头。
const IPPROTO_AH: u8 = 51;
/// IPv6 分片头。
const IPPROTO_FRAGMENT: u8 = 44;

/// IPv6 扩展头遍历的步数上限。
///
/// 扩展头是可串联的，恶意或损坏的报文可以构造出无限链。上限的作用是让「解析不收敛」
/// 表现为一个明确的错误码，而不是一次挂起或越界读。
const MAX_IPV6_EXT_HEADERS: u8 = 8;

/// 三层协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L3Proto {
    Ipv4,
    Ipv6,
}

impl L3Proto {
    /// 括号内的取值与 `PacketMeta.is_ipv6()` 的判定一致，供调用方做交叉校验。
    pub fn is_ipv6(self) -> bool {
        self == L3Proto::Ipv6
    }

    pub fn as_str(self) -> &'static str {
        match self {
            L3Proto::Ipv4 => "ipv4",
            L3Proto::Ipv6 => "ipv6",
        }
    }
}

/// 四层协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    /// 其余协议：五元组仍成立（协议号已区分），只是端口无意义。
    Other(u8),
}

impl L4Proto {
    pub const fn from_u8(v: u8) -> Self {
        match v {
            IPPROTO_TCP => L4Proto::Tcp,
            IPPROTO_UDP => L4Proto::Udp,
            IPPROTO_ICMP => L4Proto::Icmp,
            IPPROTO_ICMPV6 => L4Proto::Icmpv6,
            other => L4Proto::Other(other),
        }
    }

    /// 协议号，即 `FlowKey.proto` 的取值。
    pub const fn number(self) -> u8 {
        match self {
            L4Proto::Tcp => IPPROTO_TCP,
            L4Proto::Udp => IPPROTO_UDP,
            L4Proto::Icmp => IPPROTO_ICMP,
            L4Proto::Icmpv6 => IPPROTO_ICMPV6,
            L4Proto::Other(v) => v,
        }
    }

    /// 该协议的头里是否有端口字段。
    ///
    /// ICMP 与「其余协议」没有端口概念，其 `FlowKey` 端口恒为 0。这不是兜底，
    /// 而是这类协议的流本来就只由地址与协议号标识。
    pub const fn has_ports(self) -> bool {
        matches!(self, L4Proto::Tcp | L4Proto::Udp)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            L4Proto::Tcp => "tcp",
            L4Proto::Udp => "udp",
            L4Proto::Icmp => "icmp",
            L4Proto::Icmpv6 => "icmpv6",
            L4Proto::Other(_) => "other",
        }
    }
}

/// 解码失败的具体位置，用于把「帧太短」这类模糊描述落到具体一步。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeStage {
    Ethernet,
    Vlan,
    Ip,
    Ipv6Extension,
    L4,
}

impl DecodeStage {
    pub fn as_str(self) -> &'static str {
        match self {
            DecodeStage::Ethernet => "ethernet",
            DecodeStage::Vlan => "vlan",
            DecodeStage::Ip => "ip",
            DecodeStage::Ipv6Extension => "ipv6-ext",
            DecodeStage::L4 => "l4",
        }
    }
}

/// 解码失败原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// 帧短于该阶段所需的最小长度。截断捕获（`caplen` < `wirelen`）常触发此错。
    Truncated {
        stage: DecodeStage,
        need: usize,
        got: usize,
    },
    /// EtherType 非 IP（ARP、LLDP、STP 等）。
    NonIpEtherType { ether_type: u16 },
    /// IP 版本字段既非 4 也非 6。
    UnsupportedIpVersion { version: u8 },
    /// IPv4 头长度字段（IHL）小于 5，即不足 20 字节，与版本字段矛盾。
    Ipv4BadHeaderLength { ihl_bytes: usize },
    /// 分片且偏移非 0：该片不含四层头。
    NonInitialFragment { offset_units: u16 },
    /// IPv6 扩展头层数超过上限。
    Ipv6TooManyExtensions { limit: u8 },
    /// IPv6 遇到不打算支持的扩展头（如 ESP，其负载加密）。
    UnsupportedIpv6NextHeader { next_header: u8 },
    /// VLAN 标签嵌套超过上限。
    TooManyVlanTags { limit: u8 },
}

impl DecodeError {
    /// 稳定错误码，供统计与日志按原因聚合（文案会改，码不该改）。
    pub fn code(&self) -> &'static str {
        match self {
            DecodeError::Truncated { .. } => "decode.truncated",
            DecodeError::NonIpEtherType { .. } => "decode.non_ip",
            DecodeError::UnsupportedIpVersion { .. } => "decode.bad_ip_version",
            DecodeError::Ipv4BadHeaderLength { .. } => "decode.bad_ipv4_ihl",
            DecodeError::NonInitialFragment { .. } => "decode.non_initial_fragment",
            DecodeError::Ipv6TooManyExtensions { .. } => "decode.ipv6_ext_limit",
            DecodeError::UnsupportedIpv6NextHeader { .. } => "decode.ipv6_unsupported_nh",
            DecodeError::TooManyVlanTags { .. } => "decode.vlan_nesting",
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated { stage, need, got } => write!(
                f,
                "帧在 {} 阶段被截断：需要 {need} 字节，实有 {got} 字节\
                 （截断捕获下这是预期现象，可按需调大 --slot-size 或采集侧 snaplen）",
                stage.as_str()
            ),
            DecodeError::NonIpEtherType { ether_type } => {
                write!(f, "非 IP 帧：EtherType=0x{ether_type:04X}（ARP/STP/LLDP 等不构成五元组）")
            }
            DecodeError::UnsupportedIpVersion { version } => {
                write!(f, "IP 版本字段为 {version}，既非 4 也非 6：帧内容与以太头 EtherType 矛盾")
            }
            DecodeError::Ipv4BadHeaderLength { ihl_bytes } => write!(
                f,
                "IPv4 头长度字段算出 {ihl_bytes} 字节，小于最小值 20：该字段或版本字段已损坏"
            ),
            DecodeError::NonInitialFragment { offset_units } => write!(
                f,
                "IPv4 非首片（分片偏移 {offset_units} 个 8 字节单位）：该片不含四层头，\
                 拿不到端口。按端口 0 记入会与其它碎片塌缩成同一条假流，故拒绝"
            ),
            DecodeError::Ipv6TooManyExtensions { limit } => write!(
                f,
                "IPv6 扩展头层数超过 {limit} 层仍未到达四层头：链路可能损坏或为构造报文"
            ),
            DecodeError::UnsupportedIpv6NextHeader { next_header } => write!(
                f,
                "IPv6 下一头为 {next_header}，本解码器不展开（如 ESP 负载加密，端口本就不可见）"
            ),
            DecodeError::TooManyVlanTags { limit } => {
                write!(f, "VLAN 标签嵌套超过 {limit} 层：现实中不存在，解析位置多半已偏")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// 一帧的解码结果（比五元组多带几项下游要用的信息）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedFrame {
    /// 五元组。可直接构造 `flow::Packet`。
    pub key: FlowKey,
    pub l3: L3Proto,
    pub l4: L4Proto,
    /// VLAN 标签层数（0 表示未打标）。
    pub vlan_tags: u8,
    /// 四层段长度（IPv4 总长 / IPv6 载荷长度减去各层头）。
    ///
    /// 这是应喂给 `flow::Packet::payload_len` 的值：它比 `wirelen` 更贴近「这条流承载了
    /// 多少内容」，且不受捕获截断影响——因为它是从 IP 头长度字段算出的，不是数出来的。
    pub ip_payload_len: u32,
    /// 是否为分片首片（含未分片的普通报文）。首片带四层头，故能够解出五元组。
    pub is_initial_fragment: bool,
}

/// 解码一帧，得到五元组及其附属信息。
pub fn decode_frame(frame: &[u8]) -> Result<DecodedFrame, DecodeError> {
    // ---- 以太头 ----
    if frame.len() < ETH_HEADER_LEN {
        return Err(DecodeError::Truncated {
            stage: DecodeStage::Ethernet,
            need: ETH_HEADER_LEN,
            got: frame.len(),
        });
    }
    let mut ether_type = be16(&frame[12..14]);

    // ---- VLAN 标签（可能嵌套）----
    let mut offset = ETH_HEADER_LEN;
    let mut vlan_tags = 0u8;
    while ETHERTYPE_VLAN.contains(&ether_type) {
        if vlan_tags == MAX_VLAN_TAGS {
            return Err(DecodeError::TooManyVlanTags { limit: MAX_VLAN_TAGS });
        }
        if frame.len() < offset + VLAN_TAG_LEN {
            return Err(DecodeError::Truncated {
                stage: DecodeStage::Vlan,
                need: offset + VLAN_TAG_LEN,
                got: frame.len(),
            });
        }
        // 标签内层 EtherType 位于标签的后 2 字节。
        ether_type = be16(&frame[offset + 2..offset + 4]);
        offset += VLAN_TAG_LEN;
        vlan_tags += 1;
    }

    // ---- 三层 ----
    match ether_type {
        ETHERTYPE_IPV4 => decode_ipv4(frame, offset, vlan_tags),
        ETHERTYPE_IPV6 => decode_ipv6(frame, offset, vlan_tags),
        other => Err(DecodeError::NonIpEtherType { ether_type: other }),
    }
}

/// 只取五元组。多数调用方只需要这个。
pub fn decode_flow_key(frame: &[u8]) -> Result<FlowKey, DecodeError> {
    decode_frame(frame).map(|d| d.key)
}

/// 从帧的字节里读出 VLAN 标签层数，用于与生产端的 `flags` 交叉校验。
///
/// 返回 `None` 表示帧太短、连以太头都不完整，无法判断——刻意用 `Option` 而不是
/// 「0」：把「不知道」当成「没打标」，会让一次截断伪装成一次标记不符。
pub fn frame_has_vlan_tag(frame: &[u8]) -> Option<bool> {
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }
    let ether_type = be16(&frame[12..14]);
    Some(ETHERTYPE_VLAN.contains(&ether_type))
}

fn decode_ipv4(frame: &[u8], offset: usize, vlan_tags: u8) -> Result<DecodedFrame, DecodeError> {
    if frame.len() < offset + 20 {
        return Err(DecodeError::Truncated {
            stage: DecodeStage::Ip,
            need: offset + 20,
            got: frame.len(),
        });
    }
    let vihl = frame[offset];
    let version = vihl >> 4;
    if version != 4 {
        return Err(DecodeError::UnsupportedIpVersion { version });
    }
    let ihl_bytes = usize::from(vihl & 0x0F) * 4;
    if ihl_bytes < 20 {
        return Err(DecodeError::Ipv4BadHeaderLength { ihl_bytes });
    }
    if frame.len() < offset + ihl_bytes {
        return Err(DecodeError::Truncated {
            stage: DecodeStage::Ip,
            need: offset + ihl_bytes,
            got: frame.len(),
        });
    }

    let total_len = be16(&frame[offset + 2..offset + 4]) as u32;
    // +6..+8 是「3 位标志 + 13 位分片偏移」的合成字段。
    let frag_field = be16(&frame[offset + 6..offset + 8]);
    let frag_offset_units = frag_field & 0x1FFF;
    let more_fragments = frag_field & 0x2000 != 0;
    if frag_offset_units != 0 {
        return Err(DecodeError::NonInitialFragment {
            offset_units: frag_offset_units,
        });
    }

    let proto = frame[offset + 9];
    let l4 = L4Proto::from_u8(proto);
    let mut src = [0u8; 4];
    src.copy_from_slice(&frame[offset + 12..offset + 16]);
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&frame[offset + 16..offset + 20]);

    let l4_offset = offset + ihl_bytes;
    // 四层段长度由 IP 总长推出，不数字节：截断捕获下实际可用字节可能更少，
    // 但「这条流承载了多少」应以线上的量为准。
    let payload_len = total_len.saturating_sub(ihl_bytes as u32);
    let (src_port, dst_port) = decode_ports(frame, l4_offset, l4)?;

    Ok(DecodedFrame {
        key: FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
            src_port,
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
            dst_port,
            proto: l4.number(),
        },
        l3: L3Proto::Ipv4,
        l4,
        vlan_tags,
        ip_payload_len: payload_len,
        is_initial_fragment: more_fragments || frag_offset_units == 0,
    })
}

fn decode_ipv6(frame: &[u8], offset: usize, vlan_tags: u8) -> Result<DecodedFrame, DecodeError> {
    if frame.len() < offset + 40 {
        return Err(DecodeError::Truncated {
            stage: DecodeStage::Ip,
            need: offset + 40,
            got: frame.len(),
        });
    }
    let version = frame[offset] >> 4;
    if version != 6 {
        return Err(DecodeError::UnsupportedIpVersion { version });
    }

    let payload_len = be16(&frame[offset + 4..offset + 6]) as u32;
    let mut next_header = frame[offset + 6];
    let mut src = [0u8; 16];
    src.copy_from_slice(&frame[offset + 8..offset + 24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&frame[offset + 24..offset + 40]);

    // 走到四层头：逐层展开扩展头。每层的长度字段单位不同，且这是最容易写错的地方。
    let mut cursor = offset + 40;
    let mut hops = 0u8;
    let mut is_initial_fragment = true;
    loop {
        match next_header {
            IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMPV6 | IPPROTO_ICMP => break,
            IPPROTO_FRAGMENT => {
                // 分片头：8 字节固定。偏移字段占前 2 字节的高 13 位。
                if frame.len() < cursor + 8 {
                    return Err(DecodeError::Truncated {
                        stage: DecodeStage::Ipv6Extension,
                        need: cursor + 8,
                        got: frame.len(),
                    });
                }
                let frag_field = be16(&frame[cursor + 2..cursor + 4]);
                let frag_offset_units = frag_field >> 3;
                if frag_offset_units != 0 {
                    return Err(DecodeError::NonInitialFragment {
                        offset_units: frag_offset_units,
                    });
                }
                is_initial_fragment = true;
                next_header = frame[cursor];
                cursor += 8;
            }
            // 逐跳选项 / 路由头 / 目的选项：长度字段单位为 8 字节，且不含自身首 8 字节。
            0 | 43 | 60 => {
                if hops == MAX_IPV6_EXT_HEADERS {
                    return Err(DecodeError::Ipv6TooManyExtensions {
                        limit: MAX_IPV6_EXT_HEADERS,
                    });
                }
                if frame.len() < cursor + 8 {
                    return Err(DecodeError::Truncated {
                        stage: DecodeStage::Ipv6Extension,
                        need: cursor + 8,
                        got: frame.len(),
                    });
                }
                let ext_len = (usize::from(frame[cursor + 1]) + 1) * 8;
                next_header = frame[cursor];
                cursor += ext_len;
                hops += 1;
            }
            // 认证头：长度字段单位为 4 字节，且不含自身首 8 字节（故为 len+2）。
            IPPROTO_AH => {
                if hops == MAX_IPV6_EXT_HEADERS {
                    return Err(DecodeError::Ipv6TooManyExtensions {
                        limit: MAX_IPV6_EXT_HEADERS,
                    });
                }
                if frame.len() < cursor + 8 {
                    return Err(DecodeError::Truncated {
                        stage: DecodeStage::Ipv6Extension,
                        need: cursor + 8,
                        got: frame.len(),
                    });
                }
                let ext_len = (usize::from(frame[cursor + 1]) + 2) * 4;
                next_header = frame[cursor];
                cursor += ext_len;
                hops += 1;
            }
            // ESP 与其余未知：端口不可见，明确拒绝而不是猜。
            other => return Err(DecodeError::UnsupportedIpv6NextHeader { next_header: other }),
        }
        if cursor > frame.len() {
            return Err(DecodeError::Truncated {
                stage: DecodeStage::Ipv6Extension,
                need: cursor,
                got: frame.len(),
            });
        }
    }

    let l4 = L4Proto::from_u8(next_header);
    let (src_port, dst_port) = decode_ports(frame, cursor, l4)?;

    Ok(DecodedFrame {
        key: FlowKey {
            src_ip: IpAddr::V6(Ipv6Addr::from(src)),
            src_port,
            dst_ip: IpAddr::V6(Ipv6Addr::from(dst)),
            dst_port,
            proto: l4.number(),
        },
        l3: L3Proto::Ipv6,
        l4,
        vlan_tags,
        // IPv6 载荷长度字段已含扩展头，减去已走过的扩展头字节即四层段长度。
        ip_payload_len: payload_len.saturating_sub((cursor - (offset + 40)) as u32),
        is_initial_fragment,
    })
}

/// 取四层端口。无端口的协议返回 `(0, 0)`。
///
/// 只需要 4 字节即可得到端口对，因此**不要求完整四层头**：截断捕获常见于「只抓头」的
/// 采集配置，此时端口完全可用，拿不到完整的 20 字节 TCP 头并不影响五元组成立。
fn decode_ports(
    frame: &[u8],
    l4_offset: usize,
    l4: L4Proto,
) -> Result<(u16, u16), DecodeError> {
    if !l4.has_ports() {
        return Ok((0, 0));
    }
    if frame.len() < l4_offset + 4 {
        return Err(DecodeError::Truncated {
            stage: DecodeStage::L4,
            need: l4_offset + 4,
            got: frame.len(),
        });
    }
    Ok((
        be16(&frame[l4_offset..l4_offset + 2]),
        be16(&frame[l4_offset + 2..l4_offset + 4]),
    ))
}

/// 读 2 字节大端。调用方保证切片长度为 2。
#[inline]
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小以太 + IPv4 + TCP 帧。
    fn ipv4_tcp_frame(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00; 6]); // dst mac
        v.extend_from_slice(&[0x11; 6]); // src mac
        v.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        v.extend_from_slice(&[0x45, 0x00]); // version 4, IHL 5
        v.extend_from_slice(&40u16.to_be_bytes()); // total length = 20 + 20
        v.extend_from_slice(&[0x00, 0x00]); // id
        v.extend_from_slice(&[0x40, 0x00]); // DF，分片偏移 0
        v.extend_from_slice(&[64, IPPROTO_TCP]); // ttl, proto
        v.extend_from_slice(&[0x00, 0x00]); // checksum（故意留 0，见「不校验校验和」）
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&[0x00; 16]); // TCP 其余头部
        v
    }

    #[test]
    fn decode_ipv4_tcp() {
        let frame = ipv4_tcp_frame([10, 0, 0, 1], 12345, [93, 184, 216, 34], 443);
        let d = decode_frame(&frame).expect("应能解出");
        assert_eq!(d.l3, L3Proto::Ipv4);
        assert_eq!(d.l4, L4Proto::Tcp);
        assert_eq!(d.vlan_tags, 0);
        assert_eq!(d.ip_payload_len, 20, "IPv4 总长 40 减去头 20");
        assert_eq!(
            d.key,
            FlowKey::new_ipv4([10, 0, 0, 1], 12345, [93, 184, 216, 34], 443, IPPROTO_TCP)
        );
    }

    #[test]
    fn decode_vlan_single_and_qinq() {
        // 单层 802.1Q
        let mut frame = ipv4_tcp_frame([10, 0, 0, 2], 40000, [10, 0, 0, 3], 80);
        let mut tagged = frame[..12].to_vec();
        tagged.extend_from_slice(&0x8100u16.to_be_bytes());
        tagged.extend_from_slice(&[0x00, 0x64]); // VLAN 100
        tagged.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        tagged.extend_from_slice(&frame[14..]);
        let d = decode_frame(&tagged).expect("单层 VLAN 应能解出");
        assert_eq!(d.vlan_tags, 1);
        assert_eq!(d.key.dst_port, 80);
        assert_eq!(frame_has_vlan_tag(&tagged), Some(true));

        // QinQ：外层 0x88A8 + 内层 0x8100
        let mut qinq = frame[..12].to_vec();
        qinq.extend_from_slice(&0x88A8u16.to_be_bytes());
        qinq.extend_from_slice(&[0x00, 0x0A]);
        qinq.extend_from_slice(&0x8100u16.to_be_bytes());
        qinq.extend_from_slice(&[0x00, 0x64]);
        qinq.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        qinq.extend_from_slice(&frame[14..]);
        let d = decode_frame(&qinq).expect("QinQ 应能解出");
        assert_eq!(d.vlan_tags, 2);
        assert_eq!(d.key.dst_port, 80);

        // 三层标签：应被拒，而不是继续往深处猜
        let mut deep = frame[..12].to_vec();
        for i in 0..3u16 {
            deep.extend_from_slice(&0x8100u16.to_be_bytes());
            deep.extend_from_slice(&i.to_be_bytes());
        }
        deep.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        deep.extend_from_slice(&frame[14..]);
        assert_eq!(
            decode_frame(&deep).unwrap_err(),
            DecodeError::TooManyVlanTags { limit: MAX_VLAN_TAGS }
        );
        // 解不出来时不得给出「没打标」的结论
        frame.truncate(10);
        assert_eq!(frame_has_vlan_tag(&frame), None);
    }

    #[test]
    fn non_initial_fragment_is_rejected_not_zeroed() {
        // 这是一条把「静默错误」换成「显式错误」的用例：若按端口 0 记入，
        // 所有碎片会塌缩成同一条假流，而统计上完全看不出来。
        let mut frame = ipv4_tcp_frame([10, 0, 0, 1], 12345, [93, 184, 216, 34], 443);
        // 分片偏移置为 185（= 1480 字节 / 8），保留 MF
        frame[20] = 0x20;
        frame[21] = 0xB9;
        let err = decode_frame(&frame).unwrap_err();
        assert_eq!(err.code(), "decode.non_initial_fragment");
        assert_eq!(err, DecodeError::NonInitialFragment { offset_units: 185 });
    }

    #[test]
    fn first_fragment_still_decodes() {
        // MF 置位但偏移为 0：仍是首片，带四层头，五元组成立。
        let mut frame = ipv4_tcp_frame([10, 0, 0, 1], 12345, [93, 184, 216, 34], 443);
        frame[20] = 0x20;
        frame[21] = 0x00;
        let d = decode_frame(&frame).expect("首片应能解出");
        assert!(d.is_initial_fragment);
        assert_eq!(d.key.dst_port, 443);
    }

    #[test]
    fn ipv4_bad_ihl_and_version_are_distinguished() {
        // IHL=4（16 字节，小于最小 20）与「版本不是 4」是两回事，分别给码。
        let mut frame = ipv4_tcp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2);
        frame[14] = 0x44;
        assert_eq!(
            decode_frame(&frame).unwrap_err(),
            DecodeError::Ipv4BadHeaderLength { ihl_bytes: 16 }
        );

        frame[14] = 0x55; // 版本 5，IHL 5
        assert_eq!(
            decode_frame(&frame).unwrap_err(),
            DecodeError::UnsupportedIpVersion { version: 5 }
        );
    }

    #[test]
    fn ipv4_options_shift_l4_offset() {
        // IHL=6（24 字节头，含 4 字节选项）：端口位置必须随之右移。
        let mut frame = ipv4_tcp_frame([10, 0, 0, 1], 12345, [93, 184, 216, 34], 443);
        let mut with_opts = frame[..14].to_vec();
        with_opts.push(0x46); // version 4, IHL 6
        with_opts.push(0x00);
        with_opts.extend_from_slice(&44u16.to_be_bytes()); // 24 + 20
        with_opts.extend_from_slice(&frame[18..34]); // id/flags/ttl/proto/checksum/src/dst
        with_opts.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // 选项
        with_opts.extend_from_slice(&frame[34..]); // 端口与 TCP 头
        let d = decode_frame(&with_opts).expect("带选项的 IPv4 应能解出");
        assert_eq!(d.key.src_port, 12345);
        assert_eq!(d.key.dst_port, 443);
        assert_eq!(d.ip_payload_len, 20, "总长 44 减头 24");
        frame.clear();
    }

    #[test]
    fn non_ip_and_truncation() {
        let mut arp = ipv4_tcp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2);
        arp[12] = 0x08;
        arp[13] = 0x06; // ARP
        assert_eq!(
            decode_frame(&arp).unwrap_err(),
            DecodeError::NonIpEtherType { ether_type: 0x0806 }
        );

        // 截断用例必须用未改写的 IP 帧：否则断言的是「ARP 被截断」，
        // 而实际想验证的是「IP 帧被截断时给出 Ip 阶段」。
        let frame = ipv4_tcp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2);

        // 以太头都不全
        assert_eq!(
            decode_frame(&[0u8; 8]).unwrap_err(),
            DecodeError::Truncated {
                stage: DecodeStage::Ethernet,
                need: 14,
                got: 8
            }
        );
        // IP 头不全：以太头 14 + IPv4 头 20 = 34
        assert_eq!(
            decode_frame(&frame[..20]).unwrap_err(),
            DecodeError::Truncated {
                stage: DecodeStage::Ip,
                need: 34,
                got: 20
            }
        );
    }

    #[test]
    fn truncated_at_ports_is_explicit() {
        // 截断到刚好缺端口：必须报错，而不能给出端口 0 的假流。
        let frame = ipv4_tcp_frame([10, 0, 0, 1], 12345, [93, 184, 216, 34], 443);
        let err = decode_frame(&frame[..36]).unwrap_err();
        assert_eq!(err.code(), "decode.truncated");
        match err {
            DecodeError::Truncated { stage, need, got } => {
                assert_eq!(stage, DecodeStage::L4);
                assert_eq!((need, got), (38, 36));
            }
            other => panic!("应为 L4 阶段截断，实际 {other:?}"),
        }
    }

    #[test]
    fn icmp_has_no_ports_but_keeps_proto() {
        let mut frame = ipv4_tcp_frame([10, 0, 0, 1], 0, [10, 0, 0, 2], 0);
        frame[23] = IPPROTO_ICMP;
        let d = decode_frame(&frame).expect("ICMP 应能解出");
        assert_eq!(d.l4, L4Proto::Icmp);
        assert_eq!(d.key.proto, IPPROTO_ICMP);
        assert_eq!((d.key.src_port, d.key.dst_port), (0, 0));
    }

    #[test]
    fn ipv6_plain_tcp() {
        // 固定 40 字节 IPv6 头 + TCP 端口
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00; 6]);
        v.extend_from_slice(&[0x11; 6]);
        v.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        v.push(0x60);
        v.extend_from_slice(&[0x00, 0x00, 0x00]); // tc/flowlabel
        v.extend_from_slice(&20u16.to_be_bytes()); // payload length
        v.push(IPPROTO_TCP);
        v.push(64);
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        v.extend_from_slice(&50000u16.to_be_bytes());
        v.extend_from_slice(&443u16.to_be_bytes());
        v.extend_from_slice(&[0x00; 16]);

        let d = decode_frame(&v).expect("IPv6 TCP 应能解出");
        assert_eq!(d.l3, L3Proto::Ipv6);
        assert!(d.l3.is_ipv6());
        assert_eq!(d.key.src_port, 50000);
        assert_eq!(d.key.dst_port, 443);
        assert_eq!(d.ip_payload_len, 20);
        assert!(matches!(d.key.src_ip, IpAddr::V6(_)));
    }

    #[test]
    fn ipv6_extension_headers_are_walked() {
        // 目的选项头（60，长度单位 8 字节）后接 UDP。
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00; 6]);
        v.extend_from_slice(&[0x11; 6]);
        v.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        v.push(0x60);
        v.extend_from_slice(&[0x00, 0x00, 0x00]);
        // payload = 8（扩展头）+ 8（UDP 端口段）
        v.extend_from_slice(&16u16.to_be_bytes());
        v.push(60); // 首个扩展头：目的选项
        v.push(64);
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // 扩展头：next=UDP, len=0（表示 8 字节）
        v.push(IPPROTO_UDP);
        v.push(0);
        v.extend_from_slice(&[0x00; 6]);
        v.extend_from_slice(&53u16.to_be_bytes());
        v.extend_from_slice(&5353u16.to_be_bytes());

        let d = decode_frame(&v).expect("应能走完扩展头");
        assert_eq!(d.l4, L4Proto::Udp);
        assert_eq!(d.key.dst_port, 5353);
        assert_eq!(d.ip_payload_len, 8, "载荷 16 减去扩展头 8");
    }

    #[test]
    fn ipv6_esp_is_rejected() {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00; 6]);
        v.extend_from_slice(&[0x11; 6]);
        v.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        v.push(0x60);
        v.extend_from_slice(&[0x00, 0x00, 0x00]);
        v.extend_from_slice(&8u16.to_be_bytes());
        v.push(IPPROTO_ESP);
        v.push(64);
        v.extend_from_slice(&[0u8; 32]);
        v.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            decode_frame(&v).unwrap_err(),
            DecodeError::UnsupportedIpv6NextHeader { next_header: IPPROTO_ESP }
        );
    }

    #[test]
    fn ipv6_non_initial_fragment_is_rejected() {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00; 6]);
        v.extend_from_slice(&[0x11; 6]);
        v.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        v.push(0x60);
        v.extend_from_slice(&[0x00, 0x00, 0x00]);
        v.extend_from_slice(&16u16.to_be_bytes());
        v.push(IPPROTO_FRAGMENT);
        v.push(64);
        v.extend_from_slice(&[0u8; 32]);
        // 分片头：next=UDP，偏移字段 = 185 << 3
        v.push(IPPROTO_UDP);
        v.push(0);
        v.extend_from_slice(&(185u16 << 3).to_be_bytes());
        v.extend_from_slice(&[0x00; 4]);
        v.extend_from_slice(&[0x00; 8]);
        assert_eq!(
            decode_frame(&v).unwrap_err(),
            DecodeError::NonInitialFragment { offset_units: 185 }
        );
    }

    #[test]
    fn error_codes_are_stable_and_distinct() {
        // 错误码是给统计与日志聚合用的，必须唯一，否则按原因计数会串。
        let all = [
            DecodeError::Truncated {
                stage: DecodeStage::Ethernet,
                need: 14,
                got: 0,
            },
            DecodeError::NonIpEtherType { ether_type: 0x0806 },
            DecodeError::UnsupportedIpVersion { version: 5 },
            DecodeError::Ipv4BadHeaderLength { ihl_bytes: 16 },
            DecodeError::NonInitialFragment { offset_units: 1 },
            DecodeError::Ipv6TooManyExtensions { limit: 8 },
            DecodeError::UnsupportedIpv6NextHeader { next_header: 50 },
            DecodeError::TooManyVlanTags { limit: 2 },
        ];
        let mut codes: Vec<&str> = all.iter().map(|e| e.code()).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "错误码存在重复");
        for e in all {
            assert!(!e.code().is_empty());
            assert!(e.to_string().len() > 10, "文案不能是空壳：{e}");
        }
    }

    #[test]
    fn l4_proto_roundtrip() {
        for v in [0u8, 1, 6, 17, 47, 58, 255] {
            assert_eq!(L4Proto::from_u8(v).number(), v, "协议号往返应无损");
        }
        assert!(L4Proto::Tcp.has_ports());
        assert!(L4Proto::Udp.has_ports());
        assert!(!L4Proto::Icmp.has_ports());
        assert!(!L4Proto::Other(47).has_ports());
        assert_eq!(L4Proto::Icmpv6.as_str(), "icmpv6");
    }
}
