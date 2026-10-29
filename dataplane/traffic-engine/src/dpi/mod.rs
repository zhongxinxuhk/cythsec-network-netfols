// dpi/mod.rs —— 深度包检测（DPI）与识别框架。
//
// 为什么必须有这一层，而不是"每个协议各自解析"：
//   省网入口看到的是**一串没有标签的字节流**，只有"这段载荷属于哪个协议"这一个未知数。
//   直接在所有协议上乱试，代价随协议数线性增长；只按端口判断，又会漏掉端口漂移
//   （HTTP 跑在 8080、DoH 跑在 443）。因此这里用**三级递进**：
//
//     1. 端口：先按周知端口给出一个"最可能"的候选顺序（成本 0，一个比较）
//     2. 载荷特征：按候选顺序逐个用真实协议特征确认（成本随命中深浅递增）
//     3. 兜底 unknown：全部明确拒绝才落到这里
//
// 三级之间**不是**短路关系但也不是全跑：命中即返回，而"明确拒绝"会继续试下一个候选，
// "需要更多字节/畸形"则会记下来、但**不**立刻返回 —— 因为另一个检测器可能已经能命中。
//
// 关于"只看首包"：本层是纯函数、无状态、不重组流。重组属于 reassembly，
// 那时才谈得上把多个 TCP 段拼起来。DPI 的价值恰恰在于**不等重组**：
// 省网要在连接建立的头几百微秒内出结果，等流拼完整，SLA 早就过了。

// 标准隧道结构解析先于原有三个应用检测器，返回中等置信的结构级 AppId。
// 它不等于产品归因或密码学认证；双向确认、可信上下文和 A/B/C/U 在 identification 中处理。
pub mod attributes;
pub mod dhcp;
pub mod dhcpv6;
pub mod dns;
pub mod doh;
pub mod dot;
pub mod http;
pub mod mdns;
pub mod tls;
pub mod wire;

mod md5;
mod types;

#[cfg(test)]
mod tests;

pub use attributes::{emit, tls_version_name, Attr, AttrError};
pub use types::{AppId, Confidence, Detect, Detection, Outcome};

/// 采集层建议交付给 DPI 的字节数（默认 512）。
///
/// **这不是解析器的上限**，而是"数据面该拷多少字节过来"的策略建议：
/// ClientHello 带上 ECH、key_share 之后轻松超过 400 字节，取 256 会让相当一部分
/// 真实流量退化成"需要更多字节"，而这些流量恰恰是最该被识别的现代客户端。
/// 取 512 是"覆盖绝大多数首包"与"每包拷贝开销"之间的折中。
pub const DEFAULT_INSPECT_BYTES: usize = 512;

// `pub` 是刻意的：重组层（reassembly）在把流拼好之后要调用 `identify`，
// 它必须能引用同一个协议号常量。若各写一份 `6`，两边迟早会漂移，
// 而漂移的表现只是"某些端口的识别顺序变了"，极难定位。
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

const PORT_DNS: u16 = 53;
const PORT_HTTP: u16 = 80;
const PORT_HTTPS: u16 = 443;
const PORT_DOT: u16 = 853;

/// 按协议与目的端口给出检测顺序。
///
/// 顺序决定"谁先有机会命中"，是性能问题也是正确性问题：
/// 443 上优先试 TLS 而不是 DNS，不仅更快（DNS 头校验要读 12 字节），
/// 也避免了把某个恰好前两字节非零的 TLS 报文误判成 DNS。
fn order(proto: u8, dst_port: u16) -> [fn(&[u8]) -> Detect; 3] {
    let dns: fn(&[u8]) -> Detect = if proto == IPPROTO_TCP {
        dns::detect_tcp
    } else {
        dns::detect
    };
    match (proto, dst_port) {
        (IPPROTO_UDP, PORT_DNS) | (IPPROTO_TCP, PORT_DNS) => [dns, tls::detect, http::detect],
        (IPPROTO_TCP, PORT_DOT) => [tls::detect, dns, http::detect],
        (IPPROTO_TCP, PORT_HTTPS) => [tls::detect, http::detect, dns],
        (IPPROTO_TCP, PORT_HTTP) => [http::detect, tls::detect, dns],
        // 端口给不出线索（或端口漂移）：按"特征最强"的顺序试，TLS 的 `\x16\x03` 记录头
        // 几乎不可能与其他协议撞，放在最前面最省。
        _ => [tls::detect, http::detect, dns],
    }
}

/// 识别一段首包载荷。
///
/// 语义契约（下游统计口径完全依赖这里的区分）：
///   * `Identified` —— 有协议自身的强证据，可以计入应用识别统计；
///   * `NeedMore`   —— 载荷是好的只是没到齐（分片 / snaplen），**不得**计入 unknown；
///   * `Malformed`  —— 载荷自称是某协议但自相矛盾，计入解析失败；
///   * `Unknown`    —— 所有检测器都明确说"不是我"，计入 unknown。
pub fn identify(payload: &[u8], proto: u8, dst_port: u16) -> Outcome {
    identify_with_ports(payload, proto, 0, dst_port)
}

/// Full observed UDP port context, needed for mDNS legacy unicast responses.
/// The legacy identify API remains compatible with callers that only know dport.
pub fn identify_with_ports(payload: &[u8], proto: u8, src_port: u16, dst_port: u16) -> Outcome {
    if proto == IPPROTO_UDP && mdns::transport(payload, src_port, dst_port) {
        return match mdns::detect(payload) {
            Detect::Hit(d) => Outcome::Identified(d),
            Detect::NeedMore => Outcome::NeedMore,
            Detect::Malformed => Outcome::Malformed,
            Detect::Rejected => Outcome::Unknown,
        };
    }
    if proto == IPPROTO_UDP && dhcp::has_cookie(payload) {
        return match dhcp::detect(payload) {
            Detect::Hit(d) => Outcome::Identified(d),
            Detect::NeedMore => Outcome::NeedMore,
            Detect::Malformed => Outcome::Malformed,
            Detect::Rejected => Outcome::Unknown,
        };
    }
    if proto == IPPROTO_UDP && dhcpv6::is_message_type(payload) {
        let result = dhcpv6::detect(payload);
        if matches!(result, Detect::Hit(_)) || matches!(dst_port, 546 | 547) {
            return match result {
                Detect::Hit(d) => Outcome::Identified(d),
                Detect::NeedMore => Outcome::NeedMore,
                Detect::Malformed => Outcome::Malformed,
                Detect::Rejected => Outcome::Unknown,
            };
        }
    }
    let structural = wire::inspect_standard(payload, proto, 0, dst_port);
    let mut saw_need_more = matches!(structural, wire::Verdict::NeedMore)
        || proto == IPPROTO_UDP && matches!(dhcp::detect(payload), Detect::NeedMore);
    let mut saw_malformed = matches!(structural, wire::Verdict::Malformed);
    if let wire::Verdict::Match(f) = structural {
        let app = match f.id {
            "V001" => AppId::Esp,
            "V002" => AppId::Ah,
            "V003" => AppId::Ikev1,
            "V004" => AppId::Ikev2,
            "V006" => AppId::L2tp,
            "V008" => AppId::Pptp,
            "V009" => AppId::Gre,
            "V010" => AppId::Ipip,
            "V011" => AppId::Ipv6ip,
            "V013" => AppId::Etherip,
            "V014" => AppId::Vxlan,
            "V015" => AppId::Geneve,
            "V017" | "V018" => AppId::OpenVpn,
            "V021" => AppId::WireGuard,
            "P001" => AppId::Socks4,
            "P002" => AppId::Socks5,
            "T005" => AppId::Dtls,
            "T007" | "T008" => AppId::Quic,
            "T014" => AppId::Tlcp,
            "T016" => AppId::Ssh,
            _ => AppId::Unknown,
        };
        if app != AppId::Unknown {
            return Outcome::Identified(Detection::new(
                app,
                Confidence::Medium,
                "bounded wire structure; not product attribution or authenticated session",
            ));
        }
    }

    for detect in order(proto, dst_port) {
        match detect(payload) {
            Detect::Hit(d) => return Outcome::Identified(d),
            Detect::NeedMore => saw_need_more = true,
            Detect::Malformed => saw_malformed = true,
            Detect::Rejected => {}
        }
    }

    // Malformed 优先于 NeedMore：前者的信息量更大（"这个包是坏的"），
    // 后者只是"还不确定"。反过来排会让坏包被计入"再等等就能识别"的桶里，
    // 而它永远等不出结果 —— 在省网统计上表现为 unknown 率缓慢抬升且查不出原因。
    if saw_malformed {
        Outcome::Malformed
    } else if saw_need_more {
        Outcome::NeedMore
    } else {
        Outcome::Unknown
    }
}

#[cfg(test)]
mod framework_tests {
    use super::*;

    #[test]
    fn port_hint_puts_dns_first_for_udp_53() {
        // DNS/TCP requires its length prefix even when the service uses another
        // port. A UDP-format message alone must not become a TCP DNS hit.
        let p: &[u8] = &[
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        assert_eq!(identify(p, IPPROTO_UDP, PORT_DNS).word(), "identified");
        assert!(
            !matches!(identify(p, IPPROTO_TCP, PORT_HTTP), Outcome::Identified(d) if d.app == AppId::Dns)
        );
        let mut framed = (p.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(p);
        assert!(
            matches!(identify(&framed, IPPROTO_TCP, PORT_HTTP), Outcome::Identified(d) if d.app == AppId::Dns)
        );
    }

    #[test]
    fn garbage_is_unknown_not_malformed() {
        // 每个检测器都明确拒绝 → Unknown。这里若返回 Malformed，说明某个检测器
        // 把"不是我的协议"当成了"我的协议坏了"，统计口径就串了。
        let p = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
        assert_eq!(identify(p, IPPROTO_TCP, 9999), Outcome::Unknown);
    }

    #[test]
    fn empty_payload_is_need_more() {
        // 一个字节都还没送到：这是"还没到"，不是"不是任何协议"
        assert_eq!(identify(&[], IPPROTO_TCP, 443), Outcome::NeedMore);
    }
}
