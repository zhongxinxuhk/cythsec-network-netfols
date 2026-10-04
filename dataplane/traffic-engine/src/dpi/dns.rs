// dpi/dns.rs —— DNS 报文解析与 QNAME 提取（CYS-TRF-023）。
//
// DNS 是省网级统计里**唯一**能在加密流量之外稳定拿到域名的明文协议，也是 DPI 里
// "成本最低、覆盖面最大"的一类：绝大多数 HTTPS 连接在建连前都会先发一次 A/AAAA 查询。
//
// 本模块最要紧的不是解析，而是**压缩指针**。字段里的 0xC0 指针可以指向报文中间任意偏移，
// 包括指向自己 —— 若实现老老实实地"跟着指针走"，一条 20 字节的报文就能让解析器转个没完，
// 在省网入口这种每秒百万包的场景下，这是最省事也最致命的 DoS。
// 因此这里用**跳数上限**而非"visited 集合"来兜底：两者都能破环，但跳数上限同时天然限制了
// 每次解析的 work 量，代价只是"极深但合法的链会被拒"—— 而 255 字节的名字最多 128 跳，
// 上限取 128 意味着合法名字绝不会被误拒。

use super::types::{Confidence, Detect, Detection};

/// DNS 报文头固定 12 字节（ID/FLAGS/QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT）。
const DNS_HEADER: usize = 12;
/// RFC 1035 域名总长上限（含标签长度字节，不含根标签）。
const MAX_NAME_BYTES: usize = 255;
/// 单个标签长度上限（8 位长度字段的最高两位是类型位）。
const MAX_LABEL_LEN: usize = 63;
/// 名字最多 128 跳（255 字节 / 最小 2 字节一个标签）。达到上限即判定为指针成环。
const MAX_NAME_HOPS: usize = 128;
/// 合法 opcode：RFC 1035 只定义了 0~3，更高取值不是 DNS 流量。
const MAX_OPCODE: u8 = 3;
/// 合法 rcode：0~11，10=NOTIFY 专用、11=BADCOOKIE。
const MAX_RCODE: u8 = 11;
/// 一次解析最多看多少条资源记录（ANSWER + AUTHORITY + ADDITIONAL）。
///
/// 本模块的 work 上限分三层：名字解析有跳数上限、记录条数有这一层、
/// 每条记录的 rdlength 又必须落在报文内。三层叠起来，"一条 64KB 的报文让解析器
/// 干多少活"就是常数级的 —— 省网入口每秒百万包，任何一处无界都是把 DoS 请进门。
const MAX_RECORDS: usize = 32;
/// 最多收集多少个应答地址：属性是"这条流解析出了哪些地址"，不是 DNS 缓存的替代品。
const MAX_ANSWER_IPS: usize = 8;
/// EDNS0 的 OPT 记录类型号（RFC 6891；RFC 2671 里叫 OPT 伪 RR）。
const TYPE_OPT: u16 = 41;
/// A / AAAA 的类型号。
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
/// IN 类。
const CLASS_IN: u16 = 1;

/// 从 DNS 报文里提取出的字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    /// 查询段的名字（可能是查询、也可能是响应里的 QUESTION 段）。
    pub qname: Option<String>,
    pub qtype: u16,
    pub qclass: u16,
    /// QUESTION 名字里的压缩指针跳数（0 = 没用压缩指针）。
    pub ptr_depth: u8,
    /// 应答段里的 A/AAAA 地址（响应侧）。
    pub answer_ips: Vec<String>,
    /// EDNS0 OPT 记录里声明的 UDP 载荷上限（请求方视角）。
    pub edns0_udp_size: Option<u16>,
}

/// 解析一段 DNS 报文。
///
/// `Rejected` 表示"这不是 DNS"（例如把垃圾载荷喂进来），与 `Malformed`（是 DNS 但自相矛盾）
/// 严格区分：前者不该计入解析失败率，后者必须计入。
pub fn parse(payload: &[u8]) -> Result<DnsMessage, Detect> {
    if payload.len() < DNS_HEADER {
        return Err(Detect::NeedMore); // 头都没传全 —— 多半是分片
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let opcode = ((flags >> 11) & 0xF) as u8;
    let rcode = (flags & 0xF) as u8;
    // HEADER 常量校验放在前：这是唯一能在**只看了 4 个字节**时就否定一条载荷的依据。
    // 否则只能一路解析下去，到最后拿 qdcount 这种"越看越离谱"的字段去猜，
    // 猜出来的结果既不是 Rejected 也不是 Malformed，统计上就漏了。
    if opcode > MAX_OPCODE || rcode > MAX_RCODE {
        return Err(Detect::Rejected);
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let arcount = u16::from_be_bytes([payload[10], payload[11]]);
    let is_response = flags & 0x8000 != 0;
    // 一条**查询**报文宣称自己带着不止一个问题段，几乎可以确定它不是 DNS。
    // 这条判据的价值在于它只看头部就能否定：否则只能一路解析下去，最终靠
    // "名字读到一半缓冲区没了" 得出 NeedMore —— 而那会把一堆垃圾流量算进
    // "分片，再等等就能识别" 的桶里，unknown 率反而被压得失真。
    if !is_response && qdcount != 1 {
        return Err(Detect::Rejected);
    }

    // 解析 QUESTION 段的名字（偏移 12），随后是 4 字节 qtype+qclass
    let (name, after, ptr_depth) = parse_name(payload, DNS_HEADER)?;
    if after + 4 > payload.len() {
        return Err(Detect::NeedMore);
    }
    let qtype = u16::from_be_bytes([payload[after], payload[after + 1]]);
    let qclass = u16::from_be_bytes([payload[after + 2], payload[after + 3]]);

    // 资源记录段：**尽力而为**，且失败不影响上面的识别结论。
    //
    // 理由：首包常常只到 QUESTION 段（应答段被 snaplen 截掉或被拆到下一个 TCP 段），
    // 若因为"应答段没到齐"就把整条报文判成 NeedMore，会把大量已经拿到域名强证据的
    // 响应流量从"已识别"里推回去 —— 而 QUESTION 段的证据强度与应答段无关。
    // 所以这里只收集能完整读到的部分，读不完就停（不报错），真正的边界由
    // `MAX_RECORDS` 与 rdlength 边界检查保证。
    let sections = SectionCounts {
        answer: usize::from(ancount),
        authority: usize::from(nscount),
        additional: usize::from(arcount),
    };
    let scanned = scan_records(payload, after + 4, sections);
    // 同一条报文里两条 OPT：RFC 6891 明文规定至多一条，收到多条应回 FORMERR。
    // 这不是"再等等就能读出来"的截断问题，补多少字节都不成立 —— 判畸形。
    if scanned.duplicate_opt {
        return Err(Detect::Malformed);
    }

    Ok(DnsMessage {
        id,
        is_response,
        opcode,
        rcode,
        qname: if name.is_empty() { None } else { Some(name) },
        qtype,
        qclass,
        ptr_depth: ptr_depth.min(u8::MAX as usize) as u8,
        answer_ips: scanned.answer_ips,
        edns0_udp_size: scanned.edns0_udp_size,
    })
}

/// 三段资源记录的条数（来自头部计数）。
struct SectionCounts {
    answer: usize,
    authority: usize,
    additional: usize,
}

/// 扫描结果。
#[derive(Default)]
struct Scanned {
    answer_ips: Vec<String>,
    edns0_udp_size: Option<u16>,
    opt_seen: bool,
    /// OPT 记录出现两次以上（RFC 6891 §6.1.1 规定至多一条）。
    duplicate_opt: bool,
}

/// 逐条走过 ANSWER / AUTHORITY / ADDITIONAL，收集 A/AAAA 地址与 EDNS0 的 OPT。
///
/// **不报错、只停止**：缓冲区里没读全就停下（首包截断是常态），
/// 唯一例外是"同一条报文里出现两条 OPT"——那是协议违规，由调用方判畸形。
fn scan_records(data: &[u8], start: usize, counts: SectionCounts) -> Scanned {
    let mut out = Scanned::default();
    let mut off = start;
    let total = (counts.answer + counts.authority + counts.additional).min(MAX_RECORDS);

    for i in 0..total {
        let in_answer = i < counts.answer;
        let in_additional = i >= counts.answer + counts.authority;

        let Ok((_name, after, _hops)) = parse_name(data, off) else {
            break; // 名字被截断或越界：后面的都读不了了
        };
        // 定长部分：TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        let Some(head) = data.get(after..after + 10) else {
            break;
        };
        let rtype = u16::from_be_bytes([head[0], head[1]]);
        let rclass = u16::from_be_bytes([head[2], head[3]]);
        let rdlen = usize::from(u16::from_be_bytes([head[8], head[9]]));
        let rdata_at = after + 10;
        let Some(rdata) = data.get(rdata_at..rdata_at.saturating_add(rdlen)) else {
            break; // rdlength 越过报文末尾：这块读不全，停
        };

        if in_answer && out.answer_ips.len() < MAX_ANSWER_IPS {
            if let Some(ip) = addr_of(rtype, rclass, rdata) {
                out.answer_ips.push(ip);
            }
        }
        if in_additional && rtype == TYPE_OPT {
            if out.opt_seen {
                out.duplicate_opt = true;
            } else {
                out.opt_seen = true;
                // OPT 的 CLASS 字段被复用为"请求方能接收的最大 UDP 载荷字节数"
                out.edns0_udp_size = Some(rclass);
            }
        }

        off = rdata_at + rdlen;
    }

    out
}

/// 把一条 A/AAAA 记录的 rdata 变成地址字符串（类型/类别/长度都要对得上）。
fn addr_of(rtype: u16, rclass: u16, rdata: &[u8]) -> Option<String> {
    if rclass != CLASS_IN {
        return None; // CH/HS 类里的 rdata 不是 IP 地址
    }
    match rtype {
        TYPE_A if rdata.len() == 4 => Some(format!(
            "{}.{}.{}.{}",
            rdata[0], rdata[1], rdata[2], rdata[3]
        )),
        TYPE_AAAA if rdata.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

/// 逐段解析域名：标签序列与 0xC0 压缩指针走同一条循环。
///
/// 返回 `(名字, 名称之后第一个字节的偏移, 指针跳数)`。名字为空表示这是一个全指针
/// （畸形，由调用方丢弃）。跳数单独返回是因为它是**可观测的解析成本**：
/// 0 表示名字是线性读出来的，非 0 表示跳了几次（对应属性 `ATTR_DNS_PTR_DEPTH`）。
fn parse_name(data: &[u8], start: usize) -> Result<(String, usize, usize), Detect> {
    let mut labels: Vec<String> = Vec::new();
    let mut used = 0usize;
    let mut off = start;
    let mut hops = 0usize;
    let mut ptr_hops = 0usize;
    // 名字在**原始位置**上占到哪里为止。
    //
    // 这一步是压缩指针最容易写错的地方：名字跳走之后读到的是别处的字节，
    // 而调用方要的是"这个名字字段本身结束了，下一个字节在哪"。
    // 答名字用 `0xC0 0x0C` 指向 QUESTION 时，若把"跟着指针读完后的位置"
    // （QUESTION 内的偏移）返回给调用方，调用方就会从报文中间继续读资源记录 ——
    // 读出来的 TYPE/CLASS/RDLENGTH 全是错位字节，而报文本身完全合法。
    // 正解：第一次发生跳转时记下"指针字段结束"的位置（off + 2），后面即使跳得更远也用它。
    let mut origin_end: Option<usize> = None;

    loop {
        hops += 1;
        if hops > MAX_NAME_HOPS {
            // 指针成环：自指、互指、长链都落在这里 —— 没有这个上限，这里就是一个死循环。
            return Err(Detect::Malformed);
        }
        if off >= data.len() {
            return Err(Detect::NeedMore); // 名字还没传完
        }
        let b = data[off];
        // 首字节的两位类型位决定这一小段是什么：
        //   0b00 → 标签（低 6 位即长度）；0b11 → 压缩指针；0b01/0b10 → 非法。
        // 判成指针之后，指针本身占满两个字节（0xC0xxxx），低 14 位才是偏移。
        if b & 0xC0 == 0xC0 {
            if off + 1 >= data.len() {
                return Err(Detect::NeedMore);
            }
            let target =
                (((u16::from(b) & 0x3F) as usize) << 8) | u16::from(data[off + 1]) as usize;
            if target >= data.len() {
                // 指向缓冲区之外：指向报文内部才合理，越界即长度字段有问题
                return Err(Detect::Malformed);
            }
            if origin_end.is_none() {
                origin_end = Some(off + 2);
            }
            off = target;
            ptr_hops += 1;
            continue;
        }
        if b == 0x00 {
            // 根标签：名字到此结束
            return Ok((labels.join("."), origin_end.unwrap_or(off + 1), ptr_hops));
        }
        {
            if usize::from(b) > MAX_LABEL_LEN {
                // 0x40~0xBF：长度字段最高两位是类型位，这些取值不是合法标签长度
                return Err(Detect::Malformed);
            }
            let len = b as usize;
            if off + 1 + len > data.len() {
                return Err(Detect::NeedMore);
            }
            used += 1 + len;
            if used > MAX_NAME_BYTES {
                return Err(Detect::Malformed);
            }
            labels.push(ascii_label(&data[off + 1..off + 1 + len])?);
            off += 1 + len;
        }
    }
}

/// 域名标签归一化为小写：大小写不影响解析结果，但会让域名维度的统计裂成两桶。
fn ascii_label(b: &[u8]) -> Result<String, Detect> {
    let s = std::str::from_utf8(b).map_err(|_| Detect::Malformed)?;
    if !s.chars().all(|c| c.is_ascii()) {
        return Err(Detect::Malformed);
    }
    Ok(s.to_ascii_lowercase())
}

/// 供框架调用的统一入口。
pub fn detect(payload: &[u8]) -> Detect {
    match parse(payload) {
        Ok(m) => Detect::Hit(m.into_detection()),
        Err(e) => e,
    }
}

impl DnsMessage {
    pub fn into_detection(self) -> Detection {
        let mut d = Detection::new(
            super::types::AppId::Dns,
            Confidence::High,
            "dns.header: HEADER 常量自洽且 QUESTION 段可完整解析",
        );
        d.qname = self.qname;
        d.qtype = Some(self.qtype);
        d.qclass = Some(self.qclass);
        // RCODE 只在响应上写：查询报文的这一段是保留位且恒 0，
        // 写成 0 等于宣称"这次查询没有错误"，而它根本不是"一次回答"。
        if self.is_response {
            d.rcode = Some(self.rcode);
        }
        d.answer_ips = self.answer_ips;
        d.ptr_depth = Some(self.ptr_depth);
        d.edns0_udp_size = self.edns0_udp_size;
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclic_pointer_terminates() {
        // 自指指针（0xC0 0x0C 指向自己所在的偏移 12）。
        // 若实现没有跳数上限，这个 19 字节的报文会让进程转死 —— 用例存在的唯一目的就是证明不会。
        let mut msg = Vec::new();
        msg.extend_from_slice(&0x9999u16.to_be_bytes());
        msg.push(0x01);
        msg.push(0x00); // flags: QUERY
        msg.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        msg.extend_from_slice(&0u16.to_be_bytes()); // ancount
        msg.extend_from_slice(&0u16.to_be_bytes()); // nscount
        msg.extend_from_slice(&0u16.to_be_bytes()); // arcount
        msg.extend_from_slice(&[0xC0, 0x0C, 0x00]); // 名字：指针指向偏移 12（自己）
        msg.extend_from_slice(&1u16.to_be_bytes()); // qtype
        msg.extend_from_slice(&1u16.to_be_bytes()); // qclass
        assert_eq!(parse(&msg), Err(Detect::Malformed));
    }

    #[test]
    fn opcode_out_of_range_is_rejected_not_dns() {
        let mut msg = vec![0u8; DNS_HEADER + 4];
        msg[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        msg[2..4].copy_from_slice(&0x0Fu16.to_be_bytes()); // opcode=15
        assert_eq!(parse(&msg), Err(Detect::Rejected));
    }

    #[test]
    fn short_header_is_need_more() {
        assert_eq!(parse(&[0x12, 0x34, 0x01]), Err(Detect::NeedMore));
    }

    #[test]
    fn name_after_pointer_reports_the_origin_end_not_the_target_end() {
        // 这个用例守的是一个真实踩过的坑：名字由压缩指针构成时，
        // "名字之后的下一个字节"必须是**指针字段之后**（原始位置），
        // 而不是"跟着指针读完后的位置"。
        //
        // 报文（偏移标注）：
        //   12: 07 'example' 03 'com' 00   ← QUESTION 的 QNAME，结束于 24
        //   24: 00 01 (QTYPE) 00 01 (QCLASS)
        //   28: C0 0C (指回 12) 00 01 00 01 ...
        // 在 28 处解析名字：读完是 "example.com"，但下一个字节是 30（指针之后），
        // 不是 24。返回 24 的话，调用方会把 QTYPE/QCLASS 当成记录的 TYPE/CLASS 读，
        // 于是资源记录全部错位 —— 而报文本身完全合法。
        let mut msg = vec![0u8; DNS_HEADER];
        msg.extend_from_slice(b"\x07example\x03com\x00");
        msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE
        msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS
        let ptr_at = msg.len();
        msg.extend_from_slice(&[0xC0, 0x0C]); // 名字：指向 12
        msg.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        msg.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        msg.extend_from_slice(&[0u8; 4]); // TTL
        msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        msg.extend_from_slice(&[93, 184, 216, 34]);

        let (name, after, ptr_hops) = parse_name(&msg, ptr_at).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(after, ptr_at + 2, "指针名字的结束位置应为指针字段之后");
        assert_eq!(ptr_hops, 1);
    }

    #[test]
    fn response_without_edns0_yields_none_not_zero() {
        // "这条报文没有 EDNS0" 与 "EDNS0 声明的上限是 0" 是两件事：
        // 后者在协议上没有意义（0 字节的 UDP 载荷荒谬），拿它当缺省值会污染统计。
        let mut msg = vec![0u8; DNS_HEADER];
        msg.extend_from_slice(b"\x01a\x00");
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg[5] = 1; // qdcount = 1
        assert_eq!(parse(&msg).unwrap().edns0_udp_size, None);
    }

    #[test]
    fn query_never_reports_rcode() {
        // 查询报文的 RCODE 段是保留位：不产出该属性，而不是产出 0。
        let mut msg = vec![0u8; DNS_HEADER];
        msg[5] = 1; // qdcount = 1
        msg.extend_from_slice(b"\x01a\x00");
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let d = parse(&msg).unwrap().into_detection();
        assert!(d.rcode.is_none());
        assert_eq!(d.qclass, Some(1));
    }
}
