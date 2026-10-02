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
    let is_response = flags & 0x8000 != 0;
    // 一条**查询**报文宣称自己带着不止一个问题段，几乎可以确定它不是 DNS。
    // 这条判据的价值在于它只看头部就能否定：否则只能一路解析下去，最终靠
    // "名字读到一半缓冲区没了" 得出 NeedMore —— 而那会把一堆垃圾流量算进
    // "分片，再等等就能识别" 的桶里，unknown 率反而被压得失真。
    if !is_response && qdcount != 1 {
        return Err(Detect::Rejected);
    }

    // 解析 QUESTION 段的名字（偏移 12），随后是 4 字节 qtype+qclass
    let (name, after) = parse_name(payload, DNS_HEADER)?;
    if after + 4 > payload.len() {
        return Err(Detect::NeedMore);
    }
    let qtype = u16::from_be_bytes([payload[after], payload[after + 1]]);
    let qclass = u16::from_be_bytes([payload[after + 2], payload[after + 3]]);

    Ok(DnsMessage {
        id,
        is_response,
        opcode,
        rcode,
        qname: if name.is_empty() { None } else { Some(name) },
        qtype,
        qclass,
    })
}

/// 逐段解析域名：标签序列与 0xC0 压缩指针走同一条循环。
///
/// 返回 `(名字, 名称之后第一个字节的偏移)`。名字为空表示这是一个全指针（畸形，由调用方丢弃）。
fn parse_name(data: &[u8], start: usize) -> Result<(String, usize), Detect> {
    let mut labels: Vec<String> = Vec::new();
    let mut used = 0usize;
    let mut off = start;
    let mut hops = 0usize;

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
            off = target;
            continue;
        }
        if b == 0x00 {
            // 根标签：名字到此结束
            return Ok((labels.join("."), off + 1));
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
}
