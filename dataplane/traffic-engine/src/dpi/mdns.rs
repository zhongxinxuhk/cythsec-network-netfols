//! Bounded mDNS and common DNS-SD record decoding (RFC 6762/6763).
//! Transport context selects this parser; a name alone cannot establish mDNS.
use super::{dns::parse_mdns_name, AppId, Confidence, Detect, Detection};

const MAX_BYTES: usize = 8192;
const MAX_ITEMS: usize = 64;
const MAX_TXT_STRINGS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
    pub unicast_response: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Ptr(String),
    Cname(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Opaque character strings, not UTF-8 claims or verified device attributes.
    Txt(Vec<Vec<u8>>),
    Opaque(Vec<u8>),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
    pub cache_flush: bool,
    pub ttl_seconds: u32,
    pub section: Section,
    pub data: Data,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub is_response: bool,
    pub authoritative: bool,
    /// The wire TC bit, including known-answer continuation on queries.
    pub truncated: bool,
    pub questions: Vec<Question>,
    pub records: Vec<Record>,
}
fn be16(p: &[u8]) -> u16 {
    u16::from_be_bytes(p[..2].try_into().unwrap())
}
fn be32(p: &[u8]) -> u32 {
    u32::from_be_bytes(p[..4].try_into().unwrap())
}

/// Either a query to the mDNS service or a response from it (including legacy
/// unicast responses). Port context is only routing, never sufficient for a hit.
pub fn transport(payload: &[u8], src_port: u16, dst_port: u16) -> bool {
    dst_port == 5353 || src_port == 5353 && payload.get(2).is_some_and(|v| v & 0x80 != 0)
}

pub fn parse(payload: &[u8]) -> Result<Message, Detect> {
    if payload.len() > MAX_BYTES {
        return Err(Detect::NeedMore);
    }
    if payload.len() < 12 {
        return Err(Detect::NeedMore);
    }
    let flags = be16(&payload[2..]);
    if flags & 0x780f != 0 {
        return Err(Detect::Rejected);
    }
    let counts = [
        be16(&payload[4..]),
        be16(&payload[6..]),
        be16(&payload[8..]),
        be16(&payload[10..]),
    ];
    let total: usize = counts.iter().map(|v| usize::from(*v)).sum();
    if total == 0 {
        return Err(Detect::Rejected);
    }
    if total > MAX_ITEMS {
        return Err(Detect::NeedMore);
    }
    let mut message = Message {
        id: be16(payload),
        is_response: flags & 0x8000 != 0,
        authoritative: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        questions: Vec::new(),
        records: Vec::new(),
    };
    let mut off = 12;
    let mut txt_strings = 0;
    for _ in 0..counts[0] {
        let (name, after, _) = parse_mdns_name(payload, off)?;
        let head = payload.get(after..after + 4).ok_or(Detect::NeedMore)?;
        let record_type = be16(head);
        let raw_class = be16(&head[2..]);
        if record_type == 0 || raw_class & 0x7fff == 0 {
            return Err(Detect::Malformed);
        }
        message.questions.push(Question {
            name,
            record_type,
            class: raw_class & 0x7fff,
            unicast_response: raw_class & 0x8000 != 0,
        });
        off = after + 4;
    }
    for (index, section) in [Section::Answer, Section::Authority, Section::Additional]
        .into_iter()
        .enumerate()
    {
        for _ in 0..counts[index + 1] {
            let (name, after, _) = parse_mdns_name(payload, off)?;
            let head = payload.get(after..after + 10).ok_or(Detect::NeedMore)?;
            let record_type = be16(head);
            let raw_class = be16(&head[2..]);
            if record_type == 0 || record_type != 41 && raw_class & 0x7fff == 0 {
                return Err(Detect::Malformed);
            }
            let start = after + 10;
            let end = start + usize::from(be16(&head[8..]));
            let value = payload.get(start..end).ok_or(Detect::NeedMore)?;
            let data = match record_type {
                1 => Data::A(value.try_into().map_err(|_| Detect::Malformed)?),
                28 => Data::Aaaa(value.try_into().map_err(|_| Detect::Malformed)?),
                5 => Data::Cname(rdata_name(payload, start, end)?),
                12 => Data::Ptr(rdata_name(payload, start, end)?),
                33 => {
                    if value.len() < 7 {
                        return Err(Detect::Malformed);
                    }
                    Data::Srv {
                        priority: be16(value),
                        weight: be16(&value[2..]),
                        port: be16(&value[4..]),
                        target: rdata_name(payload, start + 6, end)?,
                    }
                }
                16 => {
                    let mut strings = Vec::new();
                    let mut at = 0;
                    while at < value.len() {
                        if txt_strings == MAX_TXT_STRINGS {
                            return Err(Detect::NeedMore);
                        }
                        txt_strings += 1;
                        let length = usize::from(value[at]);
                        at += 1;
                        strings.push(
                            value
                                .get(at..at + length)
                                .ok_or(Detect::Malformed)?
                                .to_vec(),
                        );
                        at += length;
                    }
                    Data::Txt(strings)
                }
                _ => Data::Opaque(value.to_vec()),
            };
            message.records.push(Record {
                name,
                record_type,
                class: if record_type == 41 {
                    raw_class
                } else {
                    raw_class & 0x7fff
                },
                cache_flush: record_type != 41 && raw_class & 0x8000 != 0,
                ttl_seconds: be32(&head[4..]),
                section,
                data,
            });
            off = end;
        }
    }
    if off != payload.len() {
        return Err(Detect::Malformed);
    }
    Ok(message)
}
fn rdata_name(payload: &[u8], start: usize, end: usize) -> Result<String, Detect> {
    let (name, after, _) = parse_mdns_name(&payload[..end], start).map_err(|error| {
        if error == Detect::NeedMore {
            Detect::Malformed
        } else {
            error
        }
    })?;
    if after != end {
        return Err(Detect::Malformed);
    }
    Ok(name)
}
pub fn detect(payload: &[u8]) -> Detect {
    match parse(payload) {
        Ok(_) => Detect::Hit(Detection::new(AppId::Mdns, Confidence::Medium,
            "mdns: UDP service context and bounded DNS records; locality and advertised identity not verified")),
        Err(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::{identify, identify_with_ports, Outcome};

    fn name(value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in value.split('.') {
            out.push(label.len() as u8);
            out.extend(label.as_bytes());
        }
        out.push(0);
        out
    }
    fn header(flags: u16, q: u16, a: u16, ns: u16, ar: u16) -> Vec<u8> {
        [0, flags, q, a, ns, ar]
            .into_iter()
            .flat_map(u16::to_be_bytes)
            .collect()
    }
    fn question(value: &str, kind: u16, class: u16) -> Vec<u8> {
        let mut p = name(value);
        p.extend(kind.to_be_bytes());
        p.extend(class.to_be_bytes());
        p
    }
    fn record(owner: &[u8], kind: u16, class: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
        let mut p = owner.to_vec();
        p.extend(kind.to_be_bytes());
        p.extend(class.to_be_bytes());
        p.extend(ttl.to_be_bytes());
        p.extend((data.len() as u16).to_be_bytes());
        p.extend(data);
        p
    }
    fn query() -> Vec<u8> {
        let mut p = header(0, 1, 0, 0, 0);
        p.extend(question("Host.local", 1, 0x8001));
        p
    }

    #[test]
    fn multi_question_qu_and_transport_context() {
        let mut p = header(0x0200, 2, 0, 0, 0);
        p.extend(question("Host.local", 1, 0x8001));
        p.extend([0xc0, 0x0c, 0, 28, 0, 1]);
        let m = parse(&p).unwrap();
        assert_eq!(m.questions.len(), 2);
        assert!(m.truncated);
        assert_eq!(m.questions[1].name, "Host.local");
        assert!(m.questions[0].unicast_response);
        assert!(!m.questions[1].unicast_response);
        assert_eq!(m.questions[0].class, 1);
        assert!(matches!(identify(&p, 17, 5353), Outcome::Identified(d) if d.app == AppId::Mdns));
        assert!(!matches!(identify(&p, 6, 5353), Outcome::Identified(d) if d.app == AppId::Mdns));
        assert!(!matches!(identify(&p, 17, 53), Outcome::Identified(d) if d.app == AppId::Mdns));
        assert!(
            !matches!(identify_with_ports(&p, 17, 5353, 53), Outcome::Identified(d) if d.app == AppId::Mdns)
        );
    }

    #[test]
    fn unsolicited_records_dns_sd_and_goodbye() {
        let owner = name("Printer.local");
        let mut p = header(0x8400, 0, 1, 1, 3);
        p.extend(record(&owner, 1, 0x8001, 0, &[192, 0, 2, 9]));
        p.extend(record(&[0xc0, 0x0c], 28, 0x8001, 120, &[0x20; 16]));
        p.extend(record(
            &name("_ipp._tcp.local"),
            12,
            1,
            4500,
            &name("Office Printer._ipp._tcp.local"),
        ));
        let mut srv = vec![0, 1, 0, 2, 2, 119];
        srv.extend([0xc0, 0x0c]);
        p.extend(record(
            &name("Office Printer._ipp._tcp.local"),
            33,
            0x8001,
            120,
            &srv,
        ));
        p.extend(record(
            &name("Office Printer._ipp._tcp.local"),
            16,
            0x8001,
            120,
            b"\x03a=b\x00",
        ));
        let m = parse(&p).unwrap();
        assert!(m.questions.is_empty());
        assert!(m.is_response);
        assert_eq!(m.records[0].ttl_seconds, 0);
        assert_eq!(m.records[0].class, 1);
        assert!(m.records[0].cache_flush);
        assert_eq!(m.records[0].data, Data::A([192, 0, 2, 9]));
        assert_eq!(m.records[1].data, Data::Aaaa([0x20; 16]));
        assert_eq!(m.records[1].section, Section::Authority);
        assert_eq!(
            m.records[2].data,
            Data::Ptr("Office Printer._ipp._tcp.local".into())
        );
        assert_eq!(
            m.records[3].data,
            Data::Srv {
                priority: 1,
                weight: 2,
                port: 631,
                target: "Printer.local".into()
            }
        );
        assert_eq!(m.records[4].data, Data::Txt(vec![b"a=b".to_vec(), vec![]]));
        assert!(
            matches!(identify_with_ports(&p, 17, 5353, 40000), Outcome::Identified(d) if d.app == AppId::Mdns)
        );
    }

    #[test]
    fn utf8_and_shared_dns_name_contract() {
        let mut p = header(0, 1, 0, 0, 0);
        p.extend(question("打印机.local", 255, 1));
        assert_eq!(parse(&p).unwrap().questions[0].name, "打印机.local");
        assert!(matches!(
            super::super::dns::parse(&p),
            Err(Detect::Malformed)
        ));
        let mut p = header(0, 1, 0, 0, 0);
        p.extend([3, b'A', b'.', b'B', 0, 0, 1, 0, 1]);
        assert_eq!(parse(&p).unwrap().questions[0].name, "A\\046B");
        let q = query();
        assert_eq!(
            super::super::dns::parse(&q).unwrap().qname.as_deref(),
            Some("host.local")
        );
    }

    #[test]
    fn truncated_rdata_compression_loops_and_budgets() {
        let p = query();
        for n in 0..p.len() {
            assert!(!matches!(parse(&p[..n]), Ok(_)), "cut={n}");
        }
        let mut cycle = header(0, 1, 0, 0, 0);
        cycle.extend([0xc0, 0x0c, 0, 1, 0, 1]);
        assert_eq!(parse(&cycle), Err(Detect::Malformed));
        let mut bad = header(0x8400, 0, 2, 0, 0);
        bad.extend(record(&name("Host.local"), 12, 1, 120, &[3, b'a']));
        bad.extend(record(&name("Other.local"), 1, 1, 120, &[192, 0, 2, 1]));
        assert_eq!(parse(&bad), Err(Detect::Malformed));
        let mut bad_txt = header(0x8400, 0, 1, 0, 0);
        bad_txt.extend(record(&name("Host.local"), 16, 1, 120, b"\x04ab"));
        assert_eq!(parse(&bad_txt), Err(Detect::Malformed));
        let mut txt_budget = header(0x8400, 0, 1, 0, 0);
        txt_budget.extend(record(
            &name("Host.local"),
            16,
            1,
            120,
            &[0; MAX_TXT_STRINGS + 1],
        ));
        assert_eq!(parse(&txt_budget), Err(Detect::NeedMore));
        assert_eq!(parse(&header(0, 65, 0, 0, 0)), Err(Detect::NeedMore));
        assert_eq!(parse(&vec![0; MAX_BYTES + 1]), Err(Detect::NeedMore));
        assert_eq!(parse(&header(0, 0, 0, 0, 0)), Err(Detect::Rejected));
        let mut trailing = query();
        trailing.push(0);
        assert_eq!(parse(&trailing), Err(Detect::Malformed));
    }
}
