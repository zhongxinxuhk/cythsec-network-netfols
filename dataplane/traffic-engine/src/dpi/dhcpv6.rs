//! Bounded DHCPv6 message structures (RFC 9915); no lease or identity attestation.
use super::{AppId, Confidence, Detect, Detection};

const MAX_BYTES: usize = 4096;
const MAX_OPTIONS: usize = 256;
const MAX_RELAYS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub address: [u8; 16],
    pub preferred_seconds: u32,
    pub valid_seconds: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    pub address: [u8; 16],
    pub length: u8,
    pub preferred_seconds: u32,
    pub valid_seconds: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityAssociation {
    pub kind: u16,
    pub iaid: u32,
    pub t1_seconds: u32,
    pub t2_seconds: u32,
    pub addresses: Vec<Address>,
    pub prefixes: Vec<Prefix>,
    pub status_code: Option<u16>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub hop_count: u8,
    pub link_address: [u8; 16],
    pub peer_address: [u8; 16],
    pub interface_id: Option<Vec<u8>>,
    pub inner: Box<Message>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub message_type: u8,
    /// Relay headers have no transaction ID. The inner message retains its own.
    pub transaction_id: Option<u32>,
    /// Opaque DUIDs, including future types. Never derive a MAC or owner from them.
    pub client_id: Option<Vec<u8>>,
    pub server_id: Option<Vec<u8>>,
    pub requested_options: Vec<u16>,
    pub elapsed_centiseconds: Option<u16>,
    pub status_code: Option<u16>,
    pub associations: Vec<IdentityAssociation>,
    pub relay: Option<Relay>,
}
impl Message {
    fn new(message_type: u8) -> Self {
        Self {
            message_type,
            transaction_id: None,
            client_id: None,
            server_id: None,
            requested_options: Vec::new(),
            elapsed_centiseconds: None,
            status_code: None,
            associations: Vec::new(),
            relay: None,
        }
    }
}

pub fn is_message_type(payload: &[u8]) -> bool {
    payload.first().is_some_and(|v| (1..=13).contains(v))
}
fn be16(data: &[u8]) -> u16 {
    u16::from_be_bytes(data[..2].try_into().unwrap())
}
fn be32(data: &[u8]) -> u32 {
    u32::from_be_bytes(data[..4].try_into().unwrap())
}
fn incomplete(complete: bool) -> Detect {
    if complete {
        Detect::Malformed
    } else {
        Detect::NeedMore
    }
}

/// Every nested option/message shares one option budget. Length-delimited children
/// are complete slices: an overrun cannot be repaired with bytes from a sibling.
fn options<'a>(
    mut data: &'a [u8],
    left: &mut usize,
    complete: bool,
) -> Result<Vec<(u16, &'a [u8])>, Detect> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if *left == 0 {
            return Err(Detect::NeedMore);
        }
        if data.len() < 4 {
            return Err(incomplete(complete));
        }
        *left -= 1;
        let code = be16(data);
        let length = usize::from(be16(&data[2..]));
        let value = data
            .get(4..4 + length)
            .ok_or_else(|| incomplete(complete))?;
        if matches!(code, 1 | 2 | 6 | 7 | 8 | 9 | 11 | 13 | 14 | 18 | 19 | 20)
            && out.iter().any(|(previous, _)| *previous == code)
        {
            return Err(Detect::Malformed);
        }
        out.push((code, value));
        data = &data[4 + length..];
    }
    Ok(out)
}
fn duid(data: &[u8]) -> Result<Vec<u8>, Detect> {
    if !(3..=130).contains(&data.len()) {
        return Err(Detect::Malformed);
    }
    Ok(data.to_vec())
}
fn status(data: &[u8]) -> Result<u16, Detect> {
    if data.len() < 2 {
        return Err(Detect::Malformed);
    }
    Ok(be16(data))
}
fn association(kind: u16, data: &[u8], left: &mut usize) -> Result<IdentityAssociation, Detect> {
    if data.len() < 12 {
        return Err(Detect::Malformed);
    }
    let mut ia = IdentityAssociation {
        kind,
        iaid: be32(data),
        t1_seconds: be32(&data[4..]),
        t2_seconds: be32(&data[8..]),
        addresses: Vec::new(),
        prefixes: Vec::new(),
        status_code: None,
    };
    if ia.t1_seconds != 0 && ia.t2_seconds != 0 && ia.t1_seconds > ia.t2_seconds {
        return Err(Detect::Malformed);
    }
    for (code, value) in options(&data[12..], left, true)? {
        match code {
            5 if kind == 3 => {
                if value.len() < 24 {
                    return Err(Detect::Malformed);
                }
                let preferred = be32(&value[16..]);
                let valid = be32(&value[20..]);
                if preferred > valid {
                    return Err(Detect::Malformed);
                }
                validate_leaf(&value[24..], left)?;
                ia.addresses.push(Address {
                    address: value[..16].try_into().unwrap(),
                    preferred_seconds: preferred,
                    valid_seconds: valid,
                });
            }
            26 if kind == 25 => {
                if value.len() < 25 || value[8] > 128 {
                    return Err(Detect::Malformed);
                }
                let preferred = be32(value);
                let valid = be32(&value[4..]);
                if preferred > valid {
                    return Err(Detect::Malformed);
                }
                validate_leaf(&value[25..], left)?;
                ia.prefixes.push(Prefix {
                    address: value[9..25].try_into().unwrap(),
                    length: value[8],
                    preferred_seconds: preferred,
                    valid_seconds: valid,
                });
            }
            13 => ia.status_code = Some(status(value)?),
            1..=6 | 9 | 25 | 26 => return Err(Detect::Malformed),
            _ => {}
        }
    }
    Ok(ia)
}
fn validate_leaf(data: &[u8], left: &mut usize) -> Result<(), Detect> {
    for (code, value) in options(data, left, true)? {
        match code {
            13 => {
                status(value)?;
            }
            1..=6 | 9 | 25 | 26 => return Err(Detect::Malformed),
            _ => {}
        }
    }
    Ok(())
}

pub fn parse(payload: &[u8]) -> Result<Message, Detect> {
    if payload.len() > MAX_BYTES {
        return Err(Detect::NeedMore);
    }
    let mut left = MAX_OPTIONS;
    parse_message(payload, 0, &mut left, false)
}
fn parse_message(
    payload: &[u8],
    depth: usize,
    left: &mut usize,
    complete: bool,
) -> Result<Message, Detect> {
    let Some(&kind) = payload.first() else {
        return Err(incomplete(complete));
    };
    if !(1..=13).contains(&kind) {
        return Err(Detect::Rejected);
    }
    let header = if kind >= 12 { 34 } else { 4 };
    if payload.len() < header {
        return Err(incomplete(complete));
    }
    let mut message = Message::new(kind);
    let parsed = options(&payload[header..], left, complete)?;
    if kind >= 12 {
        if depth >= MAX_RELAYS {
            return Err(Detect::NeedMore);
        }
        if payload[1] > 8 {
            return Err(Detect::Malformed);
        }
        let inner = parsed
            .iter()
            .find(|(code, _)| *code == 9)
            .ok_or(Detect::Rejected)?
            .1;
        let interface_id = parsed
            .iter()
            .find(|(code, _)| *code == 18)
            .map(|(_, v)| v.to_vec());
        message.relay = Some(Relay {
            hop_count: payload[1],
            link_address: payload[2..18].try_into().unwrap(),
            peer_address: payload[18..34].try_into().unwrap(),
            interface_id,
            inner: Box::new(parse_message(inner, depth + 1, left, true)?),
        });
        return Ok(message);
    }
    message.transaction_id = Some(u32::from_be_bytes([0, payload[1], payload[2], payload[3]]));
    let mut reconfigure = None;
    for (code, value) in parsed {
        match code {
            1 => message.client_id = Some(duid(value)?),
            2 => message.server_id = Some(duid(value)?),
            3 | 25 => {
                let ia = association(code, value, left)?;
                if message
                    .associations
                    .iter()
                    .any(|old| old.kind == ia.kind && old.iaid == ia.iaid)
                {
                    return Err(Detect::Malformed);
                }
                message.associations.push(ia);
            }
            6 => {
                if value.is_empty() || value.len() % 2 != 0 {
                    return Err(Detect::Malformed);
                }
                message.requested_options = value.chunks_exact(2).map(be16).collect();
            }
            8 => {
                if value.len() != 2 {
                    return Err(Detect::Malformed);
                }
                message.elapsed_centiseconds = Some(be16(value));
            }
            13 => message.status_code = Some(status(value)?),
            14 | 20 if !value.is_empty() => return Err(Detect::Malformed),
            19 => {
                if value.len() != 1 || !matches!(value[0], 5 | 11) {
                    return Err(Detect::Malformed);
                }
                reconfigure = Some(value[0]);
            }
            5 | 9 | 26 => return Err(Detect::Malformed),
            _ => {} // Unknown and obsolete options carry no inferred capability.
        }
    }
    let client = message.client_id.is_some();
    let server = message.server_id.is_some();
    let invalid = match kind {
        1 | 4 | 6 => !client || server,
        2 | 3 | 5 | 8 | 9 => !client || !server,
        7 => !server,
        10 => !client || !server || reconfigure.is_none(),
        11 => !message.associations.is_empty(),
        _ => false,
    };
    if invalid {
        return Err(Detect::Rejected);
    }
    // Anonymous Information-request without an ORO has too little wire evidence.
    if !client && !server && message.requested_options.is_empty() {
        return Err(Detect::Rejected);
    }
    Ok(message)
}
pub fn detect(payload: &[u8]) -> Detect {
    match parse(payload) {
        Ok(_) => Detect::Hit(Detection::new(AppId::Dhcpv6, Confidence::High,
            "dhcpv6: bounded message/options and identifier or ORO evidence; not an authenticated lease")),
        Err(verdict) => verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::{identify, Outcome};

    fn option(code: u16, value: &[u8]) -> Vec<u8> {
        let mut out = code.to_be_bytes().to_vec();
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }
    fn packet(kind: u8) -> Vec<u8> {
        let mut p = vec![kind, 0x12, 0x34, 0x56];
        if kind != 11 {
            p.extend(option(1, &[0, 3, 0, 1, 2, 0, 0, 0, 0, 1]));
        }
        if matches!(kind, 2 | 3 | 5 | 7..=10) {
            p.extend(option(
                2,
                &[0, 4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            ));
        }
        if kind == 10 {
            p.extend(option(19, &[5]));
        }
        if kind == 11 {
            p.extend(option(6, &[0, 23, 0, 24]));
        }
        p
    }
    fn relay(kind: u8, inner: &[u8]) -> Vec<u8> {
        let mut p = vec![0; 34];
        p[0] = kind;
        p[17] = 1;
        p[33] = 2;
        p.extend(option(18, b"interface"));
        p.extend(option(9, inner));
        p
    }

    #[test]
    fn base_messages_duids_and_transport() {
        for kind in 1..=11 {
            let p = packet(kind);
            let m = parse(&p).unwrap();
            assert_eq!((m.message_type, m.transaction_id), (kind, Some(0x123456)));
            for port in [546, 547, 40000] {
                assert!(
                    matches!(identify(&p, 17, port), Outcome::Identified(d) if d.app == AppId::Dhcpv6)
                );
            }
            assert!(
                !matches!(identify(&p, 6, 547), Outcome::Identified(d) if d.app == AppId::Dhcpv6)
            );
        }
        let mut future = vec![1, 0, 0, 0];
        future.extend(option(1, &[0xfe, 0xdc, 1]));
        assert_eq!(parse(&future).unwrap().client_id, Some(vec![0xfe, 0xdc, 1]));
        assert_eq!(parse(&[11, 0, 0, 0]), Err(Detect::Rejected));
        assert!(!matches!(
            identify(&[1, 0, 0, 0], 17, 547),
            Outcome::Identified(_)
        ));
    }

    #[test]
    fn ia_na_and_pd_keep_fields_and_parent_boundaries() {
        let mut p = packet(7);
        let mut ia = [0x01020304u32, 60, 120]
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>();
        let mut addr = [0u8; 16].to_vec();
        addr[0] = 0x20;
        addr[1] = 1;
        addr[15] = 9;
        addr.extend(300u32.to_be_bytes());
        addr.extend(600u32.to_be_bytes());
        ia.extend(option(5, &addr));
        p.extend(option(3, &ia));
        let mut pd = [9u32, 60, 120]
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>();
        let mut prefix = 300u32.to_be_bytes().to_vec();
        prefix.extend(600u32.to_be_bytes());
        prefix.push(64);
        prefix.extend([0x20u8; 16]);
        pd.extend(option(26, &prefix));
        p.extend(option(25, &pd));
        let m = parse(&p).unwrap();
        assert_eq!(
            (
                m.associations[0].iaid,
                m.associations[0].t1_seconds,
                m.associations[0].t2_seconds
            ),
            (0x01020304, 60, 120)
        );
        assert_eq!(
            m.associations[0].addresses[0],
            Address {
                address: addr[..16].try_into().unwrap(),
                preferred_seconds: 300,
                valid_seconds: 600
            }
        );
        assert_eq!(m.associations[1].prefixes[0].length, 64);
        assert_eq!(m.associations[1].prefixes[0].address, [0x20; 16]);
        let mut broken = packet(7);
        ia.pop(); // IAADDR declares 24 bytes but only 23 are in its IA_NA.
        broken.extend(option(3, &ia));
        broken.extend(option(65000, &[0; 24]));
        assert_eq!(parse(&broken), Err(Detect::Malformed));
        let mut bad_lifetime = packet(7);
        addr[16..20].copy_from_slice(&601u32.to_be_bytes());
        let mut ia = vec![0; 12];
        ia.extend(option(5, &addr));
        bad_lifetime.extend(option(3, &ia));
        assert_eq!(parse(&bad_lifetime), Err(Detect::Malformed));
    }

    #[test]
    fn relay_encapsulation_and_global_budgets() {
        for kind in [12, 13] {
            let p = relay(kind, &packet(if kind == 12 { 1 } else { 7 }));
            let m = parse(&p).unwrap();
            assert_eq!(m.transaction_id, None);
            let r = m.relay.unwrap();
            assert_eq!(r.inner.transaction_id, Some(0x123456));
            assert_eq!((r.link_address[15], r.peer_address[15]), (1, 2));
            assert_eq!(r.interface_id, Some(b"interface".to_vec()));
        }
        let mut p = packet(1);
        for _ in 0..MAX_RELAYS {
            p = relay(12, &p);
        }
        assert!(parse(&p).is_ok());
        assert_eq!(parse(&relay(12, &p)), Err(Detect::NeedMore));
        let mut too_many = packet(1);
        for _ in 0..MAX_OPTIONS {
            too_many.extend(option(65000, &[]));
        }
        assert_eq!(parse(&relay(12, &too_many)), Err(Detect::NeedMore));
        let mut huge = packet(1);
        huge.resize(MAX_BYTES + 1, 0);
        assert_eq!(parse(&huge), Err(Detect::NeedMore));
        let mut bad = relay(12, &[1, 2, 3]);
        assert_eq!(parse(&bad), Err(Detect::Malformed));
        bad = relay(12, &packet(1));
        bad[1] = 9;
        assert_eq!(parse(&bad), Err(Detect::Malformed));
    }

    #[test]
    fn truncation_singletons_unknown_and_ia_validation() {
        let p = packet(1);
        for n in 0..p.len() {
            assert!(!matches!(parse(&p[..n]), Ok(_)), "cut={n}");
        }
        let mut duplicate = p.clone();
        duplicate.extend(option(1, &[0, 3, 1]));
        assert_eq!(parse(&duplicate), Err(Detect::Malformed));
        let mut invalid = p.clone();
        invalid.extend(option(6, &[0]));
        assert_eq!(parse(&invalid), Err(Detect::Malformed));
        invalid = p.clone();
        invalid.extend(option(2, &[0, 3, 1]));
        assert_eq!(parse(&invalid), Err(Detect::Rejected));
        invalid = p.clone();
        invalid.extend([0, 100, 255, 255]);
        assert_eq!(parse(&invalid), Err(Detect::NeedMore));
        assert_eq!(parse(&[99, 0, 0, 0]), Err(Detect::Rejected));
        let mut info = packet(11);
        info.extend(option(3, &[0; 12]));
        assert_eq!(parse(&info), Err(Detect::Rejected));
        let mut unknown = p;
        unknown.extend(option(65000, b"future"));
        assert!(parse(&unknown).is_ok());
    }
}
