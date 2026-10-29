//! Bounded DHCPv4 visible messages (RFC 2131/2132/3396), without lease inference.
use std::collections::BTreeMap;

use super::{AppId, Confidence, Detect, Detection};

const FIXED: usize = 236;
const COOKIE: [u8; 4] = [99, 130, 83, 99];
const MAX_BYTES: usize = 4096;
const MAX_OPTIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub op: u8,
    pub message_type: u8,
    pub xid: u32,
    pub hardware_type: u8,
    pub client_hardware: Vec<u8>,
    pub client_ip: [u8; 4],
    pub your_ip: [u8; 4],
    pub server_ip: [u8; 4],
    pub relay_ip: [u8; 4],
    pub requested_ip: Option<[u8; 4]>,
    pub server_identifier: Option<[u8; 4]>,
    pub lease_seconds: Option<u32>,
    /// Raw advertised bytes, not verified host identity or device classification.
    pub host_name: Option<Vec<u8>>,
    pub vendor_class: Option<Vec<u8>>,
    pub client_identifier: Option<Vec<u8>>,
}

pub fn has_cookie(payload: &[u8]) -> bool {
    payload.get(FIXED..FIXED + 4) == Some(COOKIE.as_slice())
}

#[derive(Default)]
struct Options {
    values: BTreeMap<u8, Vec<u8>>,
    count: usize,
}
impl Options {
    fn scan(&mut self, data: &[u8], fixed_field: bool) -> Result<(), Detect> {
        let incomplete = || {
            if fixed_field {
                Detect::Malformed
            } else {
                Detect::NeedMore
            }
        };
        let mut at = 0;
        while let Some(&code) = data.get(at) {
            at += 1;
            match code {
                0 => continue,
                255 => return Ok(()),
                _ => {}
            }
            self.count += 1;
            if self.count > MAX_OPTIONS {
                return Err(Detect::NeedMore); // Inspection budget, not malformed traffic.
            }
            let length = usize::from(*data.get(at).ok_or_else(incomplete)?);
            at += 1;
            let value = data.get(at..at + length).ok_or_else(incomplete)?;
            at += length;
            if code == 52 && fixed_field {
                return Err(Detect::Malformed); // No recursive overload declarations.
            }
            if matches!(code, 12 | 50..=54 | 60 | 61) {
                self.values
                    .entry(code)
                    .or_default()
                    .extend_from_slice(value);
            }
        }
        Err(incomplete()) // END is required in each selected option area.
    }

    fn fixed<const N: usize>(&self, code: u8) -> Result<Option<[u8; N]>, Detect> {
        self.values
            .get(&code)
            .map(|v| v.as_slice().try_into().map_err(|_| Detect::Malformed))
            .transpose()
    }
}

/// Parse one DHCP prefix. A BOOTP cookie alone is insufficient: option 53 and END are required.
pub fn parse(payload: &[u8]) -> Result<Message, Detect> {
    if payload.len() < FIXED + 4 {
        if payload.first().is_some_and(|op| !matches!(op, 1 | 2)) {
            return Err(Detect::Rejected);
        }
        if payload.len() > FIXED && !COOKIE.starts_with(&payload[FIXED..]) {
            return Err(Detect::Rejected);
        }
        return Err(Detect::NeedMore);
    }
    if !has_cookie(payload) {
        return Err(Detect::Rejected);
    }
    if !matches!(payload[0], 1 | 2) || payload[2] > 16 {
        return Err(Detect::Malformed);
    }
    if payload.len() > MAX_BYTES {
        return Err(Detect::NeedMore);
    }
    let mut options = Options::default();
    options.scan(&payload[FIXED + 4..], false)?;
    let overload = options.fixed::<1>(52)?.map(|v| v[0]);
    if overload.is_some_and(|v| !(1..=3).contains(&v)) {
        return Err(Detect::Malformed);
    }
    // RFC 3396 logical order: options, file, sname (not physical field order).
    if overload.is_some_and(|v| v & 1 != 0) {
        options.scan(&payload[108..236], true)?;
    }
    if overload.is_some_and(|v| v & 2 != 0) {
        options.scan(&payload[44..108], true)?;
    }
    let Some([message_type]) = options.fixed::<1>(53)? else {
        return Err(Detect::Rejected); // Plain BOOTP is outside this recognizer.
    };
    if !(1..=8).contains(&message_type) {
        return Err(Detect::Rejected); // Extensions remain unknown, never invented as a base type.
    }
    let response = matches!(message_type, 2 | 5 | 6);
    if response != (payload[0] == 2) {
        return Err(Detect::Malformed);
    }
    let requested_ip = options.fixed::<4>(50)?;
    let server_identifier = options.fixed::<4>(54)?;
    let lease_seconds = options.fixed::<4>(51)?.map(u32::from_be_bytes);
    if options.values.get(&61).is_some_and(|v| v.len() < 2)
        || [12, 60]
            .iter()
            .any(|code| options.values.get(code).is_some_and(Vec::is_empty))
    {
        return Err(Detect::Malformed);
    }
    Ok(Message {
        op: payload[0],
        message_type,
        xid: u32::from_be_bytes(payload[4..8].try_into().unwrap()),
        hardware_type: payload[1],
        client_hardware: payload[28..28 + usize::from(payload[2])].to_vec(),
        client_ip: payload[12..16].try_into().unwrap(),
        your_ip: payload[16..20].try_into().unwrap(),
        server_ip: payload[20..24].try_into().unwrap(),
        relay_ip: payload[24..28].try_into().unwrap(),
        requested_ip,
        server_identifier,
        lease_seconds,
        host_name: options.values.remove(&12),
        vendor_class: options.values.remove(&60),
        client_identifier: options.values.remove(&61),
    })
}

pub fn detect(payload: &[u8]) -> Detect {
    match parse(payload) {
        Ok(_) => Detect::Hit(Detection::new(
            AppId::Dhcpv4,
            Confidence::High,
            "dhcpv4: BOOTP header, magic cookie, message type and bounded options; not a verified lease",
        )),
        Err(verdict) => verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::{identify, Outcome};

    fn packet(kind: u8, opts: &[u8]) -> Vec<u8> {
        let mut p = vec![0; FIXED];
        p[..3].copy_from_slice(&[if matches!(kind, 2 | 5 | 6) { 2 } else { 1 }, 1, 6]);
        p[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        p.extend_from_slice(&COOKIE);
        p.extend_from_slice(&[53, 1, kind]);
        p.extend_from_slice(opts);
        p.push(255);
        p
    }

    #[test]
    fn message_types_fields_and_transport() {
        for kind in 1..=8 {
            let p = packet(
                kind,
                &[
                    50, 4, 192, 0, 2, 9, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 0x0e, 0x10,
                ],
            );
            let m = parse(&p).unwrap();
            assert_eq!((m.message_type, m.xid), (kind, 0x12345678));
            assert_eq!(m.requested_ip, Some([192, 0, 2, 9]));
            assert_eq!(m.server_identifier, Some([192, 0, 2, 1]));
            assert_eq!(m.lease_seconds, Some(3600));
            for port in [67, 68, 45678] {
                assert!(
                    matches!(identify(&p, 17, port), Outcome::Identified(d) if d.app == AppId::Dhcpv4)
                );
            }
            assert!(
                !matches!(identify(&p, 6, 67), Outcome::Identified(d) if d.app == AppId::Dhcpv4)
            );
        }
    }

    #[test]
    fn overload_concatenation_keeps_field_boundaries() {
        let mut p = packet(5, &[52, 1, 3, 12, 1, b'a', 54, 2, 192, 0]);
        p[108..117].copy_from_slice(&[12, 1, b'b', 54, 2, 2, 1, 0, 255]);
        p[44..48].copy_from_slice(&[12, 1, b'c', 255]);
        let m = parse(&p).unwrap();
        assert_eq!(m.host_name.as_deref(), Some(b"abc".as_slice()));
        assert_eq!(m.server_identifier, Some([192, 0, 2, 1]));
        p[108] = 54;
        p[109] = 127; // Cannot borrow a value from the main option area.
        assert_eq!(parse(&p), Err(Detect::Malformed));
    }

    #[test]
    fn truncation_negative_and_budget_semantics() {
        let p = packet(1, &[]);
        for n in 0..p.len() {
            assert_eq!(parse(&p[..n]), Err(Detect::NeedMore), "cut={n}");
        }
        let mut no_cookie = p.clone();
        no_cookie[236] = 0;
        assert_eq!(parse(&no_cookie), Err(Detect::Rejected));
        let mut bootp = p[..240].to_vec();
        bootp.push(255);
        assert_eq!(parse(&bootp), Err(Detect::Rejected));
        for opts in [&[53, 1, 1][..], &[54, 3, 1, 2, 3], &[52, 1, 4], &[61, 1, 1]] {
            assert_eq!(parse(&packet(1, opts)), Err(Detect::Malformed));
        }
        let mut wrong_op = p.clone();
        wrong_op[0] = 2;
        assert_eq!(parse(&wrong_op), Err(Detect::Malformed));
        wrong_op[0] = 1;
        wrong_op[2] = 17;
        assert_eq!(parse(&wrong_op), Err(Detect::Malformed));
        assert_eq!(parse(&packet(9, &[])), Err(Detect::Rejected));
        let mut large = p.clone();
        large.resize(MAX_BYTES + 1, 0);
        assert_eq!(parse(&large), Err(Detect::NeedMore));
        let options = vec![200, 0].repeat(MAX_OPTIONS);
        assert_eq!(parse(&packet(1, &options)), Err(Detect::NeedMore));
        assert!(
            !matches!(identify(&[0; 300], 17, 67), Outcome::Identified(d) if d.app == AppId::Dhcpv4)
        );
    }
}
