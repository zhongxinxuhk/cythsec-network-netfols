//! Low-cardinality carrier header candidates only. No SNI, ALPN, CID, domain or app extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    TlsRecord,
    QuicLongHeader,
}
pub fn classify(proto: u8, p: &[u8], declared_len: usize) -> Option<Carrier> {
    if proto == 6
        && p.len() >= 5
        && (20..=23).contains(&p[0])
        && p[1] == 3
        && (1..=3).contains(&p[2])
    {
        let len = usize::from(u16::from_be_bytes([p[3], p[4]]));
        if (1..=18432).contains(&len) && 5 + len <= declared_len && 5 + len <= p.len() {
            return Some(Carrier::TlsRecord);
        }
    }
    if proto != 17 || p.len() < 7 || p[0] & 0xc0 != 0xc0 {
        return None;
    }
    let captured_len = p.len();
    let p = &p[..p.len().min(128)];
    let version = u32::from_be_bytes(p[1..5].try_into().ok()?);
    if ![1, 0x6b3343cf].contains(&version) {
        return None;
    }
    let dcid = usize::from(p[5]);
    if dcid > 20 {
        return None;
    }
    let mut o = 6 + dcid;
    let scid = usize::from(*p.get(o)?);
    if scid > 20 {
        return None;
    }
    o += 1 + scid;
    if o > p.len() {
        return None;
    }
    let kind = (p[0] >> 4) & 3;
    let initial = if version == 1 { 0 } else { 1 };
    let retry = if version == 1 { 3 } else { 0 };
    if kind == retry {
        return None;
    }
    if kind == initial {
        let len = varint(p, &mut o)?;
        o = o.checked_add(len)?;
        if o > p.len() {
            return None;
        }
    }
    let n = varint(p, &mut o)?;
    if n < 17 || o.checked_add(n)? > declared_len || o.checked_add(n)? > captured_len {
        return None;
    }
    Some(Carrier::QuicLongHeader)
}
fn varint(p: &[u8], o: &mut usize) -> Option<usize> {
    let first = *p.get(*o)?;
    let n = 1usize << (first >> 6);
    let bytes = p.get(*o..o.checked_add(n)?)?;
    let mut v = u64::from(first & 63);
    for b in &bytes[1..] {
        v = (v << 8) | u64::from(*b);
    }
    *o += n;
    usize::try_from(v).ok()
}
