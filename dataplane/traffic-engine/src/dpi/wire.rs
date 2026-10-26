//! Bounded structural recognizers. A match is a candidate, not authentication.
use crate::dpi::{self, Detect};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fact {
    pub id: &'static str,
    pub message: u16,
    pub local_id: u64,
    pub peer: u64,
}
impl Fact {
    fn new(id: &'static str, message: u16, local_id: u64, peer: u64) -> Self {
        Self {
            id,
            message,
            local_id,
            peer,
        }
    }
    /// Only narrowly specified request/reply pairs may promote structural evidence.
    pub fn confirms(self, response: Self) -> bool {
        if self.id != response.id {
            return false;
        }
        match self.id {
            "V021" => self.message == 1 && response.message == 2 && self.local_id == response.peer,
            "V004" => {
                self.message & 0x8000 == 0
                    && response.message == self.message | 0x8000
                    && self.local_id == response.local_id
                    && self.peer == 0
                    && response.peer != 0
            }
            "V003" => {
                self.message != 0xffff
                    && self.message == response.message
                    && self.local_id == response.local_id
                    && self.peer == 0
                    && response.peer != 0
            }
            "V017" | "V018" => {
                self.message == 7
                    && response.message == 8
                    && self.local_id == response.peer
                    && response.local_id != 0
            }
            "V008" => self.message == 1 && response.message == 2,
            "P001" => self.message == 1 && response.message == 2,
            "P002" => {
                self.message == 1
                    && response.message == 2
                    && response.local_id < 64
                    && self.local_id & (1 << response.local_id) != 0
            }
            _ => false,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Match(Fact),
    NeedMore,
    Malformed,
    NoMatch,
}
fn hit(id: &'static str) -> Verdict {
    Verdict::Match(Fact::new(id, 0, 0, 0))
}
fn be16(p: &[u8], n: usize) -> u16 {
    u16::from_be_bytes([p[n], p[n + 1]])
}
fn be32(p: &[u8], n: usize) -> u32 {
    u32::from_be_bytes(p[n..n + 4].try_into().unwrap())
}
fn be64(p: &[u8], n: usize) -> u64 {
    u64::from_be_bytes(p[n..n + 8].try_into().unwrap())
}
fn le32(p: &[u8], n: usize) -> u32 {
    u32::from_le_bytes(p[n..n + 4].try_into().unwrap())
}

/// Ports influence NAT-T demultiplexing only; no port alone returns a match.
pub fn inspect(p: &[u8], proto: u8, src_port: u16, dst_port: u16) -> Verdict {
    let r = inspect_standard(p, proto, src_port, dst_port);
    if matches!(r, Verdict::Match(_)) || proto != 6 {
        return r;
    }
    if let Detect::Hit(d) = dpi::tls::detect(p) {
        return Verdict::Match(Fact::new(
            "T022",
            1,
            u64::from(d.tls_version.unwrap_or(0)),
            0,
        ));
    }
    if let Detect::Hit(d) = dpi::http::detect(p) {
        return hit(if d.method.as_deref() == Some("CONNECT") {
            "P003"
        } else {
            "T009"
        });
    }
    r
}

/// Structural dispatch used by the existing DPI path without duplicating TLS/HTTP parsing.
pub fn inspect_standard(p: &[u8], proto: u8, src_port: u16, dst_port: u16) -> Verdict {
    if p.is_empty() {
        return Verdict::NeedMore;
    }
    match proto {
        50 => {
            if p.len() >= 8 && be32(p, 0) != 0 {
                hit("V001")
            } else {
                Verdict::NeedMore
            }
        }
        51 => ah(p),
        47 => gre(p),
        4 => inner_ip(p, 4),
        41 => inner_ip(p, 6),
        97 => {
            if p.len() < 16 {
                Verdict::NeedMore
            } else if p[0] == 0x30 && p[1] == 0 {
                hit("V013")
            } else {
                Verdict::NoMatch
            }
        }
        17 => {
            if (src_port == 4500 || dst_port == 4500) && p.starts_with(&[0, 0, 0, 0]) {
                return ike(&p[4..]);
            }
            let mut fallback = Verdict::NoMatch;
            for f in [
                wireguard as fn(&[u8]) -> Verdict,
                ike,
                l2tp,
                vxlan,
                geneve,
                dtls,
                quic,
            ] {
                let r = f(p);
                if matches!(r, Verdict::Match(_)) {
                    return r;
                }
                if r == Verdict::Malformed || fallback == Verdict::NoMatch {
                    fallback = r;
                }
            }
            let r = openvpn(p, false);
            if matches!(r, Verdict::Match(_)) {
                r
            } else if fallback != Verdict::NoMatch {
                fallback
            } else {
                r
            }
        }
        6 => {
            for f in [ssh as fn(&[u8]) -> Verdict, pptp, socks4, socks5] {
                let r = f(p);
                if !matches!(r, Verdict::NoMatch) {
                    return r;
                }
            }
            tlcp(p).or_else(|| openvpn(p, true))
        }
        _ => Verdict::NoMatch,
    }
}
impl Verdict {
    fn or_else(self, f: impl FnOnce() -> Self) -> Self {
        if self == Self::NoMatch {
            f()
        } else {
            self
        }
    }
}
fn wireguard(p: &[u8]) -> Verdict {
    if p.len() < 4 || p[1..4] != [0, 0, 0] || !(1..=4).contains(&p[0]) {
        return Verdict::NoMatch;
    }
    let expected = match p[0] {
        1 => 148,
        2 => 92,
        3 => 64,
        _ => 32,
    };
    if p.len() < expected {
        return Verdict::NeedMore;
    }
    if p[0] != 4 && p.len() != expected || p[0] == 4 && (p.len() - 32) % 16 != 0 {
        return Verdict::Malformed;
    }
    let index = le32(p, 4);
    let peer = if p[0] == 2 { le32(p, 8) } else { 0 };
    Verdict::Match(Fact::new("V021", p[0] as u16, index as u64, peer as u64))
}
fn ike(p: &[u8]) -> Verdict {
    if p.len() < 18 || ![0x10, 0x20].contains(&p[17]) {
        return Verdict::NoMatch;
    }
    if p.len() < 28 {
        return Verdict::NeedMore;
    }
    let v2 = p[17] == 0x20;
    let ex = p[18];
    if v2 && !(34..=37).contains(&ex) || !v2 && !(1..=6).contains(&ex) {
        return Verdict::NoMatch;
    }
    let total = be32(p, 24) as usize;
    if total < 28 || be64(p, 0) == 0 || (v2 && p[19] & !0x38 != 0) {
        return Verdict::Malformed;
    }
    if total > p.len() {
        return Verdict::NeedMore;
    }
    if total != p.len() {
        return Verdict::Malformed;
    }
    if be32(p, 20) != 0 {
        // Binding later messages needs a full exchange tracker; keep them candidates.
        return Verdict::Match(Fact::new(
            if v2 { "V004" } else { "V003" },
            0xffff,
            be64(p, 0),
            be64(p, 8),
        ));
    }
    if v2 && ex == 34 && (p[16] == 0 || total == 28) {
        return Verdict::Malformed;
    }
    // Encrypted IKEv1 or SK/SKF payloads are opaque, never parsed as plaintext.
    if !(!v2 && p[19] & 1 != 0) {
        let mut next = p[16];
        let mut off = 28;
        let mut count = 0;
        while next != 0 {
            count += 1;
            if count > 64 || off + 4 > total {
                return Verdict::Malformed;
            }
            let n = be16(p, off + 2) as usize;
            if n < 4 || off + n > total {
                return Verdict::Malformed;
            }
            let encrypted = v2 && (next == 46 || next == 53);
            next = if encrypted { 0 } else { p[off] };
            off += n;
        }
        if off != total {
            return Verdict::Malformed;
        }
    }
    let msg = u16::from(ex) | if v2 && p[19] & 0x20 != 0 { 0x8000 } else { 0 };
    Verdict::Match(Fact::new(
        if v2 { "V004" } else { "V003" },
        msg,
        be64(p, 0),
        be64(p, 8),
    ))
}
fn ah(p: &[u8]) -> Verdict {
    if p.len() < 12 {
        return Verdict::NeedMore;
    }
    let n = (usize::from(p[1]) + 2) * 4;
    if n < 12 || p[2..4] != [0, 0] || be32(p, 4) == 0 {
        return Verdict::Malformed;
    }
    if n > p.len() {
        Verdict::NeedMore
    } else {
        hit("V002")
    }
}
fn inner_ip(p: &[u8], version: u8) -> Verdict {
    let min = if version == 4 { 20 } else { 40 };
    if p.len() < min {
        return Verdict::NeedMore;
    }
    if p[0] >> 4 != version {
        return Verdict::NoMatch;
    }
    let (header, total) = if version == 4 {
        (usize::from(p[0] & 15) * 4, usize::from(be16(p, 2)))
    } else {
        (40, 40 + usize::from(be16(p, 4)))
    };
    if header < min || total < header {
        return Verdict::Malformed;
    }
    if p.len() < total {
        return Verdict::NeedMore;
    }
    hit(if version == 4 { "V010" } else { "V011" })
}
fn gre(p: &[u8]) -> Verdict {
    if p.len() < 4 {
        return Verdict::NeedMore;
    }
    let flags = be16(p, 0);
    let typ = be16(p, 2);
    if flags & 7 == 1 {
        // PPTP enhanced GRE: K mandatory, A/S optional; EtherType PPP.
        if typ != 0x880b || flags & 0x2000 == 0 || flags & !0x3081 != 0 {
            return Verdict::NoMatch;
        }
        let h =
            8 + if flags & 0x1000 != 0 { 4 } else { 0 } + if flags & 0x0080 != 0 { 4 } else { 0 };
        if p.len() < h {
            return Verdict::NeedMore;
        }
        return if h + usize::from(be16(p, 4)) <= p.len() {
            hit("V008")
        } else {
            Verdict::NeedMore
        };
    }
    if flags & !0xb000 != 0 || ![0x0800, 0x86dd, 0x6558].contains(&typ) {
        return Verdict::NoMatch;
    }
    let h = 4
        + if flags & 0x8000 != 0 { 4 } else { 0 }
        + if flags & 0x2000 != 0 { 4 } else { 0 }
        + if flags & 0x1000 != 0 { 4 } else { 0 };
    if p.len()
        < h + if typ == 0x86dd {
            40
        } else if typ == 0x0800 {
            20
        } else {
            14
        }
    {
        return Verdict::NeedMore;
    }
    if typ == 0x0800 && p[h] >> 4 != 4 || typ == 0x86dd && p[h] >> 4 != 6 {
        return Verdict::Malformed;
    }
    hit("V009")
}
fn l2tp(p: &[u8]) -> Verdict {
    if p.len() < 2 || p[1] & 15 != 2 || p[0] & 0x80 == 0 {
        return Verdict::NoMatch;
    }
    let flags = be16(p, 0);
    if flags & 0xc800 != 0xc800 || flags & !0xc802 != 0 {
        return Verdict::NoMatch;
    }
    if p.len() < 12 {
        return Verdict::NeedMore;
    }
    let n = usize::from(be16(p, 2));
    if n < 12 {
        return Verdict::Malformed;
    }
    if n > p.len() {
        return Verdict::NeedMore;
    }
    if n != p.len() {
        return Verdict::Malformed;
    }
    if n == 12 {
        return hit("V006");
    } // ZLB ACK
    let mut off = 12;
    let mut msg = 0;
    while off < n {
        if off + 6 > n {
            return Verdict::Malformed;
        }
        let a = be16(p, off);
        let len = usize::from(a & 0x3ff);
        if len < 6 || off + len > n {
            return Verdict::Malformed;
        }
        if off == 12 {
            if a & 0xc000 != 0x8000 || len != 8 || be16(p, off + 2) != 0 || be16(p, off + 4) != 0 {
                return Verdict::Malformed;
            }
            msg = be16(p, off + 6);
            if !(1..=16).contains(&msg) {
                return Verdict::Malformed;
            }
        }
        off += len;
    }
    Verdict::Match(Fact::new("V006", msg, be16(p, 4) as u64, be16(p, 8) as u64))
}
fn vxlan(p: &[u8]) -> Verdict {
    if p.len() < 8 || p[..4] != [8, 0, 0, 0] || p[7] != 0 {
        return Verdict::NoMatch;
    }
    if p.len() < 22 {
        return Verdict::NeedMore;
    }
    if ![0x0800, 0x86dd, 0x8100, 0x88a8, 0x0806].contains(&be16(p, 20)) {
        return Verdict::NoMatch;
    }
    hit("V014")
}
fn geneve(p: &[u8]) -> Verdict {
    if p.len() < 8
        || p[0] >> 6 != 0
        || p[1] & 0x3f != 0
        || p[7] != 0
        || ![0x6558, 0x0800, 0x86dd].contains(&be16(p, 2))
    {
        return Verdict::NoMatch;
    }
    let h = 8 + usize::from(p[0] & 0x3f) * 4;
    if p.len() < h {
        return Verdict::NeedMore;
    }
    let mut off = 8;
    let mut critical = false;
    while off < h {
        if off + 4 > h || p[off + 3] & 0xe0 != 0 {
            return Verdict::Malformed;
        }
        critical |= p[off + 2] & 0x80 != 0;
        off += 4 + usize::from(p[off + 3] & 0x1f) * 4;
        if off > h {
            return Verdict::Malformed;
        }
    }
    if critical != (p[1] & 0x40 != 0) {
        return Verdict::Malformed;
    }
    let inner = be16(p, 2);
    let min = if inner == 0x6558 {
        14
    } else if inner == 0x0800 {
        20
    } else {
        40
    };
    if p.len() < h + min {
        return Verdict::NeedMore;
    }
    if inner == 0x0800 && p[h] >> 4 != 4 || inner == 0x86dd && p[h] >> 4 != 6 {
        return Verdict::Malformed;
    }
    hit("V015")
}
fn openvpn(p: &[u8], tcp: bool) -> Verdict {
    let p = if tcp {
        if p.len() < 3 {
            return Verdict::NoMatch;
        }
        let n = usize::from(be16(p, 0));
        let op = p[2] >> 3;
        let reset_len = match op {
            7 => 14,
            8 => 26,
            _ => return Verdict::NoMatch,
        };
        if n != reset_len || p[2] & 7 != 0 {
            return Verdict::NoMatch;
        }
        if p.len() < n + 2 {
            return Verdict::NeedMore;
        }
        &p[2..n + 2]
    } else {
        p
    };
    if p.is_empty() || ![7, 8].contains(&(p[0] >> 3)) || p[0] & 7 != 0 {
        return Verdict::NoMatch;
    }
    if p.len() < 14 {
        return Verdict::NeedMore;
    }
    let ack = usize::from(p[9]);
    if ack > 8 || be64(p, 1) == 0 {
        return Verdict::NoMatch;
    }
    let h = 10 + ack * 4 + if ack > 0 { 8 } else { 0 } + 4;
    if p.len() < h {
        return Verdict::NeedMore;
    }
    if p.len() != h {
        return Verdict::NoMatch;
    } // Only explicit unauthenticated reset layout; no guessing HMAC sizes.
    let peer = if ack > 0 { be64(p, 10 + ack * 4) } else { 0 };
    if be32(p, h - 4) != 0
        || p[0] >> 3 == 7 && ack != 0
        || p[0] >> 3 == 8 && (ack != 1 || peer == 0)
    {
        return Verdict::NoMatch;
    }
    Verdict::Match(Fact::new(
        if tcp { "V018" } else { "V017" },
        u16::from(p[0] >> 3),
        be64(p, 1),
        peer,
    ))
}
fn ssh(p: &[u8]) -> Verdict {
    if !p.starts_with(b"SSH-") {
        return Verdict::NoMatch;
    }
    let Some(end) = p.windows(2).position(|s| s == b"\r\n") else {
        return if p.len() > 255 {
            Verdict::Malformed
        } else {
            Verdict::NeedMore
        };
    };
    if end + 2 > 255
        || !(p.starts_with(b"SSH-2.0-") || p.starts_with(b"SSH-1.99-"))
        || !p[..end].iter().all(|b| (32..=126).contains(b))
    {
        return Verdict::Malformed;
    }
    hit("T016")
}
fn pptp(p: &[u8]) -> Verdict {
    if p.len() < 8 || be16(p, 2) != 1 || be32(p, 4) != 0x1a2b3c4d {
        return Verdict::NoMatch;
    }
    if p.len() < 12 {
        return Verdict::NeedMore;
    }
    let n = usize::from(be16(p, 0));
    let m = be16(p, 8);
    let expected = match m {
        1 | 2 => 156,
        3 | 4 => 16,
        5 => 16,
        6 => 20,
        7 => 168,
        8 => 32,
        9 => 220,
        10 => 24,
        11 => 28,
        12 => 16,
        13 => 148,
        14 => 40,
        15 => 24,
        _ => return Verdict::Malformed,
    };
    if n != expected || be16(p, 10) != 0 {
        return Verdict::Malformed;
    }
    if p.len() < n {
        return Verdict::NeedMore;
    }
    if (m == 1 || m == 2) && be16(p, 12) != 0x0100 {
        return Verdict::Malformed;
    }
    if m == 2 && (p[14] != 1 || p[15] != 0) {
        return Verdict::NoMatch;
    }
    Verdict::Match(Fact::new("V008", m, 0, 0))
}
fn socks4(p: &[u8]) -> Verdict {
    if p.len() == 8 && p[0] == 0 && (90..=93).contains(&p[1]) {
        return Verdict::Match(Fact::new("P001", 2, 0, 0));
    }
    if p[0] != 4 || p.len() < 2 || ![1, 2].contains(&p[1]) {
        return Verdict::NoMatch;
    }
    if p.len() < 9 {
        return Verdict::NeedMore;
    }
    if be16(p, 2) == 0 {
        return Verdict::Malformed;
    }
    let Some(end) = p[8..].iter().position(|b| *b == 0) else {
        return Verdict::NeedMore;
    };
    if p[4..7] == [0, 0, 0] && p[7] != 0 {
        let d = 8 + end + 1;
        if d >= p.len() {
            return Verdict::NeedMore;
        }
        let Some(n) = p[d..].iter().position(|b| *b == 0) else {
            return Verdict::NeedMore;
        };
        if n == 0 || n > 253 || !p[d..d + n].iter().all(|b| b.is_ascii_graphic()) {
            return Verdict::Malformed;
        }
    }
    Verdict::Match(Fact::new("P001", 1, 0, 0))
}
fn socks5(p: &[u8]) -> Verdict {
    if p[0] != 5 {
        return Verdict::NoMatch;
    }
    if p.len() < 2 {
        return Verdict::NeedMore;
    }
    if p.len() == 2 {
        return Verdict::Match(Fact::new("P002", 2, u64::from(p[1]), 0));
    }
    let n = usize::from(p[1]);
    if n == 0 {
        return Verdict::Malformed;
    }
    if p.len() < n + 2 {
        return Verdict::NeedMore;
    }
    let methods = p[2..n + 2]
        .iter()
        .filter(|m| **m < 64)
        .fold(0u64, |acc, m| acc | (1 << m));
    Verdict::Match(Fact::new("P002", 1, methods, 0))
}
fn dtls(p: &[u8]) -> Verdict {
    if p.len() < 3 || !(20..=23).contains(&p[0]) || ![0xfeff, 0xfefd].contains(&be16(p, 1)) {
        return Verdict::NoMatch;
    }
    if p.len() < 13 {
        return Verdict::NeedMore;
    }
    let n = usize::from(be16(p, 11));
    if n == 0 {
        return Verdict::Malformed;
    }
    if p.len() < 13 + n {
        return Verdict::NeedMore;
    }
    if p[0] == 22 && be16(p, 3) == 0 {
        if n < 12 {
            return Verdict::Malformed;
        }
        let u24 =
            |i| usize::from(p[i]) * 65536 + usize::from(p[i + 1]) * 256 + usize::from(p[i + 2]);
        if u24(19) + u24(22) > u24(14) || u24(22) > n - 12 {
            return Verdict::Malformed;
        }
    }
    hit("T005")
}
fn varint(p: &[u8], o: &mut usize) -> Option<usize> {
    let first = *p.get(*o)?;
    let n = 1usize << (first >> 6);
    let b = p.get(*o..*o + n)?;
    let mut v = u64::from(first & 0x3f);
    for c in &b[1..] {
        v = (v << 8) | u64::from(*c);
    }
    *o += n;
    usize::try_from(v).ok()
}
fn quic(p: &[u8]) -> Verdict {
    if p.len() < 7 || p[0] & 0xc0 != 0xc0 {
        return Verdict::NoMatch;
    }
    let version = be32(p, 1);
    let initial = match version {
        1 => 0,
        0x6b3343cf => 1,
        _ => return Verdict::NoMatch,
    };
    if (p[0] >> 4) & 3 != initial {
        return Verdict::NoMatch;
    } // No guesses for protected short headers or Retry.
    let dl = usize::from(p[5]);
    if dl > 20 {
        return Verdict::Malformed;
    }
    let mut o = 6 + dl;
    let Some(&sl) = p.get(o) else {
        return Verdict::NeedMore;
    };
    if sl > 20 {
        return Verdict::Malformed;
    }
    o += 1 + usize::from(sl);
    if o > p.len() {
        return Verdict::NeedMore;
    }
    let Some(local_id) = varint(p, &mut o) else {
        return Verdict::NeedMore;
    };
    let Some(end) = o.checked_add(local_id) else {
        return Verdict::Malformed;
    };
    o = end;
    if o > p.len() {
        return Verdict::NeedMore;
    }
    let Some(n) = varint(p, &mut o) else {
        return Verdict::NeedMore;
    };
    if n < 17 {
        return Verdict::Malformed;
    }
    if n > p.len().saturating_sub(o) {
        return Verdict::NeedMore;
    }
    // Header protection and AEAD have not been verified: NEVER promote this structural candidate to A.
    hit(if version == 1 { "T007" } else { "T008" })
}
fn tlcp(p: &[u8]) -> Verdict {
    if p.len() < 3 || p[..3] != [22, 1, 1] {
        return Verdict::NoMatch;
    }
    if p.len() < 9 {
        return Verdict::NeedMore;
    }
    let n = usize::from(be16(p, 3));
    if n < 4 || ![1, 2].contains(&p[5]) {
        return Verdict::Malformed;
    }
    if p.len() < n + 5 {
        return Verdict::NeedMore;
    }
    let h = usize::from(p[6]) * 65536 + usize::from(p[7]) * 256 + usize::from(p[8]);
    if h + 4 > n {
        return Verdict::Malformed;
    }
    hit("T014")
}
