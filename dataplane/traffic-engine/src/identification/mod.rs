//! Layered VPN/ZTNA identification. Structural facts and imported attribution remain separate.
use crate::channel::{decode_frame, l4_payload, tcp_flags, tcp_seq_ack};
use crate::flow::FlowKey;
use crate::reassembly::stream::{Stream, StreamConfig};
use std::collections::BTreeMap;
use std::io::{self, Write};

pub mod evidence;
pub mod probe;
pub use crate::dpi::wire;
mod catalog_gen;
pub use catalog_gen::{CATALOG, RULE_VERSION};

#[derive(Debug)]
pub struct CatalogEntry {
    pub id: &'static str,
    pub name: &'static str,
    pub layer: &'static str,
    pub parser: &'static str,
    pub ip_protocols: &'static [u8],
    pub parent: Option<&'static str>,
}
pub fn lookup(id: &str) -> Option<&'static CatalogEntry> {
    CATALOG
        .binary_search_by_key(&id, |e| e.id)
        .ok()
        .map(|i| &CATALOG[i])
}

#[derive(Debug, Clone)]
pub struct Identification {
    pub id: &'static str,
    pub grade: &'static str,
    pub classification: &'static str,
    pub reason: &'static str,
    pub evidence_ids: Vec<String>,
    pub counter_evidence_ids: Vec<String>,
    pub version: Option<String>,
    pub mode: Option<String>,
}
impl Identification {
    pub fn new(
        id: &str,
        grade: &'static str,
        classification: &'static str,
        reason: &'static str,
    ) -> Self {
        Self {
            id: lookup(id).expect("recognizers only emit registered IDs").id,
            grade,
            classification,
            reason,
            evidence_ids: Vec::new(),
            counter_evidence_ids: Vec::new(),
            version: None,
            mode: None,
        }
    }
}
struct Flow {
    first: u64,
    last: u64,
    packets: u64,
    bytes: u64,
    streams: [Stream; 2],
    prefixes: [Vec<u8>; 2],
    facts: Vec<(bool, wire::Fact, u64)>,
    limited: bool,
    syns: [Option<u32>; 2],
}
impl Flow {
    fn new(now: u64) -> Self {
        let cfg = StreamConfig {
            max_buffered: 8192,
            max_span: 16384,
            ..Default::default()
        };
        Self {
            first: now,
            last: now,
            packets: 0,
            bytes: 0,
            streams: [Stream::new(cfg), Stream::new(cfg)],
            prefixes: [Vec::new(), Vec::new()],
            facts: Vec::new(),
            limited: false,
            syns: [None, None],
        }
    }
}
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub frames: u64,
    pub decode_errors: u64,
    pub capacity_drops: u64,
    pub truncated: u64,
    pub regressions: u64,
}
/// Optional deeper analysis, outside the default per-packet fast path. Bounded to 4096 sessions.
pub struct Engine {
    flows: BTreeMap<(FlowKey, u64), Flow>,
    active: BTreeMap<FlowKey, u64>,
    pub stats: Stats,
    max_sessions: usize,
    max_prefix: usize,
}
impl Default for Engine {
    fn default() -> Self {
        Self::new(4096, 4096)
    }
}
impl Engine {
    pub fn new(max_sessions: usize, max_prefix: usize) -> Self {
        Self {
            flows: BTreeMap::new(),
            active: BTreeMap::new(),
            stats: Stats::default(),
            max_sessions: max_sessions.clamp(1, 4096),
            max_prefix: max_prefix.clamp(64, 8192),
        }
    }
    pub fn observe(&mut self, frame: &[u8], now: u64) {
        self.stats.frames += 1;
        let d = match decode_frame(frame) {
            Ok(d) => d,
            Err(_) => {
                self.stats.decode_errors += 1;
                return;
            }
        };
        let original = d.key;
        let key = original.min(original.reverse());
        let reverse = key != original;
        let side = usize::from(reverse);
        let tcp = tcp_flags(frame, &d).zip(tcp_seq_ack(frame, &d));
        let old = self
            .active
            .get(&key)
            .and_then(|epoch| self.flows.get(&(key, *epoch)));
        let new_epoch = old
            .map(|f| {
                now.saturating_sub(f.last) > 60_000_000
                    || tcp
                        .map(|(flags, (seq, _))| {
                            flags.syn
                                && !flags.ack
                                && f.syns[side]
                                    .map(|old| old != seq)
                                    .unwrap_or(!f.prefixes[side].is_empty())
                        })
                        .unwrap_or(false)
            })
            .unwrap_or(true);
        if new_epoch {
            if self.flows.len() >= self.max_sessions {
                self.stats.capacity_drops += 1;
                return;
            }
            // Distinguish a same-microsecond tuple reuse without overwriting the previous epoch.
            let mut epoch = now;
            while self.flows.contains_key(&(key, epoch)) {
                let Some(next) = epoch.checked_add(1) else {
                    self.stats.capacity_drops += 1;
                    return;
                };
                epoch = next;
            }
            self.active.insert(key, epoch);
            self.flows.insert((key, epoch), Flow::new(now));
        }
        let epoch = self.active[&key];
        let f = self.flows.get_mut(&(key, epoch)).unwrap();
        if now < f.last {
            self.stats.regressions += 1;
        }
        f.first = f.first.min(now);
        f.last = f.last.max(now);
        f.packets += 1;
        f.bytes += u64::from(d.ip_payload_len);
        let payload = if d.key.proto.has_ports() {
            let Some(p) = l4_payload(frame, &d) else {
                self.stats.truncated += 1;
                return;
            };
            if p.is_truncated() {
                self.stats.truncated += 1;
                f.limited = true;
            }
            p.bytes
        } else {
            let end = d
                .l4_offset
                .saturating_add(d.ip_payload_len as usize)
                .min(frame.len());
            let Some(p) = frame.get(d.l4_offset..end) else {
                return;
            };
            if p.len() < d.ip_payload_len as usize {
                self.stats.truncated += 1;
                f.limited = true;
            }
            p
        };
        let inspected = if d.key.proto.is_tcp() {
            let (Some(flags), Some((seq, _))) = (tcp_flags(frame, &d), tcp_seq_ack(frame, &d))
            else {
                return;
            };
            let room = self.max_prefix.saturating_sub(f.prefixes[side].len());
            if payload.len() > room {
                f.limited = true;
            }
            // Bound even an advancing segment: Stream's own cap primarily bounds out-of-order data.
            if flags.syn {
                f.syns[side] = Some(seq);
                f.streams[side].on_syn(seq);
            }
            let data_seq = seq.wrapping_add(u32::from(flags.syn));
            let action = f.streams[side].on_data(data_seq, &payload[..payload.len().min(room)]);
            if matches!(
                action,
                crate::reassembly::stream::SegAction::DroppedForMemory
                    | crate::reassembly::stream::SegAction::BeyondWindow
            ) || f.streams[side]
                .interval_stats()
                .map(|s| s.conflict_bytes > 0)
                .unwrap_or(false)
            {
                f.limited = true;
            }
            if flags.fin {
                f.streams[side].on_fin(data_seq.wrapping_add(payload.len() as u32));
            }
            if flags.rst {
                f.streams[side].on_rst();
            }
            let delivered = f.streams[side].take_all();
            let left = self.max_prefix.saturating_sub(f.prefixes[side].len());
            if delivered.len() > left {
                f.limited = true;
            }
            f.prefixes[side].extend_from_slice(&delivered[..delivered.len().min(left)]);
            f.prefixes[side].as_slice()
        } else {
            payload
        };
        if let wire::Verdict::Match(fact) = wire::inspect(
            inspected,
            original.proto.number(),
            original.src_port,
            original.dst_port,
        ) {
            if !f.facts.iter().any(|(s, p, _)| *s == reverse && *p == fact) {
                if f.facts.len() < 32 {
                    f.facts.push((reverse, fact, now));
                    if (original.src_port == 4500 || original.dst_port == 4500)
                        && payload.starts_with(&[0, 0, 0, 0])
                        && ["V003", "V004"].contains(&fact.id)
                        && f.facts.len() < 32
                    {
                        let wrapper = wire::Fact {
                            id: "V005",
                            message: 0,
                            local_id: 0,
                            peer: 0,
                        };
                        if !f
                            .facts
                            .iter()
                            .any(|(s, p, _)| *s == reverse && *p == wrapper)
                        {
                            f.facts.push((reverse, wrapper, now));
                        }
                    }
                } else {
                    f.limited = true;
                }
            }
        }
    }
    pub fn write_jsonl<W: Write>(
        &self,
        mut out: W,
        evidence: &[evidence::Evidence],
    ) -> io::Result<()> {
        for ((key, _epoch), f) in &self.flows {
            let mut results = Vec::new();
            let mut ids = Vec::new();
            for (_, fact, _) in &f.facts {
                if !ids.contains(&fact.id) {
                    ids.push(fact.id);
                }
            }
            for id in ids {
                let confirmed = !f.limited
                    && f.facts.iter().any(|(side, a, at)| {
                        a.id == id
                            && f.facts.iter().any(|(other, b, bt)| {
                                side != other && bt >= at && bt - at <= 15_000_000 && a.confirms(*b)
                            })
                    });
                results.push(Identification::new(id,if confirmed{"A"}else{"C"},if confirmed{"wire_confirmed"}else{"candidate"},if confirmed{"bidirectional structural identifiers matched; cryptographic authentication not verified"}else{"bounded wire structure only; insufficient for product attribution"}));
            }
            results.extend(evidence::correlate(*key, f.first, f.last, evidence));
            if results.is_empty() {
                write_row(&mut out, *key, f, None)?;
            } else {
                for r in &results {
                    write_row(&mut out, *key, f, Some(r))?;
                }
            }
        }
        Ok(())
    }
}
fn js(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}
fn opt(v: Option<&str>) -> String {
    v.map(js).unwrap_or_else(|| "null".into())
}
fn write_row<W: Write>(
    out: &mut W,
    key: FlowKey,
    f: &Flow,
    r: Option<&Identification>,
) -> io::Result<()> {
    let e = r.and_then(|r| lookup(r.id));
    let name = e.map(|e| e.name);
    let grade = r.map(|r| r.grade).unwrap_or("U");
    let verified = r.map(|r| r.grade == "B").unwrap_or(false);
    let axis = e.map(|e| e.layer).unwrap_or("");
    let crypto = f.facts.iter().find_map(|(_, x, _)| match x.id {
        "V001" => Some("ESP"),
        "V003" => Some("IKEv1"),
        "V004" => Some("IKEv2"),
        "V021" => Some("WireGuard candidate"),
        "T022" => Some("TLS"),
        "T005" => Some("DTLS"),
        "T007" | "T008" => Some("QUIC candidate"),
        "T014" => Some("TLCP candidate"),
        _ => None,
    });
    let evidence = r
        .map(|r| {
            r.evidence_ids
                .iter()
                .map(|s| js(s))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let counters = r
        .map(|r| {
            r.counter_evidence_ids
                .iter()
                .map(|s| js(s))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    writeln!(out,"{{\"schema_version\":1,\"rule_version\":{},\"src_ip\":{},\"src_port\":{},\"dst_ip\":{},\"dst_port\":{},\"ip_proto\":{},\"first_us\":{},\"last_us\":{},\"packets\":{},\"bytes\":{},\"protocol_id\":{},\"name\":{},\"layer\":{},\"classification\":{},\"confidence_level\":{},\"transport_family\":{},\"cryptographic_transport\":{},\"tunnel_or_proxy_family\":{},\"access_architecture\":{},\"vendor_product\":{},\"obfuscation_overlay\":{},\"version\":{},\"mode\":{},\"evidence_ids\":[{}],\"counter_evidence_ids\":[{}],\"reason\":{},\"budget_or_capture_limited\":{}}}",js(RULE_VERSION),js(&key.src_ip.to_string()),key.src_port,js(&key.dst_ip.to_string()),key.dst_port,key.proto.number(),f.first,f.last,f.packets,f.bytes,opt(r.map(|r|r.id)),opt(name),js(axis),js(r.map(|r|r.classification).unwrap_or("unknown")),js(grade),js(key.proto.as_str()),opt(crypto),opt(if axis=="tunnel"{name}else{None}),opt(if verified {r.and_then(|r|r.mode.as_deref())}else{None}),opt(if axis=="product"&&verified{name}else{None}),opt(if axis=="overlay"&&verified{name}else{None}),opt(r.and_then(|r|r.version.as_deref())),opt(r.and_then(|r|r.mode.as_deref())),evidence,counters,js(r.map(|r|r.reason).unwrap_or("no supported wire or independent trusted evidence")),f.limited)
}

#[cfg(test)]
mod tests;
