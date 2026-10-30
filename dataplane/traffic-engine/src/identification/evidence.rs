//! Explicitly trusted, operator-imported evidence. Network payload can never create these records.
use super::{lookup, Identification};
use crate::flow::FlowKey;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Evidence {
    pub id: String,
    pub trust_root: String,
    pub kind: String,
    pub protocol_id: String,
    pub version: String,
    pub mode: String,
    pub key: FlowKey,
    pub start_us: u64,
    pub end_us: u64,
    pub deny: bool,
}
impl Evidence {
    pub fn validate(&self) -> Result<(), &'static str> {
        let Some(entry) = lookup(&self.protocol_id) else {
            return Err("unknown catalog ID");
        };
        if !entry.ip_protocols.is_empty() && !entry.ip_protocols.contains(&self.key.proto.number())
        {
            return Err("protocol incompatible with observed transport");
        }
        if !self.key.proto.has_ports() && (self.key.src_port != 0 || self.key.dst_port != 0) {
            return Err("native IP protocol cannot carry synthetic ports");
        }
        if !["inventory", "endpoint", "gateway", "probe"].contains(&self.kind.as_str()) {
            return Err("invalid evidence kind");
        }
        if self.id.is_empty()
            || self.trust_root.is_empty()
            || self.version.is_empty()
            || self.mode.is_empty()
            || [&self.id, &self.trust_root, &self.version, &self.mode]
                .iter()
                .any(|s| s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err("invalid evidence identity/version/mode");
        }
        if self.end_us < self.start_us || self.end_us - self.start_us > 300_000_000 {
            return Err("evidence window exceeds 300 seconds");
        }
        Ok(())
    }
    pub fn applies(&self, key: FlowKey, first: u64, last: u64) -> bool {
        (self.key == key || self.key.reverse() == key)
            && self.start_us <= last
            && first <= self.end_us
    }
}

/// Returns only classifications supported by a two-root, two-kind quorum. Conflicts fail closed.
pub fn correlate(key: FlowKey, first: u64, last: u64, items: &[Evidence]) -> Vec<Identification> {
    let mut groups: BTreeMap<(&str, &str, &str), Vec<&Evidence>> = BTreeMap::new();
    let mut denied = BTreeSet::new();
    for e in items {
        if e.validate().is_err() || !e.applies(key, first, last) {
            continue;
        }
        if e.deny {
            denied.insert(e.protocol_id.as_str());
        }
        groups
            .entry((&e.protocol_id, &e.version, &e.mode))
            .or_default()
            .push(e);
    }
    let mut out = Vec::new();
    for ((id, version, mode), evidence) in groups {
        let roots: BTreeSet<_> = evidence
            .iter()
            .filter(|e| !e.deny)
            .map(|e| e.trust_root.as_str())
            .collect();
        let kinds: BTreeSet<_> = evidence
            .iter()
            .filter(|e| !e.deny)
            .map(|e| e.kind.as_str())
            .collect();
        let ids: BTreeSet<_> = evidence
            .iter()
            .filter(|e| !e.deny)
            .map(|e| e.id.as_str())
            .collect();
        if roots.len() < 2 || kinds.len() < 2 || ids.len() < 2 {
            continue;
        }
        let mut r=Identification::new(id,"B","context_verified","two independent trusted roots and evidence kinds match observed flow, version and mode");
        r.version = Some(version.to_owned());
        r.mode = Some(mode.to_owned());
        r.evidence_ids = ids.into_iter().map(str::to_owned).collect();
        if denied.contains(id) {
            r.counter_evidence_ids = items
                .iter()
                .filter(|e| e.deny && e.protocol_id == id && e.applies(key, first, last))
                .map(|e| e.id.clone())
                .collect();
            r.grade = "U";
            r.classification = "unknown";
            r.reason = "conflicting trusted evidence";
        }
        out.push(r);
    }
    // Two versions/modes of one object or two product identities on one flow are ambiguous.
    let mut counts = BTreeMap::new();
    let products = out
        .iter()
        .filter(|r| lookup(r.id).map(|e| e.layer) == Some("product"))
        .count();
    for r in &out {
        *counts.entry(r.id).or_insert(0) += 1;
    }
    for r in &mut out {
        if counts[r.id] > 1 || products > 1 && lookup(r.id).map(|e| e.layer) == Some("product") {
            r.grade = "U";
            r.classification = "unknown";
            r.reason = "ambiguous product, version or mode; independent resolution required";
        }
    }
    out
}
