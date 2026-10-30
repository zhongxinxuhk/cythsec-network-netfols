//! Bounded first-frame DNS/TCP inspection, independent from other classifiers.
use std::collections::BTreeMap;

use crate::dpi::{dns, Confidence, Detect, Outcome};
use crate::flow::FlowKey;
use crate::reassembly::stream::{Stream, StreamConfig};
use crate::reassembly::tcp::TcpSegment;
use crate::record::AppInfo;
use crate::session::Observation;
use crate::tcp::Side;

const MAX_FLOWS: usize = 1024;
const MAX_PREFIX: usize = 4096;
const MAX_SEGMENTS: usize = 64;
const IDLE_US: u64 = 30_000_000;

struct Direction {
    isn: Option<u32>,
    stream: Option<Stream>,
    segments: usize,
    stopped: bool,
}
impl Direction {
    fn new() -> Self {
        Self {
            isn: None,
            stream: None,
            segments: 0,
            stopped: false,
        }
    }
}
struct Entry {
    session_id: u64,
    opening: Option<(Side, u32)>,
    directions: [Direction; 2],
    last_seen: u64,
}
impl Entry {
    fn new(id: u64, now: u64) -> Self {
        Self {
            session_id: id,
            opening: None,
            directions: [Direction::new(), Direction::new()],
            last_seen: now,
        }
    }
}
pub(super) struct Update {
    pub reset: bool,
    pub info: Option<AppInfo>,
}
pub(super) struct DnsTcpStreams {
    entries: BTreeMap<FlowKey, Entry>,
    limit: usize,
    prefix: usize,
}
fn waiting(reason: &'static str, bytes: usize) -> AppInfo {
    let mut info = AppInfo::from_outcome(&Outcome::NeedMore, bytes);
    info.rationale = Some(reason);
    info
}
fn outcome(result: Detect, bytes: usize) -> AppInfo {
    let result = match result {
        Detect::Hit(d) => Outcome::Identified(d),
        Detect::NeedMore => Outcome::NeedMore,
        Detect::Malformed => Outcome::Malformed,
        Detect::Rejected => Outcome::Unknown,
    };
    AppInfo::from_outcome(&result, bytes)
}
impl DnsTcpStreams {
    pub fn new(inspect_bytes: usize, max_sessions: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            limit: max_sessions.clamp(1, MAX_FLOWS),
            prefix: inspect_bytes.min(MAX_PREFIX),
        }
    }

    pub fn observe(
        &mut self,
        obs: &Observation,
        seg: &TcpSegment<'_>,
        now: u64,
        seen: bool,
        fragmented: bool,
    ) -> Update {
        let key = obs.key;
        let index = if obs.side == Side::A { 0 } else { 1 };
        let opening = seg.flags.syn && !seg.flags.ack;
        let mut reset = obs.is_new;
        let replaced = self
            .entries
            .get(&key)
            .is_some_and(|e| obs.is_new || e.session_id != obs.session_id);
        if replaced
            || self
                .entries
                .get(&key)
                .is_some_and(|e| now.saturating_sub(e.last_seen) > IDLE_US)
        {
            self.entries.remove(&key);
            reset |= replaced;
        }
        if seg.flags.rst {
            self.entries.remove(&key);
            return Update {
                reset,
                info: (!seen && !seg.payload.is_empty())
                    .then(|| waiting("dns_tcp.reset_before_frame", 0)),
            };
        }
        if fragmented || self.prefix == 0 {
            return Update {
                reset,
                info: (!seg.payload.is_empty()).then(|| {
                    waiting(
                        if fragmented {
                            "dns_tcp.ip_fragment_unassembled"
                        } else {
                            "dns_tcp.prefix_budget"
                        },
                        0,
                    )
                }),
            };
        }
        if opening
            && self
                .entries
                .get(&key)
                .is_none_or(|e| e.opening != Some((obs.side, seg.seq)))
        {
            self.entries.remove(&key);
            reset = true;
        }
        if !self.entries.contains_key(&key) && seg.flags.syn {
            if self.entries.len() >= self.limit {
                // ponytail: bounded scan only on admission pressure; expiry index if profiling warrants it.
                self.entries
                    .retain(|_, e| now.saturating_sub(e.last_seen) <= IDLE_US);
            }
            if self.entries.len() < self.limit {
                self.entries.insert(key, Entry::new(obs.session_id, now));
            }
        }
        let Some(entry) = self.entries.get_mut(&key) else {
            if seen && !reset || seg.payload.is_empty() {
                return Update { reset, info: None };
            }
            // Preserve legacy complete-packet inspection, with an explicit weak
            // boundary observation. Never accumulate bytes without a SYN anchor.
            let bytes = &seg.payload[..seg.payload.len().min(self.prefix)];
            let mut info = outcome(dns::detect_tcp(bytes), bytes.len());
            info.rationale = Some(if self.entries.len() >= self.limit {
                "dns_tcp.flow_capacity_packet_only"
            } else {
                "dns_tcp.unanchored_packet_only"
            });
            if info.is_identified() {
                info.confidence = Some(Confidence::Medium);
            }
            return Update {
                reset,
                info: Some(info),
            };
        };
        entry.last_seen = entry.last_seen.max(now);
        if opening {
            entry.opening = Some((obs.side, seg.seq));
        }
        let direction = &mut entry.directions[index];
        if seg.flags.syn
            && seg.flags.ack
            && entry
                .opening
                .is_some_and(|(side, seq)| side != obs.side && seg.ack != seq.wrapping_add(1))
        {
            direction.stream = None;
            direction.stopped = true;
            return Update {
                reset,
                info: Some(waiting("dns_tcp.syn_ack_mismatch", 0)),
            };
        }
        if seg.flags.syn && direction.isn != Some(seg.seq) {
            if direction.isn.is_some() && !opening {
                direction.stream = None;
                direction.stopped = true;
                return Update {
                    reset,
                    info: Some(waiting("dns_tcp.syn_epoch_conflict", 0)),
                };
            }
            direction.isn = Some(seg.seq);
            direction.stopped = false;
            direction.segments = 0;
            let mut stream = Stream::new(StreamConfig {
                max_buffered: self.prefix,
                max_span: self.prefix as u32,
                ..StreamConfig::default()
            });
            stream.on_syn(seg.seq);
            direction.stream = Some(stream);
        }
        if direction.stopped {
            return Update { reset, info: None };
        }
        let Some(stream) = direction.stream.as_mut() else {
            if seen && !reset || seg.payload.is_empty() {
                return Update { reset, info: None };
            }
            let bytes = &seg.payload[..seg.payload.len().min(self.prefix)];
            let mut info = outcome(dns::detect_tcp(bytes), bytes.len());
            info.rationale = Some("dns_tcp.direction_unanchored_packet_only");
            if info.is_identified() {
                info.confidence = Some(Confidence::Medium);
            }
            direction.stopped = true;
            return Update {
                reset,
                info: Some(info),
            };
        };
        if seg.payload.is_empty() && !seg.flags.fin {
            return Update { reset, info: None };
        }
        if seg.payload.is_empty() && stream.buffered() == 0 {
            if seg.flags.fin {
                direction.stream = None;
                direction.stopped = true;
            }
            return Update { reset, info: None };
        }
        if !seg.payload.is_empty() {
            direction.segments += 1;
            if direction.segments > MAX_SEGMENTS {
                direction.stream = None;
                direction.stopped = true;
                return Update {
                    reset,
                    info: Some(waiting("dns_tcp.segment_budget", 0)),
                };
            }
            stream.on_data(seg.seq.wrapping_add(u32::from(seg.flags.syn)), seg.payload);
        }
        let prefix = stream.peek(self.prefix);
        let mut info = outcome(dns::detect_tcp(prefix), prefix.len());
        let conflict = stream
            .interval_stats()
            .is_some_and(|s| s.conflict_bytes != 0);
        if conflict {
            info = waiting("dns_tcp.conflicting_overlap", prefix.len());
        } else if info.outcome == "need_more" {
            info.rationale = Some(if seg.flags.fin {
                "dns_tcp.closed_with_gap"
            } else if prefix.len() == self.prefix {
                "dns_tcp.prefix_budget"
            } else {
                "dns_tcp.awaiting_contiguous_prefix"
            });
        }
        if conflict || info.outcome != "need_more" || seg.flags.fin || prefix.len() == self.prefix {
            direction.stream = None;
            direction.stopped = true;
        }
        Update {
            reset,
            info: Some(info),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reassembly::tcp;
    use crate::tcp::TcpState;

    fn observation(side: Side) -> Observation {
        Observation {
            session_id: 1,
            key: FlowKey::new_ipv4([192, 0, 2, 1], 40000, [198, 51, 100, 2], 53, 6).canonical(),
            is_new: false,
            side,
            state: TcpState::Established,
            illegal: None,
        }
    }
    fn segment(seq: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes[4..8].copy_from_slice(&seq.to_be_bytes());
        bytes[8..12].copy_from_slice(&ack.to_be_bytes());
        bytes[12] = 0x50;
        bytes[13] = flags;
        bytes.extend_from_slice(data);
        bytes
    }
    fn feed(table: &mut DnsTcpStreams, seq: u32, flags: u8, data: &[u8]) -> Update {
        let bytes = segment(seq, 0, flags, data);
        table.observe(
            &observation(Side::A),
            &tcp::parse(&bytes).unwrap(),
            1,
            false,
            false,
        )
    }
    fn query() -> Vec<u8> {
        let body: &[u8] = include_bytes!("../../../../datasets/dpi/payloads/dns-query-a.bin");
        let mut framed = (body.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(body);
        framed
    }
    #[test]
    fn dns_stream_out_of_order_retransmission_and_wraparound() {
        for isn in [100u32, u32::MAX - 1] {
            let q = query();
            let mut table = DnsTcpStreams::new(512, 16);
            assert!(feed(&mut table, isn, 2, &[]).info.is_none());
            let tail = feed(&mut table, isn.wrapping_add(3), 0x18, &q[2..]);
            assert_eq!(tail.info.unwrap().outcome, "need_more");
            assert_eq!(
                feed(&mut table, isn.wrapping_add(3), 0x18, &q[2..])
                    .info
                    .unwrap()
                    .outcome,
                "need_more"
            );
            let done = feed(&mut table, isn.wrapping_add(1), 0x18, &q[..2])
                .info
                .unwrap();
            assert!(done.is_identified());
            assert_eq!(done.app, Some(crate::dpi::AppId::Dns));
            assert_eq!(done.bytes_inspected, q.len());
            assert!(table
                .entries
                .values()
                .all(|e| e.directions[0].stream.is_none()));
        }
    }
    #[test]
    fn dns_stream_conflicts_and_holes_never_become_complete() {
        let q = query();
        let mut table = DnsTcpStreams::new(512, 16);
        feed(&mut table, 100, 2, &[]);
        feed(&mut table, 101, 0x18, &q[..10]);
        let mut changed = q[..10].to_vec();
        changed[5] ^= 1;
        let result = feed(&mut table, 101, 0x18, &changed).info.unwrap();
        assert_eq!(result.outcome, "need_more");
        assert_eq!(result.rationale, Some("dns_tcp.conflicting_overlap"));
        assert!(feed(&mut table, 111, 0x18, &q[10..]).info.is_none());
        let mut table = DnsTcpStreams::new(512, 16);
        feed(&mut table, 100, 2, &[]);
        let result = feed(&mut table, 103, 0x19, &q[2..]).info.unwrap();
        assert_eq!(result.outcome, "need_more");
        assert_eq!(result.rationale, Some("dns_tcp.closed_with_gap"));
    }
    #[test]
    fn dns_stream_budgets_and_no_payload_close_are_explicit() {
        let q = query();
        let mut table = DnsTcpStreams::new(8, 1);
        feed(&mut table, 100, 2, &[]);
        let result = feed(&mut table, 101, 0x18, &q).info.unwrap();
        assert_eq!(result.outcome, "need_more");
        assert_eq!(result.rationale, Some("dns_tcp.prefix_budget"));
        let mut table = DnsTcpStreams::new(512, 1);
        feed(&mut table, 100, 2, &[]);
        for _ in 0..MAX_SEGMENTS {
            assert_eq!(
                feed(&mut table, 101, 0x18, &q[..1]).info.unwrap().outcome,
                "need_more"
            );
        }
        assert_eq!(
            feed(&mut table, 101, 0x18, &q[..1]).info.unwrap().rationale,
            Some("dns_tcp.segment_budget")
        );
        let mut table = DnsTcpStreams::new(512, 1);
        feed(&mut table, 100, 2, &[]);
        assert!(feed(&mut table, 101, 0x11, &[]).info.is_none());
    }
    #[test]
    fn dns_stream_new_syn_and_peer_ack_isolate_epochs() {
        let q = query();
        let mut table = DnsTcpStreams::new(512, 1);
        feed(&mut table, 100, 2, &[]);
        feed(&mut table, 101, 0x18, &q[..10]);
        assert!(feed(&mut table, 200, 2, &[]).reset);
        assert_eq!(
            feed(&mut table, 111, 0x18, &q[10..]).info.unwrap().outcome,
            "need_more"
        );
        let bytes = segment(500, 101, 0x12, &[]);
        assert_eq!(
            table
                .observe(
                    &observation(Side::B),
                    &tcp::parse(&bytes).unwrap(),
                    2,
                    false,
                    false
                )
                .info
                .unwrap()
                .rationale,
            Some("dns_tcp.syn_ack_mismatch")
        );
        assert!(feed(&mut table, 201, 0x18, &q)
            .info
            .unwrap()
            .is_identified());
    }
    #[test]
    fn dns_stream_capacity_idle_and_unanchored_fallback_are_bounded() {
        let q = query();
        let mut table = DnsTcpStreams::new(512, 1);
        feed(&mut table, 100, 2, &[]);
        let mut second = observation(Side::A);
        second.key.src_port = 40001;
        second.session_id = 2;
        let bytes = segment(200, 0, 2, &[]);
        table.observe(&second, &tcp::parse(&bytes).unwrap(), 2, false, false);
        assert_eq!(table.entries.len(), 1);
        let bytes = segment(201, 0, 0x18, &q);
        let result = table
            .observe(&second, &tcp::parse(&bytes).unwrap(), 3, false, false)
            .info
            .unwrap();
        assert_eq!(result.rationale, Some("dns_tcp.flow_capacity_packet_only"));
        assert_eq!(result.confidence, Some(Confidence::Medium));
        let bytes = segment(200, 0, 2, &[]);
        table.observe(
            &second,
            &tcp::parse(&bytes).unwrap(),
            IDLE_US + 2,
            false,
            false,
        );
        assert_eq!(table.entries.len(), 1);
        assert!(table.entries.contains_key(&second.key));
        let bytes = segment(201, 0, 0x18, &q);
        assert_eq!(
            table
                .observe(
                    &second,
                    &tcp::parse(&bytes).unwrap(),
                    IDLE_US + 3,
                    false,
                    true
                )
                .info
                .unwrap()
                .rationale,
            Some("dns_tcp.ip_fragment_unassembled")
        );
    }
}
