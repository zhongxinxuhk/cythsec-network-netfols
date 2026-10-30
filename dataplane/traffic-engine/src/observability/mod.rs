//! Aggregate operational telemetry, independent of application/VPN classification and FlowRecord.
//! Exact tuples exist only in a bounded window-local map; public outputs contain counters only.
use crate::channel::{decode_frame, l4_payload, tcp_flags, tcp_seq_ack, DecodeError};
use crate::flow::FlowKey;
use crate::pcapfile::PcapRecord;
use std::collections::{hash_map::RandomState, HashMap};
use std::hash::{BuildHasher, Hash, Hasher};
use std::io::{self, Write};

pub mod carrier;
pub mod quality;
use carrier::Carrier;
use quality::{Quality, TcpQuality};

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub window_seconds: u64,
    pub sampling_interval: u32,
    pub max_flows: usize,
    pub minimum_flows: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            window_seconds: 60,
            sampling_interval: 1,
            max_flows: 4096,
            minimum_flows: 20,
        }
    }
}
impl Config {
    pub fn validate(self) -> Result<Self, &'static str> {
        if !(60..=3600).contains(&self.window_seconds) {
            return Err("window must be 60..3600 seconds");
        }
        if !(1..=1_000_000).contains(&self.sampling_interval) {
            return Err("sampling interval must be 1..1000000");
        }
        if !(20..=65536).contains(&self.max_flows)
            || self.minimum_flows < 20
            || self.minimum_flows > self.max_flows
        {
            return Err(
                "flow capacity and minimum cohort must satisfy 20 <= cohort <= capacity <= 65536",
            );
        }
        Ok(self)
    }
}
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    pub records: u64,
    pub captured_octets: u64,
    pub wire_octets: u64,
    pub snaplen_truncated: u64,
    pub decoded: u64,
    pub non_ip: u64,
    pub decode_incomplete: u64,
    pub unparsed_fragments: u64,
    pub unsupported_or_bad_headers: u64,
    pub unusable_transport: u64,
    pub fragmented_transport: u64,
    pub timestamp_regressions: u64,
    pub late_records: u64,
    pub capacity_rejected_packets: u64,
    pub unsampled_packets: u64,
    pub sampled_packets: u64,
}
#[derive(Debug, Clone)]
pub struct Window {
    pub start_seconds: u64,
    pub duration_seconds: u64,
    pub interval: u32,
    pub contributing_flows: usize,
    pub tcp_flows: usize,
    pub tls_flows: usize,
    pub quic_flows: usize,
    pub suppressed: bool,
    pub minimum_flows: usize,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub other_ip_packets: u64,
    pub tls_record_candidates: u64,
    pub quic_long_header_candidates: u64,
    pub integrity: Integrity,
    pub quality: Quality,
}
struct Flow {
    tcp: TcpQuality,
    tls: bool,
    quic: bool,
    delay_sampled: bool,
}
impl Default for Flow {
    fn default() -> Self {
        Self {
            tcp: TcpQuality::default(),
            tls: false,
            quic: false,
            delay_sampled: false,
        }
    }
}
struct Active {
    out: Window,
    flows: HashMap<FlowKey, Flow>,
    selection: RandomState,
    last_timestamp: u64,
}
impl Active {
    fn new(start: u64, cfg: Config) -> Self {
        Self {
            out: Window {
                start_seconds: start,
                duration_seconds: cfg.window_seconds,
                interval: cfg.sampling_interval,
                minimum_flows: cfg.minimum_flows,
                contributing_flows: 0,
                tcp_flows: 0,
                tls_flows: 0,
                quic_flows: 0,
                suppressed: true,
                tcp_packets: 0,
                udp_packets: 0,
                other_ip_packets: 0,
                tls_record_candidates: 0,
                quic_long_header_candidates: 0,
                integrity: Integrity::default(),
                quality: Quality::default(),
            },
            flows: HashMap::new(),
            selection: RandomState::new(),
            last_timestamp: 0,
        }
    }
    fn complete(mut self) -> Window {
        self.out.suppressed = self.out.contributing_flows < self.out.minimum_flows;
        self.out
    }
    fn observe(&mut self, p: &PcapRecord, cfg: Config, late: bool) {
        let i = &mut self.out.integrity;
        i.records += 1;
        i.captured_octets += p.data.len() as u64;
        i.wire_octets += u64::from(p.orig_len);
        if p.is_truncated() {
            i.snaplen_truncated += 1;
        }
        if late {
            i.late_records += 1;
            return;
        }
        if p.timestamp_us < self.last_timestamp {
            i.timestamp_regressions += 1;
        }
        self.last_timestamp = self.last_timestamp.max(p.timestamp_us);
        let d = match decode_frame(&p.data) {
            Ok(d) => d,
            Err(e) => {
                match e {
                    DecodeError::NonIpEtherType { .. } => i.non_ip += 1,
                    DecodeError::Truncated { .. } => i.decode_incomplete += 1,
                    DecodeError::NonInitialFragment { .. } => i.unparsed_fragments += 1,
                    _ => i.unsupported_or_bad_headers += 1,
                };
                return;
            }
        };
        i.decoded += 1;
        match d.key.proto.number() {
            6 => self.out.tcp_packets += 1,
            17 => self.out.udp_packets += 1,
            _ => self.out.other_ip_packets += 1,
        }
        if d.is_fragmented {
            i.fragmented_transport += 1;
            return;
        }
        let view = if d.key.proto.has_ports() {
            let Some(mut v) = l4_payload(&p.data, &d) else {
                i.unusable_transport += 1;
                return;
            };
            if d.l4_header_len
                .map(|n| n > d.ip_payload_len as usize)
                .unwrap_or(true)
            {
                i.unusable_transport += 1;
                return;
            }
            if d.key.proto.is_udp() {
                let Some(h) = p.data.get(d.l4_offset..d.l4_offset + 8) else {
                    i.unusable_transport += 1;
                    return;
                };
                let n = usize::from(u16::from_be_bytes([h[4], h[5]]));
                if n < 8 || n > d.ip_payload_len as usize {
                    i.unusable_transport += 1;
                    return;
                }
                v.declared_len = n - 8;
                v.bytes = &v.bytes[..v.bytes.len().min(v.declared_len)];
            }
            Some(v)
        } else {
            None
        };
        let key = d.key.canonical();
        let side = usize::from(d.key != key);
        let mut hasher = self.selection.build_hasher();
        key.hash(&mut hasher);
        if hasher.finish() % u64::from(cfg.sampling_interval) != 0 {
            i.unsampled_packets += 1;
            return;
        }
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= cfg.max_flows {
                i.capacity_rejected_packets += 1;
                return;
            }
            self.flows.insert(key, Flow::default());
            self.out.contributing_flows += 1;
            if key.proto.is_tcp() {
                self.out.tcp_flows += 1;
            }
        }
        i.sampled_packets += 1;
        let flow = self.flows.get_mut(&key).unwrap();
        let Some(view) = view else {
            return;
        };
        let payload = view.bytes;
        let declared = view.declared_len;
        if d.key.proto.is_tcp() {
            let (Some(flags), Some((seq, ack))) =
                (tcp_flags(&p.data, &d), tcp_seq_ack(&p.data, &d))
            else {
                i.unusable_transport += 1;
                return;
            };
            let mut quality =
                flow.tcp
                    .observe(side, seq, ack, flags, declared as u32, p.timestamp_us);
            // One delay contribution per tuple/window, including reused connections.
            // The histogram cohort must count distinct sampled flows, not repeated handshakes.
            if quality.response_samples > 0 {
                if flow.delay_sampled {
                    quality.response_samples = 0;
                    quality.delay_histogram = [0; 10];
                } else {
                    flow.delay_sampled = true;
                }
            }
            self.out.quality.merge(&quality);
        }
        match carrier::classify(d.key.proto.number(), payload, declared) {
            Some(Carrier::TlsRecord) => {
                self.out.tls_record_candidates += 1;
                if !flow.tls {
                    flow.tls = true;
                    self.out.tls_flows += 1;
                }
            }
            Some(Carrier::QuicLongHeader) => {
                self.out.quic_long_header_candidates += 1;
                if !flow.quic {
                    flow.quic = true;
                    self.out.quic_flows += 1;
                }
            }
            _ => {}
        }
    }
}
pub struct Aggregator {
    cfg: Config,
    current: Option<Active>,
    records: u64,
    published: u64,
    suppressed: u64,
    capacity_limited: bool,
}
impl Aggregator {
    pub fn new(cfg: Config) -> Result<Self, &'static str> {
        Ok(Self {
            cfg: cfg.validate()?,
            current: None,
            records: 0,
            published: 0,
            suppressed: 0,
            capacity_limited: false,
        })
    }
    pub fn records(&self) -> u64 {
        self.records
    }
    pub fn observe(&mut self, p: &PcapRecord) -> Option<Window> {
        self.records += 1;
        let seconds = p.timestamp_us / 1_000_000;
        let bin = seconds / self.cfg.window_seconds * self.cfg.window_seconds;
        let mut finished = None;
        if self
            .current
            .as_ref()
            .map(|a| bin > a.out.start_seconds)
            .unwrap_or(false)
        {
            finished = self.finish();
        }
        let a = self
            .current
            .get_or_insert_with(|| Active::new(bin, self.cfg));
        let late = bin < a.out.start_seconds;
        a.observe(p, self.cfg, late);
        finished
    }
    pub fn finish(&mut self) -> Option<Window> {
        self.current.take().map(|a| {
            let w = a.complete();
            self.capacity_limited |= w.integrity.capacity_rejected_packets > 0;
            if w.suppressed {
                self.suppressed += 1
            } else {
                self.published += 1
            }
            w
        })
    }
    pub fn capacity_limited(&self) -> bool {
        self.capacity_limited
    }
    pub fn window_counts(&self) -> (u64, u64) {
        (self.published, self.suppressed)
    }
}
#[derive(Debug, Clone, Copy)]
pub struct SourceCounters {
    pub eligible: u64,
    pub delivered: u64,
    pub dropped: u64,
}
impl SourceCounters {
    pub fn validate(self, records: u64) -> bool {
        self.delivered == records && self.delivered.checked_add(self.dropped) == Some(self.eligible)
    }
}

impl Window {
    /// Stable aggregate-only schema. Small cohorts expose no traffic/quality fields.
    pub fn write_json<W: Write>(&self, mut out: W) -> io::Result<()> {
        write!(out,"{{\"type\":\"aggregate_window\",\"schema_version\":1,\"window_start_seconds\":{},\"window_seconds\":{},\"suppressed\":{},\"sampling_interval\":{}",self.start_seconds,self.duration_seconds,self.suppressed,self.interval)?;
        if self.suppressed {
            return writeln!(
                out,
                ",\"reason\":\"insufficient_sampled_flow_cohort\",\"statistics\":null}}"
            );
        }
        let i = &self.integrity;
        write!(out,",\"statistics\":{{\"contributing_sampled_flows\":{},\"tcp_packets\":{},\"udp_packets\":{},\"other_ip_packets\":{},\"tls_record_candidate_packets\":{},\"quic_long_header_candidate_packets\":{},",self.contributing_flows,self.tcp_packets,self.udp_packets,self.other_ip_packets,if self.tls_flows>=self.minimum_flows{self.tls_record_candidates.to_string()}else{"null".into()},if self.quic_flows>=self.minimum_flows{self.quic_long_header_candidates.to_string()}else{"null".into()})?;
        write!(out,"\"integrity\":{{\"records\":{},\"captured_octets\":{},\"wire_octets\":{},\"snaplen_truncated\":{},\"decoded_ip\":{},\"non_ip\":{},\"decode_incomplete\":{},\"unparsed_fragments\":{},\"unsupported_or_bad_headers\":{},\"unusable_transport\":{},\"fragmented_transport\":{},\"timestamp_regressions\":{},\"late_records\":{},\"unsampled_packets\":{},\"sampled_packets\":{},\"capacity_rejected_packets\":{}}},",i.records,i.captured_octets,i.wire_octets,i.snaplen_truncated,i.decoded,i.non_ip,i.decode_incomplete,i.unparsed_fragments,i.unsupported_or_bad_headers,i.unusable_transport,i.fragmented_transport,i.timestamp_regressions,i.late_records,i.unsampled_packets,i.sampled_packets,i.capacity_rejected_packets)?;
        if self.tcp_flows < self.minimum_flows {
            return writeln!(out, "\"tcp_quality\":null}}}}");
        }
        let q = &self.quality;
        write!(out,"\"tcp_quality\":{{\"sampled_tcp_flows\":{},\"judged_segments\":{},\"retransmission_candidates\":{},\"out_of_order_candidates\":{},\"forward_gap_candidates\":{},\"ambiguous_sequences\":{},\"reused_tuples\":{},\"ambiguous_responses\":{},\"unmatched_responses\":{},\"response_delay_upper_bounds_ms\":[1,5,10,25,50,100,250,1000,30000,null],\"response_delay_samples\":{},\"response_delay_histogram\":{}}}}}}}",self.tcp_flows,q.judged_segments,q.retransmission_candidates,q.out_of_order_candidates,q.forward_gaps,q.ambiguous_sequences,q.reused_tuples,q.ambiguous_responses,q.unmatched_responses,if q.response_samples>=self.minimum_flows as u64{q.response_samples.to_string()}else{"null".into()},if q.response_samples>=self.minimum_flows as u64{format!("{:?}",q.delay_histogram)}else{"null".into()})?;
        writeln!(out)
    }
}
#[cfg(test)]
mod tests;
