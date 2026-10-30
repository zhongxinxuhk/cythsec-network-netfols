//! Header-only, ephemeral TCP quality state. No payload, addresses or identifiers are exported.
use crate::reassembly::seq::{seq_gt, seq_le, seq_lt, SEQ_HALF};
use crate::reassembly::tcp::TcpFlags;

pub const DELAY_BOUNDS_US: [u64; 9] = [
    1_000, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 1_000_000, 30_000_000,
];
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Quality {
    pub judged_segments: u64,
    pub retransmission_candidates: u64,
    pub out_of_order_candidates: u64,
    pub forward_gaps: u64,
    pub ambiguous_sequences: u64,
    pub reused_tuples: u64,
    pub response_samples: u64,
    pub ambiguous_responses: u64,
    pub unmatched_responses: u64,
    pub delay_histogram: [u64; 10],
}
impl Quality {
    pub fn merge(&mut self, other: &Self) {
        self.judged_segments += other.judged_segments;
        self.retransmission_candidates += other.retransmission_candidates;
        self.out_of_order_candidates += other.out_of_order_candidates;
        self.forward_gaps += other.forward_gaps;
        self.ambiguous_sequences += other.ambiguous_sequences;
        self.reused_tuples += other.reused_tuples;
        self.response_samples += other.response_samples;
        self.ambiguous_responses += other.ambiguous_responses;
        self.unmatched_responses += other.unmatched_responses;
        for (a, b) in self.delay_histogram.iter_mut().zip(other.delay_histogram) {
            *a += b;
        }
    }
}
#[derive(Default)]
struct Sequence {
    cursor: Option<u32>,
    high: u32,
}
impl Sequence {
    fn observe(&mut self, seq: u32, consume: u32, out: &mut Quality) {
        if consume == 0 {
            return;
        }
        out.judged_segments += 1;
        let end = seq.wrapping_add(consume);
        let Some(cursor) = self.cursor else {
            self.cursor = Some(end);
            self.high = end;
            return;
        };
        if seq.wrapping_sub(cursor) == SEQ_HALF || end.wrapping_sub(cursor) == SEQ_HALF {
            out.ambiguous_sequences += 1;
            return;
        }
        if seq_le(end, cursor) {
            out.retransmission_candidates += 1;
        } else if seq_lt(seq, cursor) {
            out.out_of_order_candidates += 1;
            if seq_gt(end, self.high) {
                self.high = end;
            }
        } else if seq == cursor {
            if seq_lt(end, self.high) {
                out.out_of_order_candidates += 1;
            }
            self.cursor = Some(end);
            if seq_gt(end, self.high) {
                self.high = end;
            }
        } else {
            out.forward_gaps += 1;
            if seq_gt(end, self.high) {
                self.high = end;
            }
        }
    }
}
#[derive(Clone, Copy)]
struct Syn {
    seq: u32,
    at: u64,
    ambiguous: bool,
}
#[derive(Default)]
pub struct TcpQuality {
    seq: [Sequence; 2],
    syn: [Option<Syn>; 2],
    responded: bool,
}
impl TcpQuality {
    pub fn observe(
        &mut self,
        side: usize,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        payload_len: u32,
        now: u64,
    ) -> Quality {
        let mut out = Quality::default();
        if flags.syn && !flags.ack {
            if self.syn[side]
                .map(|s| s.seq != seq)
                .unwrap_or(self.seq[side].cursor.is_some())
            {
                *self = Self::default();
                out.reused_tuples += 1;
            }
            match &mut self.syn[side] {
                Some(s) => s.ambiguous = true,
                slot @ None => {
                    *slot = Some(Syn {
                        seq,
                        at: now,
                        ambiguous: payload_len != 0,
                    })
                }
            }
        }
        if flags.syn && flags.ack && !self.responded {
            if let Some(s) = self.syn[1 - side] {
                if ack != s.seq.wrapping_add(1) {
                    out.unmatched_responses += 1;
                } else if s.ambiguous || now < s.at || now.saturating_sub(s.at) > 30_000_000 {
                    out.ambiguous_responses += 1;
                    self.responded = true;
                } else {
                    let delta = now - s.at;
                    let bucket = DELAY_BOUNDS_US
                        .iter()
                        .position(|b| delta <= *b)
                        .unwrap_or(9);
                    out.delay_histogram[bucket] += 1;
                    out.response_samples += 1;
                    self.responded = true;
                }
            } else {
                out.unmatched_responses += 1;
            }
        }
        self.seq[side].observe(
            seq,
            payload_len + u32::from(flags.syn) + u32::from(flags.fin),
            &mut out,
        );
        out
    }
}
