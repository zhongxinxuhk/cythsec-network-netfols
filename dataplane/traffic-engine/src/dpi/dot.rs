//! DNS frames from caller-attested TLS application plaintext, never wire decryption.
use std::fmt;

use super::{dns, AppId, Confidence, Detect, Detection};
use crate::record::escape_json_into;

pub const MAX_FRAME_BYTES: usize = 8192;
pub const MAX_MESSAGES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}
impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientToServer => "client_to_server",
            Self::ServerToClient => "server_to_client",
        }
    }
}

/// The caller attests that these are contiguous application bytes from one TLS
/// connection/direction at its frame boundary. This is provenance, not authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    source_id: String,
    session_id: String,
    direction: Direction,
}
impl Context {
    pub fn new(
        source_id: &str,
        session_id: &str,
        direction: Direction,
    ) -> Result<Self, &'static str> {
        let valid_identifier = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        };
        if !valid_identifier(source_id) || !valid_identifier(session_id) {
            return Err("source/session IDs require 1..128 ASCII letters, digits, . _ : -");
        }
        Ok(Self {
            source_id: source_id.into(),
            session_id: session_id.into(),
            direction,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Stopped,
    FrameTooShort,
    FrameBudget,
    MessageBudget,
    MalformedDns,
    UnsupportedDns,
    DirectionMismatch,
    Incomplete,
    Empty,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub stream_offset: u64,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DoT plaintext {:?} at stream offset {}",
            self.kind, self.stream_offset
        )
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub context: Context,
    pub stream_offset: u64,
    pub dns_length: usize,
    pub dns: dns::DnsMessage,
}
impl Message {
    pub fn detection(&self) -> Detection {
        let mut result = self.dns.clone().into_detection();
        result.app = AppId::Dot;
        result.confidence = Confidence::Medium;
        result.rationale = "dot: caller-attested TLS application plaintext and bounded DNS frame; TLS peer authentication unverified";
        result
    }
    /// Separate message-event schema; this does not manufacture a FlowRecord or a five-tuple.
    pub fn to_json(&self) -> String {
        let mut out = format!("{{\"schema_version\":1,\"record_type\":\"tls_plaintext_dns_message\",\"app\":\"dot\",\"app_id\":{},\"outcome\":\"identified\",\"confidence\":\"medium\",\"transport_evidence\":\"caller_attested_tls_termination\",\"tls_peer_authenticated\":null,\"dns_scope\":\"first_question_and_selected_answers\",\"source_id\":", AppId::Dot.as_u32());
        escape_json_into(&mut out, &self.context.source_id);
        out.push_str(",\"session_id\":");
        escape_json_into(&mut out, &self.context.session_id);
        out.push_str(",\"direction\":");
        escape_json_into(&mut out, self.context.direction.as_str());
        out.push_str(&format!(",\"stream_offset\":{},\"dns_length\":{},\"dns\":{{\"id\":{},\"is_response\":{},\"qname\":", self.stream_offset, self.dns_length, self.dns.id, self.dns.is_response));
        if let Some(name) = &self.dns.qname {
            escape_json_into(&mut out, name);
        } else {
            out.push_str("null");
        }
        out.push_str(&format!(
            ",\"qtype\":{},\"qclass\":{},\"rcode\":",
            self.dns.qtype, self.dns.qclass
        ));
        if self.dns.is_response {
            out.push_str(&self.dns.rcode.to_string());
        } else {
            out.push_str("null");
        }
        out.push_str(",\"answer_ips\":[");
        for (i, ip) in self.dns.answer_ips.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            escape_json_into(&mut out, ip);
        }
        out.push_str("]}}");
        out
    }
}

/// One source/session/direction per instance. No heuristic resynchronization after
/// corruption, budget exhaustion, or EOF; create a new instance for a new stream.
pub struct PlaintextStream {
    context: Context,
    pending: Vec<u8>,
    offset: u64,
    messages: usize,
    stopped: bool,
}
impl PlaintextStream {
    pub fn new(context: Context) -> Self {
        Self {
            context,
            pending: Vec::new(),
            offset: 0,
            messages: 0,
            stopped: false,
        }
    }
    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }
    fn error(&mut self, kind: ErrorKind) -> Error {
        self.stopped = true;
        Error {
            kind,
            stream_offset: self.offset,
        }
    }
    /// Emits each complete frame exactly once, independent of chunk boundaries.
    /// Messages emitted before a later error remain a valid prefix, not a complete stream.
    pub fn push(&mut self, mut bytes: &[u8], mut emit: impl FnMut(Message)) -> Result<(), Error> {
        if self.stopped {
            return Err(self.error(ErrorKind::Stopped));
        }
        while !bytes.is_empty() {
            if self.messages == MAX_MESSAGES {
                return Err(self.error(ErrorKind::MessageBudget));
            }
            if self.pending.len() < 2 {
                let n = bytes.len().min(2 - self.pending.len());
                self.pending.extend_from_slice(&bytes[..n]);
                bytes = &bytes[n..];
                if self.pending.len() < 2 {
                    break;
                }
            }
            let length = usize::from(u16::from_be_bytes([self.pending[0], self.pending[1]]));
            if length < 12 {
                return Err(self.error(ErrorKind::FrameTooShort));
            }
            if length > MAX_FRAME_BYTES {
                return Err(self.error(ErrorKind::FrameBudget));
            }
            let n = bytes.len().min(length + 2 - self.pending.len());
            self.pending.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.pending.len() != length + 2 {
                break;
            }
            let body = &self.pending[2..];
            if u16::from_be_bytes([body[4], body[5]]) != 1 {
                return Err(self.error(ErrorKind::UnsupportedDns));
            }
            let dns = match dns::parse(body) {
                Ok(dns) => dns,
                Err(Detect::Rejected) => return Err(self.error(ErrorKind::UnsupportedDns)),
                Err(_) => return Err(self.error(ErrorKind::MalformedDns)),
            };
            if dns.is_response != (self.context.direction == Direction::ServerToClient) {
                return Err(self.error(ErrorKind::DirectionMismatch));
            }
            emit(Message {
                context: self.context.clone(),
                stream_offset: self.offset,
                dns_length: length,
                dns,
            });
            self.offset += (length + 2) as u64;
            self.messages += 1;
            self.pending.clear();
        }
        Ok(())
    }
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.stopped {
            return Err(self.error(ErrorKind::Stopped));
        }
        if !self.pending.is_empty() {
            return Err(self.error(ErrorKind::Incomplete));
        }
        if self.messages == 0 {
            return Err(self.error(ErrorKind::Empty));
        }
        self.stopped = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Context {
        Context::new("tls-endpoint", "session-1", Direction::ClientToServer).unwrap()
    }
    fn query(id: u16) -> Vec<u8> {
        let mut p = [id, 0x0100, 1, 0, 0, 0]
            .into_iter()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>();
        p.extend(b"\x08resolver\x07example\x00\x00\x01\x00\x01");
        p
    }
    fn frame(body: &[u8]) -> Vec<u8> {
        let mut p = (body.len() as u16).to_be_bytes().to_vec();
        p.extend(body);
        p
    }
    #[test]
    fn every_split_and_coalesced_frames_preserve_provenance() {
        let first = frame(&query(0x1234));
        let mut all = first.clone();
        all.extend(frame(&query(0x5678)));
        for cut in 0..=all.len() {
            let mut stream = PlaintextStream::new(context());
            let mut out = Vec::new();
            stream.push(&all[..cut], |m| out.push(m)).unwrap();
            assert!(stream.pending_bytes() <= MAX_FRAME_BYTES + 2);
            stream.push(&all[cut..], |m| out.push(m)).unwrap();
            stream.finish().unwrap();
            assert_eq!(
                out.iter().map(|m| m.dns.id).collect::<Vec<_>>(),
                [0x1234, 0x5678]
            );
            assert_eq!(out[1].stream_offset, first.len() as u64);
            assert_eq!(out[0].context, context());
            assert_eq!(out[0].detection().app, AppId::Dot);
            assert_eq!(
                out[0].detection().qname.as_deref(),
                Some("resolver.example")
            );
            assert!(out[0].to_json().contains("caller_attested_tls_termination"));
        }
    }
    #[test]
    fn malformed_frame_cannot_borrow_or_resynchronize() {
        let good = frame(&query(1));
        let mut short = query(2);
        short.pop();
        let mut bytes = good.clone();
        bytes.extend(frame(&short));
        bytes.extend(&good);
        for size in [1, 2, bytes.len()] {
            let mut stream = PlaintextStream::new(context());
            let mut out = Vec::new();
            let mut error = None;
            for part in bytes.chunks(size) {
                if let Err(e) = stream.push(part, |m| out.push(m)) {
                    error = Some(e);
                    break;
                }
            }
            assert_eq!(out.len(), 1);
            assert_eq!(
                error,
                Some(Error {
                    kind: ErrorKind::MalformedDns,
                    stream_offset: good.len() as u64
                })
            );
            assert_eq!(
                stream.push(&good, |_| {}).unwrap_err().kind,
                ErrorKind::Stopped
            );
        }
    }
    #[test]
    fn eof_direction_and_budgets_are_explicit() {
        assert!(Context::new("", "session", Direction::ClientToServer).is_err());
        assert!(Context::new("source", "bad\nsource", Direction::ClientToServer).is_err());
        for (bytes, expected) in [
            (vec![0, 0], ErrorKind::FrameTooShort),
            (vec![0, 11], ErrorKind::FrameTooShort),
            (
                ((MAX_FRAME_BYTES + 1) as u16).to_be_bytes().to_vec(),
                ErrorKind::FrameBudget,
            ),
        ] {
            assert_eq!(
                PlaintextStream::new(context())
                    .push(&bytes, |_| {})
                    .unwrap_err()
                    .kind,
                expected
            );
        }
        for bytes in [vec![0], frame(&query(1))[..5].to_vec()] {
            let mut stream = PlaintextStream::new(context());
            stream.push(&bytes, |_| {}).unwrap();
            assert_eq!(stream.finish().unwrap_err().kind, ErrorKind::Incomplete);
        }
        assert_eq!(
            PlaintextStream::new(context()).finish().unwrap_err().kind,
            ErrorKind::Empty
        );
        let mut response = query(1);
        response[2] = 0x81;
        assert_eq!(
            PlaintextStream::new(context())
                .push(&frame(&response), |_| {})
                .unwrap_err()
                .kind,
            ErrorKind::DirectionMismatch
        );
        let mut stream = PlaintextStream::new(context());
        let mut count = 0;
        let all = frame(&query(1)).repeat(MAX_MESSAGES + 1);
        assert_eq!(
            stream.push(&all, |_| count += 1).unwrap_err().kind,
            ErrorKind::MessageBudget
        );
        assert_eq!(count, MAX_MESSAGES);
        let tls = include_bytes!("../../../../datasets/dpi/payloads/tls-basic.bin");
        for port in [443, 853, 40000] {
            assert!(
                !matches!(super::super::identify(tls, 6, port), super::super::Outcome::Identified(d) if d.app == AppId::Dot)
            );
        }
    }
}
