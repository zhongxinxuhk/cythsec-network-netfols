//! Bounded RFC 8484 representations from caller-attested, decoded HTTPS messages.
//! HTTP/2/3 framing, source authorization and TLS authentication belong to the host.
use super::{
    dns,
    dot::{valid_identifier, Context, Direction},
    AppId, Confidence, Detection,
};
use crate::record::escape_json_into;

pub const MAX_DNS_BYTES: usize = 8192;
const MAX_URL_BYTES: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidContext,
    InvalidUrl,
    UnsupportedTemplate,
    InvalidBase64,
    DnsBudget,
    IncompleteBody,
    UnsupportedMedia,
    UnsupportedEncoding,
    HttpMetadata,
    HttpStatus,
    UnsupportedDns,
    DirectionMismatch,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DoH message {self:?}")
    }
}
impl std::error::Error for Error {}

/// One complete, transfer-decoded HTTP entity supplied by the owning HTTPS stack.
/// The host must reject duplicate/conflicting framing headers before normalization.
pub struct HttpMessage<'a> {
    pub method: Option<&'a str>,
    pub status: Option<u16>,
    pub content_type: Option<&'a str>,
    pub content_encoding: Option<&'a str>,
    pub content_length: Option<usize>,
    pub body: &'a [u8],
}

pub struct Message {
    pub context: Context,
    pub request_id: String,
    pub authority: String,
    pub path: String,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub dns: dns::DnsMessage,
}

fn endpoint(url: &str) -> Result<(&str, &str, Option<&str>), Error> {
    if url.len() > MAX_URL_BYTES
        || !url.is_ascii()
        || url.bytes().any(|b| b <= 32 || b == 127)
        || url.contains('#')
    {
        return Err(Error::InvalidUrl);
    }
    let rest = url.strip_prefix("https://").ok_or(Error::InvalidUrl)?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return Err(Error::InvalidUrl);
    }
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let close = ipv6.find(']').ok_or(Error::InvalidUrl)?;
        ipv6[..close]
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| Error::InvalidUrl)?;
        let tail = &ipv6[close + 1..];
        (
            &ipv6[..close],
            if tail.is_empty() {
                None
            } else {
                Some(tail.strip_prefix(':').ok_or(Error::InvalidUrl)?)
            },
        )
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        if host.len() > 253
            || host.split('.').any(|part| {
                part.is_empty()
                    || part.len() > 63
                    || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(Error::InvalidUrl);
        }
        (host, port)
    };
    if host.is_empty()
        || port.is_some_and(|p| {
            p.is_empty()
                || !p.bytes().all(|b| b.is_ascii_digit())
                || p.parse::<u16>().map_or(true, |v| v == 0)
        })
    {
        return Err(Error::InvalidUrl);
    }
    let target = &rest[end..];
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(p, q)| (p, Some(q)));
    let path = if path.is_empty() { "/" } else { path };
    if !path.starts_with('/') || path.contains('\\') {
        return Err(Error::InvalidUrl);
    }
    Ok((authority, path, query))
}

fn base64url(text: &str) -> Result<Vec<u8>, Error> {
    if text.len() > (MAX_DNS_BYTES * 4).div_ceil(3) {
        return Err(Error::DnsBudget);
    }
    if text.is_empty() || text.len() % 4 == 1 {
        return Err(Error::InvalidBase64);
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in text.bytes() {
        let value = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(Error::InvalidBase64),
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err(Error::InvalidBase64);
    }
    Ok(out)
}

pub fn parse_https(
    context: Context,
    request_id: &str,
    url: &str,
    http: HttpMessage<'_>,
) -> Result<Message, Error> {
    if !valid_identifier(request_id) {
        return Err(Error::InvalidContext);
    }
    let (authority, path, query) = endpoint(url)?;
    if http.body.len() > MAX_DNS_BYTES {
        return Err(Error::DnsBudget);
    }
    if http.content_length.is_some_and(|v| v != http.body.len()) {
        return Err(Error::IncompleteBody);
    }
    if http
        .content_encoding
        .is_some_and(|v| !v.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(Error::UnsupportedEncoding);
    }
    let media = || {
        http.content_type
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/dns-message"))
    };
    let bytes = match context.direction() {
        Direction::ClientToServer => {
            if http.status.is_some() {
                return Err(Error::HttpMetadata);
            }
            match http.method {
                Some("GET") => {
                    if !http.body.is_empty() || http.content_type.is_some() && !media() {
                        return Err(Error::HttpMetadata);
                    }
                    let encoded = query
                        .and_then(|q| q.strip_prefix("dns="))
                        .ok_or(Error::UnsupportedTemplate)?;
                    base64url(encoded)?
                }
                Some("POST") => {
                    if query.is_some() {
                        return Err(Error::UnsupportedTemplate);
                    }
                    if !media() {
                        return Err(Error::UnsupportedMedia);
                    }
                    http.body.to_vec()
                }
                _ => return Err(Error::HttpMetadata),
            }
        }
        Direction::ServerToClient => {
            if http.method.is_some() {
                return Err(Error::HttpMetadata);
            }
            if !http.status.is_some_and(|v| (200..=299).contains(&v)) {
                return Err(Error::HttpStatus);
            }
            if !media() {
                return Err(Error::UnsupportedMedia);
            }
            http.body.to_vec()
        }
    };
    if bytes.len() < 12
        || bytes.len() > MAX_DNS_BYTES
        || u16::from_be_bytes([bytes[4], bytes[5]]) != 1
    {
        return Err(Error::UnsupportedDns);
    }
    let parsed = dns::parse(&bytes).map_err(|_| Error::UnsupportedDns)?;
    if parsed.is_response != (context.direction() == Direction::ServerToClient) {
        return Err(Error::DirectionMismatch);
    }
    Ok(Message {
        context,
        request_id: request_id.into(),
        authority: authority.into(),
        path: path.into(),
        method: http.method.map(str::to_string),
        status: http.status,
        dns: parsed,
    })
}

impl Message {
    pub fn detection(&self) -> Detection {
        let mut result = self.dns.clone().into_detection();
        result.app = AppId::Doh;
        result.confidence = Confidence::Medium;
        result.rationale = "doh: caller-attested decoded HTTPS message, HTTP representation and bounded DNS evidence; source and TLS authentication unverified";
        result
    }
    pub fn to_json(&self) -> String {
        let mut out = format!("{{\"schema_version\":1,\"record_type\":\"https_dns_message\",\"app\":\"doh\",\"app_id\":{},\"outcome\":\"identified\",\"confidence\":\"medium\",\"transport_evidence\":\"caller_attested_decoded_https\",\"tls_peer_authenticated\":null,\"dns_scope\":\"first_question_and_selected_answers\",\"source_id\":", AppId::Doh.as_u32());
        escape_json_into(&mut out, self.context.source_id());
        out.push_str(",\"session_id\":");
        escape_json_into(&mut out, self.context.session_id());
        out.push_str(",\"direction\":");
        escape_json_into(&mut out, self.context.direction().as_str());
        out.push_str(",\"request_id\":");
        escape_json_into(&mut out, &self.request_id);
        out.push_str(",\"https_authority\":");
        escape_json_into(&mut out, &self.authority);
        out.push_str(",\"endpoint_path\":");
        escape_json_into(&mut out, &self.path);
        out.push_str(",\"method\":");
        if let Some(v) = &self.method {
            escape_json_into(&mut out, v);
        } else {
            out.push_str("null");
        }
        out.push_str(",\"http_status\":");
        if let Some(v) = self.status {
            out.push_str(&v.to_string());
        } else {
            out.push_str("null");
        }
        out.push_str(&format!(
            ",\"dns\":{{\"id\":{},\"is_response\":{},\"qname\":",
            self.dns.id, self.dns.is_response
        ));
        if let Some(v) = &self.dns.qname {
            escape_json_into(&mut out, v);
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
        for (i, v) in self.dns.answer_ips.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            escape_json_into(&mut out, v);
        }
        out.push_str("]}}");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(direction: Direction) -> Context {
        Context::new("https-stack", "connection-1", direction).unwrap()
    }
    fn query(response: bool) -> Vec<u8> {
        let mut p = [0u16, if response { 0x8180 } else { 0x0100 }, 1, 0, 0, 0]
            .into_iter()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>();
        p.extend(b"\x08resolver\x07example\x00\x00\x01\x00\x01");
        p
    }
    fn post(body: &[u8]) -> HttpMessage<'_> {
        HttpMessage {
            method: Some("POST"),
            status: None,
            content_type: Some("application/dns-message"),
            content_encoding: None,
            content_length: Some(body.len()),
            body,
        }
    }
    #[test]
    fn post_and_response_keep_http_identity_and_dns_semantics() {
        let q = query(false);
        let m = parse_https(
            context(Direction::ClientToServer),
            "stream-1",
            "https://dns.example/custom",
            post(&q),
        )
        .unwrap();
        assert_eq!(m.dns.id, 0);
        assert_eq!(m.dns.qname.as_deref(), Some("resolver.example"));
        assert_eq!(m.request_id, "stream-1");
        assert_eq!(m.path, "/custom");
        assert_eq!(m.detection().app, AppId::Doh);
        let mut r = query(true);
        r[3] = 0x83;
        let mut h = post(&r);
        h.method = None;
        h.status = Some(200);
        let m = parse_https(
            context(Direction::ServerToClient),
            "stream-2",
            "https://[2001:db8::1]:8443/custom",
            h,
        )
        .unwrap();
        assert_eq!(m.dns.rcode, 3);
        assert_eq!(m.status, Some(200));
        assert!(m.to_json().contains("caller_attested_decoded_https"));
    }
    #[test]
    fn get_encoding_is_url_safe_unpadded_and_canonical() {
        assert_eq!(base64url("AAEC-_8").unwrap(), [0, 1, 2, 251, 255]);
        for v in ["", "A", "AA=", "AA+", "AA/", "AB", "AA&dns=AA", "%41A"] {
            assert!(base64url(v).is_err(), "{v}");
        }
        let encoded = "AAABAAABAAAAAAAACHJlc29sdmVyB2V4YW1wbGUAAAEAAQ";
        let h = HttpMessage {
            method: Some("GET"),
            status: None,
            content_type: None,
            content_encoding: None,
            content_length: Some(0),
            body: &[],
        };
        assert!(parse_https(
            context(Direction::ClientToServer),
            "get-1",
            &format!("https://dns.example/query?dns={encoded}"),
            h
        )
        .is_ok());
    }
    #[test]
    fn metadata_lengths_media_and_direction_do_not_fall_back() {
        let q = query(false);
        for url in [
            "http://dns.example/query",
            "https://user:pass@dns.example/query",
            "https://dns.example:0/query",
            "https://dns.example/q#part",
            "https://dns.example/q?dns=AA",
        ] {
            assert!(parse_https(context(Direction::ClientToServer), "one", url, post(&q)).is_err());
        }
        let mut h = post(&q);
        h.content_length = Some(q.len() + 1);
        assert_eq!(
            parse_https(
                context(Direction::ClientToServer),
                "one",
                "https://dns.example/q",
                h
            )
            .err(),
            Some(Error::IncompleteBody)
        );
        let mut h = post(&q);
        h.content_type = Some("application/json");
        assert_eq!(
            parse_https(
                context(Direction::ClientToServer),
                "one",
                "https://dns.example/q",
                h
            )
            .err(),
            Some(Error::UnsupportedMedia)
        );
        let mut h = post(&q);
        h.content_encoding = Some("gzip");
        assert_eq!(
            parse_https(
                context(Direction::ClientToServer),
                "one",
                "https://dns.example/q",
                h
            )
            .err(),
            Some(Error::UnsupportedEncoding)
        );
        let r = query(true);
        assert_eq!(
            parse_https(
                context(Direction::ClientToServer),
                "one",
                "https://dns.example/q",
                post(&r)
            )
            .err(),
            Some(Error::DirectionMismatch)
        );
        let mut h = post(&r);
        h.method = None;
        h.status = Some(500);
        assert_eq!(
            parse_https(
                context(Direction::ServerToClient),
                "one",
                "https://dns.example/q",
                h
            )
            .err(),
            Some(Error::HttpStatus)
        );
        assert!(parse_https(
            context(Direction::ClientToServer),
            "bad id",
            "https://dns.example/q",
            post(&q)
        )
        .is_err());
        let huge = vec![0; MAX_DNS_BYTES + 1];
        assert_eq!(
            parse_https(
                context(Direction::ClientToServer),
                "one",
                "https://dns.example/q",
                post(&huge)
            )
            .err(),
            Some(Error::DnsBudget)
        );
        assert!(
            !matches!(super::super::identify(b"GET /dns-query HTTP/1.1\r\nHost: dns.example\r\n\r\n",6,443),super::super::Outcome::Identified(d) if d.app==AppId::Doh)
        );
    }
}
