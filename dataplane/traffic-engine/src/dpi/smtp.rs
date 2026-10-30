//! Bounded SMTP (RFC 5321) command and reply recognition.
//!
//! 三个边界决定，都不是风格问题：
//!
//! 1. **只在 25/587/2525 的传输上下文里启用**。465 是隐式 TLS（SMTPS），
//!    那里看到的字节是 TLS 记录，必须留给 TLS 检测器；把 465 纳入明文 SMTP
//!    端口的后果是 STARTTLS 前后的口径混在一起，且会与 TLS 首包争抢命中。
//! 2. **只判定第一条消息**（一行命令，或一条多行应答）。SMTP 允许流水线，
//!    但识别不需要读完整个会话；后续命令属于重组/事务层，本模块不累积字节。
//! 3. **应答行必须完整（含 CRLF）才算命中**。FTP 的应答也是三位数字，
//!    端口上下文是唯一区分依据，因此裸应答只给 `Medium`；只有带 `SMTP`/`ESMTP`
//!    关键字的 220 问候才升级为 `High`。极短前缀（`22`、`250`）一律 `NeedMore`。
//!
//! 这里不解析正文（DATA 段）、不还原邮件、不判断认证或投递结果；
//! 也不提供任何规避审查、主动探测或封锁能力。

use super::{AppId, Confidence, Detect, Detection};

/// 明文 SMTP 的服务端口。465 刻意不在其中（隐式 TLS）。
const PORTS: [u16; 3] = [25, 587, 2525];
const MAX_BYTES: usize = 8192;
const MAX_LINE: usize = 2048;
const MAX_LINES: usize = 16;
const MAX_VERB: usize = 8;
const MAX_DOMAIN: usize = 255;

/// 已登记的 SMTP 命令动词（RFC 5321 及 STARTTLS/AUTH/BDAT 扩展）。
const VERBS: [&str; 20] = [
    "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "SEND", "SOML", "SAML", "VRFY", "EXPN", "HELP",
    "NOOP", "QUIT", "TURN", "ETRN", "ATRN", "AUTH", "STARTTLS", "BDAT",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// 大写动词（线上大小写不敏感，统一成大写便于比对）。
    pub verb: String,
    /// 单个分隔空格之后的原始参数；无参数时为 `None`。
    pub argument: Option<String>,
    /// MAIL/RCPT 校验过的 `<path>` 内容（`<>` 为空串），其他动词为 `None`。
    pub path: Option<String>,
    /// `<path>` 之后的 ESMTP 参数、AUTH 初始响应或 BDAT 的 `LAST`。
    pub parameter: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    /// 每行去掉 `code` 与分隔符之后的文本，按线上顺序。
    pub lines: Vec<String>,
    /// 多行应答里首词为纯字母的关键字（如 `PIPELINING`/`STARTTLS`），大写。
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Command(Command),
    Reply(Reply),
}

impl Message {
    /// 置信度：完整的 EHLO/HELO/MAIL/RCPT 与带 SMTP 关键字的问候是协议自身的强证据；
    /// 单条短命令或裸应答只靠端口上下文，给 Medium。
    pub fn confidence(&self) -> Confidence {
        match self {
            Message::Command(c) if matches!(c.verb.as_str(), "HELO" | "EHLO" | "MAIL" | "RCPT") => {
                Confidence::High
            }
            Message::Reply(r) => {
                if r.code == 220
                    && r.lines
                        .first()
                        .is_some_and(|line| contains_ascii_case_insensitive(line, "SMTP"))
                {
                    Confidence::High
                } else {
                    Confidence::Medium
                }
            }
            Message::Command(_) => Confidence::Medium,
        }
    }

    pub fn rationale(&self) -> &'static str {
        match self {
            Message::Command(c) => match c.verb.as_str() {
                "HELO" | "EHLO" => "smtp greeting command with a domain argument",
                "MAIL" | "RCPT" => "smtp envelope path command",
                "DATA" | "RSET" | "QUIT" | "STARTTLS" | "TURN" => "smtp session command",
                "AUTH" | "BDAT" | "ETRN" | "ATRN" => "smtp extension command",
                _ => "smtp command with a printable argument",
            },
            Message::Reply(r) if r.code == 220 => "smtp greeting reply on the service port",
            Message::Reply(r) if r.lines.len() > 1 => "smtp multiline reply on the service port",
            Message::Reply(_) => "smtp reply on the service port",
        }
    }
}

/// 传输上下文：只按服务端口路由，端口本身不构成命中证据。
pub fn transport(src_port: u16, dst_port: u16) -> bool {
    PORTS.contains(&dst_port) || PORTS.contains(&src_port)
}

pub fn detect(payload: &[u8]) -> Detect {
    match parse(payload) {
        Ok(message) => Detect::Hit(Detection::new(
            AppId::Smtp,
            message.confidence(),
            message.rationale(),
        )),
        Err(verdict) => verdict,
    }
}

pub fn parse(payload: &[u8]) -> Result<Message, Detect> {
    let Some(first) = payload.first() else {
        return Err(Detect::NeedMore);
    };
    if payload.len() > MAX_BYTES {
        return Err(Detect::NeedMore);
    }
    match first {
        b'0'..=b'9' => parse_reply(payload).map(Message::Reply),
        b'A'..=b'Z' | b'a'..=b'z' => parse_command(payload).map(Message::Command),
        // 不是 SMTP 的开头（TLS 记录、POP3 的 `+OK`、IMAP 的 `* OK` 等）：
        // 明确拒绝，让框架继续试其他检测器。
        _ => Err(Detect::Rejected),
    }
}

fn parse_command(payload: &[u8]) -> Result<Command, Detect> {
    let mut end = 0;
    while end < payload.len() && end < MAX_VERB && payload[end].is_ascii_alphabetic() {
        end += 1;
    }
    if end == 0 {
        return Err(Detect::Rejected);
    }
    let raw = &payload[..end];
    let verb = to_ascii_upper(raw);
    let known = VERBS.contains(&verb.as_str());
    if !known {
        // 词还没收全（`EHL`）：再给字节就可能认出，保持 NeedMore；
        // 收全了却不在动词表里（`GET`/`SSH`）就不是 SMTP。
        if payload.len() == end
            && VERBS
                .iter()
                .any(|candidate| starts_with_ignore_ascii_case(candidate.as_bytes(), raw))
        {
            return Err(Detect::NeedMore);
        }
        return Err(Detect::Rejected);
    }
    let (argument, _) = match payload.get(end) {
        None => return Err(Detect::NeedMore),
        Some(b' ') => {
            let (line, next) = read_line(payload, end + 1)?;
            (Some(String::from_utf8_lossy(line).into_owned()), next)
        }
        Some(b'\r') => {
            require_lf(payload, end)?;
            (None, end + 2)
        }
        Some(b'\n') | Some(_) => return Err(Detect::Malformed),
    };
    // 只关心第一条命令；流水线里的后续命令留给重组/事务层。

    let mut path = None;
    let mut parameter = None;
    match verb.as_str() {
        "HELO" | "EHLO" => {
            let domain = argument.as_deref().ok_or(Detect::Malformed)?;
            validate_domain(domain)?;
        }
        "MAIL" => {
            let (parsed_path, parsed_parameter) = parse_path(argument.as_deref(), "FROM:")?;
            path = Some(parsed_path);
            parameter = parsed_parameter;
        }
        "RCPT" => {
            let (parsed_path, parsed_parameter) = parse_path(argument.as_deref(), "TO:")?;
            path = Some(parsed_path);
            parameter = parsed_parameter;
        }
        "DATA" | "RSET" | "QUIT" | "STARTTLS" | "TURN" => {
            if argument.as_deref().is_some_and(|arg| !arg.is_empty()) {
                return Err(Detect::Malformed);
            }
        }
        "AUTH" => {
            let arg = argument.as_deref().ok_or(Detect::Malformed)?;
            validate_auth(arg)?;
            parameter = Some(arg.to_string());
        }
        "BDAT" => {
            let arg = argument.as_deref().ok_or(Detect::Malformed)?;
            validate_bdat(arg)?;
            parameter = Some(arg.to_string());
        }
        // NOOP/HELP/VRFY/EXPN/SEND/SOML/SAML/ETRN/ATRN 允许自由文本参数，
        // 只保留可打印性校验（read_line 已保证）。
        _ => {}
    }
    Ok(Command {
        verb,
        argument,
        path,
        parameter,
    })
}

fn parse_reply(payload: &[u8]) -> Result<Reply, Detect> {
    let mut offset = 0;
    let mut code = None;
    let mut lines = Vec::new();
    let mut extensions = Vec::new();
    loop {
        if lines.len() >= MAX_LINES {
            return Err(Detect::NeedMore);
        }
        let (line, next) = read_line(payload, offset)?;
        if line.len() < 3 {
            // 行已以 CRLF 结束却不足三位：不是 SMTP 应答；若已在多行应答中途，
            // 则是自相矛盾。两种都不该用 NeedMore 再等字节。
            return Err(if code.is_some() {
                Detect::Malformed
            } else {
                Detect::Rejected
            });
        }
        if !line[..3].iter().all(u8::is_ascii_digit) {
            return Err(if code.is_some() {
                // 多行应答中途出现非数字行：自相矛盾，补字节也救不回来。
                Detect::Malformed
            } else {
                Detect::Rejected
            });
        }
        let current = parse_code(&line[..3])?;
        match code {
            Some(expected) if expected != current => return Err(Detect::Malformed),
            None => code = Some(current),
            _ => {}
        }
        let (text, final_line) = match line.get(3).copied() {
            Some(b'-') => (&line[4..], false),
            Some(b' ') => (&line[4..], true),
            None => (&line[3..], true),
            Some(_) => return Err(Detect::Malformed),
        };
        lines.push(String::from_utf8_lossy(text).into_owned());
        if let Some(keyword) = first_alpha_word(text) {
            extensions.push(keyword);
        }
        offset = next;
        if final_line {
            return Ok(Reply {
                code: code.unwrap_or(0),
                lines,
                extensions,
            });
        }
        if offset >= payload.len() {
            // 多行应答还差后续行：这是"还没到"，不是畸形。
            return Err(Detect::NeedMore);
        }
    }
}

/// 读取一行（不含 CRLF），只接受可打印 ASCII 与 HTAB。
///
/// 无 CRLF → `NeedMore`（可能是捕获截断）；裸 LF、CR 后不是 LF、其他控制字节
/// → `Malformed`。行长超过 `MAX_LINE` → `NeedMore`（预算耗尽，不冒充完整）。
fn read_line(payload: &[u8], start: usize) -> Result<(&[u8], usize), Detect> {
    let mut i = start;
    while i < payload.len() {
        match payload[i] {
            b'\r' => {
                if i + 1 >= payload.len() {
                    return Err(Detect::NeedMore);
                }
                if payload[i + 1] != b'\n' {
                    return Err(Detect::Malformed);
                }
                return Ok((&payload[start..i], i + 2));
            }
            b'\n' => return Err(Detect::Malformed),
            b if b == b'\t' || (0x20..=0x7e).contains(&b) => {
                if i - start >= MAX_LINE {
                    return Err(Detect::NeedMore);
                }
                i += 1;
            }
            _ => return Err(Detect::Malformed),
        }
    }
    Err(Detect::NeedMore)
}

fn require_lf(payload: &[u8], cr: usize) -> Result<(), Detect> {
    match payload.get(cr + 1) {
        Some(b'\n') => Ok(()),
        Some(_) => Err(Detect::Malformed),
        None => Err(Detect::NeedMore),
    }
}

fn parse_code(digits: &[u8]) -> Result<u16, Detect> {
    let class = digits[0];
    if !(b'2'..=b'5').contains(&class) || digits[1] > b'5' {
        // 不是 SMTP 应答类别（1xx/6xx-9xx 或第二位非法）：明确拒绝。
        return Err(Detect::Rejected);
    }
    Ok(u16::from(class - b'0') * 100
        + u16::from(digits[1] - b'0') * 10
        + u16::from(digits[2] - b'0'))
}

fn validate_domain(domain: &str) -> Result<(), Detect> {
    if domain.is_empty() || domain.len() > MAX_DOMAIN || domain.contains(' ') {
        return Err(Detect::Malformed);
    }
    if let Some(inner) = domain.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else {
            return Err(Detect::Malformed);
        };
        if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
            return Err(Detect::Malformed);
        }
        return Ok(());
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err(Detect::Malformed);
    }
    if !domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
    {
        return Err(Detect::Malformed);
    }
    Ok(())
}

fn parse_path(argument: Option<&str>, keyword: &str) -> Result<(String, Option<String>), Detect> {
    let argument = argument.ok_or(Detect::Malformed)?;
    if argument.len() < keyword.len() || !argument[..keyword.len()].eq_ignore_ascii_case(keyword) {
        return Err(Detect::Malformed);
    }
    // RFC 5321 写作 `MAIL FROM:<path>`（冒号后不空格）；部分实现会多打一个空格，
    // 两者都接受，但只允许一个 —— 两个空格说明参数本身以空格开头，按畸形处理。
    let rest = argument[keyword.len()..]
        .strip_prefix(' ')
        .unwrap_or(&argument[keyword.len()..]);
    let rest = rest.strip_prefix('<').ok_or(Detect::Malformed)?;
    let close = rest.find('>').ok_or(Detect::Malformed)?;
    let path = &rest[..close];
    if path.contains(' ') || path.contains('<') {
        return Err(Detect::Malformed);
    }
    let tail = &rest[close + 1..];
    let parameter = if tail.is_empty() {
        None
    } else {
        let value = tail.strip_prefix(' ').ok_or(Detect::Malformed)?;
        if value.is_empty() {
            return Err(Detect::Malformed);
        }
        Some(value.to_string())
    };
    Ok((path.to_string(), parameter))
}

fn validate_auth(argument: &str) -> Result<(), Detect> {
    let mechanism = argument.split(' ').next().unwrap_or("");
    if mechanism.is_empty()
        || !mechanism
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(Detect::Malformed);
    }
    Ok(())
}

fn validate_bdat(argument: &str) -> Result<(), Detect> {
    let mut parts = argument.splitn(2, ' ');
    let size = parts.next().unwrap_or("");
    if size.is_empty() || size.len() > 9 || !size.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Detect::Malformed);
    }
    if let Some(rest) = parts.next() {
        if !rest.eq_ignore_ascii_case("LAST") {
            return Err(Detect::Malformed);
        }
    }
    Ok(())
}

fn first_alpha_word(text: &[u8]) -> Option<String> {
    let word = text.split(|b| *b == b' ').next().unwrap_or(&[]);
    if word.len() < 3 || word.len() > 32 || !word.iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    Some(to_ascii_upper(word))
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn starts_with_ignore_ascii_case(candidate: &[u8], prefix: &[u8]) -> bool {
    candidate.len() >= prefix.len() && candidate[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn to_ascii_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_ascii_uppercase)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_commands_and_envelope_paths_are_bounded() {
        let greeting = parse(b"220 mail.example.com ESMTP Postfix\r\n").unwrap();
        assert_eq!(greeting.confidence(), Confidence::High);
        assert!(matches!(greeting, Message::Reply(ref r) if r.code == 220));

        let ehlo = parse(b"ehlo client.example\r\n").unwrap();
        assert_eq!(ehlo.confidence(), Confidence::High);
        assert!(matches!(ehlo, Message::Command(ref c) if c.verb == "EHLO"));

        let mail = parse(b"MAIL FROM:<alice@example.com> SIZE=100\r\n").unwrap();
        assert_eq!(mail.confidence(), Confidence::High);
        match mail {
            Message::Command(command) => {
                assert_eq!(command.path.as_deref(), Some("alice@example.com"));
                assert_eq!(command.parameter.as_deref(), Some("SIZE=100"));
            }
            _ => panic!("expected command"),
        }

        let empty_path = parse(b"RCPT TO:<>\r\n").unwrap();
        assert_eq!(empty_path.confidence(), Confidence::High);
        assert!(matches!(empty_path, Message::Command(ref c) if c.path.as_deref() == Some("")));
    }

    #[test]
    fn multiline_replies_keep_code_continuation_and_keywords() {
        let reply = parse(
            b"250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n",
        )
        .unwrap();
        assert_eq!(reply.confidence(), Confidence::Medium);
        match reply {
            Message::Reply(reply) => {
                assert_eq!(reply.code, 250);
                assert_eq!(reply.lines.len(), 4);
                assert_eq!(
                    reply.extensions,
                    vec![
                        "PIPELINING".to_string(),
                        "SIZE".to_string(),
                        "STARTTLS".to_string()
                    ]
                );
            }
            _ => panic!("expected reply"),
        }
        // 只取第一条消息：后续流水线应答不影响判决。
        assert!(
            matches!(parse(b"221 Bye\r\n250 next\r\n").unwrap(), Message::Reply(ref r) if r.code == 221)
        );
    }

    #[test]
    fn incomplete_lines_are_need_more_not_guesses() {
        for prefix in [
            &b"2"[..],
            b"22",
            b"220",
            b"220 ",
            b"220 mail.example",
            b"220 mail.example\r",
            b"E",
            b"EHL",
            b"EHLO",
            b"EHLO client",
            b"EHLO client\r",
            b"MAIL FROM:<a@b>",
        ] {
            assert_eq!(parse(prefix), Err(Detect::NeedMore), "{prefix:?}");
        }
        assert_eq!(parse(&b"2".repeat(MAX_LINE + 1)), Err(Detect::NeedMore));
        assert_eq!(parse(&b"2".repeat(MAX_BYTES + 1)), Err(Detect::NeedMore));
    }

    #[test]
    fn malformed_claims_and_other_protocols_are_distinguished() {
        for malformed in [
            &b"EHLO client\n"[..],
            b"EHLO bad domain\r\n",
            b"EHLO\r\n",
            b"MAIL FROM:alice@example.com\r\n",
            b"MAIL FROM:<a b>\r\n",
            b"RCPT TO:<a@b> \r\n",
            b"DATA payload\r\n",
            b"AUTH\r\n",
            b"BDAT 12MORE\r\n",
            b"250-a\r\n251 b\r\n",
            b"250-a\r\n",
            b"250-a\r\n2\r\n",
            b"220 x\r\x00\n",
        ] {
            assert!(parse(malformed).is_err(), "{malformed:?}");
        }
        for rejected in [
            &b"\x16\x03\x01\x00"[..],
            b"+OK ready\r\n",
            b"* OK IMAP\r\n",
            b"GET / HTTP/1.1\r\n",
            b"SSH-2.0-x\r\n",
            b"999 nope\r\n",
            b"2\r\n",
            b"\x00\x01",
        ] {
            assert_eq!(parse(rejected), Err(Detect::Rejected), "{rejected:?}");
        }
    }

    #[test]
    fn transport_context_is_service_port_only() {
        assert!(transport(25, 40000) && transport(40000, 25));
        assert!(transport(0, 587) && transport(2525, 50000));
        for port in [21, 22, 80, 465, 993, 995] {
            assert!(!transport(40000, port), "{port}");
            assert!(!transport(port, 40000), "{port}");
        }
    }
}
