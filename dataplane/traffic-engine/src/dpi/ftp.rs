//! Bounded FTP (RFC 959 / RFC 2428 / RFC 4217) control-channel recognition.
//!
//! 边界与 SMTP 同族，但有两处不能照抄：
//!
//! 1. **FTP 的多行应答格式与 SMTP 不同**。SMTP 每行都带同一个应答码；
//!    FTP 只有首行 `code-`、末行 `code SP`，中间行是任意文本。把 SMTP 的
//!    "逐行同码"规则套过来，会把 `211-Features:\r\n UTF8\r\n211 End` 判成畸形。
//! 2. **`PASS` 的实参是凭据**。识别只需要"这条命令存在且语法成立"，
//!    因此 `Command.argument` 对 PASS 恒为 `None`（`redacted=true`），
//!    不在解析结果、日志或记录里保留口令。
//!
//! 其余边界：只在 TCP 21/2121 的明文控制通道启用（990 是隐式 FTPS，留给 TLS）；
//! 只看首条命令或首条应答；行/字节/行数预算与四态语义显式；不解析数据通道、
//! 文件内容、目录列表或登录结果。

use super::{AppId, Confidence, Detect, Detection};

/// 明文 FTP 控制端口。990 是隐式 FTPS，刻意不纳入。
const PORTS: [u16; 2] = [21, 2121];
const MAX_BYTES: usize = 8192;
const MAX_LINE: usize = 2048;
const MAX_LINES: usize = 16;
const MAX_VERB: usize = 4;

const VERBS: [&str; 55] = [
    "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN", "PORT", "PASV", "TYPE", "STRU",
    "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD",
    "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP", "NOOP", "FEAT", "OPTS", "AUTH",
    "PBSZ", "PROT", "CCC", "SIZE", "MDTM", "MLSD", "MLST", "MFMT", "EPSV", "EPRT", "LANG", "HOST",
    "ADAT", "MIC", "CONF", "ENC", "XCUP", "XCWD", "XMKD",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// 大写动词。
    pub verb: String,
    /// 实参；`PASS` 恒为 `None`（不保留凭据）。
    pub argument: Option<String>,
    /// 该命令的实参是否因凭据语义被刻意丢弃。
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    /// 每行去掉应答码/分隔符后的文本。
    pub lines: Vec<String>,
    pub multiline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Command(Command),
    Reply(Reply),
}

impl Message {
    pub fn confidence(&self) -> Confidence {
        match self {
            Message::Command(c) if strong_command(&c.verb) => Confidence::High,
            Message::Reply(r) => {
                if r.code == 220
                    && r.lines
                        .first()
                        .is_some_and(|line| contains_ignore_case(line, "FTP"))
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
                "USER" | "PASS" | "ACCT" => "ftp login command",
                "RETR" | "STOR" | "STOU" | "APPE" => "ftp data transfer command",
                "PORT" | "PASV" | "EPRT" | "EPSV" => "ftp data connection command",
                "TYPE" | "STRU" | "MODE" | "REST" | "ALLO" | "PBSZ" | "PROT" => {
                    "ftp transfer parameter command"
                }
                _ => "ftp control command",
            },
            Message::Reply(r) if r.code == 220 => "ftp greeting reply on the control port",
            Message::Reply(r) if r.multiline => "ftp multiline reply on the control port",
            Message::Reply(_) => "ftp reply on the control port",
        }
    }
}

/// 传输上下文：端口只做路由，本身不构成命中证据。
pub fn transport(src_port: u16, dst_port: u16) -> bool {
    PORTS.contains(&dst_port) || PORTS.contains(&src_port)
}

pub fn detect(payload: &[u8]) -> Detect {
    match parse(payload) {
        Ok(message) => Detect::Hit(Detection::new(
            AppId::Ftp,
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
        _ => Err(Detect::Rejected),
    }
}

fn parse_command(payload: &[u8]) -> Result<Command, Detect> {
    let mut end = 0;
    while end < payload.len() && end < MAX_VERB && payload[end].is_ascii_alphabetic() {
        end += 1;
    }
    let raw = &payload[..end];
    let known = end >= 3 && VERBS.contains(&to_ascii_upper(raw).as_str());
    if !known {
        // 词没收全（`US`/`EHL`）→ 再给字节可能认出；收全却不在表里 → 不是 FTP。
        if payload.len() == end
            && VERBS
                .iter()
                .any(|candidate| starts_with_ignore_case(candidate.as_bytes(), raw))
        {
            return Err(Detect::NeedMore);
        }
        return Err(Detect::Rejected);
    }
    let verb = to_ascii_upper(raw);
    let argument = match payload.get(end) {
        None => return Err(Detect::NeedMore),
        Some(b' ') => {
            let (line, _) = read_line(payload, end + 1)?;
            if line.is_empty() {
                return Err(Detect::Malformed);
            }
            Some(String::from_utf8_lossy(line).into_owned())
        }
        Some(b'\r') => {
            require_lf(payload, end)?;
            None
        }
        Some(b'\n') | Some(_) => return Err(Detect::Malformed),
    };
    let stored = validate_argument(&verb, argument.as_deref())?;
    let redacted = verb == "PASS";
    Ok(Command {
        verb,
        argument: stored,
        redacted,
    })
}

/// 校验每条命令的实参形状，并返回可安全保留的实参。
///
/// `PASS` 走单独分支：只校验"非空且可打印"，不把口令带出解析层。
fn validate_argument(verb: &str, argument: Option<&str>) -> Result<Option<String>, Detect> {
    match arity(verb) {
        Arity::None => {
            if argument.is_some() {
                return Err(Detect::Malformed);
            }
            return Ok(None);
        }
        Arity::One => {
            let arg = argument.ok_or(Detect::Malformed)?;
            let stored = match verb {
                "PASS" => None,
                "USER" => {
                    validate_token(arg)?;
                    Some(arg.to_string())
                }
                "TYPE" => {
                    validate_transfer_type(arg)?;
                    Some(arg.to_string())
                }
                "STRU" => {
                    validate_single(arg, b"FRP")?;
                    Some(arg.to_string())
                }
                "MODE" => {
                    validate_single(arg, b"SBC")?;
                    Some(arg.to_string())
                }
                "PORT" => {
                    validate_port(arg)?;
                    Some(arg.to_string())
                }
                "EPRT" => {
                    validate_eprt(arg)?;
                    Some(arg.to_string())
                }
                "REST" | "PBSZ" => {
                    validate_digits(arg)?;
                    Some(arg.to_string())
                }
                "ALLO" => {
                    validate_allo(arg)?;
                    Some(arg.to_string())
                }
                "PROT" => {
                    validate_single(arg, b"CSEP")?;
                    Some(arg.to_string())
                }
                "AUTH" => {
                    validate_token(arg)?;
                    Some(arg.to_string())
                }
                "OPTS" => {
                    if arg.is_empty() {
                        return Err(Detect::Malformed);
                    }
                    Some(arg.to_string())
                }
                // 路径类命令允许空格与 UTF-8（RFC 2640），只要求非空。
                "CWD" | "SMNT" | "RETR" | "STOR" | "APPE" | "RNFR" | "RNTO" | "DELE" | "RMD"
                | "MKD" | "SITE" | "SIZE" | "MDTM" | "MFMT" | "LANG" | "HOST" | "ADAT" | "MIC"
                | "CONF" | "ENC" | "XCUP" | "XCWD" | "XMKD" => {
                    if arg.is_empty() {
                        return Err(Detect::Malformed);
                    }
                    Some(arg.to_string())
                }
                _ => Some(arg.to_string()),
            };
            Ok(stored)
        }
        Arity::Optional => Ok(argument.map(str::to_string)),
    }
}

#[derive(Clone, Copy)]
enum Arity {
    None,
    One,
    Optional,
}

fn arity(verb: &str) -> Arity {
    match verb {
        "CDUP" | "QUIT" | "PASV" | "ABOR" | "PWD" | "SYST" | "FEAT" | "CCC" | "NOOP" => Arity::None,
        "STOU" | "LIST" | "NLST" | "STAT" | "HELP" | "MLSD" | "MLST" | "EPSV" => Arity::Optional,
        _ => Arity::One,
    }
}

fn strong_command(verb: &str) -> bool {
    matches!(
        verb,
        "USER"
            | "PASS"
            | "PORT"
            | "PASV"
            | "TYPE"
            | "EPSV"
            | "EPRT"
            | "STRU"
            | "MODE"
            | "REST"
            | "ALLO"
            | "PBSZ"
            | "PROT"
            | "AUTH"
            | "SIZE"
            | "MDTM"
            | "MFMT"
    )
}

/// FTP 多行应答：首行 `code-`，末行 `code SP`，中间行是任意文本。
fn parse_reply(payload: &[u8]) -> Result<Reply, Detect> {
    let (first, mut offset) = read_line(payload, 0)?;
    let (code, multiline) = reply_head(first)?;
    let mut lines = vec![reply_text(first)];
    if !multiline {
        return Ok(Reply {
            code,
            lines,
            multiline: false,
        });
    }
    loop {
        if lines.len() >= MAX_LINES {
            return Err(Detect::NeedMore);
        }
        if offset >= payload.len() {
            return Err(Detect::NeedMore);
        }
        let (line, next) = read_line(payload, offset)?;
        offset = next;
        if line.len() >= 3 && line[..3].iter().all(u8::is_ascii_digit) {
            let current = parse_code(&line[..3])?;
            if current == code {
                match line.get(3).copied() {
                    None | Some(b' ') => {
                        lines.push(reply_text(line));
                        return Ok(Reply {
                            code,
                            lines,
                            multiline: true,
                        });
                    }
                    Some(b'-') => {
                        lines.push(reply_text(line));
                        continue;
                    }
                    Some(_) => return Err(Detect::Malformed),
                }
            }
        }
        lines.push(String::from_utf8_lossy(line).into_owned());
    }
}

fn reply_head(line: &[u8]) -> Result<(u16, bool), Detect> {
    if line.len() < 3 {
        return Err(Detect::Rejected);
    }
    if !line[..3].iter().all(u8::is_ascii_digit) {
        return Err(Detect::Rejected);
    }
    let code = parse_code(&line[..3])?;
    match line.get(3) {
        None => Ok((code, false)),
        Some(b' ') => Ok((code, false)),
        Some(b'-') => Ok((code, true)),
        Some(_) => Err(Detect::Malformed),
    }
}

fn reply_text(line: &[u8]) -> String {
    let start = if line.len() > 3 { 4 } else { line.len() };
    String::from_utf8_lossy(line.get(start..).unwrap_or(&[])).into_owned()
}

fn parse_code(digits: &[u8]) -> Result<u16, Detect> {
    let class = digits[0];
    if !(b'1'..=b'5').contains(&class) || digits[1] > b'5' {
        return Err(Detect::Rejected);
    }
    Ok(u16::from(class - b'0') * 100
        + u16::from(digits[1] - b'0') * 10
        + u16::from(digits[2] - b'0'))
}

/// 读取一行（不含 CRLF）。FTP 允许 UTF-8 路径/应答文本，因此只拒绝控制字节。
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
            b if b == b'\t' || b >= 0x20 => {
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

fn validate_token(value: &str) -> Result<(), Detect> {
    if value.is_empty() || value.contains(' ') || value.len() > 255 {
        return Err(Detect::Malformed);
    }
    Ok(())
}

fn validate_single(value: &str, allowed: &[u8]) -> Result<(), Detect> {
    if value.len() != 1 || !allowed.contains(&value.as_bytes()[0].to_ascii_uppercase()) {
        return Err(Detect::Malformed);
    }
    Ok(())
}

fn validate_transfer_type(value: &str) -> Result<(), Detect> {
    let first = value
        .as_bytes()
        .first()
        .copied()
        .map(|b| b.to_ascii_uppercase());
    if !matches!(first, Some(b'A' | b'E' | b'I' | b'L')) {
        return Err(Detect::Malformed);
    }
    // `TYPE L 8` 是唯一允许的第二参数形式；其他多余内容按畸形处理。
    if value.len() > 1 {
        let rest = value[1..].strip_prefix(' ').ok_or(Detect::Malformed)?;
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Detect::Malformed);
        }
    }
    Ok(())
}

fn validate_digits(value: &str) -> Result<(), Detect> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Detect::Malformed);
    }
    Ok(())
}

fn validate_allo(value: &str) -> Result<(), Detect> {
    let mut parts = value.splitn(3, ' ');
    validate_digits(parts.next().unwrap_or(""))?;
    if let Some(rest) = parts.next() {
        if !rest.eq_ignore_ascii_case("R") {
            return Err(Detect::Malformed);
        }
        validate_digits(parts.next().ok_or(Detect::Malformed)?)?;
    }
    Ok(())
}

fn validate_port(value: &str) -> Result<(), Detect> {
    let fields: Vec<&str> = value.split(',').collect();
    if fields.len() != 6 {
        return Err(Detect::Malformed);
    }
    for field in fields {
        if field.is_empty() || field.len() > 3 || !field.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Detect::Malformed);
        }
        if field.parse::<u16>().map_err(|_| Detect::Malformed)? > 255 {
            return Err(Detect::Malformed);
        }
    }
    Ok(())
}

fn validate_eprt(value: &str) -> Result<(), Detect> {
    let mut parts = value.split('|');
    if parts.next() != Some("") {
        return Err(Detect::Malformed);
    }
    let family = parts.next().ok_or(Detect::Malformed)?;
    if family != "1" && family != "2" {
        return Err(Detect::Malformed);
    }
    let address = parts.next().ok_or(Detect::Malformed)?;
    if address.is_empty() || address.contains(' ') {
        return Err(Detect::Malformed);
    }
    validate_digits(parts.next().ok_or(Detect::Malformed)?)?;
    if parts.next() != Some("") {
        return Err(Detect::Malformed);
    }
    Ok(())
}

fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn starts_with_ignore_case(candidate: &[u8], prefix: &[u8]) -> bool {
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
    fn login_and_transfer_commands_keep_grammar_but_drop_passwords() {
        let user = parse(b"USER anonymous\r\n").unwrap();
        assert_eq!(user.confidence(), Confidence::High);
        assert!(
            matches!(user, Message::Command(ref c) if c.argument.as_deref() == Some("anonymous"))
        );

        let pass = parse(b"PASS hunter2 with spaces\r\n").unwrap();
        assert_eq!(pass.confidence(), Confidence::High);
        match pass {
            Message::Command(command) => {
                assert_eq!(command.verb, "PASS");
                assert_eq!(command.argument, None);
                assert!(command.redacted);
            }
            _ => panic!("expected command"),
        }

        let port = parse(b"PORT 192,0,2,1,10,20\r\n").unwrap();
        assert_eq!(port.confidence(), Confidence::High);
        assert!(matches!(port, Message::Command(ref c) if c.verb == "PORT"));
    }

    #[test]
    fn multiline_replies_follow_ftp_not_smtp_layout() {
        let reply = parse(b"211-Features:\r\n UTF8\r\n MDTM\r\n211 End\r\n").unwrap();
        assert_eq!(reply.confidence(), Confidence::Medium);
        match reply {
            Message::Reply(reply) => {
                assert_eq!(reply.code, 211);
                assert!(reply.multiline);
                assert_eq!(reply.lines, vec!["Features:", " UTF8", " MDTM", "End"]);
            }
            _ => panic!("expected reply"),
        }
        let greeting = parse(b"220 (vsFTPd 3.0.5)\r\n").unwrap();
        assert_eq!(greeting.confidence(), Confidence::High);
        assert!(matches!(greeting, Message::Reply(ref r) if r.code == 220));
    }

    #[test]
    fn incomplete_lines_are_need_more_and_arguments_are_checked() {
        for prefix in [
            &b"2"[..],
            b"22",
            b"220",
            b"220 ",
            b"220 (vsFTPd",
            b"220 x\r",
            b"US",
            b"USER",
            b"USER anon",
            b"USER anon\r",
        ] {
            assert_eq!(parse(prefix), Err(Detect::NeedMore), "{prefix:?}");
        }
        for malformed in [
            &b"USER\r\n"[..],
            b"PASS\r\n",
            b"TYPE X\r\n",
            b"STRU X\r\n",
            b"MODE X\r\n",
            b"PORT 1,2,3\r\n",
            b"PORT 1,2,3,4,5,256\r\n",
            b"EPRT |3|1.2.3.4|80|\r\n",
            b"REST abc\r\n",
            b"ALLO 10 R\r\n",
            b"QUIT now\r\n",
            b"FEAT x\r\n",
            b"220 x\n",
            b"220 x\r\x00\n",
            b"211-a\r\n211-\r\n",
        ] {
            assert!(parse(malformed).is_err(), "{malformed:?}");
        }
        for rejected in [
            &b"\x16\x03\x01\x00"[..],
            b"+OK ready\r\n",
            b"* OK IMAP\r\n",
            b"GET / HTTP/1.1\r\n",
            b"SSH-2.0-x\r\n",
            b"EHLO client.example\r\n",
            b"999 nope\r\n",
            b"600 nope\r\n",
            b"X\r\n",
            b"\x00\x01",
        ] {
            assert_eq!(parse(rejected), Err(Detect::Rejected), "{rejected:?}");
        }
    }

    #[test]
    fn transport_context_is_control_port_only() {
        assert!(transport(21, 40000) && transport(40000, 21));
        assert!(transport(0, 2121) && transport(2121, 50000));
        for port in [25, 80, 443, 990, 992] {
            assert!(!transport(40000, port), "{port}");
            assert!(!transport(port, 40000), "{port}");
        }
    }
}
