// dpi/http.rs —— HTTP 请求解析与 Host 头提取。
//
// 这里是整套 DPI 里最"朴素"的一块：明文、有换行分隔、字段语义稳定。但它有个容易被忽略的
// 坑：**首包常常只到一半**。省网边的网卡上，一个 HTTP 请求被拆成两个 TCP 段是常态，
// 抓到的前 43 字节可能只有请求行和一个 User-Agent —— 此时 Host 到底"没有"还是"还没到"
// 是完全不同的两件事：前者是这条流真的没有 Host（例如 CONNECT），后者只是分片。
// 把后者当成前者，会凭空多出一堆"无 Host 流量"，进而让域名维度的统计整体偏低。

use super::types::{Confidence, Detect, Detection};

/// HTTP/1.x 方法集合。刻意**只收请求方法**：响应报文（HTTP/1.1 200 OK）走不到这里，
/// 由框架按端口/载荷路由决定，避免"见到 HTTP/ 就当是请求"。
const METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
];

/// 请求行里方法名之后最多搜多少字节找第一个空格（请求行不会更长）。
const MAX_METHOD_LOOKAHEAD: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// 请求方法（大写原样）。
    pub method: String,
    pub uri: String,
    /// HTTP 版本，如 `HTTP/1.1`。
    pub version: String,
    /// Host 头（已剥离端口、去空白、归一小写）。
    pub host: Option<String>,
    /// User-Agent 头（去首尾空白，大小写原样保留：它是客户端指纹，不是域名）。
    pub user_agent: Option<String>,
    /// Content-Type 头。
    ///
    /// 请求侧也有这个头（`POST` 的 body 类型），语义与响应侧相同，
    /// 因此两侧都产出 `ATTR_HTTP_CONTENT_TYPE`：分流器关心的"这是什么内容"
    /// 在请求上就能看出来，等到响应就把一个往返的处置窗口浪费掉了。
    pub content_type: Option<String>,
    /// Content-Length 头（十进制）。
    ///
    /// **解析但不产出属性**：属性字典里没有登记 Content-Length，而"只产出已登记属性"
    /// 是硬约束。留着它是因为解析器要能回答"这个请求声称自己带多少字节"，
    /// 重组层与后续的文件还原都要用；没有登记就不产出，而不是随便找个属性塞进去。
    pub content_length: Option<u64>,
}

/// 解析出的一段 HTTP 响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP 版本，如 `HTTP/1.1`。
    pub version: String,
    /// 三位状态码。
    pub status_code: u16,
    /// 原因短语（`200 OK` 里的 `OK`），可能为空。
    pub reason: String,
    /// Content-Type（见 `normalize_content_type`）。
    pub content_type: Option<String>,
    /// Content-Length（同请求侧：解析但不产出）。
    pub content_length: Option<u64>,
}

/// 合法状态码区间。RFC 9110 只定义了 1xx~5xx，三位数里的 600~999 不属于任何类别；
/// 把它当"状态码"照单全收，会让"HTTP 响应状态分布"里多出一堆协议里不存在的取值。
const MIN_STATUS: u16 = 100;
const MAX_STATUS: u16 = 599;

/// 响应报文的最大方法/版本前缀（用于"半截 `HTTP/`"的判定）。
const VERSION_PREFIX: &[u8] = b"HTTP/";

/// 解析一段 HTTP 请求载荷。
pub fn parse(payload: &[u8]) -> Result<HttpRequest, Detect> {
    // 1) 方法：请求行第一个空格之前的 token 必须是已知方法。
    //    看不到空格 → 载荷不足 → 需要更多字节（而不是"不是 HTTP"）。
    let mut method_end = None;
    for (i, &b) in payload.iter().enumerate().take(MAX_METHOD_LOOKAHEAD) {
        if b == b' ' {
            method_end = Some(i);
            break;
        }
    }
    let method_end = match method_end {
        Some(i) => i,
        None => {
            // 找不到空格：要么连请求行都还没到（首字节就是换行），要么根本不是请求行。
            // 两者对下游的意义相反：前者该等，后者该判"不是 HTTP"。
            let no_request_line_yet = payload
                .first()
                .map_or(false, |b| *b == b'\r' || *b == b'\n');
            return if no_request_line_yet {
                Err(Detect::NeedMore)
            } else {
                Err(Detect::Rejected)
            };
        }
    };
    let method = std::str::from_utf8(&payload[..method_end]).map_err(|_| Detect::Rejected)?;
    if !METHODS.contains(&method) {
        return Err(Detect::Rejected);
    }

    // 2) 头部结束标志：必须出现空行，否则 Host "可能还在路上"
    let Some(head_end) = header_end(payload) else {
        return Err(Detect::NeedMore);
    };
    let body = std::str::from_utf8(&payload[..head_end]).map_err(|_| Detect::Malformed)?;

    // 3) 请求行三元组
    let mut it = body.splitn(3, ' ');
    let _m = it.next();
    let Some(uri) = it.next() else {
        return Err(Detect::Malformed);
    };
    let Some(version) = it.next() else {
        return Err(Detect::NeedMore);
    };
    if !version.starts_with("HTTP/") {
        return Err(Detect::Malformed);
    }

    Ok(HttpRequest {
        method: method.to_string(),
        uri: uri.to_string(),
        version: version.to_string(),
        host: header_value(body, "host"),
        user_agent: header_value_exact(body, "user-agent"),
        content_type: header_value_exact(body, "content-type").map(|v| normalize_content_type(&v)),
        content_length: header_u64(body, "content-length"),
    })
}

/// 解析一段 HTTP **响应**载荷。
///
/// 与请求侧共用同一个"头部必须完整结束"的判据：只看到状态行时是 `NeedMore`，
/// 因为 Content-Type 与其余头部"还没到"和"没有"是两件事。
pub fn parse_response(payload: &[u8]) -> Result<HttpResponse, Detect> {
    let line_end = payload
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(payload.len());
    let line = &payload[..line_end];
    let line = std::str::from_utf8(line).map_err(|_| Detect::Rejected)?;

    // `HTTP/1.1 200 OK` —— 版本、状态码、可选原因短语
    let mut it = line.splitn(3, ' ');
    let Some(version) = it.next() else {
        return Err(Detect::NeedMore);
    };
    if !version.starts_with("HTTP/") {
        return Err(Detect::Rejected);
    }
    let Some(code_tok) = it.next() else {
        // 有版本、还没有状态码：这一行还没到齐
        return Err(Detect::NeedMore);
    };
    // 状态码不足三位 → 这一行还在路上（例如只到了 `HTTP/1.1 20`），判 NeedMore；
    // 三位以外（`HTTP/1.1 2000` / `2O0`）→ 这一行不是状态行，判 Malformed。
    // 两者的下游含义相反，混作一谈会让"分片"被记成"解析失败"。
    if code_tok.len() < 3 {
        return Err(Detect::NeedMore);
    }
    if code_tok.len() != 3 || !code_tok.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(Detect::Malformed);
    }
    let status_code: u16 = code_tok.parse().map_err(|_| Detect::Malformed)?;
    if !(MIN_STATUS..=MAX_STATUS).contains(&status_code) {
        return Err(Detect::Malformed);
    }
    let reason = it.next().unwrap_or("").trim().to_string();

    // 头部必须真的结束（空行），否则 Content-Type 可能还在路上
    let Some(head_end) = header_end(payload) else {
        return Err(Detect::NeedMore);
    };
    let head = std::str::from_utf8(&payload[..head_end]).map_err(|_| Detect::Malformed)?;

    Ok(HttpResponse {
        version: version.to_string(),
        status_code,
        reason: reason.to_string(),
        content_type: header_value_exact(head, "content-type").map(|v| normalize_content_type(&v)),
        content_length: header_u64(head, "content-length"),
    })
}

/// 找空行位置（返回返回体之前最后一个字节的偏移）。
fn header_end(p: &[u8]) -> Option<usize> {
    for i in 0..p.len().saturating_sub(3) {
        if p[i] == b'\r' && p[i + 1] == b'\n' && p[i + 2] == b'\r' && p[i + 3] == b'\n' {
            return Some(i);
        }
    }
    None
}

/// 从头部文本里取某个头的值（大小写不敏感），并做归一化。
///
/// Host 一律剥掉端口：规则里 `host == "example.com"` 与 `host == "example.com:8443"`
/// 是两条规则，同一个域名却能被两种写法命中，等于把域名维度统计劈成两半。
/// 端口剥离只在尾部是数字时做，避免把 IPv6 字面量 `[::1]:8080` 中间的冒号误伤。
fn header_value(headers: &str, name: &str) -> Option<String> {
    for line in headers.split("\r\n") {
        // 不能在这里用 `?`：第一行是请求行（没有冒号），用 `?` 会直接短路返回 None，
        // 后面的 Host 头就永远读不到 —— 这正是"看起来能跑、其实每次都取不到 Host"的那类缺陷。
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(name) {
            let v = v.trim().trim_end_matches(|c: char| c.is_ascii_digit());
            let v = v.trim_end_matches(':');
            let v = v.trim();
            if v.is_empty() {
                return None;
            }
            return Some(v.to_ascii_lowercase());
        }
    }
    None
}

/// 从头部文本里取某个头的原始值（大小写不敏感），只做首尾去空白。
///
/// 与 `header_value` 的区别：**不做域名式归一化**。Host 要剥端口、转小写，
/// 因为它是同一件事的不同写法；User-Agent / Content-Type 是值本身，
/// 擅自改写它们会让"客户端指纹"和"内容类型"两个维度失真。
fn header_value_exact(headers: &str, name: &str) -> Option<String> {
    for line in headers.split("\r\n") {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(name) {
            let v = v.trim();
            if v.is_empty() {
                return None;
            }
            return Some(v.to_string());
        }
    }
    None
}

/// 取一个十进制整数头（如 Content-Length）。非数字或超范围一律当"没有这个头"。
fn header_u64(headers: &str, name: &str) -> Option<u64> {
    header_value_exact(headers, name)?.parse::<u64>().ok()
}

/// Content-Type 归一化：统一小写。
///
/// `Application/JSON` 与 `application/json` 是同一个类型，两种写法各占一个统计桶
/// 会让"内容类型分布"凭空分裂。参数（`; charset=…`）保留 —— 它是同一类型的不同变体，
/// 规则想忽略参数时可以按前缀匹配，反过来（丢掉参数就再也拿不回来）做不到。
pub fn normalize_content_type(v: &str) -> String {
    v.to_ascii_lowercase()
}

/// 供框架调用的统一入口：请求与响应共用同一对函数。
///
/// 判别只看一个字节级事实 —— 载荷是否以 `HTTP/` 开头。请求行第一个 token 是方法名，
/// 永远不可能是 `HTTP/`（没有哪个 HTTP 方法叫 HTTP），因此这个判别不会误伤请求。
pub fn detect(payload: &[u8]) -> Detect {
    // "半截 HTTP/"：`H` / `HT` / `HTT` / `HTTP` 都是响应的前缀。若交给请求解析器，
    // 它会因为"找不到方法后的空格"判 Rejected —— 于是分片被记成"不是 HTTP"。
    if !payload.is_empty() && VERSION_PREFIX.starts_with(payload) {
        return Detect::NeedMore;
    }
    if payload.starts_with(VERSION_PREFIX) {
        return match parse_response(payload) {
            Ok(r) => Detect::Hit(r.into_detection()),
            Err(e) => e,
        };
    }
    match parse(payload) {
        Ok(r) => Detect::Hit(r.into_detection()),
        Err(e) => e,
    }
}

impl HttpRequest {
    pub fn into_detection(self) -> Detection {
        let mut d = Detection::new(
            super::types::AppId::Http,
            Confidence::High,
            "http.request_line: 方法/URI/版本三元组自洽且头部完整结束",
        );
        d.method = Some(self.method);
        d.uri = Some(self.uri);
        d.host = self.host;
        d.user_agent = self.user_agent;
        d.content_type = self.content_type;
        d
    }
}

impl HttpResponse {
    pub fn into_detection(self) -> Detection {
        let mut d = Detection::new(
            super::types::AppId::Http,
            Confidence::High,
            "http.status_line: 版本/三位状态码自洽且头部完整结束",
        );
        d.status_code = Some(self.status_code);
        d.content_type = self.content_type;
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_is_stripped() {
        let p = b"GET /x HTTP/1.1\r\nHost: Api.Example.com:8443\r\n\r\n";
        assert_eq!(parse(p).unwrap().host.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn incomplete_headers_are_need_more_not_no_host() {
        // 只有请求行与一个 UA 头，空行还没到 → Host 是"还没到"，不是"没有"
        let p = b"GET /early HTTP/1.1\r\nUser-Agent: curl/8.0\r\n";
        assert_eq!(parse(p), Err(Detect::NeedMore));
    }

    #[test]
    fn unknown_method_is_rejected() {
        assert_eq!(
            parse(b"FROBNICATE /x HTTP/1.1\r\n\r\n"),
            Err(Detect::Rejected)
        );
    }

    #[test]
    fn request_carries_uri_ua_and_content_type() {
        let p = b"POST /submit?x=1 HTTP/1.1\r\nHost: form.example.net\r\n\
                  User-Agent: Mozilla/5.0 (X11)\r\nContent-Type: Application/JSON\r\n\r\n{}";
        let r = parse(p).unwrap();
        assert_eq!(r.uri, "/submit?x=1");
        assert_eq!(r.user_agent.as_deref(), Some("Mozilla/5.0 (X11)"));
        // Content-Type 归一化为小写，UA 保持原样（它是指纹，不是可归一化的域名）
        assert_eq!(r.content_type.as_deref(), Some("application/json"));
        assert_eq!(r.content_length, None);
    }

    #[test]
    fn response_status_and_content_type() {
        let p = b"HTTP/1.1 404 Not Found\r\nContent-Type: Application/JSON\r\n\
                  Content-Length: 2\r\n\r\n{}";
        let r = parse_response(p).unwrap();
        assert_eq!(r.status_code, 404);
        assert_eq!(r.reason, "Not Found");
        assert_eq!(r.content_type.as_deref(), Some("application/json"));
        assert_eq!(r.content_length, Some(2));
        let d = r.into_detection();
        assert_eq!(d.status_code, Some(404));
        // 响应里没有方法/URI/UA：这些字段必须是 None，而不是空串
        assert!(d.method.is_none() && d.uri.is_none() && d.user_agent.is_none());
    }

    #[test]
    fn partial_status_code_is_need_more_not_malformed() {
        // 只到了 `2`：分片，不是坏包。两者被混为一谈会让"分片"记进解析失败率。
        assert_eq!(parse_response(b"HTTP/1.1 2"), Err(Detect::NeedMore));
        assert_eq!(parse_response(b"HTTP/1.1 20"), Err(Detect::NeedMore));
        assert_eq!(parse_response(b"HTTP/1.1 200"), Err(Detect::NeedMore));
        // 三位但不是数字 / 超出 1xx~5xx → 自相矛盾
        assert_eq!(
            parse_response(b"HTTP/1.1 2O0 OK\r\n\r\n"),
            Err(Detect::Malformed)
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 2000 OK\r\n\r\n"),
            Err(Detect::Malformed)
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 999 Nope\r\n\r\n"),
            Err(Detect::Malformed)
        );
    }

    #[test]
    fn partial_version_prefix_is_need_more() {
        // `H` / `HT` / `HTT` / `HTTP` 都可能是响应的开头。若交给请求解析器，
        // 会因为"方法后没有空格"判 Rejected —— 分片被记成"不是 HTTP"。
        for p in [&b"H"[..], b"HT", b"HTT", b"HTTP"] {
            assert_eq!(detect(p), Detect::NeedMore, "载荷 {p:?}");
        }
        // 而完全不是 HTTP 开头的垃圾仍然必须是"不是我的协议"
        assert_eq!(detect(b"ZZZ"), Detect::Rejected);
    }

    #[test]
    fn detect_routes_responses_to_the_response_parser() {
        // 判别只看一个事实：载荷是否以 `HTTP/` 开头（请求行首 token 是方法名）
        assert!(matches!(detect(b"HTTP/1.1 200 OK\r\n\r\n"), Detect::Hit(_)));
        assert!(matches!(
            detect(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"),
            Detect::Hit(_)
        ));
    }
}
