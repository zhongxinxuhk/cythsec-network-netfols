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
}

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

/// 供框架调用的统一入口。
pub fn detect(payload: &[u8]) -> Detect {
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
        d.host = self.host;
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
}
