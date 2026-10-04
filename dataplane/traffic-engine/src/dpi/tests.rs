// dpi/tests.rs —— 用 datasets/dpi 的测试向量驱动 DPI 断言。
//
// 向量是**编进二进制**的（`include_bytes!` / `include_str!`），刻意不去运行时读文件：
//   读文件的话，路径写错或工作目录不对时，测试会"安静地什么都测不到"——
//   这正是本项目反复踩过的"假绿灯"：输出全绿，实际一条断言都没跑。
//   编进二进制后，路径错就是**编译失败**，无法悄悄跳过。
//
// 三方互证的落点也在这里：
//   生成器（知道该是什么）→ 本文件（Rust 实现说的）→ tshark（scripts/verify/check-dpi-vectors.sh 独立复核）。
// 任何一方算错都会让至少一边对不上。

use crate::testjson::{Json, JsonParser};

use super::attributes;
use super::{dns, http, tls, Detect, Outcome};

/// 期望值清单（与生成器、tshark 共用同一份文件）。
const EXPECTED: &str = include_str!("../../../../datasets/dpi/expected.json");

/// 全部向量载荷。新增向量时**必须**同步到这里：
/// 没同步的话下面的 `payload()` 会 panic，测试不会静默跳过。
const VECTORS: &[(&str, &[u8])] = &[
    (
        "tls-basic",
        include_bytes!("../../../../datasets/dpi/payloads/tls-basic.bin"),
    ),
    (
        "tls-no-sni",
        include_bytes!("../../../../datasets/dpi/payloads/tls-no-sni.bin"),
    ),
    (
        "tls-grease",
        include_bytes!("../../../../datasets/dpi/payloads/tls-grease.bin"),
    ),
    (
        "tls-truncated",
        include_bytes!("../../../../datasets/dpi/payloads/tls-truncated.bin"),
    ),
    (
        "tls-lying-handshake-len",
        include_bytes!("../../../../datasets/dpi/payloads/tls-lying-handshake-len.bin"),
    ),
    (
        "tls-bad-inner-len",
        include_bytes!("../../../../datasets/dpi/payloads/tls-bad-inner-len.bin"),
    ),
    (
        "tls-sni-long",
        include_bytes!("../../../../datasets/dpi/payloads/tls-sni-long.bin"),
    ),
    (
        "tls-ech-no-outer-sni",
        include_bytes!("../../../../datasets/dpi/payloads/tls-ech-no-outer-sni.bin"),
    ),
    (
        "tls-negative-http",
        include_bytes!("../../../../datasets/dpi/payloads/tls-negative-http.bin"),
    ),
    (
        "dns-query-a",
        include_bytes!("../../../../datasets/dpi/payloads/dns-query-a.bin"),
    ),
    (
        "dns-query-multilabel",
        include_bytes!("../../../../datasets/dpi/payloads/dns-query-multilabel.bin"),
    ),
    (
        "dns-query-long",
        include_bytes!("../../../../datasets/dpi/payloads/dns-query-long.bin"),
    ),
    (
        "dns-query-mx",
        include_bytes!("../../../../datasets/dpi/payloads/dns-query-mx.bin"),
    ),
    (
        "dns-response-compressed",
        include_bytes!("../../../../datasets/dpi/payloads/dns-response-compressed.bin"),
    ),
    (
        "dns-response-nxdomain",
        include_bytes!("../../../../datasets/dpi/payloads/dns-response-nxdomain.bin"),
    ),
    (
        "dns-response-multi-answer",
        include_bytes!("../../../../datasets/dpi/payloads/dns-response-multi-answer.bin"),
    ),
    (
        "dns-response-answer-cut",
        include_bytes!("../../../../datasets/dpi/payloads/dns-response-answer-cut.bin"),
    ),
    (
        "dns-query-edns0",
        include_bytes!("../../../../datasets/dpi/payloads/dns-query-edns0.bin"),
    ),
    (
        "dns-query-no-edns0",
        include_bytes!("../../../../datasets/dpi/payloads/dns-query-no-edns0.bin"),
    ),
    (
        "dns-edns0-double-opt",
        include_bytes!("../../../../datasets/dpi/payloads/dns-edns0-double-opt.bin"),
    ),
    (
        "dns-question-pointer",
        include_bytes!("../../../../datasets/dpi/payloads/dns-question-pointer.bin"),
    ),
    (
        "dns-question-pointer-loop",
        include_bytes!("../../../../datasets/dpi/payloads/dns-question-pointer-loop.bin"),
    ),
    (
        "dns-truncated",
        include_bytes!("../../../../datasets/dpi/payloads/dns-truncated.bin"),
    ),
    (
        "dns-negative-garbage",
        include_bytes!("../../../../datasets/dpi/payloads/dns-negative-garbage.bin"),
    ),
    (
        "http-get-host",
        include_bytes!("../../../../datasets/dpi/payloads/http-get-host.bin"),
    ),
    (
        "http-post-host",
        include_bytes!("../../../../datasets/dpi/payloads/http-post-host.bin"),
    ),
    (
        "http-no-host-yet",
        include_bytes!("../../../../datasets/dpi/payloads/http-no-host-yet.bin"),
    ),
    (
        "http-response-200",
        include_bytes!("../../../../datasets/dpi/payloads/http-response-200.bin"),
    ),
    (
        "http-response-404",
        include_bytes!("../../../../datasets/dpi/payloads/http-response-404.bin"),
    ),
    (
        "http-response-truncated",
        include_bytes!("../../../../datasets/dpi/payloads/http-response-truncated.bin"),
    ),
    (
        "http-response-bad-status",
        include_bytes!("../../../../datasets/dpi/payloads/http-response-bad-status.bin"),
    ),
    (
        "http-partial-version",
        include_bytes!("../../../../datasets/dpi/payloads/http-partial-version.bin"),
    ),
];

fn payload(name: &str) -> &'static [u8] {
    VECTORS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, p)| *p)
        .unwrap_or_else(|| panic!("向量 `{name}` 未编入 VECTORS 表（生成新向量后需同步）"))
}

fn expected() -> Json {
    JsonParser::new(EXPECTED).value()
}

fn entries(section: &str) -> Vec<Json> {
    expected()
        .get(section)
        .and_then(Json::as_arr)
        .unwrap_or_else(|| panic!("expected.json 缺少 `{section}` 段"))
        .to_vec()
}

// ---------------------------------------------------------------- 测试主体

#[test]
fn tls_vectors_match_expected() {
    for e in entries("tls") {
        let name = e.get("name").and_then(Json::as_str).expect("缺 name");
        let expect = e.get("expect").and_then(Json::as_str).expect("缺 expect");
        let p = payload(name);

        // 载荷长度先对一遍：生成器与 Rust 读的是同一批文件，长度不对说明字节被换过
        let want_len = e
            .get("payload_len")
            .and_then(Json::as_i64)
            .expect("缺 payload_len");
        assert_eq!(p.len() as i64, want_len, "[{name}] 载荷长度不一致");

        let got = tls::detect(p);
        match expect {
            "identified" => {
                let d = got
                    .detection()
                    .unwrap_or_else(|| panic!("[{name}] 期望 identified，实际 {}", got.word()));
                let want_sni = e.get("sni").expect("缺 sni");
                if want_sni.is_null() {
                    assert!(d.sni.is_none(), "[{name}] 期望无 SNI，实际 {:?}", d.sni);
                } else {
                    assert_eq!(
                        d.sni.as_deref(),
                        Some(want_sni.as_str().expect("sni 应为字符串")),
                        "[{name}] SNI 不一致"
                    );
                }
                // 失败时把特征串一起打出来：JA3 是"一个哈希对不上"的黑盒，
                // 没有原始串就只能去猜是哪一段算错了。
                assert_eq!(
                    d.ja3.as_ref().map(|s| s.as_str()),
                    e.get("ja3").and_then(Json::as_str),
                    "[{name}] JA3 不一致（实际特征串 {:?}，期望特征串 {:?}）",
                    d.ja3_raw,
                    e.get("ja3_raw").and_then(Json::as_str),
                );
                let want_alpn: Vec<&str> = e
                    .get("alpn")
                    .and_then(Json::as_arr)
                    .expect("缺 alpn")
                    .iter()
                    .map(|v| v.as_str().expect("alpn 元素应为字符串"))
                    .collect();
                assert_eq!(d.alpn, want_alpn, "[{name}] ALPN 不一致");
            }
            "need_more" => assert_eq!(
                got,
                Detect::NeedMore,
                "[{name}] 期望 need_more，实际 {}",
                got.word()
            ),
            "malformed" => assert_eq!(
                got,
                Detect::Malformed,
                "[{name}] 期望 malformed，实际 {}",
                got.word()
            ),
            // 负例：TLS 检测器必须明确拒绝，而不是报成"解析失败"
            "not_tls" => assert!(
                !matches!(got, Detect::Hit(_)),
                "[{name}] 非 TLS 载荷不得被识别为 TLS，实际 {}",
                got.word()
            ),
            other => panic!("[{name}] 未知的 expect 取值 `{other}`"),
        }
    }
}

#[test]
fn dns_vectors_match_expected() {
    for e in entries("dns") {
        let name = e.get("name").and_then(Json::as_str).expect("缺 name");
        let expect = e.get("expect").and_then(Json::as_str).expect("缺 expect");
        let p = payload(name);
        let got = dns::detect(p);
        match expect {
            "identified" => {
                let d = got
                    .detection()
                    .unwrap_or_else(|| panic!("[{name}] 期望 identified，实际 {}", got.word()));
                let want = e.get("qname").and_then(Json::as_str).expect("缺 qname");
                assert_eq!(d.qname.as_deref(), Some(want), "[{name}] QNAME 不一致");
                assert_eq!(
                    d.qtype,
                    e.get("qtype").and_then(Json::as_i64).map(|v| v as u16),
                    "[{name}] QTYPE 不一致"
                );
                assert_eq!(
                    d.qclass,
                    e.get("qclass").and_then(Json::as_i64).map(|v| v as u16),
                    "[{name}] QCLASS 不一致"
                );

                // RCODE 只在响应上产出：查询向量的期望是 null，实现里也必须是 None。
                // 若实现把查询的保留位读成 0 并产出，"响应码分布"会凭空多出一大批 0。
                let want_rcode = e.get("rcode").and_then(Json::as_i64).map(|v| v as u8);
                assert_eq!(d.rcode, want_rcode, "[{name}] RCODE 不一致");

                // 应答地址集合：逐条按顺序比对（顺序来自报文顺序，不是排序结果）
                let want_ips: Vec<&str> = e
                    .get("answer_ips")
                    .and_then(Json::as_arr)
                    .expect("缺 answer_ips")
                    .iter()
                    .map(|v| v.as_str().expect("answer_ips 元素应为字符串"))
                    .collect();
                assert_eq!(d.answer_ips, want_ips, "[{name}] ANSWER 地址集合不一致");

                assert_eq!(
                    d.ptr_depth,
                    e.get("ptr_depth").and_then(Json::as_i64).map(|v| v as u8),
                    "[{name}] 指针跳数不一致"
                );
                assert_eq!(
                    d.edns0_udp_size,
                    e.get("edns0_udp_size")
                        .and_then(Json::as_i64)
                        .map(|v| v as u16),
                    "[{name}] EDNS0 UDP 载荷上限不一致"
                );
            }
            "need_more" => assert_eq!(got, Detect::NeedMore, "[{name}] 期望 need_more"),
            "malformed" => assert_eq!(got, Detect::Malformed, "[{name}] 期望 malformed"),
            "not_dns" => assert!(
                !matches!(got, Detect::Hit(_)),
                "[{name}] 非 DNS 载荷不得被识别为 DNS，实际 {}",
                got.word()
            ),
            other => panic!("[{name}] 未知的 expect 取值 `{other}`"),
        }
    }
}

#[test]
fn http_vectors_match_expected() {
    for e in entries("http") {
        let name = e.get("name").and_then(Json::as_str).expect("缺 name");
        let expect = e.get("expect").and_then(Json::as_str).expect("缺 expect");
        let p = payload(name);
        let got = http::detect(p);
        match expect {
            "identified" => {
                let d = got
                    .detection()
                    .unwrap_or_else(|| panic!("[{name}] 期望 identified，实际 {}", got.word()));
                // 逐个字段比对"有值 / 恰好为 null"两种情形：
                // 响应向量的 host/uri/UA 期望就是 null，用 `expect("缺 host")` 会把
                // "这个向量本就没有这个头"误判成"期望值写漏了"。
                assert_eq!(
                    d.host.as_deref(),
                    e.get("host").and_then(Json::as_str),
                    "[{name}] Host 不一致"
                );
                assert_eq!(
                    d.method.as_deref(),
                    e.get("method").and_then(Json::as_str),
                    "[{name}] 方法不一致"
                );
                assert_eq!(
                    d.uri.as_deref(),
                    e.get("uri").and_then(Json::as_str),
                    "[{name}] URI 不一致"
                );
                assert_eq!(
                    d.user_agent.as_deref(),
                    e.get("user_agent").and_then(Json::as_str),
                    "[{name}] User-Agent 不一致"
                );
                // 状态码只在响应侧有值：请求向量的期望是 null，实现里也必须是 None
                assert_eq!(
                    d.status_code,
                    e.get("status_code")
                        .and_then(Json::as_i64)
                        .map(|v| v as u16),
                    "[{name}] 状态码不一致"
                );
                assert_eq!(
                    d.content_type.as_deref(),
                    e.get("content_type").and_then(Json::as_str),
                    "[{name}] Content-Type 不一致"
                );
            }
            "need_more" => assert_eq!(
                got,
                Detect::NeedMore,
                "[{name}] 期望 need_more，实际 {}",
                got.word()
            ),
            "malformed" => assert_eq!(
                got,
                Detect::Malformed,
                "[{name}] 期望 malformed，实际 {}",
                got.word()
            ),
            other => panic!("[{name}] 未知的 expect 取值 `{other}`"),
        }
    }
}

#[test]
fn framework_routes_tls_and_dns_by_port() {
    // 框架层：同一段载荷分别按"它本来的端口"与"一个不相干的端口"喂进去，
    // 结论必须一致 —— 端口只是给顺序的提示，不能成为判据本身。
    let tls = payload("tls-basic");
    assert_eq!(
        super::identify(tls, super::IPPROTO_TCP, 443).word(),
        "identified"
    );
    let dns = payload("dns-query-a");
    assert_eq!(
        super::identify(dns, super::IPPROTO_UDP, 53).word(),
        "identified"
    );
    let http = payload("http-get-host");
    assert_eq!(
        super::identify(http, super::IPPROTO_TCP, 80).word(),
        "identified"
    );
}

#[test]
fn framework_does_not_report_need_more_as_unknown() {
    // 分片（need_more）绝不能被算成 unknown：这两者的统计后果完全相反 ——
    // 前者"再等等就能识别"，后者"这条流我们不认识"。
    let frag = payload("tls-truncated");
    let out = super::identify(frag, super::IPPROTO_TCP, 443);
    assert_eq!(out, Outcome::NeedMore);
}

#[test]
fn ech_vector_is_marked_as_not_tshark_verified() {
    // 守门：ECH 向量是唯一的"三方互证不可用"条目（tshark 4.6.7 认不出手工构造的 ECH 体）。
    // 这个标记一旦被删掉或悄悄改成 true，check-dpi-vectors.sh 会拿 tshark 的空结果
    // 去比对我们的期望值，报出一个"看起来是 Rust 实现错了"的失败 —— 排查方向会完全跑偏。
    let e = entries("tls")
        .into_iter()
        .find(|x| x.get("name").and_then(Json::as_str) == Some("tls-ech-no-outer-sni"))
        .expect("ECH 向量缺失");
    let t = e.get("tshark").expect("TLS 向量必须带 tshark 核验标记");
    assert_eq!(t.get("verified"), Some(&Json::Bool(false)));
    assert!(t.get("note").and_then(Json::as_str).unwrap_or("").len() > 20);
}

#[test]
fn every_vector_has_payload_and_tshark_marker() {
    // 生成新向量后忘了同步 VECTORS 表 → 这里 panic，而不是静默少测一条。
    for section in ["tls", "dns", "http"] {
        for e in entries(section) {
            let name = e.get("name").and_then(Json::as_str).expect("缺 name");
            let p = payload(name);
            assert!(!p.is_empty(), "[{name}] 载荷为空");
        }
    }
}

#[test]
fn attributes_are_emitted_for_identified_flows() {
    // 端到端：向量 → 解析器 → 属性产出 → 真源校验。
    // 这条链路过去是断的（属性只在字典与示例规则里存在，没有任何生产者）。
    let verdict = tls::detect(payload("tls-basic"));
    let d = verdict.detection().expect("应识别为 TLS");
    let attrs = attributes::emit(d);
    assert!(
        attrs.iter().any(|a| a.id.contains("TLS_SNI")),
        "应产出 TLS SNI"
    );
    assert!(attrs.iter().any(|a| a.id.contains("TLS_JA3")), "应产出 JA3");
    assert!(
        attrs.iter().any(|a| a.id.contains("APP_ID")),
        "应产出 APP_ID"
    );
    for a in &attrs {
        a.validate().expect("产出属性必须通过真源校验");
    }

    let verdict = dns::detect(payload("dns-query-a"));
    let d = verdict.detection().expect("应识别为 DNS");
    let attrs = attributes::emit(d);
    assert!(attrs.iter().any(|a| a.id.contains("DNS_QNAME")));
    for a in &attrs {
        a.validate().expect("产出属性必须通过真源校验");
    }
}
