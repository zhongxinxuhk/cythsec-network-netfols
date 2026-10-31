// tls_inspect.rs —— `cythsec-tls-inspect`：key log 驱动的 TLS 1.2/1.3 离线解密 + DPI。
//
// 为什么单独成一个二进制，而不是改 FlowRecord：
//   FlowRecord 的字节布局与列式落盘是已实测的对外契约，往里塞"明文结论"会改变
//   每条记录的落盘字节，必须单独一批重测。这里把解密结果写成独立的 JSONL 事件流，
//   复用同一套 pcap 解码/TCP 重组/DPI，不碰既有记录契约。
//
// 安全边界：
//   * 必须显式 `--decrypt`（或策略文件里 tls_decrypt.enabled=true）才解密；
//   * 只接受运维方提供的 NSS key log，文件必须 0600；
//   * 不输出明文正文，只输出长度、SHA-256、DPI 结论与 HTTP 元数据；
//   * 不主动探测、不导出/猜测密钥。

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

use traffic_engine::build_info;
use traffic_engine::channel::decode_frame;
use traffic_engine::dpi::{self, DpiPolicy, Intensity, Outcome};
use traffic_engine::flow::FlowKey;
use traffic_engine::pcapfile::{PcapReader, LINKTYPE_ETHERNET};
use traffic_engine::reassembly::stream::{Stream, StreamConfig};
use traffic_engine::reassembly::tcp;
use traffic_engine::tlsdecrypt::crypto::sha256;
use traffic_engine::tlsdecrypt::keylog::KeyLog;
use traffic_engine::tlsdecrypt::record::{
    hex, parse_client_hello, Plaintext, TlsSession, TlsVersion,
};

const USAGE: &str = "\
cythsec-tls-inspect —— 用 NSS key log 解密 TLS 1.2/1.3 应用记录并做 DPI

用法:
  cythsec-tls-inspect -r <input.pcap> --keylog <FILE> --decrypt [选项]

选项:
  -r, --read <FILE>        输入经典 pcap（链路层必须是以太网）
      --keylog <FILE>      NSS key log（SSLKEYLOGFILE 格式），必须是 0600 普通文件；
                           TLS 1.3 需要 CLIENT/SERVER_TRAFFIC_SECRET_0，TLS 1.2 需要 CLIENT_RANDOM
      --dpi-policy <FILE>  DPI 策略 JSON；必须 enabled=true、intensity=deep、
                           tls_decrypt.enabled=true
      --decrypt            显式允许解密（策略文件未打开时必须同时给出）
      --dpi <LEVEL>        覆盖策略强度：off/basic/standard/deep；解密要求 deep
  -o, --output <FILE>      JSONL 输出；缺省或 `-` 写 stdout
      --limit <N>          最多输出 N 条流事件（按规范五元组排序）
      --max-flows <N>      最多同时保留 N 条 TCP 流（默认 10000；超出后不再新建）
      --max-bytes <N>      每个方向最多重组多少字节（默认 4194304）
  -q, --quiet              不打印统计摘要
  -V, --version            打印版本信息
  -h, --help               打印本帮助

输出:
  每行一个 JSON 事件。`tls_flow` 含 DPI 结论、HTTP 元数据、告警计数与解密记录数；
  `tls_flow_error` 含失败原因。**不输出明文载荷**。

退出码: 0 成功；1 参数/IO/策略/密钥日志/自检失败。
";

#[derive(Debug)]
struct Args {
    input: String,
    output: Option<String>,
    keylog: Option<String>,
    dpi_policy: Option<String>,
    decrypt: bool,
    dpi: Option<Intensity>,
    limit: Option<usize>,
    max_flows: usize,
    max_bytes: usize,
    quiet: bool,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut input = None;
    let mut output = None;
    let mut keylog = None;
    let mut dpi_policy = None;
    let mut decrypt = false;
    let mut dpi = None;
    let mut limit = None;
    let mut max_flows = 10_000usize;
    let mut max_bytes = 4 * 1024 * 1024usize;
    let mut quiet = false;
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        let mut take = |name: &str| -> Result<String, String> {
            i += 1;
            argv.get(i)
                .cloned()
                .ok_or_else(|| format!("{name} 缺少参数"))
        };
        match arg {
            "-r" | "--read" => input = Some(take("--read")?),
            "-o" | "--output" => output = Some(take("--output")?),
            "--keylog" => keylog = Some(take("--keylog")?),
            "--dpi-policy" => dpi_policy = Some(take("--dpi-policy")?),
            "--decrypt" => decrypt = true,
            "--dpi" => {
                let v = take("--dpi")?;
                dpi = Some(Intensity::parse(&v)?);
            }
            "--limit" => {
                let v = take("--limit")?;
                limit = Some(v.parse::<usize>().map_err(|_| "--limit 不是整数")?);
            }
            "--max-flows" => {
                let v = take("--max-flows")?;
                max_flows = v
                    .parse::<usize>()
                    .map_err(|_| "--max-flows 不是整数")?
                    .max(1);
            }
            "--max-bytes" => {
                let v = take("--max-bytes")?;
                max_bytes = v
                    .parse::<usize>()
                    .map_err(|_| "--max-bytes 不是整数")?
                    .max(4096);
            }
            "-q" | "--quiet" => quiet = true,
            "-V" | "--version" => {
                let b = build_info();
                println!(
                    "cythsec-tls-inspect {} commit={} built={}",
                    b.version, b.commit, b.build_time
                );
                std::process::exit(0);
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("未知参数 `{other}`（--help 查看用法）")),
        }
        i += 1;
    }
    Ok(Args {
        input: input.ok_or("必须给出 -r/--read")?,
        output,
        keylog,
        dpi_policy,
        decrypt,
        dpi,
        limit,
        max_flows,
        max_bytes,
        quiet,
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cythsec-tls-inspect: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv)?;

    let mut policy = match &args.dpi_policy {
        Some(path) => DpiPolicy::from_file(Path::new(path))?,
        None => DpiPolicy::default(),
    };
    if let Some(level) = args.dpi {
        policy.intensity = level;
    }
    if let Some(path) = &args.keylog {
        policy.tls_decrypt.keylog_file = Some(path.clone());
    }
    if args.decrypt {
        policy.tls_decrypt.enabled = true;
    }
    if !policy.decrypt_tls() {
        return Err(format!(
            "TLS 解密未启用（{}）。需要 enabled=true、intensity=deep、tls_decrypt.enabled=true \
             且 keylog_file 非空；可加 --dpi deep --decrypt --keylog <FILE>",
            policy.summary()
        ));
    }
    if !policy.module_enabled("tls") {
        return Err("tls 模块被策略关闭，不能进行 TLS 解密".into());
    }
    let keylog_path = policy
        .tls_decrypt
        .keylog_file
        .as_deref()
        .ok_or("策略未给出 keylog_file")?;
    let keylog = KeyLog::load(Path::new(keylog_path))?;

    let file = File::open(&args.input).map_err(|e| format!("打开 {}: {e}", args.input))?;
    let mut reader = PcapReader::new(BufReader::new(file))
        .map_err(|e| format!("读取 pcap 头 {}: {e}", args.input))?;
    if reader.linktype() != LINKTYPE_ETHERNET {
        return Err(format!(
            "只支持以太网链路层 pcap（linktype={}），当前为 {}",
            reader.linktype(),
            reader.header().linktype_name()
        ));
    }

    let mut flows: BTreeMap<FlowKey, FlowBuf> = BTreeMap::new();
    let mut stats = Stats::default();
    while let Some(rec) = reader
        .next_record()
        .map_err(|e| format!("读取 pcap 记录: {e}"))?
    {
        stats.packets += 1;
        let d = match decode_frame(&rec.data) {
            Ok(d) => d,
            Err(_) => {
                stats.decode_errors += 1;
                continue;
            }
        };
        if d.key.proto.number() != dpi::IPPROTO_TCP || !d.is_initial_fragment {
            continue;
        }
        let end = d
            .l4_offset
            .saturating_add(d.ip_payload_len as usize)
            .min(rec.data.len());
        let l4 = match rec.data.get(d.l4_offset..end) {
            Some(v) if !v.is_empty() => v,
            _ => {
                stats.truncated += 1;
                continue;
            }
        };
        let seg = match tcp::parse(l4) {
            Ok(s) => s,
            Err(_) => {
                stats.tcp_parse_errors += 1;
                continue;
            }
        };
        let canon = d.key.canonical();
        if !flows.contains_key(&canon) && flows.len() >= args.max_flows {
            stats.flows_dropped += 1;
            continue;
        }
        let entry = flows
            .entry(canon)
            .or_insert_with(|| FlowBuf::new(args.max_bytes));
        let side = if d.key == canon {
            &mut entry.a
        } else {
            &mut entry.b
        };
        feed_segment(side, &seg);
    }

    let out: Box<dyn Write> = match args.output.as_deref() {
        None | Some("-") => Box::new(io::stdout().lock()),
        Some(path) => Box::new(BufWriter::new(
            File::create(path).map_err(|e| format!("创建 {path}: {e}"))?,
        )),
    };
    let mut out = BufWriter::new(out);
    let mut emitted = 0usize;
    for (key, mut buf) in flows {
        if args.limit.is_some_and(|n| emitted >= n) {
            break;
        }
        let a_holes = buf.a.holes().len();
        let b_holes = buf.b.holes().len();
        let a_syn = buf.a.anchored_by_syn();
        let b_syn = buf.b.anchored_by_syn();
        let a_bytes = buf.a.take_all();
        let b_bytes = buf.b.take_all();
        if a_bytes.len() < 5 && b_bytes.len() < 5 {
            continue;
        }
        // 先判断哪一侧是客户端：有 ClientHello 的一侧。没有 ClientHello 的流
        // 不是 TLS 会话（或抓包起点太晚），不产生事件。
        let (client_bytes, server_bytes, client_is_a) = if parse_client_hello(&a_bytes).is_ok() {
            (a_bytes, b_bytes, true)
        } else if parse_client_hello(&b_bytes).is_ok() {
            (b_bytes, a_bytes, false)
        } else {
            stats.not_tls += 1;
            continue;
        };
        let (client_key, server_key) = if client_is_a {
            (key, key.reverse())
        } else {
            (key.reverse(), key)
        };
        let (client_holes, server_holes, client_syn, server_syn) = if client_is_a {
            (a_holes, b_holes, a_syn, b_syn)
        } else {
            (b_holes, a_holes, b_syn, a_syn)
        };
        let client = fmt_endpoint(&client_key);
        let server = fmt_endpoint(&server_key);
        match TlsSession::from_streams(&client_bytes, &server_bytes, &keylog) {
            Ok(mut session) => {
                let client_pt = session.decrypt_client(&client_bytes);
                let server_pt = session.decrypt_server(&server_bytes);
                match (client_pt, server_pt) {
                    (Ok(c), Ok(s)) => {
                        stats.decrypted += 1;
                        let msgs = render_messages("client", &c, &policy, &mut stats)
                            .into_iter()
                            .chain(render_messages("server", &s, &policy, &mut stats))
                            .collect::<Vec<_>>();
                        let alerts = alerts(&c, &s);
                        let version = match session.version {
                            TlsVersion::Tls12 => "1.2",
                            TlsVersion::Tls13 => "1.3",
                        };
                        let line = format!(
                            "{{\"schema_version\":1,\"event\":\"tls_flow\",\"client\":{},\"server\":{},\
                             \"server_name\":{},\"cipher_suite\":\"{}\",\"tls_version\":\"{}\",\"client_random\":\"{}\",\
                             \"records\":{{\"client\":{{\"opened\":{},\"skipped\":{}}},\
                             \"server\":{{\"opened\":{},\"skipped\":{}}}}},\
                             \"stream\":{{\"client_bytes\":{},\"server_bytes\":{},\
                             \"client_holes\":{},\"server_holes\":{},\"client_syn\":{},\"server_syn\":{}}},\
                             \"alerts\":[{}],\"messages\":[{}]}}",
                            jstr(&client),
                            jstr(&server),
                            session
                                .server_name
                                .as_deref()
                                .map(jstr)
                                .unwrap_or_else(|| "null".into()),
                            traffic_engine::tlsdecrypt::record::suite_name(session.cipher_suite),
                            version,
                            hex(&session.client_random),
                            session.client.opened(),
                            session.client.skipped(),
                            session.server.opened(),
                            session.server.skipped(),
                            client_bytes.len(),
                            server_bytes.len(),
                            client_holes,
                            server_holes,
                            client_syn,
                            server_syn,
                            alerts.join(","),
                            msgs.join(","),
                        );
                        writeln!(out, "{line}").map_err(|e| format!("写输出: {e}"))?;
                        emitted += 1;
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        stats.failed += 1;
                        emit_error(&mut out, &client, &server, &e)?;
                        emitted += 1;
                    }
                }
            }
            Err(e) => {
                stats.failed += 1;
                emit_error(&mut out, &client, &server, &e)?;
                emitted += 1;
            }
        }
    }
    out.flush().map_err(|e| format!("刷新输出: {e}"))?;
    if !args.quiet {
        eprintln!(
            "tls-inspect packets={} decode_errors={} tcp_parse_errors={} truncated={} \
             not_tls={} flows_dropped={} decrypted={} failed={} messages={} emitted={} keylog_entries={}",
            stats.packets,
            stats.decode_errors,
            stats.tcp_parse_errors,
            stats.truncated,
            stats.not_tls,
            stats.flows_dropped,
            stats.decrypted,
            stats.failed,
            stats.messages,
            emitted,
            keylog.len()
        );
    }
    Ok(())
}

struct FlowBuf {
    a: Stream,
    b: Stream,
}

impl FlowBuf {
    fn new(max_bytes: usize) -> Self {
        let cfg = StreamConfig {
            max_buffered: max_bytes.min(2 * 1024 * 1024),
            max_span: max_bytes.min(u32::MAX as usize) as u32,
            ..StreamConfig::default()
        };
        Self {
            a: Stream::new(cfg),
            b: Stream::new(cfg),
        }
    }
}

fn feed_segment(stream: &mut Stream, seg: &tcp::TcpSegment<'_>) {
    if seg.flags.syn {
        stream.on_syn(seg.seq);
        if !seg.payload.is_empty() {
            stream.on_data(seg.seq.wrapping_add(1), seg.payload);
        }
    } else if !seg.payload.is_empty() {
        stream.on_data(seg.seq, seg.payload);
    }
    if seg.flags.fin {
        stream.on_fin(seg.seq.wrapping_add(seg.payload.len() as u32));
    }
    if seg.flags.rst {
        stream.on_rst();
    }
}

#[derive(Default)]
struct Stats {
    packets: u64,
    decode_errors: u64,
    tcp_parse_errors: u64,
    truncated: u64,
    not_tls: u64,
    flows_dropped: u64,
    decrypted: u64,
    failed: u64,
    messages: u64,
}

fn render_messages(
    direction: &str,
    plain: &[Plaintext],
    policy: &DpiPolicy,
    stats: &mut Stats,
) -> Vec<String> {
    let mut out = Vec::new();
    for pt in plain {
        if pt.content_type != 23 || pt.data.is_empty() {
            continue;
        }
        stats.messages += 1;
        // 解密后的单条记录最多 16 KiB，但仍按策略窗口截断：DPI 不应偷偷
        // 吃掉比策略声明更多的明文字节。长度与 SHA-256 仍按完整明文报告。
        let limit = policy
            .effective_inspect_bytes(dpi::DEFAULT_INSPECT_BYTES)
            .max(1);
        let view = &pt.data[..pt.data.len().min(limit)];
        let outcome = dpi::identify_with_policy(view, dpi::IPPROTO_TCP, 443, 443, policy);
        let digest = hex(&sha256(&pt.data));
        let (outcome_word, app, confidence, rationale, http) = match &outcome {
            Outcome::Identified(info) => {
                let http = if info.app == dpi::AppId::Http {
                    render_http(view)
                } else {
                    None
                };
                (
                    "identified",
                    Some(info.app.as_str()),
                    Some(info.confidence.as_str()),
                    Some(info.rationale),
                    http,
                )
            }
            other => (other.word(), None, None, None, None),
        };
        out.push(
            format!(
                "{{\"direction\":\"{direction}\",\"bytes\":{},\"sha256\":\"{}\",\
             \"dpi\":{{\"outcome\":\"{}\"",
                pt.data.len(),
                digest,
                outcome_word
            ) + &app.map(|a| format!(",\"app\":\"{a}\"")).unwrap_or_default()
                + &confidence
                    .map(|c| format!(",\"confidence\":\"{c}\""))
                    .unwrap_or_default()
                + &rationale
                    .map(|r| format!(",\"rationale\":{}", jstr(r)))
                    .unwrap_or_default()
                + &http.map(|h| format!(",\"http\":{h}")).unwrap_or_default()
                + "}}",
        );
    }
    out
}

fn render_http(data: &[u8]) -> Option<String> {
    if let Ok(req) = dpi::http::parse(data) {
        return Some(format!(
            "{{\"kind\":\"request\",\"method\":{},\"uri\":{},\"version\":{},\"host\":{}}}",
            jstr(&req.method),
            jstr(&req.uri),
            jstr(&req.version),
            req.host
                .as_deref()
                .map(jstr)
                .unwrap_or_else(|| "null".into())
        ));
    }
    if let Ok(resp) = dpi::http::parse_response(data) {
        return Some(format!(
            "{{\"kind\":\"response\",\"status\":{},\"reason\":{},\"version\":{}}}",
            resp.status_code,
            jstr(&resp.reason),
            jstr(&resp.version)
        ));
    }
    None
}

fn alerts(client: &[Plaintext], server: &[Plaintext]) -> Vec<String> {
    let mut out = Vec::new();
    for (dir, list) in [("client", client), ("server", server)] {
        for pt in list {
            if pt.content_type == 21 && pt.data.len() >= 2 {
                out.push(format!(
                    "{{\"direction\":\"{dir}\",\"level\":{},\"description\":\"{}\"}}",
                    pt.data[0],
                    alert_name(pt.data[1])
                ));
            }
        }
    }
    out
}

fn alert_name(code: u8) -> &'static str {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown_alert",
    }
}

fn emit_error(out: &mut impl Write, client: &str, server: &str, error: &str) -> Result<(), String> {
    writeln!(
        out,
        "{{\"schema_version\":1,\"event\":\"tls_flow_error\",\"client\":{},\"server\":{},\"error\":{}}}",
        jstr(client),
        jstr(server),
        jstr(error)
    )
    .map_err(|e| format!("写输出: {e}"))
}

fn fmt_endpoint(k: &FlowKey) -> String {
    match k.src_ip {
        std::net::IpAddr::V4(ip) => format!("{ip}:{}", k.src_port),
        std::net::IpAddr::V6(ip) => format!("[{ip}]:{}", k.src_port),
    }
}

fn jstr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
