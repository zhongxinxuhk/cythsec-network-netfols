// analyze.rs —— `cythsec-analyze`：离线 pcap → FlowRecord(JSONL)（CYS-TRF-035）。
//
// 这个二进制的存在意义是：**让整条数据链在没有采集面、没有共享内存、没有内核模块的
// 情况下也能被端到端验证。** 给定一个 pcap，它跑的是和在线路径相同的那几个模块，
// 所以它同时也是那条链的**回归测试载体**。
//
// 本文件只负责三件事：解析命令行、开文件、按契约写 JSONL / 导出 IPFIX。真正的分析逻辑在
// `traffic_engine::pipeline`（同一份代码也被 `tests/pipeline_sample.rs` 驱动，
// 命令行与测试因此不可能漂移）。

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::process::ExitCode;

use traffic_engine::pipeline::{analyze_pcap_with, AnalyzeOptions, AnalyzeStats};
use traffic_engine::record::write_jsonl;
use traffic_engine::{build_info, crate_version};

const USAGE: &str = "\
cythsec-analyze —— 离线 pcap 分析，产出 FlowRecord（JSONL）

用法:
  cythsec-analyze -r <input.pcap> [-o <flows.jsonl>] [选项]

选项:
  -r, --read <FILE>        输入经典 pcap 文件（必填）
  -o, --output <FILE>      输出 JSONL 文件；缺省或 `-` 表示写 stdout
      --limit <N>          最多输出 N 条记录（按会话键排序后截取前 N 条）
      --inspect-bytes <N>  喂给 DPI 的首包字节数上限（默认 512）
      --max-sessions <N>   会话表容量上限（默认 65536）
      --workers <N>        消费侧并行 worker 数（默认 1 = 就地单线程，见下）
      --strict             严格 TCP 模式：未见到握手的会话不采纳（默认容忍，见下）
      --ipfix-udp <ADDR>  把每条 FlowRecord 按 RFC 7011 导出为 IPFIX，UDP 发往
                          host:port（采集器地址；解析失败直接退出，不降级）
      --ipfix-pcap <FILE>  同一批 IPFIX 报文包成 UDP 帧落盘为 pcap（供 tshark 独立
                          校验与 tcpreplay 回放；可与 --ipfix-udp 同时使用）
      --ipfix-domain <N>  Observation Domain ID（默认 1；采集侧按它区分模板与序列号）
      --ipfix-max-msg <N>  单个 IPFIX 报文字节上限（默认 1400；UDP 上超 MTU 会被分片
                          甚至丢弃，IPv6 最小 MTU 场景应调小）
      --ipfix-template-refresh <N>
                          每 N 条报文重发一次模板（默认 20；UDP 无连接、采集器会重启，
                          只发一次意味着采集器一重启后面全解不开）
  -q, --quiet              不打印统计摘要
  -V, --version            打印版本信息
  -h, --help               打印本帮助

默认值说明:
  * 默认**容忍模式**：离线抓包的起点几乎总是切在会话中间，严格模式会把这类会话
    一律判成 Closed，那不是协议的真实状态。需要严格判定时加 `--strict`。
  * 文件末尾仍打开的会话**照常产出记录**（它们承载了数据）。
  * `--workers N`（N>1）按**方向无关的会话键**静态分片，每个 worker 私有流表、会话、
    特征与 DPI 探针（即「每核一张独立表」，无锁）；派发端单线程读盘/解帧/分片，
    会话 id 也由派发端按首次出现顺序统一分配，因此 `--workers N` 与 `--workers 1`
    在容量充足时输出**逐字节一致**。两点限制：每个 worker 各自持有 `--max-sessions`
    额度（总容量 = N × 额度），且一旦发生会话逐出，各 worker 的存活集合本就会不同。

输出:
  每行一条 JSON 的 FlowRecord（schema 见 traffic_engine::record）。
  --ipfix-* 打开时**同时**导出 IPFIX：这是让记录走进运营商既有流级通道（NetFlow/IPFIX
  采集体系）的唯一出口，也是「流级 vs 逐包」这条量级问题的正面回答——逐包采集在省网
  不存在（单条 100G 最坏帧 148.8 Mpps；骨干 10 Tbps 全量约 108 PB/天）。
  统计摘要写 stderr，因此 `-o -` 时 stdout 是**干净的 JSONL**，可直接管道给下游。

退出码: 0 成功；1 参数/IO/自检失败（自检失败说明输出不可信）。
";

#[derive(Debug)]
struct Args {
    input: String,
    output: Option<String>,
    limit: Option<usize>,
    inspect_bytes: usize,
    max_sessions: usize,
    workers: usize,
    strict: bool,
    quiet: bool,
    ipfix: Option<IpfixArgs>,
}

#[derive(Debug)]
struct IpfixArgs {
    udp: Option<String>,
    pcap: Option<String>,
    domain: u32,
    template_refresh: u32,
    max_msg_bytes: usize,
}

#[derive(Debug)]
enum Parsed {
    Run(Box<Args>),
    Help,
    Version,
}

fn parse_args(argv: &[String]) -> Result<Parsed, String> {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut limit: Option<usize> = None;
    let mut inspect_bytes = traffic_engine::dpi::DEFAULT_INSPECT_BYTES;
    let mut max_sessions = 1usize << 16;
    let mut workers = 1usize;
    let mut strict = false;
    let mut quiet = false;
    let mut ipfix_udp: Option<String> = None;
    let mut ipfix_pcap: Option<String> = None;
    let mut ipfix_domain: u32 = 1;
    let mut ipfix_template_refresh: u32 = 20;
    let mut ipfix_max_msg: usize = 1400;

    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        // 同时支持 `--opt=value` 与 `--opt value`：只支持一种的话，另一种会被
        // 当成无法识别的参数（好一点）或位置参数（坏得多，会被静默忽略）。
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (arg, None),
        };
        let mut take_value = |what: &str| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            i += 1;
            argv.get(i)
                .cloned()
                .ok_or_else(|| format!("{what} 缺少取值"))
        };
        match name {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "-r" | "--read" => input = Some(take_value("--read")?),
            "-o" | "--output" => output = Some(take_value("--output")?),
            "--limit" => {
                let v = take_value("--limit")?;
                limit = Some(
                    v.parse::<usize>()
                        .map_err(|_| format!("--limit 需要一个非负整数，得到 `{v}`"))?,
                );
            }
            "--inspect-bytes" => {
                let v = take_value("--inspect-bytes")?;
                inspect_bytes = v
                    .parse::<usize>()
                    .map_err(|_| format!("--inspect-bytes 需要一个非负整数，得到 `{v}`"))?;
            }
            "--max-sessions" => {
                let v = take_value("--max-sessions")?;
                let n = v
                    .parse::<usize>()
                    .map_err(|_| format!("--max-sessions 需要一个正整数，得到 `{v}`"))?;
                if n == 0 {
                    return Err("--max-sessions 必须大于 0".to_string());
                }
                max_sessions = n;
            }
            "--workers" => {
                let v = take_value("--workers")?;
                let n = v
                    .parse::<usize>()
                    .map_err(|_| format!("--workers 需要一个正整数，得到 `{v}`"))?;
                // 上限只挡明显的笔误（例如把字节数填进来）。超配不禁止：交叉验证时
                // 刻意跑 N > 核数是有意义的（看是不是队列/锁在拖后腿）。
                if n == 0 || n > 256 {
                    return Err(format!("--workers 需要在 1..=256 之间，得到 `{v}`"));
                }
                workers = n;
            }
            "--strict" => strict = true,
            "--ipfix-udp" => ipfix_udp = Some(take_value("--ipfix-udp")?),
            "--ipfix-pcap" => ipfix_pcap = Some(take_value("--ipfix-pcap")?),
            "--ipfix-domain" => {
                let v = take_value("--ipfix-domain")?;
                ipfix_domain = v
                    .parse::<u32>()
                    .map_err(|_| format!("--ipfix-domain 需要一个 32 位无符号整数，得到 `{v}`"))?;
            }
            "--ipfix-max-msg" => {
                let v = take_value("--ipfix-max-msg")?;
                ipfix_max_msg = v
                    .parse::<usize>()
                    .map_err(|_| format!("--ipfix-max-msg 需要一个正整数，得到 `{v}`"))?;
            }
            "--ipfix-template-refresh" => {
                let v = take_value("--ipfix-template-refresh")?;
                let n = v
                    .parse::<u32>()
                    .map_err(|_| format!("--ipfix-template-refresh 需要一个正整数，得到 `{v}`"))?;
                // 0 会让"每 0 条重发"变成除零；同时它也说不清语义（从不发？）。
                if n == 0 {
                    return Err("--ipfix-template-refresh 必须大于 0".to_string());
                }
                ipfix_template_refresh = n;
            }
            "-q" | "--quiet" => quiet = true,
            other => return Err(format!("无法识别的参数 `{other}`（用 --help 看用法）")),
        }
        i += 1;
    }

    let input = input.ok_or_else(|| "缺少必填参数 -r/--read（输入 pcap）".to_string())?;
    // 两个都缺时 `ipfix` 为 None（纯离线分析，不导出）。
    let ipfix = if ipfix_udp.is_some() || ipfix_pcap.is_some() {
        Some(IpfixArgs {
            udp: ipfix_udp,
            pcap: ipfix_pcap,
            domain: ipfix_domain,
            template_refresh: ipfix_template_refresh,
            max_msg_bytes: ipfix_max_msg,
        })
    } else {
        None
    };
    Ok(Parsed::Run(Box::new(Args {
        input,
        output,
        limit,
        inspect_bytes,
        max_sessions,
        workers,
        strict,
        quiet,
        ipfix,
    })))
}

/// 统计摘要一律写 stderr：这样 `-o -` 时 stdout 是干净 JSONL，可直接管道给下游。
fn report(stats: &AnalyzeStats, input: &str, strict: bool, emitted: usize) {
    let e = io::stderr();
    let mut err = e.lock();
    let _ = writeln!(
        err,
        "[cythsec-analyze] input={input} version={} linktype={} strict={strict}",
        crate_version(),
        stats.linktype_name
    );
    let _ = writeln!(
        err,
        "[cythsec-analyze] packets_read={} packets_decoded={} decode_errors={} truncated={} payload_start_unknown={}",
        stats.packets_read,
        stats.packets_decoded,
        stats.decode_error_count(),
        stats.truncated_captures,
        stats.payload_start_unknown
    );
    for (code, n) in &stats.decode_errors {
        let _ = writeln!(err, "[cythsec-analyze] decode_error code={code} count={n}");
    }
    let _ = writeln!(
        err,
        "[cythsec-analyze] sessions={} emitted={} created={} expired={} evicted={} illegal_tcp_events={}",
        stats.records,
        emitted,
        stats.session.sessions_created,
        stats.session.sessions_expired,
        stats.session.sessions_evicted,
        stats.session.illegal_tcp_events
    );
    let apps: Vec<String> = stats
        .app_outcomes
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let _ = writeln!(err, "[cythsec-analyze] app_outcome: {}", apps.join(" "));
    let shards: Vec<String> = stats.worker_flows.iter().map(|n| n.to_string()).collect();
    let _ = writeln!(
        err,
        "[cythsec-analyze] workers={} worker_flows=[{}] evicted={}",
        stats.workers,
        shards.join(","),
        stats.session.sessions_evicted
    );
    if stats.workers > 1 {
        // 这句必须打印：不打印的话，下游无法判断"这份输出与单线程是否可比"。
        let _ = writeln!(
            err,
            "[cythsec-analyze] 分片模式：每 worker 私有状态、会话 id 由派发端定序；\
             与 --workers 1 逐字节一致的前提是未发生会话逐出（本次 evicted={}，\
             且每 worker 各自持有 --max-sessions 额度）",
            stats.session.sessions_evicted
        );
    }
    let _ = writeln!(
        err,
        "[cythsec-analyze] non_finite_feature_vectors={} counter_mismatches={} sorted_by_key={}",
        stats.non_finite_vectors, stats.counter_mismatches, stats.sorted_by_key
    );
}

fn run(args: &Args) -> Result<usize, String> {
    let file =
        File::open(&args.input).map_err(|e| format!("打不开输入文件 `{}`：{e}", args.input))?;
    let base = if args.strict {
        AnalyzeOptions::strict()
    } else {
        AnalyzeOptions::default()
    };
    let opts = AnalyzeOptions {
        inspect_bytes: args.inspect_bytes,
        session: traffic_engine::session::SessionConfig {
            max_sessions: args.max_sessions,
            ..base.session
        },
    };

    let (records, stats) = analyze_pcap_with(BufReader::new(file), &opts, args.workers)
        .map_err(|e| format!("分析 `{}` 失败：{e}", args.input))?;

    let emitted = match args.limit {
        Some(n) => records.len().min(n),
        None => records.len(),
    };
    let records = &records[..emitted];

    let stdout = io::stdout();
    let mut out: Box<dyn Write> = match args.output.as_deref() {
        None | Some("-") => Box::new(BufWriter::new(stdout.lock())),
        Some(path) => Box::new(BufWriter::new(
            File::create(path).map_err(|e| format!("创建输出文件 `{path}` 失败：{e}"))?,
        )),
    };
    write_jsonl(&mut out, records).map_err(|e| format!("写输出失败：{e}"))?;
    out.flush().map_err(|e| format!("刷输出失败：{e}"))?;

    // ---- IPFIX 导出（可选）----
    // 顺序说明：先落 JSONL 再导出。导出的记录集与 JSONL **同源同序**（都取自
    // `records[..emitted]`），这样 `--ipfix-pcap` 的产物能与 JSONL 逐条对照——
    // 校验脚本（scripts/verify/check-ipfix-export.sh）正是靠这个对应关系，让
    // tshark 独立解出的字段与我们的记录逐项相比。
    if let Some(ix) = &args.ipfix {
        let cfg = traffic_engine::export::ExportConfig {
            domain_id: ix.domain,
            template_refresh_msgs: ix.template_refresh,
            max_msg_bytes: ix.max_msg_bytes,
            ..Default::default()
        };
        let mut enc = traffic_engine::export::Encoder::new(cfg)
            .map_err(|e| format!("IPFIX 配置无效：{e}"))?;
        let udp = match &ix.udp {
            Some(addr) => Some(
                traffic_engine::export::sink::UdpSink::connect(addr)
                    .map_err(|e| format!("打开 IPFIX UDP 目标 `{addr}` 失败：{e}"))?,
            ),
            None => None,
        };
        let pcap = match &ix.pcap {
            Some(path) => Some(
                traffic_engine::export::sink::PcapSink::create(path)
                    .map_err(|e| format!("创建 IPFIX pcap `{path}` 失败：{e}"))?,
            ),
            None => None,
        };
        let mut sinks = traffic_engine::export::sink::Sinks::new(udp, pcap);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0) as u32;
        let msgs = enc
            .encode_batch(&records[..emitted], now)
            .map_err(|e| format!("IPFIX 编码失败：{e}"))?;
        for m in &msgs {
            // 微秒位固定 0：亚秒精度由采集侧的到达时间决定，这里不编造。
            sinks.emit(m, now, 0);
        }
        sinks.finish();
        let st = sinks.stats();
        if !args.quiet {
            let e = io::stderr();
            let mut err = e.lock();
            let _ = writeln!(
                err,
                // records 与 seq_next 数值相同（导出结束时序列号正好等于总记录数），
                // 但语义不同：前者是"导出了多少条"，后者是"下一条报文的序列号"。
                // 采集侧用后者定位丢包，所以两个名字都留着，别合并。
                "[cythsec-analyze] ipfix domain={} messages={} records={} seq_next={} datagrams={} bytes={} errors={} udp={} pcap={}",
                ix.domain,
                msgs.len(),
                enc.sequence_number(),
                enc.sequence_number(),
                st.datagrams,
                st.bytes,
                st.errors,
                ix.udp.as_deref().unwrap_or("-"),
                ix.pcap.as_deref().unwrap_or("-")
            );
            if let Some(e) = &st.last_error {
                let _ = writeln!(err, "[cythsec-analyze] ipfix last_error: {e}");
            }
        }
        // 导出一条都没出去＝分母没了却报成功，这是最坏的"看起来正常"，必须失败退出。
        let st = sinks.stats();
        if st.datagrams == 0 && st.errors > 0 {
            return Err(format!(
                "IPFIX 导出全部失败（{} 次）：{}",
                st.errors,
                st.last_error.as_deref().unwrap_or("未知原因")
            ));
        }
    }

    if !args.quiet {
        report(&stats, &args.input, args.strict, emitted);
    }
    Ok(emitted)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&argv) {
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Parsed::Version) => {
            let info = build_info();
            println!("cythsec-analyze version={}", info.version);
            println!("cythsec-analyze commit={}", info.commit);
            println!("cythsec-analyze build_time={}", info.build_time);
            ExitCode::SUCCESS
        }
        Ok(Parsed::Run(args)) => match run(&args) {
            Ok(_) => ExitCode::SUCCESS,
            Err(msg) => {
                eprintln!("[cythsec-analyze] 错误: {msg}");
                ExitCode::FAILURE
            }
        },
        Err(msg) => {
            eprintln!("[cythsec-analyze] 错误: {msg}");
            eprint!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn run_args(args: &[&str]) -> Args {
        match parse_args(&v(args)).expect("应能解析") {
            Parsed::Run(a) => *a,
            _ => panic!("应为 Run"),
        }
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert!(matches!(parse_args(&v(&["--help"])), Ok(Parsed::Help)));
        assert!(matches!(parse_args(&v(&["-h"])), Ok(Parsed::Help)));
        assert!(matches!(parse_args(&v(&["-V"])), Ok(Parsed::Version)));
        // --help 优先于其它参数：缺 -r 时也应给帮助，而不是先甩一个"缺少必填参数"。
        assert!(matches!(
            parse_args(&v(&["--limit", "3", "-h"])),
            Ok(Parsed::Help)
        ));
    }

    #[test]
    fn read_is_required() {
        let err = parse_args(&v(&["--limit", "1"])).unwrap_err();
        assert!(err.contains("-r"), "{err}");
    }

    #[test]
    fn both_option_styles_are_accepted() {
        let a = run_args(&["-r", "a.pcap", "--limit", "5", "--inspect-bytes", "64"]);
        assert_eq!(a.input, "a.pcap");
        assert_eq!(a.limit, Some(5));
        assert_eq!(a.inspect_bytes, 64);

        let b = run_args(&["--read=b.pcap", "--limit=7"]);
        assert_eq!(b.input, "b.pcap");
        assert_eq!(b.limit, Some(7));
        // 默认容忍模式：离线抓包起点总在会话中间；默认输出到 stdout、不裁记录数。
        assert!(!b.strict);
        assert_eq!(b.output, None);
    }

    #[test]
    fn output_dash_means_stdout() {
        let a = run_args(&["-r", "a.pcap", "-o", "-"]);
        assert_eq!(a.output.as_deref(), Some("-"));
    }

    #[test]
    fn bad_numbers_are_rejected_with_the_offending_value() {
        let err = parse_args(&v(&["-r", "a.pcap", "--limit", "many"])).unwrap_err();
        assert!(err.contains("many"), "{err}");
        let err2 = parse_args(&v(&["-r", "a.pcap", "--max-sessions", "0"])).unwrap_err();
        assert!(err2.contains("大于 0"), "{err2}");
        let err3 = parse_args(&v(&["-r"])).unwrap_err();
        assert!(err3.contains("缺少取值"), "{err3}");
    }

    #[test]
    fn unknown_flag_is_not_silently_ignored() {
        let err = parse_args(&v(&["-r", "a.pcap", "--wat"])).unwrap_err();
        assert!(err.contains("--wat"), "{err}");
    }
}
