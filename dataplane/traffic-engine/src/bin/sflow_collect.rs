// bin/sflow_collect.rs —— sFlow v5 采集器 CLI（RFC 3176）。
//
// 与 NetFlow v9/IPFIX 采集器的差别：sFlow 没有模板，sample/record 自带长度；
// 序号是**数据报**序号，所以这里报 `lost_datagrams`，不是丢记录数。
//
// 输出分两路：
//   - flow sample -> `--output`（默认 stdout），一行一个采样包；
//   - counter sample -> `--counters`（可选），一行一个计数器 record。
// 两路都输出到 stdout 会互相穿插，故显式禁止。

use std::io::{self, BufReader, BufWriter, Write};
use std::net::{IpAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use traffic_engine::channel::{decode_frame, l4_payload, Proto};
use traffic_engine::ipfix::collector::ExporterId;
use traffic_engine::pcapfile::{PcapReader, LINKTYPE_ETHERNET};
use traffic_engine::sflow::{
    SflowCollector, SflowConfig, SflowOutcome, DEFAULT_DEDUP_WINDOW, SFLOW_PORT,
};

const USAGE: &str = "\
cythsec-sflow-collect —— sFlow v5 采集器（RFC 3176）：解 flow/counter sample，报**数据报**丢包

用法:
  cythsec-sflow-collect --pcap <file.pcap> [选项]   # 离线：从落盘的 sFlow 报文里收
  cythsec-sflow-collect --udp <bind addr> [选项]     # 在线：真收 UDP（如 0.0.0.0:6343）

选项:
  -o, --output <file>        flow sample 写成 JSONL（默认 stdout，`-` 表示 stdout）
      --counters <file>      counter sample 写成 JSONL（默认不写；`-` 表示 stdout）
      --duration <sec>       在线模式最多收多少秒（默认 0 = 收到信号为止）
      --dedup-window <n>     去重窗口（sample 条数，默认 4096；0 = 不去重）
      --any-port             pcap 模式不按端口 6343 过滤
  -q, --quiet                不打印统计行
  -h, --help                 显示本帮助

输出（stderr，一行）:
  [cythsec-sflow-collect] datagrams=… bytes=… agents=… sequence_tracked=… samples=…
                          flow_samples=… counter_samples=… flow_records=… counter_records=…
                          delivered_flows=… delivered_counters=… duplicates=… gaps=…
                          lost_datagrams=… loss_ppm=… out_of_order=… duplicate_datagrams=…
                          malformed=… version_mismatch=… unknown_sample_types=…
                          unknown_flow_records=… unknown_counter_records=… missing_key=…
                          conflicts=… truncations=… nonzero_padding=… trailing_bytes=…

  `loss_ppm` 的分母是「实收 v5 数据报 + 推定丢失数据报」，不是 sample/record 数。

退出码:
  0  正常
  1  参数或 I/O 错误
  2  收到了数据报，但一个 flow/counter record 都没解出来
";

#[derive(Debug, Default)]
struct Args {
    pcap: Option<String>,
    udp: Option<String>,
    output: Option<String>,
    counters: Option<String>,
    duration_s: u64,
    dedup_window: usize,
    any_port: bool,
    quiet: bool,
    help: bool,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        dedup_window: DEFAULT_DEDUP_WINDOW,
        ..Default::default()
    };
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        let mut take = |what: &str| -> Result<String, String> {
            i += 1;
            argv.get(i)
                .cloned()
                .ok_or_else(|| format!("{what} 缺少参数值"))
        };
        match arg {
            "-h" | "--help" => a.help = true,
            "--pcap" => a.pcap = Some(take("--pcap")?),
            "--udp" => a.udp = Some(take("--udp")?),
            "-o" | "--output" => a.output = Some(take("--output")?),
            "--counters" => a.counters = Some(take("--counters")?),
            "--duration" => {
                a.duration_s = take("--duration")?
                    .parse()
                    .map_err(|e| format!("--duration: {e}"))?
            }
            "--dedup-window" => {
                a.dedup_window = take("--dedup-window")?
                    .parse()
                    .map_err(|e| format!("--dedup-window: {e}"))?
            }
            "--any-port" => a.any_port = true,
            "-q" | "--quiet" => a.quiet = true,
            other => return Err(format!("未知参数：{other}")),
        }
        i += 1;
    }
    match (&a.pcap, &a.udp) {
        (Some(_), Some(_)) => return Err("--pcap 与 --udp 只能选一个".to_string()),
        (None, None) => return Err("必须指定 --pcap 或 --udp".to_string()),
        _ => {}
    }
    let stdout_flows = a.output.as_deref().is_none_or(|p| p == "-");
    let stdout_counters = a.counters.as_deref() == Some("-");
    if stdout_flows && stdout_counters {
        return Err("flow 与 counter 不能同时写 stdout；请用 --counters <file>".to_string());
    }
    Ok(a)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("参数错误：{e}\n\n{USAGE}");
            return ExitCode::from(1);
        }
    };
    if args.help {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let cfg = SflowConfig {
        dedup_window: args.dedup_window,
        ..Default::default()
    };
    let mut collector = SflowCollector::new(cfg);
    let run = if let Some(path) = &args.pcap {
        collect_from_pcap(&mut collector, path, args.any_port)
    } else {
        collect_from_udp(
            &mut collector,
            args.udp.as_deref().unwrap_or_default(),
            Duration::from_secs(args.duration_s),
        )
    };
    if let Err(e) = run {
        eprintln!("采集失败：{e}");
        return ExitCode::from(1);
    }

    let flows = collector.take_flows();
    let counters = collector.take_counters();
    if let Err(e) = write_flows(&args.output, &flows) {
        eprintln!("写 flow 输出失败：{e}");
        return ExitCode::from(1);
    }
    if let Some(path) = &args.counters {
        if let Err(e) = write_counters(path, &counters) {
            eprintln!("写 counter 输出失败：{e}");
            return ExitCode::from(1);
        }
    } else if !counters.is_empty() {
        eprintln!(
            "警告：解出 {} 条 counter record，但未指定 --counters；只统计、未写出",
            counters.len()
        );
    }

    let st = collector.stats();
    if !args.quiet {
        let uf: Vec<String> = st
            .unknown_flow_record_types
            .iter()
            .map(|v| v.to_string())
            .collect();
        let uc: Vec<String> = st
            .unknown_counter_record_types
            .iter()
            .map(|v| v.to_string())
            .collect();
        eprintln!(
            "[cythsec-sflow-collect] datagrams={} bytes={} agents={} sequence_tracked={} \
             samples={} flow_samples={} expanded_flow_samples={} counter_samples={} \
             expanded_counter_samples={} flow_records={} counter_records={} \
             delivered_flows={} delivered_counters={} duplicate_samples={} gaps={} lost_datagrams={} \
             loss_ppm={} out_of_order={} duplicate_datagrams={} malformed={} version_mismatch={} \
             unknown_sample_types={} unknown_flow_records={} unknown_counter_records={} \
             missing_key={} conflicts={} truncations={} nonzero_padding={} trailing_bytes={}",
            st.datagrams,
            st.bytes,
            st.agents,
            st.sequence_tracked,
            st.samples,
            st.flow_samples,
            st.expanded_flow_samples,
            st.counter_samples,
            st.expanded_counter_samples,
            st.flow_records,
            st.counter_records,
            st.delivered_flows,
            st.delivered_counters,
            st.duplicate_samples,
            st.sequence_gaps,
            st.datagrams_lost,
            st.loss_ppm(),
            st.out_of_order,
            st.duplicate_datagrams,
            st.malformed_datagrams,
            st.version_mismatch,
            st.unknown_sample_types,
            if uf.is_empty() {
                "-".to_string()
            } else {
                uf.join(",")
            },
            if uc.is_empty() {
                "-".to_string()
            } else {
                uc.join(",")
            },
            st.flow_records_missing_key,
            st.flow_record_conflicts,
            st.record_truncations,
            st.nonzero_padding,
            st.trailing_bytes,
        );
    }
    if st.datagrams > 0 && st.delivered_records() == 0 {
        eprintln!(
            "采集未产出任何 flow/counter record（datagrams={} malformed={} version_mismatch={} \
             unknown_sample_types={}）",
            st.datagrams, st.malformed_datagrams, st.version_mismatch, st.unknown_sample_types
        );
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn write_flows(
    path: &Option<String>,
    flows: &[traffic_engine::sflow::SflowFlow],
) -> io::Result<usize> {
    write_lines(path, flows.iter().map(|f| f.to_json_line()))
}

fn write_counters(
    path: &str,
    counters: &[traffic_engine::sflow::SflowCounter],
) -> io::Result<usize> {
    write_lines(
        &Some(path.to_string()),
        counters.iter().map(|c| c.to_json_line()),
    )
}

fn write_lines(path: &Option<String>, lines: impl Iterator<Item = String>) -> io::Result<usize> {
    match path.as_deref() {
        None | Some("-") => {
            let mut out = BufWriter::new(io::stdout().lock());
            let n = write_all_lines(&mut out, lines)?;
            out.flush()?;
            Ok(n)
        }
        Some(p) => {
            let mut out = BufWriter::new(std::fs::File::create(p)?);
            let n = write_all_lines(&mut out, lines)?;
            out.flush()?;
            Ok(n)
        }
    }
}

fn write_all_lines<W: Write>(
    out: &mut W,
    lines: impl Iterator<Item = String>,
) -> io::Result<usize> {
    let mut n = 0usize;
    for line in lines {
        out.write_all(line.as_bytes())?;
        out.write_all(b"\n")?;
        n += 1;
    }
    Ok(n)
}

fn collect_from_pcap(
    collector: &mut SflowCollector,
    path: &str,
    any_port: bool,
) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("打开 {path}: {e}"))?;
    let mut reader =
        PcapReader::new(BufReader::new(file)).map_err(|e| format!("读 pcap 头: {e}"))?;
    if reader.linktype() != LINKTYPE_ETHERNET {
        return Err(format!(
            "只支持以太网链路的 pcap（当前 linktype={} {}）",
            reader.linktype(),
            reader.header().linktype_name()
        ));
    }
    while let Some(rec) = reader
        .next_record()
        .map_err(|e| format!("读 pcap 记录: {e}"))?
    {
        let ts_ms = rec.timestamp_us / 1000;
        let Ok(d) = decode_frame(&rec.data) else {
            continue;
        };
        if d.l4 != Proto::Udp {
            continue;
        }
        let Some(payload) = l4_payload(&rec.data, &d) else {
            continue;
        };
        let (src_port, dst_port) = (d.key.src_port, d.key.dst_port);
        if !any_port && src_port != SFLOW_PORT && dst_port != SFLOW_PORT {
            continue;
        }
        let exporter = ExporterId {
            ip: d.key.src_ip,
            port: src_port,
        };
        collector.on_datagram(exporter, payload.bytes, ts_ms);
    }
    Ok(())
}

fn collect_from_udp(
    collector: &mut SflowCollector,
    bind: &str,
    duration: Duration,
) -> Result<(), String> {
    let sock = UdpSocket::bind(bind).map_err(|e| format!("绑定 {bind}: {e}"))?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    eprintln!(
        "[cythsec-sflow-collect] 注意：本版不设置 SO_RCVBUF（std 无接口、仓库不引第三方依赖）；\n\
         \x20 高突发下内核丢弃会体现为序号缺口，会污染 loss_ppm 口径"
    );
    eprintln!("[cythsec-sflow-collect] 监听 {bind}");
    let deadline = if duration.is_zero() {
        None
    } else {
        Some(Instant::now() + duration)
    };
    let mut buf = vec![0u8; 65535];
    loop {
        if let Some(d) = deadline {
            if Instant::now() >= d {
                break;
            }
        }
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let exporter = ExporterId {
                    ip: normalize_ip(src.ip()),
                    port: src.port(),
                };
                match collector.on_datagram(exporter, &buf[..n], now_ms) {
                    SflowOutcome::Accepted { lost_datagrams, .. } if lost_datagrams > 0 => {
                        eprintln!(
                            "[cythsec-sflow-collect] 警告：{exporter} 序号缺口，丢失 {lost_datagrams} 个数据报"
                        );
                    }
                    SflowOutcome::VersionMismatch { got } => {
                        eprintln!(
                            "[cythsec-sflow-collect] 警告：{exporter} 版本 {got} ≠ 5，已忽略"
                        );
                    }
                    _ => {}
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) => return Err(format!("收包失败：{e}")),
        }
    }
    Ok(())
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}
