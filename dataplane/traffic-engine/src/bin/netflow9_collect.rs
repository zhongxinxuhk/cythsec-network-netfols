// bin/netflow9_collect.rs —— NetFlow v9 采集器 CLI（RFC 3954）。
//
// 与 `cythsec-ipfix-collect` 的差别只有一个，但必须说清：
// v9 的 sequence 是**导出报文序号**，不是"此前已发送的数据记录数"。因此这里报的是
// `lost_export_packets` 与**报文级**丢包率；把它叫成记录级丢包率会凭空放大数字。
//
// 输入与 IPFIX 采集器一致：`--pcap` 离线复跑（时间取抓包时间戳，结果可复现），
// `--udp` 在线联调。pcap 模式默认按端口 2055 过滤，`--any-port` 可关闭。

use std::io::{self, BufReader, BufWriter, Write};
use std::net::{IpAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use traffic_engine::channel::{decode_frame, l4_payload, Proto};
use traffic_engine::ipfix::collector::{ExporterId, DEFAULT_DEDUP_WINDOW};
use traffic_engine::netflow9::{Netflow9Collector, Netflow9Config, Netflow9Outcome, NETFLOW9_PORT};
use traffic_engine::pcapfile::{PcapReader, LINKTYPE_ETHERNET};
use traffic_engine::record::write_jsonl;

const USAGE: &str = "\
cythsec-netflow9-collect —— NetFlow v9 采集器（RFC 3954）：解模板/数据流集，报出**导出报文**丢包

用法:
  cythsec-netflow9-collect --pcap <file.pcap> [选项]   # 离线：从落盘的 v9 报文里收
  cythsec-netflow9-collect --udp <bind addr> [选项]     # 在线：真收 UDP（如 0.0.0.0:2055）

选项:
  -o, --output <file>        还原出的记录写成 JSONL（默认 stdout，`-` 表示 stdout）
      --duration <sec>       在线模式最多收多少秒（默认 0 = 收到信号为止）
      --template-timeout <sec>
                             模板生存期；缺省按观测到的重传间隔 × 3（未观测到用 600 秒）
      --dedup-window <n>     去重窗口（条数，默认 4096；0 = 不去重）
      --any-port             pcap 模式不按端口 2055 过滤
  -q, --quiet                不打印统计行
  -h, --help                 显示本帮助

输出（stderr，一行）:
  [cythsec-netflow9-collect] datagrams=… bytes=… export_packets=… exporters=… records=…
                             delivered=… duplicates=… gaps=… lost_export_packets=… loss_ppm=…
                             out_of_order=… duplicate_datagrams=… templates=… expired=…
                             no_template_sets=… malformed=… version_mismatch=… unknown_field_types=…
                             templates_refreshed=… template_conflicts=… options_template_records=…
                             options_data_sets_skipped=… count_mismatches=…
                             records_missing_key=… nonzero_padding=…

  `loss_ppm` 的分母是「实收 v9 报文 + 推定丢失报文」，不是数据记录数。

退出码:
  0  正常
  1  参数或 I/O 错误
  2  收到了报文但一个数据记录都没解出来（模板未到 / 版本不符 / 全畸形）
";

#[derive(Debug, Default)]
struct Args {
    pcap: Option<String>,
    udp: Option<String>,
    output: Option<String>,
    duration_s: u64,
    template_timeout_s: Option<u64>,
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
            "--duration" => {
                a.duration_s = take("--duration")?
                    .parse()
                    .map_err(|e| format!("--duration: {e}"))?
            }
            "--template-timeout" => {
                a.template_timeout_s = Some(
                    take("--template-timeout")?
                        .parse()
                        .map_err(|e| format!("--template-timeout: {e}"))?,
                )
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
    if a.template_timeout_s == Some(0) {
        return Err("--template-timeout 0 会让模板立刻过期；请给正秒数".to_string());
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

    let cfg = Netflow9Config {
        template_lifetime_ms: args.template_timeout_s.map(|s| s.saturating_mul(1000)),
        dedup_window: args.dedup_window,
        ..Default::default()
    };
    let mut collector = Netflow9Collector::new(cfg);
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
    let records: Vec<_> = flows.iter().map(|f| f.to_flow_record()).collect();
    match write_records(&args.output, &records) {
        Ok(n) => {
            if !args.quiet {
                eprintln!("[cythsec-netflow9-collect] 写出 {n} 条记录");
            }
        }
        Err(e) => {
            eprintln!("写输出失败：{e}");
            return ExitCode::from(1);
        }
    }
    let st = collector.stats();
    if !args.quiet {
        let types: Vec<String> = st
            .unknown_field_types
            .iter()
            .map(|c| c.to_string())
            .collect();
        eprintln!(
            "[cythsec-netflow9-collect] datagrams={} bytes={} export_packets={} exporters={} \
             records={} delivered={} duplicates={} gaps={} lost_export_packets={} loss_ppm={} \
             out_of_order={} duplicate_datagrams={} templates={} expired={} no_template_sets={} \
             malformed={} version_mismatch={} unknown_field_types={} templates_refreshed={} \
             template_conflicts={} options_template_records={} options_data_sets_skipped={} \
             count_mismatches={} records_missing_key={} nonzero_padding={}",
            st.datagrams,
            st.bytes,
            st.export_packets,
            st.exporters,
            st.data_records,
            st.delivered_records,
            st.duplicate_records,
            st.sequence_gaps,
            st.export_packets_lost,
            st.loss_ppm(),
            st.out_of_order,
            st.duplicate_datagrams,
            st.templates_received,
            st.templates_expired,
            st.sets_without_template,
            st.malformed_datagrams,
            st.version_mismatch,
            if types.is_empty() {
                "-".to_string()
            } else {
                types.join(",")
            },
            st.template_refresh,
            st.template_conflicts,
            st.options_template_records,
            st.options_data_sets_skipped,
            st.count_mismatches,
            st.records_missing_key,
            st.nonzero_padding,
        );
    }
    if st.datagrams > 0 && st.data_records == 0 {
        eprintln!(
            "采集未产出任何数据记录（datagrams={} malformed={} version_mismatch={} no_template_sets={}）",
            st.datagrams, st.malformed_datagrams, st.version_mismatch, st.sets_without_template
        );
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn write_records(
    path: &Option<String>,
    records: &[traffic_engine::record::FlowRecord],
) -> io::Result<usize> {
    match path.as_deref() {
        None | Some("-") => {
            let mut out = BufWriter::new(io::stdout().lock());
            let n = write_jsonl(&mut out, records)?;
            out.flush()?;
            Ok(n)
        }
        Some(p) => {
            let mut out = BufWriter::new(std::fs::File::create(p)?);
            let n = write_jsonl(&mut out, records)?;
            out.flush()?;
            Ok(n)
        }
    }
}

fn collect_from_pcap(
    collector: &mut Netflow9Collector,
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
        if !any_port && src_port != NETFLOW9_PORT && dst_port != NETFLOW9_PORT {
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
    collector: &mut Netflow9Collector,
    bind: &str,
    duration: Duration,
) -> Result<(), String> {
    let sock = UdpSocket::bind(bind).map_err(|e| format!("绑定 {bind}: {e}"))?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    eprintln!(
        "[cythsec-netflow9-collect] 注意：本版不设置 SO_RCVBUF（std 无接口、仓库不引第三方依赖）；\n\
         \x20 高突发下内核丢弃会体现为序号缺口，会污染 loss_ppm 口径"
    );
    eprintln!("[cythsec-netflow9-collect] 监听 {bind}");
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
                    Netflow9Outcome::Accepted {
                        lost_export_packets,
                        ..
                    } if lost_export_packets > 0 => {
                        eprintln!(
                            "[cythsec-netflow9-collect] 警告：{exporter} 序号缺口，丢失 {lost_export_packets} 个导出报文"
                        );
                    }
                    Netflow9Outcome::VersionMismatch { got } => {
                        eprintln!(
                            "[cythsec-netflow9-collect] 警告：{exporter} 版本 {got} ≠ 9，已忽略"
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
