// bin/ipfix_collect.rs —— IPFIX 采集器 CLI（M11 / CYS-TRF-054）。
//
// ## 这个程序回答什么问题
//
// 导出侧（`cythsec-analyze --ipfix-*`）只能证明"我发了 N 条"。运营商口径要的是
// **"对端到底收到多少、丢了多少"** —— 只有采集侧能算：RFC 7011 §3.1 的序列号
// 是"本报文之前已发送的数据记录累计数"，于是缺口就是导出链路上丢掉的记录条数
// （§11.6 要求采集进程必须靠跟踪序号发现丢包）。
//
// ## 两种输入，同一套语义
//
// - `--pcap <file>`：从**落盘的 UDP 载荷**里收（可离线复跑、可反向注入丢包），
//   时间取抓包时间戳 —— 因此同一段 pcap 重放两次结果**逐位相同**。
// - `--udp <addr>`：真收 UDP（现场联调用）。时间取系统时钟。
//
// 两者都只处理落在一个 IPFIX 报文里的载荷；pcap 模式下按端口 4739 过滤
// （`--any-port` 可关掉，用于联调非常规端口）。
//
// ## 诚实边界（写在这里，免得报告里被抹平）
//
// - **首报文之前丢的东西不可知**：没有基线就没有缺口。这是"采集覆盖率"要单独说的原因。
// - **UDP 无法保证送达**：`lost_records` 是"按序列号推出来的缺失条数"，
//   它同时包含网络丢包、采集器丢弃（队列溢出）、以及导出侧自己丢的记录
//   （RFC 7011 §10.2.2 要求导出侧在丢记录时必须让序列号体现出来）。
//   把它当成"网络丢包率"是不准确的；它是**导出丢包率**（export loss）。

use std::io::{self, BufReader, BufWriter, Write};
use std::net::{IpAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use traffic_engine::channel::{decode_frame, l4_payload, Proto};
use traffic_engine::ipfix::collector::{
    Collector, CollectorConfig, DatagramOutcome, ExporterId, DEFAULT_DEDUP_WINDOW,
};
use traffic_engine::ipfix::IPFIX_PORT;
use traffic_engine::pcapfile::{PcapReader, LINKTYPE_ETHERNET};
use traffic_engine::record::write_jsonl;

const USAGE: &str = "\
cythsec-ipfix-collect —— IPFIX 采集器（RFC 7011）：解模板/数据集，按序列号缺口报出**导出丢包率**

用法:
  cythsec-ipfix-collect --pcap <file.pcap> [选项]      # 离线：从落盘的 IPFIX 报文里收
  cythsec-ipfix-collect --udp <bind addr> [选项]        # 在线：真收 UDP（如 0.0.0.0:4739）

选项:
  -o, --output <file>        还原出的记录写成 JSONL（默认 stdout，`-` 表示 stdout）
      --duration <sec>       在线模式最多收多少秒（默认 0 = 收到信号为止）
      --template-timeout <sec>
                             模板生存期；缺省按 RFC 7011 §8.4 用「观测到的重传间隔 × 3」
                             （尚未观测到时用 600 秒）。未刷新的模板到期即丢弃。
      --dedup-window <n>     去重窗口（条数，默认 4096；0 = 不去重）
      --any-port             pcap 模式不按端口 4739 过滤（联调非常规端口用）
  -q, --quiet                不打印统计行
  -h, --help                 显示本帮助

输出（stderr，一行）:
  [cythsec-ipfix-collect] datagrams=… bytes=… exporters=… records=… delivered=… duplicates=…
                          gaps=… lost_records=… loss_ppm=… out_of_order=… templates=… expired=…
                          no_template_sets=… malformed=… version_mismatch=… unknown_ies=…
                          templates_refreshed=… template_conflicts=… withdrawals_ignored=…
                          options_template_sets=… nonzero_padding=… records_missing_key=…

  后 6 项是**联调时最先要看的东西**：`template_conflicts`（同号不同定义：异厂导出器改过模板
  而我们保留了旧的）、`withdrawals_ignored`（对端在 UDP 上发模板撤回，按 §8.4 必须忽略）、
  `nonzero_padding`（非零填充 ≈ 记录长度算错的强信号）、`records_missing_key`（解出了记录但
  没有五元组 —— 会把「没采到」伪装成「这条流没有关键字段」）。

退出码:
  0  正常
  1  参数或 I/O 错误
  2  收到了报文但**一个都没解出来**（模板从未到达 / 版本不符 / 全是畸形）
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
    // 输入源必须**恰好一个**：两个都给会让人以为两条路都跑了（实际只会跑一条），
    // 一个都不给则无从收包。这类"看起来像配置成功"的歧义必须当场拒绝。
    match (&a.pcap, &a.udp) {
        (Some(_), Some(_)) => return Err("--pcap 与 --udp 只能选一个".to_string()),
        (None, None) => return Err("必须指定 --pcap 或 --udp".to_string()),
        _ => {}
    }
    if a.template_timeout_s == Some(0) {
        return Err(
            "--template-timeout 0 会让模板立刻过期，等于收不到数据；请给正秒数".to_string(),
        );
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

    let cfg = CollectorConfig {
        template_lifetime_ms: args.template_timeout_s.map(|s| s.saturating_mul(1000)),
        dedup_window: args.dedup_window,
        ..Default::default()
    };
    let mut collector = Collector::new(cfg);

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

    // ---- 输出：还原出的记录 + 统计 ----
    let flows = collector.take_flows();
    let records: Vec<_> = flows.iter().map(|f| f.to_flow_record()).collect();
    match write_records(&args.output, &records) {
        Ok(n) => {
            if !args.quiet {
                eprintln!("[cythsec-ipfix-collect] 写出 {n} 条记录");
            }
        }
        Err(e) => {
            eprintln!("写输出失败：{e}");
            return ExitCode::from(1);
        }
    }
    let st = collector.stats();
    if !args.quiet {
        let ies: Vec<String> = st.unknown_ies.iter().map(|c| c.to_string()).collect();
        eprintln!(
            "[cythsec-ipfix-collect] datagrams={} bytes={} exporters={} records={} delivered={} \
             duplicates={} gaps={} lost_records={} loss_ppm={} out_of_order={} templates={} \
             expired={} no_template_sets={} malformed={} version_mismatch={} unknown_ies={} \
             templates_refreshed={} template_conflicts={} withdrawals_ignored={} \
             options_template_sets={} nonzero_padding={} records_missing_key={}",
            st.datagrams,
            st.bytes,
            st.exporters,
            st.data_records,
            st.delivered_records,
            st.duplicate_records,
            st.sequence_gaps,
            st.lost_records,
            st.loss_ppm(),
            st.out_of_order,
            st.templates_received,
            st.templates_expired,
            st.sets_without_template,
            st.malformed_datagrams,
            st.version_mismatch,
            if ies.is_empty() {
                "-".to_string()
            } else {
                ies.join(",")
            },
            // 这 6 项是联调/运维真正会用来定位的东西（异厂导出器改模板、发撤回、填充不合法…），
            // 之前没打印：统计结构里有、命令行里看不到 —— 于是"能不能采"只能靠猜。
            // 追加在**末尾**且不动前面字段的顺序：既有门禁里有 `gaps=0 lost_records=0 loss_ppm=0`
            // 这类相邻断言，改顺序会让它们误红。
            st.template_refresh,
            st.template_conflicts,
            st.withdrawals_ignored,
            st.options_template_sets,
            st.nonzero_padding,
            st.records_missing_key,
        );
    }
    // 收到了报文却一条都没解出来 = 采集**实际没在工作**。静默退出 0 会让
    // "采到了"与"什么都没采到"长得一模一样，故用退出码区分。
    if st.datagrams > 0 && st.data_records == 0 {
        eprintln!(
            "采集未产出任何记录（datagrams={} malformed={} version_mismatch={} no_template_sets={}）",
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

/// 离线：把 pcap 里的 UDP 载荷喂给采集器。
///
/// 时间取**抓包时间戳**（不是系统时钟）：同一段 pcap 重放两次必须得到逐位相同的结果，
/// 否则模板生存期与去重窗口这些依赖时间的判定就无法复现，门禁也就无从断言。
fn collect_from_pcap(collector: &mut Collector, path: &str, any_port: bool) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("打开 {path}: {e}"))?;
    let mut reader =
        PcapReader::new(BufReader::new(file)).map_err(|e| format!("读 pcap 头: {e}"))?;
    if reader.linktype() != LINKTYPE_ETHERNET {
        return Err(format!(
            "只支持以太网链路的 pcap（当前 linktype={} {}）；请先用 tshark 转换：\
             tshark -r in.pcap -w out.pcap",
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
        if !any_port && src_port != IPFIX_PORT && dst_port != IPFIX_PORT {
            continue;
        }
        // 导出进程身份 = (源地址, 源端口)：UDP 无连接，用传输会话近似（见 ExporterId 说明）。
        let exporter = ExporterId {
            ip: d.key.src_ip,
            port: src_port,
        };
        collector.on_datagram(exporter, payload.bytes, ts_ms);
    }
    Ok(())
}

/// 在线：真收 UDP。
fn collect_from_udp(
    collector: &mut Collector,
    bind: &str,
    duration: Duration,
) -> Result<(), String> {
    let sock = UdpSocket::bind(bind).map_err(|e| format!("绑定 {bind}: {e}"))?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    // **本版无法放大内核收包缓冲**：`std::net::UdpSocket` 没有 `SO_RCVBUF` 接口，
    // 而本仓不做第三方依赖（socket2 / libc 都不引）。这不是小事，必须当场说清：
    // IPFIX 是突发流量，默认 rmem（Linux 212992 B）在高突发下会溢出，**内核丢的是我们自己的包**，
    // 而这些丢失会以"序列号缺口"的形式出现 —— 即 `loss_ppm` 在高压力下混入了采集侧自身丢弃。
    // 结论：本版 `loss_ppm` 只在**低突发**（单机回环/离线重放）下口径干净；
    // 线速现场必须先按 CYS-PKT-032 那批内核侧工作解决（或换支持 SO_RCVBUF 的实现）。
    eprintln!(
        "[cythsec-ipfix-collect] 注意：本版不设置 SO_RCVBUF（std 无接口、仓库不引第三方依赖）；\n\
         \x20 高突发下内核丢弃会体现为序号缺口，会污染 loss_ppm 口径（见 HANDOFF §6）"
    );
    eprintln!("[cythsec-ipfix-collect] 监听 {bind}");
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
                    DatagramOutcome::Accepted { lost, .. } if lost > 0 => {
                        eprintln!(
                            "[cythsec-ipfix-collect] 警告：{exporter} 序号缺口，丢失 {lost} 条记录"
                        );
                    }
                    DatagramOutcome::VersionMismatch { got } => {
                        eprintln!(
                            "[cythsec-ipfix-collect] 警告：{exporter} 版本 {got} ≠ 10，已忽略"
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

/// IPv4 映射 IPv6 地址（::ffff:a.b.c.d）归一成 IPv4。
///
/// 否则同一台导出进程在双栈监听下会变成两个不同的 `ExporterId`，
/// 序号基线被拆成两份 —— 缺口统计会莫名其妙地少报（甚至全零）。
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}
