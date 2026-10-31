// bin/arp_collect.rs —— Ethernet ARP/RARP 事件采集器（RFC 826 / RFC 903）。
//
// 与 sFlow/NetFlow 采集器不同，ARP 没有 IP 五元组，也不属于 `FlowRecord`；
// 这里输出的是**帧级事件**。采集器只读 Pcap，不主动发 ARP、不修改邻居表、
// 不根据 reply 推断主机在线或地址归属。
//
// Pcap 只接受以太网链路（LINKTYPE_ETHERNET）。Linux cooked capture / raw IP /
// pcapng 不做猜测：转换方式由调用方决定。

use std::io::{self, BufReader, BufWriter, Write};
use std::process::ExitCode;

use traffic_engine::arp::{self, ArpStats};
use traffic_engine::pcapfile::{PcapReader, LINKTYPE_ETHERNET};

const USAGE: &str = "\
cythsec-arp —— 以太网 ARP/RARP 有界事件采集器（RFC 826 / RFC 903）

用法:
  cythsec-arp --pcap <file.pcap> [选项]

选项:
  -o, --output <file>   输出 JSONL（默认 stdout，`-` 表示 stdout）
  -q, --quiet           不打印统计行
  -h, --help            显示本帮助

输出（stderr，一行）:
  [cythsec-arp] arp arp_frames=… requests=… replies=… rarp_requests=…
                rarp_replies=… other_operations=… probes=… gratuitous=…
                vlan_tagged=… unknown_hardware=… unknown_protocol=…
                malformed=… truncated=… non_arp=… capture_truncated=… frames=…

退出码:
  0  正常（包括 pcap 里没有 ARP 的情况；统计行会明确报 arp_frames=0）
  1  参数、pcap 或 I/O 错误
";

#[derive(Debug, Default)]
struct Args {
    pcap: Option<String>,
    output: Option<String>,
    quiet: bool,
    help: bool,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
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
            "-o" | "--output" => a.output = Some(take("--output")?),
            "-q" | "--quiet" => a.quiet = true,
            other => return Err(format!("未知参数：{other}")),
        }
        i += 1;
    }
    if a.pcap.is_none() {
        return Err("必须指定 --pcap".to_string());
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

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("采集失败：{e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let path = args.pcap.as_deref().unwrap_or_default();
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

    let mut out: Box<dyn Write> = match args.output.as_deref() {
        None | Some("-") => Box::new(BufWriter::new(io::stdout())),
        Some(p) => Box::new(BufWriter::new(
            std::fs::File::create(p).map_err(|e| format!("创建 {p}: {e}"))?,
        )),
    };

    let mut stats = ArpStats::default();
    let mut frames = 0u64;
    while let Some(rec) = reader
        .next_record()
        .map_err(|e| format!("读 pcap 记录: {e}"))?
    {
        frames += 1;
        match arp::parse_ethernet(&rec.data) {
            Ok(mut f) => {
                f.capture_truncated = rec.is_truncated();
                stats.observe(&f);
                writeln!(
                    out,
                    "{}",
                    f.to_json_line(rec.timestamp_us, frames, rec.orig_len as usize)
                )
                .map_err(|e| format!("写输出: {e}"))?;
            }
            Err(e) => stats.record_error(e),
        }
    }
    out.flush().map_err(|e| format!("刷输出: {e}"))?;

    if !args.quiet {
        eprintln!("[cythsec-arp] {} frames={frames}", stats.render_line());
    }
    Ok(())
}
