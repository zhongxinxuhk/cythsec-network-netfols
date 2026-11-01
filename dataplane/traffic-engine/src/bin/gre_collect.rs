// bin/gre_collect.rs —— GRE / PPTP GRE 有界事件采集器（RFC 2784 / RFC 2890 / RFC 2637）。
//
// 输出的是**报文级 JSONL**：外层五元组、GRE 版本、可选头字段、内层协议头。
// 采集器只读 Pcap，不发探测、不修改隧道配置、不根据单个包推断隧道对端在线。
//
// Pcap 只接受以太网链路（LINKTYPE_ETHERNET）。

use std::io::{self, BufReader, BufWriter, Write};
use std::process::ExitCode;

use traffic_engine::channel::decode_frame;
use traffic_engine::gre::{self, GreStats};
use traffic_engine::pcapfile::{PcapReader, LINKTYPE_ETHERNET};

const USAGE: &str = "\
cythsec-gre —— GRE/PPTP GRE 有界事件采集器（RFC 2784 / RFC 2890 / RFC 2637）

用法:
  cythsec-gre --pcap <file.pcap> [选项]

选项:
  -o, --output <file>   输出 JSONL（默认 stdout，`-` 表示 stdout）
  -q, --quiet           不打印统计行
  -h, --help            显示本帮助

输出（stderr，一行）:
  [cythsec-gre] gre gre_frames=… version0=… version1=… keyed=… unkeyed=…
                protocol_ipv4=… protocol_ipv6=… inner_complete=… malformed=…
                frames=… non_gre=… decode_errors=…

退出码:
  0  正常（包括 pcap 里没有 GRE 的情况；统计行会明确报 gre_frames=0）
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

    let mut stats = GreStats::default();
    let mut frames = 0u64;
    let mut non_gre = 0u64;
    let mut decode_errors = 0u64;
    while let Some(rec) = reader
        .next_record()
        .map_err(|e| format!("读 pcap 记录: {e}"))?
    {
        frames += 1;
        let d = match decode_frame(&rec.data) {
            Ok(d) => d,
            Err(_) => {
                decode_errors += 1;
                continue;
            }
        };
        if d.key.proto.number() != gre::IPPROTO_GRE {
            non_gre += 1;
            continue;
        }
        let want = d.ip_payload_len as usize;
        let available = rec.data.get(d.l4_offset..).unwrap_or(&[]);
        let payload = &available[..available.len().min(want)];
        match gre::parse(payload) {
            Ok(mut f) => {
                f.capture_truncated = rec.is_truncated() || payload.len() < want;
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
        eprintln!(
            "[cythsec-gre] {} frames={frames} non_gre={non_gre} decode_errors={decode_errors}",
            stats.render_line()
        );
    }
    Ok(())
}
