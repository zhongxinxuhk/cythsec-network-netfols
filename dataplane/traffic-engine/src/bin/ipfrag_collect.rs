// bin/ipfrag_collect.rs —— IPv4/IPv6 分片事件采集器（B008 / CYS-TRF-018）。
//
// 这个二进制只做“观察”：它按顺序把每一片交给 `IpReassembler`，输出一条帧级
// JSONL；完整数据报另外输出一条 `datagram_complete`。它不主动探测、不修改任何
// 内核分片表，也不把未完成的数据报伪装成已交付。
//
// 为什么还要一个独立事件流：主流水线的统计行只能说明“发生了多少”，无法给出
// 具体是哪个 identification、哪个 offset 缺片/重叠。排障与门禁需要逐片证据。
// 字段名是 scripts/verify/check-ipfrag.py 的契约，改名必须同批改脚本。

use std::io::{self, BufReader, BufWriter, Write};
use std::process::ExitCode;

use traffic_engine::channel::LinkLayer;
use traffic_engine::pcapfile::PcapReader;
use traffic_engine::reassembly::ip::{FragmentSummary, IpFragError, IpReassembler, PushOutcome};

const USAGE: &str = "\
cythsec-ipfrag —— IPv4/IPv6 分片事件采集器（B008）

用法:
  cythsec-ipfrag --pcap <file.pcap> [选项]

选项:
  -o, --output <file>   输出 JSONL（默认 stdout，`-` 表示 stdout）
  -q, --quiet           不打印统计行
  -h, --help            显示本帮助

输出（stderr，一行）:
  [cythsec-ipfrag] ipfrag frags=… v4=… v6=… datagrams=… complete=…
                   incomplete=… malformed=… dup=… overlap=…
                   truncated=… oversize=… evicted=… expired=…
                   bytes=… pending_at_eof=… frames=…

退出码:
  0  正常（包括没有任何分片；统计行会明确报 frags=0）
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
    if a.help {
        return Ok(a);
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
    let link = LinkLayer::from_linktype(reader.linktype()).ok_or_else(|| {
        format!(
            "只支持 Ethernet/Linux SLL/SLL2 链路（当前 linktype={} {}）",
            reader.linktype(),
            reader.header().linktype_name()
        )
    })?;

    let mut out: Box<dyn Write> = match args.output.as_deref() {
        None | Some("-") => Box::new(BufWriter::new(io::stdout())),
        Some(p) => Box::new(BufWriter::new(
            std::fs::File::create(p).map_err(|e| format!("创建 {p}: {e}"))?,
        )),
    };

    let mut reassembler = IpReassembler::default();
    let mut frames = 0u64;
    while let Some(rec) = reader
        .next_record()
        .map_err(|e| format!("读 pcap 记录: {e}"))?
    {
        frames += 1;
        match reassembler.push(
            &rec.data,
            link,
            rec.timestamp_us,
            rec.is_truncated(),
        ) {
            PushOutcome::NotFragment => {}
            PushOutcome::Pending(s) => {
                write_fragment(&mut out, frames, rec.timestamp_us, &s, "pending", None)
                    .map_err(|e| format!("写输出: {e}"))?;
            }
            PushOutcome::Complete(d) => {
                writeln!(
                    out,
                    "{{\"schema_version\":1,\"event\":\"datagram_complete\",\"frame\":{frames},\"timestamp_us\":{},\"version\":\"{}\",\"src\":\"{}\",\"dst\":\"{}\",\"identification\":{},\"fragments\":{},\"payload_bytes\":{},\"frame_bytes\":{},\"outcome\":\"complete\"}}",
                    d.timestamp_us,
                    d.version.as_str(),
                    d.src,
                    d.dst,
                    d.identification,
                    d.fragments,
                    d.payload_bytes,
                    d.frame.len(),
                )
                .map_err(|e| format!("写输出: {e}"))?;
            }
            PushOutcome::Dropped { summary, error } => match summary {
                Some(s) => write_fragment(
                    &mut out,
                    frames,
                    rec.timestamp_us,
                    &s,
                    "dropped",
                    Some(error),
                )
                .map_err(|e| format!("写输出: {e}"))?,
                None => writeln!(
                    out,
                    "{{\"schema_version\":1,\"event\":\"fragment_rejected\",\"frame\":{frames},\"timestamp_us\":{},\"outcome\":\"dropped\",\"error\":\"{}\"}}",
                    rec.timestamp_us,
                    error.code(),
                )
                .map_err(|e| format!("写输出: {e}"))?,
            },
        }
    }
    let _finish = reassembler.finish();
    out.flush().map_err(|e| format!("刷输出: {e}"))?;

    if !args.quiet {
        eprintln!(
            "[cythsec-ipfrag] {} frames={frames}",
            reassembler.stats().render_line()
        );
    }
    Ok(())
}

fn write_fragment<W: Write>(
    out: &mut W,
    frame: u64,
    timestamp_us: u64,
    s: &FragmentSummary,
    outcome: &str,
    error: Option<IpFragError>,
) -> io::Result<()> {
    let err = match error {
        Some(e) => format!("\"{}\"", e.code()),
        None => "null".to_string(),
    };
    writeln!(
        out,
        "{{\"schema_version\":1,\"event\":\"fragment\",\"frame\":{frame},\"timestamp_us\":{timestamp_us},\"version\":\"{}\",\"src\":\"{}\",\"dst\":\"{}\",\"identification\":{},\"offset\":{},\"payload_len\":{},\"more_fragments\":{},\"datagram_fragments\":{},\"buffered_bytes\":{},\"outcome\":\"{outcome}\",\"error\":{err}}}",
        s.version.as_str(),
        s.src,
        s.dst,
        s.identification,
        s.offset,
        s.payload_len,
        s.more_fragments,
        s.datagram_fragments,
        s.buffered_bytes,
    )
}
