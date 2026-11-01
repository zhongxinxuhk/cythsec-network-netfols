// bin/vxlan_collect.rs —— VXLAN 有界事件采集器（RFC 7348）。
//
// 输出的是报文级 JSONL：外层五元组、VNI、基础 flags、可见内层以太网/IP 头。
// 采集器只读 Pcap，不发探测、不改 VTEP/VNI 配置、不根据单个包推断隧道对端在线
// 或租户拓扑。内层 IP 只作为“这个包携带了什么”的可见字段输出，不进入 FlowRecord。
//
// Pcap 接受 Ethernet 与 Linux cooked capture（SLL/SLL2）；raw IP、pcapng 不支持。

use std::io::{self, BufReader, BufWriter, Write};
use std::process::ExitCode;

use traffic_engine::channel::{decode_frame_with_link, l4_payload, LinkLayer};
use traffic_engine::pcapfile::PcapReader;
use traffic_engine::vxlan::{self, VxlanStats};

const USAGE: &str = "\
cythsec-vxlan —— VXLAN 有界事件采集器（RFC 7348）

用法:
  cythsec-vxlan --pcap <file.pcap> [选项]

选项:
  -o, --output <file>   输出 JSONL（默认 stdout，`-` 表示 stdout）
  -q, --quiet           不打印统计行
  -h, --help            显示本帮助

输出（stderr，一行）:
  [cythsec-vxlan] vxlan vxlan_frames=… vni_zero=… vlan_tagged=…
                  inner_ipv4=… inner_ipv6=… inner_arp=… inner_other=…
                  inner_complete=… inner_incomplete=… capture_truncated=…
                  truncated=… malformed=… missing_i_flag=… reserved_nonzero=…
                  too_many_vlans=… frames=… non_vxlan=… decode_errors=…

退出码:
  0  正常（包括 pcap 里没有 VXLAN 的情况；统计行会明确报 vxlan_frames=0）
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

    let mut stats = VxlanStats::default();
    let mut frames = 0u64;
    let mut non_vxlan = 0u64;
    let mut decode_errors = 0u64;
    while let Some(rec) = reader
        .next_record()
        .map_err(|e| format!("读 pcap 记录: {e}"))?
    {
        frames += 1;
        let d = match decode_frame_with_link(&rec.data, link) {
            Ok(d) => d,
            Err(_) => {
                decode_errors += 1;
                continue;
            }
        };
        if d.key.proto.number() != 17
            || (!vxlan::is_vxlan_port(d.key.src_port) && !vxlan::is_vxlan_port(d.key.dst_port))
        {
            non_vxlan += 1;
            continue;
        }
        let Some(payload) = l4_payload(&rec.data, &d) else {
            stats.record_error(vxlan::VxlanError::TruncatedHeader { need: 8, got: 0 });
            continue;
        };
        let complete = !rec.is_truncated() && !payload.is_truncated();
        match vxlan::parse_with_complete(payload.bytes, complete) {
            Ok(mut f) => {
                f.capture_truncated = rec.is_truncated() || payload.is_truncated();
                stats.observe(&f);
                writeln!(
                    out,
                    "{}",
                    f.to_json_line(
                        rec.timestamp_us,
                        frames,
                        rec.orig_len as usize,
                        d.key.src_ip,
                        d.key.dst_ip,
                        d.key.src_port,
                        d.key.dst_port,
                    )
                )
                .map_err(|e| format!("写输出: {e}"))?;
            }
            Err(e) => stats.record_error(e),
        }
    }
    out.flush().map_err(|e| format!("刷输出: {e}"))?;

    if !args.quiet {
        eprintln!(
            "[cythsec-vxlan] {} frames={frames} non_vxlan={non_vxlan} decode_errors={decode_errors}",
            stats.render_line()
        );
    }
    Ok(())
}
