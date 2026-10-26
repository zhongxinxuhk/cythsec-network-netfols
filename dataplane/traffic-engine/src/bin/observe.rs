//! Aggregate-only offline host. Never writes flow records, addresses, domains, payloads or samples.
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::process::ExitCode;
use traffic_engine::observability::{Aggregator, Config, SourceCounters};
use traffic_engine::pcapfile::{PcapReader, LINKTYPE_ETHERNET};

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut input = None;
    let mut output = None;
    let mut cfg = Config::default();
    let (mut eligible, mut delivered, mut dropped) = (None, None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("cythsec-observe -r input.pcap [-o new-aggregate.jsonl]\n--window-seconds 60..3600 --sample-every 1..1000000\n--max-flows 20..65536 --minimum-flows 20..capacity\nOptional same-capture counters (all three required):\n--source-eligible N --source-delivered N --source-dropped N\nOutput: coarse windows plus mandatory capture_status trailer. No VPN/app/domain attribution.\nTLS/QUIC header counts and TCP quality are sampled lower-bound observations, not application totals.");
                return Ok(());
            }
            "--version" => {
                let b = traffic_engine::build_info();
                println!(
                    "cythsec-observe version={}\ncythsec-observe commit={}",
                    b.version, b.commit
                );
                return Ok(());
            }
            "-r" | "--read" => input = Some(args.next().ok_or("missing input path")?),
            "-o" | "--output" => output = Some(args.next().ok_or("missing output path")?),
            "--window-seconds" => {
                cfg.window_seconds = args
                    .next()
                    .ok_or("missing window")?
                    .parse()
                    .map_err(|_| "invalid window")?
            }
            "--sample-every" => {
                cfg.sampling_interval = args
                    .next()
                    .ok_or("missing interval")?
                    .parse()
                    .map_err(|_| "invalid interval")?
            }
            "--max-flows" => {
                cfg.max_flows = args
                    .next()
                    .ok_or("missing capacity")?
                    .parse()
                    .map_err(|_| "invalid capacity")?
            }
            "--minimum-flows" => {
                cfg.minimum_flows = args
                    .next()
                    .ok_or("missing cohort")?
                    .parse()
                    .map_err(|_| "invalid cohort")?
            }
            "--source-eligible" => {
                eligible = Some(
                    args.next()
                        .ok_or("missing source counter")?
                        .parse::<u64>()
                        .map_err(|_| "invalid counter")?,
                )
            }
            "--source-delivered" => {
                delivered = Some(
                    args.next()
                        .ok_or("missing source counter")?
                        .parse::<u64>()
                        .map_err(|_| "invalid counter")?,
                )
            }
            "--source-dropped" => {
                dropped = Some(
                    args.next()
                        .ok_or("missing source counter")?
                        .parse::<u64>()
                        .map_err(|_| "invalid counter")?,
                )
            }
            _ => return Err("unknown argument; see --help".into()),
        }
    }
    let source = match (eligible, delivered, dropped) {
        (None, None, None) => None,
        (Some(eligible), Some(delivered), Some(dropped)) => Some(SourceCounters {
            eligible,
            delivered,
            dropped,
        }),
        _ => return Err("all source counters must be supplied together".into()),
    };
    let input = input.ok_or("-r is required")?;
    let mut engine = Aggregator::new(cfg).map_err(str::to_owned)?;
    let mut reader = PcapReader::new(BufReader::new(
        File::open(&input).map_err(|_| "cannot open input")?,
    ))
    .map_err(|_| "invalid pcap header")?;
    if reader.linktype() != LINKTYPE_ETHERNET {
        return Err("only classic Ethernet pcap is supported".into());
    }
    let mut out: Box<dyn Write> = match output {
        Some(p) if p != "-" => Box::new(BufWriter::new(
            File::options()
                .write(true)
                .create_new(true)
                .open(p)
                .map_err(|_| "output must be a new writable path")?,
        )),
        _ => Box::new(BufWriter::new(io::stdout())),
    };
    let mut input_error = false;
    loop {
        match reader.next_record() {
            Ok(Some(p)) => {
                if let Some(w) = engine.observe(&p) {
                    w.write_json(&mut out)
                        .map_err(|_| "cannot write aggregate")?;
                }
            }
            Ok(None) => break,
            Err(_) => {
                input_error = true;
                break;
            }
        }
    }
    if let Some(w) = engine.finish() {
        w.write_json(&mut out)
            .map_err(|_| "cannot write aggregate")?;
    }
    let consistent = source.map(|s| s.validate(engine.records()));
    let capture_loss = match source {
        Some(s) if consistent == Some(true) => {
            if s.dropped == 0 {
                "declared_zero"
            } else {
                "declared_nonzero"
            }
        }
        Some(_) => "inconsistent_counters",
        None => "unknown",
    };
    let (published, suppressed) = engine.window_counts();
    writeln!(out,"{{\"type\":\"capture_status\",\"schema_version\":1,\"input_complete\":{},\"analysis_complete\":{},\"published_windows\":{},\"suppressed_windows\":{},\"capture_loss_status\":\"{}\",\"source_counter_consistent\":{},\"source_scope\":{}}}",!input_error,!input_error && !engine.capacity_limited(),published,suppressed,capture_loss,consistent.map(|v|v.to_string()).unwrap_or_else(||"null".into()),if source.is_some(){"\"operator_declared_same_capture\""}else{"null"}).map_err(|_|"cannot write status")?;
    out.flush().map_err(|_| "cannot flush output")?;
    if engine.capacity_limited() {
        return Err("flow capacity exhausted; quality output is partial".into());
    }
    if input_error {
        return Err("pcap ended with an invalid or incomplete record; output is partial".into());
    }
    if consistent == Some(false) {
        return Err("source counters disagree with capture; completeness unverified".into());
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cythsec-observe: {e}");
            ExitCode::from(2)
        }
    }
}
