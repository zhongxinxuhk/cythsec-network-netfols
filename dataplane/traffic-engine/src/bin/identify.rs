//! Offline identification host; no packet transmission or privilege elevation.
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::process::ExitCode;
use traffic_engine::flow::{FlowKey, Proto};
use traffic_engine::identification::{evidence::Evidence, Engine, CATALOG};
use traffic_engine::pcapfile::{PcapReader, LINKTYPE_ETHERNET};

fn read_evidence(path: &str) -> Result<Vec<Evidence>, String> {
    let mut text = String::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(1_048_577)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > 1_048_576 {
        return Err("trusted evidence exceeds 1 MiB".into());
    }
    let mut out = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let c: Vec<_> = line.split('\t').collect();
        if c.len() != 14 {
            return Err(format!(
                "evidence line {}: expected 14 tab-separated fields",
                i + 1
            ));
        }
        let parse_err = || format!("evidence line {}: invalid typed field", i + 1);
        let e = Evidence {
            id: c[0].into(),
            trust_root: c[1].into(),
            kind: c[2].into(),
            protocol_id: c[3].into(),
            version: c[4].into(),
            mode: c[5].into(),
            key: FlowKey {
                src_ip: c[6].parse().map_err(|_| parse_err())?,
                src_port: c[7].parse().map_err(|_| parse_err())?,
                dst_ip: c[8].parse().map_err(|_| parse_err())?,
                dst_port: c[9].parse().map_err(|_| parse_err())?,
                proto: Proto::from_u8(c[10].parse().map_err(|_| parse_err())?),
            },
            start_us: c[11].parse().map_err(|_| parse_err())?,
            end_us: c[12].parse().map_err(|_| parse_err())?,
            deny: match c[13] {
                "assert" => false,
                "deny" => true,
                _ => return Err(parse_err()),
            },
        };
        e.validate()
            .map_err(|err| format!("evidence line {}: {}", i + 1, err))?;
        if !ids.insert(e.id.clone()) {
            return Err("duplicate evidence ID".into());
        }
        out.push(e);
        if out.len() > 4096 {
            return Err("trusted evidence exceeds 4096 events".into());
        }
    }
    Ok(out)
}
fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut input = None;
    let mut output = None;
    let mut context = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--version" => {
                let b = traffic_engine::build_info();
                println!("cythsec-identify version={}\ncythsec-identify commit={}\ncythsec-identify build_time={}",b.version,b.commit,b.build_time);
                return Ok(());
            }
            "--catalog" => {
                for e in CATALOG {
                    println!("{}\t{}\t{}\t{}", e.id, e.name, e.layer, e.parser);
                }
                return Ok(());
            }
            "--help" | "-h" => {
                println!("cythsec-identify -r input.pcap [-o identifications.jsonl] [--trusted-evidence operator-attested.tsv]\n--catalog lists designed objects; does not claim wire/sample coverage.\nClassic Ethernet pcap only. No active probes are executed. Evidence schema: docs/architecture/vpn-ztna-identification.md");
                return Ok(());
            }
            "-r" | "--read" => input = Some(args.next().ok_or("missing input path")?),
            "-o" | "--output" => output = Some(args.next().ok_or("missing output path")?),
            "--trusted-evidence" => {
                context = Some(args.next().ok_or("missing trusted evidence path")?)
            }
            _ => return Err(format!("unknown argument {a}")),
        }
    }
    let input = input.ok_or("-r is required")?;
    if output.as_deref() == Some(input.as_str()) || output.is_some() && context == output {
        return Err("output must not overwrite an input".into());
    }
    let evidence = match context {
        Some(p) => read_evidence(&p)?,
        None => Vec::new(),
    };
    let f = File::open(&input).map_err(|e| e.to_string())?;
    let mut pcap = PcapReader::new(BufReader::new(f)).map_err(|e| e.to_string())?;
    if pcap.linktype() != LINKTYPE_ETHERNET {
        return Err("only Ethernet linktype is supported; no silent reinterpretation".into());
    }
    let mut engine = Engine::default();
    while let Some(p) = pcap.next_record().map_err(|e| e.to_string())? {
        engine.observe(&p.data, p.timestamp_us);
    }
    let mut out: Box<dyn Write> = match output {
        Some(p) if p != "-" => Box::new(BufWriter::new(
            File::options()
                .write(true)
                .create_new(true)
                .open(p)
                .map_err(|e| e.to_string())?,
        )),
        _ => Box::new(BufWriter::new(io::stdout())),
    };
    engine
        .write_jsonl(&mut out, &evidence)
        .map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    eprintln!("identification frames={} decode_errors={} capacity_drops={} capture_truncated={} timestamp_regressions={}",engine.stats.frames,engine.stats.decode_errors,engine.stats.capacity_drops,engine.stats.truncated,engine.stats.regressions);
    if engine.stats.capacity_drops > 0 {
        return Err("session capacity exhausted; output incomplete".into());
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cythsec-identify: {e}");
            ExitCode::from(2)
        }
    }
}
