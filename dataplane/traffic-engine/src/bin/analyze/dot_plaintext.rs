//! Explicit caller-attested TLS application input, separate from raw pcap flows.
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

use traffic_engine::dpi::dot::{Context, Direction, PlaintextStream};

const HELP: &str = "cythsec-analyze dot-plaintext -r plaintext.bin --source-id ID --session-id ID --direction client|server [-o messages.jsonl]\nInput: contiguous TLS application bytes from one caller-attested termination/session/direction, starting at a DNS length frame. No TLS keys or decryption.\nOutput: tls_plaintext_dns_message JSONL, not FlowRecord. TLS authentication is unverified. Existing output files are refused.\n";

pub fn run(args: &[String]) -> Result<(), String> {
    if args == ["--help"] || args == ["-h"] {
        print!("{HELP}");
        return Ok(());
    }
    let mut input = None;
    let mut output = None;
    let mut source = None;
    let mut session = None;
    let mut direction = None;
    let mut seen = BTreeSet::new();
    let mut at = 0;
    while at < args.len() {
        let flag = args[at].as_str();
        let canonical = match flag {
            "-r" | "--read" => "input",
            "-o" | "--output" => "output",
            "--source-id" => "source",
            "--session-id" => "session",
            "--direction" => "direction",
            _ => return Err(format!("unsupported dot-plaintext argument: {flag}")),
        };
        if !seen.insert(canonical) {
            return Err(format!("duplicate dot-plaintext option: {flag}"));
        }
        let value = args
            .get(at + 1)
            .ok_or_else(|| format!("missing value: {flag}"))?
            .clone();
        match canonical {
            "input" => input = Some(value),
            "output" => output = Some(value),
            "source" => source = Some(value),
            "session" => session = Some(value),
            "direction" => {
                direction = Some(match value.as_str() {
                    "client" => Direction::ClientToServer,
                    "server" => Direction::ServerToClient,
                    _ => return Err("direction must be client or server".into()),
                })
            }
            _ => unreachable!(),
        }
        at += 2;
    }
    let input = input.ok_or("dot-plaintext requires -r/--read")?;
    let context = Context::new(
        &source.ok_or("dot-plaintext requires --source-id")?,
        &session.ok_or("dot-plaintext requires --session-id")?,
        direction.ok_or("dot-plaintext requires --direction")?,
    )
    .map_err(str::to_string)?;
    let mut file = File::open(&input).map_err(|e| format!("open plaintext input: {e}"))?;
    let mut stream = PlaintextStream::new(context);
    let mut messages = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = match file.read(&mut buffer) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read plaintext input: {e}")),
        };
        if n == 0 {
            break;
        }
        stream
            .push(&buffer[..n], |message| messages.push(message))
            .map_err(|e| e.to_string())?;
    }
    stream.finish().map_err(|e| e.to_string())?;
    // Validate the complete bounded input before creating output or writing stdout.
    let stdout = io::stdout();
    let mut out: Box<dyn Write> = match output.as_deref() {
        None | Some("-") => Box::new(stdout.lock()),
        Some(path) => Box::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| format!("create new plaintext output: {e}"))?,
        ),
    };
    for message in &messages {
        writeln!(out, "{}", message.to_json())
            .map_err(|e| format!("write plaintext output: {e}"))?;
    }
    out.flush()
        .map_err(|e| format!("flush plaintext output: {e}"))?;
    Ok(())
}
