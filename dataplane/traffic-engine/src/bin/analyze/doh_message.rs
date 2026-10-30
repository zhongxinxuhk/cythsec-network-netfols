//! One complete decoded HTTPS message from the owning HTTP stack.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use traffic_engine::dpi::{
    doh::{self, HttpMessage, MAX_DNS_BYTES},
    dot::{Context, Direction},
};

const HELP:&str="cythsec-analyze doh-message --source-id ID --session-id ID --request-id ID --direction client|server --url https://host/path [--method GET|POST | --status 200] [-r decoded-dns-body.bin] [--content-type application/dns-message] [--content-length N] [--content-encoding identity] [-o event.jsonl]\nInput is one caller-attested complete, transfer-decoded HTTPS message. HTTP/2/3 framing and TLS verification belong to the source. GET carries unpadded base64url in the single dns query parameter.\n";
pub fn run(args: &[String]) -> Result<(), String> {
    if args == ["--help"] || args == ["-h"] {
        print!("{HELP}");
        return Ok(());
    }
    let mut values = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut at = 0;
    while at < args.len() {
        let key = match args[at].as_str() {
            "-r" | "--read" => "input",
            "-o" | "--output" => "output",
            "--source-id" => "source",
            "--session-id" => "session",
            "--request-id" => "request",
            "--direction" => "direction",
            "--url" => "url",
            "--method" => "method",
            "--status" => "status",
            "--content-type" => "media",
            "--content-length" => "length",
            "--content-encoding" => "encoding",
            other => return Err(format!("unsupported doh-message option: {other}")),
        };
        if !seen.insert(key) {
            return Err(format!("duplicate doh-message option: {}", args[at]));
        }
        values.insert(
            key,
            args.get(at + 1)
                .ok_or("missing doh-message option value")?
                .as_str(),
        );
        at += 2;
    }
    let required = |key| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| format!("doh-message requires {key}"))
    };
    let direction = match required("direction")? {
        "client" => Direction::ClientToServer,
        "server" => Direction::ServerToClient,
        _ => return Err("direction must be client or server".into()),
    };
    let context = Context::new(required("source")?, required("session")?, direction)
        .map_err(str::to_string)?;
    let request = required("request")?;
    let url = required("url")?;
    let status = values
        .get("status")
        .map(|v| {
            v.parse::<u16>()
                .map_err(|_| "status must be an unsigned integer")
        })
        .transpose()?;
    let length = values
        .get("length")
        .map(|v| {
            v.parse::<usize>()
                .map_err(|_| "content-length must be an unsigned integer")
        })
        .transpose()?;
    let mut body = Vec::new();
    if let Some(path) = values.get("input") {
        File::open(path)
            .map_err(|e| format!("open decoded body: {e}"))?
            .take((MAX_DNS_BYTES + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|e| format!("read decoded body: {e}"))?;
    }
    let event = doh::parse_https(
        context,
        request,
        url,
        HttpMessage {
            method: values.get("method").copied(),
            status,
            content_type: values.get("media").copied(),
            content_encoding: values.get("encoding").copied(),
            content_length: length,
            body: &body,
        },
    )
    .map_err(|e| e.to_string())?;
    let stdout = io::stdout();
    let mut out: Box<dyn Write> = match values.get("output").copied() {
        None | Some("-") => Box::new(stdout.lock()),
        Some(path) => Box::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| format!("create new DoH output: {e}"))?,
        ),
    };
    writeln!(out, "{}", event.to_json()).map_err(|e| format!("write DoH event: {e}"))?;
    out.flush().map_err(|e| format!("flush DoH event: {e}"))?;
    Ok(())
}
