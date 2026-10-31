// 端到端：Pcap → TCP 重组 → TLS 1.3 记录解密 → DPI → JSONL。
//
// 这里刻意不用 RFC 8448 的固定记录做“唯一”验证：那条向量已经验证了密码学与
// 序号处理（见 tlsdecrypt::record 单元测试）。本测试要验证的是**另一件事**：
// 解密后的明文确实被送进了 DPI，而不是只把字节数写进报告。因此用仓库内的
// AEAD 构造一条带 HTTP 明文的 TLS 1.3 记录；AES-GCM 与 ChaCha20-Poly1305
// 本身分别由 NIST/RFC 8439 向量独立校验，不会变成“自己加密自己解密”的循环论证。

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use traffic_engine::tlsdecrypt::crypto::{aes_gcm_seal, chacha20_poly1305_seal};
use traffic_engine::tlsdecrypt::record::{
    Aead, Tls12Keys, TrafficKeys, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
};

fn u16be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn record(header: [u8; 5], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    out
}

fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(kind);
    let n = body.len() as u32;
    out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    out.extend_from_slice(body);
    out
}

fn client_hello(random: [u8; 32], suite: u16) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&random);
    body.push(0); // session id
    body.extend_from_slice(&[0x00, 0x02]);
    body.extend_from_slice(&suite.to_be_bytes());
    body.extend_from_slice(&[0x01, 0x00]); // null compression
    body.extend_from_slice(&[0x00, 0x00]); // no extensions
    let hs = handshake(1, &body);
    let mut hdr = vec![0x16, 0x03, 0x01];
    hdr.extend_from_slice(&u16be(hs.len() as u16));
    record([hdr[0], hdr[1], hdr[2], hdr[3], hdr[4]], &hs)
}

fn server_hello(random: [u8; 32], suite: u16) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&random);
    body.push(0);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&[0x00, 0x00]);
    let hs = handshake(2, &body);
    let mut hdr = vec![0x16, 0x03, 0x03];
    hdr.extend_from_slice(&u16be(hs.len() as u16));
    record([hdr[0], hdr[1], hdr[2], hdr[3], hdr[4]], &hs)
}

fn app_record(keys: &TrafficKeys, seq: u64, inner_type: u8, data: &[u8]) -> Vec<u8> {
    let mut inner = data.to_vec();
    inner.push(inner_type);
    let len = inner.len() + 16;
    let header = [23u8, 3, 3, (len >> 8) as u8, len as u8];
    let mut nonce = keys.iv;
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let sealed = match keys.aead {
        Aead::Aes128Gcm | Aead::Aes256Gcm => {
            aes_gcm_seal(&keys.key, &nonce, &header, &inner).unwrap()
        }
        Aead::ChaCha20Poly1305 => {
            chacha20_poly1305_seal(&keys.key, &nonce, &header, &inner).unwrap()
        }
    };
    record(header, &sealed)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += u32::from(b) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn frame(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&u16be(sport));
    tcp.extend_from_slice(&u16be(dport));
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.extend_from_slice(&u16be((5 << 12) | u16::from(flags)));
    tcp.extend_from_slice(&u16be(65535));
    tcp.extend_from_slice(&[0, 0]);
    tcp.extend_from_slice(&[0, 0]);
    tcp.extend_from_slice(payload);
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&u16be((20 + tcp.len()) as u16));
    ip.extend_from_slice(&[0, 1, 0, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&u16be(c));
    ip.extend_from_slice(&tcp);
    let mut eth = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    eth
}

fn pcap(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&u32::from(u16::MAX).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (i, p) in packets.iter().enumerate() {
        out.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

fn temp_dir(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("cythsec-tls-{tag}-{}-{n}", std::process::id()));
    fs::create_dir_all(&d).unwrap();
    d
}

fn run_decrypt_case(tag: &str, suite: u16, c_traffic: &[u8], s_traffic: &[u8]) -> String {
    let dir = temp_dir(tag);
    let random = [0x11u8; 32];
    let c_keys = TrafficKeys::derive(c_traffic, suite).unwrap();
    let s_keys = TrafficKeys::derive(s_traffic, suite).unwrap();
    let request = b"GET /probe?x=1 HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    let client_payload = [
        client_hello(random, suite),
        app_record(&c_keys, 0, 23, request),
    ]
    .concat();
    let server_payload = [
        server_hello(random, suite),
        app_record(&s_keys, 0, 23, response),
    ]
    .concat();
    let cport = 12345u16;
    let sport = 443u16;
    let cseq = 1000u32;
    let sseq = 5000u32;
    let packets = vec![
        frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            cport,
            sport,
            cseq,
            0,
            0x02,
            &[],
        ),
        frame(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            sport,
            cport,
            sseq,
            cseq + 1,
            0x12,
            &[],
        ),
        frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            cport,
            sport,
            cseq + 1,
            sseq + 1,
            0x10,
            &[],
        ),
        frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            cport,
            sport,
            cseq + 1,
            sseq + 1,
            0x18,
            &client_payload,
        ),
        frame(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            sport,
            cport,
            sseq + 1,
            cseq + 1 + client_payload.len() as u32,
            0x18,
            &server_payload,
        ),
    ];
    let pcap_path = dir.join("in.pcap");
    fs::write(&pcap_path, pcap(&packets)).unwrap();
    let log_path = dir.join("tls.keys");
    fs::write(
        &log_path,
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nSERVER_TRAFFIC_SECRET_0 {} {}\n",
            hex(&random),
            hex(&c_traffic),
            hex(&random),
            hex(&s_traffic)
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out_path = dir.join("out.jsonl");
    let out = Command::new(env!("CARGO_BIN_EXE_cythsec-tls-inspect"))
        .args([
            "-r",
            pcap_path.to_str().unwrap(),
            "--keylog",
            log_path.to_str().unwrap(),
            "--dpi",
            "deep",
            "--decrypt",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = fs::read_to_string(&out_path).unwrap();
    let _ = fs::remove_dir_all(&dir);
    text
}

fn tls12_ccs() -> Vec<u8> {
    record([20, 3, 3, 0, 1], &[1])
}

fn tls12_record(keys: &Tls12Keys, seq: u64, content_type: u8, data: &[u8]) -> Vec<u8> {
    let explicit = seq.to_be_bytes();
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&explicit);
    aad[8] = content_type;
    aad[9..11].copy_from_slice(&0x0303u16.to_be_bytes());
    aad[11..13].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let payload = match keys.aead {
        Aead::Aes128Gcm | Aead::Aes256Gcm => {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&keys.fixed_iv[..4]);
            nonce[4..].copy_from_slice(&explicit);
            let sealed = aes_gcm_seal(&keys.key, &nonce, &aad, data).unwrap();
            let mut payload = explicit.to_vec();
            payload.extend_from_slice(&sealed);
            payload
        }
        Aead::ChaCha20Poly1305 => {
            let mut nonce: [u8; 12] = keys.fixed_iv.as_slice().try_into().unwrap();
            for (slot, seq_byte) in nonce[4..].iter_mut().zip(explicit) {
                *slot ^= seq_byte;
            }
            chacha20_poly1305_seal(&keys.key, &nonce, &aad, data).unwrap()
        }
    };
    let len = payload.len() as u16;
    record([content_type, 3, 3, (len >> 8) as u8, len as u8], &payload)
}

fn run_tls12_case() -> String {
    run_tls12_case_with(0xc02f, "tls12")
}

fn run_tls12_chacha_case() -> String {
    run_tls12_case_with(0xcca8, "tls12-chacha")
}

fn run_tls12_case_with(suite: u16, tag: &str) -> String {
    let dir = temp_dir(tag);
    let random = [0x11u8; 32];
    let server_random = [0x22u8; 32];
    let master: Vec<u8> = (1u8..=48).collect();
    let (c_keys, s_keys) = Tls12Keys::derive(&master, &random, &server_random, suite).unwrap();
    let request = b"GET /legacy?x=1 HTTP/1.1\r\nHost: legacy.test\r\n\r\n";
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    let mut client_payload = client_hello(random, suite);
    client_payload.extend_from_slice(&tls12_ccs());
    client_payload.extend_from_slice(&tls12_record(&c_keys, 0, 22, &[0x14, 0, 0, 12]));
    client_payload.extend_from_slice(&tls12_record(&c_keys, 1, 23, request));

    let mut server_payload = server_hello(server_random, suite);
    server_payload.extend_from_slice(&tls12_ccs());
    server_payload.extend_from_slice(&tls12_record(&s_keys, 0, 22, &[0x14, 0, 0, 12]));
    server_payload.extend_from_slice(&tls12_record(&s_keys, 1, 23, response));

    let cport = 12346u16;
    let sport = 443u16;
    let cseq = 2000u32;
    let sseq = 6000u32;
    let packets = vec![
        frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            cport,
            sport,
            cseq,
            0,
            0x02,
            &[],
        ),
        frame(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            sport,
            cport,
            sseq,
            cseq + 1,
            0x12,
            &[],
        ),
        frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            cport,
            sport,
            cseq + 1,
            sseq + 1,
            0x10,
            &[],
        ),
        frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            cport,
            sport,
            cseq + 1,
            sseq + 1,
            0x18,
            &client_payload,
        ),
        frame(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            sport,
            cport,
            sseq + 1,
            cseq + 1 + client_payload.len() as u32,
            0x18,
            &server_payload,
        ),
    ];
    let pcap_path = dir.join("in.pcap");
    fs::write(&pcap_path, pcap(&packets)).unwrap();
    let log_path = dir.join("tls.keys");
    fs::write(
        &log_path,
        format!("CLIENT_RANDOM {} {}\n", hex(&random), hex(&master)),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out_path = dir.join("out.jsonl");
    let out = Command::new(env!("CARGO_BIN_EXE_cythsec-tls-inspect"))
        .args([
            "-r",
            pcap_path.to_str().unwrap(),
            "--keylog",
            log_path.to_str().unwrap(),
            "--dpi",
            "deep",
            "--decrypt",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = fs::read_to_string(&out_path).unwrap();
    let _ = fs::remove_dir_all(&dir);
    text
}

fn assert_http_dpi(text: &str) {
    assert!(text.contains("\"event\":\"tls_flow\""), "{text}");
    assert!(text.contains("\"app\":\"http\""), "{text}");
    assert!(text.contains("\"method\":\"GET\""), "{text}");
    assert!(text.contains("\"host\":\"example.test\""), "{text}");
    assert!(text.contains("\"status\":204"), "{text}");
    assert!(text.contains("\"opened\":1"), "{text}");
}

#[test]
fn cli_decrypts_tls13_aes128_http_and_reports_dpi() {
    let text = run_decrypt_case(
        "aes128",
        TLS_AES_128_GCM_SHA256,
        &[0x22u8; 32],
        &[0x33u8; 32],
    );
    assert_http_dpi(&text);
    assert!(
        text.contains("\"cipher_suite\":\"TLS_AES_128_GCM_SHA256\""),
        "{text}"
    );
}

#[test]
fn cli_decrypts_tls13_aes256_http_and_reports_dpi() {
    let text = run_decrypt_case(
        "aes256",
        TLS_AES_256_GCM_SHA384,
        &[0x22u8; 48],
        &[0x33u8; 48],
    );
    assert_http_dpi(&text);
    assert!(
        text.contains("\"cipher_suite\":\"TLS_AES_256_GCM_SHA384\""),
        "{text}"
    );
}

#[test]
fn cli_decrypts_tls13_chacha20_http_and_reports_dpi() {
    let text = run_decrypt_case(
        "chacha20",
        TLS_CHACHA20_POLY1305_SHA256,
        &[0x22u8; 32],
        &[0x33u8; 32],
    );
    assert_http_dpi(&text);
    assert!(
        text.contains("\"cipher_suite\":\"TLS_CHACHA20_POLY1305_SHA256\""),
        "{text}"
    );
}

#[test]
fn cli_decrypts_tls12_aes128_gcm_and_reports_dpi() {
    let text = run_tls12_case();
    assert!(text.contains("\"event\":\"tls_flow\""), "{text}");
    assert!(text.contains("\"tls_version\":\"1.2\""), "{text}");
    assert!(
        text.contains("\"cipher_suite\":\"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\""),
        "{text}"
    );
    assert!(text.contains("\"app\":\"http\""), "{text}");
    assert!(text.contains("\"method\":\"GET\""), "{text}");
    assert!(text.contains("\"host\":\"legacy.test\""), "{text}");
    assert!(text.contains("\"status\":200"), "{text}");
    assert!(text.contains("\"opened\":2"), "{text}");
}

#[test]
fn cli_decrypts_tls12_chacha20_and_reports_dpi() {
    let text = run_tls12_chacha_case();
    assert!(text.contains("\"event\":\"tls_flow\""), "{text}");
    assert!(text.contains("\"tls_version\":\"1.2\""), "{text}");
    assert!(
        text.contains("\"cipher_suite\":\"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256\""),
        "{text}"
    );
    assert!(text.contains("\"app\":\"http\""), "{text}");
    assert!(text.contains("\"method\":\"GET\""), "{text}");
    assert!(text.contains("\"host\":\"legacy.test\""), "{text}");
    assert!(text.contains("\"status\":200"), "{text}");
    assert!(text.contains("\"opened\":2"), "{text}");
}

#[test]
fn cli_refuses_decryption_without_explicit_opt_in() {
    let dir = temp_dir("no-opt-in");
    let pcap_path = dir.join("in.pcap");
    fs::write(&pcap_path, pcap(&[])).unwrap();
    let log_path = dir.join("tls.keys");
    fs::write(
        &log_path,
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nSERVER_TRAFFIC_SECRET_0 {} {}\n",
            hex(&[0x11u8; 32]),
            hex(&[0x22u8; 32]),
            hex(&[0x11u8; 32]),
            hex(&[0x33u8; 32])
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out = Command::new(env!("CARGO_BIN_EXE_cythsec-tls-inspect"))
        .args([
            "-r",
            pcap_path.to_str().unwrap(),
            "--keylog",
            log_path.to_str().unwrap(),
            "--dpi",
            "deep",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("TLS 解密未启用"), "{stderr}");
    let _ = fs::remove_dir_all(&dir);
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
