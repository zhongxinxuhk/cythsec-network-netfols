//! TLS 1.3 / TLS 1.2 记录层解析与按 key log 解密。
//!
//! TLS 1.3：外层 `application_data`（23），内层 content type 在解密后剥离。
//! TLS 1.2：支持 AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 套件的 AEAD
//! 记录；主密钥来自 key log 的 `CLIENT_RANDOM` 行。TLS 1.2 的 CBC 套件仍明确报错。

#[cfg(test)]
use crate::tlsdecrypt::crypto::chacha20_poly1305_seal;
use crate::tlsdecrypt::crypto::{
    aes_gcm_open, chacha20_poly1305_open, expand_label, expand_label_sha384,
};
use crate::tlsdecrypt::keylog::KeyLog;

pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

const MAX_RECORD: usize = 18_432;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub content_type: u8,
    pub version: u16,
    pub payload: Vec<u8>,
    /// 原始 5 字节记录头；TLS 1.3 AEAD 的 AAD 就是它（长度字段保持密文长度）。
    pub header: [u8; 5],
}

impl Record {
    pub fn raw(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.payload.len());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.payload);
        out
    }
}

/// 解析一个完整 TLS 记录流。末尾不完整的记录是错误，不静默丢弃。
pub fn parse_records(bytes: &[u8]) -> Result<Vec<Record>, String> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        if bytes.len() - off < 5 {
            return Err(format!("truncated TLS record header at offset {off}"));
        }
        let header = [
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
        ];
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > MAX_RECORD {
            return Err(format!("TLS record length {len} exceeds {MAX_RECORD}"));
        }
        if bytes.len() - off - 5 < len {
            return Err(format!(
                "truncated TLS record at offset {off}: need {len} bytes, have {}",
                bytes.len() - off - 5
            ));
        }
        out.push(Record {
            content_type: header[0],
            version: u16::from_be_bytes([header[1], header[2]]),
            payload: bytes[off + 5..off + 5 + len].to_vec(),
            header,
        });
        off += 5 + len;
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    pub random: [u8; 32],
    pub cipher_suites: Vec<u16>,
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHelloInfo {
    pub random: [u8; 32],
    pub cipher_suite: u16,
}

/// 从客户端字节流里找第一个 ClientHello，提取 client random、套件与 SNI。
pub fn parse_client_hello(bytes: &[u8]) -> Result<ClientHelloInfo, String> {
    let records = parse_records(bytes)?;
    for rec in &records {
        if rec.content_type != 22 || rec.payload.len() < 4 || rec.payload[0] != 1 {
            continue;
        }
        let body_len =
            u32::from_be_bytes([0, rec.payload[1], rec.payload[2], rec.payload[3]]) as usize;
        if rec.payload.len() < 4 + body_len {
            return Err("ClientHello handshake length exceeds record payload".into());
        }
        // handshake header(4) + legacy_version(2) + random(32)
        if rec.payload.len() < 38 {
            return Err("ClientHello is shorter than random".into());
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&rec.payload[6..38]);
        let sid_len = *rec
            .payload
            .get(38)
            .ok_or("ClientHello missing session id")? as usize;
        let cs_off = 39 + sid_len;
        if rec.payload.len() < cs_off + 2 {
            return Err("ClientHello missing cipher suites".into());
        }
        let cs_len = u16::from_be_bytes([rec.payload[cs_off], rec.payload[cs_off + 1]]) as usize;
        if cs_len % 2 != 0 || rec.payload.len() < cs_off + 2 + cs_len {
            return Err("ClientHello cipher suite vector is malformed".into());
        }
        let mut cipher_suites = Vec::with_capacity(cs_len / 2);
        for pair in rec.payload[cs_off + 2..cs_off + 2 + cs_len].chunks_exact(2) {
            cipher_suites.push(u16::from_be_bytes([pair[0], pair[1]]));
        }
        // SNI 复用已有 DPI 解析器，避免两套扩展解析各自漂移。
        let server_name = crate::dpi::tls::parse(&rec.raw())
            .ok()
            .and_then(|h| h.server_name);
        return Ok(ClientHelloInfo {
            random,
            cipher_suites,
            server_name,
        });
    }
    Err("no ClientHello record found".into())
}

/// 从服务端字节流里找第一个 ServerHello，提取选中的套件。
pub fn parse_server_hello(bytes: &[u8]) -> Result<ServerHelloInfo, String> {
    let records = parse_records(bytes)?;
    for rec in &records {
        if rec.content_type != 22 || rec.payload.len() < 4 || rec.payload[0] != 2 {
            continue;
        }
        if rec.payload.len() < 38 {
            return Err("ServerHello is shorter than random".into());
        }
        let body_len =
            u32::from_be_bytes([0, rec.payload[1], rec.payload[2], rec.payload[3]]) as usize;
        if rec.payload.len() < 4 + body_len {
            return Err("ServerHello handshake length exceeds record payload".into());
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&rec.payload[6..38]);
        let sid_len = *rec
            .payload
            .get(38)
            .ok_or("ServerHello missing session id")? as usize;
        let cs_off = 39 + sid_len;
        if rec.payload.len() < cs_off + 2 {
            return Err("ServerHello missing cipher suite".into());
        }
        return Ok(ServerHelloInfo {
            random,
            cipher_suite: u16::from_be_bytes([rec.payload[cs_off], rec.payload[cs_off + 1]]),
        });
    }
    Err("no ServerHello record found".into())
}

pub fn suite_name(suite: u16) -> &'static str {
    match suite {
        TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        TLS_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficKeys {
    pub key: Vec<u8>,
    pub iv: [u8; 12],
    pub aead: Aead,
}

impl TrafficKeys {
    /// 从 key log 的 traffic secret 派生 key/iv。
    ///
    /// 已实现 0x1301（AES-128-GCM + SHA-256）、0x1302（AES-256-GCM + SHA-384）
    /// 与 0x1303（ChaCha20-Poly1305 + SHA-256）。
    pub fn derive(traffic_material: &[u8], suite: u16) -> Result<Self, String> {
        let (key, iv_vec, aead) = match suite {
            TLS_AES_128_GCM_SHA256 => {
                if traffic_material.len() != 32 {
                    return Err(format!(
                        "traffic secret length {} does not match SHA-256 suite",
                        traffic_material.len()
                    ));
                }
                (
                    expand_label(traffic_material, "key", &[], 16),
                    expand_label(traffic_material, "iv", &[], 12),
                    Aead::Aes128Gcm,
                )
            }
            TLS_AES_256_GCM_SHA384 => {
                if traffic_material.len() != 48 {
                    return Err(format!(
                        "traffic secret length {} does not match SHA-384 suite",
                        traffic_material.len()
                    ));
                }
                (
                    expand_label_sha384(traffic_material, "key", &[], 32),
                    expand_label_sha384(traffic_material, "iv", &[], 12),
                    Aead::Aes256Gcm,
                )
            }
            TLS_CHACHA20_POLY1305_SHA256 => {
                if traffic_material.len() != 32 {
                    return Err(format!(
                        "traffic secret length {} does not match SHA-256 suite",
                        traffic_material.len()
                    ));
                }
                (
                    expand_label(traffic_material, "key", &[], 32),
                    expand_label(traffic_material, "iv", &[], 12),
                    Aead::ChaCha20Poly1305,
                )
            }
            _ => {
                return Err(format!(
                    "unsupported TLS 1.3 cipher suite {} ({})",
                    suite,
                    suite_name(suite)
                ));
            }
        };
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_vec);
        Ok(Self { key, iv, aead })
    }
}

impl Drop for TrafficKeys {
    fn drop(&mut self) {
        self.key.fill(0);
        self.iv.fill(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plaintext {
    /// 解密后的内层 content type（22 handshake / 23 application_data / 21 alert）。
    pub content_type: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Tls13Direction {
    keys: TrafficKeys,
    seq: u64,
    started: bool,
    opened: u64,
    skipped: u64,
}

impl Tls13Direction {
    pub fn new(keys: TrafficKeys) -> Self {
        Self {
            keys,
            seq: 0,
            started: false,
            opened: 0,
            skipped: 0,
        }
    }

    /// 尝试解密一条记录。
    ///
    /// `Ok(None)` 有两种含义，调用方应分开统计：
    /// * 外层不是 application_data（明文握手记录）；
    /// * 尚未解出第一条应用密钥记录，当前记录属于握手密钥 epoch，按设计跳过。
    ///
    /// 一旦解出过一条，后续标签失败就是**错误**：继续往下试会让序号错位，
    /// 把后面所有记录都"解"成垃圾。
    pub fn open(&mut self, rec: &Record) -> Result<Option<Plaintext>, String> {
        if rec.content_type != 23 {
            return Ok(None);
        }
        if rec.payload.len() < 17 {
            return Err("TLS 1.3 record shorter than explicit nonce + tag".into());
        }
        let aad = rec.header;
        let mut nonce = self.keys.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        let opened = match self.keys.aead {
            Aead::Aes128Gcm | Aead::Aes256Gcm => {
                aes_gcm_open(&self.keys.key, &nonce, &aad, &rec.payload)
            }
            Aead::ChaCha20Poly1305 => {
                chacha20_poly1305_open(&self.keys.key, &nonce, &aad, &rec.payload)
            }
        };
        match opened {
            Ok(mut pt) => {
                while pt.last() == Some(&0) {
                    pt.pop();
                }
                let inner = pt.pop().ok_or("decrypted TLS record is all padding")?;
                self.seq += 1;
                self.started = true;
                self.opened += 1;
                Ok(Some(Plaintext {
                    content_type: inner,
                    data: pt,
                }))
            }
            Err(e) => {
                if self.started {
                    Err(format!(
                        "TLS record tag mismatch at sequence {}: {e}",
                        self.seq
                    ))
                } else {
                    // 握手密钥 epoch 的记录（EncryptedExtensions/Certificate/Finished）
                    // 在应用密钥下必然解不开；跳过且不推进序号。
                    self.skipped += 1;
                    Ok(None)
                }
            }
        }
    }

    pub fn opened(&self) -> u64 {
        self.opened
    }

    pub fn skipped(&self) -> u64 {
        self.skipped
    }
}

/// TLS 1.2 AEAD 套件的密钥材料。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls12Keys {
    pub key: Vec<u8>,
    /// AES-GCM 为 4 字节，ChaCha20-Poly1305 为 12 字节。
    pub fixed_iv: Vec<u8>,
    pub aead: Aead,
}

impl Tls12Keys {
    /// 从 48 字节 master secret 派生客户端/服务端写密钥。
    ///
    /// 覆盖 AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 套件；CBC 不在此处。
    pub fn derive(
        legacy_material: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        suite: u16,
    ) -> Result<(Self, Self), String> {
        let (key_len, sha384, aead) = tls12_suite_spec(suite).ok_or_else(|| {
            format!(
                "unsupported TLS 1.2 cipher suite {} ({}); only AES-GCM and ChaCha20-Poly1305 suites are implemented",
                suite,
                suite_name(suite)
            )
        })?;
        if legacy_material.len() != 48 {
            return Err(format!(
                "TLS 1.2 master secret length {} is not 48",
                legacy_material.len()
            ));
        }
        let iv_len = match aead {
            Aead::ChaCha20Poly1305 => 12,
            Aead::Aes128Gcm | Aead::Aes256Gcm => 4,
        };
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(server_random);
        seed.extend_from_slice(client_random);
        let total = 2 * key_len + 2 * iv_len;
        let block = tls12_prf(legacy_material, b"key expansion", &seed, total, sha384);
        let client_key = block[..key_len].to_vec();
        let server_key = block[key_len..2 * key_len].to_vec();
        let client_iv = block[2 * key_len..2 * key_len + iv_len].to_vec();
        let server_iv = block[2 * key_len + iv_len..2 * key_len + 2 * iv_len].to_vec();
        Ok((
            Self {
                key: client_key,
                fixed_iv: client_iv,
                aead,
            },
            Self {
                key: server_key,
                fixed_iv: server_iv,
                aead,
            },
        ))
    }
}

impl Drop for Tls12Keys {
    fn drop(&mut self) {
        self.key.fill(0);
        self.fixed_iv.fill(0);
    }
}

fn tls12_suite_spec(suite: u16) -> Option<(usize, bool, Aead)> {
    match suite {
        // ECDHE_ECDSA / ECDHE_RSA / RSA / DHE_RSA with AES-128-GCM-SHA256
        0xc02b | 0xc02f | 0x009c | 0x009e => Some((16, false, Aead::Aes128Gcm)),
        // Same key exchange families with AES-256-GCM-SHA384
        0xc02c | 0xc030 | 0x009d | 0x009f => Some((32, true, Aead::Aes256Gcm)),
        // ECDHE_ECDSA / ECDHE_RSA / DHE_RSA with ChaCha20-Poly1305-SHA256
        0xcca8 | 0xcca9 | 0xccaa => Some((32, false, Aead::ChaCha20Poly1305)),
        _ => None,
    }
}

fn p_hash_sha256(prf_input: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut a = crate::tlsdecrypt::crypto::hmac_sha256(prf_input, seed).to_vec();
    while out.len() < len {
        let mut msg = Vec::with_capacity(a.len() + seed.len());
        msg.extend_from_slice(&a);
        msg.extend_from_slice(seed);
        out.extend_from_slice(&crate::tlsdecrypt::crypto::hmac_sha256(prf_input, &msg));
        a = crate::tlsdecrypt::crypto::hmac_sha256(prf_input, &a).to_vec();
    }
    out.truncate(len);
    out
}

fn p_hash_sha384(prf_input: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut a = crate::tlsdecrypt::crypto::hmac_sha384(prf_input, seed).to_vec();
    while out.len() < len {
        let mut msg = Vec::with_capacity(a.len() + seed.len());
        msg.extend_from_slice(&a);
        msg.extend_from_slice(seed);
        out.extend_from_slice(&crate::tlsdecrypt::crypto::hmac_sha384(prf_input, &msg));
        a = crate::tlsdecrypt::crypto::hmac_sha384(prf_input, &a).to_vec();
    }
    out.truncate(len);
    out
}

fn tls12_prf(prf_input: &[u8], label: &[u8], seed: &[u8], len: usize, sha384: bool) -> Vec<u8> {
    let mut full = Vec::with_capacity(label.len() + seed.len());
    full.extend_from_slice(label);
    full.extend_from_slice(seed);
    if sha384 {
        p_hash_sha384(prf_input, &full, len)
    } else {
        p_hash_sha256(prf_input, &full, len)
    }
}

/// TLS 1.2 单向解密状态。ChangeCipherSpec 之后的所有记录都用同一组写密钥。
#[derive(Debug, Clone)]
pub struct Tls12Direction {
    keys: Tls12Keys,
    seq: u64,
    active: bool,
    opened: u64,
    skipped: u64,
}

impl Tls12Direction {
    pub fn new(keys: Tls12Keys) -> Self {
        Self {
            keys,
            seq: 0,
            active: false,
            opened: 0,
            skipped: 0,
        }
    }

    pub fn open(&mut self, rec: &Record) -> Result<Option<Plaintext>, String> {
        if rec.content_type == 20 {
            if rec.payload == [1] {
                self.active = true;
                self.seq = 0;
            }
            return Ok(None);
        }
        if !self.active {
            self.skipped += 1;
            return Ok(None);
        }
        let (sealed, plaintext_len, nonce) = match self.keys.aead {
            Aead::Aes128Gcm | Aead::Aes256Gcm => {
                if rec.payload.len() < 24 {
                    return Err("TLS 1.2 GCM record shorter than explicit nonce + tag".into());
                }
                let iv = self
                    .keys
                    .fixed_iv
                    .get(..4)
                    .ok_or("TLS 1.2 AES-GCM fixed IV must be 4 bytes")?;
                let explicit = &rec.payload[..8];
                let sealed = &rec.payload[8..];
                let plaintext_len = sealed.len() - 16;
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(iv);
                nonce[4..].copy_from_slice(explicit);
                (sealed, plaintext_len, nonce)
            }
            Aead::ChaCha20Poly1305 => {
                if rec.payload.len() < 16 {
                    return Err("TLS 1.2 ChaCha20-Poly1305 record shorter than tag".into());
                }
                let iv: [u8; 12] = self
                    .keys
                    .fixed_iv
                    .as_slice()
                    .try_into()
                    .map_err(|_| "TLS 1.2 ChaCha20-Poly1305 fixed IV must be 12 bytes")?;
                let mut nonce = iv;
                for (slot, seq_byte) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
                    *slot ^= seq_byte;
                }
                (&rec.payload[..], rec.payload.len() - 16, nonce)
            }
        };
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&self.seq.to_be_bytes());
        aad[8] = rec.content_type;
        aad[9..11].copy_from_slice(&rec.version.to_be_bytes());
        aad[11..13].copy_from_slice(&(plaintext_len as u16).to_be_bytes());
        let pt = match self.keys.aead {
            Aead::Aes128Gcm | Aead::Aes256Gcm => aes_gcm_open(&self.keys.key, &nonce, &aad, sealed),
            Aead::ChaCha20Poly1305 => chacha20_poly1305_open(&self.keys.key, &nonce, &aad, sealed),
        }
        .map_err(|e| format!("TLS 1.2 record tag mismatch at sequence {}: {e}", self.seq))?;
        self.seq += 1;
        self.opened += 1;
        Ok(Some(Plaintext {
            content_type: rec.content_type,
            data: pt,
        }))
    }

    pub fn opened(&self) -> u64 {
        self.opened
    }

    pub fn skipped(&self) -> u64 {
        self.skipped
    }
}

/// 会话方向：按协商版本分派 TLS 1.3 / TLS 1.2 记录处理。
#[derive(Debug, Clone)]
pub enum Direction {
    Tls13(Tls13Direction),
    Tls12(Tls12Direction),
}

impl Direction {
    /// 兼容旧测试/调用方的 TLS 1.3 构造入口。
    pub fn new(keys: TrafficKeys) -> Self {
        Self::Tls13(Tls13Direction::new(keys))
    }

    pub fn new_tls12(keys: Tls12Keys) -> Self {
        Self::Tls12(Tls12Direction::new(keys))
    }

    pub fn open(&mut self, rec: &Record) -> Result<Option<Plaintext>, String> {
        match self {
            Self::Tls13(dir) => dir.open(rec),
            Self::Tls12(dir) => dir.open(rec),
        }
    }

    pub fn opened(&self) -> u64 {
        match self {
            Self::Tls13(dir) => dir.opened(),
            Self::Tls12(dir) => dir.opened(),
        }
    }

    pub fn skipped(&self) -> u64 {
        match self {
            Self::Tls13(dir) => dir.skipped(),
            Self::Tls12(dir) => dir.skipped(),
        }
    }
}

/// 一条已完成握手、可解密应用记录的 TLS 1.3 / TLS 1.2 会话。
#[derive(Debug, Clone)]
pub struct TlsSession {
    pub version: TlsVersion,
    pub client_random: [u8; 32],
    pub cipher_suite: u16,
    pub server_name: Option<String>,
    pub client: Direction,
    pub server: Direction,
}

impl TlsSession {
    /// 从两个方向的 TCP 重组流建立会话。
    ///
    /// TLS 1.3 需要 `CLIENT_TRAFFIC_SECRET_0` 与 `SERVER_TRAFFIC_SECRET_0`；
    /// TLS 1.2 需要 `CLIENT_RANDOM` 的 48 字节 master secret。
    pub fn from_streams(
        client_stream: &[u8],
        server_stream: &[u8],
        keylog: &KeyLog,
    ) -> Result<Self, String> {
        let ch = parse_client_hello(client_stream)?;
        let sh = parse_server_hello(server_stream)?;
        let entry = keylog
            .get(&ch.random)
            .ok_or_else(|| format!("keylog has no entry for client random {}", hex(&ch.random)))?;
        if tls12_suite_spec(sh.cipher_suite).is_some() {
            let master = entry
                .legacy_master
                .as_deref()
                .ok_or("keylog entry lacks CLIENT_RANDOM for TLS 1.2")?;
            let (client_keys, server_keys) =
                Tls12Keys::derive(master, &ch.random, &sh.random, sh.cipher_suite)?;
            return Ok(Self {
                version: TlsVersion::Tls12,
                client_random: ch.random,
                cipher_suite: sh.cipher_suite,
                server_name: ch.server_name,
                client: Direction::Tls12(Tls12Direction::new(client_keys)),
                server: Direction::Tls12(Tls12Direction::new(server_keys)),
            });
        }
        if !matches!(sh.cipher_suite, 0x1301..=0x1305) {
            return Err(format!(
                "unsupported TLS cipher suite {} ({}); supported: TLS 1.3 standard AEAD and TLS 1.2 AES-GCM/ChaCha20-Poly1305",
                sh.cipher_suite,
                suite_name(sh.cipher_suite)
            ));
        }
        let client_value = entry
            .client_app
            .as_deref()
            .ok_or("keylog entry lacks CLIENT_TRAFFIC_SECRET_0")?;
        let server_value = entry
            .server_app
            .as_deref()
            .ok_or("keylog entry lacks SERVER_TRAFFIC_SECRET_0")?;
        let client_keys = TrafficKeys::derive(client_value, sh.cipher_suite)?;
        let server_keys = TrafficKeys::derive(server_value, sh.cipher_suite)?;
        Ok(Self {
            version: TlsVersion::Tls13,
            client_random: ch.random,
            cipher_suite: sh.cipher_suite,
            server_name: ch.server_name,
            client: Direction::Tls13(Tls13Direction::new(client_keys)),
            server: Direction::Tls13(Tls13Direction::new(server_keys)),
        })
    }

    pub fn decrypt_client(&mut self, stream: &[u8]) -> Result<Vec<Plaintext>, String> {
        decrypt_stream(&mut self.client, stream)
    }

    pub fn decrypt_server(&mut self, stream: &[u8]) -> Result<Vec<Plaintext>, String> {
        decrypt_stream(&mut self.server, stream)
    }
}

fn decrypt_stream(dir: &mut Direction, bytes: &[u8]) -> Result<Vec<Plaintext>, String> {
    let mut out = Vec::new();
    for rec in parse_records(bytes)? {
        if let Some(pt) = dir.open(&rec)? {
            out.push(pt);
        }
    }
    Ok(out)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlsdecrypt::crypto::{aes_gcm_seal, chacha20_poly1305_seal};
    use crate::tlsdecrypt::keylog::{decode_hex, KeyLog};

    const RANDOM: &str = "cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7";
    const CLIENT_APP_TRAFFIC: &str =
        "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
    const SERVER_APP_TRAFFIC: &str =
        "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";

    const CLIENT_HELLO: &str = "\
16 03 01 00 c4 01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a
8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00
09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00
01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00
0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02
06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

    const SERVER_HELLO: &str = "\
16 03 03 00 5a 02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5
cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11
20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02
03 04";

    const CLIENT_APP: &str = "\
17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab
3f 2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d
ea e6 3a ee bb 21 69 49 15 e4";

    const SERVER_NST: &str = "\
17 03 03 00 de 3a 6b 8f 90 41 4a 97 d6 95 9c 34 87 68 0d e5 13 4a 2b 24 0e 6c ff ac 11 6e 95
d4 1d 6a f8 f6 b5 80 dc f3 d1 1d 63 c7 58 db 28 9a 01 59 40 25 2f 55 71 3e 06 1d c1 3e 07 88
91 a3 8e fb cf 57 53 ad 8e f1 70 ad 3c 73 53 d1 6d 9d a7 73 b9 ca 7f 2b 9f a1 b6 c0 d4 a3 d0
3f 75 e0 9c 30 ba 1e 62 97 2a c4 6f 75 f7 b9 81 be 63 43 9b 29 99 ce 13 06 46 15 13 98 91 d5
e4 c5 b4 06 f1 6e 3f c1 81 a7 7c a4 75 84 00 25 db 2f 0a 77 f8 1b 5a b0 5b 94 c0 13 46 75 5f
69 23 2c 86 51 9d 86 cb ee ac 87 aa c3 47 d1 43 f9 60 5d 64 f6 50 db 4d 02 3e 70 e9 52 ca 49
fe 51 37 12 1c 74 bc 26 97 68 7e 24 87 46 d6 df 35 30 05 f3 bc e1 86 96 12 9c 81 53 55 6b 3b
6c 67 79 b3 7b f1 59 85 68 4f";

    const SERVER_APP: &str = "\
17 03 03 00 43 2e 93 7e 11 ef 4a c7 40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b
36 e3 0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8 fc c4 9c 4b f2 e5 f0 a2 1c 00 47 c2 ab f3
32 54 0d d0 32 e1 67 c2 95 5d";

    const CLIENT_ALERT: &str = "\
17 03 03 00 13 c9 87 27 60 65 56 66 b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3";

    const SERVER_ALERT: &str = "\
17 03 03 00 13 b5 8f d6 71 66 eb f5 99 d2 47 20 cf be 7e fa 7a 88 64 a9";

    fn hexv(s: &str) -> Vec<u8> {
        decode_hex(&s.chars().filter(|c| !c.is_whitespace()).collect::<String>()).unwrap()
    }

    fn keylog() -> KeyLog {
        KeyLog::parse(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {RANDOM} {CLIENT_APP_TRAFFIC}\n\
             SERVER_TRAFFIC_SECRET_0 {RANDOM} {SERVER_APP_TRAFFIC}\n"
        ))
        .unwrap()
    }

    #[test]
    fn parses_hellos_from_rfc8448() {
        let ch = parse_client_hello(&hexv(CLIENT_HELLO)).unwrap();
        assert_eq!(hex(&ch.random), RANDOM);
        assert_eq!(ch.cipher_suites, vec![0x1301, 0x1303, 0x1302]);
        assert_eq!(ch.server_name.as_deref(), Some("server"));
        let sh = parse_server_hello(&hexv(SERVER_HELLO)).unwrap();
        assert_eq!(sh.cipher_suite, TLS_AES_128_GCM_SHA256);
        assert_eq!(
            hex(&sh.random),
            "a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928"
        );
    }

    #[test]
    fn decrypts_rfc8448_application_data_and_tickets() {
        let mut s =
            TlsSession::from_streams(&hexv(CLIENT_HELLO), &hexv(SERVER_HELLO), &keylog()).unwrap();
        assert_eq!(hex(&s.client_random), RANDOM);
        assert_eq!(s.server_name.as_deref(), Some("server"));

        let client = s
            .decrypt_client(&[hexv(CLIENT_HELLO), hexv(CLIENT_APP), hexv(CLIENT_ALERT)].concat())
            .unwrap();
        assert_eq!(client.len(), 2);
        assert_eq!(client[0].content_type, 23);
        assert_eq!(client[0].data, (0u8..=0x31).collect::<Vec<_>>());
        assert_eq!(client[1].content_type, 21);
        assert_eq!(client[1].data, vec![1, 0]);
        assert_eq!(s.client.opened(), 2);
        // 明文 ClientHello 不是 application_data，未进入解密尝试，因此 skipped 为 0。
        assert_eq!(s.client.skipped(), 0);

        let server = s
            .decrypt_server(
                &[
                    hexv(SERVER_HELLO),
                    hexv(SERVER_NST),
                    hexv(SERVER_APP),
                    hexv(SERVER_ALERT),
                ]
                .concat(),
            )
            .unwrap();
        assert_eq!(server.len(), 3);
        assert_eq!(server[0].content_type, 22);
        assert_eq!(server[0].data.len(), 205);
        assert_eq!(server[0].data[0], 4); // NewSessionTicket
        assert_eq!(server[1].content_type, 23);
        assert_eq!(server[1].data, (0u8..=0x31).collect::<Vec<_>>());
        assert_eq!(server[2].content_type, 21);
        assert_eq!(server[2].data, vec![1, 0]);
        assert_eq!(s.server.opened(), 3);
        assert_eq!(s.server.skipped(), 0);
    }

    #[test]
    fn tampering_after_first_record_is_an_error_not_silent_desync() {
        let mut s =
            TlsSession::from_streams(&hexv(CLIENT_HELLO), &hexv(SERVER_HELLO), &keylog()).unwrap();
        let mut app = hexv(CLIENT_APP);
        let last = app.len() - 1;
        app[last] ^= 1;
        // 先解出 seq 0，再让 seq 1 的标签失败：必须报错，不能把后续记录错位解成垃圾。
        let err = s
            .decrypt_client(&[hexv(CLIENT_APP), app].concat())
            .unwrap_err();
        assert!(err.contains("sequence 1"), "{err}");
        assert!(err.contains("tag mismatch"), "{err}");
    }

    #[test]
    fn unsupported_suite_is_reported_explicitly() {
        let e = TrafficKeys::derive(&[0u8; 32], TLS_AES_256_GCM_SHA384).unwrap_err();
        assert!(e.contains("length 32"), "{e}");
        let e = TrafficKeys::derive(&[0u8; 48], TLS_AES_128_GCM_SHA256).unwrap_err();
        assert!(e.contains("length 48"), "{e}");
        let e = TrafficKeys::derive(&[0u8; 48], TLS_CHACHA20_POLY1305_SHA256).unwrap_err();
        assert!(e.contains("length 48"), "{e}");
        let e = TrafficKeys::derive(&[0u8; 32], 0xc02b).unwrap_err();
        assert!(e.contains("unsupported"), "{e}");
        let keys = TrafficKeys::derive(&[0u8; 48], TLS_AES_256_GCM_SHA384).unwrap();
        assert_eq!(keys.key.len(), 32);
        assert_eq!(keys.aead, Aead::Aes256Gcm);
        let keys = TrafficKeys::derive(&[0u8; 32], TLS_CHACHA20_POLY1305_SHA256).unwrap();
        assert_eq!(keys.key.len(), 32);
        assert_eq!(keys.aead, Aead::ChaCha20Poly1305);
    }

    #[test]
    fn aes256_gcm_record_roundtrip() {
        let keys = TrafficKeys::derive(&[0x42u8; 48], TLS_AES_256_GCM_SHA384).unwrap();
        let mut nonce = keys.iv;
        // 第一条应用记录 seq=0；nonce = iv XOR seq。
        for (i, b) in 0u64.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        let mut inner = b"hello".to_vec();
        inner.push(23); // TLSInnerPlaintext.content_type
        let ct_len = inner.len() + 16;
        let header = [23, 3, 3, (ct_len >> 8) as u8, ct_len as u8];
        let sealed = aes_gcm_seal(&keys.key, &nonce, &header, &inner).unwrap();
        let rec = Record {
            content_type: 23,
            version: 0x0303,
            payload: sealed,
            header,
        };
        let mut dir = Direction::new(keys);
        let pt = dir.open(&rec).unwrap().unwrap();
        assert_eq!(pt.content_type, 23);
        assert_eq!(pt.data, b"hello");
        assert_eq!(dir.opened(), 1);
        assert_eq!(dir.skipped(), 0);
    }

    #[test]
    fn chacha20_poly1305_record_roundtrip() {
        let keys = TrafficKeys::derive(&[0x42u8; 32], TLS_CHACHA20_POLY1305_SHA256).unwrap();
        let nonce = keys.iv;
        let mut inner = b"chacha".to_vec();
        inner.push(23);
        let ct_len = inner.len() + 16;
        let header = [23, 3, 3, (ct_len >> 8) as u8, ct_len as u8];
        let sealed = chacha20_poly1305_seal(&keys.key, &nonce, &header, &inner).unwrap();
        let rec = Record {
            content_type: 23,
            version: 0x0303,
            payload: sealed,
            header,
        };
        let mut dir = Direction::new(keys);
        let pt = dir.open(&rec).unwrap().unwrap();
        assert_eq!(pt.content_type, 23);
        assert_eq!(pt.data, b"chacha");
        assert_eq!(dir.opened(), 1);
        assert_eq!(dir.skipped(), 0);
    }

    #[test]
    fn tls12_key_block_matches_independent_hmac() {
        let master: Vec<u8> = (1u8..=48).collect();
        let client_random = [0x11u8; 32];
        let server_random = [0x22u8; 32];

        let (client, server) =
            Tls12Keys::derive(&master, &client_random, &server_random, 0xc02f).unwrap();
        assert_eq!(client.key, hexv("21444f2064b5b63368804c604b6a6b3e"));
        assert_eq!(server.key, hexv("3ae6365fea4589989fbf82a7cdcc2691"));
        assert_eq!(client.fixed_iv, hexv("6e9a1078"));
        assert_eq!(server.fixed_iv, hexv("249b1d32"));

        let (client, server) =
            Tls12Keys::derive(&master, &client_random, &server_random, 0xc030).unwrap();
        assert_eq!(
            client.key,
            hexv("bcb9889cde17b80c916d7c9a157afd89f42582ec06828f9a73c86e366106c95e")
        );
        assert_eq!(
            server.key,
            hexv("7d719c664fa2f22014d832ee7baccb90cc36c9bed8b45035cf2f2ac56f9068e3")
        );
        assert_eq!(client.fixed_iv, hexv("05fa26a0"));
        assert_eq!(server.fixed_iv, hexv("562abe59"));
    }

    #[test]
    fn tls12_chacha20_key_block_matches_independent_hmac() {
        let master: Vec<u8> = (1u8..=48).collect();
        let (client, server) =
            Tls12Keys::derive(&master, &[0x11u8; 32], &[0x22u8; 32], 0xcca8).unwrap();
        assert_eq!(client.aead, Aead::ChaCha20Poly1305);
        assert_eq!(server.aead, Aead::ChaCha20Poly1305);
        assert_eq!(
            client.key,
            hexv("21444f2064b5b63368804c604b6a6b3e3ae6365fea4589989fbf82a7cdcc2691")
        );
        assert_eq!(
            server.key,
            hexv("6e9a1078249b1d32163e17bd2d4e358f13a1ef98cdeb95d589e232dc0d335779")
        );
        assert_eq!(client.fixed_iv, hexv("41a56e25208fe50482870091"));
        assert_eq!(server.fixed_iv, hexv("5903d34b4c72f6c179ec59b8"));
    }

    fn tls12_record(keys: &Tls12Keys, seq: u64, content_type: u8, data: &[u8]) -> Record {
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
        let header = [content_type, 3, 3, (len >> 8) as u8, len as u8];
        Record {
            content_type,
            version: 0x0303,
            payload,
            header,
        }
    }

    #[test]
    fn tls12_decrypts_after_ccs_and_advances_sequence() {
        let master: Vec<u8> = (1u8..=48).collect();
        let (client_keys, _) =
            Tls12Keys::derive(&master, &[0x11u8; 32], &[0x22u8; 32], 0xc02f).unwrap();
        let mut dir = Tls12Direction::new(client_keys.clone());
        let ccs = Record {
            content_type: 20,
            version: 0x0303,
            payload: vec![1],
            header: [20, 3, 3, 0, 1],
        };
        assert!(dir.open(&ccs).unwrap().is_none());
        let finished = tls12_record(&client_keys, 0, 22, &[0x14, 0, 0, 12]);
        let pt = dir.open(&finished).unwrap().unwrap();
        assert_eq!(pt.content_type, 22);
        assert_eq!(pt.data, [0x14, 0, 0, 12]);
        let app = tls12_record(&client_keys, 1, 23, b"GET / HTTP/1.1\r\n\r\n");
        let pt = dir.open(&app).unwrap().unwrap();
        assert_eq!(pt.content_type, 23);
        assert_eq!(pt.data, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(dir.opened(), 2);
        assert_eq!(dir.skipped(), 0);
    }

    #[test]
    fn tls12_aes256_gcm_record_roundtrip() {
        let master: Vec<u8> = (1u8..=48).collect();
        let (client_keys, _) =
            Tls12Keys::derive(&master, &[0x11u8; 32], &[0x22u8; 32], 0xc030).unwrap();
        let mut dir = Tls12Direction::new(client_keys.clone());
        let ccs = Record {
            content_type: 20,
            version: 0x0303,
            payload: vec![1],
            header: [20, 3, 3, 0, 1],
        };
        assert!(dir.open(&ccs).unwrap().is_none());
        let app = tls12_record(&client_keys, 0, 23, b"legacy aes256");
        let pt = dir.open(&app).unwrap().unwrap();
        assert_eq!(pt.data, b"legacy aes256");
        assert_eq!(dir.opened(), 1);
    }

    #[test]
    fn tls12_chacha20_record_roundtrip() {
        let master: Vec<u8> = (1u8..=48).collect();
        let (client_keys, _) =
            Tls12Keys::derive(&master, &[0x11u8; 32], &[0x22u8; 32], 0xcca8).unwrap();
        let mut dir = Tls12Direction::new(client_keys.clone());
        let ccs = Record {
            content_type: 20,
            version: 0x0303,
            payload: vec![1],
            header: [20, 3, 3, 0, 1],
        };
        assert!(dir.open(&ccs).unwrap().is_none());
        let finished = tls12_record(&client_keys, 0, 22, &[0x14, 0, 0, 12]);
        assert_eq!(dir.open(&finished).unwrap().unwrap().content_type, 22);
        let app = tls12_record(&client_keys, 1, 23, b"legacy chacha");
        let pt = dir.open(&app).unwrap().unwrap();
        assert_eq!(pt.content_type, 23);
        assert_eq!(pt.data, b"legacy chacha");
        assert_eq!(dir.opened(), 2);
        assert_eq!(dir.skipped(), 0);
    }

    #[test]
    fn tls12_chacha20_record_matches_independent_aead_vector() {
        let keys = Tls12Keys {
            key: hexv("21444f2064b5b63368804c604b6a6b3e3ae6365fea4589989fbf82a7cdcc2691"),
            fixed_iv: hexv("41a56e25208fe50482870091"),
            aead: Aead::ChaCha20Poly1305,
        };
        // RFC 7905 记录：nonce = fixed_iv XOR (0^4 || seq)，AAD 与 AES-GCM 相同。
        // 期望值由 Python cryptography 的 ChaCha20Poly1305 独立生成。
        let expected = hexv("7f082a7971b281c0b10293d9b50cfc85c6d146db9bffee766c80eb01afb456890c60");
        let encoded = tls12_record(&keys, 1, 23, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(encoded.payload, expected);
        let finished = tls12_record(&keys, 0, 22, &[0x14, 0, 0, 12]);

        let mut dir = Tls12Direction::new(keys);
        let ccs = Record {
            content_type: 20,
            version: 0x0303,
            payload: vec![1],
            header: [20, 3, 3, 0, 1],
        };
        assert!(dir.open(&ccs).unwrap().is_none());
        assert!(dir.open(&finished).unwrap().is_some());
        let pt = dir.open(&encoded).unwrap().unwrap();
        assert_eq!(pt.content_type, 23);
        assert_eq!(pt.data, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn tls12_tampering_is_an_error() {
        let master: Vec<u8> = (1u8..=48).collect();
        let (client_keys, _) =
            Tls12Keys::derive(&master, &[0x11u8; 32], &[0x22u8; 32], 0xc02f).unwrap();
        let mut dir = Tls12Direction::new(client_keys.clone());
        let ccs = Record {
            content_type: 20,
            version: 0x0303,
            payload: vec![1],
            header: [20, 3, 3, 0, 1],
        };
        assert!(dir.open(&ccs).unwrap().is_none());
        let mut rec = tls12_record(&client_keys, 0, 23, b"hello");
        let last = rec.payload.len() - 1;
        rec.payload[last] ^= 1;
        assert!(dir.open(&rec).is_err());
    }

    #[test]
    fn record_header_length_is_preserved_for_aad() {
        let recs = parse_records(&hexv(CLIENT_APP)).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].header, [23, 3, 3, 0, 0x43]);
        assert_eq!(recs[0].payload.len(), 0x43);
        assert_eq!(recs[0].raw(), hexv(CLIENT_APP));
        assert!(parse_records(&hexv(CLIENT_APP)[..40]).is_err());
    }
}
