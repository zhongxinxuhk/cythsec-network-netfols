//! NSS key log 解析。
//!
//! 只读取运维方显式提供的文件；不生成、不导出、不推断任何密钥。
//! 文件权限在加载时强制为 0600（Unix），避免密钥日志被同机其他用户读取。

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// 单个 client random 对应的 TLS 1.3 流量密钥或 TLS 1.2 主密钥。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    pub client_app: Option<Vec<u8>>,
    pub server_app: Option<Vec<u8>>,
    pub client_handshake: Option<Vec<u8>>,
    pub server_handshake: Option<Vec<u8>>,
    pub client_early: Option<Vec<u8>>,
    /// TLS 1.2 的 `CLIENT_RANDOM` 条目（48 字节 master secret）。
    pub legacy_master: Option<Vec<u8>>,
}

impl Entry {
    fn slot(&mut self, label: &str) -> Option<&mut Option<Vec<u8>>> {
        match label {
            "CLIENT_TRAFFIC_SECRET_0" => Some(&mut self.client_app),
            "SERVER_TRAFFIC_SECRET_0" => Some(&mut self.server_app),
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => Some(&mut self.client_handshake),
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => Some(&mut self.server_handshake),
            "CLIENT_EARLY_TRAFFIC_SECRET" => Some(&mut self.client_early),
            "CLIENT_RANDOM" => Some(&mut self.legacy_master),
            _ => None,
        }
    }

    pub fn has_application_traffic(&self) -> bool {
        self.client_app.is_some() && self.server_app.is_some()
    }

    pub fn has_legacy_master(&self) -> bool {
        self.legacy_master.is_some()
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        fn wipe(slot: &mut Option<Vec<u8>>) {
            if let Some(value) = slot {
                value.fill(0);
            }
        }
        wipe(&mut self.client_app);
        wipe(&mut self.server_app);
        wipe(&mut self.client_handshake);
        wipe(&mut self.server_handshake);
        wipe(&mut self.client_early);
        wipe(&mut self.legacy_master);
    }
}

/// 解析后的 key log。按 client random 建索引。
#[derive(Debug, Clone, Default)]
pub struct KeyLog {
    entries: BTreeMap<[u8; 32], Entry>,
    ignored_lines: usize,
}

impl KeyLog {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut log = Self::default();
        for (line_no, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let label = parts.next().unwrap_or("");
            let random_hex = match parts.next() {
                Some(v) => v,
                None => {
                    return Err(format!(
                        "keylog line {}: missing client random",
                        line_no + 1
                    ));
                }
            };
            let value_hex = match parts.next() {
                Some(v) => v,
                None => {
                    return Err(format!("keylog line {}: missing value", line_no + 1));
                }
            };
            if parts.next().is_some() {
                return Err(format!("keylog line {}: trailing fields", line_no + 1));
            }
            let mut entry = Entry::default();
            if entry.slot(label).is_none() {
                // 其它标签（例如 EXPORTER_SECRET）不参与应用记录解密；
                // 忽略而不是报错，便于直接使用 OpenSSL 原始文件。
                log.ignored_lines += 1;
                continue;
            }
            let random = decode_hex_array::<32>(random_hex)
                .map_err(|e| format!("keylog line {}: client random: {e}", line_no + 1))?;
            let value = decode_hex(value_hex)
                .map_err(|e| format!("keylog line {}: value: {e}", line_no + 1))?;
            let expected_len = if label == "CLIENT_RANDOM" { 48 } else { 0 };
            if expected_len != 0 && value.len() != expected_len {
                return Err(format!(
                    "keylog line {}: value length {} is not {} for {label}",
                    line_no + 1,
                    value.len(),
                    expected_len
                ));
            }
            if expected_len == 0 && value.len() != 32 && value.len() != 48 {
                return Err(format!(
                    "keylog line {}: value length {} is not 32 or 48",
                    line_no + 1,
                    value.len()
                ));
            }
            let existing = log.entries.entry(random).or_default();
            let slot = existing.slot(label).expect("checked above");
            if let Some(prev) = slot {
                if prev != &value {
                    return Err(format!(
                        "keylog line {}: conflicting duplicate {label} for same client random",
                        line_no + 1
                    ));
                }
            } else {
                *slot = Some(value);
            }
        }
        if log.entries.is_empty() {
            return Err("keylog contains no application traffic or legacy master entries".into());
        }
        Ok(log)
    }

    /// 读取并校验权限。Unix 下拒绝 group/other 可读写的文件与符号链接。
    pub fn load(path: &Path) -> Result<Self, String> {
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("stat keylog {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "keylog {} is a symlink; refusing to follow",
                path.display()
            ));
        }
        if !meta.is_file() {
            return Err(format!("keylog {} is not a regular file", path.display()));
        }
        if meta.len() > 4 * 1024 * 1024 {
            return Err(format!("keylog {} is larger than 4 MiB", path.display()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "keylog {} has mode {:03o}; require 0600 (or stricter)",
                    path.display(),
                    mode
                ));
            }
        }
        let bytes = fs::read(path).map_err(|e| format!("read keylog {}: {e}", path.display()))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| format!("keylog {} is not valid UTF-8", path.display()))?;
        Self::parse(text)
    }

    pub fn get(&self, random: &[u8; 32]) -> Option<&Entry> {
        self.entries.get(random)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn ignored_lines(&self) -> usize {
        self.ignored_lines
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = hex_nibble(b[i])?;
        let lo = hex_nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn decode_hex_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = decode_hex(s)?;
    if v.len() != N {
        return Err(format!("expected {} bytes, got {}", N, v.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit {:?}", b as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM: &str = "cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7";
    const CLIENT_APP: &str = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
    const SERVER_APP: &str = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
    const LEGACY_MASTER: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";

    #[test]
    fn parses_rfc8448_style_file_and_ignores_unknown_labels() {
        let text = format!(
            "# comment\nCLIENT_HANDSHAKE_TRAFFIC_SECRET {RANDOM} {CLIENT_APP}\n\
             SERVER_HANDSHAKE_TRAFFIC_SECRET {RANDOM} {SERVER_APP}\n\
             CLIENT_TRAFFIC_SECRET_0 {RANDOM} {CLIENT_APP}\n\
             SERVER_TRAFFIC_SECRET_0 {RANDOM} {SERVER_APP}\n\
             CLIENT_RANDOM {RANDOM} {LEGACY_MASTER}\n\
             EXPORTER_SECRET {RANDOM} {CLIENT_APP}\n"
        );
        let log = KeyLog::parse(&text).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log.ignored_lines(), 1);
        let random = decode_hex_array::<32>(RANDOM).unwrap();
        let e = log.get(&random).unwrap();
        assert_eq!(
            e.client_app.as_deref(),
            Some(&decode_hex(CLIENT_APP).unwrap()[..])
        );
        assert_eq!(
            e.server_app.as_deref(),
            Some(&decode_hex(SERVER_APP).unwrap()[..])
        );
        assert!(e.has_application_traffic());
        assert!(e.has_legacy_master());
        assert_eq!(
            e.legacy_master.as_deref(),
            Some(&decode_hex(LEGACY_MASTER).unwrap()[..])
        );
    }

    #[test]
    fn rejects_malformed_and_duplicate_conflicts() {
        assert!(KeyLog::parse("CLIENT_TRAFFIC_SECRET_0 zz 00").is_err());
        let a = format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM} {CLIENT_APP}\n");
        let b = format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM} {SERVER_APP}\n");
        assert!(KeyLog::parse(&(a.clone() + &b)).is_err());
        assert!(KeyLog::parse(&(a.clone() + &a)).is_ok());
        assert!(KeyLog::parse("CLIENT_TRAFFIC_SECRET_0").is_err());
        assert!(KeyLog::parse(&format!("CLIENT_RANDOM {RANDOM} {CLIENT_APP}\n")).is_err());
        assert!(KeyLog::parse("CLIENT_TRAFFIC_SECRET_0 xx yy").is_err());
        assert!(KeyLog::parse("").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn load_requires_private_permissions_and_regular_file() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cythsec-keylog-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.log");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM} {CLIENT_APP}\n").as_bytes())
            .unwrap();
        drop(f);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(KeyLog::load(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(KeyLog::load(&path).unwrap().len(), 1);
        #[cfg(unix)]
        {
            let link = dir.join("link.log");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(KeyLog::load(&link).is_err());
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
