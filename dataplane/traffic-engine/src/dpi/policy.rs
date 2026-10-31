// dpi/policy.rs —— DPI 模块开关、检测强度与 TLS 解密配置。
//
// 为什么策略必须进数据面而不是只写在控制台：
//   "关掉某类 DPI"如果只是界面上的一个布尔值，而每包仍然照常解析，那它既没有
//   省下开销，也无法解释"为什么这条记录没有应用结论"。因此策略在
//   `identify_with_policy` 里逐模块裁决，并在流水线里决定喂多少字节。
//
// 三种强度不是营销档位，而是**可判定的行为差异**：
//   off      —— 一次检测器都不调用；记录写 `not_inspected`，不写 `unknown`。
//   basic    —— 只跑 TLS/HTTP/DNS 三个轻量检测器，窗口 128 字节。
//   standard —— 全部已启用模块，窗口沿用调用方上限（CLI 默认 512）。
//   deep     —— 窗口至少 4096 字节；配置了密钥日志时尝试解密 TLS 1.3。
//
// 模块键与 `AppId` 一一对应；同一个检测器覆盖多个目录 ID 时（例如 TLS 1.2/1.3
// 共用 ClientHello 解析）只给一个开关，不造三个看起来独立、实际同生共死的假开关。

use std::collections::BTreeMap;
use std::path::Path;

use super::types::AppId;

/// 检测强度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intensity {
    Off,
    Basic,
    Standard,
    Deep,
}

impl Intensity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Intensity::Off => "off",
            Intensity::Basic => "basic",
            Intensity::Standard => "standard",
            Intensity::Deep => "deep",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "off" => Ok(Intensity::Off),
            "basic" => Ok(Intensity::Basic),
            "standard" => Ok(Intensity::Standard),
            "deep" => Ok(Intensity::Deep),
            _ => Err(format!(
                "未知 DPI 强度 `{value}`（可选 off/basic/standard/deep）"
            )),
        }
    }
}

/// TLS 解密配置。
///
/// 只接受运维方提供的 NSS key log（`SSLKEYLOGFILE` 格式）。本模块不做主动探测、
/// 不导出会话密钥、不尝试破解密码学；没有密钥时保持"只读可见字段"的既有边界。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsDecryptPolicy {
    pub enabled: bool,
    pub keylog_file: Option<String>,
}

impl TlsDecryptPolicy {
    /// 配了开关但没有可读文件时，解密**不生效**；返回 `false` 而不是猜一个默认路径。
    pub fn active(&self) -> bool {
        self.enabled
            && self
                .keylog_file
                .as_deref()
                .is_some_and(|path| !path.trim().is_empty())
    }
}

/// 完整的 DPI 策略。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpiPolicy {
    pub enabled: bool,
    pub intensity: Intensity,
    /// 显式窗口覆盖；`None` 表示按强度取默认。
    pub inspect_bytes: Option<usize>,
    /// 模块键 → 是否启用。缺省项按目录默认值（true）。
    pub modules: BTreeMap<String, bool>,
    pub tls_decrypt: TlsDecryptPolicy,
}

impl Default for DpiPolicy {
    fn default() -> Self {
        let modules = ALL_MODULE_KEYS
            .iter()
            .map(|key| ((*key).to_string(), true))
            .collect();
        Self {
            enabled: true,
            intensity: Intensity::Standard,
            inspect_bytes: None,
            modules,
            tls_decrypt: TlsDecryptPolicy::default(),
        }
    }
}

impl DpiPolicy {
    pub fn is_off(&self) -> bool {
        !self.enabled || self.intensity == Intensity::Off
    }

    /// 模块是否参与本包裁决。`off` 优先级最高；`basic` 只放行三个轻量检测器。
    pub fn module_enabled(&self, key: &str) -> bool {
        if self.is_off() {
            return false;
        }
        if self.intensity == Intensity::Basic && !matches!(key, "tls" | "http" | "dns") {
            return false;
        }
        self.modules.get(key).copied().unwrap_or(true)
    }

    /// 实际喂给 DPI 的字节数。`base` 是调用方上限（CLI `--inspect-bytes`）。
    ///
    /// basic 只会**缩小**窗口，standard 沿用，deep 只会**放大**：强度是下限/上限
    /// 语义，不是把调用方明确设置的 512 悄悄改成 128。
    pub fn effective_inspect_bytes(&self, base: usize) -> usize {
        if self.is_off() {
            return 0;
        }
        if let Some(n) = self.inspect_bytes {
            return n;
        }
        match self.intensity {
            Intensity::Off => 0,
            Intensity::Basic => base.min(128),
            Intensity::Standard => base,
            Intensity::Deep => base.max(4096),
        }
    }

    /// 只有 deep + 显式开关 + 非空密钥日志三者同时成立，才尝试解密。
    pub fn decrypt_tls(&self) -> bool {
        !self.is_off() && self.intensity == Intensity::Deep && self.tls_decrypt.active()
    }

    /// 被显式关闭的模块数（不含 basic 的隐式过滤）。
    pub fn disabled_module_count(&self) -> usize {
        self.modules.values().filter(|enabled| !**enabled).count()
    }

    pub fn summary(&self) -> String {
        format!(
            "enabled={} intensity={} inspect_bytes={} modules_disabled={} tls_decrypt={}",
            self.enabled,
            self.intensity.as_str(),
            self.effective_inspect_bytes(super::DEFAULT_INSPECT_BYTES),
            self.disabled_module_count(),
            self.decrypt_tls()
        )
    }

    /// 从 JSON 文本加载。字段白名单严格校验：拼错的开关必须报错，不能静默变成默认值。
    pub fn from_json(text: &str) -> Result<Self, String> {
        let root = json::parse(text)?;
        let object = root.as_object().ok_or("DPI 策略必须是 JSON 对象")?;
        let mut policy = DpiPolicy::default();
        for (key, value) in object {
            match key.as_str() {
                "schema_version" => {
                    let version = value.as_u64().ok_or("schema_version 必须是整数")?;
                    if version != 1 {
                        return Err(format!("不支持的 DPI 策略 schema_version={version}"));
                    }
                }
                "enabled" => {
                    policy.enabled = value.as_bool().ok_or("enabled 必须是布尔值")?;
                }
                "intensity" => {
                    let text = value.as_str().ok_or("intensity 必须是字符串")?;
                    policy.intensity = Intensity::parse(text)?;
                }
                "inspect_bytes" => {
                    if value.is_null() {
                        policy.inspect_bytes = None;
                    } else {
                        let n = value.as_u64().ok_or("inspect_bytes 必须是整数或 null")?;
                        if !(64..=65536).contains(&n) {
                            return Err(format!("inspect_bytes={n} 超出 64..=65536"));
                        }
                        policy.inspect_bytes = Some(n as usize);
                    }
                }
                "modules" => {
                    let modules = value.as_object().ok_or("modules 必须是对象")?;
                    for (name, enabled) in modules {
                        if !is_known_module(name) {
                            return Err(format!("未知 DPI 模块 `{name}`"));
                        }
                        let enabled = enabled
                            .as_bool()
                            .ok_or_else(|| format!("模块 `{name}` 的开关必须是布尔值"))?;
                        policy.modules.insert(name.clone(), enabled);
                    }
                }
                "tls_decrypt" => {
                    let object = value.as_object().ok_or("tls_decrypt 必须是对象")?;
                    for (name, item) in object {
                        match name.as_str() {
                            "enabled" => {
                                policy.tls_decrypt.enabled =
                                    item.as_bool().ok_or("tls_decrypt.enabled 必须是布尔值")?;
                            }
                            "keylog_file" => {
                                let path = item
                                    .as_str()
                                    .ok_or("tls_decrypt.keylog_file 必须是字符串或 null")?;
                                policy.tls_decrypt.keylog_file = if path.is_empty() {
                                    None
                                } else {
                                    Some(path.to_string())
                                };
                            }
                            other => return Err(format!("未知 tls_decrypt 字段 `{other}`")),
                        }
                    }
                }
                other => return Err(format!("未知 DPI 策略字段 `{other}`")),
            }
        }
        Ok(policy)
    }

    /// 从文件加载；读取失败或内容非法都返回带路径的错误，由调用方致命退出。
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("读取 DPI 策略 {} 失败: {error}", path.display()))?;
        Self::from_json(&text)
            .map_err(|error| format!("解析 DPI 策略 {} 失败: {error}", path.display()))
    }

    /// 生成与 `from_json` 对称的 JSON（控制台/测试共用；字段顺序固定）。
    pub fn to_json(&self) -> String {
        let mut modules: Vec<(&String, &bool)> = self.modules.iter().collect();
        modules.sort_by(|a, b| a.0.cmp(b.0));
        let modules = modules
            .into_iter()
            .map(|(key, enabled)| format!("{}:{}", quote(key), enabled))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"schema_version\":1,\"enabled\":{},\"intensity\":{},\"inspect_bytes\":{},\"modules\":{{{}}},\"tls_decrypt\":{{\"enabled\":{},\"keylog_file\":{}}}}}",
            self.enabled,
            quote(self.intensity.as_str()),
            self.inspect_bytes
                .map(|n| n.to_string())
                .unwrap_or_else(|| "null".to_string()),
            modules,
            self.tls_decrypt.enabled,
            self.tls_decrypt
                .keylog_file
                .as_deref()
                .map(quote)
                .unwrap_or_else(|| "null".to_string())
        )
    }
}

fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `AppId` → 模块键。`Unknown` 没有模块，返回空串。
pub const fn module_key(app: AppId) -> &'static str {
    match app {
        AppId::Tls => "tls",
        AppId::Http => "http",
        AppId::Dns => "dns",
        AppId::Dhcpv4 => "dhcpv4",
        AppId::Dhcpv6 => "dhcpv6",
        AppId::Mdns => "mdns",
        AppId::Dot => "dot",
        AppId::Doh => "doh",
        AppId::Smtp => "smtp",
        AppId::Ftp => "ftp",
        AppId::Quic => "quic",
        AppId::Ssh => "ssh",
        AppId::WireGuard => "wireguard",
        AppId::Ikev1 => "ikev1",
        AppId::Ikev2 => "ikev2",
        AppId::Esp => "esp",
        AppId::Ah => "ah",
        AppId::Gre => "gre",
        AppId::Ipip => "ipip",
        AppId::Ipv6ip => "ipv6-in-ip",
        AppId::Etherip => "etherip",
        AppId::L2tp => "l2tp",
        AppId::Pptp => "pptp",
        AppId::Vxlan => "vxlan",
        AppId::Geneve => "geneve",
        AppId::OpenVpn => "openvpn",
        AppId::Socks4 => "socks4",
        AppId::Socks5 => "socks5",
        AppId::Dtls => "dtls",
        AppId::Tlcp => "tlcp",
        AppId::Unknown => "",
    }
}

pub const ALL_MODULE_KEYS: &[&str] = &[
    "tls",
    "http",
    "dns",
    "dhcpv4",
    "dhcpv6",
    "mdns",
    "smtp",
    "ftp",
    "dot",
    "doh",
    "quic",
    "ssh",
    "wireguard",
    "ikev1",
    "ikev2",
    "esp",
    "ah",
    "gre",
    "ipip",
    "ipv6-in-ip",
    "etherip",
    "l2tp",
    "pptp",
    "vxlan",
    "geneve",
    "openvpn",
    "socks4",
    "socks5",
    "dtls",
    "tlcp",
];

pub fn is_known_module(key: &str) -> bool {
    ALL_MODULE_KEYS.contains(&key)
}

/// 极小的 JSON 子集解析器：只服务策略文件，不引入第三方依赖。
///
/// 支持 object/array/string/number/bool/null，深度上限 32。拒绝尾随字符和
/// 未转义控制字符；策略文件不需要的 `\u` 代理对按单码点处理（路径/键名足够）。
mod json {
    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Null,
        Bool(bool),
        Number(f64),
        String(String),
        Array(Vec<Value>),
        Object(Vec<(String, Value)>),
    }

    impl Value {
        pub fn is_null(&self) -> bool {
            matches!(self, Value::Null)
        }
        pub fn as_bool(&self) -> Option<bool> {
            match self {
                Value::Bool(v) => Some(*v),
                _ => None,
            }
        }
        pub fn as_u64(&self) -> Option<u64> {
            match self {
                Value::Number(v) if v.is_finite() && *v >= 0.0 && v.fract() == 0.0 => {
                    if *v <= u64::MAX as f64 {
                        Some(*v as u64)
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
        pub fn as_str(&self) -> Option<&str> {
            match self {
                Value::String(v) => Some(v),
                _ => None,
            }
        }
        pub fn as_object(&self) -> Option<&[(String, Value)]> {
            match self {
                Value::Object(v) => Some(v),
                _ => None,
            }
        }
        #[cfg(test)]
        pub fn as_array(&self) -> Option<&[Value]> {
            match self {
                Value::Array(v) => Some(v),
                _ => None,
            }
        }
    }

    pub fn parse(input: &str) -> Result<Value, String> {
        let mut parser = Parser {
            bytes: input.as_bytes(),
            pos: 0,
        };
        parser.ws();
        let value = parser.value(0)?;
        parser.ws();
        if parser.pos != parser.bytes.len() {
            return Err(format!("JSON 尾随内容位于字节 {}", parser.pos));
        }
        Ok(value)
    }

    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Parser<'a> {
        fn ws(&mut self) {
            while matches!(self.bytes.get(self.pos), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                self.pos += 1;
            }
        }

        fn value(&mut self, depth: usize) -> Result<Value, String> {
            if depth > 32 {
                return Err("JSON 嵌套超过 32 层".to_string());
            }
            match self.bytes.get(self.pos).copied() {
                None => Err("JSON 意外结束".to_string()),
                Some(b'n') => {
                    self.literal("null")?;
                    Ok(Value::Null)
                }
                Some(b't') => {
                    self.literal("true")?;
                    Ok(Value::Bool(true))
                }
                Some(b'f') => {
                    self.literal("false")?;
                    Ok(Value::Bool(false))
                }
                Some(b'"') => Ok(Value::String(self.string()?)),
                Some(b'[') => self.array(depth),
                Some(b'{') => self.object(depth),
                Some(b'-' | b'0'..=b'9') => self.number(),
                Some(c) => Err(format!("JSON 非法字符 0x{c:02x} 位于字节 {}", self.pos)),
            }
        }

        fn literal(&mut self, want: &str) -> Result<(), String> {
            if self.bytes[self.pos..].starts_with(want.as_bytes()) {
                self.pos += want.len();
                Ok(())
            } else {
                Err(format!("JSON 期望 `{want}` 位于字节 {}", self.pos))
            }
        }

        fn string(&mut self) -> Result<String, String> {
            self.pos += 1; // opening quote
            let mut out: Vec<u8> = Vec::new();
            loop {
                let byte = *self
                    .bytes
                    .get(self.pos)
                    .ok_or_else(|| "JSON 字符串未结束".to_string())?;
                match byte {
                    b'"' => {
                        self.pos += 1;
                        return String::from_utf8(out)
                            .map_err(|_| "JSON 字符串不是 UTF-8".to_string());
                    }
                    b'\\' => {
                        self.pos += 1;
                        let esc = *self
                            .bytes
                            .get(self.pos)
                            .ok_or_else(|| "JSON 转义未结束".to_string())?;
                        match esc {
                            b'"' => out.push(b'"'),
                            b'\\' => out.push(b'\\'),
                            b'/' => out.push(b'/'),
                            b'b' => out.push(8),
                            b'f' => out.push(12),
                            b'n' => out.push(b'\n'),
                            b'r' => out.push(b'\r'),
                            b't' => out.push(b'\t'),
                            b'u' => {
                                let hex = self
                                    .bytes
                                    .get(self.pos + 1..self.pos + 5)
                                    .ok_or_else(|| "JSON \\u 转义不完整".to_string())?;
                                let text = std::str::from_utf8(hex)
                                    .map_err(|_| "JSON \\u 转义非法".to_string())?;
                                let code = u16::from_str_radix(text, 16)
                                    .map_err(|_| "JSON \\u 转义非法".to_string())?;
                                let ch = char::from_u32(u32::from(code))
                                    .ok_or_else(|| "JSON \\u 码点非法".to_string())?;
                                let mut buf = [0u8; 4];
                                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                                self.pos += 4;
                            }
                            other => {
                                return Err(format!(
                                    "JSON 非法转义 \\{} 位于字节 {}",
                                    other as char, self.pos
                                ))
                            }
                        }
                        self.pos += 1;
                    }
                    0x00..=0x1f => return Err(format!("JSON 字符串含未转义控制字符 0x{byte:02x}")),
                    _ => {
                        out.push(byte);
                        self.pos += 1;
                    }
                }
            }
        }

        fn number(&mut self) -> Result<Value, String> {
            let start = self.pos;
            if self.bytes.get(self.pos) == Some(&b'-') {
                self.pos += 1;
            }
            while matches!(self.bytes.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.bytes.get(self.pos) == Some(&b'.') {
                self.pos += 1;
                while matches!(self.bytes.get(self.pos), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            if matches!(self.bytes.get(self.pos), Some(b'e' | b'E')) {
                self.pos += 1;
                if matches!(self.bytes.get(self.pos), Some(b'+' | b'-')) {
                    self.pos += 1;
                }
                while matches!(self.bytes.get(self.pos), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            let text = std::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| "JSON 数字不是 UTF-8".to_string())?;
            let number = text
                .parse::<f64>()
                .map_err(|_| format!("JSON 数字非法 `{text}`"))?;
            Ok(Value::Number(number))
        }

        fn array(&mut self, depth: usize) -> Result<Value, String> {
            self.pos += 1;
            let mut items = Vec::new();
            self.ws();
            if self.bytes.get(self.pos) == Some(&b']') {
                self.pos += 1;
                return Ok(Value::Array(items));
            }
            loop {
                self.ws();
                items.push(self.value(depth + 1)?);
                self.ws();
                match self.bytes.get(self.pos) {
                    Some(b',') => {
                        self.pos += 1;
                    }
                    Some(b']') => {
                        self.pos += 1;
                        return Ok(Value::Array(items));
                    }
                    _ => return Err(format!("JSON 数组缺少 `,` 或 `]` 位于字节 {}", self.pos)),
                }
            }
        }

        fn object(&mut self, depth: usize) -> Result<Value, String> {
            self.pos += 1;
            let mut items = Vec::new();
            self.ws();
            if self.bytes.get(self.pos) == Some(&b'}') {
                self.pos += 1;
                return Ok(Value::Object(items));
            }
            loop {
                self.ws();
                if self.bytes.get(self.pos) != Some(&b'"') {
                    return Err(format!("JSON 对象键必须是字符串，字节 {}", self.pos));
                }
                let key = self.string()?;
                self.ws();
                if self.bytes.get(self.pos) != Some(&b':') {
                    return Err(format!("JSON 对象缺少 `:` 位于字节 {}", self.pos));
                }
                self.pos += 1;
                self.ws();
                let value = self.value(depth + 1)?;
                items.push((key, value));
                self.ws();
                match self.bytes.get(self.pos) {
                    Some(b',') => {
                        self.pos += 1;
                    }
                    Some(b'}') => {
                        self.pos += 1;
                        return Ok(Value::Object(items));
                    }
                    _ => return Err(format!("JSON 对象缺少 `,` 或 `}}` 位于字节 {}", self.pos)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_standard_all_modules() {
        let policy = DpiPolicy::default();
        assert!(policy.enabled);
        assert_eq!(policy.intensity, Intensity::Standard);
        assert_eq!(policy.effective_inspect_bytes(512), 512);
        assert!(policy.module_enabled("tls"));
        assert!(!policy.decrypt_tls());
    }

    #[test]
    fn off_means_zero_bytes_and_no_modules() {
        let policy = DpiPolicy::from_json(r#"{"enabled":true,"intensity":"off"}"#).unwrap();
        assert!(policy.is_off());
        assert_eq!(policy.effective_inspect_bytes(4096), 0);
        assert!(!policy.module_enabled("tls"));
        assert!(!policy.decrypt_tls());
    }

    #[test]
    fn basic_only_allows_cheap_detectors_and_caps_window() {
        let policy = DpiPolicy::from_json(r#"{"intensity":"basic"}"#).unwrap();
        assert!(policy.module_enabled("tls"));
        assert!(policy.module_enabled("http"));
        assert!(policy.module_enabled("dns"));
        assert!(!policy.module_enabled("dhcpv4"));
        assert!(!policy.module_enabled("smtp"));
        assert_eq!(policy.effective_inspect_bytes(4096), 128);
    }

    #[test]
    fn deep_raises_window_and_requires_keylog_for_decryption() {
        let mut policy = DpiPolicy::from_json(r#"{"intensity":"deep"}"#).unwrap();
        assert_eq!(policy.effective_inspect_bytes(512), 4096);
        assert!(
            !policy.decrypt_tls(),
            "只有 deep 不够，必须显式开关+密钥日志"
        );
        policy.tls_decrypt.enabled = true;
        policy.tls_decrypt.keylog_file = Some("/tmp/tls.keys".to_string());
        assert!(policy.decrypt_tls());
        policy.intensity = Intensity::Standard;
        assert!(!policy.decrypt_tls(), "standard 不得偷偷解密");
    }

    #[test]
    fn module_switch_is_authoritative() {
        let policy = DpiPolicy::from_json(r#"{"modules":{"tls":false,"dns":true}}"#).unwrap();
        assert!(!policy.module_enabled("tls"));
        assert!(policy.module_enabled("dns"));
        assert!(policy.module_enabled("http"), "未列出的模块保持默认启用");
        assert_eq!(policy.disabled_module_count(), 1);
    }

    #[test]
    fn unknown_field_module_and_intensity_are_errors() {
        assert!(DpiPolicy::from_json(r#"{"intensiti":"deep"}"#).is_err());
        assert!(DpiPolicy::from_json(r#"{"intensity":"turbo"}"#).is_err());
        assert!(DpiPolicy::from_json(r#"{"modules":{"tls":true,"typo":true}}"#).is_err());
        assert!(DpiPolicy::from_json(r#"{"inspect_bytes":32}"#).is_err());
        assert!(DpiPolicy::from_json(r#"{"tls_decrypt":{"enabled":true,"file":"x"}}"#).is_err());
        assert!(DpiPolicy::from_json("[]").is_err());
        assert!(DpiPolicy::from_json("{} trailing").is_err());
    }

    #[test]
    fn json_roundtrip_preserves_values() {
        let source = r#"{"enabled":false,"intensity":"deep","inspect_bytes":8192,"modules":{"tls":false,"smtp":true},"tls_decrypt":{"enabled":true,"keylog_file":"/var/lib/cythsec/tls.keys"}}"#;
        let policy = DpiPolicy::from_json(source).unwrap();
        let reparsed = DpiPolicy::from_json(&policy.to_json()).unwrap();
        assert_eq!(policy, reparsed);
        assert!(reparsed.to_json().contains("\"inspect_bytes\":8192"));
    }

    #[test]
    fn catalog_json_matches_rust_module_keys() {
        let text = include_str!("../../../../configs/registry/dpi-modules.json");
        let root = json::parse(text).expect("目录 JSON 必须可解析");
        let modules = root
            .as_object()
            .and_then(|object| {
                object
                    .iter()
                    .find(|(key, _)| key == "modules")
                    .map(|(_, value)| value)
            })
            .and_then(|value| value.as_array())
            .expect("目录必须有 modules 数组");
        let mut keys: Vec<&str> = modules
            .iter()
            .map(|value| {
                value
                    .as_object()
                    .and_then(|fields| {
                        fields
                            .iter()
                            .find(|(key, _)| key == "key")
                            .and_then(|(_, value)| value.as_str())
                    })
                    .expect("每个模块必须有 key")
            })
            .collect();
        keys.sort_unstable();
        let mut expected = ALL_MODULE_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected, "目录与 Rust 模块键必须一一对应");
    }
}
