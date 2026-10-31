//! 基于 NSS key log 的 TLS 1.3 离线解密与 DPI 明文分析。
//!
//! 边界：
//! * 只接受运维方提供的 key log；不主动探测、不导出/猜测密钥。
//! * 支持 TLS 1.3 + TLS_AES_128_GCM_SHA256（0x1301）与
//!   TLS_AES_256_GCM_SHA384（0x1302），其它套件明确报错。
//! * 解密结果只用于本地 DPI 结论与审计元数据，默认不落明文。

pub mod crypto;
pub mod keylog;
pub mod record;

pub use keylog::KeyLog;
pub use record::{
    parse_client_hello, parse_records, parse_server_hello, suite_name, Direction, Plaintext,
    Record, TlsSession, TrafficKeys,
};
