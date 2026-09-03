// lib.rs - traffic-engine 核心库入口
// 将 flow 与 session 作为库模块暴露，便于 main 与单元/集成测试复用。
// 数据链：Packet -> Flow -> Session
pub mod flow;
pub mod session;

/// 包版本号（与 Cargo.toml 的 version 保持一致，由包元数据提供）。
pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
