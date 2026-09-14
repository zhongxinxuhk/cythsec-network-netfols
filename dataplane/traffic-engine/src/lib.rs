// lib.rs - traffic-engine 核心库入口
// 将 flow 与 session 作为库模块暴露，便于 main 与单元/集成测试复用。
// 数据链：Packet -> Flow -> Session
//
// channel 是数据链的源头：C++ packet-engine 经共享内存把裸帧送进来（CYS-PKT-024），
// 由 channel::decode 解成 FlowKey，再汇入 flow/session。它不依赖 flow/session 的实现，
// 只依赖其 FlowKey 类型，因此单独成模块、可独立测试。
pub mod attributes_gen;
pub mod channel;
pub mod flow;
pub mod session;

/// 包版本号。
///
/// 取自 build.rs 在编译期从仓库根 `VERSION` 注入的环境变量。
/// 刻意**不用** `env!("CARGO_PKG_VERSION")`：那读的是 Cargo.toml 里的
/// 另一份字面量副本，会让「VERSION 是唯一真源」名存实亡。
pub fn crate_version() -> &'static str {
    env!("CYTHSEC_VERSION")
}

/// 提交哈希（非 git 工作树为 `"unknown"`）。
pub fn crate_commit() -> &'static str {
    env!("CYTHSEC_COMMIT")
}

/// 构建时间（UTC RFC3339）。
pub fn crate_build_time() -> &'static str {
    env!("CYTHSEC_BUILD_TIME")
}

/// 构建信息三元组，与 Go 侧 versioninfo 的对外字段保持一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildInfo {
    pub version: &'static str,
    pub commit: &'static str,
    pub build_time: &'static str,
}

/// 返回本次构建的版本信息。
pub fn build_info() -> BuildInfo {
    BuildInfo {
        version: crate_version(),
        commit: crate_commit(),
        build_time: crate_build_time(),
    }
}
