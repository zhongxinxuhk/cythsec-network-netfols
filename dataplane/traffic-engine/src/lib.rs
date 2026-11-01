// lib.rs - traffic-engine 核心库入口
// 将 flow / session / tcp 作为库模块暴露，便于 main 与单元/集成测试复用。
// 数据链：Packet -> FlowTable -> Session -> FlowRecord
//
// channel 是数据链的源头：C++ packet-engine 经共享内存把裸帧送进来（CYS-PKT-024），
// 由 channel::decode 解成 FlowKey，再汇入 flow/session。它不依赖 flow/session 的实现，
// 只依赖其 FlowKey 类型，因此单独成模块、可独立测试。
//
// tcp 单独成模块（而不是塞进 session）：连接状态机同时被 **flow::table**（超时档位
// 要按 Established/Transient 分档）与 **session**（会话状态）使用。放进 session 会让
// flow 反向依赖 session，形成模块环。
//
// feature / record 是数据链的出口：会话聚合完成后压成定长特征（feature），
// 再序列化成 FlowRecord（record）落盘。两者都不依赖 channel —— 离线 CLI 先用
// channel 解帧，再把解出的 FlowKey/Packet 喂进来。
pub mod arp;
pub mod attributes_gen;
pub mod channel;
pub mod dpi;
// export 是数据链的**对外出口**（M11）：FlowRecord → IPFIX（RFC 7011）。
// 它只依赖 record 的类型，不反向依赖 pipeline/channel —— 离线 CLI 与在线路径共用同一份编码器。
pub mod export;
pub mod feature;
pub mod flow;
// GRE / PPTP GRE 有界解析（RFC 2784 / RFC 2890 / RFC 2637）：基础隧道协议识别，
// 无端口、不进应用识别；事件由 cythsec-gre 输出，主流水线只做报文级计数。
pub mod gre;
// hash 是流键的稳定哈希：分片（pipeline）与采样（sampling）共用一份实现，
// 免得两处各写一份 FNV/splitmix 后各自漂移。见 HANDOFF §2.10 那次"低位恒定"事故。
pub mod hash;
// ICMPv4 / ICMPv6 有界解析（RFC 792 / RFC 4443 / RFC 4861）：基础协议识别，
// 事件由 cythsec-icmp 输出，主流水线只做报文级计数。
pub mod icmp;
// ipfix 是 IPFIX 线路格式与采集侧（M11 / CYS-TRF-051/054）：**编码器与采集器共用同一份
// IE 编号与模板定义**，免得"两侧各自定义一次、一起写错还互相验证通过"。
// 它只依赖 flow/record/feature 的类型，不依赖 pipeline/channel。
pub mod identification;
pub mod ipfix;
// NetFlow v9 采集侧（RFC 3954）：与 IPFIX 分开，因为它的序号单位是**导出报文**，
// 复用 IPFIX 的记录级记账会把丢包率算错一个数量级。
pub mod netflow9;
// sFlow v5 采集侧（RFC 3176）：自描述 sample/record，序号单位是**数据报**；
// 与模板制的 IPFIX/v9 没有可复用的状态机。
pub mod observability;
pub mod pcapfile;
pub mod pipeline;
pub mod reassembly;
pub mod record;
pub mod sflow;
// sampling 是流级采样（CYS-TRF-053）：**声明（IE 34）与执行必须一致**，
// 两者共用同一份 SamplingConfig —— 单一来源，别留"能声明却不执行"的入口。
pub mod sampling;
pub mod session;
// storage 是数据链的**列式落盘出口**（CYS-STO-002 / CYS-STO-007 第一步）：
// FlowRecord → ClickHouse `Native` 块 + 建表 DDL 的单一真源。
// 与 export（IPFIX）一样，它只依赖 record/feature/flow 的类型，不反向依赖 pipeline。
pub mod storage;
pub mod tcp;
// VXLAN 有界解析（RFC 7348）：VNI、基础 flags 与可见内层以太网/IP 头。
// 事件由 cythsec-vxlan 输出，主流水线只做报文级计数，内层不建流。
pub mod vxlan;
// TLS 1.3 keylog 解密（仅离线 DPI；零第三方依赖的密码学原语见模块注释）。
pub mod tlsdecrypt;

/// 测试专用的最小 JSON 解析器，供各向量驱动测试共用。
#[cfg(test)]
pub mod testjson;

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
