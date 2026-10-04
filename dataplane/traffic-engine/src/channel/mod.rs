// channel/mod.rs —— 跨语言共享内存通道的 Rust 消费端（CYS-PKT-024）。
//
// 角色划分：
//   C++ packet-engine（生产端）  ──写──▶  共享区域  ──读──▶  本模块（消费端）
//
// 本模块只做三件事，且刻意不做第四件：
//   1. 映射区域并**校验两端对同一块内存的理解是否一致**（region）
//   2. 以 SPSC 语义取走报文，把字节交给调用方处理（consumer）
//   3. 把以太帧解成五元组，接入既有 Flow/Session 数据链（decode）
//
// 刻意不做：**任何形态的「容错」**。跨语言共享内存的失败模式是不崩、只错读——偏移差
// 8 字节就永久错位，读到的每个字段都无意义却不会报错。因此本模块的策略是「宁可拒绝
// 启动，也不带着错误理解继续跑」，所有不一致都在 attach 期或首个异常描述符上中断，
// 并给出与 C++ 端逐字一致的诊断文案（由 abi_gen::diag 生成）。
//
// 零第三方依赖：mmap 等 POSIX 符号在本模块内自行声明（std 已链接 libc），不新增 crate。

pub mod abi_gen;

mod consumer;
mod decode;
mod region;

// 端到端测试：在测试期内扮演 C++ 生产端，直接按 ABI 布局写共享区域。
// 放在本模块内而非 tests/ 目录，是为了能访问 pub(crate) 的 region 内部接口。
#[cfg(test)]
mod tests;

pub use consumer::{ConsumeError, Consumer, ConsumerStats, PacketMeta};
pub use decode::{decode_flow_key, decode_frame, DecodeError, DecodeStage, DecodedFrame, L3Proto};
pub use region::{AttachError, Channel, ChannelStats, RegionPerm};

// 四层协议类型由 flow 模块统一提供（CYS-TRF-004），这里只做转发，
// 免得解码器的调用方再依赖一个和 `FlowKey.proto` 不同的类型。
pub use crate::flow::Proto;
