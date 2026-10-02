// reassembly/mod.rs —— TCP 流重组。
//
// 为什么必须要有这一层，DPI 只做首包判定不够：
//   首包判定在省网是对的（几百微秒内必须出结果），但它有一个硬前提 ——
//   ClientHello / 请求行必须**完整地落在第一个报文里**。真实链路并不保证这件事：
//   路径 MTU 变化、TSO/GRO 关闭、中间设备分片、客户端把 ClientHello 拆成两段发送，
//   都会让它被切开。此时 DPI 只能回答 `NeedMore`，而这个回答本身没有价值，
//   除非有人能把缺的那部分补上。补的人就是这一层。
//
// 分工（刻意，不越界）：
//   本层只负责"把字节按顺序摆好"，**不做任何协议判断**。摆好之后调用
//   `dpi::identify` —— 同一个纯函数解析器，不做任何针对重组的改动。
//   若把协议判断掺进重组里，两边都会长成对方的样子，最后谁也改不动。
//
// 目录：
//   seq.rs       32 位序号的回绕算术（循环空间上的比较/区间/交并）
//   intervals.rs 已收数据的有序区间集（重叠仲裁、空洞追踪、窗口裁剪）
//   tcp.rs       TCP 头与选项解析（MSS / 窗口缩放 / SACK / 时间戳）
//   stream.rs    单向流（锚定、交付、内存上限、FIN 语义）
//   mod.rs       双向 Reassembler：把上面几块拼成"一条连接"

pub mod intervals;
pub mod seq;
pub mod stream;
pub mod tcp;

#[cfg(test)]
mod tests;
