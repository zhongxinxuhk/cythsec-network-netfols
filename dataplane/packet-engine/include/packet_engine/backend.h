// backend.h - 收发包后端抽象接口（零拷贝）。
//
// 本接口是各类捕获/收发后端的统一契约。已实现：pcap-file（离线）、af-packet（Linux
// 实时）、bpf（macOS/BSD 实时）。规划中：XDP、AF_XDP、DPDK（CYS-PKT-006/009/010）。
// 所有批量收发操作均基于 PacketBuffer 视图，数据体不拷贝。
//
// **数据有效期契约**（各实现必须遵守，调用方必须了解）：rx_burst 返回的
// PacketBuffer::data 通常指向后端内部缓冲或内核映射区，**在下一次 rx_burst
// 或 close() 之前有效**。需要跨调用持有数据时必须显式拷贝。
#pragma once

#include "packet_engine/packet_buffer.h"

#include <cstdint>
#include <string>
#include <vector>

namespace packet_engine {

// 后端统计信息（用于 telemetry/可观测性）。
struct BackendStats {
  uint64_t rx_packets = 0;
  uint64_t rx_bytes = 0;
  uint64_t tx_packets = 0;
  uint64_t tx_bytes = 0;
  uint64_t rx_dropped = 0;
  uint64_t rx_errors = 0;
  // 内核侧**交付**计数（AF_PACKET 的 PACKET_STATISTICS.tp_packets）。
  //
  // 为什么它与 rx_packets 是两个数：rx_packets 是「本进程取走的」，tp_packets 是
  // 「内核放进环/队列的」。关闭时两者之差仍不为 0，说明**有包进了环却没被取走**
  // （留在环里那些既不算丢包、也没进应用）—— 只报 rx_packets 的抓包工具无法区分
  // 「线上没流量」和「流量被丢了」，排障时会一路查错方向。
  //
  // 0 的含义：**该后端不提供**这一计数（BPF / pcap 文件后端不填）。不能用它断言
  // 「内核一个包都没交付」—— 那种判断要结合 rx_packets 与 rx_dropped 一起看。
  uint64_t rx_kernel_packets = 0;
};

// 采集模式偏好。默认 kAuto = 由后端自选（AF_PACKET 侧即 V3→V2→recvfrom 降级链）。
//
// 为什么需要它：① 对照基准（「mmap 环」vs「拷贝模式」）必须能**指定**模式 ——
// 否则两档跑出来都是同一条降级链的同一个结果，「对照」就成了自己跟自己比；
// ② 需要「确证跑在某模式上」的场景（如 V3 专属的块退休语义）不能让内核悄悄换掉实现。
// 指定模式 = **严格指定**：建立失败即报错，不降级到别的模式。
enum class CaptureMode {
  kAuto = 0,
  kTpacketV3,
  kTpacketV2,
  kRecvfrom,
};

inline const char* capture_mode_pref_name(CaptureMode m) {
  switch (m) {
  case CaptureMode::kAuto:
    return "auto";
  case CaptureMode::kTpacketV3:
    return "v3";
  case CaptureMode::kTpacketV2:
    return "v2";
  case CaptureMode::kRecvfrom:
    return "recvfrom";
  }
  return "unknown";
}

// 打开前的采集参数。集中成一个结构体而非一堆散落的 setter：
// 各后端的可调项不同（AF_PACKET 有块退休超时，BPF 有 see-sent），
// 若把这些做成基类的虚 setter，接口会随后端增加而无限膨胀；而调用方
// （CLI/服务）其实只想说「我要这些」，不想关心谁支持。
struct CaptureOptions {
  bool promisc = false;         // 混杂模式
  bool ignore_outgoing = false; // 不看本机发出的包（Linux 4.20+ 才有 PACKET_IGNORE_OUTGOING）
  bool allow_fallback = true;   // 允许降级到低版本 / 慢路径
  uint32_t buffer_bytes = 0;    // 环 / 读缓冲大小，0 = 后端默认
  uint32_t retire_ms = 0;       // 块退休超时毫秒（仅 AF_PACKET V3），0 = 后端默认
  uint32_t read_timeout_ms = 0; // 单次读超时毫秒，0 = 后端默认
  uint32_t snap_len = 0;        // 截取长度上限，0 = 后端默认
  CaptureMode mode = CaptureMode::kAuto; // 采集模式偏好（见 CaptureMode 注释）
};

// 收发包后端纯虚接口。
class PacketBackend {
public:
  virtual ~PacketBackend() = default;

  // 打开后端（绑定网卡 / 加载 eBPF 程序 / 打开 pcap 文件 / 初始化队列等）。
  // source 为数据源标识（如文件路径、接口名），具体含义由后端实现决定。
  // 返回 0 表示成功，负数表示错误码；失败原因见 error_reason()。
  virtual int open(const char* source) = 0;

  // 关闭后端、释放资源。
  virtual void close() = 0;

  // 批量收包：从后端取最多 max 个包，写入 pkts（调用方提供的 PacketBuffer* 数组）。
  // 返回实际收到的包数；<0 表示错误。
  virtual int rx_burst(PacketBuffer** pkts, uint32_t max) = 0;

  // 批量发包：发送 cnt 个包。返回实际发送数；<0 表示错误。
  virtual int tx_burst(PacketBuffer** pkts, uint32_t cnt) = 0;

  // 读取统计信息快照。
  virtual BackendStats stats() = 0;

  // 等待数据可读。返回值：>0 可读，0 超时/无法判定，<0 错误。
  //
  // 提到抽象层的原因：各后端的等待语义差别很大 —— 文件后端**永远**不阻塞
  // （rx_burst 立即返回 0），AF_PACKET 环模式非阻塞但可 poll，BPF 的 read 自带
  // 超时。若调用方（CLI/服务）不知道这一点，就会在文件后端上忙等、在 BPF 上
  // 白等两遍。把等待统一成这个接口后，调用方只需 `if (wait_readable(t) <= 0)
  // continue;`，无需知道自己在哪个后端上。
  //
  // 默认实现为「短暂休眠后返回 0」。休眠而非立即返回，是因为默认返回 0 会
  // 让调用方进入忙等 —— 抓包工具忙等就是 100% CPU，远比多 2ms 延迟糟糕。
  virtual int wait_readable(uint32_t timeout_ms);

  // ---------------------------------------------------------------------
  // 以下为「自省接口」。存在的统一理由：**调用方不该为了打印一行状态而知道
  // 自己跑在哪个后端上**。若把这些放到各派生类里，CLI 就得写 dynamic_cast 或
  // #ifdef 分支，平台与后端的差异会立刻上浮到工具层 —— 那正是跨平台代码
  // 腐化的起点。全部给出保守默认值，派生类按需覆写。
  // ---------------------------------------------------------------------

  // 最后一次失败的人类可读原因（中文，含可操作提示）。默认值刻意不是空串：
  // 空白的原因会让调用方无从判断，不如明说「本后端未提供」。
  virtual const char* error_reason() const { return "本后端未提供失败原因"; }

  // 该失败是否属于「权限/环境不足」类。用于让上层区分「跑不起来是环境问题」
  // 与「跑不起来是代码问题」—— 前者在测试中应记为跳过，后者必须记为失败。
  // 若把两者混为一谈，权限不足就会长期伪装成测试通过。
  virtual bool error_is_permission() const { return false; }

  // 已绑定数据源的系统索引（未绑定或该后端无此概念时为 0）。
  virtual uint32_t bound_ifindex() const { return 0; }

  // 已绑定数据源的链路层类型（平台编号空间：Linux 为 ARPHRD_*，BSD 为 DLT_*）。
  // 转可读名请用 backends/link_type.h 的 link_type_name()，它会按平台选对映射。
  virtual uint32_t bound_link_type() const { return 0; }

  // 实际生效的采集路径名（如 tpacket_v3 / bpf / file）。用于如实上报
  // 「这次到底跑在哪条路径上」—— 只报「成功」而不报路径，降级就无法归因。
  virtual const char* capture_mode_name() const { return "unknown"; }

  // 降级原因；未发生降级时为空串。
  virtual const char* fallback_reason() const { return ""; }

  // 打开前配置。返回**本后端不支持的项**的可读描述（空串表示全部接受）。
  //
  // 为什么返回值不是 void：静默忽略设置是危险的 —— 用户要了混杂模式却跑在
  // 非混杂下，会以为「抓不到某些包是网络问题」。宁可明确告知不支持。
  virtual std::string configure(const CaptureOptions& options);

  // 返回后端原生句柄（如 socket fd、XDP prog fd、DPDK port id 等），
  // 用于上层做高级操作。返回 void* 以避免暴露具体后端类型。
  virtual void* native_handle() = 0;
};

// 工厂：按名称创建后端。失败返回 nullptr，原因见 create_backend_error()。
//
// 已知名称：
//   "pcap-file"  经典 pcap 文件（离线），全平台可用
//   "live"       实时抓包，**按平台自动路由**（Linux→af-packet / macOS,BSD→bpf）
//   "af-packet"  Linux AF_PACKET，显式指定；非 Linux 平台报错而非回退
//   "bpf"        macOS/BSD /dev/bpfN，显式指定；非 BSD 系平台报错而非回退
// 跨平台代码应使用 "live"：平台分支被收敛在工厂内部，调用方无需条件编译。
PacketBackend* create_backend(const char* name);
const char* create_backend_error();

// 本编译环境下可用的后端名列表（按帮助文本顺序）。供 CLI 自省与错误文案使用。
// 存在理由：「本平台有哪些后端」是编译期决定的（af-packet 只在 Linux 编译进来），
// 硬编码一份列表到 CLI 里，会在跨平台构建时与实际不符。
std::vector<std::string> available_backends();

// 上述列表的逗号连接形式（如 "pcap-file, live, af-packet"）。
// 返回指针由内部静态存储持有，只能在下一次调用前使用。
const char* available_backends_joined();

// "live" 在本平台实际路由到的后端名："af-packet"（Linux）/"bpf"（macOS,BSD）。
// 本平台无任何实时后端时返回**空串**（不是猜一个名字）。
//
// 为什么不从 available_backends() 里取：那个列表的首项是 pcap-file，实时后端
// 并不固定在某个下标上。CLI 曾用 `names[1]` 取「路由目标」，结果打印出
// 「live 会按平台自动路由到 live」—— 一个自指且无意义的说法。列表顺序与
// 路由目标是两件事，硬把它们绑在一起，任何一项顺序调整都会静默产出错文案。
const char* native_live_backend_name();

} // namespace packet_engine
