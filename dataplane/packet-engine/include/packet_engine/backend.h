// backend.h - 收发包后端抽象接口（零拷贝）。
//
// 本接口是各类捕获/收发后端的统一契约：XDP、AF_XDP、DPDK、pcap（后续迭代实现）。
// 所有批量收发操作均基于 PacketBuffer 视图，数据体不拷贝。
#pragma once

#include "packet_engine/packet_buffer.h"

#include <cstdint>

namespace packet_engine {

// 后端统计信息（用于 telemetry/可观测性）。
struct BackendStats {
  uint64_t rx_packets = 0;
  uint64_t rx_bytes = 0;
  uint64_t tx_packets = 0;
  uint64_t tx_bytes = 0;
  uint64_t rx_dropped = 0;
  uint64_t rx_errors = 0;
};

// 收发包后端纯虚接口。
class PacketBackend {
public:
  virtual ~PacketBackend() = default;

  // 打开后端（绑定网卡 / 加载 eBPF 程序 / 打开 pcap 文件 / 初始化队列等）。
  // source 为数据源标识（如文件路径、接口名），具体含义由后端实现决定。
  // 返回 0 表示成功，负数表示错误码；失败原因由各后端自行提供（见其 error_reason()）。
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

  // 返回后端原生句柄（如 socket fd、XDP prog fd、DPDK port id 等），
  // 用于上层做高级操作。返回 void* 以避免暴露具体后端类型。
  virtual void* native_handle() = 0;
};

// 工厂：按名称创建后端。当前尚无后端实现，返回 nullptr（reason 说明原因）。
// 后续 XDP/AF_XDP/DPDK/pcap 实现后在此挂入（CYS-PKT-006 等）。
PacketBackend* create_backend(const char* name);
const char* create_backend_error();

} // namespace packet_engine
