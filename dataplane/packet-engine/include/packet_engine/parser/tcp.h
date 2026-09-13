// parser/tcp.h - TCP 头解析（含 NS 标志、选项区跳过）。
// 零拷贝：选项区为指针视图。
#pragma once

#include "packet_engine/parser/common.h"
#include "packet_engine/parser/result.h"

#include <cstdint>
#include <cstddef>

namespace packet_engine {
namespace parser {

struct TcpFlags {
  bool ns = false;  // 显式拥塞通知回显（RFC 3540），位于 data[12] 最低位，勿遗漏
  bool cwr = false; // Congestion Window Reduced
  bool ece = false; // ECN-Echo
  bool urg = false;
  bool ack = false;
  bool psh = false;
  bool rst = false;
  bool syn = false;
  bool fin = false;
};

struct TcpView {
  bool present = false;
  uint16_t src_port = 0, dst_port = 0;
  uint32_t seq = 0, ack = 0;
  uint8_t data_offset = 0; // 4 字节单位；头部长度 = data_offset*4
  uint8_t header_len = 0;  // = data_offset * 4
  TcpFlags flags;
  uint16_t window = 0;
  uint16_t checksum = 0;
  uint16_t urgent_ptr = 0;
  const uint8_t* options = nullptr;
  size_t options_len = 0;
  const uint8_t* payload = nullptr;
  size_t payload_len = 0;
};

// 解析 TCP 头。data 指向 TCP 头起点，len 为可用字节数。
ParseResult parse_tcp(const uint8_t* data, size_t len, TcpView& out);

} // namespace parser
} // namespace packet_engine
