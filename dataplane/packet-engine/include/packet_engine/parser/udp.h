// parser/udp.h - UDP 头解析。
#pragma once

#include "packet_engine/parser/common.h"
#include "packet_engine/parser/result.h"

#include <cstdint>
#include <cstddef>

namespace packet_engine {
namespace parser {

struct UdpView {
  bool present = false;
  uint16_t src_port = 0, dst_port = 0;
  uint16_t length = 0; // UDP 头 + 数据长度（受 caplen 约束）
  uint16_t checksum = 0;
  const uint8_t* payload = nullptr;
  size_t payload_len = 0;
};

// 解析 UDP 头。data 指向 UDP 头起点，len 为可用字节数。
ParseResult parse_udp(const uint8_t* data, size_t len, UdpView& out);

} // namespace parser
} // namespace packet_engine
