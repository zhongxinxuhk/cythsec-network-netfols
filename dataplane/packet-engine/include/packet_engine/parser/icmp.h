// parser/icmp.h - ICMPv4 / ICMPv6 头解析（两者头部布局相同）。
#pragma once

#include "packet_engine/parser/common.h"
#include "packet_engine/parser/result.h"

#include <cstdint>
#include <cstddef>

namespace packet_engine {
namespace parser {

struct IcmpView {
  bool present = false;
  uint8_t type = 0;
  uint8_t code = 0;
  uint16_t checksum = 0;
  const uint8_t* body = nullptr; // type/code/checksum 之后的剩余体
  size_t body_len = 0;
};

// 解析 ICMP（v4 或 v6）头。data 指向 ICMP 头起点，len 为可用字节数。
ParseResult parse_icmp(const uint8_t* data, size_t len, IcmpView& out);

} // namespace parser
} // namespace packet_engine
