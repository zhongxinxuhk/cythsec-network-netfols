// parser/ipv6.h - IPv6 基头与扩展头链解析（Hop-by-Hop/Routing/Fragment/Dest/AH）。
// 零拷贝：地址与扩展头链均通过指针与偏移访问，不做拷贝。
#pragma once

#include "packet_engine/parser/common.h"
#include "packet_engine/parser/result.h"

#include <cstdint>
#include <cstddef>

namespace packet_engine {
namespace parser {

// 已知扩展头 next-header 值（用于决定「继续遍历」还是「视为上层协议」）。
// 仅对 RFC 定义的标准扩展头做链式跳过；其余值视作上层协议（含 No Next Header）。
inline bool is_ipv6_ext_header(uint8_t nh) {
  return nh == 0      // Hop-by-Hop Options
         || nh == 43  // Routing
         || nh == 44  // Fragment
         || nh == 51  // Authentication Header (AH)
         || nh == 60; // Destination Options
}

struct Ipv6View {
  bool present = false;
  uint8_t version = 0;
  uint8_t traffic_class = 0;   // 0..255
  uint32_t flow_label = 0;     // 0..0xFFFFF
  uint16_t payload_length = 0; // 不含 40 字节基头
  uint8_t next_header = 0;     // 紧接基头后的下一个头
  uint8_t hop_limit = 0;
  const uint8_t* src_addr = nullptr; // 16 字节
  const uint8_t* dst_addr = nullptr; // 16 字节

  uint8_t ext_header_count = 0; // 遍历跳过的扩展头个数
  uint8_t upper_proto = 0;      // 最终上层协议号（L4 类型）

  const uint8_t* payload = nullptr; // L4 起始（扩展头链之后）
  size_t payload_len = 0;
};

// 解析 IPv6 头及扩展头链。data 指向 IPv6 头起点，len 为可用字节数。
ParseResult parse_ipv6(const uint8_t* data, size_t len, Ipv6View& out);

} // namespace parser
} // namespace packet_engine
