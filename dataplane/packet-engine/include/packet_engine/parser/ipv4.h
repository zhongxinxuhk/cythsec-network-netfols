// parser/ipv4.h - IPv4 头解析（含选项区跳过、total_length 越界处理）。
// 零拷贝：地址与选项区均为指针视图。
#pragma once

#include "packet_engine/parser/common.h"
#include "packet_engine/parser/result.h"

#include <cstdint>
#include <cstddef>

namespace packet_engine {
namespace parser {

struct Ipv4View {
  bool present = false;
  uint8_t version = 0;       // 应为 4
  uint8_t ihl = 0;           // 头长度单位（4 字节）；头部实际长度 = ihl*4
  uint8_t header_len = 0;    // = ihl * 4
  uint8_t dscp = 0;          // 0..63
  uint8_t ecn = 0;           // 0..3
  uint16_t total_length = 0; // IP 数据报总长（可能 > caplen，见 payload_len 注释）
  uint16_t id = 0;
  bool df = false, mf = false;
  uint16_t frag_offset = 0;
  uint8_t ttl = 0;
  uint8_t protocol = 0; // IP 协议号
  uint16_t checksum = 0;
  const uint8_t* src_addr = nullptr; // 4 字节（网络序）
  const uint8_t* dst_addr = nullptr; // 4 字节
  const uint8_t* options = nullptr;  // 选项区（可能为空）
  size_t options_len = 0;
  const uint8_t* payload = nullptr; // L4 起始
  size_t payload_len = 0;           // 受 caplen 约束的 L4 长度
};

// 解析 IPv4 头。data 指向 IP 头起点，len 为从 IP 头到报文末尾的可用字节数。
ParseResult parse_ipv4(const uint8_t* data, size_t len, Ipv4View& out);

} // namespace parser
} // namespace packet_engine
