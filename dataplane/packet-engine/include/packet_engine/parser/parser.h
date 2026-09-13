// parser/parser.h - 统一解析入口与跨层调度。
#pragma once

#include "packet_engine/parser/parsed_packet.h"
#include "packet_engine/parser/result.h"

#include <cstdint>
#include <cstddef>

namespace packet_engine {
namespace parser {

// 统一解析入口：解析完整报文（从 L2 到 L4）。
// data/len 为原始报文内存（零拷贝，解析结果指向 data 内部）。
// 畸形包返回错误状态而非崩溃；非 IPv4/IPv6 的 EtherType 返回 kUnsupported（仍解析了 L2）。
ParseResult parse_packet(const uint8_t* data, size_t len, ParsedPacket& out);

} // namespace parser
} // namespace packet_engine
