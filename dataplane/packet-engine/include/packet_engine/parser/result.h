// parser/result.h - 解析结果状态。
//
// 设计原则：解析器对「畸形包」一律返回错误状态，不使用异常、也不以 assert
// 代替错误返回——畸形包（截断、offload、构造攻击）是线上常态，属于正常输入，
// 而非编程错误。零拷贝特性要求任何错误都必须安全返回，绝不发生越界读写。
#pragma once

#include <cstdint>

namespace packet_engine {
namespace parser {

// 解析状态。kUnsupported 表示「协议不支持」而非失败（如非 IPv4/IPv6 的 EtherType）。
enum class ParseStatus : uint8_t {
  kOk = 0,       // 解析成功
  kTruncated,    // 数据长度不足，截断在某一层头部中间
  kMalformed,    // 格式非法（如 IHL<5、data_offset<5）
  kOverflow,     // 长度字段算术溢出
  kLoopDetected, // IPv6 扩展头链成环或超出重复上限
  kUnsupported,  // 协议不支持——非错误，L2 已解析
};

struct ParseResult {
  ParseStatus status = ParseStatus::kOk;
  const char* reason = ""; // 指向静态字符串，便于日志/CLI 展示

  bool ok() const { return status == ParseStatus::kOk; }
  // 不支持的协议（如 ARP）不算失败：L2 已解析，只是上层未处理。
  bool unsupported() const { return status == ParseStatus::kUnsupported; }
};

inline ParseResult make_result(ParseStatus s, const char* r) {
  return ParseResult{s, r};
}

} // namespace parser
} // namespace packet_engine
