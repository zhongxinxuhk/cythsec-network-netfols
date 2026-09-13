// parser/common.h - 解析器公共工具：长度常量、边界检查、大端读取。
// 本文件为纯内联工具，零第三方依赖。
//
// 零拷贝约束（贯穿整个解析器族）：解析器只读取并指向原始报文内存，
// 绝不 memcpy 数据体；所有协议视图均返回「指针 + 长度」，而非拷贝副本。
#pragma once

#include <cstdint>
#include <cstddef>

namespace packet_engine {
namespace parser {

// ---- 长度常量 ---------------------------------------------------------------
constexpr size_t kEthAddrLen = 6;        // MAC 地址长度
constexpr size_t kEthHeaderLen = 14;     // 目的6 + 源6 + 类型2
constexpr size_t kMaxVlanTags = 4;       // VLAN 栈最大层数（含 QinQ 多层）。
                                         // 真实部署极少超过 2 层；取 4 作为安全上界。
constexpr size_t kIpv4HeaderLenMin = 20; // IHL=5 时的最小 IPv4 头长度
constexpr size_t kIpv6HeaderLen = 40;    // IPv6 基头固定长度
constexpr size_t kMaxIpv6ExtHeaders = 8; // 扩展头链最大遍历次数（防环/防滥用）
constexpr size_t kMaxIpv6ExtRepeat = 2;  // 同一扩展头类型最大重复次数
                                         // （Destination Options 可按 RFC 出现两次）
constexpr size_t kTcpHeaderLenMin = 20;  // data_offset=5 时的最小 TCP 头长度
constexpr size_t kUdpHeaderLen = 8;
constexpr size_t kIcmpHeaderLen = 4;

// ---- 边界检查 ---------------------------------------------------------------
// 安全判断 [off, off+n) 是否落在 [0, total) 内。
// 关键点：用「total - off」做减法而非「off + n」做加法，避免 size_t 回绕导致的
// off+n<off 类溢出误判（畸形包常故意制造大长度字段触发此问题）。
inline bool in_bounds(size_t total, size_t off, size_t n) {
  return off <= total && n <= (total - off);
}

// ---- 大端读取（网络字节序）--------------------------------------------------
inline uint16_t read_be16(const uint8_t* p) {
  return static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1]);
}
inline uint32_t read_be32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline uint64_t read_be64(const uint8_t* p) {
  return (uint64_t(read_be32(p)) << 32) | read_be32(p + 4);
}

} // namespace parser
} // namespace packet_engine
