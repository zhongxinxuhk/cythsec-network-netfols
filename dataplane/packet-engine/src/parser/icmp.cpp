// parser/icmp.cpp - ICMPv4 / ICMPv6 头解析实现（两者头部布局相同）。
//
// 前 4 字节（Type/Code/Checksum）在 v4 与 v6 中布局一致，故两者共用本解析器：
//   +--------+--------+-------------------+
//   | Type   | Code   | Checksum          |  <- 4 字节固定头
//   | 1 字节 | 1 字节 | 2 字节            |
//   +--------+--------+-------------------+
// 其后为可变长度正文（body），具体含义随 Type/Code 而定（如 echo 的标识符+序号、
// 差错报文中嵌套的原始 IP 头等），本层只做定位，不解析其语义。
//
// 注意 v4 与 v6 的差异（本函数不涉及，由上层依据 IP 版本处理）：
//   - v6 的校验和覆盖伪首部（伪头），计算/验证方式与 v4 不同；
//   - v6 无独立的「ICMP 协议号」重复语义，Type/Code 取值空间也与 v4 不同。
//
// 本函数零拷贝：body 仅为指向原始报文的指针，不做任何数据体拷贝。
#include "packet_engine/parser/icmp.h"

namespace packet_engine {
namespace parser {

ParseResult parse_icmp(const uint8_t* data, size_t len, IcmpView& out) {
  // 失败路径会提前 return，先清零输出，避免调用方读到上一包的残留值。
  out = IcmpView{};
  // 固定头 4 字节：类型(1) + 代码(1) + 校验和(2)
  if (!in_bounds(len, 0, kIcmpHeaderLen)) {
    return make_result(ParseStatus::kTruncated, "ICMP 头截断（<4 字节）");
  }
  out.type = data[0];                 // 类型：偏移 0
  out.code = data[1];                 // 代码：偏移 1
  out.checksum = read_be16(data + 2); // 校验和：偏移 2，2 字节（大端，原值保留）
  out.body = data + kIcmpHeaderLen;   // 正文起始：偏移 4，仅记录指针
  // body_len = 「正文起始到捕获报文末尾」的字节数。上方 in_bounds 已保证
  // kIcmpHeaderLen<=len，故正常不会走 else；三元判断仅作兜底，防止 size_t 相减回绕。
  out.body_len = (kIcmpHeaderLen <= len) ? (len - kIcmpHeaderLen) : 0;
  out.present = true;
  return make_result(ParseStatus::kOk, "");
}

} // namespace parser
} // namespace packet_engine
