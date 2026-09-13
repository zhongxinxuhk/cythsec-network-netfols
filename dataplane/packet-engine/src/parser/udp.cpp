// parser/udp.cpp - UDP 头解析实现。
//
// 8 字节固定头部布局（RFC 768）：
//   +---------------------+---------------------+
//   |   Source Port (16)  | Destination Port(16)|  偏移 0-3
//   +---------------------+---------------------+
//   |   Length (16)       |   Checksum (16)     |  偏移 4-7
//   +---------------------+---------------------+
//   |             Data（可变长度）                 |  偏移 8-...
//
// UDP 头定长、无选项，故解析最简：校验长度后即可定位全部字段与载荷。
// 注意 Length 字段为该 UDP 数据报总长（头 + 数据），可能大于捕获长度
// （offload/截断），本层只保留原值，实际边界一律以 caplen 为准。
// 全程零拷贝：payload 为指向原始报文的指针。
#include "packet_engine/parser/udp.h"

namespace packet_engine {
namespace parser {

ParseResult parse_udp(const uint8_t* data, size_t len, UdpView& out) {
  // 失败路径会提前 return，先清零输出，避免调用方读到上一包的残留值。
  out = UdpView{};
  // 固定 8 字节：源端口(2) + 目的端口(2) + 长度(2) + 校验和(2)
  if (!in_bounds(len, 0, kUdpHeaderLen)) {
    return make_result(ParseStatus::kTruncated, "UDP 头截断（<8 字节）");
  }
  out.src_port = read_be16(data + 0); // 源端口，大端原值
  out.dst_port = read_be16(data + 2); // 目的端口
  out.length = read_be16(data + 4);   // UDP 头 + 数据的总长度（大端原值，本层不裁剪）
  out.checksum = read_be16(data + 6); // 校验和（大端原值；IPv4 下可置 0 表示不校验）
  out.payload = data + kUdpHeaderLen; // 数据起始：固定偏移 8，仅记录指针
  // payload_len = 「数据起始到捕获报文末尾」的字节数。上方 in_bounds 已保证
  // kUdpHeaderLen<=len，故正常不会走 else；三元判断仅作兜底，防止 size_t 相减回绕。
  out.payload_len = (kUdpHeaderLen <= len) ? (len - kUdpHeaderLen) : 0;
  out.present = true;
  return make_result(ParseStatus::kOk, "");
}

} // namespace parser
} // namespace packet_engine
