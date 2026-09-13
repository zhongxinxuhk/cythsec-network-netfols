// parser/ipv4.cpp - IPv4 头解析实现。
//
// 20 字节最小头部布局（RFC 791）：
//   +--------+--------+-------------------+
//   |Ver|IHL|  TOS   |  Total Length     |  偏移 0-3
//   | Identification  |Flags|Frag Offset  |  偏移 4-7
//   |   TTL  |Protocol|  Header Checksum  |  偏移 8-11
//   |        Source Address (4 字节)      |  偏移 12-15
//   |      Destination Address (4 字节)   |  偏移 16-19
//   +--------+--------+-------------------+
//   |  Options（仅当 IHL>5 时存在，长度 = (IHL-5)*4）|
//
// 解析分三步：① 校验最小长度并解析定长字段；② 定位选项区；③ 计算 L4 边界，
// 并对 total_length 与捕获长度不一致（offload/截断）的情况做兜底。
// 全程零拷贝：地址、选项、载荷均为指向原始报文的指针。
#include "packet_engine/parser/ipv4.h"

namespace packet_engine {
namespace parser {

ParseResult parse_ipv4(const uint8_t* data, size_t len, Ipv4View& out) {
  out = Ipv4View{};
  // 至少需 20 字节（IHL=5、无选项）。
  if (!in_bounds(len, 0, kIpv4HeaderLenMin)) {
    return make_result(ParseStatus::kTruncated, "IPv4 头截断（<20 字节）");
  }
  // 首字节同时承载版本与头长度：高 4 位 Version，低 4 位 IHL。
  const uint8_t vihl = data[0];
  out.version = vihl >> 4;
  out.ihl = vihl & 0x0F;
  // IHL 以 4 字节为单位，合法最小值 5（即 20 字节）。IHL<5 属格式非法，
  // 需与「截断」区分：报文本身完整，只是字段值不合法。
  if (out.ihl < 5) {
    return make_result(ParseStatus::kMalformed, "IPv4 IHL<5（非法头长度）");
  }
  out.header_len = static_cast<uint8_t>(out.ihl * 4);
  // 头部声明长度超出实际捕获长度：说明选项区被截断。
  if (out.header_len > len) {
    return make_result(ParseStatus::kTruncated, "IPv4 头长度超出捕获长度");
  }
  // TOS 字节：高 6 位 DSCP，低 2 位 ECN。
  out.dscp = data[1] >> 2;
  out.ecn = data[1] & 0x03;
  out.total_length = read_be16(data + 2); // 数据报总长（含头），大端原值
  out.id = read_be16(data + 4);           // 分片标识
  // 偏移 6-7 共 16 位：高位 3 位为 Flags（保留/DF/MF），低位 13 位为分片偏移。
  const uint8_t flags_frag_hi = data[6];
  const uint8_t frag_lo = data[7];
  out.df = (flags_frag_hi & 0x40) != 0; // Don't Fragment
  out.mf = (flags_frag_hi & 0x20) != 0; // More Fragments
  // 分片偏移：高 5 位来自 flags_frag_hi 低 5 位，拼接 8 位低字节，单位为 8 字节。
  out.frag_offset = static_cast<uint16_t>(((flags_frag_hi & 0x1F) << 8) | frag_lo);
  out.ttl = data[8];
  out.protocol = data[9];              // IP 协议号，决定上层（TCP/UDP/ICMP…）
  out.checksum = read_be16(data + 10); // 首部校验和，大端原值（本层不校验）
  out.src_addr = data + 12;            // 源地址：4 字节，网络序，仅记录指针
  out.dst_addr = data + 16;            // 目的地址：4 字节

  // 选项区：介于 20 字节基头与 header_len 之间
  if (out.header_len > kIpv4HeaderLenMin) {
    out.options = data + kIpv4HeaderLenMin;
    out.options_len = out.header_len - kIpv4HeaderLenMin;
  }

  // L4 边界与 offload 处理：
  // total_length 可能大于实际捕获长度（TSO/GRO offload 或 pcap 截断是常见现象）。
  // 解析器一律以 caplen(len) 为硬边界，不越界访问；total_length 原值保留，
  // 上层若需完整 L4 校验应使用 wirelen 或要求重抓。
  const size_t l4_off = out.header_len;
  size_t l4_len;
  // 仅当 total_length 自洽（不小于头长且不超过捕获长度）时才据其推导 L4 长度；
  // 否则回退为「捕获长度 - 头长」，保证不越过 caplen 边界。
  if (out.total_length >= out.header_len && out.total_length <= len) {
    l4_len = static_cast<size_t>(out.total_length) - out.header_len;
  } else {
    l4_len = (l4_off <= len) ? (len - l4_off) : 0;
  }
  // 上方已校验 header_len<=len，此处三元判断仅作兜底（防止极端路径下指针越界）。
  out.payload = (l4_off <= len) ? (data + l4_off) : nullptr;
  out.payload_len = l4_len;
  out.present = true;
  return make_result(ParseStatus::kOk, "");
}

} // namespace parser
} // namespace packet_engine
