// parser/parser.cpp - 统一解析入口：L2 -> L3 -> L4 串联。
//
// 调用链：
//   parse_packet()
//     ├─ parse_ethernet()  -> L2View（含 VLAN 栈，定位 L3 起点）
//     └─ 按 EtherType 分派 L3：
//          ├─ 0x0800 IPv4 -> parse_ipv4() -> 取 protocol 分派 L4
//          └─ 0x86DD IPv6 -> parse_ipv6() -> 取 upper_proto 分派 L4
//                 └─ dispatch_l4()：6=TCP / 17=UDP / 1,58=ICMP -> 各 L4 视图
//
// 逐层解析，任一层失败即携带其错误状态提前返回；已解析完成的低层视图在
// out 中保持有效（例如 L3 不支持时，out.l2 仍可用）。全程零拷贝：所有视图
// 仅持有指向原始报文 data 的指针与长度。
#include "packet_engine/parser/parser.h"
#include "packet_engine/parser/ethernet.h"
#include "packet_engine/parser/ipv4.h"
#include "packet_engine/parser/ipv6.h"
#include "packet_engine/parser/tcp.h"
#include "packet_engine/parser/udp.h"
#include "packet_engine/parser/icmp.h"

namespace packet_engine {
namespace parser {

namespace {
// 根据上层协议号解析 L4，并写入 out 的对应视图。
// data/len 为 L4 头起点与可用字节数。
// 约定：无论是否支持，都先设置 out.l4_type，便于调用方判断已识别到哪一层；
// 未支持时返回 kUnsupported（属正常分支，非致命错误）。
ParseResult dispatch_l4(uint8_t proto, const uint8_t* data, size_t len, ParsedPacket& out) {
  switch (proto) {
  case 6: { // TCP
    out.l4_type = L4Kind::kTcp;
    return parse_tcp(data, len, out.tcp);
  }
  case 17: { // UDP
    out.l4_type = L4Kind::kUdp;
    return parse_udp(data, len, out.udp);
  }
  case 1:    // ICMPv4
  case 58: { // ICMPv6（与 v4 头部布局相同，复用同一解析器）
    out.l4_type = L4Kind::kIcmp;
    return parse_icmp(data, len, out.icmp);
  }
  default:
    out.l4_type = L4Kind::kOther;
    return make_result(ParseStatus::kUnsupported, "不支持的 L4 协议号");
  }
}
} // namespace

ParseResult parse_packet(const uint8_t* data, size_t len, ParsedPacket& out) {
  // 失败路径会提前 return，先清零聚合结果，避免残留上一次解析的内容。
  out = ParsedPacket{};
  // 空指针属调用方误用，显式拦截（len 可能为 0，但 data 不应为空）。
  if (data == nullptr) {
    return make_result(ParseStatus::kTruncated, "空报文指针");
  }
  // ---- L2 ----
  ParseResult r = parse_ethernet(data, len, out.l2);
  if (!r.ok())
    return r;
  out.has_l2 = true;

  // ---- L3 ----（按 EtherType 选择 IP 版本；VLAN 栈已在 L2 中剥离）
  switch (out.l2.ether_type) {
  case kEthTypeIpv4: {
    out.l3_type = IpVersion::kIpv4;
    ParseResult ip = parse_ipv4(out.l2.l3_data, out.l2.l3_len, out.ipv4);
    if (!ip.ok())
      return ip;
    // IPv4 由 protocol 字段指示 L4 类型
    return dispatch_l4(out.ipv4.protocol, out.ipv4.payload, out.ipv4.payload_len, out);
  }
  case kEthTypeIpv6: {
    out.l3_type = IpVersion::kIpv6;
    ParseResult ip = parse_ipv6(out.l2.l3_data, out.l2.l3_len, out.ipv6);
    if (!ip.ok())
      return ip;
    // IPv6 需跳过扩展头链，upper_proto 才是最终 L4 类型
    return dispatch_l4(out.ipv6.upper_proto, out.ipv6.payload, out.ipv6.payload_len, out);
  }
  default:
    // 非 IPv4/IPv6 的 EtherType（如 ARP）：解析 L2 成功，上层标记为不支持。
    // 返回 kUnsupported 而非错误：L2 视图出参有效，调用方可按需处理。
    out.l3_type = IpVersion::kOther;
    return make_result(ParseStatus::kUnsupported, "非 IPv4/IPv6 的 EtherType");
  }
}

} // namespace parser
} // namespace packet_engine
