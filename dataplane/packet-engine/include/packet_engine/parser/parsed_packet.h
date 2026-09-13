// parser/parsed_packet.h - 统一解析结果聚合结构。
// 由 parse_packet() 在单次调用中填充 L2/L3/L4 各层视图。
#pragma once

#include "packet_engine/parser/ethernet.h"
#include "packet_engine/parser/ipv4.h"
#include "packet_engine/parser/ipv6.h"
#include "packet_engine/parser/tcp.h"
#include "packet_engine/parser/udp.h"
#include "packet_engine/parser/icmp.h"

#include <cstdint>

namespace packet_engine {
namespace parser {

enum class IpVersion { kNone, kIpv4, kIpv6, kOther };
enum class L4Kind { kNone, kTcp, kUdp, kIcmp, kOther };

struct ParsedPacket {
  // 链路层
  bool has_l2 = false;
  L2View l2;

  // 网络层
  IpVersion l3_type = IpVersion::kNone;
  Ipv4View ipv4;
  Ipv6View ipv6;

  // 传输层
  L4Kind l4_type = L4Kind::kNone;
  TcpView tcp;
  UdpView udp;
  IcmpView icmp;
};

} // namespace parser
} // namespace packet_engine
