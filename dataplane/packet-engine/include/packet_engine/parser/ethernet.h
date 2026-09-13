// parser/ethernet.h - 以太网 II 帧解析（含 VLAN 栈 / QinQ）。
// 零拷贝：所有地址字段均为指向原始报文的指针，不拷贝数据体。
#pragma once

#include "packet_engine/parser/common.h"
#include "packet_engine/parser/result.h"

#include <cstdint>
#include <cstddef>

namespace packet_engine {
namespace parser {

// EtherType 取值（网络字节序原值，未转换为主机序）
constexpr uint16_t kEthTypeIpv4 = 0x0800;
constexpr uint16_t kEthTypeIpv6 = 0x86DD;
constexpr uint16_t kEthTypeVlan = 0x8100;    // 802.1Q
constexpr uint16_t kEthTypeQinQ = 0x88A8;    // 802.1ad
constexpr uint16_t kEthTypeVlanAlt = 0x9100; // 部分厂商 QinQ 标记

inline bool is_vlan_ethertype(uint16_t et) {
  return et == kEthTypeVlan || et == kEthTypeQinQ || et == kEthTypeVlanAlt;
}

struct VlanTag {
  uint16_t tpid = 0; // 标签协议标识（0x8100/0x88a8/0x9100）
  uint8_t pcp = 0;   // 优先级（3 位）
  uint8_t dei = 0;   // 丢弃指示（1 位）
  uint16_t vid = 0;  // VLAN ID（12 位）
};

struct L2View {
  bool present = false;
  const uint8_t* dst_mac = nullptr; // 6 字节
  const uint8_t* src_mac = nullptr; // 6 字节
  uint16_t ether_type = 0;          // 原始 EtherType（网络字节序原值）

  uint8_t vlan_count = 0;
  VlanTag vlan[kMaxVlanTags];

  const uint8_t* l3_data = nullptr; // L3 起始（已跳过以太头与 VLAN 栈）
  size_t l3_len = 0;                // L3 到报文末尾的字节数
};

// 解析以太网 II 帧。data 指向帧起点，len 为可用字节数（应为 caplen）。
ParseResult parse_ethernet(const uint8_t* data, size_t len, L2View& out);

} // namespace parser
} // namespace packet_engine
