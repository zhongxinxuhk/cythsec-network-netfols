// parser/ethernet.cpp - 以太网 II 帧解析实现。
//
// 无 VLAN 时的帧布局：
//   +----------+----------+----------+
//   | 目的 MAC  | 源 MAC   | 类型     |  <- 14 字节固定头
//   |  6 字节   | 6 字节   | 2 字节   |
//   +----------+----------+----------+
//
// 带 VLAN 时，类型字段取值为 0x8100/0x88A8/0x9100，其后追加一层
// TCI(2 字节) + 内层类型(2 字节)；若内层类型仍为 VLAN 标记，则继续叠加，
// 形成 QinQ 多层栈。
//
// 本函数只做定位与校验，不拷贝任何数据：L2View 中的字段均指向 data。
#include "packet_engine/parser/ethernet.h"

namespace packet_engine {
namespace parser {

ParseResult parse_ethernet(const uint8_t* data, size_t len, L2View& out) {
  // 失败路径会提前 return，先把输出清零，避免调用方读到上一包的残留值。
  out = L2View{};
  // 至少需 14 字节：目的 MAC(6) + 源 MAC(6) + EtherType(2)
  if (!in_bounds(len, 0, kEthHeaderLen)) {
    return make_result(ParseStatus::kTruncated, "以太网头截断（<14 字节）");
  }
  // 固定头字段定位：仅记录指针与原始值，不做字节序转换或拷贝。
  out.present = true;
  out.dst_mac = data;                    // 目的 MAC：偏移 0，6 字节
  out.src_mac = data + kEthAddrLen;      // 源 MAC：偏移 6，6 字节
  out.ether_type = read_be16(data + 12); // 类型/长度：偏移 12，2 字节（大端）

  // 逐层剥离 VLAN 标签（0x8100/0x88a8/0x9100），支持 QinQ 多层。
  // pos 为当前读指针：首轮 EtherType 在偏移 12，pos 停留在 14；
  // 之后每个 VLAN 标签消费 TCI(2) + 内层 EtherType(2) 共 4 字节。
  size_t pos = kEthHeaderLen;
  while (is_vlan_ethertype(out.ether_type)) {
    // 防御深度：真实部署极少超过 2 层，超过 kMaxVlanTags 视为畸形/滥用。
    if (out.vlan_count >= kMaxVlanTags) {
      return make_result(ParseStatus::kMalformed, "VLAN 标签层数超过上限");
    }
    // 需要 TCI(2) + 下一个 EtherType(2)
    if (!in_bounds(len, pos, 4)) {
      return make_result(ParseStatus::kTruncated, "VLAN 标签截断");
    }
    VlanTag& tag = out.vlan[out.vlan_count++];
    tag.tpid = out.ether_type; // 记录本层标签协议标识
    const uint16_t tci = read_be16(data + pos);
    // TCI 位布局（大端 16 位）：PCP(3) | DEI(1) | VID(12)
    tag.pcp = static_cast<uint8_t>((tci >> 13) & 0x07); // 优先级，3 位
    tag.dei = static_cast<uint8_t>((tci >> 12) & 0x01); // 丢弃指示，1 位
    tag.vid = static_cast<uint16_t>(tci & 0x0FFF);      // VLAN ID，12 位
    // 内层封装的 EtherType（可能是另一个 VLAN 标签，形成 QinQ）
    out.ether_type = read_be16(data + pos + 2);
    pos += 4;
  }

  // 循环结束：pos 已跳过以太头与全部 VLAN 标签，指向 L3 起始。
  out.l3_data = data + pos;
  // l3_len = 「L3 起始到捕获报文末尾」的字节数。每步 pos 前进均由上方
  // in_bounds 保证 pos<=len，故正常情况下不会进入 else 分支；三元判断仅作
  // 兜底，避免极端情况下 size_t 相减回绕出巨大长度。
  out.l3_len = (pos <= len) ? (len - pos) : 0;
  return make_result(ParseStatus::kOk, "");
}

} // namespace parser
} // namespace packet_engine
