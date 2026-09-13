// parser/ipv6.cpp - IPv6 基头与扩展头链解析实现。
//
// 40 字节固定基头布局（RFC 8200）：
//   +-----+-----------+-----------------------------+
//   | Ver | Traffic   | Flow Label                  |  偏移 0-3
//   | (4) | Class (8) |            (20)             |
//   +-----+-----------+-----------------------------+
//   | Payload Length (16)  | Next Header | Hop Limit |  偏移 4-7
//   +---------------------+-------------+-----------+
//   |          Source Address (16 字节)              |  偏移 8-23
//   |        Destination Address (16 字节)           |  偏移 24-39
//   +------------------------------------------------+
//
// 基头之后可能串联若干「扩展头」，每个扩展头的 Next Header 字段指向下一个头，
// 直到某个 Next Header 不再是扩展头（即为真正的上层协议号，如 TCP/UDP/ICMPv6）。
// 本函数遍历并跳过该链，最终定位 L4 起始。
//
// 解析分三步：① 解析 40 字节基头；② 计算有效区域终点 end（受 caplen 约束）；
// ③ 遍历扩展头链。全程零拷贝：地址与 payload 均为指向原始报文的指针。
#include "packet_engine/parser/ipv6.h"

namespace packet_engine {
namespace parser {

ParseResult parse_ipv6(const uint8_t* data, size_t len, Ipv6View& out) {
  // 失败路径会提前 return，先清零输出，避免调用方读到上一包的残留值。
  out = Ipv6View{};
  // 基头固定 40 字节。
  if (!in_bounds(len, 0, kIpv6HeaderLen)) {
    return make_result(ParseStatus::kTruncated, "IPv6 基头截断（<40 字节）");
  }
  // 首 4 字节打包 Version(4) | Traffic Class(8) | Flow Label(20)，共 32 位。
  const uint8_t vtc = data[0];
  out.version = vtc >> 4;
  // Traffic Class 跨越首字节低 4 位与次字节高 4 位。
  out.traffic_class = static_cast<uint8_t>(((vtc & 0x0F) << 4) | (data[1] >> 4));
  // Flow Label 为次字节低 4 位 + 第 3、4 字节，共 20 位。
  out.flow_label = (uint32_t(data[1] & 0x0F) << 16) | (uint32_t(data[2]) << 8) | data[3];
  out.payload_length = read_be16(data + 4); // 不含 40 字节基头的载荷长度（大端原值）
  out.next_header = data[6];                // 紧接基头的第一个头类型
  out.hop_limit = data[7];                  // 跳数上限，等价于 IPv4 的 TTL
  out.src_addr = data + 8;                  // 源地址：16 字节，仅记录指针
  out.dst_addr = data + 24;                 // 目的地址：16 字节

  // IPv6 有效区域终点 = 基头(40) + payload_length；但必须受 caplen 约束。
  size_t end = kIpv6HeaderLen + out.payload_length;
  if (end > len)
    end = len; // 截断：以 caplen 为界

  // 遍历扩展头链。每步都必须严格前进且落在区间内，否则判为截断或成环。
  uint8_t nh = out.next_header;
  size_t off = kIpv6HeaderLen; // 当前读指针，初始指向第一个扩展头
  uint8_t repeat[256] = {0};   // 按 next-header 值统计各类型出现次数，用于防环
  while (is_ipv6_ext_header(nh)) {
    // 总量上限：即使每类都未超限，链过长也判为异常（防资源耗尽）。
    if (out.ext_header_count >= kMaxIpv6ExtHeaders) {
      return make_result(ParseStatus::kLoopDetected, "IPv6 扩展头链超过遍历上限");
    }
    // 扩展头至少需 next_header(1) + hdr_ext_len(1)
    if (!in_bounds(end, off, 2)) {
      return make_result(ParseStatus::kTruncated, "IPv6 扩展头截断");
    }
    const uint8_t next = data[off];            // 本扩展头指向的下一个头类型
    const uint8_t hdr_ext_len = data[off + 1]; // 长度字段（含义随头类型而异）
    // Fragment(44) 固定 8 字节；其余 = (hdr_ext_len+1)*8
    const size_t hdr_len = (nh == 44) ? 8u : (size_t(hdr_ext_len) + 1) * 8u;
    // 防环：hdr_len==0 不会前进（死循环）；hdr_len 越界则截断。
    // 关键：用「end - off」减法比较而非「off + hdr_len」，避免 size_t 回绕。
    if (hdr_len == 0) {
      return make_result(ParseStatus::kLoopDetected, "IPv6 扩展头长度为 0（无法前进）");
    }
    if (hdr_len > end - off) {
      return make_result(ParseStatus::kTruncated, "IPv6 扩展头越界");
    }
    // 同种扩展头重复次数上限（防环 / 防滥用）
    if (++repeat[nh] > kMaxIpv6ExtRepeat) {
      return make_result(ParseStatus::kLoopDetected, "IPv6 扩展头类型重复超过上限");
    }
    out.ext_header_count++;
    nh = next;      // 推进到下一个头类型
    off += hdr_len; // 指针跳过本扩展头
  }

  // 循环结束：nh 不再是扩展头，即为最终上层协议号；off 指向 L4 起始。
  out.upper_proto = nh;
  // 边界兜底：正常情况下 off<=end<=len 恒成立，此处的比较仍以防越界为目标，
  // 越界时返回空指针/0 长度而非不安全地址。
  out.payload = (off < len) ? (data + off) : nullptr;
  out.payload_len = (off < len) ? (len - off) : 0;
  out.present = true;
  return make_result(ParseStatus::kOk, "");
}

} // namespace parser
} // namespace packet_engine
