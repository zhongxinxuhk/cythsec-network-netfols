// parser/tcp.cpp - TCP 头解析实现。
//
// 20 字节最小头部布局（RFC 793 / RFC 9293）：
//   +---------------------+---------------------+
//   |   Source Port (16)  | Destination Port(16)|  偏移 0-3
//   +---------------------+---------------------+
//   |              Sequence Number (32)         |  偏移 4-7
//   +-------------------------------------------+
//   |          Acknowledgment Number (32)       |  偏移 8-11
//   +----+-------+-----------------------------+
//   |Data|Rsvd|NS |   Flags (CWR ECE URG ACK   |  偏移 12-13
//   |Off |    |   |    PSH RST SYN FIN)        |
//   +----+-------+-----------------------------+
//   |  Window Size (16)   |  Checksum (16)      |  偏移 14-17
//   +---------------------+---------------------+
//   | Urgent Pointer (16) |  Options(n)         |  偏移 18-19 / ...
//
// 解析分三步：① 校验最小长度，解析 data_offset 并校验合法性；② 解析定长字段
// 与 9 个标志位；③ 定位选项区与载荷。全程零拷贝：选项与载荷均为指向原始报文的指针。
#include "packet_engine/parser/tcp.h"

namespace packet_engine {
namespace parser {

ParseResult parse_tcp(const uint8_t* data, size_t len, TcpView& out) {
  // 失败路径会提前 return，先清零输出，避免调用方读到上一包的残留值。
  out = TcpView{};
  // 至少需 20 字节（data_offset=5、无选项）。
  if (!in_bounds(len, 0, kTcpHeaderLenMin)) {
    return make_result(ParseStatus::kTruncated, "TCP 头截断（<20 字节）");
  }
  // 偏移 12 字节：高 4 位为 data_offset，比特 3-1 为保留位，最低位为 NS。
  const uint8_t off_flags = data[12];
  out.data_offset = off_flags >> 4;
  // data_offset 以 4 字节为单位，合法最小值 5（即 20 字节）。data_offset<5 属
  // 格式非法，需与「截断」区分：报文本身完整，只是字段值不合法。
  if (out.data_offset < 5) {
    return make_result(ParseStatus::kMalformed, "TCP data_offset<5（非法头长度）");
  }
  out.header_len = static_cast<uint8_t>(out.data_offset * 4);
  // 头部声明长度超出实际捕获长度：说明选项区被截断。
  if (out.header_len > len) {
    return make_result(ParseStatus::kTruncated, "TCP 头长度超出捕获长度");
  }
  out.src_port = read_be16(data + 0); // 源端口，大端原值
  out.dst_port = read_be16(data + 2); // 目的端口
  out.seq = read_be32(data + 4);      // 序号（32 位，大端）
  out.ack = read_be32(data + 8);      // 确认号（32 位，大端）
  // NS 标志位于 data[12] 的最低位（RFC 3540），极易遗漏，单独处理。
  out.flags.ns = (off_flags & 0x01) != 0;
  // 偏移 13 字节：8 个标志位，bit7..bit0 依次为 CWR/ECE/URG/ACK/PSH/RST/SYN/FIN。
  const uint8_t flags2 = data[13];
  out.flags.cwr = (flags2 & 0x80) != 0;  // bit7 Congestion Window Reduced
  out.flags.ece = (flags2 & 0x40) != 0;  // bit6 ECN-Echo
  out.flags.urg = (flags2 & 0x20) != 0;  // bit5 Urgent
  out.flags.ack = (flags2 & 0x10) != 0;  // bit4 Acknowledgment
  out.flags.psh = (flags2 & 0x08) != 0;  // bit3 Push
  out.flags.rst = (flags2 & 0x04) != 0;  // bit2 Reset
  out.flags.syn = (flags2 & 0x02) != 0;  // bit1 Synchronize
  out.flags.fin = (flags2 & 0x01) != 0;  // bit0 Finish
  out.window = read_be16(data + 14);     // 接收窗口大小
  out.checksum = read_be16(data + 16);   // 校验和（大端原值，本层不校验）
  out.urgent_ptr = read_be16(data + 18); // 紧急指针（仅 URG 置位时有效）

  // 选项区：介于 20 字节基头与 header_len 之间（长度必为 4 字节的整数倍）。
  if (out.header_len > kTcpHeaderLenMin) {
    out.options = data + kTcpHeaderLenMin;
    out.options_len = out.header_len - kTcpHeaderLenMin;
  }
  out.payload = data + out.header_len; // 载荷起始：紧跟选项区
  // payload_len = 「载荷起始到捕获报文末尾」的字节数。上方已校验 header_len<=len，
  // 故正常不会走 else；三元判断仅作兜底，防止 size_t 相减回绕。
  out.payload_len = (out.header_len <= len) ? (len - out.header_len) : 0;
  out.present = true;
  return make_result(ParseStatus::kOk, "");
}

} // namespace parser
} // namespace packet_engine
