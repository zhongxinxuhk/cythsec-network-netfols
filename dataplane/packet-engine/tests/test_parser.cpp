// test_parser.cpp - packet-engine 协议解析器单元测试（CTest，零第三方依赖）。
// 所有用例纯内存字节数组驱动，无需 root / 网卡 / libpcap（CYS-PKT-018）。
// 复用 tests/test_util.h 的 check()/summary()（CYS-PKT-025）。
#include "packet_engine/parser/parser.h"
#include "packet_engine/parser/parsed_packet.h"

#include <cstdio>
#include <cstring>
#include <vector>

#include "test_util.h"

using packet_engine::test::check;
using packet_engine::test::summary;
using namespace packet_engine::parser;

// 反复使用的以太地址常量
static const std::vector<uint8_t> kEthHead = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // 目的 MAC
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // 源 MAC
};

static bool eq4(const uint8_t* p, uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return p[0] == a && p[1] == b && p[2] == c && p[3] == d;
}

int main() {
  // ===================== 正常解析：IPv4 + TCP =====================
  {
    const std::vector<uint8_t> f = kEthHead;
    std::vector<uint8_t> pkt(f.begin(), f.end());
    // EtherType = IPv4
    pkt.insert(pkt.end(), {0x08, 0x00});
    // IPv4: 版本/IHL=45, 总长=0x34(52), id=0x1234, flags/frag=0, ttl=0x40, proto=6(TCP),
    //       校验和=0, src=10.0.0.1, dst=10.0.0.2
    pkt.insert(pkt.end(), {0x45, 0x00, 0x00, 0x34, 0x12, 0x34, 0x00, 0x00, 0x40, 0x06,
                           0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02});
    // TCP: sport=12345(0x3039), dport=80(0x0050), seq=1, ack=0, doff=5/SYN, win=0x7210
    pkt.insert(pkt.end(), {0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                           0x00, 0x00, 0x50, 0x02, 0x72, 0x10, 0x00, 0x00, 0x00, 0x00});
    // 负载 "HELLO DATA!!" (12 字节)
    pkt.insert(pkt.end(), {0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x20, 0x44, 0x41, 0x54, 0x41, 0x21, 0x21});

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.ok(), "正常IPv4+TCP: parse_packet 成功");
    check(out.has_l2 && out.l2.ether_type == 0x0800, "正常IPv4+TCP: L2 EtherType=IPv4");
    check(out.l3_type == IpVersion::kIpv4, "正常IPv4+TCP: L3=IPv4");
    check(out.ipv4.protocol == 6, "正常IPv4+TCP: protocol=TCP(6)");
    check(out.ipv4.total_length == 52, "正常IPv4+TCP: total_length=52");
    check(out.ipv4.ttl == 64, "正常IPv4+TCP: ttl=64");
    check(eq4(out.ipv4.src_addr, 10, 0, 0, 1), "正常IPv4+TCP: src=10.0.0.1");
    check(eq4(out.ipv4.dst_addr, 10, 0, 0, 2), "正常IPv4+TCP: dst=10.0.0.2");
    check(out.ipv4.header_len == 20, "正常IPv4+TCP: IPv4头长=20");
    check(out.ipv4.payload_len == 32, "正常IPv4+TCP: L4负载=32(20TCP+12)");
    check(out.l4_type == L4Kind::kTcp, "正常IPv4+TCP: L4=TCP");
    check(out.tcp.src_port == 12345 && out.tcp.dst_port == 80, "正常IPv4+TCP: 端口 12345->80");
    check(out.tcp.seq == 1 && out.tcp.ack == 0, "正常IPv4+TCP: seq=1 ack=0");
    check(out.tcp.header_len == 20, "正常IPv4+TCP: TCP头长=20");
    check(out.tcp.flags.syn && !out.tcp.flags.ack, "正常IPv4+TCP: SYN=1 ACK=0");
    check(!out.tcp.flags.ns, "正常IPv4+TCP: NS=0（未误置）");
    check(out.tcp.window == 0x7210, "正常IPv4+TCP: window=0x7210");
    check(out.tcp.payload_len == 12, "正常IPv4+TCP: TCP负载=12");
  }

  // ===================== 正常解析：IPv4 + UDP =====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x08, 0x00});
    // IPv4 proto=17(UDP), 总长=0x1f(31)
    pkt.insert(pkt.end(), {0x45, 0x00, 0x00, 0x1f, 0x12, 0x34, 0x00, 0x00, 0x40, 0x11,
                           0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02});
    // UDP: sport=12345, dport=53, len=0x0b(11), csum=0
    pkt.insert(pkt.end(), {0x30, 0x39, 0x00, 0x35, 0x00, 0x0b, 0x00, 0x00});
    pkt.insert(pkt.end(), {0x61, 0x62, 0x63}); // "abc"

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.ok(), "正常IPv4+UDP: parse_packet 成功");
    check(out.l4_type == L4Kind::kUdp, "正常IPv4+UDP: L4=UDP");
    check(out.udp.src_port == 12345 && out.udp.dst_port == 53, "正常IPv4+UDP: 端口 12345->53");
    check(out.udp.length == 11, "正常IPv4+UDP: UDP长度=11");
    check(out.udp.payload_len == 3, "正常IPv4+UDP: 负载=3");
  }

  // ===================== 正常解析：IPv4 + ICMPv4 =====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x08, 0x00});
    pkt.insert(pkt.end(), {0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x00, 0x00, 0x40, 0x01,
                           0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02});
    // ICMP: type=8(echo request), code=0, csum=0, id=1, seq=0
    pkt.insert(pkt.end(), {0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00});

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.ok(), "正常IPv4+ICMPv4: parse_packet 成功");
    check(out.l4_type == L4Kind::kIcmp, "正常IPv4+ICMPv4: L4=ICMP");
    check(out.icmp.type == 8 && out.icmp.code == 0, "正常IPv4+ICMPv4: type=8 code=0");
    check(out.icmp.body_len == 4, "正常IPv4+ICMPv4: ICMP体=4");
  }

  // ===================== 正常解析：IPv6 + ICMPv6（含 Hop-by-Hop 扩展头跳过）=====
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x86, 0xdd}); // EtherType=IPv6
    // IPv6 基头：ver=6, tc=0, flow=0, payload_len=0x10(16), next=0(Hop-by-Hop), hop=64
    pkt.insert(pkt.end(), {0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x40});
    // src 2001:db8::1
    pkt.insert(pkt.end(), {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x01});
    // dst 2001:db8::2
    pkt.insert(pkt.end(), {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x02});
    // Hop-by-Hop 扩展头：next=58(ICMPv6), hdr_ext_len=0, 余 6 字节填充
    pkt.insert(pkt.end(), {0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    // ICMPv6: type=128(echo request), code=0, csum=0, id=1, seq=1
    pkt.insert(pkt.end(), {0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01});

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.ok(), "正常IPv6+ICMPv6: parse_packet 成功");
    check(out.l3_type == IpVersion::kIpv6, "正常IPv6+ICMPv6: L3=IPv6");
    check(out.ipv6.next_header == 0, "正常IPv6+ICMPv6: 基头next=Hop-by-Hop(0)");
    check(out.ipv6.ext_header_count == 1, "正常IPv6+ICMPv6: 跳过1个扩展头");
    check(out.ipv6.upper_proto == 58, "正常IPv6+ICMPv6: 上层=ICMPv6(58)");
    check(out.l4_type == L4Kind::kIcmp, "正常IPv6+ICMPv6: L4=ICMP");
    check(out.icmp.type == 128, "正常IPv6+ICMPv6: ICMPv6 type=128");
  }

  // ===================== 畸形包：IPv6 扩展头链成环 =====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x86, 0xdd});
    // IPv6 基头：payload_len=0x18(24), next=43(Routing), hop=64
    pkt.insert(pkt.end(), {0x60, 0x00, 0x00, 0x00, 0x00, 0x18, 0x2b, 0x40});
    pkt.insert(pkt.end(), 32, 0x00); // src+dst 全 0
    // 连续 3 个 Routing 扩展头（next=43, hdr_ext_len=0），触发同类型重复上限
    for (int i = 0; i < 3; ++i) {
      pkt.insert(pkt.end(), {0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    }
    pkt.insert(pkt.end(), 20, 0x00); // 填充至 78 字节

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.status == ParseStatus::kLoopDetected,
          "畸形IPv6: 扩展头同类型重复超限 -> kLoopDetected");
  }

  // ===================== 正常解析：单层 VLAN =====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x81, 0x00}); // 0x8100 VLAN
    pkt.insert(pkt.end(), {0xa0, 0x64}); // TCI: pcp=5, dei=0, vid=100
    pkt.insert(pkt.end(), {0x08, 0x00}); // 内层 EtherType=IPv4
    pkt.insert(pkt.end(), {0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x00, 0x00, 0x40, 0x01,
                           0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02});
    pkt.insert(pkt.end(), {0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00});

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.ok(), "单层VLAN: parse_packet 成功");
    check(out.l2.vlan_count == 1, "单层VLAN: vlan_count=1");
    check(out.l2.vlan[0].tpid == 0x8100, "单层VLAN: tpid=0x8100");
    check(out.l2.vlan[0].pcp == 5 && out.l2.vlan[0].vid == 100, "单层VLAN: pcp=5 vid=100");
    check(out.l3_type == IpVersion::kIpv4, "单层VLAN: 内层解析为 IPv4");
  }

  // ===================== 正常解析：QinQ（双层 VLAN）=====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x88, 0xa8}); // 外层 0x88a8
    pkt.insert(pkt.end(), {0x00, 0xc8}); // 外层 vid=200
    pkt.insert(pkt.end(), {0x81, 0x00}); // 内层 0x8100
    pkt.insert(pkt.end(), {0x01, 0x2c}); // 内层 vid=300
    pkt.insert(pkt.end(), {0x08, 0x00}); // 内层 EtherType=IPv4
    pkt.insert(pkt.end(), {0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x00, 0x00, 0x40, 0x01,
                           0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02});
    pkt.insert(pkt.end(), {0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00});

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.ok(), "QinQ: parse_packet 成功");
    check(out.l2.vlan_count == 2, "QinQ: vlan_count=2");
    check(out.l2.vlan[0].tpid == 0x88a8 && out.l2.vlan[0].vid == 200,
          "QinQ: 外层 tpid=0x88a8 vid=200");
    check(out.l2.vlan[1].tpid == 0x8100 && out.l2.vlan[1].vid == 300,
          "QinQ: 内层 tpid=0x8100 vid=300");
    check(out.l3_type == IpVersion::kIpv4, "QinQ: 内层解析为 IPv4");
  }

  // ===================== 非 IPv4/IPv6 EtherType（ARP -> 不支持，非错误）=====
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x08, 0x06}); // ARP
    pkt.insert(pkt.end(), 28, 0x00);     // ARP 体（任意）

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.unsupported(), "ARP: 返回 kUnsupported（非错误）");
    check(out.has_l2 && out.l2.ether_type == 0x0806, "ARP: L2 已解析 ether_type=ARP");
    check(out.l3_type == IpVersion::kOther, "ARP: L3 标记 kOther");
  }

  // ===================== 畸形包：以太网头截断（<14）=====================
  {
    std::vector<uint8_t> pkt = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.status == ParseStatus::kTruncated, "畸形: 以太网头截断 -> kTruncated");
  }

  // ===================== 畸形包：IPv4 头截断（不足 20 字节）=====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x08, 0x00});
    pkt.insert(pkt.end(), {0x45, 0x00, 0x00, 0x34, 0x12, 0x34, 0x00, 0x00, 0x40,
                           0x06}); // 仅 10 字节（缺 10 字节）
    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.status == ParseStatus::kTruncated, "畸形: IPv4头截断 -> kTruncated");
  }

  // ===================== 畸形包：IPv4 IHL < 5 =====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x08, 0x00});
    pkt.insert(pkt.end(), {0x43, 0x00, 0x00, 0x34, 0x12, 0x34, 0x00, 0x00, 0x40, 0x06,
                           0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02});
    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.status == ParseStatus::kMalformed, "畸形: IPv4 IHL<5 -> kMalformed");
  }

  // ===================== offload：IPv4 total_length > caplen =====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x08, 0x00});
    // total_length 故意设为 0x0bb8(3000) > 实际捕获长度，模拟 offload/截断
    pkt.insert(pkt.end(), {0x45, 0x00, 0x0b, 0xb8, 0x12, 0x34, 0x00, 0x00, 0x40, 0x06,
                           0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02});
    pkt.insert(pkt.end(), {0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                           0x00, 0x00, 0x50, 0x02, 0x72, 0x10, 0x00, 0x00, 0x00, 0x00});
    pkt.insert(pkt.end(), {0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x20, 0x44, 0x41, 0x54, 0x41, 0x21, 0x21});

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.ok(), "offload: total_length>caplen 仍以 caplen 为界解析成功");
    check(out.ipv4.total_length == 0x0bb8, "offload: total_length 原值保留");
    check(out.ipv4.payload_len == 32, "offload: L4负载按 caplen 计算=32");
    check(out.tcp.payload_len == 12, "offload: TCP负载=12");
  }

  // ===================== 畸形包：TCP data_offset < 5 =====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x08, 0x00});
    pkt.insert(pkt.end(), {0x45, 0x00, 0x00, 0x34, 0x12, 0x34, 0x00, 0x00, 0x40, 0x06,
                           0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02});
    // TCP 首字节 data_offset=4（非法）
    pkt.insert(pkt.end(), {0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                           0x00, 0x00, 0x40, 0x00, 0x72, 0x10, 0x00, 0x00, 0x00, 0x00});
    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.status == ParseStatus::kMalformed, "畸形: TCP data_offset<5 -> kMalformed");
  }

  // ===================== 畸形包：TCP 头超出报文 =====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x08, 0x00});
    pkt.insert(pkt.end(), {0x45, 0x00, 0x00, 0x34, 0x12, 0x34, 0x00, 0x00, 0x40, 0x06,
                           0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02});
    pkt.insert(pkt.end(),
               {0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}); // 仅 10 字节 TCP
    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.status == ParseStatus::kTruncated, "畸形: TCP头超出报文 -> kTruncated");
  }

  // ===================== 畸形包：IPv6 扩展头长度字段溢出（防回绕）=====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x86, 0xdd});
    // payload_len=0x10(16) -> end=56；扩展头 hdr_ext_len=0xFF 会让 hdr_len=2048
    pkt.insert(pkt.end(), {0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x2b, 0x40});
    pkt.insert(pkt.end(), 32, 0x00);     // src+dst
    pkt.insert(pkt.end(), {0x2b, 0xff}); // next=43, hdr_ext_len=0xFF
    pkt.insert(pkt.end(), 26, 0x00);     // 填充至 70 字节

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.status == ParseStatus::kTruncated, "畸形: IPv6扩展头长度溢出 -> 安全截断(kTruncated)");
  }

  // ===================== 正常解析：TCP 选项区存在时的偏移计算 =====================
  {
    std::vector<uint8_t> pkt(kEthHead.begin(), kEthHead.end());
    pkt.insert(pkt.end(), {0x08, 0x00});
    pkt.insert(pkt.end(), {0x45, 0x00, 0x00, 0x34, 0x12, 0x34, 0x00, 0x00, 0x40, 0x06,
                           0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02});
    // TCP: data_offset=6(24字节头), ACK 置位, 4 字节选项 + 4 字节负载
    pkt.insert(pkt.end(), {0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                           0x00, 0x00, 0x60, 0x10, 0x72, 0x10, 0x00, 0x00, 0x00, 0x00});
    pkt.insert(pkt.end(), {0x01, 0x02, 0x03, 0x04}); // 4 字节选项
    pkt.insert(pkt.end(), {0x0a, 0x0b, 0x0c, 0x0d}); // 4 字节负载

    ParsedPacket out{};
    ParseResult r = parse_packet(pkt.data(), pkt.size(), out);
    check(r.ok(), "TCP选项: parse_packet 成功");
    check(out.tcp.data_offset == 6, "TCP选项: data_offset=6");
    check(out.tcp.header_len == 24, "TCP选项: 头部长度=24");
    check(out.tcp.options_len == 4, "TCP选项: 选项区=4 字节");
    check(out.tcp.flags.ack, "TCP选项: ACK=1");
    check(out.tcp.payload_len == 4, "TCP选项: 负载=4(头24字节之后剩余)");
  }

  return summary("packet_engine_parser");
}
