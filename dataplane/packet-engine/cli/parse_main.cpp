// parse_main.cpp - cythsec-parse：命令行报文解析演示工具。
//
// 支持：
//   cythsec-parse <十六进制字节串>     例如 cythsec-parse 450000340000...
//   cythsec-parse --hex <十六进制>     同上
//   cythsec-parse -f <二进制文件>       从文件读取原始报文
//   cythsec-parse -r <file.pcap>       遍历经典 pcap 文件内全部报文并输出统计摘要
//
// 纯内存解析，不依赖 root / 网卡 / libpcap，用于手动验证解析器（CYS-PKT-030）。
//
// 该工具是「解析器 + 后端」的手动验证闭环：
//   - 单包模式（hex/-f）：解析一帧并逐层 dump L2/L3/L4 字段，便于对照报文核对；
//   - 批量模式（-r）：经 PcapFileBackend 读 pcap，逐包解析并汇总统计，
//     用于在真实抓包上快速评估解析成功率与协议分布。
#include "packet_engine/parser/parser.h"
#include "packet_engine/parser/parsed_packet.h"
#include "packet_engine/backend.h"
#include "packet_engine/backends/pcap_file.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace packet_engine::parser;

// 遍历 pcap 文件内全部报文，逐包解析并打印统计摘要（解析器 + 后端 的手动验证闭环）。
// 返回 0 成功；1 打开失败；2 后端创建失败。
static int run_pcap(const char* path) {
  // 通过工厂按名创建 pcap-file 后端；create_backend 返回 PacketBackend*，
  // 此处向下转型为具体类型以调用 pcap 专有的 link_type()。
  packet_engine::PcapFileBackend* be =
      static_cast<packet_engine::PcapFileBackend*>(packet_engine::create_backend("pcap-file"));
  if (!be) {
    std::fprintf(stderr, "无法创建 pcap-file 后端: %s\n", packet_engine::create_backend_error());
    return 2;
  }
  if (be->open(path) != 0) {
    std::fprintf(stderr, "打开 pcap 失败: %s\n", be->error_reason());
    delete be;
    return 1;
  }

  // 各类计数器：总量 / 解析结果 / L3 分布 / L4 分布。
  uint64_t total = 0, parsed = 0, malformed = 0, unsupported = 0, truncated = 0;
  uint64_t n_ipv4 = 0, n_ipv6 = 0, n_other_l3 = 0;
  uint64_t n_tcp = 0, n_udp = 0, n_icmp = 0, n_other_l4 = 0;
  // rx_burst 的批量缓冲：一次最多取 256 个包视图（零拷贝，仅指针）。
  packet_engine::PacketBuffer* bufs[256];
  int g, idx = 0;
  // 以 rx_burst 批量拉取直至无包（返回 <=0 结束循环）。
  while ((g = be->rx_burst(bufs, 256)) > 0) {
    for (int i = 0; i < g; ++i) {
      const packet_engine::PacketBuffer* pb = bufs[i];
      ++total;
      // caplen<wirelen 表示抓包时被 snaplen 截断（非畸形，但可能影响上层解析完整性）。
      if (pb->caplen != pb->wirelen)
        ++truncated;
      ParsedPacket out{};
      // 解析边界一律用 caplen（已捕获范围），而非 wirelen。
      ParseResult r = parse_packet(pb->data, pb->caplen, out);
      if (r.ok()) {
        ++parsed;
        // 仅对解析成功的包统计 L3/L4 类型分布。
        if (out.l3_type == IpVersion::kIpv4)
          ++n_ipv4;
        else if (out.l3_type == IpVersion::kIpv6)
          ++n_ipv6;
        else if (out.l3_type == IpVersion::kOther)
          ++n_other_l3;
        if (out.l4_type == L4Kind::kTcp)
          ++n_tcp;
        else if (out.l4_type == L4Kind::kUdp)
          ++n_udp;
        else if (out.l4_type == L4Kind::kIcmp)
          ++n_icmp;
        else if (out.l4_type == L4Kind::kOther)
          ++n_other_l4;
      } else if (r.unsupported()) {
        // 上层协议不支持（如 ARP 的 EtherType）：L2 已解析，不算畸形。
        ++unsupported;
      } else {
        // 其余错误（截断/畸形/成环/溢出）统一计入 malformed。
        ++malformed;
      }
      // 将 L3/L4 枚举映射为紧凑的显示名；未识别（kNone）显示 "-"。
      const char* l3 = out.l3_type == IpVersion::kIpv4    ? "IPv4"
                       : out.l3_type == IpVersion::kIpv6  ? "IPv6"
                       : out.l3_type == IpVersion::kOther ? "OTHER-L2"
                                                          : "-";
      const char* l4 = out.l4_type == L4Kind::kTcp     ? "TCP"
                       : out.l4_type == L4Kind::kUdp   ? "UDP"
                       : out.l4_type == L4Kind::kIcmp  ? "ICMP"
                       : out.l4_type == L4Kind::kOther ? "OTHER-L4"
                                                       : "-";
      // 逐包打印一行摘要：#序号 L3 L4 caplen/wirelen，失败包追加标记。
      std::printf("#%-4d %s %s caplen=%u wirelen=%u%s\n", idx, l3, l4, pb->caplen, pb->wirelen,
                  r.ok() ? "" : " [解析失败]");
      ++idx;
    }
  }

  // 汇总统计摘要。
  std::printf("\n===== pcap 统计摘要 (%s) =====\n", path);
  std::printf("总包数          : %llu\n", (unsigned long long)total);
  std::printf("解析成功        : %llu\n", (unsigned long long)parsed);
  std::printf("解析失败/畸形    : %llu\n", (unsigned long long)malformed);
  std::printf("不支持L2        : %llu\n", (unsigned long long)unsupported);
  std::printf("截断包(cap<wire) : %llu\n", (unsigned long long)truncated);
  std::printf("L3: IPv4=%llu IPv6=%llu Other=%llu\n", (unsigned long long)n_ipv4,
              (unsigned long long)n_ipv6, (unsigned long long)n_other_l3);
  std::printf("L4: TCP=%llu UDP=%llu ICMP=%llu Other=%llu\n", (unsigned long long)n_tcp,
              (unsigned long long)n_udp, (unsigned long long)n_icmp,
              (unsigned long long)n_other_l4);
  std::printf("linktype        : %u (1=Ethernet)\n", be->link_type());
  delete be;
  return 0;
}

// 将十六进制字符串转换为字节串。
// 容错处理：忽略空格/Tab/换行/回车及 ':'、'-' 分隔符；遇到非法字符或奇数个
// 有效字符时返回空 vector（由调用方视为解析失败）。
static std::vector<uint8_t> hex_to_bytes(const std::string& s) {
  std::vector<uint8_t> out;
  // 单字符转 4 位值：0-9/a-f/A-F 有效，其余返回 -1 表示非法。
  auto hv = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < s.size();) {
    char c = s[i];
    // 跳过常见分隔符，使 "aa:bb:cc"、"aa-bb"、"aa bb" 等写法均可解析。
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ':' || c == '-') {
      ++i;
      continue;
    }
    // 剩余不足两位：截断为奇数长度，判为非法。
    if (i + 1 >= s.size())
      break;
    int hi = hv(s[i]), lo = hv(s[i + 1]);
    if (hi < 0 || lo < 0)
      return {};
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    i += 2;
  }
  return out;
}

// 以二进制方式整体读取文件内容。失败时向 stderr 报错并返回空 vector。
static std::vector<uint8_t> read_file(const char* path) {
  std::vector<uint8_t> out;
  FILE* f = std::fopen(path, "rb");
  if (!f) {
    std::fprintf(stderr, "无法打开文件: %s\n", path);
    return out;
  }
  // 分块读取（4KB）追加，避免依赖文件大小。
  uint8_t buf[4096];
  size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
    out.insert(out.end(), buf, buf + n);
  }
  std::fclose(f);
  return out;
}

// 打印 6 字节 MAC，格式 xx:xx:xx:xx:xx:xx。
static void print_mac(const uint8_t* m) {
  std::printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}
// 打印 4 字节 IPv4 地址（点分十进制）。
static void print_ipv4(const uint8_t* a) {
  std::printf("%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}
// 打印 16 字节 IPv6 地址（按 2 字节一组以 ':' 分隔的 8 组十六进制）。
static void print_ipv6(const uint8_t* a) {
  for (int i = 0; i < 16; i += 2) std::printf("%s%02x%02x", i ? ":" : "", a[i], a[i + 1]);
}

// 逐层打印单包解析结果。各层均以 present 标志守卫，只输出已成功解析的部分。
static void dump(const ParsedPacket& p) {
  if (p.has_l2) {
    std::printf("[L2 Ethernet] ");
    print_mac(p.l2.dst_mac);
    std::printf(" -> ");
    print_mac(p.l2.src_mac);
    std::printf("  ether_type=0x%04x\n", p.l2.ether_type);
    // VLAN 栈逐层打印（QinQ 多层时依次输出）。
    for (uint8_t i = 0; i < p.l2.vlan_count; ++i) {
      const VlanTag& v = p.l2.vlan[i];
      std::printf("    VLAN[%u] tpid=0x%04x pcp=%u dei=%u vid=%u\n", i, v.tpid, v.pcp, v.dei,
                  v.vid);
    }
  }
  if (p.l3_type == IpVersion::kIpv4 && p.ipv4.present) {
    std::printf("[L3 IPv4] ");
    print_ipv4(p.ipv4.src_addr);
    std::printf(" -> ");
    print_ipv4(p.ipv4.dst_addr);
    std::printf("  proto=%u ttl=%u id=0x%04x frag_off=%u df=%d mf=%d total_len=%u\n",
                p.ipv4.protocol, p.ipv4.ttl, p.ipv4.id, p.ipv4.frag_offset, p.ipv4.df, p.ipv4.mf,
                p.ipv4.total_length);
  } else if (p.l3_type == IpVersion::kIpv6 && p.ipv6.present) {
    std::printf("[L3 IPv6] ");
    print_ipv6(p.ipv6.src_addr);
    std::printf(" -> ");
    print_ipv6(p.ipv6.dst_addr);
    // next 显示的是跳过扩展头链后的最终上层协议号（upper_proto）。
    std::printf("  next=%u hop=%u flow=0x%05x ext_headers=%u\n", p.ipv6.upper_proto,
                p.ipv6.hop_limit, p.ipv6.flow_label, p.ipv6.ext_header_count);
  }
  if (p.l4_type == L4Kind::kTcp && p.tcp.present) {
    std::printf("[L4 TCP] %u -> %u  seq=%u ack=%u win=%u flags=", p.tcp.src_port, p.tcp.dst_port,
                p.tcp.seq, p.tcp.ack, p.tcp.window);
    // 逐个条件打印置位的标志（未置位则不输出），顺序为 NS 起至 FIN。
    if (p.tcp.flags.ns)
      std::printf("NS");
    if (p.tcp.flags.cwr)
      std::printf("CWR");
    if (p.tcp.flags.ece)
      std::printf("ECE");
    if (p.tcp.flags.urg)
      std::printf("URG");
    if (p.tcp.flags.ack)
      std::printf("ACK");
    if (p.tcp.flags.psh)
      std::printf("PSH");
    if (p.tcp.flags.rst)
      std::printf("RST");
    if (p.tcp.flags.syn)
      std::printf("SYN");
    if (p.tcp.flags.fin)
      std::printf("FIN");
    std::printf(" (opt=%zu payload=%zu)\n", p.tcp.options_len, p.tcp.payload_len);
  } else if (p.l4_type == L4Kind::kUdp && p.udp.present) {
    std::printf("[L4 UDP] %u -> %u  len=%u (payload=%zu)\n", p.udp.src_port, p.udp.dst_port,
                p.udp.length, p.udp.payload_len);
  } else if (p.l4_type == L4Kind::kIcmp && p.icmp.present) {
    std::printf("[L4 ICMP] type=%u code=%u (body=%zu)\n", p.icmp.type, p.icmp.code,
                p.icmp.body_len);
  }
}

int main(int argc, char** argv) {
  // 无参数时必须**先**打印用法再返回：此处的 argc 检查必须早于任何 argv[1] 解引用。
  // 否则 argc == 1 时 argv[1] 为 NULL，strcmp(NULL, "-r") 属未定义行为
  // （实测 macOS 下 exit=139 SIGSEGV）。
  if (argc < 2) {
    std::fprintf(stderr,
                 "用法:\n"
                 "  cythsec-parse <hex 字节串>     例如 cythsec-parse 4500...\n"
                 "  cythsec-parse --hex <hex>       同第一种\n"
                 "  cythsec-parse -f <二进制文件>   从文件读取原始报文\n"
                 "  cythsec-parse -r <file.pcap>    遍历经典 pcap 文件内全部报文并输出统计摘要\n");
    return 2;
  }
  // 批量解析模式：遍历 pcap 文件内全部报文并输出统计摘要。
  if (std::strcmp(argv[1], "-r") == 0) {
    if (argc <= 2) {
      std::fprintf(stderr, "错误: -r 需要一个 pcap 文件路径，例如 cythsec-parse -r a.pcap\n");
      return 2;
    }
    return run_pcap(argv[2]);
  }
  // 单包模式：按参数形式选择来源——二进制文件 / --hex 显式十六进制 / 裸十六进制。
  std::vector<uint8_t> bytes;
  if (std::strcmp(argv[1], "-f") == 0 && argc > 2) {
    bytes = read_file(argv[2]);
  } else if (std::strcmp(argv[1], "--hex") == 0 && argc > 2) {
    bytes = hex_to_bytes(argv[2]);
  } else {
    bytes = hex_to_bytes(argv[1]);
  }
  // 空输入（文件为空或十六进制非法/为空）直接报错。
  if (bytes.empty()) {
    std::fprintf(stderr, "输入为空或十六进制解析失败\n");
    return 2;
  }

  ParsedPacket pkt{};
  ParseResult r = parse_packet(bytes.data(), bytes.size(), pkt);
  // 成功或「上层不支持」都视为可展示：后者 L2 已解析，仅提示原因。
  if (r.ok() || r.unsupported()) {
    if (r.unsupported()) {
      std::printf("解析部分完成（上层不支持）: %s\n", r.reason);
    }
    dump(pkt);
    return 0;
  }
  // 其余错误（截断/畸形等）：打印状态码与原因，返回 1。
  std::fprintf(stderr, "解析失败 [%d]: %s\n", static_cast<int>(r.status), r.reason);
  return 1;
}
