// test_pcap.cpp - pcap 文件后端单元测试（CTest，零第三方依赖）。
// 不放置任何二进制 fixture：所有 pcap 字节流由测试代码自行构造，以精确覆盖
// 四种魔数变体、字节序、精度、截断、畸形、linktype、pcapng、空文件、分批取包等分支。
// 纯文件读取驱动，无需 root / 网卡 / libpcap（CYS-PKT-006）。
#include "packet_engine/backend.h"
#include "packet_engine/backends/pcap_file.h"
#include "packet_engine/parser/parser.h"
#include "packet_engine/parser/parsed_packet.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "test_util.h"

using packet_engine::test::check;
using packet_engine::test::summary;
using namespace packet_engine;
using namespace packet_engine::parser;

// 一个典型 IPv4+TCP 报文（66 字节），供各用例复用。
static std::vector<uint8_t> make_eth_ipv4_tcp() {
  return {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00, // eth: dst, src, EtherType=IPv4
      0x45, 0x00, 0x00, 0x34, 0x12, 0x34, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00,
      0x01, 0x0a, 0x00, 0x00, 0x02, // IPv4
      0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x72,
      0x10, 0x00, 0x00, 0x00, 0x00, // TCP
      0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x20, 0x44, 0x41, 0x54, 0x41, 0x21,
      0x21 // "HELLO DATA!!"
  };
}

// 按指定字节序构造 pcap 字节流。
struct PcapBuilder {
  bool swap = false;
  std::vector<uint8_t> buf;
  void put32(uint32_t v) {
    if (swap) {
      buf.push_back((v >> 24) & 0xff);
      buf.push_back((v >> 16) & 0xff);
      buf.push_back((v >> 8) & 0xff);
      buf.push_back(v & 0xff);
    } else {
      buf.push_back(v & 0xff);
      buf.push_back((v >> 8) & 0xff);
      buf.push_back((v >> 16) & 0xff);
      buf.push_back((v >> 24) & 0xff);
    }
  }
  void put16(uint16_t v) {
    if (swap) {
      buf.push_back((v >> 8) & 0xff);
      buf.push_back(v & 0xff);
    } else {
      buf.push_back(v & 0xff);
      buf.push_back((v >> 8) & 0xff);
    }
  }
  void header(uint32_t magic, uint16_t vmaj, uint16_t vmin, uint32_t snaplen, uint32_t linktype) {
    put32(magic);
    put16(vmaj);
    put16(vmin);
    put32(0); // this zone
    put32(0); // sings
    put32(snaplen);
    put32(linktype);
  }
  void packet(uint32_t ts_sec, uint32_t ts_frac, uint32_t orig, const std::vector<uint8_t>& data) {
    put32(ts_sec);
    put32(ts_frac);
    put32(static_cast<uint32_t>(data.size())); // incl_len
    put32(orig);                               // orig_len
    buf.insert(buf.end(), data.begin(), data.end());
  }
};

static bool write_file(const char* path, const std::vector<uint8_t>& b) {
  FILE* f = std::fopen(path, "wb");
  if (!f)
    return false;
  std::fwrite(b.data(), 1, b.size(), f);
  std::fclose(f);
  return true;
}

int main() {
  auto pkt = make_eth_ipv4_tcp();
  char msg[160];

  // ===================== 工厂：未知后端名 =====================
  {
    PacketBackend* u = create_backend("nonexistent");
    check(u == nullptr, "create_backend(未知名) 返回 nullptr");
    check(std::strlen(create_backend_error()) > 0, "未知后端名有可读错误原因");
    delete u; // 对 nullptr 安全（noop）
  }

  // ===================== 正常：本机序·微秒，3 个包 =====================
  {
    PcapBuilder b;
    b.swap = false;
    b.header(0xa1b2c3d4, 2, 4, 65535, 1);
    for (int i = 0; i < 3; ++i) b.packet(1, 500000, static_cast<uint32_t>(pkt.size()), pkt);
    write_file("/tmp/pkt_micro.pcap", b.buf);

    PcapFileBackend* be = static_cast<PcapFileBackend*>(create_backend("pcap-file"));
    check(be != nullptr, "create_backend(pcap-file) 返回非空后端");
    check(be->open("/tmp/pkt_micro.pcap") == 0, "native micro: open 成功");
    check(be->link_type() == 1, "native micro: linktype=1 (ETHERNET)");
    check(be->error() == PcapStatus::kOk, "native micro: error=kOk");

    PacketBuffer* bufs[16];
    int got = 0, total = 0;
    while ((got = be->rx_burst(bufs, 16)) > 0) {
      for (int i = 0; i < got; ++i) {
        ParsedPacket out{};
        ParseResult r = parse_packet(bufs[i]->data, bufs[i]->caplen, out);
        std::snprintf(msg, sizeof(msg), "native micro: 包#%d caplen=66", total);
        check(bufs[i]->caplen == 66, msg);
        std::snprintf(msg, sizeof(msg), "native micro: 包#%d 解析成功", total);
        check(r.ok(), msg);
        std::snprintf(msg, sizeof(msg), "native micro: 包#%d L4=TCP", total);
        check(out.l4_type == L4Kind::kTcp, msg);
        std::snprintf(msg, sizeof(msg), "native micro: 包#%d 时间戳=1.5e9ns", total);
        check(bufs[i]->timestamp_ns == 1500000000, msg);
        ++total;
      }
    }
    check(total == 3, "native micro: 共 3 包");
    delete be;
  }

  // ===================== 四种魔数变体（精度 × 字节序）=====================
  struct Variant {
    uint32_t magic; // 写入时使用的魔数值（与 swap 共同决定磁盘字节序）
    bool swap;
    bool nano;
    const char* name;
  } variants[] = {
      {0xa1b2c3d4, false, false, "micro-native"},
      {0xa1b23c4d, false, true, "nano-native"},
      {0xa1b2c3d4, true, false, "micro-swap"},
      {0xa1b23c4d, true, true, "nano-swap"},
  };
  for (const auto& v : variants) {
    PcapBuilder b;
    b.swap = v.swap;
    b.header(v.magic, 2, 4, 65535, 1);
    uint32_t frac = v.nano ? 500000000u : 500000u;
    b.packet(1, frac, static_cast<uint32_t>(pkt.size()), pkt);
    std::string path = std::string("/tmp/pkt_var_") + v.name + ".pcap";
    write_file(path.c_str(), b.buf);

    PcapFileBackend* be = static_cast<PcapFileBackend*>(create_backend("pcap-file"));
    std::snprintf(msg, sizeof(msg), "variant %s: open 成功", v.name);
    check(be->open(path.c_str()) == 0, msg);
    PacketBuffer* one[1];
    int g = be->rx_burst(one, 1);
    std::snprintf(msg, sizeof(msg), "variant %s: 取到 1 包", v.name);
    check(g == 1, msg);
    std::snprintf(msg, sizeof(msg), "variant %s: caplen=66", v.name);
    check(one[0]->caplen == 66, msg);
    // 无论微秒/纳秒、本机序/反序，同一时间戳应得到相同的纳秒值
    std::snprintf(msg, sizeof(msg), "variant %s: 时间戳=1.5e9ns (精度+字节序正确)", v.name);
    check(one[0]->timestamp_ns == 1500000000, msg);
    delete be;
  }

  // ===================== 畸形：记录头不完整 -> kTruncated =====================
  {
    PcapBuilder b;
    b.swap = false;
    b.header(0xa1b2c3d4, 2, 4, 65535, 1);
    for (int i = 0; i < 8; ++i) b.buf.push_back(0); // 半截记录头
    write_file("/tmp/pkt_trunc.pcap", b.buf);
    PcapFileBackend* be = static_cast<PcapFileBackend*>(create_backend("pcap-file"));
    check(be->open("/tmp/pkt_trunc.pcap") != 0, "截断记录头: open 失败");
    check(be->error() == PcapStatus::kTruncated, "截断记录头: error=kTruncated");
    delete be;
  }

  // ===================== 畸形：incl_len > snaplen -> kMalformed =====================
  {
    PcapBuilder b;
    b.swap = false;
    b.header(0xa1b2c3d4, 2, 4, 10, 1);                      // snaplen=10
    b.packet(1, 0, static_cast<uint32_t>(pkt.size()), pkt); // incl_len=66 > 10
    write_file("/tmp/pkt_snaplen.pcap", b.buf);
    PcapFileBackend* be = static_cast<PcapFileBackend*>(create_backend("pcap-file"));
    check(be->open("/tmp/pkt_snaplen.pcap") != 0, "incl>snaplen: open 失败");
    check(be->error() == PcapStatus::kMalformed, "incl>snaplen: error=kMalformed");
    delete be;
  }

  // ===================== 不支持的 linktype (101=RAW) -> kUnsupported =====================
  {
    PcapBuilder b;
    b.swap = false;
    b.header(0xa1b2c3d4, 2, 4, 65535, 101);
    b.packet(1, 0, static_cast<uint32_t>(pkt.size()), pkt);
    write_file("/tmp/pkt_link.pcap", b.buf);
    PcapFileBackend* be = static_cast<PcapFileBackend*>(create_backend("pcap-file"));
    check(be->open("/tmp/pkt_link.pcap") != 0, "linktype=101: open 失败");
    check(be->error() == PcapStatus::kUnsupported, "linktype=101: error=kUnsupported");
    delete be;
  }

  // ===================== pcapng 魔数 -> 明确拒绝 =====================
  {
    std::vector<uint8_t> ng(24, 0);
    ng[0] = 0x0a;
    ng[1] = 0x0d;
    ng[2] = 0x0d;
    ng[3] = 0x0a; // pcapng 魔数
    write_file("/tmp/pkt_ng.pcap", ng);
    PcapFileBackend* be = static_cast<PcapFileBackend*>(create_backend("pcap-file"));
    check(be->open("/tmp/pkt_ng.pcap") != 0, "pcapng: open 失败");
    check(be->error() == PcapStatus::kPcapNg, "pcapng: error=kPcapNg");
    delete be;
  }

  // ===================== 空 pcap（仅全局头，0 包）=====================
  {
    PcapBuilder b;
    b.swap = false;
    b.header(0xa1b2c3d4, 2, 4, 65535, 1); // 无包
    write_file("/tmp/pkt_empty.pcap", b.buf);
    PcapFileBackend* be = static_cast<PcapFileBackend*>(create_backend("pcap-file"));
    check(be->open("/tmp/pkt_empty.pcap") == 0, "空 pcap: open 成功");
    PacketBuffer* one[1];
    check(be->rx_burst(one, 1) == 0, "空 pcap: rx_burst 返回 0 包（非错误）");
    delete be;
  }

  // ===================== 分批取包：max 小于包数时不丢包 =====================
  {
    PcapFileBackend* be = static_cast<PcapFileBackend*>(create_backend("pcap-file"));
    be->open("/tmp/pkt_micro.pcap"); // 3 包
    int c = 0;
    PacketBuffer* one[1];
    int g;
    while ((g = be->rx_burst(one, 1)) > 0) {
      check(g == 1, "分批: 每次恰取 1 包");
      ++c;
    }
    check(c == 3, "分批: 共取满 3 包不丢失");
    check(be->rx_burst(one, 1) == 0, "分批: 取完后返回 0");
    delete be;
  }

  // ===================== incl_len < orig_len（截断捕获，常态非错误）=====================
  {
    PcapBuilder b;
    b.swap = false;
    b.header(0xa1b2c3d4, 2, 4, 65535, 1);
    std::vector<uint8_t> trunc(pkt.begin(), pkt.begin() + 54); // 捕获 54 字节，原始 66
    b.packet(1, 0, static_cast<uint32_t>(pkt.size()), trunc);  // incl=54, orig=66
    write_file("/tmp/pkt_incl.pcap", b.buf);
    PcapFileBackend* be = static_cast<PcapFileBackend*>(create_backend("pcap-file"));
    be->open("/tmp/pkt_incl.pcap");
    PacketBuffer* one[1];
    int g = be->rx_burst(one, 1);
    check(g == 1, "incl<orig: 取到 1 包");
    check(one[0]->caplen == 54, "incl<orig: caplen=54");
    check(one[0]->wirelen == 66, "incl<orig: wirelen=66（caplen != wirelen）");
    ParsedPacket out{};
    ParseResult r = parse_packet(one[0]->data, one[0]->caplen, out);
    check(r.ok(), "incl<orig: 以 caplen 为界解析成功（不越界）");
    check(out.l3_type == IpVersion::kIpv4 && out.l4_type == L4Kind::kTcp,
          "incl<orig: 解析到 IPv4+TCP");
    delete be;
  }

  return summary("packet_engine_pcap");
}
