// backends/pcap_file.cpp - 经典 pcap 文件后端实现。
//
// 经典 pcap 文件格式（libpcap/tcpdump）：
//   全局头 24 字节：magic(4) ver_major(2) ver_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
//   每包记录头 16 字节：ts_sec(4) ts_frac(4) incl_len(4) orig_len(4) + 包数据(incl_len)
//     - ts_frac 在微秒文件中为微秒、纳秒文件中为纳秒（由魔数决定）
//     - incl_len = 文件实际存的长度；orig_len = 线上原始长度（incl<orig 即截断，常态非错误）
//
// 四种魔数变体必须同时支持（见 open() 内判定）：
//   0xa1b2c3d4 本机序·微秒   0xa1b23c4d 本机序·纳秒
//   0xd4c3b2a1 反序·微秒     0x4d3cb2a1 反序·纳秒
// 反序文件（大端写入）的所有多字节字段都需做字节序转换。
#include "packet_engine/backends/pcap_file.h"

#include <cstdio>
#include <cstring>

namespace packet_engine {

namespace {
constexpr uint32_t kMagicMicroNative = 0xa1b2c3d4;
constexpr uint32_t kMagicNanoNative = 0xa1b23c4d;
constexpr uint32_t kMagicMicroSwap = 0xd4c3b2a1;
constexpr uint32_t kMagicNanoSwap = 0x4d3cb2a1;
constexpr uint32_t kMagicPcapNg = 0x0a0d0d0a;
constexpr uint32_t kLinktypeEthernet = 1;

// 以主机字节序读出 4/2 字节（与 swap_ 配合完成端序判定）。
inline uint32_t host32(const uint8_t* p) {
  uint32_t v;
  std::memcpy(&v, p, 4);
  return v;
}
} // namespace

int PcapFileBackend::open(const char* source) {
  err_ = PcapStatus::kOk;
  err_reason_.clear();
  if (!source) {
    set_error(PcapStatus::kMalformed, "open: 缺少文件路径");
    return -1;
  }
  buf_.clear();
  packets_.clear();
  cursor_ = 0;
  opened_ = false;
  stats_ = BackendStats{};

  // 一次性读入整个文件（零拷贝：后续 PacketBuffer 指向 buf_）。
  FILE* f = std::fopen(source, "rb");
  if (!f) {
    set_error(PcapStatus::kNotFound, "无法打开文件（路径不存在或无权限）");
    return -1;
  }
  uint8_t chunk[1 << 16];
  size_t n;
  while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0) {
    buf_.insert(buf_.end(), chunk, chunk + n);
  }
  std::fclose(f);
  return parse();
}

int PcapFileBackend::parse() {
  if (buf_.size() < 24) {
    set_error(PcapStatus::kTruncated, "文件小于全局头(24字节)");
    return -1;
  }
  uint8_t* b = buf_.data();
  const uint32_t magic = host32(b);

  // pcapng 优先识别：魔数 0x0a0d0d0a，当前仅支持经典 pcap。
  if (magic == kMagicPcapNg) {
    set_error(PcapStatus::kPcapNg,
              "检测到 pcapng 魔数(0x0a0d0d0a)；当前仅支持经典 pcap，请用 tcpdump -w 生成经典格式");
    return -1;
  }
  if (magic == kMagicMicroNative) {
    swap_ = false;
    nano_ = false;
  } else if (magic == kMagicNanoNative) {
    swap_ = false;
    nano_ = true;
  } else if (magic == kMagicMicroSwap) {
    swap_ = true;
    nano_ = false;
  } else if (magic == kMagicNanoSwap) {
    swap_ = true;
    nano_ = true;
  } else {
    set_error(PcapStatus::kMalformed, "未知 pcap 魔数（非经典 pcap/pcapng）");
    return -1;
  }

  // network 字段（linktype）
  linktype_ = rd32(b + 20);
  snaplen_ = rd32(b + 16);
  if (linktype_ != kLinktypeEthernet) {
    set_error(
        PcapStatus::kUnsupported,
        "不支持的 linktype（当前仅支持 LINKTYPE_ETHERNET=1；101=RAW/113=LINUX_SLL 等暂不支持）");
    return -1;
  }

  size_t off = 24;
  const size_t total = buf_.size();
  while (off < total) {
    if (total - off < 16) {
      set_error(PcapStatus::kTruncated, "记录头不完整（<16字节）");
      return -1;
    }
    const uint8_t* rh = b + off;
    const uint32_t ts_sec = rd32(rh + 0);
    const uint32_t ts_frac = rd32(rh + 4); // 微秒或纳秒，由 nano_ 决定
    const uint32_t incl = rd32(rh + 8);
    const uint32_t orig = rd32(rh + 12);
    off += 16;

    // incl_len 校验：snaplen 为 0 时视为「不限」，否则必须 <= snaplen。
    if (snaplen_ != 0 && incl > snaplen_) {
      set_error(PcapStatus::kMalformed, "incl_len 超出 snaplen（文件损坏）");
      return -1;
    }
    if (total - off < incl) {
      set_error(PcapStatus::kTruncated, "包数据不完整（incl_len 超出文件剩余字节）");
      return -1;
    }

    PacketBuffer pb{};
    pb.data = b + off; // 指向 buf_ 内部，零拷贝
    pb.caplen = incl;
    pb.wirelen = orig;
    pb.headroom = 0;
    pb.ifindex = 0;
    // 时间戳统一转换为纳秒（微秒文件 ×1000）。
    uint64_t ns = static_cast<uint64_t>(ts_sec) * 1000000000ULL;
    ns += nano_ ? static_cast<uint64_t>(ts_frac) : static_cast<uint64_t>(ts_frac) * 1000ULL;
    pb.timestamp_ns = static_cast<int64_t>(ns);
    pb.refcount = 0;
    packets_.push_back(pb);
    off += incl;
  }

  opened_ = true;
  return 0;
}

int PcapFileBackend::rx_burst(PacketBuffer** pkts, uint32_t max) {
  if (!opened_) {
    set_error(PcapStatus::kMalformed, "rx_burst: 后端未打开");
    return -1;
  }
  uint32_t n = 0;
  while (n < max && cursor_ < packets_.size()) {
    pkts[n++] = &packets_[cursor_++];
  }
  stats_.rx_packets += n;
  for (uint32_t i = 0; i < n; ++i) {
    stats_.rx_bytes += pkts[i]->caplen;
  }
  return static_cast<int>(n);
}

void PcapFileBackend::close() {
  buf_.clear();
  packets_.clear();
  cursor_ = 0;
  opened_ = false;
}

} // namespace packet_engine
