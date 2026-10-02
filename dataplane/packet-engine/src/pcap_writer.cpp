// pcap_writer.cpp - 经典 pcap 文件写出实现。
//
// 字节布局必须与 src/backends/pcap_file.cpp 的解析严格互逆，故此处逐字段对照写出。
// 所有多字节字段一律按**主机字节序**写出，并用对应的本机序魔数标识 —— 这与
// libpcap 的做法一致（先写本机序魔数，读方据此判断是否需要交换）。
#include "packet_engine/pcap_writer.h"

#include <cstring>

namespace packet_engine {

namespace {

// 本机序纳秒魔数。写它表示「文件内所有多字节字段均为本机字节序，时间戳为纳秒」。
// 读取侧（pcap_file.cpp）把 0xa1b23c4d 判定为 kMagicNanoNative。
constexpr uint32_t kMagicNanoNative = 0xa1b23c4d;

constexpr uint16_t kVersionMajor = 2;
constexpr uint16_t kVersionMinor = 4; // 纳秒时间戳要求 2.4

// 支持的 linktype：与读取侧一致（当前仅以太网）。写不受支持的 linktype 会让
// 读回来的文件被自己的读者拒绝，属于必须当场报错的情况。
constexpr uint32_t kLinktypeEthernet = 1;

inline void put32(uint8_t* p, uint32_t v) {
  std::memcpy(p, &v, 4);
}
inline void put16(uint8_t* p, uint16_t v) {
  std::memcpy(p, &v, 2);
}

} // namespace

PcapWriter::~PcapWriter() {
  // 析构即关闭：忘关会让缓冲里的包永久丢失（且文件缺尾，读侧报截断）。
  close();
}

void PcapWriter::set_error(PcapWriteStatus s, const std::string& r) {
  err_ = s;
  err_reason_ = r;
}

bool PcapWriter::open(const char* path, uint32_t linktype, uint32_t snaplen) {
  if (fp_ != nullptr) {
    set_error(PcapWriteStatus::kAlreadyOpen, "已打开一个文件，请先 close()");
    return false;
  }
  if (path == nullptr || *path == '\0') {
    set_error(PcapWriteStatus::kOpenFailed, "路径为空");
    return false;
  }
  if (linktype != kLinktypeEthernet) {
    // 明确拒绝而非照写：写出一个自己读不回的文件，比当场失败更糟。
    set_error(PcapWriteStatus::kBadLinktype,
              "仅支持 LINKTYPE_ETHERNET(1)；其它链路类型当前无法回读");
    return false;
  }

  std::FILE* f = std::fopen(path, "wb");
  if (f == nullptr) {
    set_error(PcapWriteStatus::kOpenFailed,
              std::string("无法创建文件（目录不存在、只读挂载或无写权限）: ") + path);
    return false;
  }
  fp_ = f;
  path_ = path;
  written_ = 0;
  written_bytes_ = 0;

  uint8_t gh[24];
  std::memset(gh, 0, sizeof(gh));
  put32(gh + 0, kMagicNanoNative);
  put16(gh + 4, kVersionMajor);
  put16(gh + 6, kVersionMinor);
  put32(gh + 8, 0);         // thiszone：UTC 偏移，恒 0（现代约定）
  put32(gh + 12, 0);        // sigfigs：时间戳精度，恒 0
  put32(gh + 16, snaplen);  // snaplen
  put32(gh + 20, linktype); // network

  if (std::fwrite(gh, 1, sizeof(gh), fp_) != sizeof(gh)) {
    // 全局头都写不进去，后续必然全失败 —— 当场关闭并报错，不要留一个半开的文件。
    set_error(PcapWriteStatus::kWriteFailed, "写全局头失败（磁盘满或 I/O 错误）");
    std::fclose(fp_);
    fp_ = nullptr;
    return false;
  }
  err_ = PcapWriteStatus::kOk;
  err_reason_ = "ok";
  return true;
}

bool PcapWriter::write(const PacketBuffer& pb) {
  if (fp_ == nullptr) {
    set_error(PcapWriteStatus::kNotOpen, "write 在未打开的文件上被调用");
    return false;
  }
  if (pb.data == nullptr && pb.caplen > 0) {
    // caplen>0 而 data 为空是调用方的错误，若照写会读到空指针。
    set_error(PcapWriteStatus::kWriteFailed, "caplen>0 但 data 为空指针");
    return false;
  }

  // 时间戳拆成秒 + 纳秒余数。用取模而非浮点，避免精度损失。
  // 负数时间戳（理论上可能出现在相对时钟的后端上）按向零截断处理，
  // 余数取绝对值，保证 ts_frac 落在 [0, 1e9)。
  const int64_t ns = pb.timestamp_ns;
  const int64_t sec = ns / 1000000000LL;
  const int64_t rem = ns % 1000000000LL;
  const uint32_t ts_sec = static_cast<uint32_t>(sec);
  const uint32_t ts_frac = static_cast<uint32_t>(rem < 0 ? -rem : rem);

  uint8_t rh[16];
  put32(rh + 0, ts_sec);
  put32(rh + 4, ts_frac);
  put32(rh + 8, pb.caplen);
  put32(rh + 12, pb.wirelen);

  if (std::fwrite(rh, 1, sizeof(rh), fp_) != sizeof(rh)) {
    set_error(PcapWriteStatus::kWriteFailed, "写记录头失败（磁盘满或 I/O 错误）");
    return false;
  }
  if (pb.caplen > 0) {
    if (std::fwrite(pb.data, 1, pb.caplen, fp_) != pb.caplen) {
      set_error(PcapWriteStatus::kWriteFailed, "写包数据失败（磁盘满或 I/O 错误）");
      return false;
    }
  }
  ++written_;
  written_bytes_ += pb.wirelen;
  return true;
}

bool PcapWriter::close() {
  if (fp_ == nullptr) {
    return true;
  }
  // fflush 与 fclose 的返回值必须显式检查：stdio 是缓冲的，最后的若干 KB
  // 可能直到 fclose 才真正落盘，而它的失败**只**从这里能看出。
  const bool flush_ok = (std::fflush(fp_) == 0);
  const bool close_ok = (std::fclose(fp_) == 0);
  fp_ = nullptr;
  if (!flush_ok || !close_ok) {
    set_error(PcapWriteStatus::kWriteFailed,
              "关闭时 flush 失败：缓冲中的数据未完整落盘（磁盘满或 I/O 错误）");
    return false;
  }
  return true;
}

} // namespace packet_engine
