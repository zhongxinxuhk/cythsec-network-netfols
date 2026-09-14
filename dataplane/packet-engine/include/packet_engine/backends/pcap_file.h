// backends/pcap_file.h - 经典 pcap 文件后端（零第三方依赖自实现）。
//
// 不依赖 libpcap：本机无 libpcap 头文件/库可链接（见 capture/pcap/README.md），
// 故自行解析经典 pcap 文件格式。格式极简：24 字节全局头 + 每包 16 字节记录头。
//
// 零拷贝语义（CYS-PKT-017 在文件后端上的延续）：PacketBuffer::data 指向内部读缓冲
// buf_（一次性读入整个文件）。生命周期契约——**该指针在下次 rx_burst 调用或 close()
// 之前有效**，调用方不应跨 rx_burst 长期持有单个 PacketBuffer 指针。
#pragma once

#include "packet_engine/backend.h"

#include <cstdint>
#include <cstring> // std::memcpy（rd32/rd16 使用）——显式包含以保证头文件自包含
#include <string>
#include <vector>

namespace packet_engine {

// pcap 后端错误类别（与解析器 ParseStatus 概念一致，但属于后端层）。
enum class PcapStatus {
  kOk = 0,
  kNotFound,    // 文件打不开
  kUnsupported, // linktype 不支持（如 RAW/LINUX_SLL）
  kMalformed,   // 格式非法（未知魔数、incl_len>snaplen 等）
  kTruncated,   // 文件/记录截断
  kPcapNg,      // 误用 pcapng（当前仅支持经典 pcap）
};

// 经典 pcap 文件后端：读取整个文件到内存，预解析为 PacketBuffer 列表，
// rx_burst 仅做指针分发（零拷贝、无逐包 malloc）。
class PcapFileBackend : public PacketBackend {
public:
  int open(const char* source) override;
  void close() override;
  int rx_burst(PacketBuffer** pkts, uint32_t max) override;
  int tx_burst(PacketBuffer** /*pkts*/, uint32_t /*cnt*/) override { return -1; } // 只读后端
  BackendStats stats() override { return stats_; }
  void* native_handle() override { return nullptr; }

  // 后端层错误查询（open 失败后用于诊断）。
  PcapStatus error() const { return err_; }
  // 覆写基类虚接口（而非新增同名非虚函数）：CLI 一律按 PacketBackend* 使用，
  // 且刻意不做 dynamic_cast 到具体类型 —— 否则平台/后端差异会立刻上浮到工具层。
  const char* error_reason() const override { return err_reason_.c_str(); }

  // 保留强类型访问器供测试与后端专属代码使用；同时按基类契约再暴露一份。
  uint32_t link_type() const { return linktype_; }
  uint32_t bound_link_type() const override { return linktype_; }
  // 文件后端不绑定接口，故 bound_ifindex() 用基类默认值 0。
  const char* capture_mode_name() const override { return "file"; }

private:
  int parse(); // 解析已读入 buf_ 的内容
  uint32_t rd32(const uint8_t* p) const {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return swap_ ? bswap32(v) : v;
  }
  uint16_t rd16(const uint8_t* p) const {
    uint16_t v;
    std::memcpy(&v, p, 2);
    return swap_ ? bswap16(v) : v;
  }

  std::vector<uint8_t> buf_;          // 整个文件内容（PacketBuffer::data 指向此处）
  std::vector<PacketBuffer> packets_; // 预解析的报文视图
  size_t cursor_ = 0;                 // rx_burst 游标
  bool opened_ = false;
  bool swap_ = false; // 文件字节序与主机相反
  bool nano_ = false; // 纳秒精度（否则微秒）
  uint32_t snaplen_ = 0;
  uint32_t linktype_ = 0;
  BackendStats stats_{};
  PcapStatus err_ = PcapStatus::kOk;
  std::string err_reason_;

  static uint32_t bswap32(uint32_t v) {
    return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) | ((v & 0x00ff0000u) >> 8) |
           ((v & 0xff000000u) >> 24);
  }
  static uint16_t bswap16(uint16_t v) { return static_cast<uint16_t>((v >> 8) | (v << 8)); }
  void set_error(PcapStatus s, const std::string& r) {
    err_ = s;
    err_reason_ = r;
  }
};

} // namespace packet_engine
