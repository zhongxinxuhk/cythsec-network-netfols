// pcap_writer.h - 经典 pcap 文件写出（零第三方依赖）。
//
// 存在理由：抓包工具必须能把结果落盘，否则「抓到了什么」只能靠终端里的计数相信，
// 而排障时需要的是能在 Wireshark 里逐包看的证据。同时它是**往返验证**的基础 ——
// 写出后用 PcapFileBackend 读回，可比对「捕获链路」与「解析链路」对同一批报文的
// 理解是否一致（见 tests/test_live_capture.cpp）。
//
// 格式与 src/backends/pcap_file.cpp 的读取实现严格对应：
//   全局头 24 字节：magic(4) ver_major(2) ver_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
//   每包记录头 16 字节：ts_sec(4) ts_frac(4) incl_len(4) orig_len(4) + 包数据(incl_len)
//
// === 为何写纳秒精度 ===
// 写出魔数用 **纳秒变体**（0xa1b23c4d）。PacketBuffer::timestamp_ns 本来就是纳秒，
// 若写微秒格式就得除 1000 做有损截断 —— 「捕获时 123456789ns」与「落盘后 123456000ns」
// 的差异在排查时序问题时是实打实的误导。读取侧两种变体都支持，Wireshark 亦然。
//
// === 为何用 fopen/fwrite 而非缓冲累积 ===
// 抓包是长跑场景，一次抓几百万包时把全部数据留在内存里不可行。故逐包写出，
// 依赖 stdio 的缓冲（默认 4 KiB，可用 setvbuf 调整）。
#pragma once

#include "packet_engine/packet_buffer.h"

#include <cstdint>
#include <cstdio>
#include <string>

namespace packet_engine {

// pcap 写入失败分类。与读取侧的 PcapStatus 分开：写失败的原因集合不同
// （磁盘满、只读挂载、路径无权限），读取侧那套枚举里的「pcapng 魔数」等
// 在这里没有意义。
enum class PcapWriteStatus {
  kOk = 0,
  kNotOpen,     // 未成功 open 就调用 write/close
  kAlreadyOpen, // 重复 open
  kOpenFailed,  // fopen 失败（路径不可写 / 目录不存在 / 权限）
  kWriteFailed, // fwrite 失败（磁盘满 / I/O 错误）—— 唯一需要中途报错的路径
  kBadLinktype, // linktype 不受支持
};

class PcapWriter {
public:
  PcapWriter() = default;
  ~PcapWriter();
  PcapWriter(const PcapWriter&) = delete;
  PcapWriter& operator=(const PcapWriter&) = delete;

  // 打开文件并写出全局头。linktype 用 DLT_*/LINKTYPE_* 编号（以太网为 1）。
  // snaplen 记录到全局头；实际每包的 incl_len 仍以 PacketBuffer::caplen 为准。
  bool open(const char* path, uint32_t linktype = 1, uint32_t snaplen = 65535);
  bool write(const PacketBuffer& pb);
  // 关闭并 flush。返回值反映 flush 是否成功 —— 缓冲里的数据可能直到此刻才落盘，
  // 因此**忽略 close() 的返回值等于不检查写入是否真的成功**。
  bool close();

  bool is_open() const { return fp_ != nullptr; }
  uint64_t written() const { return written_; }
  uint64_t written_bytes() const { return written_bytes_; }
  const char* path() const { return path_.c_str(); }
  PcapWriteStatus error() const { return err_; }
  const char* error_reason() const { return err_reason_.c_str(); }

private:
  std::FILE* fp_ = nullptr;
  std::string path_;
  uint64_t written_ = 0;
  uint64_t written_bytes_ = 0;
  PcapWriteStatus err_ = PcapWriteStatus::kOk;
  std::string err_reason_ = "ok";

  void set_error(PcapWriteStatus s, const std::string& r);
};

} // namespace packet_engine
