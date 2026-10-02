// backends/bpf_capture.h - macOS/BSD 原生 BPF 抓包后端。
//
// 为何不用 libpcap：本机实测 /usr/lib/libpcap* 与 SDK 的 pcap 头文件**均不存在**
// （macOS 已不再随系统提供 libpcap 开发文件），而本仓库的既定原则是零第三方依赖
// （见 pcap_file.h 头注释）。BPF（/dev/bpfN）是 macOS 内核提供的原生抓包接口，
// 无需任何外部库。
//
// === 与 Linux AF_PACKET 的对应关系 ===
//   Linux AF_PACKET socket     ↔  macOS /dev/bpfN 字符设备
//   PACKET_RX_RING + mmap      ↔  （本实现未用 mmap，见下）
//   recvfrom() 逐包            ↔  read() 一次返回内核聚合的**多包**
//
// === 本实现只用 read() 路径，不用 mmap ===
// 理由：macOS BPF 的 read() 内核侧已把多个包聚合进同一缓冲，一次系统调用即可取回
// 一批报文 —— 这已满足 PacketBackend 的 rx_burst 批量语义，且无需处理 mmap 的
// 缓冲区页对齐、环形索引与映射失效。**代价**是每次 read 多一次内核到用户态的
// 拷贝，故本后端的定位是「开发环境与跨平台可用性」，高吞吐场景应以 AF_PACKET
// （Linux）或 AF_XDP 为准。此处不做未经验证的性能宣称。
//
// === 生命周期契约（与 pcap_file 一致）===
// rx_burst 返回的 PacketBuffer::data 指向后端内部读缓冲。**该指针在下一次
// rx_burst 调用或 close() 之前有效**，调用方不得跨 rx_burst 长期持有。
#pragma once

#include "packet_engine/backend.h"

#include <cstdint>
#include <string>
#include <vector>

namespace packet_engine {

// BPF 后端的失败分类。分阶段记录而非只存 errno，因为「打不开设备」与「绑不上接口」
// 是完全不同的两件事，排障动作也不同（前者查权限，后者查接口名/网卡状态）。
enum class BpfStatus {
  kOk = 0,
  kNotSupported, // 本平台无 BPF（例如 Linux）—— 属配置错误而非运行故障
  kNoDevice,     // /dev/bpf* 全部不存在（内核未启用 bpf 或不支持的平台）
  kPermission,   // 打开 /dev/bpf* 被拒（EPERM/EACCES）—— 需要 root 或相应权限
  kDeviceBusy,   // 所有 /dev/bpf* 均被占用（EBUSY）
  kNoSuchIface,  // 接口不存在（无效名字）
  kIfaceDown,    // 接口存在但未启用（link down / 未 up）
  kIoctlFailed,  // BIOCSBLEN/BIOCSETIF 等配置 ioctl 失败
  kIoError,      // 读失败
};

// 「看到本机发出的包」设置。三态而非 bool：各 BSD 系对该开关的取值语义并不一致
// （有的平台 0=看、有的 1=看），未经实测不应替用户决定，故默认 kUnspecified
// 表示保持内核默认值不动。
enum class SeeSent {
  kUnspecified = 0,
  kEnable,
  kDisable,
};

class BpfCaptureBackend : public PacketBackend {
public:
  BpfCaptureBackend();
  ~BpfCaptureBackend() override;

  // source 为接口名（如 en0）。绑定的设备路径可由 device() 查询。
  int open(const char* source) override;
  void close() override;
  int rx_burst(PacketBuffer** pkts, uint32_t max) override;

  // BPF 设备可写，但发原始帧需要额外配置（BIOCSHDRCMPLT）且当前无使用场景，
  // 故与 pcap_file 一致按只读后端处理。
  int tx_burst(PacketBuffer** /*pkts*/, uint32_t /*cnt*/) override { return -1; }

  BackendStats stats() override;
  void* native_handle() override;

  // 等待数据可读（poll 语义）。覆写基类的短暂休眠默认实现。
  //
  // 为何不用 read() 自带的 BIOCSRTIMEOUT 代替：那会把「等待」与「取数据」绑成
  // 一次调用，调用方无法在等待期间做别的事（如检查退出标志、打印进度）。分开后
  // 两者各司其职。返回值：>0 可读，0 超时，<0 错误。
  int wait_readable(uint32_t timeout_ms) override;

  BpfStatus error() const { return err_; }

  // ---- 覆写基类自省接口 ----
  // 覆写的理由同 AF_PACKET：让 CLI/服务只经 PacketBackend* 取信息，无需在工具层
  // 做 `#ifdef __APPLE__` 之类的类型判断。
  const char* error_reason() const override { return err_reason_.c_str(); }
  bool error_is_permission() const override { return err_ == BpfStatus::kPermission; }
  uint32_t bound_ifindex() const override { return ifindex_; }
  uint32_t bound_link_type() const override { return link_type_; }
  // 采集路径名。BPF 只有 read 路径一条，无降级链，故返回固定名。
  const char* capture_mode_name() const override { return "bpf"; }

  // 打开前配置。返回**本后端不支持的项**的可读描述（空串表示全部接受）。
  std::string configure(const CaptureOptions& options) override;

  const std::string& device() const { return device_; }
  // 链路层类型（DLT_* 值，取自 BIOCGDLT）。DLT_EN10MB(1) 表示以太网。
  uint32_t link_type() const { return link_type_; }
  uint32_t ifindex() const { return ifindex_; }
  // 内核侧实际生效的读缓冲大小（BIOCSBLEN 会按内核约束调整请求值，此处为回读值）。
  uint32_t buffer_size() const { return buf_size_; }

  // --- 打开前可调参数 ---
  void set_promisc(bool v) { promisc_ = v; }
  void set_see_sent(SeeSent v) { see_sent_ = v; }
  void set_read_timeout_ms(uint32_t ms) { timeout_ms_ = ms; }
  // 请求的读缓冲大小。内核可能向上调整，最终值见 buffer_size()。
  void set_buffer_size(uint32_t bytes) { want_buf_size_ = bytes; }

private:
  int fd_ = -1;
  std::string device_;              // 实际打开的 /dev/bpfN
  std::vector<uint8_t> buf_;        // 读缓冲（PacketBuffer::data 指向此处）
  std::vector<PacketBuffer> views_; // 本批的视图，容量在 open 后固定
  uint32_t want_buf_size_ = 0;      // 请求值（0 = 采用默认）
  uint32_t buf_size_ = 0;           // 内核回读的实际值
  uint32_t timeout_ms_ = 200;
  // 抓取长度上限（snaplen），0 表示不截断。
  //
  // 与 Linux 的差异：BPF **没有** per-packet snaplen 概念（内核按 BIOCSBLEN 缓冲
  // 大小和读请求决定拷回多少），故此处是在用户态交付视图时截断 caplen、并如实
  // 保留完整 wirelen。语义与其它后端一致（caplen < wirelen 即表示截断），
  // 但要注意它省不掉内核到用户态的拷贝。
  uint32_t snap_len_ = 0;
  uint32_t ifindex_ = 0;
  uint32_t link_type_ = 0;
  bool promisc_ = false;
  SeeSent see_sent_ = SeeSent::kUnspecified;
  bool opened_ = false;
  BackendStats stats_{};
  BpfStatus err_ = BpfStatus::kOk;
  std::string err_reason_;

  void set_error(BpfStatus s, const std::string& r);
  // 配置阶段的统一错误处理：把 errno 翻译成分类 + 可操作的中文原因。
  void fail_ioctl(const char* what, int err);
};

} // namespace packet_engine
