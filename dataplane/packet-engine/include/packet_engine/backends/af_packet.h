// backends/af_packet.h - Linux AF_PACKET 抓包后端。
//
// === 为什么不用 libpcap ===
// 与 BPF 后端同一理由：本仓库零第三方依赖；且 AF_PACKET 是 Linux 内核原生接口，
// 无需任何外部库。libpcap 在 Linux 上的实现本身就是 AF_PACKET 的封装。
//
// === 跨发行版通用性（本后端的首要设计目标）===
// 目标平台：Ubuntu / Rocky Linux / openEuler（以及任意 glibc Linux）。
// 三者在这条路径上的**差异都是运行时的，不是编译期的**：
//
//   1. **内核版本决定 TPACKET 版本可用性**：TPACKET_V3（3.2+）、TPACKET_V2（2.6.27+）。
//      Rocky 9（4.18）、openEuler 24.03（5.10/6.6）、Ubuntu 24.04（6.8）都支持 V3，
//      但若目标是更老的 CentOS 7（3.10）则只有 V2。**故版本靠 setsockopt(PACKET_VERSION)
//      运行时探测，绝不写编译期假设** —— 编译机与运行机可以是两个发行版。
//   2. **环形缓冲的尺寸约束由内核校验**：block_size 必须页对齐且是 frame_size 的整数倍，
//      且 frames_per_block * block_nr == frame_nr。不同内核的页大小与额外约束不同
//      （aarch64 常见 64 KiB 页），故尺寸按 PAGE_SIZE 实算，且失败时降级重试。
//   3. **权限模型一致但错误码分发点不同**：都需要 CAP_NET_RAW。无权限时 errno 为
//      EPERM/EACCES —— 本后端把它翻译成含 `setcap` 可操作提示的诊断。
//   4. **接口命名不统一**：ens33 / enp0s3 / eth0 / ens192。本后端**不假设**任何命名，
//      接口名与 index 均可作为绑定目标（见 iface_list.h）。
//
// === 降级链（按序尝试，任一成功即停）===
//     TPACKET_V3（PACKET_MMAP，块聚合 + 超时退休）
//   → TPACKET_V2（PACKET_MMAP，逐帧状态）
//   → 纯 recvfrom（无 mmap，每次系统调用一个包）
// 降级发生时会通过 mode() 与 mode_fallback_reason() 如实上报，**不静默降级** ——
// 「跑在 V2 上」与「跑在 V3 上」的吞吐差一个量级，把它藏起来会让性能问题无法归因。
//
// === 不使用 eBPF/XDP ===
// 刻意规避：XDP 需要更严格的内核版本、编译器对 BPF 的支持、以及各发行版不同的
// BTF/CO-RE 头文件打包方式 —— 那属于 CYS-PKT-006 的范畴。本后端的定位是
// 「三个发行版上开箱可用的采集通路」。
//
// === 生命周期契约（与 pcap_file / bpf_capture 一致）===
// rx_burst 返回的 PacketBuffer::data 指向内核环形缓冲区（mmap 映射）或内部读缓冲。
// **该指针在下一次 rx_burst 调用或 close() 之前有效**，调用方不得跨调用长期持有。
//
// 实现要点：环模式下，已消费完的块**不在本次调用内归还内核**，而是记入待退休队列、
// 延迟到下一次 rx_burst 开头才置 TP_STATUS_KERNEL。若在返回视图的同时就归还，
// 内核可能立刻覆盖该块，调用方读到的是新报文的字节 —— 且不会报任何错误。
// 这正是上面那条「有效期到下一次 rx_burst」契约的由来（不是保守估计，是硬约束）。
#pragma once

#include "packet_engine/backend.h"

#include <cstdint>
#include <string>
#include <vector>

namespace packet_engine {

// AF_PACKET 后端的失败分类。分阶段记录而非只存 errno：「socket 建不出来」「没有
// CAP_NET_RAW」「接口名不存在」「环申请被内核拒了」是四件完全不同的事，排障动作
// 也不同（查容器 capability / 查接口名 / 查内核版本与页大小）。
enum class AfPacketStatus {
  kOk = 0,
  kNotSupported,   // 非 Linux 平台 —— 属配置错误而非运行故障
  kSocketFailed,   // socket(AF_PACKET, ...) 失败
  kPermission,     // EPERM/EACCES —— 缺 CAP_NET_RAW
  kNoSuchIface,    // 接口不存在（ENODEV / if_nametoindex 返回 0）
  kIfaceDown,      // 接口存在但未 UP（无 IFF_UP）
  kBindFailed,     // bind 失败（含协议不支持）
  kVersionFailed,  // PACKET_VERSION 设置失败（内核不支持任何已知版本）
  kRingFailed,     // PACKET_RX_RING 失败（尺寸约束不满足 / 内存不足）
  kMmapFailed,     // mmap 环形缓冲区失败
  kIoError,        // 读失败
};

// 实际生效的采集模式。按代价从低到高排列。
enum class RingMode {
  kRecvfrom = 0, // 无 mmap，逐包系统调用（最后兜底）
  kTpacketV2,    // PACKET_MMAP，逐帧状态位
  kTpacketV3,    // PACKET_MMAP，块聚合（首选）
};

// 模式的稳定字符串名（用于机器可读输出与诊断；不要输出裸枚举值）。
const char* ring_mode_name(RingMode mode);

class AfPacketBackend : public PacketBackend {
public:
  AfPacketBackend();
  ~AfPacketBackend() override;

  // source 为接口名（如 eth0 / ens33），或形如 "ifindex:3" 的按索引指定写法。
  //
  // 支持按索引是为了规避「接口改名」：容器与某些云环境里接口名会在重启后变化，
  // 而索引在同一命名空间内更稳定。两种写法都不需要特权即可解析（校验权限在
  // 建 socket 时才需要）。
  int open(const char* source) override;
  void close() override;
  int rx_burst(PacketBuffer** pkts, uint32_t max) override;

  // AF_PACKET 可写，但发原始帧需要额外处理（sll_halen/sll_addr 填充、部分虚拟
  // 接口拒绝发送），当前无使用场景，故与其它只读后端一致按不支持处理。
  int tx_burst(PacketBuffer** /*pkts*/, uint32_t /*cnt*/) override { return -1; }

  BackendStats stats() override;
  void* native_handle() override;

  AfPacketStatus error() const { return err_; }

  // ---- 覆写基类自省接口 ----
  // 全部覆写是为了让 CLI/服务只经 PacketBackend* 就能拿到这些信息，**无需
  // dynamic_cast 到 AfPacketBackend**。后者会把「有没有 af-packet」这个平台
  // 事实泄漏进工具层的条件编译里 —— 那正是本后端头注释声明的要避免的事。
  const char* error_reason() const override { return err_reason_.c_str(); }
  // 只有 kPermission 算「环境不足」。其余（接口不存在、内核不支持）是配置或
  // 代码问题，在测试中必须记为失败 —— 归错类会让真实缺陷伪装成跳过。
  bool error_is_permission() const override { return err_ == AfPacketStatus::kPermission; }
  uint32_t bound_ifindex() const override { return ifindex_; }
  uint32_t bound_link_type() const override { return link_type_; }
  const char* capture_mode_name() const override { return ring_mode_name(mode_); }
  const char* fallback_reason() const override { return fallback_reason_.c_str(); }

  // 打开前配置。返回**本后端不支持的项**的可读描述（空串表示全部接受）。
  // 集中在此而非散落 setter：CLI 只需填一个 CaptureOptions 结构体，
  // 由后端决定哪些项在此平台/此内核上真正生效。
  std::string configure(const CaptureOptions& options) override;

  uint32_t ifindex() const { return ifindex_; }
  // 链路层类型（ARPHRD_* 值，取自 sockaddr_ll.sll_hatype）。
  // 注意：**不要**用 link_type_name() 之外的映射 —— ARPHRD_* 与 BPF 的 DLT_*
  // 是不同的编号空间（见 backends/link_type.h）。
  uint32_t link_type() const { return link_type_; }
  RingMode mode() const { return mode_; }
  // 降级原因；未发生降级时为空串。用于如实上报「为什么没跑在 V3 上」。
  const std::string& mode_fallback_reason() const { return fallback_reason_; }
  // 环的实配参数（mmap 模式下有效；recvfrom 模式下全为 0）。
  uint32_t block_size() const { return block_size_; }
  uint32_t block_nr() const { return block_nr_; }
  uint32_t frame_size() const { return frame_size_; }
  uint32_t frames_per_block() const { return frames_per_block_; }

  // --- 打开前可调参数 ---
  void set_promisc(bool v) { promisc_ = v; }
  // 期望总环大小（字节）。实际会按页大小与帧尺寸约束上取整，最终值见
  // block_size()*block_nr()。0 表示采用默认（4 MiB）。
  void set_buffer_bytes(uint32_t bytes) { want_buffer_ = bytes; }
  // 抓取长度上限（snaplen）。多出的部分只计 wirelen。
  void set_snap_len(uint32_t n) { snap_len_ = n; }
  // V3 块退休超时（毫秒）。越小延迟越低、开销越高。
  void set_block_retire_ms(uint32_t ms) { retire_ms_ = ms; }
  // 是否允许降级到低版本 TPACKET / recvfrom。默认允许。
  // 关闭后若 V3 不可用则 open 直接失败 —— 用于「必须确证跑在 V3 上」的场景。
  void set_allow_fallback(bool v) { allow_fallback_ = v; }

  // 是否忽略本机发出的包（默认 false，即与 tcpdump 默认行为一致：收发都看）。
  // 对应 PACKET_IGNORE_OUTGOING，该常量自 Linux 4.20 起才有，故在老内核上
  // 本开关会被静默忽略 —— 调用方可经 stats() 与 mode() 之外单独确认，
  // 见 ignore_outgoing_supported()。
  void set_ignore_outgoing(bool v) { ignore_outgoing_ = v; }
  // 本编译环境的内核头文件是否提供 PACKET_IGNORE_OUTGOING。
  static bool ignore_outgoing_supported();

  // 等待一个包到达（poll 语义）。返回 >0 表示可读，0 表示超时，<0 表示错误。
  // 与 rx_burst 分开：rx_burst 保持非阻塞的批量语义，等待策略由调用方决定 ——
  // 把等待塞进 rx_burst 会让「上层想做别的活时无法让出」。
  // 覆写基类默认实现（基类是短暂休眠），此处用真 poll 才能做到零忙等。
  int wait_readable(uint32_t timeout_ms) override;

private:
  int fd_ = -1;
  uint32_t ifindex_ = 0;
  uint32_t link_type_ = 0;
  std::string source_;   // 用户传入的原始 source，用于诊断回显
  std::string iface_;    // 解析后的接口名（按索引指定时回填名字）

  RingMode mode_ = RingMode::kRecvfrom;
  std::string fallback_reason_;

  // 环形缓冲（mmap）
  uint8_t* ring_ = nullptr;
  size_t ring_bytes_ = 0;
  uint32_t block_size_ = 0;
  uint32_t block_nr_ = 0;
  uint32_t frame_size_ = 0;
  uint32_t frames_per_block_ = 0;

  // 待归还内核的块。见头注释「生命周期契约」——延迟退休是正确性要求，不是优化。
  std::vector<uint32_t> pending_retire_;
  uint32_t cur_block_ = 0;
  uint32_t cur_frame_ = 0;
  uint32_t cur_off_ = 0;     // V3：块内当前包的字节偏移
  uint32_t cur_pkts_ = 0;    // V3：本块内已处理的包数
  uint32_t cur_num_pkts_ = 0; // V3：本块的 num_pkts 快照
  uint32_t cur_next_off_ = 0; // V3：下一包的偏移（0 = 本块已空）

  // recvfrom 兜底模式的读缓冲（PacketBuffer::data 指向此处）
  std::vector<uint8_t> recv_buf_;

  // 本批视图的存储。容量在 open 后固定，避免每次 rx_burst 都重新分配。
  std::vector<PacketBuffer> views_;

  bool promisc_ = false;
  bool opened_ = false;
  bool allow_fallback_ = true;
  bool ignore_outgoing_ = false;
  uint32_t want_buffer_ = 0;
  uint32_t snap_len_ = 2048;
  uint32_t retire_ms_ = 20;
  BackendStats stats_{};
  AfPacketStatus err_ = AfPacketStatus::kOk;
  std::string err_reason_;

  void set_error(AfPacketStatus s, const std::string& r);
  void fail_errno(AfPacketStatus default_status, const char* what, int err);

  // 按当前系统页大小算出满足内核约束的环参数。返回 false 表示约束下无解。
  bool compute_ring_params(uint32_t extra_hdr, uint32_t* block_size, uint32_t* block_nr,
                           uint32_t* frame_size, uint32_t* frames_per_block) const;

  // 依次尝试 V3 → V2 → recvfrom 建立采集通路。
  bool setup_v3();
  bool setup_v2();
  bool setup_recvfrom();
  bool apply_common_socket_opts(); // 权限/缓冲区/超时等与版本无关的设置
  bool configure_interface();      // 解析 source、校验接口存在且 UP、bind

  // V3/V2 的单块处理。返回写入 pkts 的个数（0 表示当前无可读块）。
  uint32_t drain_v3_block(PacketBuffer** pkts, uint32_t max);
  uint32_t drain_v2_blocks(PacketBuffer** pkts, uint32_t max);
  void retire_pending(); // 把上一批消费完的块归还内核

  void fill_from_v3_hdr(const void* hdr, PacketBuffer* out, const uint8_t** payload);
  void fill_from_v2_hdr(const void* hdr, PacketBuffer* out, const uint8_t** payload);
};

} // namespace packet_engine
