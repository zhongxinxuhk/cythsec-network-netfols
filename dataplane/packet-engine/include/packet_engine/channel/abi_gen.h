// 由 tools/codegen/gen-channel-abi.py 生成，请勿手工修改。
// 真源：configs/registry/channel-abi.json（registry_version=1.0.0）
//
// 本文件是 C++ 生产端与 Rust 消费端共享的**冻结 ABI**。改动本文件而不动真源，
// 会被 scripts/verify/check-channel-abi.sh 拦下。
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace packet_engine {
namespace channel {
namespace abi {

// ---- 真源标识 ----
inline constexpr char kRegistryVersion[] = "1.0.0";
inline constexpr char kMagicText[] = "CYTHSEC1";
inline constexpr std::size_t kMagicLen = 8;
inline constexpr uint8_t kMagicBytes[kMagicLen] = {0x43, 0x59, 0x54, 0x48, 0x53, 0x45, 0x43, 0x31};
// 魔数的 BE 解读值，仅用于日志与诊断打印（比较一律走字节，避免字节序歧义）。
inline constexpr uint64_t kMagicBE = 0x4359544853454331ULL;

// ---- 通道常量 ----
inline constexpr uint32_t kAbiVersion = 1u;
inline constexpr uint32_t kHeaderRegionSize = 4096u;
inline constexpr uint32_t kDescriptorStep = 64u;
inline constexpr uint32_t kRegionAlignment = 4096u;
inline constexpr uint32_t kDefaultSlotCount = 1024u;
inline constexpr uint32_t kDefaultSlotSize = 2048u;
inline constexpr uint32_t kMinSlotCount = 2u;
inline constexpr uint32_t kMaxSlotCount = 1048576u;
inline constexpr uint32_t kMinSlotSize = 64u;
inline constexpr uint32_t kMaxSlotSize = 65536u;

// ---- ChannelHeader 字段偏移 ----
namespace header_off {
inline constexpr uint32_t kMagic = 0u;
inline constexpr uint32_t kAbi_version = 8u;
inline constexpr uint32_t kHeader_size = 12u;
inline constexpr uint32_t kDesc_off = 16u;
inline constexpr uint32_t kData_off = 20u;
inline constexpr uint32_t kSlot_count = 24u;
inline constexpr uint32_t kSlot_size = 28u;
inline constexpr uint32_t kFlags = 32u;
inline constexpr uint32_t kReserved0 = 36u;
inline constexpr uint32_t kHead = 40u;
inline constexpr uint32_t kTail = 48u;
inline constexpr uint32_t kPublished = 56u;
inline constexpr uint32_t kConsumed = 64u;
inline constexpr uint32_t kDropped = 72u;
inline constexpr uint32_t kFull_events = 80u;
inline constexpr uint32_t kCreated_ns = 88u;
inline constexpr uint32_t kProducer_pid = 96u;
inline constexpr uint32_t kConsumer_pid = 100u;
inline constexpr uint32_t kReserved1 = 104u;
inline constexpr uint32_t kReserved2 = 112u;
inline constexpr uint32_t kReserved3 = 120u;
} // namespace header_off

// ---- PacketDescriptor 字段偏移 ----
namespace desc_off {
inline constexpr uint32_t kSeq = 0u;
inline constexpr uint32_t kTimestamp_ns = 8u;
inline constexpr uint32_t kCaplen = 16u;
inline constexpr uint32_t kWirelen = 20u;
inline constexpr uint32_t kIfindex = 24u;
inline constexpr uint32_t kData_off = 28u;
inline constexpr uint32_t kFlags = 32u;
inline constexpr uint32_t kReserved0 = 36u;
inline constexpr uint32_t kReserved1 = 40u;
inline constexpr uint32_t kReserved2 = 48u;
inline constexpr uint32_t kReserved3 = 56u;
} // namespace desc_off

// ---- 描述符 flags 位 ----
namespace flag {
inline constexpr uint32_t kTruncated = 1u << 0;   // 截断捕获（caplen < wirelen）
inline constexpr uint32_t kVlan_tagged = 1u << 1; // 含 802.1Q / QinQ VLAN 标签
inline constexpr uint32_t kIpv6 = 1u << 2;        // IPv6 报文
inline constexpr uint32_t kSynthetic = 1u << 3;   // 合成报文（非真实抓包，供测试）
} // namespace flag

// ---- 冻结结构体 ----
// 注意：这两个结构体是 POD，不含成员函数与虚表 —— 偏移即 ABI。
// 所有偏移由真源生成 static_assert 固定；改字段顺序会编译失败而非静默错读。

struct ChannelHeader {
  uint8_t magic[8];      // +0    魔数 ASCII，未初始化区域全零
  uint32_t abi_version;  // +8    ABI 版本，attach 期强校验
  uint32_t header_size;  // +12   头部区字节数（含预留），attach 期强校验
  uint32_t desc_off;     // +16   描述符区相对区域起点偏移
  uint32_t data_off;     // +20   数据区相对区域起点偏移
  uint32_t slot_count;   // +24   槽位数量（2 的幂非必需，但建议）
  uint32_t slot_size;    // +28   单槽容量（字节）
  uint32_t flags;        // +32   通道级标志位
  uint32_t reserved0;    // +36   预留
  uint64_t head;         // +40   生产者已发布总数，单调递增（不回绕）
  uint64_t tail;         // +48   消费者已消费总数，单调递增（不回绕）
  uint64_t published;    // +56   生产者累计成功发布（含已被消费）
  uint64_t consumed;     // +64   消费者累计成功消费
  uint64_t dropped;      // +72   生产者因环满/超长而丢弃的报文数
  uint64_t full_events;  // +80   生产者遇到环满的次数（非丢包数）
  uint64_t created_ns;   // +88   区域创建时间（epoch 纳秒）
  uint32_t producer_pid; // +96   生产者 pid，供排障识别残留进程
  uint32_t consumer_pid; // +100  消费者 pid，供排障识别残留进程
  uint64_t reserved1;    // +104  预留
  uint64_t reserved2;    // +112  预留
  uint64_t reserved3;    // +120  预留
};

static_assert(offsetof(ChannelHeader, magic) == 0u, "ChannelHeader.magic 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, abi_version) == 8u,
              "ChannelHeader.abi_version 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, header_size) == 12u,
              "ChannelHeader.header_size 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, desc_off) == 16u,
              "ChannelHeader.desc_off 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, data_off) == 20u,
              "ChannelHeader.data_off 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, slot_count) == 24u,
              "ChannelHeader.slot_count 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, slot_size) == 28u,
              "ChannelHeader.slot_size 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, flags) == 32u, "ChannelHeader.flags 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, reserved0) == 36u,
              "ChannelHeader.reserved0 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, head) == 40u, "ChannelHeader.head 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, tail) == 48u, "ChannelHeader.tail 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, published) == 56u,
              "ChannelHeader.published 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, consumed) == 64u,
              "ChannelHeader.consumed 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, dropped) == 72u, "ChannelHeader.dropped 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, full_events) == 80u,
              "ChannelHeader.full_events 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, created_ns) == 88u,
              "ChannelHeader.created_ns 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, producer_pid) == 96u,
              "ChannelHeader.producer_pid 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, consumer_pid) == 100u,
              "ChannelHeader.consumer_pid 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, reserved1) == 104u,
              "ChannelHeader.reserved1 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, reserved2) == 112u,
              "ChannelHeader.reserved2 偏移与通道 ABI 不符");
static_assert(offsetof(ChannelHeader, reserved3) == 120u,
              "ChannelHeader.reserved3 偏移与通道 ABI 不符");
static_assert(sizeof(ChannelHeader) == 128u, "ChannelHeader 尺寸与通道 ABI 不符");

struct PacketDescriptor {
  uint64_t seq;         // +0    全局单调序号，槽位索引 = seq % slot_count
  int64_t timestamp_ns; // +8    抓包时间戳（epoch 纳秒）
  uint32_t caplen;      // +16   实际写入数据区的字节数
  uint32_t wirelen;     // +20   线上原始长度，caplen<wirelen 表示截断捕获
  uint32_t ifindex;     // +24   接收接口索引（pcap 文件后端为 0）
  uint32_t data_off;    // +28   数据相对数据区起点偏移
  uint32_t flags;       // +32   报文级标志位（见 flags 段）
  uint32_t reserved0;   // +36   预留
  uint64_t reserved1;   // +40   预留
  uint64_t reserved2;   // +48   预留
  uint64_t reserved3;   // +56   预留
};

static_assert(offsetof(PacketDescriptor, seq) == 0u, "PacketDescriptor.seq 偏移与通道 ABI 不符");
static_assert(offsetof(PacketDescriptor, timestamp_ns) == 8u,
              "PacketDescriptor.timestamp_ns 偏移与通道 ABI 不符");
static_assert(offsetof(PacketDescriptor, caplen) == 16u,
              "PacketDescriptor.caplen 偏移与通道 ABI 不符");
static_assert(offsetof(PacketDescriptor, wirelen) == 20u,
              "PacketDescriptor.wirelen 偏移与通道 ABI 不符");
static_assert(offsetof(PacketDescriptor, ifindex) == 24u,
              "PacketDescriptor.ifindex 偏移与通道 ABI 不符");
static_assert(offsetof(PacketDescriptor, data_off) == 28u,
              "PacketDescriptor.data_off 偏移与通道 ABI 不符");
static_assert(offsetof(PacketDescriptor, flags) == 32u,
              "PacketDescriptor.flags 偏移与通道 ABI 不符");
static_assert(offsetof(PacketDescriptor, reserved0) == 36u,
              "PacketDescriptor.reserved0 偏移与通道 ABI 不符");
static_assert(offsetof(PacketDescriptor, reserved1) == 40u,
              "PacketDescriptor.reserved1 偏移与通道 ABI 不符");
static_assert(offsetof(PacketDescriptor, reserved2) == 48u,
              "PacketDescriptor.reserved2 偏移与通道 ABI 不符");
static_assert(offsetof(PacketDescriptor, reserved3) == 56u,
              "PacketDescriptor.reserved3 偏移与通道 ABI 不符");
static_assert(sizeof(PacketDescriptor) == 64u, "PacketDescriptor 尺寸与通道 ABI 不符");

// ---- 布局计算（由真源生成，两端必须用同一套算术）----
// desc_off = align_up(header_region_size, region_alignment)
// data_off = desc_off + slot_count * descriptor_step
// required = data_off + slot_count * slot_size
//
// 中间量一律用 64 位：slot_count 与 slot_size 相乘在极端配置下会溢出 32 位，
// 先溢出再比较得到的「看起来合理」的小数字，是最难查的一类错。
struct ChannelLayout {
  uint32_t desc_off = 0;
  uint32_t data_off = 0;
  uint64_t required = 0;
};

enum class LayoutError {
  kNone = 0,
  kSlotCountOutOfRange,
  kSlotSizeOutOfRange,
  kSizeOverflow,
};

inline constexpr uint64_t kOverflowLimit = 0xFFFFFFFFULL;

// 计算通道布局。成功返回 kNone 并填充 out；失败时 out 不被修改。
inline LayoutError channel_layout(uint32_t slot_count, uint32_t slot_size, ChannelLayout* out) {
  if (slot_count < kMinSlotCount || slot_count > kMaxSlotCount) {
    return LayoutError::kSlotCountOutOfRange;
  }
  if (slot_size < kMinSlotSize || slot_size > kMaxSlotSize) {
    return LayoutError::kSlotSizeOutOfRange;
  }
  const uint64_t desc_off =
      ((static_cast<uint64_t>(kHeaderRegionSize) + kRegionAlignment - 1) / kRegionAlignment) *
      kRegionAlignment;
  const uint64_t data_off = desc_off + static_cast<uint64_t>(slot_count) * kDescriptorStep;
  const uint64_t required = data_off + static_cast<uint64_t>(slot_count) * slot_size;
  if (data_off > kOverflowLimit || required > kOverflowLimit) {
    return LayoutError::kSizeOverflow;
  }
  ChannelLayout v;
  v.desc_off = static_cast<uint32_t>(desc_off);
  v.data_off = static_cast<uint32_t>(data_off);
  v.required = required;
  if (out != nullptr)
    *out = v;
  return LayoutError::kNone;
}

// ---- 诊断严重度 ----
enum class Severity : uint8_t { kWarning = 0, kError = 1 };

// 严重度字符串：与 Rust 端 as_str() 一致，是 parity 校验的一部分。
inline const char* to_string(Severity s) {
  return s == Severity::kError ? "error" : "warning";
}

// ---- 诊断（码 + 文案均由真源生成，保证两端逐字一致）----
namespace diag {

// chan.uninitialized（error）
inline constexpr char kChanUninitializedCode[] = "chan.uninitialized";
// chan.magic_mismatch（error）
inline constexpr char kChanMagicMismatchCode[] = "chan.magic_mismatch";
// chan.abi_version_mismatch（error）
inline constexpr char kChanAbiVersionMismatchCode[] = "chan.abi_version_mismatch";
// chan.header_size_mismatch（error）
inline constexpr char kChanHeaderSizeMismatchCode[] = "chan.header_size_mismatch";
// chan.layout_mismatch（error）
inline constexpr char kChanLayoutMismatchCode[] = "chan.layout_mismatch";
// chan.slot_count_out_of_range（error）
inline constexpr char kChanSlotCountOutOfRangeCode[] = "chan.slot_count_out_of_range";
// chan.slot_size_out_of_range（error）
inline constexpr char kChanSlotSizeOutOfRangeCode[] = "chan.slot_size_out_of_range";
// chan.size_overflow（error）
inline constexpr char kChanSizeOverflowCode[] = "chan.size_overflow";
// chan.region_too_small（error）
inline constexpr char kChanRegionTooSmallCode[] = "chan.region_too_small";
// chan.base_not_aligned（error）
inline constexpr char kChanBaseNotAlignedCode[] = "chan.base_not_aligned";
// chan.io_error（error）
inline constexpr char kChanIoErrorCode[] = "chan.io_error";
// chan.truncated_packet（error）
inline constexpr char kChanTruncatedPacketCode[] = "chan.truncated_packet";
// chan.tail_ahead_of_head（error）
inline constexpr char kChanTailAheadOfHeadCode[] = "chan.tail_ahead_of_head";

// chan.uninitialized
struct ChanUninitialized {
  static const char* code() { return kChanUninitializedCode; }
  static Severity severity() { return Severity::kError; }
  uint64_t local_magic = 0;
  uint64_t remote_magic = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt = "通道区域未初始化：本端期望魔数 0x%016llx，对端为 "
                       "0x%016llx；该区域可能尚未创建，或已被清零/截断（截断文件同样呈现全零）";
    const int need = std::snprintf(nullptr, 0, kFmt, static_cast<unsigned long long>(local_magic),
                                   static_cast<unsigned long long>(remote_magic));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned long long>(local_magic),
                  static_cast<unsigned long long>(remote_magic));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanUninitialized v{};
    v.local_magic = 4853002743079846705ULL;
    v.remote_magic = 0ULL;
    return v.format();
  }
};

// chan.magic_mismatch
struct ChanMagicMismatch {
  static const char* code() { return kChanMagicMismatchCode; }
  static Severity severity() { return Severity::kError; }
  uint64_t local_magic = 0;
  uint64_t remote_magic = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt = "通道魔数不匹配：本端 0x%016llx，对端 0x%016llx；该区域不是 CythSec "
                       "通道区域，或两端魔数约定不一致";
    const int need = std::snprintf(nullptr, 0, kFmt, static_cast<unsigned long long>(local_magic),
                                   static_cast<unsigned long long>(remote_magic));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned long long>(local_magic),
                  static_cast<unsigned long long>(remote_magic));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanMagicMismatch v{};
    v.local_magic = 4853002743079846705ULL;
    v.remote_magic = 3549757155296172355ULL;
    return v.format();
  }
};

// chan.abi_version_mismatch
struct ChanAbiVersionMismatch {
  static const char* code() { return kChanAbiVersionMismatchCode; }
  static Severity severity() { return Severity::kError; }
  uint32_t local = 0;
  uint32_t remote = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt = "通道 ABI 版本不匹配：本端 v%u，对端 "
                       "v%u；契约语义已变更，两端必须同时升级（禁止跨版本共享区域）";
    const int need = std::snprintf(nullptr, 0, kFmt, static_cast<unsigned>(local),
                                   static_cast<unsigned>(remote));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned>(local),
                  static_cast<unsigned>(remote));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanAbiVersionMismatch v{};
    v.local = 1ULL;
    v.remote = 2ULL;
    return v.format();
  }
};

// chan.header_size_mismatch
struct ChanHeaderSizeMismatch {
  static const char* code() { return kChanHeaderSizeMismatchCode; }
  static Severity severity() { return Severity::kError; }
  uint32_t local = 0;
  uint32_t remote = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt =
        "通道头部尺寸不匹配：本端 %u 字节，对端 %u 字节；描述符区与数据区偏移将随之错位";
    const int need = std::snprintf(nullptr, 0, kFmt, static_cast<unsigned>(local),
                                   static_cast<unsigned>(remote));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned>(local),
                  static_cast<unsigned>(remote));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanHeaderSizeMismatch v{};
    v.local = 4096ULL;
    v.remote = 2048ULL;
    return v.format();
  }
};

// chan.layout_mismatch
struct ChanLayoutMismatch {
  static const char* code() { return kChanLayoutMismatchCode; }
  static Severity severity() { return Severity::kError; }
  uint32_t local_desc = 0;
  uint32_t remote_desc = 0;
  uint32_t local_data = 0;
  uint32_t remote_data = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt = "通道布局偏移不一致：描述符区 本端 %u 对端 %u；数据区 本端 %u 对端 %u";
    const int need = std::snprintf(
        nullptr, 0, kFmt, static_cast<unsigned>(local_desc), static_cast<unsigned>(remote_desc),
        static_cast<unsigned>(local_data), static_cast<unsigned>(remote_data));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned>(local_desc),
                  static_cast<unsigned>(remote_desc), static_cast<unsigned>(local_data),
                  static_cast<unsigned>(remote_data));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanLayoutMismatch v{};
    v.local_desc = 4096ULL;
    v.remote_desc = 4128ULL;
    v.local_data = 69632ULL;
    v.remote_data = 69664ULL;
    return v.format();
  }
};

// chan.slot_count_out_of_range
struct ChanSlotCountOutOfRange {
  static const char* code() { return kChanSlotCountOutOfRangeCode; }
  static Severity severity() { return Severity::kError; }
  uint32_t value = 0;
  uint32_t min_value = 0;
  uint32_t max_value = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt = "通道槽位数越界：请求 %u，允许区间 [%u, %u]";
    const int need =
        std::snprintf(nullptr, 0, kFmt, static_cast<unsigned>(value),
                      static_cast<unsigned>(min_value), static_cast<unsigned>(max_value));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned>(value),
                  static_cast<unsigned>(min_value), static_cast<unsigned>(max_value));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanSlotCountOutOfRange v{};
    v.value = 2097152ULL;
    v.min_value = 2ULL;
    v.max_value = 1048576ULL;
    return v.format();
  }
};

// chan.slot_size_out_of_range
struct ChanSlotSizeOutOfRange {
  static const char* code() { return kChanSlotSizeOutOfRangeCode; }
  static Severity severity() { return Severity::kError; }
  uint32_t value = 0;
  uint32_t min_value = 0;
  uint32_t max_value = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt = "通道槽容量越界：请求 %u 字节，允许区间 [%u, %u]";
    const int need =
        std::snprintf(nullptr, 0, kFmt, static_cast<unsigned>(value),
                      static_cast<unsigned>(min_value), static_cast<unsigned>(max_value));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned>(value),
                  static_cast<unsigned>(min_value), static_cast<unsigned>(max_value));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanSlotSizeOutOfRange v{};
    v.value = 131072ULL;
    v.min_value = 64ULL;
    v.max_value = 65536ULL;
    return v.format();
  }
};

// chan.size_overflow
struct ChanSizeOverflow {
  static const char* code() { return kChanSizeOverflowCode; }
  static Severity severity() { return Severity::kError; }
  uint32_t slot_count = 0;
  uint32_t slot_size = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt = "通道区域尺寸计算溢出：槽位数 %u × 槽容量 %u 超出可表示范围";
    const int need = std::snprintf(nullptr, 0, kFmt, static_cast<unsigned>(slot_count),
                                   static_cast<unsigned>(slot_size));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned>(slot_count),
                  static_cast<unsigned>(slot_size));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanSizeOverflow v{};
    v.slot_count = 1048576ULL;
    v.slot_size = 65536ULL;
    return v.format();
  }
};

// chan.region_too_small
struct ChanRegionTooSmall {
  static const char* code() { return kChanRegionTooSmallCode; }
  static Severity severity() { return Severity::kError; }
  uint64_t required = 0;
  uint64_t actual = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt =
        "通道区域过小：需要 %llu 字节，实际 %llu 字节；请用匹配的槽位配置创建或检查文件是否被截断";
    const int need = std::snprintf(nullptr, 0, kFmt, static_cast<unsigned long long>(required),
                                   static_cast<unsigned long long>(actual));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned long long>(required),
                  static_cast<unsigned long long>(actual));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanRegionTooSmall v{};
    v.required = 2166784ULL;
    v.actual = 4096ULL;
    return v.format();
  }
};

// chan.base_not_aligned
struct ChanBaseNotAligned {
  static const char* code() { return kChanBaseNotAlignedCode; }
  static Severity severity() { return Severity::kError; }
  uint32_t required = 0;
  uint64_t remainder = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt = "通道区域基址未对齐：要求 %u 字节对齐，实际余数 "
                       "%llu；未对齐会破坏缓存行隔离并可能触发未对齐原子访问";
    const int need = std::snprintf(nullptr, 0, kFmt, static_cast<unsigned>(required),
                                   static_cast<unsigned long long>(remainder));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned>(required),
                  static_cast<unsigned long long>(remainder));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanBaseNotAligned v{};
    v.required = 4096ULL;
    v.remainder = 24ULL;
    return v.format();
  }
};

// chan.io_error
struct ChanIoError {
  static const char* code() { return kChanIoErrorCode; }
  static Severity severity() { return Severity::kError; }
  const char* detail = nullptr;
  uint32_t err_no = 0;
  const char* path = nullptr;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt = "通道区域 I/O 失败：%s（errno=%u，路径=%s）";
    const int need =
        std::snprintf(nullptr, 0, kFmt, (detail != nullptr ? detail : "(null)"),
                      static_cast<unsigned>(err_no), (path != nullptr ? path : "(null)"));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, (detail != nullptr ? detail : "(null)"),
                  static_cast<unsigned>(err_no), (path != nullptr ? path : "(null)"));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanIoError v{};
    v.detail = "mmap 失败";
    v.err_no = 13ULL;
    v.path = "/run/cythsec/chan0";
    return v.format();
  }
};

// chan.truncated_packet
struct ChanTruncatedPacket {
  static const char* code() { return kChanTruncatedPacketCode; }
  static Severity severity() { return Severity::kError; }
  uint32_t caplen = 0;
  uint32_t slot_size = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt = "报文长度 %u 超过槽容量 %u：回放端应开启截断或调大 --slot-size";
    const int need = std::snprintf(nullptr, 0, kFmt, static_cast<unsigned>(caplen),
                                   static_cast<unsigned>(slot_size));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned>(caplen),
                  static_cast<unsigned>(slot_size));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanTruncatedPacket v{};
    v.caplen = 9000ULL;
    v.slot_size = 2048ULL;
    return v.format();
  }
};

// chan.tail_ahead_of_head
struct ChanTailAheadOfHead {
  static const char* code() { return kChanTailAheadOfHeadCode; }
  static Severity severity() { return Severity::kError; }
  uint64_t tail = 0;
  uint64_t head = 0;

  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，
  // 定长缓冲会在最需要看到完整路径时把尾部截掉。
  std::string format() const {
    const char* kFmt =
        "消费位置越过生产位置：消费位置 %llu 大于生产位置 %llu；此时「待消费数」恒为 "
        "0，消费端会一直报告无数据，而报文在背后持续堆积——不报错、不崩溃，只是全部静默丢弃。成因通"
        "常是区域被上一版进程以不同槽位配置写过、或该区域被手工清零过一半";
    const int need = std::snprintf(nullptr, 0, kFmt, static_cast<unsigned long long>(tail),
                                   static_cast<unsigned long long>(head));
    if (need <= 0)
      return std::string();
    std::vector<char> buf(static_cast<std::size_t>(need) + 1);
    std::snprintf(buf.data(), buf.size(), kFmt, static_cast<unsigned long long>(tail),
                  static_cast<unsigned long long>(head));
    return std::string(buf.data(), static_cast<std::size_t>(need));
  }

  // parity 校验用的确定性样本（取值亦来自真源）。
  static std::string sample() {
    ChanTailAheadOfHead v{};
    v.tail = 128ULL;
    v.head = 0ULL;
    return v.format();
  }
};

} // namespace diag
} // namespace abi
} // namespace channel
} // namespace packet_engine
