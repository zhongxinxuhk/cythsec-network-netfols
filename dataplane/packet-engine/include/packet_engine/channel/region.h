// channel/region.h - 共享通道区域的映射与校验（C++ 生产端侧）。
//
// 与 Rust 侧 dataplane/traffic-engine/src/channel/region.rs 是**同一份契约的两个实现**：
// 布局算术、校验顺序、诊断码与文案全部由 abi_gen.h / abi_gen.rs 从同一真源
// （configs/registry/channel-abi.json）生成，因此两端措辞逐字一致 —— 排障的人不该
// 因为两侧输出不同而以为遇到了两个问题。
//
// 本文件只负责「映射 + 校验」这一层，不涉及收发语义（那在 producer.h）。
//
// 刻意不做任何容错：跨语言共享内存的失败模式是不崩、只错读 —— 偏移差 8 字节就永久错位，
// 之后读到的每个字段都无意义却不会报错。故此处策略是「宁可拒绝启动，也不带着错误的
// 理解继续跑」，所有不一致都在 attach 期中断。
//
// 映射机制与 Rust 侧刻意保持同构：普通文件 + open/ftruncate + mmap(MAP_SHARED)，
// 不是 POSIX shm_open。两端用同一套机制是互操作的前提 —— 任一侧改用另一套，
// 另一侧就再也映射不到同一块内存，且失败现象是「读到全零」而非报错。
#pragma once

#include "packet_engine/channel/abi_gen.h"

#include <atomic>
#include <cstdint>
#include <string>

namespace packet_engine {
namespace channel {

// 契约层的全部符号都来自真源生成的 abi 命名空间。这里**逐个显式引入**用到的名字，
// 而不是 `using namespace abi;`：后者会把整套契约名字（ChannelHeader、Severity 等
// 相当通用的标识符）泄漏给本头文件的每一个包含者，在别处造成难以定位的名字歧义。
using abi::channel_layout;
using abi::ChannelHeader;
using abi::ChannelLayout;
using abi::kAbiVersion;
using abi::kDescriptorStep;
using abi::kHeaderRegionSize;
using abi::kMagicBE;
using abi::kMagicBytes;
using abi::kMagicLen;
using abi::kMaxSlotCount;
using abi::kMaxSlotSize;
using abi::kMinSlotCount;
using abi::kMinSlotSize;
using abi::kRegionAlignment;
using abi::LayoutError;
using abi::PacketDescriptor;
using abi::Severity;

// 命名空间别名：让 `diag::ChanXxx` / `header_off::kHead` / `flag::kTruncated`
// 与 Rust 侧 `diag::` `header_off::` `flag::` 的写法逐字对应，两端读起来是同一套代码。
namespace diag = abi::diag;
namespace flag = abi::flag;
namespace header_off = abi::header_off;

// 区域映射权限。生产端需要写权限（要更新 head）；只读用于巡检类工具。
enum class RegionPerm {
  kReadOnly,
  kReadWrite,
};

// attach 失败原因：稳定诊断码 + 严重度 + 已渲染文案。
//
// 三者都由真源生成的诊断结构体提供，本类型只做承载 —— 不在这里拼接任何文案，
// 否则两端生成的文案就会分叉，而分叉处正是最需要一致的地方。
struct AttachError {
  std::string code;
  Severity severity = Severity::kError;
  std::string message;

  bool empty() const { return code.empty(); }

  // 从真源的诊断结构体构造（`D::code()` 静态，`format()` 实例）。
  template <typename D> static AttachError from(const D& d) {
    AttachError e;
    e.code = D::code();
    e.severity = D::severity();
    e.message = d.format();
    return e;
  }
};

// 映射区句柄：RAII 管理 mmap/munmap 与文件描述符。
//
// 移动语义只为了让 Channel 能从工厂函数返回；拷贝被显式禁止 —— 两次 munmap 同一地址
// 是进程级崩溃，而这类崩溃出现在析构里，堆栈与被误用的对象毫无关系。
class Region {
public:
  Region() = default;
  ~Region();
  Region(Region&& other) noexcept;
  Region& operator=(Region&& other) noexcept;
  Region(const Region&) = delete;
  Region& operator=(const Region&) = delete;

  uint8_t* base() const { return base_; }
  uint64_t len() const { return len_; }
  bool valid() const { return base_ != nullptr; }

private:
  friend class Channel;

  uint8_t* base_ = nullptr;
  uint64_t len_ = 0;
  int fd_ = -1;
};

// 已 attach 的通道：持有映射、已校验的头部快照与布局。
//
// 头部另存一份快照而非每次读映射：attach 之后头部字段即视为冻结（两端约定），
// 快照让「校验时看到的值」与「后续一直用的值」是同一组，避免校验通过之后
// 又被并发修改而无人察觉。
class Channel {
public:
  Channel() = default;
  Channel(Channel&&) noexcept = default;
  Channel& operator=(Channel&&) noexcept = default;
  Channel(const Channel&) = delete;
  Channel& operator=(const Channel&) = delete;

  // 创建并 attach 一个全新区域。文件按 layout.required 截断，头部与数据区全部清零后
  // 写入头部 —— 清零是关键：诊断里「全零魔数 = 未创建」依赖它。
  static bool create(const char* path, uint32_t slot_count, uint32_t slot_size, Channel* out,
                     AttachError* err);

  // 以默认配置为期望值 attach（只看区域自洽性，不比对部署期望）。
  static bool attach(const char* path, RegionPerm perm, Channel* out, AttachError* err);

  // attach 并校验槽位配置确为期望值。
  //
  // 期望值比对**必须排在根基校验之后**：未初始化或魔数不符的区域，其 slot_count 字段
  // 本身就没有意义，拿它去比期望值只会报出「槽位数不符」，把排障的人引向错误的字段。
  static bool attach_expect(const char* path, uint32_t slot_count, uint32_t slot_size,
                            RegionPerm perm, Channel* out, AttachError* err);

  const ChannelHeader& header() const { return header_; }
  const ChannelLayout& layout() const { return layout_; }
  uint32_t slot_count() const { return header_.slot_count; }
  uint32_t slot_size() const { return header_.slot_size; }
  uint8_t* base() const { return region_.base(); }
  uint64_t len() const { return region_.len(); }

  // 头部内某个 u64 计数器的原子视图。
  //
  // 把映射内的地址重新解释为 std::atomic 是刻意的：Rust 侧同样是
  // `&AtomicU64`（见 region.rs 的 atomic_u64），两端必须用同一套手法才能共享内存序
  // 语义。合法性由下面两条 static_assert 守着 —— 一旦 std::atomic<uint64_t> 不再是
  // 「与 uint64_t 同布局且无锁」，编译就会失败，而不是在运行时悄悄出错。
  std::atomic<uint64_t>* atomic_u64(uint32_t offset) const {
    return reinterpret_cast<std::atomic<uint64_t>*>(region_.base() + offset);
  }

  // 重读头部快照（消费端在生产端推进 head 后需据此刷新）。
  void refresh_header();

  // 结构性自检：消费位置不得越过生产位置。
  //
  // 单列为一种失败而非顺带判断，是因为它极具欺骗性：head - tail 用饱和减法恒为 0，
  // 于是消费端**永远报告「当前无数据」**，既不报错也不阻塞，而生产端在背后持续丢包。
  bool health(AttachError* err) const;

  const char* path() const { return path_.c_str(); }

private:
  bool map_region(const char* path, RegionPerm perm, uint64_t create_len, AttachError* err);
  bool validate(AttachError* err);

  Region region_;
  ChannelHeader header_{};
  ChannelLayout layout_{};
  std::string path_;
};

// 两条前提断言：std::atomic<uint64_t> 必须与 uint64_t 同尺寸且无锁，否则上述
// reinterpret_cast 手法不成立。放在头文件里，让每个引用者都参与守卫。
static_assert(sizeof(std::atomic<uint64_t>) == sizeof(uint64_t),
              "std::atomic<uint64_t> 必须与 uint64_t 同布局，否则共享区域内的原子访问不成立");
static_assert(std::atomic<uint64_t>::is_always_lock_free,
              "std::atomic<uint64_t> 必须无锁：带锁实现无法用于跨进程共享内存");

} // namespace channel
} // namespace packet_engine
