// channel/region.cpp - 共享通道区域的映射与校验实现（C++ 生产端侧）。
//
// 校验顺序与 Rust 侧 validate 逐条对应，且顺序本身是契约的一部分：
//   1. 全零魔数（未初始化）  2. 魔数不符  3. ABI 版本  4. 头部尺寸
//   5. 布局相等性（用本端常量按对端记录的配置重算一遍）
//   6. 区域容得下完整布局    7. 基址对齐
// 先「这块内存是不是我们的」再「我们对它的理解是否一致」—— 倒过来会把
// 「区域根本不是通道」报成「布局不符」，指向完全错误的排查方向。

#include "packet_engine/channel/region.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace packet_engine {
namespace channel {

namespace {

// I/O 失败诊断。errno 原样带出而不翻译成自定义码：排障时需要的是能直接
// 拿去查 man page 的那个数字。
AttachError io_error(const char* path, const char* detail, int err_no) {
  diag::ChanIoError d;
  d.detail = detail;
  d.err_no = static_cast<uint32_t>(err_no);
  d.path = path;
  return AttachError::from(d);
}

// 布局计算失败 -> attach 诊断。三个分支各自独立，不合并：它们的排查方向不同
// （改槽位数 / 改槽容量 / 配置本身在算术上不可行）。
AttachError layout_error(LayoutError le, uint32_t slot_count, uint32_t slot_size) {
  switch (le) {
  case LayoutError::kSlotCountOutOfRange: {
    diag::ChanSlotCountOutOfRange d;
    d.value = slot_count;
    d.min_value = kMinSlotCount;
    d.max_value = kMaxSlotCount;
    return AttachError::from(d);
  }
  case LayoutError::kSlotSizeOutOfRange: {
    diag::ChanSlotSizeOutOfRange d;
    d.value = slot_size;
    d.min_value = kMinSlotSize;
    d.max_value = kMaxSlotSize;
    return AttachError::from(d);
  }
  case LayoutError::kSizeOverflow: {
    diag::ChanSizeOverflow d;
    d.slot_count = slot_count;
    d.slot_size = slot_size;
    return AttachError::from(d);
  }
  case LayoutError::kNone:
    break;
  }
  return AttachError{};
}

// 从映射区读取头部。
//
// 用 memcpy 而非指针解引用：映射基址只保证页对齐，结构体字段的偏移是契约值但不保证
// 满足编译器对 ChannelHeader 的对齐假设。memcpy 在编译后就是一条无对齐要求的载入，
// 代价为零而消除了未对齐访问的 UB。Rust 侧对应做法是 read_unaligned。
void read_header(uint8_t* base, ChannelHeader* out) {
  std::memcpy(out, base, sizeof(ChannelHeader));
}

void write_header(uint8_t* base, const ChannelHeader& in) {
  std::memcpy(base, &in, sizeof(ChannelHeader));
}

uint64_t now_ns() {
  const auto d = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(d).count());
}

} // namespace

// ---------------------------------------------------------------- Region

Region::~Region() {
  if (base_ != nullptr) {
    ::munmap(base_, static_cast<size_t>(len_));
  }
  if (fd_ >= 0) {
    ::close(fd_);
  }
}

Region::Region(Region&& other) noexcept : base_(other.base_), len_(other.len_), fd_(other.fd_) {
  other.base_ = nullptr;
  other.len_ = 0;
  other.fd_ = -1;
}

Region& Region::operator=(Region&& other) noexcept {
  if (this != &other) {
    if (base_ != nullptr) {
      ::munmap(base_, static_cast<size_t>(len_));
    }
    if (fd_ >= 0) {
      ::close(fd_);
    }
    base_ = other.base_;
    len_ = other.len_;
    fd_ = other.fd_;
    other.base_ = nullptr;
    other.len_ = 0;
    other.fd_ = -1;
  }
  return *this;
}

// ---------------------------------------------------------------- Channel

bool Channel::map_region(const char* path, RegionPerm perm, uint64_t create_len, AttachError* err) {
  path_ = path;

  int flags = O_RDONLY;
  if (perm == RegionPerm::kReadWrite) {
    flags = O_RDWR;
  }
  if (create_len > 0) {
    flags |= (O_CREAT | O_TRUNC);
  }

  const int fd = ::open(path, flags, 0644);
  if (fd < 0) {
    *err = io_error(path, "open 失败", errno);
    return false;
  }

  if (create_len > 0) {
    if (::ftruncate(fd, static_cast<off_t>(create_len)) != 0) {
      const int e = errno;
      ::close(fd);
      *err = io_error(path, "ftruncate 失败", e);
      return false;
    }
  }

  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    const int e = errno;
    ::close(fd);
    *err = io_error(path, "fstat 失败", e);
    return false;
  }
  const uint64_t len = static_cast<uint64_t>(st.st_size);
  if (len == 0) {
    ::close(fd);
    diag::ChanRegionTooSmall d;
    d.required = 1;
    d.actual = 0;
    *err = AttachError::from(d);
    return false;
  }

  int prot = PROT_READ;
  if (perm == RegionPerm::kReadWrite) {
    prot |= PROT_WRITE;
  }
  void* addr = ::mmap(nullptr, static_cast<size_t>(len), prot, MAP_SHARED, fd, 0);
  if (addr == MAP_FAILED) {
    const int e = errno;
    ::close(fd);
    *err = io_error(path, "mmap 失败", e);
    return false;
  }

  region_.base_ = static_cast<uint8_t*>(addr);
  region_.len_ = len;
  region_.fd_ = fd;
  return true;
}

void Channel::refresh_header() {
  read_header(region_.base_, &header_);
}

bool Channel::validate(AttachError* err) {
  // 1. 全零魔数单独判定：文件刚创建未初始化、被截断、或从没有人写过，都呈现全零；
  //    它与「魔数不对」是两种完全不同的处置方向（重跑创建 vs 排查是否接错区域），
  //    合并成一条会让人往错的方向修。
  bool all_zero = true;
  for (size_t i = 0; i < kMagicLen; ++i) {
    if (header_.magic[i] != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) {
    diag::ChanUninitialized d;
    d.local_magic = kMagicBE;
    d.remote_magic = 0;
    *err = AttachError::from(d);
    return false;
  }

  if (std::memcmp(header_.magic, kMagicBytes, kMagicLen) != 0) {
    uint64_t remote = 0;
    for (size_t i = 0; i < kMagicLen; ++i) {
      remote = (remote << 8) | header_.magic[i];
    }
    diag::ChanMagicMismatch d;
    d.local_magic = kMagicBE;
    d.remote_magic = remote;
    *err = AttachError::from(d);
    return false;
  }

  // 2. 版本与头部尺寸：版本变了则语义整体不可比；头尺寸变了则后面所有偏移都无意义。
  if (header_.abi_version != kAbiVersion) {
    diag::ChanAbiVersionMismatch d;
    d.local = kAbiVersion;
    d.remote = header_.abi_version;
    *err = AttachError::from(d);
    return false;
  }
  if (header_.header_size != kHeaderRegionSize) {
    diag::ChanHeaderSizeMismatch d;
    d.local = kHeaderRegionSize;
    d.remote = header_.header_size;
    *err = AttachError::from(d);
    return false;
  }

  // 3. 用本端常量按对端记录的槽位配置算一遍布局，对端记录的偏移必须与之相符。
  //    这才是「两端常量是否一致」的真正检验 —— 只比常量本身无从发现差异。
  ChannelLayout local{};
  const LayoutError le = channel_layout(header_.slot_count, header_.slot_size, &local);
  if (le != LayoutError::kNone) {
    *err = layout_error(le, header_.slot_count, header_.slot_size);
    return false;
  }

  // 刻意不用 (data_off - desc_off) / slot_count 反推「对端步进」再与 kDescriptorStep 比：
  // 那个反推无法区分「对端槽位数写错」与「对端步进不同」—— 同一组数字下两者同样成立，
  // 于是槽位数写错会被报成步进不符，把人引到错误的字段上。布局相等性已蕴含步进一致。
  if (header_.desc_off != local.desc_off || header_.data_off != local.data_off) {
    diag::ChanLayoutMismatch d;
    d.local_desc = local.desc_off;
    d.remote_desc = header_.desc_off;
    d.local_data = local.data_off;
    d.remote_data = header_.data_off;
    *err = AttachError::from(d);
    return false;
  }

  // 4. 区域必须容得下完整布局。文件被截断是常见事故，且它不会自行报错。
  if (region_.len_ < local.required) {
    diag::ChanRegionTooSmall d;
    d.required = local.required;
    d.actual = region_.len_;
    *err = AttachError::from(d);
    return false;
  }

  // 5. 基址对齐。mmap 本身返回页对齐地址，此检查保护两处现实场景：进程内匿名区域
  //    （测试用堆内存，通常只 16 字节对齐）与未来的偏移映射。
  const uint64_t remainder = reinterpret_cast<uint64_t>(region_.base_) % kRegionAlignment;
  if (remainder != 0) {
    diag::ChanBaseNotAligned d;
    d.required = kRegionAlignment;
    d.remainder = remainder;
    *err = AttachError::from(d);
    return false;
  }

  layout_ = local;
  return true;
}

bool Channel::create(const char* path, uint32_t slot_count, uint32_t slot_size, Channel* out,
                     AttachError* err) {
  ChannelLayout layout{};
  const LayoutError le = channel_layout(slot_count, slot_size, &layout);
  if (le != LayoutError::kNone) {
    *err = layout_error(le, slot_count, slot_size);
    return false;
  }

  Channel ch;
  if (!ch.map_region(path, RegionPerm::kReadWrite, layout.required, err)) {
    return false;
  }

  ChannelHeader h{};
  std::memcpy(h.magic, kMagicBytes, kMagicLen);
  h.abi_version = kAbiVersion;
  h.header_size = kHeaderRegionSize;
  h.desc_off = layout.desc_off;
  h.data_off = layout.data_off;
  h.slot_count = slot_count;
  h.slot_size = slot_size;
  h.flags = 0;
  h.reserved0 = 0;
  h.head = 0;
  h.tail = 0;
  h.published = 0;
  h.consumed = 0;
  h.dropped = 0;
  h.full_events = 0;
  h.created_ns = now_ns();
  h.producer_pid = static_cast<uint32_t>(::getpid());
  h.consumer_pid = 0;
  h.reserved1 = 0;
  h.reserved2 = 0;
  h.reserved3 = 0;
  write_header(ch.region_.base_, h);

  // 数据区清零：未初始化槽位若残留上一轮内容，会被误当作有效描述符 —— 诊断里的
  // 「全零 = 未创建」判定同样依赖这一步。头部区之外全部清零，不做区段细分。
  const uint64_t data_off = static_cast<uint64_t>(layout.data_off);
  if (layout.required > data_off) {
    std::memset(ch.region_.base_ + data_off, 0, static_cast<size_t>(layout.required - data_off));
  }

  ch.refresh_header();
  // 对自己刚写入的头部再跑一遍完整校验：校验逻辑若与写入逻辑不一致，会在这里立刻暴露，
  // 而不是等到消费端 attach 时才以一个难解的布局诊断出现。
  if (!ch.validate(err)) {
    return false;
  }

  *out = std::move(ch);
  return true;
}

bool Channel::attach(const char* path, RegionPerm perm, Channel* out, AttachError* err) {
  Channel ch;
  if (!ch.map_region(path, perm, 0, err)) {
    return false;
  }
  ch.refresh_header();
  if (!ch.validate(err)) {
    return false;
  }
  *out = std::move(ch);
  return true;
}

bool Channel::attach_expect(const char* path, uint32_t slot_count, uint32_t slot_size,
                            RegionPerm perm, Channel* out, AttachError* err) {
  // 先把根基校验跑完，再比对部署期望值。顺序不可换：未初始化或魔数不符的区域，
  // 其 slot_count 字段本身没有意义，拿它比期望值只会报出「槽位数不符」。
  if (!attach(path, perm, out, err)) {
    return false;
  }
  if (out->header_.slot_count != slot_count) {
    diag::ChanSlotCountMismatch d;
    d.local = slot_count;
    d.remote = out->header_.slot_count;
    *err = AttachError::from(d);
    *out = Channel{}; // 失败路径不留下半可用对象：调用方拿到它就会去用错位的区域
    return false;
  }
  if (out->header_.slot_size != slot_size) {
    diag::ChanSlotSizeMismatch d;
    d.local = slot_size;
    d.remote = out->header_.slot_size;
    *err = AttachError::from(d);
    *out = Channel{};
    return false;
  }
  return true;
}

bool Channel::health(AttachError* err) const {
  const uint64_t head = atomic_u64(header_off::kHead)->load(std::memory_order_acquire);
  const uint64_t tail = atomic_u64(header_off::kTail)->load(std::memory_order_acquire);
  if (tail > head) {
    diag::ChanTailAheadOfHead d;
    d.tail = tail;
    d.head = head;
    *err = AttachError::from(d);
    return false;
  }
  return true;
}

} // namespace channel
} // namespace packet_engine
