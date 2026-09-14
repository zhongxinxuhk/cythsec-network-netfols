// channel/producer.cpp - 共享环 SPSC 生产端实现。
//
// 行为规格来自 Rust 侧 channel/tests.rs 的 TestProducer —— 那份测试专用生产端复刻的
// 正是**契约要求的行为**（满则丢新帧、序号、槽位索引、release 发布顺序），
// 本文件是被它模拟的真实实现。两端行为一致由 scripts/verify/e2e-shared-ring.sh
// 端到端把关：C++ 写真数据、Rust 读并核对序号与统计。

#include "packet_engine/channel/producer.h"

#include <cstring>

#include <unistd.h>

namespace packet_engine {
namespace channel {

bool Producer::create(const char* path, uint32_t slot_count, uint32_t slot_size, Producer* out,
                      AttachError* err) {
  Producer p;
  if (!Channel::create(path, slot_count, slot_size, &p.channel_, err)) {
    return false;
  }
  p.claim_as_producer();
  *out = std::move(p);
  return true;
}

bool Producer::open(const char* path, uint32_t slot_count, uint32_t slot_size, Producer* out,
                    AttachError* err) {
  Producer p;
  // 走 attach_expect 而非 attach：互操作场景下区域可能是上一版配置留下的，
  // 它自身完全自洽（校验全过），只是槽位配置不是本端要的那一个 —— 此时两端布局
  // 不同，写进去的每个描述符对消费端都无意义，而区域自检不会有任何异常。
  if (!Channel::attach_expect(path, slot_count, slot_size, RegionPerm::kReadWrite, &p.channel_,
                              err)) {
    return false;
  }
  p.claim_as_producer();
  *out = std::move(p);
  return true;
}

void Producer::claim_as_producer() {
  ChannelHeader h = channel_.header();
  h.producer_pid = static_cast<uint32_t>(::getpid());
  std::memcpy(channel_.base(), &h, sizeof(ChannelHeader));
  channel_.refresh_header();
}

void Producer::bump(uint32_t offset) {
  channel_.atomic_u64(offset)->fetch_add(1, std::memory_order_relaxed);
}

void Producer::write_slot(uint64_t seq, const uint8_t* frame, size_t len, int64_t timestamp_ns,
                          uint32_t flags, uint32_t wirelen, uint32_t ifindex) {
  const uint32_t slot_count = channel_.slot_count();
  const uint32_t slot_size = channel_.slot_size();
  const ChannelLayout layout = channel_.layout();

  const uint64_t idx = seq % static_cast<uint64_t>(slot_count);
  // 描述符里的 data_off 是**相对数据区起点**的偏移，不是相对区域起点。
  // 两者混用是最难查的一类错：读到的数据看起来总是偏了固定一段。
  const uint32_t slot_data_off = static_cast<uint32_t>(idx * static_cast<uint64_t>(slot_size));

  PacketDescriptor desc{};
  desc.seq = seq;
  desc.timestamp_ns = timestamp_ns;
  desc.caplen = static_cast<uint32_t>(len);
  desc.wirelen = wirelen;
  desc.ifindex = ifindex;
  desc.data_off = slot_data_off;
  desc.flags = flags;

  uint8_t* base = channel_.base();
  uint8_t* data_at = base + static_cast<uint64_t>(layout.data_off) + slot_data_off;
  uint8_t* desc_at =
      base + static_cast<uint64_t>(layout.desc_off) + idx * static_cast<uint64_t>(kDescriptorStep);

  // 先写数据、再写描述符：描述符一旦可见（由调用方的 release 写 head 发布），
  // 它指向的数据必须已经完整落盘。反过来的话，消费端会读到描述符却读到半截数据。
  std::memcpy(data_at, frame, len);
  std::memcpy(desc_at, &desc, sizeof(PacketDescriptor));
}

PublishStatus Producer::publish_bytes(const uint8_t* frame, size_t len, int64_t timestamp_ns,
                                      uint32_t flags, uint32_t ifindex, uint32_t wirelen) {
  if (!open()) {
    return PublishStatus::kNotOpen;
  }
  if (wirelen == 0) {
    wirelen = static_cast<uint32_t>(len);
  }
  if (wirelen > len) {
    flags |= flag::kTruncated;
  }

  const uint32_t slot_count = channel_.slot_count();
  const uint32_t slot_size = channel_.slot_size();

  // 超长帧：计入 dropped 但**不**计 full_events。两者混在一起会让
  // 「是不是消费者太慢」这个问题无从判断 —— 超长与环满是完全不同的运维动作。
  if (len > static_cast<size_t>(slot_size)) {
    bump(header_off::kDropped);
    return PublishStatus::kDroppedTooLarge;
  }

  // head 由本进程独占写，relaxed 读即可；tail 由消费端写，用 acquire 以确保
  // 读到的是消费端真正释放过的位置，而不是一个陈旧的、偏小的值 ——
  // 后者会让环看起来比实际更空，从而覆盖尚未消费的槽位。
  const uint64_t head = channel_.atomic_u64(header_off::kHead)->load(std::memory_order_relaxed);
  const uint64_t tail = channel_.atomic_u64(header_off::kTail)->load(std::memory_order_acquire);

  // 饱和减法，与 Rust 侧 saturating_sub 对齐：tail 越过 head 属消费端异常（由
  // Channel::health 单独诊断），此时积压按 0 计、继续发布，而不是回绕成一个巨大值
  // 把环永久判为满。
  const uint64_t backlog = head > tail ? head - tail : 0;
  if (backlog >= static_cast<uint64_t>(slot_count)) {
    bump(header_off::kDropped);
    bump(header_off::kFull_events);
    return PublishStatus::kDroppedFull;
  }

  write_slot(head, frame, len, timestamp_ns, flags, wirelen, ifindex);
  // release 发布：确保上面写入的数据与描述符对消费端可见之后，head 才递增。
  channel_.atomic_u64(header_off::kHead)->store(head + 1, std::memory_order_release);
  bump(header_off::kPublished);
  return PublishStatus::kPublished;
}

PublishStatus Producer::publish(const PacketBuffer& pkt) {
  if (pkt.data == nullptr) {
    return PublishStatus::kNotOpen;
  }
  // 截断标志由 publish_bytes 按 wirelen > caplen 自动补齐，此处不重复推导。
  return publish_bytes(pkt.data, pkt.caplen, pkt.timestamp_ns, 0, pkt.ifindex, pkt.wirelen);
}

ChannelStats Producer::stats() const {
  ChannelStats s;
  const ChannelHeader& h = channel_.header();
  s.head = channel_.atomic_u64(header_off::kHead)->load(std::memory_order_acquire);
  s.tail = channel_.atomic_u64(header_off::kTail)->load(std::memory_order_acquire);
  s.published = channel_.atomic_u64(header_off::kPublished)->load(std::memory_order_acquire);
  s.consumed = channel_.atomic_u64(header_off::kConsumed)->load(std::memory_order_acquire);
  s.dropped = channel_.atomic_u64(header_off::kDropped)->load(std::memory_order_acquire);
  s.full_events = channel_.atomic_u64(header_off::kFull_events)->load(std::memory_order_acquire);
  s.producer_pid = h.producer_pid;
  s.consumer_pid = h.consumer_pid;
  return s;
}

} // namespace channel
} // namespace packet_engine
