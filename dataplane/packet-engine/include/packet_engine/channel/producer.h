// channel/producer.h - 共享环的 SPSC 生产端（C++ packet-engine 侧）。
//
// 与 Rust 侧 consumer.rs 配对：本端只写 head 与生产者计数器，只读 tail；
// 消费端只写 tail 与消费者计数器，只读 head。共享字段中没有任何一个被两端同时写 ——
// 这是本设计不依赖锁的前提，任何一侧越界写对方的字段都会破坏它且不会立刻报错。
//
// 内存序约定（与 consumer.rs 逐字对应，只有一处定义，改这里即改全局）：
//   生产者  写描述符与数据  ──release──▶  head
//   消费者  acquire 读 head ──读取描述符与数据──▶ tail（release）
//
// 丢弃语义刻意分成两种（与 Rust 侧 TestProducer 一致）：
//   - 超长帧：计 dropped，**不**计 full_events。它确实没被送达，但不属于「环满」，
//     两者混在一起会让「消费者是不是太慢」这个问题无从判断。
//   - 环满：dropped 与 full_events 同时加一。
// 区分这两者是运维可读性的下限：只看 dropped 无法知道该扩容还是该提速消费者。
#pragma once

#include "packet_engine/channel/region.h"
#include "packet_engine/packet_buffer.h"

#include <cstdint>

namespace packet_engine {
namespace channel {

// 通道统计快照（与 Rust 侧 ChannelStats 字段同名同序，便于对照排障）。
struct ChannelStats {
  uint64_t head = 0;
  uint64_t tail = 0;
  uint64_t published = 0;
  uint64_t consumed = 0;
  uint64_t dropped = 0;
  uint64_t full_events = 0;
  uint32_t producer_pid = 0;
  uint32_t consumer_pid = 0;

  // 未被消费的报文数。饱和减法：tail 越过 head 时报告 0 而非回绕成大数 ——
  // 那种情形由 Channel::health 单独诊断，不该在这里表现为一个巨大的积压量。
  uint64_t backlog() const { return head > tail ? head - tail : 0; }
};

enum class PublishStatus {
  kPublished = 0,
  kDroppedTooLarge, // 帧长超过槽容量
  kDroppedFull,     // 环满：未消费槽位已达 slot_count
  kNotOpen,         // 生产端未打开
};

// 一次发布的完整结果。返回状态而非 bool：调用方几乎总要知道「为什么没发出去」，
// 而 dropped 这类计数让它无需自己维护一份平行计数。
struct PublishResult {
  PublishStatus status = PublishStatus::kNotOpen;
  uint64_t seq = 0;     // 发布成功时该帧的序号
  uint64_t dropped = 0; // 累计丢弃数（含本次，若本次被丢弃）
};

class Producer {
public:
  Producer() = default;
  Producer(Producer&&) noexcept = default;
  Producer& operator=(Producer&&) noexcept = default;
  Producer(const Producer&) = delete;
  Producer& operator=(const Producer&) = delete;

  // 创建全新区域并作为生产端打开。
  static bool create(const char* path, uint32_t slot_count, uint32_t slot_size, Producer* out,
                     AttachError* err);

  // 打开已存在区域（校验槽位配置为期望值）。互操作场景下区域可能由 Rust 侧创建，
  // 因此这里走 attach_expect 以拦下「上一版配置的残留区域」。
  static bool open(const char* path, uint32_t slot_count, uint32_t slot_size, Producer* out,
                   AttachError* err);

  // 发布一个报文视图。截断标志由本方法按 caplen < wirelen 自动补上 ——
  // 让调用方自己记得置位，迟早会漏。
  PublishStatus publish(const PacketBuffer& pkt);

  // 从原始字节发布。
  //
  // `wirelen` 传 0 表示「等于 caplen」（未截断）。传大于 len 的值时本方法自动补上
  // 截断标志 —— 让调用方自己记得置位，迟早会漏，而漏掉的后果是消费端把不完整报文
  // 当作完整报文解析。
  PublishStatus publish_bytes(const uint8_t* frame, size_t len, int64_t timestamp_ns,
                              uint32_t flags = 0, uint32_t ifindex = 0, uint32_t wirelen = 0);

  ChannelStats stats() const;

  const Channel& channel() const { return channel_; }
  bool open() const { return channel_.base() != nullptr; }

private:
  // 写一个槽位：数据先写、描述符后写。发布顺序由 publish_* 里的 release 写 head 负责。
  void write_slot(uint64_t seq, const uint8_t* frame, size_t len, int64_t timestamp_ns,
                  uint32_t flags, uint32_t wirelen, uint32_t ifindex);

  // 纯统计量自增。用 Relaxed 而非 Release：这些计数器不承担任何同步职责 ——
  // 真正需要同步的只有 head。给统计量加多余的内存序只会让人误以为
  // 「读到 published 就一定能看到对应数据」。
  void bump(uint32_t offset);

  // 把当前进程标记为本区域的生产者。排障时需要靠它识别残留进程。
  void claim_as_producer();

  Channel channel_;
};

} // namespace channel
} // namespace packet_engine
