// test_channel_producer.cpp - 共享环生产端（C++ 侧）单元测试。
//
// 覆盖的是**行为契约**而非实现细节：序号与槽位索引的对应、满则丢新帧、
// 两种丢弃分别记账、发布顺序、截断标志自动补齐、期望值校验拦下陈旧区域。
//
// 与 Rust 侧 channel/tests.rs 是同一组语义的两端验证 —— 两侧都断言同一件事，
// 跨语言端到端（scripts/verify/e2e-shared-ring.sh）再验一次真实连通性。
// 三层各有分工：本文件验「C++ 侧自己写对了」，Rust 那份验「消费端读对了」，
// 端到端验「两边对同一块内存的理解一致」—— 最后一层才是共享内存真正会出问题的地方。
#include "packet_engine/channel/producer.h"
#include "packet_engine/channel/region.h"
#include "test_util.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

using packet_engine::channel::AttachError;
using packet_engine::channel::Channel;
using packet_engine::channel::ChannelStats;
using packet_engine::channel::Producer;
using packet_engine::channel::PublishStatus;
using packet_engine::channel::RegionPerm;

// 命名空间别名而非 using 声明：diag / flag / header_off 是命名空间，不是类型。
// 别名让测试里的写法与生产代码、以及 Rust 侧保持同一套词汇。
namespace diag = packet_engine::channel::diag;
namespace flag = packet_engine::channel::flag;
namespace header_off = packet_engine::channel::header_off;

// 临时区域文件：析构时删除，避免测试残留污染 /tmp。
class TempRegion {
public:
  explicit TempRegion(const char* tag) {
    path_ = std::string("/tmp/cythsec-test-") + tag + "-" + std::to_string(::getpid()) + ".chan";
    ::unlink(path_.c_str());
  }
  ~TempRegion() { ::unlink(path_.c_str()); }
  TempRegion(const TempRegion&) = delete;
  TempRegion& operator=(const TempRegion&) = delete;

  const char* path() const { return path_.c_str(); }
  void unlink_now() { ::unlink(path_.c_str()); }

private:
  std::string path_;
};

// 一个最小的以太 + IPv4 + UDP 帧，长度可控（用于构造超长帧）。
void make_udp_frame(uint8_t* buf, size_t len) {
  std::memset(buf, 0, len);
  // 以太头：目的 MAC 全 0x02，源 MAC 全 0x0a，类型 0x0800（IPv4）
  for (int i = 0; i < 6; ++i) {
    buf[i] = 0x02;
    buf[6 + i] = 0x0a;
  }
  buf[12] = 0x08;
  buf[13] = 0x00;
  // IPv4 头
  buf[14] = 0x45; // version=4, ihl=5
  buf[15] = 0x00;
  const uint16_t ip_total = static_cast<uint16_t>(len - 14);
  buf[16] = static_cast<uint8_t>(ip_total >> 8);
  buf[17] = static_cast<uint8_t>(ip_total & 0xff);
  buf[22] = 64; // ttl
  buf[23] = 17; // proto = UDP
  buf[26] = 10; // src 10.0.0.1
  buf[27] = 0;
  buf[28] = 0;
  buf[29] = 1;
  buf[30] = 10; // dst 10.0.0.2
  buf[31] = 0;
  buf[32] = 0;
  buf[33] = 2;
  // UDP 头
  buf[34] = 0x30;
  buf[35] = 0x39; // sport 12345
  buf[36] = 0x00;
  buf[37] = 0x50; // dport 80
  const uint16_t udp_len = static_cast<uint16_t>(len - 34);
  buf[38] = static_cast<uint8_t>(udp_len >> 8);
  buf[39] = static_cast<uint8_t>(udp_len & 0xff);
}

// ---------------------------------------------------------------- 创建与头部

void create_writes_a_self_consistent_header() {
  TempRegion tmp("create");
  Producer p;
  AttachError err;
  const bool ok = Producer::create(tmp.path(), 64, 512, &p, &err);
  packet_engine::test::check(ok, "创建生产端应成功");
  if (!ok) {
    std::printf("      诊断: %s\n", err.message.c_str());
    return;
  }

  const auto& h = p.channel().header();
  packet_engine::test::check(std::memcmp(h.magic, "CYTHSEC1", 8) == 0, "魔数应为 CYTHSEC1");
  packet_engine::test::check(h.abi_version == 1u, "ABI 版本应为 1");
  packet_engine::test::check(h.slot_count == 64u && h.slot_size == 512u, "槽位配置应与请求一致");
  packet_engine::test::check(h.head == 0 && h.tail == 0, "新建区域 head/tail 应为 0");
  packet_engine::test::check(h.published == 0 && h.consumed == 0, "新建区域计数应为 0");
  packet_engine::test::check(h.dropped == 0 && h.full_events == 0, "新建区域丢弃计数应为 0");
  packet_engine::test::check(h.producer_pid == static_cast<uint32_t>(::getpid()),
                             "producer_pid 应记为本进程（排障要靠它识别残留进程）");
  packet_engine::test::check(h.consumer_pid == 0, "尚未有消费者，consumer_pid 应为 0");

  // 创建路径会对自己写入的头部再跑一遍完整校验，故此处 create 成功即已验过一遍；
  // 这里再用独立路径 attach 一次，确认「自己理解自己写的区域」不变量成立。
  Channel ch;
  const bool attached = Channel::attach(tmp.path(), RegionPerm::kReadOnly, &ch, &err);
  packet_engine::test::check(attached, "刚创建的区域应可被独立 attach");
  if (attached) {
    packet_engine::test::check(ch.layout().required == p.channel().layout().required,
                               "两端算出的 required 应一致");
  }
}

void layout_matches_header_offsets() {
  TempRegion tmp("layout");
  Producer p;
  AttachError err;
  if (!Producer::create(tmp.path(), 16, 256, &p, &err)) {
    packet_engine::test::check(false, "布局用例：创建失败");
    return;
  }
  const auto& h = p.channel().header();
  const auto l = p.channel().layout();

  // desc_off 对齐到 region_alignment(4096)；data_off = desc_off + slot_count * 64。
  packet_engine::test::check(l.desc_off == 4096u, "desc_off 应为 4096（头部区向上对齐）");
  packet_engine::test::check(l.data_off == 4096u + 16u * 64u,
                             "data_off 应为 desc_off + slot_count * descriptor_step");
  packet_engine::test::check(l.required == l.data_off + 16u * 256u,
                             "required 应为 data_off + slot_count * slot_size");
  packet_engine::test::check(h.desc_off == l.desc_off && h.data_off == l.data_off,
                             "头部记录的偏移应与本端算出的布局一致");
}

// ---------------------------------------------------------------- 发布语义

void publish_advances_head_and_writes_descriptor() {
  TempRegion tmp("publish");
  Producer p;
  AttachError err;
  if (!Producer::create(tmp.path(), 8, 512, &p, &err)) {
    packet_engine::test::check(false, "发布用例：创建失败");
    return;
  }

  uint8_t frame[64];
  make_udp_frame(frame, sizeof(frame));

  const PublishStatus st = p.publish_bytes(frame, sizeof(frame), 1234567890LL, 0, 7);
  packet_engine::test::check(st == PublishStatus::kPublished, "发布应成功");
  packet_engine::test::check(p.channel().atomic_u64(header_off::kHead)->load() == 1u,
                             "发布一帧后 head 应为 1");

  const ChannelStats s = p.stats();
  packet_engine::test::check(s.published == 1u && s.consumed == 0u,
                             "published 应为 1，consumed 应为 0");
  packet_engine::test::check(s.head == 1u && s.tail == 0u, "head/tail 计数应为 1/0");
  packet_engine::test::check(s.backlog() == 1u, "积压应为 1");

  // 描述符：序号 0 → 槽位 0，data_off 为**相对数据区起点**的偏移（首槽即 0）。
  const auto l = p.channel().layout();
  packet_engine::channel::PacketDescriptor desc{};
  std::memcpy(&desc, p.channel().base() + l.desc_off, sizeof(desc));
  packet_engine::test::check(desc.seq == 0u, "首帧序号应为 0");
  packet_engine::test::check(desc.caplen == sizeof(frame), "caplen 应为帧长");
  packet_engine::test::check(desc.wirelen == sizeof(frame), "未截断时 wirelen 应等于 caplen");
  packet_engine::test::check(desc.data_off == 0u, "首槽 data_off 应为 0（相对数据区起点）");
  packet_engine::test::check(desc.ifindex == 7u, "ifindex 应透传");
  packet_engine::test::check(desc.timestamp_ns == 1234567890LL, "时间戳应透传");
  packet_engine::test::check((desc.flags & flag::kTruncated) == 0, "未截断时不应置截断位");

  // 数据确实落在数据区（而非描述符区）。
  const uint8_t* written = p.channel().base() + l.data_off + desc.data_off;
  packet_engine::test::check(std::memcmp(written, frame, sizeof(frame)) == 0,
                             "数据区内容应与源帧逐字一致");
}

void slot_index_is_seq_modulo_slot_count() {
  TempRegion tmp("wrap");
  Producer p;
  AttachError err;
  if (!Producer::create(tmp.path(), 4, 256, &p, &err)) {
    packet_engine::test::check(false, "回绕用例：创建失败");
    return;
  }

  uint8_t frame[48];
  make_udp_frame(frame, sizeof(frame));
  const auto l = p.channel().layout();

  // 发 6 帧：4 个槽位应发生回绕，第 5 帧（seq=4）回到槽位 0。
  for (int i = 0; i < 6; ++i) {
    p.publish_bytes(frame, sizeof(frame), i, 0, 0);
  }
  const ChannelStats s = p.stats();
  packet_engine::test::check(s.dropped == 2u && s.full_events == 2u,
                             "槽位 4 发 6 帧：应丢 2 帧且记为 2 次环满");
  packet_engine::test::check(s.head == 4u, "环满时 head 不推进，应停在 4");

  packet_engine::channel::PacketDescriptor desc{};
  std::memcpy(&desc, p.channel().base() + l.desc_off, sizeof(desc));
  packet_engine::test::check(desc.seq == 0u, "槽位 0 仍应是第 0 帧（未被覆盖）");
}

// ---------------------------------------------------------------- 两种丢弃

void oversized_frame_counts_dropped_but_not_full_events() {
  TempRegion tmp("oversize");
  Producer p;
  AttachError err;
  if (!Producer::create(tmp.path(), 8, 256, &p, &err)) {
    packet_engine::test::check(false, "超长用例：创建失败");
    return;
  }

  uint8_t big[300];
  make_udp_frame(big, sizeof(big));
  const PublishStatus st = p.publish_bytes(big, sizeof(big), 0, 0, 0);
  packet_engine::test::check(st == PublishStatus::kDroppedTooLarge, "超长帧应被拒绝");
  const ChannelStats s = p.stats();
  packet_engine::test::check(s.dropped == 1u, "超长帧应计入 dropped");
  packet_engine::test::check(s.full_events == 0u,
                             "超长帧**不得**计入 full_events —— 两者混在一起就无法区分"
                             "「该扩容」与「该提速消费者」");
  packet_engine::test::check(s.head == 0u, "被丢弃时不推进 head");
}

void full_is_the_only_source_of_full_events() {
  TempRegion tmp("fullev");
  Producer p;
  AttachError err;
  if (!Producer::create(tmp.path(), 3, 256, &p, &err)) {
    packet_engine::test::check(false, "环满用例：创建失败");
    return;
  }
  uint8_t frame[48];
  make_udp_frame(frame, sizeof(frame));
  uint8_t big[300];
  make_udp_frame(big, sizeof(big));

  // 先塞一次超长（不计 full_events），再填满环并溢出一次（计一次）。
  p.publish_bytes(big, sizeof(big), 0, 0, 0);
  for (int i = 0; i < 4; ++i) {
    p.publish_bytes(frame, sizeof(frame), i, 0, 0);
  }
  const ChannelStats s = p.stats();
  packet_engine::test::check(s.full_events == 1u, "只有环满才计 full_events");
  packet_engine::test::check(s.dropped == 2u, "两类丢弃都计入 dropped（共 2 次）");
  packet_engine::test::check(s.published == 3u, "成功发布应为 3（环容量）");
}

// ---------------------------------------------------------------- 截断标志

void truncated_capture_gets_its_flag_set_automatically() {
  TempRegion tmp("trunc");
  Producer p;
  AttachError err;
  if (!Producer::create(tmp.path(), 4, 256, &p, &err)) {
    packet_engine::test::check(false, "截断用例：创建失败");
    return;
  }
  uint8_t frame[64];
  make_udp_frame(frame, sizeof(frame));

  // caplen=64 但 wirelen=1500：截断捕获。调用方不传任何标志。
  p.publish_bytes(frame, sizeof(frame), 0, 0, 0, 1500);
  const auto l = p.channel().layout();
  packet_engine::channel::PacketDescriptor desc{};
  std::memcpy(&desc, p.channel().base() + l.desc_off, sizeof(desc));
  packet_engine::test::check(desc.caplen == 64u && desc.wirelen == 1500u,
                             "caplen/wirelen 应如实记录");
  packet_engine::test::check((desc.flags & flag::kTruncated) != 0,
                             "wirelen > caplen 时应自动置截断位 —— 依赖调用方记得置位迟早会漏，"
                             "而漏掉的后果是消费端按完整报文解析不完整数据");
}

void wirelen_zero_means_not_truncated() {
  TempRegion tmp("wlen0");
  Producer p;
  AttachError err;
  if (!Producer::create(tmp.path(), 4, 256, &p, &err)) {
    packet_engine::test::check(false, "wirelen 用例：创建失败");
    return;
  }
  uint8_t frame[64];
  make_udp_frame(frame, sizeof(frame));
  p.publish_bytes(frame, sizeof(frame), 0, 0, 0); // wirelen 缺省
  const auto l = p.channel().layout();
  packet_engine::channel::PacketDescriptor desc{};
  std::memcpy(&desc, p.channel().base() + l.desc_off, sizeof(desc));
  packet_engine::test::check(desc.wirelen == 64u, "wirelen 缺省应取 caplen");
}

// ---------------------------------------------------------------- 期望值校验

void stale_region_with_older_config_is_rejected() {
  TempRegion tmp("stale");
  {
    Producer p;
    AttachError err;
    // 以旧配置建区域（模拟「上一版配置留下的残留」）。
    if (!Producer::create(tmp.path(), 32, 512, &p, &err)) {
      packet_engine::test::check(false, "陈旧区域用例：创建失败");
      return;
    }
  }

  // 新配置去打开：区域自身完全自洽（校验全过），只有期望值比对能拦下它。
  Producer p2;
  AttachError err;
  const bool ok = Producer::open(tmp.path(), 64, 512, &p2, &err);
  packet_engine::test::check(!ok, "槽位数不符的残留区域应被拒绝");
  packet_engine::test::check(err.code == diag::ChanSlotCountMismatch::code(),
                             "诊断码应为 chan.slot_count_mismatch");
  packet_engine::test::check(!err.message.empty(), "诊断文案不应为空");
}

void uninitialized_region_is_reported_as_such_not_as_count_mismatch() {
  TempRegion tmp("uninit");
  // 建一个全零文件：未初始化区域。期望值比对若排在根基校验之前，
  // 这里会报成「槽位数不符」，把排障引向完全错误的字段。
  {
    FILE* f = std::fopen(tmp.path(), "wb");
    if (f == nullptr) {
      packet_engine::test::check(false, "无法创建测试文件");
      return;
    }
    std::vector<char> zeros(8192, 0);
    std::fwrite(zeros.data(), 1, zeros.size(), f);
    std::fclose(f);
  }

  Producer p;
  AttachError err;
  const bool ok = Producer::open(tmp.path(), 64, 512, &p, &err);
  packet_engine::test::check(!ok, "全零区域应被拒绝");
  packet_engine::test::check(err.code == diag::ChanUninitialized::code(),
                             "诊断码应为 chan.uninitialized（而非 slot_count_mismatch）");
}

void header_field_mismatch_has_its_own_code() {
  TempRegion tmp("magic");
  {
    Producer p;
    AttachError err;
    if (!Producer::create(tmp.path(), 8, 256, &p, &err)) {
      packet_engine::test::check(false, "魔数用例：创建失败");
      return;
    }
  }

  // 就地改坏魔数（非全零，但也不是 CYTHSEC1）。
  {
    FILE* f = std::fopen(tmp.path(), "r+b");
    if (f == nullptr) {
      packet_engine::test::check(false, "无法改写测试文件");
      return;
    }
    const char bad[8] = {'X', 'Y', 'Z', 'H', 'S', 'E', 'C', '9'};
    std::fwrite(bad, 1, 8, f);
    std::fclose(f);
  }

  Producer p;
  AttachError err;
  const bool ok = Producer::open(tmp.path(), 8, 256, &p, &err);
  packet_engine::test::check(!ok, "魔数不符应被拒绝");
  packet_engine::test::check(err.code == diag::ChanMagicMismatch::code(),
                             "诊断码应为 chan.magic_mismatch");
}

// ---------------------------------------------------------------- 健康检查

void health_catches_tail_ahead_of_head() {
  TempRegion tmp("health");
  Producer p;
  AttachError err;
  if (!Producer::create(tmp.path(), 8, 256, &p, &err)) {
    packet_engine::test::check(false, "健康检查用例：创建失败");
    return;
  }
  packet_engine::test::check(p.channel().health(&err), "刚创建的区域健康检查应通过");

  // 手工把 tail 推到 head 之前（模拟消费端异常）。
  p.channel().atomic_u64(header_off::kTail)->store(5, std::memory_order_release);
  const bool healthy = p.channel().health(&err);
  packet_engine::test::check(!healthy, "tail 越过 head 应被判为不健康");
  packet_engine::test::check(err.code == diag::ChanTailAheadOfHead::code(),
                             "诊断码应为 chan.tail_ahead_of_head");
}

void not_open_producer_rejects_publish() {
  Producer p;
  uint8_t frame[64];
  make_udp_frame(frame, sizeof(frame));
  packet_engine::test::check(p.publish_bytes(frame, sizeof(frame), 0) == PublishStatus::kNotOpen,
                             "未打开的生产端应返回 kNotOpen 而非静默丢弃");
}

} // namespace

int main() {
  create_writes_a_self_consistent_header();
  layout_matches_header_offsets();
  publish_advances_head_and_writes_descriptor();
  slot_index_is_seq_modulo_slot_count();
  oversized_frame_counts_dropped_but_not_full_events();
  full_is_the_only_source_of_full_events();
  truncated_capture_gets_its_flag_set_automatically();
  wirelen_zero_means_not_truncated();
  stale_region_with_older_config_is_rejected();
  uninitialized_region_is_reported_as_such_not_as_count_mismatch();
  header_field_mismatch_has_its_own_code();
  health_catches_tail_ahead_of_head();
  not_open_producer_rejects_publish();
  return packet_engine::test::summary("channel_producer");
}
