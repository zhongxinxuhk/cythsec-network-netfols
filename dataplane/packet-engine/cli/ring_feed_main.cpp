// ring_feed_main.cpp - cythsec-ring-feed：把真实 pcap 报文灌入共享环（C++ 生产端）。
//
// 用法:
//   cythsec-ring-feed -r <file.pcap> [-r <more.pcap> ...] --ring <path> [选项]
//
// 选项:
//   -r, --pcap <文件>      源 pcap（经典格式，非 pcapng）；可重复指定，按顺序依次灌入
//       --ring <路径>      共享区域文件路径
//       --slot-count <N>   槽位数（默认 1024）
//       --slot-size <N>    单槽容量字节（默认 2048）
//       --recreate         强制重建区域（O_TRUNC），丢弃既有内容
//       --limit <N>        最多发布 N 个报文（调试用）
//   -q, --quiet            只输出机器可读的汇总行
//
// 退出码: 0 成功 / 2 用法错误 / 3 源 pcap 失败 / 4 区域 attach 失败 / 5 参数越界
//
// 机器可读输出（供 scripts/verify/e2e-shared-ring.sh 抓取，格式稳定不要改）。
// 每类记录有唯一的二级标签（summary / counts / region），抓取端按标签精确定位；
// 同一格式内复用同名键会让「取最后一次匹配」的抓取方式静默取到另一条记录的值。
//   ring-feed summary path=<路径> sources=<n> read=<n> published=<n> too_large=<n> full=<n> head=<n>
//   ring-feed counts bytes=<n> truncated=<n> slot_count=<n> slot_size=<n> region_bytes=<n>
//   ring-feed region published=<n> consumed=<n> dropped=<n> full_events=<n> head=<n> tail=<n>
//
// `summary` 报的是本进程自己的记账，`region` 报的是共享区域里实际落下的计数。
// 两者**必须分开报**：只报前者的话，生产者把 published 记错（写进了内存但计错次数）
// 在本端看起来完全正常 —— 实测正是一次「published 双计」的注入没被任何断言发现，
// 因为两端 CLI 各自只报了自己的本地计数，区域里的计数从没有人核对过。
//
// 本工具的定位是「C++ 生产端 ↔ Rust 消费端」跨语言链路的**生产侧驱动**：Rust 侧
// channel::Consumer 是它的对应读端。两端对同一块内存的理解一致性由已落地的
// 三层防线保证（编译期断言 / 生成物新鲜度 / 跨语言 parity dump），本工具不做重复校验。
#include "packet_engine/backend.h"
#include "packet_engine/backends/pcap_file.h"
#include "packet_engine/channel/producer.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using packet_engine::channel::AttachError;
using packet_engine::channel::ChannelStats;
using packet_engine::channel::Producer;
using packet_engine::channel::PublishStatus;

namespace {

// 参数缺省值。1024 × 2048 = 2 MiB 数据区，足以承载千兆链路上秒级的抓包突发。
constexpr uint32_t kDefaultSlotCount = 1024;
constexpr uint32_t kDefaultSlotSize = 2048;

struct Options {
  std::vector<const char*> pcap_paths;
  const char* ring_path = nullptr;
  uint32_t slot_count = kDefaultSlotCount;
  uint32_t slot_size = kDefaultSlotSize;
  uint64_t limit = 0; // 0 = 不限
  bool recreate = false;
  bool quiet = false;
};

void usage() {
  std::fprintf(stderr,
               "用法:\n"
               "  cythsec-ring-feed -r <file.pcap> [-r <more.pcap> ...] --ring <path> [选项]\n\n"
               "选项:\n"
               "  -r, --pcap <文件>      源 pcap（经典格式），可重复指定\n"
               "      --ring <路径>      共享区域文件路径\n"
               "      --slot-count <N>   槽位数（默认 %u）\n"
               "      --slot-size <N>    单槽容量字节（默认 %u）\n"
               "      --recreate         强制重建区域（丢弃既有内容）\n"
               "      --limit <N>        最多发布 N 个报文\n"
               "  -q, --quiet            只输出机器可读汇总行\n",
               kDefaultSlotCount, kDefaultSlotSize);
}

// 解析无符号整数。刻意对「解析成功但越界」与「根本不合法」返回同一结果：
// 调用方无论哪种都只能报用法错误，区分对用户没有价值。
bool parse_u64(const char* s, uint64_t* out) {
  if (s == nullptr || *s == '\0') {
    return false;
  }
  char* end = nullptr;
  const unsigned long long v = std::strtoull(s, &end, 10);
  if (end == s || *end != '\0') {
    return false;
  }
  *out = static_cast<uint64_t>(v);
  return true;
}

bool parse_args(int argc, char** argv, Options* o) {
  for (int i = 1; i < argc; ++i) {
    const char* a = argv[i];
    // 需要取值的选项统一在此处理，避免每个分支各自重复「下标越界」检查。
    auto need_value = [&](const char** dst) -> bool {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "错误: %s 需要一个取值\n", a);
        return false;
      }
      *dst = argv[++i];
      return true;
    };

    if (std::strcmp(a, "-r") == 0 || std::strcmp(a, "--pcap") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      o->pcap_paths.push_back(v);
    } else if (std::strcmp(a, "--ring") == 0) {
      if (!need_value(&o->ring_path))
        return false;
    } else if (std::strcmp(a, "--slot-count") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      uint64_t n = 0;
      if (!parse_u64(v, &n)) {
        std::fprintf(stderr, "错误: --slot-count 取值非法: %s\n", v);
        return false;
      }
      o->slot_count = static_cast<uint32_t>(n);
    } else if (std::strcmp(a, "--slot-size") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      uint64_t n = 0;
      if (!parse_u64(v, &n)) {
        std::fprintf(stderr, "错误: --slot-size 取值非法: %s\n", v);
        return false;
      }
      o->slot_size = static_cast<uint32_t>(n);
    } else if (std::strcmp(a, "--limit") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      if (!parse_u64(v, &o->limit)) {
        std::fprintf(stderr, "错误: --limit 取值非法: %s\n", v);
        return false;
      }
    } else if (std::strcmp(a, "--recreate") == 0) {
      o->recreate = true;
    } else if (std::strcmp(a, "-q") == 0 || std::strcmp(a, "--quiet") == 0) {
      o->quiet = true;
    } else if (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0) {
      usage();
      std::exit(0);
    } else {
      std::fprintf(stderr, "错误: 未知参数 %s\n", a);
      return false;
    }
  }
  if (o->pcap_paths.empty() || o->ring_path == nullptr) {
    std::fprintf(stderr, "错误: -r/--pcap 与 --ring 均为必填\n");
    return false;
  }
  return true;
}

} // namespace

int main(int argc, char** argv) {
  Options opt;
  if (!parse_args(argc, argv, &opt)) {
    usage();
    return 2;
  }

  // ---- 共享环 ----
  // 区域先于源 pcap 建立：反过来的话，源文件读不出时区域已被 O_TRUNC 清空，
  // 把「本次没灌进去」表现成「环里什么都没有」，而后者看起来像消费端的问题。
  AttachError err;
  Producer producer;
  bool opened = false;
  if (opt.recreate) {
    opened = Producer::create(opt.ring_path, opt.slot_count, opt.slot_size, &producer, &err);
  } else {
    // 先尝试按期望配置打开既有区域；区域不存在时 open 会以 chan.io_error(ENOENT) 失败，
    // 此时才创建。刻意不用「先 stat 再决定」：那中间有 TOCTOU 窗口，且多一次系统调用
    // 也换不来更清晰的失败信息 —— open 的诊断本身已足够指明原因。
    opened = Producer::open(opt.ring_path, opt.slot_count, opt.slot_size, &producer, &err);
    if (!opened) {
      opened = Producer::create(opt.ring_path, opt.slot_count, opt.slot_size, &producer, &err);
    }
  }
  if (!opened) {
    std::fprintf(stderr, "创建/打开共享环失败 [%s] %s\n", err.code.c_str(), err.message.c_str());
    return 4;
  }

  if (!opt.quiet) {
    std::printf("共享环       : %s\n", opt.ring_path);
    std::printf("槽位配置     : %u 槽 × %u 字节 = %llu 字节区域\n", opt.slot_count, opt.slot_size,
                (unsigned long long)producer.channel().len());
    std::printf("源文件       : %zu 个\n", opt.pcap_paths.size());
  }

  // ---- 逐个源灌入 ----
  uint64_t read = 0, published = 0, too_large = 0, full = 0, bytes = 0, truncated = 0;
  for (const char* path : opt.pcap_paths) {
    packet_engine::PcapFileBackend* be =
        static_cast<packet_engine::PcapFileBackend*>(packet_engine::create_backend("pcap-file"));
    if (be == nullptr) {
      std::fprintf(stderr, "无法创建 pcap-file 后端: %s\n", packet_engine::create_backend_error());
      return 3;
    }
    if (be->open(path) != 0) {
      std::fprintf(stderr, "打开 pcap 失败: %s (%s)\n", be->error_reason(), path);
      delete be;
      return 3;
    }
    if (!opt.quiet) {
      std::printf("  - %s (linktype=%u)\n", path, be->link_type());
    }

    // rx_burst 返回的 PacketBuffer 指针只在下一次 rx_burst 之前有效（零拷贝契约），
    // 故此处必须在本批内完成发布，不能攒起来。
    packet_engine::PacketBuffer* bufs[256];
    int g = 0;
    bool stop = false;
    while (!stop && (g = be->rx_burst(bufs, 256)) > 0) {
      for (int i = 0; i < g; ++i) {
        const packet_engine::PacketBuffer* pb = bufs[i];
        ++read;
        if (pb->caplen != pb->wirelen) {
          ++truncated;
        }
        const PublishStatus st = producer.publish(*pb);
        switch (st) {
        case PublishStatus::kPublished:
          ++published;
          bytes += pb->wirelen;
          break;
        case PublishStatus::kDroppedTooLarge:
          ++too_large;
          break;
        case PublishStatus::kDroppedFull:
          ++full;
          break;
        case PublishStatus::kNotOpen:
          std::fprintf(stderr, "内部错误: 生产端未打开\n");
          delete be;
          return 4;
        }
        if (opt.limit != 0 && read >= opt.limit) {
          stop = true;
          break;
        }
      }
    }
    delete be;
    if (stop) {
      break;
    }
  }

  const ChannelStats s = producer.stats();

  // 机器可读汇总（格式稳定，e2e 脚本按行抓取）。放在人读输出之前，
  // 使其在管道 grep 下不会因前面的说明行而错位。
  std::printf(
      "ring-feed summary path=%s sources=%zu read=%llu published=%llu too_large=%llu full=%llu "
      "head=%llu\n",
      opt.ring_path, opt.pcap_paths.size(), (unsigned long long)read, (unsigned long long)published,
      (unsigned long long)too_large, (unsigned long long)full, (unsigned long long)s.head);
  std::printf("ring-feed counts bytes=%llu truncated=%llu slot_count=%u slot_size=%u "
              "region_bytes=%llu\n",
              (unsigned long long)bytes, (unsigned long long)truncated, opt.slot_count,
              opt.slot_size, (unsigned long long)producer.channel().len());
  std::printf("ring-feed region published=%llu consumed=%llu dropped=%llu full_events=%llu "
              "head=%llu tail=%llu\n",
              (unsigned long long)s.published, (unsigned long long)s.consumed,
              (unsigned long long)s.dropped, (unsigned long long)s.full_events,
              (unsigned long long)s.head, (unsigned long long)s.tail);

  if (!opt.quiet) {
    std::printf("\n===== 灌入摘要 =====\n");
    std::printf("读取报文      : %llu\n", (unsigned long long)read);
    std::printf("成功发布      : %llu\n", (unsigned long long)published);
    std::printf("超长丢弃      : %llu  (帧长 > %u 字节)\n", (unsigned long long)too_large,
                opt.slot_size);
    std::printf("环满丢弃      : %llu\n", (unsigned long long)full);
    std::printf("线上字节      : %llu\n", (unsigned long long)bytes);
    std::printf("截断捕获      : %llu\n", (unsigned long long)truncated);
    std::printf("head / tail   : %llu / %llu\n", (unsigned long long)s.head,
                (unsigned long long)s.tail);
    std::printf("生产者 pid    : %u\n", s.producer_pid);
  }
  return 0;
}
