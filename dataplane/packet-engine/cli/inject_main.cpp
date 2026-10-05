// inject_main.cpp - 确定性打流工具（cythsec-inject，仅 Linux）。
//
// 为什么需要它：抓包吞吐对照（「mmap 环」vs「拷贝模式」，见
// scripts/verify/bench-capture.sh）必须有一个**可复现、可自证**的流量源。
// 外部工具（iperf3/tcpreplay/pktgen）会引入三项不可控：① 额外依赖（本仓库零第三方
// 依赖）；② 无法确定「实际发了多少」—— 而对照实验里 "抓到的 / 发出的" 正是核心口径；
// ③ 发包与抓包争抢同一台测试机的 CPU 时，无法固定谁占多少核。
//
// 本工具只做一件事：按给定的帧长/数量/速率，从指定接口发出去，并**如实报告**
// 发出了多少、花了多久、有没有出错。它不做校验和 offload 假设：IPv4 头校验和
// 自己算，UDP 校验和置 0（IPv4 允许）。
//
// 平台限制：只用 AF_PACKET 发送（SOCK_RAW），故与 af-packet 后端同条件编译。
// 需要 CAP_NET_RAW（或 root）：权限不足时给出可直接粘贴的 setcap 命令。
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kMinFrame = 60;   // 以太网最小帧长（不含 FCS）
constexpr uint32_t kMaxFrame = 1514; // 标准 MTU 下的最大帧长
constexpr uint32_t kBatch = 64;      // 一批发送多少个，之后才检查速率/退出条件

struct Options {
  std::string iface;
  uint64_t count = 0;      // 0 = 不限（此时必须给 --duration）
  double duration_sec = 0; // 0 = 不限（此时必须给 --count）
  uint64_t rate = 0;       // 每秒包数，0 = 全速
  uint32_t frame_size = 64;
  std::string dst_mac; // 空 = 广播
  uint32_t src_port = 40000;
  bool vary_port = false; // 逐包变化源端口（模拟多流）
  bool quiet = false;
};

void usage() {
  std::fprintf(
      stderr,
      "用法:\n"
      "  cythsec-inject -i <接口> [--count N] [--duration 秒] [选项]\n"
      "\n"
      "选项:\n"
      "  -i, --iface <名字>      从哪个接口发（如 veth0 / enp2s0）\n"
      "  -c, --count <N>         发 N 个包后退出（0=不限，默认 0；与 --duration 至少给一个）\n"
      "  -t, --duration <秒>     发这么久后退出（支持小数，如 2.5）\n"
      "      --rate <pps>        目标速率（包/秒），0=全速（默认）\n"
      "  -s, --size <字节>       整帧长度（含 14 字节以太头），%u..%u，默认 64\n"
      "      --dst-mac <MAC>     目的 MAC，默认广播 ff:ff:ff:ff:ff:ff\n"
      "      --src-port <N>      UDP 源端口基数，默认 40000\n"
      "      --vary-port         逐包递增源端口（产生多条流；对照/分流实验用）\n"
      "  -q, --quiet             只输出机器可读汇总行\n"
      "  -h, --help              显示本帮助\n"
      "\n"
      "输出（stdout，机器可读）:\n"
      "  inject iface=<名> src_mac=<MAC> dst_mac=<MAC> frame_size=<N> rate=<pps|max>\n"
      "  inject stats sent=<N> bytes=<N> duration_ms=<N> pps=<N> errors=<N>\n"
      "  inject result status=<ok|failed|skipped> reason=<...>\n"
      "\n"
      "退出码: 0 成功 / 2 用法 / 4 打开失败（含权限）/ 5 发送期错误 / 7 一个包都没发出去\n",
      kMinFrame, kMaxFrame);
}

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

bool parse_mac(const char* s, uint8_t out[6]) {
  unsigned b[6];
  if (std::sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
    return false;
  }
  for (int i = 0; i < 6; ++i) {
    if (b[i] > 0xff) {
      return false;
    }
    out[i] = static_cast<uint8_t>(b[i]);
  }
  return true;
}

std::string mac_to_string(const uint8_t m[6]) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4],
                m[5]);
  return std::string(buf);
}

void print_result(const char* status, const std::string& reason) {
  std::printf("inject result status=%s reason=%s\n", status, reason.empty() ? "-" : reason.c_str());
}

// 取接口 MAC 与索引。与抓包侧一样：**先解析接口，再动权限** —— 否则接口名写错
// 在无特权环境下会被误报成「权限不足」，把排障引向错误方向。
bool lookup_iface(const std::string& name, uint32_t* ifindex, uint8_t mac[6], std::string* why) {
  const unsigned idx = ::if_nametoindex(name.c_str());
  if (idx == 0) {
    *why = "接口不存在: " + name;
    return false;
  }
  *ifindex = idx;

  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    *why = std::string("socket(AF_INET) 失败: ") + std::strerror(errno);
    return false;
  }
  struct ifreq ifr;
  std::memset(&ifr, 0, sizeof(ifr));
  std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name.c_str());
  bool ok = true;
  if (::ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
    *why = std::string("SIOCGIFHWADDR 失败: ") + std::strerror(errno);
    ok = false;
  } else {
    std::memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
  }
  if (ok && ::ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
    if ((ifr.ifr_flags & IFF_UP) == 0) {
      // 接口没 UP 是最常见的「发出去了但抓不到」的原因：必须在发送前就报出来。
      *why = "接口未启用（IFF_UP 未置位）: " + name + "（先 ip link set dev " + name + " up）";
      ok = false;
    }
  }
  ::close(fd);
  return ok;
}

// 自造一帧：以太 + IPv4 + UDP + 载荷。校验和自算（不依赖 offload：坏校验和的包
// 在真实网卡上会被丢弃，而「发了很多但抓不到」会把测量引向完全错误的结论）。
void build_frame(std::vector<uint8_t>* f, const uint8_t src_mac[6], const uint8_t dst_mac[6],
                 uint16_t src_port, uint16_t dst_port, uint32_t seq) {
  uint8_t* p = f->data();
  std::memcpy(p, dst_mac, 6);
  std::memcpy(p + 6, src_mac, 6);
  p[12] = 0x08;
  p[13] = 0x00; // IPv4
  uint8_t* ip = p + 14;
  const uint32_t total_len = static_cast<uint32_t>(f->size()) - 14;
  ip[0] = 0x45;                                 // version 4, IHL 5
  ip[1] = 0x00;                                 // DSCP/ECN
  ip[2] = static_cast<uint8_t>(total_len >> 8); // total length
  ip[3] = static_cast<uint8_t>(total_len & 0xff);
  ip[4] = static_cast<uint8_t>(seq >> 8); // ID：逐包变化，便于识别乱序/丢失
  ip[5] = static_cast<uint8_t>(seq & 0xff);
  ip[6] = 0x40; // DF
  ip[7] = 0x00;
  ip[8] = 64; // TTL
  ip[9] = 17; // UDP
  ip[10] = 0;
  ip[11] = 0; // 校验和先置 0
  ip[12] = 10;
  ip[13] = 0;
  ip[14] = 0;
  ip[15] = 1; // 源 IP 10.0.0.1
  ip[16] = 10;
  ip[17] = 0;
  ip[18] = 0;
  ip[19] = 2; // 目的 IP 10.0.0.2
  uint32_t sum = 0;
  for (int i = 0; i < 20; i += 2) {
    sum += (static_cast<uint32_t>(ip[i]) << 8) | ip[i + 1];
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  const uint16_t csum = static_cast<uint16_t>(~sum);
  ip[10] = static_cast<uint8_t>(csum >> 8);
  ip[11] = static_cast<uint8_t>(csum & 0xff);

  uint8_t* udp = ip + 20;
  const uint32_t udp_len = total_len - 20;
  udp[0] = static_cast<uint8_t>(src_port >> 8);
  udp[1] = static_cast<uint8_t>(src_port & 0xff);
  udp[2] = static_cast<uint8_t>(dst_port >> 8);
  udp[3] = static_cast<uint8_t>(dst_port & 0xff);
  udp[4] = static_cast<uint8_t>(udp_len >> 8);
  udp[5] = static_cast<uint8_t>(udp_len & 0xff);
  udp[6] = 0;
  udp[7] = 0; // IPv4 下 UDP 校验和可置 0（表示未计算）
  for (size_t i = 28; i < f->size(); ++i) {
    p[i] = static_cast<uint8_t>(i & 0xff);
  }
}

bool parse_args(int argc, char** argv, Options* o) {
  for (int i = 1; i < argc; ++i) {
    const char* a = argv[i];
    auto need_value = [&](const char** dst) -> bool {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "错误: %s 需要一个取值\n", a);
        return false;
      }
      *dst = argv[++i];
      return true;
    };
    const char* v = nullptr;
    if (std::strcmp(a, "-i") == 0 || std::strcmp(a, "--iface") == 0) {
      if (!need_value(&v)) {
        return false;
      }
      o->iface = v;
    } else if (std::strcmp(a, "-c") == 0 || std::strcmp(a, "--count") == 0) {
      if (!need_value(&v) || !parse_u64(v, &o->count)) {
        std::fprintf(stderr, "错误: --count 需要非负整数\n");
        return false;
      }
    } else if (std::strcmp(a, "-t") == 0 || std::strcmp(a, "--duration") == 0) {
      if (!need_value(&v)) {
        return false;
      }
      char* end = nullptr;
      o->duration_sec = std::strtod(v, &end);
      if (end == v || *end != '\0' || o->duration_sec < 0) {
        std::fprintf(stderr, "错误: --duration 需要非负秒数（支持小数），得到 \"%s\"\n", v);
        return false;
      }
    } else if (std::strcmp(a, "--rate") == 0) {
      if (!need_value(&v) || !parse_u64(v, &o->rate)) {
        std::fprintf(stderr, "错误: --rate 需要非负整数（包/秒），0 表示全速\n");
        return false;
      }
    } else if (std::strcmp(a, "-s") == 0 || std::strcmp(a, "--size") == 0) {
      uint64_t n = 0;
      if (!need_value(&v) || !parse_u64(v, &n)) {
        std::fprintf(stderr, "错误: --size 需要整数\n");
        return false;
      }
      if (n < kMinFrame || n > kMaxFrame) {
        std::fprintf(stderr, "错误: --size 必须在 %u..%u 之间（整帧长度，含以太头），得到 %llu\n",
                     kMinFrame, kMaxFrame, (unsigned long long)n);
        return false;
      }
      o->frame_size = static_cast<uint32_t>(n);
    } else if (std::strcmp(a, "--dst-mac") == 0) {
      if (!need_value(&v)) {
        return false;
      }
      o->dst_mac = v;
    } else if (std::strcmp(a, "--src-port") == 0) {
      uint64_t n = 0;
      if (!need_value(&v) || !parse_u64(v, &n) || n == 0 || n > 65535) {
        std::fprintf(stderr, "错误: --src-port 需要 1..65535\n");
        return false;
      }
      o->src_port = static_cast<uint32_t>(n);
    } else if (std::strcmp(a, "--vary-port") == 0) {
      o->vary_port = true;
    } else if (std::strcmp(a, "-q") == 0 || std::strcmp(a, "--quiet") == 0) {
      o->quiet = true;
    } else if (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0) {
      usage();
      std::exit(0);
    } else {
      std::fprintf(stderr, "错误: 未知参数 \"%s\"（-h 看帮助）\n", a);
      return false;
    }
  }
  if (o->iface.empty()) {
    std::fprintf(stderr, "错误: 必须用 -i/--iface 指定发送接口\n");
    return false;
  }
  if (o->count == 0 && o->duration_sec == 0) {
    // 否则就是一个「永远跑下去」的命令：给测量用工具时必须要求至少一个停止条件，
    // 不然 CI 里一条挂住的命令会耗光超时预算。
    std::fprintf(stderr, "错误: --count 与 --duration 至少要给一个（都为 0 表示永不退出）\n");
    return false;
  }
  return true;
}

int run(const Options& o) {
  uint32_t ifindex = 0;
  uint8_t src_mac[6] = {0};
  std::string why;
  if (!lookup_iface(o.iface, &ifindex, src_mac, &why)) {
    std::fprintf(stderr, "打开失败: %s\n", why.c_str());
    print_result("failed", why);
    return 4;
  }
  uint8_t dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  if (!o.dst_mac.empty() && !parse_mac(o.dst_mac.c_str(), dst_mac)) {
    std::fprintf(stderr, "错误: --dst-mac 非法: %s\n", o.dst_mac.c_str());
    return 2;
  }

  const int fd = ::socket(AF_PACKET, SOCK_RAW, ::htons(ETH_P_ALL));
  if (fd < 0) {
    const bool perm = (errno == EPERM || errno == EACCES);
    std::string msg = std::string("socket(AF_PACKET, SOCK_RAW) 失败: ") + std::strerror(errno);
    if (perm) {
      msg += "（需要 CAP_NET_RAW：sudo setcap cap_net_raw+ep $(readlink -f /proc/self/exe) 或以 "
             "root 运行）";
    }
    std::fprintf(stderr, "打开失败: %s\n", msg.c_str());
    print_result(perm ? "skipped" : "failed", msg);
    return 4;
  }

  std::vector<uint8_t> frame(o.frame_size, 0);
  std::printf("inject iface=%s src_mac=%s dst_mac=%s frame_size=%u rate=%s\n", o.iface.c_str(),
              mac_to_string(src_mac).c_str(), mac_to_string(dst_mac).c_str(), o.frame_size,
              o.rate == 0 ? "max" : std::to_string(o.rate).c_str());

  const auto t0 = std::chrono::steady_clock::now();
  uint64_t sent = 0;
  uint64_t errors = 0;
  uint64_t last_errno = 0;
  const double want_sec = o.duration_sec;
  uint16_t port = static_cast<uint16_t>(o.src_port);

  while (true) {
    const auto now = std::chrono::steady_clock::now();
    const double el = std::chrono::duration<double>(now - t0).count();
    if (want_sec > 0 && el >= want_sec) {
      break;
    }
    if (o.count != 0 && sent >= o.count) {
      break;
    }

    const uint64_t left =
        o.count == 0 ? kBatch : (o.count - sent < kBatch ? o.count - sent : kBatch);
    for (uint64_t i = 0; i < left; ++i) {
      build_frame(&frame, src_mac, dst_mac, port, 53, static_cast<uint32_t>(sent + i));
      if (o.vary_port) {
        port = static_cast<uint16_t>(port == 65535 ? 1024 : port + 1);
      }
      struct sockaddr_ll sll;
      std::memset(&sll, 0, sizeof(sll));
      sll.sll_family = AF_PACKET;
      sll.sll_protocol = ::htons(ETH_P_ALL);
      sll.sll_ifindex = static_cast<int>(ifindex);
      sll.sll_halen = 6;
      std::memcpy(sll.sll_addr, dst_mac, 6);
      const ssize_t n = ::sendto(fd, frame.data(), frame.size(), 0,
                                 reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll));
      if (n < 0) {
        ++errors;
        last_errno = static_cast<uint64_t>(errno);
        if (errors == 1) {
          // 第一条错误必须立刻可见：全部静默失败会表现为「抓包侧一个包都没有」。
          std::fprintf(stderr, "sendto 失败: %s（errno=%d）\n", std::strerror(errno), errno);
        }
        if (errors >= 16) {
          break; // 连续失败就不再刷屏，直接走汇总
        }
        continue;
      }
      ++sent;
    }
    if (errors >= 16) {
      break;
    }

    if (o.rate > 0) {
      // 限速：按「已发数 / 目标速率」推算应该用的时间，落后就不睡（不追赶历史欠账）。
      const double target = static_cast<double>(sent) / static_cast<double>(o.rate);
      const double cur =
          std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
      const double sleep_s = target - cur;
      if (sleep_s > 0) {
        struct timespec ts;
        ts.tv_sec = static_cast<time_t>(sleep_s);
        ts.tv_nsec = static_cast<long>((sleep_s - static_cast<double>(ts.tv_sec)) * 1e9);
        if (ts.tv_nsec > 2000000L) {
          ts.tv_nsec = 2000000L; // 最多睡 2ms：保证退出条件与信号响应及时
        }
        ::nanosleep(&ts, nullptr);
      }
    }
  }

  const auto t1 = std::chrono::steady_clock::now();
  const double dur = std::chrono::duration<double>(t1 - t0).count();
  const uint64_t dur_ms = static_cast<uint64_t>(dur * 1000.0);
  const double pps = dur > 0 ? static_cast<double>(sent) / dur : 0.0;
  const uint64_t bytes = sent * static_cast<uint64_t>(o.frame_size);
  std::printf("inject stats sent=%llu bytes=%llu duration_ms=%llu pps=%.0f errors=%llu\n",
              (unsigned long long)sent, (unsigned long long)bytes, (unsigned long long)dur_ms, pps,
              (unsigned long long)errors);
  ::close(fd);

  if (errors > 0) {
    print_result("failed", "发送期出错（首次 errno=" + std::to_string(last_errno) + "）");
    return 5;
  }
  if (sent == 0) {
    print_result("failed", "一个包都没发出去");
    return 7;
  }
  print_result("ok", "");
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  Options o;
  if (!parse_args(argc, argv, &o)) {
    return 2;
  }
  return run(o);
}
