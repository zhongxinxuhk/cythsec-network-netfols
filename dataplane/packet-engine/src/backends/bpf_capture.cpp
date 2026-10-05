// backends/bpf_capture.cpp - macOS/BSD BPF 抓包后端实现。
//
// 本文件只在 APPLE/BSD 平台参与编译（见 CMakeLists 的平台条件），故可直接使用
// <net/bpf.h> 而不必在源码里堆 #ifdef。
//
// 所有 ioctl 的参数类型均取自 SDK 的 <net/bpf.h> 定义并已实际核对，不用推测：
//   BIOCSBLEN      _IOWR('B',102, u_int)        -> u_int*
//   BIOCSETIF      _IOW('B',108, struct ifreq)  -> struct ifreq*
//   BIOCIMMEDIATE  _IOW('B',112, u_int)         -> u_int*
//   BIOCPROMISC    _IO('B',105)                 -> 无参数
//   BIOCSRTIMEOUT  _IOW('B',109, struct timeval)-> struct timeval*
//   BIOCGDLT       _IOR('B',106, u_int)         -> u_int*
//   BIOCGSTATS     _IOR('B',111, struct bpf_stat)-> struct bpf_stat*
// 参数类型取错不会编译报错（ioctl 是可变参数），只会在运行时读到垃圾或失败，
// 因此这里逐个核对过而非按记忆书写。
//
// bpf_hdr 在本平台实测（macOS 15 / arm64，内核侧对照 XNU bsd/net/bpf.c）：
// 用户态 SDK 的 sizeof(struct bpf_hdr)=20（timeval(2×u32) 8 + caplen 4 + datalen 4
// + hdrlen 2 + 2 尾部填充），但**内核写到线上的 bh_hdrlen 是 18**（紧凑长度，
// 不含尾部填充）。因此一切边界判断必须用 18 字节的「最小头长」，用 20 会把
// **每一个正常包误判成畸形** —— 这正是本后端曾在真机实测中「0 包入、数千
// errors」且被误归因为「接口无流量」的根因。解析永远以内核给的 bh_hdrlen 为
// 准（不同 BSD 变体可能写 18/20/24），BPF_ALIGNMENT=4，下一包偏移必须用
// BPF_WORDALIGN(bh_hdrlen + bh_caplen)；少了这一步对齐，从第二个包起读到的
// 就是错位的垃圾 —— 且不会报任何错误。
#include "packet_engine/backends/bpf_capture.h"

#include "packet_engine/backends/link_type.h"

#include "packet_engine/backends/iface_list.h"

#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <poll.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

namespace packet_engine {

namespace {

// 设备枚举上限。/dev/bpf0..bpf255 是 BSD 惯例；逐个尝试是唯一可移植的分配方式
// （不存在 Linux 那样的自动分配节点 /dev/bpf）。
constexpr int kMaxBpfDevices = 256;

// 默认读缓冲 256 KiB：足以容纳千兆链路上毫秒级的突发，又不至于让每次 read 拷贝过多。
constexpr uint32_t kDefaultBufSize = 256u * 1024u;

// 线上最小头长：与 XNU bpf.c 自用公式一致（offsetof(bh_hdrlen)+sizeof(bh_hdrlen)）。
// 绝不可用 sizeof(struct bpf_hdr)(=20) 替代：内核写 hdrlen=18，用 20 做下界会把
// 所有正常包误判为畸形（真机实测踩过，症状是 read 返回数据却全部丢弃+计错）。
constexpr size_t kMinBpfHdrLen =
    offsetof(struct bpf_hdr, bh_hdrlen) + sizeof(((struct bpf_hdr*)nullptr)->bh_hdrlen);

} // namespace

// 对上层公开（而非放在匿名命名空间里自用）：抓包工具的「接口摘要」一行要显示链路
// 类型，而 DLT_* 是裸数字（1/0/12），显示 `link=1` 对排障者没有意义。放在这里而不是
// CLI 里，是因为 DLT 常量的语义属于后端知识，不该泄漏到工具层重写一遍。
std::string link_type_name(uint32_t dlt) {
  switch (dlt) {
  case DLT_EN10MB:
    return "EN10MB(以太网)";
  case DLT_NULL:
    return "NULL(回环)";
  case DLT_RAW:
    return "RAW(裸 IP)";
  case DLT_IEEE802_11:
    return "IEEE802_11(无线)";
  case DLT_PPP:
    return "PPP";
  default: {
    char buf[48];
    std::snprintf(buf, sizeof(buf), "未知链路类型(0x%04x)", dlt);
    return std::string(buf);
  }
  }
}

BpfCaptureBackend::BpfCaptureBackend() = default;

BpfCaptureBackend::~BpfCaptureBackend() {
  // 析构即关闭：忘关会让 /dev/bpfN 一直被占用（设备数有限，泄漏若干次后
  // 其他抓包进程会全部 EBUSY）。
  close();
}

std::string BpfCaptureBackend::configure(const CaptureOptions& options) {
  // 逐项落定，并把本后端无法生效的项**显式回报**给调用方（理由同 AF_PACKET：
  // 静默忽略设置会让人把「配置没生效」误判成「网络就是没这类包」）。
  promisc_ = options.promisc;
  if (options.buffer_bytes != 0) {
    want_buf_size_ = options.buffer_bytes;
  }
  if (options.read_timeout_ms != 0) {
    timeout_ms_ = options.read_timeout_ms;
  }
  if (options.snap_len != 0) {
    snap_len_ = options.snap_len;
  }

  // ignore_outgoing 在 BPF 上的对应物是 BIOCSSEESENT。语义映射：不看本机发出的包
  // ＝ 关闭 see-sent。注意各 BSD 系对该取值的约定并不一致（有的 0=看、有的 1=看），
  // 故只在用户明确提出时才设置，不替用户决定默认值。
  if (options.ignore_outgoing) {
    see_sent_ = SeeSent::kDisable;
  }

  std::string rejected;
  auto note = [&rejected](const char* name) {
    if (!rejected.empty()) {
      rejected += "、";
    }
    rejected += name;
  };

  // 块退休超时是 Linux AF_PACKET V3 的机制（tp_retire_blk_tov）。BPF 的 read()
  // 由 BIOCSRTIMEOUT 决定何时返回，没有「块」的概念，故此项无对应物。
  if (options.retire_ms != 0) {
    note("retire_ms(仅 Linux AF_PACKET V3 有块退休机制)");
  }
  // allow_fallback 在 BPF 上恒为已满足：本后端只有 read() 一条路径，不存在可降级
  // 的更低版本。因此**不**报为不支持 —— 报了会让每个 macOS 用户都看到一条
  // 无意义的警告，而真正的「不支持」信号会被这类噪声淹没。
  //
  // 采集模式偏好则必须报：它指的是 TPACKET 的三个档位（v3/v2/recvfrom），
  // BPF 上都不存在。不报的话，`--capture-mode recvfrom` 在 macOS 上会「成功」，
  // 而用户拿到的数字其实来自 BPF 的 read() 路径 —— 对照实验直接失真。
  if (options.mode != CaptureMode::kAuto) {
    note("capture_mode(是 Linux AF_PACKET 的档位选择，BPF 无对应物)");
  }

  return rejected.empty() ? std::string() : "本后端不支持这些采集参数: " + rejected;
}

void BpfCaptureBackend::set_error(BpfStatus s, const std::string& r) {
  err_ = s;
  err_reason_ = r;
}

void BpfCaptureBackend::fail_ioctl(const char* what, int err) {
  char buf[512];
  std::snprintf(buf, sizeof(buf), "%s 失败：%s (errno=%d)", what, std::strerror(err), err);
  set_error(BpfStatus::kIoctlFailed, buf);
}

int BpfCaptureBackend::open(const char* source) {
  if (opened_) {
    close();
  }
  err_ = BpfStatus::kOk;
  err_reason_ = "ok";

  if (source == nullptr || *source == '\0') {
    set_error(BpfStatus::kNoSuchIface,
              "接口名为空：请用 -i <接口名> 指定，可用 --list-ifaces 查看本机接口");
    return -1;
  }

  const std::string want(source);

  // 先确认接口真实存在，并记录 index。这一步在打开设备之前做，是为了给出比
  // BIOCSETIF 返回的 ENXIO 更明确的原因（接口不存在 vs 接口 down 都报 ENXIO，
  // 不区分的话用户只能猜）。
  IfaceInfo info;
  if (!find_interface_by_name(want.c_str(), &info)) {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
                  "接口 %s 不存在。可用 --list-ifaces 查看本机接口名"
                  "（注意各发行版/平台命名不同：macOS 为 en0，Ubuntu 常见 ens33/enp0s3，"
                  "Rocky/openEuler 常见 eth0/ens192）",
                  want.c_str());
    set_error(BpfStatus::kNoSuchIface, buf);
    return -1;
  }
  if (!info.up) {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
                  "接口 %s 存在但未启用（未 UP）：应用 ifconfig %s up 或选取 RUNNING 的接口",
                  want.c_str(), want.c_str());
    set_error(BpfStatus::kIfaceDown, buf);
    return -1;
  }
  ifindex_ = info.index;

  // ---- 打开一个可用的 /dev/bpfN ----
  int fd = -1;
  int last_errno = 0;
  bool saw_busy = false;
  for (int i = 0; i < kMaxBpfDevices; ++i) {
    char path[64];
    std::snprintf(path, sizeof(path), "/dev/bpf%d", i);
    fd = ::open(path, O_RDONLY);
    if (fd >= 0) {
      device_ = path;
      break;
    }
    last_errno = errno;
    if (errno == EPERM || errno == EACCES) {
      // 权限不足不会因为换设备而改变，立即返回以免白试 255 次。
      char buf[512];
      std::snprintf(
          buf, sizeof(buf),
          "打开 %s 被拒（%s）：捕获原始报文需要特权。macOS 14+ 的最小权限做法是把用户加入 "
          "access_bpf 组（/dev/bpf* 实为 root:access_bpf 660，组成员免 root 即可抓包）："
          "sudo dseditgroup -o edit -a <用户名> -t user access_bpf；或以 root 运行",
          path, std::strerror(errno));
      set_error(BpfStatus::kPermission, buf);
      return -1;
    }
    if (errno == EBUSY) {
      saw_busy = true;
      continue;
    }
    if (errno == ENOENT) {
      // 该设备不存在：若第一个就不存在，说明本机没有 BPF 设备，继续试也无意义。
      if (i == 0) {
        break;
      }
      continue;
    }
    // 其他错误：记录下来继续尝试下一个设备。
  }

  if (fd < 0) {
    if (saw_busy) {
      set_error(BpfStatus::kDeviceBusy,
                "所有 /dev/bpfN 均被占用（EBUSY）：同时可用的 BPF 设备数有限，"
                "请关闭其他抓包程序（tcpdump/Wireshark）后重试");
    } else {
      char buf[512];
      std::snprintf(buf, sizeof(buf),
                    "没有可用的 /dev/bpf 设备（最后一次错误：%s）。"
                    "本平台无 BPF 支持或内核模块未加载",
                    last_errno ? std::strerror(last_errno) : "设备不存在");
      set_error(BpfStatus::kNoDevice, buf);
    }
    return -1;
  }
  fd_ = fd;

  // ---- BIOCSBLEN：必须在 BIOCSETIF 之前 ----
  // man bpf 明确要求先设缓冲大小再绑定接口：缓冲区需要容纳至少一个最大包，
  // 而该值取决于接口 MTU —— 绑定之后内核会拒绝调整。
  {
    u_int want_buf = want_buf_size_ != 0 ? want_buf_size_ : kDefaultBufSize;
    if (::ioctl(fd_, BIOCSBLEN, &want_buf) < 0) {
      const int e = errno;
      // BIOCSBLEN 失败通常是请求值超限。MUST 区分「请求过大」与真正的故障：
      // 前者可用内核允许的值重试，后者只能报错。
      u_int fallback = 32768;
      if (::ioctl(fd_, BIOCSBLEN, &fallback) < 0) {
        fail_ioctl("BIOCSBLEN", e);
        close();
        return -1;
      }
      want_buf = fallback;
    }
    // 回读内核实际采纳的值：内核会按页大小与接口 MTU 调整请求值，
    // 直接相信自己请求的数字会导致后续 read 长度与内核缓冲不匹配。
    u_int actual = want_buf;
    if (::ioctl(fd_, BIOCGBLEN, &actual) == 0 && actual > 0) {
      buf_size_ = actual;
    } else {
      buf_size_ = want_buf;
    }
  }

  // ---- BIOCSETIF：绑定接口 ----
  {
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", want.c_str());
    if (::ioctl(fd_, BIOCSETIF, &ifr) < 0) {
      const int e = errno;
      char buf[512];
      if (e == ENXIO) {
        std::snprintf(buf, sizeof(buf),
                      "绑定接口 %s 失败（ENXIO）：接口可能已被移除或处于 down 状态", want.c_str());
        set_error(BpfStatus::kIfaceDown, buf);
      } else {
        std::snprintf(buf, sizeof(buf), "BIOCSETIF(%s) 失败：%s (errno=%d)", want.c_str(),
                      std::strerror(e), e);
        set_error(BpfStatus::kIoctlFailed, buf);
      }
      close();
      return -1;
    }
  }

  // ---- BIOCIMMEDIATE：不等缓冲满就返回 ----
  // 默认行为是「缓冲满或超时才返回」，对交互式抓包（如按 -n 计数后退出）会导致
  // 长时间收不到包。置 1 表示每次 read 立即返回当前可用数据。
  {
    u_int on = 1;
    if (::ioctl(fd_, BIOCIMMEDIATE, &on) < 0) {
      fail_ioctl("BIOCIMMEDIATE", errno);
      close();
      return -1;
    }
  }

  // ---- BIOCSRTIMEOUT：读超时 ----
  // 不设超时则 read 可能永久阻塞——对一个「抓 N 个包就退出」的工具意味着可能挂死。
  {
    struct timeval tv;
    tv.tv_sec = static_cast<time_t>(timeout_ms_ / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms_ % 1000) * 1000);
    if (::ioctl(fd_, BIOCSRTIMEOUT, &tv) < 0) {
      fail_ioctl("BIOCSRTIMEOUT", errno);
      close();
      return -1;
    }
  }

  // ---- BIOCPROMISC：混杂模式（可选）----
  // 失败不致命：普通模式下仍能收到发往本机与广播的包，足以完成大部分调试。
  // 但必须让调用方能察觉到「要了混杂却没开成」，故记录到错误串而不中断。
  if (promisc_) {
    if (::ioctl(fd_, BIOCPROMISC, nullptr) < 0) {
      char buf[256];
      std::snprintf(buf, sizeof(buf), "BIOCPROMISC 失败（%s）：将以非混杂模式继续",
                    std::strerror(errno));
      err_reason_ = buf;
    }
  }

  // ---- BIOCSSEESENT：是否看到本机发出的包 ----
  // 仅在调用方显式要求时设置。各 BSD 系对该值的语义并不一致，未经实测不替用户决定。
  if (see_sent_ != SeeSent::kUnspecified) {
    u_int v = (see_sent_ == SeeSent::kEnable) ? 0u : 1u;
    (void)::ioctl(fd_, BIOCSSEESENT, &v);
  }

  // ---- 记录链路层类型 ----
  {
    u_int dlt = 0;
    if (::ioctl(fd_, BIOCGDLT, &dlt) == 0) {
      link_type_ = dlt;
    }
  }

  // 读缓冲必须按内核实际采纳的大小分配，且 read 的字节数必须与它**恰好相等**
  // 而非仅不小于：XNU bpfread() 对 uio_resid != bd_bufsize 直接返回 EINVAL
  // （与 FreeBSD/Linux 的「够用即可」语义不同）。不等则 read 永远瞬时失败，
  // 一个包也取不回来。
  buf_.assign(buf_size_, 0);
  views_.reserve(1024);

  opened_ = true;
  return 0;
}

void BpfCaptureBackend::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  buf_.clear();
  buf_.shrink_to_fit();
  views_.clear();
  views_.shrink_to_fit();
  device_.clear();
  opened_ = false;
  buf_size_ = 0;
  link_type_ = 0;
  ifindex_ = 0;
}

BpfCaptureBackend::BatchResult BpfCaptureBackend::parse_batch(const uint8_t* data, size_t len,
                                                              uint32_t max, uint32_t ifindex,
                                                              uint32_t snap_len,
                                                              std::vector<PacketBuffer>* views) {
  BatchResult out;
  if (data == nullptr || len == 0 || max == 0 || views == nullptr) {
    return out;
  }

  const uint8_t* p = data;
  const uint8_t* const end = data + len;

  while (p + kMinBpfHdrLen <= end) {
    const auto* hdr = reinterpret_cast<const struct bpf_hdr*>(p);

    // hdrlen 是内核给的头部长度（含字段间对齐填充，但不含结构体尾部填充）。
    // 下界必须用 kMinBpfHdrLen(=18)：内核写的就是紧凑的 18，若用
    // sizeof(struct bpf_hdr)(=20) 会把每个正常包误判成畸形。若 hdrlen 连 18
    // 都不到，说明缓冲内容已错位 —— 继续解析只会产出垃圾，必须停下并报出，
    // 而不是把垃圾当报文交给上层。
    if (hdr->bh_hdrlen < kMinBpfHdrLen) {
      out.malformed = true;
      break;
    }
    const uint8_t* pkt = p + hdr->bh_hdrlen;
    if (pkt > end || static_cast<size_t>(end - pkt) < hdr->bh_caplen) {
      out.malformed = true;
      break;
    }

    if (out.packets >= max) {
      // 本轮 read 已把内核缓冲里的包全部取出，未被交付的部分无法在下次读回，
      // 只能计入丢弃。这是 rx_burst 的调用契约：max 应足够大。
      ++out.overflow;
    } else {
      PacketBuffer v;
      v.data = const_cast<uint8_t*>(pkt);
      // snaplen 截断：BPF 无 per-packet snaplen，故在交付视图时截断 caplen，而
      // wirelen 保留完整值。语义与其它后端一致：caplen < wirelen 即表示截断。
      // 注意截断只影响交付长度，不省内核到用户态的拷贝。
      uint32_t cap = hdr->bh_caplen;
      if (snap_len != 0 && cap > snap_len) {
        cap = snap_len;
      }
      v.caplen = cap;
      v.wirelen = hdr->bh_datalen;
      v.ifindex = ifindex;
      // bh_tstamp 在本平台是 2×u32（bpf_timeval），转纳秒。
      const auto& ts = hdr->bh_tstamp;
      v.timestamp_ns = static_cast<int64_t>(ts.tv_sec) * 1000000000LL +
                       static_cast<int64_t>(ts.tv_usec) * 1000LL;
      views->push_back(v);
      ++out.packets;
      out.bytes += hdr->bh_datalen;
    }

    // 下一包偏移必须做 4 字节对齐：bpf_hdr 之后是数据，数据之后到下一个
    // bpf_hdr 之间存在对齐填充（实测 BPF_ALIGNMENT=4）。漏掉这一步会从
    // 第二个包起持续读到错位数据，且不会产生任何错误。
    p += BPF_WORDALIGN(static_cast<size_t>(hdr->bh_hdrlen) + hdr->bh_caplen);
  }

  return out;
}

int BpfCaptureBackend::rx_burst(PacketBuffer** pkts, uint32_t max) {
  if (!opened_ || fd_ < 0) {
    set_error(BpfStatus::kIoError, "rx_burst 在未打开的后端上被调用");
    return -1;
  }
  if (pkts == nullptr || max == 0) {
    return 0;
  }

  // views_ 复用：清空但保留容量，避免每批都重新分配。
  views_.clear();

  const ssize_t n = ::read(fd_, buf_.data(), buf_.size());
  if (n < 0) {
    if (errno == EINTR) {
      // 信号打断不是错误，也不代表有包可读。
      return 0;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0; // 超时：无包
    }
    char buf[256];
    std::snprintf(buf, sizeof(buf), "read 失败：%s (errno=%d)", std::strerror(errno), errno);
    set_error(BpfStatus::kIoError, buf);
    return -1;
  }
  if (n == 0) {
    return 0; // 超时且无数据
  }

  const BatchResult r =
      parse_batch(buf_.data(), static_cast<size_t>(n), max, ifindex_, snap_len_, &views_);

  stats_.rx_packets += r.packets;
  stats_.rx_bytes += r.bytes;
  if (r.overflow > 0) {
    stats_.rx_dropped += r.overflow;
  }
  if (r.malformed) {
    // 不中断已解出的包：本批中已解析的部分是可信的，丢弃畸形尾部即可。
    // 但错误必须留痕，否则「莫名其妙少收包」将无从排查。
    stats_.rx_errors += 1;
    set_error(BpfStatus::kIoError, "读缓冲中出现畸形 bpf_hdr：已停止解析本批剩余部分");
  }

  for (uint32_t i = 0; i < r.packets; ++i) {
    pkts[i] = &views_[i];
  }
  return static_cast<int>(r.packets);
}

BackendStats BpfCaptureBackend::stats() {
  BackendStats s = stats_;
  if (fd_ >= 0) {
    // 内核侧统计：bs_drop 是内核缓冲满导致的丢包，用户空间无法观察到，
    // 只能由此取得。注意 rx_packets 与内核 bs_recv 语义不同：
    //   rx_packets = 实际交付给调用方的包数（用户空间视角）
    //   bs_recv    = 内核收到的包数
    // 前者用于判断「我处理了多少」，后者用于判断「网络上有多少」，故此处只取丢包。
    struct bpf_stat kst;
    std::memset(&kst, 0, sizeof(kst));
    if (::ioctl(fd_, BIOCGSTATS, &kst) == 0) {
      s.rx_dropped = stats_.rx_dropped + kst.bs_drop;
    }
  }
  return s;
}

void* BpfCaptureBackend::native_handle() {
  return reinterpret_cast<void*>(static_cast<intptr_t>(fd_));
}

int BpfCaptureBackend::wait_readable(uint32_t timeout_ms) {
  if (fd_ < 0) {
    set_error(BpfStatus::kIoError, "wait_readable 在未打开的后端上被调用");
    return -1;
  }
  struct pollfd pfd;
  pfd.fd = fd_;
  pfd.events = POLLIN;
  pfd.revents = 0;
  const int rc = ::poll(&pfd, 1, static_cast<int>(timeout_ms));
  if (rc < 0) {
    if (errno == EINTR) {
      // 信号打断不是错误：返回 0 让调用方继续循环。
      return 0;
    }
    char buf[256];
    std::snprintf(buf, sizeof(buf), "poll 失败：%s (errno=%d)", std::strerror(errno), errno);
    set_error(BpfStatus::kIoError, buf);
    return -1;
  }
  return rc; // 0 = 超时，1 = 可读
}

} // namespace packet_engine
