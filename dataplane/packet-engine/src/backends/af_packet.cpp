// backends/af_packet.cpp - Linux AF_PACKET 抓包后端实现。
//
// 本文件只在 Linux 平台参与编译（见 CMakeLists 的平台条件），故可直接使用
// <linux/if_packet.h> 而不必在源码里堆 #ifdef。
//
// === 所有结构体字段与常量均已实测核对，不凭记忆书写 ===
// 核对方式：在真实发行版容器内读取并编译打印，而非查阅文档：
//   Ubuntu 24.04  (linux-libc-dev 6.8.0-139)  V2HDR=52 V3HDR=68 align=16
//   Rocky Linux 9 (kernel-headers 5.14.0-687) 同上
//   openEuler     (kernel-headers 6.6.0-145)  同上
// 实测偏移（tpacket3_hdr，共 48 字节）：
//   tp_next_offset@0 tp_sec@4 tp_nsec@8 tp_snaplen@12 tp_len@16 tp_status@20 tp_mac@24
// 实测偏移（tpacket2_hdr，共 32 字节）：
//   tp_status@0 tp_len@4 tp_snaplen@8 tp_mac@12 tp_sec@16 tp_nsec@20 tp_vlan_tci@24
// 结构体成员由头文件声明，故字段名写错会在编译期暴露；但**偏移语义**（tp_mac 是
// 相对包头还是相对帧首、tp_next_offset 是否含自身）无法由编译器校验，只能实测，
// 这正是上面逐项核对的原因。
#include "packet_engine/backends/af_packet.h"

#include "packet_engine/backends/link_type.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <numeric>
#include <string>

namespace packet_engine {

namespace {

// V3 单块最小尺寸。V3 的块是「变长包容器」而非固定帧（frame_size == block_size，
// frames_per_block 恒为 1），块越大则超时退休前的聚合包越多、系统调用摊薄得越好。
constexpr uint32_t kMinV3Block = 64u * 1024u;

// 环的默认总容量 4 MiB。足以吸收千兆链路上数十毫秒的突发，同时不至于让
// 「重置环」的内存清零变得明显。
constexpr uint32_t kDefaultBuffer = 4u * 1024u * 1024u;

// 环的最小块数。块太少会让「一块正被用户态读、内核无块可写」的概率显著上升，
// 表现为 TP_STATUS_LOSING 与内核丢包。
constexpr uint32_t kMinBlocks = 4;

// 单个包在环内需要的字节（含内核包头与对齐余量）。用于校验帧尺寸是否放得下
// snaplen 指定的抓取长度。
uint32_t page_size() {
  const long ps = ::sysconf(_SC_PAGESIZE);
  return ps > 0 ? static_cast<uint32_t>(ps) : 4096u;
}

uint32_t round_up_to(uint32_t v, uint32_t unit) {
  if (unit == 0) {
    return v;
  }
  const uint32_t r = v % unit;
  return r == 0 ? v : v + (unit - r);
}

// 取当前可执行文件路径，用于给出**可直接粘贴执行**的 setcap 命令。
// 只说「需要 CAP_NET_RAW」而不给出具体命令，用户仍需自己查路径与 capability 名。
std::string self_exe_path() {
  char buf[4096];
  const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) {
    return std::string();
  }
  buf[n] = '\0';
  return std::string(buf);
}

} // namespace

const char* ring_mode_name(RingMode mode) {
  switch (mode) {
  case RingMode::kTpacketV3:
    return "TPACKET_V3";
  case RingMode::kTpacketV2:
    return "TPACKET_V2";
  case RingMode::kRecvfrom:
    return "recvfrom";
  }
  return "unknown";
}

// Linux 侧实现：本平台后端给出的 link_type 是 sockaddr_ll.sll_hatype，即 **ARPHRD_***
// 编号空间。切勿照抄 BPF 侧的 DLT_* 表 —— 两者只是以太网恰好都为 1
// （ARPHRD_ETHER=1、DLT_EN10MB=1），回环完全不同（ARPHRD_LOOPBACK=772、DLT_NULL=0）。
std::string link_type_name(uint32_t value) {
  switch (value) {
  case ARPHRD_ETHER:
    return "ETHER(以太网)";
  case ARPHRD_LOOPBACK:
    return "LOOPBACK(回环)";
  case ARPHRD_PPP:
    return "PPP";
  case ARPHRD_SIT:
    return "SIT(IPv6-in-IPv4)";
  case ARPHRD_TUNNEL:
    return "TUNNEL";
  case ARPHRD_IEEE80211:
    return "IEEE80211(无线)";
  case ARPHRD_IEEE80211_RADIOTAP:
    return "IEEE80211_RADIOTAP";
  case ARPHRD_VOID:
    return "VOID";
#ifdef ARPHRD_RAWIP
  case ARPHRD_RAWIP:
    return "RAWIP(裸 IP)";
#endif
  default: {
    char buf[48];
    std::snprintf(buf, sizeof(buf), "未知链路类型(0x%04x)", value);
    return std::string(buf);
  }
  }
}

bool AfPacketBackend::ignore_outgoing_supported() {
#ifdef PACKET_IGNORE_OUTGOING
  return true;
#else
  // 内核头文件早于 4.20：常量不存在，忽略本机发出包的开关无法生效。
  return false;
#endif
}

AfPacketBackend::AfPacketBackend() = default;

AfPacketBackend::~AfPacketBackend() {
  // 析构即关闭：环占的是内核侧不可回收内存（在 socket 生命周期内），
  // 忘关会让内存一直挂着直到进程退出。
  close();
}

std::string AfPacketBackend::configure(const CaptureOptions& options) {
  // 逐项落定，并把本后端无法生效的项**显式回报**给调用方。
  //
  // 为什么返回值不是 void：静默忽略设置是危险的。用户要了混杂模式却跑在非混杂
  // 下，会以为「抓不到某些包是网络问题」；要了 ignore_outgoing 而老内核上没生效，
  // 会看到本机发出的包却以为是重复帧。宁可明确告知不支持。
  promisc_ = options.promisc;
  allow_fallback_ = options.allow_fallback;
  if (options.buffer_bytes != 0) {
    want_buffer_ = options.buffer_bytes;
  }
  if (options.retire_ms != 0) {
    retire_ms_ = options.retire_ms;
  }
  if (options.snap_len != 0) {
    snap_len_ = options.snap_len;
  }

  std::string rejected;
  auto note = [&rejected](const char* name) {
    if (!rejected.empty()) {
      rejected += "、";
    }
    rejected += name;
  };

  if (options.ignore_outgoing) {
    if (ignore_outgoing_supported()) {
      ignore_outgoing_ = true;
    } else {
      // 编译期就没有该常量 = 目标内核头文件早于 4.20，开关无论如何都不会生效。
      note("ignore_outgoing(需 Linux>=4.20 的内核头文件)");
    }
  }

  // 单次读超时：本后端未实现。环模式是非阻塞的（由调用方 poll），recvfrom 兜底
  // 模式也未设 SO_RCVTIMEO —— 与其假装接受，不如让人知道要去用 wait_readable()。
  if (options.read_timeout_ms != 0) {
    note("read_timeout_ms(请改用 wait_readable())");
  }

  return rejected.empty() ? std::string() : "本后端不支持这些采集参数: " + rejected;
}

void AfPacketBackend::set_error(AfPacketStatus s, const std::string& r) {
  err_ = s;
  err_reason_ = r;
}

void AfPacketBackend::fail_errno(AfPacketStatus default_status, const char* what, int err) {
  AfPacketStatus status = default_status;
  char detail[512];
  switch (err) {
  case EPERM:
  case EACCES: {
    status = AfPacketStatus::kPermission;
    const std::string exe = self_exe_path();
    std::snprintf(detail, sizeof(detail),
                  "%s 被拒（%s）：本进程缺少 CAP_NET_RAW。可选处置：\n"
                  "    ① 以 root 运行；\n"
                  "    ② 给二进制度赋予 capability（无需 root 运行）："
                  "sudo setcap cap_net_raw,cap_net_admin+eip %s\n"
                  "    ③ 容器内需以 --cap-add=NET_RAW 启动（部分运行时还需 --privileged）。\n"
                  "    注意：setcap 后无法再用调试器附加（会触发 capabilities 校验），"
                  "排障时二者需分开做。",
                  what, std::strerror(err), exe.empty() ? "<可执行文件路径>" : exe.c_str());
    set_error(status, detail);
    return;
  }
  case ENODEV:
  case ENXIO:
    status = AfPacketStatus::kNoSuchIface;
    break;
  case EOPNOTSUPP:
    set_error(default_status,
              std::string(what) + " 不被内核支持（" + std::strerror(err) +
                  "）：该接口类型（如某些隧道/虚拟接口）不支持 AF_PACKET 收包");
    return;
  case ENOBUFS:
  case ENOMEM:
    set_error(AfPacketStatus::kRingFailed,
              std::string(what) + " 内存不足（" + std::strerror(err) +
                  "）：请减小环容量或块数（set_buffer_bytes / --ring-bytes）");
    return;
  default:
    break;
  }
  std::snprintf(detail, sizeof(detail), "%s 失败（%s，errno=%d）", what, std::strerror(err), err);
  set_error(status, detail);
}

void AfPacketBackend::close() {
  if (ring_ != nullptr && ring_bytes_ > 0) {
    ::munmap(ring_, ring_bytes_);
  }
  ring_ = nullptr;
  ring_bytes_ = 0;

  if (fd_ >= 0 && mode_ != RingMode::kRecvfrom) {
    // 尽量把内核侧丢包数取回来。PACKET_STATISTICS 是**读即清零**语义，故只在此处
    // 读一次（关闭时）。内核丢包数是排障时最常被忽略的一项：用户态看到「收到 N 个」
    // 却对不上线上数量时，缺的那部分就在这里。
    struct tpacket_stats st;
    socklen_t len = sizeof(st);
    std::memset(&st, 0, sizeof(st));
    if (::getsockopt(fd_, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0) {
      stats_.rx_dropped += st.tp_drops;
    }
  }
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  opened_ = false;
  pending_retire_.clear();
  cur_block_ = 0;
  cur_frame_ = 0;
  cur_off_ = 0;
  cur_pkts_ = 0;
  cur_num_pkts_ = 0;
  cur_next_off_ = 0;
}

bool AfPacketBackend::configure_interface() {
  // source 支持两种写法：接口名（eth0 / ens33）与 "ifindex:N"。
  //
  // 为什么需要按索引：容器与云主机重启后接口名可能变化（如 ens33 被重命名为 eth0），
  // 而同一网络命名空间内的索引更稳定。两种写法都无需特权即可解析 ——
  // 权限只在建 socket 那一步才需要，故「名字写错了」能在拿到权限错误之前先被区分出来。
  ifindex_ = 0;
  iface_.clear();

  const std::string src = source_;
  const std::string kPrefix = "ifindex:";
  if (src.compare(0, kPrefix.size(), kPrefix) == 0) {
    const std::string num = src.substr(kPrefix.size());
    char* end = nullptr;
    const unsigned long v = std::strtoul(num.c_str(), &end, 10);
    if (num.empty() || end == nullptr || *end != '\0' || v == 0 || v > 0xFFFFFFFFul) {
      set_error(AfPacketStatus::kNoSuchIface,
                "接口索引写法非法: \"" + src + "\"（正确形式如 ifindex:3，索引须为正整数）");
      return false;
    }
    ifindex_ = static_cast<uint32_t>(v);
    // 回填接口名用于诊断显示；索引存在但查不到名字属异常（理论上不会发生）。
    char namebuf[IF_NAMESIZE];
    if (::if_indextoname(ifindex_, namebuf) != nullptr) {
      iface_ = namebuf;
    } else {
      set_error(AfPacketStatus::kNoSuchIface,
                "接口索引 " + num + " 在本网络命名空间内不存在");
      return false;
    }
  } else {
    if (src.empty()) {
      set_error(AfPacketStatus::kNoSuchIface, "接口名为空");
      return false;
    }
    if (src.size() >= IF_NAMESIZE) {
      set_error(AfPacketStatus::kNoSuchIface,
                "接口名过长: \"" + src + "\"（内核上限 " + std::to_string(IF_NAMESIZE - 1) +
                    " 字符，请确认是否误把路径当成了接口名）");
      return false;
    }
    iface_ = src;
    ifindex_ = ::if_nametoindex(iface_.c_str());
    if (ifindex_ == 0) {
      // 不列出全部接口名：接口可能很多，且调用方（CLI）有 list_interfaces() 可自行展示。
      // 这里给出的是「确实不存在」这一确定结论，而不是猜测性的建议。
      set_error(AfPacketStatus::kNoSuchIface,
                "接口 \"" + iface_ + "\" 不存在（本网络命名空间内查无此接口）");
      return false;
    }
  }

  // 校验接口已启用。**必须用独立的 AF_INET socket**：此时 AF_PACKET socket 尚未
  // 创建（这一步失败不应消耗 CAP_NET_RAW 相关的权限判定），且 AF_INET socket 无需特权。
  if (!opened_) {
    const int chk = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (chk >= 0) {
      struct ifreq req;
      std::memset(&req, 0, sizeof(req));
      std::snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", iface_.c_str());
      if (::ioctl(chk, SIOCGIFFLAGS, &req) == 0) {
        if ((req.ifr_flags & IFF_UP) == 0) {
          ::close(chk);
          // 「接口存在但 down」与「接口不存在」是两件事：前者是环境未就绪（可等待），
          // 后者是配置错误。合并上报会让自动化脚本无法据以决定「重试」还是「报错退出」。
          set_error(AfPacketStatus::kIfaceDown,
                    "接口 \"" + iface_ + "\" 存在但未启用（缺少 IFF_UP）。"
                    "请先 ip link set " + iface_ + " up（或检查网线/上层网桥状态）");
          return false;
        }
      }
      ::close(chk);
    }
  }
  return true;
}

bool AfPacketBackend::compute_ring_params(uint32_t extra_hdr, uint32_t* out_block_size,
                                          uint32_t* out_block_nr, uint32_t* out_frame_size,
                                          uint32_t* out_frames_per_block) const {
  const uint32_t ps = page_size();
  const uint32_t want = want_buffer_ == 0 ? kDefaultBuffer : want_buffer_;

  if (extra_hdr == TPACKET3_HDRLEN) {
    // ---- TPACKET_V3 ----
    // V3 的块是变长包容器：frame_size 与 block_size 相等、frames_per_block 恒为 1，
    // 内核按 num_pkts 告知块内实际包数。故只需保证块放得下「一个最大包」，
    // 其余空间用于聚合。
    //
    // 约束（内核 packet_set_ring 校验）：block_size 必须页对齐且 > 0。
    const uint32_t min_for_one = extra_hdr + snap_len_ + 64u;
    uint32_t bs = std::max(std::max(min_for_one, kMinV3Block), ps);
    bs = round_up_to(bs, ps);
    if (bs == 0) {
      return false;
    }
    uint32_t bn = want / bs;
    if (bn < kMinBlocks) {
      bn = kMinBlocks;
    }
    *out_block_size = bs;
    *out_block_nr = bn;
    *out_frame_size = bs; // V3：与 block_size 相等
    *out_frames_per_block = 1;
    return true;
  }

  // ---- TPACKET_V2 ----
  // 固定帧布局：每帧容纳一个包。两条内核约束必须同时满足且互相牵制：
  //   (a) block_size 必须页对齐（PAGE_ALIGNED 校验）
  //   (b) block_size 必须是 frame_size 的整数倍（frames_per_block 由整除得出）
  //   (c) frames_per_block * block_nr == frame_nr
  //
  // (a)+(b) 意味着 block_size 必须是 lcm(frame_size, PAGE_SIZE)。直接取 lcm 即可
  // 同时满足两者，且 lcm/frame_size = PAGE_SIZE/gcd(frame_size, PAGE_SIZE) 就是合法的
  // frames_per_block。**若改用「block_size = frame_size * k 再向上取整到页」的做法则
  // 会破坏 (b)** —— 取整后的值不再被 frame_size 整除，内核直接 EINVAL。
  //
  // aarch64 上页大小可能是 16 KiB 甚至 64 KiB（本机容器实测为 4 KiB），旧发行版的
  // 内核对 block_nr 上限也更紧。故这里按实算而非写死，并由上层的重试逻辑兜底。
  uint32_t fs = round_up_to(extra_hdr + snap_len_, TPACKET_ALIGNMENT);
  if (fs == 0) {
    return false;
  }
  const uint32_t g = std::gcd(fs, ps);
  const uint32_t frames_per_block = ps / g;
  if (frames_per_block == 0) {
    return false;
  }
  const uint32_t bs = fs * frames_per_block;
  uint32_t bn = want / bs;
  if (bn < kMinBlocks) {
    bn = kMinBlocks;
  }
  *out_block_size = bs;
  *out_block_nr = bn;
  *out_frame_size = fs;
  *out_frames_per_block = frames_per_block;
  return true;
}

bool AfPacketBackend::apply_common_socket_opts() {
  // 收到自己发出的包由内核默认决定（默认**会**收到，与 tcpdump 行为一致）。
  // PACKET_IGNORE_OUTGOING 是 4.20 才引入的，老内核头文件可能没有 ——
  // 这正是「跨发行版」的典型差异：常量存在性随内核头文件版本变化。
#ifdef PACKET_IGNORE_OUTGOING
  if (ignore_outgoing_) {
    const int one = 1;
    ::setsockopt(fd_, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one));
  }
#endif

  if (mode_ == RingMode::kRecvfrom) {
    // 无 mmap 时收包走内核 socket 缓冲，调大以减少丢包。
    const int rcvbuf = 4 * 1024 * 1024;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  }

#ifdef SO_TIMESTAMPNS
  // 让内核在 recvmsg 的辅助数据里带上纳秒时间戳。仅在 recvfrom 兜底模式下需要：
  // mmap 模式的每包时间戳由 tpacket_hdr.tp_sec/tp_nsec 直接给出。
  if (mode_ == RingMode::kRecvfrom) {
    const int one = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_TIMESTAMPNS, &one, sizeof(one));
  }
#endif
  return true;
}

bool AfPacketBackend::setup_v3() {
  // 依次尝试 V3；失败则记录原因并返回 false，由上层的降级链继续。
  fd_ = ::socket(AF_PACKET, SOCK_RAW, ::htons(ETH_P_ALL));
  if (fd_ < 0) {
    fail_errno(AfPacketStatus::kSocketFailed, "socket(AF_PACKET, SOCK_RAW)", errno);
    return false;
  }
  mode_ = RingMode::kTpacketV3;
  apply_common_socket_opts();

  const int ver = TPACKET_V3;
  if (::setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) != 0) {
    // 内核不支持 V3（3.2 以前）。这是**环境能力差异**而非配置错误，故不设 err_，
    // 只把原因追加到降级说明里 —— 上层会继续尝试 V2。
    fallback_reason_ += "TPACKET_V3 不可用（PACKET_VERSION 被拒：" +
                        std::string(std::strerror(errno)) + "）；";
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  uint32_t bs = 0, bn = 0, fs = 0, fpb = 0;
  if (!compute_ring_params(TPACKET3_HDRLEN, &bs, &bn, &fs, &fpb)) {
    fallback_reason_ += "TPACKET_V3 环参数无解；";
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  struct tpacket_req3 req;
  std::memset(&req, 0, sizeof(req));
  req.tp_block_size = bs;
  req.tp_block_nr = bn;
  req.tp_frame_size = fs;
  req.tp_frame_nr = bn * fpb;
  req.tp_retire_blk_tov = retire_ms_;
  req.tp_sizeof_priv = 0;
  req.tp_feature_req_word = 0;

  // 内核可能拒绝请求的尺寸（内存碎片、内核上限、块数上限）。逐次减半块数重试，
  // 次数有界（3 次），避免在异常内核上无限循环。这是「适应而非假设」的具体做法：
  // 不同发行版内核对同一组参数的接受度不同，靠编译期写死一组「已知可用值」不可行。
  int last_errno = 0;
  bool ring_ok = false;
  for (int attempt = 0; attempt < 3; ++attempt) {
    if (::setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) == 0) {
      ring_ok = true;
      break;
    }
    last_errno = errno;
    if (errno != EINVAL && errno != ENOMEM && errno != ENOBUFS) {
      break; // 非尺寸类错误，重试无意义
    }
    if (req.tp_block_nr <= kMinBlocks) {
      break; // 已到最小值，再减就不值得了
    }
    req.tp_block_nr = std::max(kMinBlocks, req.tp_block_nr / 2);
    req.tp_frame_nr = req.tp_block_nr * fpb;
  }

  if (!ring_ok) {
    fallback_reason_ += std::string("TPACKET_V3 环申请被拒（") + std::strerror(last_errno) +
                        "，block_size=" + std::to_string(bs) +
                        " block_nr=" + std::to_string(bn) + "）；";
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  block_size_ = req.tp_block_size;
  block_nr_ = req.tp_block_nr;
  frame_size_ = req.tp_frame_size;
  frames_per_block_ = fpb;
  ring_bytes_ = static_cast<size_t>(block_size_) * block_nr_;
  ring_ = static_cast<uint8_t*>(
      ::mmap(nullptr, ring_bytes_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0));
  if (ring_ == MAP_FAILED) {
    ring_ = nullptr;
    ring_bytes_ = 0;
    fail_errno(AfPacketStatus::kMmapFailed, "mmap(TPACKET_V3 环)", errno);
    ::close(fd_);
    fd_ = -1;
    return false;
  }
  return true;
}

bool AfPacketBackend::setup_v2() {
  fd_ = ::socket(AF_PACKET, SOCK_RAW, ::htons(ETH_P_ALL));
  if (fd_ < 0) {
    fail_errno(AfPacketStatus::kSocketFailed, "socket(AF_PACKET, SOCK_RAW)", errno);
    return false;
  }
  mode_ = RingMode::kTpacketV2;
  apply_common_socket_opts();

  const int ver = TPACKET_V2;
  if (::setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) != 0) {
    fallback_reason_ += "TPACKET_V2 不可用（PACKET_VERSION 被拒）；";
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  uint32_t bs = 0, bn = 0, fs = 0, fpb = 0;
  if (!compute_ring_params(TPACKET2_HDRLEN, &bs, &bn, &fs, &fpb)) {
    fallback_reason_ += "TPACKET_V2 环参数无解；";
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  struct tpacket_req req;
  std::memset(&req, 0, sizeof(req));
  req.tp_block_size = bs;
  req.tp_block_nr = bn;
  req.tp_frame_size = fs;
  req.tp_frame_nr = bn * fpb;

  int last_errno = 0;
  bool ring_ok = false;
  for (int attempt = 0; attempt < 3; ++attempt) {
    if (::setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) == 0) {
      ring_ok = true;
      break;
    }
    last_errno = errno;
    if (errno != EINVAL && errno != ENOMEM && errno != ENOBUFS) {
      break;
    }
    if (req.tp_block_nr <= kMinBlocks) {
      break;
    }
    req.tp_block_nr = std::max(kMinBlocks, req.tp_block_nr / 2);
    req.tp_frame_nr = req.tp_block_nr * fpb;
  }

  if (!ring_ok) {
    fallback_reason_ += std::string("TPACKET_V2 环申请被拒（") + std::strerror(last_errno) +
                        "，block_size=" + std::to_string(bs) +
                        " frame_size=" + std::to_string(fs) + "）；";
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  block_size_ = req.tp_block_size;
  block_nr_ = req.tp_block_nr;
  frame_size_ = req.tp_frame_size;
  frames_per_block_ = fpb;
  ring_bytes_ = static_cast<size_t>(block_size_) * block_nr_;
  ring_ = static_cast<uint8_t*>(
      ::mmap(nullptr, ring_bytes_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0));
  if (ring_ == MAP_FAILED) {
    ring_ = nullptr;
    ring_bytes_ = 0;
    fail_errno(AfPacketStatus::kMmapFailed, "mmap(TPACKET_V2 环)", errno);
    ::close(fd_);
    fd_ = -1;
    return false;
  }
  return true;
}

bool AfPacketBackend::setup_recvfrom() {
  // 最后兜底：不使用 PACKET_MMAP。每个包一次系统调用，吞吐最低，但在
  // 「mmap 环因任何原因建不起来」的环境中至少仍能抓包（可用性优先于性能）。
  fd_ = ::socket(AF_PACKET, SOCK_RAW, ::htons(ETH_P_ALL));
  if (fd_ < 0) {
    fail_errno(AfPacketStatus::kSocketFailed, "socket(AF_PACKET, SOCK_RAW)", errno);
    return false;
  }
  mode_ = RingMode::kRecvfrom;
  recv_buf_.assign(snap_len_, 0);
  apply_common_socket_opts();
  return true;
}

int AfPacketBackend::open(const char* source) {
  close();
  err_ = AfPacketStatus::kOk;
  err_reason_ = "ok";
  fallback_reason_.clear();

  if (source == nullptr || *source == '\0') {
    set_error(AfPacketStatus::kNoSuchIface, "source 为空：需要接口名（如 eth0）或 ifindex:N");
    return -1;
  }
  source_ = source;

  // 先解析并校验接口，再建 socket。顺序刻意如此：接口名写错属配置错误，
  // 应在消耗/判定权限之前就报出来 —— 否则无特权环境下会把「名字写错」
  // 误报成「权限不足」，把排障引向完全错误的方向。
  if (!configure_interface()) {
    return -1;
  }

  // 降级链：V3 → V2 → recvfrom。
  bool ok = setup_v3();
  if (!ok && allow_fallback_) {
    ok = setup_v2();
  }
  if (!ok && allow_fallback_) {
    ok = setup_recvfrom();
  }
  if (!ok) {
    // 全部失败：优先保留权限/接口类错误的原始诊断（它们可操作性最强），
    // 若无此类错误则给出降级链的整体说明。
    if (err_ == AfPacketStatus::kOk) {
      set_error(AfPacketStatus::kRingFailed,
                "所有采集模式均不可用。降级链明细：" +
                    (fallback_reason_.empty() ? std::string("（无）") : fallback_reason_) +
                    "。若已 --no-fallback，请去掉该选项以允许降级到 TPACKET_V2/recvfrom");
    }
    return -1;
  }

  // bind：把 socket 绑定到目标接口与以太网层协议。
  struct sockaddr_ll sll;
  std::memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = ::htons(ETH_P_ALL);
  sll.sll_ifindex = static_cast<int>(ifindex_);
  if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) != 0) {
    fail_errno(AfPacketStatus::kBindFailed, "bind(AF_PACKET)", errno);
    close();
    return -1;
  }

  // 取链路层类型与发起者地址。sll_hatype 就是 ARPHRD_* 编号。
  struct sockaddr_ll got;
  socklen_t got_len = sizeof(got);
  std::memset(&got, 0, sizeof(got));
  if (::getsockname(fd_, reinterpret_cast<struct sockaddr*>(&got), &got_len) == 0) {
    link_type_ = got.sll_hatype;
  }

  if (promisc_) {
    // 用 PACKET_ADD_MEMBERSHIP 而非 IFF_PROMISC：前者以引用计数方式生效，退出时
    // 内核自动撤销；后者需要在退出前显式还原，进程被 kill 会把接口留在混杂模式。
    struct packet_mreq mr;
    std::memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = static_cast<int>(ifindex_);
    mr.mr_type = PACKET_MR_PROMISC;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) != 0) {
      fail_errno(AfPacketStatus::kBindFailed, "setsockopt(PACKET_ADD_MEMBERSHIP, PROMISC)", errno);
      close();
      return -1;
    }
  }

  // 视图存储一次分配到位。rx_burst 每次调用都重新分配会让「高频小批量」的调用
  // 方式持续承受分配开销。
  views_.assign(std::max<uint32_t>(1, block_size_ / 64u + 64u), PacketBuffer{});

  opened_ = true;
  stats_ = BackendStats{};
  return 0;
}

int AfPacketBackend::wait_readable(uint32_t timeout_ms) {
  if (fd_ < 0) {
    return -1;
  }
  struct pollfd pfd;
  pfd.fd = fd_;
  pfd.events = POLLIN;
  pfd.revents = 0;
  const int r = ::poll(&pfd, 1, static_cast<int>(timeout_ms));
  if (r < 0) {
    return -1;
  }
  return r; // 0 = 超时，>0 = 可读（含 POLLERR，由随后的读操作报出具体错误）
}

void AfPacketBackend::retire_pending() {
  // 把上一批消费完的块归还内核。**延迟到本次调用开头**才归还，而不是在上次
  // rx_burst 返回前归还：调用方此刻可能仍在读上次返回的视图指向的字节，
  // 提前归还会让内核立即覆盖那些字节（读到新报文），且不会有任何错误提示。
  if (ring_ == nullptr || pending_retire_.empty()) {
    return;
  }
  if (mode_ == RingMode::kTpacketV3) {
    for (uint32_t bi : pending_retire_) {
      auto* bd = reinterpret_cast<struct tpacket_block_desc*>(ring_ +
                                                             static_cast<size_t>(bi) * block_size_);
      __sync_synchronize(); // 确保对包数据的读取已完成，再交还所有权
      bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
    }
  } else if (mode_ == RingMode::kTpacketV2) {
    for (uint32_t fi : pending_retire_) {
      const uint32_t bi = fi / frames_per_block_;
      const uint32_t idx = fi % frames_per_block_;
      auto* fh = reinterpret_cast<struct tpacket2_hdr*>(
          ring_ + static_cast<size_t>(bi) * block_size_ + static_cast<size_t>(idx) * frame_size_);
      __sync_synchronize();
      fh->tp_status = TP_STATUS_KERNEL;
    }
  }
  pending_retire_.clear();
}

uint32_t AfPacketBackend::drain_v3_block(PacketBuffer** pkts, uint32_t max) {
  uint32_t count = 0;
  // 块内可能还有上次未读完的余量（pkts 数组已满而提前返回），故用 while 而非单次判断。
  for (;;) {
    if (cur_num_pkts_ == 0) {
      // 当前块尚未取用：检查内核是否已交付。
      auto* bd = reinterpret_cast<struct tpacket_block_desc*>(
          ring_ + static_cast<size_t>(cur_block_) * block_size_);
      const uint32_t status = bd->hdr.bh1.block_status;
      if ((status & TP_STATUS_USER) == 0) {
        return count; // 该块仍归内核所有，无可读数据
      }
      if ((status & TP_STATUS_COPY) != 0) {
        // 包长超过 snaplen，内核无法放入环。这类包在 V3 下会被标记但不随块交付数据。
        stats_.rx_errors++;
      }
      __sync_synchronize();
      cur_off_ = bd->hdr.bh1.offset_to_first_pkt;
      cur_num_pkts_ = bd->hdr.bh1.num_pkts;
      cur_pkts_ = 0;
      // 空块（仅因超时退休）也可能出现：计入待归还后前进到下一块。
      if (cur_num_pkts_ == 0) {
        pending_retire_.push_back(cur_block_);
        cur_block_ = (cur_block_ + 1) % block_nr_;
        continue;
      }
    }

    while (cur_pkts_ < cur_num_pkts_) {
      if (count >= max) {
        return count; // 本批已满；块内余量留待下次调用
      }
      auto* h = reinterpret_cast<struct tpacket3_hdr*>(ring_ +
                                                       static_cast<size_t>(cur_block_) * block_size_ +
                                                       cur_off_);
      const uint32_t next = h->tp_next_offset;
      const uint32_t snaplen = h->tp_snaplen;
      const uint32_t macoff = h->tp_mac;
      // 越界校验：环内数据来自内核，但一旦内核版本与头文件假设不符（例如结构体
      // 布局差异），按错误偏移读取会得到看似合理的垃圾。此处做显式边界检查并使
      // 越界走「计错误 + 跳过」而非内存访问越界。
      if (macoff > block_size_ || snaplen > block_size_ || cur_off_ > block_size_ ||
          macoff + snaplen > block_size_ || cur_off_ + macoff + snaplen > block_size_) {
        stats_.rx_errors++;
        cur_pkts_ = cur_num_pkts_; // 放弃本块剩余内容
        break;
      }

      const uint8_t* payload = ring_ + static_cast<size_t>(cur_block_) * block_size_ + cur_off_ +
                               macoff;
      PacketBuffer* out = &views_[count];
      out->data = const_cast<uint8_t*>(payload);
      out->caplen = snaplen;
      out->wirelen = h->tp_len;
      out->headroom = 0;
      out->ifindex = ifindex_;
      out->timestamp_ns =
          static_cast<int64_t>(h->tp_sec) * 1000000000LL + static_cast<int64_t>(h->tp_nsec);
      out->refcount = 0;

      // VLAN 标签由网卡硬件剥离时，内核把标签值的有效标志放在 tp_status 里，
      // 标签本身在 hv1.tp_vlan_tci。若不还原，带 VLAN 的帧会被上层按「无标签」
      // 解析——以太网类型字段位置整体错位 4 字节，解出的五元组是错的。
      if ((h->tp_status & TP_STATUS_VLAN_VALID) != 0 && h->tp_status != 0xFFFFFFFFu) {
        // 说明：本路径只在网卡做硬件 VLAN 剥离时才会命中，纯软件路径（veth 等）
        // 不会设置该标志，故常规测试不易覆盖，需专门的标签流量用例。
        out->vlan_tci = h->hv1.tp_vlan_tci;
        out->vlan_tagged = true;
      } else {
        out->vlan_tci = 0;
        out->vlan_tagged = false;
      }

      pkts[count] = out;
      ++count;
      ++cur_pkts_;
      ++stats_.rx_packets;
      stats_.rx_bytes += h->tp_len;

      if (cur_pkts_ < cur_num_pkts_) {
        if (next == 0) {
          // 非最后包却给出 0 的下一偏移：异常数据，防死循环并如实计数。
          stats_.rx_errors++;
          cur_pkts_ = cur_num_pkts_;
          break;
        }
        cur_off_ += next;
      }
    }

    // 本块读完：记入待归还并前进（归还动作延迟到下次调用，见 retire_pending）。
    pending_retire_.push_back(cur_block_);
    cur_block_ = (cur_block_ + 1) % block_nr_;
    cur_num_pkts_ = 0;
    cur_pkts_ = 0;
    cur_off_ = 0;
    if (count >= max) {
      return count;
    }
  }
}

uint32_t AfPacketBackend::drain_v2_blocks(PacketBuffer** pkts, uint32_t max) {
  uint32_t count = 0;
  for (;;) {
    if (count >= max) {
      return count;
    }
    // 逐帧检查当前块。V2 的所有权粒度是「帧」而非「块」。
    if (cur_frame_ >= frames_per_block_) {
      cur_block_ = (cur_block_ + 1) % block_nr_;
      cur_frame_ = 0;
    }
    auto* fh = reinterpret_cast<struct tpacket2_hdr*>(
        ring_ + static_cast<size_t>(cur_block_) * block_size_ +
        static_cast<size_t>(cur_frame_) * frame_size_);
    if ((fh->tp_status & TP_STATUS_USER) == 0) {
      return count; // 该帧仍归内核（可能已绕一圈追上了我们）
    }
    if ((fh->tp_status & TP_STATUS_LOSING) != 0) {
      stats_.rx_dropped++;
    }
    __sync_synchronize();

    const uint32_t snaplen = fh->tp_snaplen;
    const uint32_t macoff = fh->tp_mac;
    if (macoff > frame_size_ || snaplen > frame_size_ || macoff + snaplen > frame_size_) {
      stats_.rx_errors++;
    } else {
      const uint8_t* payload = ring_ + static_cast<size_t>(cur_block_) * block_size_ +
                               static_cast<size_t>(cur_frame_) * frame_size_ + macoff;
      PacketBuffer* out = &views_[count];
      out->data = const_cast<uint8_t*>(payload);
      out->caplen = snaplen;
      out->wirelen = fh->tp_len;
      out->headroom = 0;
      out->ifindex = ifindex_;
      out->timestamp_ns =
          static_cast<int64_t>(fh->tp_sec) * 1000000000LL + static_cast<int64_t>(fh->tp_nsec);
      out->refcount = 0;
      if ((fh->tp_status & TP_STATUS_VLAN_VALID) != 0) {
        out->vlan_tci = fh->tp_vlan_tci;
        out->vlan_tagged = true;
      } else {
        out->vlan_tci = 0;
        out->vlan_tagged = false;
      }
      pkts[count] = out;
      ++count;
      ++stats_.rx_packets;
      stats_.rx_bytes += fh->tp_len;
    }

    // 该帧记入待归还（延迟到下次调用，理由同 V3）。
    pending_retire_.push_back(cur_block_ * frames_per_block_ + cur_frame_);
    ++cur_frame_;
  }
}

int AfPacketBackend::rx_burst(PacketBuffer** pkts, uint32_t max) {
  if (!opened_ || fd_ < 0) {
    return -1;
  }
  if (pkts == nullptr || max == 0) {
    return 0;
  }
  const uint32_t cap = static_cast<uint32_t>(views_.size());
  if (max > cap) {
    max = cap; // 视图存储是本批上限；静默截断而非越界写
  }

  // 归还上一批的块。必须在返回新数据之前完成，且不能在上一批返回之前完成。
  retire_pending();

  if (mode_ == RingMode::kTpacketV3) {
    return static_cast<int>(drain_v3_block(pkts, max));
  }
  if (mode_ == RingMode::kTpacketV2) {
    return static_cast<int>(drain_v2_blocks(pkts, max));
  }

  // recvfrom 兜底：每次至多一个包（语义上仍满足批量接口：返回实际个数）。
  struct sockaddr_ll from;
  std::memset(&from, 0, sizeof(from));
  if (recv_buf_.empty()) {
    return -1;
  }
  uint8_t cmsg[256];
  struct iovec iov;
  iov.iov_base = recv_buf_.data();
  iov.iov_len = recv_buf_.size();
  struct msghdr msg;
  std::memset(&msg, 0, sizeof(msg));
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg;
  msg.msg_controllen = sizeof(cmsg);

  const ssize_t n = ::recvmsg(fd_, &msg, MSG_DONTWAIT);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0; // 暂无数据。与「出错」必须区分：调用方据 0 继续等待而非退出。
    }
    if (errno == EINTR) {
      return 0;
    }
    fail_errno(AfPacketStatus::kIoError, "recvmsg(AF_PACKET)", errno);
    return -1;
  }

  PacketBuffer* out = &views_[0];
  out->data = recv_buf_.data();
  out->caplen = static_cast<uint32_t>(n);
  out->wirelen = static_cast<uint32_t>(n);
  out->headroom = 0;
  out->ifindex = ifindex_;
  out->refcount = 0;
  out->timestamp_ns = 0;
  out->vlan_tci = 0;
  out->vlan_tagged = false;

  // 优先取内核时间戳；取不到才退回墙上时钟（并如实落到这里，不做静默兜底之外的粉饰）。
#ifdef SO_TIMESTAMPNS
  bool got_ts = false;
  for (struct cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
    if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPNS) {
      struct timespec ts;
      std::memcpy(&ts, CMSG_DATA(c), sizeof(ts));
      out->timestamp_ns =
          static_cast<int64_t>(ts.tv_sec) * 1000000000LL + static_cast<int64_t>(ts.tv_nsec);
      got_ts = true;
      break;
    }
  }
  if (!got_ts) {
    struct timespec ts;
    ::clock_gettime(CLOCK_REALTIME, &ts);
    out->timestamp_ns =
        static_cast<int64_t>(ts.tv_sec) * 1000000000LL + static_cast<int64_t>(ts.tv_nsec);
  }
#else
  struct timespec ts;
  ::clock_gettime(CLOCK_REALTIME, &ts);
  out->timestamp_ns =
      static_cast<int64_t>(ts.tv_sec) * 1000000000LL + static_cast<int64_t>(ts.tv_nsec);
#endif

  pkts[0] = out;
  ++stats_.rx_packets;
  stats_.rx_bytes += static_cast<uint64_t>(n);
  return 1;
}

BackendStats AfPacketBackend::stats() {
  BackendStats s = stats_;
  // 内核侧未交付的丢包（环未及时归还 / 无空闲块）只能在关闭时从 PACKET_STATISTICS
  // 读到（该接口读即清零），故此处只返回已累积值。
  return s;
}

void* AfPacketBackend::native_handle() {
  return fd_ >= 0 ? reinterpret_cast<void*>(static_cast<intptr_t>(fd_)) : nullptr;
}

} // namespace packet_engine
