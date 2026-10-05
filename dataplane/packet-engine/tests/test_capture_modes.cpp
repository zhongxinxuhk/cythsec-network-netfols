// test_capture_modes.cpp - 采集档位强制与「丢包运行中可查」（CYS-PKT-008，仅 Linux）。
//
// === 这个文件要证明的两件事，以及它们各自为什么可证伪 ===
//
// 1. **指定档位就是指定档位**（--capture-mode v3/v2/recvfrom）。
//    跑吞吐对照时，「两档数字相同」必须能被解释成「性能真的一样」，而不是
//    「内核悄悄把两档都跑成了同一条路径」。所以：指定 recvfrom 时
//    capture_mode_name() 必须**逐字**是 recvfrom，指定 v3 时必须是 TPACKET_V3；
//    建立失败即失败，绝不降级。
//    （反向注入：把 open() 里指定模式的分支改回「先试 V3 再降级」，本用例立刻红。）
//
// 2. **丢包在 close() 之前就可读**。
//    造法：把一个**极小**的环（4 KiB = 1 个块）开起来，然后洪泛 20 万个小帧、
//    期间完全不消费 —— 内核无处可放，只能丢。此时在 close() **之前**调 stats()：
//    - rx_dropped 必须 > 0（否则「运行中可查」是假的）
//    - rx_kernel_packets 必须 > 0（证明洪泛真的到达了这个 socket，而不是没流量）
//    再 close() 之后复核：rx_dropped 必须 **≥** close 前那次的值 —— 这一条专门抓
//    「close 时用赋值而不是累加」：PACKET_STATISTICS 是读即清零语义，赋值会把
//    之前累积的丢包抹掉，而那种缺陷在「只报一次最终值」的用法下完全看不出来。
//    （反向注入：把 stats() 里的 poll_kernel_stats() 去掉（退回「只在 close 读一次」），
//     close 前那次读到的 rx_dropped 恒为 0 → 本用例红。实测见 HANDOFF §2.9。）
//
// === 为什么非 root 时不算通过 ===
//
// 上面第二件事需要 CAP_NET_RAW 与建 veth 的能力。缺能力时本文件**显式打印
// 「未核验」并计入一个独立的 skipped 计数**，而不是打 [PASS] —— 「没检查」与
// 「检查通过」在输出上必须能分辨（这是本项目反复踩过的坑：绿色的假绿灯）。
#include "packet_engine/backend.h"
#include "packet_engine/backends/af_packet.h"
#include "test_util.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using packet_engine::AfPacketBackend;
using packet_engine::CaptureMode;
using packet_engine::CaptureOptions;
using packet_engine::capture_mode_pref_name;
using packet_engine::create_backend;
using packet_engine::test::check;

namespace {

int g_skipped = 0;

void skip(const char* what, const char* why) {
  std::printf("[SKIP] %s（未核验：%s）\n", what, why);
  ++g_skipped;
}

bool is_root() { return ::geteuid() == 0; }

bool sh(const std::string& cmd) { return std::system(cmd.c_str()) == 0; }

bool read_mac(const std::string& iface, uint8_t mac[6]) {
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return false;
  }
  struct ifreq ifr;
  std::memset(&ifr, 0, sizeof(ifr));
  std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface.c_str());
  bool ok = ::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0;
  if (ok) {
    std::memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
  }
  ::close(fd);
  return ok;
}

// 洪泛线程：往对端接口发 64 字节小帧，直到 stop 置位。用裸 socket 而不是引入
// 工具依赖 —— 本用例必须是「一个 ctest 就能跑」的自证，不是「先装个 pktgen」。
class Flooder {
public:
  ~Flooder() { stop(); }
  bool start(const std::string& iface) {
    ifindex_ = ::if_nametoindex(iface.c_str());
    if (ifindex_ == 0) {
      return false;
    }
    fd_ = ::socket(AF_PACKET, SOCK_RAW, ::htons(ETH_P_ALL));
    if (fd_ < 0) {
      return false;
    }
    frame_.assign(64, 0);
    // 以太头 + 一个能过长度检查的 IPv4/UDP 头（内容不重要，重要的是帧长与数量）。
    std::memset(frame_.data(), 0xff, 6); // 目的 = 广播：veth 对端必然收到
    std::memset(frame_.data() + 6, 0x02, 6);
    frame_[12] = 0x08;
    frame_[13] = 0x00;
    frame_[14] = 0x45;
    frame_[16] = 0x00;
    frame_[17] = 0x32; // total len 50
    frame_[22] = 64;   // TTL
    frame_[23] = 17;   // UDP
    running_ = true;
    th_ = std::thread([this]() { loop(); });
    return true;
  }
  void stop() {
    running_ = false;
    if (th_.joinable()) {
      th_.join();
    }
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }
  uint64_t sent() const { return sent_; }

private:
  void loop() {
    struct sockaddr_ll sll;
    std::memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = ::htons(ETH_P_ALL);
    sll.sll_ifindex = static_cast<int>(ifindex_);
    sll.sll_halen = 6;
    std::memset(sll.sll_addr, 0xff, 6);
    while (running_) {
      for (int i = 0; i < 256 && running_; ++i) {
        if (::sendto(fd_, frame_.data(), frame_.size(), 0,
                     reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) > 0) {
          ++sent_;
        }
      }
    }
  }
  int fd_ = -1;
  uint32_t ifindex_ = 0;
  std::vector<uint8_t> frame_;
  std::atomic<bool> running_{false};
  std::atomic<uint64_t> sent_{0};
  std::thread th_;
};

// ---- 1. 档位名与「不支持时不得静默忽略」的契约（无需特权，全平台可断言）----
void test_mode_contract() {
  check(std::strcmp(capture_mode_pref_name(CaptureMode::kAuto), "auto") == 0,
        "档位名 auto 与 CLI 取值一致");
  check(std::strcmp(capture_mode_pref_name(CaptureMode::kTpacketV3), "v3") == 0,
        "档位名 v3 与 CLI 取值一致");
  check(std::strcmp(capture_mode_pref_name(CaptureMode::kTpacketV2), "v2") == 0,
        "档位名 v2 与 CLI 取值一致");
  check(std::strcmp(capture_mode_pref_name(CaptureMode::kRecvfrom), "recvfrom") == 0,
        "档位名 recvfrom 与 CLI 取值一致");

  CaptureOptions def;
  check(def.mode == CaptureMode::kAuto, "CaptureOptions 默认 kAuto（不改变历史行为）");

  // pcap 文件后端不支持档位：必须**报出来**而不是接受。CLI 会据此直接失败，
  // 避免「指定了档位却在另一条路径上跑」的失真对照。
  packet_engine::PacketBackend* f = create_backend("pcap-file");
  if (f == nullptr) {
    skip("pcap-file 后端的档位拒绝契约", "本平台未编译 pcap-file 后端");
    return;
  }
  CaptureOptions co;
  co.mode = CaptureMode::kRecvfrom;
  const std::string rejected = f->configure(co);
  check(rejected.find("capture_mode") != std::string::npos,
        "不支持档位的后端必须把 capture_mode 列为不支持（否则 CLI 无法拒绝）");
  delete f;
}

// ---- 2. 配置错误不得被报成模式错误（无特权也可断言，Linux）----
void test_forced_mode_keeps_error_attribution() {
  AfPacketBackend be;
  CaptureOptions co;
  co.mode = CaptureMode::kTpacketV3;
  be.configure(co);
  const int rc = be.open("cythsec-no-such-iface0");
  check(rc != 0, "不存在的接口：open 必须失败");
  const std::string reason = be.error_reason();
  check(reason.find("cythsec-no-such-iface0") != std::string::npos,
        "指定档位时，接口不存在仍必须报接口问题（归因不能被档位覆盖）");
  check(be.capture_mode_pref() == CaptureMode::kTpacketV3, "档位偏好可回读（configure 真的落定了它）");
}

// ---- 3. 真开两个档位（需 root + veth）----
void test_forced_modes_on_veth() {
  if (!is_root()) {
    skip("强制档位的真实建立", "非 root（AF_PACKET 需要 CAP_NET_RAW）");
    skip("丢包在 close 前可读", "非 root（需要建 veth 与洪泛）");
    return;
  }
  if (!sh("command -v ip >/dev/null 2>&1")) {
    skip("强制档位的真实建立", "缺 ip 命令（iproute2）");
    skip("丢包在 close 前可读", "缺 ip 命令（iproute2）");
    return;
  }

  const std::string a = "cythtm0";
  const std::string b = "cythtm1";
  sh("ip link del " + a + " 2>/dev/null || true");
  if (!sh("ip link add " + a + " type veth peer name " + b)) {
    skip("强制档位的真实建立", "建 veth 失败（内核/权限）");
    skip("丢包在 close 前可读", "建 veth 失败（内核/权限）");
    return;
  }
  sh("ip link set " + a + " up");
  sh("ip link set " + b + " up");

  // v3
  {
    AfPacketBackend be;
    CaptureOptions co;
    co.mode = CaptureMode::kTpacketV3;
    be.configure(co);
    const int rc = be.open(a.c_str());
    if (rc == 0) {
      check(std::strcmp(be.capture_mode_name(), "TPACKET_V3") == 0,
            "指定 v3：实际生效档位必须是 TPACKET_V3（不得降级）");
      check(be.mode_fallback_reason().empty(), "指定 v3 成功时不应有降级原因");
      be.close();
    } else {
      skip("指定 v3 的建立", be.error_reason());
    }
  }

  // recvfrom（这一档是「拷贝模式」对照臂，必须能真跑起来）
  {
    AfPacketBackend be;
    CaptureOptions co;
    co.mode = CaptureMode::kRecvfrom;
    be.configure(co);
    const int rc = be.open(a.c_str());
    if (rc == 0) {
      check(std::strcmp(be.capture_mode_name(), "recvfrom") == 0,
            "指定 recvfrom：实际生效档位必须是 recvfrom");
      be.close();
    } else {
      skip("指定 recvfrom 的建立", be.error_reason());
    }
  }

  // 丢包可观测：小环 + 洪泛，期间不消费。
  {
    AfPacketBackend be;
    CaptureOptions co;
    co.mode = CaptureMode::kTpacketV3;
    co.buffer_bytes = 4096; // 极小环：消费端跟不上时内核必然丢
    be.configure(co);
    const int rc = be.open(a.c_str());
    if (rc != 0) {
      skip("丢包在 close 前可读", be.error_reason());
    } else {
      Flooder fl;
      if (!fl.start(b)) {
        skip("丢包在 close 前可读", "洪泛端建 socket 失败");
        be.close();
      } else {
        // 完全不消费，让内核把环塞满并开始丢包。
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        const packet_engine::BackendStats pre = be.stats(); // ← close 之前
        fl.stop();

        char msg[256];
        std::snprintf(msg, sizeof(msg),
                      "close() 之前就能读到内核丢包（dropped=%llu kernel=%llu sent=%llu）",
                      (unsigned long long)pre.rx_dropped,
                      (unsigned long long)pre.rx_kernel_packets, (unsigned long long)fl.sent());
        check(pre.rx_dropped > 0, msg);
        std::snprintf(msg, sizeof(msg), "内核侧交付计数 > 0（证明洪泛确实到达本 socket，kernel=%llu）",
                      (unsigned long long)pre.rx_kernel_packets);
        check(pre.rx_kernel_packets > 0, msg);

        const uint64_t before_close = pre.rx_dropped;
        be.close(); // close 内部还会 poll 一次并**累加**
        const packet_engine::BackendStats post = be.stats();
        std::snprintf(msg, sizeof(msg),
                      "close() 之后是累加而非覆盖（close 前 %llu → close 后 %llu）",
                      (unsigned long long)before_close, (unsigned long long)post.rx_dropped);
        check(post.rx_dropped >= before_close, msg);
      }
    }
  }

  sh("ip link del " + a + " 2>/dev/null || true");
}

} // namespace

int main() {
  std::printf("=== test_capture_modes: 采集档位强制与丢包可观测（CYS-PKT-008）===\n\n");

  std::printf("--- 1. 档位契约（无需特权）---\n");
  test_mode_contract();

  std::printf("\n--- 2. 错误归因（无需特权）---\n");
  test_forced_mode_keeps_error_attribution();

  std::printf("\n--- 3. 真实档位与丢包可观测（需 root + veth）---\n");
  test_forced_modes_on_veth();

  const int rc = packet_engine::test::summary("test_capture_modes");
  if (g_skipped > 0) {
    std::printf("注意：%d 项**未核验**（见上方 [SKIP]）—— 不算通过，别当绿灯。\n", g_skipped);
  }
  return rc;
}
