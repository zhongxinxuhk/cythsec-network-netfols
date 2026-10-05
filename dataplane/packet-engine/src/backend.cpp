// backend.cpp - 后端工厂（按名称创建，按平台路由）。
//
// === 名称与语义 ===
//   pcap-file  经典 pcap 文件（离线）。全平台可用。
//   live       实时抓包。**按平台自动路由**：Linux → af-packet，macOS/BSD → bpf。
//   af-packet  Linux AF_PACKET（显式指定，不做平台回退）。
//   bpf        macOS/BSD /dev/bpfN（显式指定，不做平台回退）。
//
// === 为什么要有 live 这一层 ===
// 跨平台代码若各自写 `#ifdef __APPLE__` 决定用哪个后端，平台分支就会向上扩散到
// 调用方（CLI、服务、测试）。`live` 把这条分支收敛到本文件一处：调用方只写
// `create_backend("live")`，在三个 Linux 发行版与 macOS 上都是同一份代码。
//
// === 显式名字为何不回退 ===
// 请求 "af-packet" 却拿到 BPF（或反之）是**静默换实现**：调用方以为自己验的是
// AF_PACKET 路径，实际跑的是另一条。故平台不匹配时返回 nullptr 并说明该用哪个名字。
//
// 已知限制：未实现 XDP / AF_XDP / DPDK（见 CYS-PKT-006/009/010）。请求这些名字
// 会得到「已规划但尚未实现」而非「未知后端」——两者对使用者的含义完全不同
// （等 vs 查拼写）。
#include "packet_engine/backend.h"

#include "packet_engine/backends/pcap_file.h"

#include <cstring>
#include <ctime>
#include <string>
#include <vector>

// 平台判定的单一位置。其余文件不做这类判定（link_type 的实现除外，那处由构建
// 系统保证同平台只编译一份）。
#if defined(__linux__)
#define CYTHSEC_HAVE_AF_PACKET 1
#else
#define CYTHSEC_HAVE_AF_PACKET 0
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define CYTHSEC_HAVE_BPF 1
#else
#define CYTHSEC_HAVE_BPF 0
#endif

#if CYTHSEC_HAVE_AF_PACKET
#include "packet_engine/backends/af_packet.h"
#endif
#if CYTHSEC_HAVE_BPF
#include "packet_engine/backends/bpf_capture.h"
#endif

namespace packet_engine {

namespace {

// 错误原因必须比函数调用活得久：用 string 持有，返回其 c_str()。
// 早先用裸 const char* 指向字面量是够的，但平台相关的诊断需要拼平台名，
// 故改为持有 string —— 若仍返回局部临时串的指针，调用方读到的是已释放内存。
std::string g_backend_error = "packet-engine: 暂无可用后端实现";

const char* platform_name() {
#if CYTHSEC_HAVE_AF_PACKET
  return "linux";
#elif CYTHSEC_HAVE_BPF
  return "bsd"; // macOS 与各 BSD 走同一套 /dev/bpfN
#else
  return "unknown";
#endif
}

// 本平台的「实时抓包后端名」。用于 live 路由与诊断文案。
const char* native_live_name() {
#if CYTHSEC_HAVE_AF_PACKET
  return "af-packet";
#elif CYTHSEC_HAVE_BPF
  return "bpf";
#else
  // 无任何实时后端。返回空串而非猜一个名字，避免诊断里出现「请用 xxx」而
  // xxx 其实不存在。
  return "";
#endif
}

} // namespace

PacketBackend* create_backend(const char* name) {
  if (name == nullptr) {
    g_backend_error =
        "packet-engine: 后端名为空（可用: " + std::string(available_backends_joined()) + "）";
    return nullptr;
  }

  if (std::strcmp(name, "pcap-file") == 0) {
    return new PcapFileBackend();
  }

  // live：按平台路由。这是跨平台调用方唯一需要记住的实时后端名。
  if (std::strcmp(name, "live") == 0) {
    const char* native = native_live_name();
    if (*native == '\0') {
      g_backend_error =
          "packet-engine: 本平台既无 AF_PACKET 也无 BPF，实时抓包不可用（可用: pcap-file）";
      return nullptr;
    }
    // 递归调用自身，复用下面两个显式分支 —— 避免在此重复一遍创建逻辑。
    return create_backend(native);
  }

#if CYTHSEC_HAVE_AF_PACKET
  if (std::strcmp(name, "af-packet") == 0) {
    return new AfPacketBackend();
  }
#else
  if (std::strcmp(name, "af-packet") == 0) {
    // 不回退到 BPF：静默换实现会让调用方以为验的是 AF_PACKET 路径。
    g_backend_error = "packet-engine: af-packet 是 Linux 专属后端，当前平台（" +
                      std::string(platform_name()) + "）不支持；跨平台请用 live";
    return nullptr;
  }
#endif

#if CYTHSEC_HAVE_BPF
  if (std::strcmp(name, "bpf") == 0) {
    return new BpfCaptureBackend();
  }
#else
  if (std::strcmp(name, "bpf") == 0) {
    g_backend_error = "packet-engine: bpf 是 macOS/BSD 专属后端，当前平台（" +
                      std::string(platform_name()) + "）不支持；跨平台请用 live";
    return nullptr;
  }
#endif

  // 名字已知但未实现 —— 与「拼错了」区分开。
  static const char* kPlanned[] = {"xdp", "af-xdp", "dpdk", "netmap"};
  for (const char* p : kPlanned) {
    if (std::strcmp(name, p) == 0) {
      g_backend_error = std::string("packet-engine: 后端 ") + name +
                        " 已规划但尚未实现（见 CYS-PKT-006/009/010）";
      return nullptr;
    }
  }

  g_backend_error = std::string("packet-engine: 未知后端名 \"") + name +
                    "\"（本平台可用: " + available_backends_joined() + "）";
  return nullptr;
}

const char* create_backend_error() {
  return g_backend_error.c_str();
}

// 默认等待实现：短暂休眠。
//
// 为什么不是「立即返回 0」：那会让调用方进入忙等，抓包工具忙等就是 100% CPU 占用，
// 远比多 2ms 延迟糟糕。也不会等到 timeout_ms —— 默认实现不代表这个后端真的能
// 等待超时那么久，谎报「等满了」会掩盖实际没有等待能力这一事实。
int PacketBackend::wait_readable(uint32_t timeout_ms) {
  const uint32_t slice_ms = timeout_ms == 0 ? 1u : (timeout_ms < 2u ? timeout_ms : 2u);
  struct timespec ts;
  ts.tv_sec = static_cast<time_t>(slice_ms / 1000u);
  ts.tv_nsec = static_cast<long>(slice_ms % 1000u) * 1000000L;
  ::nanosleep(&ts, nullptr);
  return 0;
}

// 默认配置实现：全部项都不支持。
//
// 为什么默认是「全部拒绝」而不是「尽力应用」：基类无从知道派生后端能做什么，
// 若在此猜测哪些字段该被忽略，派生类忘记覆写时就会有参数被静默丢弃。
// 默认拒绝的前提下，忘记覆写会立刻表现为「参数不被支持」并被调用方打印出来。
std::string PacketBackend::configure(const CaptureOptions& options) {
  // 只报用户真正提出的项，避免把「你没设置过的字段」也列成不支持。
  std::string rejected;
  auto note = [&rejected](const char* name) {
    if (!rejected.empty()) {
      rejected += "、";
    }
    rejected += name;
  };
  if (options.promisc)
    note("promisc");
  if (options.ignore_outgoing)
    note("ignore_outgoing");
  if (!options.allow_fallback)
    note("no_fallback");
  if (options.buffer_bytes != 0)
    note("buffer");
  if (options.retire_ms != 0)
    note("retire_ms");
  if (options.read_timeout_ms != 0)
    note("read_timeout_ms");
  if (options.snap_len != 0)
    note("snap_len");
  // 采集模式偏好同理必须报出来：在 macOS（BPF 后端）上 `--capture-mode v3`
  // 若被静默忽略，用户会以为「我指定了环模式，所以这个数字是 mmap 环的」，
  // 而实际跑的是另一条完全不同的路径 —— 对照实验就此失真。
  if (options.mode != CaptureMode::kAuto)
    note("capture_mode(仅 af-packet 后端支持)");
  if (rejected.empty()) {
    return ""; // 用户什么都没要求，不存在「不支持」的问题
  }
  return "本后端不支持这些采集参数: " + rejected;
}

std::vector<std::string> available_backends() {
  std::vector<std::string> out;
  out.emplace_back("pcap-file");
  // 顺序与帮助文本一致：先跨平台的 live，再平台专属的显式名。
  if (*native_live_name() != '\0') {
    out.emplace_back("live");
  }
#if CYTHSEC_HAVE_AF_PACKET
  out.emplace_back("af-packet");
#endif
#if CYTHSEC_HAVE_BPF
  out.emplace_back("bpf");
#endif
  return out;
}

const char* available_backends_joined() {
  // static thread_local：返回值生命周期需不短于调用方使用期。诊断路径上开销可忽略。
  static thread_local std::string s;
  s.clear();
  for (const std::string& n : available_backends()) {
    if (!s.empty()) {
      s += ", ";
    }
    s += n;
  }
  return s.c_str();
}

const char* native_live_backend_name() {
  return native_live_name();
}

} // namespace packet_engine
