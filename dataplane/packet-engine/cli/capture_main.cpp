// capture_main.cpp - cythsec-capture：跨平台实时抓包 CLI。
//
// === 用法 ===
//   cythsec-capture --list-ifaces              列出本机接口（无需特权）
//   cythsec-capture --list-backends            列出本平台可用的后端
//   cythsec-capture -i <接口> [-n <N>] [-t <秒>] [-w <out.pcap>]
//
// === 这个工具存在的意义：把跨平台差异关在后端里 ===
// 同一份命令在 macOS（en0，BPF）与 Ubuntu/Rocky/openEuler（ens33/eth0/ens192，
// AF_PACKET）上都能跑：接口名由用户给定（或经 --list-ifaces 查得），后端由
// `-b live` 按平台自动路由。**本文件不含任何平台条件编译** —— 若哪天需要加
// `#ifdef __APPLE__`，那说明差异该下沉到后端而不是上浮到工具层。
//
// === 机器可读输出（供 scripts/verify/e2e-live-capture.sh 抓取，格式稳定不要改）===
// 每类记录有**唯一的二级标签**（backend / iface / mode / stats / pcap / result /
// ifaces / backends）：
// 同一格式内复用同名键会让「取最后一次匹配」的抓取方式静默取到另一条记录的值
// —— 这个坑在本项目的 e2e 里实际踩过（见 scripts/verify/e2e-shared-ring.sh 注释）。
//   capture ifaces count=<n> mac_hidden=<n>          （--list-ifaces）
//   capture backends list=<名字,逗号分隔> platform=<linux|bsd|unknown>  （--list-backends）
//   capture backend name=<名字> platform=<linux|bsd|unknown>
//   capture iface name=<名字> index=<n> link=<可读名> link_value=<n>
//   capture mode value=<recvfrom|tpacket_v2|tpacket_v3|bpf> fallback=<原因或 ->
//   capture stats packets=<n> bytes=<n> dropped=<n> errors=<n> duration_ms=<n>
//   capture pcap path=<路径> written=<n>
//   capture result status=<ok|skipped|failed> reason=<原因或 ->
//
// **两个 list 模式不输出 capture result**：那行是「一次抓包尝试」的结论，而查询
// 没有任何采集动作。若查询也报 status=ok，按 `capture result` 抓取的 e2e 会在
// 「没抓包」的情况下读到成功。
//
// === 退出码 ===
//   0 成功            2 用法错误        3 后端创建失败
//   4 打开失败        5 运行期错误      6 落盘失败
//   7 时限内未收到任何包（断言未达成）
//
// 注意退出码 4 与 status=skipped 的组合：**无特权时本工具如实以非 0 退出**
// （它确实失败了），同时输出 status=skipped 让 e2e 能把它归类为「环境不支持」
// 而非「代码有 bug」。把权限不足伪装成 0 才是真正有害的做法。
#include "packet_engine/backend.h"
#include "packet_engine/backends/iface_list.h"
#include "packet_engine/backends/link_type.h"
#include "packet_engine/pcap_writer.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using packet_engine::BackendStats;
using packet_engine::PacketBackend;
using packet_engine::PacketBuffer;

namespace {

constexpr uint32_t kDefaultCount = 0;       // 0 = 不限
constexpr uint32_t kDefaultTimeoutSec = 10; // 默认总时限
constexpr uint32_t kDefaultSnaplen = 2048;
constexpr uint32_t kMaxBurst = 256;

struct Options {
  bool list_ifaces = false;
  bool list_backends = false;
  std::string iface;
  std::string backend = "live";
  uint64_t count = kDefaultCount;
  uint64_t timeout_sec = kDefaultTimeoutSec;
  std::string write_path;
  uint32_t snaplen = kDefaultSnaplen;
  uint32_t buffer_bytes = 0; // 0 = 后端默认
  bool promisc = false;
  bool ignore_outgoing = false;
  bool no_fallback = false;
  uint32_t retire_ms = 0; // 0 = 后端默认
  packet_engine::CaptureMode capture_mode = packet_engine::CaptureMode::kAuto; // 采集模式偏好
  uint32_t stats_every_ms = 0;                   // >0 = 运行中每隔这么多毫秒报一次计数
  bool quiet = false;
  bool verbose = false;
};

void usage() {
  std::fprintf(stderr,
               "用法:\n"
               "  cythsec-capture --list-ifaces             列出本机网络接口（无需特权）\n"
               "  cythsec-capture --list-backends            列出本平台可用的后端\n"
               "  cythsec-capture -i <接口> [选项]           从接口实时抓包\n"
               "\n"
               "选项:\n"
               "  -i, --iface <名字|ifindex:N>  接口名（如 en0 / ens33 / eth0）或索引\n"
               "  -b, --backend <名字>          后端，默认 live（按平台自动路由）\n"
               "  -n, --count <N>               收到 N 个包后退出（0=不限，默认 %u）\n"
               "  -t, --timeout <秒>            总时限（默认 %u）\n"
               "  -w, --write <file.pcap>       落盘为经典 pcap（纳秒精度，Wireshark 可直接打开）\n"
               "  -s, --snaplen <N>             截取长度（默认 %u）\n"
               "      --buffer <字节>            环/读缓冲大小（0=后端默认）\n"
               "      --promisc                  混杂模式\n"
               "      --ignore-outgoing          不看本机发出的包（仅 af-packet，需 Linux>=4.20）\n"
               "      --retire-ms <N>            V3 块退休超时毫秒（仅 af-packet）\n"
               "      --no-fallback              禁止降级（仅 af-packet：要求必须跑在 V3）\n"
               "      --capture-mode <档位>      指定采集档位：auto(默认) | v3 | v2 | recvfrom\n"
               "                                 **指定即严格**：只试该档，失败就报错，不降级。\n"
               "                                 用于「mmap 环 vs 拷贝模式」这类对照（仅 af-packet）。\n"
               "      --stats-every <毫秒>       运行中每隔这么久输出一行实时计数（含内核丢包）\n"
               "                                 （与 -q 并用时仍然输出：那是显式要求）\n"
               "  -q, --quiet                    只输出机器可读汇总行\n"
               "  -v, --verbose                  逐包输出一行\n"
               "  -h, --help                     显示本帮助\n"
               "\n"
               "退出码: 0 成功 / 2 用法 / 3 后端创建失败 / 4 打开失败 / 5 运行期错误\n"
               "        6 落盘失败 / 7 时限内未收到任何包\n",
               kDefaultCount, kDefaultTimeoutSec, kDefaultSnaplen);
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

bool parse_args(int argc, char** argv, Options* o) {
  for (int i = 1; i < argc; ++i) {
    const char* a = argv[i];
    // 需要取值的选项统一在此处理，避免每个分支各自重复下标越界检查。
    auto need_value = [&](const char** dst) -> bool {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "错误: %s 需要一个取值\n", a);
        return false;
      }
      *dst = argv[++i];
      return true;
    };

    if (std::strcmp(a, "--list-ifaces") == 0) {
      o->list_ifaces = true;
    } else if (std::strcmp(a, "--list-backends") == 0) {
      o->list_backends = true;
    } else if (std::strcmp(a, "-i") == 0 || std::strcmp(a, "--iface") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      o->iface = v;
    } else if (std::strcmp(a, "-b") == 0 || std::strcmp(a, "--backend") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      o->backend = v;
    } else if (std::strcmp(a, "-n") == 0 || std::strcmp(a, "--count") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      if (!parse_u64(v, &o->count)) {
        std::fprintf(stderr, "错误: --count 取值非法: %s\n", v);
        return false;
      }
    } else if (std::strcmp(a, "-t") == 0 || std::strcmp(a, "--timeout") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      if (!parse_u64(v, &o->timeout_sec)) {
        std::fprintf(stderr, "错误: --timeout 取值非法: %s\n", v);
        return false;
      }
    } else if (std::strcmp(a, "-w") == 0 || std::strcmp(a, "--write") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      o->write_path = v;
    } else if (std::strcmp(a, "-s") == 0 || std::strcmp(a, "--snaplen") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      uint64_t n = 0;
      if (!parse_u64(v, &n)) {
        std::fprintf(stderr, "错误: --snaplen 取值非法: %s\n", v);
        return false;
      }
      o->snaplen = static_cast<uint32_t>(n);
    } else if (std::strcmp(a, "--buffer") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      uint64_t n = 0;
      if (!parse_u64(v, &n)) {
        std::fprintf(stderr, "错误: --buffer 取值非法: %s\n", v);
        return false;
      }
      o->buffer_bytes = static_cast<uint32_t>(n);
    } else if (std::strcmp(a, "--retire-ms") == 0) {
      const char* v = nullptr;
      if (!need_value(&v))
        return false;
      uint64_t n = 0;
      if (!parse_u64(v, &n)) {
        std::fprintf(stderr, "错误: --retire-ms 取值非法: %s\n", v);
        return false;
      }
      o->retire_ms = static_cast<uint32_t>(n);
    } else if (std::strcmp(a, "--promisc") == 0) {
      o->promisc = true;
    } else if (std::strcmp(a, "--ignore-outgoing") == 0) {
      o->ignore_outgoing = true;
    } else if (std::strcmp(a, "--capture-mode") == 0) {
      const char* v = nullptr;
      if (!need_value(&v)) {
        return false;
      }
      if (std::strcmp(v, "auto") == 0) {
        o->capture_mode = packet_engine::CaptureMode::kAuto;
      } else if (std::strcmp(v, "v3") == 0) {
        o->capture_mode = packet_engine::CaptureMode::kTpacketV3;
      } else if (std::strcmp(v, "v2") == 0) {
        o->capture_mode = packet_engine::CaptureMode::kTpacketV2;
      } else if (std::strcmp(v, "recvfrom") == 0) {
        o->capture_mode = packet_engine::CaptureMode::kRecvfrom;
      } else {
        std::fprintf(stderr, "错误: --capture-mode 取值非法: \"%s\"（可选 auto/v3/v2/recvfrom）\n", v);
        return false;
      }
    } else if (std::strcmp(a, "--stats-every") == 0) {
      const char* v = nullptr;
      if (!need_value(&v)) {
        return false;
      }
      uint64_t ms = 0;
      if (!parse_u64(v, &ms) || ms == 0 || ms > 3600000u) {
        std::fprintf(stderr, "错误: --stats-every 需要 1..3600000 毫秒，得到 \"%s\"\n", v);
        return false;
      }
      o->stats_every_ms = static_cast<uint32_t>(ms);
    } else if (std::strcmp(a, "--no-fallback") == 0) {
      o->no_fallback = true;
    } else if (std::strcmp(a, "-q") == 0 || std::strcmp(a, "--quiet") == 0) {
      o->quiet = true;
    } else if (std::strcmp(a, "-v") == 0 || std::strcmp(a, "--verbose") == 0) {
      o->verbose = true;
    } else if (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0) {
      usage();
      std::exit(0);
    } else {
      std::fprintf(stderr, "错误: 未知参数 %s\n", a);
      return false;
    }
  }
  return true;
}

// 本平台标签。**单一实现**：--list-backends 的机器可读行与捕获时的 backend 记录
// 都要用它。此前这段逻辑内联在 print_backend_line 里，加第二个调用点时会自然
// 被复制一份 —— 本项目已经因为「同一逻辑两份副本、只改一处」吃过一次亏
// （前端版本号注入链路），故此处直接抽成函数。
const char* platform_tag() {
  const char* n = packet_engine::available_backends_joined();
  if (std::strstr(n, "af-packet") != nullptr) {
    return "linux";
  }
  if (std::strstr(n, "bpf") != nullptr) {
    return "bsd";
  }
  return "unknown";
}

// 输出机器可读的 backend 记录。
void print_backend_line(const char* name) {
  std::printf("capture backend name=%s platform=%s\n", name, platform_tag());
}

void print_result(const char* status, const std::string& reason) {
  std::printf("capture result status=%s reason=%s\n", status,
              reason.empty() ? "-" : reason.c_str());
}

int do_list_ifaces() {
  std::vector<packet_engine::IfaceInfo> ifs = packet_engine::list_interfaces();
  if (ifs.empty()) {
    // 区分「失败」与「本机真没接口」：后者在现实中不存在，故空必为失败。
    std::fprintf(stderr, "枚举接口失败: %s\n", packet_engine::list_interfaces_error());
    print_result("failed", std::string("枚举接口失败: ") + packet_engine::list_interfaces_error());
    return 5;
  }

  size_t hidden = 0;
  for (const auto& it : ifs) {
    if (it.mac_hidden) {
      ++hidden;
    }
  }
  // 本模式**不输出 capture result**：那是「一次抓包尝试」的结论行，而这里只是
  // 查询，没有任何采集动作。早期版本两个 list 模式都带了这行，e2e 按
  // `capture result` 抓取时会在查询模式下拿到 status=ok 而实际一个包都没抓 —— 同一
  // 格式里语义不同的记录必须用不同标签，这条在本项目的 e2e 里已经踩过一次。
  std::printf("capture ifaces count=%zu mac_hidden=%zu\n", ifs.size(), hidden);

  std::printf("接口数: %zu\n\n", ifs.size());
  for (const auto& it : ifs) {
    std::printf("  %s\n", packet_engine::format_iface_line(it).c_str());
  }

  if (hidden > 0) {
    // 如实解释「为什么这一列是 hidden」而不是让读者对着一片 hidden 猜。
    // 这类信息只有枚举层知道成因，工具层不解释就再没有地方会解释。
    std::printf("\n注意: %zu 个接口的链路层地址显示为 hidden —— 地址存在，但本平台\n"
                "      对未授权进程隐藏了真值（macOS 会为所有接口返回同一个占位值\n"
                "      02:00:00:00:00:00，与真实地址无法区分，故不显示）。\n"
                "      需要真值请用 `ifconfig <接口> | grep ether` 或提升权限运行。\n"
                "      显示 `-` 的接口则是本就没有以太网地址（lo0 / utun* 等）。\n",
                hidden);
  }
  return 0;
}

int do_list_backends() {
  std::printf("capture backends list=%s platform=%s\n", packet_engine::available_backends_joined(),
              platform_tag());
  std::printf("本平台可用后端: %s\n", packet_engine::available_backends_joined());
  // 路由目标由后端层给出，不从列表下标猜（曾因 names[1] 打印出
  // 「live 会按平台自动路由到 live」）。空串表示本平台根本没有实时后端。
  const char* native = packet_engine::native_live_backend_name();
  if (*native == '\0') {
    std::printf("（本平台无实时抓包后端，仅能读离线 pcap 文件）\n");
  } else {
    std::printf("（live 会按平台自动路由到 %s）\n", native);
  }
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  Options opt;
  if (!parse_args(argc, argv, &opt)) {
    usage();
    return 2;
  }
  if (opt.list_ifaces) {
    return do_list_ifaces();
  }
  if (opt.list_backends) {
    return do_list_backends();
  }
  if (opt.iface.empty()) {
    std::fprintf(stderr, "错误: 需要 -i <接口>（或 --list-ifaces 查看本机接口）\n");
    usage();
    return 2;
  }

  print_backend_line(opt.backend.c_str());

  // ---- 创建后端 ----
  PacketBackend* be = packet_engine::create_backend(opt.backend.c_str());
  if (be == nullptr) {
    std::fprintf(stderr, "创建后端失败: %s\n", packet_engine::create_backend_error());
    print_result("failed", packet_engine::create_backend_error());
    return 3;
  }

  // ---- 打开前配置 ----
  // 全部经 PacketBackend 的虚接口，**不做 dynamic_cast 到具体类型**。类型名随
  // 平台不同（af-packet 只在 Linux 编译进来），一旦在此做类型判断，平台分支就
  // 会立刻上浮到工具层 —— 那正是本文件开头声明的「不该发生的事」。
  // configure() 返回**本后端不支持的项**清单：不静默忽略设置，因为「用户要了
  // 混杂模式却跑在非混杂下」会让人以为抓不到某些包是网络问题。
  {
    packet_engine::CaptureOptions co;
    co.promisc = opt.promisc;
    co.ignore_outgoing = opt.ignore_outgoing;
    co.allow_fallback = !opt.no_fallback;
    co.buffer_bytes = opt.buffer_bytes;
    co.retire_ms = opt.retire_ms;
    co.snap_len = opt.snaplen;
    co.mode = opt.capture_mode;
    const std::string rejected = be->configure(co);
    if (!rejected.empty()) {
      // 显式指定了采集档位却不被支持时**必须失败**，不能只警告。
      //
      // 理由：--capture-mode 的唯一用途是「确证跑在某条路径上」。若本后端不支持它
      // 却继续跑，用户会拿着另一个后端的数字当成 mmap 环的数字 —— 对照实验的关键
      // 前提（两档真的是两条路径）被悄悄破坏，而屏幕上只有一行容易被忽略的警告。
      if (opt.capture_mode != packet_engine::CaptureMode::kAuto &&
          rejected.find("capture_mode") != std::string::npos) {
        std::fprintf(stderr, "错误: 后端 \"%s\" 不支持 --capture-mode %s：%s\n", opt.backend.c_str(),
                     packet_engine::capture_mode_pref_name(opt.capture_mode), rejected.c_str());
        print_result("failed", "capture_mode 不被所选后端支持");
        delete be;
        return 2;
      }
      std::fprintf(stderr, "警告: %s\n", rejected.c_str());
      if (!opt.quiet) {
        std::printf("参数警告     : %s\n", rejected.c_str());
      }
    }
  }

  if (!opt.quiet) {
    std::printf("后端         : %s\n", opt.backend.c_str());
    std::printf("接口         : %s\n", opt.iface.c_str());
  }

  // ---- 打开 ----
  if (be->open(opt.iface.c_str()) != 0) {
    const char* reason = be->error_reason();
    // 区分「环境不足」与「代码出错」：前者对 e2e 是 skipped（无特权时本机就是
    // 跑不了），后者必须是 failed。混为一谈会让权限问题长期伪装成测试通过。
    const bool privileged = be->error_is_permission();
    std::fprintf(stderr, "打开失败: %s\n", reason);
    print_result(privileged ? "skipped" : "failed",
                 privileged ? std::string("缺少特权: ") + reason : reason);
    delete be;
    return 4;
  }

  // ---- 记录接口与链路信息 ----
  const uint32_t ifindex = be->bound_ifindex();
  const uint32_t link = be->bound_link_type();
  {
    const std::string lname = packet_engine::link_type_name(link);
    std::printf("capture iface name=%s index=%u link=%s link_value=%u\n", opt.iface.c_str(),
                ifindex, lname.c_str(), link);
  }
  {
    // 如实上报本条采集路径与降级原因：只报「成功」而不报路径，降级就无法归因
    // —— tpacket_v3 因内核不支持退到 recvfrom 时，性能差异是数量级的。
    const char* mode = be->capture_mode_name();
    const char* fb = be->fallback_reason();
    std::printf("capture mode value=%s fallback=%s\n", mode, (fb && *fb) ? fb : "-");
    if (!opt.quiet) {
      std::printf("采集模式     : %s\n", mode);
      if (fb && *fb) {
        std::printf("降级原因     : %s\n", fb);
      }
    }
  }

  // ---- 落盘 ----
  packet_engine::PcapWriter writer;
  if (!opt.write_path.empty()) {
    // linktype 一律按以太网写：当前后端在 lo/无线接口上可能给出 NULL/80211，
    // 那些类型写到文件里读侧不支持。此时如实报错而非写出一个读不回的文件。
    if (!writer.open(opt.write_path.c_str(), 1, opt.snaplen)) {
      std::fprintf(stderr, "无法创建 pcap: %s\n", writer.error_reason());
      print_result("failed", writer.error_reason());
      delete be;
      return 6;
    }
  }

  // ---- 抓包主循环 ----
  const auto t0 = std::chrono::steady_clock::now();
  const auto deadline = t0 + std::chrono::seconds(opt.timeout_sec);
  std::vector<PacketBuffer*> bufs(kMaxBurst, nullptr);
  uint64_t packets = 0;
  uint64_t bytes = 0;
  bool write_failed = false;
  bool rx_failed = false;

  auto last_stats = t0;
  while (true) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      break;
    }
    // 运行中实时计数（显式要求才开）。丢包在**抓包进行中**往往才是关键信息：
    // 等到进程结束才报，长跑的场景里已经来不及了。
    if (opt.stats_every_ms > 0) {
      const auto since = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats).count();
      if (since >= static_cast<long long>(opt.stats_every_ms)) {
        last_stats = now;
        const auto el = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
        const BackendStats cur = be->stats(); // 现场向内核要一份（PACKET_STATISTICS）
        std::printf("capture stats-now packets=%llu bytes=%llu dropped=%llu kernel=%llu "
                    "errors=%llu duration_ms=%lld\n",
                    (unsigned long long)packets, (unsigned long long)bytes,
                    (unsigned long long)cur.rx_dropped,
                    (unsigned long long)cur.rx_kernel_packets,
                    (unsigned long long)cur.rx_errors, (long long)el);
        std::fflush(stdout);
      }
    }
    if (opt.count != 0 && packets >= opt.count) {
      break;
    }
    const auto remain_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();

    const int n = be->rx_burst(bufs.data(), static_cast<uint32_t>(bufs.size()));
    if (n < 0) {
      std::fprintf(stderr, "收包错误: %s\n", be->error_reason());
      rx_failed = true;
      break;
    }
    if (n == 0) {
      // 无数据：交给后端等待。各后端等待能力不同，见 PacketBackend::wait_readable
      // 的说明 —— 统一到这里，CLI 不需要知道自己跑在哪个后端上。
      const uint32_t slice =
          static_cast<uint32_t>(remain_ms < 50 ? (remain_ms < 0 ? 0 : remain_ms) : 50);
      const int w = be->wait_readable(slice);
      if (w < 0) {
        std::fprintf(stderr, "等待失败: %s\n", be->error_reason());
        rx_failed = true;
        break;
      }
      continue;
    }

    for (int i = 0; i < n; ++i) {
      const PacketBuffer* pb = bufs[static_cast<size_t>(i)];
      ++packets;
      bytes += pb->wirelen;
      if (opt.verbose) {
        std::printf("  #%llu caplen=%u wirelen=%u ifindex=%u ts=%lld ns\n",
                    (unsigned long long)packets, pb->caplen, pb->wirelen, pb->ifindex,
                    (long long)pb->timestamp_ns);
      }
      if (writer.is_open() && !writer.write(*pb)) {
        std::fprintf(stderr, "写入 pcap 失败: %s\n", writer.error_reason());
        write_failed = true;
        break;
      }
    }
    if (write_failed) {
      break;
    }
  }

  const auto t1 = std::chrono::steady_clock::now();
  const auto dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

  // 注意：这里必须在 close() **之前**取，否则 last poll 之后的计数拿不到；
  // close() 内部还会再 poll 一次并累加，所以两条路的合计都不丢。
  const BackendStats st = be->stats();
  std::printf("capture stats packets=%llu bytes=%llu dropped=%llu kernel=%llu errors=%llu "
              "duration_ms=%lld\n",
              (unsigned long long)packets, (unsigned long long)bytes,
              (unsigned long long)st.rx_dropped, (unsigned long long)st.rx_kernel_packets,
              (unsigned long long)st.rx_errors, (long long)dur_ms);

  if (writer.is_open()) {
    const bool closed_ok = writer.close();
    std::printf("capture pcap path=%s written=%llu\n", opt.write_path.c_str(),
                (unsigned long long)writer.written());
    if (!closed_ok && !write_failed) {
      std::fprintf(stderr, "关闭 pcap 失败: %s\n", writer.error_reason());
      write_failed = true;
    }
  }

  delete be;

  if (write_failed) {
    print_result("failed", writer.error_reason());
    return 6;
  }
  if (rx_failed) {
    print_result("failed", "运行期收包错误");
    return 5;
  }

  if (!opt.quiet) {
    std::printf("\n===== 抓包摘要 =====\n");
    std::printf("报文数       : %llu\n", (unsigned long long)packets);
    std::printf("线上字节     : %llu\n", (unsigned long long)bytes);
    std::printf("耗时         : %lld ms\n", (long long)dur_ms);
    if (!opt.write_path.empty()) {
      std::printf("已写出       : %s\n", opt.write_path.c_str());
    }
  }

  if (packets == 0) {
    // 时限内一个包都没收到。对「本机确有流量」的场景这属于验证失败，故非 0 退出；
    // 静默返回 0 会让上游把「什么都没抓到」当成「抓包正常」。
    print_result("failed", "时限内未收到任何报文（接口无流量、过滤过严或权限不足导致未真正挂上）");
    return 7;
  }

  print_result("ok", "-");
  return 0;
}
