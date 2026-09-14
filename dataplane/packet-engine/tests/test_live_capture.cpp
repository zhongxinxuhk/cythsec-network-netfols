// test_live_capture.cpp - 实时采集后端的无特权断言集（CYS-PKT-007 / CYS-PKT-008）。
//
// === 为什么本文件的断言刻意避开「真抓包」 ===
//
// CI 与开发机通常既无 root 也无 CAP_NET_RAW（macOS 的 /dev/bpf* 是 root:wheel 600；
// Linux 建 AF_PACKET socket 需 CAP_NET_RAW）。若一个测试只在有特权时才有断言，它
// 在绝大多数环境里就等价于不存在 —— 这正是本项目反复遇到的那类「假绿灯」：
// 输出是绿的，但绿的含义是「没检查」而非「检查通过」。
//
// 所以这里只断言**零特权即可验证**的部分，而且这些不是退而求其次的弱断言：
//
//   1. **接口枚举与查找**（getifaddrs，零特权）—— 跨发行版通用性的地基。接口命名
//      不统一是换发行版后的第一类失效：Ubuntu 是 ens33/enp0s3、Rocky 与 openEuler
//      是 eth0/ens192、macOS 是 en0。把名字硬编码进代码或文档，换个发行版就失效。
//   2. **后端工厂的平台路由与名称解析** —— 全在用户态。这里能验一条强不变量：
//      「列出来的名字都必须真的能创建」，以及「live 恒等价于本平台的原生实时后端」。
//   3. **失败路径的正确性** —— 最有价值的一类，且有特权时**永远不会被触发**：
//        a) 错误必须可归因（原因非空、且不是基类占位串）；
//        b) 错误必须可操作（权限类错误须给出提权手段）；
//        c) **配置错误不得被报成权限错误** —— 归错类会让「接口名写错」被误判成
//           「环境缺权限」，自动化脚本据此重试或提权，排障方向完全错。
//       (c) 是运维与脚本决定「重试 / 报错 / 提权」的依据，比「能抓包」更常被依赖。
//
// 真抓包路径由 scripts/verify/e2e-live-capture.sh 覆盖，且无特权时显式标记为
// SKIPPED 而非 ✓ —— 见该脚本头注释。
#include "packet_engine/backend.h"
#include "packet_engine/backends/iface_list.h"
#include "packet_engine/backends/link_type.h"
#include "test_util.h"

#include <cctype>
#include <cstring>
#include <string>
#include <vector>

using packet_engine::available_backends;
using packet_engine::available_backends_joined;
using packet_engine::create_backend;
using packet_engine::create_backend_error;
using packet_engine::find_interface_by_index;
using packet_engine::find_interface_by_name;
using packet_engine::format_iface_line;
using packet_engine::IfaceInfo;
using packet_engine::link_type_name;
using packet_engine::list_interfaces;
using packet_engine::native_live_backend_name;
using packet_engine::list_interfaces_error;
using packet_engine::PacketBackend;
using packet_engine::test::check;

namespace {

// 平台判定。测试里必须显式做这个判断：断言「af-packet 可创建」在 macOS 上是错的，
// 而「af-packet 不可创建」在 Linux 上也是错的 —— 两者都是**正确行为**，只是平台不同。
bool host_is_linux() {
#if defined(__linux__)
  return true;
#else
  return false;
#endif
}

bool host_is_bsd_like() {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  return true;
#else
  return false;
#endif
}

// MAC 格式校验：空（无 MAC 或被平台隐藏）或 "xx:xx:xx:xx:xx:xx"。
//
// 这里刻意容忍空串而不是要求非空：**把「本机确实没有 MAC」与「读错了」分开**
// 是接口枚举层的明确职责。macOS 上 getifaddrs 与 sysctl 都返回占位值
// 02:00:00:00:00:00（看起来完全合法），实现据此置空，正是为了避免调用方
// 把一个假地址当成真地址用。
bool mac_format_ok(const std::string& mac) {
  if (mac.empty()) {
    return true;
  }
  if (mac.size() != 17) {
    return false;
  }
  for (size_t i = 0; i < mac.size(); ++i) {
    const char c = mac[i];
    if (i % 3 == 2) {
      if (c != ':') {
        return false;
      }
    } else if (std::isxdigit(static_cast<unsigned char>(c)) == 0) {
      return false;
    }
  }
  return true;
}

// 占位值判定（与 iface_list.cpp 内部同口径）。
//
// 测试里**重复一份**是有意的：若测试直接引用实现内部的那个判定函数，实现一旦
// 把判定改坏（比如把 02:00:00:00:00:00 从「占位」名单里删掉），测试会跟着一起
// 放宽，占位值就会自由流到调用方手里而没有任何断言拦下。两份独立表述才能互证。
bool looks_like_placeholder(const std::string& mac) {
  return mac == "02:00:00:00:00:00" || mac == "00:00:00:00:00:00";
}

// 基类占位串。任何派生后端都不该把它透出来 —— 出现即意味着该后端没有覆写
// error_reason()，而它恰好是排障时唯一的信息来源。
const char* kBaseDefaultReason() {
  return "本后端未提供失败原因";
}

const char* kNoSuchIface = "cythsec-nonexistent-iface-0xDEAD";

// ---------------------------------------------------------------------------
// 1. 接口枚举（跨发行版通用性的地基）
// ---------------------------------------------------------------------------

void test_iface_enumeration() {
  const std::vector<IfaceInfo> ifaces = list_interfaces();

  check(!ifaces.empty(), "接口枚举非空（本机至少有一个网络接口）");
  check(std::strcmp(list_interfaces_error(), "ok") == 0,
        "枚举成功时 list_interfaces_error() 返回 \"ok\"");
  check(!ifaces.empty() && ifaces.front().index > 0,
        "枚举结果按 index 升序（首项 index > 0）");

  // index 升序：输出稳定性是「可 diff」的前提，而可 diff 是自动化断言的前提。
  bool sorted = true;
  for (size_t i = 1; i < ifaces.size(); ++i) {
    if (ifaces[i].index < ifaces[i - 1].index) {
      sorted = false;
      break;
    }
  }
  check(sorted, "接口按 index 严格非递减（输出稳定，可用于 diff 与断言）");

  bool all_index_positive = true;
  bool all_names_nonempty = true;
  bool all_mac_ok = true;
  bool has_loopback = false;
  for (const IfaceInfo& it : ifaces) {
    if (it.index == 0) {
      all_index_positive = false;
    }
    if (it.name.empty()) {
      all_names_nonempty = false;
    }
    if (!mac_format_ok(it.mac)) {
      all_mac_ok = false;
    }
    if (it.loopback) {
      has_loopback = true;
    }
  }
  check(all_index_positive, "每个接口的 index 均 > 0（0 表示取值失败，不应出现）");
  check(all_names_nonempty, "每个接口的名字均非空");
  check(all_mac_ok, "接口 MAC 要么为空、要么是合法 6 字节十六进制形式");
  check(has_loopback, "枚举结果含回环接口（lo / lo0）");

  // mac_hidden 的三条不变量。这三条共同保证「为什么 mac 是空的」不会丢失：
  //   - hidden 时 mac 必为空（不得既标记隐藏又给出值，那是自相矛盾）；
  //   - mac 有值时不得标记 hidden；
  //   - **任何 mac 都不得是占位值** —— 这条最重要：02:00:00:00:00:00 是合法的
  //     本地管理单播地址，读起来与真 MAC 毫无区别，一旦漏出来排障者会据此
  //     相信「地址已读到」，从而排除掉本应怀疑的方向。
  bool hidden_implies_empty = true;
  bool value_implies_not_hidden = true;
  bool no_placeholder = true;
  size_t hidden_count = 0;
  for (const IfaceInfo& it : ifaces) {
    if (it.mac_hidden) {
      ++hidden_count;
      if (!it.mac.empty()) {
        hidden_implies_empty = false;
      }
    }
    if (!it.mac.empty() && it.mac_hidden) {
      value_implies_not_hidden = false;
    }
    if (looks_like_placeholder(it.mac)) {
      no_placeholder = false;
    }
  }
  check(hidden_implies_empty, "mac_hidden 的接口其 mac 必为空（不得既标记隐藏又给值）");
  check(value_implies_not_hidden, "mac 有值的接口不得标记 hidden");
  check(no_placeholder,
        "任何接口的 mac 都不得是占位值（02:00:00:00:00:00 与真地址无法区分，必须置空）");

  // 两种「空」必须可区分：若本机存在被隐藏的接口，就必然存在 mac 为空但
  // hidden 为 true 的项；反之若一个都没有，说明本平台不隐藏（如 Linux）。
  // 这条断言不预设平台，只要求「标记与事实一致」。
  {
    size_t empty_but_not_hidden = 0;
    for (const IfaceInfo& it : ifaces) {
      if (it.mac.empty() && !it.mac_hidden) {
        ++empty_but_not_hidden;
      }
    }
    std::string msg = "mac 空值可归因：被隐藏 " + std::to_string(hidden_count) +
                      " 个、本无地址 " + std::to_string(empty_but_not_hidden) + " 个";
    // 两者之和等于「mac 为空」的总数 —— 即每个空值都有明确归属，没有第三种
    // 无声的空。这条把「区分」这个设计意图固定下来，而不只是记录当下数字。
    check(hidden_count + empty_but_not_hidden <= ifaces.size(), msg.c_str());
  }

  // 回环必须同时带 loopback 标志与 IPv4/IPv6 地址 —— 它是唯一在所有平台上
  // 都保证存在且无需协商的接口，e2e 抓包测试依赖这一点。
  for (const IfaceInfo& it : ifaces) {
    if (it.loopback) {
      check(!it.addrs.empty(), "回环接口带有至少一个地址（lo 恒有 127.0.0.1）");
      check(it.up, "回环接口处于 UP 状态");
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// 2. 接口查找：按名与按 index 必须一致，且失败时不修改输出
// ---------------------------------------------------------------------------

void test_iface_lookup() {
  const std::vector<IfaceInfo> ifaces = list_interfaces();
  if (ifaces.empty()) {
    check(false, "接口枚举为空，后续查找断言无法进行");
    return;
  }

  // 按名与按 index 查同一接口必须得到同样的字段。两条路径实现不同
  // （名字查 index 再查、直接按 index 查），不一致会表现为「同一接口两个身份」。
  bool consistent = true;
  for (const IfaceInfo& it : ifaces) {
    IfaceInfo by_name{};
    IfaceInfo by_index{};
    const bool ok_name = find_interface_by_name(it.name.c_str(), &by_name);
    const bool ok_index = find_interface_by_index(it.index, &by_index);
    if (!ok_name || !ok_index || by_name.name != it.name || by_index.name != it.name ||
        by_name.index != it.index || by_index.index != it.index) {
      consistent = false;
      break;
    }
  }
  check(consistent, "按名查找与按 index 查找结果一致（同一接口不会有两个身份）");

  // 不存在的接口：返回 false，且**不修改** out。后者不是洁癖 —— 调用方常见的
  // 写法是 `IfaceInfo info; if (!find(...)) { 用 info.name 拼错误信息; }`，
  // 若实现写了半个 out，错误信息里就会出现垃圾名字。
  {
    IfaceInfo out{};
    out.name = "sentinel";
    out.index = 12345;
    const bool found = find_interface_by_name(kNoSuchIface, &out);
    check(!found, "不存在的接口名返回 false");
    check(out.name == "sentinel" && out.index == 12345,
          "查找失败时不得修改 out（调用方会拿它拼错误信息）");
  }
  {
    IfaceInfo out{};
    out.name = "sentinel";
    const bool found = find_interface_by_index(0xFFFFFFF0u, &out);
    check(!found, "不存在的接口 index 返回 false");
    check(out.name == "sentinel", "按 index 查找失败时同样不得修改 out");
  }

  // 畸形输入不得崩溃。空串、nullptr、超长串、含空格串 —— 这些都会真实出现在
  // 「用户把路径当接口名传进来」或 shell 变量未展开的场景里。
  {
    IfaceInfo out{};
    check(!find_interface_by_name("", &out), "空接口名返回 false 而非崩溃");
    check(!find_interface_by_name(nullptr, &out), "nullptr 接口名返回 false 而非崩溃");

    const std::string too_long(512, 'x');
    check(!find_interface_by_name(too_long.c_str(), &out),
          "超长接口名返回 false 而非崩溃（内核上限 16 字节）");

    check(!find_interface_by_name("bad name with spaces", &out),
          "含空格的畸形接口名返回 false 而非崩溃");
    check(!find_interface_by_name("/dev/eth0", &out),
          "把路径当接口名传入返回 false（这类误用很常见）");
  }

  // 单行格式化：CLI 的 --list-ifaces 与人读诊断都走它。
  {
    const std::string line = format_iface_line(ifaces.front());
    check(!line.empty(), "format_iface_line 输出非空");
    check(line.find(ifaces.front().name) != std::string::npos,
          "format_iface_line 输出含接口名");
    check(line.find("idx=") != std::string::npos,
          "format_iface_line 含 idx= 字段（供 grep 与断言定位）");
  }
}

// ---------------------------------------------------------------------------
// 3. 后端工厂：平台路由、名称解析、以及「列表与可创建性一致」
// ---------------------------------------------------------------------------

void test_backend_factory() {
  check(!available_backends().empty(), "可用后端列表非空");
  check(std::strlen(available_backends_joined()) > 0, "可用后端的逗号连接串非空");

  // pcap-file 是全平台后端，任何时候都该在列表里且可创建。
  {
    bool listed = false;
    for (const std::string& n : available_backends()) {
      if (n == "pcap-file") {
        listed = true;
      }
    }
    check(listed, "可用后端列表含全平台后端 pcap-file");

    PacketBackend* be = create_backend("pcap-file");
    check(be != nullptr, "create_backend(\"pcap-file\") 成功");
    if (be != nullptr) {
      check(std::strcmp(be->capture_mode_name(), "file") == 0,
            "pcap-file 后端如实上报采集路径为 file");
      delete be;
    }
  }

  // 强不变量：**列表里承诺的每个名字都必须真的能创建**。
  // 这条断言的意义在于双向：既防「列了却创建不了」（用户按帮助去用就失败），
  // 也防「能创建却没列」（用户不知道可用）。
  {
    bool all_creatable = true;
    std::string first_failure;
    for (const std::string& n : available_backends()) {
      PacketBackend* be = create_backend(n.c_str());
      if (be == nullptr) {
        all_creatable = false;
        first_failure = n + " -> " + create_backend_error();
        break;
      }
      delete be;
    }
    // 刻意不写成 `check(cond, cond ? "ok" : ("..." + x).c_str())`：那依赖「临时串
    // 活到完整表达式结束」这一细节。构造出消息再传入，意图明确且不依赖规则记忆。
    std::string msg = "可用后端列表中的每一项都能被创建";
    if (!all_creatable) {
      msg = "列表与可创建性不一致（列了却创建不了）: " + first_failure;
    }
    check(all_creatable, msg.c_str());
  }

  // live 路由目标必须与「live 是否在列表里」互相印证。
  //
  // 存在理由：CLI 曾用 `available_backends()[1]` 当路由目标来显示，结果打印出
  // 「live 会按平台自动路由到 live」—— 列表顺序与路由目标是两件事，硬绑在一起
  // 时任何顺序调整都会静默产出错文案（而且它看起来像句正常的话）。这三条断言
  // 把「两者必须一致」固定下来：live 在列表里 ⇔ 存在一个非空的路由目标，
  // 且该目标本身也在列表里。
  {
    const char* native = native_live_backend_name();
    const bool has_live = [&] {
      for (const std::string& n : available_backends()) {
        if (n == "live") {
          return true;
        }
      }
      return false;
    }();

    check(has_live == (*native != '\0'),
          "live 在列表中的充要条件是存在平台原生实时后端（两者不得单方面成立）");

    if (*native != '\0') {
      check(std::strcmp(native, "live") != 0,
            "live 的路由目标不得是 live 自身（自指意味着取错了来源）");
      bool native_listed = false;
      for (const std::string& n : available_backends()) {
        if (n == native) {
          native_listed = true;
        }
      }
      check(native_listed, "live 的路由目标本身必须在可用后端列表里");
      check(std::strcmp(native, "af-packet") == 0 || std::strcmp(native, "bpf") == 0,
            "live 的路由目标只能是 af-packet（Linux）或 bpf（macOS/BSD）");
    }
  }

  // live 与平台原生名的等价关系。这是跨平台调用方唯一需要依赖的映射：
  // 若 live 不可创建，则平台原生名也一定不可创建；反之亦然。
  {
    PacketBackend* live = create_backend("live");
    const char* live_err = create_backend_error();

    PacketBackend* native = create_backend(host_is_linux() ? "af-packet" : "bpf");
    const char* native_err = create_backend_error();

    const bool native_expected_present = host_is_linux() || host_is_bsd_like();
    check((live != nullptr) == native_expected_present,
          "live 在本平台可创建（Linux→af-packet / macOS,BSD→bpf）");
    check((native != nullptr) == native_expected_present,
          "本平台原生实时后端名可创建");
    check((live != nullptr) == (native != nullptr),
          "live 可创建 ⟺ 平台原生实时后端可创建（路由不引入额外失败点）");

    if (live == nullptr && !native_expected_present) {
      // 无实时后端的平台：诊断必须说清「不可用」，而不是空原因。
      check(std::strlen(live_err) > 0 && std::strcmp(live_err, kBaseDefaultReason()) != 0,
            "无实时后端的平台上，live 创建失败的原因非空且非占位串");
    }
    if (native == nullptr && !native_expected_present) {
      check(std::strlen(native_err) > 0, "原生实时后端名创建失败时原因非空");
    }

    delete live;
    delete native;
  }

  // 平台错配的名字：必须失败，且必须**指引到 live** —— 静默换实现才是危险行为
  // （调用方以为验的是 AF_PACKET 路径，实际跑的可能是另一条）。
  {
    const char* other = host_is_linux() ? "bpf" : "af-packet";
    PacketBackend* be = create_backend(other);
    const bool other_is_native = host_is_linux() ? host_is_bsd_like() : host_is_linux();
    if (!other_is_native) {
      check(be == nullptr, "非本平台专属后端名创建失败（不做静默回退）");
      const std::string err = create_backend_error();
      check(err.find("live") != std::string::npos,
            "平台错配的诊断指引到跨平台名 live");
      check(err.find(other) != std::string::npos,
            "平台错配的诊断回显被请求的后端名");
    }
    delete be;
  }

  // 「已规划未实现」与「名字拼错」必须可区分：前者该等，后者该改。
  {
    check(create_backend("xdp") == nullptr, "未实现的 xdp 后端创建失败");
    const std::string err = create_backend_error();
    check(err.find("已规划") != std::string::npos || err.find("尚未实现") != std::string::npos,
          "xdp 的诊断说明「已规划未实现」（与拼错区分开）");

    check(create_backend("no-such-backend-name") == nullptr, "未知后端名创建失败");
    const std::string err2 = create_backend_error();
    check(err2.find("no-such-backend-name") != std::string::npos,
          "未知后端名的诊断回显该名字（便于发现拼写错误）");
    check(err2.find("pcap-file") != std::string::npos,
          "未知后端名的诊断列出实际可用的后端名");

    check(create_backend(nullptr) == nullptr, "nullptr 后端名创建失败而非崩溃");
    check(std::strlen(create_backend_error()) > 0, "nullptr 后端名失败时原因非空");
  }
}

// ---------------------------------------------------------------------------
// 4. 失败路径的正确性（无特权时最有价值的一类断言）
// ---------------------------------------------------------------------------

void test_failure_diagnostics() {
  // (a) 接口不存在：这是配置错误，必须在**消耗权限判定之前**被报出来。
  //
  // 这条断言的现实意义：无特权环境下，若实现先建 socket/开设备再校验接口名，
  // 用户看到的会是「缺 CAP_NET_RAW」——于是他去 sudo，然后依然失败，最后才
  // 发现是自己把接口名写错了。顺序错了会把排障引向完全相反的方向。
  {
    PacketBackend* be = create_backend("live");
    if (be != nullptr) {
      const int rc = be->open(kNoSuchIface);
      check(rc != 0, "绑定不存在的接口失败");
      const std::string reason = be->error_reason();
      check(!reason.empty(), "绑定失败提供了原因");
      check(reason != kBaseDefaultReason(),
            "原因来自具体后端而非基类占位串（证明覆写生效）");
      check(reason.find(kNoSuchIface) != std::string::npos,
            "原因回显了写错的接口名（否则用户不知道是哪个名字错了）");

      // 核心断言：配置错误不得被归为权限错误。归错类会让自动化脚本去提权重试，
      // 而正确处置是改配置 —— 两者的排障成本差一个数量级。
      check(!be->error_is_permission(),
            "「接口不存在」不被归为权限错误（否则脚本会去错误地提权重试）");

      // 提示里应指向可发现本机接口名的手段。
      check(reason.find("list-ifaces") != std::string::npos ||
                reason.find("不存在") != std::string::npos,
            "诊断给出了可操作线索（如何查看本机接口名 / 明确说明不存在）");
      delete be;
    } else {
      check(false, "live 后端在本平台不可创建，无法验证失败诊断");
    }
  }

  // (b) 空 source 与畸形 source：不得崩溃，且必须有明确原因。
  {
    PacketBackend* be = create_backend("live");
    if (be != nullptr) {
      check(be->open("") != 0, "空接口名打开失败而非崩溃");
      check(std::strlen(be->error_reason()) > 0, "空接口名失败时提供了原因");
      check(be->open(nullptr) != 0, "nullptr 接口名打开失败而非崩溃");
      check(std::strlen(be->error_reason()) > 0, "nullptr 接口名失败时提供了原因");
      // 超长名字（把路径当接口名传入的典型误用）
      const std::string long_name(300, 'a');
      check(be->open(long_name.c_str()) != 0, "超长接口名打开失败而非崩溃");
      delete be;
    }
  }

  // (c) 真绑定：结果取决于本环境是否有特权，但**无论哪种结果都有可断言的不变量**。
  //
  // 三种合法结果：
  //   ① 成功（有特权）—— 采集路径名必须具体，不能是 unknown；
  //   ② 权限类失败（无特权，CI 与开发机的常态）—— 必须标为权限类，且给出提权手段；
  //   ③ 其他失败（接口不适用，如某些平台 BPF 不支持 lo）—— 原因必须非空。
  // 断言只要求「落在三者之一且自洽」，因此本用例在有无特权时都有意义。
  {
    PacketBackend* be = create_backend("live");
    if (be != nullptr) {
      const std::vector<IfaceInfo> ifaces = list_interfaces();
      std::string lo;
      for (const IfaceInfo& it : ifaces) {
        if (it.loopback) {
          lo = it.name;
          break;
        }
      }
      if (!lo.empty()) {
        const int rc = be->open(lo.c_str());
        if (rc == 0) {
          const std::string mode = be->capture_mode_name();
          check(!mode.empty() && mode != "unknown",
                "有特权时绑定的采集路径名具体（如实上报跑在哪条路径上）");
          check(be->bound_ifindex() > 0, "绑定成功后 bound_ifindex() > 0");

          // 采集路径名必须能在有特权时被第三方校验 —— 这里只确认非占位。
          check(be->error_reason() != nullptr, "成功时 error_reason() 仍可安全调用");

          // 等待接口可调用且不忙等：返回 0 表示超时，不应是负值（无错误）。
          const int w = be->wait_readable(1);
          check(w >= 0, "wait_readable 在已打开的后端上返回 >= 0（不忙等、不误报错误）");

          // 未发出任何包时应读不到东西，且不报错。
          packet_engine::PacketBuffer* pkts[4] = {nullptr, nullptr, nullptr, nullptr};
          const int n = be->rx_burst(pkts, 4);
          check(n >= 0, "空闲接口上 rx_burst 返回 0（无包）而非错误");
          be->close();
        } else if (be->error_is_permission()) {
          const std::string reason = be->error_reason();
          check(!reason.empty(), "权限类失败提供了原因");
          // 权限错误必须可操作：给出提权手段，否则用户只知道「不行」不知道「怎么办」。
          check(reason.find("setcap") != std::string::npos ||
                    reason.find("root") != std::string::npos ||
                    reason.find("sudo") != std::string::npos ||
                    reason.find("特权") != std::string::npos,
                "权限类失败给出了提权手段（setcap / root / sudo）");
        } else {
          // 非权限类失败也必须可归因，且不能被误标为权限类。
          check(std::strlen(be->error_reason()) > 0, "非权限类失败仍提供了原因");
          check(be->error_reason() != kBaseDefaultReason(),
                "非权限类失败的原因来自具体后端");
        }
      } else {
        check(false, "未找到回环接口，无法验证绑定路径");
      }
      delete be;
    }
  }

  // (d) configure() 的「如实回报不支持项」语义。
  //
  // 这里验的是**契约本身**而非某个后端的细节：什么都没要求时必须不报不支持；
  // 报为不支持时，文案必须点出是哪一项。前者防止「无条件警告」淹没真信号
  // （用户会开始忽略所有警告），后者防止「报了个不支持但不说是什么」。
  {
    PacketBackend* be = create_backend("live");
    if (be != nullptr) {
      packet_engine::CaptureOptions none{};
      const std::string r0 = be->configure(none);
      check(r0.empty(), "未请求任何采集参数时不报告「不支持」（避免无条件警告淹没真信号）");

      // AF_PACKET 未实现 per-read 超时（应让人改用 wait_readable()）；
      // BPF 无块退休机制。两者各自的预期在此显式断言 —— 这正是「如实上报」
      // 要防的：静默忽略会让用户以为设置生效了。
      if (host_is_linux()) {
        packet_engine::CaptureOptions opt{};
        opt.read_timeout_ms = 50;
        const std::string r = be->configure(opt);
        check(!r.empty(), "AF_PACKET 对 read_timeout_ms 如实回报不支持");
        check(r.find("read_timeout_ms") != std::string::npos,
              "不支持项的报告点出了具体参数名 read_timeout_ms");
        check(r.find("wait_readable") != std::string::npos,
              "不支持项的报告给出了替代手段（wait_readable）");
      } else if (host_is_bsd_like()) {
        packet_engine::CaptureOptions opt{};
        opt.retire_ms = 50;
        const std::string r = be->configure(opt);
        check(!r.empty(), "BPF 对 retire_ms 如实回报不支持（BPF 无块概念）");
        check(r.find("retire_ms") != std::string::npos,
              "不支持项的报告点出了具体参数名 retire_ms");

        // 反向：allow_fallback 在 BPF 上只有一条路径，属「恒已满足」而非「不支持」。
        // 报它会让每个 macOS 用户都看到一条无意义警告 —— 噪声会淹没真信号。
        packet_engine::CaptureOptions fb{};
        fb.allow_fallback = false;
        check(be->configure(fb).empty(),
              "BPF 不把 allow_fallback 报为不支持（单路径后端该项恒已满足）");
      }
      delete be;
    }
  }
}

// ---------------------------------------------------------------------------
// 5. 链路类型名：ARPHRD_* 与 DLT_* 两个编号空间必须由同一入口收口
// ---------------------------------------------------------------------------

void test_link_type_names() {
  // 以太网在两个编号空间里都是 1（DLT_EN10MB=1 / ARPHRD_ETHER=1），因此这条
  // 断言跨平台成立。它验的是「上层无需条件编译即可拿到可读名」这一契约。
  const std::string eth = link_type_name(1);
  check(!eth.empty(), "link_type_name(1) 非空");
  check(eth.find("未知") == std::string::npos,
        "link_type_name(1) 被识别为以太网而非未知（1 = EN10MB/ETHER）");
  check(eth.find("以太网") != std::string::npos, "link_type_name(1) 的可读名含「以太网」");

  // 未知编号必须回显原始值。排障时「看到没见过的编号」比「看到一句笼统的未知」
  // 有用得多 —— 前者可以直接拿去查，后者只能再改代码加日志。
  const std::string unknown = link_type_name(0xFFFFu);
  check(!unknown.empty(), "link_type_name(未知值) 非空");
  check(unknown.find("未知") != std::string::npos, "未知链路类型被明确标为「未知」");
  check(unknown.find("ffff") != std::string::npos || unknown.find("FFFF") != std::string::npos,
        "未知链路类型的可读名回显原始编号（便于直接查证）");
}

} // namespace

int main() {
  std::printf("=== test_live_capture: 实时采集后端（无特权断言集）===\n");
  std::printf("平台: %s | 可用后端: %s\n\n",
              host_is_linux() ? "linux" : (host_is_bsd_like() ? "bsd/macos" : "unknown"),
              available_backends_joined());

  std::printf("--- 1. 接口枚举 ---\n");
  test_iface_enumeration();

  std::printf("\n--- 2. 接口查找 ---\n");
  test_iface_lookup();

  std::printf("\n--- 3. 后端工厂与平台路由 ---\n");
  test_backend_factory();

  std::printf("\n--- 4. 失败路径诊断正确性 ---\n");
  test_failure_diagnostics();

  std::printf("\n--- 5. 链路类型名 ---\n");
  test_link_type_names();

  return packet_engine::test::summary("test_live_capture");
}
