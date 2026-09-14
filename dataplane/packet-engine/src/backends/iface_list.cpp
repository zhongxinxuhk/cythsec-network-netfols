// backends/iface_list.cpp - 网络接口枚举实现（POSIX getifaddrs）。
//
// 平台差异集中在此文件的三个位置，其余逻辑共用：
//   1. MAC 获取：Linux 用 ioctl(SIOCGIFHWADDR)；macOS 无此 ioctl，需从 getifaddrs
//      返回的 AF_LINK 条目（sockaddr_dl）里取。
//   2. socket_dl 相关头文件仅 macOS 存在（net/if_dl.h）。
//   3. MTU 获取两边都是 ioctl(SIOCGIFMTU)，但 macOS 需显式包含 sys/sockio.h。
//
// 本模块**不使用任何特权系统调用**（无 socket(AF_PACKET)、无 /dev/bpf），
// 故可在普通用户下运行 —— 这使「先看看本机有什么接口」成为排障的第一步，
// 而不是撞到权限墙之后才开始猜。
#include "packet_engine/backends/iface_list.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <net/if_dl.h> // sockaddr_dl（AF_LINK）
#include <sys/sockio.h> // SIOCGIFMTU
#else
#include <linux/sockios.h> // SIOCGIFHWADDR / SIOCGIFMTU
#include <cstring>
#endif

#include <algorithm>
#include <cstdio>
#include <map>

namespace packet_engine {

namespace {

// 失败原因用字面量常量而非动态串：静态存储期，无分配、无竞态，
// 与 backend.cpp 的 create_backend_error() 保持同一模式。
constexpr const char* kOk = "ok";
constexpr const char* kErrGetifaddrs = "getifaddrs 失败（系统调用返回错误）";
constexpr const char* kErrSocket = "无法创建诊断 socket（ioctl 需要）";

const char* g_error = kOk;

// 从 netmask 字节序列数出前缀长度。用于把 sockaddr 形式的掩码转成 CIDR 的 /N。
uint8_t prefix_len_from_mask(const uint8_t* m, size_t n) {
  uint8_t bits = 0;
  for (size_t i = 0; i < n; ++i) {
    uint8_t b = m[i];
    while (b != 0) {
      bits += static_cast<uint8_t>(b & 0x01u);
      b >>= 1;
    }
  }
  return bits;
}

std::string format_mac(const uint8_t* p, size_t n) {
  char buf[64];
  int off = 0;
  for (size_t i = 0; i < n && off < static_cast<int>(sizeof(buf)) - 4; ++i) {
    off += std::snprintf(buf + off, sizeof(buf) - static_cast<size_t>(off), i ? ":%02x" : "%02x",
                         p[i]);
  }
  return std::string(buf);
}

// 识别「平台返回的占位值」而非真实链路层地址。
//
// 平台事实（本机实测）：macOS 对未授权进程隐藏真实 MAC —— getifaddrs 的 AF_LINK
// 与 sysctl(NET_RT_IFLIST) **两条路径都返回同一个占位值 02:00:00:00:00:00**，
// 且全部 27 个接口完全一致；而同一时刻 `ifconfig en0` 显示真实地址 ce:f7:49:1c:28:6b。
// 该 SDK 亦不提供 SIOCGIFLLADDR（已核对 sys/sockio.h，只有 SIOCGIFMAC —— 那是 MAC
// 强制访问控制框架，与 MAC 地址无关），故应用层无标准途径取得真值。
//
// 为什么必须识别而不能原样上报：02 开头是**合法的「本地管理单播」地址**，
// 这个占位值读起来与真 MAC 毫无区别。一个看起来合理的错值比一个空值危险得多 ——
// 排障者会据此相信「地址已读到」，进而排除掉本应怀疑的网络层问题。
//
// 注意本函数只判「是否是占位值」，**不含空串**：空串有两种成因（接口本就无链路层
// 地址 / 平台隐藏），需要调用方结合上下文分别处理，不能在这里一概而论。
bool is_placeholder_mac(const std::string& mac) {
  return mac == "02:00:00:00:00:00" || mac == "00:00:00:00:00:00";
}

std::string format_ip(const struct sockaddr* sa) {
  char buf[INET6_ADDRSTRLEN] = {0};
  if (sa->sa_family == AF_INET) {
    const auto* sin = reinterpret_cast<const struct sockaddr_in*>(sa);
    if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) == nullptr) {
      return std::string();
    }
    return std::string(buf);
  }
  if (sa->sa_family == AF_INET6) {
    const auto* sin6 = reinterpret_cast<const struct sockaddr_in6*>(sa);
    if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) == nullptr) {
      return std::string();
    }
    return std::string(buf);
  }
  return std::string();
}

// 用一个 AF_INET/SOCK_DGRAM socket 做 ioctl。该 socket 不绑定、不发送，
// 也不需要任何特权 —— 仅作为 ioctl 的载体。
int open_diag_socket() {
  return ::socket(AF_INET, SOCK_DGRAM, 0);
}

void fill_mtu(int fd, IfaceInfo* info) {
  if (fd < 0) {
    return;
  }
  struct ifreq req;
  // 越界写入 ifr_name 是 UB（IFNAMSIZ=16）。接口名不可能超长，但不做此检查
  // 就意味着依赖「不可能」这个假设，而它恰恰是缓冲区溢出的经典来源。
  if (info->name.size() >= sizeof(req.ifr_name)) {
    return;
  }
  std::snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", info->name.c_str());
  if (::ioctl(fd, SIOCGIFMTU, &req) == 0) {
    info->mtu = static_cast<uint32_t>(req.ifr_mtu);
  }
}

#if !defined(__APPLE__)
void fill_mac_linux(int fd, IfaceInfo* info) {
  if (fd < 0 || info->name.size() >= IFNAMSIZ) {
    return;
  }
  struct ifreq req;
  std::snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", info->name.c_str());
  if (::ioctl(fd, SIOCGIFHWADDR, &req) == 0) {
    const std::string v =
        format_mac(reinterpret_cast<const uint8_t*>(req.ifr_hwaddr.sa_data), 6);
    // Linux 不对普通进程隐藏链路层地址，故此处不会出现「隐藏」情形。占位值只
    // 出现在 lo 一类接口上（内核给的 hwaddr 全 0），那是「本就没有以太网地址」
    // 这个事实本身，不置 mac_hidden —— 否则会把系统正常行为报成异常。
    if (!is_placeholder_mac(v)) {
      info->mac = v;
    }
  }
}
#endif

} // namespace

std::vector<IfaceInfo> list_interfaces() {
  g_error = kOk;

  struct ifaddrs* head = nullptr;
  if (::getifaddrs(&head) != 0) {
    g_error = kErrGetifaddrs;
    return {};
  }

  // 以接口名为键聚合：getifaddrs 一个接口会返回多条记录（每个地址一条），
  // 而调用方要的是「一个接口一条信息」。
  std::map<std::string, IfaceInfo> by_name;

  for (struct ifaddrs* it = head; it != nullptr; it = it->ifa_next) {
    if (it->ifa_name == nullptr) {
      continue;
    }
    IfaceInfo& info = by_name[it->ifa_name];
    if (info.name.empty()) {
      info.name = it->ifa_name;
      info.flags = it->ifa_flags;
      info.up = (it->ifa_flags & IFF_UP) != 0;
      info.running = (it->ifa_flags & IFF_RUNNING) != 0;
      info.loopback = (it->ifa_flags & IFF_LOOPBACK) != 0;
    }

    if (it->ifa_addr == nullptr) {
      continue;
    }

    const int fam = it->ifa_addr->sa_family;
    if (fam == AF_INET || fam == AF_INET6) {
      IfaceAddr a;
      a.address = format_ip(it->ifa_addr);
      a.is_ipv6 = (fam == AF_INET6);
      if (a.address.empty()) {
        continue;
      }
      if (it->ifa_netmask != nullptr) {
        if (fam == AF_INET) {
          const auto* m = reinterpret_cast<const struct sockaddr_in*>(it->ifa_netmask);
          a.prefix_len = prefix_len_from_mask(reinterpret_cast<const uint8_t*>(&m->sin_addr), 4);
        } else {
          const auto* m = reinterpret_cast<const struct sockaddr_in6*>(it->ifa_netmask);
          a.prefix_len = prefix_len_from_mask(reinterpret_cast<const uint8_t*>(&m->sin6_addr), 16);
        }
      }
      info.addrs.push_back(a);
    }
#if defined(__APPLE__)
    else if (fam == AF_LINK) {
      // macOS 的链路层地址只在 AF_LINK 记录里，且长度可变（sdl_alen）。
      const auto* sdl = reinterpret_cast<const struct sockaddr_dl*>(it->ifa_addr);
      const int alen = sdl->sdl_alen;
      if (alen > 0 && alen <= 16) {
        const uint8_t* mac = reinterpret_cast<const uint8_t*>(LLADDR(sdl));
        const std::string v = format_mac(mac, static_cast<size_t>(alen));
        if (is_placeholder_mac(v)) {
          // 系统未给真值：留空并标记为「被隐藏」，理由见 is_placeholder_mac。
          // 不保留 02:00:... 是因为它与真 MAC 无法区分；只留空则是把「为什么空」
          // 这个信息丢掉了。两者都要避免，故用独立标志承载原因。
          info.mac.clear();
          info.mac_hidden = true;
        } else {
          info.mac = v;
        }
      }
    }
#endif
  }

  ::freeifaddrs(head);

  // 第二遍：补 index 与 MTU（以及 Linux 的 MAC）。
  // 单独一遍是必要的：getifaddrs 不提供 ifindex，须由 if_nametoindex 查询；
  // 而 ioctl 需要一个已填充好名字的 ifreq。
  const int fd = open_diag_socket();
  if (fd < 0) {
    g_error = kErrSocket;
    // 继续：index 仍可查，仅 MTU 缺失。宁可给出部分信息也不整体失败。
  }

  std::vector<IfaceInfo> out;
  out.reserve(by_name.size());
  for (auto& kv : by_name) {
    IfaceInfo& info = kv.second;
    info.index = ::if_nametoindex(info.name.c_str());
    fill_mtu(fd, &info);
#if !defined(__APPLE__)
    if (info.mac.empty()) {
      fill_mac_linux(fd, &info);
    }
#endif
    out.push_back(info);
  }

  if (fd >= 0) {
    ::close(fd);
  }

  // 按 index 升序。getifaddrs 的返回顺序不保证稳定，而稳定顺序对测试断言与
  // 人工比对都必要（否则 --list-ifaces 每次输出顺序可能不同）。
  std::sort(out.begin(), out.end(), [](const IfaceInfo& a, const IfaceInfo& b) {
    if (a.index != b.index) {
      return a.index < b.index;
    }
    return a.name < b.name;
  });
  return out;
}

const char* list_interfaces_error() {
  return g_error;
}

bool find_interface_by_name(const char* name, IfaceInfo* out) {
  if (name == nullptr || out == nullptr || *name == '\0') {
    return false;
  }
  for (const IfaceInfo& i : list_interfaces()) {
    if (i.name == name) {
      *out = i;
      return true;
    }
  }
  return false;
}

bool find_interface_by_index(uint32_t index, IfaceInfo* out) {
  if (out == nullptr || index == 0) {
    return false;
  }
  for (const IfaceInfo& i : list_interfaces()) {
    if (i.index == index) {
      *out = i;
      return true;
    }
  }
  return false;
}

std::string format_iface_line(const IfaceInfo& iface) {
  std::string flags;
  auto add = [&flags](const char* f) {
    if (!flags.empty()) {
      flags.push_back(',');
    }
    flags += f;
  };
  if (iface.up) {
    add("UP");
  }
  if (iface.running) {
    add("RUNNING");
  }
  if (iface.loopback) {
    add("LOOPBACK");
  }
  if (flags.empty()) {
    flags = "DOWN";
  }

  std::string addrs;
  for (const IfaceAddr& a : iface.addrs) {
    if (!addrs.empty()) {
      addrs += " ";
    }
    addrs += a.address + "/" + std::to_string(a.prefix_len);
  }
  if (addrs.empty()) {
    addrs = "-";
  }

  // mac 列有三种取值，刻意都用 ASCII 以保持 %-17s 的列对齐（中文字符的显示宽度
  // 与字节数不等，会让这一列错位）：
  //   aa:bb:cc:dd:ee:ff  正常读到
  //   hidden             存在但平台隐藏（见 IfaceInfo::mac_hidden）
  //   -                  该接口本就没有链路层地址（lo/utun 等）
  // 「hidden」与「-」必须可区分：前者要 sudo 或换途径，后者是正常状态。
  const char* mac_col = "-";
  if (!iface.mac.empty()) {
    mac_col = iface.mac.c_str();
  } else if (iface.mac_hidden) {
    mac_col = "hidden";
  }

  char buf[512];
  std::snprintf(buf, sizeof(buf), "%-16s idx=%-4u mac=%-17s mtu=%-6u %-16s %s", iface.name.c_str(),
                iface.index, mac_col, iface.mtu, flags.c_str(), addrs.c_str());
  return std::string(buf);
}

} // namespace packet_engine
