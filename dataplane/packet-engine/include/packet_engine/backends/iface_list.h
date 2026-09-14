// backends/iface_list.h - 网络接口枚举（跨平台，零特权、零第三方依赖）。
//
// 存在理由：**采集后端的第一类故障是「接口名写错」，而接口命名恰恰是各发行版/平台
// 最不统一的地方**：
//   - Ubuntu（netplan/systemd predictable names）：ens33、enp0s3、eno1
//   - Rocky / openEuler（传统或 vSphere 环境）：eth0、ens192、ens224
//   - macOS：en0、en1…（无 Linux 风格的 eth*）
//   - 容器内：eth0（但往往是 veth，混杂模式抓不到宿主流量）
// 把接口名硬编码进代码或文档，必然在换一个发行版后失效。故提供枚举能力，
// 使调用方（CLI、上层服务）能先问「本机有哪些接口」再决定绑哪个。
//
// 实现基于 POSIX getifaddrs(3)：Linux（glibc/musl）与 macOS 均提供，**无需任何特权**
// （对比 /dev/bpf 与 AF_PACKET socket 都需要 CAP_NET_RAW），因此本模块可在无特权
// 环境下作为冒烟与诊断入口。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace packet_engine {

// 接口地址（一个接口可同时有 IPv4 与 IPv6）。
struct IfaceAddr {
  std::string address;    // 点分十进制（IPv4）或 RFC 5952 压缩形式（IPv6）
  uint8_t prefix_len = 0; // 前缀长度（CIDR 中的 /N）
  bool is_ipv6 = false;
};

// 单个网络接口的信息快照。
struct IfaceInfo {
  std::string name;        // 接口名，如 ens33 / eth0 / en0 / lo（可直接传给后端 open()）
  uint32_t index = 0;      // 系统接口索引（Linux if_nametoindex；macOS 由名字查询得到）
  std::string mac;         // 链路层地址，形如 "aa:bb:cc:dd:ee:ff"；无 MAC 或平台隐藏时为空
  // 链路层地址**存在但被平台隐藏**（mac 因此为空），与「该接口本就没有链路层地址」
  // 是两件事，必须分开：
  //   - lo0 / utun* / gif* 等：结构上就没有以太网地址，空值是事实本身；
  //   - macOS 上的 en0 等真实网卡：地址存在，但系统对未授权进程返回占位值
  //     （实测 getifaddrs 的 AF_LINK 与 sysctl(NET_RT_IFLIST) 两条路径
  //     都返回 02:00:00:00:00:00，而 ifconfig 显示真值）。
  // 不区分的话，工具会对着 27 个接口整片显示 `mac=-`，读者无法判断「是枚举实现
  // 坏了」还是「系统不让看」——而这两者的处置方式完全不同（前者要修代码，
  // 后者只能 sudo 或改用别的途径）。故把「为什么空」作为一等信息保留下来。
  bool mac_hidden = false;
  uint32_t mtu = 0;        // MTU（仅 Linux 可经 ioctl 取得；取不到为 0）
  bool up = false;         // IFF_UP：接口已启用
  bool running = false;    // IFF_RUNNING：链路已就绪（网线插好/关联已建立）
  bool loopback = false;   // IFF_LOOPBACK
  uint32_t flags = 0;      // 原始 IFF_* 标志位，供调用方做更细判断
  std::vector<IfaceAddr> addrs;
};

// 枚举本机全部网络接口。按 index 升序排列，保证输出稳定（便于测试与 diff）。
//
// 刻意不提供过滤参数：过滤是调用方的策略（是否隐藏 lo、是否只保留 UP），
// 放在这里会迫使枚举层猜测使用场景，也让「本机到底有什么」这个事实变得不可见。
// 返回空 vector 表示系统调用失败（原因见 list_interfaces_error()）。
std::vector<IfaceInfo> list_interfaces();

// 上一次 list_interfaces() 失败的原因；成功时为固定串 "ok"。
//
// 存在理由：返回空 vector 同时意味着「失败」与「本机真没有接口」两种截然不同的情况，
// 而后者在现实中不存在。若不区分，调用方只能把失败当成「没有接口」上报，
// 排障时看不出真正原因。
const char* list_interfaces_error();

// 按名字查接口。找到返回 true 并填充 out；未找到返回 false（out 不被修改）。
bool find_interface_by_name(const char* name, IfaceInfo* out);

// 按 index 查接口。语义同 find_interface_by_name。
bool find_interface_by_index(uint32_t index, IfaceInfo* out);

// 把 IfaceInfo 格式化为单行可读文本（供 CLI --list-ifaces 与诊断使用）。
// 形如：  en0        idx=4   mac=aa:bb:cc:dd:ee:ff  mtu=1500  UP,RUNNING  172.20.10.2/28
// 无特权也可安全调用。
std::string format_iface_line(const IfaceInfo& iface);

} // namespace packet_engine
