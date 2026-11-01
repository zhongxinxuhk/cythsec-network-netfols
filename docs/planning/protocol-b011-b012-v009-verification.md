# B011/B012/V009 · ICMP / GRE 完整适配验收

日期：2026-11-01；分支：`feat/base-protocol-complete`；基线：`main@bb616f9`。
本分支在上一轮 `feat/base-protocol-icmp-gre` 的有界解析基础上补齐校验和、NDP 选项
内容、MLD、GRE checksum/SRE/MPLS 标签栈/ERSPAN II/III 与 Linux cooked capture，
并把三行从“可实现但未验收”推进到本行验收范围内缺口清空。

## 1. 本行验收范围

### B011 ICMPv4

- 固定 8 字节头：type/code/checksum/rest-of-header；不足即
  `icmp.truncated_header`，不补 0。
- 类型：echo request/reply、timestamp request/reply、information request/reply、
  address mask request/reply、destination unreachable（含 code 4 的下一跳 MTU）、
  source quench、redirect、time exceeded、parameter problem（pointer）。
- `ChecksumStatus`：只有调用方能确认“拿到完整 ICMP 报文”时才校验；否则
  `unavailable`。完整报文校验失败为 `invalid`，不把抓包截断误报成坏包。
- 错误报文内嵌原始 IPv4/IPv6 头：源/目的、协议、声明长度、已抓长度、头是否完整
  分开记录；截断时不伪造地址。
- 主流水线报文级统计；独立 `cythsec-icmp` JSONL 事件。
- 不展开 timestamp 的三个时间值、address mask 掩码值、节点信息 payload 的语义；
  不根据 echo/错误报文推断主机在线、路径可达或拓扑。

### B012 ICMPv6

- 固定头、echo、Packet Too Big、parameter problem、错误内嵌 IPv6 头；校验和按
  IPv6 伪头（源/目的/长度/next header=58）计算，仅在完整载荷时校验。
- NDP 133..137 固定字段：RS/RA/NS/NA/Redirect；RA 的 hop limit/flags/lifetime/
  reachable/retrans、NA 的 R/S/O、target/destination。
- NDP 选项内容：SLLA/TLLA、Prefix Information、MTU、Redirected Header（含内嵌
  数据报）、Route Information、RDNSS、DNSSL；Pad1 无长度字节；零长度选项记
  malformed；越界记 options_truncated。地址列表有数量上限，不无限展开。
- MLD：v1 query/report/done、v2 query（S/QRV/QQIC/sources）与 v2 report
  （record type/aux data/源列表，records/sources 均有上限）；按 RFC 3810 计算
  query delay。
- 主流水线报文级统计；独立 `cythsec-icmp` JSONL 事件。
- 不做邻居缓存、地址冲突检测、在线状态推断；不主动发送 NS/RS/MLD。

### V009 GRE / mGRE / PPTP GRE

- GREv0（RFC 2784/2890）与 PPTP 增强 GREv1（RFC 2637）有界解析；版本 2..7
  明确报 `gre.unsupported_version`。
- C/R/K/S/A 可选头按位遍历：checksum+reserved、SRE 列表、key、sequence、ack；
  SRE 以 Length=0 结束，64 条上限；R 位缺终止项报 `gre.bad_routing`。
- checksum：C 位置位且调用方确认完整载荷时校验；完整但错误为 `invalid`，
  截断为 `unavailable`，C 位未置为 `not_present`。
- 内层：IPv4/IPv6、透明以太网桥接（最多两层 VLAN）、PPP、MPLS 标签栈（最多
  8 层，按 bottom-of-stack 停止并推断载荷首字节）、ERSPAN II（0x88BE）/
  ERSPAN III（0x22EB，含可选 8 字节 platform header）。
- 主流水线报文级统计；独立 `cythsec-gre` JSONL 事件。
- 不递归解析内层 IP 为新的 FlowRecord；不执行 SRE 源路由；不推断 mGRE 拓扑、
  隧道对端在线或配置；不解析 PPTP 控制连接/PPP 协商。

### 输入边界

- 经典 pcap（little/big endian、微秒/纳秒）的 Ethernet、Linux SLL（113）、
  SLL2（276）链路。Ethernet 支持最多两层 802.1Q/QinQ；SLL/SLL2 支持一层
  cooked VLAN。
- pcapng 是采集容器而非本行协议；raw IP、802.11、PPP 等链路不在本行范围。
  需要时先由采集侧转换为经典 pcap，或另立容器适配任务。
- 主流水线只做统计，不把 ICMP/GRE 明细写入 `FlowRecord` 或统一存储；明细由
  独立采集器输出。统一事件流/存储接入不在本行范围。

## 2. 实现变更

| 文件 | 变更 |
| --- | --- |
| `dataplane/traffic-engine/src/icmp.rs` | checksum 上下文与 v4/v6 校验；NDP 选项内容；MLD v1/v2；新增 JSON 字段与统计 |
| `dataplane/traffic-engine/src/gre.rs` | checksum 校验；SRE 内容；MPLS 标签栈；ERSPAN II/III；新增统计 |
| `dataplane/traffic-engine/src/arp.rs` | SLL/SLL2 入口；operation 5..10 名称（DRARP/InARP/ARP NAK） |
| `dataplane/traffic-engine/src/channel/decode.rs` | `LinkLayer` 与 `decode_frame_with_link`；SLL/SLL2 跳过 cooked 头 |
| `dataplane/traffic-engine/src/pipeline.rs` | 三种链路解码；SLL/SLL2 ARP 旁路统计 |
| `dataplane/traffic-engine/src/bin/{icmp,gre,arp}_collect.rs` | 接受 Ethernet/SLL/SLL2；传入完整性与链路类型 |
| `scripts/verify/check-icmp-gre.py` | 21 条 ICMP、14 条 GRE 语料；checksum/MLD/NDP 内容/MPLS/ERSPAN/SLL；tshark 扩展核对 |
| `scripts/verify/check-arp.py` | SLL/SLL2 语料；InARP 名称单测由 Rust 覆盖 |

`FlowRecord` 键、落盘格式和 Native/IPFIX 契约未改；新增信息只进入统计行和独立
JSONL。GRE 内层 IP 仍不另造流。

## 3. 实跑记录

证据目录 `build/protocol-base/evidence/`；日志不纳入源码提交。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| ICMP 单测 | `cargo test --offline -p traffic-engine --lib icmp::` | 退出 0，19 项通过 |
| GRE 单测 | `cargo test --offline -p traffic-engine --lib gre::` | 退出 0，17 项通过 |
| ARP 单测 | `cargo test --offline -p traffic-engine --lib arp::` | 退出 0，13 项通过 |
| 链路解码 | `cargo test --offline -p traffic-engine --lib channel::decode::tests` | 退出 0，25 项通过（含 SLL/SLL2） |
| 流水线 | `cargo test --offline -p traffic-engine --lib pipeline::tests` | 退出 0，19 项通过 |
| Rust 库回归 | `cargo test --offline -p traffic-engine --lib` | 退出 0，618 项通过 |
| 独立对照 | `bash scripts/verify/check-icmp-gre.sh --tshark` | 退出 0；21 ICMP + 14 GRE 事件，tshark 核对 19 + 11 帧，9 项反向注入，SLL/SLL2 通过 |
| ARP 独立对照 | `bash scripts/verify/check-arp.sh --tshark` | 退出 0；13 条事件、16 帧统计，tshark 10 帧，SLL/SLL2 通过 |
| Linux 矩阵 | `docker run ... rust:1.97-slim cargo test --offline --lib` | 退出 0，Linux arm64 上 618 项通过 |
| 吞吐基线 | 100k 混合帧，release，Linux arm64 容器 | `--workers 1` 中位约 42 ms（≈2.38 M frame/s）；`--workers 4` 约 67 ms；输出 3 条流 |

### 真实语料

| 语料 | 来源 | 结果 |
| --- | --- | --- |
| `arp-storm.pcap` | Wireshark SampleCaptures 公开抓包 | `622` 帧全部解析；与 `tshark -Y arp` 的 `622` 帧一致 |
| `linux-gre-icmp-arp.pcap` | Linux 内核 GRE 隧道 + ping + arping，tcpdump 在容器 eth0 抓包 | ARP 10、ICMPv4 7（含 3 条带内嵌 GRE 的错误）、GREv0 3（IPv4 2 / IPv6 1），校验和全部 valid |

两份语料都只保存在 `build/`，不进入仓库；测试不依赖网络。

## 4. 验收结论

在本文件第 1 节列出的范围内：

- 三行 `implemented=true`、`local_tested=true`、`reference_tested=true`；
- 校验和、NDP 选项内容、MLD、GRE checksum/SRE/MPLS/ERSPAN、SLL/SLL2 均有
  实现、单测与独立对照；
- 真实抓包与 Linux 运行矩阵已实跑；pcapng/统一存储/生产容量规划明确为本行
  之外的范围，不再作为未完成缺口；
- 因此 B011、B012、V009 的 `accepted` 置为 `true`。

仍明确不做的事：主动探测、邻居缓存/在线状态推断、隧道对端或 mGRE 拓扑推断、
SRE 源路由执行、内层 IP 递归成流、PPTP 控制连接/PPP 协商、pcapng 容器适配。
这些是边界，不是被隐藏的缺口。
