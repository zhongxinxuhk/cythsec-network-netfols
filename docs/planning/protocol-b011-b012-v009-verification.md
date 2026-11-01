# B011/B012/V009 · ICMP / GRE 基础协议识别验收

日期：2026-11-01；基线：`dfa1e25`；分支：`feat/base-protocol-icmp-gre`。
范围：把最底层的 ICMPv4、ICMPv6、GRE/mGRE 从“协议号分类”补到有界报文解析、
报文级事件与主流水线计数；ARP（B004）已在 `07e9e9c` 单独验收，本轮不改写其结论。

## 已实现范围

### ICMPv4 / ICMPv6（B011/B012）

1. 新增零依赖 `dataplane/traffic-engine/src/icmp.rs`：公共 8 字节头（type/code/
   checksum/rest-of-header）固定要求，不足即 `icmp.truncated_header`，不拿 0 兜底。
2. ICMPv4：echo request/reply、timestamp 系列的 identifier/sequence；目的不可达
   code 4 的下一跳 MTU；参数问题指针；源抑制、重定向、超时。ICMPv6：echo、
   Packet Too Big 的 32 位 MTU、参数问题指针、MLD 常见类型名。
3. 错误报文（v4 type 3/4/5/11/12，v6 type 1..4）解析内嵌原始数据报的 IPv4/IPv6
   头：源/目的、协议、声明总长、已抓长度与“头是否完整”分开记录。抓包截断时
   只写实际读到的字段，不补 `0.0.0.0`/`::`。
4. ICMPv6 NDP（133..137）：Router Solicitation/Advertisement、Neighbor
   Solicitation/Advertisement、Redirect 的固定字段（RA 的 hop limit/flags/lifetime/
   reachable/retrans、NA flags、target/destination），以及选项 Type/Length 列表。
   Pad1 无长度字节；长度为 0 的选项记 malformed；越界记 options_truncated；
   选项内容（前缀、链路层地址）不展开。
5. 新增 `cythsec-icmp`：经典 pcap → 报文级 JSONL，字段顺序固定，未知值 `null`。
   主流水线 `cythsec-analyze` 在 ICMP/ICMPv6 流上做报文级计数（统计行），
   **不增加 `FlowRecord` 键**，避免静默改变落盘/列式契约。
6. 不校验 checksum（抓包截断、校验和卸载与分片都会让校验失败），字段原样保留；
   不根据 echo reply 推断主机在线，不根据错误报文推断路径可达性。

### GRE / mGRE（V009）

1. 新增零依赖 `dataplane/traffic-engine/src/gre.rs`：版本只认 0（RFC 2784/2890）
   与 1（RFC 2637 PPTP 增强 GRE）；2..7 报 `gre.unsupported_version`。
2. GREv0 按位解析 C/R/K/S：checksum+reserved、key、sequence；R 位的 SRE 列表按
   RFC 1701 的“SRE Length=0 为最后一项”遍历，64 条上限，越界报 `gre.bad_routing`。
3. PPTP 增强 GRE：K 必须置位、protocol 必须 0x880B、R/s/Recur/保留位必须为 0；
   Key 的高 16 位是载荷长度、低 16 位是 Call ID；S/A 位扩展 sequence/ack。
4. 内层协议有界标注：IPv4/IPv6（源/目的/协议/声明长度/IHL 或固定 40 字节）、
   透明以太网桥接 0x6558（内层 EtherType 与最多两层 VLAN）、PPP、MPLS、ERSPAN。
   不把内层 IP 拆成第二条流——一个 GRE 包只能证明封装存在，不能证明内层会话。
5. 新增 `cythsec-gre`：经典 pcap → 报文级 JSONL。主流水线只做报文级计数。
6. **“无 key”不推断为 mGRE**：mGRE 是点对多点部署形态，单包没有可判定的拓扑
   标志；输出只有 `key_present=false`。

## 实跑记录

证据目录 `build/protocol-b011-b012-v009/`；日志不纳入源码提交。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| ICMP 单测 | `cargo test --offline -p traffic-engine --lib icmp::` | 退出 0，15 项通过；`rust-icmp.log` / `rust-icmp.exit` |
| GRE 单测 | `cargo test --offline -p traffic-engine --lib gre::` | 退出 0，14 项通过；`rust-gre.log` / `rust-gre.exit` |
| 流水线 ICMP/GRE | `cargo test --offline -p traffic-engine --lib pipeline::tests` | 退出 0，18 项通过（含 3 项新增）；`rust-pipeline.log` / `rust-pipeline.exit` |
| 独立对照 | `bash scripts/verify/check-icmp-gre.sh --tshark` | 退出 0；18 条 ICMP + 11 条 GRE 事件，tshark 核对 16 + 8 帧，6 项反向注入均检出；`check-icmp-gre.log` / `check-icmp-gre.exit` |
| Rust 库回归 | `cargo test --offline -p traffic-engine --lib` | 退出 0，607 项通过；`rust-lib-final.log` / `rust-lib-final.exit` |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 退出 0；`lint-final.log` / `lint-final.exit` |
| 默认完整测试 | `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 退出 0；`test-all-final.log` / `test-all-final.exit`；ICMP/GRE 关口在 `--rust` 与默认全集各实跑一次（后者带 `--tshark`） |

最终门禁（本分支工作树）：

- `bash scripts/lint/lint-all.sh` 退出 0；Python quality 覆盖 20 个手写文件（新增
  `scripts/verify/check-icmp-gre.py`），Ruff/Black/strict mypy 均通过。
- `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` 退出 0；Rust 607 项、
  跨语言 e2e 4 阶段 19 项断言、真实网卡 15 项断言全部通过。live 关口明确标注
  “无注入目标：ICMP 可见项不适用”，未把 SKIPPED 写成通过。

## 语料与独立对照

`scripts/verify/check-icmp-gre.py` 按 RFC 独立拼字节，不调用 Rust 编码器：

- ICMPv4：echo 请求/应答、端口不可达、分片需要（MTU 1400）、超时、参数问题
  （指针 9）、重定向、时间戳、未知类型 42、ICMP 头截断、pcap capture-truncated；
- ICMPv6：echo、Packet Too Big（MTU 1280，内嵌 IPv6 头）、NS（target + SLLA）、
  NA（R/S/O flags + TLLA）、RA（hop limit/flags/lifetime/reachable/retrans + Prefix
  Information）、MLD query、未知类型 200、ICMP 头截断；
- GRE：v0 无 key、key、C+K+S、R + 一条 SRE + 结束标记、TEB（VLAN 100）、MPLS、
  未知 protocol、内层 IPv4 截断；v1 PPTP 基础、S/A、缺 K、版本 2、可选头截断、
  TEB 截断；
- 主流水线：ICMP 18 个包产出 5 条会话（v4 1 + v6 4），GRE 11 个包只产出 2 条
  外层会话（GRE + 非 GRE UDP），证明内层 IP 没有另造流。

tshark 独立核对 ICMP type/code 与 echo identifier/sequence（v4/v6 共 16 帧）、
GRE 版本/protocol/key/sequence/ack 与 PPTP 的 payload length/call id（8 帧）。

## 未完成项（因此 `accepted` 仍为 false）

- **ICMP 不校验 checksum**；时间戳/地址掩码/节点信息等类型的语义不展开。
- **NDP 只解析选项 Type/Length**：Prefix Information、SLLA/TLLA、MTU、RDNSS 等
  内容不解；邻居缓存、地址冲突、在线状态不做推断。
- **GRE 不校验 checksum、不执行 SRE 源路由、不递归解析内层 IP**；ERSPAN 与
  MPLS 只标注协议类型，不展开镜像/标签栈。
- **主流水线不持久化报文级事件**：ICMP/GRE 明细只由独立采集器输出，尚未接入
  统一事件流、Native/IPFIX 或存储。
- **只支持经典 pcap 的 Ethernet 链路**：Linux cooked capture、raw IP、PCAPNG 未实现；
  真实 mGRE/ERSPAN/厂商语料、Linux 运行矩阵、生产吞吐与误报指标未验收。

本轮不涉及规避审查的指纹、主动探测、封锁或隧道配置改写。
