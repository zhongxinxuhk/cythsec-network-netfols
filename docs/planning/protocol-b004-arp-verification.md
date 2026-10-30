# B004 · ARP/RARP 有界解析验收

日期：2026-10-31；基线：`31d1008`；分支：`feat/protocol-b004-arp`。
接基础/补充清单中最早仍未实现的 B004。B008 IP 分片重组不在本分支范围内，继续留给后续。

## 已实现范围

1. 新增零依赖 `dataplane/traffic-engine/src/arp.rs`：解析 Ethernet（含最多两层
   802.1Q/QinQ）上的 ARP/RARP 固定头与地址区。字段包括 HTYPE、PTYPE、HLEN、PLEN、
   OPER、sender/target 硬件地址与协议地址；`EtherType` 同时接受 ARP（0x0806）与
   RARP（0x8035）。
2. 只有 `HTYPE=1 + HLEN=6` 才格式化 MAC，只有 `PTYPE=0x0800 + PLEN=4` 或
   `PTYPE=0x86DD + PLEN=16` 才格式化 IPv4/IPv6。未知硬件/协议类型保留原始十六进制
   字节，**不把任意 6 字节硬件地址叫成 MAC，也不把任意 4 字节协议地址叫成 IPv4**。
3. 识别 `request`（1）、`reply`（2）、`rarp_request`（3）、`rarp_reply`（4）与未知
   operation；RARP 与未知 operation 不因端口/名称相似被归入普通 ARP 请求。
4. `gratuitous` 只对 IPv4 且 sender IP == target IP 且非 `0.0.0.0` 判定；`probe`
   只对 IPv4 请求且 sender IP 为 `0.0.0.0` 判定（RFC 5227）。其他组合为 `null`
   （“判不了”），不是 `false`。
5. 有界与异常：Ethernet 头不足、ARP 固定头不足、按 HLEN/PLEN 算出的地址区不足、
   VLAN 超过两层分别给出稳定错误码；Ethernet 尾部填充（最小 60 字节帧）被忽略；
   广播/单播目标 MAC 只是字段，不据此推断设备行为。
6. 新增独立采集器 `cythsec-arp`：从经典 pcap（仅 Ethernet 链路）输出帧级 JSONL，
   字段顺序固定，未知值为 `null`；输出 `frames`、`arp_frames`、请求/应答/RARP/
   未知 operation、probe、gratuitous、VLAN、未知 HTYPE/PTYPE、malformed、truncated、
   non_arp、capture_truncated 统计。`frame_len` 取 pcap 记录头的 `orig_len`（线上
   长度）；`capture_truncated` 表示 `caplen < orig_len`，两者不能互相冒充。
7. 主流水线 `cythsec-analyze` 在“非 IP 帧”分支旁路解析 ARP，只做帧级统计，**不伪造
   `FlowRecord`**。ARP 没有 IP 五元组；把它塞进流表会与真实 IP 流混在一起。普通
   IPv4/IPv6 解码失败不会被记成坏 ARP；VLAN 层数超限时先扫描标签链确认内层是
   ARP/RARP，避免把超嵌套的 IP 帧误记成 ARP。
8. 不主动发送 ARP、不修改邻居表、不根据 reply 推断主机在线、地址归属、冲突或欺骗。
   本轮只回答“报文结构是什么”。

依据：[RFC 826](https://www.rfc-editor.org/rfc/rfc826.html)、
[RFC 903](https://www.rfc-editor.org/rfc/rfc903.html)、
[RFC 5227](https://www.rfc-editor.org/rfc/rfc5227.html)、
[IEEE 802.1Q](https://standards.ieee.org/ieee/802.1Q/10323/)。

## 实跑记录

证据目录 `build/protocol-b004/`；日志不纳入源码提交。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| ARP 单测 | `cargo test --offline -p traffic-engine --lib arp` | 退出 0，14 项通过（12 项解析/统计 + 2 项流水线） |
| 采集器 + tshark | `bash scripts/verify/check-arp.sh --tshark` | 退出 0；13 条有效 ARP/RARP 事件、16 帧统计；tshark JSON 核对 10 帧的 opcode/MAC/IP/VLAN；3 项反向注入均被检出 |
| FlowRecord 回归 | `bash scripts/test/test-all.sh --flows` | 退出 0；新增 ARP 统计行未破坏既有 tshark/反向注入关口 |
| Rust 库回归 | `cargo test --offline -p traffic-engine --lib` | 退出 0，536 项通过 |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 退出 0；`build/protocol-b004/lint-final.log` / `lint-final.exit`；Python 质量清单 19 个手写文件 |
| 默认完整测试 | `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 退出 0；536 个 Rust lib 测试通过；live 关口 15 项断言通过；ARP 关口在 `--rust` 与默认全集各实跑一次；`build/protocol-b004/test-all-final.log` / `test-all-final.exit` |

语料由 `scripts/verify/check-arp.py` 按 RFC 独立拼字节，不调用 Rust 编码器。
样本覆盖：

- 普通请求/应答、单层 VLAN、QinQ（200/300）、广播请求；
- gratuitous ARP、ARP probe（sender IP 0.0.0.0）、RARP 请求、未知 operation 99；
- IPv6 协议地址（`PTYPE=0x86DD`、`PLEN=16`）、未知 HTYPE 99、未知 PTYPE 0x1234；
- Ethernet 尾部填充、截断 ARP 体、超过两层 VLAN、非 ARP 的 IPv4/UDP 帧；
- pcap `orig_len > caplen` 但 ARP 体完整的 capture-truncated 帧。

主流水线样本断言：13 个有效 ARP 帧 + 1 个截断 + 1 个超 VLAN 层 + 1 个非 ARP；
`arp_frames=13`、`requests=9`、`replies=2`、`malformed=1`、`truncated=1`、
`non_arp=0`（主流水线只对非 IP 帧旁路解析，不像独立采集器那样统计所有非 ARP 帧），
输出仍只有那 1 条 UDP FlowRecord。

## 未完成项（因此 `accepted` 仍为 false）

- **主流水线不持久化 ARP 事件**：只做帧级统计；详细字段由独立采集器输出，尚未接入
  统一事件流、Native/IPFIX 或存储。
- **不解析 NDP**：IPv6 邻居发现属于 ICMPv6（B012）与后续邻居表工作，本分支不把
  ARP 解析强行扩展到 NDP。
- **不做 ARP 缓存/冲突/欺骗推断**：收到 reply 不等于地址在线；gratuitous 也不等于
  地址冲突。没有主动探测、缓存表或安全结论。
- **只支持经典 pcap 的 Ethernet 链路**：Linux cooked capture、raw IP、PCAPNG 未实现；
  VLAN 最多两层，更多层记 malformed。
- **没有真实设备/厂商语料**：当前是 RFC 合成语料；真实网关、负载均衡、虚拟化环境的
  异常填充/厂商扩展未验证。
- **没有 Linux 运行矩阵与长期运行**：采集器只在当前 macOS 环境实跑；跨平台、
  大 pcap 内存/吞吐与长时间运行未验收。

本轮不涉及规避审查的指纹、主动探测、封锁或邻居表改写。
