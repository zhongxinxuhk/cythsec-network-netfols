# B004 · ARP/RARP 完整适配验收

日期：2026-11-01；分支：`feat/base-protocol-complete`；基线：`main@bb616f9`。
B004 最初在 `feat/protocol-b004-arp` 完成有界解析；本分支补齐 operation 名称、
Linux cooked capture、真实语料与运行矩阵，并把本行验收范围内的缺口清空。

## 1. 本行验收范围

- Ethernet（最多两层 802.1Q/QinQ）与 Linux cooked capture SLL（113）/SLL2（276）
  上的 ARP/RARP 有界解析。
- HTYPE/PTYPE/HLEN/PLEN/OPER 与发送/目标硬件、协议地址原始字节。
- operation 名称：1 request、2 reply、3 rarp_request、4 rarp_reply、
  5 drarp_request、6 drarp_reply、7 drarp_error、8 inarp_request、
  9 inarp_reply、10 arp_nak；其他值保留数字并输出 `unknown`。
- 只有 `HTYPE=1+HLEN=6` 才格式化 MAC；只有 `PTYPE=0x0800+PLEN=4` 或
  `PTYPE=0x86DD+PLEN=16` 才格式化 IPv4/IPv6。未知组合保留十六进制原始字节，
  绝不把任意 6/4 字节猜成 MAC/IP。
- `gratuitous` 只对 IPv4 且 sender IP == target IP 且非 `0.0.0.0` 判定；
  `probe` 只对 IPv4 请求且 sender IP 为 `0.0.0.0` 判定；其他为 `null`。
- 独立 `cythsec-arp` JSONL 事件；主流水线帧级统计，不把 ARP 写入 `FlowRecord`。
- 不主动探测、不修改邻居表、不推断邻居缓存、地址归属、冲突或欺骗。
- NDP 属于 B012/ICMPv6，不在本行扩展；统一事件流/存储接入不在本行范围；
  pcapng/raw IP/802.11 等容器或链路不在本行范围。

## 2. 实现变更

| 文件 | 变更 |
| --- | --- |
| `dataplane/traffic-engine/src/arp.rs` | SLL/SLL2 入口与协议号读取；operation 5..10 名称 |
| `dataplane/traffic-engine/src/channel/decode.rs` | `LinkLayer` 与 SLL/SLL2 链路头跳过 |
| `dataplane/traffic-engine/src/pipeline.rs` | 三种链路的 ARP 旁路统计 |
| `dataplane/traffic-engine/src/bin/arp_collect.rs` | 接受 Ethernet/SLL/SLL2 |
| `scripts/verify/check-arp.py` | SLL/SLL2 对照语料 |

## 3. 实跑记录

证据目录 `build/protocol-base/evidence/`。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| ARP 单测 | `cargo test --offline -p traffic-engine --lib arp::` | 退出 0，13 项通过 |
| 链路解码 | `cargo test --offline -p traffic-engine --lib channel::decode::tests` | 退出 0，25 项通过 |
| 流水线 | `cargo test --offline -p traffic-engine --lib pipeline::tests` | 退出 0，19 项通过（含 SLL 流水线） |
| 独立对照 | `bash scripts/verify/check-arp.sh --tshark` | 退出 0；13 条事件、16 帧统计、tshark 10 帧、SLL/SLL2、3 项反向注入 |
| Rust 库回归 | `cargo test --offline -p traffic-engine --lib` | 退出 0，618 项通过 |
| Linux 矩阵 | Linux arm64 容器 `cargo test --offline --lib` | 退出 0，618 项通过 |
| 公开真实抓包 | `arp-storm.pcap`（Wireshark SampleCaptures） | 622 帧全部解析，与 `tshark -Y arp` 的 622 帧一致 |
| Linux 真实抓包 | 内核 GRE 隧道 + arping，tcpdump 抓 eth0 | 10 条 ARP（9 请求/1 应答，4 gratuitous） |
| 吞吐基线 | release `cythsec-arp`，100k ARP 事件 | 约 224–229 ms（≈0.44 M 事件/s，JSONL 落盘占主导） |

## 4. 验收结论

在本文件第 1 节列出的范围内，B004 的 `implemented/local_tested/reference_tested`
均为 true，缺口清空，`accepted` 置为 `true`。

仍明确不做：主动探测、邻居缓存/冲突/欺骗推断、NDP、pcapng/raw IP、统一存储。
这些是边界，不是被隐藏的缺口。
