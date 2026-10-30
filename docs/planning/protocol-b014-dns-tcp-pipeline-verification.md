# B014 · DNS/TCP 主流水线重组验收

日期：2026-10-30；基线：`74bb536`；分支：`feat/protocol-b014-dns-tcp-pipeline`；
工作目录 `/Users/xuzhongxin/CLionProjects/CythSec`。

## 背景与本轮范围

B014 此前的验收只覆盖**单包内的 DNS/TCP 长度帧**：一个 TCP 段里恰好放着完整消息。
`备份n2`（`d77eade`）已经把 `pipeline/dns_tcp.rs` 接进主流水线，但清单仍把
"主流水线 TCP 重组"列为缺口。本轮不改解析契约，只做三件事：核对实现、补端到端证据、
把状态写回清单。

范围内：

- 仅 TCP 53（含源/目的端口），SYN 锚定的**有界前缀重组**；无 SYN 的中途接入保留单包弱判定。
- 每个方向一条 `Stream`，按序号把乱序/重传/回绕的段拼成连续前缀；最多 4096 字节前缀、
  64 个数据段、1024 条流、30 秒空闲。
- 只解析**首个** DNS 长度帧：`u16` 长度前缀 + 有界 DNS 字段；完整帧才 `identified`。
- 四态语义：前缀有洞/未到齐 → `need_more`；同一序号两种字节（冲突）、RST 前无帧、
  SYN-ACK 确认号不匹配、序号 epoch 冲突、超过段预算 → `need_more`/显式原因；
  IP 分片未重组 → `need_more`（`dns_tcp.ip_fragment_unassembled`），不猜。
- 不建立全局重组器：只对 DNS 端口做有界前缀，其他协议仍走首包 DPI。
  这是刻意的范围限制 —— 全局 TCP 重组是 `CYS-TRF-016`，不属于 B014。

## 实现要点

`pipeline::observe` 在 TCP 53 上把 TCP 段交给 `DnsTcpStreams::observe`，并用它的结论
直接填充该方向的 probe；其他端口仍走 `dpi::identify_with_ports`。两个必须写下来的决定：

1. **先更新会话/特征，再做 DNS/TCP 判定**。记录里的 `packets`/`bytes`/TCP 统计来自
   会话层，不能被 DPI 的提前返回吞掉。
2. **无锚点不累积字节**。没见 SYN 时只对当前段做一次完整长度帧判定，置信度降为
   `medium`，理由写 `dns_tcp.unanchored_packet_only`；这样既保留历史单包行为，
   又不会把"没看到握手"的流说成已重组。

预算与原因字符串（都可从 `app.rationale` 观察）：
`dns_tcp.awaiting_contiguous_prefix`、`dns_tcp.conflicting_overlap`、
`dns_tcp.closed_with_gap`、`dns_tcp.prefix_budget`、`dns_tcp.segment_budget`、
`dns_tcp.syn_ack_mismatch`、`dns_tcp.syn_epoch_conflict`、`dns_tcp.reset_before_frame`、
`dns_tcp.flow_capacity_packet_only`、`dns_tcp.direction_unanchored_packet_only`。
注意 `AppInfo::from_outcome` 对非 `identified` 结论不保留 `rationale`，因此 CLI 的
`need_more` 记录只表现为 `outcome=need_more`；原因字符串在库内与单测里可见。

## CLI 与输出契约

没有新增子命令。`cythsec-analyze -r x.pcap -o flows.jsonl` 对乱序分片的 DNS 查询/响应
产出同一条会话记录：

```json
{"app":{"outcome":"identified","app":"dns","app_id":65539,"confidence":"high",
 "rationale":"dns.header: HEADER 常量自洽且 QUESTION 段可完整解析",
 "server_name":null,"bytes_inspected":36}}
```

`bytes_inspected` 是**连续前缀长度**（本例 36 = 2 字节长度 + 34 字节 DNS 消息），
不是整条 TCP 流的字节数。无 SYN 的单包判定为 `medium`。

## 实跑证据

证据目录 `build/protocol-b014/`。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| 流重组单测 | `cargo test --offline -p traffic-engine --lib pipeline::dns_tcp` | 退出 0，5 项通过（乱序/重传/回绕、冲突/缺尾、预算、epoch、容量/空闲/无锚点） |
| 流水线集成单测 | `cargo test --offline -p traffic-engine --lib segmented_dns_tcp` | 退出 0；乱序分片经真实 pcap 路径得到 `dns`/`high`，1 与 2 worker 逐字节一致 |
| 离线 CLI / tshark | `bash scripts/verify/check-dns-tcp.sh --tshark` | 退出 0；单包查询/响应 + 3 个既有畸形用例 + 乱序重组/缺尾/冲突/中途接入/端口上下文 |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 退出 0；`lint.log` / `lint.exit` |
| 默认完整测试 | `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 退出 0；491 个 Rust 测试通过，live 关口 15 项断言通过；`test-all.log` / `test-all.exit` |

tshark 独立重组同一份 TCP 字节后解出 `dns.qry.name=resolver.example` 与
`dns.a=192.0.2.42`，与本地解析结果一致；这证明门禁用例里的分片不是"只有我们自己能拼"。

## 未完成项

- 只解析**首个**长度帧；持久连接上的多帧事务、消息间边界与乱序跨消息仍属未实现。
- 前缀预算 4096 字节；更大的 DNS 消息（如大 TXT/ANY 响应）会在 `prefix_budget` 处停止，
  不拼接、不截断成成功。
- 不做 IP 分片重组（`CYS-TRF-016`/B008），分片包只报 `need_more`。
- 没有 SACK/窗口语义；回绕只保证"不静默算错"，不等于完整的 32 位序号空间判定。
- 语料为合成报文；真实运营网络上的乱序率、重传率、DNS/TCP 占比、规模与 Linux 运行矩阵未验收。
- 明细未进入 `FlowRecord` 的 DNS 字段（`qname` 等仍只在 DPI 内部）；没有按消息统计。
- 完整适配因此保持未勾选；本轮只关闭"主流水线未接入"这一条已知缺口。

本轮只做通用明文协议解析与有界重组，不提供规避审查的识别指纹、主动探测或封锁实现。
