# B008 · IPv4/IPv6 分片重组完整适配验收

日期：2026-11-01；分支：`feat/b008-fragmentation-reassembly`；基线：`main@0d57b6d`。
本分支把 B008 从“识别分片并阻止伪造完整传输统计”推进到有界重组：完整数据报回到
普通解码/流表路径，不完整、重叠、冲突和超限分片只留下显式统计与事件，不合成端口为 0
的假流。

## 1. 本行验收范围

### 输入与重组键

- 经典 pcap 的 Ethernet（最多两层 802.1Q/QinQ）与 Linux SLL/SLL2 链路；只处理已由
  采集面给出的帧，不主动探测。
- IPv4（RFC 791）与 IPv6（RFC 8200）分片。IPv6 允许分片头之前存在逐跳选项、路由头、
  目的选项和 AH，最多遍历 8 个扩展头；IPv6 atomic fragment（offset=0、M=0）按普通帧
  放行，不进入重组表。
- IPv4 键为源/目的地址、Identification、协议；IPv6 键为源/目的地址、Identification。
  IPv6 同一数据报各分片的 Next Header 必须一致，不一致显式拒绝；IPv4 协议属于
  重组键，不同协议不会合并。
- 只有覆盖 `0..总长` 连续、无空洞且已看到最后一片的数据报才交付；交付后只解码一次，
  进入既有流表/会话/DPI，不另造“分片专用”流。
- IPv4 重建 total length、清除 MF/DF/offset 并重算头校验和；IPv6 重建 payload length，
  清除分片头 offset/M，保留 Next Header 与 Identification；保留原链路头/VLAN/SLL 头。
- 主流水线 `cythsec-analyze` 的 inline 与多 worker 派发路径均接入；`cythsec-ring-consume`
  的共享环消费路径接入；独立 `cythsec-ipfrag` 输出 JSONL 事件。三者共用同一重组实现。
- `FlowRecord` 键、落盘格式与 Native/IPFIX 契约未改；分片明细只进入统计行、错误码和
  独立 JSONL。

### 边界与上限

| 项 | 值 | 语义 |
| --- | --- | --- |
| 单数据报载荷 | 65535 字节 | IPv4 total length / IPv6 payload length 的协议上限；IPv6 jumbogram 不支持 |
| 并发数据报 | 默认 256 | 超过时逐出最旧数据报并计 `evicted` |
| 单数据报唯一分片 | 默认 1024 | 超过时拒绝该片并计 `ipfrag.too_many_fragments` |
| 空闲超时 | 默认 30 秒 | 以最后到达分片时间为准；下一次 push 时逐出并计 `expired`，EOF 收尾只把仍在表内的计 `incomplete` |
| IPv6 分片前扩展头 | 最多 8 个 | 超过后不再猜测分片位置，交回普通解码 |
| 分片载荷对齐 | 非最后一片必须为 8 字节整数倍 | 否则 `ipfrag.misaligned_fragment` |

### 重叠策略

重叠一律拒绝（`ipfrag.overlap`），不实现 BSD first-wins 或 Linux last-wins。旁路设备
如果替接收端选择字节，看到的载荷可能与接收端实际重组结果不同；因此宁可显式丢弃并
留下错误码。完全相同的重复分片是唯一例外：不改变字节，只计 `dup`，不重复占用分片
数或字节数。

### 明确不做

- IPv6 jumbogram 分片重组；
- raw-IP、802.11、PPP 等其它 linktype 的分片入口（先由采集侧转换或另立容器适配）；
- 主动探测、主机在线/拓扑/隧道对端推断；
- 把重组后的内层 IP 再递归拆成新的内层流；
- 超过默认上限的并发数据报/分片数扩容策略与生产吞吐标定；
- 真实省网分片比例、逃逸检测和长期运行内存曲线（本行只验收有界语义）。

## 2. 实现变更

| 文件 | 变更 |
| --- | --- |
| `dataplane/traffic-engine/src/reassembly/ip.rs` | IPv4/IPv6 分片解析、重组表、覆盖/重叠/长度/头一致性裁决、超时/逐出/上限、IPv4/IPv6 头重建、统计行 |
| `dataplane/traffic-engine/src/reassembly/ip/tests.rs` | 22 项分片语义单测（乱序、缺片、重复、重叠、冲突、截断、上限、超时、SLL、扩展头、jumbogram、原子分片、统计契约） |
| `dataplane/traffic-engine/src/reassembly/mod.rs` | 导出 `ip` 模块 |
| `dataplane/traffic-engine/src/channel/decode.rs` | 抽出 `link_payload()`，让重组器与普通解码共用链路头/VLAN/SLL 偏移 |
| `dataplane/traffic-engine/src/channel/mod.rs` | 重导出 `link_payload` |
| `dataplane/traffic-engine/src/pipeline.rs` | 派发端接入重组；完整数据报只解码一次；EOF 收尾；4 项流水线测试 |
| `dataplane/traffic-engine/src/bin/analyze.rs` | 输出 `[cythsec-analyze] ipfrag ...` 统计行 |
| `dataplane/traffic-engine/src/bin/ring_consume.rs` | 共享环消费接入重组；区分抓包帧数、逻辑包数、重组数据报数与真实解码失败数 |
| `dataplane/traffic-engine/src/bin/ipfrag_collect.rs` | 独立 `cythsec-ipfrag` JSONL 事件（fragment / datagram_complete / fragment_rejected） |
| `dataplane/traffic-engine/Cargo.toml` | 新增 `cythsec-ipfrag` bin |
| `scripts/verify/check-ipfrag.sh` / `check-ipfrag.py` | 合成语料、反向注入、tshark 独立重组对照 |
| `scripts/test/test-all.sh` | Rust 组与 tshark 组挂入 B008 门禁 |

## 3. 边界语义

| 情形 | 结果 | 统计/事件 | 是否进入流表 |
| --- | --- | --- | --- |
| 乱序但完整 | `Complete` | `complete+1`、`bytes+=载荷`、`datagram_complete` | 是，只算一个逻辑包 |
| 完全相同的重复片 | `Pending` | `dup+1`；`frags` 按帧计，但唯一分片数和缓冲字节数不重复增加 | 否（等待其余片） |
| 缺首片 | EOF 仍 `Pending` | `incomplete+1`、`pending_at_eof+1`、`decode.non_initial_fragment` | 否 |
| 缺尾片 | EOF 仍 `Pending` | `incomplete+1`、`pending_at_eof+1` | 否 |
| 重叠且字节不同 | `Dropped` | `overlap+1`、`malformed+1`、`ipfrag.overlap` | 否 |
| 同偏移重复首片但头不同 | `Dropped` | `overlap+1`、`malformed+1`、`ipfrag.inconsistent_header` | 否 |
| 同一数据报 IPv6 Next Header 不一致 | `Dropped` | `overlap+1`、`malformed+1`、`ipfrag.inconsistent_header` | 否 |
| 最后一片总长矛盾 | `Dropped` | `malformed+1`、`ipfrag.inconsistent_length` | 否 |
| 抓包截断/声明长度大于实有 | `Dropped` | `truncated+1`、`malformed+1`、`ipfrag.truncated_capture` | 否 |
| 超单数据报载荷 | `Dropped` | `oversize+1`、`malformed+1`、`ipfrag.too_large` | 否 |
| 超分片数 | `Dropped` | `malformed+1`、`ipfrag.too_many_fragments` | 否 |
| 队列满逐出最旧 | 旧数据报消失 | `evicted+1`、`incomplete+1` | 否 |
| 空闲超时 | 旧数据报消失 | `expired+1`、`incomplete+1` | 否 |
| IPv6 原子分片/普通帧 | `NotFragment` | 不计分片统计 | 走原有解码 |
| IPv6 jumbogram | `Dropped` | `malformed+1`、`ipfrag.unsupported_jumbogram` | 否 |

`ipfrag` 统计行的稳定字段为：
`frags v4 v6 datagrams complete incomplete malformed dup overlap truncated oversize evicted expired bytes pending_at_eof`。
错误码以 `IpFragError::code()` 为准，不从显示文本反推。

## 4. 实跑记录

证据保存在 `build/protocol-base/evidence/`，日志和 pcap 不纳入源码提交。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| 分片单测 | `cargo test --offline -p traffic-engine --lib reassembly::ip::tests` | 退出 0，22 项通过 |
| 流水线单测 | `cargo test --offline -p traffic-engine --lib pipeline::tests` | 退出 0，23 项通过（含 4 项 B008） |
| Rust 库回归 | `cargo test --offline -p traffic-engine --lib` | 退出 0，644 项通过 |
| 全量 lint | `bash scripts/lint/lint-all.sh` | 退出 0；含 Rust、Node、Python、CLion、协议目录与注册表自检 |
| 全量测试 | `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 退出 0；927 项 tshark 对照、8 项显式 SKIP（未核验），真实网卡抓包关口 15 项断言通过 |
| 合成语料门禁 | `bash scripts/verify/check-ipfrag.sh` | 退出 0；IPv4/IPv6 乱序、扩展头、缺首片、重叠、截断、重复片全部按预期；3 项反向注入全部检出 |
| tshark 独立对照 | `bash scripts/verify/check-ipfrag.sh --tshark` | 退出 0；tshark 4.6.7 看到 4 个分片、重组出 4 条 DNS 消息，名称为 `example.com` / `ipv6.example`，无分片错误 |
| 共享环回归 | `bash scripts/verify/e2e-shared-ring.sh` | 退出 0；4 阶段 / 19 项断言，真实样本 23 帧、14 条流、1 个孤立非首片仍计解码失败 |
| 共享环分片补充 | 见下 | `packets=6 decoded=4 decode_fail=0 flows=4 bytes=490 reassembled=2`；`ipfrag complete=2`，无假失败 |
| 真实分片抓包 | 见下 | 12 帧；`ipfrag frags=12 v4=6 v6=6 datagrams=4 complete=4 bytes=12032`；tshark 独立重组出 4 条 ICMP/ICMPv6 消息，无分片错误 |

### 合成语料

`check-ipfrag.py` 不调用 Rust 编码器，按 RFC 791 / RFC 8200 / RFC 5722 逐字节拼出：

- IPv4 乱序两片 DNS 查询 + 未分片应答；
- IPv6 带逐跳扩展头的乱序两片 DNS 查询 + 未分片应答；
- 缺首片、重叠、抓包截断、完全重复片各一份反例。

完整语料的实际统计行：

```text
ipfrag frags=4 v4=2 v6=2 datagrams=2 complete=2 incomplete=0 malformed=0 dup=0 overlap=0 truncated=0 oversize=0 evicted=0 expired=0 bytes=75 pending_at_eof=0
```

两条 FlowRecord 分别为 IPv4 DNS `192.0.2.1:53000 -> 192.0.2.2:53`（`packets=2`、
`bytes=90`）和 IPv6 DNS `[2001:db8::1]:53001 -> [2001:db8::2]:53`（`packets=2`、
`bytes=104`），均为 `app=dns`、`confidence=high`。`cythsec-ipfrag` 对同一份语料输出
2 条 `datagram_complete`，统计与 `cythsec-analyze` 一致。

### 真实分片抓包

在 Linux network namespace 中把 `lo` MTU 设为 1500，用 `nicolaka/netshoot` 的
`tcpdump -i lo -w ... "icmp or icmp6"` 抓包，同时执行：

- `ping -c 1 -s 3000 127.0.0.1`（IPv4，允许源分片）；
- `ping -6 -c 1 -s 3000 ::1`（IPv6，源分片）。

得到 12 帧真实抓包：IPv4 请求/应答各 3 片，IPv6 请求/应答各 3 片。`cythsec-analyze`
结果：

```text
packets_read=12 packets_decoded=4 decode_errors=0
icmp icmp_frames=4 v4=2 v6=2 echo_requests=2 echo_replies=2 checksum_valid=4 checksum_invalid=0 checksum_unavailable=0
ipfrag frags=12 v4=6 v6=6 datagrams=4 complete=4 incomplete=0 malformed=0 dup=0 overlap=0 truncated=0 oversize=0 evicted=0 expired=0 bytes=12032 pending_at_eof=0
```

tshark 4.6.7 对同一 pcap 独立重组出 4 条 ICMP/ICMPv6 消息（类型 8/0/128/129），
12 个分片帧全部被识别，`ip.fragment.error || ipv6.fragment.error ||
ipv6.fragment.overlap.conflict` 为 0 行。该语料只用于本轮验收，保存在 `build/` 下，
不作为仓库样本，也不声称代表省网分片比例。

### 共享环分片补充

把上述合成完整语料经 `cythsec-ring-feed` 写入共享环后，`ring-consume` 输出：

```text
ring-consume summary packets=6 decoded=4 decode_fail=0 flows=4 bytes=490 reassembled=2
ring-consume ipfrag frags=4 v4=2 v6=2 datagrams=2 complete=2 incomplete=0 malformed=0 dup=0 overlap=0 truncated=0 oversize=0 evicted=0 expired=0 bytes=75 pending_at_eof=0
```

这里 `packets` 是 6 个抓包帧，`decoded` 是 4 个逻辑包（两个查询 + 两个应答），
`reassembled` 是 2 个完整数据报，`decode_fail` 按错误码累计而不是用
`packets - decoded` 推算。修正前该场景会把 2 个正常重组误报成 2 个解码失败；现在
孤立非首片仍为 1（见共享环 19 项断言），完整重组为 0。

## 5. 验收结论

在本文件第 1 节列出的范围内：

- `implemented=true`、`local_tested=true`、`reference_tested=true`；
- IPv4/IPv6 分片表、乱序重组、扩展头、原子分片、重复片、缺片、重叠、冲突、截断、
  超限、超时、队列逐出均有实现、单测和显式统计；
- 主流水线、共享环消费和独立采集器三条出口使用同一重组实现，完整数据报只产生一个
  逻辑包，未完成分片不产生端口为 0 的假流；
- 合成语料由 tshark 独立重组核对，另有 Linux network namespace 的真实分片抓包
  交叉验证；
- 因此 B008 的 `accepted` 置为 `true`，`gap` 为空。

仍明确不做的事见第 1 节“明确不做”。这些是范围边界，不是被隐藏的未完成缺口。
