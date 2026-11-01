# V014 · VXLAN 有界解析完整适配验收

日期：2026-11-01；分支：`feat/v014-vxlan-adaptation`；基线：`main@e95fae9`。
本行把 VXLAN 从“DPI 里的结构候选”推进到可核对的基础封装解析：外层 UDP 端口只作为
触发条件，VNI、基础 flags 和内层以太网/IPv4/IPv6 头按 RFC 7348 有界展开；内层 IP
**不**回到流水线，不生成第二条 FlowRecord。

## 1. 本行验收范围

### 输入与解析范围

- 经典 pcap 的 Ethernet（最多两层 802.1Q/QinQ）与 Linux SLL/SLL2 链路。
- 外层 UDP 目的或源端口为 4789（RFC 7348）或 8472（早期 Linux 默认端口）时触发；
  端口本身不是协议结论，结构判定由 VXLAN 头完成。
- VXLAN 固定头 8 字节：flags、24 位保留、24 位 VNI、8 位保留。
  - I 位必须为 1；flags 低 7 位非零、bytes 1..4 非零或 byte 7 非零均拒绝。
  - VNI 原样保留，24 位全范围；VNI=0 单独计数，不据此宣称隧道有效。
- 内层以太网：目的/源 MAC、最多两层 802.1Q/QinQ、EtherType。
- 内层 IPv4：版本、IHL、total length、协议、源/目的地址；IHL/版本/长度不自洽时
  标记 `inner_ip_complete=false`，不补 0 地址。
- 内层 IPv6：版本、payload length、next header、源/目的地址；固定头不足 40 字节
  时标记不完整。
- 内层 ARP：只确认 EtherType 与以太头，不解析 ARP 体、不推断邻居/主机状态。
- 主流水线 `cythsec-analyze`（inline 与多 worker 派发路径）、`cythsec-ring-consume`
  与独立 `cythsec-vxlan` 共用一份 VXLAN 解析；事件只走统计行/独立 JSONL，
  `FlowRecord` 契约未改。

### 边界与上限

| 项 | 值 | 语义 |
| --- | --- | --- |
| VXLAN 固定头 | 8 字节 | 不足即 `vxlan.truncated_header` |
| 内层以太网头 | 14 字节 | 完整抓包下不足即 `vxlan.truncated_inner` |
| 内层 VLAN | 最多 2 层 | 三层及以上 `vxlan.vlan_nesting` |
| 内层 IPv4 头 | 20..60 字节 | IHL<5 或 total length<IHL 时标记不完整 |
| 内层 IPv6 头 | 40 字节 | 不足时标记不完整；不遍历扩展头 |
| VNI | 0..0xFFFFFF | 0 单独计数；不从 VNI 推断租户/VTEP |
| 外层端口 | 4789 / 8472 | 主流水线与采集器只在这些端口触发 |
| 抓包截断 | `orig_len > caplen` | 固定头完整但内层不足时记 `inner_truncated`，不记畸形 |

### 明确不做

- 不解析 VXLAN-GPE、VXLAN-GBP 或其它 flags 扩展；出现非基础位即拒绝，不猜成基础 VXLAN。
- 不在主流水线按任意 UDP 端口做结构探测；DPI 的既有结构候选不因本行改变，
  也不把候选当成已确认隧道。
- 不根据 VNI、VTEP 地址、外层端口或内层 MAC 推断租户、隧道对端在线、拓扑或
  数据面转发状态。
- 不递归解析/建立内层 FlowRecord；内层 IP 只作为“这个外层包携带了什么”的可见字段。
- 不做主动探测、VTEP 配置查询、VXLAN 解封装或隧道流量注入。
- 不支持 pcapng、raw-IP linktype；不校验外层/内层 UDP 校验和（与既有解码器的
  checksum-offload 边界一致）。

## 2. 逐项行为

| 场景 | 行为 |
| --- | --- |
| 合法 IPv4 内层 | 输出 VNI、内外 MAC、内层 IPv4 源/目的/协议/总长；内层完整 |
| 单层 VLAN / QinQ | 输出从外到内的 VLAN ID；最多两层 |
| IPv6 内层 | 输出源/目的、next header、payload 声明长度 |
| ARP 内层 | `inner_ether_type_name=arp`，`inner_ip_complete=null`，不伪造 IP |
| VNI=0 | 正常保留并计入 `vni_zero`，不宣称有效租户 |
| legacy 8472 | 与 4789 同样按结构解析 |
| 7 字节头 | `vxlan.truncated_header`，不读越界 |
| I 位为 0 | `vxlan.missing_i_flag` |
| 保留位非零 | `vxlan.reserved_nonzero`，报告偏移 |
| 完整抓包内层不足 | `vxlan.truncated_inner` |
| 抓包截断内层不足 | `inner_truncated=true`、`capture_truncated=true`，不记畸形 |
| 三层内层 VLAN | `vxlan.vlan_nesting` |
| 内层 IPv4 头不完整 | 保留可见 EtherType，`inner_ip_complete=false`，地址为 null |

## 3. 证据

### 本地单测与流水线

- `dataplane/traffic-engine/src/vxlan/tests.rs`：14 项，覆盖 IPv4/IPv6/ARP 内层、
  单层 VLAN/QinQ、VNI 0/最大值、短头、缺 I 位、保留位、三层 VLAN、完整/抓包截断、
  不完整内层 IP、统计行与 JSON 字段。
- `cargo test --offline -p traffic-engine --lib`：660 项通过（本轮全量 lib 测试，
  含上述 16 项 VXLAN 测试）。
- `dataplane/traffic-engine/src/pipeline.rs`：2 项 VXLAN 测试：
  - `vxlan_inner_ip_is_not_a_second_flow`：两个不同内层 IP 的 VXLAN 包只产生一条
    外层 UDP 流；
  - `vxlan_stats_are_identical_with_multiple_workers`：`workers=1` 与 `workers=3`
    的 VXLAN 统计与记录一致。

### 合成语料与 tshark

`scripts/verify/check-vxlan.py` 独立按 RFC 7348 拼字节，包含 6 个有效帧（IPv4、
VLAN、QinQ+IPv6、ARP、legacy 8472、抓包截断）、5 个负例（短头、缺 I、保留位、
完整抓包内层短、三层 VLAN）和 1 个非 VXLAN UDP 帧。统计期望：

```text
vxlan_frames=6 vni_zero=1 vlan_tagged=2 inner_ipv4=3 inner_ipv6=1 inner_arp=1
inner_complete=5 inner_incomplete=1 capture_truncated=1 truncated=2 malformed=3
missing_i_flag=1 reserved_nonzero=1 too_many_vlans=1
```

`--tshark` 用 Wireshark 4.6.7 对同一份 pcap 解 6 个 VXLAN 帧，逐项比较
`vxlan.vni`、I 位、内层 MAC、最内层 VLAN、内层 IPv4/IPv6 地址与协议；QinQ 的
外层 VLAN 由事件字段覆盖（tshark `occurrence=l` 只取最内层）。门禁另有 7 项
反向注入（事件 VNI/MAC/VLAN、记录少一条、统计、tshark VNI/少一帧）全部被检出。

### 真实 Linux network namespace

在 arm64 Linux 容器内建立两个 netns、veth 与 VXLAN id 100（4789），内层
192.168.100.1/24 ↔ 192.168.100.2/24，执行 `ping -c 3`，在 veth1 抓包：

- 8 帧 VXLAN，全部 VNI=100、flags=I；
- 内层 2 个 ARP、6 个 IPv4（ICMP）；
- `cythsec-vxlan`：`vxlan_frames=8 inner_ipv4=6 inner_arp=2 inner_complete=8`
  `malformed=0 truncated=0 capture_truncated=0`；
- `cythsec-analyze`：`packets_read=8 packets_decoded=8`，4 条外层流，VXLAN
  统计与采集器一致；
- tshark 独立确认 8 帧均为 VNI 100。

真实抓包保存在 `build/protocol-base/evidence/v014-real-vxlan.pcap`（构建产物，
不入库）；可复现的关口是合成语料 + tshark。

### 共享环

用 `cythsec-ring-feed` 把一帧 VXLAN pcap 灌入共享环，`ring-consume` 输出：

```text
ring-consume summary packets=1 decoded=1 decode_fail=0 flows=1
ring-consume vxlan vxlan_frames=1 inner_ipv4=1 inner_complete=1
```

说明在线消费路径与离线路径对同一份字节给出相同的 VXLAN 计数，且内层 IP 没有
额外生成流。

### 门禁

- `bash scripts/verify/check-vxlan.sh` 与 `--tshark` 均退出 0；
- `scripts/test/test-all.sh` 的 Rust 组与 tshark 组均已挂载本关口；
- 最终 `bash scripts/lint/lint-all.sh` 与
  `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` 退出 0；全量 Rust lib
  660 项通过，VXLAN 合成/tshark 关口在 Rust 组和 tshark 组各跑一次均通过；live
  段 15 项断言通过（SKIP 项按“未核验”记录，不计为通过）。

全量门禁的 live 段还暴露出一个 B008 之后的旧对账口径：完整重组的数据报会正常
解码，其非首片不再计入 `decode_fail`，而 tshark 仍是逐帧裁判。`ring-consume`
因此增补 `reassembled_non_initial` 记账，live 关口按
`decode_fail + 已重组非首片` 与 tshark 对账；这只改统计口径，不改重组、解码或
流表行为。该修正让 live 段在真实抓包恰好包含完整分片数据报时不再假红。

## 4. 复现

```bash
bash scripts/verify/check-vxlan.sh --tshark
cargo test --offline -p traffic-engine --lib vxlan
bash scripts/lint/lint-all.sh
bash scripts/test/test-all.sh
```

## 5. 结论与剩余边界

V014 在本行 scope 内达到完整适配：有界解析、截断/未知/畸形语义、独立事件流、
流水线不递归建流、合成语料、tshark 对照、真实 netns 和共享环证据齐全，`gap` 为空。

Geneve、VXLAN-GPE/GBP、非标准端口结构发现、VTEP 拓扑/租户推断、VXLAN 解封装与
内层流重建仍不在本行范围内；这些是后续 V015/跨层任务，不应由 V014 的 accepted
状态掩盖。
