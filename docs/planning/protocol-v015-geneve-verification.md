# V015 · Geneve 有界解析完整适配验收

日期：2026-11-02；分支：`feat/v015-geneve-adaptation`；基线：`main@bf589b3`。

本行把 Geneve 从目录中的“有界解析声明”推进到可核对的封装解析：外层 UDP 6081
只作为触发条件，版本、Opt Len、O/C 位、选项头、24 位 VNI 与可见内层头按
RFC 8926 有界展开；内层 IP **不**回到流水线，不生成第二条 FlowRecord。与 VXLAN
共用的内层以太网/VLAN/IP 解析抽到 `inner.rs`，VXLAN 回归仍保持通过。

## 1. 本行验收范围

### 输入与解析范围

- 经典 pcap 的 Ethernet（最多两层 802.1Q/QinQ）与 Linux SLL/SLL2 链路。
- 外层 UDP 目的或源端口为 6081 时触发；端口本身不是协议结论，结构判定由
  Geneve 头完成。
- Geneve 固定头 8 字节：version/Opt Len、flags（O/C 位）、16 位 Protocol Type、
  24 位 VNI、8 位保留。
  - 只接受 version 0；未知版本按未知 UDP 载荷处理，不猜字段。
  - Opt Len 为 6 位、单位 4 字节；选项区最多 252 字节，总头最多 260 字节。
  - 每个选项头 4 字节，长度字段低 5 位 ×4；选项数据长度必须落在 Opt Len 内。
  - C 位必须与是否存在关键选项一致；不一致显式拒绝。
  - 保留位按 RFC 8926 “收到时忽略”：不判畸形，只记 `reserved_nonzero`。
- 选项只保留 class、type、关键位、保留位和数据长度，**不保存/解释选项值**，
  不把未知厂商选项当成已解码语义。
- O=1 控制报文：只记录 O/C、VNI 和选项，载荷不按以太网/IP 解释。
- 内层 Protocol Type：
  - `0x6558`（TEB）：透明以太网，最多两层 802.1Q/QinQ，可见 IPv4/IPv6/ARP；
  - `0x0800`/`0x86DD`：裸 IPv4/IPv6；
  - 其它值：保留 Protocol Type 原值，`inner_kind=other`，不猜测内层。
- 内层 IPv4/IPv6 只读可见头：版本、IHL/固定头、total/payload length、协议/next
  header、源/目的地址；头不完整时 `inner_ip_complete=false`，不补 0 地址。
- 内层 ARP 只确认 EtherType 与以太头，不解析 ARP 体、不推断邻居/主机状态。
- 主流水线 `cythsec-analyze`（inline 与多 worker 派发路径）、`cythsec-ring-consume`
  与独立 `cythsec-geneve` 共用一份 Geneve 解析；事件只走统计行/独立 JSONL，
  `FlowRecord` 契约未改。

### 边界与上限

| 项 | 值 | 语义 |
| --- | --- | --- |
| Geneve 固定头 | 8 字节 | 不足即 `geneve.truncated_header` |
| version | 仅 0 | 其它版本 `geneve.unsupported_version` |
| Opt Len | 0..63（×4 字节） | 选项区最多 252 字节，总头最多 260 字节 |
| 选项头 | 4 字节 | 不足 4 字节或声明长度越界即 `geneve.truncated_options` / `geneve.option_overrun` |
| 选项数据 | 0..124 字节/项 | 低 5 位 ×4；高 3 位保留位只计数 |
| VNI | 0..0xFFFFFF | 原样保留；0 单独计数，不据此宣称隧道有效 |
| 内层以太网头 | 14 字节 | 完整抓包下不足即 `geneve.truncated_inner` |
| 内层 VLAN | 最多 2 层 | 三层及以上 `geneve.vlan_nesting` |
| 内层 IPv4 头 | 20..60 字节 | IHL<5 或 total length<IHL 时标记不完整 |
| 内层 IPv6 头 | 40 字节 | 不足时标记不完整；不遍历扩展头 |
| 抓包截断 | `orig_len > caplen` | 选项区/内层头不足记 `options_truncated`/`inner_truncated`，不记结构畸形 |

### 明确不做

- 不解析 Geneve GPE/GBP 扩展，也不解释任何厂商选项值。
- 不在主流水线按任意 UDP 端口做结构探测；非 6081 载荷不进入 Geneve 解析。
- 不根据 VNI、TEP 地址、外层端口或内层 MAC 推断租户、隧道对端在线、拓扑或
  数据面转发状态。
- 不递归解析/建立内层 FlowRecord；内层 IP 只作为“这个外层包携带了什么”的可见字段。
- 不做主动探测、Geneve 端点配置查询、解封装或隧道流量注入。
- 不支持 pcapng、raw-IP linktype；不校验外层/内层 UDP 校验和（与既有解码器的
  checksum-offload 边界一致）。
- 不支持 IPv6 扩展头链遍历；与 VXLAN 的可见头口径一致。

## 2. 逐项行为

| 场景 | 行为 |
| --- | --- |
| TEB + IPv4 | 输出 VNI、内外 MAC、内层 IPv4 源/目的/协议/总长；内层完整 |
| TEB + 单层 VLAN / QinQ | 输出从外到内的 VLAN ID；最多两层 |
| TEB + IPv6 | 输出源/目的、next header、payload 声明长度 |
| TEB + ARP | `inner_ether_type_name=arp`，`inner_ip_complete=null`，不伪造 IP |
| 裸 IPv4 / 裸 IPv6 | Protocol Type 直接标识内层 IP；不伪造 MAC/VLAN |
| 关键选项 + C=1 | 保留选项头；C 位与关键位一致；不解释选项值 |
| C=0 + 关键选项 | `geneve.critical_mismatch` |
| C=1 + 无关键选项 | `geneve.critical_mismatch` |
| O=1 控制报文 | `inner_kind=control`、`inner_complete=null`，载荷不解释 |
| 非零保留位 | 正常解析并记 `reserved_nonzero`，不判畸形 |
| VNI=0 / VNI=0xFFFFFF | 原样保留；VNI=0 计入 `vni_zero` |
| 7 字节头 | `geneve.truncated_header` |
| version≠0 | `geneve.unsupported_version` |
| 完整抓包选项区不足 | `geneve.truncated_options` |
| 选项长度越过 Opt Len | `geneve.option_overrun` |
| 完整抓包 TEB 内层不足 | `geneve.truncated_inner` |
| 抓包截断选项区 | 保留头/已读选项，`options_truncated=true`，不记畸形 |
| 抓包截断内层 | `inner_truncated=true`、`capture_truncated=true`，不记畸形 |
| 三层内层 VLAN | `geneve.vlan_nesting` |
| 未知 Protocol Type | 保留原值，`inner_kind=other`，不猜测 |

## 3. 证据

### 本地单测与流水线

- `dataplane/traffic-engine/src/geneve/tests.rs`：21 项，覆盖 TEB IPv4、VLAN/QinQ、
  裸 IPv4/IPv6、关键选项与 C 位、控制报文、VNI 0/最大值、非零保留位、短头、
  未知版本、选项区截断、抓包截断选项、选项越界、C 位不一致双向、内层不足、
  抓包截断内层、三层 VLAN、未知 Protocol Type、ARP、统计行与 JSON 字段。
- `cargo test --offline -p traffic-engine --lib geneve`：23 项通过（21 项模块测试 +
  2 项流水线测试）。
- `cargo test --offline -p traffic-engine --lib`：683 项通过（本轮全量 lib 测试；
  VXLAN 16 项仍通过，证明 `inner.rs` 抽取未回归）。
- `dataplane/traffic-engine/src/pipeline.rs`：2 项 Geneve 测试：
  - `geneve_inner_ip_is_not_a_second_flow`：两个不同内层 IP 的 Geneve 包只产生一条
    外层 UDP 流；
  - `geneve_stats_are_identical_with_multiple_workers`：`workers=1` 与 `workers=3`
    的 Geneve 统计与记录一致。

### 合成语料与 tshark

`scripts/verify/check-geneve.py` 独立按 RFC 8926 拼字节，包含 9 个有效帧（TEB
IPv4、VLAN+关键选项、QinQ+IPv6、ARP、裸 IPv4、裸 IPv6、O=1 控制、抓包截断、
非零保留位）、7 个负例（短头、version 1、选项区截断、选项越界、C 位不一致、
完整抓包内层不足、三层 VLAN）和 1 个非 Geneve UDP 帧。统计期望：

```text
geneve_frames=9 vni_zero=1 control=1 critical=1 options=2 options_critical=1
inner_ethernet=5 inner_ipv4=4 inner_ipv6=2 inner_arp=1 inner_other=0
inner_complete=7 inner_incomplete=1 capture_truncated=1 options_truncated=0
truncated=3 malformed=4 unsupported_version=1 critical_mismatch=1
option_overrun=1 too_many_vlans=1 reserved_nonzero=1 non_geneve=1 decode_errors=0
```

`--tshark` 用 Wireshark 4.6.7 对同一份 pcap 解 9 个 Geneve 帧，逐项比较
`geneve.vni`、version、C 位、内层 MAC、最内层 VLAN、内层 IPv4/IPv6 地址与协议；
QinQ 的外层 VLAN 由事件字段覆盖（tshark `occurrence=l` 只取最内层）。门禁另有
7 项反向注入（事件 VNI/MAC/VLAN、记录少一条、统计、tshark VNI/少一帧）全部被检出。

### 真实 Linux network namespace

在 arm64 Linux 容器内建立两个 netns、veth 与 Geneve id 100（6081），内层
10.100.0.1/24 ↔ 10.100.0.2/24，执行 `ping -c 3`，在 blue 侧 veth 抓包：

- 10 帧 Geneve，全部 VNI=100、Protocol Type=0x6558（TEB）；
- 内层 2 个 IPv6 router solicitation、2 个 ARP、6 个 IPv4（ICMP）；
- `cythsec-geneve`：`geneve_frames=10 vni_zero=0 control=0 critical=0 options=0
  inner_ethernet=10 inner_ipv4=6 inner_ipv6=2 inner_arp=2 inner_complete=10
  inner_incomplete=0 capture_truncated=0 truncated=0 malformed=0
  reserved_nonzero=0`；
- `cythsec-analyze`：10 个报文解码，6 条外层流（同五元组的请求/响应聚合），
  Geneve 统计与采集器一致；
- `cythsec-ring-consume`：`packets=10 decoded=10 decode_fail=0 flows=6`，Geneve
  统计与离线路径逐项一致；
- tshark 独立确认 10 帧均为 VNI 100、Protocol Type 0x6558，并解出内层 IPv6/ARP/
  IPv4 头。

真实抓包保存在 `build/protocol-base/evidence/v015-real-geneve.pcap`（构建产物，
不入库）；可复现的关口是合成语料 + tshark。

### 门禁

- `bash scripts/verify/check-geneve.sh` 与 `--tshark` 均退出 0；
- `scripts/test/test-all.sh` 的 Rust 组与 tshark 组均已挂载本关口；
- 最终 `bash scripts/lint/lint-all.sh` 与
  `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` 均退出 0；全量 Rust lib
  683 项通过，Geneve 合成/tshark 关口在 Rust 组和 tshark 组各跑一次均通过；live
  段 15 项断言通过（无注入目标的环境流量场景按脚本显式 SKIP 记录，不计为通过）。

## 4. 复现

```bash
bash scripts/verify/check-geneve.sh --tshark
cargo test --offline -p traffic-engine --lib geneve
cargo test --offline -p traffic-engine --lib
bash scripts/lint/lint-all.sh
bash scripts/test/test-all.sh
```

## 5. 结论与剩余边界

V015 在本行 scope 内达到完整适配：有界解析、截断/未知/畸形语义、控制报文不解释
载荷、独立事件流、流水线不递归建流、合成语料、tshark 对照、真实 netns 与共享环
证据齐全，`gap` 为空。

Geneve GPE/GBP、厂商选项值语义、VTEP/VNI 拓扑与租户推断、非 6081 端口结构发现、
解封装与内层流重建、IPv6 扩展头链仍不在本行范围内；这些不应由 V015 的 accepted
状态掩盖。
