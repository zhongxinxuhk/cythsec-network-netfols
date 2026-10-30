# B024 · sFlow v5 采集验收

日期：2026-10-31；基线：`a3eaa56`（B023）；分支：`feat/protocol-b024-sflow`；
工作目录 `/Users/xuzhongxin/CLionProjects/CythSec`。

## 本轮做了什么

B024 此前在清单里是“未实现”。本轮新增 `dataplane/traffic-engine/src/sflow.rs`
与 `cythsec-sflow-collect`，按 sFlow v5 的 XDR/TLV 线格式解析：

- 数据报头：version 5、IPv4/IPv6 agent address、sub-agent、sequence、uptime、num_samples；
- flow sample（1）与 expanded flow sample（3）；
- counter sample（2）与 expanded counter sample（4）；
- flow record：raw packet header（1，Ethernet/IPv4/IPv6）、Ethernet frame（2）、
  IPv4 data（3）、IPv6 data（4）、extended switch（1001）；
- counter record：generic interface（1）、Ethernet interface（2）、VLAN（5）。

## 为什么不能复用 IPFIX / NetFlow v9 采集器

sFlow 没有模板：每个 sample/record 都自带长度，字段是固定布局；它的 `sequence`
是**数据报序号**，既不是 IPFIX 的“此前已发送记录累计数”，也不是 v9 的“导出报文序号”。
把 sFlow 塞进模板状态机会得到“能跑但字段错位”的第二套实现；把序号缺口套成记录数
则会把丢一个数据报写成丢几十条记录。故这里从 XDR 读取器开始独立实现，只复用
`FlowKey`/`ExporterId` 这类与线格式无关的类型。

## 验收范围与口径

- `lost_datagrams = delta - 1`（delta 为 32 位无符号前进差值）；`loss_ppm` 分母 =
  实收 v5 数据报 + 推定丢失数据报。
- 首报文无基线；同序号重复不推进基线、不算丢包；倒退/乱序/2^32 回绕不误报。
- 不同 `(agent, sub_agent_id)` 各自维护序号状态；agent 地址为 0 时退回 UDP 源地址。
- 去重键 = `(agent, sub_agent, datagram_sequence, sample_sequence, sample_format)`，
  窗口有界；重复数据报里的重复 sample 只交付一次。
- flow sample 的 `packets` 不乘采样率：一条 sample 只代表一个被采到的包，采样率单独
  输出。要做量级还原由下游按 `sampling_rate` 计算，不能把估计值写成观测值。
- 同一 flow sample 内多个 record 给出不同五元组时保留首个并计
  `flow_record_conflicts`；缺五元组的 sample 计 `flow_records_missing_key`，不造
  `0.0.0.0:0` 流。
- 未知 sample/record 类型按长度跳过并登记；record 长度越界计 `record_truncations`，
  不伪造后续字段。
- counter sample 输出独立 JSONL（`--counters`），不硬塞进没有五元组的 `FlowRecord`。

## CLI

```bash
cythsec-sflow-collect --pcap sflow.pcap -o flows.jsonl --counters counters.jsonl
cythsec-sflow-collect --udp 0.0.0.0:6343 --duration 60
```

pcap 模式默认按 UDP 端口 6343 过滤（`--any-port` 可关闭）；时间取抓包时间戳，
同一份 pcap 重放结果可复现。flow/counter 两路不能同时写 stdout，脚本会显式拒绝。

## 实跑证据

证据目录 `build/protocol-b024/`。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| 单元测试 | `cargo test --offline -p traffic-engine --lib sflow` | 退出 0，16 项通过 |
| 采集 + tshark | `bash scripts/verify/check-sflow.sh --tshark` | 退出 0；flow/counter、expanded、IPv6、VLAN、序号缺口、重复、乱序、回绕、sub-agent、未知类型、截断、非零尾部、缺五元组、端口过滤全部通过；tshark 解出同一 agent/序号/sample 类型/五元组/接口计数/VLAN |
| 仓库 IPFIX 组 | `bash scripts/test/test-all.sh --ipfix` | 退出 0；IPFIX 三段 + NetFlow v9 + sFlow v5 全部通过 |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 退出 0；`build/protocol-b024/lint.log` / `lint.exit` |
| 默认完整测试 | `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 退出 0；522 个 Rust 测试通过；live 关口 15 项断言通过；`test-all.log` / `test-all.exit` |

序号缺口用例：seq 200（1 条 flow）→ seq 203（1 条 flow），`gaps=1`、
`lost_datagrams=2`、`loss_ppm=500000`（分母 = 2 个实收数据报 + 2 个推定丢失数据报）。
tshark 对同一 pcap 解出 `sflow_245.version=5`、`agent=192.0.2.10`、
`sequence_number=100`、`sampletype=1,2`、`ipv4_src=10.0.0.1`、
`ifinoct=123456789`、`vlan.in=100`，与 JSONL 逐项相符。

## 未完成项（因此 `accepted` 仍为 false）

- **扩展记录未解码**：MPLS、AS、URL、NAT、socket、host 描述/CPU/内存/磁盘等只跳过计数；
  它们不是本版“通用 flow/counter”范围，但现场设备常用，不能算完整适配。
- **采样量级还原未做**：只保留 `sampling_rate`，不把采样值放大成全网总量；这是刻意的
  口径边界，不是遗漏。
- **没有真实厂商/现场语料**：当前语料由验证脚本按 RFC 独立拼字节，能证明格式理解，
  不能证明某厂商的私有扩展或异常填充行为。
- **传输层只做 UDP/pcap**：sFlow over TCP/SCTP 未实现。
- **没有长期运行矩阵**：去重窗口、内存增长、跨天运行与 Linux 现场部署未验收。
- pcap 默认只按 6343 端口过滤；非常规端口需 `--any-port`。

本轮只做通用流/计数器导出格式的解析与统计，不涉及规避审查的指纹、主动探测或封锁实现。
