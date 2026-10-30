# B023 · NetFlow v9 采集验收

日期：2026-10-31；基线：`a695b94`；分支：`feat/protocol-b023-netflow9`；
工作目录 `/Users/xuzhongxin/CLionProjects/CythSec`。

## 本轮做了什么

B023 此前在清单里是“未实现”，采集器遇到 version=9 会直接计入 `version_mismatch`。
本轮新增 `dataplane/traffic-engine/src/netflow9.rs` 与
`cythsec-netflow9-collect`，支持 RFC 3954 的模板流集、数据流集、选项模板跳过、
模板生存期与**导出报文级**序号缺口。

### 为什么不能复用 IPFIX 采集器

IPFIX（RFC 7011）的 `sequenceNumber` 是“本报文之前该观测域已发送的**数据记录**累计数”，
所以缺口差值就是丢失的记录条数。NetFlow v9 的 `sequence` 是**导出报文序号**：
收到 11 后收到 13，只说明 12 号报文丢了，**无法知道 12 号里原本有几条记录**。
若复用 IPFIX 的记账，`gap=1` 会被写成“丢 1 条记录”，而实际可能丢了几十条；
数字看起来更精确，口径却错了。故本模块单独实现，只复用 `CollectedFlow`/`ExporterId`
这类与协议无关的类型。

## 验收范围

- v9 报文头 20 字节：version/count/sysUpTime/unixSecs/sequence/sourceID。
- 模板流集（flowsetID=0）：模板号 ≥256、字段类型/长度；同号同定义算刷新，
  同号不同定义保留旧模板并计冲突。
- 数据流集（flowsetID≥256）：按模板定长切记录；尾部填充必须全零；记录数有上限。
- 字段：1/2/4/7/8/11/12/27/28/34/148/152/153，以及 21/22（相对 `sysUpTime` 的
  FIRST/LAST_SWITCHED，换算成绝对毫秒）；未映射类型保留长度、跳过并登记。
- 选项模板流集（flowsetID=1）：只校验形状、登记模板号；选项数据集显式跳过，
  不硬解成流记录。
- 序号：首报文无基线；`delta=1` 正常；`delta>1` 记 `lost_export_packets=delta`；
  同序号记重复；倒退/2^32 回绕不误报。
- 模板生存期：显式配置 > 观测重传间隔 ×3 > 默认 600 秒。
- 去重窗口有界；缺五元组的记录计 `records_missing_key` 并丢弃，不造 0.0.0.0:0 流。
- `count` 字段与实际解析记录数不符时计 `count_mismatches`，但不丢数据。

## CLI

```bash
cythsec-netflow9-collect --pcap v9.pcap -o flows.jsonl
cythsec-netflow9-collect --udp 0.0.0.0:2055 --duration 60
```

pcap 模式默认按端口 2055 过滤（`--any-port` 可关闭）；时间取抓包时间戳，
同一份 pcap 重放结果可复现。输出是现有 `FlowRecord` JSONL，`app.outcome=not_inspected`、
`tcp.state=null` —— v9 没承载 DPI/TCP 状态，不能填占位值。

## 实跑证据

证据目录 `build/protocol-b023/`。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| 单元测试 | `cargo test --offline -p traffic-engine --lib netflow9` | 退出 0，15 项通过 |
| 采集 + tshark | `bash scripts/verify/check-netflow9.sh --tshark` | 退出 0；模板/数据、序号缺口、重复、IPv6、未知字段、sysUpTime、选项模板、缺模板、截断、count 不符全部通过；tshark 解出同一五元组与计数 |
| 仓库 IPFIX 组 | `bash scripts/test/test-all.sh --ipfix` | 退出 0；IPFIX 三段 + NetFlow v9 全部通过 |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 退出 0；`build/protocol-b023/lint.log` / `lint.exit` |
| 默认完整测试 | `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 退出 0；506 个 Rust 测试通过；live 关口 15 项断言通过；`test-all.log` / `test-all.exit` |

序号缺口用例：seq 1（模板+2 条记录）→ seq 3（2 条记录），`gaps=1`、
`lost_export_packets=1`、`loss_ppm=333333`（分母 = 2 个实收报文 + 1 个推定丢失报文）。
tshark 对同一 pcap 解出 `cflow.version=9`、`srcaddr=10.0.0.1,10.0.0.3`、
`octets=1500,1500`，与 JSONL 两条记录逐项相符。

## 未完成项（因此 `accepted` 仍为 false）

- **Options Template 不解码**：IE 直方图、采样选项等只跳过；选项数据集也跳过。
- **口径上限**：只能报“丢了多少个导出报文”，不能还原每个丢失报文里的记录数；
  `lost_export_packets` 不是流记录丢失数。
- **没有真实厂商/现场语料**：当前语料由验证脚本按 RFC 独立拼字节，能证明格式理解，
  不能证明某厂商的私有字段/模板刷新行为。
- **传输层只做 UDP/pcap**：TCP/SCTP 传输、模板会话结束语义未实现。
- **没有长期运行矩阵**：模板生存期/去重窗口/内存增长只在单次进程内验证，
  跨天运行与 Linux 现场部署未验收。
- pcap 默认只按 2055 端口过滤；非常规端口需 `--any-port`。
- 未接入采样量级还原（v9 的 sampling 字段只保留在记录里，不做全量估计）。

本轮只做通用流导出格式的解析与统计，不涉及规避审查的指纹、主动探测或封锁实现。
