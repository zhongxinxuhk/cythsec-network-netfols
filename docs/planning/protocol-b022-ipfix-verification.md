# B022 · IPFIX v10 独立对照验收

日期：2026-10-30；基线：`2c62224`；分支：`feat/protocol-b022-ipfix-reference`；
工作目录 `/Users/xuzhongxin/CLionProjects/CythSec`。

## 结论先说

B022 的采集器、导出器和三套对照脚本早已写入仓库，并已接入
`scripts/test/test-all.sh --ipfix`；但清单仍把 `reference_tested` 记为 `false`、`reference`
留空。本轮**不改实现**，只把已有证据重新跑一遍并逐项登记：`reference_tested` 改为 `true`，
`accepted` 仍为 `false`（Options Template、真实厂商语料与长期运行矩阵未完成）。

这条记录也说明 B022 的边界：它验收的是 **IPFIX 报文的编码/解码与采集口径**，
不是把 IPFIX 当成某个 `AppId` 的 DPI 识别结果。

## 验收范围

- 版本固定为 IPFIX v10（RFC 7011）；版本不符只计 `version_mismatch`，不按 v10 硬解。
- 模板集/数据集：模板 ID、字段长度、4 字节对齐、零填充；缩减长度编码（§6.2）。
- 采集侧序列号：按“本报文之前已发送的数据记录数”算缺口；只把前进方向算丢包，
  倒退算乱序，2^32 回绕不误报；不同导出器/观测域各自独立基线。
- 模板生存期：未刷新即过期；观测到重传间隔后取 `3 × 间隔`；UDP 上的模板撤回按 §8.4 忽略。
- 同号不同定义：保留旧模板并计数，不用新定义解释后续数据。
- 数据先于模板到达：计 `no_template_sets`，不凭模板号猜记录。
- 未知 IE：按模板声明长度跳过，后续字段偏移不得错位；Options Template 只跳过并计数。
- 去重窗口有界；单报文记录数有防御上限；缺关键字段的记录不臆造。
- 采集还原的记录对 TCP 状态/DPI 结论如实写 `null`/`not_inspected`，不填占位值。
- 导出侧：IANA IE 编号、采样间隔、模板刷新、IPv4/IPv6 分模板、set 长度对齐、序列号只计数据记录。

## 实跑证据

证据目录 `build/protocol-b022/`。命令：

```bash
bash scripts/test/test-all.sh --ipfix > build/protocol-b022/ipfix-gate.log 2>&1
```

退出码 `0`。三段结果：

| 段落 | 实际结果 |
| --- | --- |
| 导出 → tshark | 4 个样本（5/4/1/9 条记录）均无 malformed、version=10；报文头 length 与 UDP 载荷逐一相符；序列号等于此前记录累计数；数据记录都在模板之后；模板刷新节奏符合设置；5/4/1/9 条 × 9 类字段逐条相符；IE 152/153 的线上 8 字节逐条相符 |
| UDP 真实发送 | 本机收到 1 个 datagram、156 字节，与 pcap 通道载荷逐字节相同 |
| 导出反向注入 | 改计数值、改 setID、改报文长度、截断报文、改时标共 5 项，全部被比对器判死 |
| 采集回路 | 完整回路 `gaps=0 lost_records=0 loss_ppm=0`，逐字段还原；删掉中间 datagram 后 `gaps=1 lost_records=2 loss_ppm=222222`，与手算 `2/(7+2)` 一致；判定自身经反向注入 |
| 异厂互操作 | 独立实现（不 import 仓库常量）的 5 个场景 standard/reduced64/v6/foreign/gap 全部逐条相符；模板 ID 4001/4003、字段序相反、观测域 `0x1234ABCD`；foreign 场景 `template_conflicts=1`、`withdrawals_ignored=1`、`options_template_sets=1`、`no_template_sets=1`、`unknown_ies=9999,12345`、`gaps=1 loss_ppm=285714`（上界口径） |
| 第三实现确认 | tshark 对异厂报文读出 `cflow.version=10`，并解出模板 4001/4003；8 字节与 4 字节两种计数器编码解出同一串 octets |
| 互操作反向注入 | 换语料、篡改统计行、篡改记录时间 1 毫秒、多删一个 datagram 共 5 项，全部被判死 |

`test-all.sh --ipfix` 的汇总行是
`✓ [ipfix] 交叉核验通过（导出：UDP 通道字节比对；采集：丢包率可复算；异厂：5 场景逐条相符；三处注入全部被检出）`。
日志里出现的 `✗` 均来自反向注入的“期望失败”，紧随其后的 `✓ ... 注入已检出` 才是判定结果；
没有把注入失败改写成通过。

## 仓库级门禁

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 退出 0；`build/protocol-b022/lint.log` / `lint.exit` |
| 默认完整测试 | `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 退出 0；491 个 Rust 测试通过；IPFIX 三段全过；live 关口 15 项断言通过；`test-all.log` / `test-all.exit` |

## 未完成项（因此 `accepted` 仍为 false）

- **Options Template 未解码**：只解析长度以便跳过并计数，IE 直方图/中间流统计等不给下游。
- **没有真实厂商导出器语料**：异厂互操作用的是只读 RFC 写成的独立实现，能挡“两边一起读错”，
  但挡不住“某厂商的私有扩展/现场模板”这类现实差异。
- **没有长期运行矩阵**：模板生存期、去重窗口、容量上限只在单次进程内验证；跨天运行、
  重启恢复、内存增长与 Linux 现场部署未验收。
- **传输层只做 UDP**：TCP/SCTP 传输的隐式模板撤回（§8.1）未实现；DTLS 未做。
- **IE 字典不完整**：未登记 IE 只跳过；没有完整跨厂商 IE 语义与单位换算。
- 量级还原（`estimate.rs`）有独立单测，但本轮没有把它纳入“真实采样率/规模”的现场验收。

## 复现与判读

```bash
bash scripts/verify/check-ipfix-export.sh   # 导出：tshark + UDP + 5 项注入
bash scripts/verify/check-ipfix-collect.sh  # 采集：逐字段回路 + 丢包率 + 注入
bash scripts/verify/check-ipfix-interop.sh  # 异厂：5 场景 + tshark + 5 项注入
```

三个脚本的退出码：`0` 通过；`1` 断言失败；`2` 前置条件缺失；`3` 缺工具（**未核验**，不计通过）。
正式验收不要加 `--no-self-test`。

本轮只做通用流导出格式的解析与对照，不涉及规避审查的指纹、主动探测或封锁实现。
