# B016 · DHCPv6 流量识别验收

日期：2026-10-29；基线：`711fc26`；分支：`feat/protocol-b016-dhcpv6`。
接 B015 DHCPv4，按基础/补充清单推进 B016。复用现有工作区与依赖，不覆盖 B015 本地日志。
本轮为有界结构识别，完整适配保持未勾选。

## 实现范围

- 新增零依赖 `dpi/dhcpv6.rs`：客户端/服务器消息类型 1–11、Relay-forward 12、Relay-reply 13。
  消息头、16 位选项代码/长度按网络字节序读取，未知选项跳过，已支持的 singleton 重复拒绝，
  不采用 DHCPv4 的重复值拼接方式。缺少标识等证据的报文不因 546/547 端口而命中。
- 提取直接消息 24 位事务 ID、原始 Client/Server DUID、ORO、Elapsed Time、Status Code、
  IA_NA/IA_PD 的 IAID/T1/T2、地址/前缀及 preferred/valid lifetime。
  DUID 保留未知类型，作为不透明字节串；不能据此识别当前 MAC、真实设备或用户。
  Relay 头没有事务 ID，保持 None，内层消息单独保留其事务 ID。
- 中继保留 hop count、link/peer address、Interface-ID 与内层消息；Relay Message 选项是长度边界，
  内层短头、IA 越界或固定宽度不符不能借外层/兄弟选项补齐。
  本轮最多 8 层中继，整个解析共享 256 个选项预算，输入最多 4096 字节；预算不足保留 NeedMore。
- 检查基础消息的标识存在/禁止组合、Reconfigure Message 值、IAID 同类型唯一性、T1/T2、
  preferred≤valid、prefix length≤128、ORO/Elapsed Time 定宽。缺少可识别证据为 Rejected/Unknown，
  已支持字段内部矛盾为 Malformed；本轮不验证事务响应匹配、认证或全部消息选项合法性。
- UDP DPI 先处理 DHCPv4 cookie，再检查 DHCPv6 结构；合法的完整报文支持端口漂移。
  标准端口上已知类型的不足/畸形报文不会回落为另一明文应用命中。
  其他端口只有实际 DHCPv6 结构命中才优先采用本检测器，其余保留既有检测顺序。
- 流水线复用 B015 的 UDP 长度边界处理。DHCPv6 无 END 标记，检查预算未覆盖声明的完整数据报时，
  即使前缀已有 DUID 也不能冒充完整选项解析。初始 IP 分片、捕获截断保持 NeedMore，
  非初始分片由既有解码层拒绝；完整 IPv6 原子片仍可解析。
- 新增稳定内置 AppId 序号 25（65561），CLI 应用名 `dhcpv6`。详细解析字段尚未进入 FlowRecord/存储，
  CLI 目前交付应用标识、置信度及状态。识别不能证明租约已应用、前缀路由已安装或认证成功。

依据：[RFC 9915](https://www.rfc-editor.org/rfc/rfc9915.html)，当前规范已替代 RFC 8415。
IA_TA/Server Unicast 等废弃能力不列为本轮已支持功能。无标识且无 ORO 的匿名 Information-request
证据不足，保持 Unknown；认证、完整租约与全部扩展消息验证另行开发。

## 实跑记录

环境：macOS / Rust 1.97.1 / 本机 Wireshark tshark。证据目录 `build/protocol-b016/`。
本轮仅离线构造 IPv6 PCAP，不发送 DHCPv6 请求/应答，不修改本机地址或路由。

| 检查 | 命令 | 结果 |
| --- | --- | --- |
| DHCPv6 专项 | `cargo test --offline -p traffic-engine --lib dpi::dhcpv6` | 退出 0，4 项；`dhcpv6-unit.log` |
| Rust 库全量 | `cargo test --offline -p traffic-engine --lib` | 退出 0，464 项；`rust-lib.log` |
| CLI / tshark 对照 | `bash scripts/verify/check-dhcpv6.sh --tshark` | 首次及最终均退出 0，20 正例/37 负例及检查预算；`dhcpv6-reference-final.log` |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 实际退出 0；`lint.log` / `lint.exit` |
| 默认完整测试 | `CYTHSEC_LIVE_SUDO=0 CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 实际退出 0；`test-all.log` / `test-all.exit`，含既有未核验项，不算完整全绿 |
| 前端既有回归 | 默认全集内执行 | 25 文件、93 项通过；本轮没有前端修改 |
| en0 采集回归 | 默认全集内执行，不使用 sudo | 1899 帧回读全部解析成功，0 错误/0 不支持；15 项断言通过，Rust 环链路核对前缀 500 帧/73 Flow |

默认全集仍有既有独立对照跳过：DPI 14 项、TCP 重组 2 项、FlowRecord 8 项。
这些项继续保留为未核验，不随脚本退出 0 升级为无缺口验收。本轮不合入 main、不 push。
现场采集无注入目标，ICMP 可见项不适用；环境流量回归不等于取得真实 DHCPv6 设备/中继语料。
已将本轮通用采集产物复制到本轮证据目录的 `live-capture/`，避免后续门禁覆盖。

正例包含全部 11 种基础消息、两种中继及嵌套、IA_NA/IA_PD、端口漂移、目的扩展头、原子片和未知 DUID 类型。
基础消息单/双 worker 输出一致。tshark 独立核对消息类型、事务 ID、原始 DUID、中继 link/peer、
地址/前缀与有效期；Rust 单测明确断言对应解析值。独立字段对照不冒充 CLI 明细字段交付。
负例包含全部最小 Solicit 截断点、无标识/匿名空消息、重复 singleton、坏长度、IA 父边界、
错误标识组合、ORO 奇数长度、TCP、UDP 长度矛盾、捕获不足与 IP 分片。
中继深度、共享选项/字节预算及 lifetime 错误由专项单测覆盖。

CLI 回归接入 Rust 组；带 `--tshark` 的对照接入默认全集，缺工具返回 3。
Python 脚本加入 Ruff/Black 支持清单，协议状态真源和生成表同批更新。

## 未完成项

详细字段输出/存储、完整租约/前缀委派事务、DUID/事务响应关联、认证、全部扩展选项/消息、
中继拓扑与 hop 一致性、IP 分片重组、真实设备/中继语料、精度/规模和 Linux 实机矩阵均未完成。
本轮识别为被动结构证据，不能将 Reply/Status 成功值、DUID 或地址声明当作客户端已生效状态。
两条门禁实际退出码和未核验项分别记录；未全绿不合 main，提交只落本地，不 push。
