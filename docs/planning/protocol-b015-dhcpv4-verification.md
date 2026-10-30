# B015 · DHCPv4 流量识别验收

日期：2026-10-29；基线：`b8f5cf6`；分支：`feat/protocol-b015-dhcpv4`。
按用户确认，接上轮 B014 DNS/TCP，继续基础/补充清单 B015 DHCPv4。
V001 的独立分支及原工作区尚未提交的 DNS/TCP 重组改动均未混入本分支。

## 已实现范围

1. 新增零依赖 `dpi/dhcp.rs`，解析 BOOTP 固定头、magic cookie、option 53 消息类型和 END。
   识别要求结构证据，端口 67/68 不单独触发命中；支持端口漂移。
2. 支持 RFC 2131 的 Discover、Offer、Request、Decline、ACK、NAK、Release、Inform 八种基础消息，
   校验 BOOTREQUEST/BOOTREPLY 与消息类型一致、硬件地址长度不超过 16。
   未支持的扩展消息类型保持 Unknown；只有 BOOTP cookie 而没有 DHCP 消息类型不会命中 DHCPv4。
3. 提取事务 ID、硬件类型/声明地址、ciaddr/yiaddr/siaddr/giaddr、请求地址、服务器标识、租期、
   主机名、vendor class、client identifier。后三项保留原始字节，不推导实际设备、厂商、用户或地址归属。
   `siaddr` 与 DHCP server identifier 分开保存；ACK 本身不证明客户端已经应用租约。
4. 选项按 TLV 扫描，支持 PAD、END、未知选项跳过、overload 的 file/sname 区域，
   重复选项按 RFC 3396 的 options→file→sname 顺序拼接再校验固定宽度。
   固定区域不能借后续区域补齐越界选项，也不递归展开 overload。
5. 每次解析最多 4096 字节、256 个非 PAD/END 选项；预算不足为 NeedMore，
   不伪装 Unknown 或完整解析。短包、缺 END/未到齐的主选项值为 NeedMore，
   内部矛盾、固定字段越界与重复拼接后的非法宽度为 Malformed。
6. 仅 UDP 进入 DHCPv4 检测。已读到合法 cookie 后的解析失败不会借 TLS/HTTP/DNS 得出另一个应用命中。
   流水线保留 UDP 长度边界；IP/Ethernet 尾部字节不能补足 DHCP 选项。
   初始 IP 分片与捕获截断不形成 DHCPv4 命中，非初始分片维持解码层拒绝。
7. 新增稳定 AppId：内置命名空间序号 24，名称 `dhcpv4`；正常分析 CLI 输出应用标识和识别状态。
   详细解析字段暂未写入 FlowRecord/持久化契约，当前不能通过分析 CLI 取得这些字段。

依据：[RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html)、
[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html)、
[RFC 3396](https://www.rfc-editor.org/rfc/rfc3396.html)。
本轮是有界可见报文识别，不宣称完整租约事务状态机、全部扩展选项或生产环境精度。

## 实跑记录

环境：macOS，Rust 1.97.1；独立参考为本机 Wireshark/tshark。
本地证据：`build/protocol-b015/`；日志不纳入源码提交。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| DHCPv4 单测 | `cargo test --offline -p traffic-engine --lib dpi::dhcp` | 退出 0，3 项；全部前缀截断点、八种类型、字段、传输限制、拼接顺序、边界及预算 |
| Rust 库回归 | `cargo test --offline -p traffic-engine --lib` | 退出 0，460 项通过；`rust-lib.log` |
| CLI / tshark | `bash scripts/verify/check-dhcpv4.sh --tshark` | 退出 0，11 正例/25 负例及检查预算；`dhcp-reference.log` |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 实际退出 0；`lint.log` / `lint.exit` |
| 默认完整测试 | `CYTHSEC_LIVE_SUDO=0 CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 实际退出 0；`test-all.log` / `test-all.exit`；含既有跳过项，不算完整全绿 |
| 前端既有回归 | 默认全集内执行 | 25 个文件、93 项通过；本轮未修改前端 |
| en0 现场采集回归 | 默认全集内执行，无 sudo | 212 帧，210 解析成功/2 不支持/0 错误；15 项断言通过。无注入目标，ICMP 可见项不适用 |

默认全集仍有既有独立对照跳过：DPI 14 项（非 identified 或已知例外）、TCP 重组 2 项、
FlowRecord 8 项。均保留为未核验，不把脚本末尾的“全部通过”升级为无缺口验收。
现场环境流量回归不等于捕获到了真实 DHCPv4，也不替代 DHCPv4 设备/中继语料验证。
据此本分支仅本地提交，不合入 main、不 push。

CLI 正例包括八种基础类型、relay 的 67→67、端口漂移和 overload；基础类型在单 worker 与双 worker 下输出一致。
tshark 核对事务 ID、消息类型、请求 IP、服务器标识、租期、主机名和 overload 拼接结果；
Rust 单测对相同字段值进行显式断言。CLI 明细字段尚未输出，独立字段对照不冒充 FlowRecord 明细交付。
负例包含短包、坏 cookie、BOOTP、未知消息、错误 op/hlen、重复消息类型、错误定宽选项、TCP、
UDP 长度矛盾、捕获不足、IP 分片、固定 overload 区越界。原始字节构造可由脚本复跑。

`check-dhcpv4.sh` 接入 Rust 组，带 `--tshark` 的独立对照接入默认全集；tshark 缺失返回 3。
Python 检查代码纳入 Ruff/Black 清单。登记状态与生成表随实现同批提交。

## 未完成项

详细字段的 FlowRecord/存储输出、完整租约事务关联、重传/租约状态、全部 DHCP 扩展消息及选项、
IP 分片重组、真实设备/中继语料、误报/召回与资源规模、Linux 运行矩阵均未完成。
广播事务不能只依赖五元组判断租约已经建立；客户端声明字段不视为受管资产事实。
本轮使用离线合成 PCAP，没有发送 DHCP Discover/Offer 或修改主机地址配置。
故 B015 的实现、本地测试、独立对照分别记录，完整适配保持未勾选。
两条门禁全绿且无未核验项之前不合 main；只保留本地提交，不 push。

## CI reference compatibility repair (2026-10-30)

Ubuntu's tshark reports overloaded hostname options as separate `c,b,a` display occurrences; newer
tshark reassembles `abc`. The independent check now orders the three decoded TLVs by RFC 3396's
options/file/sname regions using PDML positions, and checks both the raw fragment bytes and displayed
values against the same hostname. It does not sort hostname characters or accept arbitrary permutations
as the assembled value. Parser behavior and acceptance status are unchanged.
