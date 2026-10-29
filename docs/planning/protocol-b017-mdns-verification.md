# B017 · mDNS 有界流量识别验收

日期：2026-10-29；基线：`978391e`；分支：`feat/protocol-b017-mdns`。
按基础/补充清单接 B016 推进 B017，复用当前工作区，不覆盖 B015/B016 专项证据目录。
本轮交付 mDNS 服务上下文中的有界消息识别，完整适配保持未勾选。

## 实现范围与边界

- 新增 `dpi/mdns.rs`，解析 DNS 头、多问题、无 Question 的主动响应、Answer/Authority/Additional 记录。
  支持原始 ID、QR/AA/TC、QU 问题位、cache-flush 记录位及去掉高位后的 class；保留 TTL=0，
  不直接执行缓存删除或把记录声明升级为设备事实。按接收语义忽略非关键头标志，不把 AA 当作认证。
- 支持 A、AAAA、PTR、CNAME、SRV、TXT；保留 SRV 优先级/权重/端口/目标，TXT 为不透明字符串字节列表。
  其他记录保留有界原始 RDATA，不宣称已解释 NSEC/EDNS 或所有 DNS-SD 扩展语义。
  OPT class 保留原始值，不误当普通记录 class/cache-flush。
- 复用 `dns.rs` 的名称压缩核心。普通 DNS 保留原 ASCII 小写归一化契约；mDNS 分支支持 UTF-8、
  保留显示大小写，对标签内的点、反斜线和控制字符使用十进制字节转义，避免混淆标签边界。
  mDNS 名称包含根标签最多 255 字节，标签最多 63 字节；限制压缩跳数并拒绝头部、自指/前向指针。
  不做 Unicode 归一化、名称所有权或资产身份确认。
- PTR/CNAME/SRV 名称受本条 RDLENGTH 限制，不能从相邻 RR 借字节修复；TXT 字符串必须留在本条 RDATA 内。
  消息受 8192 字节、合计 64 个 Question/RR、全消息 128 个 TXT 字符串预算约束。
  预算不足为 NeedMore，结构矛盾为 Malformed，不支持的 OPCODE/RCODE 或空消息为 Rejected/Unknown。
- 新增 `identify_with_ports`，保留原有 `identify` API。UDP 目的端口 5353 的查询/响应，
  以及源端口 5353 且 QR=1 的 legacy 单播响应进入 mDNS 结构检测。只看到端口不会产生命中，
  `.local` 名称在普通 DNS 端口上不会升级为 mDNS。未对任意端口上的 DNS 消息推断 mDNS。
- 流水线带入双端口上下文，并复用 UDP 声明长度检查。初始 IP 分片、捕获截断、未覆盖完整数据报的
  检查预算均保持 NeedMore；非初始分片继续由解码层拒绝。不能借 IP/Ethernet 尾部字节补齐消息。
- 新增稳定内置 AppId 26（65562），CLI 输出 `app=mdns`，置信度 medium。
  这是合法消息与服务上下文的结构候选，未验证多播目的地址、链路/接口或 TTL/hop-limit 的本地性。
  mDNS 与普通 DNS 共享报文格式；相同服务端口上的其他合法 DNS 实现不能仅凭此解析器完全区分。

依据：[RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html)、
[RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html)。
DNS-SD 声明只表明报文携带服务数据，不能证明目标可达、服务正在运行、设备型号或操作者身份。
详细问题/记录字段尚未写入 FlowRecord/存储；当前 CLI 只交付应用标识、状态及必要判据。

## 实跑记录

环境：macOS / Rust 1.97.1 / 系统 Python 3.9 / 本机 tshark。
本轮专项使用离线合成 PCAP，不发送 mDNS 查询、公告、冲突探测或缓存更新。
证据目录：`build/protocol-b017/`，后续默认门禁的通用采集产物另存 `live-capture/`。

| 检查 | 命令 | 结果 |
| --- | --- | --- |
| mDNS 专项 | `cargo test --offline -p traffic-engine --lib dpi::mdns` | 初次退出 0，4 项；最终改动由下行库全量覆盖 |
| Rust 库全量 | `cargo test --offline -p traffic-engine --lib` | 退出 0，468 项；含原 DNS 与新增 mDNS 回归；`rust-lib.log` |
| CLI / tshark | `bash scripts/verify/check-mdns.sh --tshark` | 修正核验脚本兼容问题后退出 0；25 正例/48 负例及预算测试；`mdns-reference-final.log` |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 实际退出 0；`lint.log` / `lint.exit` |
| 默认完整测试 | `CYTHSEC_LIVE_SUDO=0 CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 实际退出 0；`test-all.log` / `test-all.exit`，含既有未核验项，不算完整全绿 |
| 前端既有回归 | 默认全集内执行 | 25 文件、93 项通过；本轮未修改前端 |
| en0 通用采集 | 默认全集内执行，不使用 sudo | 6764 帧：6699 解析成功、65 不支持、0 错误；15 项断言通过，Rust 环链路核对前缀 500 帧/19 Flow |

既有独立对照跳过仍为 DPI 14 项、TCP 重组 2 项、FlowRecord 8 项，均保留未核验，
不因脚本退出 0 升级为无缺口验收。本轮只本地提交，不合入 main、不 push。
现场采集无注入目标，ICMP 可见项不适用；通用采集结果不替代 mDNS 真实设备/服务语料验收。
通用采集产物已复制到 `build/protocol-b017/live-capture/`，避免后续门禁覆盖。

独立对照核对 QU、cache-flush、class、IPv4/IPv6 地址、PTR/SRV/TXT、TTL、记录计数、ID 和 UTF-8 名称。
单/双 worker 输出一致。负例覆盖全部最小查询截断点、普通 DNS/其他端口、TCP、坏指针、坏 RDATA、
TXT 越界、空消息、非零 OPCODE/RCODE、UDP 长度矛盾、捕获不足、IP 分片。
名称循环、RDLENGTH 父边界及 Question/RR/TXT/字节预算还由专项单测覆盖。

初次独立对照退出 1：本机 tshark 的布尔字段输出 True/False，而脚本预期 1/0。
修正中又检出系统 Python 3.9 不支持 `zip(strict=True)`，以及 TC 字段同样需要布尔格式归一化，均退出 1。
仅对已知布尔字段做显式转换，字段数必须精确匹配；没有跳过字段或放宽业务期望值。
失败日志 `mdns-reference.log`、`mdns-reference-python39.log`、`mdns-reference-tc-boolean.log` 原样保留。

`check-mdns.sh` 接入 Rust 组；带 `--tshark` 的独立对照接入默认全集，缺工具返回 3。
Python 核验脚本进入 Ruff/Black 支持清单；状态真源和生成表同批提交。

## 未完成项

完整多播/链路上下文验收、名称探测/冲突处理、Known-Answer 抑制、缓存/TTL/服务生命周期、
全部记录语义、明细输出/存储、IP 重组、真实设备/服务语料、误报/召回/规模与 Linux 矩阵未完成。
本轮不因复用 DNS 解析核心或通过合成样本就勾选完整适配；两条门禁实际退出码和未核验项分别记录。
未全绿不合 main，提交只落本地，不 push。
