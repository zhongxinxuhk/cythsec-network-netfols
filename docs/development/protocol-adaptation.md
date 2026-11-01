# 协议适配状态维护

状态真源：configs/registry/protocol-adaptation.json；对象名称与既有实现声明沿用vpn-protocols.json。
流程要求以[AGENTS.md](../../AGENTS.md)的协议适配状态记录为准。
生成表：[ADAPTATION-STATUS](../protocols/ADAPTATION-STATUS.md)；
按层视图：[ADAPTATION-STATUS-BY-LAYER](../protocols/ADAPTATION-STATUS-BY-LAYER.md)；
OSI 规划：[protocol-osi-classification](../planning/protocol-osi-classification.md)。
268项目录对象与24项基础/补充核验共292行，其中存在同协议不同能力范围，
不能称作292种独立协议或全部全球协议。清单自 schema_version 2 起增加 OSI 分类字段。

每行单独维护implemented、local_tested、reference_tested、accepted。前三列为范围内的分步记录，最后一列才表示完整适配。
accepted要求前三项为true、范围明确、证据存在且缺口为空；当前不把有界首帧、候选承载、可信上下文或产品资料当完整线路识别。
端口、加密外层、目录父子关系或共同解析器都不能自动完成其他条目。

## OSI 分层字段

现有 `vpn-protocols.json` 的 `layer` 是目录轴（tunnel/overlay/product/transport/identity），不是 OSI 层。
适配清单保留该轴，另设以下字段，避免把产品、隧道和单一协议强行压成一层：

| 字段 | 取值 | 含义 |
| --- | --- | --- |
| `osi_layer` | `L1`…`L7`、`cross-layer`、`non-osi` | 唯一主层，不重复计数 |
| `osi_sublayer` | 字符串 | 子层或承载关系，如 `L2.5`、`L3-encap`、`L5-L6`、`L2-over-L3/L4` |
| `osi_role` | `base`、`encapsulation`、`control`、`security`、`session`、`application`、`identity`、`proxy`、`transform`、`product`、`crypto` | 协议在层内的角色 |
| `encap_chain` | `Lx:名称` 数组 | 可见封装路径；不表示已解析内层或已建立内层流 |
| `uses_layers` | `L1`…`L7` 数组 | 仅 `non-osi` 产品/变换/密码使用，表示受影响层 |

分类规则：

- ARP 记 `L2`、子层 `L2.5`；ICMPv4/ICMPv6 记 `L3` 控制；GRE、IP-in-IP、IPsec AH/ESP 记 `L3` 封装/安全。
- VXLAN/Geneve 主层 `L2`，`encap_chain` 明确经过 L3/L4；WireGuard/AmneziaWG 主层 `L3`、UDP 承载。
- TLS/DTLS/TLCP 主层 `L5`，L6 只记 record、证书、密码套件属性；QUIC 主层 `L4`，HTTP/3 主层 `L7`。
- SOCKS 记 `L5` 代理；HTTP CONNECT/MASQUE 记 `L7` 代理；OpenVPN/SSTP/AnyConnect 等按跨层链记录。
- 厂商产品 C/F、混淆/变形 O、SM2/SM3/SM4 及产品子项记 `non-osi`，只做上下文证据，不进入七层覆盖率分子。
- L1 当前只做 linktype/介质/速率元数据，不假装从 pcap 解码 PHY；L6 当前无独立主层条目。

`cross-layer` 必须有至少两段 `encap_chain`，且角色只能是封装或代理；`non-osi` 必须有
非空 `uses_layers`、不得声明封装链，角色只能是产品、变换或密码。OSI 行不得携带
`uses_layers`。这些约束由生成器机械检查，不靠文档约定。

修改步骤：

1. 核对该ID的代码、样本、负例、截断/未知/预算语义及输出契约，写明支持范围和缺口。
2. 实跑对应测试与独立对照，把命令、实际退出码、环境、证据路径记入验收记录；有例外不勾独立对照完成。
3. 更新该行状态及code/tests/reference引用，运行生成器；不直接编辑生成表中的勾选。
4. 完整lint/test通过才满足仓库合入前提；跳过项仍为未核验，不使用清单计数替代门禁。

```bash
python3 tools/codegen/gen-protocol-adaptation.py
python3 tools/codegen/gen-protocol-adaptation.py --check --self-test
```

生成器检查ID覆盖/唯一性、目录版本、布尔状态、路径/测试符号、完成条件及 OSI 字段约束，并有12项反向注入自证。
它验证的是记录一致性，不会仅凭文件存在推断运行通过；运行证据必须按步骤2实际取得。
生成检查已接完整lint和Rust测试；DNS/TCP CLI回归进入Rust组，tshark独立对照进入默认全集。

本轮DNS/TCP仅支持连续前缀的首个长度帧，使用现有DNS有界字段解析。补齐两字节长度、严格帧边界、
粘连只取首帧、未完整帧保持NeedMore、帧内问题段不足不能借后帧修复。
依据：[RFC7766](https://www.rfc-editor.org/rfc/rfc7766.html#section-8)。
主流水线已接入：TCP 53上按SYN锚定的有界前缀重组（4096字节/64段/1024流/30秒空闲），乱序、重传、回绕、冲突与缺尾均有显式状态；无锚点单包保留medium弱判定。持久连接多帧事务、大消息超预算与真实语料仍待开发/验收，完整适配保持未勾。

此表只记录现状和通用解析工作；本轮没有新增公众规避审查协议指纹、主动探测或封锁实现。
本轮验收见[记录](../planning/protocol-adaptation-verification.md)。

基础/补充项顺序接B014推进B015 DHCPv4，本轮范围、测试与未完成项见
[B015验收记录](../planning/protocol-b015-dhcpv4-verification.md)。门禁退出码单独实跑，
不沿用上轮DNS/TCP结果；DHCPv4详细字段尚未进入FlowRecord，完整适配保持未勾选。

下一项B016 DHCPv6的有界消息、中继与IA选项识别见
[B016验收记录](../planning/protocol-b016-dhcpv6-verification.md)。使用当前RFC 9915，DUID按不透明标识保存；
完整事务、明细输出与真实语料验收仍有缺口，不沿用B015门禁结果。

B017 mDNS的多问题、主动响应、DNS-SD常见记录及UTF-8名称解析见
[B017验收记录](../planning/protocol-b017-mdns-verification.md)。双端口上下文通过兼容的DPI入口传入，
普通DNS名称归一化保持原契约；链路本地性、缓存/冲突状态和明细输出仍未完成。

B018 DoT在显式TLS应用明文入口中解析长度帧，见[B018验收记录](../planning/protocol-b018-dot-verification.md)。
调用方声明来源/会话/方向，受控TLS1.2/1.3字节与tshark对照不替代生产数据源或认证。
普通pcap入口不凭853、SNI或ALPN把TLS升级为DoT；完整适配保持未勾选。

B019 DoH对调用方提供的完整、已解码HTTPS消息校验GET/POST/2xx DNS表示，见
[B019验收记录](../planning/protocol-b019-doh-verification.md)。不凭443/路径推断应用，不把该接口等同HTTP/2/3帧解码。
本轮在原始项目目录经CLion MCP构建/验证，来源绑定、完整事务与流记录接线仍有缺口。

B020 SMTP在TCP 25/587/2525的明文上下文里判定首条命令或一条多行应答，见
[B020验收记录](../planning/protocol-b020-smtp-verification.md)。只取第一条消息，
不解析DATA正文、AUTH凭据或投递结果；465隐式TLS不在明文端口内，裸应答只给medium。
端口只做路由，FTP端口上的同名问候不得命中；完整适配保持未勾选。

B021 FTP在TCP 21/2121的明文控制通道里判定首条命令或一条应答，见
[B021验收记录](../planning/protocol-b021-ftp-verification.md)。FTP多行应答是
"首行code-、末行code SP、中间任意文本"，不能套用SMTP的逐行同码规则；PASS实参不保留。
990隐式FTPS与AUTH TLS之后的TLS交给TLS检测器，完整适配保持未勾选。

B014 主流水线重组的端到端证据（乱序分片、缺尾、冲突、无锚点与端口上下文）见
[B014验收记录](../planning/protocol-b014-dns-tcp-pipeline-verification.md)。
本轮不改变单包长度帧契约，只把“已接入”这件事钉在流水线测试与 tshark 重组对照上。

B022 的 IPFIX v10 验收边界需要单独说明：清单登记的是**报文编码/解码与采集口径**，
不是把 IPFIX 标成某个 `AppId`。导出的 tshark 交叉核验、采集回路的丢包率手算、
异厂独立实现的 5 个场景与反向注入见
[B022验收记录](../planning/protocol-b022-ipfix-verification.md)。

B023 NetFlow v9 已按 RFC 3954 落地到独立采集器：模板/数据流集、选项模板跳过、
21/22 号时标换算，以及**导出报文级**序号缺口。它与 IPFIX 的关键差别是序号单位
（v9 报文序号 vs v10 数据记录累计数），不能互相代替；独立语料与 tshark 对照见
[B023验收记录](../planning/protocol-b023-netflow9-verification.md)。

B024 sFlow v5 已按 RFC 3176 落地到独立采集器：自描述 flow/counter sample、raw header/
IPv4/IPv6/extended switch、接口与 VLAN 计数，以及**数据报级**序号缺口。它没有模板，
序号单位也与 IPFIX（记录累计数）和 NetFlow v9（导出报文序号）不同；独立语料与
tshark 对照见 [B024验收记录](../planning/protocol-b024-sflow-verification.md)。

B004 ARP 已在声明范围内完成验收：以太网（最多两层 802.1Q/QinQ）、Linux SLL/SLL2、
ARP/RARP 及扩展操作码有界解析，见[B004验收记录](../planning/protocol-b004-arp-verification.md)。
ARP 没有 IP 五元组，主流水线只做帧级统计，详细字段走独立 `cythsec-arp` JSONL；
不主动探测、不推断邻居缓存/在线状态。

B011/B012 ICMPv4/ICMPv6 与 V009 GRE/mGRE 也已在声明范围内完成验收：ICMP 校验
checksum（仅在调用方确认完整载荷时）、echo/错误内嵌头、NDP 选项内容、MLD v1/v2；
GRE 校验 checksum、SRE 列表、MPLS 标签栈与 ERSPAN II/III 标注。独立采集器输出
报文级 JSONL，主流水线只做统计；不把内层 IP 拆成新流、不执行 SRE 源路由、不推断
mGRE 拓扑或隧道对端状态。范围与证据见
[ICMP/GRE验收记录](../planning/protocol-b011-b012-v009-verification.md)。
