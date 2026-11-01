# 流量协议 OSI 分层与适配规划

## 1. 目的与边界

本文把 `configs/registry/protocol-adaptation.json` 中的 292 行按 OSI 七层分类，
并给出后续适配顺序、验收门槛和 registry 维护规则。

这里的“分类”是工程分类，不是把每个产品、隧道或混淆技术强行塞进单一层：

- 一行只有一个主层，避免重复计数；
- 跨层封装单独记为 `cross-layer`，用封装链表示经过的层；
- 厂商产品、混淆变换和密码原语记为 `non-osi`，只做上下文证据；
- 现有 `vpn-protocols.json` 的 `layer` 轴保留，不替换成 OSI；
- 不进行主动探测，不推断主机存活、邻居缓存、拓扑或隧道对端状态。

本文不把“目录里有条目”当成“已适配”，也不把产品资料、端口、证书或外层承载当成线路识别。

## 2. 分类模型

适配清单自 `schema_version=2` 起增加以下字段：

| 字段 | 取值 | 说明 |
| --- | --- | --- |
| `osi_layer` | `L1`…`L7`、`cross-layer`、`non-osi` | 唯一主层 |
| `osi_sublayer` | 字符串 | 子层/承载关系，如 `L2.5`、`L3-encap`、`L5-L6`、`L2-over-L3/L4` |
| `osi_role` | `base`、`encapsulation`、`control`、`security`、`session`、`application`、`identity`、`proxy`、`transform`、`product`、`crypto` | 层内角色 |
| `encap_chain` | `Lx:名称` 数组 | 可见封装路径；不表示已解析内层或已建立内层流 |
| `uses_layers` | `L1`…`L7` 数组 | 仅 `non-osi` 行使用，表示受影响层 |

硬约束由 `tools/codegen/gen-protocol-adaptation.py` 检查：

- `cross-layer` 至少两段 `encap_chain`，角色只能是封装或代理；
- `non-osi` 必须有非空 `uses_layers`、不得声明封装链，角色只能是产品、变换或密码；
- OSI 行不得携带 `uses_layers`；
- 每行必须有主层、子层和角色，证据路径/测试符号仍按原规则校验。

### 2.1 主层判定

| 对象 | 主层 | 子层/角色 | 说明 |
| --- | --- | --- | --- |
| Ethernet II、802.1Q、802.1ad | L2 | L2 / base | 帧与 VLAN |
| ARP/RARP | L2 | L2.5 / control | 链路层地址解析，不是 L3 |
| PPP、EAP | L2 | L2 / encapsulation、control | L2 封装与认证 |
| IPv4、IPv6、扩展头、分片 | L3 | L3 / base | 分片重组仍属 L3 |
| ICMPv4/ICMPv6 | L3 | L3 / control | NDP/MLD 是 ICMPv6 子能力 |
| GRE、IP-in-IP、IPsec AH/ESP | L3 | L3-encap / encapsulation、security | 不递归解析内层 IP |
| WireGuard、AmneziaWG | L3 | L3-over-L4 / encapsulation | UDP 承载，但主层是 L3 |
| VXLAN、Geneve | L2 | L2-over-L3/L4 / encapsulation | 链中明确出现 L3/L4 和内层 Ethernet |
| TCP、UDP | L4 | L4 / base | 端口、状态、重组 |
| QUIC v1/v2 | L4 | L4 / base | 内建 TLS，但不归 L7 |
| TLS、DTLS、TLCP | L5 | L5-L6 / security | L6 只记 record/证书/密码套件属性 |
| SSH | L5 | L5 / session | 传输/认证/连接层不混成一个判定 |
| IKEv1/IKEv2 | L5 | L5 / security | IPsec 控制面 |
| SOCKS4/5 | L5 | L5 / proxy | 会话协商，不是 L7 内容 |
| STUN/ICE | L5 | L5 / control | 候选与连通性协商 |
| HTTP/1.1、HTTP/2、HTTP/3 | L7 | L7 / application | HTTP/3 依赖 QUIC，但本身是 L7 |
| WebSocket、gRPC | L7 | L7 / application | 有界首消息/帧边界 |
| HTTP CONNECT、MASQUE | L7 | L7 / proxy | 代理控制，不把隧道内容当新协议 |
| RADIUS、LDAP、Kerberos、SAML、OIDC、FIDO2 等 | L7 | L7 / identity | 认证/身份协议 |
| OpenVPN、SSTP、AnyConnect、GlobalProtect 等 | cross-layer | 封装 | 控制信道与数据信道分开记录 |
| 厂商产品 C/F、O 变换、SM2/SM3/SM4 | non-osi | product、transform、crypto | 只做资产/上下文证据 |

### 2.2 不这样归类

- 不因为使用 443/tcp 就判成 TLS 或 HTTP；
- 不因为外层是 UDP 就把 WireGuard 判成 L4；
- 不因为 HTTP/3 使用 QUIC 就把 QUIC 判成 L7；
- 不把 IPsec 的 IKE 控制面和 ESP 数据面合成一行；
- 不把 VXLAN/Geneve 只记成 L2 或只记成 L4，必须保留封装链；
- 不把产品名、品牌、证书 CN、SNI 或端口当成协议指纹；
- 不把 `cross-layer` 或 `non-osi` 计入七层覆盖率分子。

## 3. 当前盘点

截至 `2026-11-02.1`，清单共 292 行：268 项目录对象 + 24 项基础/补充核验项。
目录原有 `layer` 轴仍为 tunnel 118、product 64、overlay 46、transport 26、identity 14，
它与 OSI 主层不是同一维度。

| 主层 | 条目 | 实现审查 | 完整适配 | 当前口径 |
| --- | ---: | ---: | ---: | --- |
| L1 物理层 | 0 | 0 | 0 | 只做链路/介质/速率元数据，不做 PHY 解码 |
| L2 数据链路层 | 14 | 6 | 3 | B001-B004、A013-A014、V006/V008/V012-V015、X005-X006 |
| L3 网络层 | 18 | 7 | 4 | B005-B008/B011-B012、V001/V002/V009-V011/V021-V022、X001-X004/X015 |
| L4 传输层 | 4 | 2 | 0 | B009-B010、T007-T008 |
| L5 会话层 | 20 | 3 | 0 | TLS/DTLS/SSH/IKE/SOCKS/STUN 等 |
| L6 表示层 | 0 | 0 | 0 | 无独立主层；TLS record/密码属性由 L5 行承载 |
| L7 应用层 | 43 | 13 | 0 | DNS/DHCP/邮件/FTP/采集器/HTTP/身份/代理控制 |
| 跨层隧道/代理 | 72 | 0 | 0 | VPN/代理/隧道链，不递归建内层流 |
| non-OSI 产品/变换/密码 | 121 | 0 | 0 | C/F 产品、O 变换、T/SM 密码原语 |
| 合计 | 292 | 31 | 7 | 跨层与 non-OSI 不计入七层分子 |

当前完整适配仍只有 7 行：`B004`（ARP）、`B008`（IPv4/IPv6 分片重组）、
`B011`/`B012`（ICMPv4/ICMPv6）、`V009`（GRE/mGRE）、`V014`（VXLAN）、
`V015`（Geneve）。
这说明基础 L2/L3 已经打通，但 L4 以上、跨层隧道和产品上下文仍主要是“已登记未验收”。

### 3.1 各层缺口

- **L1**：目录没有 L1 条目。后续只新增采集元数据契约（linktype、介质、速率、无线信道），不承诺从 pcap 还原 PHY。
- **L2**：ARP、VXLAN、Geneve 已验收；PPP/EAP、L2TP/PPTP/L2TPv3/EtherIP、L2TPv3 UDP/IP 尚未实现。LLDP、STP/RSTP、MACsec、802.1X/EAPOL 还不在目录内，需要先决定是否纳入范围。
- **L3**：IPv4/IPv6/扩展头、ICMP、GRE 已实现，其中 ICMP/GRE 已验收；B008 分片重组已完成验收；IPsec ESP/AH、NAT-T、IP-in-IP、IPv6-in-IPv4、WireGuard/AmneziaWG 未实现。OSPF/BGP/IS-IS 等路由协议不在 292 行内，若不纳入必须在 scope 明确排除。
- **L4**：TCP/UDP 已实现；QUIC v1/v2 未实现。SCTP、UDP-Lite 未入目录，按业务场景决定是否新增。
- **L5**：TLS 1.2/1.3/TLS family 已实现；DTLS、SSH、IKE、STUN/ICE、SOCKS、mTLS、会话恢复、TLCP/国密套件未实现或未验收。L5 需要握手状态机，不能只做首包魔数。
- **L6**：不单独造协议。TLS record、证书、密码套件、ASN.1/序列化边界作为 L5 或 L7 行的属性记录，避免重复计数。
- **L7**：DNS/DHCP/邮件/FTP/采集器和 HTTP/1.1 已实现；HTTP/2、HTTP/3、WebSocket/gRPC、RADIUS/TACACS+/LDAP/Kerberos/SAML/OAuth2/OIDC/CAS/FIDO2/WebAuthn/OTP、HTTP CONNECT/MASQUE 未实现或未验收。
- **跨层**：OpenVPN、SSTP、AnyConnect、GlobalProtect、SoftEther、Shadowsocks/VLESS/Trojan/Hysteria 等 72 行没有实现验收。必须先定义控制信道/数据信道和 `encap_chain`，再谈识别。
- **non-OSI**：C/F 产品、O 变换、SM2/SM3/SM4 共 121 行没有线路适配。它们只能做资产/证书/域名/端点上下文，不能从端口或品牌推断产品身份。

## 4. 分批路线

### P0：分类基线（本批）

范围：

- registry 增加 `osi_layer`、`osi_sublayer`、`osi_role`、`encap_chain`、`uses_layers`；
- 292 行全部填主层，跨层/非 OSI 单独成组；
- 生成器增加按层汇总和逐层视图；
- 生成器增加 12 项反向注入自证；
- 不新增任何协议解析器。

完成标准：

- 292/292 行有合法主层、子层、角色；
- 跨层行有封装链，non-OSI 行有 `uses_layers`；
- `gen-protocol-adaptation.py --check --self-test` 通过；
- 现有 `ADAPTATION-STATUS.md` 与新增按层视图都由 registry 生成。

### P1：L1-L3 基础正确性

1. L1 元数据契约：linktype、介质、速率、无线信道；未知值保留 `unknown`。
2. L2：PPP/EAP、L2TP/PPTP/L2TPv3/EtherIP；VXLAN 已完成 V014，Geneve 已完成 V015；每项单独分支。
3. L3：IPsec ESP/AH、NAT-T、IP-in-IP、IPv6-in-IPv4、WireGuard/AmneziaWG。
4. 视范围决定是否新增 LLDP/STP/MACsec/802.1X 与 OSPF/BGP/IS-IS；不纳入就写入 scope 排除。

完成标准：

- 每项有界解析、截断/未知/畸形语义；
- 分片不伪造完整内层流；
- IPsec/GRE/VXLAN 只输出外层与可见内层头，不递归建流；
- tshark 独立对照、真实语料、Linux 矩阵按行记录。

### P2：L4-L5 传输与会话

1. QUIC v1/v2：版本、连接 ID、包类型、Initial/Handshake 边界；不把 QUIC 内部 TLS 当 L7。
2. 按需补 SCTP/UDP-Lite。
3. TLS/DTLS、SSH、IKE、STUN/ICE、SOCKS、mTLS/会话恢复/TLCP/国密套件。
4. 引入会话状态机：握手阶段、版本协商、重传/乱序、关闭；无密钥不解密。

完成标准：

- 首消息之外能表达握手状态；
- 截断、重传、乱序、未知版本有显式状态；
- 不把“端口 443”或“证书 CN”当作 TLS 身份结论。

### P3：L7 应用与身份

1. HTTP/2、HTTP/3、WebSocket/WSS、gRPC：帧/流边界优先。
2. RADIUS、TACACS+、LDAP/LDAPS、Kerberos、SAML、OAuth2、OIDC、CAS、FIDO2/WebAuthn、OTP。
3. HTTP CONNECT、HTTP/2 CONNECT、MASQUE：只做控制消息，不把隧道内容当新协议。
4. DNS/DHCP/邮件/FTP/采集器保持现有已验收边界，不回退。

完成标准：

- 有界首消息/帧，方法、状态码、结果码可区分；
- 不保留口令、令牌、完整证书私密字段；
- 加密应用只在调用方声明的明文/已解密上下文工作。

### P4：跨层隧道与代理

1. OpenVPN、SSTP、SoftEther、OpenConnect、AnyConnect、GlobalProtect、FortiClient、Ivanti、F5、Juniper、Check Point。
2. Shadowsocks/VLESS/Trojan/Hysteria/TUIC/AnyTLS/NaiveProxy 等代理族。
3. 每行明确控制信道、数据信道、外层承载、内层协议和 `encap_chain`。

完成标准：

- 外层/内层分离，内层不自动创建 `FlowRecord`；
- 端口/证书/SNI 不能单独确认产品；
- 不推断隧道对端状态、拓扑或 NAT 穿透成功。

### P5：non-OSI 产品/变换/密码

1. C/F 产品：资产、证书、域名、端点上下文；不生成字节指纹。
2. O 变换：描述作用位置和可见影响，不把变换当协议。
3. SM2/SM3/SM4：密码原语元数据，由 L5/L6 行引用，不参与层覆盖。

完成标准：

- 负样本充分、误报可解释；
- 只输出上下文证据等级，不把资料声明写成线路识别；
- 不把产品条目计入 OSI 覆盖率。

## 5. 依赖关系

```text
L1 链路元数据
  └─ L2 帧/VLAN/ARP/PPP/隧道
       └─ L3 IPv4/IPv6/分片/ICMP/IPsec/GRE
            └─ L4 TCP/UDP/QUIC
                 └─ L5 TLS/DTLS/SSH/IKE/STUN/SOCKS
                      └─ L6 record/证书/密码属性
                           └─ L7 HTTP/DNS/DHCP/认证/采集器
                                └─ 跨层隧道/代理链
                                     └─ 产品/混淆上下文
```

正确性轨道按 L1→L2→L3→L4→L5 推进；业务可见性轨道可在 L4 稳定后并行 L7。
跨层隧道必须在 L2-L5 基础稳定后做，否则容易把“外层识别”误当成“隧道识别”。

## 6. 验收门槛

| 层/类 | 必须证明 |
| --- | --- |
| L1 | linktype/介质/速率元数据正确；未知值不猜 |
| L2 | 帧边界、VLAN/封装、截断/畸形；不伪造 FlowRecord |
| L3 | 头长度、分片、校验和、内嵌头；不推断拓扑 |
| L4 | 端口/状态/重组；QUIC 加密边界 |
| L5 | 握手状态、版本、会话关联；无密钥不解密 |
| L6 | record/编码/证书边界；密码原语只做元数据 |
| L7 | 有界首消息、方法/状态/结果码；不保留敏感载荷 |
| 跨层 | `encap_chain` 完整；内外层分离；内层不自动建流 |
| non-OSI | 只做上下文/资产证据；不从端口/证书推断产品 |

每行仍按 `implemented`、`local_tested`、`reference_tested`、`accepted` 四个独立状态记录。
`accepted=true` 必须同时满足前三项、scope 明确、证据存在且 `gap` 为空。

每层至少需要：

- RFC/规范合成语料；
- tshark 或独立实现对照；
- 截断、未知、畸形、超预算负例；
- 反向注入，证明检查器不是恒绿；
- 真实抓包或受管环境样本；
- `lint-all.sh` 与 `test-all.sh` 实际退出码为 0。

## 7. 维护规则

- 新增协议先写 scope 和 gap，再写实现；不要把“有目录项”当成“已适配”。
- 修改 `osi_layer`/`osi_role`/`encap_chain` 必须同批更新生成视图。
- 跨层链只列可见封装路径；没有解析到的内层不得补写。
- 产品/混淆/密码行不得为了凑覆盖率改成 L4/L7。
- 一处协议一个分支；完成门禁后 `--no-ff` 合入 `main`，不 push。

B008 分片重组已完成并验收；下一步从 L2 隧道族开始，再做 L3 IPsec/隧道。L2/L3 稳定后再进入 QUIC/TLS/SSH。
产品 C/F 和混淆 O 放到最后，只做上下文证据。
