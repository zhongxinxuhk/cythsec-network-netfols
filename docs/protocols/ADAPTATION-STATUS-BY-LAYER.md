<!-- GENERATED: configs/registry/protocol-adaptation.json; gen-protocol-adaptation.py -->
# 协议适配 OSI 分层视图

修订：2026-11-01.3。共292行；一行只有一个主层，跨层封装和 non-OSI 单独列出，不重复计入七层。

口径：`osi_layer` 是主层，`osi_sublayer` 记录子层/承载关系，`osi_role` 记录协议角色，`encap_chain` 只列可见封装路径，不表示已解析内层或已建立内层流。目录原有 `layer` 轴保留。

[状态清单](ADAPTATION-STATUS.md) · [状态真源](../../configs/registry/protocol-adaptation.json) · [OSI 规划](../planning/protocol-osi-classification.md) · [维护规则](../development/protocol-adaptation.md)

## 汇总

| 主层 | 条目 | 实现审查 | 完整适配 | 口径 |
| --- | ---: | ---: | ---: | --- |
| L1 物理层 | 0 | 0 | 0 | 物理层只做链路/介质/速率元数据，不从 pcap 伪造 PHY 解析 |
| L2 数据链路层 | 14 | 4 | 1 | 帧、VLAN、ARP、PPP/EAP 与 L2 隧道 |
| L3 网络层 | 18 | 6 | 3 | IPv4/IPv6、分片、ICMP、IPsec/GRE 与 L3 隧道 |
| L4 传输层 | 4 | 2 | 0 | TCP/UDP/QUIC |
| L5 会话层 | 20 | 3 | 0 | TLS/DTLS/SSH/IKE/SOCKS/STUN 等会话与协商 |
| L6 表示层 | 0 | 0 | 0 | 表示/记录/密码属性；当前无独立主层条目 |
| L7 应用层 | 43 | 13 | 0 | 应用协议、身份认证与代理控制 |
| 跨层隧道/代理 | 72 | 0 | 0 | VPN/隧道/代理链；不递归创建内层流 |
| non-OSI 产品/变换/密码 | 121 | 0 | 0 | 产品、混淆变换、密码原语；只做上下文证据 |
| 合计 | 292 | 28 | 4 | 跨层和 non-OSI 不进入七层覆盖率分子 |

跨层和 non-OSI 不进入七层覆盖率分子；L1/L6 当前没有独立主层条目。

## L1 物理层

当前无主层条目。物理层仅记录 linktype、介质、速率等采集元数据，不假装从 pcap 解码 PHY。

## L2 数据链路层

| 完整适配 | ID | 协议/对象 | 角色 | 子层 | 封装链/使用层 | 实现审查 | 本地测试 | 独立对照 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ☐ | B001 | Ethernet II | 基础 | L2 | L2:Ethernet | ☑ | ☑ | ☐ |
| ☐ | B002 | IEEE 802.1Q VLAN | 基础 | L2 | L2:Ethernet → L2:802.1Q | ☑ | ☑ | ☐ |
| ☐ | B003 | IEEE 802.1ad QinQ | 基础 | L2 | L2:Ethernet → L2:802.1ad | ☑ | ☑ | ☐ |
| ☑ | B004 | ARP | 控制 | L2.5 | L2:Ethernet → L2:ARP | ☑ | ☑ | ☑ |
| ☐ | [V006](V006.md) | L2TP | 封装 | L2-over-L3/L4 | L2:Ethernet → L3:IP → L4:UDP → L2:L2TP → L2:PPP | ☐ | ☐ | ☐ |
| ☐ | [V008](V008.md) | PPTP | 封装 | L2-over-L3/L4 | L2:Ethernet → L3:IP → L3:GRE → L2:PPP → L2:PPTP | ☐ | ☐ | ☐ |
| ☐ | [V012](V012.md) | L2TPv3 | 封装 | L2-over-L3 | L2:Ethernet → L3:IP → L2:L2TPv3 | ☐ | ☐ | ☐ |
| ☐ | [V013](V013.md) | EtherIP | 封装 | L2-over-L3 | L2:Ethernet → L3:IP → L2:EtherIP | ☐ | ☐ | ☐ |
| ☐ | [V014](V014.md) | VXLAN | 封装 | L2-over-L3/L4 | L2:Ethernet → L3:IP → L4:UDP → L2:VXLAN → L2:Ethernet | ☐ | ☐ | ☐ |
| ☐ | [V015](V015.md) | Geneve | 封装 | L2-over-L3/L4 | L2:Ethernet → L3:IP → L4:UDP → L2:Geneve → L2:Ethernet | ☐ | ☐ | ☐ |
| ☐ | [A013](A013.md) | PPP | 封装 | L2 | L2:PPP | ☐ | ☐ | ☐ |
| ☐ | [A014](A014.md) | EAP | 控制 | L2 | L2:EAP | ☐ | ☐ | ☐ |
| ☐ | [X005](X005.md) | L2TPv3 UDP | 封装 | L2-over-L3 | L2:Ethernet → L3:IP → L4:UDP → L2:L2TPv3 | ☐ | ☐ | ☐ |
| ☐ | [X006](X006.md) | L2TPv3 IP | 封装 | L2-over-L3 | L2:Ethernet → L3:IP → L2:L2TPv3 | ☐ | ☐ | ☐ |

## L3 网络层

| 完整适配 | ID | 协议/对象 | 角色 | 子层 | 封装链/使用层 | 实现审查 | 本地测试 | 独立对照 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ☐ | B005 | IPv4 | 基础 | L3 | L2:Ethernet → L3:IPv4 | ☑ | ☑ | ☐ |
| ☐ | B006 | IPv6 | 基础 | L3 | L2:Ethernet → L3:IPv6 | ☑ | ☑ | ☐ |
| ☐ | B007 | IPv6扩展头链 | 基础 | L3 | L3:IPv6 → L3:IPv6 Extension Headers | ☑ | ☑ | ☐ |
| ☐ | B008 | IPv4/IPv6分片重组 | 基础 | L3 | L3:IPv4/IPv6 → L3:Fragments | ☐ | ☐ | ☐ |
| ☑ | B011 | ICMPv4 | 控制 | L3 | L3:IPv4 → L3:ICMPv4 | ☑ | ☑ | ☑ |
| ☑ | B012 | ICMPv6 | 控制 | L3 | L3:IPv6 → L3:ICMPv6 | ☑ | ☑ | ☑ |
| ☐ | [V001](V001.md) | IPsec ESP Tunnel / Transport | 安全 | L3-encap | L3:IP → L3:ESP | ☐ | ☐ | ☐ |
| ☐ | [V002](V002.md) | IPsec AH | 安全 | L3-encap | L3:IP → L3:AH | ☐ | ☐ | ☐ |
| ☑ | [V009](V009.md) | GRE / mGRE | 封装 | L3-encap | L3:IP → L3:GRE | ☑ | ☑ | ☑ |
| ☐ | [V010](V010.md) | IP-in-IP | 封装 | L3-encap | L3:IP → L3:IP | ☐ | ☐ | ☐ |
| ☐ | [V011](V011.md) | IPv6-in-IPv4 | 封装 | L3-encap | L3:IPv4 → L3:IPv6 | ☐ | ☐ | ☐ |
| ☐ | [V021](V021.md) | WireGuard | 封装 | L3-over-L4 | L3:IP → L4:UDP → L3:WireGuard | ☐ | ☐ | ☐ |
| ☐ | [V022](V022.md) | AmneziaWG | 封装 | L3-over-L4 | L3:IP → L4:UDP → L3:AmneziaWG | ☐ | ☐ | ☐ |
| ☐ | [X001](X001.md) | ESP Tunnel | 安全 | L3-encap | L3:IP → L3:ESP | ☐ | ☐ | ☐ |
| ☐ | [X002](X002.md) | ESP Transport | 安全 | L3-encap | L3:IP → L3:ESP | ☐ | ☐ | ☐ |
| ☐ | [X003](X003.md) | GRE | 封装 | L3-encap | L3:IP → L3:GRE | ☐ | ☐ | ☐ |
| ☐ | [X004](X004.md) | mGRE | 封装 | L3-encap | L3:IP → L3:GRE → L3:IP | ☐ | ☐ | ☐ |
| ☐ | [X015](X015.md) | AmneziaWG | 封装 | L3-over-L4 | L3:IP → L4:UDP → L3:AmneziaWG | ☐ | ☐ | ☐ |

## L4 传输层

| 完整适配 | ID | 协议/对象 | 角色 | 子层 | 封装链/使用层 | 实现审查 | 本地测试 | 独立对照 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ☐ | B009 | TCP | 基础 | L4 | L3:IP → L4:TCP | ☑ | ☑ | ☐ |
| ☐ | B010 | UDP | 基础 | L4 | L3:IP → L4:UDP | ☑ | ☑ | ☐ |
| ☐ | [T007](T007.md) | QUIC v1 | 基础 | L4 | L4:UDP → L4:QUIC v1 | ☐ | ☐ | ☐ |
| ☐ | [T008](T008.md) | QUIC v2 | 基础 | L4 | L4:UDP → L4:QUIC v2 | ☐ | ☐ | ☐ |

## L5 会话层

| 完整适配 | ID | 协议/对象 | 角色 | 子层 | 封装链/使用层 | 实现审查 | 本地测试 | 独立对照 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ☐ | [V003](V003.md) | IKEv1 | 安全 | L5 | L4:UDP → L5:IKEv1 | ☐ | ☐ | ☐ |
| ☐ | [V004](V004.md) | IKEv2 | 安全 | L5 | L4:UDP → L5:IKEv2 | ☐ | ☐ | ☐ |
| ☐ | [P001](P001.md) | SOCKS4 / SOCKS4a | 代理 | L5 | L4:TCP → L5:SOCKS4 | ☐ | ☐ | ☐ |
| ☐ | [P002](P002.md) | SOCKS5 | 代理 | L5 | L4:TCP → L5:SOCKS5 | ☐ | ☐ | ☐ |
| ☐ | [P006](P006.md) | SSH dynamic forwarding（SOCKS） | 代理 | L5 | L4:TCP → L5:SSH → L5:SOCKS | ☐ | ☐ | ☐ |
| ☐ | [T001](T001.md) | TLS 1.2 | 安全 | L5-L6 | L4:TCP → L5:TLS 1.2 | ☑ | ☑ | ☐ |
| ☐ | [T002](T002.md) | TLS 1.3 | 安全 | L5-L6 | L4:TCP → L5:TLS 1.3 | ☑ | ☑ | ☐ |
| ☐ | [T003](T003.md) | mTLS | 安全 | L5-L6 | L4:TCP → L5:TLS → L7:Application | ☐ | ☐ | ☐ |
| ☐ | [T004](T004.md) | TLS Session Resumption | 会话 | L5-L6 | L4:TCP → L5:TLS | ☐ | ☐ | ☐ |
| ☐ | [T005](T005.md) | DTLS 1.2 | 安全 | L5-L6 | L4:UDP → L5:DTLS 1.2 | ☐ | ☐ | ☐ |
| ☐ | [T006](T006.md) | DTLS 1.3 | 安全 | L5-L6 | L4:UDP → L5:DTLS 1.3 | ☐ | ☐ | ☐ |
| ☐ | [T014](T014.md) | TLCP 1.1 | 安全 | L5-L6 | L4:TCP → L5:TLCP | ☐ | ☐ | ☐ |
| ☐ | [T015](T015.md) | TLS 1.3 ShangMi cipher suites | 安全 | L5-L6 | L4:TCP → L5:TLS → L6:ShangMi | ☐ | ☐ | ☐ |
| ☐ | [T016](T016.md) | SSH 2 | 会话 | L5 | L4:TCP → L5:SSH | ☐ | ☐ | ☐ |
| ☐ | [T017](T017.md) | STUN / ICE | 控制 | L5 | L4:UDP → L5:STUN/ICE | ☐ | ☐ | ☐ |
| ☐ | [T022](T022.md) | TLS family (version unconfirmed) | 安全 | L5-L6 | L4:TCP → L5:TLS family | ☑ | ☑ | ☐ |
| ☐ | [X024](X024.md) | SOCKS4 | 代理 | L5 | L4:TCP → L5:SOCKS4 | ☐ | ☐ | ☐ |
| ☐ | [X025](X025.md) | SOCKS4a | 代理 | L5 | L4:TCP → L5:SOCKS4a | ☐ | ☐ | ☐ |
| ☐ | [X077](X077.md) | STUN | 控制 | L5 | L4:UDP → L5:STUN | ☐ | ☐ | ☐ |
| ☐ | [X078](X078.md) | ICE | 控制 | L5 | L4:UDP → L5:ICE | ☐ | ☐ | ☐ |

## L6 表示层

当前无独立主层条目。TLS record、证书和密码套件作为 L5 条目的表示层属性记录，不重复计数。

## L7 应用层

| 完整适配 | ID | 协议/对象 | 角色 | 子层 | 封装链/使用层 | 实现审查 | 本地测试 | 独立对照 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ☐ | B013 | DNS over UDP | 应用 | L7 | L4:UDP → L7:DNS | ☑ | ☑ | ☐ |
| ☐ | B014 | DNS over TCP | 应用 | L7 | L4:TCP → L7:DNS | ☑ | ☑ | ☑ |
| ☐ | B015 | DHCPv4 | 应用 | L7 | L4:UDP → L7:DHCPv4 | ☑ | ☑ | ☑ |
| ☐ | B016 | DHCPv6 | 应用 | L7 | L4:UDP → L7:DHCPv6 | ☑ | ☑ | ☑ |
| ☐ | B017 | mDNS | 应用 | L7 | L4:UDP → L7:mDNS | ☑ | ☑ | ☑ |
| ☐ | B018 | DNS over TLS | 应用 | L7-over-L5 | L4:TCP → L5:TLS → L7:DNS | ☑ | ☑ | ☑ |
| ☐ | B019 | DNS over HTTPS | 应用 | L7-over-L5 | L4:TCP → L5:TLS → L7:HTTP → L7:DNS | ☑ | ☑ | ☑ |
| ☐ | B020 | SMTP | 应用 | L7 | L4:TCP → L7:SMTP | ☑ | ☑ | ☑ |
| ☐ | B021 | FTP | 应用 | L7 | L4:TCP → L7:FTP | ☑ | ☑ | ☑ |
| ☐ | B022 | IPFIX v10 | 应用 | L7 | L4:TCP/UDP → L7:IPFIX | ☑ | ☑ | ☑ |
| ☐ | B023 | NetFlow v9 | 应用 | L7 | L4:TCP/UDP → L7:NetFlow v9 | ☑ | ☑ | ☑ |
| ☐ | B024 | sFlow | 应用 | L7 | L4:UDP → L7:sFlow | ☑ | ☑ | ☑ |
| ☐ | [P003](P003.md) | HTTP Proxy / CONNECT | 代理 | L7 | L4:TCP → L7:HTTP CONNECT | ☐ | ☐ | ☐ |
| ☐ | [P004](P004.md) | HTTP/2 CONNECT / Extended CONNECT | 代理 | L7 | L4:TCP → L7:HTTP/2 CONNECT | ☐ | ☐ | ☐ |
| ☐ | [P005](P005.md) | HTTP/3 CONNECT / MASQUE CONNECT-UDP / CONNECT-IP | 代理 | L7 | L4:UDP → L4:QUIC → L7:HTTP/3 CONNECT | ☐ | ☐ | ☐ |
| ☐ | [T009](T009.md) | HTTP/1.1 | 应用 | L7 | L4:TCP → L7:HTTP/1.1 | ☑ | ☑ | ☐ |
| ☐ | [T010](T010.md) | HTTP/2 | 应用 | L7 | L4:TCP → L7:HTTP/2 | ☐ | ☐ | ☐ |
| ☐ | [T011](T011.md) | HTTP/3 | 应用 | L7 | L4:UDP → L4:QUIC → L7:HTTP/3 | ☐ | ☐ | ☐ |
| ☐ | [T012](T012.md) | WebSocket / WSS | 应用 | L7 | L4:TCP → L7:WebSocket | ☐ | ☐ | ☐ |
| ☐ | [T013](T013.md) | gRPC | 应用 | L7 | L4:TCP → L7:gRPC | ☐ | ☐ | ☐ |
| ☐ | [T018](T018.md) | SPA / SDP authorization | 控制 | L7 | L7:SPA/SDP | ☐ | ☐ | ☐ |
| ☐ | [A001](A001.md) | RADIUS | 身份 | L7 | L4:UDP → L7:RADIUS | ☐ | ☐ | ☐ |
| ☐ | [A002](A002.md) | TACACS+ | 身份 | L7 | L4:TCP → L7:TACACS+ | ☐ | ☐ | ☐ |
| ☐ | [A003](A003.md) | LDAP | 身份 | L7 | L4:TCP → L7:LDAP | ☐ | ☐ | ☐ |
| ☐ | [A004](A004.md) | LDAPS | 身份 | L7 | L4:TCP → L5:TLS → L7:LDAP | ☐ | ☐ | ☐ |
| ☐ | [A005](A005.md) | Kerberos | 身份 | L7 | L4:UDP/TCP → L7:Kerberos | ☐ | ☐ | ☐ |
| ☐ | [A006](A006.md) | SAML | 身份 | L7 | L7:SAML | ☐ | ☐ | ☐ |
| ☐ | [A007](A007.md) | OAuth2 | 身份 | L7 | L4:TCP → L7:HTTP → L7:OAuth2 | ☐ | ☐ | ☐ |
| ☐ | [A008](A008.md) | OIDC | 身份 | L7 | L4:TCP → L7:HTTP → L7:OIDC | ☐ | ☐ | ☐ |
| ☐ | [A009](A009.md) | CAS | 身份 | L7 | L4:TCP → L7:HTTP → L7:CAS | ☐ | ☐ | ☐ |
| ☐ | [A010](A010.md) | FIDO2 | 身份 | L7 | L4:TCP → L7:HTTP → L7:FIDO2 | ☐ | ☐ | ☐ |
| ☐ | [A011](A011.md) | WebAuthn | 身份 | L7 | L4:TCP → L7:HTTP → L7:WebAuthn | ☐ | ☐ | ☐ |
| ☐ | [A012](A012.md) | OTP | 身份 | L7 | L7:OTP | ☐ | ☐ | ☐ |
| ☐ | [X026](X026.md) | HTTP forward proxy | 代理 | L7 | L4:TCP → L7:HTTP | ☐ | ☐ | ☐ |
| ☐ | [X027](X027.md) | HTTP/2 CONNECT | 代理 | L7 | L4:TCP → L7:HTTP/2 CONNECT | ☐ | ☐ | ☐ |
| ☐ | [X028](X028.md) | HTTP/2 Extended CONNECT | 代理 | L7 | L4:TCP → L7:HTTP/2 Extended CONNECT | ☐ | ☐ | ☐ |
| ☐ | [X029](X029.md) | HTTP/3 CONNECT | 代理 | L7 | L4:UDP → L4:QUIC → L7:HTTP/3 CONNECT | ☐ | ☐ | ☐ |
| ☐ | [X030](X030.md) | MASQUE CONNECT-UDP | 代理 | L7 | L4:UDP → L4:QUIC → L7:MASQUE CONNECT-UDP | ☐ | ☐ | ☐ |
| ☐ | [X031](X031.md) | MASQUE CONNECT-IP | 代理 | L7 | L4:UDP → L4:QUIC → L7:MASQUE CONNECT-IP | ☐ | ☐ | ☐ |
| ☐ | [X075](X075.md) | WebSocket | 应用 | L7 | L4:TCP → L7:WebSocket | ☐ | ☐ | ☐ |
| ☐ | [X076](X076.md) | WSS | 应用 | L7 | L4:TCP → L5:TLS → L7:WebSocket | ☐ | ☐ | ☐ |
| ☐ | [X079](X079.md) | Citrix ICA | 应用 | L7 | L4:TCP → L7:ICA | ☐ | ☐ | ☐ |
| ☐ | [X080](X080.md) | Citrix HDX | 应用 | L7 | L4:TCP → L7:HDX | ☐ | ☐ | ☐ |

## 跨层隧道/代理

| 完整适配 | ID | 协议/对象 | 角色 | 子层 | 封装链/使用层 | 实现审查 | 本地测试 | 独立对照 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ☐ | [V005](V005.md) | IPsec NAT-T | 封装 | L3-L4 | L3:IP → L4:UDP → L3:ESP | ☐ | ☐ | ☐ |
| ☐ | [V007](V007.md) | L2TP/IPsec | 封装 | L2-over-L3 | L3:IP → L3:ESP → L2:L2TP → L2:PPP | ☐ | ☐ | ☐ |
| ☐ | [V016](V016.md) | GENEVE/IPsec、GRE/IPsec、IPIP/IPsec | 封装 | L3-encap | L3:IP → L3:IPsec → L3:GRE/IP-in-IP | ☐ | ☐ | ☐ |
| ☐ | [V017](V017.md) | OpenVPN UDP | 封装 | L2/L3-over-L5 | L3:IP → L4:UDP → L5:OpenVPN | ☐ | ☐ | ☐ |
| ☐ | [V018](V018.md) | OpenVPN TCP | 封装 | L2/L3-over-L5 | L3:IP → L4:TCP → L5:OpenVPN | ☐ | ☐ | ☐ |
| ☐ | [V019](V019.md) | OpenVPN tls-crypt / tls-crypt-v2 | 封装 | L2/L3-over-L5 | L4:UDP → L5:OpenVPN → L5:tls-crypt | ☐ | ☐ | ☐ |
| ☐ | [V020](V020.md) | OpenVPN over stunnel/SSH/obfs | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS/SSH → L5:OpenVPN | ☐ | ☐ | ☐ |
| ☐ | [V023](V023.md) | IKEv2/IPsec MOBIKE | 封装 | L5/L3 | L4:UDP → L5:IKEv2 → L3:ESP | ☐ | ☐ | ☐ |
| ☐ | [V024](V024.md) | SSTP | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L2:PPP → L2:SSTP | ☐ | ☐ | ☐ |
| ☐ | [V025](V025.md) | SoftEther native SSL-VPN | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L5:SoftEther | ☐ | ☐ | ☐ |
| ☐ | [V026](V026.md) | OpenConnect / ocserv | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L5:OpenConnect | ☐ | ☐ | ☐ |
| ☐ | [V027](V027.md) | Cisco AnyConnect SSL VPN | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L5:AnyConnect | ☐ | ☐ | ☐ |
| ☐ | [V028](V028.md) | Palo Alto GlobalProtect | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L5:GlobalProtect | ☐ | ☐ | ☐ |
| ☐ | [V029](V029.md) | Fortinet FortiClient SSL VPN | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L5:FortiClient | ☐ | ☐ | ☐ |
| ☐ | [V030](V030.md) | Ivanti Connect Secure / Pulse Secure | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L5:Ivanti | ☐ | ☐ | ☐ |
| ☐ | [V031](V031.md) | F5 BIG-IP APM Network Access | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L5:F5 APM | ☐ | ☐ | ☐ |
| ☐ | [V032](V032.md) | Juniper Network Connect | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L5:Juniper | ☐ | ☐ | ☐ |
| ☐ | [V033](V033.md) | Check Point Mobile Access / Remote Access VPN | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L5:Check Point | ☐ | ☐ | ☐ |
| ☐ | [V035](V035.md) | SSTP/PPP/EAP | 封装 | L2/L3-over-L5 | L4:TCP → L5:TLS → L2:PPP → L2:EAP | ☐ | ☐ | ☐ |
| ☐ | [V036](V036.md) | SSH VPN / `ssh -w` | 封装 | L2/L3-over-L5 | L4:TCP → L5:SSH → L3:IP | ☐ | ☐ | ☐ |
| ☐ | [P007](P007.md) | Shadowsocks AEAD | 代理 | L5/L7 | L3:IP → L4:TCP/UDP → L5:Shadowsocks | ☐ | ☐ | ☐ |
| ☐ | [P008](P008.md) | Shadowsocks 2022 | 代理 | L5/L7 | L3:IP → L4:TCP/UDP → L5:Shadowsocks | ☐ | ☐ | ☐ |
| ☐ | [P009](P009.md) | ShadowsocksR（SSR） | 代理 | L5/L7 | L3:IP → L4:TCP → L5:SSR | ☐ | ☐ | ☐ |
| ☐ | [P010](P010.md) | V2Ray VMess | 代理 | L5/L7 | L4:TCP → L5:VMess | ☐ | ☐ | ☐ |
| ☐ | [P011](P011.md) | Xray VLESS | 代理 | L5/L7 | L4:TCP → L5:VLESS | ☐ | ☐ | ☐ |
| ☐ | [P012](P012.md) | Trojan / Trojan-Go | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:Trojan | ☐ | ☐ | ☐ |
| ☐ | [P013](P013.md) | Hysteria v1 | 代理 | L5/L7 | L4:UDP → L4:QUIC → L5:Hysteria | ☐ | ☐ | ☐ |
| ☐ | [P014](P014.md) | Hysteria2 | 代理 | L5/L7 | L4:UDP → L4:QUIC → L5:Hysteria | ☐ | ☐ | ☐ |
| ☐ | [P015](P015.md) | TUIC v5 | 代理 | L5/L7 | L4:UDP → L4:QUIC → L5:TUIC | ☐ | ☐ | ☐ |
| ☐ | [P016](P016.md) | AnyTLS | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:AnyTLS | ☐ | ☐ | ☐ |
| ☐ | [P017](P017.md) | NaïveProxy | 代理 | L5/L7 | L4:TCP → L5:TLS → L7:HTTP/2 | ☐ | ☐ | ☐ |
| ☐ | [P018](P018.md) | Snell | 代理 | L5/L7 | L4:TCP → L5:Snell | ☐ | ☐ | ☐ |
| ☐ | [P019](P019.md) | ShadowTLS v1/v2/v3 | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:ShadowTLS | ☐ | ☐ | ☐ |
| ☐ | [P020](P020.md) | Cloak | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:Cloak | ☐ | ☐ | ☐ |
| ☐ | [P021](P021.md) | Brook / Brook WSS | 代理 | L5/L7 | L4:TCP/UDP → L5:Brook | ☐ | ☐ | ☐ |
| ☐ | [P022](P022.md) | Outline | 代理 | L5/L7 | L4:TCP → L5:Shadowsocks | ☐ | ☐ | ☐ |
| ☐ | [P023](P023.md) | Psiphon | 代理 | L5/L7 | L4:TCP → L5:Psiphon | ☐ | ☐ | ☐ |
| ☐ | [P024](P024.md) | Tor OR / TLS | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:Tor | ☐ | ☐ | ☐ |
| ☐ | [P025](P025.md) | Tor obfs4 | 代理 | L5/L7 | L4:TCP → L5:obfs4 | ☐ | ☐ | ☐ |
| ☐ | [P026](P026.md) | Tor Snowflake | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:Snowflake | ☐ | ☐ | ☐ |
| ☐ | [P027](P027.md) | Tor meek / WebTunnel | 代理 | L5/L7 | L4:TCP → L5:TLS → L7:HTTP → L5:meek/WebTunnel | ☐ | ☐ | ☐ |
| ☐ | [P028](P028.md) | OpenVPN over Tor / WireGuard over TLS | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:OpenVPN/WireGuard | ☐ | ☐ | ☐ |
| ☐ | [X007](X007.md) | Geneve over IPsec | 封装 | L3-encap | L3:IP → L3:IPsec → L3:Geneve | ☐ | ☐ | ☐ |
| ☐ | [X008](X008.md) | GRE over IPsec | 封装 | L3-encap | L3:IP → L3:IPsec → L3:GRE | ☐ | ☐ | ☐ |
| ☐ | [X009](X009.md) | IPIP over IPsec | 封装 | L3-encap | L3:IP → L3:IPsec → L3:IP | ☐ | ☐ | ☐ |
| ☐ | [X010](X010.md) | OpenVPN tls-crypt | 封装 | L3/L5 | L4:UDP → L5:OpenVPN → L5:tls-crypt | ☐ | ☐ | ☐ |
| ☐ | [X011](X011.md) | OpenVPN tls-crypt-v2 | 封装 | L3/L5 | L4:UDP → L5:OpenVPN → L5:tls-crypt-v2 | ☐ | ☐ | ☐ |
| ☐ | [X012](X012.md) | OpenVPN over stunnel | 封装 | L3/L5 | L4:TCP → L5:TLS → L5:OpenVPN | ☐ | ☐ | ☐ |
| ☐ | [X013](X013.md) | OpenVPN over SSH | 封装 | L3/L5 | L4:TCP → L5:SSH → L5:OpenVPN | ☐ | ☐ | ☐ |
| ☐ | [X014](X014.md) | OpenVPN over obfs | 封装 | L3/L5 | L4:TCP → L5:obfs → L5:OpenVPN | ☐ | ☐ | ☐ |
| ☐ | [X019](X019.md) | SSTP over PPP EAP | 封装 | L3/L5 | L4:TCP → L5:TLS → L2:PPP → L2:EAP | ☐ | ☐ | ☐ |
| ☐ | [X032](X032.md) | Shadowsocks legacy stream | 代理 | L5/L7 | L4:TCP → L5:Shadowsocks | ☐ | ☐ | ☐ |
| ☐ | [X033](X033.md) | VLESS RAW | 代理 | L5/L7 | L4:TCP → L5:VLESS | ☐ | ☐ | ☐ |
| ☐ | [X034](X034.md) | VLESS TLS | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:VLESS | ☐ | ☐ | ☐ |
| ☐ | [X035](X035.md) | VLESS REALITY | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:VLESS → L5:REALITY | ☐ | ☐ | ☐ |
| ☐ | [X036](X036.md) | VLESS XHTTP | 代理 | L5/L7 | L4:TCP → L5:VLESS → L5:XHTTP | ☐ | ☐ | ☐ |
| ☐ | [X037](X037.md) | Trojan | 代理 | L5/L7 | L4:TCP → L5:Trojan | ☐ | ☐ | ☐ |
| ☐ | [X038](X038.md) | Trojan-Go | 代理 | L5/L7 | L4:TCP → L5:Trojan-Go | ☐ | ☐ | ☐ |
| ☐ | [X039](X039.md) | ShadowTLS v1 | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:ShadowTLS | ☐ | ☐ | ☐ |
| ☐ | [X040](X040.md) | ShadowTLS v2 | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:ShadowTLS | ☐ | ☐ | ☐ |
| ☐ | [X041](X041.md) | ShadowTLS v3 | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:ShadowTLS | ☐ | ☐ | ☐ |
| ☐ | [X042](X042.md) | Brook native | 代理 | L5/L7 | L4:TCP → L5:Brook | ☐ | ☐ | ☐ |
| ☐ | [X043](X043.md) | Brook WSS | 代理 | L5/L7 | L4:TCP → L5:TLS → L5:Brook WSS | ☐ | ☐ | ☐ |
| ☐ | [X044](X044.md) | Brook UDP | 代理 | L5/L7 | L4:UDP → L5:Brook UDP | ☐ | ☐ | ☐ |
| ☐ | [X045](X045.md) | Psiphon SSH | 代理 | L5/L7 | L4:TCP → L5:SSH → L5:Psiphon | ☐ | ☐ | ☐ |
| ☐ | [X046](X046.md) | Psiphon OSSH | 代理 | L5/L7 | L4:TCP → L5:SSH → L5:Psiphon OSSH | ☐ | ☐ | ☐ |
| ☐ | [X047](X047.md) | Psiphon HTTP | 代理 | L5/L7 | L4:TCP → L5:HTTP → L5:Psiphon | ☐ | ☐ | ☐ |
| ☐ | [X048](X048.md) | Tor Snowflake | 代理 | L5/L7 | L4:UDP → L5:TLS → L5:Snowflake | ☐ | ☐ | ☐ |
| ☐ | [X049](X049.md) | Tor meek | 代理 | L5/L7 | L4:TCP → L5:TLS → L7:HTTP → L5:meek | ☐ | ☐ | ☐ |
| ☐ | [X050](X050.md) | Tor WebTunnel | 代理 | L5/L7 | L4:TCP → L5:TLS → L7:HTTP → L5:WebTunnel | ☐ | ☐ | ☐ |
| ☐ | [X051](X051.md) | OpenVPN over Tor | 代理 | L5/L7 | L4:TCP → L5:Tor → L5:OpenVPN | ☐ | ☐ | ☐ |
| ☐ | [X052](X052.md) | WireGuard over TLS | 代理 | L5/L7 | L4:TCP → L5:TLS → L3:WireGuard | ☐ | ☐ | ☐ |

## non-OSI 产品/变换/密码

| 完整适配 | ID | 协议/对象 | 角色 | 子层 | 封装链/使用层 | 实现审查 | 本地测试 | 独立对照 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ☐ | [V034](V034.md) | StrongSwan / Libreswan / Openswan | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [V037](V037.md) | Tailscale / Headscale / ZeroTier / Nebula | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [V038](V038.md) | Cloudflare WARP | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O001](O001.md) | REALITY | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O002](O002.md) | XTLS Vision | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O003](O003.md) | XHTTP | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O004](O004.md) | FinalMask | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O005](O005.md) | Salamander | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O006](O006.md) | Gecko | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O007](O007.md) | AmneziaWG v1/v2/v3.1 | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O008](O008.md) | obfs4 | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O009](O009.md) | Snowflake/WebTunnel/meek | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O010](O010.md) | simple-obfs HTTP/TLS | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O011](O011.md) | v2ray-plugin | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O012](O012.md) | SSR `http_simple`/`http_post`/`tls1.2_ticket_auth`/`random_head` | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O013](O013.md) | TLS ClientHello fragmentation | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O014](O014.md) | TCP segmentation/record fragmentation | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O015](O015.md) | Packet padding/random length | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O016](O016.md) | Timing obfuscation/traffic shaping | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O017](O017.md) | Port hopping | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O018](O018.md) | UDP2RAW FakeTCP/ICMP | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O019](O019.md) | Domain fronting/CDN reverse proxy | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O020](O020.md) | uTLS/浏览器 TLS 模仿、JA3/JA4 模仿 | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O021](O021.md) | TLS ECH | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O022](O022.md) | QUIC padding/fragmentation | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O023](O023.md) | WireGuard pre-shared key | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [O024](O024.md) | Noise protocol framework | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [T019](T019.md) | SM2 | 密码 | non-osi | 使用 L5/L6 | ☐ | ☐ | ☐ |
| ☐ | [T020](T020.md) | SM3 | 密码 | non-osi | 使用 L5/L6 | ☐ | ☐ | ☐ |
| ☐ | [T021](T021.md) | SM4 | 密码 | non-osi | 使用 L5/L6 | ☐ | ☐ | ☐ |
| ☐ | [C001](C001.md) | 深信服 Sangfor — SSL VPN、EasyConnect、IPsec/SSL 综合网关 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C002](C002.md) | 深信服 — 零信任/安全接入/SASE 相关产品 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C003](C003.md) | 华为 Huawei — USG/HiSecEngine SSL VPN、旧 SecoClient/SVN | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C004](C004.md) | 华为 — 华为云 VPN/云安全接入 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C005](C005.md) | 新华三 H3C — SecPath SSL VPN、iNode | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C006](C006.md) | 新华三 — SecCenter ZTNA / SDP | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C007](C007.md) | 奇安信 QAX — 安全接入网关 SSL VPN、IPsec VPN 安全网关 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C008](C008.md) | 奇安信 — ZTNA、可信应用代理/API 代理/访问控制台 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C009](C009.md) | 天融信 Topsec — TopVPN、国密 SSL VPN、国密 IPsec VPN | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C010](C010.md) | 天融信 — SDP 安全网关/访问控制网关 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C011](C011.md) | 启明星辰 Venustech — SSL VPN 系统 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C012](C012.md) | 启明星辰 — 天清 SDP 访问控制网关、鸿蒙 SDP SDK | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C013](C013.md) | 绿盟 NSFOCUS — 企业 VPN / 零信任相关方案（按项目核实） | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C014](C014.md) | 山石网科 Hillstone — StoneOS SSL VPN、ZTNA 访问方案 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C015](C015.md) | 安恒 DBAPPSecurity — SSL VPN 安全网关、IPsec VPN、综合安全网关 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C016](C016.md) | 安恒 — ZTSA 零信任安全访问控制系统、零信任 VPN | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C017](C017.md) | 迪普科技 DPtech — 安全网关/防火墙 VPN 能力（按 SKU 核实） | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C018](C018.md) | 锐捷 Ruijie — RG-EG 等网关 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C019](C019.md) | 360 企业安全 — 零信任安全访问、360 连接云 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C020](C020.md) | 亚信安全 AsiaInfo Security — AISDP 零信任访问控制系统 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C021](C021.md) | 阿里云 Alibaba Cloud — 办公安全平台 SASE、零信任内网访问 VPN 版 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C022](C022.md) | 腾讯云 Tencent Cloud — VPN Connection、iOA 零信任 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C023](C023.md) | 火山引擎/字节 — 飞连（Feilian） | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C024](C024.md) | 中国电信天翼云 — VPN 连接 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C025](C025.md) | 中国移动移动云 — 云 VPN / 零信任类产品（需型号） | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C026](C026.md) | 中国联通联通云 — 云 VPN / 安全接入（需型号） | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C027](C027.md) | 联软科技 LeagSoft — UniAccess / 终端准入和接入产品 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C028](C028.md) | 派拉 Paraview — 零信任安全访问/统一访问网关 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C029](C029.md) | 竹云 BambooCloud — IAM / 零信任相关方案（需具体产品） | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C030](C030.md) | 网宿科技 Wangsu — SASE / 安全接入产品（需具体 SKU） | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C031](C031.md) | 中兴 ZTE — 防火墙 / IPsec 等网络设备 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [C032](C032.md) | 其他 OEM/密码厂商 — 国密 SSL VPN、IPsec VPN、商密安全接入 | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F001](F001.md) | Cisco Secure Client / AnyConnect | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F002](F002.md) | Palo Alto GlobalProtect | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F003](F003.md) | Fortinet FortiClient/FortiSASE | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F004](F004.md) | Ivanti Connect Secure / Pulse | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F005](F005.md) | F5 BIG-IP APM | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F006](F006.md) | Citrix Gateway / NetScaler | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F007](F007.md) | Check Point Harmony Endpoint / Remote Access | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F008](F008.md) | Zscaler ZPA / ZIA | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F009](F009.md) | Netskope Private Access / SASE | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F010](F010.md) | Cloudflare Zero Trust / WARP | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F011](F011.md) | Tailscale/Headscale | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F012](F012.md) | ZeroTier | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F013](F013.md) | NetBird / Netmaker | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F014](F014.md) | OpenZiti | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F015](F015.md) | Google BeyondCorp Enterprise / Chrome Enterprise Premium | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F016](F016.md) | Microsoft Entra Private Access / Global Secure Access | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F017](F017.md) | AWS Client VPN | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F018](F018.md) | OpenVPN Access Server / CloudConnexa | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [F019](F019.md) | Perimeter 81 / Harmony SASE | 产品 | non-osi | 使用 L2/L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X016](X016.md) | StrongSwan | 产品 | non-osi | 使用 L3/L4/L5 | ☐ | ☐ | ☐ |
| ☐ | [X017](X017.md) | Libreswan | 产品 | non-osi | 使用 L3/L4/L5 | ☐ | ☐ | ☐ |
| ☐ | [X018](X018.md) | Openswan | 产品 | non-osi | 使用 L3/L4/L5 | ☐ | ☐ | ☐ |
| ☐ | [X020](X020.md) | Tailscale | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X021](X021.md) | Headscale | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X022](X022.md) | ZeroTier | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X023](X023.md) | Nebula | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X053](X053.md) | AmneziaWG v1 | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X054](X054.md) | AmneziaWG v2 | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X055](X055.md) | AmneziaWG v3.1 | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X056](X056.md) | Snowflake | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X057](X057.md) | WebTunnel | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X058](X058.md) | meek | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X059](X059.md) | simple-obfs HTTP | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X060](X060.md) | simple-obfs TLS | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X061](X061.md) | SSR http_simple | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X062](X062.md) | SSR http_post | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X063](X063.md) | SSR tls1.2_ticket_auth | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X064](X064.md) | SSR random_head | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X065](X065.md) | TLS ClientHello fragmentation | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X066](X066.md) | TCP segmentation | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X067](X067.md) | TLS record fragmentation | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X068](X068.md) | UDP2RAW FakeTCP | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X069](X069.md) | UDP2RAW ICMP | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X070](X070.md) | Domain fronting | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X071](X071.md) | CDN reverse proxy | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X072](X072.md) | uTLS | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X073](X073.md) | JA3 imitation | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X074](X074.md) | JA4 imitation | 变换 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X081](X081.md) | NetScaler network VPN | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X082](X082.md) | NetBird | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X083](X083.md) | Netmaker | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X084](X084.md) | Google BeyondCorp Enterprise | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X085](X085.md) | Chrome Enterprise Premium | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X086](X086.md) | Microsoft Entra Private Access | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X087](X087.md) | Global Secure Access | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X088](X088.md) | OpenVPN Access Server | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X089](X089.md) | CloudConnexa | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X090](X090.md) | Perimeter 81 | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
| ☐ | [X091](X091.md) | Harmony SASE | 产品 | non-osi | 使用 L3/L4/L5/L7 | ☐ | ☐ | ☐ |
