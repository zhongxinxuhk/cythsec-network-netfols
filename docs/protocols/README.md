# VPN / ZTNA 逐项识别算法目录

修订 `2026-10-26.1`；共 **268** 项独立文档。V/P/O原始编号90项全部覆盖；另含承载/认证、32项国内产品、19项海外产品和组合项拆分。
覆盖的是算法设计、结构解析或可信上下文关联接口；不代表全部私有协议可被无密钥纯DPI唯一识别。

真源：[vpn-protocols.json](../../configs/registry/vpn-protocols.json)。
[总体架构](../architecture/vpn-ztna-identification.md) · [输入手册](../vpn_ztna_protocol_identification_2026.md) · [开发与验收](../planning/VPN-ZTNA-20261026.md)

| ID | 对象 | 层次 | 实现路径 |
| --- | --- | --- | --- |
| [V001](V001.md) | IPsec ESP Tunnel / Transport | tunnel | bounded_wire_parser |
| [V002](V002.md) | IPsec AH | tunnel | bounded_wire_parser |
| [V003](V003.md) | IKEv1 | tunnel | bounded_wire_parser |
| [V004](V004.md) | IKEv2 | tunnel | bounded_wire_parser |
| [V005](V005.md) | IPsec NAT-T | tunnel | bounded_wire_parser |
| [V006](V006.md) | L2TP | tunnel | bounded_wire_parser |
| [V007](V007.md) | L2TP/IPsec | tunnel | trusted_context |
| [V008](V008.md) | PPTP | tunnel | bounded_wire_parser |
| [V009](V009.md) | GRE / mGRE | tunnel | bounded_wire_parser |
| [V010](V010.md) | IP-in-IP | tunnel | bounded_wire_parser |
| [V011](V011.md) | IPv6-in-IPv4 | tunnel | bounded_wire_parser |
| [V012](V012.md) | L2TPv3 | tunnel | trusted_context |
| [V013](V013.md) | EtherIP | tunnel | bounded_wire_parser |
| [V014](V014.md) | VXLAN | tunnel | bounded_wire_parser |
| [V015](V015.md) | Geneve | tunnel | bounded_wire_parser |
| [V016](V016.md) | GENEVE/IPsec、GRE/IPsec、IPIP/IPsec | tunnel | trusted_context |
| [V017](V017.md) | OpenVPN UDP | tunnel | bounded_wire_parser |
| [V018](V018.md) | OpenVPN TCP | tunnel | bounded_wire_parser |
| [V019](V019.md) | OpenVPN tls-crypt / tls-crypt-v2 | tunnel | trusted_context |
| [V020](V020.md) | OpenVPN over stunnel/SSH/obfs | tunnel | trusted_context |
| [V021](V021.md) | WireGuard | tunnel | bounded_wire_parser |
| [V022](V022.md) | AmneziaWG | tunnel | trusted_context |
| [V023](V023.md) | IKEv2/IPsec MOBIKE | tunnel | trusted_context |
| [V024](V024.md) | SSTP | tunnel | trusted_context |
| [V025](V025.md) | SoftEther native SSL-VPN | tunnel | trusted_context |
| [V026](V026.md) | OpenConnect / ocserv | tunnel | trusted_context |
| [V027](V027.md) | Cisco AnyConnect SSL VPN | tunnel | trusted_context |
| [V028](V028.md) | Palo Alto GlobalProtect | tunnel | trusted_context |
| [V029](V029.md) | Fortinet FortiClient SSL VPN | tunnel | trusted_context |
| [V030](V030.md) | Ivanti Connect Secure / Pulse Secure | tunnel | trusted_context |
| [V031](V031.md) | F5 BIG-IP APM Network Access | tunnel | trusted_context |
| [V032](V032.md) | Juniper Network Connect | tunnel | trusted_context |
| [V033](V033.md) | Check Point Mobile Access / Remote Access VPN | tunnel | trusted_context |
| [V034](V034.md) | StrongSwan / Libreswan / Openswan | tunnel | trusted_context |
| [V035](V035.md) | SSTP/PPP/EAP | tunnel | trusted_context |
| [V036](V036.md) | SSH VPN / `ssh -w` | tunnel | trusted_context |
| [V037](V037.md) | Tailscale / Headscale / ZeroTier / Nebula | tunnel | trusted_context |
| [V038](V038.md) | Cloudflare WARP | tunnel | trusted_context |
| [P001](P001.md) | SOCKS4 / SOCKS4a | tunnel | bounded_wire_parser |
| [P002](P002.md) | SOCKS5 | tunnel | bounded_wire_parser |
| [P003](P003.md) | HTTP Proxy / CONNECT | tunnel | bounded_wire_parser |
| [P004](P004.md) | HTTP/2 CONNECT / Extended CONNECT | tunnel | trusted_context |
| [P005](P005.md) | HTTP/3 CONNECT / MASQUE CONNECT-UDP / CONNECT-IP | tunnel | trusted_context |
| [P006](P006.md) | SSH dynamic forwarding（SOCKS） | tunnel | trusted_context |
| [P007](P007.md) | Shadowsocks AEAD | tunnel | trusted_context |
| [P008](P008.md) | Shadowsocks 2022 | tunnel | trusted_context |
| [P009](P009.md) | ShadowsocksR（SSR） | tunnel | trusted_context |
| [P010](P010.md) | V2Ray VMess | tunnel | trusted_context |
| [P011](P011.md) | Xray VLESS | tunnel | trusted_context |
| [P012](P012.md) | Trojan / Trojan-Go | tunnel | trusted_context |
| [P013](P013.md) | Hysteria v1 | tunnel | trusted_context |
| [P014](P014.md) | Hysteria2 | tunnel | trusted_context |
| [P015](P015.md) | TUIC v5 | tunnel | trusted_context |
| [P016](P016.md) | AnyTLS | tunnel | trusted_context |
| [P017](P017.md) | NaïveProxy | tunnel | trusted_context |
| [P018](P018.md) | Snell | tunnel | trusted_context |
| [P019](P019.md) | ShadowTLS v1/v2/v3 | tunnel | trusted_context |
| [P020](P020.md) | Cloak | tunnel | trusted_context |
| [P021](P021.md) | Brook / Brook WSS | tunnel | trusted_context |
| [P022](P022.md) | Outline | tunnel | trusted_context |
| [P023](P023.md) | Psiphon | tunnel | trusted_context |
| [P024](P024.md) | Tor OR / TLS | tunnel | trusted_context |
| [P025](P025.md) | Tor obfs4 | tunnel | trusted_context |
| [P026](P026.md) | Tor Snowflake | tunnel | trusted_context |
| [P027](P027.md) | Tor meek / WebTunnel | tunnel | trusted_context |
| [P028](P028.md) | OpenVPN over Tor / WireGuard over TLS | tunnel | trusted_context |
| [O001](O001.md) | REALITY | overlay | trusted_context |
| [O002](O002.md) | XTLS Vision | overlay | trusted_context |
| [O003](O003.md) | XHTTP | overlay | trusted_context |
| [O004](O004.md) | FinalMask | overlay | trusted_context |
| [O005](O005.md) | Salamander | overlay | trusted_context |
| [O006](O006.md) | Gecko | overlay | trusted_context |
| [O007](O007.md) | AmneziaWG v1/v2/v3.1 | overlay | trusted_context |
| [O008](O008.md) | obfs4 | overlay | trusted_context |
| [O009](O009.md) | Snowflake/WebTunnel/meek | overlay | trusted_context |
| [O010](O010.md) | simple-obfs HTTP/TLS | overlay | trusted_context |
| [O011](O011.md) | v2ray-plugin | overlay | trusted_context |
| [O012](O012.md) | SSR `http_simple`/`http_post`/`tls1.2_ticket_auth`/`random_head` | overlay | trusted_context |
| [O013](O013.md) | TLS ClientHello fragmentation | overlay | trusted_context |
| [O014](O014.md) | TCP segmentation/record fragmentation | overlay | trusted_context |
| [O015](O015.md) | Packet padding/random length | overlay | trusted_context |
| [O016](O016.md) | Timing obfuscation/traffic shaping | overlay | trusted_context |
| [O017](O017.md) | Port hopping | overlay | trusted_context |
| [O018](O018.md) | UDP2RAW FakeTCP/ICMP | overlay | trusted_context |
| [O019](O019.md) | Domain fronting/CDN reverse proxy | overlay | trusted_context |
| [O020](O020.md) | uTLS/浏览器 TLS 模仿、JA3/JA4 模仿 | overlay | trusted_context |
| [O021](O021.md) | TLS ECH | overlay | trusted_context |
| [O022](O022.md) | QUIC padding/fragmentation | overlay | trusted_context |
| [O023](O023.md) | WireGuard pre-shared key | overlay | trusted_context |
| [O024](O024.md) | Noise protocol framework | overlay | trusted_context |
| [T001](T001.md) | TLS 1.2 | transport | bounded_wire_parser |
| [T002](T002.md) | TLS 1.3 | transport | bounded_wire_parser |
| [T003](T003.md) | mTLS | transport | trusted_context |
| [T004](T004.md) | TLS Session Resumption | transport | trusted_context |
| [T005](T005.md) | DTLS 1.2 | transport | bounded_wire_parser |
| [T006](T006.md) | DTLS 1.3 | transport | trusted_context |
| [T007](T007.md) | QUIC v1 | transport | bounded_wire_parser |
| [T008](T008.md) | QUIC v2 | transport | bounded_wire_parser |
| [T009](T009.md) | HTTP/1.1 | transport | bounded_wire_parser |
| [T010](T010.md) | HTTP/2 | transport | trusted_context |
| [T011](T011.md) | HTTP/3 | transport | trusted_context |
| [T012](T012.md) | WebSocket / WSS | transport | trusted_context |
| [T013](T013.md) | gRPC | transport | trusted_context |
| [T014](T014.md) | TLCP 1.1 | transport | bounded_wire_parser |
| [T015](T015.md) | TLS 1.3 ShangMi cipher suites | transport | trusted_context |
| [T016](T016.md) | SSH 2 | transport | bounded_wire_parser |
| [T017](T017.md) | STUN / ICE | transport | trusted_context |
| [T018](T018.md) | SPA / SDP authorization | transport | trusted_context |
| [T019](T019.md) | SM2 | transport | trusted_context |
| [T020](T020.md) | SM3 | transport | trusted_context |
| [T021](T021.md) | SM4 | transport | trusted_context |
| [A001](A001.md) | RADIUS | identity | trusted_context |
| [A002](A002.md) | TACACS+ | identity | trusted_context |
| [A003](A003.md) | LDAP | identity | trusted_context |
| [A004](A004.md) | LDAPS | identity | trusted_context |
| [A005](A005.md) | Kerberos | identity | trusted_context |
| [A006](A006.md) | SAML | identity | trusted_context |
| [A007](A007.md) | OAuth2 | identity | trusted_context |
| [A008](A008.md) | OIDC | identity | trusted_context |
| [A009](A009.md) | CAS | identity | trusted_context |
| [A010](A010.md) | FIDO2 | identity | trusted_context |
| [A011](A011.md) | WebAuthn | identity | trusted_context |
| [A012](A012.md) | OTP | identity | trusted_context |
| [A013](A013.md) | PPP | identity | trusted_context |
| [A014](A014.md) | EAP | identity | trusted_context |
| [C001](C001.md) | 深信服 Sangfor — SSL VPN、EasyConnect、IPsec/SSL 综合网关 | product | trusted_context |
| [C002](C002.md) | 深信服 — 零信任/安全接入/SASE 相关产品 | product | trusted_context |
| [C003](C003.md) | 华为 Huawei — USG/HiSecEngine SSL VPN、旧 SecoClient/SVN | product | trusted_context |
| [C004](C004.md) | 华为 — 华为云 VPN/云安全接入 | product | trusted_context |
| [C005](C005.md) | 新华三 H3C — SecPath SSL VPN、iNode | product | trusted_context |
| [C006](C006.md) | 新华三 — SecCenter ZTNA / SDP | product | trusted_context |
| [C007](C007.md) | 奇安信 QAX — 安全接入网关 SSL VPN、IPsec VPN 安全网关 | product | trusted_context |
| [C008](C008.md) | 奇安信 — ZTNA、可信应用代理/API 代理/访问控制台 | product | trusted_context |
| [C009](C009.md) | 天融信 Topsec — TopVPN、国密 SSL VPN、国密 IPsec VPN | product | trusted_context |
| [C010](C010.md) | 天融信 — SDP 安全网关/访问控制网关 | product | trusted_context |
| [C011](C011.md) | 启明星辰 Venustech — SSL VPN 系统 | product | trusted_context |
| [C012](C012.md) | 启明星辰 — 天清 SDP 访问控制网关、鸿蒙 SDP SDK | product | trusted_context |
| [C013](C013.md) | 绿盟 NSFOCUS — 企业 VPN / 零信任相关方案（按项目核实） | product | trusted_context |
| [C014](C014.md) | 山石网科 Hillstone — StoneOS SSL VPN、ZTNA 访问方案 | product | trusted_context |
| [C015](C015.md) | 安恒 DBAPPSecurity — SSL VPN 安全网关、IPsec VPN、综合安全网关 | product | trusted_context |
| [C016](C016.md) | 安恒 — ZTSA 零信任安全访问控制系统、零信任 VPN | product | trusted_context |
| [C017](C017.md) | 迪普科技 DPtech — 安全网关/防火墙 VPN 能力（按 SKU 核实） | product | trusted_context |
| [C018](C018.md) | 锐捷 Ruijie — RG-EG 等网关 | product | trusted_context |
| [C019](C019.md) | 360 企业安全 — 零信任安全访问、360 连接云 | product | trusted_context |
| [C020](C020.md) | 亚信安全 AsiaInfo Security — AISDP 零信任访问控制系统 | product | trusted_context |
| [C021](C021.md) | 阿里云 Alibaba Cloud — 办公安全平台 SASE、零信任内网访问 VPN 版 | product | trusted_context |
| [C022](C022.md) | 腾讯云 Tencent Cloud — VPN Connection、iOA 零信任 | product | trusted_context |
| [C023](C023.md) | 火山引擎/字节 — 飞连（Feilian） | product | trusted_context |
| [C024](C024.md) | 中国电信天翼云 — VPN 连接 | product | trusted_context |
| [C025](C025.md) | 中国移动移动云 — 云 VPN / 零信任类产品（需型号） | product | trusted_context |
| [C026](C026.md) | 中国联通联通云 — 云 VPN / 安全接入（需型号） | product | trusted_context |
| [C027](C027.md) | 联软科技 LeagSoft — UniAccess / 终端准入和接入产品 | product | trusted_context |
| [C028](C028.md) | 派拉 Paraview — 零信任安全访问/统一访问网关 | product | trusted_context |
| [C029](C029.md) | 竹云 BambooCloud — IAM / 零信任相关方案（需具体产品） | product | trusted_context |
| [C030](C030.md) | 网宿科技 Wangsu — SASE / 安全接入产品（需具体 SKU） | product | trusted_context |
| [C031](C031.md) | 中兴 ZTE — 防火墙 / IPsec 等网络设备 | product | trusted_context |
| [C032](C032.md) | 其他 OEM/密码厂商 — 国密 SSL VPN、IPsec VPN、商密安全接入 | product | trusted_context |
| [F001](F001.md) | Cisco Secure Client / AnyConnect | product | trusted_context |
| [F002](F002.md) | Palo Alto GlobalProtect | product | trusted_context |
| [F003](F003.md) | Fortinet FortiClient/FortiSASE | product | trusted_context |
| [F004](F004.md) | Ivanti Connect Secure / Pulse | product | trusted_context |
| [F005](F005.md) | F5 BIG-IP APM | product | trusted_context |
| [F006](F006.md) | Citrix Gateway / NetScaler | product | trusted_context |
| [F007](F007.md) | Check Point Harmony Endpoint / Remote Access | product | trusted_context |
| [F008](F008.md) | Zscaler ZPA / ZIA | product | trusted_context |
| [F009](F009.md) | Netskope Private Access / SASE | product | trusted_context |
| [F010](F010.md) | Cloudflare Zero Trust / WARP | product | trusted_context |
| [F011](F011.md) | Tailscale/Headscale | product | trusted_context |
| [F012](F012.md) | ZeroTier | product | trusted_context |
| [F013](F013.md) | NetBird / Netmaker | product | trusted_context |
| [F014](F014.md) | OpenZiti | product | trusted_context |
| [F015](F015.md) | Google BeyondCorp Enterprise / Chrome Enterprise Premium | product | trusted_context |
| [F016](F016.md) | Microsoft Entra Private Access / Global Secure Access | product | trusted_context |
| [F017](F017.md) | AWS Client VPN | product | trusted_context |
| [F018](F018.md) | OpenVPN Access Server / CloudConnexa | product | trusted_context |
| [F019](F019.md) | Perimeter 81 / Harmony SASE | product | trusted_context |
| [X001](X001.md) | ESP Tunnel | tunnel | trusted_context |
| [X002](X002.md) | ESP Transport | tunnel | trusted_context |
| [X003](X003.md) | GRE | tunnel | trusted_context |
| [X004](X004.md) | mGRE | tunnel | trusted_context |
| [X005](X005.md) | L2TPv3 UDP | tunnel | trusted_context |
| [X006](X006.md) | L2TPv3 IP | tunnel | trusted_context |
| [X007](X007.md) | Geneve over IPsec | tunnel | trusted_context |
| [X008](X008.md) | GRE over IPsec | tunnel | trusted_context |
| [X009](X009.md) | IPIP over IPsec | tunnel | trusted_context |
| [X010](X010.md) | OpenVPN tls-crypt | tunnel | trusted_context |
| [X011](X011.md) | OpenVPN tls-crypt-v2 | tunnel | trusted_context |
| [X012](X012.md) | OpenVPN over stunnel | tunnel | trusted_context |
| [X013](X013.md) | OpenVPN over SSH | tunnel | trusted_context |
| [X014](X014.md) | OpenVPN over obfs | tunnel | trusted_context |
| [X015](X015.md) | AmneziaWG | tunnel | trusted_context |
| [X016](X016.md) | StrongSwan | tunnel | trusted_context |
| [X017](X017.md) | Libreswan | tunnel | trusted_context |
| [X018](X018.md) | Openswan | tunnel | trusted_context |
| [X019](X019.md) | SSTP over PPP EAP | tunnel | trusted_context |
| [X020](X020.md) | Tailscale | tunnel | trusted_context |
| [X021](X021.md) | Headscale | tunnel | trusted_context |
| [X022](X022.md) | ZeroTier | tunnel | trusted_context |
| [X023](X023.md) | Nebula | tunnel | trusted_context |
| [X024](X024.md) | SOCKS4 | tunnel | trusted_context |
| [X025](X025.md) | SOCKS4a | tunnel | trusted_context |
| [X026](X026.md) | HTTP forward proxy | tunnel | trusted_context |
| [X027](X027.md) | HTTP/2 CONNECT | tunnel | trusted_context |
| [X028](X028.md) | HTTP/2 Extended CONNECT | tunnel | trusted_context |
| [X029](X029.md) | HTTP/3 CONNECT | tunnel | trusted_context |
| [X030](X030.md) | MASQUE CONNECT-UDP | tunnel | trusted_context |
| [X031](X031.md) | MASQUE CONNECT-IP | tunnel | trusted_context |
| [X032](X032.md) | Shadowsocks legacy stream | tunnel | trusted_context |
| [X033](X033.md) | VLESS RAW | tunnel | trusted_context |
| [X034](X034.md) | VLESS TLS | tunnel | trusted_context |
| [X035](X035.md) | VLESS REALITY | tunnel | trusted_context |
| [X036](X036.md) | VLESS XHTTP | tunnel | trusted_context |
| [X037](X037.md) | Trojan | tunnel | trusted_context |
| [X038](X038.md) | Trojan-Go | tunnel | trusted_context |
| [X039](X039.md) | ShadowTLS v1 | tunnel | trusted_context |
| [X040](X040.md) | ShadowTLS v2 | tunnel | trusted_context |
| [X041](X041.md) | ShadowTLS v3 | tunnel | trusted_context |
| [X042](X042.md) | Brook native | tunnel | trusted_context |
| [X043](X043.md) | Brook WSS | tunnel | trusted_context |
| [X044](X044.md) | Brook UDP | tunnel | trusted_context |
| [X045](X045.md) | Psiphon SSH | tunnel | trusted_context |
| [X046](X046.md) | Psiphon OSSH | tunnel | trusted_context |
| [X047](X047.md) | Psiphon HTTP | tunnel | trusted_context |
| [X048](X048.md) | Tor Snowflake | tunnel | trusted_context |
| [X049](X049.md) | Tor meek | tunnel | trusted_context |
| [X050](X050.md) | Tor WebTunnel | tunnel | trusted_context |
| [X051](X051.md) | OpenVPN over Tor | tunnel | trusted_context |
| [X052](X052.md) | WireGuard over TLS | tunnel | trusted_context |
| [X053](X053.md) | AmneziaWG v1 | overlay | trusted_context |
| [X054](X054.md) | AmneziaWG v2 | overlay | trusted_context |
| [X055](X055.md) | AmneziaWG v3.1 | overlay | trusted_context |
| [X056](X056.md) | Snowflake | overlay | trusted_context |
| [X057](X057.md) | WebTunnel | overlay | trusted_context |
| [X058](X058.md) | meek | overlay | trusted_context |
| [X059](X059.md) | simple-obfs HTTP | overlay | trusted_context |
| [X060](X060.md) | simple-obfs TLS | overlay | trusted_context |
| [X061](X061.md) | SSR http_simple | overlay | trusted_context |
| [X062](X062.md) | SSR http_post | overlay | trusted_context |
| [X063](X063.md) | SSR tls1.2_ticket_auth | overlay | trusted_context |
| [X064](X064.md) | SSR random_head | overlay | trusted_context |
| [X065](X065.md) | TLS ClientHello fragmentation | overlay | trusted_context |
| [X066](X066.md) | TCP segmentation | overlay | trusted_context |
| [X067](X067.md) | TLS record fragmentation | overlay | trusted_context |
| [X068](X068.md) | UDP2RAW FakeTCP | overlay | trusted_context |
| [X069](X069.md) | UDP2RAW ICMP | overlay | trusted_context |
| [X070](X070.md) | Domain fronting | overlay | trusted_context |
| [X071](X071.md) | CDN reverse proxy | overlay | trusted_context |
| [X072](X072.md) | uTLS | overlay | trusted_context |
| [X073](X073.md) | JA3 imitation | overlay | trusted_context |
| [X074](X074.md) | JA4 imitation | overlay | trusted_context |
| [X075](X075.md) | WebSocket | transport | trusted_context |
| [X076](X076.md) | WSS | transport | trusted_context |
| [X077](X077.md) | STUN | transport | trusted_context |
| [X078](X078.md) | ICE | transport | trusted_context |
| [X079](X079.md) | Citrix ICA | product | trusted_context |
| [X080](X080.md) | Citrix HDX | product | trusted_context |
| [X081](X081.md) | NetScaler network VPN | product | trusted_context |
| [X082](X082.md) | NetBird | product | trusted_context |
| [X083](X083.md) | Netmaker | product | trusted_context |
| [X084](X084.md) | Google BeyondCorp Enterprise | product | trusted_context |
| [X085](X085.md) | Chrome Enterprise Premium | product | trusted_context |
| [X086](X086.md) | Microsoft Entra Private Access | product | trusted_context |
| [X087](X087.md) | Global Secure Access | product | trusted_context |
| [X088](X088.md) | OpenVPN Access Server | product | trusted_context |
| [X089](X089.md) | CloudConnexa | product | trusted_context |
| [X090](X090.md) | Perimeter 81 | product | trusted_context |
| [X091](X091.md) | Harmony SASE | product | trusted_context |
| [T022](T022.md) | TLS family (version unconfirmed) | transport | bounded_wire_parser |
