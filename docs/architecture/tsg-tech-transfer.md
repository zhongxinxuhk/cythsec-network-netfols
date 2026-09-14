# TSG（天狗安全网关）技术解构与 CythSec 技术引入方案

> 来源论文：*Technical Analysis of the Geedge Networks Firewall Source Code Leak*
> （Ablove et al., 35th USENIX Security Symposium, Aug 2026, pp. 3123–3142；
> 本地副本：`docs/TSG-docs/usenixsecurity26-ablove-en.pdf` 英文版 20 页 /
> `docs/TSG-docs/usenixsecurity26-ablove.pdf` 中英对照版 40 页）
>
> - 文档域：ARC（架构）／关联 DOC、TRF、POL、TIP、PKT
> - 任务编号：CYS-DOC-021（本方案文档）
> - 版本：v0.3.0
> - 最后更新：2026-09-14（AEST）
> - 适用基线：`cythsec` v0.1.0（`docs/planning/BACKLOG.md` 349 任务 / 9 里程碑）
> - **落地状态**：§3 为规划清单，§9 为**已验证的落地记录**。两者不一致时以 §9 为准。

---

## 0. 结论摘要（TL;DR）

TSG（Tiangou Secure Gateway，天狗安全网关）是 Geedge Networks 的商用 DPI 产品，经泄漏源码
重建后可确认其完整技术栈。论文给出的架构、工程实践与**处置原语**，本方案按**全量引入**口径
落地：**19 项技术**（架构级 6 / 检测能力 5 / 质量与工程 6 / 部署与性能 2）**+ 1 套处置动作全集**
（13 类动作，见 §7.1）。其中 6 项架构级能力不补则「检测—判定—处置」闭环不成立。

**一句话结论**：TSG 的可借鉴价值集中在以下四项，而最后一项正是 CythSec 当前最大的空洞：

1. **可组合的插件化数据面**（SAPP 的 platform / protocol / business 三分类 + 声明式注册清单）；
2. **统一的属性—规则—动作三层解耦**（Maat 属性字典 + 规则表 + action_parameter）；
3. **多路径判定聚合与签名生命周期管理**（并行检测器汇入同一防火墙判定点 + 签名格式双向转换）；
4. **完整的处置原语集**（丢包 / RST 与 ICMP 注入 / 双粒度节流 / HTTP·DNS 重定向 / 邮件·SIP 阻断 /
   载荷篡改 / 延迟阻断）——CythSec 当前**完全没有执行面**，这是与 TSG 的最大差距。

而 TSG 在论文中被**实证暴露的缺陷**（内存不安全的 C 核心、第三方库直接拷源码、崩溃拖垮主进程、
无规则冲突检测、响应包头常量可被远程指纹、8 个整型边界意外成为指纹特征）恰好构成 CythSec
的超越路径：**内存安全 + 崩溃隔离 + 规则编译期校验 + 自身指纹卫生 + 可对标性能门禁**。

> 引入口径：本版为**全量引入**——论文描述的 TSG 能力，包括其全部阻断与篡改动作，均纳入范围。
> 第 7 节不再设「拒绝引入」清单，改为给出**完整动作矩阵 + 工程约束**（可测试性、审计链、
> 影响面预演、权限分离）。这些约束的动机是工程质量：TSG 自身因多动作策略连带封禁引发客户
> 不满（F41）、因第三方库段错误拖垮核心进程（F43），两者都是可复现的工程事故。

---

## 1. 论文事实基线（可追溯索引）

阅读范围：全文 20 页（英文版），含正文 7 章 + 附录 + 参考文献 50 条。核心事实汇总如下，
所有条目均标注论文出处，便于逐条复核。

| # | 事实 | 出处 |
| --- | --- | --- |
| F1 | 泄漏规模 572 GiB / 10 万+ 文件 / 500+ Git 仓库；2025-09 公开，最新文档至 2024-11 | §2.2 Table 1 |
| F2 | 泄漏构成：`mirror/repo.tar` 463.0 GiB（RPM 包）、`mesalab_git.tar.zst` 59.4 GiB（Git 仓库）、Confluence 46.4 GiB、Jira 2.5 GiB | Table 1 |
| F3 | 公司 2018 年由方滨兴创立；与中科院 MESA Lab 有协作关系 | §2.2 |
| F4 | 现代 DPI 四阶段工作流：Ingress → Processing → Evaluation → Interference | §3 |
| F5 | SAPP（Stream Analysis Process Platform）：MESA Labs 2005 年起，四代迭代（start / papp / SAPPv3 / SAPPv4），TSG 基于 SAPPv4 | §3.1 |
| F6 | SAPP 解析 L2–L4（Ethernet / IP / UDP / TCP）与隧道封装（VLAN / PPPoE / VXLAN）后转插件 | §3.1 |
| F7 | 插件三类：platform / protocol / business，经 `conflist.inf` + 每插件 `*.inf` 注册到指定流类型 | §3.1 |
| F8 | 流控制 API：`stream.h` 提供 `MESA_set_stream_opt`，含 `MSO_DROP_STREAM` / `MSO_DROP_CURRENT_PKT`；可发 TCP RST、注入任意报文 | §3.1 |
| F9 | 协议插件能力：DNS（query 的域名/类型/类别，response 的全部 RR 与 DNSSEC）、SSL（SNI、密码套件、扩展长度、JA3/JA4、证书 subject/issuer/有效期/SAN）、QUIC（SNI、UA、版本） | §3.2 |
| F10 | Stellar-on-SAPP：SAPP 与 Stellar 之间的过渡桥接插件；Stellar 为 C++ 实现，会话粒度更强、插件间通信更丰富；泄漏时仍在开发、未进入 TSG 构建 | §3.3 |
| F11 | Stellar 插件通过**会话级消息总线**交互：创建/定位 topic、publish、callback subscribe | §3.3 |
| F12 | Maat：规则匹配引擎，定位为「网络流处理配置的统一描述框架」，支持 **Redis / JSON / IRIS** 三种加载模式 | §3.4 |
| F13 | Maat 规则结构：`rule_table_name` / `uuid` / `service` / `action` / `blacklist_option` / `evaluation_order` / `action_parameter{sub_action, send_tcp_reset, after_n_packets, send_icmp_unreachable}` / `and_conditions[].{negate_option, attribute_name, objects[].{expression, match_method, format}}` | Table 2 |
| F14 | 扫描属性覆盖：传输层、应用层、隧道与封装元数据（内外层 IP、GRE 端点）、端点身份（源/目的 IP、端口、FQDN/SNI、ASN、国家）；TCP/UDP 均有「首包 C→S」「首包 S→C」载荷属性 | §3.4 |
| F15 | 防火墙插件同时是 SAPP 插件与 Stellar 插件；订阅 `TOPIC_APP_ID`，聚合多条并行路径属性后扫描 Maat，再经 SAPP 流 API 施加动作 | §3.5 |
| F16 | 阻断动作全集：丢包、TCP RST、会话级/包级节流、HTTP 指定状态码（200/204/403/404）或 302/303 重定向、DNS 重定向、邮件（550/551）、SIP（480/500）、篡改、延迟阻断（after N packets） | §3.5.1 |
| F17 | CBD（Context-Based Detector，前身 AppSketch）为核心应用识别系统，以 `libcbd` RPM 分发，签名从 Maat 加载；内置与自定义签名以 app-id 边界（默认 10000）区分 | §4.1 |
| F18 | 两种签名格式：ASW 与 TSG2402；由 `appsketch-works/asw-controller` 负责「上传 TSG2402 → 转 ASW → 存 Git → 可回导」 | §4.1.1 |
| F19 | 论文**未找到** ASW/TSG2402 → Maat 的显式转换代码，仅凭结构相似（`app_id`/`app_name`/`deny_action` 对齐）推断其存在 | §4.1.1 |
| F20 | 签名可匹配属性：服务端 IP、域名、JA3/JA4、证书字段、载荷长度、字节模式、`common.app_id` | §4.1.1 Table 4 |
| F21 | 典型签名：ExpressVPN=JA3；Flash VPN=证书 issuer CN/O；HideMe VPN=UDP 首包长度 54 + 载荷前缀 `000000016628`；Ultrasurf=8 组 FQDN 模式 + JA3；Psiphon-CDN=app_id(68/199) + FQDN 后缀 + 1,023 个 CDN IP 段 + **排除 56,396 个已知合法 FQDN** | Table 4 |
| F22 | 签名风险分级 1–5，VPN/翻墙工具类 29 条中 21 条为最高级 5 | Table 3 |
| F23 | Glimpse 检测器基座为 `libprotoident`（仅用应用层载荷**前 4 字节**做识别，`lpi_guess_protocol`）；另将 nDPI（GPL，2022 版）的 `openvpn.c` 改名为 `openvpn_identify.cpp`，函数 `ndpi_search_openvpn` → `app_identify_guess_openvpn`，逻辑几乎不变 | §4.2.1 |
| F24 | QDPI 检测器基座为商用 Qosmos ixEngine（宣称 4,700+ 协议/应用）；产物 `qdpi_detector.so` / `libqmengine.so` / `libqmbundle.so`；AppSketch 数据库未加载时直接退出检测 | §4.2.2 |
| F25 | 构建：`tsg-os-buildimage` 最新 tag `rel-24.10` 的 `manifest.yaml`；SAPP RPM `sapp-pr-4.3.67.07feab9` 需 HASP 许可（Sentinel LDK，每秒校验一次的监控线程），作者以 stub 替换规避 | §5.1 |
| F26 | 配置文件：`sapp.toml`（部署模式、包 I/O、二级配置文件）、`conflist.inf`（插件清单）、`main.conf`（防火墙配置） | §5.1 §5.2.1 |
| F27 | 测试床：Docker 三容器（client / DPI / 转发容器，转发容器重写 MAC）+ Kafka 日志可视化；可触发 DNS/HTTP/TLS/QUIC 的注入响应、丢包、延迟阻断 | §5.2 |
| F28 | RST 注入可配置：`NUM`=1–3 个 RST、`FLAGS`=4(RST)/20(RST+ACK)，默认 1 个 RST+ACK；`SEED1`/`SEED2` 默认 13 / 65535 | §5.2.1 |
| F29 | DNS 指纹：`get_decompressed_name` 把压缩指针跳数硬限 **17**；`build_cheat_pkt` 注入响应 flags 恒为 **0x8180** 且答案段名恒用压缩指针 | §6.1 Table 5 |
| F30 | 分片指纹：`ipv4_attack_detect` 阈值 `IPV4_FRAG_NUM_PER_IPQ=100`，因检查与自增顺序形成 **101** 的实际边界；可经 `ipv4_reassembly_enabled` 关闭 | §6.2 Table 6 |
| F31 | RST 头字段生成器 `trick_algo_getrandval_with_seed`：`win = val + dip mod k`、`ipid = M − val·k + sip mod win`、`ttl = val%200 + 48`；`k` 可由两包差分解出 | §6.3 Listing 1 |
| F32 | GFW II / GFW III 实测稳定 `k = 13`（与 TSG 默认值一致），随机巧合概率约 `10^-44`；二者 TTL 固定 255（与 TSG 的 48–247 不符，说明 2023-12 后改过实现） | §6.3 Table 7 |
| F33 | `IP DF` 位在 `deal_ipv4.h` 中硬编码置位，可作静态指纹 | §6.3 |
| F34 | TLS 长度字段排列测试：record / message / session-id / cipher-suite / compression-methods / extensions（含「排除最后一个扩展」）/ SNI-extension / SNI-list / SNI-name，取值 zero / half / double / 0xFFFF；方法学基于开源 Censor-Scanner 扩展，每向量 20 次、2/3 阈值判定、并处理 3 元组与 4 元组残余阻断 | §6.4 Table 8 Table 11 Table 12 |
| F35 | GFW II 与 TSG **旧版** SSL 模块解析行为等价；哈萨克斯坦 QUIC 解析与 TSG 旧版完全吻合 | §6.4 §6.5 |
| F36 | QUIC 指纹：强制 Initial ≥ 1200 字节、跨数据报 CRYPTO 帧分片重组、支持 GQUIC Q023–Q051 与 T050–T051、IETF draft-22~28 / draft-29 / v1 / v2、明文与加密 Initial 均可解析 | §6.5 Table 9 |
| F37 | 核心洞见之一：**单个中间盒内部存在多条互不相交的并行判定路径**（Glimpse 判 QUIC 与 QUIC 插件解析 SNI 相互独立，却都能触发同一条阻断规则） | §7 |
| F38 | 核心洞见之二：TSG 能以**较低成本**识别翻墙工具，且属性匹配发生在连接**极早期**；同时，混淆（Psiphon 无显著签名）会抬高检测成本，迫使其退化为「IP 段 + Top SNI 白名单」策略 | §4.1.2 §7 |
| F39 | 核心洞见之三：复杂度与灵活性是双刃剑——内存不安全的 C 核心、过渡性的 Stellar-on-SAPP、多处第三方代码拷贝、AppSketch DB 升级曾导致 SAPP 重启，**缺乏代码验证**，遗留模糊测试与符号执行的空白 | §7 附录 Figure 8 |
| F40 | 运维流程：`vpn` 相关 Jira 单 700 张 / 182 个 issue（缅甸 440、埃塞俄比亚 53）；主题含服务端 IP 提取、优先级、签名失效、迭代开发、**误封** | §4.1.2 |
| F41 | 误封案例（E21）：单一策略配置多条 VPN deny 导致其他应用被连带拒绝；处置逻辑按「测试 IP 是否属 Psiphon 客户端 IP → 服务端 IP 是否属 Top Server IP → SNI 是否属 Top SNI」三级放行 | Figure 3 |
| F42 | 迭代案例（OMPUB-1372）：Signal 开启「反审查」后封堵失效，需借鉴 K 项目经验补签名；LetsVPN 高优先级、LanternVPN 低优先级 | Figure 2 |
| F43 | 供应链失控案例：`libqmbundle`（第三方识别引擎库）段错误导致 SAPP 重启，根因为 AppSketch DB 升级包中 PB 版本问题 | 附录 Figure 8 |
| F44 | 作者未公开发布泄漏源码与其 TSG 部署（伦理考虑）；开放产物（PCAP、扫描器、脚本）见 Zenodo | Open Science |
| F45 | 论文未报告任何吞吐 / PPS / Gbps 指标 | 全文 |

> 说明：本节仅记录论文**描述**的架构与行为。泄漏源码本身未公开（F44），因此下述引入方案
> 全部基于论文的**架构描述**，不涉及、也不应涉及任何源码复制。这一点在无许可风险的条件下
> 反而更容易做对——见 §4 的 S6（许可工程化）与 §6 的 R2。

---

## 2. TSG 架构解构与 CythSec 映射

### 2.1 四阶段对应关系

论文用四阶段描述现代 DPI 工作流（F4）。把这四阶段与 CythSec 现有/规划组件对齐：

```
      TSG 组件                          四阶段              CythSec 组件（现状）
  ─────────────────────────────────────────────────────────────────────────────
  SAPP（packet I/O + L2–L4 + 隧道）   Ingress      →   packet-engine（XDP/AF_XDP/DPDK + 解析器）
  SAPP 协议插件 / Stellar 会话        Processing   →   traffic-engine（flow/session/reassembly/protocol）
  Maat 属性扫描 + 防火墙插件          Evaluation   →   policyd（规则引擎，规划）+ crates/risk
  stream.h（drop / RST / inject）     Interference →   ❌ 缺失（当前只读，无执行面）
  签名库（ASW / TSG2402 / CBD）       数据供给      →   threat-intelligence（规划）+ ml/model-registry
  Kafka 日志                         观测          →   telemetryd + ClickHouse + web/console
```

**第一个结构性结论**：CythSec 在 Ingress 与 Processing 两阶段的目标架构**已优于 TSG**
（内核态 XDP/eBPF、AF_XDP 零拷贝、DPDK 轮询 vs SAPP 的用户态收包；Rust 内存安全 vs C）。
真正的差距在 **Evaluation 的属性表达力**与 **Interference 的执行面完全缺失**。

### 2.2 能力对位矩阵

| 能力维度 | TSG（论文实证） | CythSec 现状 | 差距定性 | 落点任务 |
| --- | --- | --- | --- | --- |
| 收包后端 | 用户态 SAPP，支持 inline（VXLAN）/透明模式（F6 F26） | pcap 文件后端已通；AF_PACKET/XDP/AF_XDP/DPDK 规划中 | CythSec 目标领先 | CYS-PKT-008~014 |
| L2–L4 解析 | Ethernet / IP / UDP / TCP + VLAN / PPPoE / VXLAN（F6） | 已有 Ethernet/IPv4/IPv6/TCP/UDP/ICMP 骨架 + VLAN 计划 | 基本对位 | CYS-PKT-016 |
| 隧道与内外层属性 | 内外层 IP、GRE 端点（F14） | 无 | **缺** | CYS-PKT-032（新） |
| 协议解析 | DNS（含 DNSSEC RR）、TLS（含 JA3/JA4、证书）、QUIC（含 GQUIC 与多版本） | TLS/DNS/HTTP/QUIC 全部在规划中 | 需补齐 QUIC/GQUIC 与 JA4 | CYS-TRF-021~024 |
| 会话抽象 | SAPP 流 → Stellar 会话（L4–L7），会话级消息总线（F11） | session crate 规划中；无消息总线 | **缺（架构级）** | CYS-TRF-042（新） |
| 插件模型 | 三类插件 + `conflist.inf` 声明式注册（F7） | cargo workspace 单体库 | **缺（架构级）** | CYS-TRF-040（新） |
| 规则引擎 | Maat：属性扫描 + 规则表 + 三加载后端 + 结构化 action（F12 F13 F14） | policyd 仅 3 行 go.mod | **缺（核心缺口）** | CYS-POL-002~006 |
| 属性字典 | L2–L7 + 隧道元数据 + 身份字段 + 首包载荷（F14） | feature crate 规划中，维度未定义 | **缺（上限决定项）** | CYS-TRF-043（新） |
| 多引擎聚合 | SAPP 协议插件 + Stellar 检测器并行 → 防火墙统一聚合（F15 F37） | 无统一判定点 | **缺（架构级）** | CYS-TRF-042（新） |
| 第三方引擎集成 | 直接拷贝源码（libprotoident / nDPI / Qosmos）（F23 F24） | 无 | 需**以隔离方式**引入 | CYS-TRF-044（新） |
| 签名生命周期 | ASW ↔ TSG2402 双向转换 + Git 存储 + app-id 边界（F17 F18） | 无 | **缺** | CYS-TIP-011（新） |
| 执行面（处置） | 13 类动作：drop / RST / ICMP / 双粒度节流 / HTTP 码 / HTTP·DNS 重定向 / 邮件 / SIP / 篡改 / 延迟阻断（F8 F16） | 无 | **缺（最大缺口，全量引入见 §7）** | CYS-TRF-041 + CYS-TRF-046 + CYS-POL-020（新） |
| 白名单 / 排除 | 1,023 CDN 段 + 排除 56,396 FQDN；三级放行逻辑（F21 F41） | 无 | **缺（质量关键）** | CYS-POL-019（新） |
| 崩溃隔离 | 无（第三方 .so 段错误拖垮 SAPP）（F43） | 架构上可做进程隔离 | CythSec 目标领先 | CYS-TRF-044（新） |
| 内存安全 | 核心用 C，论文明确列为风险（F39） | Rust 核心 + C++ 边界 | CythSec 目标领先 | CYS-TRF-026 |
| 自身指纹 | 常量 seed(13)、硬编码 DF、恒定 0x8180、整数边界（F29 F30 F31 F32 F33） | 尚未生成响应包 | 需建立卫生规范 | CYS-TRF-047（新）+ CYS-SEC-013（新） |
| 构建可复现 | 依赖 HASP 许可（F25） | 零外部依赖、离线可构建 | CythSec 目标领先 | CYS-INF-035（新） |
| 性能指标 | **论文未报告**（F45） | 有基准框架规划 | CythSec 目标领先 | CYS-PKT-029 |
| 误报治理 | Jira 人工流程 + 连带影响分析（F40 F41） | 无 | **缺** | CYS-TST-015（新） |

---

## 3. 建议引入的技术栈

按「补齐闭环的紧迫度」排序，共 19 项，分四组。每项给出：TSG 出处 → 技术要点 → CythSec 落点
→ 建议任务编号 → 验收标准。

### 3.1 A 组：架构级引入（6 项，建议优先）

#### A1. 声明式插件注册模型（对应 F7 F5）

- **TSG 做法**：`conflist.inf` 列出插件清单，每个插件自带 `*.inf` 声明其注册的流类型；
  插件分 platform / protocol / business 三类，且**各自独立仓库、独立版本**。
- **技术要点**：「核心调度」与「功能实现」在文件系统层面分离，新增能力不改动核心代码。
- **CythSec 落点**：`dataplane/traffic-engine` 引入 `plugin-registry` 子 crate，以 TOML 清单声明
  `{name, kind, subscribes_flow_type, priority, enabled}`；`crates/dpi` 与 `crates/protocol` 的
  注册改为清单驱动；核心调度只依赖 `trait ProtocolPlugin` / `trait BusinessPlugin`。
- **建议任务**：`CYS-TRF-040` 插件注册表与调度器（P1/L）
- **验收**：新增一个协议解析器 = 新增 crate + 清单条目，**零改动**核心调度代码；清单非法时启动即报错并指出条目名。

#### A2. 会话级消息总线与统一判定点（对应 F11 F15 F37）

- **TSG 做法**：Stellar 插件通过**会话级 topic 总线**发布/订阅（创建 topic、publish、回调订阅）；
  防火墙插件同时订阅 `TOPIC_APP_ID` 等主题，与 SAPP 协议插件路径**并行**汇入同一判定点。
- **技术要点**：论文 §7 明确把「单个中间盒内部并存多条互不相交的判定路径」列为核心洞见。
  这意味着**检测器之间不应互相调用**，而应各自发布判定，由聚合层统一裁决。
- **CythSec 落点**：定义 `DetectionEvent { session_id, source_engine, attrs: AttributeSet, confidence }`
  与会话级 `EventBus`（topic 订阅）；`crates/risk` 作为聚合与裁决点，
  `crates/dpi` / `crates/behavior` / ML 推理 / 威胁情报各自作为独立发布者。
- **建议任务**：`CYS-TRF-042` 会话级事件总线与判定聚合点（P1/L，依赖 A1）
- **验收**：新增一个检测引擎仅需实现 `Publisher` 并声明 topic；聚合层单测可注入多个引擎的事件并断言融合结果与命中明细。

#### A3. 版本化属性字典（对应 F14）

- **TSG 做法**：Maat 的扫描属性横跨传输层、应用层、隧道封装元数据、端点身份，且 TCP/UDP
  均提供「首包 C→S」「首包 S→C」载荷属性。
- **技术要点**：属性字典**定义了规则引擎的表达上限**。TSG 的属性集合说明其设计者把
  「可匹配的东西」当作一等公民来枚举，而不是想到哪加到哪。
- **CythSec 落点**：建立 `attribute-registry`（单一真源，YAML 定义 + 各语言绑定生成），
  与既有 `CYS-TRF-028`（特征定义单一来源）合并为同一机制，产出四类消费者绑定：
  Rust（数据面）、Go（policyd）、Python（训练）、TypeScript（控制台展示）。
  属性命名建议采用 `ATTR_<SCOPE>_<FIELD>` 稳定标识（如 `ATTR_TUNNEL_INNER_SRC_IP`、
  `ATTR_FIRST_PAYLOAD_C2S_LEN`）。
- **建议任务**：`CYS-TRF-043` 属性字典单一真源与多语言绑定（P0/L）
- **验收**：属性清单改动后四端绑定重新生成且编译通过；属性命名变更走弃用周期（旧名保留一个版本并告警）。

#### A4. 统一流控制 API 与处置原语全集（执行面，对应 F8 F15 F16）

- **TSG 做法**：`stream.h` 提供流粒度原语——设置流选项（丢弃整条流 / 丢弃当前包）、
  发送 TCP RST、注入任意报文；且明确要求 **in-path 部署**才能丢弃报文。
  在其之上，防火墙支持 13 类动作（完整矩阵见 §7.1）。
- **技术要点**：把「处置」抽象为**流粒度原语**而非散落的 netfilter 调用，是规则引擎能
  干净地下发动作的前提。同时论文点明：**旁路部署只能观测与注入，无法丢弃**——
  即**动作可用性由部署模式决定**，这一条必须建模进系统，而不是在运行期才发现失败。
- **CythSec 落点**：定义 `trait EnforcementBackend`，覆盖 TSG 的全部原语：
  `drop_stream / drop_current_packet / reset_stream / inject_icmp_unreachable /
  rate_limit(session|packet) / inject_http(code) / inject_http_redirect(code, url) /
  inject_dns_redirect / inject_smtp(code, text) / inject_sip(code, text) /
  tamper(scope, sampling) / defer(after_n_packets)`；
  并提供四种实现：
  1. `DryRun`（记录「本应执行的动作」与动作日志，供离线回放、回归与影响面预演使用）；
  2. `Nftables`（经 `policyd` 的结构化下发，参数化构造而非字符串拼接——对齐 `threat-model.md` T1）；
  3. `Inline`（与内联数据面后端耦合，受 `CYS-PKT-013/014` 约束）；
  4. `Pcap`（离线回放注入，用于测试床与基准）。
  部署模式必须在配置中显式声明（`bypass` / `span` / `on_path_inline` / `on_path_transparent`），
  并对每个动作暴露 `is_available(mode)`，与 TSG 的 inline / transparent / on-path 概念对齐但**语义更明确**。
- **建议任务**：
  - `CYS-TRF-041` 流控制与处置后端抽象（P0/L，依赖 CYS-PKT-024）
  - `CYS-TRF-046` 报文注入与篡改原语（P1/L，依赖 CYS-TRF-041）——承载 RST / ICMP /
    HTTP 响应 / DNS 应答 / SMTP / SIP 六类注入包构造，以及载荷篡改原语
  - `CYS-POL-020` 处置动作全集与参数化（P0/M，依赖 CYS-POL-017）
- **验收**：`DryRun` 与 `Pcap` 后端可在离线 pcap 回放上产出完整「动作日志」（判定 vs 实际动作）；
  12 类动作各有单测覆盖（含畸形包构造与字段合法性）；`is_available()` 与部署模式一致；
  `Nftables` 后端的规则构造经注入测试（含 `;`、换行、通配符等载荷）无逃逸。

#### A5. Maat 式三层解耦：属性 → 规则表 → 动作参数（对应 F12 F13）

- **TSG 做法**：规则表带 `evaluation_order` 优先级；条件为 `and_conditions[]`，
  每条件含 `negate_option` / `attribute_name` / `objects[]{expression, match_method, format}`；
  动作经 `action_parameter` 携带 `sub_action` 与 `after_n_packets` 等参数。
- **技术要点**（三条可直接抄的设计）：
  1. **匹配语义与格式归一化分离**：`match_method: full` 与 `format: uncase plain`
     是正交的两个维度——匹配方式（全等/前缀/包含/正则）不该和大小写、编码归一化混在一起写；
  2. **负条件是一等公民**：`negate_option` 出现在条件层，而非用「黑名单里不写它」来规避；
  3. **动作参数与动作类型解耦**：新增动作不需要改规则结构。
- **CythSec 落点**：直接采纳为 `policyd` 规则 IR 的结构骨架（替换/细化 `CYS-POL-002` 的模型定义），
  并在其上补 TSG 缺失的能力——**规则编译期冲突与冗余检测**（已有 `CYS-POL-004`）。
- **建议任务**：`CYS-POL-017` 规则 IR 结构化与匹配语义/格式正交化（P0/M，与 CYS-POL-002/003/004 联动）
- **验收**：同一规则在 JSON / 内部 IR / DSL 三形态间往返无损；冲突用例（同属性同意义不同动作）在编译期报错而非运行期随机生效。

#### A6. 规则加载后端抽象（对应 F12）

- **TSG 做法**：三种加载模式——Redis（热更新）、JSON 文件、IRIS（文件索引 + 数据表文件）。
- **技术要点**：把「规则从哪来」与「规则怎么匹配」解耦；Redis 模式即热更新通道。
- **CythSec 落点**：`policyd` 定义 `trait RuleStore`：`memory` / `json-file` / `redis` /
  `index+datatable`（后二者对齐 TSG 的 IRIS 思路，适合大规则集分片加载）；
  并强制「版本号 + 校验和 + 回滚」，对齐已有 `CYS-POL-006`。
- **建议任务**：`CYS-POL-018` 规则加载后端抽象与热更新（P1/M，依赖 CYS-POL-017）
- **验收**：四种后端跑同一套表驱动测试；切后端不改任何匹配逻辑；热更新失败时保持旧版本生效并告警。

### 3.2 B 组：检测能力引入（5 项）

#### B1. 三层递进的协议识别引擎（对应 F23 F24）

- **TSG 做法**：三家并置——`libprotoident`（仅首 4 字节，极低成本）、nDPI（开放实现）、
  Qosmos ixEngine（商用，4,700+ 协议）。论文 §4.2.1 指出 Glimpse 甚至重复实现了 DNS/QUIC 识别。
- **技术要点**：**分层投入**。绝大比例流量只需极低成本启发式就能定性，昂贵引擎留给难例。
  但 TSG 的集成方式是**直接拷贝源码**，导致 GPL 污染（nDPI）与崩溃扩散（`libqmbundle` 段错误
  拖垮 SAPP，F43）。
- **CythSec 落点**：`crates/dpi` 内分三层并以 trait 收敛：
  1. `HeuristicEngine`（端口表 + 首 4~16 字节特征 + 包长/方向启发式），零依赖、必选；
  2. `NativeParsers`（自研 TLS / DNS / QUIC / HTTP / SSH / SMTP 完整解析），Rust，内存安全；
  3. `ExternalEngineAdapter`（nDPI 等 GPL 引擎与商用引擎），**以独立进程 + IPC 挂载**，
     进程崩溃降级为「该引擎本轮不可用」而非平台崩溃；许可边界写入 `docs/security/compliance`。
- **建议任务**：`CYS-TRF-044` 外部 DPI 引擎适配层与进程隔离（P2/L）
- **验收**：外部引擎被 `SIGKILL` 后主流程继续运行且指标暴露「引擎降级」；许可清单中标注各引擎许可与分发边界。

#### B2. 早期判定窗口（对应 F14 F38）

- **TSG 做法**：属性含「首包 C→S」「首包 S→C」载荷；论文 §7 强调匹配发生在
  **连接的极早期**，并称其应用识别管线「以相对较低成本」完成识别。
- **技术要点**：检测延迟 = 所需包数 × RTT。把「前 N 包窗口」做成显式、可枚举、可匹配的属性，
  是低延迟判定的工程前提。
- **CythSec 落点**：`crates/feature` 显式产出前缀窗口特征：
  `first_1pkt` / `first_2pkt` / `first_4pkt` / `first_8pkt` 的载荷长度序列、方向序列、
  字节分布、可打印 ASCII 比例、熵（对齐既有 `CYS-TRF-027` 的维度），并支持
  **early-exit 判定**：规则命中即终止该会话的后续重计算。
- **建议任务**：`CYS-TRF-045` 前缀窗口特征与 early-exit 判定路径（P0/M，依赖 CYS-TRF-027）
- **验收**：对固定样本集，报告「判定所需包数」分布；规则命中会话不再进入后续特征计算（以计数器断言）。

#### B3. 加密流量统计指纹（对应 F38 与相关文献 [7][46]）

- **论文侧依据**：论文 §2.1 综述了 GFW 对全加密流量的检测（载荷长度、熵、位分布、
  可打印 ASCII 位置）。TSG 自身则以 JA3/JA4、证书字段、app_id 等**明文字段**为主（F20）。
- **技术要点**：TSG 的强项在明文字段匹配；对「无明文特征」的流量（论文承认 Psiphon 即为难例，F38）
  其手段退化为 IP 段与白名单。这恰是 CythSec 用 **ML + 统计特征**超越的位置。
- **CythSec 落点**：`crates/feature` + `ml/training` 联动，把「包长分布 / IAT / 熵 / 方向切换」
  作为一等特征集，配合 `crates/behavior` 的基线偏离度，构成对无明文特征流量的识别路径；
  经 `CYS-TRF-030` 的 `AnomalyDetector` trait 挂载。
- **建议任务**：无需新增编号，纳入 `CYS-TRF-027` / `CYS-TRF-029/030` / `CYS-MLT-0xx` 的范围，
  但需在 `docs/ml/` 明确「明文字段匹配」与「统计指纹」两条路径的分工与合并策略。
- **验收**：对含明文特征与不含明文特征的两类样本分别报告检出率；给出两条路径的融合规则（谁优先、如何加权）。

#### B4. 签名格式的双向转换与生命周期（对应 F17 F18 F19）

- **TSG 做法**：外部格式 TSG2402 → 内部格式 ASW，Git 仓库存档，可回导；app-id 边界
  （默认 10000）区分内置与自定义签名。
- **技术要点**：签名是**资产**，需要版本化、可审计、可回滚、可追溯来源。
  但论文**未找到转换代码**（F19），仅凭结构相似推断——说明这套机制在 TSG 内部也是隐式、脆弱的。
- **CythSec 落点**：建立 `signature-registry`：
  - 规范化 IR（属性 + 匹配语义 + 动作 + 元数据：来源/许可/风险级/有效期）；
  - 适配器：外部格式（YARA、Suricata、以及同类商业 DPI 的导出格式）→ IR → 目标格式，**双向无损**；
  - 存储：Git 版本化 + 校验和 + 变更审计，与 `ml/model-registry` 同构（签名与模型都是「可下发的判定资产」）；
  - 内置 / 自定义分区命名空间，替代魔数 10000。
- **建议任务**：`CYS-TIP-011` 签名注册表与格式双向转换（P1/L）
- **验收**：任一外部格式经 IR 往返后语义等价（属性级 diff 为空）；每次变更产生不可变版本与 diff 记录。

#### B5. 排除集与白名单机制（对应 F21 F41）

- **TSG 做法**：Psiphon 签名包含 `排除 56,396 个已知合法 FQDN`；误封事件后的处置逻辑为
  「客户端 IP 属 Psiphon 客户端 IP → 服务端 IP 是否属 Top Server IP → SNI 是否属 Top SNI」
  三级放行（F41），并明确提到「白名单保护机制」（F38）。
- **技术要点**：负条件与白名单**必须是一等公民**，且需要独立于规则集的版本化生命周期。
  TSG 是在误封投诉之后才补上这套机制的。
- **CythSec 落点**：
  1. 规则 IR 增加 `excludes[]`（属性级负匹配）与 `allowance` 优先级语义——白名单**先于**拒绝判定；
  2. 白名单库独立版本化（与签名注册表同机制），支持大规模条目（十万级）的高效匹配
     （前缀树 / 区间树，而非线性扫描）；
  3. 每次白名单命中都要写入审计事件（谁被放行、因哪条）。
- **建议任务**：`CYS-POL-019` 白名单/排除集一等公民与高效匹配（P0/L，依赖 CYS-POL-017）
- **验收**：白名单命中在裁决链中优先于拒绝；十万级条目匹配延迟有基准数据；每次白名单命中产生审计记录。

### 3.3 C 组：质量与工程引入（6 项）

#### C1. 自身指纹卫生（对应 F29 F30 F31 F32 F33）

- **TSG 教训**：论文用 5 类指纹把 TSG 与 GFW 部署绑定（DNS 17 跳边界 + 恒定 flags、
  101 分片边界、RST 头字段的常量 seed_key=13、硬编码 DF 位、TLS/QUIC 长度字段排列）。
  其中 `k=13` 的巧合概率约 `10^-44`（F32）——即「实现常量」本身就是可远程利用的标识。
- **技术要点**：CythSec 未来必然生成主动响应报文（RST/ICMP/DNS 重定向）。这些报文的
  头部字段若含常量、若来自固定随机源、若可被差分估算出种子，则第三方可识别、可伪造、可规避。
- **CythSec 落点**（三项强制要求）：
  1. **响应包构造规范**：IPID / TTL / TCP window 等易被差分建模的字段必须来自经工程化的随机源
     （非固定种子、非可推导序列），且不得与其他字段存在线性耦合；
  2. **常量清单化**：所有协议交互中的固定值（flags、选项顺序、压缩指针用法）登记在
     `docs/architecture/response-fingerprint.md`，逐项判定「必须固定 / 应当随机 / 可配置」；
  3. **自身指纹回归测试**：对自产响应包跑一组差分与边界探针，断言「无法从少量样本反推常量或种子」。
- **建议任务**：`CYS-TRF-047` 响应报文构造与自身指纹卫生（P1/M）；
  `CYS-SEC-013` 自身指纹清单与回归测试（P1/M，与安全域联动）
- **验收**：自身响应包的差分分析报告不含恒定种子；随机性测试（如 NIST SP 800-22 子集）通过；边界探针不暴露固定整数阈值。

#### C2. 「能力边界」作为可测属性（对应 F29 F30 F34）

- **方法学**：论文用三类探针（17/18 跳压缩指针、分片数递增、长度字段排列）精确刻画
  中间盒「在什么输入上放弃解析」。这是**把健壮性变成可测量量**的方法论。
- **CythSec 落点**：
  1. 为每个解析器维护「能力边界清单」：在哪些畸形输入下放弃、放弃后的语义（丢/旁路/告警）；
  2. 提供 `tools/boundary-probe`：生成边界探针语料（分片数、压缩指针深度、长度字段排列、
     扩展链长度、选项区越界），对**自有组件**做一致性测试（不是对外扫描）；
  3. 把边界值做成配置项（如 TSG 的 `ipv4_reassembly_enabled`），并在配置文档中说明其副作用
     （TSG 的教训是：边界写死在代码里 → 变成指纹）。
- **建议任务**：`CYS-TLS-008` 解析能力边界探针工具（P2/M）；边界清单文档纳入 `CYS-DOC-**`
- **验收**：每个解析器有边界清单与对应测试用例；边界值可配置且改动不影响其他解析器。

#### C3. 同构测试床与确定性网络条件（对应 F27）

- **TSG 做法**：Docker 三容器拓扑（端点 / DPI / 转发容器，转发容器重写 MAC 以便出网）+ Kafka。
- **CythSec 落点**：`tests/e2e` 建立确定性拓扑（network namespace 或 Docker Compose），
  **额外能力**（TSG 未展示）：用 `tc netem` 注入乱序、丢包、重复、分片、MTU 收缩，
  以验证 `crates/reassembly` 与超时老化逻辑；所有 e2e 用例消费固定 pcap，输出可快照断言。
- **建议任务**：`CYS-TST-016` 确定性 e2e 拓扑与损伤注入（P1/L）
- **验收**：乱序/丢包/分片注入下断言稳定可复现；同一 pcap 两次运行的 FlowRecord 输出逐字节一致。

#### C4. 差分模糊测试与内存安全（对应 F39）

- **论文依据**：§7 把「C 核心 + 缺乏代码验证」列为风险，并指出模糊测试/符号执行是遗留空白。
- **CythSec 落点**：在既有 `CYS-TRF-026`（cargo-fuzz）与 `CYS-PKT-027/028`（ASan/UBSan/TSan）之上，
  增加**差分模糊**：同一 pcap 输入，比较「自研解析器」与「外部引擎（B1 的隔离进程）」
  的协议判定与字段提取差异，差异即为二者之一的缺陷候选（需人工裁决）。
- **建议任务**：`CYS-TST-017` 差分模糊测试框架（P2/M，依赖 CYS-TRF-044）
- **验收**：差分语料库可累积；每周至少一次长跑（≥ 6 h）无崩溃；发现差异自动落盘最小复现样本。

#### C5. 误报治理流程与连带影响分析（对应 F40 F41 F42）

- **TSG 教训**：误封（collateral damage）是其客户投诉的主要来源（F41），处置方式是人工 Jira
  流程 + 三级放行逻辑；F42 显示「封堵失效」也依赖跨项目的经验复用。
- **CythSec 落点**（三项，均为工程化超越）：
  1. **上线前影响面推演**：给定候选规则与历史 FlowRecord 集（ClickHouse），
     在**离线**环境推演命中集合与连带命中集合，输出「新增命中 / 连带命中 / 白名单拦截」三类计数；
  2. **规则级健康度指标**：命中量、白名单拦截率、唯一 FQDN 数、随时间的新增命中曲线
     （对齐 `CYS-TEL-**` 遥测）；
  3. **反馈闭环**：误报工单 → 白名单/签名修订 → 回归用例落库，形成「误报即测试」的资产沉淀。
- **建议任务**：`CYS-TST-015` 规则影响面推演工具（P1/L）；指标纳入 `CYS-TEL-014`（新）可观测性扩展
- **验收**：任一规则上线前必须产出推演报告；报告含三类计数与 Top-N 受影响资产；误报修订自动生成回归用例。

#### C6. 端到端可追溯审计（对应 F15 F40 F43）

- **TSG 弱点**：论文显示其运维依赖 Jira/Confluence 人工流程，缺少「规则 → 命中 → 动作 → 效果」
  的机器可追溯链路；升级包导致核心进程重启也缺少前置校验（F43）。
- **CythSec 落点**：以 `request_id` 为轴贯通：
  规则版本 → 下发事件（谁、何时、diff）→ 判定事件（属性快照、命中规则、置信度）→
  处置事件（动作、是否 dry-run、结果）→ 效果指标。存储采用 ClickHouse 列存，
  控制台可下钻。**签发与下发分离**：下发者与审批者不同主体（对齐 `threat-model.md` T1/T2 的缓解要求）。
- **建议任务**：`CYS-STO-011` 判定与处置事件 schema（P1/M）；`CYS-TEL-014` 可观测性扩展（P1/M）
- **验收**：任一次处置可经 `request_id` 还原完整因果链；schema 冻结并版本化；控制台可下钻到属性快照级别。

### 3.4 D 组：部署与性能（2 项）

#### D1. 部署模式语义化（对应 F26 F8）

- **TSG 做法**：支持 inline（需 VXLAN overlay）与 transparent（不重写 MAC 的不完整 L2 转发）、on-path
  与 off-path；论文点明**旁路无法丢弃报文**。
- **CythSec 落点**：配置中显式声明部署模式枚举（`bypass` / `span` / `on_path_inline` /
  `on_path_transparent`），并让**能力可用性**随模式自动收敛：`bypass` 模式下
  `drop_stream` 类动作自动降级为「告警 + 注入」，不允许静默失败。控制台需展示当前模式与
  「哪些动作不可用」。
- **建议任务**：纳入 `CYS-DEP-**` 与 `CYS-CON-**` 范围；新增 `CYS-DEP-013` 部署模式与能力收敛（P1/M）
- **验收**：切换模式后 `/api/v1/capabilities` 反映可用动作集合；不可用动作在前端置灰并给出原因。

#### D2. 性能门禁与对标（对应 F45）

- **关键事实**：论文**未报告任何吞吐指标**（F45）。这意味着「超越 TSG」在性能维度上
  缺少公开基准——因此 CythSec 应当**自建可对标、可回归的门禁**，而不是宣称对比。
- **CythSec 落点**：
  1. 基准矩阵：收包（PPS/Gbps，按后端分档）、解析（每包 ns，按协议分档）、
     流表（插入/查询 ops/s，1M 流）、特征提取（流/s）、重组（乱序吞吐）；
  2. 门禁：`CYS-PKT-029` / `CYS-TRF-037` 的基准结果入库，CI 中回归超阈值即失败；
  3. 文档：`docs/performance/` 记录硬件、内核版本、参数与原始数据，杜绝「无据性能宣称」。
- **建议任务**：`CYS-DOC-021` 性能对标报告（本方案文档即为 `CYS-DOC-021` 的组成部分之一，性能部分独立成篇）
- **验收**：每次发布附基准报告；回归超阈值阻断合并；报告含可复现命令与原始 JSON。

---

## 4. 超越 TSG 的六个具体维度

「超越」不是功能列表堆叠，而是在 TSG 已被实证暴露短板的维度上系统性领先。以下六项均有
论文原文依据，可在验收时作为硬指标。

| # | 维度 | TSG 的问题（论文依据） | CythSec 的目标态 | 验收信号 |
| --- | --- | --- | --- | --- |
| S1 | **内存安全与崩溃隔离** | 核心组件为内存不安全的 C（F39）；第三方 `.so` 段错误导致 SAPP 重启（F43） | Rust 实现全部解析/重组/特征路径；第三方引擎以独立进程隔离，崩溃即降级 | 长跑模糊测试无崩溃；SIGKILL 外部引擎后主流程存活 |
| S2 | **规则质量** | 规则表无冲突/冗余检测；误封靠人工投诉驱动（F40 F41） | 规则编译期冲突与冗余检测；上线前影响面推演；误报即回归用例 | 冲突用例在编译期报错；每规则附推演报告 |
| S3 | **置信度融合替代硬聚合** | 多路径判定「各自发布 + 硬聚合」，无置信度（F15 F37） | 每个检测事件带置信度与命中明细，`risk` 层做可解释融合（已有 `CYS-TRF-031` 的「可解释评分」目标） | 判定输出含命中明细与贡献权重 |
| S4 | **自身指纹卫生** | 常量 seed(13)、硬编码 DF、恒定 0x8180、整数边界均可远程指纹（F29–F33） | 响应包随机源工程化；常量清单化；自身指纹回归测试 | 差分分析无反推常量；指纹回归用例常驻 CI |
| S5 | **属性/特征/规则/签名的单一真源** | 签名内部格式转换代码缺失（F19）；组件各自独立版本，指纹一个不代表另一个（§3.2 Takeaway） | 属性字典 + 特征 schema + 规则 IR + 签名 IR 四者同源、版本化、双向无损 | 四端绑定生成一致；往返 diff 为空 |
| S6 | **许可工程化** | 直接拷贝 GPL 的 nDPI 代码进入产品（F23），升级与修复被动 | 外部引擎走进程隔离 + 许可清单（隔离是为可维护性与可升级性，不是禁用）；SBOM 可生成 | 依赖许可清单完整；SBOM 可生成；外部引擎可独立升级 |

> 附注：TSG 有一项 CythSec 不应模仿的「优势」——**它把版本一致性做得比其他维度更诚实**：
> 论文指出「一个部署可能跑同版本 SAPP 但不同版本 SSL 插件」，故「指纹到一个插件不代表另一个存在」。
> 这个教训反过来要求 CythSec 必须提供**部署清单与版本上报**（每个插件版本可查询），
> 否则可观测性会退化。落点：`CYS-TEL-**` 的组件版本指标。

---

## 5. 落地路线图（对齐既有里程碑）

| 阶段 | 目标 | 引入项 | 依赖的既有里程碑 | 出口标准 |
| --- | --- | --- | --- | --- |
| **P1 地基** | 属性与特征有单一真源，插件模型成型 | A1 A3 B2 | M2（`CYS-PKT-024` 共享内存契约）、M3 | 新增解析器零改动核心；四端绑定生成通过 |
| **P2 判定** | 规则引擎可表达、可加载、可校验 | A5 A6 A2 | M4（policyd 骨架） | 规则 IR 往返无损；四加载后端同套测试通过 |
| **P3 闭环** | 处置原语全集落地：13 类动作 + 白名单 + 影响面分析 | A4（含 `CYS-TRF-046` `CYS-POL-020`）B5 C5 D1 | M4 M5 | 13 类动作各有单测与回放动作日志；推演报告成为上线前置 |
| **P4 检测深化** | 多引擎分层与签名生命周期 | B1 B4 B3 | M7（ML / 威胁情报） | 外部引擎隔离可用；签名往返无损 |
| **P5 超越验证** | 质量与性能门禁全部落地 | C1 C2 C4 C6 D2 S1–S6 | M9（测试·安全·文档·发布） | 模糊长跑、指纹回归、基准门禁全部常驻 CI |

**关键路径提示**（与 `SPRINT-01.md` §6 的判断一致）：`CYS-PKT-024`（C++ ↔ Rust 通道契约）
是 A2/A4/B2 的共同前置，应尽早冻结；`CYS-POL-017`（规则 IR）是 A5/A6/B5/C5 及
`CYS-POL-020`（动作参数化）的共同前置，必须在 policyd 骨架落地时一次性把结构定对，
否则后续全部返工。

---

## 6. 已识别风险

| # | 风险 | 等级 | 依据 | 缓解 |
| --- | --- | --- | --- | --- |
| R1 | 规则 IR 定型过早导致后期返工 | 高 | A5/A6/B5/C5 均依赖它 | 在 `CYS-POL-002/003/004` 阶段以「往返无损 + 表驱动测试」作为关口，不达标不进 P3 |
| R2 | 外部 DPI 引擎的许可与升级风险 | 中 | TSG 拷贝 nDPI(GPL) 源码后升级与修复被动（F23） | 进程隔离 + 许可清单 + SBOM 审计（推荐隔离引入而非源码嵌入） |
| R3 | 处置误伤（连带命中） | 高 | F41：TSG 单策略多 deny 导致其他应用被连带拒绝，客户不满 | 上线前影响面预演（G3）；白名单优先（G4）；规则编译期互斥与冗余校验（`CYS-POL-004`） |
| R4 | 白名单（B5）成为大规模放行漏洞 | 中 | 白名单先于拒绝判定 | 白名单变更与规则变更同等审批；命中留痕；支持按规则限定白名单作用域 |
| R5 | 属性字典膨胀导致性能退化 | 中 | 属性越多，每包计算成本越高 | 属性按「需要才计算」分级（lazy evaluation），给出分级与代价表；基准门禁覆盖 |
| R6 | 自身响应包随机源实现不当（如用弱 PRNG） | 中 | C1 的目标即防差分建模 | 随机源用 CSPRNG；补充统计随机性测试；常量清单评审 |
| R7 | 论文事实被过度外推（如把「架构描述」当成「已验证行为」） | 中 | F44：源码未公开，作者未发布构建 | 本方案所有引入项基于架构描述，须在 CythSec 自有测试中**独立验证**；不得引用论文数据当作性能依据 |
| R8 | 引用来源风险 | 中 | F1 F44；论文伦理章节明确不公开源码与构建 | 仓库内只引用公开论文与其开放产物（Zenodo），不引入任何泄漏源码/文档 |

---

## 7. 处置原语全集与工程约束（全量引入）

本版按**全量引入**口径推进：论文描述的 TSG 全部阻断与篡改动作均纳入 CythSec 范围。
本节给出动作矩阵（7.1）、动作对部署模式与协议的依赖（7.2），以及随动作一同交付的
**工程约束**（7.3–7.4）。约束的动机是工程可靠性与可维护性——TSG 的两次可复现事故
（多动作策略连带封禁引发客户不满 F41；第三方库段错误拖垮核心进程 F43）在设计阶段即可避免。

### 7.1 处置动作矩阵（TSG 全集 → CythSec 原语）

| # | 动作 | TSG 语义与参数（论文出处） | CythSec 原语 | 落点任务 |
| --- | --- | --- | --- | --- |
| 1 | 流丢弃 | `MSO_DROP_STREAM`：丢弃该流后续全部报文（F8） | `drop_stream(session)` | CYS-TRF-041 |
| 2 | 单包丢弃 | `MSO_DROP_CURRENT_PKT`：仅丢弃当前处理报文（F8） | `drop_current_packet(pkt)` | CYS-TRF-041 |
| 3 | TCP RST 注入 | `NUM`=1–3 个；`FLAGS`=4(RST)/20(RST+ACK)；默认 1 个 RST+ACK（F28） | `reset_stream(count, flags)` | CYS-TRF-046 |
| 4 | ICMP 不可达注入 | `send_icmp_unreachable`（F13 F16） | `inject_icmp_unreachable(code)` | CYS-TRF-046 |
| 5 | 会话级节流 | 以 N bps 初始化令牌桶，按决策丢包（F16） | `rate_limit(Session, bps)` | CYS-TRF-041 |
| 6 | 包级节流 | 丢弃尺寸大于配置 bps 的报文（F16） | `rate_limit(Packet, max_bps)` | CYS-TRF-041 |
| 7 | HTTP 状态码注入 | 注入 200 / 204 / 403 / 404 响应（F16） | `inject_http(code)` | CYS-TRF-046 |
| 8 | HTTP 重定向 | 注入 302 / 303 + 目标站点（F16） | `inject_http_redirect(code, url)` | CYS-TRF-046 |
| 9 | DNS 重定向 | 应答重定向（F16） | `inject_dns_redirect(rrset)` | CYS-TRF-046 + `dnsd` 联动 |
| 10 | 邮件阻断 | 注入 `550 ...spam` 或 `551 User not local`（F16） | `inject_smtp(code, text)` | CYS-TRF-046 |
| 11 | SIP 阻断 | 注入 `SIP/2.0 480 Temporarily Unavailable` 或 `500`（F16） | `inject_sip(code, text)` | CYS-TRF-046 |
| 12 | 载荷篡改 | 交换载荷首尾各 2 字节 → 丢弃原包 → 构造并发送改包；可按每包或按采样参数执行（F16） | `tamper(scope=Every\|Sampled, ratio)` | CYS-TRF-046 |
| 13 | 延迟阻断 | `after_n_packets`：处理满 N 个报文后才生效（F13 F16） | `defer(after_n_packets)` | CYS-POL-020 |

**动作参数化要求**（源自 TSG 的可配置性设计，F28）：每个动作的外部可配置项必须在
规则 IR 中显式建模，并与实现默认值分离——TSG 的 `NUM` / `FLAGS` / `SEED1` / `SEED2`
即为范例。`CYS-POL-020` 负责把上述 13 类动作与其参数纳入规则 IR 的 `action_parameter` 结构，
保持「动作类型与动作参数解耦」（A5 第 3 条）。

### 7.2 动作可用性由部署模式与协议决定

TSG 的关键约束（F8 F26）：**旁路部署只能观测与注入，无法丢弃报文**（in-path 是丢包的前提）；
且各动作只对特定协议有意义（HTTP 码注入对纯 TLS 流无意义）。

| 部署模式 | drop_stream / drop_current_packet | reset_stream / inject_* | rate_limit | tamper |
| --- | --- | --- | --- | --- |
| `bypass`（端口镜像 / SPAN） | ✗ 不可用 | ✓ 可注入（旁路注入） | ✗ | ✗ |
| `on_path_inline` | ✓ | ✓ | ✓ | ✓ |
| `on_path_transparent` | ✓ | ✓ | ✓ | ✓ |
| `Pcap`（离线回放） | ✓（模拟） | ✓（写入输出 pcap） | ✓（模拟） | ✓（模拟） |

实现要求：`EnforcementBackend::is_available(action, mode, session)` 必须显式回答可用性，
**不允许静默失败**；控制台需展示当前模式与「哪些动作不可用及原因」（对齐 `CYS-DEP-013`）。
动作与协议的适配性由 `CYS-POL-020` 在规则编译期校验（例如 HTTP 码注入要求该流已识别为 HTTP）。

### 7.3 随动作交付的工程约束

| # | 约束 | 具体做法 | 动机（工程依据） |
| --- | --- | --- | --- |
| G1 | **离线可回放** | `DryRun` / `Pcap` 后端把「判定 + 动作」全量写入动作日志；同一 pcap 输入两次运行结果逐字节一致 | 处置逻辑无独立测试手段将无法回归；这是最有效的可测试性投资 |
| G2 | **判定—动作—效果审计链** | 以 `request_id` 贯通：规则版本 → 下发 diff → 属性快照 → 命中规则 → 动作与参数 → 结果 | TSG 依赖 Jira 人工流程（F40），无法机器追溯；`CYS-STO-011` / `CYS-TEL-014` 承担 |
| G3 | **上线前影响面预演** | 候选规则先在历史 FlowRecord 上离线推演，输出「新增命中 / 连带命中 / 白名单拦截」三类计数与 Top-N 资产 | F41：TSG 因单策略含多条 deny 导致其他应用被连带拒绝，客户明确不满 |
| G4 | **白名单优先于拒绝** | 负条件 `excludes[]` 与白名单为裁决链的优先层，命中留痕 | F21 F38 F41：TSG 在误封之后才补上「IP 段 + Top SNI」白名单保护 |
| G5 | **执行面权限分离与结构化下发** | 处置执行面以独立最小特权子进程承载；nftables 规则参数化构造，禁止字符串拼接 | `threat-model.md` E1（root 边界）与 T1（策略注入）；论文亦暴露 TSG 核心进程无隔离（F43） |
| G6 | **崩溃隔离** | 第三方引擎（规则库 / 识别引擎）以独立进程 + IPC 挂载，崩溃降级为「该引擎本轮不可用」 | F43：`libqmbundle` 段错误导致 SAPP 重启 |
| G7 | **可编排的动作组合** | 一条规则可指定主动作 + 子动作（TSG 为 `sub_action`，F13），如「先篡改再延迟阻断」；组合需在编译期做互斥校验 | TSG 的 `sub_action` 是隐式组合；显式建模可避免语义冲突 |
| G8 | **性能宣称只引用自有基准** | 论文未报告吞吐（F45），任何性能结论必须来自 `CYS-PKT-029` / `CYS-TRF-037` 的实测数据 | 无据性能宣称在技术评审中不可辩护 |

### 7.4 变更治理

1. **规则与白名单同等对待**：两者均版本化（`CYS-POL-006`）、留 diff、可回滚；
   白名单变更与规则变更走同一审批流（依据 G3 G4——白名单直接决定放行范围）。
2. **动作上线的双闸门**：规则编译期校验（冲突 / 冗余 / 动作-协议适配，`CYS-POL-004`）
   + 影响面预演报告（G3），两者齐备方可进入下发队列。
3. **紧急回滚**：任一下发批次必须预先登记回滚版本；热更新失败保持旧版本生效并告警（`CYS-POL-018` 验收项）。

### 7.5 用途声明（非技术约束）

本方案的技术内容全部来自公开论文（USENIX Security 2026）与其开放产物，未引入任何泄漏源码
或文档（F44）。指纹类方法（DNS 压缩指针边界、分片边界、RST 头字段差分、TLS/QUIC 长度字段排列）
在 CythSec 中的工程用途为：**自身组件的行为一致性验证**（C2）、**自身响应报文的防指纹**（C1）、
以及**授权范围内的对端设备类型识别**。工具层的用途边界不替代部署方对其自身授权范围与
适用法律的判断——`LICENSE` 与 `threat-model.md` 已就此给出项目侧的表述，此处不重复展开。

---

## 8. 参考

### 8.1 主论文

- Anna Ablove, Johnnie Walker, Ben Wolin, Niklas Niere, Felix Lange, Aaron Ortwein,
  Armin Huremagic, Richa Priyanka, Ali Zohaib, Jade Sheffey, Nico Heitmann, J. Alex Halderman,
  Juraj Somorovsky, Amir Houmansadr, Roya Ensafi, Mingshi Wu, Eric Wustrow.
  *Technical Analysis of the Geedge Networks Firewall Source Code Leak.*
  35th USENIX Security Symposium, 2026, pp. 3123–3142.
  本地：`docs/TSG-docs/usenixsecurity26-ablove-en.pdf`（英文 20 页）、
  `docs/TSG-docs/usenixsecurity26-ablove.pdf`（中英对照 40 页）。
  开放产物：论文 Open Science 章节所述 Zenodo 记录（含匿名化 PCAP、扫描器与脚本）。

### 8.2 论文中被 CythSec 直接借鉴的技术来源

| 技术 | 出处（论文引文） | CythSec 引入项 |
| --- | --- | --- |
| libprotoident（首 4 字节启发式识别） | [6] Libtrace Team | B1 第 1 层 |
| nDPI | [15] Deri et al., 2014 | B1 第 3 层（隔离引入） |
| Qosmos ixEngine | [18] Enea AB | B1 第 3 层（商用对照） |
| Censor-Scanner（长度字段排列测试） | [29] Niere et al., IEEE S&P 2025 | C2 探针语料 |
| Geneva（分片与规避策略生成） | [11] Bock et al., CCS 2019 | C3 损伤注入参考 |
| 全加密流量检测（长度/熵/位分布） | [46] Wu et al., USENIX Sec 2023 | B3 统计指纹 |
| DPI 设备歧义指纹 | [48] Xue et al., CCS 2025 | C1 C2 方法学 |

### 8.3 项目内相关文档

- `docs/planning/BACKLOG.md` —— 349 任务 / 9 里程碑；本方案新增编号均从各域现有上限顺延。
- `docs/planning/SPRINT-01.md` —— 本轮编排与关键路径判断。
- `docs/security/threat-model.md` —— 参照模型；本方案 §7.3 的 G5（执行面权限分离与结构化下发）
  与其 E1（root 边界）、T1（策略注入）直接对齐。
- `capture/pcap/README.md` —— 零第三方依赖与零拷贝契约（本方案 C5/D2 的前提）。
- `README.md` —— 分层与工程映射。

### 8.4 落地实现的代码入口（与 §9 对应）

读 §9 时按下表定位实现；改规则时先看这里，避免在错误的层改动。

| 想改什么 | 改哪里 | 注意 |
| --- | --- | --- |
| 新增/调整属性 | `configs/registry/attributes.json` | 真源；改完必须跑 `python3 tools/codegen/gen-attributes.py` 重新生成四语言绑定 |
| 新增匹配方法或格式 | `services/policyd/internal/ruleir/match.go` | 同时更新 `MethodsFor` / `DefaultMethod` / `DefaultFormat`，否则控制台不会下发该组合 |
| 新增处置原语 | `services/policyd/internal/ruleir/action.go` + `ir.go` 的 `SubActions()` | 三处必须同步：常量、`SubActionAvailable` 的可用性、`requiredProtocol` 的协议要求 |
| 新增编译期校验规则 | `services/policyd/internal/ruleir/compile.go` | 诊断码用稳定标识（`rule.conflict` 等），文案可改、码不可改 |
| 改求值顺序或轨迹文案 | `services/policyd/internal/ruleir/evaluate.go` | 轨迹形状被测试锁定，改文案需同步 `evaluate_test.go` |
| 改装载/版本化语义 | `services/policyd/internal/ruleir/store.go` | `Install` 必须保持「全量成功或全量不生效」的原子性 |
| 改控制面端点或响应字段 | `services/policyd/internal/api/rules.go` | 新字段一律 snake_case；契约由 `rules_test.go` 锁定 |
| 示例规则 | `services/policyd/configs/rules.example.json` | 该文件同时是回归夹具（`example_file_test.go`），改它必须让测试仍绿 |

### 8.5 本方案新增建议任务编号一览

| 编号 | 任务 | 优先级 | 依赖 |
| --- | --- | --- | --- |
| `CYS-TRF-040` | 插件注册表与调度器 | P1/L | CYS-TRF-001 |
| `CYS-TRF-041` | 流控制与处置后端抽象（4 后端 × 13 动作） | P0/L | CYS-PKT-024 |
| `CYS-TRF-042` | 会话级事件总线与判定聚合点 | P1/L | CYS-TRF-040 |
| `CYS-TRF-043` | 属性字典单一真源与多语言绑定 | P0/L | CYS-TRF-028 |
| `CYS-TRF-044` | 外部 DPI 引擎适配层与进程隔离 | P2/L | CYS-TRF-019 |
| `CYS-TRF-045` | 前缀窗口特征与 early-exit 判定 | P0/M | CYS-TRF-027 |
| `CYS-TRF-046` | 报文注入与篡改原语（RST/ICMP/HTTP/DNS/SMTP/SIP + tamper） | P1/L | CYS-TRF-041 |
| `CYS-TRF-047` | 响应报文构造与自身指纹卫生 | P1/M | CYS-TRF-041 |
| `CYS-POL-017` | 规则 IR 结构化（匹配语义/格式正交） | P0/M | CYS-POL-002 |
| `CYS-POL-018` | 规则加载后端抽象与热更新 | P1/M | CYS-POL-017 |
| `CYS-POL-019` | 白名单/排除集一等公民与高效匹配 | P0/L | CYS-POL-017 |
| `CYS-POL-020` | 处置动作全集与参数化（13 类动作入 IR） | P0/M | CYS-POL-017 |
| `CYS-PKT-032` | 隧道与封装解析（VXLAN/GRE/PPPoE）与内外层属性 | P1/L | CYS-PKT-016 |
| `CYS-TIP-011` | 签名注册表与格式双向转换 | P1/L | — |
| `CYS-TST-015` | 规则影响面推演工具 | P1/L | CYS-TRF-033 |
| `CYS-TST-016` | 确定性 e2e 拓扑与损伤注入 | P1/L | CYS-PKT-006 |
| `CYS-TST-017` | 差分模糊测试框架 | P2/M | CYS-TRF-044 |
| `CYS-TLS-008` | 解析能力边界探针工具 | P2/M | CYS-PKT-006 |
| `CYS-TEL-014` | 可观测性扩展（规则健康度/组件版本） | P1/M | CYS-TEL-001 |
| `CYS-STO-011` | 判定与处置事件 schema | P1/M | CYS-STO-001 |
| `CYS-DEP-013` | 部署模式与能力收敛 | P1/M | CYS-DEP-001 |
| `CYS-INF-035` | 可重现构建与 SBOM | P2/M | CYS-INF-020 |
| `CYS-SEC-013` | 自身指纹清单与回归测试 | P1/M | CYS-SEC-001 |
| `CYS-DOC-021` | 本方案文档 | P1/M | — |

> 编号分配：共 24 项，均从 `BACKLOG.md` 各域现有最大编号顺延（`TRF` 40→47；`POL` 17→20；
> `TEL` 14；`STO` 11；`TIP` 11；`TST` 15→17；`TLS` 8；`PKT` 32；`DEP` 13；
> `INF` 35；`SEC` 13；`DOC` 21）。

---

## 9. 实现落地记录（第一批：治理层 + 控制面）

本节记录**已落地并经验证**的部分。与第 3 节的关系：第 3 节是「应该做什么」，本节是
「已经做了什么、怎么验证的、还剩什么」。**未在本节出现的能力一律视为尚未实现**——
方案文档与代码之间最容易出现的偏差，就是把「计划」读成「已有」。

落地范围刻意限定在**治理层与控制面**：属性字典、规则 IR、编译期校验、求值引擎、
装载与版本化、只读 API。这一层不碰数据面转发路径，因此可以在不动 `dataplane/`
的前提下先立契约；而契约正是后续所有数据面工作的前置。

### 9.1 落地清单

| 编号 | 能力 | 实现位置 | 状态 |
| --- | --- | --- | --- |
| A1 | 属性—规则—动作三层解耦 | `configs/registry/attributes.json`（真源）+ `services/policyd/internal/ruleir/` | ✅ 已落地 |
| A3（治理部分） | 声明式能力注册与元数据下发 | `GET /api/v1/attributes` | ✅ 已落地 |
| A5 | 规则 IR 结构化（匹配语义/格式正交） | `ruleir/match.go`（8 种 `match_method` × 5 种 `format`） | ✅ 已落地 |
| A5′ | 规则加载后端抽象 | `ruleir/store.go`（`memory` / `json-file` 已实现；`redis` 留接口） | ✅ 部分（后端 2/3） |
| A6 | 规则编译期校验与热更新语义 | `ruleir/compile.go` + `Registry`（revision / checksum / rollback） | ✅ 已落地 |
| B5 | 白名单 / 排除集一等公民 | `ruleir/evaluate.go`（allow 先行 + `excludes`） | ✅ 已落地 |
| C4 | 规则冲突与冗余检测 | `ruleir/compile.go`（`rule.conflict` / `rule.duplicated` / `rule.subsumed` / `rule.negate_contradiction`） | ✅ 已落地 |
| C2（部分） | 试算与回放（离线预演） | `POST /api/v1/rule-tables/{name}/evaluate` | ✅ 已落地（端点层） |
| C5（部分） | 判断影响面 | 试算端点返回完整求值轨迹 | ✅ 已落地（端点层） |
| D2 | 部署模式与能力收敛 | `ruleir/action.go`（4 模式 × 11 原语可用性矩阵） | ✅ 已落地（判定层；内联数据面未接） |
| A2 / A4 / B1–B4 / C1 / C3 / D1 | 数据面、收包、检测算法、指纹卫生、性能门禁 | — | ⬜ 未落地 |

### 9.2 新增文件与规模

| 文件 | 行数 | 职责 |
| --- | --- | --- |
| `configs/registry/attributes.json` | 143 | 属性字典**唯一真源**（98 个属性，含类型 / 作用域 / 计算阶段 / 代价 / 来源） |
| `tools/codegen/gen-attributes.py` | 805 | 由真源生成 Go / Rust / TS / Python 四语言绑定（含 `--check` 幂等校验） |
| `scripts/verify/check-attributes.sh` | 62 | 生成物一致性关口（退出码 0/1/2/3 分语义） |
| `services/pkg/attributes/gen.go` | 387 | Go 绑定（生成物） |
| `services/policyd/internal/ruleir/`（实现） | 3,354 | 规则 IR、匹配语义、动作模型、编译校验、求值引擎、装载与版本化 |
| `services/policyd/internal/ruleir/`（测试） | 1,933 | 同上；测试与实现在同一包内并列 |
| `services/policyd/internal/api/rules.go` + `rules_test.go` | 849 | 只读控制面端点 + 契约测试 |
| `services/policyd/configs/rules.example.json` | 231 | 示例规则（同时作为回归夹具） |
| `dataplane/traffic-engine/src/attributes_gen.rs` | 1,155 | Rust 绑定（生成物） |
| `web/console/src/constants/attributes.gen.ts` | 322 | TS 绑定（生成物） |
| `ml/training/features/attributes_gen.py` | 1,051 | Python 绑定（生成物） |

合计约 10,500 行（其中生成物 2,915 行，真源 + 生成器 + 关口 1,010 行）。

### 9.3 关键设计决策（编码时定型，与方案文档的对应关系）

1. **匹配语义与格式归一化正交分离**（对齐论文 §5.3 的 `match_method` / `format`）。
   拆开的好处是组合空间可枚举：8 × 5 的组合由类型约束裁剪后，控制台可以只渲染合法组合，
   而不是让使用者盲填字符串。
2. **部署模式把「能力可用性」从文档约定提升为代码约束**。`SubActionAvailable(原语, 模式)`
   是唯一判定入口，控制台、下发前预检、求值引擎都必须经它。旁路模式下
   `drop_stream` / `drop_current_packet` / `throttle_*` 返回 false——**旁路物理上不在报文
   路径上**，若不做成硬约束，「规则命中但流量照走」的静默失效一定会发生。
3. **严重度按「是否启用」分级**：启用规则使用了当前模式不可用的原语 → 阻塞级错误，
   拒绝装载；停用规则 → 提示级警告，允许装载。前者会让设备静默失去防护，必须拦；
   后者是待办而非缺陷，不该拦。
4. **白名单先于拒绝**（与论文 §4.1.2 的做法相反）。这是刻意的可用性取舍：
   安全设备最贵的故障是误封，而「先拒绝再回头看白名单」意味着每次误封都已生效过一次。
5. **求值轨迹必须写出「期望匹配什么」**。初版只记录命中的对象，导致未命中的条件退化为
   `条件 X:  → 不成立` 这样的空信息行——恰好抹掉了排查「规则为什么没生效」所需的唯一线索。
   现改为列出期望对象集（上限 3 条 + 总数提示）。
6. **求值出错与值不匹配必须在轨迹里区分**（`求值出错: …` vs `未匹配任何对象（期望: …）`）。
   两者的处置动作完全不同：前者改采集，后者改规则。
7. **属性字典真源唯一**：四语言绑定全部生成，`--check` 进 lint 关口。
   手工维护四份副本必然漂移，而漂移的表现是「Go 侧认识的属性 Rust 侧不认识」。
8. **规则表导出/回灌的字段名一律 snake_case**。缺 JSON tag 时 Go 会按字段原名输出
   （`Severity` / `RuleUUID`），前端取 `severity` 得到 `undefined`——不报错、不崩，
   只是一片空白。已加契约测试锁定。

### 9.4 验证结果

| 关口 | 命令 | 结果 |
| --- | --- | --- |
| Go 格式 | `GOWORK=off gofmt -l services/` | ✅ 无输出 |
| Go 静态检查 | `GOWORK=off go vet ./...`（各服务） | ✅ 通过 |
| Go 测试 | `bash scripts/test/test-all.sh --go` | ✅ 全部通过（含 `pkg` + 四服务） |
| 属性字典生成物 | `bash scripts/verify/check-attributes.sh` | ✅ 98 个属性 / 4 个目标文件一致 |
| Rust 格式 | `cargo fmt --all -- --check` | ⚠️ 仅 `build.rs` 有差异（**既有问题，非本次改动**） |
| Rust 测试 | `cargo test --offline` | ✅ 7 passed |
| 端到端冒烟 | 启动 `policyd` 装载示例规则并打全部端点 | ✅ 见 9.5 |

> ⚠️ **既有问题（未修）**：`dataplane/traffic-engine/build.rs` 不符合 rustfmt，
> 因此 `bash scripts/lint/lint-all.sh` 的 Rust 段当前为红。该文件不在本次改动集内，
> 未擅自格式化。修复只需 `cargo fmt --all`。

### 9.5 端到端冒烟记录

以 `-rule-tables-file configs/rules.example.json` 启动，分别在 `bypass` 与
`on_path_inline` 两种模式下验证：

| 场景 | 输入 | 结果 |
| --- | --- | --- |
| 白名单优先（两条件 AND） | `ATTR_SERVER_FQDN=app.corp.internal` + `ATTR_DST_IP=10.1.2.3` | `allow`，轨迹含「白名单命中，跳过其余规则」 |
| 大小写不敏感阻断 | `ATTR_SERVER_FQDN=C2.EXAMPLE` | `deny`，原语 `reset_stream`，参数 `reset_count/reset_flags` 透传 |
| 排除集保护 | `ATTR_SERVER_FQDN=cdn.tracker.example` | 命中规则但「排除集命中，规则不生效」→ 回落默认动作 |
| 同一规则正常生效 | `ATTR_SERVER_FQDN=ads.tracker.example` | `deny` |
| 协议适配校验 | `ATTR_DNS_QNAME=x.malware.example` | `redirect`，原语 `inject_dns_redirect` |
| 前缀窗口早期判定 | 首包载荷前缀 + 长度 | 命中观察规则（`log`） |
| 属性拼写回显 | 混入 `ATTR_TYPO_FQDN` | `unknown_attributes` 显式回显，已登记属性照常参与判定 |
| 部署模式诊断 | 同一文件，`bypass` vs `on_path_inline` | 警告数 3 → 1（旁路下丢包/限速不可用告警消失） |
| 404 / 400 / 503 | `GET` 不存在的表、非法体、未配置规则表 | 分别 `404/4004`、`400/4001`、`503/4004`（503 的文案指出配置项 `rule_tables_file`） |

### 9.6 未落地部分与下一步

1. **数据面（A2 / A4 / C1）**：`trait EnforcementBackend` 与流控制原语尚未写入
   `dataplane/traffic-engine`。前置是 `CYS-PKT-024`（C++ ↔ Rust 通道契约）冻结。
2. **规则下发链路**：`ruleir` 目前只在控制面内求值，尚未经通道下发到数据面执行。
   这是 A2 与 A4 的共同前置。
3. **Redis 加载后端**：`RedisStore` 结构已就位但未实现（缺少可用的 Redis 环境与依赖决策）。
4. **签名注册表（`CYS-TIP-011`）**：格式双向转换尚未开始。
5. **性能门禁（D1）**：论文无吞吐数据，必须自建可对标门禁；当前尚未建立基线与阈值。
6. **`CYS-POL-019` 白名单/排除集的大规模匹配**：当前实现基于逐条表达式求值，
   尚未引入 TSG 那套「1,023 CDN 段 + 56,396 FQDN」规模下的索引结构（如前缀树 / 位图）。
   在规则量进入万级前不构成瓶颈，但需要在 `CYS-POL-019` 中显式设计。

---

## 10. 变更记录

| 时间 | 变更 |
| --- | --- |
| 2026-09-14 | 初版 v0.1.0：完成论文全文（20 页英文版）事实提取（F1–F45）、TSG 架构对位矩阵、19 项技术引入清单、6 项超越维度、5 阶段路线图与合规边界 |
| 2026-09-14 | v0.2.0：改为**全量引入**口径——移除「拒绝引入清单」，新增 §7.1 处置动作矩阵（13 类动作全集，含载荷篡改与延迟阻断）、§7.2 动作可用性矩阵（部署模式 × 动作）、§7.3 八项工程约束（G1–G8）、§7.4 变更治理、§7.5 用途声明；A4 扩展为 4 后端 × 13 动作；新增任务 `CYS-TRF-046`、`CYS-POL-020`（累计 24 项）；R2/R3/R8 风险重述为工程性风险；S6 由「许可清洁」改为「许可工程化」 |
| 2026-09-14 | v0.3.0：新增 §9 实现落地记录——落地治理层与控制面（属性字典真源 + 四语言代码生成 + 规则 IR + 编译期校验 + 白名单优先求值 + 装载版本化 + 只读 API），记录 8 项关键设计决策、验证关口结果与端到端冒烟证据，并显式列出 6 项未落地能力 |
