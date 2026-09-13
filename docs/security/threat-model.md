# 威胁模型 / Threat Model — cythsec v0.1.0

- 文档域：SEC（安全与合规）
- 任务编号：CYS-SEC-001
- 版本：v0.1.0（四层最小纵向切片）
- 维护者：security-expert
- 最后更新：2026-09-14
- 适用代码基线：`services/routerd`（Go 控制面只读 API）、`web/console`（React 控制台）、规划中的 `policyd` / `dnsd` / 数据面抓包。

> 本模型基于对**现存代码**的逐文件核实（行号均来自实际读取），并针对「已规划但尚未实现」的高权限能力（nftables / netlink 路由下发 / DNS 重定向）预留威胁条目。cythsec 本身是安全产品，其自身被攻陷的后果（整机失陷、内网侦察、流量/情报泄露）比普通业务系统更严重，故威胁等级普遍上调半档。

---

## 1. 资产清单 / Asset Inventory

| 资产 | 类型 | 敏感度 | 当前存储/暴露位置 |
| --- | --- | --- | --- |
| 本机网络配置（网卡 / IP / MTU / MAC） | 配置 | 中 | `netinfo.ListInterfaces` → `/api/v1/interfaces` |
| 路由表 | 配置 | 高 | `netinfo.ListRoutes` → `/api/v1/routes` |
| 流量计数器（rx/tx bytes & packets） | 元数据 | 中 | `netinfo.ListTraffic` → `/api/v1/traffic` |
| 抓包数据（可能含明文凭据、SNI、DNS 查询） | 数据 | **极高** | 规划：`dataplane/`（抓包）、`capture/` |
| 策略规则（nftables / 防火墙） | 策略 | **极高** | 规划：`policyd` |
| IOC / 威胁情报 | 情报 | 高 | `threat-intelligence/` |
| ML 模型文件与权重 | 模型 | 高 | `ml/` |
| 凭据（API token、私钥、控制台登录态） | 凭据 | **极高** | `.env` / `secrets/`（已 gitignore）、运行时内存 |
| 系统/内核信息 | 配置 | 低 | `netinfo.GetSystem` → `/api/v1/system` |

---

## 2. 信任边界 / Trust Boundaries

| 边界 | 说明 | 跨越风险 |
| --- | --- | --- |
| 本机 ↔ 内网 | routerd 默认监听 `:8080`（`main.go:27`），对内网可达 | 内网任意主机可直连读取网络拓扑 |
| 内网 ↔ 外网 | 若部署跨网段且无网络隔离 | 明文 HTTP 被中间人嗅探/篡改 |
| 进程 ↔ 内核 | netlink / nftables 需 `CAP_NET_ADMIN`；抓包需 `CAP_NET_RAW` | 越权写内核态 = 整机失陷 |
| 控制面 ↔ 数据面 | 规划中共享内存（`CYS-PKT-024`） | 同机低权进程篡改数据包元数据 |
| 控制台浏览器 ↔ routerd | `web/console` 经 Vite proxy 或反代调用 API | 跨站读取（含 DNS rebinding） |
| 认证主体 ↔ 未认证 | **当前不存在任何鉴权边界**（`server.go:24-29`） | 所有端点对任何人开放 |

---

## 3. 攻击面清单 / Attack Surface

逐项引用真实文件与行号：

| # | 端点/能力 | 位置 | 现状 |
| --- | --- | --- | --- |
| A1 | `GET /healthz` | `services/routerd/internal/api/server.go:19` | 无鉴权，信息无害 |
| A2 | `GET /api/v1/system` | `server.go:24` | 无鉴权，泄露 hostname/os/arch/go_version/pid |
| A3 | `GET /api/v1/interfaces` | `server.go:25` | 无鉴权，泄露全部网卡/IP/MAC |
| A4 | `GET /api/v1/routes` | `server.go:26` | 无鉴权，泄露路由表（内网拓扑） |
| A5 | `GET /api/v1/traffic` | `server.go:27` | 无鉴权，泄露流量计数 |
| A6 | 中间件链 | `server.go:29` | 仅 `logMiddleware`，**无 auth / 无 CORS** |
| A7 | 错误回显 | `server.go:46-48`（writeErr）、`57/66/75` | `err.Error()` 原样返回 |
| A8 | 监听配置 | `main.go:27,30-34` | 默认 `:8080`、无 TLS、无 Read/WriteTimeout |
| A9 | 前端直连 | `web/console/src/api/client.ts:13,25-39` | 无 Authorization 头、无凭据 |
| A10 | 开发代理 | `web/console/vite.config.ts:13-19` | `/api` → `http://localhost:8080` 明文 |
| A11 | 路径拼接 | `traffic.go:42,65-76` | `filepath.Join(iface,...)`，`iface` 来自 `os.ReadDir` 内核枚举 |
| A12 | 配置死文件 | `configs/config.yaml` | 未被加载，规划中的鉴权/TLS 开关无落地 |
| A13 | 抓包（规划） | `dataplane/`、`capture/` | 高权、明文元数据 |
| A14 | 策略下发（规划） | `policyd` | nftables 规则注入 → root 边界 |
| A15 | 路由变更（规划） | `routerd` 未来写路由 | netlink 写 → root 边界 |
| A16 | DNS 重定向（规划） | `dnsd` | 解析篡改 → 流量劫持 |

---

## 4. STRIDE 分析

每条均含：场景 → 影响 → 现有缓解 → 建议缓解 → 风险等级。

### 4.1 Spoofing（伪装）

- **S1 / 内网伪装为控制台**：攻击者在内网任意主机伪装成 Web Console，直接请求 `/api/v1/routes`（`server.go:26`）。因无鉴权，routerd 无法区分合法控制台与攻击者。**影响**：内网拓扑被任意读取。**现有缓解**：无。**建议**：Bearer Token 中间件（见 `auth-design.md`）+ 绑定管理网段。**等级：高**。
- **S2 / DNS rebinding 伪装浏览器源**：受害者浏览器加载恶意网页，该页通过 DNS rebinding 将域名解析到 routerd 内网地址，绕过同源策略读取 `/api/v1/interfaces`（`server.go:25`）。**影响**：跨站内网侦察。**现有缓解**：无 CORS（`server.go:38-44` 仅设 Content-Type）。**建议**：启用 CORS 白名单 + 校验 `Host`/`Origin` + 强制令牌。**等级：高**。

### 4.2 Tampering（篡改）

- **T1 / 策略规则注入（规划）**：`policyd` 下发 nftables 规则时若规则内容拼接自不可信输入，攻击者可注入 `; ...` 或构造恶意规则实现放行/转发/端口镜像。**影响**：防火墙被绕过、流量被复制。**现有缓解**：未实现。**建议**：结构化规则对象 + 参数化下发（禁止字符串拼接）+ 下发前校验 + 审计。**等级：高（规划）**。
- **T2 / 路由表篡改（规划）**：`routerd` 未来写路由若未校验目标，攻击者可注入默认路由实现流量劫持。**影响**：整机/内网流量被重定向。**现有缓解**：未实现。**建议**：路由变更需管理员角色 + 变更审批 + netlink 结构化调用。**等级：高（规划）**。
- **T3 / 抓包数据篡改（共享内存规划）**：`CYS-PKT-024` 共享内存若权限过宽，同机低权进程可改写包元数据欺骗检测引擎。**影响**：检测绕过。**现有缓解**：未实现。**建议**：共享内存限定 owner/组 + 只读映射检测侧 + 校验和。**等级：中（规划）**。

### 4.3 Repudiation（抵赖）

- **R1 / 无审计日志**：所有端点与未来写操作均无操作日志（`server.go:81-87` 仅记录 method/path，无主体/结果）。**影响**：无法追溯谁改了路由/策略。**现有缓解**：无。**建议**：落盘审计日志（见 `audit-logging.md`），含主体/动作/目标/结果/request_id。**等级：中**。
- **R2 / 错误回显无关联**：`writeErr`（`server.go:46-48`）回显错误但不带 request_id，事后无法关联。**影响**：事件不可关联。**建议**：错误响应带 `request_id` 并写入审计。**等级：低**。

### 4.4 Information Disclosure（信息泄露）

- **I1 / 零鉴权暴露网络拓扑**：`/api/v1/interfaces` + `/api/v1/routes`（`server.go:25-26`）等于把内网地图白送。**影响**：内网侦察、后续横向移动。**现有缓解**：无。**建议**：鉴权 + RBAC + 网络隔离 + 可选字段脱敏。**等级：高**。
- **I2 / 错误信息泄露系统细节**：`err.Error()` 原样返回（`server.go:57,66,75` → `46-48`），可能泄露路径、内核接口名、内部状态。**影响**：辅助攻击者构造利用。**现有缓解**：无。**建议**：返回通用错误 + 详情入库（带 request_id）。**等级：中**。
- **I3 / 明文 HTTP**：`main.go:30-34` 无 TLS，跨网段明文。**影响**：凭据/拓扑被嗅探。**建议**：TLS 终止于反代或进程内；内网也建议 mTLS。**等级：高（跨网段）/ 中（纯本机回环）**。
- **I4 / 抓包元数据隐私（规划）**：明文 SNI/DNS/凭据进入 `capture/`（`dataplane/`）。**影响**：隐私/合规风险（尤其澳州隐私法）。**建议**：元数据最小化、加密落盘、访问控制、留存期限。**等级：高（规划）**。
- **I5 / 路径注入评估（现有）**：`readCounter`（`traffic.go:65-76`）用 `filepath.Join(iface,"statistics",stat)`，`iface` 来自 `os.ReadDir(sysNetDir)`（内核枚举名，非用户输入）。**结论**：当前**不可利用**，等级低；但若未来允许通过 HTTP 参数指定 iface，则升级为高。**等级：低（接受，理由：输入源可信）**。

### 4.5 Denial of Service（拒绝服务）

- **D1 / 无超时与限流**：`main.go:33` 仅 `ReadHeaderTimeout`，无 `ReadTimeout`/`WriteTimeout`；无请求体大小限制、无速率限制。**影响**：慢速连接/大响应耗尽连接（当前仅 GET、风险有限，扩展写接口后放大）。**建议**：补全超时 + 限流 + 响应裁剪。**等级：低（当前）/ 中（扩展后）**。
- **D2 / 递归目录读取开销**：`ListTraffic`/`ListRoutes` 读 `/sys`/`/proc`，高频调用放大 I/O。**影响**：本地资源耗尽。**建议**：缓存 + 节流 + 端点级配额。**等级：低**。

### 4.6 Elevation of Privilege（权限提升）

- **E1 / 控制面被拿下后提权到 root（规划）**：若 `policyd`/`routerd` 写能力以 root 运行且被 RCE，攻击者可经 nftables/netlink 完全控制主机网络栈。**影响**：整机失陷。**现有缓解**：未实现。**建议**：控制面**不以 root 运行**；仅数据面抓包需 `CAP_NET_RAW`；写内核能力用独立最小特权子进程 + `NoNewPrivileges` + `CapabilityBoundingSet`（见 `hardening.md`）。**等级：高（规划，必须卡死）**。
- **E2 / 默认绑定全接口**：`main.go:27` 默认 `:8080` 绑定 `0.0.0.0`。**影响**：扩大暴露面。**建议**：默认绑定 `127.0.0.1`，生产经反代 + 网络策略放开。**等级：中**。
- **E3 / 供应链投毒**：Go/C++/Rust/Node 依赖被投毒。**影响**：构建/运行时代码执行。**建议**：`govulncheck` + 锁文件 + 私有代理 + SBOM。**等级：中**。

---

## 5. 重点场景 / Key Scenarios

1. **内网攻击者直连 8080 获取拓扑**：A2–A5 零鉴权 → I1（高）。
2. **浏览器跨站读取（含 DNS rebinding）**：A6/A9/A10 无 CORS/无令牌 → S2/I1（高）。
3. **控制面被拿下经 nftables/netlink 提权**：E1（规划，高，强制最小权限隔离）。
4. **抓包隐私与合规**：I4（规划，高，澳州隐私法考量）。
5. **供应链**：E3（中）。
6. **数据面共享内存被篡改**：T3（规划，中）。

---

## 6. 威胁条目汇总表

| ID | 类别 | 等级 | 状态 | 对应交付物 |
| --- | --- | --- | --- | --- |
| S1 | Spoofing | 高 | 待修复 | auth-design.md |
| S2 | Spoofing | 高 | 待修复 | auth-design.md |
| T1 | Tampering | 高(规划) | 设计前置 | auth-design.md + hardening.md |
| T2 | Tampering | 高(规划) | 设计前置 | auth-design.md |
| T3 | Tampering | 中(规划) | 设计前置 | threat-model 4.2 |
| R1 | Repudiation | 中 | 待实现 | audit-logging.md |
| R2 | Repudiation | 低 | 待实现 | audit-logging.md |
| I1 | InfoDisclosure | 高 | 待修复 | auth-design.md |
| I2 | InfoDisclosure | 中 | 待修复 | auth-design.md |
| I3 | InfoDisclosure | 高 | 待修复 | hardening.md |
| I4 | InfoDisclosure | 高(规划) | 设计前置 | compliance.md |
| I5 | InfoDisclosure | 低 | 接受 | 本模型 4.4 |
| D1 | DoS | 低/中 | 待修复 | hardening.md |
| D2 | DoS | 低 | 接受 | — |
| E1 | EoP | 高(规划) | 强制卡死 | hardening.md |
| E2 | EoP | 中 | 待修复 | hardening.md |
| E3 | EoP | 中 | 持续 | security.yml(govulncheck) |

> 每条威胁均已给出缓解措施或明确「接受 + 理由」（I5、D2）。其余为「待修复/待实现/设计前置」，由对应专家落地。
