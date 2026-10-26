# 2026-10-26 核心开发阶段与持久化纵向切片

基线：`1047cba`；本批分支：`feat/aggregate-storage-console`。本记录按实际代码和本轮验证维护，不把历史待办表的里程碑标题当作当前完成率。

## 核心处于什么阶段

当前处于**数据面离线／本机链路可验证，控制面与历史分析进入纵向联调**阶段，尚未达到生产网关验收阶段。

| 层 | 代码事实 | 尚缺的验收或能力 |
| --- | --- | --- |
| 采集与通道 | C++ Ethernet PCAP 回放、macOS BPF／Linux AF_PACKET 后端、共享环和跨语言校验已存在 | Linux 实机复验与持续运行、目标负载吞吐、背压和故障切换未整体验收 |
| Rust 分析 | 流／会话、TCP 重组、协议解析、IPFIX、通用聚合观测入口均有实现与测试 | 合成语料不代表全产品识别精度；统计候选不代表真实网络丢包；尚无城域网线速证明 |
| 存储编码 | 已有 `001_flows.sql`、56 列 Native 编码和 ClickHouse local 正确性关口 | 常驻 ClickHouse 写入／背压／失败重放、规模查询和 PostgreSQL／Redis 业务落地未完成 |
| Go 控制面 | 四服务可启动；routerd 只读网络信息，policyd 策略试算，dnsd 区域内存，telemetryd 目标注册 | 不等于转发策略执行；DNS 报文服务、抓取调度、统一鉴权／RBAC／审计和生产 API 契约未完成 |
| React 控制台 | 本批前已有 Dashboard／Interfaces／Routes／Traffic／System 五页 | 原 Traffic 是接口累计计数，没有历史分析；登录、生产权限控制和策略执行闭环尚未完成 |
| 本批新增 | 聚合结果持久化、校验、去重、重启恢复、历史查询；第六页“聚合分析” | 本地有限容量实现；不等于 ClickHouse 常驻入库或生产数据仓库 |

本批只接受 `cythsec-observe` 的聚合结果，不接受逐用户、逐流载荷、网站域名或 VPN 专属指纹记录，不接入阻断执行。

## 本批交付与验收目标

1. 严格 schema 导入：只接受已知数值／枚举字段；缺字段、null 冒充 0、未知字段、窗重叠、计数不守恒、缺尾记录和超限请求均拒绝。
2. 真正持久化：私有目录、不可变 JSONL 文件、内容地址去重、文件与目录同步、单写进程锁；成功应答只在同步后返回。重启读取相同数据，损坏文件导致启动失败。
3. 有限资源：单批 1 MiB／1024 窗，总计 64 MiB／1024 批；不自动删除历史，不静默转为内存存储。容量满返回 507。
4. 查询与控制台：按批次、窗口起点范围 `[from,to)`、分页查询；保留抑制、采样间隔、分析不完整和来源丢包未知。重叠批次不自动相加。
5. 可执行验证：真实 Rust 输出→Go HTTP→文件→服务重启→逐对象相同；并包含故障反向验证。不是只看 mock API 或页面截图。

契约和运行命令见 [聚合持久化](../observability/persistence.md)。
## 本轮实跑验收

| 命令／检查 | 实际退出码 | 证据和限制 |
| --- | --- | --- |
| `PATH=/tmp/cythsec-format-env/bin:$PATH bash scripts/lint/lint-all.sh` | 0 | 完整静态门禁通过 |
| `bash scripts/build/build-all.sh` | 0 | 四栈构建通过，前端 53 modules，JS gzip 65.96 kB |
| 经本轮批准运行 `CYTHSEC_LIVE_SUDO=1 CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 0 | 含新存储端到端；既有裁判例外仍保留，不能说全部已核验 |
| telemetryd `GOWORK=off go test -race ./...` | 0 | 持久化／API／配置与原有目标模块通过，含并发重试和单写者检查 |
| telemetryd `GOWORK=off go vet ./...` 与新增包覆盖率 | 0 | aggregate 81.5%、api 90.7%，不宣称覆盖所有故障 |
| 前端 typecheck／ESLint／Vitest | 0 | 7 个测试文件、41 项测试通过；含旧请求晚返回、范围分页、重复导入、空值与错误态 |
| `bash scripts/verify/check-aggregate-storage.sh` | 0 | 真实 Rust→HTTP→文件→重启逐对象相同；非法字段、缺尾记录、损坏文件启动失败均检出 |
| `bash scripts/verify/e2e-control-plane.sh` | 0 | 四服务 59 项通过、0 失败、0 跳过；健康、指标、业务查询和优雅退出 |
| Actionlint／shell 语法／新增 Python Ruff、Black、py_compile／diff 检查 | 0 | 通过 |
| Mermaid 与新增文档链接 | 0 | 新增持久化数据路径图语法和入口链接通过 |
| `bash scripts/security/scan-secrets.sh` | 0 | 兜底扫描 0 命中，不代表全面安全审计 |

经本轮单独批准，仅捕获子进程提权；BPF 在 en0 采集 15 秒，取得 **2131 帧**，错误 0，tshark 与写盘一致，自家解码为 2130 IP＋1 其他 L2 帧；前 500 帧共享环消费数一致，合计 **14 项断言通过**。没有可用网关注入目标，没有发送 ping，ICMP 注入核验未执行。

全量门禁仍保留既有 **DPI 14、TCP 重组 2、FlowRecord 8 项未核验**，没有重写为通过。新代码仅本地提交，未合入 main、未推送，GitHub 远端矩阵未运行。

浏览器通过 Vite 开发代理连接真实 telemetryd，导入两个合成窗口后查询、刷新和空值展示符合 API。截图位于本机 `build/aggregate-storage/preview/`；预览仅启动 telemetryd，routerd 未启动，页头因此如实显示 routerd offline。使用合成流量，不将 BPF 原始抓包导入页面。

本机详细日志保存在 `build/aggregate-storage/validation/`，不提交生成物。台账追加 `CYS-STO-013`／`CYS-TEL-016`／`CYS-CON-029` 三项进行中，合计 379：302 未开始／25 进行中／52 完成；历史里程碑标题与部分任务登记仍滞后，本轮没有凭代码存在批量关闭旧任务。

## 后续顺序

- 当前切片验收后，先基于聚合存储测量写入量／查询量，再实现适合该容量的 ClickHouse 常驻写入与查询；保留提交确认、幂等重试、完整性和空值语义。
- 控制面进入受控管理开发：鉴权／权限、配置版本与审计、健康与错误语义，先完善 API 契约再增加写能力。
- 控制台继续接入经过验证的数据与状态，不以静态页面数量替代服务端能力。告警规则、授权管理和生产部署分别验收。
- 真实链路吞吐、丢包校准和长时间运行单独建立性能基线；既有第三方裁判例外不能因页面上线而关闭。
