# Recent local updates, before main integration

These measurements describe the earlier v1 checkpoint. Current integration follows main FlowRecord v2.

### 2.17 FlowRecord 对齐 MergeTree 与真实落盘测量（2026-10-29）

承接 §8 第一梯队第 4 项。`storage/clickhouse/flow_records_v1.sql` 对齐 FlowRecord v1
全部 9 个顶层字段与 21 个特征，Nullable 保留缺失证据、UInt64 保留大计数，命名 Tuple
允许 JSONEachRow 直接导入。首份流表按 epoch 微秒划日分区；完整 M6 的月分区/TTL、
其余表、迁移和常驻写入器仍未完成（`CYS-STO-002` 保持 ◐）。

本机 ClickHouse **26.10.2.103 stable / macOS arm64**：37 条合成协议/会话向量
active parts **9,334 B = 252.27 B/记录**；20,182 条同质压测记录
**437,765 B = 21.69 B/记录**。两档均在写入进程退出后，用独立进程重新打开库并
逐字段读回一致；重复次数保留，不能靠仅比条数掩盖字段丢失。测量产物在
`measurements/clickhouse-storage-*.json`，含输入/DDL/二进制 SHA256 与平台、版本和时间。

复验：`CLICKHOUSE_BIN=/path/to/clickhouse bash scripts/verify/check-clickhouse-storage.sh`。
覆盖 IPv6、UInt64 最大值、null、Unicode/转义、重复行与末行无换行；8 项真实路径注入
（版本×2、嵌套/顶层缺字段与未知字段、溢出、null 计数）必须拒绝，缺引擎退出 3。
纯 Python 比对器自证进默认 `--plan`，真实引擎检查进 CI `clickhouse-storage` 作业
（固定 Linux 26.10.2.103 + 官方 SHA512）。**Docker Desktop Linux 服务复验已完成**（§2.18）；
远端 CI 与物理 Linux 服务器现场复验尚未运行。

**引用边界**：part 总字节包含索引/marks/part 元数据；压缩列流字节另报，工作目录逻辑
长度也另报，均不含复制/备份/合并峰值。小批固定开销与同质语料压缩效果不可互换。
进程耗时含启动/开表/解析/落盘/退出，不是常驻服务吞吐。容量默认值继续对应
**gzip(JSONL) 79.4 B/记录**；下一项是常驻 ClickHouse 写入器的批处理/背压/失败重放
（`CYS-STO-007`）和实际批次/现场语料测量；在线采样点仍依赖 `CYS-PKT-032`。

### 2.18 Docker Compose 服务写入与命名卷持久化（2026-10-30）

用户启动 Docker 后，新增 `deploy/docker/compose.storage-test.yml`，固定 ClickHouse
26.10.2.103 官方镜像、内部测试网络、健康检查与命名卷，不映射宿主机端口。
`python3 scripts/verify/check-clickhouse-compose.py` 自动准备当前源码的分析器与两档语料，
复用 §2.17 的字段比对和故障注入；额外验证真正重建容器后仍可完整读回。

本机 Docker Desktop **Linux arm64** 服务结果：37 条语料 **9,334 B**、20,182 条
**437,765 B**，active parts 总字节与 macOS local 模式逐字节一致（252.27 / 21.69 B/记录）。
8 项错误输入均被检查检出；容器 ID 变化后，两档再次逐字段读回一致。
产物 `measurements/clickhouse-storage-compose.json` 记录镜像、数据卷、输入 SHA256、
容器 ID 和数据库/表。测试服务和测量库保留供检查，故障注入库已清理。

首次镜像拉取超时，使用宿主机获取同一官方 ARM64 镜像并校验各层 SHA256 / diff_id，
通过 `docker load` 导入后完成上述验证。CI 已接入同一 Compose 脚本，远端尚未运行。
**边界**：本批仅 ClickHouse 测试编排；PG/Redis 全套一键起库 `CYS-STO-005` 仍未完成。
容器重建验证正常持久化，不等于断电/崩溃恢复；计时含客户端与传输，不是持续吞吐。

### 2.19 native 批量写入、背压和持久化重放（2026-10-30）

承接 `CYS-STO-007`，新增 `services/pkg/clickhousewriter` 与 `cmd/cythsec-ch-write`。
Go 标准库管理持久化批次队列，官方 `clickhouse-client` 完成 native TCP；没有自写协议或
第三方驱动。队列独占锁、目标绑定、文件/目录同步与原子改名、条数/SHA256 校验，
同步 INSERT 成功才删批次。上限包含在途批次，满时阻塞并响应取消；耗尽重试保留批次。
重启先重放已有队列。按条数/字节/间隔封批，私有队列文件不存密码。

`flow_records_v1_dedup.sql` 独立启用非复制 MergeTree 去重窗口；不改原 DDL 的测量口径。
同一持久化批次始终复用 token，独立同内容提交用新 token。Go 的五组检查与竞态检查
通过；统一 Go 构建/测试、`--plan` 与 lint 均通过。构建入口产出
`build/bin/cythsec-ch-write`，版本继承根 VERSION。

`check-clickhouse-writer.py` 使用 Compose `writer` profile 的独立客户端容器和
`writer_spool` 卷。实际结果：37 条正常写入；两次独立同内容输入保留 74 条；
停机后批次保留、新进程重放 37 条；真正 INSERT 成功后故意返回失败模拟 ACK 丢失，
多次重试及新进程重放后仍为 37 条；20,182 条压力语料完整读回，积压观测
1,417,750 B < 1,600,000 B，背压等待确实发生，恢复后排空。
产物 `measurements/clickhouse-writer.json`。服务恢复健康，测试库和队列目录保留。
CI 接入同一故障脚本，远端未运行。

**剩余边界**：仅 fsync 完成的批次算已接收；内存尾批和文件输入偏移需要上游持久化确认，
不能在失败后盲目重新提交整个文件。去重受有限窗口约束；每批启动一次官方客户端，
尚无物理服务器持续吞吐验收。文件交接/断点已于 §2.20 补齐，`CYS-STO-007` 保持 ◐，后续是实时确认和
持续写入基线；具体使用见 `storage/clickhouse/WRITER.md`。

### 2.20 采集文件持久化回执与输入断点（2026-10-30）

补齐 §2.19 的文件输入边界。采集器新增 `--durable-output`：内容写入同目录临时文件并
sync_all，通过不覆盖目标的 hard_link 原子发布，再同步目录；成功打印路径/条数/字节回执。
父目录须已存在，发布名必须唯一，stdout 模式不能启用此选项。

写入器新增 `--resume-file`，仅处理已完成的不可变普通文件，保存源路径、长度、完整
SHA256 与接收字节偏移/累计行数。每个批次有带校验和的源字节范围；批次先同步，
检查点后更新。重启从完整批次恢复连续高水位，再重放并续读；检查点以下的重复/重叠
范围也拒绝。检查点与源范围各自校验，源内容改变拒绝沿用。支持 CRLF、空白行、末行无换行。
文件模式保留未提交 `.pending-*.tmp`、统计 `uncommitted_temps`，从已校验源重读，
不把临时文件视为已接收批次；普通队列的遗留临时文件仍报错。

Go 单测与竞态检查覆盖批次已落盘但检查点仍旧、遗留临时文件、完成文件零重发、
等长源变更、偏移/检查点校验、目标丢失与范围重叠。Rust 新增两个持久化发布/参数检查。
实际 Compose：采集 15 条并确认发布；重复发布拒绝且原文件不变；完成文件重启零发送；
等长修改拒绝；20,182 条部分接收后重启完整恢复；首批 4 条已落库未确认时 SIGKILL，
新进程恢复后仍为原 15 条。产物 `measurements/clickhouse-resume.json`。
CI 接入同一复验，远端未运行。测试服务恢复 healthy。

**尚未覆盖**：实时 UDP 端到端确认、追加/轮转文件、物理服务器持续吞吐。
采集文件需在处理期间保持不可变，每个源使用独立 spool；stdin 仍无持久化输入偏移。
后续优先做持续写入基线和长连接开销评估。

### 2.21 安装完整 Ant Design Pro（2026-10-30）

按用户给出的官方分析页和本地 `OpenHotelManagementSystem/frontend-admin-pro` 参考工程，
从官方提交 `42f2cb1d303380909ea04c73b5e60679d09c321a` 接入 Pro 6.0.3 完整前端。
全部 28 个上游页面组件与配套模块保留，另将旧 5 个 CythSec 真实 API 页面迁为
ProLayout / ProTable / ProCard，路由 `/network/*`。原接口/路由/流量/系统 URL 保留重定向。
参考工程只读，未复制酒店业务配置；说明见 `web/README.md`、`web/console/UPSTREAM.md`。

依赖为 Umi Max 4.7.27 / React 19 / antd 6 / ProComponents 3，干净 npm ci 已验证；
遵循上游 .npmrc，显式声明配置直接读取的 @utoo/pack。Node 单测与 Chromium 组件测试
分开，客户端出口别名避免将 Umi Node CLI/fsevents 编进测试；空跑判失败。
24 + 50 = 74 项通过，严格类型、生产构建与 lint 通过，CI 使用 Node24。
版本仍从根 VERSION 读取；版本门禁迁至真实 Umi 配置并加入字面量回退注入。

实际 UI 已确认完整分析图表（17 canvas）、查询表格与新建表单、高级表单、AI 界面，
真实系统页读到 routerd，旧 /interfaces 正常重定向且显示真实接口。联调发现 flags 可为 null，
已修正类型/显示。默认视口无页面横向溢出。入口为 http://127.0.0.1:15173/dashboard/analysis。
Umi 外层 server.listen 未传 host，开发启动器针对 15173 补 loopback，实际监听地址与单测均确认。

模板页面保留示例数据；CythSec API 仅 `/api/v1` 走真实代理。生产不包含开发 mock，
模板账户不等于真实后端认证；AI 默认同源接口，后端尚需接入。当前后台仍为只读网络页面。
远端 CI 尚未运行，完整模板安装不等同于安全业务功能全部完成。
