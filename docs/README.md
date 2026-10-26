# docs/ — 技术文档

> 架构、实现契约、协议识别、部署、规划与安全文档。目录随实现更新，不以历史行数表示覆盖范围。

## 当前入口

| 文档 | 主题 |
| --- | --- |
| [VPN/ZTNA识别手册](vpn_ztna_protocol_identification_2026.md) | 原始识别对象、公开资料与证据边界 |
| [逐项协议算法目录](protocols/README.md) | 268项独立MD：90个V/P/O项及承载、认证、产品和组合拆分 |
| [识别引擎架构](architecture/vpn-ztna-identification.md) | 标准解析、会话确认、可信上下文、主动计划、资源与CLI契约 |
| [本轮开发与验收](planning/VPN-ZTNA-20261026.md) | 适配范围、实际验证和真实样本限制 |
| [聚合观测契约](observability/aggregate-stats.md) | TCP/UDP 总量、TLS/QUIC 头候选、TCP 质量与采集完整性；独立离线入口 |
| [聚合观测验收](planning/AGGREGATE-20261026.md) | 本批范围、实际退出码和未核验边界 |
| [核心阶段与持久化验收](planning/CORE-STATUS-20261026.md) | 数据面、控制面、存储和控制台的实际阶段 |
| [聚合持久化与查询](observability/persistence.md) | 本地同步存储、导入契约、查询 API 和第六页控制台 |
| [聚合持续写入队列](observability/ingest-worker.md) | 磁盘接收确认、恢复、退避和控制台积压状态 |
| [本批队列验收](planning/INGEST-20261026.md) | 实际命令结果和阶段限制 |
| [真实采集回读守恒](planning/LIVE-READBACK-20261026.md) | 失败类别保留、真实解析器自证及计数故障注入 |
| [Ant Design Pro 前端工程](development/frontend-standard.md) | 强制开发标准入口、Umi Max 架构、六个管理页面与验收方式 |
| [Pro 迁移验收](planning/ANT-PRO-20261026.md) | 最终本地验证、兼容基线与依赖安全阻断 |
| [BACKLOG](planning/BACKLOG.md) | 376项任务；完成状态以登记和验收证据为准 |
| [接力文档](planning/HANDOFF.md) | 既有数据链、第三方裁判、性能与工程约定 |
| [分层与插件化](architecture/layered-plugin-architecture.md) | L0契约、核心与宿主边界，M10计划尚未整体完成 |
| [TSG技术引入](architecture/tsg-tech-transfer.md) | 论文事实、规划与已验证实现分开记录 |
| [开发运行](deployment/dev-run-deploy.md) | 本机与Linux部署 |
| [Actions](deployment/actions-ci.md) / [Rust CI](deployment/rust-ci.md) | 工作流及互操作边界 |
| [威胁模型](security/threat-model.md) | 历史基线及新增识别/探测输入边界 |
| [Sprint 01](planning/SPRINT-01.md) / [Sprint 02](planning/SPRINT-02.md) | 历史执行/规划记录，不代表新功能均已完成 |

## TSG-docs/ — 参考论文

两份 USENIX Security '26 论文（Geedge Networks 防火墙源码泄漏分析），是 `tsg-tech-transfer.md` 的来源：

- `usenixsecurity26-ablove-en.pdf`（英文版，20 页）
- `usenixsecurity26-ablove.pdf`（中英对照，40 页）

## planning/scripts/ — 规划工具

| 脚本 | 用途 |
| --- | --- |
| `check-deps.py` | BACKLOG 依赖图校验：环 / 悬空 / 自依赖 / 状态一致性 |
| `count-backlog.sh` | 统计任务数并写回 STATS 区段 |

## 待补子目录

`api/`、`controlplane/`、`dataplane/`、`ml/`、`performance/` —— 按实际文件维护；新增协议文档统一位于 `protocols/`。

> 各模块速览请直接看模块内 README（`dataplane/` `services/` `web/` `ml/` `platform/` `storage/` `threat-intelligence/` `capture/` `tests/` `datasets/` `tools/` `configs/` `deploy/` `scripts/`）。

管理中后台访问认证：[设计与操作](development/control-access.md)、[本轮验收](planning/ACCESS-20261026.md)。

CLion 开发环境：[编译、启动、测试与监测](development/clion.md)。

控制台依赖安全：[2026-10-27 修复与验证](development/dependency-remediation.md)。

防火墙字段目录与技术层级：[透明串联与旁路镜像](防火墙分析识别属性清单_透明串联与旁路镜像.md)。

前端控制台完整设计：[总览、36页规格、布局、数据权限与验收](console-design/README.md)。
