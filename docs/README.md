# docs/ — 技术文档

> 架构、部署、规划与安全文档。**当前有 5 篇实质文档（共约 2100 行），多数子目录待补**。

## 实质文档索引

| 文档 | 规模 | 主题 |
| --- | --- | --- |
| [`planning/BACKLOG.md`](planning/BACKLOG.md) | 808 行 | 主待办表：**349 任务 / 9 里程碑**（M1 工程 54、M2 数据面 38、M3 流量分析 39、M4 控制面 45、M5 服务化 24、M6 存储前端 38、M7 ML 情报 37、M8 部署 28、M9 测试安全 46）；P0 137 / P1 141 / P2 61 / P3 10；编号 `CYS-<域>-<序号>` |
| [`architecture/tsg-tech-transfer.md`](architecture/tsg-tech-transfer.md) | 757 行 | TSG（天狗安全网关）技术解构与引入方案 v0.3.0：全量引入 19 项技术 + 13 类处置动作；§3 规划清单、§9 已验证落地记录 |
| [`planning/SPRINT-01.md`](planning/SPRINT-01.md) | 234 行 | Sprint-01 编排：三原则（先清障、按文件区域切分、可执行验证关口），团队 3 专家 + 1 lead |
| [`deployment/dev-run-deploy.md`](deployment/dev-run-deploy.md) | 172 行 | 开发/运行/部署手册：纵向切片 packet-engine → traffic-engine → routerd → console，覆盖本机与 openEuler 2403 sp4 |
| [`security/threat-model.md`](security/threat-model.md) | 142 行 | 威胁模型 v0.1.0（CYS-SEC-001）：资产清单、基于逐行代码核实的威胁条目，为 nftables/netlink/DNS 重定向预留 |

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

`api/`、`controlplane/`、`dataplane/`、`dpi/`、`ml/`、`performance/` —— 目前为空，`architecture/` 与 `security/` 各仅 1 篇。

> 各模块速览请直接看模块内 README（`dataplane/` `services/` `web/` `ml/` `platform/` `storage/` `threat-intelligence/` `capture/` `tests/` `datasets/` `tools/` `configs/` `deploy/` `scripts/`）。
