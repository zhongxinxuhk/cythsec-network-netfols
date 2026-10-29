# deploy/ — 部署

> 多形态部署承载：openEuler / OpenWrt / Docker / VMware。

**状态**：已有 `docker/compose.storage-test.yml`（ClickHouse 隔离测试编排，使用官方镜像与命名卷），
默认服务复验入口见 [ClickHouse 存储说明](../storage/clickhouse/README.md)，
可选 `writer` profile 的 native 写入与失败重放见 [写入器说明](../storage/clickhouse/WRITER.md)。
其他部署目录仍为骨架，无生产 Dockerfile、systemd unit 或 RPM spec。
规划见 `docs/planning/BACKLOG.md` 里程碑 M8（28 任务）。

⚠️ 实操部署文档当前在 `docs/deployment/dev-run-deploy.md`（目标环境 openEuler 2403 sp4），先看那里。

## 目录规划

| 子目录 | 规划内容 |
| --- | --- |
| `openeuler/` | systemd 单元（`systemd/`）、配置（`configs/`）、脚本（`scripts/`）、RPM 打包（`rpm/`） |
| `openwrt/` | OpenWrt package、`init.d/` 启动脚本、UCI 配置 |
| `docker/` | 容器化部署 |
| `vmware/` | 虚拟机网络与测试拓扑（`test/` `network/`） |

## 相关

- 部署实操（当前唯一有效文档）：`docs/deployment/dev-run-deploy.md`
- 目标平台适配层：`platform/README.md`
