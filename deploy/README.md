# deploy/ — 部署

> 多形态部署承载：openEuler / OpenWrt / Docker / VMware。

**状态**：🚧 **完全空骨架** —— 全部子目录仅含 `.gitkeep`，无 Dockerfile、无 systemd unit、无 RPM spec。规划见 `docs/planning/BACKLOG.md` 里程碑 M8（28 任务）。

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
