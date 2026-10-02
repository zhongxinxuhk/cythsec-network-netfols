# platform/ — 平台抽象层

> 目标：屏蔽 Linux / openEuler / OpenWrt 底层差异，统一网络 / 防火墙 / 路由能力接口。

**状态**：🚧 **纯目录骨架，零源码、零构建文件**。全部子目录仅含 `.gitkeep`。

⚠️ 注意：当前平台差异实际上在 `dataplane/packet-engine/src/backends/` 内部处理（Linux 走 AF_PACKET、macOS/BSD 走 BPF）。本模块是未来系统级能力（netlink、nftables、uci/ubus）的规划承载。

## 目录规划

```
common/               # 跨平台接口契约
├── network/          # 网络配置抽象
├── firewall/         # 防火墙抽象
├── routing/          # 路由抽象
├── interface/        # 网卡接口抽象
└── system/           # 系统服务抽象

linux/                # Linux 通用实现
├── netlink/          # 路由/链路 netlink
├── nftables/         # nftables 防火墙
└── ethtool/          # 网卡参数

openeuler/            # openEuler 适配
├── network/  service/  packaging/  configs/

openwrt/              # OpenWrt 适配
├── uci/              # UCI 配置
├── ubus/             # ubus 总线
├── netifd/           # netifd 对接
└── service/  packaging/  configs/
```

## 相关

- 里程碑规划：`docs/planning/BACKLOG.md`（`CYS-PLT-*` 域）
- 威胁模型中对 nftables / netlink 的预留条目：`docs/security/threat-model.md`
- 现有平台条件编译参考：`dataplane/README.md`
