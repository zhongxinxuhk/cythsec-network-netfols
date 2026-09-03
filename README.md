# cythsec

> 网络流量安全分析系统（Cyber Threat Security / cythsec）

cythsec 是一套面向流量感知与威胁检测的分层系统，采用多语言混合架构：
数据平面负责高速收包与流量分析（C/C++、Rust），控制面由各 Go 服务协同（路由、
策略、DNS、遥测），AI/ML 层负责模型训练（Python）与生产推理（C++），Web 控制面
（React/TS）提供可视化操作，平台适配层屏蔽 openEuler / OpenWrt / 通用 Linux 的差异。

---

## 分层与工程映射

| 层级 | 工程名 | 主要语言 |
| --- | --- | --- |
| 高速收包 | `packet-engine` | C/C++ |
| 流量分析 | `traffic-engine` | Rust |
| 路由系统 | `routerd` | Go |
| 策略系统 | `policyd` | Go |
| DNS | `dnsd` | Go |
| 遥测 | `telemetryd` | Go |
| AI 训练 | `training` | Python |
| AI 推理 | `inference` | C++ |
| Web 控制面 | `console` | React/TS |
| 平台适配 | `platform` | C/C++/Go |
| 数据存储 | `storage` | 多语言 |
| 测试 | `tests` | 多语言 |
| 流量数据 | `datasets` | PCAP / JSON / Parquet 等 |

---

## 目标工程结构与各目录职责（规划）

> 下列结构为**目标架构**，将随开发逐步落地。当前仓库遵循「只建立真正需要开始
> 开发的工程」原则，未预先创建空目录。

- **dataplane/** — 数据平面
  - `packet-engine/`：高速数据包处理（C/C++）。含 `xdp/`（XDP/eBPF）、`af_xdp/`、
    `dpdk/`、`buffer/`（Packet Buffer）、`dispatcher/`（Packet Dispatcher）、
    `rss/`（RSS/Queue）、`ebpf/`（eBPF Programs）。
  - `traffic-engine/`：流量分析核心（Rust workspace）。`crates/` 下含
    `flow/`（Flow Engine）、`session/`（Session）、`reassembly/`（TCP/IP 重组）、
    `dpi/`（深度包检测）、`protocol/`（协议解析）、`feature/`（特征提取）、
    `behavior/`（行为分析）、`risk/`（风险引擎）、`common/`（公共类型）。
- **services/** — 控制面（Go 服务）
  - `routerd/` 路由器核心服务、`policyd/` 策略引擎、`dnsd/` DNS 策略服务、
    `telemetryd/` 指标/遥测/监控。每个服务含 `cmd/ internal/ pkg/ api/ tests/`
    （部分含 `configs/`），各自持有独立 `go.mod`。
- **web/console/** — Web 控制面（React + TypeScript）。`src/` 下含 `api/ assets/
  components/ layouts/ pages/ routes/ stores/ hooks/ services/ types/ utils/ constants/`。
- **ml/** — AI/ML
  - `training/`：模型训练（Python），含 `datasets/ preprocessing/ features/
    models/ experiments/ evaluation/ scripts/`。
  - `inference/`：生产推理（C++），含 `onnx/`（ONNX Runtime）、`runtime/`。
  - `model-registry/`：模型版本与元数据。
- **platform/** — 平台抽象层。`common/`（跨平台接口：network/firewall/routing/
  interface/system）、`linux/`（netlink/nftables/ethtool）、`openeuler/`
  （network/service/packaging/configs）、`openwrt/`（uci/ubus/netifd/service/
  packaging/configs）。
- **storage/** — 数据存储：`postgres/`、`clickhouse/`（Flow/Analytics）、
  `redis/`（实时状态）、`schema/`（数据库 Schema）。
- **threat-intelligence/** — 威胁情报：`ip/ domain/ hash/ reputation/ feeds/`。
- **capture/** — 流量采集抽象：`pcap/ af_packet/ af_xdp/ xdp/ dpdk/`。
- **tests/** — 全局测试：`unit/ integration/ e2e/ traffic/ dpi/ ml/ security/
  performance/ compatibility/ fixtures/`。
- **datasets/** — 测试/训练数据：`pcap/ traffic/ flows/ features/ models/ samples/`。
- **tools/** — 开发工具：`traffic-generator/ pcap-replay/ benchmark/
  packet-generator/ codegen/ scripts/`。
- **configs/** — 全局配置模板：`development/ testing/ production/`。
- **deploy/** — 部署：`openeuler/`（systemd/rpm/scripts/configs）、`openwrt/`
  （package/init.d/configs）、`docker/`、`vmware/`（network/test）。
- **build/** — 本地统一构建入口：`windows/ linux/`。
- **scripts/** — 项目级脚本：`build/ test/ release/ dev/`。
- **docs/** — 技术文档：`architecture/ dataplane/ controlplane/ dpi/ ml/ api/
  deployment/ performance/ security/`。
- **.github/workflows/** — CI/CD 流水线。

---

## 当前仓库状态

本仓库为**最小化初始化**，当前仅包含根级文件：

```
cythsec/
├── README.md      # 本文件
├── LICENSE        # 许可证待定
├── .gitignore     # 多语言构建产物忽略规则
└── VERSION        # 当前版本 0.1.0
```

子工程目录将在确定具体开发模块后再行建立，避免过早铺陈空目录。

---

## 快速开始

各子工程的编译与运行命令将在对应模块落地后补充。统一管理入口见 `build/`
（本地构建）与 `scripts/`（项目级脚本）。

---

## 许可证

`LICENSE` 当前为占位声明，**许可证待定**。在明确之前，未经著作权人书面许可，
不得复制、修改、分发或用于商业用途。
