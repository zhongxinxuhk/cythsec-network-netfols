# cythsec

> 高性能网络安全数据平面与控制平面一体化平台（Cyber Threat Security）。

cythsec 是一套面向网络安全检测、流量分析与威胁防御的异构多语言工程。
数据平面以 C/C++（packet-engine）与 Rust（traffic-engine）实现高速收包与流量分析，
控制平面以 Go 实现路由、策略、DNS 与遥测服务，Web 控制面以 React + TypeScript 提供可视化运营，
AI/ML 部分以 Python 训练、C++ 推理闭环，平台抽象层统一适配 Linux / openEuler / OpenWrt 等多形态部署目标。

---

## 分层与工程映射

| 层级 | 工程名 | 主要语言 | 职责 |
| --- | --- | --- | --- |
| 高速收包 | `packet-engine` | C/C++ | 基于 XDP/eBPF、AF_XDP、DPDK 的高速数据包收发与缓冲调度 |
| 流量分析 | `traffic-engine` | Rust | Flow/Session 重组、协议解析、DPI、特征提取、行为分析与风险引擎 |
| 路由系统 | `routerd` | Go | 路由器核心服务：路由表管理、转发控制、北向 API |
| 策略系统 | `policyd` | Go | 策略引擎：规则编排、匹配与下发 |
| DNS | `dnsd` | Go | DNS 策略服务：解析、分流与策略化劫持/转发 |
| 遥测 | `telemetryd` | Go | 指标 / 遥测 / 监控：采集、暴露与告警 |
| AI 训练 | `training` | Python | 模型训练：数据集、预处理、特征、实验、评估 |
| AI 推理 | `inference` | C++ | 生产推理：ONNX 运行时、低延迟推理服务 |
| Web 控制面 | `console` | React/TS | 可视化控制台：面板、配置、监控与运维交互 |
| 平台适配 | `platform` | C/C++/Go | 跨平台抽象：网络/防火墙/路由接口，Linux/openEuler/OpenWrt 适配 |
| 数据存储 | `storage` | 多语言 | PostgreSQL / ClickHouse / Redis 及 Schema 定义 |
| 测试 | `tests` | 多语言 | 单元/集成/e2e/流量/dpi/ml/安全/性能/兼容性测试与 fixtures |
| 流量数据 | `datasets` | PCAP/JSON/Parquet 等 | 测试与训练使用的流量样本、Flow、特征与模型数据 |

### 两条流量路径的边界（可判定，别混用）

| 路径 | 定位 | 判据（拿数字就能判） |
| --- | --- | --- |
| **包级**：`packet-engine` 收包 → `traffic-engine` 逐包流水线（Flow/Session/DPI/特征） | **单点**能力：DPI / 取证 / 告警，**10~100G/点** | 要求「逐包全量留存」时，落盘量 = 带宽 ÷ 8 × 86400。**10 Tbps ⇒ 108 PB/天**，且逐包全量在省网是量级错误（差 4 个数量级）—— 见下 |
| **流级**：`traffic-engine` 流表 → IPFIX 导出 → 采集集群（`cythsec-ipfix-*`） | **省网/骨干量级**的唯一入口 | 被观测链路按**采样率**导出记录，容量与**链路包率解耦**：`记录率 = 包率 ÷ 采样率`、`台数 = ceil(记录率 ÷ (每台实测容量 × 余量))`、`TB/天 = 记录率 × 86400 × 每条字节` |

**算式可复跑**：`python3 scripts/plan/collector-capacity.py`（省网 20 Tbps / 1:1000 ⇒ 5 Mrec/s → 2~3 台 →
**34.29 TB/天**，落盘取**实测** 79.4 B/记录；逐包全量对照 10 Tbps ⇒ **108 PB/天**，
倍数 6,297 = 3.8 个数量级）。模型参数逐条标明出处，
`--self-test` 用手算期望值 + 3 项反向注入自证。详细口径（采样率 / 导出丢包率 / **采集覆盖率**）见 `docs/planning/HANDOFF.md` §2.13。

---

## 目录结构总览

```
cythsec/
├── dataplane/              # 数据平面
│   ├── packet-engine/     # C/C++ 高速数据包处理（XDP/eBPF、AF_XDP、DPDK）
│   └── traffic-engine/    # Rust 流量分析核心（crates 化）
├── services/              # 控制平面 / 系统服务（Go）
│   ├── routerd/           # 路由器核心服务
│   ├── policyd/           # 策略引擎
│   ├── dnsd/              # DNS 策略服务
│   └── telemetryd/        # 指标 / 遥测 / 监控
├── web/                   # Web 控制面
│   └── console/           # React + TypeScript 控制台
├── ml/                    # AI / ML
│   ├── training/          # Python 模型训练
│   ├── inference/         # C++ 生产推理
│   └── model-registry/    # 模型版本与元数据
├── platform/              # 平台抽象层
│   ├── common/            # 跨平台接口
│   ├── linux/             # Linux 通用实现
│   ├── openeuler/         # openEuler 适配
│   └── openwrt/           # OpenWrt 适配
├── storage/               # 数据存储
│   ├── postgres/          # PostgreSQL
│   ├── clickhouse/        # Flow / Analytics
│   ├── redis/             # 实时状态
│   └── schema/            # 数据库 Schema
├── threat-intelligence/   # 威胁情报
│   ├── ip/ domain/ hash/ reputation/ feeds/
├── capture/               # 流量采集测试 / 抽象
│   ├── pcap/ af_packet/ af_xdp/ xdp/ dpdk/
├── tests/                 # 全局测试
│   ├── unit/ integration/ e2e/ traffic/ dpi/ ml/ security/ performance/ compatibility/ fixtures/
├── datasets/              # 测试 / 训练数据
│   ├── pcap/ traffic/ flows/ features/ models/ samples/
├── tools/                 # 开发工具
│   ├── traffic-generator/ pcap-replay/ benchmark/ packet-generator/ codegen/ scripts/
├── configs/               # 全局配置模板
│   ├── development/ testing/ production/
├── deploy/                # 部署
│   ├── openeuler/ openwrt/ docker/ vmware/
├── build/                 # 本地统一构建入口/脚本
│   ├── windows/ linux/
├── scripts/               # 项目级脚本
│   ├── build/ test/ release/ dev/
├── docs/                  # 技术文档
│   ├── architecture/ dataplane/ controlplane/ dpi/ ml/ api/ deployment/ performance/ security/
├── .github/               # CI/CD（workflows）
├── .gitignore
├── CMakeLists.txt         # 根 CMake（C/C++ 数据平面）
├── Cargo.toml             # 根 Cargo workspace（Rust）
├── go.work                # Go 多模块工作区
├── README.md
├── LICENSE
└── VERSION
```

---

## 各目录功能说明

### 数据平面 `dataplane/`
承载高性能收包与流量分析的底层实现，是整条链路的数据入口。

- **`packet-engine/`（C/C++）**：高速数据包处理引擎。
  - `include/`、`src/`：核心源码与头文件。
  - `xdp/`、`ebpf/`：XDP 与 eBPF 程序，在内核态完成早期丢包/转发决策。
  - `af_xdp/`：AF_XDP 用户态零拷贝收包通道。
  - `dpdk/`：DPDK 轮询模式驱动（PMD）收发包。
  - `buffer/`：Packet Buffer 管理（内存池、环形队列）。
  - `dispatcher/`：数据包分发器，将报文按 RSS 分流至工作队列。
  - `rss/`：RSS 与多队列管理，保障多核负载均衡与流亲和性。
  - `tests/`：引擎单元测试与微基准。
- **`traffic-engine/`（Rust）**：流量分析核心，以 cargo workspace 的 `crates/` 组织。
  - `crates/flow/`：Flow 引擎（五元组流表、老化、状态）。
  - `crates/session/`：会话管理与关联。
  - `crates/reassembly/`：TCP/IP 重组（乱序、分片）。
  - `crates/dpi/`：深度包检测与协议识别。
  - `crates/protocol/`：协议解析器（HTTP/DNS/TLS 等）。
  - `crates/feature/`：特征提取（统计、时序、熵等）。
  - `crates/behavior/`：行为分析（基线、异常）。
  - `crates/risk/`：风险引擎（评分、研判）。
  - `crates/common/`：公共类型与工具。
  - `tests/`：Rust 集成测试。

### 控制平面服务 `services/`
以 Go 实现的可独立部署系统服务，通过 API 与数据平面、Web 控制面交互。

- **`routerd/`**：路由器核心服务。`cmd/` 入口、`internal/` 内部实现、`pkg/` 可复用库、`api/` 北向接口、`configs/` 配置、`tests/` 测试、`go.mod` 模块定义。
- **`policyd/`**：策略引擎。负责策略的建模、匹配与下发（结构同 routerd）。
- **`dnsd/`**：DNS 策略服务。解析、分流与策略化转发（无 `configs/` 子目录，配置收敛于 `policyd`/`configs` 全局模板）。
- **`telemetryd/`**：指标 / 遥测 / 监控。采集各组件运行时指标并暴露监控端点。

### Web 控制面 `web/`
- **`console/`（Ant Design Pro 6 + Umi Max + React + TypeScript）**：完整 Pro 基础工程与 CythSec 运营控制台。
  - `public/`：静态资源。`src/api/` 接口封装、`src/assets/` 资源、`src/components/` 组件、
    `src/layouts/` 布局、`src/pages/` 页面、`src/routes/` 路由、`src/stores/` 状态（Pinia/Zustand 等）、
    `src/hooks/` 钩子、`src/services/` 业务服务、`src/types/` 类型、`src/utils/` 工具、`src/constants/` 常量。
  - `tests/`：Node 单测与 Chromium 浏览器测试；`config/` 管理 Umi 路由、主题、代理与版本注入。安装与启动见 `web/README.md`。

### AI / ML `ml/`
- **`training/`（Python）**：模型训练流水线。`datasets/` 数据集、`preprocessing/` 预处理、
  `features/` 特征工程、`models/` 模型定义、`experiments/` 实验记录、`evaluation/` 评估、`scripts/` 脚本。
- **`inference/`（C++）**：生产推理。`include/`、`src/`、`onnx/` ONNX 模型接入、`runtime/` 推理运行时，`CMakeLists.txt` 构建定义。
- **`model-registry/`**：模型版本与元数据登记（版本、指标、来源）。

### 平台抽象层 `platform/`
屏蔽底层操作系统差异，统一网络/防火墙/路由能力接口。

- **`common/`**：跨平台接口契约。`network/`、`firewall/`、`routing/`、`interface/`、`system/`。
- **`linux/`**：Linux 通用实现。`netlink/`、`nftables/`、`ethtool/`。
- **`openeuler/`**：openEuler 适配。`network/`、`service/`、`packaging/`、`configs/`。
- **`openwrt/`**：OpenWrt 适配。`uci/`、`ubus/`、`netifd/`、`service/`、`packaging/`、`configs/`。

### 数据存储 `storage/`
- `postgres/`：业务/配置关系存储。`clickhouse/`：Flow 与 Analytics 列存。`redis/`：实时状态缓存。`schema/`：各库 Schema 与迁移。

### 威胁情报 `threat-intelligence/`
- `ip/`、`domain/`、`hash/`：按 IOC 类型的情报库。`reputation/`：信誉评分。`feeds/`：外部情报源接入与同步。

### 流量采集 `capture/`
采集测试与抽象层：`pcap/`（libpcap）、`af_packet/`、`af_xdp/`、`xdp/`、`dpdk/`，用于不同收包后端的抓包与回放验证。

### 全局测试 `tests/`
- `unit/` 单元、`integration/` 集成、`e2e/` 端到端、`traffic/` 流量、`dpi/` 检测、`ml/` 模型、
  `security/` 安全、`performance/` 性能、`compatibility/` 兼容性、`fixtures/` 测试夹具数据。

### 数据集 `datasets/`
- `pcap/` 抓包样本、`traffic/` 合成流量、`flows/` 流记录、`features/` 特征集、`models/` 模型产物、`samples/` 其他样本（PCAP/JSON/Parquet 等）。

### 开发工具 `tools/`
- `traffic-generator/` 流量生成、`pcap-replay/` 回放、`benchmark/` 基准、`packet-generator/` 报文生成、`codegen/` 代码生成、`scripts/` 杂项脚本。

### 配置 `configs/`
全局配置模板，按环境划分：`development/`、`testing/`、`production/`。

### 部署 `deploy/`
- `openeuler/`：systemd 单元、RPM 打包、脚本与配置。`openwrt/`：package、init.d、配置。`docker/`：容器化部署。`vmware/`：虚拟机网络与测试拓扑。

### 构建与脚本 `build/`、`scripts/`
- `build/`：本地统一构建入口，按平台分 `windows/`、`linux/`。
- `scripts/`：项目级脚本，`build/`、`test/`、`release/`、`dev/` 分类。

### 文档 `docs/`
技术文档：`architecture/`（架构）、`dataplane/`、`controlplane/`、`dpi/`、`ml/`、`api/`（接口）、`deployment/`（部署）、`performance/`（性能）、`security/`（安全）。

### CI/CD `.github/`
- `workflows/`：GitHub Actions 流水线（构建、测试、发布、安全扫描）。

---

## 技术栈

- 数据平面：C/C++（XDP/eBPF、AF_XDP、DPDK）、Rust（cargo workspace）
- 控制平面：Go（go.work 多模块）
- 前端：Ant Design Pro 6 / Umi Max / React 19 / Ant Design 6 / ProComponents 3
- AI/ML：Python（训练）、C++ + ONNX Runtime（推理）
- 存储：PostgreSQL、ClickHouse、Redis
- 部署目标：Linux / openEuler / OpenWrt；Docker / VMware

---

## 构建与开发（占位，后续补充）

- C/C++ 数据平面：根 `CMakeLists.txt` 与 `packet-engine/CMakeLists.txt`、`inference/CMakeLists.txt`。
- Rust 流量引擎：`dataplane/traffic-engine/Cargo.toml`（workspace）。
- Go 服务：根 `go.work` 串联 `services/*` 四个模块。
- Web 控制台：`web/console/` 下 `npm install && npm run dev`。
- 统一入口：`scripts/` 与 `build/` 提供跨平台构建、测试、发布与开发脚本。

> 详细构建命令、环境变量与依赖版本见 `docs/build` 与 `scripts/`（持续补充中）。
