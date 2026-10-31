# services/ — 控制平面（Go）

> Go 1.22 多模块工作区（根 `go.work` 串联 5 个模块），可独立部署的系统服务。

**零第三方依赖**：所有 `require` 均为 `cythsec/services/*` 自研包，`GOPROXY=off` 下可构建。

| 服务 | 默认端口 | 状态 | 实际职责 |
| --- | --- | --- | --- |
| `routerd/` | :8080 | ✅ 可用 | **只读网络信息采集 API**（网卡/路由/系统/流量），不含转发控制 |
| `policyd/` | :8081 | ✅ 可用 | 策略引擎：规则 IR + 编译期诊断 + allow 优先判定 |
| `dnsd/` | :8082 | 🚧 骨架 | 仅区域内存存储；**无 DNS 报文收发**（RFC 1035 解析/递归/转发属 M5） |
| `telemetryd/` | :8083 | ◐ 部分实现 | 目标注册表；可选本机聚合持久化和历史查询；**无实际抓取与调度循环** |
| `pkg/` | — | ✅ 可用 | 四服务共享底座（无 bin） |

---

## 统一服务模式

每个服务遵循同一结构：

```
cmd/<svc>/main.go    # 入口
internal/api/        # HTTP API
internal/config/     # 配置（优先级：flag > 环境变量 > YAML > 默认值）
internal/*           # 业务实现
*_test.go            # 测试（每服务 4-12 个文件）
```

基础端点（`/healthz`、`/metrics`、`/api/v1/version`）与中间件栈由 `pkg/controlplane` 统一装配。载入失败一律致命退出 —— 设计原则：**静默降级比崩溃更危险**。

---

## 各服务要点

### routerd

- `internal/netinfo/`：网卡、路由（Linux 解析 `/proc/net/route`）、系统、流量采集
- API：`/api/v1/system|interfaces|routes|traffic`；启用 `-dpi-policy-dir` 后另有
  `GET/PUT /api/v1/dpi/policy` 与 `GET /api/v1/dpi/modules`（策略契约见
  [DPI 策略](../docs/development/dpi-policy.md)）

### policyd

- 核心：`internal/ruleir/`（ir / compile / evaluate / match / action / store）
- 规则中间表示 + **编译期诊断**（冲突/冗余检测）+ allow 优先判定引擎
- 设计来源：TSG/Maat 论文分析（见 `docs/architecture/tsg-tech-transfer.md`）
- API：`/api/v1/policies|attributes|rule-tables`，`POST /api/v1/.../evaluate`（dry-run）
- 示例规则：`configs/rules.example.json`

### dnsd / telemetryd

dnsd 的网络 DNS 服务、telemetryd 的抓取调度仍属后续任务。telemetryd 新增可选 `-aggregate-dir`，提供严格聚合 JSONL 导入、同步落盘、重复导入去重和历史分页；必须绑定回环 IP。见 [持久化契约](../docs/observability/persistence.md)，它不等于 ClickHouse 常驻写入或生产鉴权。

---

## pkg/ — 共享底座

| 包 | 职责 |
| --- | --- |
| `controlplane/` | HTTP 装配骨架：3 基础端点 + 中间件链 + 优雅关闭 |
| `metrics/` | 自研 Prometheus 文本格式 0.0.4（Counter/Gauge/Histogram），刻意不用 client_golang |
| `logging/` | `log/slog` JSON 结构化日志 + HTTP 中间件 |
| `httpx/` | StatusRecorder / 中间件 Chain / 低基数路由标签 / ClientIP |
| `configutil/` | 极简 YAML 子集解析（仅顶层 key: value）+ 环境变量 |
| `apiresp/` | 统一响应 envelope `{code,data,error,request_id}` |
| `versioninfo/` | `-ldflags` 注入版本三元组（真源：根 `VERSION`） |
| `attributes/` | 属性字典 Go 绑定（codegen 生成） |

## 构建与验证

```bash
go build ./...                    # 每个模块目录下
scripts/verify/e2e-control-plane.sh   # 四服务端到端验收（启动→探测→metrics→日志→优雅关闭）
```

## 相关

- 前端消费方：`web/README.md`（console 调 routerd `/api/v1`）
- 属性字典真源：`configs/README.md`

聚合写入新增可选 `-aggregate-queue-dir`：队列同步后接收、后台历史写入、失败退避及重启恢复。仅接收完整聚合批次，详见 [队列契约](../docs/observability/ingest-worker.md)。
