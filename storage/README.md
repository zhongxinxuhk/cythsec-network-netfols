# storage/ — 数据存储

> PostgreSQL（业务/配置）、ClickHouse（Flow/Analytics 列存）、Redis（实时状态）及统一 Schema。

**状态**：🚧 **完全空骨架** —— 四个子目录仅含 `.gitkeep`，无任何 SQL / 迁移文件。规划见 `docs/planning/BACKLOG.md` 里程碑 M6（38 任务）。

## 目录规划

| 子目录 | 用途 | 典型数据 |
| --- | --- | --- |
| `postgres/` | 业务/配置关系存储 | 策略、规则表、账号 |
| `clickhouse/` | Flow 与 Analytics 列存 | 五元组流记录、特征序列 |
| `redis/` | 实时状态缓存 | 会话状态、限速计数 |
| `schema/` | 各库 Schema 与迁移 | 单一真源的 DDL |

## 数据来源（规划态）

```
traffic-engine Flow/Session ──► clickhouse（流记录）
policyd 策略/规则           ──► postgres（配置态）
packet-engine / 各服务状态   ──► redis（实时态）
```

## 相关

- 控制面服务：`services/README.md`
- 测试数据形态：`datasets/README.md`
