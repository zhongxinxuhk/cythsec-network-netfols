# storage/ — 数据存储

> PostgreSQL（业务/配置）、ClickHouse（Flow/Analytics 列存）、Redis（实时状态）及统一 Schema。

**状态**：ClickHouse 已有 [FlowRecord v1 DDL 与可复跑的 MergeTree 落盘测量](clickhouse/README.md)；
另已实现 [native 批量写入器、背压和失败重放](clickhouse/WRITER.md)。
采集文件持久化发布与不可变文件断点也已实现；其余存储仍为骨架，
完整多表迁移、实时 UDP 确认和生产高吞吐尚未验收。
规划见 `docs/planning/BACKLOG.md` 里程碑 M6（38 任务）。

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
