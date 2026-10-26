# storage/ — 数据存储

> PostgreSQL（业务/配置）、ClickHouse（Flow/Analytics 列存）、Redis（实时状态）及统一 Schema。

**状态**：部分实现。`clickhouse/001_flows.sql` 已存在（由 Rust 列契约生成），有 Native 编码和 ClickHouse local 正确性验证；常驻 ClickHouse 写入、背压／重放及规模查询仍未完成。PostgreSQL／Redis 仍为规划。新增聚合历史由 telemetryd 的可选本地不可变 JSONL 存储承担，具备同步落盘、内容去重、重启校验与分页查询，限定 64 MiB／1024 批，不代表列存后端已完成。

契约和运行命令：[聚合持久化](../docs/observability/persistence.md)。阶段和验收：[核心进度](../docs/planning/CORE-STATUS-20261026.md)。

## 目录规划

| 子目录 | 用途 | 典型数据 |
| --- | --- | --- |
| `postgres/` | 业务/配置关系存储 | 策略、规则表、账号 |
| `clickhouse/` | Flow 与 Analytics 列存 | 五元组流记录、特征序列 |
| `redis/` | 实时状态缓存 | 会话状态、限速计数 |
| `schema/` | 各库 Schema 与迁移 | 单一真源的 DDL |

## 数据来源（列存为规划态；聚合本地存储已实现）

```
cythsec-observe 聚合 JSONL ──► telemetryd 私有本地目录 ──► 历史查询 / console
traffic-engine Flow/Session ──► clickhouse（常驻写入待实现）
policyd 策略/规则           ──► postgres（配置态）
packet-engine / 各服务状态   ──► redis（实时态）
```

## 相关

- 控制面服务：`services/README.md`
- 测试数据形态：`datasets/README.md`
