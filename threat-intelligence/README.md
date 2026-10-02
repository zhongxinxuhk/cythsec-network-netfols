# threat-intelligence/ — 威胁情报

> 按 IOC 类型组织情报库（IP / 域名 / 哈希）、信誉评分与外部情报源接入。

**状态**：🚧 **完全空骨架** —— 五个子目录仅含 `.gitkeep`，无情报源清单、无格式定义。规划见 `docs/planning/BACKLOG.md` 里程碑 M7（37 任务）。

## 目录规划

| 子目录 | 用途 |
| --- | --- |
| `ip/` | IP 维度 IOC（恶意 IP、C2、 Tor 出口等） |
| `domain/` | 域名维度 IOC（DGA、钓鱼域等） |
| `hash/` | 文件哈希 IOC |
| `reputation/` | 信誉评分模型与数据 |
| `feeds/` | 外部情报源接入、同步与去重 |

## 与检测链路的关系（规划态）

```
feeds 拉取 ──► ip/domain/hash 情报库 ──► 信誉评分 ──► policyd 策略匹配
                                          │
              traffic-engine DPI 观测 ────┘（命中回写、闭环）
```

## 相关

- DPI 检测框架：`dataplane/README.md`（traffic-engine `src/dpi/`）
- 属性字典（情报属性登记）：`configs/README.md`
