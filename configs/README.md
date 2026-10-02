# configs/ — 全局配置

> 环境配置模板 + **单一真源（Single Source of Truth）注册表**。后者是本目录的核心价值。

| 子目录 | 状态 | 内容 |
| --- | --- | --- |
| `registry/` | ✅ 实质内容 | 2 个真源 JSON：属性字典 + 通道 ABI |
| `development/` | 🚧 空 | 开发环境配置模板 |
| `testing/` | 🚧 空 | 测试环境配置模板 |
| `production/` | 🚧 空 | 生产环境配置模板 |

---

## registry/attributes.json — 属性字典真源（18303B）

- version=1，**98 条属性**，每条含 `id / type / scope / stage / cost / source / desc`
- 14 种类型：string / bytes / ip / ip_prefix / port / u8-u64 / i64 / bool / enum / string_set / time_ms
- 8 个 scope：l2 / l3 / l4 / l5plus / tunnel / identity / flow / derived
- 5 个 stage、3 级 cost

**派生绑定**（由 `tools/codegen/gen-attributes.py` 生成）：

| 语言 | 路径 |
| --- | --- |
| Go | `services/pkg/attributes/gen.go` |
| Rust | `dataplane/traffic-engine/src/attributes_gen.rs` |
| TS | `web/console/src/constants/attributes.gen.ts` |
| Python | `ml/training/features/attributes_gen.py` |

## registry/channel-abi.json — 共享通道 ABI 真源（13738B）

跨语言（C++ 生产端 ⇄ Rust 消费端）共享内存环的冻结契约（决策 CYS-PKT-024）：

- `magic = "CYTHSEC1"`，`abi_version = 1`
- `region_alignment = 4096`，默认 `slot_count = 1024`、`slot_size = 2048`
- 取值范围：slot 数 2~1048576，slot 大小 64~65536
- 内容：21 个 header 字段、11 个 descriptor 字段、4 个 flag、15 条诊断码
- **冻结规则：增减字段必须提升 `abi_version`**

**派生代码**（由 `tools/codegen/gen-channel-abi.py` 生成）：

- C++：`dataplane/packet-engine/include/packet_engine/channel/abi_gen.h`
- Rust：`dataplane/traffic-engine/src/channel/abi_gen.rs`

## 修改流程（强制）

```
改真源 JSON ──► 重跑 tools/codegen/*.py ──► 跑 scripts/verify/check-*.sh ──► 提交
```

跳过校验直接改生成物会被 CI 拦下（`check-attributes.sh` / `check-channel-abi.sh` / `check-channel-parity.sh`）。

## 相关

- 生成器：`tools/README.md`
- 消费方：`dataplane/` `services/` `web/` `ml/` 各自 README
