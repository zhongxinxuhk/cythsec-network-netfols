# tools/ — 开发工具

> 流量生成、回放、基准测试与**代码生成**（codegen 是本目录当前的核心）。

| 子目录 | 状态 | 内容 |
| --- | --- | --- |
| `codegen/` | ✅ 实质内容 | 2 个生成器：属性字典绑定 + 通道 ABI 契约 |
| `traffic-generator/` | 🚧 空 | 合成流量生成（规划） |
| `pcap-replay/` | 🚧 空 | pcap 回放（规划） |
| `benchmark/` | 🚧 空 | 基准测试（规划） |
| `packet-generator/` | 🚧 空 | 报文构造（规划） |
| `scripts/` | 🚧 空 | 杂项脚本（规划） |

---

## codegen/ — 代码生成器

本项目「单一真源 → 生成 → 校验关口」体系的生成端：

### gen-attributes.py

- 真源：`configs/registry/attributes.json`（98 条属性）
- 产出四语言绑定：
  - Go：`services/pkg/attributes/gen.go`
  - Rust：`dataplane/traffic-engine/src/attributes_gen.rs`
  - TS：`web/console/src/constants/attributes.gen.ts`
  - Python：`ml/training/features/attributes_gen.py`
- 设计借鉴：TSG/Maat 属性集合设计（`docs/architecture/tsg-tech-transfer.md`）

### gen-channel-abi.py

- 真源：`configs/registry/channel-abi.json`（跨语言共享通道 ABI）
- 产出双端契约代码：
  - C++：`dataplane/packet-engine/include/packet_engine/channel/abi_gen.h`（35 条 static_assert）
  - Rust：`dataplane/traffic-engine/src/channel/abi_gen.rs`
- 目标：**双端不一致时必须在编译期显式失败**

## 校验关口（配套，位于 scripts/verify/）

```bash
scripts/verify/check-attributes.sh      # 四语言绑定 vs 真源
scripts/verify/check-channel-abi.sh     # ABI 生成物一致性 + 诊断码可达性
scripts/verify/check-channel-parity.sh  # C++/Rust dump-abi 逐行 diff
```

**约定**：改 `configs/registry/*.json` 后必须重跑生成器 + 校验脚本；生成物头部标注勿手改。

## 相关

- 真源定义：`configs/README.md`
- 消费方：`dataplane/README.md`、`services/README.md`、`web/README.md`、`ml/README.md`
