# tests/ — 全局测试

> 规划中的集中测试承载：单元 / 集成 / e2e / 流量 / DPI / ML / 安全 / 性能 / 兼容性。

**状态**：`ci/` 包含工作流与执行脚本回归，`ml/` 包含训练工程测试；其他规划目录仍按实际文件逐步补充。

业务测试主要**就近挂在各子工程内**，本目录待后续收敛（规划见 `docs/planning/BACKLOG.md` M9，46 任务）。

CI 编排检查：`python3 -m unittest discover -s tests/ci -v`。流水线与本地验证范围见 [流水线说明](../.github/workflows/README.md) 和 [验证记录](ci/VALIDATION.md)。

## 现有测试的真实位置

| 栈 | 位置 | 数量/形态 |
| --- | --- | --- |
| C/C++ packet-engine | `dataplane/packet-engine/`（CTest） | 6 个：`test_packet` `test_parser` `test_pcap` `test_channel_abi` `test_channel_producer` `test_live_capture` |
| Rust traffic-engine | `dataplane/traffic-engine/src/`（内联 `#[cfg(test)]`）+ `src/channel/tests.rs` | 约 965 行通道测试等 |
| Go 服务 | `services/*/internal/**/*_test.go` | 每服务 4-12 个文件 |
| 前端 console | `web/console/tests/` + `src/components/*.test.tsx` | vitest + testing-library |

## 统一入口

```bash
make test                       # 等价于：
scripts/test/test-all.sh        # 四栈测试 + 通道 ABI parity + 跨语言 e2e，逐栈汇总
```

## 子目录规划

`unit/`（单元）、`integration/`（集成）、`e2e/`（端到端）、`traffic/`（流量回放）、`dpi/`（检测向量）、`ml/`（模型）、`security/`（安全）、`performance/`（性能）、`compatibility/`（兼容性）、`fixtures/`（夹具数据）。

## 相关

- 端到端脚本：`scripts/README.md`（`scripts/verify/`）
- 测试数据与样本：`datasets/README.md`
