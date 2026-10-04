# scripts/ — 项目级脚本

> 构建 / 测试 / 质量关口的统一入口。根 `Makefile` 是薄转发层：`build` `test` `lint` `fmt` `clean` `ci`（`ci: lint build test`）全部转发到这里。

## build/

| 脚本 | 用途 |
| --- | --- |
| `build-all.sh` | 统一构建 C++/Rust/Go/前端四栈；工具链版本预检；失败栈数作为退出码 |

## test/

| 脚本 | 用途 |
| --- | --- |
| `test-all.sh` | 四栈测试 + 通道 ABI parity + 跨语言 e2e + 三道 tshark 核验 + 数据面基准（`--bench` 需显式开），逐栈汇总 |

## lint/ 与 fmt/

| 脚本 | 用途 |
| --- | --- |
| `lint-all.sh` | clang-format / cargo fmt / gofmt / eslint **只查不改**；CI `lint.yml` 直接调用 |
| `fmt-all.sh` | C++/Rust/Go 自动格式化修复 |

## release/

| 脚本 | 用途 |
| --- | --- |
| `check-version.sh` | 校验版本单一真源：`Cargo.toml` 与 `package.json` 必须等于根 `VERSION` |

## security/

| 脚本 | 用途 |
| --- | --- |
| `scan-secrets.sh` | 零依赖 grep 明文凭据扫描（CYS-SEC-003/006）；不打印密钥原文；兼容 BSD/GNU grep |

## verify/ — 语义关口（本项目质量体系核心）

| 脚本 | 用途 |
| --- | --- |
| `check-attributes.sh` | 属性字典四语言绑定 vs 真源一致性 |
| `check-channel-abi.sh` | 通道 ABI 生成物一致性 + 诊断码可达性 |
| `check-channel-parity.sh` | C++ `cythsec-dump-abi` 与 Rust `dump-abi` 输出逐行 diff（产物留 `build/parity/`） |
| `check-prometheus-format.py` | Python 独立重实现的 Prometheus 文本格式（0.0.4）严格校验器 |
| `check-dpi-vectors.sh` | **tshark 独立复核** DPI 向量（挂 `test-all.sh --dpi`） |
| `check-reassembly-vectors.sh` | **tshark 独立复核** TCP 重组向量（挂 `--reassembly`） |
| `check-flow-records.sh` | **tshark 独立复核** FlowRecord（会话/计数/状态/应用）+ 17 项反向故障注入（挂 `--flows`） |
| `check-flow-bench.sh` | 数据面基准（CYS-TRF-037）的**回归下限**门禁 + 3 项反向注入；需求目标只报告（挂 `--bench`，**默认不在 ALL 里**：阈值带机器属性） |
| `e2e-control-plane.sh` | 四服务端到端验收：启动 routerd/policyd/dnsd/telemetryd → 探测端点 → 校验 metrics → jq 验证结构化日志 → 优雅关闭 |
| `e2e-shared-ring.sh` | 跨语言共享环 e2e（CYS-TRF-034）：C++ ring-feed 写 mmap → Rust ring-consume 读并聚合 FlowKey |

## dev/

🚧 空占位。

---

## 常用入口速查

```bash
make ci                  # lint + build + test（CI 等价物）
make build               # 四栈构建
make test                # 四栈测试 + parity + e2e
scripts/security/scan-secrets.sh    # 提交前自查
scripts/release/check-version.sh    # 版本一致性自查
```

## 相关

- 生成器与真源：`tools/README.md`、`configs/README.md`
- 构建产物去向：`build/README.md`
