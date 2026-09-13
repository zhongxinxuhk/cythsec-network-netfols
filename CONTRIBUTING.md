# 贡献指南（工程基座）

本文件说明 cythsec 的本地构建、测试、静态检查与版本号规范。
所有构建/测试/检查逻辑收敛在 `scripts/` 下，顶层 `Makefile` 仅做转发（避免在多处重复）。

## 快速开始

```bash
make build   # 构建四栈（C++ / Rust / Go / 前端）
make test    # 跑四栈测试
make lint    # 静态检查（clang-format / cargo fmt / gofmt / eslint）
make fmt     # 自动格式化（C++/Rust/Go）
make clean   # 清理 build/ 与 target/
make ci      # 本地复现 CI 全流程（lint -> build -> test）
```

也可只跑某一栈，例如：

```bash
bash scripts/build/build-all.sh --go --rust
bash scripts/test/test-all.sh --go
bash scripts/lint/lint-all.sh --help
```

## 工具链要求

- cmake ≥ 3.20
- go ≥ 1.22
- rustc/cargo（稳定版）
- node ≥ 18 + npm

脚本开头会做版本预检，不足时给出可读报错并非 0 退出。

## Go 服务构建说明

四个 Go 服务是独立 module，共享代码放在 `services/pkg/`（`cythsec/services/pkg`）。
`routerd` 通过 `go.mod` 中的 `replace cythsec/services/pkg => ../pkg` 在离线（`GOPROXY=off`）下解析共享包，
同时 `go.work` 也 `use ./services/pkg` 以支持 workspace 模式。

> 本机在 workspace 模式下 `go` 命令可能卡住，统一用以下前缀：
> `GOWORK=off GOPROXY=off GOTOOLCHAIN=local go <cmd>`

## 版本号单一来源

根目录 `VERSION` 文件是四端版本号的唯一真源：

- **C++**：根 `CMakeLists.txt` 读取 `VERSION` 注入 `${CYTHSEC_VERSION}`（子工程应改用此变量，勿硬编码）。
- **Rust**：根 `Cargo.toml` 的 `[workspace.package] version` 为工作区单一来源。
- **Go**：构建脚本用 `-ldflags "-X main.version=<VER>"` 注入 `main.version`（见 `scripts/build/build-all.sh`）。
- **前端**：`web/console/vite.config.ts` 读取根 `VERSION` 注入全局常量 `__APP_VERSION__`。

提交前请运行 `bash scripts/release/check-version.sh` 校验四端一致（不一致非 0 退出）。

## 提交前自查

```bash
bash scripts/release/check-version.sh
bash scripts/lint/lint-all.sh
bash scripts/test/test-all.sh --go   # Go 服务必须有测试且通过
```

> 注意：C++ / 前端源文件由对应负责人维护（dataplane/、web/src/），请勿越权修改。
