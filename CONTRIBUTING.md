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

## CI 格式化器版本

C++ 静态检查与通道 ABI 生成器共用 PATH 中的 clang-format。CI 的精确版本保存在
`.clang-format-version`，不能使用发行版的无版本 `apt install clang-format` 替代：不同版本
会改变注释/对齐输出，产生本地通过而 CI 失败的结果。在开发环境中安装该版本后再运行门禁：

```bash
python3 -m pip install "clang-format==$(cat .clang-format-version)"
clang-format --version
```

工作流运行数量、触发条件与安全扫描入口见 [Actions 说明](docs/deployment/actions-ci.md)。

## 分支与合并（硬规则，有钩子拦）

**一个问题一条分支；两条门禁全绿才并入 `main`；提交只落本地。**

```bash
make hooks                             # 每个新克隆先跑一次（见下方"为什么还要这条"）
git switch -c <type>/<topic>           # type ∈ feat fix chore docs refactor test
#   …改完在这个分支上提交…
bash scripts/lint/lint-all.sh && bash scripts/test/test-all.sh   # 全绿才算"完成"
git switch main && git merge --no-ff <type>/<topic>            # --no-ff：历史上看得见这条分支
```

- 直接 `git commit` 在 `master`/`main` 上会被 `scripts/hooks/pre-commit` 拒绝，并把上面这套
  正确做法打印出来。唯一例外口是 `CYTHSEC_ALLOW_MAIN_COMMIT=1`（会打警告，理由须写进提交说明）；
  **不要用 `--no-verify`** —— 那连明文密钥兜底扫描一起绕了。
- `git push` 需要用户明确授权（Agent 侧由 `scripts/hooks/guard-agent-git.sh` 拦，
  例外口 `CYTHSEC_ALLOW_PUSH=1`）。
- **为什么规则还要配钩子**：`core.hooksPath` 是本地 git 配置、**不随克隆走**。新克隆里钩子文件
  在仓库里躺着却一次都不会执行 —— 本仓库为"检查器存在但没人调用"踩过三次坑，所以
  `bash scripts/test/test-all.sh --branch-policy`（`make check-hooks`）既自证钩子的判定逻辑
  （S1–S7 + 2 项反向注入），也检查本克隆的安装状态；未安装时显式报「未核验」而不是通过。
- 规则真源在仓库根 `AGENTS.md`（`CLAUDE.md`、`.claude/settings.json`、`.workbuddy/memory/MEMORY.md`
  都指回它），本文件只面向人类贡献者复述一遍。

## 提交前自查

```bash
bash scripts/release/check-version.sh
bash scripts/lint/lint-all.sh
bash scripts/test/test-all.sh --go   # Go 服务必须有测试且通过
```

> 注意：C++ / 前端源文件由对应负责人维护（dataplane/、web/src/），请勿越权修改。
