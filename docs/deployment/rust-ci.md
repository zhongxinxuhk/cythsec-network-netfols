# Rust GitHub Actions

Rust 检查入口为 `.github/workflows/rust.yml`，由 `ci.yml` 在推送 `main` 或开启/更新 PR 时调用，也支持 Actions 页面的手动运行。复用调用与手动调用执行同一套作业；不再单独监听相同的 push/PR，以免一份提交排队两次。

## 作业与结果

| 作业 | 内容 | 阻断条件 |
| --- | --- | --- |
| quality | rustfmt、全目标/全 feature Clippy、rustdoc | 格式不符、编译错误、Clippy correctness、文档警告 |
| build-test | Ubuntu 24.04 与 macOS 15；Debug/Release workspace 全目标与全 feature 编译测试、文档测试、Rust/Python 特征契约与反向注入、版本冒烟 | 任一步退出非零或版本/提交戳不符 |
| interoperability | Linux C++/Rust ABI、共享环、DPI、TCP 重组、FlowRecord/TCP 统计、IPFIX 导出/采集/异厂互通、采样及相应反向注入 | 断言不符、缺少裁判工具导致分组未执行 |
| result | 汇总上述作业 | 任一作业失败、取消或跳过 |

Rust stable 由工具链 Action 安装；Action 本身钉扎提交 SHA。编译和测试采用 `--frozen`，不允许修改 Cargo.lock 或访问依赖网络；当前 Rust crate 没有第三方依赖。Python 使用 3.11，特征核验只需标准库。`channel::region` 使用 Unix 接口，当前平台矩阵不包含 Windows。

生成样本必须先于首次编译：Rust tests/examples 用 `include_bytes!` / `include_str!` 嵌入 `.gitignore` 中的向量。`scripts/test/prepare-rust-fixtures.sh` 是 CI 与 `test-all.sh` 共用的四类样本生成入口，不依赖开发机已有产物。

缓存按平台、工具链和作业用途隔离，只有 `main` 写缓存。`build.rs` 当前只跟踪 VERSION，故构建前清理 `traffic-engine` 包的缓存结果，保留依赖缓存，随后用 `git rev-parse --short HEAD` 校验发布二进制的提交戳，防止沿用旧构建信息。

## 验证范围与例外

现有 Clippy 风格警告保留在日志中；本阶段仅 correctness 和编译错误阻断，不宣称历史警告已清零。rustdoc 单独启用 `-D warnings`。

第三方协议裁判存在已登记的例外：DPI 非 identified 输入及手工 ECH、TCP 重叠仲裁/内存上限策略、FlowRecord 应用未识别字段。这些项目由原核验脚本明确列出为 `SKIP` 或“跳过”，不计为已完成的第三方核验；Rust 单测和生成器期望仍会执行。CI 会将这些记录写入作业摘要。环境缺失的 `⚠ … 未核验 / 未验收 / SKIPPED` 则使互操作作业失败。

专用 Rust CI 不运行真实网卡抓包、真实 ClickHouse Native 回读和按机器标定的性能基准。这些项目分别由全量 `test-all.sh`、`--columnar` 与显式 `--bench` 验收。CI 的通过不能代替仓库合并规则要求的两条全量本地门禁，更不能把缺捕获权限时的 `SKIPPED` 记为通过。

## 产物与复现

质量和矩阵测试日志保留 7 天；互操作失败时保存日志与共享环诊断。`main` 和手动运行在测试成功后保存 Linux/macOS Release 压缩包，保留 14 天；包含七个 Rust 二进制、VERSION 与 Cargo.lock。产物是 CI 构建包，不是已签名正式发行版。

本地复现（从仓库根目录）：

```bash
bash scripts/test/prepare-rust-fixtures.sh
cargo fmt --all -- --check
cargo clippy --frozen --workspace --all-targets --all-features -- -D clippy::correctness
RUSTDOCFLAGS='-D warnings' cargo doc --frozen --workspace --all-features --no-deps
cargo clean --package traffic-engine
cargo build --frozen --workspace --all-targets --all-features
bash scripts/test/test-all.sh --rust
cargo build --frozen --release --workspace --all-targets --all-features
cargo test --frozen --release --workspace --all-targets --all-features
# 还需 cmake、C++ 编译器与 tshark：
bash scripts/test/test-all.sh --cpp --rust --parity --e2e --dpi --reassembly --flows --ipfix --sampling
```

仓库主分支现名为 `main`，GitHub 默认分支与本地 `github/HEAD` 均指向它。本地 `main` 跟踪 `github/main`；GitCode 的 `origin` 独立保留。分支名称与 upstream 的调整不代表之前未验收的功能已合入本地主分支。
