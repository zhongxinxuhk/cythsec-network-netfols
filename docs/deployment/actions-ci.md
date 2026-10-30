# Actions 触发与检查

## 为什么同一 PR 有三条运行

三个独立入口各执行一次，属于正常行为：

| 入口 | 职责 | 触发 |
| --- | --- | --- |
| CI | 多语言构建、测试、控制面 e2e，并调用 Rust 可复用工作流 | main push / pull_request |
| Lint | 格式、生成物、版本与前端静态检查 | main push / pull_request |
| security | 密钥扫描、所有 Go 模块漏洞扫描 | main push / pull_request / 定时 / 手动 |

GitHub 默认用 PR 标题作运行标题，所以三条记录原先看起来一样。现在每个入口的 `run-name`
显示 `CI / Lint / Security · 事件 · 分支`。Rust 只有 `workflow_call` 与手动入口，PR 中由 CI
调用一次，不再单独订阅 push/PR。向功能分支推送时不会同时触发 main push；合并后 main 上
的新提交属于另一事件，需要重新验收。

Lint、security 和 Rust 各自设置并发组：同一事件、同一分支的旧运行会被新运行取消，不会
取消另一个工作流，也不会把定时安全扫描与 push 混为一组。已经结束的历史记录仍会保留。

## 已修复的失败原因

- **clang-format 漂移**：Ubuntu 无版本包实际安装 18，本地生成物使用 21。Lint 现在从
  `.clang-format-version` 安装精确版本，格式检查与 ABI 生成器通过 PATH 使用同一个二进制。
  未重写 C++ 业务源码或生成契约。
- **Gitleaks PR 入口缺令牌**：传入 GitHub 自动生成的令牌，只授予 contents / pull-requests
  读取权限，关闭 PR 评论；升级至支持 Node 24 的 Action 并钉扎 SHA。兜底密钥扫描即使
  Gitleaks 失败也继续执行。兜底扫描器仅对 workflow 文件中整行、无拼接的 GitHub 运行时
  引用放行；明文值、拼接值、条件值和其他路径仍阻断，并以独立自证验证。
- **Go 扫描工作目录错误**：根目录只有 go.work，没有 go.mod。新增
  `scripts/security/scan-go-vulns.sh`，发现 Git 索引中的全部 go.mod，逐模块切换目录扫描；
  `GOWORK=off`、`GOTOOLCHAIN=local` 保证模块和工作流指定工具链的边界。没有模块、缺工具、
  扫描错误或发现可达漏洞均退出非零；一个模块失败后仍扫描其余模块。

Go 安全作业使用钉扎的扫描器及受支持的 Go 工具链，构建兼容性仍由 CI 的 Go 1.22 作业验证。
不再用 continue-on-error 将扫描失败忽略。脚本的 `--self-test` 使用独立临时 Git 索引，验证
现有布局、未来深层新增模块、正确工作目录、环境隔离、中途失败的传播和空模块集合拒绝。

Rust 的平台矩阵、产物和第三方裁判例外见 [Rust Actions](rust-ci.md)。仓库合并仍要求全量
本地门禁；真实抓包因缺权限 SKIPPED 时不能据此宣称全绿。
