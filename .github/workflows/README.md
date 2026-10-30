# GitHub Actions 流水线

`ci.yml` 是 push / pull_request / merge_group 的唯一编排入口，也支持手动运行。
`push` 不限制分支、tag 或路径；每次推送均执行相同检查。PR 检查保留，因此打开 PR 的分支推送会
分别产生 push 和 PR 两次运行（PR 检查验证合并引用）。没有按分支取消旧运行的 concurrency 配置，
后续推送不会主动取消前一次流水线；不同推送的运行可并发，每次运行内部按下列阶段排序。

| 顺序 | 阶段 | 检查内容 |
| --- | --- | --- |
| 1 | workflow-tests | actionlint、工作流依赖/触发/门禁回归、Shell 语法 |
| 2 | lint | 仓库统一静态门禁，包含生成物、类型检查、前端与 Python 质量检查 |
| 3 | security | 密钥扫描、全部 Go 模块漏洞检查、前端完整锁文件漏洞检查 |
| 4 | cpp | Linux GCC/Clang、macOS Clang 编译与 CTest；无测试目标也失败 |
| 5 | rust | 质量检查 → Linux/macOS Debug/Release 构建测试 → C++/tshark 互操作 |
| 6 | python | 锁定 Python/uv 环境、质量工具和隔离安装包验收 |
| 7 | go | Go 1.22 编译、五个模块测试、vet、race |
| 8 | node | 仓库指定 Node 版本、npm ci、类型、ESLint、测试、生产构建与 dist |
| 9 | full-validation | Linux 四栈构建、静态门禁、默认测试全集、root 采集档位验收 |
| 10 | e2e | 四服务端到端验收、聚合持久化与重启查询 |
| 汇总 | CI required | 无论前序成功、失败或跳过均运行，仅全部阶段 success 时通过 |

阶段间通过 `needs` 建立成功依赖；前序失败会阻断后续依赖阶段，最终门禁报告失败。
同一阶段内部的跨平台矩阵/独立安全检查可并行，矩阵使用 `fail-fast: false` 收集各平台结果。
`CI required` 的 `needs` 列出所有阶段，避免前序失败导致后序 skipped 而汇总误绿。
仓库规则集若需阻止不合格合并，应将 **CI required** 设为必需检查；本次文件修改不会变更远端规则集。

## 默认全集的环境与结果

`full-validation.yml` 不枚举默认测试分组，直接调用无参数 `bash scripts/test/test-all.sh`，
因此今后加入默认集合的新检查会自动纳入流水线。机器相关 `--bench` 按现有测试约定不纳入默认全集。

`.github/actions/full-environment` 预装所有语言工具链，在线准备 Cargo/uv/npm 缓存后执行离线验收，
并通过 `make hooks` 安装当前克隆的分支策略钩子。tshark 与 ClickHouse 是独立参考实现；ClickHouse
使用官方 LTS 25.8.1.5101 Linux amd64 包，安装前校验固定 SHA-512 摘要。

抓包在专用 Ubuntu runner 的临时 veth/network namespace 中产生流量，成功或失败都会清理。
默认全集仍以 runner 用户运行，仅抓包子进程使用 sudo；采集档位与丢包观测另以 root 显式执行。
这段特权接线仅用于专用 Linux CI runner，不用于开发 Mac 或真实网络。

`scripts/ci/run-check.sh` 保存命令原始日志与非零退出码，拒绝实际出现的权限跳过、环境未核验和
`[SKIP]` 结果。它不会把自证描述中的“未核验”或已登记协议字段差异的 `SKIP(...)` 当作环境跳过。
后者继续出现在 Rust 互操作日志/摘要中，不能解释成相关字段已通过第三方核验。
最终成功说明本流水线定义的验收范围通过，不声明未纳入范围的协议或硬件已完成验证。

## 其他工作流

- `lint.yml`、`security.yml`、`cmake-multi-platform.yml`、`rust.yml`、`full-validation.yml` 支持
  `workflow_call` 和手动运行，不独立重复响应 push/PR；Security 保留每周定时扫描。
- `generator-generic-ossf-slsa3-publish.yml` 保留 release/手动发布来源证明入口。普通推送执行编译测试，
  发布来源证明仍由发布事件触发；私有仓库的公共 Rekor 披露边界沿用原设置。
- 所有常规远程 Action 固定到提交 SHA，checkout 不保留凭据。安全子流程需要的
  `pull-requests: read` 由编排入口显式传递；SLSA 发布作业沿用独立的发布权限。

## 预发布包

`prerelease.yml` 不直接响应 push，而是监听 `ci.yml` 的 `workflow_run` 完成事件：只有
**push 触发的 CI 成功**后才构建发布包；PR、`merge_group` 或失败的 CI 不会发布。
手动运行 `workflow_dispatch` 可对当前默认分支重新打包。

发布作业在成功提交上重新构建五个模块（不复用各阶段缓存，保证资产与提交一致）：

| 模块 | 资产 |
| --- | --- |
| C++ | `cythsec-cpp-<ver>-<os>-<arch>.tar.gz`：capture / parse / dump-abi / ring-feed |
| Rust | `cythsec-rust-<ver>-<os>-<arch>.tar.gz`：analyze / IPFIX / NetFlow v9 / bench 等 |
| Go | `cythsec-go-<ver>-<os>-<arch>.tar.gz`：routerd / policyd / dnsd / telemetryd |
| 前端 | `cythsec-console-<ver>.tar.gz`：`web/console/dist` |
| Python | `cythsec_training-<ver>-*.whl` 与 sdist |

每个提交对应一个 `pre-<short-sha>` 标签，发布为 GitHub **Pre-release**（不会成为 Latest），
并附 `SHA256SUMS`。同一提交重跑时只更新资产与说明，不删除重建标签。
构建与发布脚本是 `scripts/ci/package-release.sh`、`scripts/ci/publish-prerelease.sh`；
本地可用 `package-release.sh build/prerelease-local` 复现同一套打包（不发布）。

## 本地检查

```bash
python3 -m pip install -r tests/ci/requirements.txt
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
actionlint -shellcheck= -pyflakes=
python3 -m unittest discover -s tests/ci -v
git ls-files -z '*.sh' | xargs -0 -n 1 bash -n
bash scripts/lint/lint-all.sh
bash scripts/test/test-all.sh
```

具体实跑记录见 `tests/ci/VALIDATION.md`。本地检查不能替代 GitHub runner 的实际执行证据。
GitHub 的依赖/失败传播语义以 [workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idneeds) 为准。
