# 顺序流水线验证记录（2026-10-29）

分支：`chore/ordered-push-pipeline`。原工作区中已有 DNS/TCP 实现改动及另一文档的暂存状态，
不属于本次 CI 提交；仓库级门禁在当前工作区执行，不能解释为这些既有改动已完成独立验收。

- 工作流/脚本回归：`python3 -m unittest discover -s tests/ci -v`，21 项通过。
- actionlint 1.7.12：退出码 0。
- 入库及新增 CI Shell 语法、`git diff --check`：退出码 0。
- 新增 Python 脚本/回归测试的 Ruff、Black 检查：退出码 0。
- `bash scripts/lint/lint-all.sh`：退出码 0（PATH 加入本机已安装的 clang-format 21.1.8）。
- `bash scripts/test/test-all.sh`：实际退出码 0。本机真实抓包 16 项断言完成；列式落盘使用本机
  ClickHouse 26.11.1.153 完成参考实现核验。该结果不代表所有第三方字段均已核验：DPI 摘要为
  比对 92 项、跳过 14 项（非 identified 或已知例外）；重组比对 16 项、跳过 2 项（重叠仲裁、
  内存上限例外）；FlowRecord 比对 927 项、跳过 8 项。具体应用未识别例外仍按原脚本打印。
- `run-check.sh` 对这次真实默认全集日志的重放：退出码 0；上述已登记字段例外未被改写为通过。
  回归测试另外证明环境缺失、权限 SKIPPED 和 `[SKIP]` 会导致包装器退出 1。
- `bash scripts/build/build-all.sh`：退出码 0，C++ / Rust / Go / 前端四栈全部编译完成。
- 控制面 E2E（经 `run-check.sh` 执行）：退出码 0，59 项断言通过、失败 0、跳过 0。

本次只在专用分支提交 CI 范围；既有第三方字段跳过项尚未清空，未宣称无跳过全绿或合入 main。

未执行推送、远端 GitHub Actions、远端分支规则修改、发布或部署。
Linux root 抓包、Ubuntu/macOS 矩阵、ClickHouse LTS Linux 包读回与最终必需检查仍需 GitHub runner 实跑。
