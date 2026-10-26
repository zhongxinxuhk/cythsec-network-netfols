# CLion 编译、启动、测试与监测

共享运行配置位于仓库根 `.run/`。CLion 打开仓库即可加载；不依赖同步 `.idea/workspace.xml`。
本轮通过当前 CLion MCP 读取了项目、CMake 模型与运行配置，并实际发起构建和测试。

## 日常操作顺序

1. 选择 `CythSec Preflight`，检查工具是否存在。它只检查可发现性；版本约束由构建和测试真源继续校验。
2. 选择 `CythSec Build All` 构建四栈，或选择同组的 Cpp / Rust / Go / Console 单项。
3. 选择 `CythSec Lint All` 和 `CythSec Test All` 运行两条完整门禁。
4. 选择 `CythSec Run Development` 同时启动四个 Go 服务和前端。各进程在 Run 窗口分别查看日志、停止和重启。
5. 选择 `CythSec Monitor Once` 做单次健康检查，或 `CythSec Monitor Watch` 每轮后等待 5 秒，再输出状态与 HTTP 探测耗时。

构建、lint 和测试都复用 `scripts/build/build-all.sh`、`scripts/lint/lint-all.sh`、
`scripts/test/test-all.sh`。IDE 入口 `scripts/dev/clion.sh` 保留真实退出码，并输出证据目录
`build/clion/runs/<动作>.<随机后缀>/`，含 `output.log` 和 `exit-code`。中断而没有写出退出码时，不能据此判断通过。

不要在前端开发服务运行时执行 Build All / Build Console：统一构建中的 `npm ci` 会重建依赖目录。
运行 Lint All 前也先停前端，因为 Umi 类型准备会重建 `.umi`。构建完成后重新启动开发实例。

## 配置分组

共 36 个共享配置，名称统一以 `CythSec` 开头。

| 分组 | 入口与用途 |
| --- | --- |
| 0 Environment | Preflight：工具可发现性检查 |
| 1 Build | All、Cpp、Rust、Go、Console |
| 2 Quality | Lint All、Check IDE（配置与失败路径自证）、Dependency Audit |
| 3 Tests | All、Cpp、Rust、Go、Console、ABI、DPI、Reassembly、Flows、IPFIX、Shared Ring、Live BPF、Storage、Branch Policy、Capacity、Sampling、Benchmark、Control Plane |
| 4 Run | routerd、policyd、dnsd、telemetryd、Console、Development（复合启动）、Observe Sample |
| 5 Monitor | Once、Watch |

保留 CLion 原生 CMake Debug 配置和已有 CTest 配置，可继续使用 C++ 断点、原生构建及测试树。
这些共享 Shell 配置在 Run 窗口呈现完整输出与退出状态，不等同于 Go / Rust 插件的原生调试器或测试树。
Benchmark 仍是显式单项测试，默认 Test All 不执行有机器标定条件的基准门槛。

## 开发实例和数据

| 组件 | 监听 / 路径 |
| --- | --- |
| routerd | `127.0.0.1:18080` |
| policyd | `127.0.0.1:18081` |
| dnsd | `127.0.0.1:18082`，当前为 HTTP 管理骨架，无 DNS 报文服务 |
| telemetryd | `127.0.0.1:18083` |
| Pro 控制台 | `http://127.0.0.1:15174`，代理到上述 routerd / telemetryd |
| 聚合历史 / 队列 | `build/clion/aggregate/archive` / `build/clion/aggregate/queue` |
| 样本观察结果 | `build/clion/observations/run.*/aggregate.jsonl`，每次保留独立输出 |

复合启动并行启动各进程，不保证业务就绪顺序；以 Monitor Once 和浏览器实际请求为准。
缺少二进制会明确提示先 Build Go；端口被占用时服务启动失败，不自动停止占用进程。
这些配置只运行本机开发 API，不配置主路转发、阻断或生产部署。

Observe Sample 使用仓库生成的 PCAP，执行现有 `cythsec-observe` 产出粗粒度聚合结果；
样本过小而不发布窗口时保留真实完整性状态，不补造数据。监测只读取四个 `/healthz`，
校验服务名和状态，拒绝重定向、绕过系统 HTTP 代理；单次任一服务不可用就退出 1。
持续监测显示当前探测状态，不能证明服务有完整业务能力，也不是全量性能监控。

## 工具环境与权限

入口补齐常见 Go / Rust / Node / uv 安装路径；需要本机路径时使用被忽略的
`scripts/dev/config.local.env`，内容为 shell 环境赋值，例如 `export PATH="本机工具目录:$PATH"`。
共享 XML 不写个人绝对路径、凭据或 sudo 配置；机器环境文件不要存凭据。
本机已有 clang-format 21.1.8 已从临时虚拟环境复制到 `~/.cache/cythsec-tools/bin/`，
本机环境文件只把该目录加入 PATH。其他机器需要自行提供工具；预检缺工具会失败。

所有配置强制 `CYTHSEC_LIVE_SUDO=0`。Live BPF / Test All 可用现有抓包权限执行；
权限不足会按原门禁显示 SKIPPED / 未核验。每次提权仍需单独申请，配置不保存密码或自动执行 sudo。
可通过正常环境变量 `CYTHSEC_LIVE_IFACE` 指定本机接口，不在共享配置中写死 macOS 接口。

routerd / telemetryd 的访问认证配置继续遵循 [管理服务访问认证](control-access.md)。
未提供策略文件的回环开发实例明确显示“鉴权未启用”，不生成演示账号。

## 验收边界

`CythSec Check IDE` 已接入 lint，校验配置引用、项目宏、运行目录、复合依赖，并用反向注入
验证坏配置被拒；同时实测监测健康/错误身份/重定向/服务关闭和失败测试退出码保存。

完整脚本退出 0 不能消除既有 tshark 未核验项；依赖审计非 0 也不能写为通过。
MCP 可连接、XML 已识别、进程已启动和业务已就绪分别记录，不相互替代。


## 本机实际验收记录（2026-10-26）

CLion `CL-262.10968.176` 的 MCP 成功读取 CMake Loaded / Debug 模型，加载全部 36 个配置，
并实际执行以下检查。机器证据汇总：`build/clion/validation/mcp-verification.json`。

| CLion 入口 | 实际结果 | 证据 |
| --- | --- | --- |
| Preflight / Check IDE | 均退出 0 | MCP 输出；配置检查已挂 lint |
| Build All | 退出 0 | `build/clion/runs/build.ewyyEm/` |
| Lint All（最终复跑） | 退出 0 | `build/clion/runs/lint.Msertx/` |
| Test All | 退出 0；前端 52 项通过；BPF 16 项断言、15646 帧，未 sudo | `build/clion/runs/test.rqbXAq/` |
| 原生 CMake `test_packet` | 退出 0 | MCP 原生运行输出 |
| Observe Sample | 退出 0 | `build/clion/observations/run.bCVx9E/aggregate.jsonl` |
| Run Development | 四服务和前端均为 CLion 子进程，监听地址逐项核对 | 运行窗口、进程树、lsof |
| Monitor Once | 退出 0；四项均 online | MCP 实际响应 |
| Monitor Watch | 已在 IDE 启动，观察到至少两个 5 秒周期均 online | MCP 输出与 IDE 子进程 |
| 凭据扫描 | 退出 0；命中 0 处 | `build/clion/validation/secrets.log` |

首次 lint 因本机环境文件使用 `.sh` 后缀触发遗漏源码检查，返回 1；改为机器环境文件
`config.local.env` 后复跑通过，没有放宽扫描规则。Check IDE 的故障注入会生成退出码 2
的 `test.*` 证据目录，这是明确验证未知测试分组被拒绝的负向用例，不能与完整测试目录混淆。

MCP 并非完全稳定：本轮复合/长驻进程启动反馈曾报失败或传输中断，之后子进程才变得可观察；
读取配置与普通任务执行仍可用。调用失败不能直接判断进程未启动，重试前先核对 Run 窗口、
端口和健康状态，避免重复进程。本轮重复启动的监测进程已清理，仅保留一个 Watch。
长任务返回不带 exitCode 时不声明完成，构建/门禁以真实 evidence/exit-code 复核。

独立 Dependency Audit 初次 MCP 返回时尚未完成，随后完整日志已报告 21 项依赖告警
（11 low、10 moderate），与 Build All 的 npm ci 报告一致；本次未由 MCP 观察到退出码，
没有标为通过。DPI 14、TCP 重组 2、FlowRecord 8 项
仍跳过或未核验。所有这些边界继续保留，本轮仅提交本地开发分支，未合入 main、未推送。

后续依赖状态更新：见 [2026-10-27 控制台依赖修复](../development/dependency-remediation.md)，本页保留该批次实际审计结果。
