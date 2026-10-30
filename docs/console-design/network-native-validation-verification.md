# NC-02B1 验证记录

本轮先修复构建配置的 TS1259，再在独立功能分支补充原生工具解析校验。
证据目录：本机 `build/typescript-interop/`、`build/network-native-validation/`。

| 检查 | 当前记录 |
| --- | --- |
| TS 主/Node/关闭互操作选项回归 | 三项退出0；CLion 构建配置文件诊断无错误 |
| 首轮完整 lint | 退出0 |
| 首轮默认完整测试 | 前端执行出现多项超时/失败，保留原日志，不作为通过证据 |
| Go 原生校验与API定向测试 | 退出0；覆盖非特权/平台/版本/启动阶段/目录模式/超时/空输出/单并发/严格请求/429 |
| 最终完整 lint | 退出0；acceptance/lint-all.log |
| 最终默认完整测试 | 退出0；前端24文件82项通过，BPF16项断言通过；acceptance/test-all.log |
| 最终生产构建 | 退出0；acceptance/build.log；三项退出码见acceptance/exits.txt |
| Go race | 最终代码退出0；networkcfg与api；acceptance/go-race.log |
| Linux交叉编译 | amd64/arm64/loong64/mipsle成功，不替代目标系统运行验收 |
| 真实HTTP | macOS返回unsupported，摘要、文件检查和can_apply=false正确 |
| 浏览器 | 同一15173控制台，完成真实接口请求、结果抽屉、键盘关闭、修改MTU后摘要与时间更新；无新增warn/error |
| 截图 | build/network-native-validation/native-validation-desktop.png |

前端测试限制同时运行的 DOM worker 为1。完整前端曾达到80/82通过，两个多步交互用例触发
Vitest默认的整体5秒上限；定向复验还发现另一个同类5秒预算不足的用例，因此统一DOM集成测试
整体预算为15秒，与既有网络配置等长交互测试一致。原有请求超时、waitFor等待、业务断言、
次数、权限和旧响应隔离要求保持不变；没有用任意重试或伪造控件放行。
原生执行器实际子进程回归校验了 stdin、清洁环境、工作目录、非零退出码；
原有真实子进程输出限额和取消测试保留。macOS 的路径别名在测试中通过 realpath 核对。

Ubuntu/Rocky/Kylin V11/OpenWrt 原生命令运行、版本矩阵、持久配置来源、接管、管理链路、
事务应用/确认/回滚仍未核验；Linux模拟返回值不是这些发行版的运行证明。
既有 tshark DPI14、TCP重组2、FlowRecord8项例外仍保持未核验。
两条门禁脚本退出0不覆盖上述24项未核验，不能据此将项目整体标为全绿。
仅落本地功能分支，未合入main或推送。没有改本机IP/DNS/路由，没有运行sudo。
浏览器只创建内存中的文档地址草稿用于校验，没有保存；桌面截图与HTTP结果仅留本机。
