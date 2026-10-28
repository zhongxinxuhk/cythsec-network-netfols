# NC-02B2 验证记录

证据目录为本机build/network-persistent-inspection；仅本地功能分支，不推送或合入main。

| 验证 | 结果 |
| --- | --- |
| Go读取器/API定向与race | 最终代码退出0；go-race-final.log |
| 前端API/页面定向 | 2文件10项通过；新增来源组件展示1项通过；默认全集25文件85项通过 |
| Python纯投影 | Go测试实际调用Python3；白名单、MAC匹配限制、复杂路由属性与敏感字段排除 |
| 原生PyYAML | 本机实际解码YAML，验证白名单、安全标签拒绝与空诊断；yaml-native-check.txt |
| 来源证据 | 文件副本、三层输入、版本变化/重启隔离、符号链接与大文件拒绝、未配置与未知、空DNS与未知Metric |
| 原生查询边界 | 固定只读argv、绝对副本、私有权限、失败不发布合并结果、忙返回429、无效请求不读源文件 |
| 完整lint/默认完整测试/生产构建 | 最终代码均退出0；final/exits.txt及同目录日志 |
| BPF真实采集 | 普通用户权限，16项断言通过；未执行sudo |
| 真实HTTP | 三个backend在macOS均返回unsupported、无虚构声明、can_apply=false；http.json |
| 浏览器 | 无草稿读取、结果抽屉与两页签、未知状态、键盘关闭通过；无warn/error |
| 响应式 | 390px断点稳定后，页面与抽屉宽度均390；表格在容器内横滚；临时视口已恢复 |
| 桌面截图 | persistent-desktop.png |
| Linux交叉编译 | amd64/arm64/loong64/mipsle成功；crosscompile.txt；不是运行认证 |

NetworkManager源文件权限/实际加载、Netplan字段级来源归因、UCI目标版本、Ubuntu/Rocky/Kylin V11/OpenWrt实际运行矩阵仍未核验。
本机macOS不执行Linux配置查询；不以夹具、交叉编译、源文件读取或HTTP200标记目标系统适配完成。
既有tshark裁判DPI14、TCP重组2、FlowRecord8项仍未核验，脚本退出0不能覆盖这些例外。

补充回归：复杂策略路由不被压平成普通主表路由；NM分号地址及gateway显式优先级；原生UCI空导出返回unavailable，不作为零配置成功。
浏览器验证使用同一15173控制台的后台标签页；未改用户正在浏览的页面，也未创建或保存接口草稿。
