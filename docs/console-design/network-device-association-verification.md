# NC-02B3B1 验证记录

日期：2026-10-29。

证据目录：`build/network-loaded-evidence/`。

| 检查 | 结果 |
| --- | --- |
| Go定向与race | 最终退出0；状态矩阵、UUID大小写/冲突、未知值、不可读取、512设备上限与设备绑定边界；go-race.log |
| 前端定向 | 2文件9项通过；有效组合、伪激活/未知回填、范围/平台/UUID与旧后端显示 |
| 完整lint | 最终退出0；lint-all-final.log，含类型检查、ESLint及其他仓库静态检查 |
| 默认完整测试 | 显式CYTHSEC_LIVE_IFACE=en0、CYTHSEC_LIVE_SUDO=0运行，无分组裁剪，最终退出0；test-all-final.log；25文件89项前端测试通过 |
| 生产构建 | build-all.sh --go --node退出0；Go服务与Umi生产构建通过；build.log |
| Linux交叉编译 | amd64/arm64/loong64/mipsle均退出0；crosscompile.log；仅证明可编译 |
| 实际HTTP | macOS返回unsupported，device_evidence=unsupported，can_adopt/can_apply=false；http.json |
| 浏览器 | 设备关联与平台状态、键盘ArrowRight+Return激活页签通过，无warn/error；device-association-desktop.png与browser-verification.json |
| 窄屏布局 | 390px视口、文档及抽屉宽390px；表格容器294px、内容1100px，独立横向滚动；已恢复桌面视口 |
| en0实际采集 | 普通用户15项断言通过；4218帧，回读4216成功/2不支持/0错误；环境流量验收，无注入目标，ICMP可见项不适用；证据build/e2e-live |

首次默认测试退出1：自动选口因本机路由/邻居状态选择lo0，链路类型检查正确拒绝非以太网接口。
没有改写检查器或放行失败，显式指定活动en0后复跑整个默认集合通过。
首次lint检出新增显示表达式使用宽松相等，改用严格布尔三态后复跑完整lint退出0。
两次初始日志与退出码仍保留，不把初始失败改成成功。

NM设备与加载引用通过格式夹具验证，真实目标Linux运行矩阵仍未核验。
既有tshark DPI14、TCP重组2、FlowRecord8项裁判例外仍未核验；不合main，不推送。
本轮不执行sudo、系统网络配置或配置接管。
脚本退出0不覆盖这些例外，也不代表整个NC-02B3B或目标系统运行验收已完成。
