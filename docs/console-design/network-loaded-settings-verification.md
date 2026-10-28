# NC-02B3B2验证记录

日期：2026-10-29。证据目录：build/network-loaded-settings。

| 检查 | 结果 |
| --- | --- |
| Go定向与race | 最终退出0；白名单、字段漂移、未知、自动MTU、空输出、UUID批量乱序关联与权限/超时边界；go-race.log |
| 前端定向 | 2文件11项通过；伪一致、来源错绑、未知转空、汇总掩盖、自动值与未知反馈 |
| 完整lint | 退出0；lint.log；含两套前端类型检查、ESLint与其他仓库静态检查 |
| 默认完整测试 | CYTHSEC_LIVE_SUDO=0、CYTHSEC_LIVE_IFACE=en0，无分组裁剪；退出0；25文件91项前端测试通过；test.log |
| 生产构建 | build-all.sh --go --node退出0；四个Go服务与Umi生产构建；build.log |
| Linux交叉编译 | amd64/arm64/loong64/mipsle均退出0；crosscompile.log；不是运行认证 |
| 实际HTTP | macOS返回unsupported、profiles=[]，can_adopt/can_apply=false；http.json |
| 浏览器 | 加载差异页签与平台反馈、ArrowRight+Return页签切换通过；console无warn/error；loaded-settings-desktop.png、browser.json |
| 响应式 | 390px视口/文档/抽屉，表格容器294px、滚动内容1100px；已恢复桌面视口并关闭临时QA页 |
| 本机抓包 | 普通用户en0采集8271帧，8269成功解析/2不支持/0错误，15项断言通过；无注入目标，ICMP可见项不适用；build/e2e-live |

仅本机开发验证；目标Ubuntu/Rocky/Kylin的实际nmcli格式与daemon行为仍未核验。
OpenWrt/Netplan本轮不提供加载字段比较。既有tshark DPI14、重组2、FlowRecord8项裁判例外仍未核验。
不合main、不推送；本轮不执行sudo、接管或系统网络变更。
脚本退出0不覆盖裁判例外，也不代表完整NC-02B3B、路由/列表顺序或配置应用闭环已完成。
