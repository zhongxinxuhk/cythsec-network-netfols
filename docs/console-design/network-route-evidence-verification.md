# NC-02B3B3验收记录

日期：2026-10-29。证据目录：build/network-route-evidence。

| 检查 | 结果 |
| --- | --- |
| 初次Go/前端定向 | Go通过；前端2文件13项通过；含新只读查询白名单与故障隔离 |
| 模糊测试 | 10秒请求、2 worker，实际约11.9秒、629499次执行，退出0；fuzz.log；有限执行不代表穷尽输入 |
| 最终race | 退出0；networkcfg与api包；go-race.log |
| 完整lint | 退出0；lint.log；含前端类型、ESLint及仓库其他静态检查 |
| 默认完整测试 | CYTHSEC_LIVE_SUDO=0、CYTHSEC_LIVE_IFACE=en0，无分组裁剪，退出0；25文件93项前端测试；test.log |
| 生产构建 | build-all.sh --go --node退出0；四个Go服务与Umi生产构建；build.log |
| Linux交叉编译 | amd64/arm64/loong64/mipsle均退出0；crosscompile.log；不代表目标运行认证 |
| 实际HTTP | 服务就绪后返回darwin/unsupported、profiles=[]、can_adopt/can_apply=false；http.json |
| 浏览器 | 路由差异页签、平台反馈、ArrowRight+Return键盘切换通过，无warn/error；route-desktop.png、browser.json |
| 响应式 | 390px视口/文档/抽屉，表格容器294px、内容1150px；已恢复桌面视口并关闭临时QA页 |
| BPF | 普通用户en0，25216帧，25215成功解析/1不支持/0错误，15项断言通过；无注入目标，ICMP可见项不适用 |

目标Linux实际nmcli格式与运行、复杂路由语义、整机资源/长稳、事务应用与独立回滚仍未核验。
既有DPI14、TCP重组2、FlowRecord8项tshark裁判例外保留未核验；不合main、不推送，不执行sudo。
高可靠基线是内部工程要求追踪，不是“军工级”认证结果。

本地evidence-manifest.json绑定提交、改动文件与已完成日志/构建物的SHA-256，供检测后续文件变化。
它不是签名/可信时间证明；活动服务日志及会被下一轮覆盖的共享抓包目录不纳入固定清单，不复制原始流量。
共享抓包的本轮计数依据已保留在独立test.log；证据目录保持本地，不进入Git或对外报告。
