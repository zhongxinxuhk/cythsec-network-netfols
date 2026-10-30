# 完整 Ant Design Pro 接入（2026-10-30）

用户指定官方分析页及 OpenHotelManagementSystem/frontend-admin-pro 作为安装参考，
本次将 web/console 从 Vite 小型入口迁为完整 Pro 6.0.3 / Umi Max 工程。
保留全部 28 个上游页面组件及其配套模块，并把 CythSec 的 5 个真实 API 页面接入相同布局。

验收：干净 npm ci、严格类型、Node 单测、真实 Chromium 组件测试、生产构建；
浏览器检查分析页/标准表格/表单、网络真实数据与旧 URL 重定向、默认视口布局和页面错误。
版本注入门禁迁至真实 Umi 配置，并加入回退字面量的反向注入；Node CI 同步升级至24。

功能范围和启动说明见 web/README.md；来源与本地调整见 web/console/UPSTREAM.md。
这批完成的是完整基础工程，原模板标准页面的示例数据并非 CythSec 安全业务数据。
真实流量趋势、策略写入、生产认证等仍按各自后端任务验收。
