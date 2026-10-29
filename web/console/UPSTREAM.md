# Ant Design Pro 完整工程来源

- 官方仓库：https://github.com/ant-design/ant-design-pro
- 固定提交：`42f2cb1d303380909ea04c73b5e60679d09c321a`
- 模板版本：6.0.3（`package.json.antDesignProTemplateVersion`）。应用版本仍来自 CythSec 根 VERSION。
- 对照工程：`/Users/xuzhongxin/IdeaProjects/OpenHotelManagementSystem/frontend-admin-pro`，仅读取结构与依赖配置。
- 保留 LICENSE、全部 28 个上游页面组件、配套服务/mock/国际化/组件/表单/图表/测试及配置。

本地接入：CythSec 标识、5 个只读网络页面、routerd 同源代理、根版本注入、独立 Node 测试、
真实 Chromium 测试客户端别名、CI Node 24。默认第三方统计配置已移除，应用请求不再默认指向
上游演示后端；AI 助手默认同源。上游 .npmrc 和 lock 策略保留，显式声明配置直接使用的
`@utoo/pack@1.5.31`，避免依赖间接提升位置。

Umi 4.7.27 的 webpack/utoopack 外层 server.listen 未传 host，单靠 HOST 只改变显示 URL。
开发启动器加载一个仅针对 15173 的 loopback 补丁，在 Node 原生 listen 处补 127.0.0.1；
不修改依赖包、不影响生产构建，并有真实 socket 单测和监听地址验收。生产仍使用原 utoopack。

`src/.umi*`、`.turbopack` 等为自动生成目录，不入库；原 Vite/手写布局入口已被 Umi 替代。
官方页面保留示例数据；真实 CythSec API 页面与其分开路由，后端业务接入需逐项完成。
