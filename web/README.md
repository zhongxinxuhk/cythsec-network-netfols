# CythSec 控制台

`console/` 已安装完整 Ant Design Pro 6.0.3 工程，结构与用户指定的
`OpenHotelManagementSystem/frontend-admin-pro` 一致：Umi Max、Ant Design、ProComponents、
Plots、国际化、访问控制、登录/注册、布局设置、OpenAPI、标准页面及测试。

## 启动

```bash
cd web/console
npm ci
npm run dev
```

入口：http://127.0.0.1:15173/dashboard/analysis 。Node >=22，CI 使用 Node 24。
`npm ci` 会执行 `max setup` 生成类型；不要在运行中的 dev server 上并行执行 `max setup`。
框架原有 `.npmrc` 的 `legacy-peer-deps=true` 与参考工程保持一致，锁文件已完整生成。

## 页面与数据

保留上游 **28 个页面组件**：欢迎、管理、分析/监控/工作台、基础/分步/高级表单、
搜索/查询/基础/卡片列表、基础/高级详情、成功/失败结果、403/404/500、账户中心/设置、
登录/注册/注册结果、AI 助手。

另有 **5 个 CythSec 页面**，全部在同一 ProLayout 中：

| 路径 | 功能 | 数据 |
| --- | --- | --- |
| `/network/overview` | 主机/接口/路由概览 | routerd system/interfaces/routes |
| `/network/interfaces` | 接口状态/IP/MAC/MTU | routerd interfaces，5s 刷新 |
| `/network/routes` | IPv4 路由 | routerd routes |
| `/network/traffic` | 收发/错误/丢弃累计计数 | routerd traffic，3s 刷新 |
| `/network/system` | 主机/OS/架构/进程 | routerd system |

原 `/interfaces`、`/routes`、`/traffic`、`/system` 路径保留重定向。
`/api/v1` 与 `/healthz` 代理到 `127.0.0.1:8080`，可用 `CYTHSEC_ROUTERD_TARGET` 修改。
版本来自仓库根 VERSION，应用版本与模板版本分开记录。

标准页面保留原模板数据与开发 mock，dev 默认按官方预览方式进入；生产构建不包含 mock。
这些页面作为后续业务接入基础，不代表对应安全业务已经实现。CythSec 页面只使用真实 routerd API。
当前 routerd 页面沿用既有只读访问；模板用户/访问控制不等于后端认证。
AI 助手界面保留，默认走同源 `/api/chat/completions`，后端需另行接入。

## 验证

```bash
npm run typecheck
npx playwright install chromium
npm test
npm run lint
npm run build
```

测试分成 Node（API/格式化/版本/loopback）和真实 Chromium（上游组件/表单/表格/数据与错误处理）。
浏览器测试映射到 Umi 客户端出口，避免错误地把 Node CLI 编译进浏览器；无用例时失败。
CI Linux 环境使用 `npx playwright install --with-deps chromium`。
生产构建输出 `console/dist/`；实际部署需为 `/api/v1` 配置同源反向代理。

## 来源与调整

来源、固定提交、版本与本地调整见 [UPSTREAM.md](console/UPSTREAM.md)。
未复制参考工程的酒店业务配置。旧控制台在 Git 基线中可恢复，本次迁移前另在
`build/frontend-before-pro/` 保存了本地备份。
