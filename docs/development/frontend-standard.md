# CythSec 标准中后台前端工程

项目的强制开发规则统一维护在 [AGENTS.md 前端开发标准](../../AGENTS.md#前端开发标准强制)。
本文件记录实现方案和验证方式，不另设一套流程规则。
完整目标设计见 [控制台设计基线](../console-design/README.md)，设计页面须按能力发布，不能直接当作已实现菜单。

## 技术基线

采用 [Ant Design Pro](https://github.com/ant-design/ant-design-pro) 官方工程的 Umi Max、
Ant Design 和 ProComponents 组合。Pro 是中后台应用方案，不能仅通过修改原有 CSS 宣称已接入。
本次采用 `@umijs/max 4.7.27`、`antd 6.6.8`、`@ant-design/pro-components 3.1.14-2`、
`@ant-design/icons 6.3.4`，使用满足 ProComponents peer 要求的 React 18.3.1，类型包分别为 18.3.31 / 18.3.7。
ProComponents 3 当前为预发布版本，版本精确锁定；与官方主线采用相同的 3.1.14-2 基线，
后续升级需要复跑组件交互、类型与生产构建验证。不能将 ProComponents 2 与 antd 6 强行混装。
当前预发布版的表格密度图标在 React 18 下存在 ref 警告，暂关闭该入口；列设置、排序、分页和刷新保留。

官方工程的示例登录、示例身份、演示菜单、mock 服务、在线统计脚本不纳入本项目。
当前控制台使用真实 routerd / telemetryd 接口，已增加可配置的静态 Bearer 服务认证与聚合写入权限区分，见 [访问认证](control-access.md)；完整生产身份与权限体系尚未完成，
发布到公网或接入生产环境前须单独完成认证、授权、审计和部署安全验收。

## 工程与页面

| 位置 | 职责 |
| --- | --- |
| `web/console/config/config.ts` | Umi Max 插件、ProLayout、Ant ConfigProvider、代理和构建常量 |
| `web/console/config/routes.ts` | 菜单、面包屑、九个业务路由与独立 404 |
| `web/console/src/app.tsx` | Pro 布局运行时、真实服务健康状态、根 VERSION 版本号 |
| `web/console/src/pages/` | PageContainer 页面，ProTable / ProDescriptions / ProCard |
| `web/console/src/global.css` | 业务结构布局，视觉主题交给 Ant Design Token |
| `web/console/src/api/` | 保留后端 envelope、异常、上传限额和队列确认语义 |
| `web/console/tests/`、相邻 `*.test.tsx` | Vitest + Testing Library，真实 Ant / Pro 组件交互 |

| 页面 | 组件与功能 |
| --- | --- |
| 运行概览 `/` | ProCard、Statistic、Ant Table；主机、路由和接口独立状态，未知不是零 |
| 网络接口 `/interfaces` | ProTable；地址、MAC、MTU、状态，5 秒刷新 |
| 路由表 `/routes` | ProTable；IPv4 路由只读，Metric 排序与手动刷新 |
| 接口流量 `/traffic` | ProTable；累计收发、丢弃、错误，3 秒刷新；不虚构实时速率 |
| 聚合分析 `/analytics` | Ant Upload、Form、DatePicker、Select；ProTable 服务端分页、Collapse / Progress 时差桶 |
| 网络配置 `/network/configuration` | Pro表单、IP/DNS/静态路由、原生预览与版本化草稿；系统应用未发布 |
| 指标字典 `/analytics/metrics` | Ant Tree、Input、ProDescriptions、ProTable；30个实际查询字段，键绑定DTO |
| 写入队列 `/data/queue` | 复用状态轮询与IngestPanel；容量Progress、最近成功读取、手动刷新和处理说明 |
| 系统信息 `/system` | ProDescriptions；主机与运行进程信息 |

全局使用 ProLayout 的headerRender/menuRender扩展点实现顶栏、模块快捷栏与分组功能菜单；面包屑和页面容器仍由Pro统一管理。目录、收藏和最近访问从同一份routes元数据生成，详见[导航收纳与动效](../console-design/cloud-navigation.md)。错误路径独立显示 Ant Result 404。
官方组件 API 参考 [ProComponents](https://procomponents.ant.design/) 与
[Ant Design 主题定制](https://ant.design/docs/react/customize-theme-cn/)。

## 数据与交互语义

界面文案遵守 [AGENTS.md 第8—9条](../../AGENTS.md#前端开发标准强制)：业务页面采用正式产品用语，
开发过程和设计用途放在配套文档。界面不使用自述式营销、身份免责声明或重复的工程限制横幅。
例如按钮使用“刷新”“查看证据”，请求失败使用“加载失败，请重试”；必要的来源、时效和权限信息就地显示。

- routerd 和 telemetryd 健康检查独立，2.5 秒超时；未返回前标为检查中，不能标绿。
- 常规控制面请求 10 秒超时；刷新前的旧请求晚返回不能覆盖新结果；内联 fetcher 不触发无限请求。
- 聚合分析仅接收不超过 1 MiB 的聚合 JSONL，不传原始 PCAP。队列状态未知时禁用上传。
- 队列接收确认只表示待写文件落盘；历史确认只由历史接口返回的批次证明。历史保存不证明采集无损。
- 统计按批次独立，时间查询按本机时区解释，范围 `[from, to)`，每页最多 100 窗。
  null、样本抑制、来源丢包未知均保留原意，不转换为零；TLS / QUIC 是头候选计数。
- 新增网络配置草稿/预览契约由routerd提供，见[网络配置API](network-configuration-api.md)；真实系统应用尚未发布。其他没有接口支撑的配置、账号、权限与业务操作不显示为已实现。

## 开发与验证

```bash
cd web/console
npm ci
npm run dev
npm run typecheck:all
npm run lint
npm test
npm run build
npm run preview
```

Umi Max 代替 Vite 开发/构建；Vitest 继续用于组件测试。`npm ci` 的 prepare 执行 `max setup`，
生成的 `src/.umi*` 不入库。原有 `VITE_*` 变量名为兼容启动脚本保留，均在 Umi 配置中读取：

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `VITE_ROUTERD_TARGET` | `http://127.0.0.1:18080` | 开发代理 `/api`、`/healthz` |
| `VITE_TELEMETRYD_TARGET` | `http://127.0.0.1:18083` | 开发代理 `/telemetry`，剥除该前缀 |
| `VITE_ROUTERD_BASE` | `/api/v1` | 编译期控制面 API 基地址 |
| `VITE_TELEMETRYD_BASE` | `/telemetry/api/v1` | 编译期聚合 API 基地址 |
| `PORT` | `15173` | 开发/构建预览统一端口，冲突时失败，不自动递增 |
| `CONSOLE_OUTPUT_PATH` | `dist` | 发版版本号实验的独立产物目录 |

生产环境由反向代理提供相同路径和 SPA 回退。开发代理不会写入 `dist`，Umi preview读取同一代理配置用于本机复验；正式部署仍由反向代理提供同源API。
`__APP_VERSION__` 在构建与测试中复用 `version-source.ts` 从仓库根 VERSION 注入，缺失即失败。

验收要覆盖九条路由直达与菜单切换、404、窄屏菜单和表格、服务离线、空列表、上传禁用与去重、
队列接受与历史确认、日期范围、服务端翻页以及旧请求晚到。测试可以隔离网络服务，但不能把
Ant / Pro 控件整体 mock 掉。仓库 lint 通过 ESLint 禁止业务组件重建原生按钮、输入和表格。
本地证据放在忽略目录 `build/ant-design-console/`；实际结果与未核验项目由本轮交付记录报告。

## 本轮依赖安全边界

框架迁移时的历史告警见 [原审计记录](../security/ant-pro-dependencies-20261026.md)，
后续清零与兼容性验证见 [2026-10-27依赖修复](dependency-remediation.md)。
审计、功能测试和第三方独立核验分别判断；保留的未核验项不能因设计更新改成通过。

## 统一控制台入口

开发与CLion统一访问`http://127.0.0.1:15173`；`npm run dev`和`npm run preview`复用同一端口约束，不能同时另起入口。
默认本机代理目标为routerd `127.0.0.1:18080`、telemetryd `127.0.0.1:18083`；可通过既有环境变量设置真实服务地址。
浏览器仅请求当前源的`/api`、`/telemetry`和`/healthz`，不直接连接后端端口。
九个业务入口和开发环境的五个设计视图共用Umi路由、ProLayout、服务访问与主题。
设计视图从`/design`进入；样例代码仅在development路由树加载，生产构建不注册，也不将样例数据混入业务统计。
原15174开发入口与15176静态预览已停用，不再维护第二个React根、路由器或构建脚本。

完整整合结构、启动冲突处理和验证证据见[统一控制台工程](unified-console.md)。
