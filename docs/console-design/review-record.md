# v1.1设计与预览核验记录

日期：2026-10-27。交付：52页目标规格、受管网络资产、安全设备协作、20类可视化，
以及独立的5视图合成预览。不是生产功能验收或设备兼容认证。

## 1. 设计产物

- [总入口](README.md)、[原P01—P36](pages.md)、[P37—P43](network-assets.md)、[P44—P52](security-integrations.md)。
- [设备运维特性](appliance-operations.md)：HA、冗余、Bypass、硬件、配置与维护。
- [图表与视觉规范](visualization-spec.md)：V01—V20、交互、单位、质量、响应式和性能目标。
- [实现前置与验收](delivery-and-acceptance.md)：新增FE-A/FE-S/FE-V均待实施。

## 2. 可复现预览检查

执行`node docs/console-design/build-preview.mjs`：严格TypeScript检查、ESLint和esbuild打包。
ESLint复用前端规则；预览在生产tsconfig之外，因此解析project单独处理，类型由前一步完整检查；
独立静态包没有Fast Refresh，故不应用该一项规则。没有关闭生产工程规则，没有新增依赖。
最终命令退出码0；不是生产Umi应用完整构建、组件测试或真实后端验收。

浏览器使用本机回环地址的独立静态服务，不接入现有控制台服务。
已核验5视图加载、拓扑证据抽屉、图层切换、矩阵选中、深色主题、资产Tab、
工单阶段状态。早期版本曾提供本地阶段切换，现按正式界面文案规则移除，保留只读任务状态。

已检查1440与390宽度，页面根节点未出现横向溢出；最后一次概览加载的浏览器错误/警告列表为空。
已核验资产表核心区筛选；事件确认现为禁用状态，服务未连接时不能写入。
其余设计宽度、自动色觉/对比度检查、完整键盘回归、图表大规模性能、
真实适配器与后台幂等/重启恢复仍未核验。Mermaid只检查源码围栏，没有执行渲染器。

## 3. 真实浏览器截图

这些是预览运行截图，数据为合成值，绝不是现场网络数据。

| 视图 | 截图 |
| --- | --- |
| 浅色概览 | [overview-light.png](screenshots/overview-light.png) |
| 深色拓扑 | [topology-dark.png](screenshots/topology-dark.png) |
| 资产技术画像 | [asset-light.png](screenshots/asset-light.png) |
| 安全设备联动 | [integrations-light.png](screenshots/integrations-light.png) |
| 事件调查 | [incident-light.png](screenshots/incident-light.png) |
| 窄屏资产摘要 | [asset-mobile.png](screenshots/asset-mobile.png) |

## 4. 核验边界

本轮未修改`web/console`生产代码、依赖锁文件、服务与数据面；未运行BPF或提权命令，
未发送消息、创建真实工单或执行设备配置。`lint-all.sh`与`test-all.sh`未在本轮执行，
不声明完整门禁全绿，不合主线、不push。用户原有其他文档状态保持不动。

设计一致性检查覆盖P01—P52唯一编号/路径与规格、A01—A15及N01—N25引用、
V01—V20图表编号、内部文件引用、Markdown围栏与截图存在性；机器检查结果存于
`build/console-design/v1.1-checks.json`。它只证明结构与引用，不替代内容评审或UI功能验收。

结构核验结果：52页/路径唯一，E6/R8/C8/P30；15组现有API、25组目标契约、20类图表、15处Mermaid源码；64处内部文件引用有效，6张PNG尺寸与目标一致。

## 5. 界面文案标准修订

按用户明确要求，强制规则写入AGENTS.md前端第8—9条。删除重复开发横幅、虚构身份区、页脚自述和图表开发编号；样例来源与未接后端的事实仍保留在本设计包，未改变生产能力。
移除手动推进模拟回执/验证的按钮，工单展示只读阶段；事件服务未接入时禁用确认操作并提供简短原因。
当前截图随文案修订更新；历史本地交互检查不代表当前版本仍提供模拟按钮。

本次文案修订复验：独立预览严格类型检查、ESLint和打包退出0；浏览器确认通栏声明/虚构身份/页脚自述已删除、联动为只读状态、事件确认禁用，深色与390/1440布局检查完成，6张截图已更新，错误/警告列表为空。
