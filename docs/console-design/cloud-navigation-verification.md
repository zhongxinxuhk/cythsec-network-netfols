# 云控制台式导航验收记录

日期：2026-10-27。分支：`feat/cloud-console-navigation`。
范围：整体控制台导航、功能收纳、交互与动效；未改动后端协议分析或设备策略。

## 已实现

- ProLayout扩展点承载50px顶栏、56px模块快捷栏、216px当前模块菜单。
- 分类目录、模块搜索、全局搜索、收藏增删、最近访问、菜单分组折叠、侧栏收起。
- 768px以下切换抽屉式功能菜单；390px浏览器测量页面宽度与scrollWidth均390px。
- Drawer/Menu官方动效，侧栏200ms收起过渡，系统减少动态效果偏好接入Ant motion与自有CSS。
- 单Umi路由真源；六个业务页面与开发设计视图共用15173。
- 偏好只保留已发布静态路径，不保留业务数据、任意URL或凭据；存储错误不阻断导航。

## 执行证据

| 检查 | 实际结果 | 本地证据（忽略目录） |
| --- | --- | --- |
| `CYTHSEC_LIVE_SUDO=0 bash scripts/dev/clion.sh lint`（内部运行lint-all.sh） | 退出0；前端类型检查、ESLint及其他仓库lint完成 | `build/cloud-console-navigation/lint-all.log` / `lint-exit-code` |
| `CYTHSEC_LIVE_SUDO=0 bash scripts/dev/clion.sh test`（内部运行默认test-all.sh） | 退出0；前端20文件68项通过，其他默认组完成；已知跳过单列如下 | `build/cloud-console-navigation/test-all.log` / `test-exit-code` |
| `npm run build`（web/console） | 退出0，含typecheck:all与Umi生产构建 | `build/cloud-console-navigation/build.log` / `build-exit-code` |
| 真实BPF关口 | 普通用户执行，16项断言通过；本轮没有sudo或权限设置变更 | `test-all.log`与`build/e2e-live/` |
| 浏览器桌面 | 1440px布局、分类目录、搜索、模块切换、侧栏收起及恢复可操作 | `desktop.png` / `catalog.png` |
| 浏览器窄屏 | 390px无页面横向溢出；当前模块抽屉切换后关闭；Esc关闭目录，焦点回到“打开产品与服务”按钮 | `mobile.png` / `mobile-catalog.png` |
| 浏览器生产预览 | 四个业务模块、六个业务入口；无开发设计目录；直达`/design/topology`显示404 | 同一15173端口临时预览验收，随后恢复开发启动 |
| 生产产物 | 没有设计页面组件chunk，未发现设计样例标记CORE-GW-01、物理关系与容量 | `web/console/dist/`；路由定义模块可能保留无执行用途的开发路径字符串，不等于加载设计组件 |
| 系统减少动态效果 | 浏览器模拟reduce后媒体查询命中，侧栏过渡降至近零；模拟结束后恢复系统设置 | CUA只读样式检查 |
| 提交前密钥扫描 | 退出0，命中0；Ant主题字段使用带引号的公共属性键，未修改或关闭扫描规则 | `build/cloud-console-navigation/secrets.log` |
| 浏览器运行日志 | 验收期间未发现error/warn | CUA本地浏览器只读检查 |

先前的单项回归曾发现抽屉退场内容未销毁影响连续打开，修复为destroyOnHidden；最终默认全集包含该回归。
提交前扫描曾把Ant主题字段误判为通用凭据赋值；改为带引号的公共属性键并保留用途注释后扫描通过，最终文件重新执行完整门禁。没有安装新依赖，也没有保存阿里云账号或资源截图。

## 保留的未核验项

默认脚本退出0不代表所有独立裁判项目全绿。现有tshark对照仍跳过：
DPI 14项、TCP重组2项、FlowRecord 8项。它们继续作为未核验记录，未改成通过。
本轮不以退出0覆盖这些状态，不合入主分支，不推送远端；保留可审查的本地分支提交。
