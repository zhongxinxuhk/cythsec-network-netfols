# 控制台依赖安全修复（2026-10-27）

本轮处理 npm audit 的 21 项受影响依赖报告。它们来自三个根依赖及父包传播，不能解释为
21 个独立漏洞，也不能通过关闭 audit、仅审计生产依赖或改写上游版本号来消除。

## 修复路径

| 根依赖 | 本轮处理 | 上游依据 |
| --- | --- | --- |
| decode-uri-component <=0.4.2 | 使用真实上游 0.5.1，并以薄 CJS 入口适配 query-string 6；不重写解码算法 | [GHSA-vcc3-ghjq-m6fr](https://github.com/advisories/GHSA-vcc3-ghjq-m6fr) 的修复版本为 0.5.0 起 |
| react-router 6.x / 7.17及以下 | 路由核心和实际 DOM 实现使用 7.18.4；保留 Umi 调用的旧 server 子路径；Dva 独立4.x依赖保持原API | [导航 URL 规范化](https://github.com/advisories/GHSA-wrjc-x8rr-h8h6)、[SSR 错误反序列化](https://github.com/advisories/GHSA-337j-9hxr-rhxg) 的修复版本为 7.18.0 起 |
| elliptic | 不声称存在上游修复；从控制台浏览器 Node 垫片中移除 crypto-browserify 及其签名/ECDH依赖链，Node crypto 显式报错 | [GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84) 尚无修复版 |

Umi Max 仍为 4.7.27，Ant Design Pro / React / Ant Design 版本与现有工程一致。
核对了 Umi 4.7.28，其相关依赖仍锁定旧路由和浏览器加密垫片，单独升级该补丁版不能完成本次修复。

兼容包位于 [web/console/compat](../../web/console/compat/README.md)。仅保留模块入口转换与
浏览器 builtin 策略；不复制路由/解码实现，不加入自制加密算法。Node 环境、Go 服务端加密及
浏览器原生 TLS / Web Crypto 不受影响。控制台不再提供 Node 风格加密 API；未来依赖需要此
能力时必须重新设计与验收，不能用返回空对象的假垫片悄悄降级。

## 可重复安装与回归

`package.json` 与锁文件同时更新。所有本地包必须入库，普通 `npm ci` 应能重新创建依赖树。
采用根 file 依赖与 `$name` 引用，避免 npm 将 file 覆盖解析到第三方包目录而产生缺失链接。

生产构建移除 Umi 对 react-router 的宽泛目录别名，允许 v7 的 root / dom 子路径正常遵循
package exports，避免仅通过单元测试、却在真实 webpack 构建中解析失败或出现双份上下文。

安全回归包括：

- Umi preset、renderer、server 实际解析的路由入口和 server 子路径存在，Dva旧API不被跨主版本覆盖。
- 同源反斜线链接在 SPA 导航前按上游修复语义规范化；正常查询参数不丢失。显式外部链接不是
  通用重定向白名单，业务若未来接收用户提供的跳转目标仍须自行限制。
- query-string 处理空格、中文、重复参数；含10000段畸形百分号输入的独立进程在超时内完成。
- 锁文件中不存在 elliptic、crypto-browserify、browserify-sign、create-ecdh；两个浏览器 builtin
  入口都明确拒绝 Node crypto，保留其他已用映射。

验证范围是当前 webpack SPA。其他构建器、完整 SSR / 水合和未启用插件的业务行为不因此宣称通过。
该范围不改变两条仓库级门禁的要求；既有 tshark 未核验项仍须保留。

## 实际验证结果

本机证据位于 `build/dependency-remediation/`，本轮未执行 sudo。

| 检查 | 实际结果 | 证据 |
| --- | --- | --- |
| 普通 npm ci，含 Umi prepare | 退出 0；实际安装后的审计0项 | `install.log` / `.exit` |
| npm audit --package-lock-only --audit-level=low --json | 退出 0；info/low/moderate/high/critical 均为0 | `audit.json` / `.exit` |
| npm ls 指定路由/解码依赖 | 退出 0；Umi用7.18.4，Dva独立4.3.1 | `tree.log` / `.exit` |
| 四栈 build-all | 退出 0 | `build-all-launch.log` / `.exit` |
| lint-all | 退出 0 | `lint-all-launch.log` / `.exit` |
| test-all | 退出 0；前端16文件、56项通过 | `test-all-launch.log` / `.exit` |
| 真实 BPF | 16项断言、6832帧；沿用普通用户现有权限 | `test-all-launch.log`、`build/e2e-live/` |
| 生产产物检查 | 未包含主动拒绝Node crypto的模块，当前应用没有误依赖它 | 本机逐块文本检查 |

浏览器实测运行概览、接口、路由、流量、聚合和系统页，菜单SPA切换、前进后退、404与中文查询
深链接；开发服务器由现有CLion Run Console配置启动，实际监听 `127.0.0.1:15174`。
截图及浏览器日志位于同一证据目录。完整SSR部署和其他构建器仍未验证。

DPI14、TCP重组2、FlowRecord8项第三方裁判跳过/未核验仍保留，不能因npm审计清零而写成全部核验。
本轮不推送、不合入main。

## 2026-11-02 第二轮：构建链审计清零

GitHub Actions 的 `npm audit --package-lock-only --audit-level=low` 报告 41 项
（2 low / 39 moderate）。报告不是 41 个独立漏洞：`@hono/node-server` 通过
`@utoo/pack` 传播，`deepmerge` 通过 `@svgr/plugin-svgo` 与
`fork-ts-checker-webpack-plugin` 传播，`glob` / `minimatch` 通过旧版
`rimraf`、`test-exclude` 和 ESLint 8 依赖链传播。所有受影响包都位于
`devDependencies` 的构建/测试链，生产 `dependencies` 未变化。

本轮没有关闭 audit、没有改成只审计生产依赖，也没有用 `--force` /
`--legacy-peer-deps` 绕过约束。处理如下：

| 根依赖 | 本轮处理 | 上游依据 |
| --- | --- | --- |
| `@hono/node-server` 1.19.17 | 根 override 固定到 2.1.5；仅被 `@utoo/pack` / `@hono/node-ws` 的开发服务器使用 | [GHSA-rmxm-3fg6-px4f](https://github.com/advisories/GHSA-rmxm-3fg6-px4f) 的修复版本从 2.1.3 起 |
| `deepmerge` 4.3.1 | `compat/deepmerge-safe` 保留 4.3.1 合并算法，拒绝 `__proto__` / `constructor` / `prototype` 键；上游无修复版 | [GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4) |
| `glob` 7.2.3 / 10.5.0 | 升级 `rimraf` 到 6.1.3、`test-exclude` 到 8.0.0，并 override `glob` 到 14.0.3 | [GHSA-3g3m-2fjr-6pw4](https://github.com/advisories/GHSA-3g3m-2fjr-6pw4) 的修复版本从 14.0.2 起 |
| `minimatch` 3.1.5 / 10.2.6 | `compat/minimatch-safe` 包装真实 11.0.3：保留旧 ESLint 插件需要的可调用 CommonJS 导出，同时提供 glob 14 使用的 v11 命名导出 | [GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249) 的修复版本从 11.0.1 起 |

`@hono/node-ws` 的 peer 范围仍写着 `^1.19.11`，这是上游尚未跟进 2.x 的声明；
根 override 只用于开发服务器依赖，webpack 生产构建、现有测试和类型检查均通过。
如果后续启用 Utoo 开发服务器或升级 Umi 构建器，必须重新验证该组合。

### 可重复安装与回归

`package.json` 的 file 依赖和 `$name` override 与 `package-lock.json` 同批提交。
普通 `npm ci` 会安装 `deepmerge-safe`、`minimatch-safe` 及固定的构建链版本；
不依赖安装后手工改文件。新增回归在 `tests/dependency-security.test.tsx`：
锁文件版本断言、`deepmerge` 原型键拒绝、`minimatch` 可调用与 v11 命名 API 双兼容。

### 实际验证结果

| 检查 | 实际结果 |
| --- | --- |
| `npm ci` | 退出 0；1483 packages；安装后审计 0 项 |
| `npm audit --package-lock-only --audit-level=low` | 退出 0；0 vulnerabilities |
| `npm audit --audit-level=low` | 退出 0；0 vulnerabilities |
| `npm run lint` | 退出 0 |
| `npm test` | 退出 0；27 个测试文件、102 项通过 |
| `npm run build` | 退出 0；typecheck + webpack 生产构建通过 |
| `bash scripts/lint/lint-all.sh` | 退出 0；汇总“全部通过” |
| `bash scripts/test/test-all.sh` | 退出 0；汇总“全部通过” |

`test-all.sh` 的 tshark 交叉核验仍显式跳过 8 项 DNS 向量（脚本标注“跳过 = 未核验，
不计入通过”），本轮未把它们写成已核验。该跳过与前端依赖修复无关，保持原状。

验证范围仅限当前 webpack SPA 与上述构建链。Mako / Utoo / Vite 构建器、完整 SSR /
水合、`@hono/node-server` 2.x 的开发服务器行为和未启用插件的业务行为未因此宣称通过。
