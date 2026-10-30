# Ant Design Pro 依赖审计记录（2026-10-26）

状态：**阻断合入 / 发布**。本轮引入官方 Pro / Umi Max 工程后，完整锁文件审计仍有告警。
前端可本地运行、构建和测试通过，不能据此宣称依赖安全门禁通过。

## 审计口径

```bash
npm --prefix web/console audit --package-lock-only --audit-level=low --json
npm --prefix web/console ls --all --json
```

完整依赖审计包含开发依赖，不使用 `--omit=dev`、忽略清单或提高阈值来隐藏结果。
部分构建依赖会进入浏览器产物，不能笼统地把开发依赖告警全部判为无影响。
本地原始证据：`build/ant-design-console/validation/npm-audit.json`。

当前审计报告为 **21 个受影响依赖项：11 low、10 moderate、0 high、0 critical**。
这个数量包含沿依赖链传播的受影响包，不代表 21 个独立安全通告。
根因集中在以下三个包，涉及四个通告：

| 包 / 来源 | 当前约束与待处理问题 |
| --- | --- |
| `decode-uri-component` / `@umijs/history → query-string` | 锁定在旧解码器分支；新解码器与历史 CJS 调用方式需要兼容验证，未强换 API |
| `elliptic` / Umi 的浏览器加密依赖链 | 官方当前没有修复版本，需要上游替换或经过验证的补丁 |
| `react-router` / Umi renderer、preset、server | 兼容升级至 6.30.6 后仍在通告范围；7.18.0 修复导航问题，但 Umi 当前固定在 6 系 API，未强行跨主版本替换 |

对应原始通告：

- [decode-uri-component 解码拒绝服务](https://github.com/advisories/GHSA-vcc3-ghjq-m6fr)
- [elliptic ECDSA 实现问题](https://github.com/advisories/GHSA-848j-6mx2-7j84)
- [React Router 导航重定向](https://github.com/advisories/GHSA-wrjc-x8rr-h8h6)
- [React Router SSR hydration 构造器注入](https://github.com/advisories/GHSA-337j-9hxr-rhxg)

本轮没有完成全部通告的可达性证明，也没有将未启用的能力作为自动豁免理由。
这些项目保留为真实失败，现有 GitHub 完整依赖扫描继续阻断。

## 已执行的兼容修复

`package.json` 的覆盖规则与锁文件一同提交，修复低版本 Babel core/runtime、esbuild、
node-fetch、path-to-regexp、PostCSS selector parser 和 Vite 的有补丁依赖。
Vite 7.3.7 仅作为 Vitest / Umi 工具链依赖，生产入口仍由 Umi Max 构建。
React 固定为满足 ProComponents peer 要求的 18.3.1，类型包分别为 18.3.31 / 18.3.7；
不跨主版本改写未启用的 Umi Dva / Redux 依赖链。ProComponents 3 当前密度图标存在 React 18
ref 兼容警告，暂关闭表格密度切换入口，保留列设置、排序、分页与刷新。
没有使用 `--force` / `--legacy-peer-deps`。

退出条件：通过可复现的上游升级或补丁消除剩余告警，重新核验依赖树、完整审计、页面交互、
生产构建和仓库门禁；在此之前保持本地功能分支，不合入主分支，不进行生产部署。
