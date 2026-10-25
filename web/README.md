# web/ — Web 控制面

> `console/`：React + TypeScript + Vite 可视化控制台，消费 routerd 的 `/api/v1`。

**状态**：✅ 核心已实现（5 页面 + API 客户端 + 组件 + 测试），共约 526 行业务代码。

## 技术栈（刻意极简）

- React ^18.3.1 + react-router-dom ^7.18.4 —— **runtime 依赖仅 3 个**
- TypeScript ^5.5 / Vite ^6.4.5 / Vitest ^4.1.12 / ESLint ^8.57
- **无状态管理库**：`src/stores/` 目前是占位，实际状态就是 React `useState` + 自研 `useApi` hook

Node 版本使用根 `.node-version`（24.15.0）；package.json engines 为兼容边界。

## 命令

```bash
cd console
npm ci
npm run dev          # 开发（/api 代理到 http://localhost:8080，可用 VITE_ROUTERD_TARGET 覆盖，见 .env.example）
npm run build        # tsc && vite build
npm run typecheck    # tsc --noEmit
npm run test         # vitest（jsdom；coverage 需额外安装同版本 provider）
npm run lint
npm audit --package-lock-only --audit-level=low # 包含开发依赖的安全门禁
```

## 结构

```
src/main.tsx                 # 入口 → BrowserRouter
src/App.tsx                  # 5 个页面路由：/ /interfaces /routes /traffic /system
src/api/client.ts            # fetch 客户端：envelope 解包 + ApiError
src/hooks/useApi.ts          # loading/error/data + 可选轮询
src/pages/                   # Dashboard / Interfaces / Routes / Traffic / System 共 5 页
src/components/              # Layout、Card、StatusBadge（含测试）
src/constants/attributes.gen.ts   # 属性字典 TS 绑定（codegen 生成，勿手改）
version-source.ts            # 版本注入链：根 VERSION → __APP_VERSION__
tests/                       # api-client 等测试 + vitest setup
```

## 与其他模块的关系

- **routerd**：页面数据全部来自 `http://localhost:8080/api/v1/*`（dev proxy 已配）
- **configs/registry/attributes.json**：经 `tools/codegen/gen-attributes.py` 生成 `src/constants/attributes.gen.ts`
- **根 VERSION**：经 `version-source.ts` 注入前端版本号，与 Go/Rust/C++ 同源

## 相关

- 部署侧尚无产物配置，见 `deploy/README.md`
- 控制面服务：`services/README.md`
