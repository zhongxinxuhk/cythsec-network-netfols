# web/ — Web 控制面

> `console/`：Ant Design Pro + Umi Max + React + TypeScript 可视化控制台，消费 routerd 和 telemetryd 的 API。

**状态**：部分实现，现有 6 个页面、API 客户端与组件测试；聚合历史已接真实本机持久化 API，生产鉴权与其他业务闭环仍未完成。

## 技术栈

- Ant Design Pro 官方体系：Umi Max 4.7.27、ProComponents 3.1.14-2、Ant Design 6.6.8。
- React 18.3.1 + TypeScript；Vitest + Testing Library 验证真实组件交互。
- ProLayout 管理外壳，PageContainer 页面，ProTable / ProDescriptions / ProCard 承载业务。

Node 版本使用根 `.node-version`（24.15.0）；package.json engines 为兼容边界。

## 命令

```bash
cd console
npm ci
npm run dev          # 开发（/api 代理到 http://localhost:8080，可用 VITE_ROUTERD_TARGET 覆盖，见 .env.example）
npm run build        # Umi Max setup + 类型检查 + 生产构建
npm run typecheck    # tsc --noEmit
npm run test         # vitest（jsdom；coverage 需额外安装同版本 provider）
npm run lint
npm audit --package-lock-only --audit-level=low # 包含开发依赖的安全门禁
```

## 结构

```
config/config.ts             # Umi Max、Ant Design 与 ProLayout 配置
config/routes.ts             # 六个页面与404，菜单、路由、面包屑同源
src/app.tsx                  # Pro 运行时布局与真实服务状态
src/api/client.ts            # fetch 客户端：envelope 解包 + ApiError
src/hooks/useApi.ts          # loading/error/data + 轮询与旧请求隔离
src/pages/                   # 六个 PageContainer 页面
src/components/              # ProCard、Ant Badge、服务状态与队列状态
src/constants/attributes.gen.ts   # 属性字典 TS 绑定（codegen 生成，勿手改）
version-source.ts            # 版本注入链：根 VERSION → __APP_VERSION__
tests/                       # api-client 等测试 + vitest setup
```

## 与其他模块的关系

- **routerd**：五个原有页面数据来自 `http://localhost:8080/api/v1/*`（dev proxy 已配）
- **configs/registry/attributes.json**：经 `tools/codegen/gen-attributes.py` 生成 `src/constants/attributes.gen.ts`
- **根 VERSION**：经 `version-source.ts` 注入前端版本号，与 Go/Rust/C++ 同源

## 相关

- 部署侧尚无产物配置，见 `deploy/README.md`
- 控制面服务：`services/README.md`

## 聚合历史分析增量

控制台现有第六页 `/analytics`：导入经过校验的聚合 JSONL，查询持久化批次、时间范围、TCP/UDP 计数、TLS/QUIC 头候选与采集状态。开发代理 `/telemetry` 指向 telemetryd（默认 `127.0.0.1:8083`，`VITE_TELEMETRYD_TARGET` 可覆盖）；既有 `/api` 仍指向 routerd。先启动启用 `-aggregate-dir` 的本机 telemetryd，页面数据才来自真实存储；未启用显示错误，不回退假数据。完整命令见 [聚合持久化](../docs/observability/persistence.md)。

聚合分析页新增持续写入队列面板：积压、失败原因、退避和进程计数每三秒刷新。队列启用时上传只先确认入队；状态不可用则暂停上传，仍可查历史。见 [队列契约](../docs/observability/ingest-worker.md)。

前端开发标准与代理配置见 [前端工程说明](../docs/development/frontend-standard.md)。
