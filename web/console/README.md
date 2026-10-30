# CythSec Console · Ant Design Pro

控制台采用 Umi Max + Ant Design + ProComponents。项目规范、启动方式、代理配置、
页面能力与数据语义见 [前端工程说明](../../docs/development/frontend-standard.md)，
强制规则以 [AGENTS.md](../../AGENTS.md) 为准。

`npm ci` → `npm run dev` 启动；`npm run typecheck:all`、`npm run lint`、`npm test`、
`npm run build` 分别检查类型、规范、交互和生产产物。生成的 `.umi*` 不入库。

管理服务的静态 Bearer 访问认证、凭据配置和当前限制见 [管理服务访问认证](../../docs/development/control-access.md)。
开发代理仅监听回环地址，认证凭据只保留在页面内存。
