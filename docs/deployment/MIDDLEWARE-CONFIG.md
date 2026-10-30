# 中间件连接配置与 CI 隔离

## 应用连接

连接参数按以下顺序取值：显式命令行参数 > 环境变量 > 指定 JSON 配置文件 > 内置回环默认值。
应用不自动加载工作目录中的 `.env` 或未指定的中间件 JSON 文件，避免 CI 意外连接开发/生产环境。

- JSON 模板：`configs/middleware.example.json`，版本为 1，仅当前已实现的 ClickHouse 客户端已接线。
- 环境模板：`configs/middleware.env.example`。真实覆盖文件使用 `config.local.*` 或受保护的部署路径，
  不提交到仓库；示例文件不包含真实凭据。
- 用 `--config /etc/cythsec/middleware.json` 或 `CYTHSEC_MIDDLEWARE_CONFIG` 指定配置。
  显式文件不存在、未知字段、错误类型或错误版本会拒绝启动，不静默换回默认服务器。

| 环境变量 | JSON 字段 | 含义 |
| --- | --- | --- |
| CLICKHOUSE_CLIENT | clickhouse.client | 官方 native 客户端路径 |
| CLICKHOUSE_HOST | clickhouse.host | 主机名/IP，不接受带凭据的连接 URI |
| CLICKHOUSE_PORT | clickhouse.port | native TCP 端口 |
| CLICKHOUSE_USER | clickhouse.user | 用户名 |
| CLICKHOUSE_DATABASE | clickhouse.database | 数据库 |
| CLICKHOUSE_TABLE | clickhouse.table | 表 |
| CLICKHOUSE_SECURE | clickhouse.secure | native TLS 开关 |
| CLICKHOUSE_TIMEOUT | clickhouse.timeout | 单次写入超时，如 10s |
| CLICKHOUSE_PASSWORD | 不接受明文 password 字段 | 密码，由运行环境注入 |
| CLICKHOUSE_PASSWORD_FILE | clickhouse.password_file | 私有密码文件/Secrets 挂载路径 |

环境中的 PASSWORD 和 PASSWORD_FILE 不能同时设置。环境凭据高于配置文件的 password_file；
显式设置空 PASSWORD 表示无密码覆盖。配置文件里的相对密码路径按该配置文件所在目录解析，
环境给出的文件路径按进程工作目录解析，建议使用绝对路径。
密码文件须为不超过 64KiB 的普通文件，允许 Kubernetes Secrets 的符号链接挂载，去除一个末尾换行。
加载到单个客户端实例，不修改进程全局环境；客户端子进程通过 CLICKHOUSE_PASSWORD 接收，
不进入参数、目标绑定、队列、报告或客户端 JSON。带凭据的 native 错误详情不直接回显，避免截断日志泄露密码。

例如，设置连接变量和凭据文件后，原单文件或常驻目录命令均可继续使用，不必写连接参数：

```bash
export CYTHSEC_MIDDLEWARE_CONFIG=/etc/cythsec/middleware.json
export CLICKHOUSE_PASSWORD_FILE=/run/secrets/clickhouse-password
build/bin/cythsec-ch-write --input-dir /data/incoming --spool /data/writer-state
```

连接目标仍绑定到队列状态；改主机/端口/用户/库/表/TLS 不会将旧队列静默改投。密码轮换不改变目标身份。

## GitHub Actions

普通 PR、主线 CI 与标签交付复用的 CI 均保持自包含，不依赖生产 Secrets：

1. 连接拓扑及引擎版本取自 `configs/testing/middleware.json`。
2. ClickHouse 任务在 Compose 前调用 `.github/actions/middleware-test-environment`。
3. 初始化器生成随机测试密码，先通过 Actions `add-mask` 屏蔽，再写入当前任务的 GITHUB_ENV。
   私有环境文件置于 RUNNER_TEMP、权限 0600，不上传为制品。后续任务不继承该密码。
4. Compose 服务及全部验收脚本读取同一组 CYTHSEC_TEST_CLICKHOUSE_* 变量。
   服务仅在内部测试网络运行，无宿主机端口映射；测试入口拒绝外部主机，避免混入生产目标。
5. Compose 健康检查和查询不使用 --password 参数；密码从容器运行环境读取。
6. 测试配置失败、连接失败或缺少所需环境均报错，现有失败传播与 CI required 保持不变。

本地直接运行 `python3 scripts/verify/check-clickhouse-inbox.py` 等脚本时，会自动准备
`build/middleware-test.env`（gitignored，0600），之后复用测试凭据；无需手工复制密码。
也可以先运行 `python3 scripts/ci/middleware_test_env.py`，再由自己的 dotenv 加载器加载文件启动 Compose。
不要使用 `eval` 解析环境文件，也不要将文件加入日志/制品。初始化器不读取或覆盖应用的 CLICKHOUSE_* 凭据。

CI 的引擎版本、镜像、测试用户和端口可经上述测试 JSON 或 CYTHSEC_TEST_CLICKHOUSE_* 覆盖；
镜像须为对应版本的官方镜像或固定 digest，版本检查继续强制执行，不支持 latest 漂移。
密码不需要预置为仓库 Secret，也不能把生产密码接入 PR 验收。

## 后续组件约定

PostgreSQL、Redis 的命名模板已保留在环境示例中；当前没有将这些组件虚构为已接入客户端。
新增组件时同样使用 PREFIX_HOST/PORT/USER/DATABASE、PASSWORD 或 PASSWORD_FILE、TLS/超时，
并补齐配置优先级、边界校验、私有凭据与自包含 CI 测试。生产发布如果以后需要真实连接，
非敏感参数放受控配置/Actions Variables，密码放部署环境 Secrets 或私有挂载文件；
在独立部署任务和受保护 environment 中注入，不能成为当前 PR 构建/测试的必要条件。

官方 native 客户端的密码环境变量和连接选项说明：
[ClickHouse Client](https://clickhouse.com/docs/concepts/features/interfaces/client#environment-variable-options)。
