# routerd网络配置草稿API

日期：2026-10-27。平台选型、字段、阶段与界面见[网络配置专项](../console-design/network-configuration.md)。
当前只实现草稿及预览，不调用netplan、NetworkManager、ubus或ip命令，不写系统网络文件。

| 入口 | 成功数据 | HTTP失败与语义 |
| --- | --- | --- |
| GET /api/v1/network/configuration | snapshot：revision/updated_at/stage/config；capabilities：platform/can_preview/can_save/can_apply/store_enabled/preview_backends；ETag | 存储启动加载失败时服务拒绝启动，不回落空成功 |
| POST /api/v1/network/configuration/preview | digest（规范JSON SHA-256）、stage=validated_preview、artifacts(name/content) | 400模型/未知字段/大小/多对象；415媒体类型；开启访问策略时需要读取身份 |
| PUT /api/v1/network/configuration | revision+1、stage=draft_saved、updated_at、config；新ETag | 403无管理员或未启用；428缺If-Match；412版本过期；500写入结果待核实 |

所有请求同源通过控制台/api代理，认证沿用routerd自己的内存Bearer连接；不新增通用Shell、文件读写或任意目标URL。
只读身份可校验原生预览，但不能保存；未启用访问认证时也不能保存。PUT权限只放行routerd这个精确路径，不扩大到DELETE、系统应用或其他服务。

## 启用与持久化

配置优先级沿用flag > ROUTERD_*环境变量 > YAML > 默认：

| 配置方式 | 参数 |
| --- | --- |
| flag | -network-config-dir /var/lib/cythsec/network-drafts |
| 环境 | ROUTERD_NETWORK_CONFIG_DIR |
| YAML | network_config_dir |
| 默认 | 空，存储未启用，预览可用 |

目录须为当前服务账号控制的私有本地目录（0700），文件0600，单写入进程锁。
服务启动时只读取与校验desired.json，不读取它去改变系统网络。
当前保存最新草稿而非完整历史，audit/回滚/任务能力需后续契约，不能从一个desired.json推断具备生产变更闭环。

例：先GET取得revision=3，保存时请求头If-Match为带双引号的3，正文为同一配置对象。并发保存会使旧版本返回412，客户端保留编辑、重新读取后比较，不提供绕过版本的强制覆盖。

无条件PUT、未知backend、任意命令字段、额外JSON对象、超大JSON都拒绝。
网络输入中的shell引号、换行与路径不作为操作系统语法使用；合法网络值由netip解析，标识和域名使用受限语法。

## 验证边界

Go测试覆盖三个原生预览、模型注入/边界、私有目录、写入进程锁、版本冲突、重启恢复、损坏拒绝、匿名/只读写入拒绝、CORS版本头与共享权限边界。
前端测试覆盖只读预览、管理员草稿确认、412保留编辑、同源路径和If-Match。
原生解析器验证、目标机接管、真实应用、断线回滚和CPU/发行版兼容性仍独立未核验。
