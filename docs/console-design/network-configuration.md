# 网络配置中心与跨系统适配

日期：2026-10-27；页面P53：`/network/configuration`，归属“网络管理→网络配置”。
本轮实现阶段NC-01：统一配置、模型校验、原生预览、管理员草稿持久化。
真实系统应用、管理连接确认、断线回滚仍属NC-02—NC-05，未发布为可执行按钮。

## 1. 网络管理选型

| 目标系统 | 使用方式 | 持久化与控制接口 | 取舍与事实来源 |
| --- | --- | --- | --- |
| Ubuntu Server | 保留Netplan，服务器基线renderer为networkd | Netplan配置/API；后续Try→Accept/Cancel | Ubuntu官方采用Netplan抽象网络配置；若实际renderer为NetworkManager，必须识别后走对应整合路径，不能同时改两套配置。[官方说明](https://ubuntu.com/server/docs/explanation/networking/configuring-networks/) |
| Rocky Linux | NetworkManager | 连接profile、D-Bus；nmcli作诊断与受控适配入口 | 保留系统网络服务，不直接用临时ip命令代替持久配置。[Rocky文档](https://docs.rockylinux.org/9/guides/network/basic_network_configuration/) |
| 银河麒麟V11 Server | NetworkManager | 连接profile、D-Bus；能力和版本以目标机为准 | 已核对厂商V11白皮书将NetworkManager列为网络管理工具；不据此声称所有硬件和镜像均完成兼容。[厂商V11白皮书V1.2](https://www.kylinos.cn/upload/1/kycms/20261022/2113191548762034176.pdf) |
| OpenWrt | 保留UCI / netifd / ubus / rpcd | UCI network配置、ubus运行状态、rpcd受控事务 | 不安装systemd或NetworkManager替换原生管理；逻辑接口名与Linux设备名分别建模。[UCI](https://openwrt.org/docs/techref/uci)、[netifd/ubus](https://openwrt.org/docs/guide-developer/ubus/network) |

决策：上层统一模型，下层三个原生适配器。新建专用服务器镜像时可固定管理栈；既有部署按实际运行管理器及接口所有权接管，不按发行版名字强行替换。

## 2. 功能与页面布局

| 区域 | 显示内容 | 控件与交互 | 当前状态 |
| --- | --- | --- | --- |
| 页头 | 网络配置、重新读取 | PageContainer；重新读取须确认替换未保存编辑 | 已实现 |
| 状态摘要 | 草稿版本、系统应用状态、保存权限 | ProDescriptions；实际能力返回，草稿不叫已生效 | 已实现 |
| 目标管理器 | Netplan/networkd、NetworkManager、OpenWrt | Select；表示编译目标，不能当作已探测到正在运行的管理器 | 已实现 |
| 接口配置卡 | 配置标识、设备名、MTU | Form.List、AutoComplete、InputNumber；增加/删除配置项 | 已实现 |
| 静态IP Tab | 多个IPv4/IPv6主机CIDR | Tags输入；服务端校验地址族、网络/广播地址、IPv6 MTU | 已实现 |
| DNS Tab | 服务器IP、搜索域 | 每接口上游DNS与搜索域；不代表DNS监听服务或DHCP租约分发 | 已实现 |
| 静态路由 Tab | 目标CIDR、下一跳、Metric | 动态路由条目；默认路由用0.0.0.0/0或::/0 | 已实现 |
| 操作条 | 添加接口、校验预览、保存草稿 | 校验非执行；保存需管理员及存储启用；版本冲突保留编辑 | 已实现 |
| 原生预览抽屉 | 摘要hash、文件名、原生内容 | Tabs与只读TextArea；编辑改变后旧预览失效 | 已实现 |
| 应用与确认 | 变更差异、管理链路影响、确认期限、实际核对 | 未来发布事务任务；未接线前不提供假应用按钮 | NC-02—NC-05 |

## 3. 当前统一字段约束

| 对象/字段 | 类型与约束 | 语义 |
| --- | --- | --- |
| backend | netplan / networkmanager / openwrt | 目标编译器，不是自动平台识别结论 |
| interfaces | 1—32个 | 每个物理以太网设备仅一个本配置profile；桥/VLAN/Bond另做明确模型 |
| id | 字母开头，字母/数字/下划线，1—32字符，唯一 | CythSec配置标识；OpenWrt生成cythsec_前缀逻辑接口 |
| device | 1—15位字母/数字/点/短横/下划线，不允许lo，唯一 | Linux设备名；当前名称候选从真实接口API读取，未由预览执行设备接管 |
| mtu | 整数576—9216；含IPv6时至少1280 | 初始允许范围；实际硬件上限由后续应用前检查进一步约束 |
| addresses | 1—8个单播主机IP/CIDR，不重复 | 保留主机位；IPv4网络/广播地址在/31、/32之外拒绝 |
| dns | 最多6个单播IP，不重复 | 当前静态模式要求有同族接口地址；不会将IP当URL探测 |
| search | 最多6个ASCII域名，每个≤253字符 | 标签1—63字符；不接受命令、路径或表达式 |
| routes | 每接口最多128条 | 当前仅显式单播静态路由，不提供ECMP、策略路由或动态协议 |
| destination | 规范网络CIDR | 必须无主机位，与下一跳/接口地址族一致 |
| gateway | 单播IP，直连子网内或有效链路本地地址 | 不自动加onlink绕过可达性约束 |
| metric | uint32整数 | 相同接口、目标和Metric不重复；不将同分路由默认为ECMP设计 |
| revision | 服务端版本号 | If-Match精确前置条件，过期返回412 |
| stage | unconfigured / draft_saved | 当前持久化阶段；不表示系统已应用 |

静态模型不会自动继承DHCP/RA参数。当前原生预览明确关闭动态地址获取；真实应用前必须读取已有profile，展示静态接管差异并确认管理通路。DHCP客户端、PPPoE、DHCP服务、VLAN/Bridge/Bond后续单独建模，不把它们藏进任意脚本字段。

## 4. 原生配置映射

| 适配器 | 预览产物 | 当前实现 | 后续原生检查与应用 |
| --- | --- | --- | --- |
| netplan | 90-cythsec.yaml，JSON语法的YAML配置 | network.version=2，renderer=networkd；地址、nameservers、MTU、routes | 在隔离根目录执行generate验证；配置合并/所有权检查；Try、确认/拒绝和持久/运行态核对 |
| networkmanager | 每profile一个cythsec-ID.nmconnection | keyfile；IPv4/IPv6 manual或disabled、地址、DNS、routeN；UUID由NM按文件名生成 | 优先D-Bus加载与读取profile；checkpoint→修改/激活→核对→确认/回滚 |
| openwrt | network.cythsec.uci片段 | 独立cythsec_逻辑接口；设备、ipaddr/ip6addr、DNS、route/route6 | 不覆盖整个network文件；UCI增量事务、现有逻辑接口与firewall zone归属校验、rpcd应用与确认 |

当前“校验”只指统一模型校验与受控配置生成。原生解析器、目标机权限、版本兼容、实际网络状态尚未因此得到验证。
Keyfile格式依据[NetworkManager官方参考](https://networkmanager.dev/docs/api/latest/nm-settings-keyfile.html)。

## 5. API、身份与存储

| 方法/路径（routerd） | 权限 | 响应/状态 | 副作用 |
| --- | --- | --- | --- |
| GET /api/v1/network/configuration | 既有读取权限；无鉴权仅本机回环开发 | snapshot、capabilities、ETag | 读取CythSec期望配置，不冒充运行态 |
| POST /api/v1/network/configuration/preview | 已认证读取角色，或无鉴权本机开发 | validated_preview、digest、artifacts | 纯校验与生成；不执行命令、不写系统文件 |
| PUT /api/v1/network/configuration | routerd已认证admin + 存储启用 + If-Match | draft_saved与新版本；428缺版本、412冲突、403无权 | 写私有草稿文件；不应用OS网络 |
| 系统应用/确认/回滚API | 尚未发布 | capabilities.can_apply=false | 无可执行路径；不能被admin身份隐式绕过 |

请求只接受JSON及已知字段，最多128KiB；模型规范序列化最多120KiB。前端请求10秒超时；错误不显示保存成功，写结果未知时先重新读取版本核对。

`-network-config-dir` / `ROUTERD_NETWORK_CONFIG_DIR` / YAML `network_config_dir`启用私有存储；默认未启用。
目录0700，文件0600，单进程文件锁+请求内互斥；临时写入、文件fsync、原子rename、目录fsync。
重启加载校验失败不回落为空配置。落盘异常可能是结果未知，不自动重试覆盖。当前仅最新草稿，不是完整历史审计；N13审计和变更任务在后续阶段补齐。

## 6. 系统应用与断线回滚的开发顺序

```mermaid
flowchart LR
 A[控制台编辑] --> B[模型校验与差异]
 B --> C[版本化草稿]
 C --> D[实际管理器/接口所有权探测]
 D --> E[创建原生checkpoint/事务]
 E --> F[受控应用]
 F --> G[读取实际地址/DNS/路由与管理连接]
 G --> H{期限内确认}
 H -->|是| I[原生确认与持久化核对]
 H -->|否或失联| J[原生回滚与独立核对]
 I --> K[任务/版本/操作者审计]
 J --> K
```

| 任务 | 内容 | 状态 |
| --- | --- | --- |
| NC-01 | P53统一模型、静态IP/DNS/路由、预览、admin草稿保存、版本冲突与重启恢复 | 本轮实现，验证见记录 |
| NC-02 | 各发行版实际管理器/版本探测、接口profile接管、现有配置读取与差异、原生校验 | 待开发和目标系统验收 |
| NC-03 | 三管理器事务应用、独立回滚期限、管理连接确认、进程崩溃/重启恢复 | 待开发 |
| NC-04 | 已应用状态核对、回滚失败/部分/未知结果、持久化及操作者审计 | 待开发 |
| NC-05 | Ubuntu/Rocky/Kylin V11/OpenWrt版本×CPU×接口类型的虚拟机/实机门禁 | 待验收环境，不因交叉编译通过而标兼容 |

NetworkManager提供[CheckpointCreate/Destroy/Rollback](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html)。
Netplan提供[try及确认/拒绝](https://netplan.readthedocs.io/en/1.1.2/netplan-try/)，官方也提示回滚后仍须检查真实状态。
OpenWrt的[UCI/rpcd应用流程](https://openwrt.org/docs/techref/uci)包含确认与回滚语义；不能用直接重启network替代完整受控事务。

## 7. 验收边界

必须覆盖CIDR/地址族/直连网关、DNS/域名/命令注入、重复接口/路由、大小限制、无管理员、匿名写入、过期版本、两个写入进程、存储损坏、重启恢复。
NC-02以后的必须另验管理端口断线、失去确认、回滚失败、daemon崩溃、系统重启、已有DHCP/RA/桥接与其他网络管理器冲突。
本轮不改开发电脑IP、DNS、路由或系统网络文件；没有以这轮验证替代真实目标机网络应用验收。

## 8. 控制面与数据面的作用范围

| 层 | 本配置的关系 | 验收要求 |
| --- | --- | --- |
| Linux系统网络 | IP、DNS与静态路由的最终作用对象 | 原生管理器事务与实际内核状态一致 |
| 管理连接 | 可能被改地址/路由中断的控制台链路 | 应用前识别管理口；期限内确认，否则独立回滚 |
| 透明/镜像采集口 | 不能仅因出现在接口列表就视为普通三层网口 | 接管前核对接口角色、bridge成员、镜像声明与所有权 |
| CythSec包处理/高性能转发 | Netplan或NM配置不等于AF_PACKET/BPF发送、透明转发或DPI策略生效 | 原有核心转发门禁独立保留，不能由网口配置成功替代 |

当前P53没有激活上述系统应用链路。阶段与实际证据见[本轮验收记录](network-configuration-verification.md)。
