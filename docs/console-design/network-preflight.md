# NC-02运行态观测与应用前检查

本轮范围为NC-02的运行态部分：实际管理器响应、接口归属、内核IP/MTU与链路DNS/搜索域、主路由表及草稿差异。
持久配置读取、配置来源接管、原生配置校验、系统应用与回滚仍未完成，不以本报告授予应用权限。

## 1. 页面交付

| 区域 | 功能 | 显示与状态规则 |
| --- | --- | --- |
| 网络环境与接口归属 | 手动读取本机快照；不自动轮询 | 平台、时间、部分/已取得、管理器工具版本、读取状态与诊断 |
| 管理器表 | NetworkManager、systemd-networkd、OpenWrt/netifd | 可读取/未运行/不适用/不可读取/格式未兼容分开；工具版本不是运行daemon版本 |
| 接口表 | 接口、类型、归属声明、MTU、运行IP、DNS | 接口枚举失败不称“0接口”；缺DNS或归属不称空列表或未托管 |
| 应用前检查 | 校验当前表单，再读取新的运行态并比较 | 报告绑定草稿digest与快照ID；编辑后报告失效；不使用早先的环境快照冒充最新检查 |
| 检查项 | 阻断与待核对项 | 接口不存在、归属未知/多个归属、管理器不匹配、复杂接口；持久配置、管理连接、原生验证待核对 |
| 运行态差异 | MTU、地址、链路DNS、搜索域、主路由表 | 相同/不同/未知；未知Current为null，不转成0或空集合；路由不是执行删除计划 |

## 2. 只读数据源

| 数据源 | 固定查询 | 证据与限制 |
| --- | --- | --- |
| 内核接口 | Go net.Interfaces及每接口Addrs；Linux sysfs类型证据 | MTU与地址分别标记known；识别回环、桥、Bond、VLAN、组合成员、无线与未知类型 |
| NetworkManager | 先systemctl is-active，再nmcli只读白名单字段；不读取profile秘密或使用--show-secrets | 管理状态与ActiveConnection引用；DNS/搜索域缺字段时保持未知；命令失败不推断服务离线 |
| systemd-networkd | 先is-active；busctl调用Manager.Describe，显式禁止自动启动与交互授权 | 指定JSON投影；读取NetworkFile与AdministrativeState。文件名含netplan不证明由Netplan生成 |
| OpenWrt/netifd | ubus call network.interface dump | 白名单投影逻辑接口/L3设备/DNS；丢弃data等其他字段，不返回原始输出 |
| 主路由表 | ip -j -4/-6 route show table main | 两族查询成功才作为完整合并字段；ECMP、封装、特殊路由或格式不兼容保持未知；不混入其他路由表 |

规范核对：[NetworkManager CLI](https://networkmanager.dev/docs/api/latest/nmcli.html)、
[systemd network1](https://www.freedesktop.org/software/systemd/man/255/org.freedesktop.network1.html)、
[busctl安全开关](https://www.freedesktop.org/software/systemd/man/255/busctl.html)、
[systemd v255 JSON实现](https://github.com/systemd/systemd/blob/v255/src/network/networkd-json.c)、
[OpenWrt运行态样例](https://lxr.openwrt.org/source/firewall4/tests/mocks/ubus/network.interface~dump.json)、
[ip JSON](https://www.man7.org/linux/man-pages/man8/ip.8.html)、[主路由表范围](https://www.man7.org/linux/man-pages/man8/ip-route.8.html)。

## 3. 边界、归属与差异语义

| 项目 | 当前处理 |
| --- | --- |
| 发行版名称 | 不用于确认管理器正在运行 |
| Netplan与networkd | Netplan是配置抽象，实际运行归属记录networkd；Netplan草稿与networkd可匹配renderer，但合并配置来源和接管仍须核对 |
| 同设备多个归属 | 不选择其中一个作为真值；DNS/搜索域撤销为未知，并生成阻断项。OpenWrt同设备多个逻辑接口同样须专门模型 |
| 物理网口与组合成员 | 组合/虚拟/无线/未知类型不按普通物理以太网静态模型接管 |
| 地址集合 | 运行值可能包含DHCP、RA或自动地址；差异不等于将删除这些地址的命令 |
| DNS与域名 | 规范化IP与大小写；缺字段不当成“没有DNS”；显式空数组才表示空值 |
| 路由集合 | 当前主表运行路由包含直连/动态项；仅比较目标/下一跳/Metric，不证明静态持久路由一致 |
| 快照一致性 | 非事务快照；开始/结束时间与ID可查；报告不是应用令牌，应用前仍须新鲜读取及原生事务 |
| 非Linux开发机 | 可读取真实内核接口，Linux管理器标不适用；不会尝试Linux命令，不伪装已完成发行版验收 |

## 4. API与资源边界

| API | 行为 | 权限 |
| --- | --- | --- |
| GET /api/v1/network/configuration/observation | 新运行态快照 | 既有读取身份；无认证仍只允许回环开发部署 |
| POST /api/v1/network/configuration/preflight | 严格校验草稿，读取新快照并生成差异/检查项 | 读取角色；与preview一样是只读操作；不扩大PUT保存权限 |
| 已有保存/预览 | 行为保持原NC-01契约 | 仍须admin与If-Match才能保存；can_apply=false |

每个服务实例同时最多一个观测任务，冲突返回429与Retry-After，不返回空成功。
观测总预算5秒，单进程1.5秒，每次stdout最多1MiB；stderr丢弃，不将native错误原文或秘密写入API/日志。
仅解析固定工具路径及固定参数，使用exec argv而非shell，净化环境和locale；客户端不能指定查询命令、路径或目标地址。
接口最多512个，每接口地址最多256个，主表路由最多4096条；超过限额标记不可读取，不悄悄截断为完整结果。

## 5. 阶段与后续

```mermaid
flowchart LR
 A[当前草稿] --> V[统一模型校验]
 V --> K[内核接口与类型]
 K --> M[只读管理器观测]
 M --> R[主表路由读取]
 R --> S[带时间与ID的运行态快照]
 S --> D[逐字段差异与未知值]
 D --> C[阻断/待核对报告]
 C --> P[后续：持久配置与接管确认]
 P --> N[后续：原生校验与事务应用]
```

| NC-02子项 | 状态 |
| --- | --- |
| 只读运行态、管理归属、IP/MTU/DNS/主表、差异、报告绑定 | 本轮实现，证据见验收记录 |
| 持久profile、Netplan合并配置、UCI源配置投影及导入 | 待开发；不读取或导出未知秘密字段 |
| 管理链路身份、明确接管、原生解析器校验 | 待开发 |
| 目标发行版与不同版本真实运行矩阵 | 未核验；协议格式夹具不等于系统兼容性 |
| NC-03/04实际应用、确认、回滚、崩溃恢复与审计 | 未发布，应用按钮不显示 |

实际门禁、浏览器检查和未核验项见[本轮验收](network-preflight-verification.md)。
