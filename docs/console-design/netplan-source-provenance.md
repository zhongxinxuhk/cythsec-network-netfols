# NC-02B3B4A：Netplan字段声明来源核验

日期：2026-10-29。范围为Linux网关后端；依用户要求跳过macOS兼容适配与平台界面复验。
本轮没有前端业务改动，新增来源API可选字段，不增加服务或端口。

## 流程与口径

沿用已捕获的私有源文件副本及原生 `netplan get --root-dir DIR network.ethernets` 合并视图。
在既有白名单投影完成后，用同一Python隔离执行器、固定 `--source-trace DIR` 操作构建来源索引。
stdin仅含来源ID/文件路径及已过滤的合并投影，来源内容只从私有副本读取，不使用主机路径或命令插值。

规则依据[Netplan官方多文件说明](https://netplan.readthedocs.io/en/stable/netplan-generate/#handling-multiple-files)：

| 规则 | 实现 |
| --- | --- |
| 同名文件遮蔽 | /run优先于/etc，/etc优先于/lib；被遮蔽文件不解析或参与字段归因 |
| 不同文件名顺序 | 按文件名词典序处理，不以目录优先级替代不同文件名排序 |
| 标量覆盖 | 记录最后明确声明的有效来源；保留false与数值类型 |
| 序列追加 | 记录按合并顺序出现的声明文件，保留重复及显式空声明；不去重、不猜测单个元素身份 |
| 原生结果对照 | 来源推导值必须与原生合并投影的JSON类型和值一致；否则unverified |

核验字段固定为：mtu、dhcp4、dhcp6、accept-ra、addresses、nameservers.addresses、nameservers.search、
routes、gateway4、gateway6。仅记录“投影路径的声明来源”，不是完整配置、归一化后每个地址的来源或实际运行来源。
例如公开profile.dns可能已规范化/去重，而来源索引核对的是原生投影中的nameservers.addresses序列。
match、set-name、renderer、其他设备类型、完整网络字段、设备归属与运行内容仍未归因。
复杂路由可能有可追踪的声明来源，但其语义仍可为unsupported；来源可追踪不能消除相应阻断。

## 资源与失败边界

| 约束 | 边界 |
| --- | --- |
| 来源数量/大小 | 沿用64文件、单文件1MiB、捕获总量2MiB；辅助输入和输出均受1MiB限制 |
| YAML结构 | 每个有效文件最多8192节点、深度32；拒绝重复键、锚点/别名、非字符串映射键及未支持标签 |
| 投影集合 | 每字段至多256项；来源与合并Ethernet ID集合必须对齐 |
| 时间/环境 | 沿用单命令1.5秒和来源检查6秒上下文、固定工具目录、Python -I、私有工作目录 |
| 诊断 | 固定错误代码，stdout不输出YAML诊断、字段值或秘密；失败不返回部分来源证明 |

特殊标签或别名即使被某些Netplan版本接受，本阶段仍保守报告来源索引unavailable。
索引不可读取、超时或格式错误时，保留已取得的原生合并配置；来源条件保持阻断，不回落为来源已核验。
Go再次验证文件遮蔽/顺序、来源ID分区、字段集合、标量单来源、序列来源顺序和profile对应，
全部通过才一次性发布来源结果；任何一项无效都不能写入半份field_origins。

## API扩展与权限

沿用POST `/api/v1/network/configuration/persistent-inspection` 的只读身份及backend校验。

| 字段 | 内容 |
| --- | --- |
| netplan_source_index.state | indexed/unavailable；未完成来源读取时可能不提供该扩展 |
| scope | 固定netplan_projected_field_sources |
| observed_at / diagnostic | 索引检查时间与固定状态代码 |
| active_source_ids / shadowed_source_ids | 有效文件的合并顺序、被同名文件遮蔽的来源ID |
| profiles[].field_origins | scope及fields列表，每项field/state/source_ids/reason |
| fields[].state | traced或unverified；仅对本字段投影来源成立 |

返回对象只含白名单路径和捕获时生成的来源ID，不携带源值、原始YAML、认证材料或MAC匹配数据。
源文件版本/权限/捕获一致性继续由原sources字段提供。没有改写原profile.SourceIDs，也不将origin_verified设为true。
来源索引缺失或未对齐有明确阻断；所有字段均traced时，整体归因、明确接管、管理链路和独立回滚仍待核验。
can_adopt=false、can_apply=false，未发布执行入口。

```mermaid
flowchart LR
 A[已捕获的私有源副本] --> B[同名遮蔽与文件名排序]
 B --> C[有界YAML读取与白名单字段声明]
 A --> D[原生Netplan合并与投影]
 C --> E[标量覆盖 / 序列追加]
 D --> F[类型和值逐项核对]
 E --> F
 F --> G[字段来源元数据]
 G --> H[Go独立检查ID / 顺序 / 字段 / 原子发布]
 H --> I[接管条件保持受限]
```

测试说明及实际证据见[验收记录](netplan-source-provenance-verification.md)。
