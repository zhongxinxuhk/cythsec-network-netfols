# 网络配置中心NC-01验收记录

日期：2026-10-27；本地分支：`feat/network-configuration-console`。
状态：NC-01配置底座已实现；真实系统应用/确认/回滚尚未实现，不能称为四发行版完整兼容。

## 本轮交付

| 层 | 实现 | 明确边界 |
| --- | --- | --- |
| 选型 | Ubuntu Server保留Netplan；Rocky/Kylin V11使用NetworkManager；OpenWrt保留UCI/netifd | 设计决策不等于目标机探测；版本、CPU与管理器实际能力待原生验收 |
| 控制台P53 | 接口标识/设备/MTU、静态IPv4/IPv6、多DNS与搜索域、静态路由、原生预览、草稿版本与权限 | 不提供未接线应用按钮；界面显示系统应用未发布 |
| routerd | GET读取、POST校验/预览、PUT版本化草稿；管理员权限、If-Match/412、大小限制 | 仅私有草稿存储；不执行OS命令，不写系统网络配置 |
| 模型校验 | CIDR、广播/网络地址、自身下一跳、地址族、直连网关、IPv6 MTU、重复/数量、域名与注入 | 统一模型校验，不等于原生管理器或硬件接受配置 |
| 原生编译目标 | Netplan JSON/YAML、NetworkManager keyfile、OpenWrt UCI片段 | 当前只有预览；没有调用原生加载/激活/回滚接口 |
| 持久化 | 私有目录/文件、单写入进程锁、CAS版本、fsync+rename、重启校验和损坏拒绝 | 保存最新草稿，不是完整历史审计；异常可能结果未知，要求读取核对 |

## 实际验证

| 检查 | 实际结果 | 本机证据（build/network-configuration） |
| --- | --- | --- |
| `CYTHSEC_LIVE_SUDO=0 bash scripts/dev/clion.sh lint` | 退出0，含Go格式/前端类型/ESLint及其他仓库lint | lint-all.log / lint-exit-code |
| `CYTHSEC_LIVE_SUDO=0 bash scripts/dev/clion.sh test` | 退出0，前端24文件77项通过，默认跨栈组完成；独立裁判跳过单列 | test-all.log / test-exit-code |
| `npm run build --prefix web/console` | 退出0，含typecheck:all与生产构建 | build.log / build-exit-code |
| `go test -race ./internal/networkcfg ./internal/api` | 退出0 | go-race.log |
| Linux交叉编译 | CGO关闭，amd64、arm64、loong64、mipsle（softfloat）构建成功；ELF格式核对 | routerd-linux-*；不等于运行或发行版认证 |
| 普通用户BPF关口 | 16项断言通过；本轮没有sudo或权限设置变更 | test-all.log、build/e2e-live |
| 真实HTTP联调 | 同源API读取实际capabilities；表单IP/DNS/路由生成Netplan预览；生产构建也验证NM和UCI预览 | routerd.log、preview-desktop.png |
| 生产隔离 | 正式P53可访问，生产导航无设计工作区；9个业务入口 | 生产preview复验 |
| 响应式 | 1440桌面、390窄屏；修正抽屉固定宽度后dialogWidth=390，页面无横向溢出 | routes-desktop.png、routes-mobile.png、preview-mobile.png、openwrt-preview-mobile.png |
| 草稿保留 | 生产构建下390↔桌面切换仍保留未保存地址；没有重现开发热更新期间的一次重置 | CUA生产浏览器复验 |
| JS日志 | 页面联调未发现error/warn；telemetryd未启动时仍如实显示offline | CUA只读日志检查 |

浏览器输入为RFC文档地址192.0.2.0/24及eth0配置标识，仅用于预览；没有保存到实际系统网络，没有伪装成已观察或已生效地址。
管理员草稿保存、只读/匿名拒绝、版本冲突和重启恢复在httptest及临时私有目录验证；没有在开发机上新建真实管理员访问策略。

## 未核验与后续任务

| 项目 | 状态 |
| --- | --- |
| tshark DPI14项、TCP重组2项、FlowRecord8项对照 | 沿用既有跳过，未核验，不改为通过 |
| Netplan generate/try/确认/回滚 | 未执行，待NC-02—NC-05 |
| NetworkManager原生profile加载/checkpoint/激活/回滚 | 未执行，待NC-02—NC-05 |
| OpenWrt UCI合并/rpcd事务/确认/回滚 | 未执行，待NC-02—NC-05 |
| Ubuntu/Rocky/Kylin V11/OpenWrt虚拟机与实机矩阵 | 尚未执行；不以本机编译或预览替代 |
| DHCP/PPPoE、DHCP服务、VLAN/Bridge/Bond、NAT/转发策略 | 不在本轮静态配置实现范围，须独立模型与受控应用 |

两条门禁退出0不覆盖以上未核验项。本轮只保留本地功能分支提交，不合入main、不推送；无关工作树改动保留。
