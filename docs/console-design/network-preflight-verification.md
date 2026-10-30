# NC-02运行态观测与应用前检查验收记录

分支：`feat/network-preflight-observation`。范围为NC-02A运行态部分；持久配置读取/来源确认/原生校验仍属NC-02B，未标记整个NC-02完成。

## 实现与边界

| 项目 | 本轮实现 | 边界 |
| --- | --- | --- |
| 观测接口 | GET observation、POST preflight，归属routerd现有读取权限 | 不扩大admin保存权限；不发布应用/确认/回滚路径 |
| 内核运行态 | 接口、IP/CIDR、MTU、启用与类型证据 | 地址读取失败和枚举失败各自保留未知；不把缺数据当0接口 |
| 管理器 | 固定只读查询、active响应、归属声明、工具版本、诊断 | 非Linux不运行Linux查询；工具版本不是daemon版本；未知服务状态不当已停止 |
| 归属与复杂接口 | 多归属、桥/Bond/VLAN/组合成员、间接L3关联等阻断 | NetworkFile名字含netplan不作为Netplan来源确认或接管授权 |
| 差异 | 五字段相同/不同/未知；规范化IP/域名集合；主表运行路由 | 运行值包含自动/动态项，差异不是持久配置变更或删除计划 |
| 资源控制 | 单并发、5秒总预算、1.5秒子进程、1MiB stdout、无shell和交互提权 | 429不是空成功；未知native字段/原始stderr不进入接口和日志 |
| 控制台 | 环境折叠区、管理器/接口表、检查项/运行态差异抽屉、digest与快照ID | 不显示系统应用按钮；读取失败撤销旧环境；编辑后需新报告 |

## 实际执行证据

| 检查 | 结果 | 本机证据（build/network-preflight） |
| --- | --- | --- |
| `CYTHSEC_LIVE_SUDO=0 bash scripts/dev/clion.sh lint` | 退出0，含Go格式、前端类型与ESLint及其他仓库检查 | lint-all.log / lint-exit-code |
| `CYTHSEC_LIVE_SUDO=0 bash scripts/dev/clion.sh test` | 最终退出0，前端24文件80项通过，默认其他栈完成；独立裁判跳过另列 | test-all.log / test-exit-code |
| `npm run build --prefix web/console` | 退出0 | build.log / build-exit-code |
| Go race | networkcfg与api通过 | go-tests.log |
| Linux交叉编译 | amd64/arm64/loong64/mipsle成功；CGO关闭，mipsle softfloat | routerd-linux-*，不等于运行认证 |
| BPF真实采集 | 普通用户权限，16项断言通过；未运行sudo或修改权限设置 | test-all.log / build/e2e-live |
| 读取器与比较回归 | NM转义、networkd D-Bus JSON、OpenWrt投影、DNS scope、空/未知、敏感字段不回传、冲突归属、L3父设备、主表特殊路由、单并发、真实子进程输出/超时 | Go测试与race |
| 权限与API | 读取角色可观测/预检查，其他服务不能借用；无效草稿不启动原生查询；忙返回429 | API与共享权限测试 |
| 本机真实HTTP | macOS返回真实内核接口；Linux管理器不适用；未尝试Linux原生命令 | routerd.log、浏览器实际读取 |
| 生产构建 | 正式P53可访问；设计入口数为0；真实后端返回报告 | CUA生产预览 |
| 报告绑定 | 改MTU为1600后digest变化，报告草稿值更新；未知当前值仍为未取得 | differences-desktop.png |
| 响应式 | 1440桌面、390窄屏；抽屉宽390，页面无横向溢出；表格在内部横滚 | differences-mobile.png / checks-desktop.png |
| 浏览器日志 | 期间无JS error/warn；未启动的telemetryd仍如实offline | CUA只读日志 |

输入eth0与192.0.2.10/24仅作为RFC文档地址预检查；本机没有eth0时报告阻断，不伪造已观察或已配置地址。
没有保存或应用本机IP/DNS/路由；没有创建真实管理员访问策略。快照只保留在请求/页面内存，未新增浏览器持久化或观测档案。

## 修复的验证问题

| 发现 | 修复与复验 |
| --- | --- |
| Go嵌入bytes.Buffer使ReaderFrom绕过Write限额 | 改为具名内部缓冲，真实子进程超大输出与截止回归通过 |
| 未知服务状态可能被归为inactive | 改为unavailable/unknown诊断并增加回归，避免虚假未运行结论 |
| 全集首次出现队列刷新测试时序失败 | 使用受控时钟与act完成加载态切换，保留真实Ant/Pro、真实hook和两次请求断言；最终全集80项通过 |

## 未核验与后续

| 项目 | 状态 |
| --- | --- |
| 既有tshark DPI14、TCP重组2、FlowRecord8项跳过 | 未核验，未改写通过 |
| Ubuntu/Rocky/Kylin V11/OpenWrt实际命令及版本矩阵 | 尚未执行；格式夹具和交叉编译不代替目标系统验收 |
| 持久配置读取、源配置接管与导入、原生解析器校验 | NC-02B待开发 |
| 管理链路确认、事务应用、失联回滚、崩溃恢复、审计 | NC-03/04未发布；can_apply仍为false |

两条门禁退出0不覆盖以上未核验。仅提交本地功能分支，不合入main、不推送；保留无关工作树改动。
