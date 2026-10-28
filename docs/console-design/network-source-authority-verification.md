# NC-02B3A 验证记录

本地证据：build/network-source-authority。

| 检查 | 结果 |
| --- | --- |
| Go定向/race | 已通过；权限矩阵无需chown/提权；真实文件修改、原子替换、符号链接及引用边界 |
| 前端定向 | 2文件7项通过；UID非法值、can_adopt伪许可、可见范围、阻断汇总、旧后端兼容 |
| 完整lint/默认测试/构建 | 最终均退出0；final/exits.txt及日志；25文件87项前端测试通过 |
| BPF | 普通用户采集，16项断言通过，未执行sudo |
| 真实HTTP | macOS明确unsupported，authority=blocked，can_adopt/can_apply均false；http.json |
| 浏览器 | 实际来源与接管页签通过；稳定行标识修复后无新增warn/error；authority-desktop.png |
| 交叉编译 | Linux amd64/arm64/loong64/mipsle通过；不代表运行认证 |

不使用sudo，不修改源文件权限或系统网络，不发送Trojan探测或增加公网流量识别规则。
NM引用查询为格式夹具，不能当作目标发行版daemon运行或内容一致证明。
Netplan/OpenWrt加载内容、插件/ifcfg、字段级归因、明确接管与回滚仍待后续。
既有tshark DPI14、重组2、FlowRecord8项未核验；不合main、不推送。

表格不再使用已弃用的rowKey索引参数；路由重复声明保留独立展示键，接管检查按来源/引用/级别/代码生成稳定键。
两条脚本退出0不覆盖既有24项裁判未核验，不据此将项目整体标为全绿。
