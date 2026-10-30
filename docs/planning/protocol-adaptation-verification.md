# 协议适配清单与DNS/TCP验收

日期：2026-10-29；证据目录：build/protocol-adaptation-status。
范围：统一协议状态清单、通用DNS/TCP首帧解析及门禁接线，不扩展受限场景的专用识别能力。

| 检查 | 结果 |
| --- | --- |
| DNS/TCP定向单测 | 长度前缀、各截断点、压缩响应、粘连、帧边界、错误长度、端口漂移及UDP/TCP区分通过 |
| Rust库回归 | 最终457项通过，退出0；rust-lib-final.log |
| 离线CLI / tshark | 查询/响应字段对照、3项错误帧输入通过，退出0；dns-tcp-final.log；默认全集再次执行独立对照 |
| 清单检查与反向注入 | 292行唯一覆盖、版本/证据检查及6项非法元数据注入通过；生成检查接入lint与Rust组 |
| 完整lint | 退出0；lint-final.log；新增两份Python代码纳入Ruff/Black支持清单 |
| 默认完整测试 | 无分组裁剪，CYTHSEC_LIVE_SUDO=0、CYTHSEC_LIVE_IFACE=en0，退出0；test.log；前端25文件93项维持通过 |
| Rust构建 | build-all.sh --rust退出0；build.log；本轮未修改前端业务，不重复前端生产构建 |
| 开发机采集回归 | 4850帧，4848解析成功/2不支持/0错误，15项断言通过；无注入目标，ICMP可见项不适用 |

首次Rust库回归退出101：旧断言将UDP格式的裸DNS消息在TCP上判为已识别。
按照DNS/TCP长度帧契约，保留UDP成功断言，补充裸TCP消息不能命中与合法长度帧成功的成对断言；
修正后457项通过。原始rust-lib.log及其退出码保留，未将初次失败重写为通过。

当前勾选统计：实现审查17、本地测试17、独立对照1、完整适配0；分别表示不同步骤，不累计成协议完成数。
本轮DNS/TCP尚无主流水线重组、多事务或实际Linux现场完整验收，故B014的完整适配仍未勾选。

资料覆盖不是协议适配完成。完整适配栏当前不因有界实现、本地合成样本、上下文接口或共同承载自动勾选。
既有DPI14、TCP重组2、FlowRecord8项裁判例外继续未核验；不合main、不推送。
依用户要求跳过macOS网关兼容适配，不做unsupported界面复验；保留通用开发门禁。
本地evidence-manifest.json绑定提交、变更文件与完成日志的SHA-256；未签名，不代替第三方验收或可信时间证明。

后续基础/补充清单从B015 DHCPv4继续，独立的本轮结果见
[DHCPv4验收记录](protocol-b015-dhcpv4-verification.md)，不以此页历史退出码替代本轮门禁。

B016 DHCPv6继续按基础清单顺序推进，范围与本轮实跑结果见
[DHCPv6验收记录](protocol-b016-dhcpv6-verification.md)。

B017 mDNS的范围、专项/独立对照及本轮门禁见
[mDNS验收记录](protocol-b017-mdns-verification.md)，不使用本页历史结果替代。

B018 DoT的显式TLS明文入口、受控TLS字节对照及本轮门禁见
[DoT验收记录](protocol-b018-dot-verification.md)。

B019 DoH的已解码HTTPS消息表示与原目录CLion MCP实跑见[DoH验收记录](protocol-b019-doh-verification.md)。

B020 SMTP的首条命令/多行应答、端口上下文与tshark对照见
[SMTP验收记录](protocol-b020-smtp-verification.md)；本轮不沿用B019的门禁退出码。

B021 FTP的控制命令/应答、FTP式多行格式与tshark对照见
[FTP验收记录](protocol-b021-ftp-verification.md)；本轮不沿用B020的门禁退出码。

B014 的“主流水线 TCP 重组”缺口已于 2026-10-30 单独验收：SYN 锚定的有界前缀重组、
乱序/冲突/缺尾/中途接入与 tshark 独立重组对照见
[DNS/TCP主流水线验收记录](protocol-b014-dns-tcp-pipeline-verification.md)。
本页上方“尚无主流水线重组”的表述保留为当时状态，不据此改写历史结论。
