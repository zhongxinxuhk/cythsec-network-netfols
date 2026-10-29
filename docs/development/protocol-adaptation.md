# 协议适配状态维护

状态真源：configs/registry/protocol-adaptation.json；对象名称与既有实现声明沿用vpn-protocols.json。
流程要求以[AGENTS.md](../../AGENTS.md)的协议适配状态记录为准。
生成表：[ADAPTATION-STATUS](../protocols/ADAPTATION-STATUS.md)。268项目录对象与24项基础/补充核验共292行，
其中存在同协议不同能力范围，不能称作292种独立协议或全部全球协议。

每行单独维护implemented、local_tested、reference_tested、accepted。前三列为范围内的分步记录，最后一列才表示完整适配。
accepted要求前三项为true、范围明确、证据存在且缺口为空；当前不把有界首帧、候选承载、可信上下文或产品资料当完整线路识别。
端口、加密外层、目录父子关系或共同解析器都不能自动完成其他条目。

修改步骤：

1. 核对该ID的代码、样本、负例、截断/未知/预算语义及输出契约，写明支持范围和缺口。
2. 实跑对应测试与独立对照，把命令、实际退出码、环境、证据路径记入验收记录；有例外不勾独立对照完成。
3. 更新该行状态及code/tests/reference引用，运行生成器；不直接编辑生成表中的勾选。
4. 完整lint/test通过才满足仓库合入前提；跳过项仍为未核验，不使用清单计数替代门禁。

```bash
python3 tools/codegen/gen-protocol-adaptation.py
python3 tools/codegen/gen-protocol-adaptation.py --check --self-test
```

生成器检查ID覆盖/唯一性、目录版本、布尔状态、路径/测试符号和完成条件，并有6项反向注入自证。
它验证的是记录一致性，不会仅凭文件存在推断运行通过；运行证据必须按步骤2实际取得。
生成检查已接完整lint和Rust测试；DNS/TCP CLI回归进入Rust组，tshark独立对照进入默认全集。

本轮DNS/TCP仅支持连续前缀的首个长度帧，使用现有DNS有界字段解析。补齐两字节长度、严格帧边界、
粘连只取首帧、未完整帧保持NeedMore、帧内问题段不足不能借后帧修复。
依据：[RFC7766](https://www.rfc-editor.org/rfc/rfc7766.html#section-8)。
主流水线尚未将TCP重组模块接入DPI，因此本条完整适配保持未勾；大消息超预算、持久连接多事务与真实语料仍待开发/验收。

此表只记录现状和通用解析工作；本轮没有新增公众规避审查协议指纹、主动探测或封锁实现。
本轮验收见[记录](../planning/protocol-adaptation-verification.md)。

基础/补充项顺序接B014推进B015 DHCPv4，本轮范围、测试与未完成项见
[B015验收记录](../planning/protocol-b015-dhcpv4-verification.md)。门禁退出码单独实跑，
不沿用上轮DNS/TCP结果；DHCPv4详细字段尚未进入FlowRecord，完整适配保持未勾选。

下一项B016 DHCPv6的有界消息、中继与IA选项识别见
[B016验收记录](../planning/protocol-b016-dhcpv6-verification.md)。使用当前RFC 9915，DUID按不透明标识保存；
完整事务、明细输出与真实语料验收仍有缺口，不沿用B015门禁结果。

B017 mDNS的多问题、主动响应、DNS-SD常见记录及UTF-8名称解析见
[B017验收记录](../planning/protocol-b017-mdns-verification.md)。双端口上下文通过兼容的DPI入口传入，
普通DNS名称归一化保持原契约；链路本地性、缓存/冲突状态和明细输出仍未完成。

B018 DoT在显式TLS应用明文入口中解析长度帧，见[B018验收记录](../planning/protocol-b018-dot-verification.md)。
调用方声明来源/会话/方向，受控TLS1.2/1.3字节与tshark对照不替代生产数据源或认证。
普通pcap入口不凭853、SNI或ALPN把TLS升级为DoT；完整适配保持未勾选。

B019 DoH对调用方提供的完整、已解码HTTPS消息校验GET/POST/2xx DNS表示，见
[B019验收记录](../planning/protocol-b019-doh-verification.md)。不凭443/路径推断应用，不把该接口等同HTTP/2/3帧解码。
本轮在原始项目目录经CLion MCP构建/验证，来源绑定、完整事务与流记录接线仍有缺口。
