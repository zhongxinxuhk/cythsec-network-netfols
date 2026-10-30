# B018 · DNS over TLS 显式明文入口验收

日期：2026-10-29；基线：`5abe050`；分支：`feat/protocol-b018-dot`。
清单原范围为“授权可见明文条件下的 DNS 消息分析”。本轮实现 TLS 应用明文的流解析接口和离线入口，
生产 TLS 数据源接线、密码学来源验证及完整适配仍未完成，不将接口存在勾成完整适配。

## 输入、输出与信任边界

库入口：`dpi::dot::PlaintextStream`。每个实例固定一个 `Context`（source ID、TLS session ID、方向）。
调用方负责确认授权、源/连接映射、从 TLS 终止点取得连续有序应用字节，且从 DNS 长度帧边界开始。
标识校验只约束长度与字符集，不验证授权书、TLS 连接或上游声明的真实性；记录明示为 caller-attested。
本轮没有从原始抓包解密 TLS，也没有接入生产终止点或读取用户密钥。

现有 CLI 新增显式子命令：

```bash
target/debug/cythsec-analyze dot-plaintext \
  -r owned-tls-application.bin \
  --source-id managed-resolver --session-id tls-session-1 \
  --direction client -o dns-messages.jsonl
```

`client` 表示 client→server 请求方向，`server` 表示 server→client 响应方向。
所有来源、会话与方向均必填；不接受重复参数、无效标识、未知方向或错误的 QR 方向。
`-r` 输入为 TLS 应用字节，不是 pcap、TLS record 或去掉长度前缀的裸 DNS。
没有默认的“853/SNI 即 DoT”规则；普通 pcap 路径继续根据可见 TLS/DNS 字节输出，不能因此生成 DoT 应用。

输出为独立 `tls_plaintext_dns_message` JSONL schema v1，包含 source/session/direction、应用字节偏移、
DNS 长度、消息 ID、首问题字段及选定应答地址。`app=dot` / AppId=65563 / medium，
`transport_evidence=caller_attested_tls_termination`，`tls_peer_authenticated=null`。
`dns_scope=first_question_and_selected_answers` 明确字段范围，不宣称完整 RR 验证或 DNSSEC。
这些事件不是 FlowRecord，不制造五元组、网络流字节、TLS 认证成功或租约/事务完成状态；未写入 Native/IPFIX。

## 帧与资源语义

- 依据 [RFC 7858 §3.3](https://www.rfc-editor.org/rfc/rfc7858.html#section-3.3)，处理两字节网络序长度帧；
  支持任意块拆分、多个粘连消息及持续输入。每个完整帧只产出一次，偏移按应用字节累加，包含长度前缀。
- 复用现有有界 DNS 字段解析，当前仅支持 QDCOUNT=1；首问题可完整解析，部分应答地址有既有预算。
  完整帧内首问题不足为 Malformed，不借后帧补齐。QDCOUNT=0/多问题、扩展 opcode 等为不支持。
  完整 RR、无 Question 的错误响应与多问题事务未实现，不能以字段列表为空证明无应答。
- 每帧最多 8192 DNS 字节，每个实例最多 128 消息，待拼接缓冲不超过 8194 字节。
  超预算显式报错并停止，不能当作 Unknown 后继续猜测。错误、截断 EOF、空输入或结束后调用均有明确错误。
- 库按帧回调；后续错误之前的消息只代表有效前缀，宿主必须检查错误后才判断流是否完整。
  CLI 先验证整个有界输入，成功后才创建输出/写 stdout，失败不输出成功消息；既有输出文件拒绝覆盖。

[RFC 8310](https://www.rfc-editor.org/rfc/rfc8310.html) 的认证配置与 TLS 服务器身份验证不由本入口代替。
测试用自签名 TLS 连接没有执行 PKIX/ADN 验证，输出认证状态为未知，不能报告认证通过。

## 实跑记录

证据目录 `build/protocol-b018/`。Rust 零新增依赖；TLS 对照复用仓库锁定的 Python 3.11 环境及 OpenSSL。
系统 macOS Python 3.9/LibreSSL 缺少 keylog/TLS1.3 接口，未用它冒充参考实现；缺 uv/openssl/tshark 或所需 SSL 能力显式未核验。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| 流解析专项 | `cargo test --offline -p traffic-engine --lib dpi::dot` | 退出 0，3 项；每个切点、粘连、EOF、方向、预算、错误偏移及禁止重同步；`dot-unit.log` |
| Rust 库全量 | `cargo test --offline -p traffic-engine --lib` | 退出 0，471 项；`rust-lib.log` |
| TLS / CLI / 独立对照 | `bash scripts/verify/check-dot.sh --tshark` | 最终退出 0；TLS1.2/1.3 MemoryBIO、8 消息事件、16 个 CLI 失败场景；`dot-reference-final.log` |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 实际退出 0；`lint.log` / `lint.exit` |
| 默认完整测试 | `CYTHSEC_LIVE_SUDO=0 CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 实际退出 0；`test-all.log` / `test-all.exit`；含既有未核验项，不算完整全绿 |
| 前端既有回归 | 默认全集内执行 | 25 文件、93 项通过；本轮未修改前端 |
| en0 通用采集 | 最终默认全集内执行，不使用 sudo | 1619 帧：1541 解析成功、78 不支持、0 错误；15 项断言通过。Rust 前缀 500 帧/81 Flow，23 条不可解帧与 tshark 口径一致 |

默认全集仍有既有对照跳过：DPI 14 项、TCP 重组 2 项、FlowRecord 8 项，全部保留为未核验。
脚本末尾的“全部通过”不代表这些项目已经验收。本轮不合 main、不 push。
现场采集无注入目标，ICMP 可见项不适用；这验证通用链路，不代表生产 TLS 明文源已经接入。
通用采集产物另存本轮 `live-capture/`，避免后续门禁覆盖。

首次提交被 `GENERIC_SECRET_ASSIGN` 钩子拦截：局部标识校验闭包名为 `token`，没有真实凭据。
重命名为 `valid_identifier` 后扫描退出 0，未修改扫描规则、未用 `--no-verify`。
最终代码重新执行完整 lint/test，均退出 0；首次两条门禁也均退出 0，其日志与 1500 帧采集证据保留在
`*-before-identifier-rename.*` / `live-capture-before-identifier-rename/`，不混作最终代码结果。
失败与修复后的扫描证据分别为 `secret-scan-initial.log`、`secret-scan.log`。

保留一组额外本地 TLS1.3 样例：`local-tls13.pcap`、`local-tls13-reference.txt`、
`tls13-client/server-application.bin` 和 `tls13-client/server-messages.jsonl`。
应用字节实际取自该次 MemoryBIO 的对端 TLS read；临时私钥/keylog 已删除，没有随产物保存。
这些是本地合成连接与 caller-attested 事件，不是生产来源认证或外部验收证明。

对照在私有临时目录生成自签名证书/私钥，使用 Python ssl MemoryBIO 完成 TLS1.2/1.3 握手，
以拆分写入发送双查询/双响应，从对端 TLS read 取回应用明文，送入新增 CLI；
同时把实际 TLS record 包成有序 TCP pcap，tshark 用该次临时 keylog 独立解码消息 ID、QNAME、A/AAAA。
测试只在内存/离线文件中进行，不创建网络 socket、不查询真实解析器。证书私钥与 keylog 在用例退出时删除，
不复制进项目产物、日志或证据摘要；生产 TLS 终止/密钥管理不在本轮实现范围。

原始加密 PCAP 分析不得因 853、`dns.example` SNI 或 dot ALPN 自动输出 Dot。
CLI 负例含空输入、短长度/短帧、坏长度、跨帧借字节、尾部截断、129 消息、TLS record、HTTP 字节、
错误方向、缺失来源、重复参数、输出覆盖输入及覆盖既有文件。
首次对照退出 1：脚本手工 IPv6 十六进制多写一字节（17 字节），解析器未把它作为 AAAA 地址提取；
改用标准库 `ipaddress` 生成 16 字节值后完整对照通过。原 `dot-reference.log` 保留，未改写为通过。

专项 CLI 接入 Rust 组；带 `--tshark` 的独立对照接入默认全集；检查脚本进入 Ruff/Black 支持清单。
状态真源、生成表、实现与本记录同批提交。

## 未完成项

生产 TLS 明文数据源与会话/时间/五元组绑定、授权/来源认证、原始 PCAP TLS 重组与解密、
TLS/ADN/证书验证、完整 DNS/RR/事务与乱序响应关联、FlowRecord/存储接线、真实语料精度/规模和 Linux 矩阵均未完成。
本轮虽有受控 TLS 字节对照，仍是 caller-attested 明文接口，不能勾选完整线路识别或生产集成。
完整门禁退出码与未核验项分开记录；未全绿不合 main，提交只落本地，不 push。
