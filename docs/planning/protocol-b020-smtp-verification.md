# B020 · SMTP 明文命令与应答识别验收

日期：2026-10-30；基线：`d77eade`；分支：`feat/protocol-b020-smtp`；
工作目录 `/Users/xuzhongxin/CLionProjects/CythSec`。

## 本轮范围与实现

`dpi::smtp` 在 **TCP 25/587/2525** 的传输上下文里判定首条 SMTP（RFC 5321）消息。
465 是隐式 TLS（SMTPS），刻意不纳入：那里的字节是 TLS 记录，必须由 TLS 检测器处理；
把 465 当作明文 SMTP 会让 STARTTLS 前后的口径混在一起。

- 命令：`EHLO`/`HELO` 校验域名（含 address-literal）、`MAIL FROM:`/`RCPT TO:` 校验
  尖括号路径与可选 ESMTP 参数、`AUTH` 校验机制、`BDAT` 校验分块长度与 `LAST`，
  `DATA`/`RSET`/`QUIT`/`STARTTLS` 拒绝参数，其余动词只保留可打印性校验。
- 应答：三位应答码按类别（2–5）与第二位（0–5）校验；多行应答要求各行同码，
  `-` 续行直到 `code SP text` 结束；扩展关键字只作为解析结果保存，不写成"已协商能力"。
- 只判定**第一条消息**。SMTP 允许流水线，但识别不需要读完整个会话；
  后续命令、`DATA` 正文与投递结果属于重组/事务层，本模块不累积字节。
- 四态语义：完整命中才 `Identified`；行未以 CRLF 结束、或达到行/字节预算 → `NeedMore`；
  冒号后缺路径、裸 LF、多行应答混码、协议自相矛盾 → `Malformed`；
  TLS 记录、`+OK`(POP3)、`* OK`(IMAP)、HTTP 方法、SSH  banner、非 SMTP 应答类别 → `Rejected`
  （继续尝试其他检测器，587 上 STARTTLS 之后的 TLS 因此仍能被识别）。
- 预算：每行 2048 字节、每方向 8192 字节、多行应答 16 行、域名 255 字节、BDAT 9 位数字。
- 识别结果走既有 `AppInfo`：`app=smtp`、`app_id=65565`（内置段 29）、
  `confidence=high|medium`、静态 `rationale`。没有新增属性、CLI 子命令或流记录字段；
  `STARTTLS` 广告不等于已升级 TLS，因此不写 `tls_*` 属性。

置信度口径：完整 `EHLO`/`HELO`/`MAIL`/`RCPT`，以及带 `SMTP`/`ESMTP` 关键字的 220 问候为
`high`；单条短命令或裸应答只靠端口上下文，为 `medium`。FTP 的应答同样是三位数字，
端口上下文是唯一区分依据，因此不把裸应答当成强证据。

依据：[RFC 5321](https://www.rfc-editor.org/rfc/rfc5321.html)、
[RFC 3207](https://www.rfc-editor.org/rfc/rfc3207.html)（STARTTLS）、
[RFC 3030](https://www.rfc-editor.org/rfc/rfc3030.html)（BDAT）。

## CLI 与输出契约

没有新增子命令；`cythsec-analyze -r x.pcap -o flows.jsonl` 与在线流水线共用
`dpi::identify_with_ports`。判定结果出现在流记录的 `app` 对象：

```json
{"app":{"outcome":"identified","app":"smtp","app_id":65565,"confidence":"high",
 "rationale":"smtp greeting command with a domain argument","server_name":null,"bytes_inspected":21}}
```

端口只做路由，不构成命中证据：同样的 `220 ... ESMTP` 字节出现在 21/465/993 上必须是
`unknown`，不会被记成 SMTP。

## 实跑证据

证据目录 `build/protocol-b020/`。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| 专项单测 | `cargo test --offline -p traffic-engine --lib dpi::smtp` | 退出 0，5 项通过；`smtp-unit.log` / `smtp-unit.exit` |
| DPI 全集 | `cargo test --offline -p traffic-engine --lib dpi::` | 退出 0，69 项通过（含既有 TLS/HTTP/DNS 向量） |
| 离线 CLI / tshark | `bash scripts/verify/check-smtp.sh --tshark` | 退出 0，25 个正例 / 55 个负例 + 预算用例；`smtp-reference.log` |
| Python 质量 | `bash scripts/verify/check-python-quality.sh` | 退出 0，17 个手写文件（含新增 `check-smtp.py`） |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 退出 0；`lint.log` / `lint.exit` |
| 默认完整测试 | `bash scripts/test/test-all.sh` | 退出 0，485 项 Rust 库测试通过；SMTP 专项在 Rust 组与默认全集中各执行一次，后者带 tshark；`test-all.log` / `test-all.exit` |

独立对照取 Wireshark 4.6.7 的原始字段，不取渲染文本：
`smtp.req.command` / `smtp.req.parameter` 对照命令与参数，
`smtp.response.code` / `smtp.rsp.parameter` 对照应答码与多行内容。
Wireshark 把 `STARTTLS` 显示成 `STAR` + `TLS`（它按前四字节取命令），这是第三方展示口径，
不是协议事实；该用例只做本地判定，不拿它当对照证据，并在脚本里写明原因。

负例覆盖：FTP 端口上的同名问候、465/993/80、TLS ClientHello、SSH、HTTP、POP3、IMAP、
裸 LF、缺少尖括号的 `MAIL FROM:`、路径含空格、`EHLO` 域名含空格、`DATA` 带参数、
空 `AUTH`、非法 `BDAT` 后缀、多行混码、`2\r\n`、`999`、二进制、超长动词、错误 IP 长度，
以及问候的每个截断点（1..len-1）都不得被识别。`--inspect-bytes 10` 时必须为 `need_more`。

## 未完成项

- 仅首条消息、仅端口上下文；不解析 `DATA` 正文、邮件头、附件或投递结果，不做事务关联。
- 不做 `AUTH` 凭据语义、认证结果或账号识别；不把扩展广告当成已协商能力。
- 不处理 STARTTLS 之后的 TLS（那是 TLS 检测器）、隐式 TLS 的 SMTPS/465、
  以及 HTTP 代理上的 SMTP 隧道。
- 明细字段未进入 `FlowRecord`、Native/IPFIX 或持久化；没有按会话统计邮件命令/应答分布。
- 语料为合成报文，真实运营网络上的误报率、SMTP 流量占比、规模与 Linux 运行矩阵未验收。
- 完整适配因此保持未勾选；本记录只证明"范围内实现、本地测试、独立对照"三步，
  不等于生产可用或协议完整适配。

本轮只做通用明文协议解析，不提供规避审查的识别指纹、主动探测或封锁实现。
