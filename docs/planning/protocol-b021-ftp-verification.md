# B021 · FTP 明文控制通道识别验收

日期：2026-10-30；基线：`337958e`；分支：`feat/protocol-b021-ftp`；
工作目录 `/Users/xuzhongxin/CLionProjects/CythSec`。

## 本轮范围与实现

`dpi::ftp` 在 **TCP 21/2121** 的明文控制通道里判定首条 FTP（RFC 959）命令或首条应答。
990 是隐式 FTPS，刻意不纳入：那里的字节是 TLS 记录，必须由 TLS 检测器处理。
21 上显式 `AUTH TLS` 之后的握手同样回落到 TLS 检测器。

- 命令：登记 RFC 959 与常用扩展动词（`USER`/`PASS`/`RETR`/`STOR`/`PORT`/`PASV`/
  `TYPE`/`STRU`/`MODE`/`REST`/`ALLO`/`SIZE`/`MDTM`/`MLSD`/`EPSV`/`EPRT`/`AUTH`/
  `PBSZ`/`PROT` 等），按命令校验实参：`TYPE` 只接受 `A/E/I/L`（`L 8` 允许），
  `STRU` 只接受 `F/R/P`，`MODE` 只接受 `S/B/C`，`PORT` 要求六段 0–255，
  `EPRT` 要求 `|1|addr|port|` 或 `|2|...|`，`REST`/`PBSZ` 为十进制，
  `ALLO` 允许 `n R m`，`PROT` 只接受 `C/S/E/P`；无参命令带参数即判畸形。
- **`PASS` 不保留实参**：`Command.argument` 恒为 `None` 且 `redacted=true`。
  识别只需要"命令存在且非空"，口令不进入解析结果、日志或后续记录。
- 应答：1xx–5xx 且第二位 0–5；**FTP 的多行应答格式与 SMTP 不同** ——
  首行 `code-`、中间行任意文本、末行 `code SP`。按 SMTP 的"逐行同码"解析会把
  `211-Features:\r\n UTF8\r\n211 End` 误判为畸形，因此单独实现。
- 四态语义：完整命中才 `Identified`；行未以 CRLF 结束或达到行/字节/行数预算 → `NeedMore`；
  裸 LF、缺参、参数语法错误、应答码/分隔符自相矛盾 → `Malformed`；
  TLS 记录、POP3/IMAP、HTTP、SMTP、SSH、非 1xx–5xx 应答 → `Rejected`
  （继续尝试其他检测器）。
- 预算：每行 2048 字节、每方向 8192 字节、多行应答 16 行；路径允许空格与 UTF-8
  （RFC 2640），控制字节仍拒绝。
- 结果走既有 `AppInfo`：`app=ftp`、`app_id=65566`（内置段 30）、
  `confidence=high|medium`、静态 `rationale`。没有新增属性、CLI 子命令或流记录字段。

置信度口径：`USER`/`PASS`/`PORT`/`PASV`/`TYPE`/`EPSV`/`EPRT`/`STRU`/`MODE`/`REST`/
`ALLO`/`PBSZ`/`PROT`/`AUTH`/`SIZE`/`MDTM`/`MFMT` 等带结构参数的动词为 `high`；
路径类与会话类命令为 `medium`。应答只有 220 且文本含 `FTP`（如 `vsFTPd`/`ProFTPD`）
时为 `high`，其余应答只靠端口上下文，为 `medium`。

依据：[RFC 959](https://www.rfc-editor.org/rfc/rfc959.html)、
[RFC 2428](https://www.rfc-editor.org/rfc/rfc2428.html)（EPSV/EPRT）、
[RFC 4217](https://www.rfc-editor.org/rfc/rfc4217.html)（显式 FTPS）、
[RFC 2640](https://www.rfc-editor.org/rfc/rfc2640.html)（UTF-8 路径）。

## CLI 与输出契约

没有新增子命令；`cythsec-analyze -r x.pcap -o flows.jsonl` 与在线流水线共用
`dpi::identify_with_ports`。判定结果出现在流记录的 `app` 对象：

```json
{"app":{"outcome":"identified","app":"ftp","app_id":65566,"confidence":"high",
 "rationale":"ftp login command","server_name":null,"bytes_inspected":16}}
```

端口只做路由：同样的 `USER anonymous` 出现在 25 上必须是 `unknown`（或由该端口自己的
协议判定），不会被记成 FTP。

## 实跑证据

证据目录 `build/protocol-b021/`。

| 检查 | 命令 | 实际结果 |
| --- | --- | --- |
| 专项单测 | `cargo test --offline -p traffic-engine --lib dpi::ftp` | 退出 0，4 项通过；`ftp-unit.log` / `ftp-unit.exit` |
| DPI 全集 | `cargo test --offline -p traffic-engine --lib dpi::` | 退出 0，74 项通过（含既有 TLS/HTTP/DNS/SMTP 向量） |
| 离线 CLI / tshark | `bash scripts/verify/check-ftp.sh --tshark` | 退出 0，57 个正例 / 44 个负例 + 预算用例；`ftp-reference.log` |
| Python 质量 | `bash scripts/verify/check-python-quality.sh` | 退出 0，18 个手写文件（含新增 `check-ftp.py`） |
| 完整 lint | `bash scripts/lint/lint-all.sh` | 退出 0；`lint.log` / `lint.exit` |
| 默认完整测试 | `CYTHSEC_LIVE_IFACE=en0 bash scripts/test/test-all.sh` | 退出 0，490 项 Rust 库测试通过；`test-all.log` / `test-all.exit` |

独立对照取 Wireshark 4.6.7 的 `ftp.request.command` / `ftp.request.arg` 与
`ftp.response.code` / `ftp.response.arg`。tshark 对 FTP 多行应答只显示首行文本
（`211` / `Features:`），多行结构由本地用例断言；这不影响命令/应答码的独立核对。

负例覆盖：25 端口上的 FTP 问候、990/992、80、TLS ClientHello、SSH、HTTP、SMTP `EHLO`、
POP3、IMAP、裸 LF、`USER` 缺参、`TYPE X`、`STRU X`、`PORT` 段数不足/越界、
`EPRT` 非法地址族、`REST abc`、`QUIT now`、`FEAT x`、`999`、`600`、二进制、
超长动词、错误 IP 长度，以及问候的每个截断点（1..len-1）都不得被识别。
`--inspect-bytes 10` 与截断的多行应答必须为 `need_more`。


首次默认全集运行在真实网卡关口失败（退出 1）：默认路由被隧道接管，自动探测选中
`lo0`，而 `-w` 只支持以太网链路类型。原始日志保留为
`test-all-live-lo0-failed.log` / `.exit`，没有把这次失败改写成通过；按 B019 的做法
显式指定 `CYTHSEC_LIVE_IFACE=en0` 后重跑，退出 0。两轮之间未改代码。

默认全集仍有既有的未核验项：DPI 14 项、TCP 重组 2 项、FlowRecord 8 项为已知例外；
列式落盘 D 组因本机无 ClickHouse 二进制标为「未核验」；真实网卡关口有脚本内部
显式标注的 SKIPPED 场景。进程退出 0 不等于这些项已验收。

## 未完成项

- 仅首条命令/应答、仅控制端口上下文；不解析数据通道、文件内容、目录列表、
  登录/传输结果或命令-响应配对。
- `PASS` 只做语法校验且不保留实参；不做凭据、账号或认证结果识别。
- 不处理 990 隐式 FTPS、`AUTH TLS` 之后的 TLS（由 TLS 检测器负责）、
  HTTP 代理上的 FTP 隧道与 FTP over SSH。
- 明细字段未进入 `FlowRecord`、Native/IPFIX 或持久化；没有按会话统计命令/
  应答分布或传输量。
- 语料为合成报文，真实运营网络上的误报率、FTP 流量占比、规模与 Linux 运行矩阵未验收。
- 完整适配因此保持未勾选；本记录只证明"范围内实现、本地测试、独立对照"三步，
  不等于生产可用或协议完整适配。

本轮只做通用明文协议解析，不提供规避审查的识别指纹、主动探测或封锁实现。
