# B019 · DNS over HTTPS 消息表示验收

日期：2026-10-29；基线：`92276f3`；分支：`feat/protocol-b019-doh-original`。
工作目录固定 `/Users/xuzhongxin/CLionProjects/CythSec`；本轮文件修改、构建与验证经本机 CLion MCP 执行。
原目录的 CI 提交 `8dc8776` 与 B015–B018 提交已保留；原有 DNS/TCP 改动及已暂存/已删除文档未纳入本轮提交。

## 本轮输入与实现

`dpi::doh::parse_https` 接受上游拥有者提供的完整、已解码 HTTPS 消息表示；HTTP/2/3 帧、HPACK/QPACK、
传输编码/重复头验证与消息完成边界由上游 HTTP 栈负责。本轮没有实现这些线路解码或生产代理接线。
复用 B018 的来源/会话/方向 Context，额外要求独立 HTTP request ID，不以通常为 0 的 DNS ID 关联 HTTP 事务。
标识校验只约束格式，不验证授权、TLS 身份或来源声明，事件明示 caller-attested。

- GET：HTTPS URI 中只支持单一 `dns` 参数，严格校验无填充 base64url、字符集、尾部填充位与大小。
  不支持其他静态查询参数、百分号编码模板或多变量模板；不要求固定 `/dns-query` 路径。
- POST：仅支持 `application/dns-message` 的原始 DNS body，不带 DoT 两字节长度前缀。
- 响应：仅解析 2xx、`application/dns-message`、QR=1 的 DNS 表示；HTTP 200 与 DNS RCODE 分开保存，
  NXDOMAIN 不升级为成功解析。HTTP 错误响应不产生已识别 DNS 消息，不能据此证明没有 DoH 服务。
- 限制 DNS body 8192 字节、URL 16384 字节；媒体类型大小写不敏感，参数/其他媒体类型及非 identity 编码不支持。
  声明 Content-Length 时必须等于完整 decoded body 长度，拒绝不完整消息与角色/方法/状态矛盾。
- URI 要求显式 HTTPS、ASCII authority/路径；支持合法 IPv6 authority 和可选端口，拒绝用户信息、片段及空/非法端口。
  URI 仅为调用方提供的元数据，不访问 URL、不验证配置权限、证书名称或该 endpoint 是否真实提供解析服务。
- 复用既有有界 DNS 字段解析，当前 QDCOUNT=1，首问题与选定应答地址有明确范围；完整 RR/DNSSEC/事务未实现。
  默认 PCAP/DPI 不凭 443、SNI、ALPN 或 URI 路径输出 DoH。

依据：[RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html)。
本轮对照采用 HTTP/1.1 over TLS；支持已解码表示不等于实现 HTTP/2/3 线路识别。

## CLI 与输出契约

```bash
target/debug/cythsec-analyze doh-message \
  --source-id owned-https-stack --session-id connection-1 --request-id stream-1 \
  --direction client --url https://dns.example/custom --method POST \
  --content-type application/dns-message -r complete-dns-body.bin
```

GET 使用 `--method GET --url 'https://dns.example/custom?dns=...'`，body 为空；
响应使用 `--direction server --status 200 --content-type application/dns-message -r body.bin`。
可提供 `--content-length`、`--content-encoding`。必填元数据、重复参数、错误方向与既有输出覆盖均被拒绝。
输入只在验证成功后输出，不启动监听器或发起请求。

输出独立 `https_dns_message` JSONL schema v1：`app=doh` / AppId=65564 / medium，
包含 source/session/direction/request ID、声明的 HTTPS authority/endpoint path、方法或 HTTP status、DNS 字段。
不回显编码后的 DNS 查询参数；`transport_evidence=caller_attested_decoded_https`，`tls_peer_authenticated=null`，
`dns_scope=first_question_and_selected_answers`。不制造 FlowRecord、五元组、TLS 认证或 HTTP 请求响应匹配结果。
详细事件尚未接入 FlowRecord/Native/IPFIX/持久化。

## CLion MCP 实跑

本机配置端点：`http://127.0.0.1:64362/stream`，CLion MCP Server 2026.2.3.1。
调用时指定 `projectPath=/Users/xuzhongxin/CLionProjects/CythSec`，通过 IDE 终端或项目运行配置执行。
Agent 终端仅承载 JSON-RPC 客户端，没有在其自身进程中替代执行项目构建/测试。
证据目录 `build/protocol-b019/`。

| 检查 | CLion MCP 发起的动作 | 结果 |
| --- | --- | --- |
| 专项单测 | IDE terminal：`cargo test --offline -p traffic-engine --lib dpi::doh` | 实际退出 0，3 项；`doh-unit.log` / `doh-unit.exit` |
| TLS / HTTPS / CLI | IDE terminal：`bash scripts/verify/check-doh.sh --tshark` | 实际退出 0，8 事件/20 个 CLI 失败场景；`doh-reference.log` / `doh-reference.exit` |
| Rust 库回归 | CLion MCP 默认全集 | 479 项通过，含原目录现存 DNS/TCP 用例；`test-all.log` |
| 完整 lint | MCP `execute_run_configuration`：`CythSec Lint All` | CLion receipt 实际退出 0；`build/clion/runs/lint.BkSQVz/`，已另存 `lint.log` / `lint.exit` |
| 默认完整测试 | MCP IDE terminal：`CYTHSEC_LIVE_IFACE=en0 bash scripts/dev/clion.sh test` | 实际退出 0；`build/clion/runs/test.mu4u8l/`，已另存 `test-all.log` / `test-all.exit` |
| 前端既有回归 | 同一默认全集 | 25 文件、93 项通过；本轮未修改前端 |
| en0 通用采集 | 同一默认全集，wrapper 固定不使用 sudo | 4588 帧全部解析成功，0 错误/0 不支持；15 项断言通过，Rust 环前缀 500 帧/58 Flow |

默认全集仍有既有独立对照跳过：DPI 14 项、TCP 重组 2 项、FlowRecord 8 项，均继续未核验。
进程退出 0 不代表这些项已验收；不合 main、不 push。现场采集没有注入目标，ICMP 可见项不适用，
通用采集通过不能替代真实 DoH 来源/服务语料。本轮采集产物另存 `live-capture/`。
本地 TLS1.3 POST 请求/响应事件样本位于 `https13-client/server-message.jsonl`，实际 body 与加密 PCAP 同目录保存，
私钥/keylog 已删除。摘要是本地文件绑定，不提供签名或外部来源认证。

测试复用本项目锁定 Python 3.11/OpenSSL，生成临时自签名证书，以 MemoryBIO 完成 TLS1.2/1.3、
ALPN=http/1.1 的 GET/POST 交换；从实际 TLS read 字节解析完整 HTTP 表示，调用新增 CLI。
tshark 独立解密同次 TCP443 PCAP，核对 HTTP 方法/URI、POST/响应 DNS 字段与应答地址；
GET 参数由 tshark 提取 URI 后用 Python 标准库独立解码，并与原 DNS 字节核对。
私钥和 keylog 位于私有临时目录，退出时删除，不保留到项目/日志/证据摘要；没有网络 socket 或真实解析器请求。

负例涵盖非 HTTPS/用户信息、缺失/重复/坏编码 dns 参数、GET body、错误媒体/编码/长度、
非法请求 ID、方法/状态矛盾、缺少来源、重复 CLI 参数、覆盖输入、错误 QR、500 状态及超预算。
共享 TLS 夹具只新增可选 ALPN/端口参数，B018 默认保持 dot/853，并在完整门禁内回归。
共享 Context 只提取同一标识校验函数并增加只读字段访问，不改变 B018 来源或认证语义。

一次 `CythSec Preflight` MCP 请求等待超时，没有取得退出码，不记为通过。
`CythSec Lint All` 运行请求的 MCP 传输返回 HTTP404，但 IDE 实际完成，已通过 MCP 回读其完整 output.log 与 exit-code=0，
没有仅凭启动请求写成通过。默认全集通过 MCP IDE 终端执行同一 canonical wrapper，读取其独立 receipt 确认退出 0。
IDE 终端发起的实际单测/CLI 已取得明确退出码；后续完整门禁以其实际输出及 exit-code 为准。
原目录已有未提交 DNS/TCP 源码，工作树回归测试数包含其用例；不能将这些改动视为 B019 已提交代码。

## 未完成项

生产 HTTPS 数据源/完成标记/授权与 request ID 绑定、HTTP/2/3/HPACK/QPACK、通用 URI 模板、
压缩/其他媒体、完整 DNS/RR/HTTP-DNS事务关联、TLS认证、流记录/存储接线、真实语料/精度/规模及Linux矩阵均未完成。
本轮为 caller-attested 完整消息表示接口，完整适配保持未勾选。两条完整门禁退出码与未核验项分别记录，
未全绿不合 main，提交只落本地，不 push。
