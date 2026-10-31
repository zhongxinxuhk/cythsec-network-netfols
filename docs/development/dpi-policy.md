# DPI 模块开关与检测强度

状态真源：`configs/registry/dpi-modules.json`（模块目录）与
`configs/registry/protocol-adaptation.json`（协议适配验收）。本页只说明控制面
与数据面的策略契约，不把"模块可关闭"写成"协议适配已完成"。

## 1. 策略对象

数据面（`cythsec-analyze`）与控制面（`routerd`）共用同一份 JSON：

```json
{
  "schema_version": 1,
  "enabled": true,
  "intensity": "standard",
  "inspect_bytes": null,
  "modules": { "tls": true, "dns": false },
  "tls_decrypt": { "enabled": false, "keylog_file": "" }
}
```

- `enabled=false` 与 `intensity="off"` 等价：一次检测器都不调用，记录写
  `app.outcome=not_inspected`，**不写 `unknown`**（"没看"和"看了不认识"在统计上后果相反）。
- `intensity`：
  - `off`：0 字节，0 个检测器。
  - `basic`：仅 TLS/HTTP/DNS，窗口上限 128 字节。
  - `standard`：全部已启用模块，窗口沿用调用方上限（CLI 默认 512）。
  - `deep`：窗口至少 4096 字节；配置密钥日志后尝试解密 TLS 1.2/1.3。
- `inspect_bytes`：显式覆盖 64..=65536；`null` 表示按强度取默认。
- `modules`：键与 `AppId` 一一对应；缺省项按目录 `default_enabled` 处理。
  拼错的键、未知强度、相对 key log 路径都会导致加载失败，不静默回落。
- `tls_decrypt`：只接受运维方提供的 NSS key log 绝对路径；只有
  `intensity=deep` + `enabled=true` + 非空路径三者同时成立才生效。

模块目录里的 `availability` 必须如实展示：

| 值 | 含义 |
| --- | --- |
| `implemented` | 已有专用检测器并纳入本地测试 |
| `context` | 只接收调用方已解密/已解码输入（DoT/DoH），不是线缆识别 |
| `candidate` | 仅有有界结构候选，不计入协议适配完成 |

TLS 1.2/1.3 共用同一个 ClientHello 检测器，因此目录中只有一个 `tls` 开关，
不把 T001/T002/T022 拆成三个看起来独立、实际同生共死的假开关。

## 2. 数据面

```bash
# 默认标准强度
cythsec-analyze -r capture.pcap -o flows.jsonl

# 关闭全部 DPI；输出仍是完整 FlowRecord，只是 app.outcome=not_inspected
cythsec-analyze -r capture.pcap --no-dpi

# 读取控制面保存的策略
cythsec-analyze -r capture.pcap --dpi-policy /var/lib/cythsec/dpi/policy.json

# 命令行覆盖强度；cythsec-analyze 只记录策略与可见字段，不执行 TLS 解密
cythsec-analyze -r capture.pcap --dpi deep --dpi-keylog /var/lib/cythsec/tls.keys
```

统计行会打印实际生效的策略，便于把"声明关闭"与"实际没跑"对上：

```text
[cythsec-analyze] dpi enabled=false intensity=off modules_disabled=0
```

`cythsec-analyze` 的 `--dpi-keylog` / `--dpi-decrypt` 只表达"允许解密"的策略输入；
它不改变 FlowRecord 的落盘契约，也不在分析流水线里缓存整条 TCP 流。真正读取
key log、重组 TCP、解密记录并分析明文的是第 6 节的独立工具。

## 3. 控制面

routerd 新增：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/dpi/modules` | 模块目录（含 availability 与 catalog_ids） |
| GET | `/api/v1/dpi/policy` | 当前策略、版本、`can_save`/`store_enabled` |
| PUT | `/api/v1/dpi/policy` | 管理员保存；必须带 `If-Match: "<revision>"` |

启动参数：

```bash
routerd -dpi-policy-dir /var/lib/cythsec/dpi
```

存储目录必须私有（`0700`），`policy.json` 必须 `0600`；写入采用临时文件 +
`rename` + 目录 `fsync`，并用 `If-Match` 防止两个控制台互相覆盖。控制面只保证
"下一次数据面启动/分析读到这份文件"，不声称热更新正在运行的进程。

## 4. 控制台

`流量分析 → DPI 策略`（`/analytics/dpi`）：

- 总开关、四档强度、逐协议开关、TLS 解密开关与 key log 路径；
- 未启用存储、只读身份、版本冲突、保存失败分别显示，不伪装成成功；
- `candidate` 模块标为"结构候选"，不与已实现模块混为一谈。

## 5. 安全边界

- key log 只读，不导出、不复制、不写入 FlowRecord；
- 没有密钥时保持仅解析可见 ClientHello，不尝试破解密码学；
- 关闭模块是真实跳过调用，不是"解析完再丢结果"；
- 本功能不提供主动探测、指纹规避或封锁实现。

## 6. TLS 1.2/1.3 key log 解密

`cythsec-tls-inspect` 是独立二进制：读 pcap，按方向重组 TCP，解析 TLS 记录，
用 NSS key log 解密应用数据，再把明文送入现有 DPI。它**不修改** FlowRecord
的字节布局，也不把明文写进事件。

```bash
# 策略文件方式（推荐）：enabled=true、intensity=deep、tls_decrypt.enabled=true
cythsec-tls-inspect -r capture.pcap \
  --dpi-policy /var/lib/cythsec/dpi/policy.json \
  --keylog /var/lib/cythsec/tls.keys \
  -o tls-events.jsonl

# 命令行方式：必须显式 --decrypt
cythsec-tls-inspect -r capture.pcap \
  --dpi deep --decrypt --keylog /var/lib/cythsec/tls.keys \
  -o tls-events.jsonl
```

每一行是一个事件：

```json
{"schema_version":1,"event":"tls_flow","client":"10.0.0.1:12345",
 "server":"10.0.0.2:443","server_name":"example.test",
 "cipher_suite":"TLS_AES_128_GCM_SHA256","tls_version":"1.3",
 "records":{"client":{"opened":1,"skipped":0},"server":{"opened":1,"skipped":0}},
 "messages":[{"direction":"client","bytes":42,"sha256":"…",
   "dpi":{"outcome":"identified","app":"http","confidence":"high",
          "http":{"kind":"request","method":"GET","uri":"/probe",
                  "version":"HTTP/1.1","host":"example.test"}}}]}
```

- 默认**不输出明文正文**：只给长度、SHA-256、DPI 结论与 HTTP 方法/URI/Host。
  需要正文取证时应在仓库外另行授权，不能靠本工具绕过数据最小化。
- 失败写 `tls_flow_error`，例如没有对应 client random 的 key log、标签校验失败、
  不支持的套件；不会把"解不开"写成"没有应用数据"。
- key log 必须是普通文件、非符号链接、权限 `0600`（或更严）、不超过 4 MiB。
  只读取；不复制、不导出、不打印路径以外的内容。
- 支持 TLS 1.3 的三个标准 AEAD 套件：`TLS_AES_128_GCM_SHA256`（0x1301）、
  `TLS_AES_256_GCM_SHA384`（0x1302）与 `TLS_CHACHA20_POLY1305_SHA256`（0x1303）。
- 支持 TLS 1.2 的 AES-GCM 套件：ECDHE_ECDSA/ECDHE_RSA/RSA/DHE_RSA 下的
  AES-128-GCM-SHA256 与 AES-256-GCM-SHA384（0xC02B/0xC02C/0xC02F/0xC030/
  0x009C/0x009D/0x009E/0x009F）。TLS 1.2 需要 key log 中的 `CLIENT_RANDOM`
  48 字节 master secret；ChangeCipherSpec 之前的记录跳过，之后按序号解密。
- TLS 1.2 CBC/ChaCha20 套件、0-RTT early data、握手密钥 epoch 的记录不解密；
  不支持的套件明确报 "unsupported"，不是静默跳过。TLS 1.3 的握手记录按设计
  跳过（应用密钥解不开握手记录，序号不推进）。
- 一旦解出第一条应用密钥记录，后续标签失败即报错：继续试序号会让整条流
  错位，把后面的记录解成垃圾。
- TCP 只使用连续前缀；乱序空洞、snaplen 截断与抓包起点过晚都会导致
  `client_holes`/`server_holes` 非 0 或 `not_tls`，事件中如实报告，不补造。
  抓包必须覆盖 ClientHello/ServerHello，只有应用记录而没有握手的流无法建立密钥上下文。
- ECH 下 SNI 不可见是预期结果，工具不尝试解密 ECH；`server_name` 为 `null`。

密码学实现为零第三方依赖：SHA-256/SHA-384、HMAC、HKDF、AES-128/256、AES-GCM、
ChaCha20-Poly1305 均为本仓库实现，并用 NIST/RFC 4231/RFC 5869/RFC 8439/RFC 8448
向量验证。它们只用于离线分析，不宣称抗侧信道；不用于在线密钥协商或生产加密。
