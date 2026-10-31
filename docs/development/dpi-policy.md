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
  - `deep`：窗口至少 4096 字节；配置密钥日志后尝试解密 TLS 1.3。
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

# 命令行覆盖强度；deep + keylog 才尝试 TLS 解密
cythsec-analyze -r capture.pcap --dpi deep --dpi-keylog /var/lib/cythsec/tls.keys
```

统计行会打印实际生效的策略，便于把"声明关闭"与"实际没跑"对上：

```text
[cythsec-analyze] dpi enabled=false intensity=off modules_disabled=0
```

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
