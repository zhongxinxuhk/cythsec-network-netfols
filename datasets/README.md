# datasets/ — 测试与训练数据

> 流量样本（PCAP）、DPI 测试向量、Flow 记录、特征集与模型产物。

**状态**：`dpi/` 与 `pcap/` 有实质内容且体系化，其余子目录占位。全项目共 5 个 pcap。

## dpi/ — DPI 测试向量（核心）

**设计理念：生成器 + 期望值三方互证**

- 期望值由构造参数**推出**而非解析产出 —— 避免用被测代码生成答案
- SNI / JA3 / QNAME 由 **tshark 独立复核**；`tshark.verified=false` 的条目须在 `expected.json` 中显式列出

| 文件 | 说明 |
| --- | --- |
| `generate-dpi-samples.py` | 确定性向量生成器：DNS / HTTP / TLS，覆盖畸形输入（截断、长度字段撒谎、压缩指针成环） |
| `expected.json` | 期望值真源（9984B），含 tshark 复核标记 |
| `dns-vectors.pcap` / `http-vectors.pcap` / `tls-vectors.pcap` | 协议向量包 |
| `payloads/`（21 个 .bin） | 手工构造的负向/边界样本：11 DNS + 3 HTTP + 7 TLS |

典型负向样本：`dns-question-pointer-loop.bin`（压缩指针成环）、`http-get-host.bin`（缺 Host）、`tls-ech-no-outer-sni.bin`（ECH 无外层 SNI）、`tls-sni-long.bin`（332B 超长 SNI）。

## pcap/ — 基础 pcap 样本

| 文件 | 说明 |
| --- | --- |
| `generate-samples.py` | 确定性生成器：LINKTYPE_ETHERNET=1、微秒精度、小端 |
| `sample-ipv4-mixed.pcap` | 4 报文：TCP / UDP / ICMP / 截断捕获 |
| `sample-ipv6-tcp.pcap` | 1 报文 IPv6 TCP |

## 占位子目录

`features/`（特征集）、`flows/`（流记录）、`models/`（模型产物）、`samples/`（其他样本）、`traffic/`（合成流量）—— 均 `.gitkeep`。

## 约定

- **样本必须由脚本确定性生成**，不提交手工录制的二进制（便于审计与再生成）
- 修改向量须同步更新 `expected.json` 并跑通 tshark 复核或显式标注

## 相关

- 消费方：traffic-engine DPI（`dataplane/README.md`）
- 回放工具：`tools/README.md`（`pcap-replay/` 规划中）
