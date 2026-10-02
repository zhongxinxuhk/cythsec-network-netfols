# capture/ — 流量采集测试与抽象

> 不同收包后端（pcap / AF_PACKET / AF_XDP / XDP / DPDK）的抓包与回放验证层。

**状态**：🚧 目录级规划，仅 `pcap/` 有实质设计文档。

⚠️ **注意：采集后端的实际实现在 `dataplane/packet-engine/src/backends/`**（`pcap_file.cpp`、`af_packet.cpp`、`bpf_capture.cpp` 等）。本目录承载的是设计决策与验证材料，不是运行时代码。

## 目录状态

| 子目录 | 状态 | 内容 |
| --- | --- | --- |
| `pcap/` | ✅ 有设计文档 | `README.md`（97 行）：pcap 自实现决策与格式要点 |
| `af_packet/` | 🚧 空 | 实现见 `dataplane/packet-engine/src/backends/af_packet.cpp` |
| `af_xdp/` | 🚧 空 | 规划中（packet-engine 对应目录也是占位） |
| `xdp/` | 🚧 空 | 规划中 |
| `dpdk/` | 🚧 空 | 规划中 |

## pcap/ 设计要点（详见 `pcap/README.md`）

1. **决策 CYS-PKT-006**：自行实现 pcap 解析，不引入 libpcap（本机 pkg-config/头文件/库均不可链接）
2. **格式要点**：4 种魔数变体（微秒/纳秒 × 大小端）、`incl_len` 与 `orig_len` 区别、linktype 仅支持 Ethernet(1)、pcapng 魔数 `0x0a0d0d0a` 显式拒绝、截断防护
3. **零拷贝语义**（CYS-PKT-017）：`cythsec-parse` 用法与 tcpdump 交叉验证

## 相关

- 实现与构建：`dataplane/README.md`
- 测试样本：`datasets/README.md`（`datasets/pcap/`）
