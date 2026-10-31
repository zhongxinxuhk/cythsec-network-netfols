# dataplane/ — 数据平面

> 整条链路的数据入口：高速收包（C/C++）与流量分析（Rust）。

| 子模块 | 语言 | 状态 |
| --- | --- | --- |
| `packet-engine/` | C/C++17 | ✅ 核心链路已实现（解析/采集/共享通道），高速后端占位 |
| `traffic-engine/` | Rust | ✅ Flow/Session/DPI/共享环消费已实现，子 crate 拆分占位 |

---

## packet-engine/（C/C++17）

零第三方依赖：不链 libpcap/libbpf/DPDK，pcap 读写自实现。Linux 走 AF_PACKET，macOS/BSD 走 BPF，按平台条件编译。

**构建产物**（`dataplane/packet-engine/CMakeLists.txt`）：

- 静态库 `packet_engine`
- CLI 可执行 5 个：
  - `hello_packet` — 冒烟
  - `cythsec-parse` — pcap 解析演示（零拷贝）
  - `cythsec-dump-abi` — 通道 ABI parity 输出（与 Rust 侧逐行 diff）
  - `cythsec-ring-feed` — pcap → 共享内存环生产端
  - `cythsec-capture` — 跨平台实时抓包
- CTest 测试 6 个：`test_packet` / `test_parser` / `test_pcap` / `test_channel_abi` / `test_channel_producer` / `test_live_capture`

**源码结构**（`src/` + `include/packet_engine/`，共 38 个 .cpp/.h）：

```
src/parser/        # 零拷贝 L2/L3/L4 解析（ethernet/ipv4/ipv6/tcp/udp/icmp）
src/backends/      # 采集后端：pcap_file / iface_list / af_packet / bpf_capture + 工厂
src/channel/       # SPSC 共享内存环生产端（region / producer）
include/.../abi_gen.h  # 冻结 ABI 契约（35 条 static_assert，由 codegen 生成）
```

**占位目录**（仅 `.gitkeep`，待实现）：`xdp/` `ebpf/` `af_xdp/` `dpdk/` `buffer/` `dispatcher/` `rss/`。CMake 选项 `ENABLE_XDP` / `ENABLE_AF_XDP` / `ENABLE_DPDK` 默认 OFF，目录无实现时自动落 INTERFACE 占位目标。

**构建**：

```bash
cmake -B build && cmake --build build && ctest --test-dir build
```

---

## traffic-engine/（Rust）

⚠️ 当前是**单包实现**（`crates/` 下 9 个子目录均为 `.gitkeep` 占位），Cargo.toml 注释明确：统一在单包内演进，子 crate 后续拆分。依赖为空 —— 零第三方依赖。

**产物**：lib `traffic_engine` + 主要 bin：

- `traffic-engine` — 演示入口（支持 `--version`）
- `dump-abi` — ABI 输出，与 C++ 侧 `cythsec-dump-abi` 逐行 diff
- `ring-consume` — 共享内存环消费端，解码为 Flow
- `cythsec-analyze` — 离线 pcap → FlowRecord（JSONL/IPFIX/Native）
- `cythsec-tls-inspect` — NSS key log → TLS 1.3 应用记录解密 → DPI JSONL 事件

**模块布局**（约 6700 行）：

| 模块 | 职责 |
| --- | --- |
| `src/flow/` | 五元组 `FlowKey`（实现 `Ord` 保证输出确定性）+ `Packet` |
| `src/session/` | 双向会话（TCP SYN→Established→Closed 状态雏形） |
| `src/dpi/` | 三级递进检测：端口 → 载荷特征 → unknown；DNS/HTTP/TLS/MD5 子模块；`policy.rs` 负责总开关/强度/逐协议开关，策略契约见 [DPI 策略](../docs/development/dpi-policy.md) |
| `src/tlsdecrypt/` | TLS 1.3 key log 解析、记录层 AES-128/256-GCM 解密与 SHA-256/384 HKDF；零第三方依赖，仅离线分析使用 |
| `src/channel/` | 跨语言共享内存消费端：mmap+校验、SPSC 内存序、以太帧→五元组解码 |
| `src/attributes_gen.rs` | 属性字典 Rust 绑定（codegen 生成） |

DPI 建议采集层交付 512 字节（`DEFAULT_INSPECT_BYTES`）。

**构建**：

```bash
cargo build --release && cargo test
```

---

## 跨语言端到端链路

```
pcap ──► cythsec-ring-feed (C++) ──► mmap 共享环 ──► ring-consume (Rust) ──► Flow
              生产端                 ABI 契约冻结          消费端
```

ABI 契约由 `configs/registry/channel-abi.json` 单一真源生成双端代码，一致性由 `scripts/verify/check-channel-parity.sh` 把关（产物留 `build/parity/`）。

## 相关

- 采集后端设计决策：`capture/pcap/README.md`
- ABI 真源：`configs/README.md`
- 端到端验证：`scripts/verify/e2e-shared-ring.sh`
