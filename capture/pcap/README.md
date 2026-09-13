# capture/pcap — 经典 pcap 文件抓取与解析

本目录对应 `CYS-CAP-001` 的文档部分，说明 packet-engine 中 pcap 文件后端的
两个关键决策：**为什么不用 libpcap** 与 **pcap 格式要点**。

## 决策一：自行实现 pcap 解析，不引入 libpcap（CYS-PKT-006）

### 本机检测证据（libpcap 不可链接）

```
$ pkg-config --exists libpcap        → 未找到
$ ls /usr/lib /usr/local/lib /opt/homebrew/lib 下 libpcap*  → 无
$ ls /usr/include /usr/local/include /opt/homebrew/include 下 pcap.h → 无
$ tcpdump --version                  → tcpdump version 4.99.1（仅有二进制，未暴露可链接库）
$ 仓库内 *.pcap / *.pcapng 样本       → 0 个
```

结论：**libpcap 的头文件与库都不可链接**。因此 packet-engine 的 pcap 后端
（`dataplane/packet-engine/src/backends/pcap_file.cpp`）**自行解析经典 pcap 文件格式**，
不依赖任何第三方库。

### 为什么这样更好（而非退而求其次）

1. **与本工程零第三方依赖原则一致**：`packet-engine` 至今不依赖 gtest/Catch2，
   `traffic-engine`（Rust）也是零依赖；自实现 pcap 解析延续了这一约束，可在
   完全离线的环境构建与测试。
2. **不需要 root、不需要网卡**：纯文件读取，测试可在任意机器跑（CI、笔记本、容器）。
3. **格式极简、可控性高**：24 字节全局头 + 每包 16 字节记录头，自行解析比依赖
   外部库更易审计、更易针对畸形输入做边界防护。

> 注：`tcpdump 4.99.1` 作为**独立预言机**仍可用于交叉验证（见下方格式要点与测试）。

## 决策二：经典 pcap 格式要点（实现必须正确处理）

### 1. 四种魔数变体（全部支持，按字节判定，不靠猜）

| 魔数（主机序解读） | 字节序 | 时间精度 |
| --- | --- | --- |
| `0xa1b2c3d4` | 本机序 | 微秒 |
| `0xa1b23c4d` | 本机序 | 纳秒 |
| `0xd4c3b2a1` | 反序（大端写入） | 微秒 |
| `0x4d3cb2a1` | 反序（大端写入） | 纳秒 |

实现：读出 4 字节后同时与四个魔数比较，据此确定「精度 + 是否需要 swap」；
反序文件的所有多字节字段（ts、incl_len、orig_len、snaplen、network）都做字节序转换。
`PacketBuffer::timestamp_ns` 统一为纳秒：微秒文件 `ts_frac × 1000`，纳秒文件直接用 `ts_frac`。

### 2. incl_len 与 orig_len 的区别（关键）

- `incl_len`：**文件里实际存**的字节数（捕获长度）。
- `orig_len`：**线上原始**长度。
- 映射：`PacketBuffer.caplen = incl_len`，`PacketBuffer.wirelen = orig_len`。
- `incl_len < orig_len`（截断捕获）是**常态，不是错误**；解析器一律以 `caplen` 为硬边界。
- `incl_len > snaplen`（且 snaplen≠0）才是畸形，报 `kMalformed`。

### 3. linktype（全局头 network 字段）

- `1` (LINKTYPE_ETHERNET)：正常解析。
- 其他（如 `101` RAW、`113` LINUX_SLL）：返回 `kUnsupported` 并给出可读原因，**不崩溃**。
  当前版本仅支持 Ethernet。

### 4. pcapng 检测与拒绝

pcapng 魔数为 `0x0a0d0d0a`。识别到即明确拒绝并提示「这是 pcapng 格式，当前仅支持经典 pcap」。
用户拿错文件时的报错质量，决定工具的可用性。

### 5. 截断（Truncated）

- 文件 < 24 字节：全局头截断。
- 记录头 < 16 字节：记录截断。
- `incl_len` 超出文件剩余字节：包数据不完整。
以上均返回 `kTruncated`，绝不越界访问。

## 零拷贝语义

`PacketBuffer::data` 指向后端内部读缓冲（`pcap_file` 一次性读入整个文件）。
生命周期契约：**该指针在下次 `rx_burst` 调用或 `close()` 之前有效**。
这是 `CYS-PKT-017` 零拷贝约束在文件后端上的延续。

## 用法

```bash
# 解析单条十六进制 / 二进制报文
cythsec-parse <hex>
cythsec-parse -f <raw.bin>

# 遍历 pcap 文件内全部报文并打印统计摘要
cythsec-parse -r <file.pcap>
```

交叉验证（可选，需权限）：
```bash
sudo tcpdump -i lo -c 20 -w /tmp/real.pcap 'tcp or udp' &
sleep 3 && kill %1
cythsec-parse -r /tmp/real.pcap        # 包数 / caplen / wirelen 应与 tcpdump -r 一致
tcpdump -v -r /tmp/real.pcap | less     # 逐包 length 可与 wirelen 比对
```
