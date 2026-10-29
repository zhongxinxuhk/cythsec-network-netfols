# 实测产物（`docs/planning/measurements/`）

这里放**测量产物**（JSON），不是文档，也不是门禁。每个产物都记着：输入文件、样本量、
方法、工具版本。**引用其中任何数字时必须一起给出样本量**（否则就是一个没有分母的平均数）。

## 落盘字节/记录（`CYS-INF-041`）

回答的是容量表里最后一个假设：*一条 `FlowRecord` 落盘到底占多少字节*。

| 产物 | 语料 | 样本量 | 未压缩 JSONL | gzip -9 |
| --- | --- | --- | --- | --- |
| `storage-ratio-real.json` | **版本库内可复现**：`datasets/dpi/*.pcap` + `datasets/pcap/sample-session-tcp.pcap` | 37 条 | 1008.3 B/记录 | **79.4 B/记录** |
| `storage-ratio-homogeneous.json` | 同质压测语料 `build/bench-pipeline/bench.pcap`（914,254 帧；**非版本库内**） | 20,182 条 | 1066.0 B/记录 | 21.0 B/记录 |
| `storage-ratio.json` | 上面两份合成**规划值** | 20,219 条 | **1066.0 B/记录**（上界） | **79.4 B/记录**（规划用这个） |

### 采样方差（`sampling-variance.json`，`CYS-TRF-053` ③）

估计量的区间按**独立伯努利**抽样推，而导出器用的是**确定性哈希**（准系统抽样）。
这份产物量的是两者差多少（`scripts/plan/measure-sampling-variance.py`，含 2 项注入）：

| 量 | 实测 | 理论 | 口径 |
| --- | --- | --- | --- |
| 留存条数 sd（600 条流 @1:4） | **5.45** | 伯努利 10.61 | 设计效应 `(5.45/10.61)² = 0.26` |
| 估计值相对误差 sd | **3.23%** | — | 产品自报相对 se 均值 **7.18%** ⇒ 区间约宽一倍 |
| 95% 区间覆盖率 | **200/200**（200 种子） | 95% | 覆盖率 100% 与"区间偏保守"一致 |

必带口径：① 语料是**合成流量**（各流大小相近、800~750 B 量级），真实流量更重尾 ⇒ 设计效应
必须**现场多种子重标定**；② 保守的前提是哈希在真实键分布上分布良好，**键分布退化时方差会超过
伯努利上界、区间偏窄**；③ 真值来自同语料**未采样**的一次运行（直接量总体），不是估计量自证。
复算：`cargo build --release && python3 scripts/plan/measure-sampling-variance.py --json <path>`。

**结论（三条，缺一条这个数就会被误用）**

1. **旧的「40 B/记录（列式压缩假设）」实测不成立**：gzip 档 79.4 B 就已是它的 2 倍，
   未压缩 JSONL 1066 B 是它的 27 倍。容量表的 `TB/天` 必须按 79.4 B 重算
   （20 Tbps / 1:1000：17.28 → **34.29 TB/天**）。
2. **gzip 档与内容重复度强相关**：同质压测语料能压到 21 B/记录，真实（多样）语料 79.4 B。
   合成规划值**取较差端**（不是平均、不是最小）—— 这条规则写在脚本里且可被判死
   （注入 `pick-best` 时必须红）。用 21 B 做规划，就是把乐观假设偷偷带回来。
3. **未压缩档才是上界**：JSONL 就是本仓当前真实的落盘格式；要降到几十字节必须**改格式**
   （列式/二进制），那时要重新测，不能沿用这里的数字。

**方法（复现时要对齐的细节）**

- 压缩用 **stdin 管道**（`gzip -9 -c`，不含 `FNAME`/`MTIME` 头）。用 `gzip -9 <file>`
  复现会多嵌文件名/时间戳，字节数会略高（实测文件名长 19 字节时多 20 B）—— 这不是测量误差，
  是两种方法本来不同。产物里记了 `gzip_method` 与 `gzip_tool`（本机 `Apple gzip 487.0.1`）。
- **压缩必须过往返校验**（解压后与原文逐字节相同）才算数：一个截断输入的实现也能给出更小的数，
  但它不是"压缩"。脚本里这是硬失败，不是警告。
- **两机复验（2026-10-05）**：同一份语料，macOS `Apple gzip 487.0.1` 与 Rocky 10.2 `GNU gzip 1.13`
  输出**字节数完全相同**（37,306 B → 2,937 B）。所以上面这些数不是某个 gzip 实现的特征，
  但 `gzip_tool` 与 `gzip_method` 仍写进产物：方法不对齐（文件参数 vs stdin）差 20 B，
  那种差异看起来像测量误差，实际是方法不同。

**复现命令**

```bash
# 1) 真实向量语料（版本库内，任何人都能复现）
mkdir -p /tmp/msr
for p in datasets/dpi/*.pcap datasets/pcap/sample-session-tcp.pcap; do
  ./target/release/cythsec-analyze -r "$p" -o "/tmp/msr/$(basename "$p" .pcap).jsonl" --quiet
done
cat /tmp/msr/{tls-vectors,dns-vectors,http-vectors,sample-session-tcp}.jsonl > /tmp/msr/all-versioned.jsonl
python3 scripts/plan/measure-storage.py --jsonl /tmp/msr/all-versioned.jsonl \
  --label "真实向量语料" --json docs/planning/measurements/storage-ratio-real.json

# 2) 同质压测语料（大样本稳定性对照；bench.pcap 需先生成）
bash scripts/verify/bench-pipeline.sh 888000 3          # 产出 build/bench-pipeline/bench.pcap
./target/release/cythsec-analyze -r build/bench-pipeline/bench.pcap -o /tmp/msr/bench.jsonl --quiet
python3 scripts/plan/measure-storage.py --jsonl /tmp/msr/bench.jsonl \
  --label "同质压测语料" --json=docs/planning/measurements/storage-ratio-homogeneous.json

# 3) 合成规划值（两档各取较差端）
python3 scripts/plan/measure-storage.py \
  --combine docs/planning/measurements/storage-ratio-real.json \
            docs/planning/measurements/storage-ratio-homogeneous.json \
  --json docs/planning/measurements/storage-ratio.json
```

**接线（谁来用这个数）**：`scripts/plan/collector-capacity.py` 默认读
`storage-ratio.json` 的 gzip 档当 `--storage-bytes-per-record`，并在报告里打印口径
（含样本量）。`test-all.sh --plan` 会核对「脚本内置默认值」与「产物里的值」是否一致
（`--verify-defaults`）——**只改一处时，"实测"这个词就变成假话**，故这条检查是门禁的一部分。

**未核验的部分（别越界引用）**

- 上述 `storage-ratio*.json` 的 21~79.4 B 都是 **gzip 后的 JSONL**；独立的 ClickHouse 实测见下。
- 只有 37 条（版本库内语料）这一档做了两机对照；20,182 条那档只用 macOS 量过
  （其输入 `build/bench-pipeline/bench.pcap` 需现场生成，未在两机上都跑）。

## ClickHouse MergeTree（2026-10-29）

`clickhouse-storage-vectors.json` 与 `clickhouse-storage-homogeneous.json` 记录
ClickHouse 26.10.2.103 stable / macOS arm64 上的单批落盘与独立进程完整读回。
37 条合成协议/会话向量为 **252.27 B/记录**，20,182 条同质压测记录为 **21.69 B/记录**，
按 active parts 总字节计（包含 part 索引/元数据）。小批固定开销与同质压缩效果不可互换。
本机两档均读回一致；Docker Desktop Linux 服务复验已于 2026-10-30 完成，见下。
重建语料和复验命令见 [存储说明](../../../storage/clickhouse/README.md)。
容量模型默认值继续对应 gzip(JSONL)，尚未建立常驻数据库部署的容量模型。

`clickhouse-storage-compose.json`：Linux arm64 / ClickHouse 26.10.2.103 服务模式，
37 / 20,182 条语料的 active parts 总字节与 macOS local 模式逐字节一致，
8 项错误输入检查通过；强制重建容器后再次逐字段读回一致。
报告包含镜像标识、命名卷、容器重建前后 ID、输入 SHA256 与表名。
复验入口 `python3 scripts/verify/check-clickhouse-compose.py` 会从当前源码重新构建分析器和语料。
Docker Desktop 的 Linux VM 不替代物理服务器实测；远端 CI 尚未运行。

## native 写入器故障复验（2026-10-30）

`clickhouse-writer.json` 记录 `cythsec-ch-write` 在独立 Compose 客户端容器中的实际结果：
正常 37 条、两次独立同内容输入保留 74 条、停机落盘后新进程恢复 37 条、
ACK 丢失后重试和新进程重放仍为原 37 条、20,182 条压力语料逐字段一致并最终排空。
观测到积压 **1,417,750 B**，小于配置 **1,600,000 B**，统计确有背压等待。
测试表启用了 10,000 个 block_id 的非复制去重窗口；不能据此承诺无限期 exactly-once。
报告含写入器版本/二进制 SHA256、输入 SHA256 与 accepted/recovered/delivered/pending 统计。
复验：`python3 scripts/verify/check-clickhouse-writer.py`。
本试验含停机、客户端启动与重试，计时不作为持续吞吐基线。

## 采集文件持久化交接与断点（2026-10-30）

`clickhouse-resume.json`：IPFIX 采集器通过 `--durable-output` 发布 15 条 DNS 流记录，
输出文件/目录同步后打印持久化回执；相同发布名拒绝覆盖。写入器 `--resume-file`
绑定路径/长度/完整 SHA256，按持久化字节偏移重启，完成文件重跑零发送，等长内容修改被拒绝。
20,182 条文件在部分接收后停机，重启先重放再续读剩余部分，最终逐字段一致；
首批 4 条已落库、客户端仍未收到确认时 SIGKILL，恢复后仍为原 15 条。
报告含采集发布回执、源摘要、输入高水位/累计行数、恢复/交付统计和强杀退出码。
复验：`python3 scripts/verify/check-clickhouse-resume.py`。
该证据针对不可变文件，不代表实时 UDP 确认、追加/轮转输入或持续吞吐已完成。
