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

- 没有真实数据库/列式格式的写入实测；21~79.4 B 都是**gzip 后的 JSONL**，不是 ClickHouse 落盘实测。
- 只有 37 条（版本库内语料）这一档做了两机对照；20,182 条那档只用 macOS 量过
  （其输入 `build/bench-pipeline/bench.pcap` 需现场生成，未在两机上都跑）。
