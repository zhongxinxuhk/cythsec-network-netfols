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

- 本节三个产物（21~79.4 B）都是**gzip 后的 JSONL**，不是 ClickHouse 落盘实测；
  列式那档自 2026-10-22 起另有实测产物，见下一节「列式落盘字节/记录」。
- 只有 37 条（版本库内语料）这一档做了两机对照；20,182 条那档只用 macOS 量过
  （其输入 `build/bench-pipeline/bench.pcap` 需现场生成，未在两机上都跑）。

## 列式落盘字节/记录（`columnar-*.json`，`CYS-INF-041` 收尾 / `CYS-STO-002`、`CYS-STO-007`）

回答的是容量表旁边那句**没人量过的话**：「换成列式数据库能压到几十 B/记录」。
2026-10-22 本机把它换成了实测。数字来自**真实 ClickHouse 落进 MergeTree 之后数 part 目录的字节**
（`*.bin` 记为列数据，`*.mrk2/*.idx/*_count.txt` 等记为索引/元数据），不是估算。

| 产物 | 语料 | 条数 | JSONL 未压缩 | JSONL+gzip9 | Native 未压缩 | **CH 默认 LZ4** | **CH 我们的 DDL** | 可进容量表 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `columnar-real.json` | 真实向量（版本库内） | 37 | 1008.27 | 80.24 | 514.54 | 141.49 | 139.16 | ✗ 小样本，part 固定开销主导 |
| `columnar-bench.json` | 同质压测 `bench.pcap` | 20,182 | 1066.05 | 21.04 | 347.06 | 22.81 | **5.11** | ✓ |
| `columnar-diverse.json` | 多样合成 `bench-diverse.pcap` | 20,000 | 1082.42 | 130.16 | 346.91 | 138.32 | **78.50** | ✓ |
| `columnar.json` | 上面两档取**较差端** | 40,182 | — | — | — | — | **78.50 B/记录** | ✓ 这就是规划值 |

必带口径（缺一条这个数就会被误用）：

1. **「列式」本身不省字节，省字节的是按列编解码器。** 同一份 schema 只差 CODEC/LowCardinality：
   多样语料 138.32 → 78.50（1.8×）、同质语料 22.81 → 5.11（4.5×）。而 **CH 默认 LZ4 档并不比
   gzip(JSONL) 好**（多样语料 138.32 vs 130.16，甚至略输）—— 所以「迁到列式数据库就省几倍」
   这句话在本仓的证据里**不成立**，收益来自 DDL 里那串 CODEC 选择。
2. **规划值 78.5 B/记录与 gzip(JSONL) 的 79.4 基本持平** ⇒ 容量表的 `TB/天` 不会因为
   "改用列式"而改变量级（34.29 → 33.91 TB/天）。这条是本档最重要的结论。
3. **它依赖 `storage/clickhouse/001_flows.sql` 的 CODEC/LowCardinality 选择**；换 DDL 必须重测。
   产物里把这句话写成了字段（`not_a_claim`），`collector-capacity.py` 缺它就拒绝读数。
4. **两档大样本语料都是本仓生成器合成的**（`generate-bench.py --profile homogeneous|diverse`）。
   `diverse` 档的多样性由脚本里的端口池/地址池/域名池给，**不代表任何现场**；
   37 条那档虽然是版本库内真实向量，但样本太小（`usable_for_capacity: false`）。
   ⇒ 现场必须用自己的流量重标定，`--combine` 只接受 ≥5,000 条且真的落进过 ClickHouse 的档。
5. 语料是页缓存热的 macOS 单机数字；Rocky 复验只做过了 gzip 档（见上一节），
   **列式档尚未在两机上对照**（那台机上没有 ClickHouse 二进制）。

### 一条**待决**：gzip 档的"较差端"规则与多样合成语料冲突

按本节与上一节共同的规则——**规划取较差端**——把多样合成语料测出的
gzip(JSONL) **130.16 B/记录**计入后，`storage-ratio.json` 的 gzip 规划值就应从 79.4 抬到 130.16
（20 Tbps×1:1000 ⇒ 34.29 → **56.23 TB/天**）。本批**没有**这么改，理由是：`diverse` 档的多样性
由生成器**刻意最大化**（每条流一个随机域名/SNI），真实省网流量的popular host 呈重尾分布、
重复度高于它，130.16 更像**上界**而不是规划值。但这条判断本身需要现场语料才能定，
所以记成待决事项（HANDOFF §8 第一梯队第 4 项）：**要么拿现场语料重测，要么把 gzip 规划值抬到
130.16 并在对外口径里改用列式的 78.5**——两件事都不该悄悄做。

### 复现命令

```bash
# 0) 参考实现：任选一种 —— PATH 上的 clickhouse / --clickhouse <路径> / 环境变量 CLICKHOUSE
cargo build --release -p traffic-engine --bin cythsec-analyze --bin cythsec-dump-ddl

# 1) 真实向量档（正确性对照，不进容量表）
python3 scripts/plan/measure-columnar.py \
  --label "真实向量语料" --pcap datasets/pcap/sample-session-tcp.pcap datasets/dpi/*.pcap \
  --analyze target/release/cythsec-analyze --clickhouse "$CH" \
  --json docs/planning/measurements/columnar-real.json

# 2) 同质压测档（bench.pcap 与历史口径同源，需先生成）
python3 datasets/pcap/generate-bench.py build/bench-pipeline/bench.pcap 20000 50
python3 scripts/plan/measure-columnar.py --label "同质压测语料" \
  --pcap build/bench-pipeline/bench.pcap --analyze target/release/cythsec-analyze \
  --clickhouse "$CH" --json docs/planning/measurements/columnar-bench.json

# 3) 多样合成档（新档；--profile homogeneous 是默认值，逐字节维持历史行为）
python3 datasets/pcap/generate-bench.py build/bench-pipeline/bench-diverse.pcap 20000 50 --profile diverse
python3 scripts/plan/measure-columnar.py --label "多样合成语料" \
  --pcap build/bench-pipeline/bench-diverse.pcap --analyze target/release/cythsec-analyze \
  --clickhouse "$CH" --json docs/planning/measurements/columnar-diverse.json

# 4) 合成规划值（任一档不可用 ⇒ 整体不可用，不许"挑一个能用的"）
python3 scripts/plan/measure-columnar.py --combine \
  docs/planning/measurements/columnar-bench.json \
  docs/planning/measurements/columnar-diverse.json \
  --json docs/planning/measurements/columnar.json

# 5) 容量模型改用列式档
python3 scripts/plan/collector-capacity.py --storage-format columnar
```

**接线**：`collector-capacity.py --storage-format columnar` 默认读 `columnar.json`；
`--verify-defaults`（挂在 `test-all.sh --plan`）**同时核对 gzip 与列式两档**的内置默认值 ↔ 产物，
只改一处就会判红。列式字节格式本身的关口是 `test-all.sh --columnar`
（`scripts/verify/check-columnar.sh`）。

**测这一档时抓出的两个真缺陷**（都不是"环境有问题"，是脚本自己写错）：

1. `baseline_ddl()` 用「找第一个 `)`」剥 `CODEC(...)`，遇到 `CODEC(Delta(4), ZSTD(1))` 这类
   嵌套就把 `, ZSTD(1))` 留在原地 ⇒ ClickHouse 报 `Unmatched parentheses` 拒收，
   ③ 档（无 CODEC 对照）静默变成「未核验」，而报告照样打印「净收益 N×」。
   现在按平衡括号扫描（并跳过单引号字符串），且 `check_baseline_ddl()` 四项自检
   （行数、列名集合、残留子句、整篇括号配平）不合格就**硬失败**。
2. staging 表名用 `ddl.replace("flows", table, 1)` 改 —— 而这份 DDL 里 "flows" **第一次出现
   在文件头的「重新生成」注释里**，于是改在了注释上，CREATE 语句仍是 `flows`
   ⇒ `INSERT INTO flows_default` 报 UNKNOWN_TABLE。现在 `rename_table()` 只认 CREATE 语句那一处，
   且 `_looks_like_our_sql_defect()` 把 UNKNOWN_TABLE/SYNTAX_ERROR 归为**缺陷**（判红），
   只有"二进制找不到"这类才算未核验。两条都在 `measure-columnar.py --self-test` 里有反向注入。
