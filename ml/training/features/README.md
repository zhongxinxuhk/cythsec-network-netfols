# 训练特征产物（CYS-MLT-006）

当前契约是 `configs/registry/features.json` 的 **v1 / 21 维**。本模块只从包观测提取特征，或从已有 FlowRecord 投影特征，产出 CSV 与可校验清单。没有数据集切分、归一化、标签推断、模型训练或性能评估。

依赖：Python 3.9+ 标准库（含 sqlite3），从仓库根目录运行，无需 pip 安装。Python 工程与依赖锁定仍属 CYS-MLT-001。

## 包观测输入

每行一条样本，格式固定：

```json
{"schema_version":1,"sample_id":"example-1","samples":[{"side":"A","payload_len":2,"timestamp_us":0,"payload_hex":"0001"},{"side":"B","payload_len":4,"timestamp_us":1000,"payload_hex":"00010001"}]}
```

- `sample_id`：当前源内唯一的非空字符串（最长 512 字符，不含控制字符）。一份产物只对应一个显式 `source_id`；跨源关联时必须一起使用 source_id 与 sample_id。
- `side`：规范端点 A/B，**不能用发起方、上行/下行代替**。
- `payload_len`：按 `FlowSample` 契约提供的长度，u32；`timestamp_us` 为 u64 微秒。
- `payload_hex`：实际捕获的载荷字节，可为空；长度不能超过声明长度。缺失键不会默认补成零。截断载荷只参与已捕获字节的熵统计。
- `samples` 保留输入到达顺序，不按时间戳排序。空样本列表不能作为训练行；这不改变底层提取器对空流返回零向量的行为。
- 单行最多 16 MiB；空行、重复 JSON 键、非有限数、未知格式版本均拒绝。

```bash
python3 -m ml.training.features.dataset build \
  --input tests/fixtures/mlt006-observations.jsonl \
  --output build/training-features/example-unlabeled \
  --source-id synthetic-mlt006-fixture --format observations
```

## FlowRecord 输入

```bash
cargo run --offline --bin cythsec-analyze -- \
  -r datasets/pcap/sample-session-tcp.pcap -o build/example-flows.jsonl -q
python3 -m ml.training.features.dataset build \
  --input build/example-flows.jsonl \
  --output build/training-features/example-from-records \
  --source-id synthetic-session-pcap-fixture --format flow-record
```

当前只接受外层 **FlowRecord v2**、内层 **feature v1**。行标识来自 `session_id`；时间来自 `time.first_seen_us` / `last_seen_us`；特征键集合必须恰好等于生成契约。JSON 对象的键顺序可以不同，CSV 列顺序始终来自 `FEATURE_NAMES`。本模块校验消费字段的投影，不代替整个 FlowRecord 的完整协议校验。

不会重新从聚合记录推算熵/IAT；这些量只能由原始观测得到。该路径保留 Rust 已产出的特征值，独立 Python 计算的数值对齐由观测输入与 Rust 编译内嵌夹具另行验证。

## 显式标签

无标签参数时，不生成 `label` 列，清单 `labels.status=absent`。DPI 应用名、风险分数和特征值不会被当成标签。

标签文件每行固定为：

```json
{"sample_id":"example-1","label":"explicit-annotation"}
```

使用标签必须同时提供来源说明；缺标签、多余标签、重复标注、空标签均失败。标签值和其正确性来自外部标注，本工具只证明匹配完整性，不证明标注正确。

```bash
python3 -m ml.training.features.dataset build \
  --input tests/fixtures/mlt006-observations.jsonl \
  --output build/training-features/example-labeled \
  --source-id synthetic-mlt006-fixture --format observations \
  --labels tests/fixtures/mlt006-labels.jsonl \
  --label-source 'synthetic fixture grouping only; not real traffic labels'
```

入库的三个观测样本与两类分组标签全部是**合成测试夹具**。它们用于检查接口与标签连接，不是攻击/正常流量的真实标注数据集。

## 输出与完整性校验

输出目录必须不存在，不支持覆盖。目录包含：

- `features.csv`：`sample_id,first_seen_us,last_seen_us`，可选 `label`，随后是严格按契约排列的 21 个数值特征。
- `manifest.json`：产物版本、来源标识/原始输入 SHA-256、实际生成绑定的契约指纹、列顺序、行数、CSV SHA-256，以及显式标签的来源/输入摘要/类别计数。无墙钟时间与本机绝对路径，同字节输入与配置产生同字节产物。

训练侧必须只选择清单 `feature_schema.names` 的 21 列作为特征；标识、绝对时间和标签均为元数据，不应当作模型特征。

```bash
python3 -m ml.training.features.dataset validate build/training-features/example-labeled
```

构建时使用临时目录与磁盘 SQLite 索引检查重复标识和标签连接，逐行处理输入，不持有整份样本/标注列表；Python 内存仍与最大行大小、类别数和解析器开销有关。输出目录独占创建，CSV 发布后最后发布 manifest；**有目录不等于产物完成**。读取方必须先执行校验，缺清单、哈希不符、列顺序/维数错误、重复行、非法数值、类别计数不符均拒绝。

SHA-256 用于检查一致性，不是来源真实性签名。构建失败不会生成完成清单，发布失败会回滚本次新建目录。清单不声明防泄漏切分或可用于生产训练；时间/分组切分由 CYS-MLT-004 另行实现。

## 验收入口

```bash
python3 -m unittest discover -s tests/ml -p 'test_feature_dataset.py' -v
bash scripts/test/test-all.sh --rust
```

后者包含向量契约与本模块验收，默认全集和现有 CI Rust job 也执行同一入口。Rust/pcap 夹具须先由默认测试向量阶段生成（统一测试入口会自动生成）；全新克隆若单独运行 unittest，应先运行 `bash scripts/test/test-all.sh --rust`。
