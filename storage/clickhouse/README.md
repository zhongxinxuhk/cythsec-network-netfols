# FlowRecord v1：MergeTree 字段契约与落盘测量

`flow_records_v1.sql` 对齐 Rust `record::FlowRecord` 的 9 个顶层字段与
`feature::FEATURE_NAMES` 的 21 个特征。嵌套对象使用命名 Tuple；计数保持 UInt64，
微秒时间保持 UInt64，IP 保持原始字符串（IPv4/IPv6 均可），缺失证据保留 Nullable，
不把 `null` 改写成零。表约束拒绝非 v1 的记录/特征版本。

这是当前流记录的第一份存储契约。按 UTC epoch 微秒划日分区，以协议、规范端点、
时间、会话号排序，采用引擎默认压缩；不设置 TTL，避免测量过程自动删除旧向量。
多表 schema 与月分区/TTL 仍需后续任务；native 批量写入、背压和失败落盘重放已实现，
见 [写入器说明](WRITER.md)。

## 复验

需要 Python 3、Cargo、ClickHouse 独立二进制。引擎通过 `local --path` 在临时目录运行，
每次测量创建新库，退出后清理。无需启动服务器。

```bash
CLICKHOUSE_BIN=/absolute/path/to/clickhouse bash scripts/verify/check-clickhouse-storage.sh
```

脚本从 Rust 分析器产出真实 FlowRecord，再执行写入和**独立新进程**读回，按完整记录的
多重集合比较（忽略行顺序、保留重复次数），不是仅比条数或字节总量。覆盖 UInt64 最大值、
IPv6、Unicode/引号/换行/反斜杠、特征 null、风险评分 null/0、重复行和末行无换行。
8 项真实路径故障注入：记录版本、特征版本、嵌套/顶层缺字段、嵌套/顶层未知字段、
端口溢出、非空计数写 null，均须被拒绝。缺 ClickHouse 返回 3（未核验），不当作通过。

比对器的纯 Python 自证进入 `test-all.sh --plan`；真实引擎检查进入 CI
`clickhouse-storage` 作业，固定 Linux 版本 26.10.2.103，并核对官方下载的 SHA512。
CI 配置已加入；远端执行结果需实际运行后取得。

## 重建两档测量语料

```bash
python3 datasets/pcap/generate-samples.py
python3 datasets/dpi/generate-dpi-samples.py
cargo build --release --offline --bin cythsec-analyze
mkdir -p build/storage-measurement
for p in datasets/dpi/*.pcap datasets/pcap/sample-session-tcp.pcap; do
  target/release/cythsec-analyze -r "${p}" -o "build/storage-measurement/$(basename "${p}" .pcap).jsonl" --quiet
done
cat build/storage-measurement/tls-vectors.jsonl build/storage-measurement/dns-vectors.jsonl \
    build/storage-measurement/http-vectors.jsonl build/storage-measurement/sample-session-tcp.jsonl \
    > build/storage-measurement/vectors.jsonl
python3 datasets/pcap/generate-bench.py build/storage-measurement/bench.pcap 20182 50
target/release/cythsec-analyze -r build/storage-measurement/bench.pcap \
  -o build/storage-measurement/homogeneous.jsonl --quiet
python3 scripts/plan/measure-clickhouse.py --clickhouse /absolute/path/to/clickhouse \
  --jsonl build/storage-measurement/vectors.jsonl --label '版本库合成协议与会话向量（37条）' \
  --json docs/planning/measurements/clickhouse-storage-vectors.json
python3 scripts/plan/measure-clickhouse.py --clickhouse /absolute/path/to/clickhouse \
  --jsonl build/storage-measurement/homogeneous.jsonl --label '同质压测语料（20182条）' \
  --json docs/planning/measurements/clickhouse-storage-homogeneous.json
```

输入 SHA256 用于确认重建语料一致；JSON 中另记引擎版本、二进制/DDL SHA256、平台与测量时间。
语料来自合成向量和合成压测流量，不是运营商现场样本。

## 2026-10-29 本机结果

ClickHouse **26.10.2.103 stable**、macOS arm64、单批写入；两档均逐字段读回一致。

| 语料 | 条数 | active part 总字节 | 压缩列流字节 | part 字节/记录 |
| --- | ---: | ---: | ---: | ---: |
| 协议/会话向量 | 37 | 9,334 | 3,028 | 252.27 |
| 同质压测 | 20,182 | 437,765 | 427,917 | 21.69 |

小样本的 part 元数据开销占比高；21.69 B/记录只对应当前同质语料。`bytes_on_disk` 按
`system.parts WHERE active` 汇总，包含索引、marks 和 part 元数据；工作目录文件逻辑长度
另行报告。它们都不含文件系统块取整、复制、备份与合并峰值，不能直接当生产容量承诺。
写入计时包含进程启动、开表、JSON 解析、落盘与退出，不作为常驻服务吞吐基线。
容量模型仍引用 **gzip(JSONL) 79.4 B/记录**，其存储格式口径保持明确。

引擎字段口径参见 [system.parts 官方文档](https://clickhouse.com/docs/reference/system-tables/parts)。

## Docker Compose 服务复验

```bash
python3 scripts/verify/check-clickhouse-compose.py
docker compose -f deploy/docker/compose.storage-test.yml ps
docker compose -f deploy/docker/compose.storage-test.yml exec clickhouse \
  clickhouse-client --user cythsec_test --password local_storage_test
```

一键脚本等待服务健康后，从当前源码重新构建 Rust 分析器和两档测量语料，复用上面的
逐字段比对及 8 项坏输入检查，在 **Linux 常驻服务**上写入两档记录。随后强制重建容器，
确认容器 ID 确实改变，再逐字段读回两档数据，验证命名卷持久化。
每次使用唯一数据库名；仅删除本次故障注入库，测量库和服务保留供检查。
报告默认保存到 `build/storage-measurement/clickhouse-compose.json`，可用 `--json` 指定路径。

编排为 `deploy/docker/compose.storage-test.yml`，项目名 `cythsec-storage-test`，
固定 ClickHouse 26.10.2.103，内部测试网络，不映射宿主机端口，测试凭据只用于该编排。
数据放在项目的 `clickhouse_data` 命名卷。停止编排并保留数据：

```bash
docker compose -f deploy/docker/compose.storage-test.yml down
```

服务写入计时含 `docker exec`、客户端启动和传输开销；Docker Desktop Linux VM 的结果
不替代物理 Linux 服务器现场复验。默认只启 ClickHouse；新增 `writer` profile 用于
独立 native 写入器及命名卷队列的故障复验，入口见 [写入器说明](WRITER.md)。
PostgreSQL/Redis 不属于这份测试编排。

### 2026-10-30 服务模式实测

Docker Desktop / Linux arm64、ClickHouse 26.10.2.103：37 条向量与 20,182 条同质记录
均逐字段读回一致，active parts 总字节分别为 **9,334 B / 437,765 B**，
即 **252.27 / 21.69 B/记录**，与 macOS local 模式逐字节一致。
8 项错误输入检查全部通过；强制重建后的容器 ID 与原容器不同，两档数据再次完整读回一致。
报告见 `docs/planning/measurements/clickhouse-storage-compose.json`。

本次保留的测量库为 `cythsec_measure_4248dad67acc`，表 `flow_records_v1_10`（37 条）与
`flow_records_v1_11`（20,182 条），命名卷为 `cythsec-storage-test_clickhouse_data`。
首次 Docker 拉取超时后，通过宿主机获取同一官方 ARM64 镜像，逐层校验 SHA256 和解压后
diff_id，再使用 `docker load` 导入；报告记录的是 Docker 实际导入后的本地镜像标识。
远端 CI 尚未运行。
