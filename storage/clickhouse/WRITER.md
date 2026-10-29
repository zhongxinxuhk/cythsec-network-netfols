# FlowRecord native 批量写入器

`CYS-STO-007` 的首个实现：Go 标准库持久化队列 + 官方 `clickhouse-client` native TCP。
`JSONEachRow` 是客户端读取输入的格式；网络连接使用 native 协议，未引入第三方 Go 驱动。

## 构建与使用

```bash
bash scripts/build/build-all.sh --go
build/bin/cythsec-ch-write --version
```

先执行 `flow_records_v1.sql` 建表；需要非复制 MergeTree 的重试去重时，再执行
`flow_records_v1_dedup.sql`。库表由部署步骤管理，写入器不自动建表或修改生产设置。

```bash
export CLICKHOUSE_HOST=127.0.0.1
export CLICKHOUSE_USER=writer
# CLICKHOUSE_PASSWORD 由运行环境注入，不写入参数或队列元数据。
build/bin/cythsec-ch-write --database default --table flow_records_v1 \
  --spool /data/cythsec/spool --input flows.jsonl --resume-file
build/bin/cythsec-ch-write --database default --table flow_records_v1 \
  --spool /data/cythsec/spool --replay-only
```

客户端须在 PATH 中，也可用 `--client /path/to/clickhouse-client` 指定。
TLS native 连接使用 `--secure --port 9440`。常用限制：

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `--batch-rows` | 2000 | 每批最大条数 |
| `--batch-bytes` | 4 MiB | 每批 JSONL 大小，也限制单条记录 |
| `--flush-interval` | 1s | 低流量尾批刷新间隔 |
| `--max-pending-bytes` | 64 MiB | 含正在发送批次的队列文件总字节上限 |
| `--timeout` | 10s | 单次 native 写入超时 |
| `--attempts` | 3 | 耗尽后返回非零，原批次保留 |
| `--retry-interval` | 1s | 失败重试间隔 |
| `--resume-file` | 关闭 | 为不可变普通文件保存输入断点；须指定 `--input`，不能用于 stdin |

默认读取 stdin；`--input` 可读取 JSONL 文件。退出 0 表示此次输入与已有队列均已交付；
非零表示未完成，stderr 的 JSON 统计包含 accepted/recovered/delivered/pending 行数与字节、
尝试/失败次数和背压等待次数。统计为本次进程口径，恢复出的行单列 `recovered_rows`。

## 确认、背压和恢复

批次先写私有临时文件并 fsync，再原子改名并同步目录；新建目录的父目录也同步。
`Queue.Enqueue` 返回成功才算已接收。写入器收到同步 INSERT 成功后删除批次并同步目录。
队列满时阻塞提交方，不使用无界内存缓存；等待可由 context 取消。

队列目录通过进程锁独占并绑定主机/端口/用户/库/表/TLS。重启先重放已持久化的批次，
再读新输入。批次保存版本、随机 ID、条数、SHA256；损坏、未知文件和遗留临时文件会
明确报错，保留现场，不自动丢弃。目录只允许写入器管理。
文件断点模式会保留尚未提交的 `.pending-*.tmp` 并在 `uncommitted_temps` 中计数；
它们从未确认接收，不会被发送，相关字节由已校验源文件重新读取。普通 stdin 队列仍拒绝遗留临时文件。

**接收边界**：内存中尚未封批/持久化的尾批不是已接收记录；stdin 没有逐条持久化确认协议。
普通 stdin/未启用断点的文件模式仍须由上游保留检查点；直接重新提交整个输入可能重复。

启用 `--resume-file` 后，同一输入文件可直接用原命令重启：先重放队列，再从持久化偏移续读。
`.source` 绑定绝对路径、长度和完整 SHA256，保存已由持久化队列接收的字节偏移与累计行数；
批次同时携带源摘要和字节范围。批次先落盘、检查点后更新，重启据完整批次补齐连续高水位，
因此中断不会把已排队的记录再次封成新批次。完成文件重跑为零发送。
检查点和批次范围另有校验和，损坏/缺口/重叠会报错，不能无声跳过源数据。

只支持已完成的不可变普通文件，不跟随追加或轮转；同一路径内容改变也拒绝沿用旧断点。
支持 CRLF、空白行与末行无换行。每个源文件使用独立队列目录；下一个发布文件使用新目录。
源文件在首次读取和 EOF 时校验，必须在处理期间保持不变。
统计增加 `source_sha256/source_size/source_offset/source_rows`；退出 0 且偏移到 EOF 表示
该源文件与队列均已处理完成，可供采集端记录确认，程序不会自动删除源文件。

## 采集器的持久化发布

```bash
target/release/cythsec-ipfix-collect --pcap exported.pcap \
  --output /data/cythsec/incoming/batch-001.jsonl --durable-output
build/bin/cythsec-ch-write --database default --table flow_records_v1 \
  --input /data/cythsec/incoming/batch-001.jsonl \
  --spool /data/cythsec/spool/batch-001 --resume-file
```

`--durable-output` 先同步同目录临时文件，通过 hard_link 原子发布到新文件名，再同步目录；
已有输出名会报错并保持原文件。成功后 stderr 输出 `durable_output` JSON 回执（路径/条数/字节）。
应同时检查采集器退出码为 0。父目录须已存在，发布后文件不可改写；默认输出模式保持兼容。
这是采集**文件**的持久化交接，不为实时 UDP 增加确认协议。

每个持久化批次使用稳定 `insert_deduplication_token`；重试和进程重启沿用同一 ID，
独立提交相同内容则使用新 ID，保留合法重复记录。非复制 MergeTree 的去重窗口默认关闭，
须用专门 SQL 启用并按现场流量标定。窗口有限，超过窗口后的重放仍可能重复；
本实现是 **at-least-once**，不承诺无限期 exactly-once。
去重语义参见 [ClickHouse 官方说明](https://clickhouse.com/docs/guides/developer/deduplicating-inserts-on-retries)。

## 一键故障复验

```bash
python3 scripts/verify/check-clickhouse-writer.py
python3 scripts/verify/check-clickhouse-resume.py
```

脚本自动生成语料和 Linux 写入器，通过 Compose `writer` profile 启动独立客户端容器，
将队列挂到 `writer_spool` 命名卷。只操作当前隔离测试项目中的 ClickHouse；
停机注入结束后恢复服务，测量库/队列留作检查。

检查覆盖：正常 37 条、两次独立相同输入保留 74 条、停机后新进程重放 37 条、
真正执行 INSERT 后故意返回失败（ACK 丢失）再重放仍为 37 条、
20,182 条在有界队列满后等待并在服务恢复后排空。每项均逐字段比较完整多重集合。
报告默认 `build/storage-measurement/clickhouse-writer.json`；本次固化报告见
`docs/planning/measurements/clickhouse-writer.json`。

断点检查另覆盖：采集器发布 15 条与重复发布拒绝；已完成文件重跑零发送；等长内容变更拒绝；
20,182 条文件部分接收后重启只读剩余部分；首批 4 条已落库但未确认时对写入器容器
注入 SIGKILL，新进程恢复后仍为原 15 条。报告为 `docs/planning/measurements/clickhouse-resume.json`。

Go 的队列/边界/损坏/取消/竞态检查进 `test-all.sh --go`；真实故障检查进 CI 的
`clickhouse-storage` 作业。远端执行结果需实际运行后取得。

**当前性能边界**：每批启动一次官方客户端；停机恢复试验不是持续吞吐基线。
采集文件持久化交接和不可变文件断点已验证；实时 UDP 确认、追加文件/轮转、
物理服务器高吞吐与长期去重窗口仍未验收。
