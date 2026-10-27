# 首批实现字段显示字典

日期：2026-10-27；来源：`src/api/analytics.ts`实际查询DTO。字段路径在TypeScript中绑定DTO键。

本表与P17页面对应。nullable指叶字段自身；所有statistics子字段仍受整窗抑制，tcp_quality子字段还受父对象未发布影响。没有发布的生产者字段不列作已查询指标。

| 字段路径 | 显示名称 | 分类 | 单位 | 叶值可空 | 定义 | 发布条件 | 显示限制 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `window_start_seconds` | 窗口起点 | 窗口口径 | Unix秒 | 否 | 输入时间戳按窗口宽度向下对齐后的起点。 | 有输入记录的窗口。 | 查询区间按起点匹配[from,to)；缺失窗口不补造零流量。 |
| `window_seconds` | 窗口宽度 | 窗口口径 | 秒 | 否 | 生产者声明的聚合窗口宽度。 | 每个已返回窗口。 | 首尾窗口可能只有部分覆盖，不能用名义窗宽直接计算pps或Gbps。 |
| `sampling_interval` | 整流采样间隔 | 窗口口径 | 1:N | 否 | 窗口内约1/N双向流进入有界采样状态。 | 每个已返回窗口。 | 不是按包独立抽样；采样观察值不乘N外推。 |
| `suppressed` | 整窗抑制 | 窗口口径 | 布尔 | 否 | 窗口样本流数不足时不发布statistics。 | 每个已返回窗口。 | true时各统计保留未发布，不能显示为零。 |
| `statistics.contributing_sampled_flows` | 贡献样本流数 | 承载统计 | 流 | 否 | 已接纳并参与当前窗口统计的不同采样流数。 | statistics已发布。 | 流数不是用户数；不同窗口不能去重为设备数。 |
| `statistics.tcp_packets` | TCP报文数 | 承载统计 | 包 | 否 | 可解码且归属本窗的TCP记录数量。 | statistics已发布；不受流采样影响。 | 不是全部线上包数；解码失败与非首片等诊断另外记录。 |
| `statistics.udp_packets` | UDP报文数 | 承载统计 | 包 | 否 | 可解码且归属本窗的UDP记录数量。 | statistics已发布；不受流采样影响。 | 不是全部线上包数；解码失败与非首片等诊断另外记录。 |
| `statistics.other_ip_packets` | 其他IP报文数 | 承载统计 | 包 | 否 | 可解码且归属本窗的非TCP/UDP的IP记录数量。 | statistics已发布；不受流采样影响。 | 不是全部线上包数；解码失败与非首片等诊断另外记录。 |
| `statistics.tls_record_candidate_packets` | TLS记录头候选 | 承载统计 | 包 | 是 | 采样流内载荷起点满足TLS记录头、长度与完整捕获条件的报文数。 | 整窗与TLS子组均满足最小流数。 | 不重组跨段记录，不解密；不是TLS会话数、具体应用或VPN数量。 |
| `statistics.quic_long_header_candidate_packets` | QUIC长头候选 | 承载统计 | 包 | 是 | 采样流内符合已支持QUIC长头格式与捕获边界的报文数。 | 整窗与QUIC子组均满足最小流数。 | 不含短头、Retry、版本协商或未知版本；不是加密真实性验证。 |
| `statistics.tcp_quality.retransmission_candidates` | 重传候选 | TCP质量 | 次 | 否 | 段末序号未超过当前方向已推进的序号游标。 | statistics与tcp_quality均已发布。 | 基于可见TCP序号的候选；缺口不等于链路丢包，缺少judged_segments分母时不算比例。 |
| `statistics.tcp_quality.out_of_order_candidates` | 乱序候选 | TCP质量 | 次 | 否 | 旧新序号重叠或在已见高水位之前补洞。 | statistics与tcp_quality均已发布。 | 基于可见TCP序号的候选；缺口不等于链路丢包，缺少judged_segments分母时不算比例。 |
| `statistics.tcp_quality.forward_gap_candidates` | 前向缺口候选 | TCP质量 | 次 | 否 | 当前段起点位于连续序号游标之后。 | statistics与tcp_quality均已发布。 | 基于可见TCP序号的候选；缺口不等于链路丢包，缺少judged_segments分母时不算比例。 |
| `statistics.tcp_quality.response_delay_samples` | SYN响应时差样本 | TCP质量 | 样本 | 是 | 首次无歧义SYN到反向SYN-ACK的有效时间差样本数量。 | 独立贡献流达到发布门槛；每流每窗最多一次。 | 不是端到端完整RTT、单向时延或网站加载时延。 |
| `statistics.tcp_quality.response_delay_upper_bounds_ms` | 时差桶上界 | TCP质量 | 毫秒数组 | 否 | 各非累积直方图桶的右边界；首桶从0起。 | tcp_quality已发布；与histogram按索引配对。 | 数组元素null表示无穷上界；不能由分桶内插生成精确p95。 |
| `statistics.tcp_quality.response_delay_histogram` | SYN响应时差直方图 | TCP质量 | 样本数组 | 是 | 每个时差桶内有效样本数，采用非累积桶。 | 有效时差样本达到最小流数。 | 显示每桶范围与样本数；空值表示未发布，不补为全零分布。 |
| `statistics.integrity.records` | 输入记录 | 采集完整性 | 条 | 否 | 当前窗口归属的输入PCAP记录数。 | statistics已发布。 | 不等于成功解码数或线上总包数。 |
| `statistics.integrity.snaplen_truncated` | 捕获截断 | 采集完整性 | 条 | 否 | 捕获长度小于原始长度的记录数。 | statistics已发布。 | 不是网络丢包率。 |
| `statistics.integrity.decode_incomplete` | 解码不完整 | 采集完整性 | 条 | 否 | 头部不足或无法完整解码的记录数。 | statistics已发布。 | 处理完成不代表所有报文均可解码。 |
| `statistics.integrity.unparsed_fragments` | 未解析非首片 | 采集完整性 | 条 | 否 | 缺少可解码传输头的非首片等记录数。 | statistics已发布。 | 不能视为未知应用命中。 |
| `statistics.integrity.fragmented_transport` | 分片传输首片 | 采集完整性 | 条 | 否 | 已识别传输头但仍存在IP分片的观察记录。 | statistics已发布。 | 未完整重组时不能推断完整应用内容。 |
| `statistics.integrity.capacity_rejected_packets` | 容量拒绝报文 | 采集完整性 | 包 | 否 | 有界流状态达到容量后被拒绝接纳的报文计数。 | statistics已发布。 | 会影响分析完整性，不能默认为无损。 |
| `statistics.integrity.late_records` | 迟到记录 | 采集完整性 | 条 | 否 | 落入已经结束窗口的迟到输入记录。 | statistics已发布。 | 不按接收时刻重新归入当前窗。 |
| `statistics.integrity.timestamp_regressions` | 时间戳回退 | 采集完整性 | 条 | 否 | 输入记录时间出现回退的诊断计数。 | statistics已发布。 | 不同于网络响应时差，不能据此推算时钟偏移。 |
| `import.status.input_complete` | 输入读取完成 | 批次状态 | 布尔 | 否 | 尾记录声明输入读取是否完整。 | 已保存批次的capture_status投影。 | 独立于分析处理状态与来源丢包状态。 |
| `import.status.analysis_complete` | 分析处理完成 | 批次状态 | 布尔 | 否 | 生产者声明聚合分析是否完成。 | 已保存批次的capture_status投影。 | 不能作为全部报文可解码或线上无丢包证据。 |
| `import.status.capture_loss_status` | 来源丢包状态 | 批次状态 | 枚举 | 否 | unknown / declared_zero / declared_nonzero / inconsistent_counters。 | 已保存批次的capture_status投影。 | 零丢包声明不等于独立验证无丢失；未知不是零。 |
| `import.status.published_windows` | 发布窗口 | 批次状态 | 窗 | 否 | 当前批次已发布统计的窗口数。 | 已保存批次的capture_status投影。 | 不与其他批次合计为采集覆盖时长。 |
| `import.status.suppressed_windows` | 抑制窗口 | 批次状态 | 窗 | 否 | 当前批次因样本门槛等原因未发布统计的窗口数。 | 已保存批次的capture_status投影。 | 保留抑制状态，不能删除后称连续覆盖。 |
| `import.status.source_counter_consistent` | 来源计数一致 | 批次状态 | 布尔 | 是 | 声明的来源接收/丢弃等计数是否相互一致。 | 已保存批次的capture_status投影。 | 来源计数未提供时为null，不显示一致。 |

## 队列P19字段

| 字段 | 显示内容/单位 | 规则 |
| --- | --- | --- |
| enabled / running / state | 启用、消费者、业务阶段 | 业务状态与连接失败分别显示；disabled不是零积压成功 |
| pending_batches / max_batches | 批次与容量，批次 | max>0才显示比例；保留实际分子，超限不截断计数 |
| pending_bytes / max_bytes | 待写逻辑数据与容量，B/KiB/MiB | 单位统一；无分母不生成容量百分比 |
| oldest_queued_at | 最早待写时间 | null显示未提供；不编造排队年龄 |
| next_retry_at | 下次重试时间 | 没有调度时不倒计时为已恢复 |
| last_error | 固定错误码映射 | 未知码给业务错误，外部文本不作为HTML |
| completed_this_process / duplicates_this_process | 本进程确认/去重次数 | 不是历史总数，重启归零 |
| failures_this_process / consecutive_failures | 本进程失败/连续失败 | 与待写批次不做差推算数据丢失 |
| updatedAt（前端观察） | 最近成功读取时刻 | 不是后台写入时间；请求超时清旧状态，保留最近成功时间便于诊断 |
