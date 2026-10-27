import type { AggregateWindow, CaptureStatus } from '@/api/analytics';

type Statistics = NonNullable<AggregateWindow['statistics']>;
type Quality = NonNullable<Statistics['tcp_quality']>;
export type MetricField = Exclude<keyof AggregateWindow, 'statistics'>
  | `statistics.${Exclude<keyof Statistics, 'integrity' | 'tcp_quality'>}`
  | `statistics.integrity.${keyof Statistics['integrity']}`
  | `statistics.tcp_quality.${keyof Quality}`
  | `import.status.${keyof CaptureStatus}`;
export interface MetricDefinition {
  field: MetricField;
  name: string;
  group: string;
  unit: string;
  nullable: boolean;
  definition: string;
  availability: string;
  limits: string;
}
// Reviewed against the query DTO, not the richer producer JSONL or attribute registry.
export const aggregateMetrics: MetricDefinition[] = [
  {
    "field": "window_start_seconds",
    "name": "窗口起点",
    "group": "窗口口径",
    "unit": "Unix秒",
    "nullable": false,
    "definition": "输入时间戳按窗口宽度向下对齐后的起点。",
    "availability": "有输入记录的窗口。",
    "limits": "查询区间按起点匹配[from,to)；缺失窗口不补造零流量。"
  },
  {
    "field": "window_seconds",
    "name": "窗口宽度",
    "group": "窗口口径",
    "unit": "秒",
    "nullable": false,
    "definition": "生产者声明的聚合窗口宽度。",
    "availability": "每个已返回窗口。",
    "limits": "首尾窗口可能只有部分覆盖，不能用名义窗宽直接计算pps或Gbps。"
  },
  {
    "field": "sampling_interval",
    "name": "整流采样间隔",
    "group": "窗口口径",
    "unit": "1:N",
    "nullable": false,
    "definition": "窗口内约1/N双向流进入有界采样状态。",
    "availability": "每个已返回窗口。",
    "limits": "不是按包独立抽样；采样观察值不乘N外推。"
  },
  {
    "field": "suppressed",
    "name": "整窗抑制",
    "group": "窗口口径",
    "unit": "布尔",
    "nullable": false,
    "definition": "窗口样本流数不足时不发布statistics。",
    "availability": "每个已返回窗口。",
    "limits": "true时各统计保留未发布，不能显示为零。"
  },
  {
    "field": "statistics.contributing_sampled_flows",
    "name": "贡献样本流数",
    "group": "承载统计",
    "unit": "流",
    "nullable": false,
    "definition": "已接纳并参与当前窗口统计的不同采样流数。",
    "availability": "statistics已发布。",
    "limits": "流数不是用户数；不同窗口不能去重为设备数。"
  },
  {
    "field": "statistics.tcp_packets",
    "name": "TCP报文数",
    "group": "承载统计",
    "unit": "包",
    "nullable": false,
    "definition": "可解码且归属本窗的TCP记录数量。",
    "availability": "statistics已发布；不受流采样影响。",
    "limits": "不是全部线上包数；解码失败与非首片等诊断另外记录。"
  },
  {
    "field": "statistics.udp_packets",
    "name": "UDP报文数",
    "group": "承载统计",
    "unit": "包",
    "nullable": false,
    "definition": "可解码且归属本窗的UDP记录数量。",
    "availability": "statistics已发布；不受流采样影响。",
    "limits": "不是全部线上包数；解码失败与非首片等诊断另外记录。"
  },
  {
    "field": "statistics.other_ip_packets",
    "name": "其他IP报文数",
    "group": "承载统计",
    "unit": "包",
    "nullable": false,
    "definition": "可解码且归属本窗的非TCP/UDP的IP记录数量。",
    "availability": "statistics已发布；不受流采样影响。",
    "limits": "不是全部线上包数；解码失败与非首片等诊断另外记录。"
  },
  {
    "field": "statistics.tls_record_candidate_packets",
    "name": "TLS记录头候选",
    "group": "承载统计",
    "unit": "包",
    "nullable": true,
    "definition": "采样流内载荷起点满足TLS记录头、长度与完整捕获条件的报文数。",
    "availability": "整窗与TLS子组均满足最小流数。",
    "limits": "不重组跨段记录，不解密；不是TLS会话数、具体应用或VPN数量。"
  },
  {
    "field": "statistics.quic_long_header_candidate_packets",
    "name": "QUIC长头候选",
    "group": "承载统计",
    "unit": "包",
    "nullable": true,
    "definition": "采样流内符合已支持QUIC长头格式与捕获边界的报文数。",
    "availability": "整窗与QUIC子组均满足最小流数。",
    "limits": "不含短头、Retry、版本协商或未知版本；不是加密真实性验证。"
  },
  {
    "field": "statistics.tcp_quality.retransmission_candidates",
    "name": "重传候选",
    "group": "TCP质量",
    "unit": "次",
    "nullable": false,
    "definition": "段末序号未超过当前方向已推进的序号游标。",
    "availability": "statistics与tcp_quality均已发布。",
    "limits": "基于可见TCP序号的候选；缺口不等于链路丢包，缺少judged_segments分母时不算比例。"
  },
  {
    "field": "statistics.tcp_quality.out_of_order_candidates",
    "name": "乱序候选",
    "group": "TCP质量",
    "unit": "次",
    "nullable": false,
    "definition": "旧新序号重叠或在已见高水位之前补洞。",
    "availability": "statistics与tcp_quality均已发布。",
    "limits": "基于可见TCP序号的候选；缺口不等于链路丢包，缺少judged_segments分母时不算比例。"
  },
  {
    "field": "statistics.tcp_quality.forward_gap_candidates",
    "name": "前向缺口候选",
    "group": "TCP质量",
    "unit": "次",
    "nullable": false,
    "definition": "当前段起点位于连续序号游标之后。",
    "availability": "statistics与tcp_quality均已发布。",
    "limits": "基于可见TCP序号的候选；缺口不等于链路丢包，缺少judged_segments分母时不算比例。"
  },
  {
    "field": "statistics.tcp_quality.response_delay_samples",
    "name": "SYN响应时差样本",
    "group": "TCP质量",
    "unit": "样本",
    "nullable": true,
    "definition": "首次无歧义SYN到反向SYN-ACK的有效时间差样本数量。",
    "availability": "独立贡献流达到发布门槛；每流每窗最多一次。",
    "limits": "不是端到端完整RTT、单向时延或网站加载时延。"
  },
  {
    "field": "statistics.tcp_quality.response_delay_upper_bounds_ms",
    "name": "时差桶上界",
    "group": "TCP质量",
    "unit": "毫秒数组",
    "nullable": false,
    "definition": "各非累积直方图桶的右边界；首桶从0起。",
    "availability": "tcp_quality已发布；与histogram按索引配对。",
    "limits": "数组元素null表示无穷上界；不能由分桶内插生成精确p95。"
  },
  {
    "field": "statistics.tcp_quality.response_delay_histogram",
    "name": "SYN响应时差直方图",
    "group": "TCP质量",
    "unit": "样本数组",
    "nullable": true,
    "definition": "每个时差桶内有效样本数，采用非累积桶。",
    "availability": "有效时差样本达到最小流数。",
    "limits": "显示每桶范围与样本数；空值表示未发布，不补为全零分布。"
  },
  {
    "field": "statistics.integrity.records",
    "name": "输入记录",
    "group": "采集完整性",
    "unit": "条",
    "nullable": false,
    "definition": "当前窗口归属的输入PCAP记录数。",
    "availability": "statistics已发布。",
    "limits": "不等于成功解码数或线上总包数。"
  },
  {
    "field": "statistics.integrity.snaplen_truncated",
    "name": "捕获截断",
    "group": "采集完整性",
    "unit": "条",
    "nullable": false,
    "definition": "捕获长度小于原始长度的记录数。",
    "availability": "statistics已发布。",
    "limits": "不是网络丢包率。"
  },
  {
    "field": "statistics.integrity.decode_incomplete",
    "name": "解码不完整",
    "group": "采集完整性",
    "unit": "条",
    "nullable": false,
    "definition": "头部不足或无法完整解码的记录数。",
    "availability": "statistics已发布。",
    "limits": "处理完成不代表所有报文均可解码。"
  },
  {
    "field": "statistics.integrity.unparsed_fragments",
    "name": "未解析非首片",
    "group": "采集完整性",
    "unit": "条",
    "nullable": false,
    "definition": "缺少可解码传输头的非首片等记录数。",
    "availability": "statistics已发布。",
    "limits": "不能视为未知应用命中。"
  },
  {
    "field": "statistics.integrity.fragmented_transport",
    "name": "分片传输首片",
    "group": "采集完整性",
    "unit": "条",
    "nullable": false,
    "definition": "已识别传输头但仍存在IP分片的观察记录。",
    "availability": "statistics已发布。",
    "limits": "未完整重组时不能推断完整应用内容。"
  },
  {
    "field": "statistics.integrity.capacity_rejected_packets",
    "name": "容量拒绝报文",
    "group": "采集完整性",
    "unit": "包",
    "nullable": false,
    "definition": "有界流状态达到容量后被拒绝接纳的报文计数。",
    "availability": "statistics已发布。",
    "limits": "会影响分析完整性，不能默认为无损。"
  },
  {
    "field": "statistics.integrity.late_records",
    "name": "迟到记录",
    "group": "采集完整性",
    "unit": "条",
    "nullable": false,
    "definition": "落入已经结束窗口的迟到输入记录。",
    "availability": "statistics已发布。",
    "limits": "不按接收时刻重新归入当前窗。"
  },
  {
    "field": "statistics.integrity.timestamp_regressions",
    "name": "时间戳回退",
    "group": "采集完整性",
    "unit": "条",
    "nullable": false,
    "definition": "输入记录时间出现回退的诊断计数。",
    "availability": "statistics已发布。",
    "limits": "不同于网络响应时差，不能据此推算时钟偏移。"
  },
  {
    "field": "import.status.input_complete",
    "name": "输入读取完成",
    "group": "批次状态",
    "unit": "布尔",
    "nullable": false,
    "definition": "尾记录声明输入读取是否完整。",
    "availability": "已保存批次的capture_status投影。",
    "limits": "独立于分析处理状态与来源丢包状态。"
  },
  {
    "field": "import.status.analysis_complete",
    "name": "分析处理完成",
    "group": "批次状态",
    "unit": "布尔",
    "nullable": false,
    "definition": "生产者声明聚合分析是否完成。",
    "availability": "已保存批次的capture_status投影。",
    "limits": "不能作为全部报文可解码或线上无丢包证据。"
  },
  {
    "field": "import.status.capture_loss_status",
    "name": "来源丢包状态",
    "group": "批次状态",
    "unit": "枚举",
    "nullable": false,
    "definition": "unknown / declared_zero / declared_nonzero / inconsistent_counters。",
    "availability": "已保存批次的capture_status投影。",
    "limits": "零丢包声明不等于独立验证无丢失；未知不是零。"
  },
  {
    "field": "import.status.published_windows",
    "name": "发布窗口",
    "group": "批次状态",
    "unit": "窗",
    "nullable": false,
    "definition": "当前批次已发布统计的窗口数。",
    "availability": "已保存批次的capture_status投影。",
    "limits": "不与其他批次合计为采集覆盖时长。"
  },
  {
    "field": "import.status.suppressed_windows",
    "name": "抑制窗口",
    "group": "批次状态",
    "unit": "窗",
    "nullable": false,
    "definition": "当前批次因样本门槛等原因未发布统计的窗口数。",
    "availability": "已保存批次的capture_status投影。",
    "limits": "保留抑制状态，不能删除后称连续覆盖。"
  },
  {
    "field": "import.status.source_counter_consistent",
    "name": "来源计数一致",
    "group": "批次状态",
    "unit": "布尔",
    "nullable": true,
    "definition": "声明的来源接收/丢弃等计数是否相互一致。",
    "availability": "已保存批次的capture_status投影。",
    "limits": "来源计数未提供时为null，不显示一致。"
  }
];
