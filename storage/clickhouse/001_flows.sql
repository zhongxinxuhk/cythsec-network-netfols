-- 生成物，**勿手改**。
-- 真源：dataplane/traffic-engine/src/storage/mod.rs 的 flow_columns()。
-- 重新生成：cargo run --offline --quiet --bin cythsec-dump-ddl > storage/clickhouse/001_flows.sql
-- 一致性关口：bash scripts/verify/check-columnar.sh
--   （它同时把本文件交给真实 ClickHouse 执行，并核对生成物与真源逐字节相同）
-- 列契约版本：2（改列名/类型/顺序必须抬它）

CREATE TABLE IF NOT EXISTS flows
(
    schema_version UInt32 COMMENT '记录契约版本（FlowRecord.schema_version）' CODEC(Delta(4), ZSTD(1)),
    column_contract_version UInt32 COMMENT '列契约版本：列名/类型/顺序变更必须抬它' CODEC(Delta(4), ZSTD(1)),
    session_id UInt64 COMMENT '会话 id（同一双向会话两个方向共用）' CODEC(Delta(8), ZSTD(1)),
    ip_family UInt8 COMMENT '地址族 4|6（派生）；决定 IPv6 列里的 ::ffff: 前缀如何反解' CODEC(Delta(1), ZSTD(1)),
    src_ip IPv6 COMMENT '源地址；IPv4 以 RFC 4291 §2.5.5.2 的 ::ffff:a.b.c.d 存放' CODEC(ZSTD(1)),
    dst_ip IPv6 COMMENT '目的地址；IPv4 同上' CODEC(ZSTD(1)),
    src_port UInt16 COMMENT '源端口（ICMP 等无端口协议恒为 0）' CODEC(Delta(2), ZSTD(1)),
    dst_port UInt16 COMMENT '目的端口' CODEC(Delta(2), ZSTD(1)),
    proto UInt8 COMMENT 'IANA 协议号（6=TCP 17=UDP 1=ICMP 58=ICMPv6）' CODEC(Delta(1), ZSTD(1)),
    proto_name LowCardinality(String) COMMENT '协议名（人可读；与 proto 同源）' CODEC(ZSTD(1)),
    tcp_state LowCardinality(Nullable(String)) COMMENT 'TCP 末态；非 TCP 为 NULL（不是空串）' CODEC(ZSTD(1)),
    tcp_initiator LowCardinality(Nullable(String)) COMMENT '发起方 fwd|rev；没见过 SYN 为 NULL（中途接入不猜）' CODEC(ZSTD(1)),
    adopted_midstream UInt8 COMMENT '是否中途接入（1/0；列式不用 Bool 是为了少一种类型）' CODEC(Delta(1), ZSTD(1)),
    illegal_tcp_events UInt64 COMMENT '非法 TCP 迁移次数（被拒绝的证据，不是被丢弃的包）' CODEC(Delta(8), ZSTD(1)),
    tcp_seq_judged Nullable(UInt64) COMMENT '参与重传/乱序判定的段数（样本量）；0 表示本会话无判定输入，非 TCP 为 NULL' CODEC(Delta(8), ZSTD(1)),
    tcp_retransmissions Nullable(UInt64) COMMENT '重传段数（口径与 Wireshark retransmission 在同一条 pcap 上逐模式对齐）；无判定输入为 NULL' CODEC(Delta(8), ZSTD(1)),
    tcp_out_of_order Nullable(UInt64) COMMENT '乱序段数（含部分重叠与补洞段）；缺段不计此项而是 lost_segment 口径；无判定输入为 NULL' CODEC(Delta(8), ZSTD(1)),
    tcp_handshake_rtt_us Nullable(UInt64) COMMENT '握手 RTT（SYN → 对侧 SYN/ACK，微秒）；与 tshark iRTT 口径不同（后者量到第三次 ACK）；未见到完整握手为 NULL' CODEC(Delta(8), ZSTD(1)),
    tcp_uplink_bytes Nullable(UInt64) COMMENT '发起方方向字节（IP 载荷长，含四层头）；中途接入发起方未知为 NULL，不拿字典序兜底' CODEC(Delta(8), ZSTD(1)),
    tcp_downlink_bytes Nullable(UInt64) COMMENT '应答方方向字节；与 uplink 合计等于 bytes；上下行比由查询侧相除（不存比例：0 分母另需表达）' CODEC(Delta(8), ZSTD(1)),
    first_seen_us UInt64 COMMENT '首包时间（epoch 微秒）' CODEC(Delta(8), ZSTD(1)),
    last_seen_us UInt64 COMMENT '末包时间（epoch 微秒）' CODEC(Delta(8), ZSTD(1)),
    duration_us UInt64 COMMENT '时长（微秒；派生自末减首，乱序到达时钳到 0）' CODEC(Delta(8), ZSTD(1)),
    packets UInt64 COMMENT '包数' CODEC(Delta(8), ZSTD(1)),
    bytes UInt64 COMMENT '字节数' CODEC(Delta(8), ZSTD(1)),
    direction_switches UInt64 COMMENT '方向切换次数' CODEC(Delta(8), ZSTD(1)),
    app_outcome LowCardinality(String) COMMENT '识别裁决 identified|need_more|malformed|unknown|not_inspected' CODEC(ZSTD(1)),
    app_name LowCardinality(Nullable(String)) COMMENT '应用名；未识别为 NULL' CODEC(ZSTD(1)),
    app_id Nullable(UInt32) COMMENT '应用编号（命名空间<<16|序号）；未识别为 NULL' CODEC(Delta(4), ZSTD(1)),
    app_confidence LowCardinality(Nullable(String)) COMMENT '置信度 high|medium|low；未识别为 NULL' CODEC(ZSTD(1)),
    app_rationale LowCardinality(Nullable(String)) COMMENT '判据留痕（回答「凭什么说是这个」）；未识别为 NULL' CODEC(ZSTD(1)),
    app_server_name Nullable(String) COMMENT '归一化服务名（TLS SNI / HTTP Host）；无则 NULL' CODEC(ZSTD(1)),
    app_bytes_inspected UInt64 COMMENT '实际喂给 DPI 的字节数（0 = 没看过，与 unknown 语义不同）' CODEC(Delta(8), ZSTD(1)),
    features_schema_version UInt32 COMMENT '特征块契约版本' CODEC(Delta(4), ZSTD(1)),
    feat_packets Float64 COMMENT '包数（双向合计，与 counters.packets 同源）' CODEC(ZSTD(1)),
    feat_bytes Float64 COMMENT '字节数（双向合计，含链路层头）' CODEC(ZSTD(1)),
    feat_fwd_packets Float64 COMMENT '正向包数（规范端点序，不是发起方）' CODEC(ZSTD(1)),
    feat_fwd_bytes Float64 COMMENT '正向字节数' CODEC(ZSTD(1)),
    feat_rev_packets Float64 COMMENT '反向包数' CODEC(ZSTD(1)),
    feat_rev_bytes Float64 COMMENT '反向字节数' CODEC(ZSTD(1)),
    feat_fwd_byte_ratio Float64 COMMENT '正向字节占比 0..1' CODEC(ZSTD(1)),
    feat_duration_us Float64 COMMENT '首末包时间差（微秒）' CODEC(ZSTD(1)),
    feat_byte_rate_bps Float64 COMMENT '字节速率 bit/s' CODEC(ZSTD(1)),
    feat_packet_rate_pps Float64 COMMENT '包速率 pkt/s' CODEC(ZSTD(1)),
    feat_mean_payload_len Float64 COMMENT '载荷平均长度（字节）' CODEC(ZSTD(1)),
    feat_min_payload_len Float64 COMMENT '载荷最小长度' CODEC(ZSTD(1)),
    feat_max_payload_len Float64 COMMENT '载荷最大长度' CODEC(ZSTD(1)),
    feat_stddev_payload_len Float64 COMMENT '载荷长度标准差' CODEC(ZSTD(1)),
    feat_mean_iat_us Float64 COMMENT '包间隔平均（微秒）' CODEC(ZSTD(1)),
    feat_min_iat_us Float64 COMMENT '包间隔最小（微秒）' CODEC(ZSTD(1)),
    feat_max_iat_us Float64 COMMENT '包间隔最大（微秒）' CODEC(ZSTD(1)),
    feat_stddev_iat_us Float64 COMMENT '包间隔标准差（微秒）' CODEC(ZSTD(1)),
    feat_direction_switches Float64 COMMENT '方向切换次数' CODEC(ZSTD(1)),
    feat_small_packet_ratio Float64 COMMENT '小包占比（载荷 <=64B）0..1' CODEC(ZSTD(1)),
    feat_payload_entropy_bits Float64 COMMENT '载荷字节熵（bit/字节）' CODEC(ZSTD(1)),
    risk_score Nullable(Float64) COMMENT '风险评分；未评分为 NULL（绝不写 0.0）' CODEC(ZSTD(1)),
    event_date Date MATERIALIZED toDate(intDiv(first_seen_us, 1000000)) COMMENT '分区与 TTL 都要用它，这两处不接受 ALIAS',
    src_ip_text String ALIAS if(ip_family = 4, substring(IPv6NumToString(src_ip), 8), IPv6NumToString(src_ip)) COMMENT '只为人读；落盘会把地址存两份（实测 +4.6 B/记录）',
    dst_ip_text String ALIAS if(ip_family = 4, substring(IPv6NumToString(dst_ip), 8), IPv6NumToString(dst_ip)) COMMENT '同 src_ip_text'
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (first_seen_us, session_id)
TTL event_date + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
