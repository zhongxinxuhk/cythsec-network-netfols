-- FlowRecord v2 / FeatureVector v1: JSONEachRow 可直接导入，不丢弃嵌套字段。
-- schema 与特征版本变化时新增迁移；未知字段、缺失字段由写入检查拒绝。
CREATE TABLE flow_records_v2
(
    schema_version UInt32,
    session_id UInt64,
    flow Tuple(src_ip String, src_port UInt16, dst_ip String, dst_port UInt16,
               proto UInt8, proto_name String),
    tcp Tuple(state Nullable(String), initiator Nullable(String),
              adopted_midstream Bool, illegal_events UInt64,
              seq_judged Nullable(UInt64), retransmissions Nullable(UInt64), out_of_order Nullable(UInt64),
              handshake_rtt_us Nullable(UInt64), uplink_bytes Nullable(UInt64), downlink_bytes Nullable(UInt64)),
    time Tuple(first_seen_us UInt64, last_seen_us UInt64, duration_us UInt64),
    counters Tuple(packets UInt64, bytes UInt64, direction_switches UInt64),
    app Tuple(outcome String, app Nullable(String), app_id Nullable(UInt32),
              confidence Nullable(String), rationale Nullable(String),
              server_name Nullable(String), bytes_inspected UInt64),
    features Tuple(
        schema_version UInt32,
        packets Nullable(Float64), bytes Nullable(Float64),
        fwd_packets Nullable(Float64), fwd_bytes Nullable(Float64),
        rev_packets Nullable(Float64), rev_bytes Nullable(Float64),
        fwd_byte_ratio Nullable(Float64), duration_us Nullable(Float64),
        byte_rate_bps Nullable(Float64), packet_rate_pps Nullable(Float64),
        mean_payload_len Nullable(Float64), min_payload_len Nullable(Float64),
        max_payload_len Nullable(Float64), stddev_payload_len Nullable(Float64),
        mean_iat_us Nullable(Float64), min_iat_us Nullable(Float64),
        max_iat_us Nullable(Float64), stddev_iat_us Nullable(Float64),
        direction_switches Nullable(Float64), small_packet_ratio Nullable(Float64),
        payload_entropy_bits Nullable(Float64)),
    risk_score Nullable(Float64),
    CONSTRAINT record_version CHECK schema_version = 2,
    CONSTRAINT feature_version CHECK features.schema_version = 1
)
ENGINE = MergeTree
PARTITION BY intDiv(time.first_seen_us, 86400000000)
ORDER BY (flow.proto, flow.src_ip, flow.dst_ip, time.first_seen_us, session_id);
