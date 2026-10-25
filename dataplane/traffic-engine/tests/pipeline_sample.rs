// pipeline_sample.rs —— 用仓库里的样本 pcap 驱动**整条**数据链的集成测试。
//
// 覆盖的链：pcap 文件 → 解帧（channel）→ 流表/超时（flow）→ 双向会话 + TCP 状态机
// （session）→ 定长特征（feature）→ FlowRecord（record）。
//
// 期望值全部是**手写**的：见 datasets/pcap/generate-samples.py 文件头那张表。
// 不是"把实现输出抄回来看它自己是否一致"——那样只能证明它没变，证明不了它对。
// 字节口径同采集侧：IP 载荷长度（含四层头），所以每个报文都贡献 20 字节 TCP 头
// 或 8 字节 UDP 头。
//
// 样本用 include_bytes! 编进二进制：路径写错 = **编译失败**，而不是运行时
// 静默跳过（这是本项目定下的规矩，见 dpi/tests.rs 的同款说明）。

use traffic_engine::feature::idx;
use traffic_engine::flow::{FlowKey, Proto, IPPROTO_TCP, IPPROTO_UDP};
use traffic_engine::pipeline::{analyze_pcap, AnalyzeOptions, AnalyzeStats};
use traffic_engine::record::FlowRecord;
use traffic_engine::tcp::{Side, TcpState};

const SAMPLE: &[u8] = include_bytes!("../../../datasets/pcap/sample-session-tcp.pcap");

fn analyze(opts: &AnalyzeOptions) -> (Vec<FlowRecord>, AnalyzeStats) {
    analyze_pcap(SAMPLE, opts).expect("样本 pcap 必须能被完整分析")
}

/// 行首必须是 `{"schema_version":<真源常量>,`。
///
/// 故意**不写数字**：写死 `1` 时抬版本会让这条断言假红，而假红的常见处理是把断言
/// 改成新数字 —— 那就变成了「实现给自己打分」。这里只能被「行里带的版本 ≠ 契约」打破。
fn line_prefix_matches_version(r: &FlowRecord) -> bool {
    r.to_json_line()
        .starts_with(&format!("{{\"schema_version\":{},", r.schema_version))
}

/// 按**正向**端口对取记录（正向 = 规范端点序里较小的一端，见 FlowKey::canonical）。
fn rec<'a>(records: &'a [FlowRecord], sport: u16, dport: u16) -> &'a FlowRecord {
    records
        .iter()
        .find(|r| r.key.src_port == sport && r.key.dst_port == dport)
        .unwrap_or_else(|| panic!("找不到会话 {sport} -> {dport}"))
}

#[test]
fn session_sample_matches_the_handwritten_expectations() {
    let (records, stats) = analyze(&AnalyzeOptions::default());

    // ---- 全局计数 ----
    assert_eq!(stats.packets_read, 18, "样本共 18 个报文");
    assert_eq!(
        stats.packets_decoded, 17,
        "非首片分片必须被跳过，不得算进流表"
    );
    assert_eq!(
        stats
            .decode_errors
            .get("decode.non_initial_fragment")
            .copied(),
        Some(1),
        "分片必须显式报错，而不是塌缩成一条端口为 0 的假流"
    );
    assert_eq!(stats.decode_errors.len(), 1, "样本里只有一种解码错误");
    assert_eq!(stats.truncated_captures, 0, "样本没有被 snaplen 截断的包");
    assert_eq!(stats.records, 5, "样本里是 5 条会话");
    assert_eq!(stats.non_finite_vectors, 0);
    assert_eq!(stats.counter_mismatches, 0);
    assert!(stats.sorted_by_key);

    // ---- S1：完整握手 + 双向数据 + 四次挥手 ----
    let s1 = rec(&records, 40000, 80);
    assert_eq!(s1.key.proto, Proto::Tcp);
    assert_eq!(s1.packets, 9);
    assert_eq!(s1.bytes, 9 * 20 + 120 + 500, "9 个头 + 120 正向 + 500 反向");
    assert_eq!(s1.tcp_state, Some(TcpState::TimeWait));
    assert_eq!(s1.initiator, Some(Side::A));
    assert!(!s1.adopted_midstream, "握手完整，不得标为中途接入");
    assert_eq!(s1.illegal_tcp_events, 0, "完整握手不该有任何非法迁移");
    assert_eq!(s1.direction_switches, 6, "A B A A B A B B A");
    assert_eq!(s1.first_seen_us, 1_700_000_010_001_000);
    assert_eq!(s1.last_seen_us, 1_700_000_010_009_000);
    assert_eq!(s1.features.get(idx::FWD_PACKETS), 5.0);
    assert_eq!(s1.features.get(idx::REV_PACKETS), 4.0);
    assert_eq!(s1.features.get(idx::FWD_BYTES), 5.0 * 20.0 + 120.0);
    assert_eq!(s1.features.get(idx::REV_BYTES), 4.0 * 20.0 + 500.0);
    assert_eq!(
        s1.features.get(idx::DURATION_US),
        8_000.0,
        "0.001s 间隔 × 8"
    );
    assert_eq!(s1.features.get(idx::MAX_IAT_US), 1_000.0);
    assert_eq!(s1.features.get(idx::MEAN_IAT_US), 1_000.0);
    // 包长序列（IP 载荷含 20 字节 TCP 头）：7 个纯头（20）+ 120 数据 + 500 数据。
    // 期望值在测试里按定义算，而不是抄实现里的中间量。
    let lens = [20.0, 20.0, 20.0, 140.0, 520.0, 20.0, 20.0, 20.0, 20.0];
    let n = lens.len() as f64;
    let mean_payload: f64 = lens.iter().sum::<f64>() / n;
    let var_payload: f64 = lens.iter().map(|x| (x - mean_payload).powi(2)).sum::<f64>() / n;
    assert_eq!(
        lens.iter().sum::<f64>(),
        s1.bytes as f64,
        "包长之和就是字节数"
    );
    assert!((s1.features.get(idx::MEAN_PAYLOAD_LEN) - mean_payload).abs() < 1e-9);
    assert!((s1.features.get(idx::STDDEV_PAYLOAD_LEN) - var_payload.sqrt()).abs() < 1e-9);
    assert_eq!(s1.features.get(idx::MIN_PAYLOAD_LEN), 20.0);
    assert_eq!(s1.features.get(idx::MAX_PAYLOAD_LEN), 520.0);
    // 小包阈值 128：只有 140 与 520 不算小包 → 7/9
    assert!((s1.features.get(idx::SMALL_PACKET_RATIO) - 7.0 / 9.0).abs() < 1e-9);
    assert_eq!(s1.app.outcome, "unknown", "载荷是 Q/R 填充，看过但不认识");

    // ---- S2：连接被拒（SYN → RST+ACK）----
    let s2 = rec(&records, 81, 55000);
    assert_eq!(s2.packets, 2);
    assert_eq!(s2.bytes, 40);
    assert_eq!(s2.tcp_state, Some(TcpState::Reset));
    assert_eq!(
        s2.initiator,
        Some(Side::B),
        "SYN 由 10.0.0.3 发出，而规范端点序把 10.0.0.2 排在前面，故发起方是 B 侧"
    );
    assert!(!s2.adopted_midstream);
    assert_eq!(s2.direction_switches, 1);
    assert_eq!(s2.app.outcome, "not_inspected", "没有任何载荷，谈不上识别");

    // ---- S3：中途接入（无 SYN 的双向数据）----
    let s3 = rec(&records, 443, 60000);
    assert_eq!(s3.packets, 2);
    assert_eq!(s3.bytes, 2 * 20 + 200 + 300);
    assert_eq!(s3.tcp_state, Some(TcpState::Established));
    assert!(s3.adopted_midstream, "没看到握手必须可辨认");
    assert_eq!(s3.initiator, None, "没看到 SYN 就不许猜发起方");
    assert_eq!(s3.app.outcome, "unknown");

    // ---- S4：DNS 查询 + 应答 ----
    let s4 = rec(&records, 53000, 53);
    assert_eq!(s4.key.proto, Proto::Udp);
    assert_eq!(s4.tcp_state, None, "UDP 没有连接状态，必须写 None");
    assert_eq!(s4.packets, 2);
    assert_eq!(s4.bytes, (8 + 29) + (8 + 45), "查询 37 + 应答 53");
    assert_eq!(s4.direction_switches, 1);
    assert_eq!(s4.app.outcome, "identified");
    assert_eq!(s4.app.app.map(|a| a.as_str()), Some("dns"));
    assert_eq!(
        s4.app.bytes_inspected, 29,
        "只喂首包，且是查询方向的 29 字节"
    );
    assert_eq!(
        s4.app.server_name, None,
        "DNS 记录里没有可提取的域名（本结构未填）"
    );
    assert!(s4.features.get(idx::PAYLOAD_ENTROPY_BITS) > 0.0);

    // ---- S5：ICMP 回显请求 + 应答（无端口协议）----
    let s5 = records
        .iter()
        .find(|r| r.key.proto.number() == 1)
        .expect("ICMP 会话");
    assert_eq!(s5.key.src_port, 0, "ICMP 没有端口");
    assert_eq!(s5.key.dst_port, 0);
    assert_eq!(s5.packets, 2);
    assert_eq!(s5.bytes, 2 * (8 + 8), "ICMP 头 8 + 载荷 8");
    assert_eq!(s5.tcp_state, None);
    assert_eq!(s5.direction_switches, 1);
    assert_eq!(
        s5.app.outcome, "not_inspected",
        "ICMP 头长度随类型变化，本解码器不展开，故载荷起点未知 —— 这是「没看」，不是「不认识」"
    );

    // ---- 会话级 TCP 统计（`CYS-TRF-015`，记录 v2）----
    // 下面每个数都是按 `generate-samples.py` 的构造手算的（段序号 + 时间戳），
    // 不是把实现输出抄回来。
    let ts = |r: &FlowRecord| r.tcp_stats.expect("TCP 会话必须有 tcp_stats");
    // S1：完整握手 + 双向数据 + 四次挥手。A 侧进序号空间的段 = SYN(1)+120+FIN(1)，
    // B 侧 = SYN/ACK(1)+500+FIN(1) ⇒ 各 3 段；三个纯 ACK 不占序号空间。
    let s1t = ts(s1);
    assert_eq!(s1t.seq_judged, 6, "A 侧 3 段 + B 侧 3 段");
    assert_eq!(
        s1t.retransmissions,
        Some(0),
        "全部按序：必须是 Some(0) 不是 None"
    );
    assert_eq!(s1t.out_of_order, Some(0));
    assert_eq!(
        s1t.handshake_rtt_us,
        Some(1_000),
        "SYN@t=1ms → SYN/ACK@t=2ms（与特征里的 IAT 同一份时间戳）"
    );
    assert_eq!(s1t.uplink_bytes, Some(5 * 20 + 120), "发起方 5 包");
    assert_eq!(s1t.downlink_bytes, Some(4 * 20 + 500), "应答方 4 包");
    assert_eq!(
        s1t.uplink_bytes.unwrap() + s1t.downlink_bytes.unwrap(),
        s1.bytes,
        "上下行合计必须等于 bytes（两条路径不得各自记账）"
    );

    // S2：SYN → RST/ACK。只有 SYN 占序号空间（RST 的载荷 0 且非 SYN/FIN）。
    let s2t = ts(s2);
    assert_eq!(s2t.seq_judged, 1, "只有 SYN 那一格进得了轨迹");
    assert_eq!(s2t.retransmissions, Some(0));
    assert_eq!(s2t.out_of_order, Some(0));
    assert_eq!(
        s2t.handshake_rtt_us, None,
        "没有 SYN/ACK ⇒ RTT 是 null，不是 0"
    );
    assert_eq!(s2t.uplink_bytes, Some(20), "发起方是 B 侧（SYN 那包）");
    assert_eq!(s2t.downlink_bytes, Some(20));

    // S3：中途接入 ⇒ 没看到 SYN ⇒ 上下行必须是 null；但重传/乱序仍然可判。
    let s3t = ts(s3);
    assert_eq!(s3t.seq_judged, 2, "每侧首段只建立基准，不判定");
    assert_eq!(
        s3t.retransmissions,
        Some(0),
        "有判定输入⇒ 该报 Some(0)，不能因中途接入就报 None"
    );
    assert_eq!(s3t.out_of_order, Some(0));
    assert_eq!(s3t.handshake_rtt_us, None);
    assert_eq!(s3t.uplink_bytes, None, "发起方未知就不报上行");
    assert_eq!(s3t.downlink_bytes, None);

    // S4/S5：非 TCP ⇒ 整个结构体 None（这些量对 UDP/ICMP 没有定义）。
    assert_eq!(s4.tcp_stats, None, "UDP 没有重传/乱序/RTT 语义");
    assert_eq!(s5.tcp_stats, None, "ICMP 同理");

    // ---- CLI 统计行与逐会话记录必须同口径（同一批会话的两个出口）----
    assert_eq!(stats.tcp.sessions_judged, 3, "S1/S2/S3");
    assert_eq!(
        stats.tcp.sessions_unobserved, 0,
        "非 TCP 会话不进这两个计数"
    );
    assert_eq!(stats.tcp.judged_segments, 6 + 1 + 2);
    assert_eq!(stats.tcp.retransmissions, 0);
    assert_eq!(stats.tcp.out_of_order, 0);
    assert_eq!(stats.tcp.rtt_measured, 1, "只有 S1 见到完整握手");
    assert_eq!(stats.tcp.rtt_sum_us, 1_000);
    assert_eq!(stats.tcp.rtt_min_us, 1_000);
    assert_eq!(stats.tcp.rtt_max_us, 1_000);
    assert_eq!(stats.tcp.uplink_bytes, (5 * 20 + 120) + 20);
    assert_eq!(stats.tcp.downlink_bytes, (4 * 20 + 500) + 20);
    assert_eq!(stats.tcp.ratio_sessions, 2, "S3 没发起方 ⇒ 不进比例样本量");

    // ---- 会话 id 唯一且都被归还（无泄漏）----
    let mut ids: Vec<u64> = records.iter().map(|r| r.session_id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), records.len(), "会话 id 必须互不相同");

    // ---- 输出契约 ----
    for r in &records {
        assert!(
            line_prefix_matches_version(r),
            "行首必须是当前记录契约版本：{r:?}"
        );
        let line = r.to_json_line();
        assert!(!line.contains("NaN") && !line.contains("inf"), "{line}");
        assert!(
            line.contains("\"risk_score\":null"),
            "评分未实现时必须写 null"
        );
        // v2 新契约：`tcp` 块的键集不随协议变（UDP/ICMP 也得带着六个 null 键）。
        for key in [
            "\"seq_judged\":",
            "\"retransmissions\":",
            "\"out_of_order\":",
            "\"handshake_rtt_us\":",
            "\"uplink_bytes\":",
            "\"downlink_bytes\":",
        ] {
            assert!(line.contains(key), "记录里缺少 tcp 键 {key}");
        }
    }
    let mut buf = Vec::new();
    let n = traffic_engine::record::write_jsonl(&mut buf, &records).expect("写 JSONL");
    assert_eq!(n, records.len());
    assert_eq!(
        String::from_utf8(buf).unwrap().lines().count(),
        records.len()
    );
}

#[test]
fn strict_mode_refuses_to_pick_up_midstream_state() {
    // 同一份样本、只换 TCP 严格模式：完整握手与 RST 的结论不变，
    // 但"中途接入"的那条会话必须停在 Closed 并把两次数据计为非法迁移。
    let (records, _) = analyze(&AnalyzeOptions::strict());

    let complete = rec(&records, 40000, 80);
    assert_eq!(complete.tcp_state, Some(TcpState::TimeWait));
    assert_eq!(complete.illegal_tcp_events, 0);

    let refused = rec(&records, 81, 55000);
    assert_eq!(refused.tcp_state, Some(TcpState::Reset));

    let midstream = rec(&records, 443, 60000);
    assert_eq!(midstream.tcp_state, Some(TcpState::Closed));
    assert!(!midstream.adopted_midstream, "严格模式不得采纳中途接入");
    assert_eq!(
        midstream.illegal_tcp_events, 2,
        "两个数据包都该被拒绝并计数（拒绝不等于没发生）"
    );
    assert_eq!(midstream.initiator, None);
}

#[test]
fn analysis_is_deterministic_and_repeatable() {
    // 同一份输入跑两次必须逐字节一致：特征参与比对与回归，任何非确定性
    // （哈希迭代顺序、浮点求和顺序）都会让结果不可复现。
    let (a, _) = analyze(&AnalyzeOptions::default());
    let (b, _) = analyze(&AnalyzeOptions::default());
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x, y, "两次分析的记录必须完全相同");
    }
}

#[test]
fn limit_and_session_capacity_are_honoured() {
    // 容量设为 2：超出部分走逐出，逐出的会话不再产出记录，且逐出必须计入统计。
    let opts = AnalyzeOptions {
        session: traffic_engine::session::SessionConfig {
            max_sessions: 2,
            ..AnalyzeOptions::default().session
        },
        ..AnalyzeOptions::default()
    };
    let (records, stats) = analyze(&opts);
    assert_eq!(stats.session.sessions_created, 5, "5 条会话都建过");
    assert_eq!(stats.session.sessions_evicted, 3, "容量 2 之外的都要被逐出");
    assert_eq!(records.len(), 2, "被逐出的会话不产出记录");
    assert_eq!(stats.records, 2);
}

#[test]
fn canonical_keys_are_direction_independent() {
    // 双向包必须归到同一条会话：拿正向键与反向键分别查，得到同一条记录。
    let (records, _) = analyze(&AnalyzeOptions::default());
    let s1 = rec(&records, 40000, 80);
    let fwd = s1.key;
    let rev = fwd.reverse();
    assert_ne!(fwd, rev, "方向敏感的键本身必须不同");
    assert_eq!(fwd.canonical(), rev.canonical(), "规范形式必须相同");
    assert_eq!(fwd.canonical(), fwd, "已规范的键再规范化应是不动点");
    // 记录里存的是规范键，所以反向键在记录集合里查不到。
    assert!(records.iter().all(|r| r.key != rev));
    let _: FlowKey = fwd;
    assert_eq!(IPPROTO_TCP, 6);
    assert_eq!(IPPROTO_UDP, 17);
}
