// record/mod.rs —— FlowRecord：数据面**对外的交付格式**（CYS-TRF-033）。
//
// 这是"从能识别到能产出记录"这条链的终点：前面的解码、流表、会话、状态机、特征提取
// 全部做完之后，最终只有这里的一个东西会被落盘、被下游读取。因此这个 schema 是
// **契约**，不是内部结构体的顺手序列化。
//
// 三条不可退让的约定：
//
// 1. **版本化**：`schema_version` 是每行都带的字段（不是文件头）。
//    JSONL 会被逐行追加到同一个文件里，只有"每行自带版本"才能让新老记录共存
//    并让读取方按版本分支；写在文件头则一次追加就毁掉整份文件的解释方式。
//
// 2. **缺失与零值必须能区分**。有 TCP 才有 TCP 状态，没 TCP 就是 `null`；
//    "没检查过应用协议"与"检查了但没认出来"是两个不同的 outcome，不能都写成
//    `unknown`；风险评分还没实现就写 `null`，绝不写 0.0 ——
//    0.0 会被读成"已评分且无风险"，这是把一个缺失证据伪装成一个结论。
//
// 3. **零依赖手写 JSON**。仓库的红线是零第三方 Rust 依赖（离线可构建），
//    因此这里自己转义、自己格式化数字。手写 JSON 唯一真正危险的地方是转义与
//    非有限浮点，两者都有专门的用例与显式处理（见 `escape_json_into` / `json_number`）。

use std::io::{self, Write};

use crate::dpi::{AppId, Confidence, Outcome};
use crate::feature::{json_number, FeatureVector};
use crate::flow::FlowKey;
use crate::tcp::{Side, TcpState};

/// 记录格式版本。**改字段含义或删字段必须升版**；新增可选字段也应升版，
/// 因为读取方按列取数，"多出来一列"在严格模式下就是解析失败。
///
/// `1 → 2`（2026-10-23，`CYS-TRF-015`）：`tcp` 块新增六个会话级统计键
/// （`retransmissions` / `out_of_order` / `seq_judged` / `handshake_rtt_us` /
/// `uplink_bytes` / `downlink_bytes`）。**只加不改**：v1 的全部字段名、类型与含义逐字
/// 不变，因此读取方可以"按版本分支 + 同一套老字段"继续读 v1；但**不能**把 v2 的记录
/// 当 v1 读 —— 那会让列式侧少六列而插入失败（见 `storage::COLUMN_CONTRACT_VERSION`，
/// 两个版本号为什么必须分开抬，那里的注释写了）。
pub const RECORD_SCHEMA_VERSION: u32 = 2;

/// 应用识别结果的记录形态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInfo {
    /// `identified` / `need_more` / `malformed` / `unknown` / `not_inspected`。
    pub outcome: &'static str,
    pub app: Option<AppId>,
    pub confidence: Option<Confidence>,
    /// 判据留痕（规则审计与误报复盘要回答"凭什么说是这个"）。
    pub rationale: Option<&'static str>,
    /// 归一化服务端域名（TLS SNI / HTTP Host）。
    pub server_name: Option<String>,
    /// 实际喂给 DPI 的字节数（0 表示没喂过）。
    pub bytes_inspected: usize,
}

impl AppInfo {
    /// 没有可检查的载荷（例如只抓到握手的流）。
    ///
    /// 这**不是** `unknown`：`unknown` 的含义是"看过并且都不认识"。
    /// 把"没看"记成"不认识"，会让 unknown 率随采集策略变化而漂移，
    /// 而漂移的原因（换了 snaplen）在数据里完全不可见。
    pub fn not_inspected() -> Self {
        Self {
            outcome: "not_inspected",
            app: None,
            confidence: None,
            rationale: None,
            server_name: None,
            bytes_inspected: 0,
        }
    }

    /// 由 DPI 裁决构造。
    pub fn from_outcome(outcome: &Outcome, bytes_inspected: usize) -> Self {
        match outcome {
            Outcome::Identified(d) => Self {
                outcome: outcome.word(),
                app: Some(d.app),
                confidence: Some(d.confidence),
                rationale: Some(d.rationale),
                server_name: d.server_fqdn().map(|s| s.to_string()),
                bytes_inspected,
            },
            _ => Self {
                outcome: outcome.word(),
                app: None,
                confidence: None,
                rationale: None,
                server_name: None,
                bytes_inspected,
            },
        }
    }

    pub fn is_identified(&self) -> bool {
        self.outcome == "identified"
    }
}

/// 会话级 TCP 统计（`CYS-TRF-015`）。
///
/// 三个设计决定，都不是风格问题：
///
/// 1. **它是会话级，不是方向级**。一条会话出一份记录（`pipeline::finish` 按
///    `sessions_sorted()` 逐会话产记录，键是规范方向），所以下面这些数与
///    `packets`/`bytes` 一样是"这条会话的合计"，下游按记录求和**不会重复计数**。
/// 2. **重传/乱序/RTT/上下行是 `Option`，`seq_judged` 不是**。`retransmissions == None`
///    的含义是"这个会话没有任何序号输入"（截断采集 / 只看标志位的调用路径），而
///    `Some(0)` 的含义是"判定过了，确实没有重传"。把前者落成 `0` 会让下游读到
///    "全网零重传"，而那是一份没有证据的结论。`seq_judged` 恒有值：它就是
///    "这条会话到底被判定了多少个段"的样本量，也是把上面两种情况区分开的依据。
/// 3. **上下行存字节而不是比例**。比例上界无限、且 0 分母要额外表达；存
///    `uplink_bytes`/`downlink_bytes` 后查询侧除一下就有比例，还留着样本量。
///    发起方未知（中途接入）⇒ 两者都是 `None`，不拿字典序一侧兜底。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpSessionStats {
    /// 参与过重传/乱序判定的段数（两侧合计）。非 TCP 会话整个结构体为 `None`。
    pub seq_judged: u64,
    /// 重传段数。`None` = 没有任何序号输入（**不是** 0）。
    pub retransmissions: Option<u64>,
    /// 乱序段数。同上语义。
    pub out_of_order: Option<u64>,
    /// 握手 RTT（SYN → 对侧 SYN/ACK，微秒）。没见到完整握手 ⇒ `None`（中途接入不猜）。
    pub handshake_rtt_us: Option<u64>,
    /// 发起方方向字节（口径同 `FlowRecord::bytes`：IP 载荷长度，含四层头）。
    pub uplink_bytes: Option<u64>,
    /// 应答方方向字节。同上。
    pub downlink_bytes: Option<u64>,
}

/// 一条流记录。
#[derive(Debug, Clone, PartialEq)]
pub struct FlowRecord {
    pub schema_version: u32,
    /// 会话 id（同一双向会话的两个方向共用一个 id）。
    pub session_id: u64,
    /// **规范**（方向无关）五元组。方向级明细在 `counters` 的 fwd/rev 中。
    pub key: FlowKey,
    /// 非 TCP 协议没有连接状态，故为 `None`。
    pub tcp_state: Option<TcpState>,
    /// 发起方；没见过 SYN 时为 `None`（中途接入不猜）。
    pub initiator: Option<Side>,
    pub adopted_midstream: bool,
    /// 非法 TCP 迁移次数（"被拒绝"的证据，不是被丢弃的包）。
    pub illegal_tcp_events: u64,
    /// 会话级 TCP 统计（重传/乱序/RTT/上下行）。**非 TCP 会话为 `None`** ——
    /// 这些量对 UDP/ICMP 没有定义，写 0 等于把"不适用"说成"没有异常"。
    pub tcp_stats: Option<TcpSessionStats>,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub packets: u64,
    pub bytes: u64,
    pub direction_switches: u64,
    pub features: FeatureVector,
    pub app: AppInfo,
    /// 风险评分。CYS-TRF-031 落地前恒为 `None`。
    ///
    /// 写 `null` 而不是 `0.0`：0.0 在下游是"已评分且判定为无风险"，
    /// 与"还没有评分"混在一起，会让风控面板看起来"全网零风险"。
    pub risk_score: Option<f64>,
}

impl FlowRecord {
    /// 序列化成一行 JSON（不含换行）。
    pub fn to_json_line(&self) -> String {
        let mut s = String::with_capacity(1024);
        s.push('{');
        push_key(&mut s, "schema_version");
        s.push_str(&self.schema_version.to_string());

        s.push(',');
        push_key(&mut s, "session_id");
        s.push_str(&self.session_id.to_string());

        // ---- flow ----
        s.push_str(",\"flow\":{");
        push_key(&mut s, "src_ip");
        escape_json_into(&mut s, &self.key.src_ip.to_string());
        s.push(',');
        push_key(&mut s, "src_port");
        s.push_str(&self.key.src_port.to_string());
        s.push(',');
        push_key(&mut s, "dst_ip");
        escape_json_into(&mut s, &self.key.dst_ip.to_string());
        s.push(',');
        push_key(&mut s, "dst_port");
        s.push_str(&self.key.dst_port.to_string());
        s.push(',');
        push_key(&mut s, "proto");
        s.push_str(&self.key.proto.number().to_string());
        s.push(',');
        push_key(&mut s, "proto_name");
        escape_json_into(&mut s, self.key.proto.as_str());
        s.push('}');

        // ---- tcp ----
        s.push_str(",\"tcp\":{");
        push_key(&mut s, "state");
        match self.tcp_state {
            Some(st) => escape_json_into(&mut s, st.as_str()),
            None => s.push_str("null"),
        }
        s.push(',');
        push_key(&mut s, "initiator");
        match self.initiator {
            Some(side) => escape_json_into(&mut s, side_word(side)),
            None => s.push_str("null"),
        }
        s.push(',');
        push_key(&mut s, "adopted_midstream");
        s.push_str(if self.adopted_midstream {
            "true"
        } else {
            "false"
        });
        s.push(',');
        push_key(&mut s, "illegal_events");
        s.push_str(&self.illegal_tcp_events.to_string());
        // ---- 会话级 TCP 统计（CYS-TRF-015）----
        // 非 TCP 会话也必须把这六个键写出来（全 null）：键集合按版本固定，
        // 不能随流量构成变化 —— 否则列式侧"这一条少一列"的表现是插入失败，
        // 而 JSONL 侧的表现是下游按行取键时偶发 KeyError。
        let empty = TcpSessionStats::default();
        let ts = self.tcp_stats.as_ref().unwrap_or(&empty);
        let unobserved = self.tcp_stats.is_none();
        s.push(',');
        push_key(&mut s, "seq_judged");
        if unobserved {
            s.push_str("null");
        } else {
            s.push_str(&ts.seq_judged.to_string());
        }
        for (key, val) in [
            ("retransmissions", ts.retransmissions),
            ("out_of_order", ts.out_of_order),
            ("handshake_rtt_us", ts.handshake_rtt_us),
            ("uplink_bytes", ts.uplink_bytes),
            ("downlink_bytes", ts.downlink_bytes),
        ] {
            s.push(',');
            push_key(&mut s, key);
            match val {
                Some(v) => s.push_str(&v.to_string()),
                None => s.push_str("null"),
            }
        }
        s.push('}');

        // ---- time ----
        s.push_str(",\"time\":{");
        push_key(&mut s, "first_seen_us");
        s.push_str(&self.first_seen_us.to_string());
        s.push(',');
        push_key(&mut s, "last_seen_us");
        s.push_str(&self.last_seen_us.to_string());
        s.push(',');
        push_key(&mut s, "duration_us");
        s.push_str(
            &self
                .last_seen_us
                .saturating_sub(self.first_seen_us)
                .to_string(),
        );
        s.push('}');

        // ---- counters ----
        s.push_str(",\"counters\":{");
        push_key(&mut s, "packets");
        s.push_str(&self.packets.to_string());
        s.push(',');
        push_key(&mut s, "bytes");
        s.push_str(&self.bytes.to_string());
        s.push(',');
        push_key(&mut s, "direction_switches");
        s.push_str(&self.direction_switches.to_string());
        s.push('}');

        // ---- app ----
        s.push_str(",\"app\":{");
        push_key(&mut s, "outcome");
        escape_json_into(&mut s, self.app.outcome);
        s.push(',');
        push_key(&mut s, "app");
        match self.app.app {
            Some(app) => escape_json_into(&mut s, app.as_str()),
            None => s.push_str("null"),
        }
        s.push(',');
        push_key(&mut s, "app_id");
        match self.app.app {
            Some(app) => s.push_str(&app.as_u32().to_string()),
            None => s.push_str("null"),
        }
        s.push(',');
        push_key(&mut s, "confidence");
        match self.app.confidence {
            Some(c) => escape_json_into(&mut s, c.as_str()),
            None => s.push_str("null"),
        }
        s.push(',');
        push_key(&mut s, "rationale");
        match self.app.rationale {
            Some(r) => escape_json_into(&mut s, r),
            None => s.push_str("null"),
        }
        s.push(',');
        push_key(&mut s, "server_name");
        match &self.app.server_name {
            Some(n) => escape_json_into(&mut s, n),
            None => s.push_str("null"),
        }
        s.push(',');
        push_key(&mut s, "bytes_inspected");
        s.push_str(&self.app.bytes_inspected.to_string());
        s.push('}');

        // ---- features ----
        s.push_str(",\"features\":{");
        push_key(&mut s, "schema_version");
        s.push_str(&self.features.schema_version.to_string());
        s.push(',');
        self.features.json_pairs_into(&mut s);
        s.push('}');

        // ---- risk ----
        s.push(',');
        push_key(&mut s, "risk_score");
        match self.risk_score {
            Some(v) => s.push_str(&json_number(v)),
            None => s.push_str("null"),
        }
        s.push('}');
        s
    }
}

/// 记录里出现的顶层列（供 schema 校验与文档共用，避免"文档写一版、代码写一版"）。
pub const TOP_LEVEL_COLUMNS: [&str; 9] = [
    "schema_version",
    "session_id",
    "flow",
    "tcp",
    "time",
    "counters",
    "app",
    "features",
    "risk_score",
];

/// 特征块里除 `schema_version` 之外的列名（与 `feature::FEATURE_NAMES` 同源）。
pub fn feature_columns() -> &'static [&'static str] {
    &crate::feature::FEATURE_NAMES
}

/// `tcp` 块里的键，**顺序与写出顺序一致**。
///
/// 为什么钉到块内而不是只看顶层：v2 的六个新键全部落在 `tcp` 块里，顶层仍是 9 个。
/// 只看 `TOP_LEVEL_COLUMNS` 的门禁会对"加了一个块内键"完全无感，而列式侧少一列的
/// 表现是插入失败、JSONL 侧的表现是下游偶尔 KeyError —— 两者都不会在这条断言上红。
pub const TCP_BLOCK_COLUMNS: [&str; 10] = [
    "state",
    "initiator",
    "adopted_midstream",
    "illegal_events",
    "seq_judged",
    "retransmissions",
    "out_of_order",
    "handshake_rtt_us",
    "uplink_bytes",
    "downlink_bytes",
];

/// 批量写 JSONL（每行一条，行尾 `\n`）。返回写出的记录数。
///
/// 用 `BufWriter` 由调用方提供：记录可能很多（省网级单次分析百万级会话），
/// 逐条 flush 会把 I/O 变成瓶颈。
pub fn write_jsonl<W: Write>(w: &mut W, records: &[FlowRecord]) -> io::Result<usize> {
    let mut n = 0usize;
    for r in records {
        w.write_all(r.to_json_line().as_bytes())?;
        w.write_all(b"\n")?;
        n += 1;
    }
    Ok(n)
}

/// 记录层的方向词汇：`fwd` / `rev`。
///
/// `pub(crate)` 而不是私有：列式落盘（`storage::project_row`）必须用**同一份**词汇，
/// 两处各写一份时，改一边会让 JSONL 与列式对同一条记录说不同的话。
///
/// 为什么不直接把 `Side` 的 `"a"`/`"b"` 写进记录：落盘之后没有代码在旁边解释，
/// `"a"` 完全不可读；而 `fwd`/`rev` 与特征名 `fwd_packets`/`rev_packets` 是同一套
/// 方向语义（都按**规范端点序**），读记录的人不需要再猜一次。
///
/// 注意它**不是**"谁发起"：中途接入时没有 SYN，`initiator` 为 `null`；
/// 即便有值，也只有在握手顺序与规范端点序一致时才恰好等于 fwd。
pub(crate) fn side_word(side: Side) -> &'static str {
    match side {
        Side::A => "fwd",
        Side::B => "rev",
    }
}

fn push_key(out: &mut String, key: &str) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
}

/// JSON 字符串转义（RFC 8259 §7）。
///
/// 只做"必须做"的部分：引号、反斜杠、控制字符。**不**转义非 ASCII ——
/// JSON 允许 UTF-8 原样输出，把 `example.com` 或中文域名转成 `\uXXXX`
/// 只是让记录更难读，且会让下游的字符串比较多一层编解码。
pub fn escape_json_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::identify;
    use crate::feature::{FeatureExtractor, FEATURE_COUNT, FEATURE_SCHEMA_VERSION};
    use crate::flow::{FlowKey, IPPROTO_TCP, IPPROTO_UDP};
    use crate::testjson::{Json, JsonParser};

    /// 用仓库既有的最小解析器解析一行（不引 serde：零第三方依赖是红线）。
    fn parse(line: &str) -> Json {
        let mut p = JsonParser::new(line);
        p.value()
    }

    fn obj_len(v: &Json) -> usize {
        match v {
            Json::Obj(m) => m.len(),
            other => panic!("期望对象，得到 {other:?}"),
        }
    }

    /// 取 `a.b` 的整数取值。
    fn num(v: &Json, path: &[&str]) -> Option<i64> {
        let mut cur = v;
        for key in path {
            cur = cur.get(key)?;
        }
        cur.as_i64()
    }

    /// 取 `a.b` 的字符串取值。
    fn text<'a>(v: &'a Json, path: &[&str]) -> Option<&'a str> {
        let mut cur = v;
        for key in path {
            cur = cur.get(key)?;
        }
        cur.as_str()
    }

    fn sample_record() -> FlowRecord {
        let key = FlowKey::new_ipv4([10, 0, 0, 1], 40000, [93, 184, 216, 34], 443, IPPROTO_TCP);
        let mut ex = FeatureExtractor::default();
        ex.observe(&crate::feature::FlowSample::len_only(
            Side::A,
            1200,
            1_000_000,
        ));
        ex.observe(&crate::feature::FlowSample::len_only(
            Side::B,
            800,
            1_500_000,
        ));
        FlowRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            session_id: 7,
            key,
            tcp_state: Some(TcpState::Established),
            initiator: Some(Side::A),
            adopted_midstream: false,
            illegal_tcp_events: 0,
            tcp_stats: Some(TcpSessionStats {
                seq_judged: 5,
                retransmissions: Some(1),
                // `Some(0)` 而不是 `None`：这是"判定了 5 个段，确实没乱序"。
                out_of_order: Some(0),
                handshake_rtt_us: Some(1_500),
                uplink_bytes: Some(1_200),
                downlink_bytes: Some(800),
            }),
            first_seen_us: 1_000_000,
            last_seen_us: 2_000_000,
            packets: 2,
            bytes: 2000,
            direction_switches: 1,
            features: ex.vector(),
            app: AppInfo::not_inspected(),
            risk_score: None,
        }
    }

    #[test]
    fn json_line_is_parseable_by_a_real_parser() {
        // 手写 JSON 必须用**真正的解析器**验证，只靠 contains 猜不出括号与转义错。
        let line = sample_record().to_json_line();
        let v = parse(&line);
        assert_eq!(num(&v, &["schema_version"]), Some(2));
        assert_eq!(num(&v, &["session_id"]), Some(7));
        assert_eq!(num(&v, &["flow", "src_port"]), Some(40000));
        assert_eq!(num(&v, &["flow", "proto"]), Some(6));
        assert_eq!(text(&v, &["flow", "proto_name"]), Some("tcp"));
        assert_eq!(text(&v, &["tcp", "state"]), Some("established"));
        assert_eq!(text(&v, &["tcp", "initiator"]), Some("fwd"));
        assert_eq!(num(&v, &["counters", "bytes"]), Some(2000));
        assert_eq!(num(&v, &["time", "duration_us"]), Some(1_000_000));
        let feats = v.get("features").expect("features 块");
        assert_eq!(obj_len(feats), FEATURE_COUNT + 1);
        assert_eq!(
            num(feats, &["schema_version"]),
            Some(i64::from(FEATURE_SCHEMA_VERSION))
        );
        assert!(v.get("risk_score").expect("risk_score 必须在").is_null());
    }

    #[test]
    fn all_declared_columns_are_present_in_every_line() {
        let line = sample_record().to_json_line();
        let v = parse(&line);
        for col in TOP_LEVEL_COLUMNS {
            assert!(v.get(col).is_some(), "列 {col} 缺失");
        }
        // 特征列一个都不能少：少一列时下游按列取数会静默取到 None。
        let feats = v.get("features").expect("features 块");
        for name in feature_columns() {
            assert!(feats.get(name).is_some(), "特征列 {name} 缺失");
        }
        assert_eq!(
            obj_len(&v),
            TOP_LEVEL_COLUMNS.len(),
            "顶层列数必须与契约一致"
        );
    }

    #[test]
    fn non_tcp_records_have_null_state_and_initiator() {
        let mut r = sample_record();
        r.key = FlowKey::new_ipv4([10, 0, 0, 1], 53, [8, 8, 8, 8], 53, IPPROTO_UDP);
        r.tcp_state = None;
        r.initiator = None;
        let v = parse(&r.to_json_line());
        assert!(v.get("tcp").unwrap().get("state").unwrap().is_null());
        assert!(v.get("tcp").unwrap().get("initiator").unwrap().is_null());
        assert_eq!(text(&v, &["flow", "proto_name"]), Some("udp"));
        // 非 TCP 的 tcp 块仍必须存在且**键集不随协议变**（否则读取方要分两种模式解析）。
        // v2 后是 10 键：原 4 个 + 会话级 TCP 统计 6 个（全 null）。
        assert_eq!(obj_len(v.get("tcp").unwrap()), TCP_BLOCK_COLUMNS.len());
    }

    #[test]
    fn not_inspected_is_distinguishable_from_unknown() {
        let mut r = sample_record();
        r.app = AppInfo::not_inspected();
        let v = parse(&r.to_json_line());
        assert_eq!(text(&v, &["app", "outcome"]), Some("not_inspected"));
        assert!(v.get("app").unwrap().get("app").unwrap().is_null());
        assert_eq!(num(&v, &["app", "bytes_inspected"]), Some(0));

        // 真正"看过但不认识"是 unknown，且必须带上实际喂进去的字节数。
        let payload = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
        let outcome = identify(payload, 6, 9999);
        r.app = AppInfo::from_outcome(&outcome, payload.len());
        let v2 = parse(&r.to_json_line());
        assert_eq!(text(&v2, &["app", "outcome"]), Some("unknown"));
        assert_eq!(num(&v2, &["app", "bytes_inspected"]), Some(16));
        assert!(v2.get("app").unwrap().get("rationale").unwrap().is_null());
    }

    #[test]
    fn identified_app_carries_evidence_and_extracted_name() {
        // 一个最小 DNS 查询（与 dpi 向量同构）。
        let payload: &[u8] = &[
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        let outcome = identify(payload, 17, 53);
        assert_eq!(outcome.word(), "identified");
        let info = AppInfo::from_outcome(&outcome, payload.len());
        assert!(info.is_identified());
        assert_eq!(info.app, Some(AppId::Dns));
        assert!(info.rationale.is_some(), "识别结论必须带判据");

        let mut r = sample_record();
        r.app = info;
        let v = parse(&r.to_json_line());
        assert_eq!(text(&v, &["app", "app"]), Some("dns"));
        assert_eq!(text(&v, &["app", "confidence"]), Some("high"));
        assert!(num(&v, &["app", "app_id"]).is_some());
        assert!(v
            .get("app")
            .unwrap()
            .get("rationale")
            .unwrap()
            .as_str()
            .is_some());
    }

    #[test]
    fn risk_score_null_is_not_zero() {
        let line = sample_record().to_json_line();
        assert!(line.contains("\"risk_score\":null"));
        assert!(!line.contains("\"risk_score\":0"));
    }

    #[test]
    fn escape_handles_quotes_backslashes_and_control_chars() {
        let mut out = String::new();
        escape_json_into(&mut out, "a\"b\\c\nd\te\u{1}f");
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\te\\u0001f\"");
        // 非 ASCII 原样输出（不转 \uXXXX）：转义只让记录更难读。
        let mut cn = String::new();
        escape_json_into(&mut cn, "例子.测试");
        assert_eq!(cn, "\"例子.测试\"");
    }

    #[test]
    fn control_chars_in_server_name_do_not_break_the_line() {
        // 异常/恶意 SNI 里带引号或换行时，整行 JSONL 必须仍是一行且可解析。
        let mut r = sample_record();
        r.app.outcome = "identified";
        r.app.server_name = Some("bad\"name\nwith\\escape".to_string());
        let line = r.to_json_line();
        assert_eq!(line.matches('\n').count(), 0, "换行必须被转义");
        let v = parse(&line);
        assert_eq!(
            text(&v, &["app", "server_name"]),
            Some("bad\"name\nwith\\escape")
        );
    }

    #[test]
    fn ipv6_key_round_trips_as_a_string() {
        let mut r = sample_record();
        r.key = FlowKey::new_ipv6(
            "2001:db8::1".parse().unwrap(),
            1234,
            "2001:db8::2".parse().unwrap(),
            443,
            IPPROTO_TCP,
        );
        let v = parse(&r.to_json_line());
        assert_eq!(text(&v, &["flow", "src_ip"]), Some("2001:db8::1"));
        assert_eq!(text(&v, &["flow", "dst_ip"]), Some("2001:db8::2"));
    }

    #[test]
    fn duration_is_derived_and_never_negative() {
        let mut r = sample_record();
        r.first_seen_us = 5_000_000;
        r.last_seen_us = 1_000_000; // 乱序到达的极端情形
        let v = parse(&r.to_json_line());
        assert_eq!(num(&v, &["time", "duration_us"]), Some(0));
    }

    #[test]
    fn tcp_block_key_set_and_order_match_the_v2_contract() {
        // 键集合与**顺序**一起钉：下游里有按位置取数的（CSV/Parquet 导出），
        // 只改顺序不改名字时名字断言拓不到。
        let v = parse(&sample_record().to_json_line());
        let blk = v.get("tcp").expect("tcp 块");
        let Json::Obj(pairs) = blk else {
            panic!("tcp 必须是对象");
        };
        let got: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(got, TCP_BLOCK_COLUMNS.to_vec());
        assert_eq!(num(&v, &["tcp", "seq_judged"]), Some(5));
        assert_eq!(num(&v, &["tcp", "retransmissions"]), Some(1));
        assert_eq!(num(&v, &["tcp", "out_of_order"]), Some(0));
        assert_eq!(num(&v, &["tcp", "handshake_rtt_us"]), Some(1_500));
        assert_eq!(num(&v, &["tcp", "uplink_bytes"]), Some(1_200));
        assert_eq!(num(&v, &["tcp", "downlink_bytes"]), Some(800));
    }

    #[test]
    fn non_tcp_record_still_carries_all_six_keys_and_they_are_null() {
        // “UDP 没有重传这个概念”与“TCP 会话没重传”不能都写成 0；非 TCP 时整个
        // tcp_stats 为 None ⇒ 六键全部存而在、全部 null（键集不随流量构成变）。
        let mut r = sample_record();
        r.tcp_stats = None;
        let v = parse(&r.to_json_line());
        let Json::Obj(pairs) = v.get("tcp").expect("tcp 块") else {
            panic!("tcp 必须是对象");
        };
        let got: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(got, TCP_BLOCK_COLUMNS.to_vec(), "非 TCP 不得省键");
        for key in [
            "seq_judged",
            "retransmissions",
            "out_of_order",
            "handshake_rtt_us",
            "uplink_bytes",
            "downlink_bytes",
        ] {
            let item = pairs.iter().find(|(k, _)| k == key).expect(key);
            assert!(item.1.is_null(), "{key} 必须是 null，不是 0");
        }
    }

    #[test]
    fn zero_judged_segments_is_null_counts_while_real_zero_is_a_value() {
        // 本项最不能错的一条：截断采集（读不到序号）与“判定过了确实是 0”在
        // 记录里必须长得不一样。前者 seq_judged=0 而计数是 null；后者是 Some(0)。
        let mut r = sample_record();
        r.tcp_stats = Some(TcpSessionStats {
            seq_judged: 0,
            retransmissions: None,
            out_of_order: None,
            handshake_rtt_us: None,
            uplink_bytes: None,
            downlink_bytes: None,
        });
        let v = parse(&r.to_json_line());
        assert_eq!(num(&v, &["tcp", "seq_judged"]), Some(0), "样本量本身是事实");
        let Json::Obj(pairs) = v.get("tcp").expect("tcp 块") else {
            panic!("tcp 必须是对象");
        };
        for key in ["retransmissions", "out_of_order"] {
            let item = pairs.iter().find(|(k, _)| k == key).expect(key);
            assert!(item.1.is_null(), "{key} 在无判定输入时不得写成 0");
        }
    }

    #[test]
    fn feature_columns_match_the_layout_in_order() {
        // 记录里的特征列顺序必须与 FEATURE_NAMES 完全一致：
        // 顺序不同时按列位置消费的下游（CSV/Parquet 导出）会张冠李戴。
        let mut r = sample_record();
        r.features = FeatureExtractor::default().vector();
        let line = r.to_json_line();
        let v = parse(&line);
        let feats = v.get("features").expect("features 块");
        let Json::Obj(pairs) = feats else {
            panic!("features 必须是对象");
        };
        let got: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        let mut want: Vec<&str> = vec!["schema_version"];
        want.extend(feature_columns().iter().copied());
        assert_eq!(got, want);
        // 空提取器：所有特征为 0，且没有 NaN/inf 混进 JSON。
        assert!(!line.contains("NaN") && !line.contains("inf"));
    }

    #[test]
    fn write_jsonl_emits_one_line_per_record_with_trailing_newline() {
        let recs = vec![sample_record(), sample_record()];
        let mut buf = Vec::new();
        let n = write_jsonl(&mut buf, &recs).expect("写盘成功");
        assert_eq!(n, 2);
        let text_out = String::from_utf8(buf).expect("UTF-8");
        assert!(text_out.ends_with('\n'));
        let lines: Vec<&str> = text_out.lines().collect();
        assert_eq!(lines.len(), 2);
        for l in lines {
            parse(l);
        }
    }
}
