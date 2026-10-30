// storage/mod.rs —— FlowRecord 的**列式落盘契约**（CYS-STO-002 / CYS-STO-007 的第一步）。
//
// ## 为什么要有这一层
//
// `record::FlowRecord` 的 JSONL 出口是**我们自己的格式**：每条约 1066 B 未压缩、
// gzip 后 79.4 B（`CYS-INF-041` 实测）。那两个数撑起容量表的同时也暴露了它的天花板：
// JSONL 是**行式文本**，同一个字段名每行重复一次，字段间的压缩机会基本浪费。
// 省网量级（20 Tbps × 1:1000 ≈ 5 Mrec/s）真正落盘时用的是列式数据库，而容量表里
// 「列式能压到几十 B/记录」这一档**始终是假设，没人量过**。
//
// 所以这一层要同时交出三件东西：
//   1. **列清单的单一真源**（`FLOW_COLUMNS`）：DDL、编码器、第三方对照三者必须吃同一份
//      定义。任何一处手抄都会漂移，而漂移的表现是"某列静默取到 null"。
//   2. **ClickHouse `Native` 块编码器/解码器**（`native.rs`）：字节格式对齐参考实现，
//      由真实 ClickHouse 逐字节裁判（见 `scripts/verify/check-columnar.sh`）。
//   3. **建表 DDL 生成物**（`storage/clickhouse/001_flows.sql`）：由本模块生成，
//      顺带把 `CYS-TRF-033` 那条「未达成：与 storage/clickhouse 建表 DDL 对齐」补掉。
//
// ## 三条不可退让的约定
//
// 1. **缺失与零值必须能区分**（与 `record/mod.rs` 同一条红线）。`tcp_state` 在非 TCP
//    记录上是 `NULL`，不是空串；`risk_score` 没评分是 `NULL`，不是 0.0。列式里没有
//    "少一个键"这种表达方式，所以可空列一律用 `Nullable(...)`，而 null 位图**必须真写**
//    （ClickHouse 的 Nullable 序列化是「掩码字节 + 全部行都写嵌套值」，见 native.rs）。
//
// 2. **地址不降级**：`src_ip`/`dst_ip` 存成 `IPv6`（16 字节二进制），IPv4 走 RFC 4291
//    §2.5.5.2 的 IPv4-mapped 形式（`::ffff:a.b.c.d`）。文本地址在列式里是最贵的一种存法
//    （每条约 30 B 且压缩率差），而 mapped 形式与 ClickHouse 自己的 `toIPv6('10.0.0.1')`
//    **逐字节相同**（已在门禁里对照），因此反解不需要我们的代码参与。
//    代价是「同一条记录里源与目的必须同族」：混族时 `::ffff:` 前缀无法区分"v4 地址"与
//    "恰好长这样的 v6 地址"，故 `project_row` 直接拒绝混族而不是猜（见 `ProjectError`）。
//
// 3. **非有限浮点拒绝写出**。JSONL 对 `NaN/inf` 写 `null`（`feature::json_number`），
//    而 `Float64` 列没有 null 可用：写 NaN 位模式会让"这一条到底是不是数"取决于
//    下游读法。故这里显式报错并指出 session id 与特征名 —— 宁可不出产物，
//    也不出一条只有我们能解释的记录。

pub mod native;

use std::net::IpAddr;

use crate::feature::FEATURE_NAMES;
use crate::record::FlowRecord;
use crate::tcp::Side;

/// 列的取值种类。`ch_type()` 给出 ClickHouse 类型名，`Kind` 决定编码宽度。
///
/// 刻意只有这七种：每加一种类型就多一份「我们理解的字节格式」，而理解本身
/// 只有参考实现能裁判。类型集合越窄，第三方逐字节比对覆盖到的比例越高。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    U8,
    U16,
    U32,
    U64,
    F64,
    /// 16 字节二进制地址，字节序与 `IPv6NumToString` 的输入一致（大端）。
    Ip6,
    /// varint 长度 + UTF-8 字节。
    Str,
}

impl Kind {
    pub const fn ch_type(self) -> &'static str {
        match self {
            Kind::U8 => "UInt8",
            Kind::U16 => "UInt16",
            Kind::U32 => "UInt32",
            Kind::U64 => "UInt64",
            Kind::F64 => "Float64",
            Kind::Ip6 => "IPv6",
            Kind::Str => "String",
        }
    }

    /// 列式落盘的**裸宽度**（不含 varint 长度、不含 null 掩码、不含压缩）。
    ///
    /// 它只用于"字节花在哪"的诊断输出，不能当成实测值 —— 实测必须由产物文件算。
    pub const fn raw_width(self) -> usize {
        match self {
            Kind::U8 => 1,
            Kind::U16 => 2,
            Kind::U32 => 4,
            Kind::U64 => 8,
            Kind::F64 => 8,
            Kind::Ip6 => 16,
            Kind::Str => 0, // 变长，由调用方按实际字节计
        }
    }

    /// 由 ClickHouse 类型名反解种类（解码侧用它校验"声明的类型能不能真的读"）。
    pub fn from_ch_type(t: &str) -> Option<Self> {
        Some(match t {
            "UInt8" => Kind::U8,
            "UInt16" => Kind::U16,
            "UInt32" => Kind::U32,
            "UInt64" => Kind::U64,
            "Float64" => Kind::F64,
            "IPv6" => Kind::Ip6,
            "String" => Kind::Str,
            _ => return None,
        })
    }
}

/// 一列的完整声明。
///
/// **线路类型与落库类型是两回事**，这里刻意分开：
///   * `kind` + `nullable` ⇒ `ch_type()`，写进 Native 块（编码器只认这个）。
///   * `low_cardinality` + `codec` ⇒ `ddl_type()`，写进建表 DDL（存储侧优化）。
///
/// 为什么可以不一致：ClickHouse 在 `INSERT ... FORMAT Native` 时会把
/// `String` 自动转成 `LowCardinality(String)`（2026-10-19 在参考实现上实测，
/// 含 `LowCardinality(Nullable(String))`）。于是写入侧保持最窄的类型集合，
/// 压缩收益全部落在 DDL —— 实测同一批 20,000 条多样语料：
/// 默认 LZ4 33.0 B/记录 → 调优后 4.5 B/记录（见 HANDOFF 列式落盘一节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnSpec {
    pub name: &'static str,
    pub kind: Kind,
    /// `true` ⇒ DDL 里是 `Nullable(T)`，线路上多一个掩码字节/行。
    pub nullable: bool,
    /// 归属块（与 JSONL 的嵌套块同名），供文档与"字节花在哪"的分组统计。
    pub group: &'static str,
    /// 对应的 JSONL 取值路径（`a.b` 形式）。第三方对照脚本按它从 JSONL 取值，
    /// 于是"列名改了但对照没改"会立刻变成对不上，而不是悄悄跳过。
    pub jsonl_path: &'static str,
    /// 写进 DDL 的列注释（落盘之后没有代码在旁边解释）。
    pub comment: &'static str,
    /// 存储侧用 `LowCardinality(...)`。**只允许用在 `Kind::Str` 上**
    /// （DDL 生成时断言）：给数值列套 LC 不会报错但也没收益，只会让 DDL 难读。
    pub low_cardinality: bool,
    /// 存储侧编解码器（如 `Delta(8), ZSTD(1)`）；空串 = 用引擎默认（LZ4）。
    pub codec: &'static str,
}

impl ColumnSpec {
    /// 线路上出现的类型名（含 `Nullable`）：Native 块头里写的就是它。
    pub fn ch_type(&self) -> String {
        if self.nullable {
            format!("Nullable({})", self.kind.ch_type())
        } else {
            self.kind.ch_type().to_string()
        }
    }

    /// DDL 里的列类型（存储侧优化后的形态）。
    ///
    /// 与 `ch_type()` 的差异**只能是对存储的优化，不能是对数据的改写**：
    /// `LowCardinality(String)` 与 `String` 存的是同一串字节，只是加了字典编码。
    /// 数值列套 LC 不报错但无收益，所以这里用断言挡住（不是注释里的"请勿"）。
    pub fn ddl_type(&self) -> String {
        let wire = self.ch_type();
        if self.low_cardinality {
            assert_eq!(
                self.kind,
                Kind::Str,
                "列 {} 不是 String 却要求 LowCardinality",
                self.name
            );
            return format!("LowCardinality({wire})");
        }
        wire
    }

    /// DDL 里这一列的完整定义（类型 + 可选 CODEC + 注释）。
    pub fn ddl_column(&self) -> String {
        let mut s = format!("{} {}", self.name, self.ddl_type());
        // ClickHouse parses COMMENT before CODEC in a column declaration.
        s.push_str(&format!(" COMMENT '{}'", self.comment.replace('\'', "\\'")));
        if !self.codec.is_empty() {
            s.push_str(&format!(" CODEC({})", self.codec));
        }
        s
    }
}

/// 一个取值。`Null` 只允许出现在 `nullable = true` 的列上。
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    F64(f64),
    Ip6([u8; 16]),
    Str(&'a str),
    Null,
}

/// 投影失败。两种都是"不能伪装成可落盘数据"的情形。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectError {
    /// 源与目的地址族不同：IPv6 单列 + mapped 前缀无法无损表达（见模块头第 2 条）。
    MixedIpFamily { session_id: u64, src: u8, dst: u8 },
    /// 特征值非有限（NaN/inf）。
    NonFiniteFeature {
        session_id: u64,
        feature: &'static str,
    },
}

impl std::fmt::Display for ProjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectError::MixedIpFamily {
                session_id,
                src,
                dst,
            } => write!(
                f,
                "会话 {session_id} 的源/目的地址族不同（src=IPv{src} dst=IPv{dst}）：\
                 列式用单列 IPv6 + ::ffff: 前缀表达 IPv4，混族时该前缀无法区分「IPv4 地址」\
                 与「恰好形如 ::ffff:x 的 IPv6 地址」，拒绝投影"
            ),
            ProjectError::NonFiniteFeature {
                session_id,
                feature,
            } => write!(
                f,
                "会话 {session_id} 的特征 `{feature}` 不是有限数：Float64 列没有 null 可用，\
                 写出 NaN/inf 位模式会让下游把它读成数还是缺值取决于读法，拒绝投影"
            ),
        }
    }
}

impl std::error::Error for ProjectError {}

// ---------------------------------------------------------------------------
// 列清单：唯一真源
// ---------------------------------------------------------------------------

/// 派生列：`ip_family` 不在 JSONL 里，是 `IPv4|IPv6 → 4|6` 的投影，
/// 保留它是为了让反解规则在 SQL 里可写、可核对（不必从字节的 `::ffff:` 猜）。
const DERIVED_JSONL: &str = "flow.src_ip(派生)";

/// 特征列在扁平表里的列名（带 `feat_` 前缀）。
///
/// 为什么必须加前缀：JSONL 的嵌套结构让 `counters.packets` 与 `features.packets`
/// 是两个不同的键，而**列式表没有嵌套**——同名列在 ClickHouse 建表时直接失败，
/// 更坏的情况是它建起来了而按名取数拿到另一列。前缀把"嵌套路径"压平成唯一列名。
const FEATURE_COLUMN_NAMES: [&str; crate::feature::FEATURE_COUNT] = [
    "feat_packets",
    "feat_bytes",
    "feat_fwd_packets",
    "feat_fwd_bytes",
    "feat_rev_packets",
    "feat_rev_bytes",
    "feat_fwd_byte_ratio",
    "feat_duration_us",
    "feat_byte_rate_bps",
    "feat_packet_rate_pps",
    "feat_mean_payload_len",
    "feat_min_payload_len",
    "feat_max_payload_len",
    "feat_stddev_payload_len",
    "feat_mean_iat_us",
    "feat_min_iat_us",
    "feat_max_iat_us",
    "feat_stddev_iat_us",
    "feat_direction_switches",
    "feat_small_packet_ratio",
    "feat_payload_entropy_bits",
];

fn feat(i: usize) -> ColumnSpec {
    ColumnSpec {
        name: FEATURE_COLUMN_NAMES[i],
        kind: Kind::F64,
        nullable: false,
        group: "features",
        jsonl_path: FEATURE_JSONL_PATHS[i],
        comment: FEATURE_COMMENTS[i],
        low_cardinality: false,
        // 特征列全是 Float64：Delta 对浮点没有意义（跨 1.0 边界会算出巨大差值），
        // 所以只压不差分 —— 实测 ZSTD(1) 在本组特征列上有效。
        codec: "ZSTD(1)",
    }
}

/// 特征列的 JSONL 路径（`features.<name>`）。
///
/// 与 `FEATURE_NAMES` 同长度、编译期钉住：加了特征却忘了补这里会编译失败，
/// 而不是"运行时对不上"（这类错只能靠类型系统，人肉数数不可靠）。
const FEATURE_JSONL_PATHS: [&str; crate::feature::FEATURE_COUNT] = [
    "features.packets",
    "features.bytes",
    "features.fwd_packets",
    "features.fwd_bytes",
    "features.rev_packets",
    "features.rev_bytes",
    "features.fwd_byte_ratio",
    "features.duration_us",
    "features.byte_rate_bps",
    "features.packet_rate_pps",
    "features.mean_payload_len",
    "features.min_payload_len",
    "features.max_payload_len",
    "features.stddev_payload_len",
    "features.mean_iat_us",
    "features.min_iat_us",
    "features.max_iat_us",
    "features.stddev_iat_us",
    "features.direction_switches",
    "features.small_packet_ratio",
    "features.payload_entropy_bits",
];

/// 特征列注释。DDL 落盘后是唯一能说明"这一列是什么口径"的地方。
const FEATURE_COMMENTS: [&str; crate::feature::FEATURE_COUNT] = [
    "包数（双向合计，与 counters.packets 同源）",
    "字节数（双向合计，含链路层头）",
    "正向包数（规范端点序，不是发起方）",
    "正向字节数",
    "反向包数",
    "反向字节数",
    "正向字节占比 0..1",
    "首末包时间差（微秒）",
    "字节速率 bit/s",
    "包速率 pkt/s",
    "载荷平均长度（字节）",
    "载荷最小长度",
    "载荷最大长度",
    "载荷长度标准差",
    "包间隔平均（微秒）",
    "包间隔最小（微秒）",
    "包间隔最大（微秒）",
    "包间隔标准差（微秒）",
    "方向切换次数",
    "小包占比（载荷 <=64B）0..1",
    "载荷字节熵（bit/字节）",
];

/// `flows` 表的列清单，**顺序即线路顺序**。
///
/// 增删列或改类型必须同时：① 抬 `RECORD_SCHEMA_VERSION` 的配套列契约版本
/// （`COLUMN_CONTRACT_VERSION`）、② 重新生成 DDL、③ 让门禁重跑第三方对照。
/// 只做其中一步的表现是"某一边仍能跑通但读出来是错的"。
pub const FLOW_COLUMNS: &[ColumnSpec] = &[
    // ---- meta ----
    ColumnSpec {
        name: "schema_version",
        kind: Kind::U32,
        nullable: false,
        group: "meta",
        jsonl_path: "schema_version",
        comment: "记录契约版本（FlowRecord.schema_version）",
        low_cardinality: false,
        codec: "Delta(4), ZSTD(1)",
    },
    ColumnSpec {
        name: "column_contract_version",
        kind: Kind::U32,
        nullable: false,
        group: "meta",
        jsonl_path: "(常量)",
        comment: "列契约版本：列名/类型/顺序变更必须抬它",
        low_cardinality: false,
        codec: "Delta(4), ZSTD(1)",
    },
    ColumnSpec {
        name: "session_id",
        kind: Kind::U64,
        nullable: false,
        group: "meta",
        jsonl_path: "session_id",
        comment: "会话 id（同一双向会话两个方向共用）",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    // ---- flow ----
    ColumnSpec {
        name: "ip_family",
        kind: Kind::U8,
        nullable: false,
        group: "flow",
        jsonl_path: DERIVED_JSONL,
        comment: "地址族 4|6（派生）；决定 IPv6 列里的 ::ffff: 前缀如何反解",
        low_cardinality: false,
        codec: "Delta(1), ZSTD(1)",
    },
    ColumnSpec {
        name: "src_ip",
        kind: Kind::Ip6,
        nullable: false,
        group: "flow",
        jsonl_path: "flow.src_ip",
        comment: "源地址；IPv4 以 RFC 4291 §2.5.5.2 的 ::ffff:a.b.c.d 存放",
        low_cardinality: false,
        codec: "ZSTD(1)",
    },
    ColumnSpec {
        name: "dst_ip",
        kind: Kind::Ip6,
        nullable: false,
        group: "flow",
        jsonl_path: "flow.dst_ip",
        comment: "目的地址；IPv4 同上",
        low_cardinality: false,
        codec: "ZSTD(1)",
    },
    ColumnSpec {
        name: "src_port",
        kind: Kind::U16,
        nullable: false,
        group: "flow",
        jsonl_path: "flow.src_port",
        comment: "源端口（ICMP 等无端口协议恒为 0）",
        low_cardinality: false,
        codec: "Delta(2), ZSTD(1)",
    },
    ColumnSpec {
        name: "dst_port",
        kind: Kind::U16,
        nullable: false,
        group: "flow",
        jsonl_path: "flow.dst_port",
        comment: "目的端口",
        low_cardinality: false,
        codec: "Delta(2), ZSTD(1)",
    },
    ColumnSpec {
        name: "proto",
        kind: Kind::U8,
        nullable: false,
        group: "flow",
        jsonl_path: "flow.proto",
        comment: "IANA 协议号（6=TCP 17=UDP 1=ICMP 58=ICMPv6）",
        low_cardinality: false,
        codec: "Delta(1), ZSTD(1)",
    },
    ColumnSpec {
        name: "proto_name",
        kind: Kind::Str,
        nullable: false,
        group: "flow",
        jsonl_path: "flow.proto_name",
        comment: "协议名（人可读；与 proto 同源）",
        low_cardinality: true,
        codec: "ZSTD(1)",
    },
    // ---- tcp ----
    ColumnSpec {
        name: "tcp_state",
        kind: Kind::Str,
        nullable: true,
        group: "tcp",
        jsonl_path: "tcp.state",
        comment: "TCP 末态；非 TCP 为 NULL（不是空串）",
        low_cardinality: true,
        codec: "ZSTD(1)",
    },
    ColumnSpec {
        name: "tcp_initiator",
        kind: Kind::Str,
        nullable: true,
        group: "tcp",
        jsonl_path: "tcp.initiator",
        comment: "发起方 fwd|rev；没见过 SYN 为 NULL（中途接入不猜）",
        low_cardinality: true,
        codec: "ZSTD(1)",
    },
    ColumnSpec {
        name: "adopted_midstream",
        kind: Kind::U8,
        nullable: false,
        group: "tcp",
        jsonl_path: "tcp.adopted_midstream",
        comment: "是否中途接入（1/0；列式不用 Bool 是为了少一种类型）",
        low_cardinality: false,
        codec: "Delta(1), ZSTD(1)",
    },
    ColumnSpec {
        name: "illegal_tcp_events",
        kind: Kind::U64,
        nullable: false,
        group: "tcp",
        jsonl_path: "tcp.illegal_events",
        comment: "非法 TCP 迁移次数（被拒绝的证据，不是被丢弃的包）",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    // ---- 会话级 TCP 统计（CYS-TRF-015，记录 v2）----
    // 六列全可空：`NULL` = 没有这项证据，`0` = 判定了且确实是 0。这两个数在下游
    // 含义相反（前者不能进分母），所以上面那行不能迿进列式：列式没有"缺键"这种
    // 表达，只能用 Nullable + null 位图（见 `native.rs` 的序列化口径）。
    ColumnSpec {
        name: "tcp_seq_judged",
        kind: Kind::U64,
        nullable: true,
        group: "tcp",
        jsonl_path: "tcp.seq_judged",
        comment: "参与重传/乱序判定的段数（样本量）；0 表示本会话无判定输入，非 TCP 为 NULL",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    ColumnSpec {
        name: "tcp_retransmissions",
        kind: Kind::U64,
        nullable: true,
        group: "tcp",
        jsonl_path: "tcp.retransmissions",
        comment: "重传段数（口径与 Wireshark retransmission 在同一条 pcap 上逐模式对齐）；无判定输入为 NULL",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    ColumnSpec {
        name: "tcp_out_of_order",
        kind: Kind::U64,
        nullable: true,
        group: "tcp",
        jsonl_path: "tcp.out_of_order",
        comment: "乱序段数（含部分重叠与补洞段）；缺段不计此项而是 lost_segment 口径；无判定输入为 NULL",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    ColumnSpec {
        name: "tcp_handshake_rtt_us",
        kind: Kind::U64,
        nullable: true,
        group: "tcp",
        jsonl_path: "tcp.handshake_rtt_us",
        comment: "握手 RTT（SYN → 对侧 SYN/ACK，微秒）；与 tshark iRTT 口径不同（后者量到第三次 ACK）；未见到完整握手为 NULL",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    ColumnSpec {
        name: "tcp_uplink_bytes",
        kind: Kind::U64,
        nullable: true,
        group: "tcp",
        jsonl_path: "tcp.uplink_bytes",
        comment: "发起方方向字节（IP 载荷长，含四层头）；中途接入发起方未知为 NULL，不拿字典序兜底",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    ColumnSpec {
        name: "tcp_downlink_bytes",
        kind: Kind::U64,
        nullable: true,
        group: "tcp",
        jsonl_path: "tcp.downlink_bytes",
        comment: "应答方方向字节；与 uplink 合计等于 bytes；上下行比由查询侧相除（不存比例：0 分母另需表达）",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    // ---- time ----
    ColumnSpec {
        name: "first_seen_us",
        kind: Kind::U64,
        nullable: false,
        group: "time",
        jsonl_path: "time.first_seen_us",
        comment: "首包时间（epoch 微秒）",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    ColumnSpec {
        name: "last_seen_us",
        kind: Kind::U64,
        nullable: false,
        group: "time",
        jsonl_path: "time.last_seen_us",
        comment: "末包时间（epoch 微秒）",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    ColumnSpec {
        name: "duration_us",
        kind: Kind::U64,
        nullable: false,
        group: "time",
        jsonl_path: "time.duration_us",
        comment: "时长（微秒；派生自末减首，乱序到达时钳到 0）",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    // ---- counters ----
    ColumnSpec {
        name: "packets",
        kind: Kind::U64,
        nullable: false,
        group: "counters",
        jsonl_path: "counters.packets",
        comment: "包数",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    ColumnSpec {
        name: "bytes",
        kind: Kind::U64,
        nullable: false,
        group: "counters",
        jsonl_path: "counters.bytes",
        comment: "字节数",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    ColumnSpec {
        name: "direction_switches",
        kind: Kind::U64,
        nullable: false,
        group: "counters",
        jsonl_path: "counters.direction_switches",
        comment: "方向切换次数",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    // ---- app ----
    ColumnSpec {
        name: "app_outcome",
        kind: Kind::Str,
        nullable: false,
        group: "app",
        jsonl_path: "app.outcome",
        comment: "识别裁决 identified|need_more|malformed|unknown|not_inspected",
        low_cardinality: true,
        codec: "ZSTD(1)",
    },
    ColumnSpec {
        name: "app_name",
        kind: Kind::Str,
        nullable: true,
        group: "app",
        jsonl_path: "app.app",
        comment: "应用名；未识别为 NULL",
        low_cardinality: true,
        codec: "ZSTD(1)",
    },
    ColumnSpec {
        name: "app_id",
        kind: Kind::U32,
        nullable: true,
        group: "app",
        jsonl_path: "app.app_id",
        comment: "应用编号（命名空间<<16|序号）；未识别为 NULL",
        low_cardinality: false,
        codec: "Delta(4), ZSTD(1)",
    },
    ColumnSpec {
        name: "app_confidence",
        kind: Kind::Str,
        nullable: true,
        group: "app",
        jsonl_path: "app.confidence",
        comment: "置信度 high|medium|low；未识别为 NULL",
        low_cardinality: true,
        codec: "ZSTD(1)",
    },
    ColumnSpec {
        name: "app_rationale",
        kind: Kind::Str,
        nullable: true,
        group: "app",
        jsonl_path: "app.rationale",
        comment: "判据留痕（回答「凭什么说是这个」）；未识别为 NULL",
        low_cardinality: true,
        codec: "ZSTD(1)",
    },
    ColumnSpec {
        name: "app_server_name",
        kind: Kind::Str,
        nullable: true,
        group: "app",
        jsonl_path: "app.server_name",
        comment: "归一化服务名（TLS SNI / HTTP Host）；无则 NULL",
        low_cardinality: false,
        codec: "ZSTD(1)",
    },
    ColumnSpec {
        name: "app_bytes_inspected",
        kind: Kind::U64,
        nullable: false,
        group: "app",
        jsonl_path: "app.bytes_inspected",
        comment: "实际喂给 DPI 的字节数（0 = 没看过，与 unknown 语义不同）",
        low_cardinality: false,
        codec: "Delta(8), ZSTD(1)",
    },
    // ---- features（与 FEATURE_NAMES 同序）----
    ColumnSpec {
        name: "features_schema_version",
        kind: Kind::U32,
        nullable: false,
        group: "features",
        jsonl_path: "features.schema_version",
        comment: "特征块契约版本",
        low_cardinality: false,
        codec: "Delta(4), ZSTD(1)",
    },
];

/// 特征列在完整清单中的起始下标。
///
/// 由 `FLOW_COLUMNS.len()` 派生而**不写数字**：写死下标时，加一列就会让
/// "起点"悄悄指到别的列，而它看起来仍然是个合法列。
pub const FEATURE_COLUMN_START: usize = FLOW_COLUMNS.len();

/// 完整列清单 = 契约列 + 特征列（`feat_` 前缀）+ 风险列。
///
/// 分成两段是为了让特征列能由 `FEATURE_NAMES` 派生（`feat(i)`），
/// 于是"加了特征但 DDL 少一列"在编译期/门禁期都会失败，而不是运行时少一列。
pub fn flow_columns() -> Vec<ColumnSpec> {
    let mut v: Vec<ColumnSpec> = FLOW_COLUMNS.to_vec();
    for i in 0..crate::feature::FEATURE_COUNT {
        v.push(feat(i));
    }
    v.push(ColumnSpec {
        name: "risk_score",
        kind: Kind::F64,
        nullable: true,
        group: "risk",
        jsonl_path: "risk_score",
        comment: "风险评分；未评分为 NULL（绝不写 0.0）",
        low_cardinality: false,
        codec: "ZSTD(1)",
    });
    v
}

/// 列契约版本。改列名/类型/顺序必须抬它。
///
/// 为什么和 `RECORD_SCHEMA_VERSION` 分开：JSONL 的列变更与列式的列变更**不是同一件事**
/// ——JSONL 少一个键是解析失败，列式少一列是插入失败，两者的下游也不同。
/// 合成一个版本号会在只改一边时被迫抬两边。
///
/// `1 → 2`（2026-10-23）：`tcp` 组末尾增加六列会话级 TCP 统计（`CYS-TRF-015`）。
/// 与 `RECORD_SCHEMA_VERSION` 同批抬是因为本批两边真的都改了；只改一边时仍然只抬一边。
pub const COLUMN_CONTRACT_VERSION: u32 = 2;

/// 派生列（**不在 `flow_columns()` 里**，因为不由我们写）与它的存储形式。
///
/// `MATERIALIZED` 会真的落盘，`ALIAS` 只在查询时算、一个字节都不存。
/// 这个区别不是风格问题：本表实测 `src_ip_text` 用 MATERIALIZED 时 9.12 B/记录，
/// 改成 ALIAS 后 4.5 B/记录 —— 地址被存了两份（二进制 IPv6 + 文本），
/// 而文本那份几乎压不动。规则因此是：**分区/TTL 需要的列才 MATERIALIZED，
/// 纯展示用途一律 ALIAS**。
pub struct DerivedColumn {
    pub name: &'static str,
    pub ch_type: &'static str,
    pub expr: &'static str,
    /// `"MATERIALIZED"` 或 `"ALIAS"`。
    pub storage: &'static str,
    /// 为什么是这个存储形式（写进 DDL 注释，落盘后没人会回来翻代码）。
    pub why: &'static str,
}

pub const DERIVED_COLUMNS: &[DerivedColumn] = &[
    DerivedColumn {
        name: "event_date",
        ch_type: "Date",
        expr: "toDate(intDiv(first_seen_us, 1000000))",
        storage: "MATERIALIZED",
        why: "分区与 TTL 都要用它，这两处不接受 ALIAS",
    },
    DerivedColumn {
        name: "src_ip_text",
        ch_type: "String",
        expr: "if(ip_family = 4, substring(IPv6NumToString(src_ip), 8), IPv6NumToString(src_ip))",
        storage: "ALIAS",
        why: "只为人读；落盘会把地址存两份（实测 +4.6 B/记录）",
    },
    DerivedColumn {
        name: "dst_ip_text",
        ch_type: "String",
        expr: "if(ip_family = 4, substring(IPv6NumToString(dst_ip), 8), IPv6NumToString(dst_ip))",
        storage: "ALIAS",
        why: "同 src_ip_text",
    },
];

pub const TABLE_NAME: &str = "flows";

/// 生成建表 DDL。
///
/// `ttl_days = 0` 表示不带 TTL（开发/回溯场景）。分区与 TTL 都挂在物化列
/// `event_date` 上：把 `toDateTime` 写在分区表达式里能过，但每次查询都要重算，
/// 且分区裁剪依赖它 —— 落成 Date 列更便宜也更直白。
pub fn ddl_flows(ttl_days: u32) -> String {
    let cols = flow_columns();
    let mut s = String::new();
    s.push_str("-- 生成物，**勿手改**。\n");
    s.push_str("-- 真源：dataplane/traffic-engine/src/storage/mod.rs 的 flow_columns()。\n");
    s.push_str("-- 重新生成：cargo run --offline --quiet --bin cythsec-dump-ddl > storage/clickhouse/001_flows.sql\n");
    s.push_str("-- 一致性关口：bash scripts/verify/check-columnar.sh\n");
    s.push_str("--   （它同时把本文件交给真实 ClickHouse 执行，并核对生成物与真源逐字节相同）\n");
    s.push_str(&format!(
        "-- 列契约版本：{COLUMN_CONTRACT_VERSION}（改列名/类型/顺序必须抬它）\n\n"
    ));
    s.push_str(&format!("CREATE TABLE IF NOT EXISTS {TABLE_NAME}\n(\n"));
    let mut lines: Vec<String> = Vec::new();
    for c in &cols {
        // 用 ddl_column() 而不是手拼：**线路类型与落库类型不是同一个东西**，
        // 在这里写 c.ch_type() 会让 DDL 永远拿不到 LowCardinality/CODEC 的压缩收益。
        lines.push(format!("    {}", c.ddl_column()));
    }
    for d in DERIVED_COLUMNS {
        // 注释必须走 COMMENT 子句而**不是**行尾 `--`：行尾注释会把紧随的逗号一起吃掉
        // （`, -- 说明` 之后，逗号属于注释），ClickHouse 报
        // `Syntax error ... Expected one of: ... Comma`。2026-10-19 真实踩过。
        lines.push(format!(
            "    {} {} {} {} COMMENT '{}'",
            d.name,
            d.ch_type,
            d.storage,
            d.expr,
            d.why.replace('\'', "\\'")
        ));
    }
    s.push_str(&lines.join(",\n"));
    s.push_str("\n)\nENGINE = MergeTree\n");
    s.push_str("PARTITION BY toYYYYMM(event_date)\n");
    s.push_str("ORDER BY (first_seen_us, session_id)\n");
    if ttl_days > 0 {
        s.push_str(&format!("TTL event_date + INTERVAL {ttl_days} DAY\n"));
    }
    s.push_str("SETTINGS index_granularity = 8192;\n");
    s
}

// ---------------------------------------------------------------------------
// 投影：FlowRecord → 列值
// ---------------------------------------------------------------------------

/// 把一条记录投影成 `flow_columns()` 同序的列值。
///
/// 这是**唯一**允许把 `FlowRecord` 变成列的地方：编码器、对照脚本的期望值、
/// 单测三者都走它，所以"列取错序"不可能只在一处发生。
pub fn project_row<'a>(r: &'a FlowRecord) -> Result<Vec<Value<'a>>, ProjectError> {
    let src6 = matches!(r.key.src_ip, IpAddr::V6(_));
    let dst6 = matches!(r.key.dst_ip, IpAddr::V6(_));
    if src6 != dst6 {
        return Err(ProjectError::MixedIpFamily {
            session_id: r.session_id,
            src: if src6 { 6 } else { 4 },
            dst: if dst6 { 6 } else { 4 },
        });
    }
    let family: u8 = if src6 { 6 } else { 4 };

    for (i, name) in FEATURE_NAMES.iter().enumerate() {
        if !r.features.values[i].is_finite() {
            return Err(ProjectError::NonFiniteFeature {
                session_id: r.session_id,
                feature: *name,
            });
        }
    }

    let mut out: Vec<Value<'a>> = Vec::with_capacity(flow_columns().len());
    out.push(Value::U32(r.schema_version));
    out.push(Value::U32(COLUMN_CONTRACT_VERSION));
    out.push(Value::U64(r.session_id));
    out.push(Value::U8(family));
    out.push(Value::Ip6(to_ipv6_bytes(r.key.src_ip)));
    out.push(Value::Ip6(to_ipv6_bytes(r.key.dst_ip)));
    out.push(Value::U16(r.key.src_port));
    out.push(Value::U16(r.key.dst_port));
    out.push(Value::U8(r.key.proto.number()));
    out.push(Value::Str(r.key.proto.as_str()));
    out.push(match r.tcp_state {
        Some(st) => Value::Str(st.as_str()),
        None => Value::Null,
    });
    out.push(match r.initiator {
        Some(side) => Value::Str(side_word(side)),
        None => Value::Null,
    });
    out.push(Value::U8(u8::from(r.adopted_midstream)));
    out.push(Value::U64(r.illegal_tcp_events));
    // 会话级 TCP 统计（CYS-TRF-015）。非 TCP 记录（`tcp_stats == None`）六列全部投 NULL：
    // 它们对 UDP/ICMP 没有定义，写 0 等于把"不适用"说成"无异常"。
    match r.tcp_stats {
        Some(t) => {
            out.push(Value::U64(t.seq_judged));
            out.push(match t.retransmissions {
                Some(v) => Value::U64(v),
                None => Value::Null,
            });
            out.push(match t.out_of_order {
                Some(v) => Value::U64(v),
                None => Value::Null,
            });
            out.push(match t.handshake_rtt_us {
                Some(v) => Value::U64(v),
                None => Value::Null,
            });
            out.push(match t.uplink_bytes {
                Some(v) => Value::U64(v),
                None => Value::Null,
            });
            out.push(match t.downlink_bytes {
                Some(v) => Value::U64(v),
                None => Value::Null,
            });
        }
        None => {
            for _ in 0..6 {
                out.push(Value::Null);
            }
        }
    }
    out.push(Value::U64(r.first_seen_us));
    out.push(Value::U64(r.last_seen_us));
    out.push(Value::U64(r.last_seen_us.saturating_sub(r.first_seen_us)));
    out.push(Value::U64(r.packets));
    out.push(Value::U64(r.bytes));
    out.push(Value::U64(r.direction_switches));
    out.push(Value::Str(r.app.outcome));
    out.push(match r.app.app {
        Some(app) => Value::Str(app.as_str()),
        None => Value::Null,
    });
    out.push(match r.app.app {
        Some(app) => Value::U32(app.as_u32()),
        None => Value::Null,
    });
    out.push(match r.app.confidence {
        Some(c) => Value::Str(c.as_str()),
        None => Value::Null,
    });
    out.push(match r.app.rationale {
        Some(x) => Value::Str(x),
        None => Value::Null,
    });
    out.push(match &r.app.server_name {
        Some(x) => Value::Str(x.as_str()),
        None => Value::Null,
    });
    out.push(Value::U64(r.app.bytes_inspected as u64));
    out.push(Value::U32(r.features.schema_version));
    for i in 0..crate::feature::FEATURE_COUNT {
        out.push(Value::F64(r.features.values[i]));
    }
    out.push(match r.risk_score {
        Some(v) if v.is_finite() => Value::F64(v),
        Some(_) => {
            return Err(ProjectError::NonFiniteFeature {
                session_id: r.session_id,
                feature: "risk_score",
            })
        }
        None => Value::Null,
    });
    Ok(out)
}

/// IPv4 走 `::ffff:a.b.c.d`（RFC 4291 §2.5.5.2）——与 ClickHouse 的
/// `toIPv6('10.0.0.1')` 逐字节相同（门禁 `check-columnar.sh` 对照参考实现确认）。
pub fn to_ipv6_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut b = [0u8; 16];
            b[10] = 0xff;
            b[11] = 0xff;
            b[12..].copy_from_slice(&v4.octets());
            b
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// 由 16 字节还原可读地址文本（解码侧的展示；`ip_family` 决定要不要剥 `::ffff:`）。
pub fn ip_text_from_bytes(b: &[u8; 16], family: u8) -> String {
    if family == 4 {
        return format!("{}.{}.{}.{}", b[12], b[13], b[14], b[15]);
    }
    IpAddr::from(*b).to_string()
}

/// 方向词汇与 `record/mod.rs` 同源：`fwd` / `rev`。
///
/// 刻意不在此重复实现 —— 两处各写一份时，改一边就会让 JSONL 与列式**说不同的话**，
/// 而下游把两个出口当同一条链的两端看。
fn side_word(side: Side) -> &'static str {
    crate::record::side_word(side)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::{AppId, Confidence};
    use crate::feature::FEATURE_COUNT;
    use crate::flow::{FlowKey, IPPROTO_TCP, IPPROTO_UDP};
    use crate::record::{AppInfo, RECORD_SCHEMA_VERSION};
    use crate::tcp::TcpState;

    fn sample() -> FlowRecord {
        let key = FlowKey::new_ipv4([10, 0, 0, 1], 40000, [93, 184, 216, 34], 443, IPPROTO_TCP);
        FlowRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            session_id: 7,
            key,
            tcp_state: Some(TcpState::Established),
            initiator: Some(Side::A),
            adopted_midstream: false,
            illegal_tcp_events: 0,
            tcp_stats: None,
            first_seen_us: 1_000_000,
            last_seen_us: 2_000_000,
            packets: 2,
            bytes: 2000,
            direction_switches: 1,
            features: crate::feature::FeatureExtractor::default().vector(),
            app: AppInfo::not_inspected(),
            risk_score: None,
        }
    }

    #[test]
    fn column_count_is_contract_plus_features_plus_risk() {
        let cols = flow_columns();
        assert_eq!(cols.len(), FLOW_COLUMNS.len() + FEATURE_COUNT + 1);
        assert_eq!(cols[FEATURE_COLUMN_START].name, "feat_packets");
        assert_eq!(
            cols[FEATURE_COLUMN_START - 1].name,
            "features_schema_version"
        );
        assert_eq!(cols.last().unwrap().name, "risk_score");
    }

    #[test]
    fn feature_column_names_are_prefixed_forms_of_the_feature_layout() {
        // 前缀列名是手抄的一份，必须逐条钉回真源：否则"改了特征名但 DDL 没改"
        // 表现为一列静静失踪，而不是任何一处报错。
        for (i, name) in FEATURE_COLUMN_NAMES.iter().enumerate() {
            assert!(
                name.starts_with("feat_") && &name[5..] == FEATURE_NAMES[i],
                "特征列 {name} 与 FEATURE_NAMES[{i}] = {} 不同源",
                FEATURE_NAMES[i]
            );
            assert!(
                FEATURE_JSONL_PATHS[i] == format!("features.{}", FEATURE_NAMES[i]),
                "特征列 {name} 的 JSONL 路径与特征名不符"
            );
        }
    }

    #[test]
    fn column_names_are_unique() {
        // 重名时 ClickHouse 建表直接失败，但**更坏的情况**是它成功建表而两列同名异义，
        // 于是按名取数拿到另一列。这里提前挡住。
        let cols = flow_columns();
        let mut seen: Vec<&str> = Vec::new();
        for c in &cols {
            assert!(!seen.contains(&c.name), "列名重复：{}", c.name);
            seen.push(c.name);
        }
    }

    #[test]
    fn projection_length_and_kinds_match_the_spec_exactly() {
        let cols = flow_columns();
        let r = sample();
        let row = project_row(&r).expect("投影成功");
        assert_eq!(row.len(), cols.len(), "投影列数必须与契约一致");
        for (c, v) in cols.iter().zip(&row) {
            let ok = match c.kind {
                Kind::U8 => matches!(v, Value::U8(_) | Value::Null),
                Kind::U16 => matches!(v, Value::U16(_) | Value::Null),
                Kind::U32 => matches!(v, Value::U32(_) | Value::Null),
                Kind::U64 => matches!(v, Value::U64(_) | Value::Null),
                Kind::F64 => matches!(v, Value::F64(_) | Value::Null),
                Kind::Ip6 => matches!(v, Value::Ip6(_) | Value::Null),
                Kind::Str => matches!(v, Value::Str(_) | Value::Null),
            };
            assert!(ok, "列 {} 声明 {} 得到 {v:?}", c.name, c.ch_type());
            if matches!(v, Value::Null) {
                assert!(c.nullable, "列 {} 不可空却投出 NULL", c.name);
            }
        }
    }

    #[test]
    fn null_stays_null_and_zero_is_not_null() {
        let r = sample();
        let row = project_row(&r).expect("投影成功");
        let cols = flow_columns();
        let idx = |n: &str| cols.iter().position(|c| c.name == n).unwrap();
        assert_eq!(row[idx("tcp_state")], Value::Str("established"));
        assert_eq!(row[idx("risk_score")], Value::Null, "未评分必须是 NULL");
        assert_eq!(row[idx("app_name")], Value::Null);
        // 识别出来了就必须有名字，且 NULL 换成值。
        let mut r = sample();
        r.app = AppInfo {
            outcome: "identified",
            app: Some(AppId::Dns),
            confidence: Some(Confidence::High),
            rationale: Some("dns-header"),
            server_name: None,
            bytes_inspected: 21,
        };
        let row2 = project_row(&r).expect("投影成功");
        assert_eq!(row2[idx("app_name")], Value::Str("dns"));
        assert_eq!(row2[idx("app_id")], Value::U32(AppId::Dns.as_u32()));
        assert_eq!(row2[idx("app_bytes_inspected")], Value::U64(21));
    }

    #[test]
    fn tcp_stat_columns_are_null_when_unobserved_and_values_when_observed() {
        // `CYS-TRF-015` 落到列式的那一条红线：NULL 与 0 必须在字节上就不同。
        let cols = flow_columns();
        let idx = |n: &str| cols.iter().position(|c| c.name == n).unwrap();
        for name in [
            "tcp_seq_judged",
            "tcp_retransmissions",
            "tcp_out_of_order",
            "tcp_handshake_rtt_us",
            "tcp_uplink_bytes",
            "tcp_downlink_bytes",
        ] {
            let c = &cols[idx(name)];
            assert!(c.nullable, "{name} 必须是 Nullable：它要能表达“没证据”");
            assert_eq!(c.group, "tcp");
        }
        // ① 非 TCP（整块 None）：六列全 NULL。
        let r = sample();
        let row = project_row(&r).expect("投影成功");
        for name in [
            "tcp_seq_judged",
            "tcp_retransmissions",
            "tcp_out_of_order",
            "tcp_handshake_rtt_us",
            "tcp_uplink_bytes",
            "tcp_downlink_bytes",
        ] {
            assert_eq!(row[idx(name)], Value::Null, "非 TCP 时 {name} 不得有值");
        }
        // ② TCP 但没判定输入：seq_judged=0（这是事实），计数是 NULL（这是没证据）。
        let mut r = sample();
        r.tcp_stats = Some(crate::record::TcpSessionStats {
            seq_judged: 0,
            ..Default::default()
        });
        let row = project_row(&r).expect("投影成功");
        assert_eq!(row[idx("tcp_seq_judged")], Value::U64(0));
        assert_eq!(row[idx("tcp_retransmissions")], Value::Null);
        assert_eq!(row[idx("tcp_out_of_order")], Value::Null);
        // ③ 真判定出 0 重传：必须是 0，不能回退成 NULL。
        r.tcp_stats = Some(crate::record::TcpSessionStats {
            seq_judged: 4,
            retransmissions: Some(0),
            out_of_order: Some(0),
            handshake_rtt_us: Some(1_500),
            uplink_bytes: Some(1_200),
            downlink_bytes: Some(800),
        });
        let row = project_row(&r).expect("投影成功");
        assert_eq!(
            row[idx("tcp_retransmissions")],
            Value::U64(0),
            "Some(0) 不得变成 NULL"
        );
        assert_eq!(row[idx("tcp_out_of_order")], Value::U64(0));
        assert_eq!(row[idx("tcp_handshake_rtt_us")], Value::U64(1_500));
        assert_eq!(row[idx("tcp_uplink_bytes")], Value::U64(1_200));
        assert_eq!(row[idx("tcp_downlink_bytes")], Value::U64(800));
    }

    #[test]
    fn ipv4_maps_to_ipv4_mapped_ipv6_bytes() {
        // 与 ClickHouse `toIPv6('10.0.0.1')` 的字节一致：00*10 ff ff 0a 00 00 01。
        let b = to_ipv6_bytes(IpAddr::V4("10.0.0.1".parse().unwrap()));
        assert_eq!(
            b,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1],
            "IPv4-mapped 的字节序是 ::ffff:a.b.c.d（大端 16 字节）"
        );
        let b6 = to_ipv6_bytes(IpAddr::V6("2001:db8::1".parse().unwrap()));
        assert_eq!(&b6[..2], &[0x20, 0x01]);
        assert_eq!(b6[15], 1);
        assert_eq!(ip_text_from_bytes(&b, 4), "10.0.0.1");
        assert_eq!(ip_text_from_bytes(&b6, 6), "2001:db8::1");
    }

    #[test]
    fn mixed_family_and_non_finite_are_rejected_not_faked() {
        let mut r = sample();
        let proto = r.key.proto;
        r.key = FlowKey {
            src_ip: IpAddr::V4("10.0.0.1".parse().unwrap()),
            src_port: 1,
            dst_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
            dst_port: 2,
            proto,
        };
        assert!(matches!(
            project_row(&r),
            Err(ProjectError::MixedIpFamily { .. })
        ));

        let mut r2 = sample();
        r2.features.values[3] = f64::NAN;
        assert!(matches!(
            project_row(&r2),
            Err(ProjectError::NonFiniteFeature {
                feature: "fwd_bytes",
                ..
            })
        ));

        let mut r3 = sample();
        r3.risk_score = Some(f64::INFINITY);
        assert!(matches!(
            project_row(&r3),
            Err(ProjectError::NonFiniteFeature { .. })
        ));
    }

    #[test]
    fn duration_is_clamped_the_same_way_as_jsonl() {
        // JSONL 用 saturating_sub；列式必须同一口径，否则两个出口给出不同的时长。
        let mut r = sample();
        r.first_seen_us = 5_000_000;
        r.last_seen_us = 1_000_000;
        let cols = flow_columns();
        let idx = cols.iter().position(|c| c.name == "duration_us").unwrap();
        assert_eq!(project_row(&r).unwrap()[idx], Value::U64(0));
    }

    #[test]
    fn ddl_names_every_column_and_is_stable() {
        let ddl = ddl_flows(90);
        for c in flow_columns() {
            assert!(
                ddl.contains(&format!("    {}", c.ddl_column())),
                "DDL 与 ddl_column() 不一致：{}",
                c.name
            );
        }
        assert!(ddl.contains("PARTITION BY toYYYYMM(event_date)"), "分区函数名必须由真实 ClickHouse 执行过：toYYYYMonth 不存在（2026-10-19 被参考实现判红）");
        assert!(ddl.contains("TTL event_date + INTERVAL 90 DAY"));
        assert_eq!(ddl, ddl_flows(90), "同一输入必须逐字节相同（可复现前提）");
        // 布尔列落成 UInt8 而不是 Bool：多一种类型就多一份字节理解。
        assert!(ddl.contains("    adopted_midstream UInt8"));
        // **线路类型 ≠ 落库类型**：块头里写 String，DDL 里是 LowCardinality(String)。
        // 这两件事必须同时成立，所以两边分别断言（只断言一边时，改错另一边没人管）。
        let cols = flow_columns();
        let proto = cols.iter().find(|c| c.name == "proto_name").unwrap();
        assert_eq!(proto.ch_type(), "String", "线路类型必须保持最窄集合");
        assert_eq!(proto.ddl_type(), "LowCardinality(String)");
        let st = cols.iter().find(|c| c.name == "tcp_state").unwrap();
        assert_eq!(st.ch_type(), "Nullable(String)");
        assert_eq!(
            st.ddl_type(),
            "LowCardinality(Nullable(String))",
            "LC 必须包在 Nullable 外面"
        );
        // Nullable + LC 的组合是可写的：ClickHouse 在 INSERT 时自动把
        // Nullable(String) 的块转成 LowCardinality(Nullable(String))（参考实现实测）。
        assert!(ddl.contains("    tcp_state LowCardinality(Nullable(String)) COMMENT"));
        for c in &cols {
            let definition = c.ddl_column();
            if !c.codec.is_empty() {
                assert!(
                    definition.find(" COMMENT ").unwrap() < definition.find(" CODEC(").unwrap()
                );
            }
        }
        // 数值列不许套 LC（无收益、只让 DDL 难读）。
        for c in &cols {
            if c.kind != Kind::Str {
                assert!(
                    !c.low_cardinality,
                    "非 String 列 {} 要求了 LowCardinality",
                    c.name
                );
            }
        }
        // 展示列不许落盘：只有分区/TTL 需要的 event_date 才 MATERIALIZED。
        assert!(ddl.contains("    event_date Date MATERIALIZED"));
        assert!(ddl.contains("    src_ip_text String ALIAS"));
        assert!(ddl.contains("    dst_ip_text String ALIAS"));
    }

    #[test]
    fn udp_record_has_null_tcp_columns_not_empty_strings() {
        let mut r = sample();
        r.key = FlowKey::new_ipv4([10, 0, 0, 1], 53, [8, 8, 8, 8], 53, IPPROTO_UDP);
        r.tcp_state = None;
        r.initiator = None;
        let cols = flow_columns();
        let i_state = cols.iter().position(|c| c.name == "tcp_state").unwrap();
        let i_init = cols.iter().position(|c| c.name == "tcp_initiator").unwrap();
        let row = project_row(&r).unwrap();
        assert_eq!(row[i_state], Value::Null);
        assert_eq!(row[i_init], Value::Null);
        assert_eq!(
            row[cols.iter().position(|c| c.name == "proto").unwrap()],
            Value::U8(17)
        );
    }
}
