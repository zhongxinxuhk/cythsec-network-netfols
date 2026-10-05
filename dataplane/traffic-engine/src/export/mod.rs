// export/mod.rs —— FlowRecord 的对外导出（M11 / CYS-TRF-051）。
//
// ## 为什么要有这一层
//
// 前面整条链（解码 → 流表 → 会话 → 特征 → 识别 → FlowRecord）产出的东西，
// 此前只有两个出口：JSONL 文件和共享环。JSONL 是**我们自己的**格式，只有我们读。
// 而省网量级的现实是：**逐包采集不存在**（单条 100G 链路最坏 64 B 帧 = 148.8 Mpps；
// 骨干 10 Tbps 全量 = 2.5 Gpps ≈ 108 PB/天）。运营商扛这个量的办法是让**网元采样导出**，
// 由采集集群消费 **IPFIX / NetFlow v9 / sFlow**。所以「让记录走进运营商既有的流级通道」
// 是这条链能不能用于省网的**分水岭**，而不是一个可选功能。
//
// ## 三条不可退让的约定
//
// 1. **零第三方依赖**（仓库红线，离线可构建）：IPFIX 编码手写，与 `record/mod.rs`
//    手写 JSON 同源同理由。协议本身是定长字段的 TLV，手写的风险面很小，且**有
//    tshark 做独立裁判**（`scripts/verify/check-ipfix-export.sh`）。
//
// 2. **长度与对齐必须按 RFC 7011 来**，不能"看起来能解就行"：
//    - 报文头 16 字节（version/length/exportTime/sequenceNumber/observationDomainID）；
//    - Set 头 4 字节（setID/length）；模板集 setID=2，数据集 setID ≥ 256；
//    - 填充**只允许零字节**，且填充长度必须**短于**该 Set 里任何一条记录
//      （RFC 7011 §3.3.1）—— 因此本实现的模板集天然 4 字节对齐，数据集按需补 0~3 字节；
//    - 信息元素编号取自 IANA IPFIX registry（2026-10-05 取表核对），**不许凭记忆写**。
//
// 3. **序列号是采集侧发现"导出丢包"的唯一手段**，语义必须精确：RFC 7011 §3.1 规定
//    Sequence Number = 本报文**之前**该 Observation Domain 已发送的数据记录累计数
//    （模板记录不计入）。写错这个数，采集器要么误报丢包、要么把丢包读成正常。
//    这也是 M11 完成判据里"采集侧能报出导出丢包"的地基。
//
// ## 本版（v1）刻意不做的两件事（避免"看起来支持了"）
//
// - **RFC 5103 双方向（biflow）**：反转字段不是新编号，而是「同一个 IE 编号 + 企业位 +
//   PEN 29305」（RFC 5103 §6.1）。我们现在的 `FlowRecord` 只有**总量**计数
//   （`packets`/`bytes`），没有分方向计数，硬做 biflow 只能编造方向归属。
//   故 v1 只导出**单向记录**（规范五元组方向），biflow 待分方向计数落地后再开。
// - **DPI 应用名（IE 96 applicationName）**：字符串字段会引入变长编码与截断语义，
//   与 v1「定长、无歧义」的目标冲突，故留作增量。

use std::net::IpAddr;

use crate::ipfix::{Ie, Template, IPFIX_VERSION, MSG_HEADER_LEN, TEMPLATE_SET_ID};
use crate::record::FlowRecord;

pub mod sink;

/// 导出配置。
#[derive(Debug, Clone)]
pub struct ExportConfig {
    /// Observation Domain ID（采集侧按 `exporter + ODID` 区分模板与序列号）。
    pub domain_id: u32,
    /// 单个 IPFIX 报文的目标上限（含报文头）。真实导出受 MTU 限制，
    /// UDP 上超 MTU 会被分片甚至丢弃，所以必须能配。
    pub max_msg_bytes: usize,
    /// 每多少条报文重发一次模板。UDP 无连接、采集器会重启，模板只发一次
    /// 意味着"采集器一重启，之后所有数据记录都解不开"。
    pub template_refresh_msgs: u32,
    /// 采样间隔（1 = 未采样）。**声明与执行必须一致**：v1 只支持 1，
    /// 因为数据面还没有真采样（见 `CYS-TRF-053`）；声明 <1 的采样率却按全量导出，
    /// 会让下游把采样流量当全量算，是最容易被忽略的错。
    pub sampling_interval: u32,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            domain_id: 1,
            // 1400 - 20(IP) - 8(UDP) = 1372，留余量给隧道封装。
            max_msg_bytes: 1400,
            template_refresh_msgs: 20,
            sampling_interval: 1,
        }
    }
}

/// 导出统计（CLI 必须把它打出来：导出失败不可见＝静默丢数据）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportStats {
    pub messages: u64,
    pub data_records: u64,
    pub bytes: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// `max_msg_bytes` 连「报文头 + 模板 + 一条记录」都放不下。
    MessageTooSmall { need: usize, got: usize },
    /// 模板刷新周期必须 ≥ 1（0 会让 `% 0` panic，也可能被读成"从不发模板"）。
    BadTemplateRefresh(u32),
    /// 采样间隔必须 ≥ 1。
    BadSamplingInterval(u32),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageTooSmall { need, got } => write!(
                f,
                "IPFIX 报文上限过小：至少需要 {need} 字节（报文头+模板+一条记录），当前 {got}"
            ),
            Self::BadTemplateRefresh(n) => write!(f, "模板刷新周期必须是正整数，得到 {n}"),
            Self::BadSamplingInterval(n) => write!(f, "采样间隔必须是正整数，得到 {n}"),
        }
    }
}

impl std::error::Error for ExportError {}

/// IPFIX 编码器：有状态（序列号与模板刷新都跨报文）。
#[derive(Debug)]
pub struct Encoder {
    cfg: ExportConfig,
    v4: Template,
    v6: Template,
    /// 已发出的报文数（决定模板是否重发）。
    msgs_emitted: u64,
    /// 每个地址族**上次携带模板**的报文序号（None = 一次都没发过）。
    /// 分族记录而不是共用一个计数器：只发 v4 的批不该把 v6 的模板一起推出去，
    /// 也不该因为"v6 从未出现"就让 v6 模板永远停在"已发过"。
    template_sent_at: [Option<u64>; 2],
    /// 已发送的数据记录累计数（序列号基准，mod 2^32）。
    data_records_sent: u32,
}

impl Encoder {
    pub fn new(cfg: ExportConfig) -> Result<Self, ExportError> {
        if cfg.template_refresh_msgs == 0 {
            return Err(ExportError::BadTemplateRefresh(cfg.template_refresh_msgs));
        }
        if cfg.sampling_interval == 0 {
            return Err(ExportError::BadSamplingInterval(cfg.sampling_interval));
        }
        Ok(Self {
            cfg,
            v4: Template::ipv4(),
            v6: Template::ipv6(),
            msgs_emitted: 0,
            template_sent_at: [None, None],
            data_records_sent: 0,
        })
    }

    pub fn config(&self) -> &ExportConfig {
        &self.cfg
    }

    /// 已发送的数据记录累计数（= 下一个报文头的序列号）。
    pub fn sequence_number(&self) -> u32 {
        self.data_records_sent
    }

    /// 把一批记录编码成若干 IPFIX 报文。
    ///
    /// `export_time` 是报文头里的导出时刻（Unix 秒）。**由调用方传入**而不是内部取
    /// 系统时间：单测要能写死期望字节，否则"金标准字节"测试就变成了"和上一版自己比"。
    pub fn encode_batch(
        &mut self,
        records: &[FlowRecord],
        export_time: u32,
    ) -> Result<Vec<Vec<u8>>, ExportError> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let rec4 = self.v4.record_len();
        let rec6 = self.v6.record_len();

        // 配置下限：必须能装下「报文头 + 两个模板 + 最长的一条记录」。只按"一个模板"
        // 定下限的话，两个族同时到期又同批出现时会半途失败——而导出是边发边写的，
        // 半途失败意味着产物**残缺**。宁可配置期就拒绝。
        let worst = MSG_HEADER_LEN
            + self.v4.template_set_len()
            + self.v6.template_set_len()
            + rec4.max(rec6);
        if self.cfg.max_msg_bytes < worst {
            return Err(ExportError::MessageTooSmall {
                need: worst,
                got: self.cfg.max_msg_bytes,
            });
        }

        let mut out = Vec::new();
        let mut idx = 0usize;
        let refresh = self.cfg.template_refresh_msgs as u64;
        while idx < records.len() {
            // 1) 先判断本批**可能用到**哪些族，以及它们的模板是否到期。
            let rest = &records[idx..];
            let has_v4_rest = rest.iter().any(|r| r.key.src_ip.is_ipv4());
            let has_v6_rest = rest.iter().any(|r| !r.key.src_ip.is_ipv4());
            let due = |fam: usize| -> bool {
                match self.template_sent_at[fam] {
                    None => true,
                    Some(m) => self.msgs_emitted.saturating_sub(m) >= refresh,
                }
            };
            let reserve_v4 = due(0) && has_v4_rest;
            let reserve_v6 = due(1) && has_v6_rest;

            let mut budget = self.cfg.max_msg_bytes - MSG_HEADER_LEN;
            if reserve_v4 {
                budget -= self.v4.template_set_len();
            }
            if reserve_v6 {
                budget -= self.v6.template_set_len();
            }
            let mut chosen: Vec<&FlowRecord> = Vec::new();
            let mut remaining = budget;
            while idx + chosen.len() < records.len() {
                let r = &records[idx + chosen.len()];
                let cost = if r.key.src_ip.is_ipv4() { rec4 } else { rec6 };
                if cost > remaining {
                    break;
                }
                remaining -= cost;
                chosen.push(r);
            }
            if chosen.is_empty() {
                // 预算连一条记录都放不下：与上面的 worst 检查同因，给同一个错。
                return Err(ExportError::MessageTooSmall {
                    need: self.cfg.max_msg_bytes - remaining + rec4,
                    got: self.cfg.max_msg_bytes,
                });
            }

            // 2) 组装报文：模板集（如到期）+ 按地址族分组的若干数据集。
            let mut msg = Vec::with_capacity(self.cfg.max_msg_bytes);
            msg.extend_from_slice(&[0u8; MSG_HEADER_LEN]); // 占位，最后回填 length
            let chosen_has_v4 = chosen.iter().any(|r| r.key.src_ip.is_ipv4());
            let chosen_has_v6 = chosen.iter().any(|r| !r.key.src_ip.is_ipv4());
            if reserve_v4 && chosen_has_v4 {
                push_template_set(&mut msg, &self.v4);
                self.template_sent_at[0] = Some(self.msgs_emitted);
            }
            if reserve_v6 && chosen_has_v6 {
                push_template_set(&mut msg, &self.v6);
                self.template_sent_at[1] = Some(self.msgs_emitted);
            }
            let mut i = 0usize;
            while i < chosen.len() {
                let is_v4 = chosen[i].key.src_ip.is_ipv4();
                let mut j = i;
                while j < chosen.len() && chosen[j].key.src_ip.is_ipv4() == is_v4 {
                    j += 1;
                }
                let (tid, tmpl) = if is_v4 {
                    (self.v4.id, &self.v4)
                } else {
                    (self.v6.id, &self.v6)
                };
                push_data_set(&mut msg, tid, tmpl, &chosen[i..j]);
                i = j;
            }

            // 3) 回填报头（序列号必须是"本报文之前"的累计数）。
            let seq = self.data_records_sent;
            let len = msg.len() as u16;
            msg[0..2].copy_from_slice(&IPFIX_VERSION.to_be_bytes());
            msg[2..4].copy_from_slice(&len.to_be_bytes());
            msg[4..8].copy_from_slice(&export_time.to_be_bytes());
            msg[8..12].copy_from_slice(&seq.to_be_bytes());
            msg[12..16].copy_from_slice(&self.cfg.domain_id.to_be_bytes());

            self.data_records_sent = self.data_records_sent.wrapping_add(chosen.len() as u32);
            self.msgs_emitted += 1;
            idx += chosen.len();
            out.push(msg);
        }
        Ok(out)
    }
}

/// 追加一个模板集（setID=2）。模板头 4 字节 + 每字段 4 字节，天然 4 字节对齐。
fn push_template_set(out: &mut Vec<u8>, t: &Template) {
    let set_len = t.template_set_len() as u16;
    out.extend_from_slice(&TEMPLATE_SET_ID.to_be_bytes());
    out.extend_from_slice(&set_len.to_be_bytes());
    out.extend_from_slice(&t.id.to_be_bytes());
    out.extend_from_slice(&(t.fields.len() as u16).to_be_bytes());
    for f in &t.fields {
        out.extend_from_slice(&f.ie.code().to_be_bytes());
        out.extend_from_slice(&f.len.to_be_bytes());
    }
}

/// 追加一个数据集（setID = 模板 id）。末尾补 0 到 4 字节对齐。
fn push_data_set(out: &mut Vec<u8>, template_id: u16, t: &Template, records: &[&FlowRecord]) {
    let start = out.len();
    out.extend_from_slice(&template_id.to_be_bytes());
    out.extend_from_slice(&[0u8; 2]); // 长度占位
    for r in records {
        write_record(out, t, r);
    }
    // 填充只允许零字节，且填充长度（≤3）必须短于记录长度（本版 ≥ 57）。
    while (out.len() - start) % 4 != 0 {
        out.push(0);
    }
    let len = (out.len() - start) as u16;
    out[start + 2..start + 4].copy_from_slice(&len.to_be_bytes());
}

/// 按模板字段顺序写一条数据记录。
fn write_record(out: &mut Vec<u8>, t: &Template, r: &FlowRecord) {
    for f in &t.fields {
        match f.ie {
            Ie::SourceIPv4Address => write_ipv4(out, &r.key.src_ip),
            Ie::DestinationIPv4Address => write_ipv4(out, &r.key.dst_ip),
            Ie::SourceIPv6Address => write_ipv6(out, &r.key.src_ip),
            Ie::DestinationIPv6Address => write_ipv6(out, &r.key.dst_ip),
            Ie::SourceTransportPort => out.extend_from_slice(&r.key.src_port.to_be_bytes()),
            Ie::DestinationTransportPort => out.extend_from_slice(&r.key.dst_port.to_be_bytes()),
            Ie::ProtocolIdentifier => out.push(r.key.proto.number()),
            Ie::OctetDeltaCount => out.extend_from_slice(&r.bytes.to_be_bytes()),
            Ie::PacketDeltaCount => out.extend_from_slice(&r.packets.to_be_bytes()),
            Ie::FlowStartMilliseconds => {
                out.extend_from_slice(&(r.first_seen_us / 1000).to_be_bytes())
            }
            Ie::FlowEndMilliseconds => {
                out.extend_from_slice(&(r.last_seen_us / 1000).to_be_bytes())
            }
            Ie::FlowId => out.extend_from_slice(&r.session_id.to_be_bytes()),
            Ie::SamplingInterval => out.extend_from_slice(&1u32.to_be_bytes()),
        }
    }
}

/// IPv4 地址占位：模板与地址族不匹配时写全 0（不 panic：导出不该因为一条脏记录
/// 让整批数据消失；但调用方**不应该**走到这里，单测专门守着这条不变式）。
fn write_ipv4(out: &mut Vec<u8>, ip: &IpAddr) {
    match ip {
        IpAddr::V4(a) => out.extend_from_slice(&a.octets()),
        IpAddr::V6(_) => out.extend_from_slice(&[0u8; 4]),
    }
}

fn write_ipv6(out: &mut Vec<u8>, ip: &IpAddr) {
    match ip {
        IpAddr::V6(a) => out.extend_from_slice(&a.octets()),
        IpAddr::V4(_) => out.extend_from_slice(&[0u8; 16]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 只在测试里用到的常量/类型放在这里：放模块级会让非测试构建（CLI）报未使用 import，
    // 而"关掉警告"是错的做法 —— 警告正是提醒我们 import 的位置不对。
    use crate::dpi::{AppId, Confidence, Outcome};
    use crate::feature::FeatureVector;
    use crate::ipfix::{SET_HEADER_LEN, TEMPLATE_ID_V4, TEMPLATE_ID_V6, TEMPLATE_SET_ID};
    use crate::record::AppInfo;
    use std::net::Ipv6Addr;

    fn rec_v4() -> FlowRecord {
        FlowRecord {
            schema_version: 1,
            session_id: 7,
            key: crate::flow::FlowKey::new_ipv4([192, 0, 2, 1], 12345, [198, 51, 100, 7], 443, 6),
            tcp_state: None,
            initiator: None,
            adopted_midstream: false,
            illegal_tcp_events: 0,
            first_seen_us: 1_000_000_000_000_000,
            last_seen_us: 1_000_000_001_000_000,
            packets: 10,
            bytes: 1500,
            direction_switches: 0,
            features: FeatureVector {
                schema_version: 1,
                values: [0f64; crate::feature::FEATURE_COUNT],
            },
            app: AppInfo::not_inspected(),
            risk_score: None,
        }
    }

    fn rec_v6() -> FlowRecord {
        let mut r = rec_v4();
        r.session_id = 8;
        r.key.src_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        r.key.dst_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        r
    }

    /// 信息元素编号必须与 IANA 注册表一致。**手写期望值**：如果这里改成"跑一遍实现
    /// 记下来"，那么编号写错时两端会一起错，测试就永远绿。
    #[test]
    fn ie_codes_match_iana_registry() {
        assert_eq!(Ie::OctetDeltaCount.code(), 1);
        assert_eq!(Ie::PacketDeltaCount.code(), 2);
        assert_eq!(Ie::ProtocolIdentifier.code(), 4);
        assert_eq!(Ie::SourceTransportPort.code(), 7);
        assert_eq!(Ie::SourceIPv4Address.code(), 8);
        assert_eq!(Ie::DestinationTransportPort.code(), 11);
        assert_eq!(Ie::DestinationIPv4Address.code(), 12);
        assert_eq!(Ie::SourceIPv6Address.code(), 27);
        assert_eq!(Ie::DestinationIPv6Address.code(), 28);
        assert_eq!(Ie::SamplingInterval.code(), 34);
        assert_eq!(Ie::FlowId.code(), 148);
        assert_eq!(Ie::FlowStartMilliseconds.code(), 152);
        assert_eq!(Ie::FlowEndMilliseconds.code(), 153);
    }

    #[test]
    fn template_lengths_are_4_octet_aligned() {
        let v4 = Template::ipv4();
        let v6 = Template::ipv6();
        // 11 字段：4 + 4 + 11*4 = 52
        assert_eq!(v4.template_set_len(), 52);
        assert_eq!(v6.template_set_len(), 52);
        assert_eq!(v4.template_set_len() % 4, 0);
        // 记录长度：4+4+2+2+1+8+8+8+8+8+4 = 57（IPv4）/ 16+16+... = 81（IPv6）
        assert_eq!(v4.record_len(), 57);
        assert_eq!(v6.record_len(), 81);
    }

    /// 金标准字节：一条 IPv4 记录的完整报文，逐字节手写期望值。
    /// 这是唯一能抓住"字段顺序/端序/填充"这类错误的单测（tshark 关口在外面再兜一道）。
    #[test]
    fn golden_message_bytes() {
        let mut e = Encoder::new(ExportConfig {
            domain_id: 0x0000_00AA,
            max_msg_bytes: 1400,
            template_refresh_msgs: 20,
            sampling_interval: 1,
        })
        .unwrap();
        let msgs = e.encode_batch(&[rec_v4()], 1_700_000_000).unwrap();
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];

        let mut expect: Vec<u8> = Vec::new();
        // --- 报文头（16B）：version=10, length=?, exportTime, seq=0, odid=0xAA ---
        expect.extend_from_slice(&[0x00, 0x0A]);
        let total = 16 + 52 + 64; // 头 + 模板集 + 数据集
        expect.extend_from_slice(&(total as u16).to_be_bytes());
        expect.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        expect.extend_from_slice(&0u32.to_be_bytes()); // 首个报文之前没有数据记录
        expect.extend_from_slice(&0x0000_00AAu32.to_be_bytes());
        // --- 模板集（setID=2, len=52）---
        expect.extend_from_slice(&[0x00, 0x02, 0x00, 0x34]);
        expect.extend_from_slice(&[0x01, 0x00]); // template id 256
        expect.extend_from_slice(&[0x00, 0x0B]); // 11 个字段
        for (ie, len) in [
            (8u16, 4u16),
            (12, 4),
            (7, 2),
            (11, 2),
            (4, 1),
            (1, 8),
            (2, 8),
            (152, 8),
            (153, 8),
            (148, 8),
            (34, 4),
        ] {
            expect.extend_from_slice(&ie.to_be_bytes());
            expect.extend_from_slice(&len.to_be_bytes());
        }
        // --- 数据集（setID=256, len=4+57+3=64）---
        expect.extend_from_slice(&[0x01, 0x00, 0x00, 0x40]);
        expect.extend_from_slice(&[192, 0, 2, 1]); // src
        expect.extend_from_slice(&[198, 51, 100, 7]); // dst
        expect.extend_from_slice(&12345u16.to_be_bytes()); // sport
        expect.extend_from_slice(&443u16.to_be_bytes()); // dport
        expect.push(6); // proto
        expect.extend_from_slice(&1500u64.to_be_bytes()); // octets
        expect.extend_from_slice(&10u64.to_be_bytes()); // packets
        expect.extend_from_slice(&1_000_000_000_000u64.to_be_bytes()); // start ms
        expect.extend_from_slice(&1_000_000_001_000u64.to_be_bytes()); // end ms
        expect.extend_from_slice(&7u64.to_be_bytes()); // flowId = session_id
        expect.extend_from_slice(&1u32.to_be_bytes()); // samplingInterval = 未采样
        expect.extend_from_slice(&[0, 0, 0]); // 填充：只允许零，且短于记录长度

        assert_eq!(m, &expect, "报文字节与手写期望不符");
        assert_eq!(m.len(), total);
    }

    #[test]
    fn sequence_number_counts_data_records_only() {
        // 配置下限在**编码时**校验（`new()` 只校验模板周期与采样间隔的合法性）：
        // 预算连「报文头+两个模板+最长记录」(16+52+52+81=201) 都放不下时必须明确报错，
        // 而不是静默产出空报文或残缺产物。
        let mut too_small = Encoder::new(ExportConfig {
            max_msg_bytes: 128,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            too_small.encode_batch(&[rec_v4()], 1).unwrap_err(),
            ExportError::MessageTooSmall {
                need: 201,
                got: 128
            }
        );
        let mut e = Encoder::new(ExportConfig {
            max_msg_bytes: 220,
            template_refresh_msgs: 20,
            ..Default::default()
        })
        .unwrap();
        let recs = vec![rec_v4(), rec_v4(), rec_v4()];
        let msgs = e.encode_batch(&recs, 100).unwrap();
        assert!(msgs.len() >= 2, "3 条记录应在 220 字节预算下切成多条报文");
        // 第一条报文 seq=0；第二条报文的 seq 必须等于第一条装的数据记录数。
        assert_eq!(
            u32::from_be_bytes([msgs[0][8], msgs[0][9], msgs[0][10], msgs[0][11]]),
            0
        );
        let first_records = data_record_count(&msgs[0]);
        assert_eq!(
            u32::from_be_bytes([msgs[1][8], msgs[1][9], msgs[1][10], msgs[1][11]]),
            first_records
        );
        assert_eq!(e.sequence_number(), 3);
    }

    /// 从报文里数出数据记录条数（测试专用：按模板长度推）。
    fn data_record_count(msg: &[u8]) -> u32 {
        let t = Template::ipv4();
        let mut off = MSG_HEADER_LEN;
        let mut n = 0;
        while off + SET_HEADER_LEN <= msg.len() {
            let set_id = u16::from_be_bytes([msg[off], msg[off + 1]]);
            let set_len = u16::from_be_bytes([msg[off + 2], msg[off + 3]]) as usize;
            if set_id == TEMPLATE_SET_ID {
                off += set_len;
                continue;
            }
            let body = set_len - SET_HEADER_LEN;
            // 减去可能的填充（< 记录长度）
            let mut rest = body;
            while rest >= t.record_len() {
                n += 1;
                rest -= t.record_len();
            }
            off += set_len;
        }
        n
    }

    #[test]
    fn template_refresh_resends_periodically() {
        let mut e = Encoder::new(ExportConfig {
            max_msg_bytes: 220,
            template_refresh_msgs: 2,
            ..Default::default()
        })
        .unwrap();
        let recs: Vec<FlowRecord> = (0..6).map(|_| rec_v4()).collect();
        let msgs = e.encode_batch(&recs, 1).unwrap();
        assert!(msgs.len() >= 3);
        let has_template = |m: &[u8]| {
            u16::from_be_bytes([m[MSG_HEADER_LEN], m[MSG_HEADER_LEN + 1]]) == TEMPLATE_SET_ID
        };
        assert!(has_template(&msgs[0]), "首报文必须带模板");
        assert!(!has_template(&msgs[1]), "第 2 条不必重复模板");
        assert!(
            has_template(&msgs[2]),
            "到期必须重发模板（否则采集器重启后解不开）"
        );
    }

    #[test]
    fn ipv6_record_uses_v6_template_and_length() {
        let mut e = Encoder::new(ExportConfig::default()).unwrap();
        let msgs = e.encode_batch(&[rec_v6()], 1).unwrap();
        let m = &msgs[0];
        // 模板集里必须出现 IPv6 地址 IE（27/28）
        let body = &m[MSG_HEADER_LEN..];
        let has = |ie: u16| {
            body.windows(4)
                .any(|w| u16::from_be_bytes([w[0], w[1]]) == ie && w[2] == 0 && w[3] == 16)
        };
        assert!(has(27) && has(28), "IPv6 模板必须用 27/28 且长度 16");
        // 数据集长度 = 4 + 81 + 3 = 88
        let tlen = Template::ipv4().template_set_len();
        let set_id = u16::from_be_bytes([m[MSG_HEADER_LEN + tlen], m[MSG_HEADER_LEN + tlen + 1]]);
        let set_len =
            u16::from_be_bytes([m[MSG_HEADER_LEN + tlen + 2], m[MSG_HEADER_LEN + tlen + 3]]);
        assert_eq!(set_id, TEMPLATE_ID_V6);
        assert_eq!(set_len, 88);
    }

    #[test]
    fn mixed_families_go_into_separate_data_sets() {
        let mut e = Encoder::new(ExportConfig::default()).unwrap();
        let msgs = e.encode_batch(&[rec_v4(), rec_v6(), rec_v4()], 1).unwrap();
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];
        let mut off = MSG_HEADER_LEN;
        let mut set_ids = Vec::new();
        while off + SET_HEADER_LEN <= m.len() {
            let set_id = u16::from_be_bytes([m[off], m[off + 1]]);
            let set_len = u16::from_be_bytes([m[off + 2], m[off + 3]]) as usize;
            set_ids.push(set_id);
            off += set_len;
        }
        // 两个模板集（都是 setID=2，各带一个模板）+ 三段数据集：v4、v6、v4
        // （同族不连续时不合并，按段切分——合并会让"记录顺序"与数据集边界脱钩）
        assert_eq!(
            set_ids,
            vec![
                TEMPLATE_SET_ID,
                TEMPLATE_SET_ID,
                TEMPLATE_ID_V4,
                TEMPLATE_ID_V6,
                TEMPLATE_ID_V4
            ]
        );
        assert_eq!(off, m.len(), "Set 长度必须能严丝合缝地把报文走完");
    }

    #[test]
    fn rejects_zero_template_refresh_and_sampling() {
        assert_eq!(
            Encoder::new(ExportConfig {
                template_refresh_msgs: 0,
                ..Default::default()
            })
            .unwrap_err(),
            ExportError::BadTemplateRefresh(0)
        );
        assert_eq!(
            Encoder::new(ExportConfig {
                sampling_interval: 0,
                ..Default::default()
            })
            .unwrap_err(),
            ExportError::BadSamplingInterval(0)
        );
    }

    #[test]
    fn every_set_length_is_a_multiple_of_4_and_zero_padded() {
        let mut e = Encoder::new(ExportConfig::default()).unwrap();
        let recs = vec![rec_v4(), rec_v4(), rec_v6()];
        let msgs = e.encode_batch(&recs, 1).unwrap();
        for m in &msgs {
            let mut off = MSG_HEADER_LEN;
            while off + SET_HEADER_LEN <= m.len() {
                let set_len = u16::from_be_bytes([m[off + 2], m[off + 3]]) as usize;
                assert_eq!(set_len % 4, 0, "Set 长度必须 4 字节对齐（RFC 7011 §3.3.1）");
                assert!(off + set_len <= m.len());
                off += set_len;
            }
            assert_eq!(off, m.len());
        }
    }

    /// 记录里的应用识别结果**不参与** v1 导出：断言这一点，防止有人"顺手"加字段
    /// 却忘了它在协议里没有对应 IE（编造字段号比不导出更糟）。
    #[test]
    fn app_info_is_not_exported_in_v1() {
        let mut r = rec_v4();
        r.app = AppInfo {
            outcome: "identified",
            app: Some(AppId::Tls),
            confidence: Some(Confidence::High),
            rationale: Some("test"),
            server_name: Some("example.com".into()),
            bytes_inspected: 512,
        };
        let mut e = Encoder::new(ExportConfig::default()).unwrap();
        let with_app = e.encode_batch(&[r.clone()], 1).unwrap();
        r.app = AppInfo::not_inspected();
        let mut e2 = Encoder::new(ExportConfig::default()).unwrap();
        let without_app = e2.encode_batch(&[r], 1).unwrap();
        assert_eq!(
            with_app, without_app,
            "v1 不导出 DPI 结果，两者字节必须相同"
        );
    }

    #[test]
    fn outcome_type_is_used() {
        // 让 `Outcome` 的导入不被优化掉（同时说明 v1 与 DPI 的关系：不导出但同处一条链）。
        let _ = Outcome::Unknown;
    }
}
