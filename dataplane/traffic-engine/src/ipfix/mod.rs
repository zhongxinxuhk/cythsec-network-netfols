// ipfix/mod.rs —— IPFIX（RFC 7011）**线路格式**：编码与解码共用这一份定义。
//
// ## 为什么单独一层
//
// 编码器（`export/mod.rs`）与采集器（`ipfix/collector.rs`）是同一个协议的**两侧**。
// 若各自写一份 IE 编号与模板布局，就会出现最坏的一类 bug：**两端都错、且互相验证通过**
// （编码器把字节 5 当协议号、解码器也从字节 5 读协议号 → 往返测试全绿，真采集器全错）。
// 所以 IE 编号、字段长度、模板结构、Set/报文头长度**只在这里定义一次**，
// 两侧都 `use` 它；而"到底对不对"由**第三方**（tshark）裁决，不由我们自己裁决。
//
// ## 与 RFC 的对应
//
// - 报文头 16 字节：version(10) / length / exportTime / sequenceNumber / observationDomainID（§3.1）
// - Set 头 4 字节：setID / length；模板集 setID=2（选项模板集 3），数据集 setID ≥ 256（§3.3.2）
// - 填充只允许零字节，且填充长度必须**短于** Set 内任何一条记录（§3.3.1）
// - 模板在 UDP 上必须周期性重传；采集侧给模板设**生存期**，未刷新即丢弃（§8.4）
// - 序列号 = 本报文**之前**该 Observation Domain 已发送的**数据记录**累计数（模板不计，§3.1）
//   —— 这是采集侧发现"导出丢包"的唯一手段（§11.6）

pub mod collector;
// estimate 是**采样后的量级还原**（CYS-TRF-053 缺口③）：把样本求和 ×N 得到全量估计，
// 并给出 95% 区间。放在 ipfix 下是因为它消费的是采集侧解码出的记录（IE 34 是它的输入）。
pub mod estimate;

pub use collector::{Collector, CollectorConfig, CollectorStats, DatagramOutcome, ExporterId};

/// IPFIX 版本号（RFC 7011 固定为 10）。
pub const IPFIX_VERSION: u16 = 10;
/// 报文头长度（字节）。
pub const MSG_HEADER_LEN: usize = 16;
/// Set 头长度（字节）。
pub const SET_HEADER_LEN: usize = 4;
/// 模板集标识。
pub const TEMPLATE_SET_ID: u16 = 2;

/// 选项模板集 setID（RFC 7011 §3.3.2）。本版采集器只解析长度并跳过，不解码选项模板。
pub const OPTIONS_TEMPLATE_SET_ID: u16 = 3;
/// 数据集标识下界（RFC 7011：≥ 256）。
pub const FIRST_DATA_SET_ID: u16 = 256;
/// IANA 为 IPFIX 分配的默认端口（RFC 7011 §10.2.1 注册 4739）。
pub const IPFIX_PORT: u16 = 4739;
/// IPv4 模板 id。
pub const TEMPLATE_ID_V4: u16 = 256;
/// IPv6 模板 id。
pub const TEMPLATE_ID_V6: u16 = 257;

/// IPFIX 信息元素编号。
///
/// **对照 IANA "IPFIX Information Elements" 注册表（2026-10-05 取表）**：
/// 1 octetDeltaCount / 2 packetDeltaCount / 4 protocolIdentifier / 7 sourceTransportPort /
/// 8 sourceIPv4Address / 11 destinationTransportPort / 12 destinationIPv4Address /
/// 27 sourceIPv6Address / 28 destinationIPv6Address / 34 samplingInterval /
/// 148 flowId / 152 flowStartMilliseconds / 153 flowEndMilliseconds。
///
/// 单位与语义按注册表：`*Milliseconds` 是毫秒（不是微秒），`samplingInterval = 1`
/// 的含义是「未采样」（RFC 5476：间隔 1 即每个包都观察）。**值不再硬编码**：
/// 由导出侧从真正执行采样的那份配置传入（`CYS-TRF-053`），否则 IE 34 只是句声明。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Ie {
    OctetDeltaCount = 1,
    PacketDeltaCount = 2,
    ProtocolIdentifier = 4,
    SourceTransportPort = 7,
    SourceIPv4Address = 8,
    DestinationTransportPort = 11,
    DestinationIPv4Address = 12,
    SourceIPv6Address = 27,
    DestinationIPv6Address = 28,
    SamplingInterval = 34,
    FlowId = 148,
    FlowStartMilliseconds = 152,
    FlowEndMilliseconds = 153,
}

impl Ie {
    /// 注册表里的编号。写成方法而不是让调用点写裸数字：裸数字散落在编码器里
    /// 正是"字段号写错但两端都同意"这类 bug 的温床（两端都错＝测试全绿）。
    pub fn code(self) -> u16 {
        self as u16
    }

    /// 从线上编号还原语义。未登记的编号返回 `None` —— **不许兜底成某个默认 IE**：
    /// 采集侧遇到不认识的编号必须"跳过该字段"，而不是按已知字段去解释它。
    pub fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            1 => Self::OctetDeltaCount,
            2 => Self::PacketDeltaCount,
            4 => Self::ProtocolIdentifier,
            7 => Self::SourceTransportPort,
            8 => Self::SourceIPv4Address,
            11 => Self::DestinationTransportPort,
            12 => Self::DestinationIPv4Address,
            27 => Self::SourceIPv6Address,
            28 => Self::DestinationIPv6Address,
            34 => Self::SamplingInterval,
            148 => Self::FlowId,
            152 => Self::FlowStartMilliseconds,
            153 => Self::FlowEndMilliseconds,
            _ => return None,
        })
    }
}

/// 模板里的一个字段：IE + 长度（定长编码）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    pub ie: Ie,
    pub len: u16,
}

/// 解码侧的字段：`ie = None` 表示**未登记编号** —— 长度必须保留。
///
/// 这一条看着琐碎，却是最容易静默出错的地方：如果未知 IE 直接从字段表里**删掉**，
/// 后面所有字段的偏移都会整体前移，而前移后读出来的往往仍是"合法"的字节
/// （把 flowStart 的 8 字节当成 octets 之类），于是"数据全错但看起来全对"。
/// 故：未知 IE 保留长度、不解释语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireField {
    /// `None` = 未登记编号（跳过 `len` 字节，不赋语义）。
    pub ie: Option<Ie>,
    pub len: u16,
}

/// 一个模板（v1 只有 v4/v6 两套，字段结构相同，仅地址 IE 与长度不同）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub id: u16,
    pub fields: Vec<FieldSpec>,
}

impl Template {
    /// IPv4 模板。
    pub fn ipv4() -> Self {
        Self {
            id: TEMPLATE_ID_V4,
            fields: vec![
                FieldSpec {
                    ie: Ie::SourceIPv4Address,
                    len: 4,
                },
                FieldSpec {
                    ie: Ie::DestinationIPv4Address,
                    len: 4,
                },
                FieldSpec {
                    ie: Ie::SourceTransportPort,
                    len: 2,
                },
                FieldSpec {
                    ie: Ie::DestinationTransportPort,
                    len: 2,
                },
                FieldSpec {
                    ie: Ie::ProtocolIdentifier,
                    len: 1,
                },
                FieldSpec {
                    ie: Ie::OctetDeltaCount,
                    len: 8,
                },
                FieldSpec {
                    ie: Ie::PacketDeltaCount,
                    len: 8,
                },
                FieldSpec {
                    ie: Ie::FlowStartMilliseconds,
                    len: 8,
                },
                FieldSpec {
                    ie: Ie::FlowEndMilliseconds,
                    len: 8,
                },
                FieldSpec {
                    ie: Ie::FlowId,
                    len: 8,
                },
                FieldSpec {
                    ie: Ie::SamplingInterval,
                    len: 4,
                },
            ],
        }
    }

    /// IPv6 模板。
    pub fn ipv6() -> Self {
        let mut t = Self::ipv4();
        t.id = TEMPLATE_ID_V6;
        t.fields[0] = FieldSpec {
            ie: Ie::SourceIPv6Address,
            len: 16,
        };
        t.fields[1] = FieldSpec {
            ie: Ie::DestinationIPv6Address,
            len: 16,
        };
        t
    }

    /// 一条数据记录的长度（定长编码，与记录内容无关）。
    pub fn record_len(&self) -> usize {
        self.fields.iter().map(|f| f.len as usize).sum()
    }

    /// 模板集的字节长度（4 字节对齐：Set 头 4 + 模板头 4 + 4 字节/字段）。
    pub fn template_set_len(&self) -> usize {
        SET_HEADER_LEN + 4 + 4 * self.fields.len()
    }
}
