// dpi/types.rs —— DPI 的公共类型与裁决语义。
//
// 整个模块的职责边界只有一句：**从首包的前若干字节判断这是什么应用，并说明凭什么这么判。**
// 它不重组流、不还原文件、不做行为分析 —— 那些属于 reassembly / feature / behavior，
// DPI 只负责"这一段的字节说明了什么"，且必须是**纯函数**：同一段字节永远给同一结论，
// 否则省网级统计的置信度就无从谈起。

/// 应用标识取值（对应 `ATTR_APP_ID`）。
///
/// 属性字典里 `ATTR_APP_ID` 的 desc 明确写着「内置与自定义以命名空间区分，**不使用魔数边界**」。
/// 因此这里刻意**不**用 1/2/3 这种散落的魔数，而是把 u32 拆成「高 16 位=命名空间、
/// 低 16 位=命名空间内序号」两段显式编码，自定义应用可在 `NS_CUSTOM` 段自行分配。
///
/// 之所以在代码里就把取值空间画出来：一旦有人开始用 4/5/6，就会有人自造 100 用作"临时值"，
/// 两个月后没人记得它算内置还是自定义 —— 命名空间存在的意义就是不让这件事发生。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppId {
    Tls,
    Http,
    Dns,
    Dhcpv4,
    Dhcpv6,
    Mdns,
    Quic,
    Ssh,
    WireGuard,
    Ikev1,
    Ikev2,
    Esp,
    Ah,
    Gre,
    Ipip,
    Ipv6ip,
    Etherip,
    L2tp,
    Pptp,
    Vxlan,
    Geneve,
    OpenVpn,
    Socks4,
    Socks5,
    Dtls,
    Tlcp,
    Unknown,
}

impl AppId {
    /// 内置段（`NS_BUILTIN`）内的协议号。
    pub const NS_BUILTIN: u32 = 0x0001;
    /// 自定义段起点：第 0x8000 个内置之后的取值归使用者自行定义。
    pub const NS_CUSTOM: u32 = 0x8000;

    pub const fn encode(ns: u32, seq: u16) -> u32 {
        (ns << 16) | (seq as u32)
    }

    /// 与 `ATTR_APP_ID`（u32）同型的取值。
    pub const fn as_u32(self) -> u32 {
        match self {
            AppId::Tls => AppId::encode(AppId::NS_BUILTIN, 1),
            AppId::Http => AppId::encode(AppId::NS_BUILTIN, 2),
            AppId::Dns => AppId::encode(AppId::NS_BUILTIN, 3),
            AppId::Quic => AppId::encode(AppId::NS_BUILTIN, 4),
            AppId::Ssh => AppId::encode(AppId::NS_BUILTIN, 5),
            AppId::WireGuard => AppId::encode(AppId::NS_BUILTIN, 6),
            AppId::Ikev1 => AppId::encode(AppId::NS_BUILTIN, 7),
            AppId::Ikev2 => AppId::encode(AppId::NS_BUILTIN, 8),
            AppId::Esp => AppId::encode(AppId::NS_BUILTIN, 9),
            AppId::Ah => AppId::encode(AppId::NS_BUILTIN, 10),
            AppId::Gre => AppId::encode(AppId::NS_BUILTIN, 11),
            AppId::Ipip => AppId::encode(AppId::NS_BUILTIN, 12),
            AppId::Ipv6ip => AppId::encode(AppId::NS_BUILTIN, 13),
            AppId::Etherip => AppId::encode(AppId::NS_BUILTIN, 14),
            AppId::L2tp => AppId::encode(AppId::NS_BUILTIN, 15),
            AppId::Pptp => AppId::encode(AppId::NS_BUILTIN, 16),
            AppId::Vxlan => AppId::encode(AppId::NS_BUILTIN, 17),
            AppId::Geneve => AppId::encode(AppId::NS_BUILTIN, 18),
            AppId::OpenVpn => AppId::encode(AppId::NS_BUILTIN, 19),
            AppId::Socks4 => AppId::encode(AppId::NS_BUILTIN, 20),
            AppId::Socks5 => AppId::encode(AppId::NS_BUILTIN, 21),
            AppId::Dtls => AppId::encode(AppId::NS_BUILTIN, 22),
            AppId::Tlcp => AppId::encode(AppId::NS_BUILTIN, 23),
            AppId::Dhcpv4 => AppId::encode(AppId::NS_BUILTIN, 24),
            AppId::Dhcpv6 => AppId::encode(AppId::NS_BUILTIN, 25),
            AppId::Mdns => AppId::encode(AppId::NS_BUILTIN, 26),
            AppId::Unknown => AppId::encode(AppId::NS_CUSTOM, 0),
        }
    }

    /// 人类可读名（日志、控制台展示用）。
    pub const fn as_str(self) -> &'static str {
        match self {
            AppId::Tls => "tls",
            AppId::Http => "http",
            AppId::Dns => "dns",
            AppId::Dhcpv4 => "dhcpv4",
            AppId::Dhcpv6 => "dhcpv6",
            AppId::Mdns => "mdns",
            AppId::Quic => "quic",
            AppId::Ssh => "ssh",
            AppId::WireGuard => "wireguard",
            AppId::Ikev1 => "ikev1",
            AppId::Ikev2 => "ikev2",
            AppId::Esp => "esp",
            AppId::Ah => "ah",
            AppId::Gre => "gre",
            AppId::Ipip => "ipip",
            AppId::Ipv6ip => "ipv6-in-ip",
            AppId::Etherip => "etherip",
            AppId::L2tp => "l2tp",
            AppId::Pptp => "pptp",
            AppId::Vxlan => "vxlan",
            AppId::Geneve => "geneve",
            AppId::OpenVpn => "openvpn",
            AppId::Socks4 => "socks4",
            AppId::Socks5 => "socks5",
            AppId::Dtls => "dtls",
            AppId::Tlcp => "tlcp",
            AppId::Unknown => "unknown",
        }
    }
}

/// 置信度：省网级统计要能回答"这个数能不能拿去做容量规划"。
///
/// 三档而非连续浮点：`High` 意味着有协议自身的强证据（载荷里真的有 ClientHello / DNS 报文头），
/// `Medium` 是端口 + 弱特征（例如 443 上出现 `\x16\x03\x01` 之外的握手痕迹），
/// `Low` 则是兜底猜测。把置信度显式化，规则引擎才能决定"这条要不要采信/要不要二次确认"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    /// 数值越高置信度越强，便于排序与阈值比较。
    pub const fn weight(self) -> u8 {
        match self {
            Confidence::High => 3,
            Confidence::Medium => 2,
            Confidence::Low => 1,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

/// 单个协议的识别结果：所有检测器共用的输出形状。
///
/// 字段一律用 `Option`：SNI 缺失与"没识别出这是 TLS"是两件完全不同的事，
/// 用同一个 `Option::None` 表达二者，下游就会把"ECH 加密的流量"统计成"解析失败的流量"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub app: AppId,
    pub confidence: Confidence,
    /// 判据留痕：规则审计与误报复盘靠它回答"凭什么说是这个"。
    pub rationale: &'static str,

    // ---- TLS ----
    /// TLS 记录层里看到的 SNI（可能为空：无 SNI / ECH / 加密扩展）。
    pub sni: Option<String>,
    /// JA3 指纹（仅 TLS 首包可算）。
    pub ja3: Option<String>,
    /// JA3 未哈希的原始串，便于人工比对。
    pub ja3_raw: Option<String>,
    /// ALPN 协商协议（可能为空）。
    pub alpn: Vec<String>,
    /// TLS 握手版本号。
    pub tls_version: Option<u16>,
    /// 存在加密 ClientHello（ECH）扩展：真实 SNI 不可见是**预期**而非故障。
    pub ech: bool,

    // ---- HTTP ----
    pub method: Option<String>,
    pub host: Option<String>,
    /// 请求 URI（含路径与查询）。仅请求侧有值。
    pub uri: Option<String>,
    /// 请求 User-Agent。仅请求侧有值：响应里没有这个头（`Server` 是另一个字段）。
    pub user_agent: Option<String>,
    /// 响应状态码。仅**响应**侧有值 —— 请求侧留 `None`，
    /// 而不是填 0："这个报文不是响应"与"响应的状态码是 0"在下游是两件事。
    pub status_code: Option<u16>,
    /// Content-Type（请求/响应都产出；类型名已归一小写，`; charset=…` 参数保留，
    /// 见 `http::normalize_content_type` 里对「为什么保留参数」的说明）。
    pub content_type: Option<String>,

    // ---- DNS ----
    pub qname: Option<String>,
    pub qtype: Option<u16>,
    /// 查询类别（IN/CH/HS…）。查询与响应的 QUESTION 段都有。
    pub qclass: Option<u16>,
    /// 响应码 RCODE。**只在响应上产出**：查询报文的 RCODE 段是保留位且恒为 0，
    /// 把它当成"这次查询没出错"写进指标，等于凭空造出一批正常样本。
    pub rcode: Option<u8>,
    /// 应答里的地址集合（A/AAAA）。响应侧才有，按报文顺序。
    pub answer_ips: Vec<String>,
    /// QUESTION 名字解析时的压缩指针跳数（0 = 没用压缩指针）。
    /// 它是"解析成本"的可观测面：非 0 说明这条报文的名字是跳着读出来的。
    pub ptr_depth: Option<u8>,
    /// EDNS0 请求方声明的 UDP 载荷上限（OPT 记录的 CLASS 字段）。
    pub edns0_udp_size: Option<u16>,
}

impl Detection {
    /// 构造一份"已识别"结果（检测器的统一出口）。
    pub fn new(app: AppId, confidence: Confidence, rationale: &'static str) -> Self {
        Self {
            app,
            confidence,
            rationale,
            sni: None,
            ja3: None,
            ja3_raw: None,
            alpn: Vec::new(),
            tls_version: None,
            ech: false,
            method: None,
            host: None,
            uri: None,
            user_agent: None,
            status_code: None,
            content_type: None,
            qname: None,
            qtype: None,
            qclass: None,
            rcode: None,
            answer_ips: Vec::new(),
            ptr_depth: None,
            edns0_udp_size: None,
        }
    }

    /// 归一化的服务端域名：TLS SNI / HTTP Host / QUIC SNI 都归一到这一个属性
    /// （对应 `ATTR_SERVER_FQDN` 的 desc）。多个来源同时存在时按证据强度取一个，
    /// 重复产出会让下游在"这条流有几个域名"上算错。
    pub fn server_fqdn(&self) -> Option<&str> {
        self.sni.as_deref().or(self.host.as_deref())
    }
}

/// 单个协议检测器对一段载荷的裁决。
///
/// 这里刻意**不用** `Result`/`DpiError`："这个包不是 TLS"与"TLS 包自己解析坏了"在
/// `Result` 里都只是 `Err`，下游无法区分该等后续字节（分片）还是该直接丢弃（畸形），
/// 而把两者混为一谈正是省网级统计里"未知流量"虚高的主要来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detect {
    /// 确认是它，并给出可提取的字段。
    Hit(Detection),
    /// 还不够（多半是分片）：补上字节就能继续，**不得**报 Hit 或"未识别"。
    NeedMore,
    /// 这段载荷开头就**不是**这个协议（不是"我解析失败"，是"它根本不是"）。
    Rejected,
    /// 开头像，但内部自相矛盾：补多少字节都救不回来，只能丢弃。
    Malformed,
}

impl Detect {
    /// 与 `expected.json` 的 `expect` 字段对应的词形，供测试与向量比对。
    pub const fn word(&self) -> &'static str {
        match self {
            Detect::Hit(_) => "identified",
            Detect::NeedMore => "need_more",
            Detect::Rejected => "rejected",
            Detect::Malformed => "malformed",
        }
    }

    /// 取内部结论（`Hit` 之外一律 `None`）。
    pub fn detection(&self) -> Option<&Detection> {
        match self {
            Detect::Hit(d) => Some(d),
            _ => None,
        }
    }
}

/// 内层读取失败的两种原因，与 `Detect` 的语义一一对应。
///
/// 区分它们不是为了好看：`Incomplete` 说明"包是好的、只是还没到"，
/// `Inconsistent` 说明"这个包是坏的"。下游把两者混管，省网级的 unknown 率就会虚高。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadErr {
    /// 只是当前缓冲区里还没有那么多字节 —— 多半是分片。
    Incomplete,
    /// 声明的长度越过了它自己所在的结构边界 —— 补多少字节都无解。
    Inconsistent,
}

impl From<ReadErr> for Detect {
    fn from(v: ReadErr) -> Self {
        match v {
            ReadErr::Incomplete => Detect::NeedMore,
            ReadErr::Inconsistent => Detect::Malformed,
        }
    }
}

/// 框架级结论：检测器们投票之后的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 已识别（框架按端口/载荷选出主检测器后的结论）。
    Identified(Detection),
    /// 需要更多字节才能判断。
    NeedMore,
    /// 至少有一个检测器见到了自相矛盾的载荷。
    Malformed,
    /// 所有检测器都明确拒绝：这段载荷不属于任何已知协议（例如把 HTTP 请求喂给 TLS 检测器）。
    Unknown,
}

impl Outcome {
    /// 与 `expected.json` 的词形对齐。
    pub const fn word(&self) -> &'static str {
        match self {
            Outcome::Identified(_) => "identified",
            Outcome::NeedMore => "need_more",
            Outcome::Malformed => "malformed",
            Outcome::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 命名空间必须真的分段，否则 `as_u32` 与"不使用魔数边界"的约束就是空话。
    #[test]
    fn app_id_namespaces_are_split() {
        assert_eq!(AppId::Tls.as_u32(), 0x0001_0001);
        assert_eq!(AppId::Http.as_u32(), 0x0001_0002);
        assert_eq!(AppId::Dns.as_u32(), 0x0001_0003);
        assert_eq!(AppId::Dhcpv4.as_u32(), 0x0001_0018);
        assert_eq!(AppId::Dhcpv4.as_str(), "dhcpv4");
        assert_eq!(AppId::Dhcpv6.as_u32(), 0x0001_0019);
        assert_eq!(AppId::Dhcpv6.as_str(), "dhcpv6");
        assert_eq!(AppId::Mdns.as_u32(), 0x0001_001a);
        assert_eq!(AppId::Mdns.as_str(), "mdns");
        // 自定义段与内置段不能撞号
        assert!(AppId::Unknown.as_u32() >= AppId::encode(AppId::NS_CUSTOM, 0));
        assert!(AppId::Tls.as_u32() < AppId::encode(AppId::NS_CUSTOM, 0));
    }

    #[test]
    fn server_fqdn_prefers_tls_sni() {
        let mut d = Detection::new(AppId::Tls, Confidence::High, "test");
        d.sni = Some("a.example".to_string());
        d.host = Some("b.example".to_string());
        assert_eq!(d.server_fqdn(), Some("a.example"));

        let e = Detection::new(AppId::Http, Confidence::High, "test");
        assert_eq!(e.server_fqdn(), None);
    }

    #[test]
    fn detect_word_matches_expectation_vocabulary() {
        assert_eq!(
            Detect::Hit(Detection::new(AppId::Dns, Confidence::High, "t")).word(),
            "identified"
        );
        assert_eq!(Detect::NeedMore.word(), "need_more");
        assert_eq!(Detect::Malformed.word(), "malformed");
        assert_eq!(Detect::Rejected.word(), "rejected");
    }
}
