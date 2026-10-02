// dpi/tls.rs —— TLS ClientHello 解析与 JA3 指纹（CYS-TRF-021）。
//
// 为什么只解析 ClientHello：省网级统计里 HTTPS 流量的应用识别，**信息几乎全在这一个报文里**。
// SNI 决定"连到哪个域名"，ALPN 决定"跑的是 HTTP/2 还是 HTTP/1.1"，而 JA3 决定"是哪个客户端程序"
// —— 这三个维度合起来就能把绝大多数加密流量分到具体应用。等握手往下走（证书、Finished）
// 只能换来更差的时效性（首包判定才能让省网侧在连接建立的头几百微秒内出结果）。
//
// 三条不可让步的约束：
//   1. **只看首包前若干字节**：不重组流、不收更多包，解析器必须是纯函数。
//   2. **绝不信任长度字段**。长度字段是攻击者最容易操纵的位置：写个 0xFFFF 让实现去拷贝
//      4GB 就是现成的拒绝服务；写个超大但"看起来合法"的值则可能让索引越界。
//      本模块所有读取都走 `Cursor`，越界要么 NeedMore 要么 Malformed，没有第三种结局。
//   3. **不 panic**。任何输入都不得让进程崩 —— 省网设备上是内核旁路路径，一个 panic 就是整机掉包。

use super::md5::md5_hex;
use super::types::{Confidence, Detect, Detection, ReadErr};

// ---- 扩展号 ----
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
const EXT_EC_POINT_FORMATS: u16 = 0x000B;
const EXT_ALPN: u16 = 0x0010;
/// supported_versions（RFC 8446 4.2.1）：TLS 1.3 客户端在握手版本字段里**仍然写 0x0303**，
/// 真正想用的版本只出现在这个扩展里。只信握手版本会把 TLS 1.3 流量统统记成 TLS 1.2 ——
/// 在今天的省网 HTTPS 里那是一多半流量，所以这里必须单独解析。
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
/// 加密 ClientHello（ECH，draft-13 起为该号）。
/// 出现即说明**真实 SNI 被加密、外层不可见**——这是预期状态，不是解析失败。
const EXT_ECH: u16 = 0xFE0D;

/// RFC 8701 GREASE 值：两个字节相同且低半字节为 0xa（0x0a0a / 0x1a1a / …）。
/// 浏览器每次连接随机插入若干个，导致同一客户端的 JA3 **逐连接变化**；
/// 不剔除的话，JA3 分位数统计会把一个浏览器拆成几十个"指纹"。
const GREASE: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// 会话 ID 长度上限（RFC 8446 4.1.1）。超过即结构上不可能，属畸形而非"需要更多字节"。
const MAX_SESSION_ID: usize = 32;
/// 单个扩展体长度上限：真实客户端远小于此，超过就是想让解析器去拷一大块内存。
const MAX_EXT_BODY: usize = 64 * 1024;

/// 从 ClientHello 里提取出的结构化字段（供其他模块与测试复用）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientHello {
    /// 记录层版本（payload[1..3] 通常在在线抓包里是 0x0301/0x0303）。
    pub record_version: u16,
    /// 握手层版本（JA3 用它作为第一字段）。
    pub handshake_version: u16,
    pub cipher_suites: Vec<u16>,
    /// 扩展号**按出现顺序**排列（含 GREASE，供 JA3 与审计使用）。
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    /// supported_versions 扩展里的版本列表（为空表示没有该扩展）。
    pub supported_versions: Vec<u16>,
    /// 存在即表示真实 SNI 不可见。
    pub has_ech: bool,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
}

/// 读取游标：所有字节读取的唯一入口。
///
/// 它把"越界"拆成两种彼此不同的结局，这正是本模块最关键的语义决策：
///   * 越过 `hard_end`（**声明的**握手体末端）→ `Inconsistent` → Malformed。
///     理由：握手长度由握手头自己声明，若子字段长度越过它，说明这个包自相矛盾，
///     再补多少字节都不可能变正确。
///   * 越过 `buf.len()`（**已捕获的**字节）→ `Incomplete` → NeedMore。
///     理由：省网里 TCP 分片、snaplen 截断都长这样，只能等后续字节。
///
/// 顺序不能反：先判结构边界再判缓冲区，否则"畸形"会被误报成"分片"，
/// 而分片在统计上意味着"再等等就能识别"，畸形意味着"这条直接丢"——后果完全不同。
struct Cursor<'a> {
    buf: &'a [u8],
    hard_end: usize,
    p: usize,
}

impl<'a> Cursor<'a> {
    /// `start` 是握手体的起点（记录头 5 字节 + 握手头 4 字节之后）。
    /// 把它当成参数而不是"默认 0 再手动跳过"，是为了让"从哪开始"这件事只有一个地方说了算：
    /// 少跳 9 个字节的表现是"每个字段都错位"，输出仍然像模像样，排查成本很高。
    fn new(buf: &'a [u8], hard_end: usize, start: usize) -> Self {
        Self {
            buf,
            hard_end,
            p: start,
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ReadErr> {
        if self.p + n > self.hard_end {
            return Err(ReadErr::Inconsistent);
        }
        if self.p + n > self.buf.len() {
            return Err(ReadErr::Incomplete);
        }
        let s = &self.buf[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, ReadErr> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ReadErr> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn pos(&self) -> usize {
        self.p
    }
}

/// 解析一段 ClientHello 载荷。
///
/// 返回 `Ok` 表示成功取到字段；`Err(Detect::Rejected)` 表示"这根本不是 TLS"，
/// `Err(Detect::NeedMore|Malformed)` 表示"是 TLS，但当前字节不够 / 自相矛盾"。
pub fn parse(payload: &[u8]) -> Result<ClientHello, Detect> {
    // ---- 记录层 ----
    if payload.len() < 5 {
        return Err(Detect::NeedMore);
    }
    if payload[0] != 0x16 {
        return Err(Detect::Rejected); // 不是握手记录（这一条就是"看到 \x16 才当 TLS"的反例）
    }
    // 记录层版本最低要求 0x03xx：0x0300(SSLv3) 以上。大小写 0x0301/0x0303 都常见。
    if payload[1] != 0x03 {
        return Err(Detect::Rejected);
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if record_len < 4 {
        // 握手头自身就 4 字节，记录层装不下它 → 绝不是一条合法 TLS 记录
        return Err(Detect::Rejected);
    }
    let record_end = 5 + record_len;
    if payload.len() < record_end {
        return Err(Detect::NeedMore); // 记录本身被截断（snaplen / 分片）
    }
    let record_version = u16::from_be_bytes([payload[1], payload[2]]);

    // ---- 握手头 ----
    // 握手头 4 字节：payload[5] = 握手类型（ClientHello 为 0x01），
    // payload[6..9] = **3 字节**握手长度。长度不是常见的 2 字节，按 2 字节读会整体错位一字节，
    // 得到的是一个"看起来合法但荒谬"的长度（例如 0x010000）——这正是需要硬断言去防的那类错。
    // 到此已确认 payload.len() >= record_end >= 9，因此 [6..9] 必然在界内。
    let handshake_len =
        (u32::from(payload[6]) << 16) | (u32::from(payload[7]) << 8) | u32::from(payload[8]);
    // 刻意**不**检查 `handshake_len + 4 <= record_len`：
    // 握手消息可以**跨多条 record 分片**（带后量子密钥的巨型 ClientHello 必然如此），
    // 因此"握手长度超出单条 record"是完全合法的形态，判 Malformed 会误杀这类流量。
    //
    // 反过来，**已捕获字节装不下整条握手消息**则是确凿的"还没到" —— 只能等后续 record。
    // 这条判据让"握手长度字段撒谎"与"真分片"落到同一个结论上：都不是畸形，都是数据不全。
    let hard_end = 9usize.saturating_add(handshake_len as usize);
    if hard_end > payload.len() {
        return Err(Detect::NeedMore);
    }
    const HANDSHAKE_BODY_START: usize = 9; // 记录头 5 字节 + 握手头 4 字节
    let mut c = Cursor::new(payload, hard_end, HANDSHAKE_BODY_START);

    let handshake_version = c.u16()?;
    let _random = c.take(32)?;
    let session_id_len = c.u8()? as usize;
    if session_id_len > MAX_SESSION_ID {
        return Err(Detect::Malformed);
    }
    if session_id_len > 0 {
        c.take(session_id_len)?;
    }

    // ---- 密码套件 ----
    let cs_len = c.u16()? as usize;
    if cs_len < 2 || cs_len % 2 != 0 {
        return Err(Detect::Malformed); // 数量为零或奇数个都构不成套件列表
    }
    let cs_bytes = c.take(cs_len)?;
    let cipher_suites = parse_u16_slice(cs_bytes)?;

    // ---- 压缩方法 ----
    let comp_len = c.u8()? as usize;
    if comp_len < 1 {
        return Err(Detect::Malformed);
    }
    let _comp = c.take(comp_len)?;

    // ---- 扩展（可缺省）：残余为空说明这个 Hello 没有扩展块，属合法 ----
    let mut hello = ClientHello {
        record_version,
        handshake_version,
        cipher_suites,
        extensions: Vec::new(),
        supported_groups: Vec::new(),
        ec_point_formats: Vec::new(),
        supported_versions: Vec::new(),
        has_ech: false,
        server_name: None,
        alpn: Vec::new(),
    };
    if hard_end <= c.pos() {
        return Ok(hello);
    }

    let ext_block_len = c.u16()? as usize;
    let ext_end = c.pos() + ext_block_len;
    while c.pos() < ext_end {
        let etype = c.u16()?;
        let elen = c.u16()? as usize;
        if elen > MAX_EXT_BODY {
            return Err(Detect::Malformed);
        }
        let body = c.take(elen)?;
        hello.extensions.push(etype);
        match etype {
            EXT_SERVER_NAME => {
                if hello.server_name.is_none() {
                    hello.server_name = parse_sni(body)?;
                }
            }
            EXT_ALPN => hello.alpn = parse_alpn(body)?,
            EXT_SUPPORTED_GROUPS => hello.supported_groups = parse_u16_list(body, 2)?,
            // supported_versions 的长度字段是 **1 字节**（RFC 8446：versions<2..254>），
            // 与 supported_groups 的 2 字节长度头不同 —— 两者混用会把长度值读成一个版本号。
            EXT_SUPPORTED_VERSIONS => hello.supported_versions = parse_u16_list(body, 1)?,
            EXT_EC_POINT_FORMATS => {
                if let Some(v) = parse_ec_formats(body)? {
                    hello.ec_point_formats = v;
                }
            }
            EXT_ECH => hello.has_ech = true,
            // 其余扩展（sig_algs、padding、key_share…）对识别无用，按不透明字节跳过。
            // 关键：跳过时**不做任何解释**，避免"自作聪明解析不认识的东西"引入新的解析攻击面。
            _ => {}
        }
    }
    if c.pos() != ext_end {
        // 扩展块长度与逐条扩展的实际占用对不上 → 冗余字节或长度撒谎
        return Err(Detect::Malformed);
    }

    Ok(hello)
}

/// 供框架调用的统一入口。
pub fn detect(payload: &[u8]) -> Detect {
    match parse(payload) {
        Ok(h) => Detect::Hit(h.into_detection()),
        Err(e) => e,
    }
}

/// JA3 特征串：`版本,套件,扩展,椭圆曲线,椭圆点格式`（GREASE 剔除后以 `-` 连接）。
///
/// 返回值是未哈希的原始串，便于人工比对；哈希见 [`ja3`]。
pub fn ja3_raw(hello: &ClientHello) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}", hello.handshake_version));
    out.push(',');
    out.push_str(&join_grease(hello.cipher_suites.iter().copied()));
    out.push(',');
    out.push_str(&join_grease(hello.extensions.iter().copied()));
    out.push(',');
    out.push_str(&join_grease(hello.supported_groups.iter().copied()));
    out.push(',');
    out.push_str(&join_grease_u8(hello.ec_point_formats.iter().copied()));
    out
}

/// JA3 指纹本体：JA3 特征串的 MD5（小写十六进制）。
pub fn ja3(hello: &ClientHello) -> String {
    md5_hex(ja3_raw(hello).as_bytes())
}

impl ClientHello {
    /// 客户端"打算用"的 TLS 版本：supported_versions 优先（握手版本对 TLS 1.3 会撒谎）。
    ///
    /// 注意这是客户端的**能力上限**，不是最终协商结果 —— 真正的协商结果只在 ServerHello 里。
    /// 首包判定的代价就是这个，规则里读 `ATTR_TLS_VERSION` 时应当按"客户端支持版本"理解。
    pub fn client_version(&self) -> u16 {
        self.supported_versions
            .iter()
            .copied()
            .max()
            .unwrap_or(self.handshake_version)
    }

    /// 转成框架级的 `Detection`（附 JA3 与置信度）。
    pub fn into_detection(self) -> Detection {
        let raw = ja3_raw(&self);
        let mut d = Detection::new(
            super::types::AppId::Tls,
            Confidence::High,
            "tls.client_hello: record+handshake 结构自洽",
        );
        d.ja3 = Some(md5_hex(raw.as_bytes()));
        d.ja3_raw = Some(raw);
        // 先算完所有借用字段再开始搬移：否则借用检查会在中途拦下
        d.tls_version = Some(self.client_version());
        d.ech = self.has_ech;
        d.sni = self.server_name;
        d.alpn = self.alpn;
        d
    }
}

/// 剔除 GREASE 后以 `-` 连接（u16 字段）。
fn join_grease<I: Iterator<Item = u16>>(vals: I) -> String {
    vals.filter(|v| !GREASE.contains(v))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// 剔除 GREASE 后以 `-` 连接（ec_point_formats 这类单字节字段）。
fn join_grease_u8<I: Iterator<Item = u8>>(vals: I) -> String {
    vals.filter(|v| !GREASE.contains(&u16::from(*v)))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn parse_u16_slice(b: &[u8]) -> Result<Vec<u16>, Detect> {
    if b.len() % 2 != 0 {
        return Err(Detect::Malformed);
    }
    Ok(b.chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

/// 解析带长度头的 u16 列表扩展体：`body[0..n]` 是长度字段，其后才是列表本体。
///
/// 长度头若被当成列表元素，表现是"指纹里多出一个来路不明的小数字"——
/// 它不影响解析成功，只让每一个 JA3 都与参考实现对不上，属于最难察觉的一类错。
fn parse_u16_list(b: &[u8], header: usize) -> Result<Vec<u16>, Detect> {
    if b.len() < header {
        return Err(Detect::Malformed);
    }
    let declared = match header {
        1 => usize::from(b[0]),
        _ => u16::from_be_bytes([b[0], b[1]]) as usize,
    };
    if declared != b.len() - header {
        return Err(Detect::Malformed);
    }
    parse_u16_slice(&b[header..])
}

/// SNI 扩展体：先是 2 字节的**列表总长**，之后才是若干 (type, len, value) 条目。
///
/// 那个列表长度头很容易被漏掉 —— 漏了之后读到的"第一个条目类型"其实是长度字节，
/// 于是绝大多数真实流量都会被判成畸形，而少数恰好低字节为 0 的流量又"碰巧能用"，
/// 这种"部分可用"的 bug 比全不可用更难发现。
fn parse_sni(b: &[u8]) -> Result<Option<String>, Detect> {
    if b.len() < 2 {
        return Err(Detect::Malformed);
    }
    let list_len = u16::from_be_bytes([b[0], b[1]]) as usize;
    if list_len != b.len() - 2 {
        return Err(Detect::Malformed);
    }
    let mut p = 2usize;
    let mut out: Option<String> = None;
    while p < b.len() {
        if p + 3 > b.len() {
            return Err(Detect::Malformed);
        }
        let kind = b[p];
        let len = u16::from_be_bytes([b[p + 1], b[p + 2]]) as usize;
        if p + 3 + len > b.len() {
            return Err(Detect::Malformed);
        }
        if kind == 0x00 && out.is_none() {
            // SNI 归一化成小写：DNS 名字大小写等价（RFC 1035），
            // 但浏览器对 SNI 的大小写写法不统一 —— 不归一会让"同一批流量"在域名维度上
            // 被拆成 `Example.com` 与 `example.com` 两个桶，域名维度的统计直接失真。
            out = Some(ascii_str(&b[p + 3..p + 3 + len])?.to_ascii_lowercase());
        }
        p += 3 + len;
    }
    Ok(out)
}

/// ALPN 扩展体：2 字节总长 + 若干 (1 字节长度 + 协议串)。
fn parse_alpn(b: &[u8]) -> Result<Vec<String>, Detect> {
    if b.len() < 2 {
        return Err(Detect::Malformed);
    }
    let total = u16::from_be_bytes([b[0], b[1]]) as usize;
    if total as usize != b.len() - 2 {
        // 声明的总长必须与实际剩余字节严格相等，多一个字节都说明长度字段有问题
        return Err(Detect::Malformed);
    }
    let mut out = Vec::new();
    let mut p = 2usize;
    while p < b.len() {
        let len = b[p] as usize;
        p += 1;
        if p + len > b.len() {
            return Err(Detect::Malformed);
        }
        // ALPN 保留原始大小写：它是协议名（区分大小写），不是 DNS 名字
        out.push(ascii_str(&b[p..p + len])?);
        p += len;
    }
    Ok(out)
}

/// EC 点格式：1 字节计数 + 若干单字节格式值。空列表是合法的（只取第一个字节即可）。
fn parse_ec_formats(b: &[u8]) -> Result<Option<Vec<u8>>, Detect> {
    if b.is_empty() {
        return Ok(None);
    }
    let n = b[0] as usize;
    if b.len() - 1 != n {
        return Err(Detect::Malformed);
    }
    Ok(Some(b[1..].to_vec()))
}

/// ASCII 严格校验：出现非 ASCII 字节通常是在做指纹混淆，
/// 与其猜一个"看起来像域名"的字符串，不如让上层看到 `None` 并计入"无 SNI"。
fn ascii_str(b: &[u8]) -> Result<String, Detect> {
    match std::str::from_utf8(b) {
        Ok(s) if s.chars().all(|ch| ch.is_ascii()) => Ok(s.to_string()),
        _ => Err(Detect::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一份最小 ClientHello 骨架，仅测试时填充差异字段。
    fn skeleton() -> ClientHello {
        ClientHello {
            record_version: 0x0301,
            handshake_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![16, 10, 11, 13],
            supported_groups: vec![0x001D],
            ec_point_formats: vec![0, 1],
            supported_versions: Vec::new(),
            has_ech: false,
            server_name: None,
            alpn: vec![],
        }
    }

    #[test]
    fn tls13_version_comes_from_supported_versions() {
        // 握手版本写着 0x0303（TLS1.2），但 supported_versions 里是 0x0304（TLS1.3）：
        // 只信握手版本会把这条流量记成 TLS1.2 —— 这正是 TLS 1.3 占比被系统性低估的原因。
        let h = ClientHello {
            handshake_version: 0x0303,
            supported_versions: vec![0x0304],
            ..skeleton()
        };
        assert_eq!(h.client_version(), 0x0304);
        let classic = ClientHello {
            handshake_version: 0x0301,
            ..skeleton()
        };
        assert_eq!(classic.client_version(), 0x0301);
    }

    #[test]
    fn grease_is_filtered_from_ja3() {
        // 同一客户端插了不同 GREASE 值后，JA3 必须稳定 —— 否则 JA3 分位数统计
        // 会把一个浏览器拆成几十个指纹，这是 JA3 最典型的踩坑。
        let plain = skeleton();
        let greased = ClientHello {
            cipher_suites: vec![0x0A0A, 0x1301, 0x1302, 0x1A1A],
            extensions: vec![0x2A2A, 16, 10, 0x3A3A, 11, 13],
            supported_groups: vec![0x2A2A, 0x001D],
            ..skeleton()
        };
        // JA3 用**十进制**编号，不是十六进制字面量：0x1301 写作 4865
        assert_eq!(ja3_raw(&greased), "771,4865-4866,16-10-11-13,29,0-1");
        assert_eq!(ja3(&greased), ja3(&plain));
    }

    #[test]
    fn empty_fields_stay_empty_in_ja3() {
        // JA3 的五个字段空值要留空（`..` 而非 `-`），填占位符会让"无扩展"的客户端
        // 指纹集体偏离参考实现 —— 这条断言就是那条边界的守门人。
        let h = ClientHello {
            handshake_version: 0x0303,
            ..Default::default()
        };
        assert_eq!(ja3_raw(&h), "771,,,,");
        assert_eq!(ja3(&h), "bddda940f9963577c41d7c28b1a5f65f");
    }

    #[test]
    fn cursor_separates_incomplete_from_inconsistent() {
        // 同一段"读不下"的输入，缓冲区短 → NeedMore；越过声明边界 → Malformed。
        let buf = [0u8; 4096];
        let mut c = Cursor::new(&buf[..16], 4096, 0);
        // 结构边界在 4096（握手体"应该有"那么长），但只捕获了 16 字节 → 分片
        assert_eq!(c.take(32), Err(ReadErr::Incomplete));
        let mut c = Cursor::new(&buf[..4096], 32, 0);
        assert_eq!(c.take(64), Err(ReadErr::Inconsistent));
    }

    #[test]
    fn ech_sets_flag_without_leaking_sni() {
        // ECH 只置位，不清空 JA3、不报错：真实 SNI 不可见是预期
        let raw = b"771,4865-4866-4867-49195-49199-156-157,16-10-11-13-65037,29-23-24,0-1";
        assert_eq!(
            ja3_raw(&ClientHello {
                handshake_version: 771,
                cipher_suites: vec![4865, 4866, 4867, 49195, 49199, 156, 157],
                extensions: vec![16, 10, 11, 13, EXT_ECH],
                supported_groups: vec![29, 23, 24],
                ec_point_formats: vec![0, 1],
                ..Default::default()
            }),
            String::from_utf8_lossy(raw)
        );
    }
}
