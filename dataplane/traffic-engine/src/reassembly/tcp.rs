// reassembly/tcp.rs —— TCP 头与选项解析（CYS-TRF-017）。
//
// 为什么选项解析必须做，而不是只看 seq/payload：
//   * **SACK** 直接决定重组的可见性：对端在 SACK 里说"我收到了 1000-2000"，
//     这是**接收端视角**的确认。旁路设备看不到对端实际收没收到，但可以据此判断
//     "发送端认为这段已送达"。省网上重放/注入攻击的判别，依赖把 SACK 的行为
//     与本地观察到的段序列做交叉验证。
//   * **窗口缩放** 决定真实窗口大小（`window << wscale`）。不做这步，看到的所有
//     窗口都是"最多 65535"，吞吐量分析会系统性低估高带宽长连接。
//   * **时间戳** 是估算 RTT 与识别重传段（同一 TSval 出现两次即重传）的低成本手段，
//     比比较载荷内容便宜得多。
//
// 关于选项解析的容错：TCP 选项区是**长度自描述**的（TLV），一个坏的长度字节
// 会让后续全部错位。因此这里一旦遇到越界长度就置 `malformed` 并停止解析，
// 而不是试图"跳过继续" —— 继续解析出来的东西没有可信度，反而会污染统计。
//
// 刻意不做：校验和验证。旁路抓到的报文大量是校验和卸载（TSO/LRO/GRO）后的
// 半成品，校验和字段本身不可信，验证了也是假阳性。

use super::seq::{seq_add, SeqRange};

/// TCP 头最小长度（字节）。
pub const TCP_MIN_HEADER_LEN: usize = 20;

/// 单个 SACK 块数量的解析上限。
///
/// 这不是拍脑袋的"合理值"，而是**协议本身的硬上限**：data offset 只有 4 位，
/// 头部至多 60 字节，扣掉 20 字节固定头后选项区至多 40 字节；SACK 选项占
/// `8n + 2` 字节，解 `8n + 2 ≤ 40` 得 `n ≤ 4`（若同时带时间戳则只有 3）。
/// 常量写 4 是为了让这个推导结果显式出现在代码里，循环里的判等则是
/// 防止将来有人放宽选项区长度时静默失去约束。
pub const MAX_SACK_BLOCKS: usize = 4;

/// RFC 7323：窗口缩放的合法移位值是 0..=14，超过 14 的必须按 14 处理。
pub const MAX_WINDOW_SHIFT: u8 = 14;

/// TCP 控制位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    /// ECN 隐藏位（原 TCP 头保留位，RFC 3540）。
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TcpFlags {
    /// 由第 12 与第 13 字节还原标志位。
    ///
    /// 第 12 字节高 4 位是 data offset，**低 4 位中最低位**是 NS；
    /// 第 13 字节低 6 位依次是 CWR/ECE/URG/ACK/PSH/RST/SYN/FIN 中的后 8 个。
    pub fn from_bytes(b12: u8, b13: u8) -> Self {
        Self {
            ns: b12 & 0x01 != 0,
            cwr: b13 & 0x80 != 0,
            ece: b13 & 0x40 != 0,
            urg: b13 & 0x20 != 0,
            ack: b13 & 0x10 != 0,
            psh: b13 & 0x08 != 0,
            rst: b13 & 0x04 != 0,
            syn: b13 & 0x02 != 0,
            fin: b13 & 0x01 != 0,
        }
    }

    /// 低 8 位（不含 NS）的位图，便于与外部工具（tshark `tcp.flags`）对照。
    pub fn bits(&self) -> u8 {
        let mut b = 0u8;
        if self.cwr {
            b |= 0x80;
        }
        if self.ece {
            b |= 0x40;
        }
        if self.urg {
            b |= 0x20;
        }
        if self.ack {
            b |= 0x10;
        }
        if self.psh {
            b |= 0x08;
        }
        if self.rst {
            b |= 0x04;
        }
        if self.syn {
            b |= 0x02;
        }
        if self.fin {
            b |= 0x01;
        }
        b
    }

    pub fn is_syn(&self) -> bool {
        self.syn && !self.ack
    }

    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack
    }

    /// SYN / FIN 各占用一个序号，因此它们也影响"这段消耗了多少序号"。
    pub fn consumes_seq(&self) -> u32 {
        u32::from(self.syn) + u32::from(self.fin)
    }
}

/// 解析出的 TCP 选项。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpOptions {
    /// 最大报文段长度（kind 2）。
    pub mss: Option<u16>,
    /// 窗口缩放移位值（kind 3）。**未做钳位**，保留报文里的原值以便诊断；
    /// 计算真实窗口请用 [`TcpOptions::window_shift`]。
    pub window_scale: Option<u8>,
    /// 允许 SACK（kind 4）。
    pub sack_permitted: bool,
    /// SACK 块（kind 5），每块是半开区间 `[left, right)`。
    pub sacks: Vec<SeqRange>,
    /// 时间戳 `(TSval, TSecr)`（kind 8）。
    pub timestamp: Option<(u32, u32)>,
    /// 本端不认识的 option kind（仅记录，不影响重组）。
    pub unknown_kinds: Vec<u8>,
    /// 选项区自身是否有矛盾（长度越界 / 声明长度不足）。
    pub malformed: bool,
}

impl TcpOptions {
    /// 真实窗口移位值：RFC 7323 要求 > 14 的值按 14 处理。
    ///
    /// 不钳位会算出 65535 << 255 这种荒谬窗口，进而让"发送端还能发多少"的判断
    /// 完全失真 —— 而这类报文在省网上是真实存在的（实现 bug 或刻意探测）。
    pub fn window_shift(&self) -> u8 {
        self.window_scale.map_or(0, |s| s.min(MAX_WINDOW_SHIFT))
    }
}

/// TCP 解析失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpParseError {
    /// 报文短于 20 字节，连固定头都不完整。
    TooShort,
    /// data offset 小于 5（违反 RFC 9293：头至少 20 字节）。
    BadDataOffset,
    /// data offset 声明的头部长度超过了收到的字节数（snaplen 截断或故意构造）。
    HeaderExceedsBuffer,
}

/// 一个已解析的 TCP 段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    /// 头部长度（字节），即 data offset × 4。
    pub header_len: usize,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: TcpOptions,
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    /// 本段消耗的序号数（载荷长度 + SYN/FIN 各占一个）。
    ///
    /// 这是重组里唯一正确的"下一段起点"算法。写成 `payload.len()` 会让
    /// 带 FIN 的段少算 1，表现为流结尾永远差一个字节 —— 而 TCP 上大量连接
    /// 的最后一段正是带 FIN 的，错误会被放大成"每条流都差一点"。
    pub fn seq_consumed(&self) -> u32 {
        self.payload.len() as u32 + self.flags.consumes_seq()
    }

    /// 本段之后的下一个序号。
    pub fn next_seq(&self) -> u32 {
        seq_add(self.seq, self.seq_consumed())
    }

    /// 载荷区间（半开）。无载荷时为空区间。
    pub fn payload_range(&self) -> SeqRange {
        SeqRange::new(self.seq, self.payload.len() as u32)
    }

    /// 真实接收窗口（已应用窗口缩放）。
    pub fn scaled_window(&self) -> u32 {
        u32::from(self.window) << self.options.window_shift()
    }
}

/// 解析一个 TCP 段。
pub fn parse(buf: &[u8]) -> Result<TcpSegment<'_>, TcpParseError> {
    if buf.len() < TCP_MIN_HEADER_LEN {
        return Err(TcpParseError::TooShort);
    }
    let data_offset = usize::from(buf[12] >> 4);
    if data_offset < 5 {
        return Err(TcpParseError::BadDataOffset);
    }
    let header_len = data_offset * 4;
    if header_len > buf.len() {
        return Err(TcpParseError::HeaderExceedsBuffer);
    }

    let seg = TcpSegment {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        header_len,
        flags: TcpFlags::from_bytes(buf[12], buf[13]),
        window: u16::from_be_bytes([buf[14], buf[15]]),
        checksum: u16::from_be_bytes([buf[16], buf[17]]),
        urgent_ptr: u16::from_be_bytes([buf[18], buf[19]]),
        options: parse_options(&buf[TCP_MIN_HEADER_LEN..header_len]),
        payload: &buf[header_len..],
    };
    Ok(seg)
}

/// 解析选项区（TLV 序列）。
fn parse_options(opts: &[u8]) -> TcpOptions {
    let mut out = TcpOptions::default();
    let mut i = 0usize;

    while i < opts.len() {
        let kind = opts[i];
        match kind {
            0 => break, // EOL：后面全是填充
            1 => {
                i += 1; // NOP：单字节，用于对齐
                continue;
            }
            _ => {}
        }

        // 其余选项都是 kind + len + body。len 字节缺失本身就算畸形：
        // 一个 TLV 序列只要有一处长度不可信，后续全部不可信。
        if i + 1 >= opts.len() {
            out.malformed = true;
            break;
        }
        let len = usize::from(opts[i + 1]);
        if len < 2 || i + len > opts.len() {
            out.malformed = true;
            break;
        }
        let body = &opts[i + 2..i + len];

        match kind {
            2 if body.len() >= 2 => {
                out.mss = Some(u16::from_be_bytes([body[0], body[1]]));
            }
            3 if body.len() >= 1 => {
                out.window_scale = Some(body[0]);
            }
            4 if body.is_empty() => {
                out.sack_permitted = true;
            }
            5 => {
                // SACK 块：每块 8 字节（左边界 4 + 右边界 4）。
                if body.len() % 8 == 0 {
                    for chunk in body.chunks_exact(8) {
                        if out.sacks.len() >= MAX_SACK_BLOCKS {
                            break;
                        }
                        let left = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        let right = u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                        out.sacks.push(SeqRange {
                            start: left,
                            end: right,
                        });
                    }
                } else {
                    out.malformed = true;
                }
            }
            8 if body.len() >= 8 => {
                let tsval = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let tsecr = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                out.timestamp = Some((tsval, tsecr));
            }
            _ => {
                if !out.unknown_kinds.contains(&kind) {
                    out.unknown_kinds.push(kind);
                }
            }
        }

        i += len;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    fn be16(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    /// 构造一个 TCP 段：flags 用低 8 位位图，options 直接拼在头后面。
    fn build(seq: u32, flags: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&be16(12345));
        v.extend_from_slice(&be16(443));
        v.extend_from_slice(&be32(seq));
        v.extend_from_slice(&be32(0));
        let hl = (20 + options.len()) / 4;
        v.push((hl as u8) << 4);
        v.push(flags);
        v.extend_from_slice(&be16(65535));
        v.extend_from_slice(&be16(0));
        v.extend_from_slice(&be16(0));
        v.extend_from_slice(options);
        // 选项区按 4 字节对齐补齐（真实报文如此）。
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v[12] = ((v.len() / 4) as u8) << 4;
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn parses_fixed_header() {
        let buf = build(0x1122_3344, 0x18, &[], b"hello");
        let seg = parse(&buf).unwrap();
        assert_eq!(seg.src_port, 12345);
        assert_eq!(seg.dst_port, 443);
        assert_eq!(seg.seq, 0x1122_3344);
        assert_eq!(seg.header_len, 20);
        assert!(seg.flags.psh && seg.flags.ack);
        assert_eq!(seg.payload, b"hello");
        assert_eq!(seg.seq_consumed(), 5);
        assert_eq!(seg.next_seq(), 0x1122_3349);
    }

    #[test]
    fn syn_and_fin_each_consume_one_seq() {
        let buf1 = build(100, 0x02, &[], b"");
        let syn = parse(&buf1).unwrap();
        assert_eq!(syn.seq_consumed(), 1, "SYN 占一个序号");
        assert_eq!(syn.next_seq(), 101);

        let buf2 = build(100, 0x11, &[], b"bye");
        let fin = parse(&buf2).unwrap();
        assert_eq!(fin.seq_consumed(), 4, "FIN 段：3 字节载荷 + FIN 一个序号");
        assert_eq!(fin.next_seq(), 104);
    }

    #[test]
    fn too_short_is_rejected() {
        assert_eq!(parse(&[0u8; 19]), Err(TcpParseError::TooShort));
    }

    #[test]
    fn data_offset_below_five_is_rejected() {
        let mut buf = build(0, 0x10, &[], b"");
        buf[12] = 0x40; // data offset = 4
        assert_eq!(parse(&buf), Err(TcpParseError::BadDataOffset));
    }

    #[test]
    fn header_exceeding_buffer_is_rejected() {
        let mut buf = build(0, 0x10, &[], b"");
        buf[12] = 0xF0; // data offset = 15 → 60 字节头，实际只有 20
        assert_eq!(parse(&buf), Err(TcpParseError::HeaderExceedsBuffer));
    }

    // ---- 选项 ----

    #[test]
    fn parses_mss_and_window_scale() {
        let opts = [2u8, 4, 0x05, 0xB4, 3, 3, 7, 1]; // MSS=1460, WS=7, NOP
        let buf3 = build(0, 0x02, &opts, b"");
        let seg = parse(&buf3).unwrap();
        assert_eq!(seg.options.mss, Some(1460));
        assert_eq!(seg.options.window_scale, Some(7));
        assert_eq!(seg.options.window_shift(), 7);
    }

    #[test]
    fn window_shift_is_clamped_to_14() {
        // 移位值 255 属于违规报文，按 RFC 7323 应视作 14 而不是照算。
        let opts = [3u8, 3, 255, 1];
        let buf4 = build(0, 0x02, &opts, b"");
        let seg = parse(&buf4).unwrap();
        assert_eq!(seg.options.window_scale, Some(255), "原值保留以便诊断");
        assert_eq!(seg.options.window_shift(), 14, "但计算窗口时必须钳位");
        assert_eq!(seg.scaled_window(), 65535 << 14);
    }

    #[test]
    fn parses_sack_blocks() {
        let mut opts = vec![4u8, 2, 1, 1]; // SACK-permitted + 两个 NOP 对齐
        opts.extend_from_slice(&[5, 2 + 8 * 2]); // SACK 长度 = 8n + 2（含 kind 与 len）
        opts.extend_from_slice(&be32(1000));
        opts.extend_from_slice(&be32(2000));
        opts.extend_from_slice(&be32(3000));
        opts.extend_from_slice(&be32(4000));
        let buf5 = build(0, 0x10, &opts, b"");
        let seg = parse(&buf5).unwrap();
        assert!(seg.options.sack_permitted);
        assert_eq!(
            seg.options.sacks,
            vec![
                SeqRange {
                    start: 1000,
                    end: 2000
                },
                SeqRange {
                    start: 3000,
                    end: 4000
                }
            ]
        );
    }

    #[test]
    fn parses_timestamp() {
        let mut opts = vec![8u8, 10];
        opts.extend_from_slice(&be32(0xAABB_CCDD));
        opts.extend_from_slice(&be32(0x1122_3344));
        let buf6 = build(0, 0x10, &opts, b"");
        let seg = parse(&buf6).unwrap();
        assert_eq!(seg.options.timestamp, Some((0xAABB_CCDD, 0x1122_3344)));
    }

    #[test]
    fn unknown_kinds_are_recorded() {
        let opts = [28u8, 4, 0, 0]; // kind 28 = TFO cookie 之外的一个未实现选项
        let buf7 = build(0, 0x02, &opts, b"");
        let seg = parse(&buf7).unwrap();
        assert_eq!(seg.options.unknown_kinds, vec![28]);
        assert!(!seg.options.malformed, "不认识的选项不是畸形");
    }

    #[test]
    fn out_of_range_option_length_is_malformed() {
        // 声明长度 200，但选项区只有 4 字节。
        let opts = [2u8, 200, 0, 0];
        let buf8 = build(0, 0x02, &opts, b"");
        let seg = parse(&buf8).unwrap();
        assert!(seg.options.malformed);
    }

    #[test]
    fn sack_with_odd_body_length_is_malformed() {
        let opts = [5u8, 6, 0, 0, 0, 0]; // 长度 6 → body 4 字节，不是 8 的倍数
        let buf9 = build(0, 0x10, &opts, b"");
        let seg = parse(&buf9).unwrap();
        assert!(seg.options.malformed);
    }

    #[test]
    fn eol_stops_parsing() {
        // EOL 之后放一个合法 MSS，不应被解析出来。
        let opts = [0u8, 2, 4, 0x05, 0xB4];
        let buf10 = build(0, 0x02, &opts, b"");
        let seg = parse(&buf10).unwrap();
        assert_eq!(seg.options.mss, None);
    }

    #[test]
    fn four_sack_blocks_is_the_protocol_maximum() {
        // 选项区至多 40 字节，SACK 占 8n+2 → n ≤ 4。这 4 块必须全部解析出来。
        let mut opts = vec![5u8, 2 + 8 * 4];
        for i in 0..4u32 {
            opts.extend_from_slice(&be32(i * 100));
            opts.extend_from_slice(&be32(i * 100 + 50));
        }
        let buf11 = build(0, 0x10, &opts, b"");
        let seg = parse(&buf11).unwrap();
        assert_eq!(seg.options.sacks.len(), MAX_SACK_BLOCKS);
        assert!(!seg.options.malformed);
        assert_eq!(
            seg.options.sacks[3],
            SeqRange {
                start: 300,
                end: 350
            }
        );
    }

    #[test]
    fn sack_option_longer_than_the_option_area_is_malformed() {
        // 声明 5 块（长度 42），但整个选项区只有 40 字节 —— 必然越界。
        // 这类报文在真实链路里是攻击者的探针：解析若不判越界就会读到头之外。
        let mut opts = vec![5u8, 2 + 8 * 5];
        for i in 0..5u32 {
            opts.extend_from_slice(&be32(i * 100));
            opts.extend_from_slice(&be32(i * 100 + 50));
        }
        opts.truncate(40);
        assert_eq!(opts.len(), 40, "选项区被截到协议上限");
        let buf12 = build(0, 0x10, &opts, b"");
        let seg = parse(&buf12).unwrap();
        assert!(seg.options.malformed);
        assert!(seg.options.sacks.is_empty(), "畸形选项不得产出部分结果");
    }

    #[test]
    fn flags_round_trip_through_bits() {
        let f = TcpFlags::from_bytes(0x00, 0x12); // SYN+ACK
        assert!(f.is_syn_ack());
        assert!(!f.is_syn());
        assert_eq!(f.bits(), 0x12);

        let ns = TcpFlags::from_bytes(0x01, 0x10);
        assert!(ns.ns && ns.ack);
    }
}
