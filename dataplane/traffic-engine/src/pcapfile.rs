// pcapfile.rs —— 经典 pcap 文件读取（离线分析入口用，CYS-TRF-035）。
//
// 为什么自己写而不引 pcap 库：仓库红线是**零第三方 Rust 依赖、离线可构建**。
// 经典 pcap 的文件格式小到可以完整实现（24 字节全局头 + 每包 16 字节记录头），
// 而且这里只需要"读"，不需要抓包、不需要过滤器、不需要 BPF。
//
// 解析里真正容易出错的只有三件事，全部显式处理：
//   1. **字节序**：magic 反过来写的文件很常见（抓包机是大端、分析机是小端）。
//      判断依据是"magic 的四个字节按什么顺序落盘"，不是"我用什么读"。
//   2. **时间精度**：微秒版与纳秒版 magic 只差一个字节（0xa1b2c3d4 / 0xa1b23c4d）。
//      当成同一种格式读，纳秒文件的时间戳会差 1000 倍 —— 而它看起来只是个"很大的时间"。
//   3. **截断的记录**：文件在中间被截断是常态（抓包进程被杀）。必须报错并指出
//      第几个包，而不是把半个包头当成下一个包继续解 —— 那样会产出一串
//      看起来合法、实际完全错位的记录。

use std::io::{self, Read};

/// 单包上限（含 256 KiB 的以太帧已是上限的数十倍）。用它挡住"incl_len 字段被
/// 损坏成一个极大值"的情况：不设上限时，一个坏文件会让分析进程先吃光内存再失败。
pub const MAX_PACKET_BYTES: u32 = 256 * 1024;

/// 全局头长度。
pub const GLOBAL_HEADER_LEN: usize = 24;
/// 每包记录头长度。
pub const RECORD_HEADER_LEN: usize = 16;

/// 链路层类型（全局头 network 字段）。
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW_IP: u32 = 101;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_LINUX_SLL2: u32 = 276;
/// pcapng 的 magic（块类型 SHB）。明确区分出来只为给出可操作的报错。
pub const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

/// 全局头（已按文件字节序解析）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapHeader {
    pub version_major: u16,
    pub version_minor: u16,
    /// GMT 偏移（秒）。现实中恒为 0，保留只为原样报出来。
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    /// 链路层类型。
    pub network: u32,
    /// 时间戳是否为纳秒精度。
    pub nanosecond: bool,
    /// 文件字节序与本机（大端解释）相反。
    pub byte_swapped: bool,
}

impl PcapHeader {
    pub fn linktype_name(&self) -> &'static str {
        match self.network {
            LINKTYPE_ETHERNET => "ethernet",
            LINKTYPE_RAW_IP => "raw-ip",
            LINKTYPE_LINUX_SLL => "linux-sll",
            LINKTYPE_LINUX_SLL2 => "linux-sll2",
            _ => "unknown",
        }
    }
}

/// 一个抓包记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapRecord {
    /// 到达时间（微秒）。纳秒文件已折算成微秒（截断，不四舍五入）。
    pub timestamp_us: u64,
    /// 原始线上长度（可能大于 `data.len()`：snaplen 截断）。
    pub orig_len: u32,
    /// 实际捕获到的字节。
    pub data: Vec<u8>,
}

impl PcapRecord {
    /// 这条记录是否被 snaplen 截断。
    ///
    /// 截断与否决定载荷能不能用来做识别：被截断的载荷应当导向 `need_more`，
    /// 而不是"不认识的协议"。因此这个判断要能一路传到 DPI 调用点。
    pub fn is_truncated(&self) -> bool {
        (self.data.len() as u32) < self.orig_len
    }
}

/// 经典 pcap 读取器。
#[derive(Debug)]
pub struct PcapReader<R: Read> {
    inner: R,
    header: PcapHeader,
    /// 已读出的记录数（报错时用来说明位置）。
    read_records: u64,
}

impl<R: Read> PcapReader<R> {
    /// 读取并校验全局头。
    pub fn new(mut inner: R) -> io::Result<Self> {
        let mut buf = [0u8; GLOBAL_HEADER_LEN];
        inner.read_exact(&mut buf).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("读 pcap 全局头失败（文件可能为空或不是 pcap）：{e}"),
            )
        })?;
        if buf[..4] == PCAPNG_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "这是 pcapng 格式，本工具只读经典 pcap；请先转换：\
                 `tshark -F pcap -r in.pcapng -w out.pcap` 或 `editcap -F pcap`",
            ));
        }
        let (byte_swapped, nanosecond) = match [buf[0], buf[1], buf[2], buf[3]] {
            [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
            [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
            [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
            [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "不是经典 pcap（magic = {:02x?}）；期望 a1b2c3d4 / d4c3b2a1 / \
                         a1b23c4d / 4d3cb2a1 之一",
                        other
                    ),
                ));
            }
        };
        let rd = |b: &[u8]| -> u16 {
            let a = [b[0], b[1]];
            if byte_swapped {
                u16::from_le_bytes(a)
            } else {
                u16::from_be_bytes(a)
            }
        };
        let rd32 = |b: &[u8]| -> u32 {
            let a = [b[0], b[1], b[2], b[3]];
            if byte_swapped {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        };
        let header = PcapHeader {
            version_major: rd(&buf[4..6]),
            version_minor: rd(&buf[6..8]),
            thiszone: rd32(&buf[8..12]) as i32,
            sigfigs: rd32(&buf[12..16]),
            snaplen: rd32(&buf[16..20]),
            network: rd32(&buf[20..24]),
            nanosecond,
            byte_swapped,
        };
        Ok(Self {
            inner,
            header,
            read_records: 0,
        })
    }

    pub fn header(&self) -> &PcapHeader {
        &self.header
    }

    pub fn linktype(&self) -> u32 {
        self.header.network
    }

    /// 已读出的记录数。
    pub fn read_records(&self) -> u64 {
        self.read_records
    }

    /// 读下一个记录；正常读到文件末尾返回 `Ok(None)`。
    pub fn next_record(&mut self) -> io::Result<Option<PcapRecord>> {
        let idx = self.read_records;
        let mut hdr = [0u8; RECORD_HEADER_LEN];
        let got = read_up_to(&mut self.inner, &mut hdr)?;
        if got == 0 {
            return Ok(None);
        }
        if got < RECORD_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "第 {} 个包的记录头只有 {} 字节（需要 {}）：文件在中间被截断了",
                    idx + 1,
                    got,
                    RECORD_HEADER_LEN
                ),
            ));
        }
        let (ts_sec, ts_frac, incl_len, orig_len) = if self.header.byte_swapped {
            (
                u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]),
                u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]),
                u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
                u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
            )
        } else {
            (
                u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]),
                u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]),
                u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
                u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
            )
        };

        if incl_len > MAX_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "第 {} 个包声明长度 {} 字节，超过上限 {}：记录头很可能已损坏",
                    idx + 1,
                    incl_len,
                    MAX_PACKET_BYTES
                ),
            ));
        }
        if incl_len > orig_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "第 {} 个包捕获长度 {} 大于线上长度 {}：记录头自相矛盾",
                    idx + 1,
                    incl_len,
                    orig_len
                ),
            ));
        }
        // 亚秒字段越界说明时间精度判断错了（或文件损坏）。宁可报错，
        // 也不要把它当成"多出来的秒"悄悄加到时间戳上。
        let sub_limit = if self.header.nanosecond {
            1_000_000_000
        } else {
            1_000_000
        };
        if ts_frac >= sub_limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "第 {} 个包的亚秒字段 {} 超过 {} 上限（{} 精度）：时间戳不可信",
                    idx + 1,
                    ts_frac,
                    sub_limit,
                    if self.header.nanosecond {
                        "纳秒"
                    } else {
                        "微秒"
                    }
                ),
            ));
        }

        let mut data = vec![0u8; incl_len as usize];
        let filled = read_up_to(&mut self.inner, &mut data)?;
        if filled < data.len() {
            // 载荷不足时**不许补零**：补零会产出一条字节数正确、内容全假的记录，
            // 而它在统计上完全看不出来（长度对、包数对，只有载荷是错的）。
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "第 {} 个包的载荷只有 {} 字节（记录头声明 {}）：文件在这里被截断了",
                    idx + 1,
                    filled,
                    incl_len
                ),
            ));
        }
        let sub_us = if self.header.nanosecond {
            ts_frac / 1000
        } else {
            ts_frac
        };
        self.read_records += 1;
        Ok(Some(PcapRecord {
            timestamp_us: u64::from(ts_sec) * 1_000_000 + u64::from(sub_us),
            orig_len,
            data,
        }))
    }
}

/// 读满缓冲区，返回实际读到的字节数（只在真 EOF 时小于请求长度）。
fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// 构造一个小 pcap（纳秒 / 字节序 / 记录条数可调）。
    fn build_pcap(swapped: bool, nanosecond: bool, records: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        // magic 也必须按文件自身的字节序落盘：小端文件写出来是 d4 c3 b2 a1。
        // 写反了的话，解析器会给出一份"能读但数值全错"的结果（字节序判断恰好相反）。
        let base: [u8; 4] = if nanosecond {
            [0xa1, 0xb2, 0x3c, 0x4d]
        } else {
            [0xa1, 0xb2, 0xc3, 0xd4]
        };
        let magic = if swapped {
            [base[3], base[2], base[1], base[0]]
        } else {
            base
        };
        let w16 = |v: u16| {
            if swapped {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        };
        let w32 = |v: u32| {
            if swapped {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        };
        out.extend_from_slice(&magic);
        out.extend_from_slice(&w16(2));
        out.extend_from_slice(&w16(4));
        out.extend_from_slice(&w32(0));
        out.extend_from_slice(&w32(0));
        out.extend_from_slice(&w32(65535));
        out.extend_from_slice(&w32(LINKTYPE_ETHERNET));
        for (sec, frac, data) in records {
            out.extend_from_slice(&w32(*sec));
            out.extend_from_slice(&w32(*frac));
            out.extend_from_slice(&w32(data.len() as u32));
            out.extend_from_slice(&w32(data.len() as u32));
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn little_endian_microsecond_file_reads_back_byte_for_byte() {
        let bytes = build_pcap(
            true,
            false,
            &[
                (1_700_000_000, 123_456, vec![1, 2, 3, 4]),
                (1_700_000_001, 0, vec![9; 10]),
            ],
        );
        let mut r = PcapReader::new(Cursor::new(&bytes)).expect("全局头应可解析");
        assert!(r.header().byte_swapped);
        assert!(!r.header().nanosecond);
        assert_eq!(r.header().network, LINKTYPE_ETHERNET);
        assert_eq!(r.header().linktype_name(), "ethernet");

        let a = r.next_record().unwrap().expect("第一条");
        assert_eq!(a.timestamp_us, 1_700_000_000 * 1_000_000 + 123_456);
        assert_eq!(a.data, vec![1, 2, 3, 4]);
        assert!(!a.is_truncated());
        let b = r.next_record().unwrap().expect("第二条");
        assert_eq!(b.timestamp_us, 1_700_000_001 * 1_000_000);
        assert_eq!(b.data.len(), 10);
        assert!(r.next_record().unwrap().is_none(), "读到末尾应返回 None");
        assert_eq!(r.read_records(), 2);
    }

    #[test]
    fn big_endian_nanosecond_file_is_scaled_to_microseconds() {
        // 同一个「秒 + 亚秒」在两种精度下必须给出同一个微秒时间戳：
        // 若把纳秒文件当成微秒读，时间会差 1000 倍，而且看起来只是"一个更大的数"。
        let ns = build_pcap(false, true, &[(10, 250_000_000, vec![7])]);
        let mut rns = PcapReader::new(Cursor::new(&ns)).expect("纳秒 pcap 应可解析");
        assert!(rns.header().nanosecond);
        assert!(!rns.header().byte_swapped);
        assert_eq!(rns.next_record().unwrap().unwrap().timestamp_us, 10_250_000);

        let us = build_pcap(false, false, &[(10, 250_000, vec![7])]);
        let mut rus = PcapReader::new(Cursor::new(&us)).expect("微秒 pcap 应可解析");
        assert_eq!(rus.next_record().unwrap().unwrap().timestamp_us, 10_250_000);
    }

    #[test]
    fn snaplen_truncation_is_visible() {
        let mut bytes = build_pcap(true, false, &[(1, 0, vec![0u8; 4])]);
        // 把 orig_len 改成 1500（捕获只有 4 字节）
        let n = bytes.len();
        bytes[n - 8..n - 4].copy_from_slice(&1500u32.to_le_bytes());
        let mut r = PcapReader::new(Cursor::new(&bytes)).unwrap();
        let rec = r.next_record().unwrap().unwrap();
        assert_eq!(rec.orig_len, 1500);
        assert_eq!(rec.data.len(), 4);
        assert!(rec.is_truncated(), "被 snaplen 截断必须可判别");
    }

    #[test]
    fn pcapng_is_rejected_with_an_actionable_message() {
        // 必须够 24 字节，否则会先因为"全局头读不全"而失败，测不到格式判断。
        let mut bytes = [0u8; GLOBAL_HEADER_LEN];
        bytes[..4].copy_from_slice(&PCAPNG_MAGIC);
        let err = PcapReader::new(Cursor::new(&bytes)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pcapng"), "报错必须点名格式：{msg}");
        assert!(
            msg.contains("tshark"),
            "报错必须给出可执行的转换办法：{msg}"
        );
    }

    #[test]
    fn foreign_magic_is_rejected() {
        let mut bytes = [0u8; GLOBAL_HEADER_LEN];
        bytes[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let err = PcapReader::new(Cursor::new(&bytes)).unwrap_err();
        assert!(err.to_string().contains("不是经典 pcap"));
    }

    #[test]
    fn empty_input_is_reported_as_such() {
        let err = PcapReader::new(Cursor::new(Vec::<u8>::new())).unwrap_err();
        assert!(err.to_string().contains("全局头"));
    }

    #[test]
    fn truncated_payload_is_reported_and_never_zero_padded() {
        let mut bytes = build_pcap(true, false, &[(1, 0, vec![1, 2, 3, 4])]);
        bytes.truncate(bytes.len() - 2); // 砍掉载荷尾部两字节
        let mut r = PcapReader::new(Cursor::new(&bytes)).unwrap();
        let err = r.next_record().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("第 1 个包"), "{msg}");
        assert!(msg.contains("载荷只有 2 字节"), "{msg}");
    }

    #[test]
    fn half_written_header_is_reported_instead_of_read_as_a_packet() {
        let mut bytes = build_pcap(true, false, &[(1, 0, vec![1, 2, 3, 4])]);
        bytes.truncate(GLOBAL_HEADER_LEN + 8); // 只留下半个记录头
        let mut r = PcapReader::new(Cursor::new(&bytes)).unwrap();
        let err = r.next_record().unwrap_err();
        assert!(err.to_string().contains("第 1 个包"), "{err}");
        assert!(err.to_string().contains("截断"), "{err}");
    }

    /// 记录头里 incl_len 字段的绝对位置（小端样本文件）。
    const INCL_LEN_AT: usize = GLOBAL_HEADER_LEN + 8;
    /// 记录头里 orig_len 字段的绝对位置。
    const ORIG_LEN_AT: usize = GLOBAL_HEADER_LEN + 12;

    #[test]
    fn absurd_capture_length_is_rejected() {
        let mut bytes = build_pcap(true, false, &[(1, 0, vec![1, 2, 3, 4])]);
        bytes[INCL_LEN_AT..INCL_LEN_AT + 4].copy_from_slice(&(MAX_PACKET_BYTES + 1).to_le_bytes());
        let mut r = PcapReader::new(Cursor::new(&bytes)).unwrap();
        let err = r.next_record().unwrap_err();
        assert!(err.to_string().contains("超过上限"), "{err}");
    }

    #[test]
    fn capture_length_larger_than_wire_length_is_rejected() {
        let mut bytes = build_pcap(true, false, &[(1, 0, vec![1, 2, 3, 4])]);
        // incl_len = 4（不变），orig_len = 2：捕获长度大于线上长度，记录头自相矛盾。
        bytes[ORIG_LEN_AT..ORIG_LEN_AT + 4].copy_from_slice(&2u32.to_le_bytes());
        let mut r = PcapReader::new(Cursor::new(&bytes)).unwrap();
        let err = r.next_record().unwrap_err();
        assert!(err.to_string().contains("自相矛盾"), "{err}");
    }

    #[test]
    fn out_of_range_subsecond_field_is_rejected() {
        let bytes = build_pcap(true, false, &[(1, 1_500_000, vec![1])]);
        let mut r = PcapReader::new(Cursor::new(&bytes)).unwrap();
        let err = r.next_record().unwrap_err();
        assert!(err.to_string().contains("亚秒字段"), "{err}");
    }

    #[test]
    fn the_packaged_sample_file_parses() {
        // 用 include_bytes! 把仓库里的样本编进测试二进制：路径写错会**编译失败**，
        // 而不是运行时静默跳过（这是本项目定下的规矩）。
        const SAMPLE: &[u8] = include_bytes!("../../../datasets/pcap/sample-ipv4-mixed.pcap");
        let mut r = PcapReader::new(Cursor::new(SAMPLE)).expect("样本 pcap 应可解析");
        assert_eq!(r.header().network, LINKTYPE_ETHERNET);
        let mut n = 0;
        while let Some(rec) = r.next_record().expect("样本记录应可解析") {
            assert!(rec.data.len() >= 14, "以太帧至少要有 14 字节头");
            n += 1;
        }
        assert_eq!(n, 4, "样本里应有 4 个包（改动样本必须同步这里）");
    }
}
