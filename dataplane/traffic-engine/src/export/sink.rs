// export/sink.rs —— 导出通道（M11 / CYS-TRF-052）。
//
// 两条通道，各有不可替代的用途：
//
// 1. **UDP 导出**（`--ipfix-udp host:port`）：真实部署形态。用 std 的 `UdpSocket`
//    自己发，零第三方依赖。
// 2. **落盘成 pcap**（`--ipfix-pcap file`）：把每个 IPFIX 报文包成
//    Ethernet/IPv4/UDP 帧写进经典 pcap。这条通道解决两个真问题：
//    - **可独立校验**：产物能被 tshark 解（`check-ipfix-export.sh`），
//      否则"我们的编码对不对"只能自己说了算；
//    - **可回放**：`tcpreplay` 就能把同一批导出灌进真实采集器做联调，
//      不需要为了测试去搭一台导出设备。
//
// 为什么在这里手写以太网/IP/UDP 头：仓库无第三方依赖（没有 libpcap/afpacket 可用），
// 而 IPFIX 只走 UDP，头部一共 42 字节固定长度，手写比引依赖更可控。校验和必须**真算**：
// 写个 0 在某些工具里会被标成非法，产物就不再是"能被第三方工具正常读取"的了。
//
// 一条纪律：**导出失败不能静默**。UDP 发送可能因 MTU/缓冲区失败（EMSGSIZE/ENOBUFS），
// 这类失败在网络里表现为"采集侧少了一条记录"，若不计入 stats，运维看到的就是
// "一切正常但数据少了一半"。故本模块把 errors 计数与最近一次错误文本都暴露出来。

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

/// pcap 链路类型：以太网。
pub const PCAP_LINKTYPE_ETHERNET: u32 = 1;
/// pcap 记录里单个帧的长度上限（IPFIX 报文远小于此）。
pub const PCAP_SNAPLEN: u32 = 65535;

const ETH_LEN: usize = 14;
const IPV4_LEN: usize = 20;
const UDP_LEN: usize = 8;
/// 帧固定开销：以太网 + IPv4 + UDP。
pub const FRAME_OVERHEAD: usize = ETH_LEN + IPV4_LEN + UDP_LEN;

const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const SRC_IP: [u8; 4] = [10, 255, 0, 1];
const DST_IP: [u8; 4] = [10, 255, 0, 2];
/// 导出侧的源端口（真实实现是临时端口，这里固定以便产物可复现比较）。
pub const SRC_PORT: u16 = 49152;

/// 导出统计。`errors` 与 `last_error` 必须被 CLI 打出来。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SinkStats {
    pub datagrams: u64,
    pub bytes: u64,
    pub errors: u64,
    pub last_error: Option<String>,
}

/// UDP 导出通道。
pub struct UdpSink {
    sock: UdpSocket,
    addr: SocketAddr,
}

impl UdpSink {
    /// `addr` 形如 `10.0.0.9:4739`（也接受主机名，用 `ToSocketAddrs` 解析）。
    ///
    /// 解析失败被视为**配置错误**（调用方应直接退出）：一个写错的采集器地址
    /// 如果被降级成"不发但继续跑"，运维只会看到"数据没到"，看不到原因。
    pub fn connect(addr: &str) -> io::Result<Self> {
        let resolved = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "地址未解析出任何端点"))?;
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        Ok(Self {
            sock,
            addr: resolved,
        })
    }

    pub fn target(&self) -> SocketAddr {
        self.addr
    }

    fn send(&self, msg: &[u8]) -> io::Result<usize> {
        self.sock.send_to(msg, self.addr)
    }
}

/// 经典 pcap 写器（只写 UDP/IPFIX 一种帧）。
pub struct PcapSink {
    out: BufWriter<File>,
}

impl PcapSink {
    pub fn create(path: &str) -> io::Result<Self> {
        let mut out = BufWriter::new(File::create(path)?);
        write_pcap_header(&mut out)?;
        out.flush()?;
        Ok(Self { out })
    }

    fn write_datagram(&mut self, msg: &[u8], ts_sec: u32, ts_usec: u32) -> io::Result<()> {
        let frame = build_udp_frame(msg, SRC_PORT, crate::ipfix::IPFIX_PORT);
        // pcap 记录头 16 字节：ts_sec / ts_usec / incl_len / orig_len
        let mut hdr = [0u8; 16];
        hdr[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        hdr[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        hdr[8..12].copy_from_slice(&(frame.len() as u32).to_le_bytes());
        hdr[12..16].copy_from_slice(&(frame.len() as u32).to_le_bytes());
        self.out.write_all(&hdr)?;
        self.out.write_all(&frame)?;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// 组合导出通道：UDP 与/或 pcap，至少一个。
pub struct Sinks {
    udp: Option<UdpSink>,
    pcap: Option<PcapSink>,
    stats: SinkStats,
}

impl Sinks {
    pub fn new(udp: Option<UdpSink>, pcap: Option<PcapSink>) -> Self {
        Self {
            udp,
            pcap,
            stats: SinkStats::default(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.udp.is_some() || self.pcap.is_some()
    }

    pub fn stats(&self) -> &SinkStats {
        &self.stats
    }

    /// 发送一个 IPFIX 报文。**不返回 Result**：单个 datagram 失败不应中断整批导出
    /// （剩下的记录还有价值），但必须计数并保留原因。
    pub fn emit(&mut self, msg: &[u8], ts_sec: u32, ts_usec: u32) {
        if let Some(u) = &self.udp {
            match u.send(msg) {
                Ok(n) => {
                    self.stats.datagrams += 1;
                    self.stats.bytes += n as u64;
                }
                Err(e) => {
                    self.stats.errors += 1;
                    self.stats.last_error = Some(format!("udp 发送失败：{e}"));
                }
            }
        }
        if let Some(p) = &mut self.pcap {
            match p.write_datagram(msg, ts_sec, ts_usec) {
                Ok(()) => {
                    self.stats.datagrams += 1;
                    self.stats.bytes += msg.len() as u64;
                }
                Err(e) => {
                    self.stats.errors += 1;
                    self.stats.last_error = Some(format!("pcap 写入失败：{e}"));
                }
            }
        }
    }

    pub fn finish(&mut self) {
        if let Some(p) = &mut self.pcap {
            if let Err(e) = p.flush() {
                self.stats.errors += 1;
                self.stats.last_error = Some(format!("pcap 刷盘失败：{e}"));
            }
        }
    }
}

/// 经典 pcap 全局头（24 字节）。
///
/// 小端魔数 `0xa1b2c3d4` + 版本 2.4 + thiszone 0 + sigfigs 0 + snaplen 65535 + linktype 1。
/// **历史教训**（`capture/af_packet/af_packet_capture.c`）：把 `ver_major/ver_minor`
/// 各写成 4 字节会让整块后移 4 字节，`network` 字段被读成 snaplen，产物任何工具都打不开。
/// 这里的字段宽度由类型定死（u16 就是 2 字节），并有字节级单测守着。
pub fn write_pcap_header<W: Write>(w: &mut W) -> io::Result<()> {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    h[4..6].copy_from_slice(&2u16.to_le_bytes()); // version major
    h[6..8].copy_from_slice(&4u16.to_le_bytes()); // version minor
    h[8..12].copy_from_slice(&0i32.to_le_bytes()); // thiszone
    h[12..16].copy_from_slice(&0u32.to_le_bytes()); // sigfigs
    h[16..20].copy_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    h[20..24].copy_from_slice(&PCAP_LINKTYPE_ETHERNET.to_le_bytes());
    w.write_all(&h)
}

/// 把 IPFIX 报文包成 Ethernet/IPv4/UDP 帧（校验和真算）。
pub fn build_udp_frame(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
    let udp_len = UDP_LEN + payload.len();
    let ip_len = IPV4_LEN + udp_len;
    let mut f = Vec::with_capacity(FRAME_OVERHEAD + payload.len());

    // --- Ethernet ---
    f.extend_from_slice(&DST_MAC);
    f.extend_from_slice(&SRC_MAC);
    f.extend_from_slice(&0x0800u16.to_be_bytes());

    // --- IPv4 ---
    let ip_start = f.len();
    f.push(0x45); // version 4 + IHL 5
    f.push(0); // DSCP/ECN
    f.extend_from_slice(&(ip_len as u16).to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes()); // identification
    f.extend_from_slice(&0x4000u16.to_be_bytes()); // flags: DF
    f.push(64); // TTL
    f.push(17); // protocol = UDP
    f.extend_from_slice(&[0, 0]); // checksum 占位
    f.extend_from_slice(&SRC_IP);
    f.extend_from_slice(&DST_IP);
    let ip_sum = checksum(&f[ip_start..ip_start + IPV4_LEN]);
    f[ip_start + 10..ip_start + 12].copy_from_slice(&ip_sum.to_be_bytes());

    // --- UDP ---
    let udp_start = f.len();
    f.extend_from_slice(&src_port.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&(udp_len as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]); // checksum 占位
    f.extend_from_slice(payload);
    // UDP 校验和含伪首部（IPv4：src/dst/zero/proto/len）。IPv4 下 0 合法，但真算
    // 才能让产物不触发"校验和非法"的告警。
    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(&SRC_IP);
    pseudo.extend_from_slice(&DST_IP);
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&f[udp_start..udp_start + udp_len]);
    let mut udp_sum = checksum(&pseudo);
    if udp_sum == 0 {
        udp_sum = 0xFFFF; // RFC 768：算出来 0 要写成全 1
    }
    f[udp_start + 6..udp_start + 8].copy_from_slice(&udp_sum.to_be_bytes());
    f
}

/// 反码求和校验（IPv4/UDP 通用）。
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_header_is_24_bytes_with_2_byte_version_fields() {
        let mut buf = Vec::new();
        write_pcap_header(&mut buf).unwrap();
        assert_eq!(buf.len(), 24);
        assert_eq!(&buf[0..4], &[0xd4, 0xc3, 0xb2, 0xa1], "小端魔数");
        assert_eq!(&buf[4..6], &[2, 0]);
        assert_eq!(&buf[6..8], &[4, 0]);
        assert_eq!(&buf[16..20], &PCAP_SNAPLEN.to_le_bytes());
        assert_eq!(
            &buf[20..24],
            &1u32.to_le_bytes(),
            "linktype 必须是 1(Ethernet)"
        );
    }

    #[test]
    fn frame_is_well_formed_and_checksums_verify() {
        let payload = [0xAAu8; 100];
        let f = build_udp_frame(&payload, SRC_PORT, 4739);
        assert_eq!(f.len(), FRAME_OVERHEAD + 100);
        // 以太网
        assert_eq!(&f[0..6], &DST_MAC);
        assert_eq!(&f[6..12], &SRC_MAC);
        assert_eq!(&f[12..14], &[0x08, 0x00]);
        // IPv4
        assert_eq!(f[14], 0x45);
        assert_eq!(
            u16::from_be_bytes([f[16], f[17]]) as usize,
            IPV4_LEN + UDP_LEN + 100
        );
        assert_eq!(f[23], 17, "protocol = UDP");
        assert_eq!(checksum(&f[14..34]), 0, "IP 校验和必须自洽");
        // UDP
        assert_eq!(u16::from_be_bytes([f[34], f[35]]), SRC_PORT);
        assert_eq!(u16::from_be_bytes([f[36], f[37]]), 4739);
        assert_eq!(u16::from_be_bytes([f[38], f[39]]) as usize, UDP_LEN + 100);
        // UDP 校验和（含伪首部）自洽
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&f[26..30]); // src ip
        pseudo.extend_from_slice(&f[30..34]); // dst ip
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&f[38..40]);
        pseudo.extend_from_slice(&f[34..34 + UDP_LEN + 100]);
        assert_eq!(checksum(&pseudo), 0);
        assert_eq!(&f[42..], &payload);
    }

    #[test]
    fn odd_length_payload_checksum_still_verifies() {
        // 奇数长度会走到校验和的"最后一个字节左移"分支，这条分支最容易写错。
        let payload = [0x5Au8; 101];
        let f = build_udp_frame(&payload, 1234, 4739);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&f[26..30]);
        pseudo.extend_from_slice(&f[30..34]);
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&f[38..40]);
        pseudo.extend_from_slice(&f[34..34 + UDP_LEN + 101]);
        assert_eq!(checksum(&pseudo), 0);
    }

    #[test]
    fn udp_sink_rejects_unresolvable_address() {
        // 只验证"解析失败必须报错"，不去真发（测试环境不该依赖网络）。
        let e = UdpSink::connect("no-such-host.invalid:4739");
        assert!(e.is_err(), "无法解析的采集器地址必须报错，不能静默降级");
    }

    #[test]
    fn pcap_sink_writes_header_then_datagram_record() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "cythsec-ipfix-sink-test-{}.pcap",
            std::process::id()
        ));
        let p = path.to_str().unwrap().to_string();
        {
            let mut sink = PcapSink::create(&p).unwrap();
            sink.write_datagram(&[1, 2, 3, 4], 100, 200).unwrap();
            sink.flush().unwrap();
        }
        let data = std::fs::read(&p).unwrap();
        // 24 字节全局头 + 16 字节记录头 + 帧（42 + 4 字节载荷）
        assert_eq!(data.len(), 24 + 16 + FRAME_OVERHEAD + 4);
        assert_eq!(&data[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(
            u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            100
        );
        assert_eq!(
            u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            200
        );
        let incl = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        assert_eq!(incl as usize, FRAME_OVERHEAD + 4);
        let _ = std::fs::remove_file(&p);
    }
}
