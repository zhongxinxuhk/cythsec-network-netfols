// channel/tests.rs —— 通道的区域映射、attach 校验与 SPSC 消费语义的端到端测试。
//
// 为什么这些测试放在 crate 内而不是 `tests/` 目录：
// 测试需要一个「扮演 C++ 生产端」的写入路径，而该路径刻意只以 `#[cfg(test)]` 暴露
// （见 `Channel::test_bytes_mut` 的说明）。集成测试编译时按外部 crate 处理、拿不到它。
//
// 覆盖重点全部落在**静默失效**上：跨语言共享内存的难点不是「能不能跑通」，而是
// 「错位之后还能跑，只是结论全错」。因此每条用例都在验证「不一致时是否显式失败」。
//
// 生产端语义（契约的一部分，两个测试各自从一侧锁定它）：
//   **环满时生产端丢弃新帧、不覆盖未消费槽位。**
// 这条不只是「选一种策略」：消费者把报文以借用形式交给回调，若生产端可以自由覆盖，
// 回调执行期间正在读的槽位就可能被改写 —— 零拷贝承诺与数据正确性同时失效。因此
// 「越界覆盖」在本模块里不是一种可选策略，而是必须被检测出来的故障（见 FaultyProducer）。

use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::Ordering;

use super::abi_gen::{
    self, desc_off as doff, header_off, ChannelHeader, PacketDescriptor, DESCRIPTOR_STEP,
};
use super::consumer::{ConsumeError, Consumer, CorruptReason};
use super::region::{AttachError, Channel, RegionPerm};

/// 测试用临时区域：Drop 时删除文件。
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        // 进程 id 参与命名：并行测试与并行 CI 作业之间不会互相踩。
        let path = std::env::temp_dir().join(format!(
            "cythsec-chan-test-{}-{}.bin",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        TempRegion { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRegion {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// 往头部某个计数器加一。
///
/// 用 Relaxed 而非 Release：这些计数器是纯统计量，不承担任何同步职责 —— 真正需要
/// 同步的是 head/tail（见下面的 publish）。给统计量加多余的内存序只会让人误以为
/// 「读到 published 就一定能看到对应数据」。
fn bump(chan: &Channel, offset: usize) {
    chan.atomic_u64(offset).fetch_add(1, Ordering::Relaxed);
}

/// 按契约写入一个槽位：数据先写、描述符后写（发布顺序由调用方负责 release 写 head）。
fn write_slot(chan: &mut Channel, seq: u64, frame: &[u8], timestamp_ns: i64, flags: u32) {
    let slot_count = chan.slot_count();
    let slot_size = chan.slot_size();
    let layout = chan.layout();
    let idx = seq % u64::from(slot_count);
    let slot_data_off = (idx * u64::from(slot_size)) as u32;
    let desc = PacketDescriptor {
        seq,
        timestamp_ns,
        caplen: frame.len() as u32,
        wirelen: frame.len() as u32,
        ifindex: 0,
        data_off: slot_data_off,
        flags,
        reserved0: 0,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
    };

    let bytes = chan.test_bytes_mut();
    let desc_at = layout.desc_off as usize + (idx as usize) * (DESCRIPTOR_STEP as usize);
    let data_at = layout.data_off as usize + slot_data_off as usize;
    // 先写数据、再写描述符 —— 与契约要求的内存序一致。
    bytes[data_at..data_at + frame.len()].copy_from_slice(frame);
    unsafe {
        ptr::write_unaligned(
            bytes.as_mut_ptr().add(desc_at) as *mut PacketDescriptor,
            desc,
        );
    }
}

/// 测试专用生产端：复刻契约要求的**行为**（满则丢新帧、序号、槽位索引、release 发布顺序），
/// 不复刻任何特定实现。真正的生产端在 C++ 一侧，其一致性由 `--dump-abi` 的跨语言 parity 保证。
struct TestProducer;

impl TestProducer {
    /// 返回 false 表示该帧被丢弃（超长或环满），`dropped` 已记账。
    fn publish(chan: &mut Channel, frame: &[u8], timestamp_ns: i64, flags: u32) -> bool {
        let slot_count = chan.slot_count();
        let slot_size = chan.slot_size();
        if frame.len() > slot_size as usize {
            // 超长帧：同样计入 dropped（它确实没被送达），但不计 full_events ——
            // 那是「环满」专用的计数，两者混在一起会让「是不是消费者太慢」无从判断。
            bump(chan, header_off::DROPPED);
            return false;
        }

        let head = chan.load_head();
        let tail = chan.load_tail();
        if head.saturating_sub(tail) >= u64::from(slot_count) {
            bump(chan, header_off::DROPPED);
            bump(chan, header_off::FULL_EVENTS);
            return false;
        }

        write_slot(chan, head, frame, timestamp_ns, flags);
        chan.atomic_u64(header_off::HEAD)
            .store(head + 1, Ordering::Release);
        bump(chan, header_off::PUBLISHED);
        true
    }
}

/// **故障注入器**：无条件推进 head，即「生产端忽略 tail、直接覆盖未消费槽位」。
///
/// 它存在的唯一理由是制造那个必须被发现的场景。这个行为在真实系统里对应若干种事故：
/// 生产端实现漏掉了环满检查、区域被上一版进程以不同槽位配置写过、手工清零了一半头部。
/// 它们的共同点是**消费端看起来一切正常** —— 不报错、不阻塞，只是再也读不到数据。
struct FaultyProducer;

impl FaultyProducer {
    /// 返回写入的序号。刻意不检查环满、不更新 dropped —— 正是这个「不更新」使下面的
    /// 用例能证明：这类丢失在生产者计数器上完全不可见，只能靠消费端自己算出来。
    fn publish(chan: &mut Channel, frame: &[u8], timestamp_ns: i64) -> u64 {
        let head = chan.load_head();
        write_slot(chan, head, frame, timestamp_ns, 0);
        chan.atomic_u64(header_off::HEAD)
            .store(head + 1, Ordering::Release);
        bump(chan, header_off::PUBLISHED);
        head
    }
}

/// 构造一个最小的以太 + IPv4 + UDP 帧（负载任意）。
fn udp_frame(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: u8) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x02; 6]);
    v.extend_from_slice(&[0x03; 6]);
    v.extend_from_slice(&0x0800u16.to_be_bytes());
    v.extend_from_slice(&[0x45, 0x00]);
    let total = 20 + 8 + u16::from(payload);
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(&[0x00, 0x01]);
    v.extend_from_slice(&[0x40, 0x00]);
    v.extend_from_slice(&[64, 17]); // ttl, proto=UDP
    v.extend_from_slice(&[0x00, 0x00]);
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&(8u16 + u16::from(payload)).to_be_bytes()); // UDP 长度
    v.extend_from_slice(&[0x00, 0x00]); // UDP 校验和
    v.extend(std::iter::repeat_n(0xAB, usize::from(payload)));
    v
}

// ---------------------------------------------------------------- 创建与 attach

#[test]
fn create_then_attach_sees_same_header() {
    let tmp = TempRegion::new("attach");
    let created = Channel::create(tmp.path(), 64, 512).expect("创建应成功");
    let layout = created.layout();
    assert_eq!(
        layout.desc_off % abi_gen::REGION_ALIGNMENT,
        0,
        "描述符区应页对齐"
    );
    assert_eq!(created.header().magic, abi_gen::MAGIC);
    assert_eq!(created.header().abi_version, abi_gen::ABI_VERSION);
    drop(created);

    // 另一端 attach：必须得到完全相同的布局理解。
    let attached = Channel::attach(tmp.path()).expect("attach 应成功");
    assert_eq!(attached.layout(), layout);
    assert_eq!(attached.slot_count(), 64);
    assert_eq!(attached.slot_size(), 512);
    assert_eq!(attached.stats().head, 0);
    assert_eq!(attached.stats().tail, 0);
}

#[test]
fn uninitialized_region_is_distinguished_from_wrong_magic() {
    // 全零区域与「魔数不对」是两种完全不同的处置方向：
    // 前者说明区域没建成（去建），后者说明拿错了文件（去查配置）。
    let tmp = TempRegion::new("uninit");
    std::fs::write(tmp.path(), vec![0u8; 4096 + 64 * 64 + 64 * 512]).unwrap();
    let err = Channel::attach(tmp.path()).unwrap_err();
    assert_eq!(err.code(), "chan.uninitialized");
    assert_eq!(
        err,
        AttachError::Uninitialized {
            local_magic: abi_gen::MAGIC_BE,
            remote_magic: 0,
        }
    );

    // 写入一个「像魔数但不对」的值：应落到 magic_mismatch。
    let mut bytes = vec![0u8; 4096 + 64 * 64 + 64 * 512];
    bytes[..8].copy_from_slice(b"CYTHSEC9");
    std::fs::write(tmp.path(), &bytes).unwrap();
    let err = Channel::attach(tmp.path()).unwrap_err();
    assert_eq!(err.code(), "chan.magic_mismatch");
}

#[test]
fn attach_rejects_header_field_mismatch_with_its_own_code() {
    // 逐字段篡改头部，确认每一种不一致都有**专属**诊断码。
    // 若这些情形塌缩成同一个「通道不匹配」，排障时就得靠猜 —— 这正是 TSG 的教训。
    let tmp = TempRegion::new("fields");
    {
        let _c = Channel::create(tmp.path(), 64, 512).expect("创建应成功");
    }
    let good = std::fs::read(tmp.path()).unwrap();

    let cases: Vec<(&str, Box<dyn Fn(&mut [u8])>, &str)> = vec![
        (
            "ABI 版本",
            Box::new(|b: &mut [u8]| {
                b[header_off::ABI_VERSION..header_off::ABI_VERSION + 4]
                    .copy_from_slice(&(abi_gen::ABI_VERSION + 1).to_ne_bytes());
            }),
            "chan.abi_version_mismatch",
        ),
        (
            "头部区尺寸",
            Box::new(|b: &mut [u8]| {
                b[header_off::HEADER_SIZE..header_off::HEADER_SIZE + 4]
                    .copy_from_slice(&8192u32.to_ne_bytes());
            }),
            "chan.header_size_mismatch",
        ),
        (
            "描述符区偏移",
            Box::new(|b: &mut [u8]| {
                b[header_off::DESC_OFF..header_off::DESC_OFF + 4]
                    .copy_from_slice(&8192u32.to_ne_bytes());
            }),
            "chan.layout_mismatch",
        ),
        (
            "数据区偏移",
            Box::new(|b: &mut [u8]| {
                b[header_off::DATA_OFF..header_off::DATA_OFF + 4]
                    .copy_from_slice(&9000u32.to_ne_bytes());
            }),
            "chan.layout_mismatch",
        ),
        (
            "槽位数",
            Box::new(|b: &mut [u8]| {
                b[header_off::SLOT_COUNT..header_off::SLOT_COUNT + 4]
                    .copy_from_slice(&128u32.to_ne_bytes());
            }),
            "chan.layout_mismatch",
        ),
    ];

    for (name, tamper, want_code) in cases {
        let mut bytes = good.clone();
        tamper(&mut bytes);
        std::fs::write(tmp.path(), &bytes).unwrap();
        let err = Channel::attach(tmp.path()).unwrap_err();
        assert_eq!(err.code(), want_code, "{name}: 诊断码不符（实际 {err}）");
        // 文案必须带上具体取值，否则排障的人只知道「不匹配」却不知差多少。
        assert!(
            err.to_string().chars().any(|c| c.is_ascii_digit()),
            "{name}: 诊断文案缺少具体取值: {err}"
        );
    }
}

#[test]
fn layout_mismatch_message_carries_all_four_offsets() {
    // 槽位数与步进在只有头部自身数字时无法区分（见 validate 中的说明），因此这里
    // 不设「专指某一字段」的诊断，而是把四个偏移值全部摊开。本用例锁定这一点：
    // 缺任何一个数，排障的人就得靠推算。
    let tmp = TempRegion::new("layoutmsg");
    {
        let _c = Channel::create(tmp.path(), 64, 512).expect("创建应成功");
    }
    let mut bytes = std::fs::read(tmp.path()).unwrap();
    bytes[header_off::DATA_OFF..header_off::DATA_OFF + 4].copy_from_slice(&9000u32.to_ne_bytes());
    std::fs::write(tmp.path(), &bytes).unwrap();

    let text = Channel::attach(tmp.path()).unwrap_err().to_string();
    for v in ["8192", "9000"] {
        assert!(text.contains(v), "文案应含偏移 {v}: {text}");
    }
    for label in ["描述符区", "数据区"] {
        assert!(text.contains(label), "文案应区分 {label}: {text}");
    }
}

#[test]
fn attach_rejects_truncated_region() {
    // 文件被截断不会自行报错：映射成功，读到的尾部是零或空洞。
    let tmp = TempRegion::new("trunc");
    {
        let c = Channel::create(tmp.path(), 64, 512).expect("创建应成功");
        let need = c.layout().required;
        // 截到布局所需长度的一半
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path())
            .unwrap();
        f.set_len(need / 2).unwrap();
    }
    let err = Channel::attach(tmp.path()).unwrap_err();
    assert_eq!(err.code(), "chan.region_too_small");
    match err {
        AttachError::RegionTooSmall { required, actual } => {
            assert!(required > actual, "required 应大于 actual 才叫「太小」");
        }
        other => panic!("应为 region_too_small，实际 {other:?}"),
    }
}

#[test]
fn attach_expect_catches_stale_region_from_older_config() {
    // 现实场景：部署配置写「1024 × 2048」，而区域是上一版配置建的。
    // 此时布局不同，读到的每个字段都无意义 —— 必须由配置期望值拦下。
    let tmp = TempRegion::new("expect");
    {
        let _c = Channel::create(tmp.path(), 64, 512).expect("创建应成功");
    }
    let c = Channel::attach_expect(tmp.path(), 64, 512, RegionPerm::ReadWrite)
        .expect("与区域一致的期望值应通过");
    assert_eq!(c.slot_count(), 64);

    let err = Channel::attach_expect(tmp.path(), 1024, 2048, RegionPerm::ReadWrite).unwrap_err();
    assert_eq!(err.code(), "chan.slot_count_mismatch");

    let err = Channel::attach_expect(tmp.path(), 64, 4096, RegionPerm::ReadWrite).unwrap_err();
    assert_eq!(err.code(), "chan.slot_size_mismatch");
}

#[test]
fn attach_expect_ranks_root_cause_above_config_mismatch() {
    // 顺序回归锁定：期望值比对必须排在 validate 之后。
    //
    // 若顺序颠倒，全零区域的 slot_count 读出来是 0，会先报 slot_count_mismatch
    // （「期望 64、对端 0」），把排障的人引向「配置写错了」；而根因是区域尚未初始化，
    // 该做的是重建区域 —— 两者处置方向相反，误导的代价是白改一轮配置。
    let tmp = TempRegion::new("expect_blank");
    {
        // 长度足以通过区域尺寸检查，但内容全零 —— 等价于「创建后未初始化」或「被手工清零」。
        let f = std::fs::File::create(tmp.path()).expect("创建文件应成功");
        f.set_len(8 * 1024 * 1024).expect("设置长度应成功");
    }
    let err = Channel::attach_expect(tmp.path(), 64, 512, RegionPerm::ReadWrite).unwrap_err();
    assert_eq!(
        err.code(),
        "chan.uninitialized",
        "全零区域应报「未初始化」这个根因，而不是配置不匹配"
    );

    // 同理：拿错文件（魔数不对）时也该报 magic_mismatch，而非配置不匹配。
    let tmp2 = TempRegion::new("expect_wrong_magic");
    {
        let _c = Channel::create(tmp2.path(), 64, 512).expect("创建应成功");
    }
    let mut bytes = std::fs::read(tmp2.path()).unwrap();
    bytes[..8].copy_from_slice(b"NOTACHAN");
    std::fs::write(tmp2.path(), &bytes).unwrap();
    let err = Channel::attach_expect(tmp2.path(), 1024, 2048, RegionPerm::ReadWrite).unwrap_err();
    assert_eq!(
        err.code(),
        "chan.magic_mismatch",
        "魔数不符是根因，应优先于槽位配置不匹配报出"
    );
}

#[test]
fn attach_rejects_out_of_range_slot_config() {
    // 区域里写着越界配置：不得按它去算布局（会溢出/越界），必须拒绝。
    let tmp = TempRegion::new("range");
    {
        let _c = Channel::create(tmp.path(), 64, 512).expect("创建应成功");
    }
    let mut bytes = std::fs::read(tmp.path()).unwrap();
    bytes[header_off::SLOT_COUNT..header_off::SLOT_COUNT + 4]
        .copy_from_slice(&(abi_gen::MAX_SLOT_COUNT + 1).to_ne_bytes());
    std::fs::write(tmp.path(), &bytes).unwrap();
    let err = Channel::attach(tmp.path()).unwrap_err();
    assert_eq!(err.code(), "chan.slot_count_out_of_range");
    match err {
        AttachError::SlotCountOutOfRange {
            value,
            min_value,
            max_value,
        } => {
            assert_eq!(value, abi_gen::MAX_SLOT_COUNT + 1);
            assert_eq!(
                (min_value, max_value),
                (abi_gen::MIN_SLOT_COUNT, abi_gen::MAX_SLOT_COUNT)
            );
        }
        other => panic!("应为 slot_count_out_of_range，实际 {other:?}"),
    }
}

#[test]
fn readonly_attach_can_inspect_without_consuming() {
    // 只读映射用于巡检工具。消费端必须写 tail，因此只读权限下不该被当成消费端使用。
    // 这里验证的是「权限确实生效了」：写只读页会得到 SIGSEGV，无法在测试里安全触发，
    // 故改为验证只读映射本身可用、且能正确反映生产端已发布的内容。
    let tmp = TempRegion::new("ro");
    {
        let mut c = Channel::create(tmp.path(), 16, 256).expect("创建应成功");
        assert!(TestProducer::publish(
            &mut c,
            &udp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0),
            1,
            0
        ));
    }
    let ro =
        Channel::attach_expect(tmp.path(), 16, 256, RegionPerm::ReadOnly).expect("只读应可 attach");
    assert_eq!(ro.stats().head, 1);
    assert_eq!(ro.stats().tail, 0);
    assert_eq!(ro.stats().backlog(), 1);
}

#[test]
fn debug_impl_reports_understanding_not_addresses() {
    // 手写 Debug 的目的就是让它可读：若退回 derive，输出里只有裸指针与映射长度，
    // 排障时无法用于任何比对。
    let tmp = TempRegion::new("debug");
    let chan = Channel::create(tmp.path(), 16, 256).expect("创建应成功");
    let text = format!("{chan:?}");
    assert!(text.contains("CYTHSEC1"), "应显示魔数文本: {text}");
    assert!(text.contains("16 x 256"), "应显示槽位配置: {text}");
    assert!(text.contains("desc_off"), "应显示布局: {text}");
}

// ---------------------------------------------------------------- 消费语义

#[test]
fn publish_then_consume_end_to_end_into_flow_keys() {
    let tmp = TempRegion::new("e2e");
    let mut chan = Channel::create(tmp.path(), 8, 2048).expect("创建应成功");

    let frames = vec![
        udp_frame([10, 0, 0, 1], 40000, [93, 184, 216, 34], 53, 4),
        udp_frame([10, 0, 0, 1], 40001, [93, 184, 216, 34], 53, 8),
        udp_frame([10, 0, 0, 2], 40002, [93, 184, 216, 35], 123, 16),
    ];
    for (i, f) in frames.iter().enumerate() {
        assert!(
            TestProducer::publish(&mut chan, f, 1_000_000 * (i as i64 + 1), 0),
            "第 {i} 帧应发布成功"
        );
    }

    let mut consumer = Consumer::resume(&mut chan);
    assert_eq!(consumer.pending(), 3);
    assert!(consumer.health().is_ok(), "正常通道应通过健康检查");

    let mut keys = Vec::new();
    let n = consumer
        .drain(|meta, data| {
            let d = super::decode::decode_frame(data).expect("帧应能解出五元组");
            // 描述符序号与解码结果一起留存：两者必须能对上，否则说明槽位与序号已错位。
            keys.push((meta.seq, d.key, d.ip_payload_len));
        })
        .expect("排空应成功");
    assert_eq!(n, 3);
    assert_eq!(consumer.stats().packets, 3);
    assert_eq!(consumer.pending(), 0);

    assert_eq!(keys[0].0, 0, "序号应与发布顺序一致");
    assert_eq!(keys[0].1.dst_port, 53);
    assert_eq!(keys[1].1.src_port, 40001);
    assert_eq!(keys[2].1.dst_port, 123);
    // ip_payload_len = IPv4 总长 - IP 头长，即「UDP 头 + 载荷」。
    // 用头部长度字段而非数出来的字节数，是为了让截断捕获不使流量统计系统性偏小。
    assert_eq!(keys[0].2, 12, "UDP 头 8 + 载荷 4");
    assert_eq!(keys[2].2, 24, "UDP 头 8 + 载荷 16");
    assert_eq!(
        consumer.stats().bytes,
        frames.iter().map(|f| f.len() as u64).sum::<u64>()
    );

    // 通道自身的累计计数应同步。
    let st = consumer.channel_stats();
    assert_eq!((st.head, st.tail, st.consumed), (3, 3, 3));
    assert_eq!(st.consumer_pid, std::process::id(), "消费端 pid 必须可查");
}

#[test]
fn drain_returns_zero_when_nothing_pending() {
    let tmp = TempRegion::new("idle");
    let mut chan = Channel::create(tmp.path(), 4, 256).expect("创建应成功");
    let mut consumer = Consumer::resume(&mut chan);
    assert_eq!(consumer.drain(|_, _| panic!("不该有回调")).unwrap(), 0);
    assert_eq!(consumer.pending(), 0);
}

#[test]
fn from_head_skips_backlog_resume_replays_it() {
    // 「续跑」与「从当前开始」的区别必须明确可测：默默重放一小时前的积压是很难发现的错。
    let tmp = TempRegion::new("resume");
    let mut chan = Channel::create(tmp.path(), 8, 512).expect("创建应成功");
    for i in 0..3u8 {
        assert!(TestProducer::publish(
            &mut chan,
            &udp_frame([10, 0, 0, 1], 100 + u16::from(i), [10, 0, 0, 2], 9, i),
            1,
            0
        ));
    }

    {
        let mut c = Consumer::from_head(&mut chan);
        assert_eq!(c.pending(), 0, "from_head 应丢弃历史积压");
        assert_eq!(c.drain(|_, _| {}).unwrap(), 0);
    }
    // from_head 已把 tail 推到 head，因此续跑同样读不到旧数据。
    {
        let mut c = Consumer::resume(&mut chan);
        assert_eq!(c.pending(), 0);
        assert_eq!(c.drain(|_, _| {}).unwrap(), 0);
    }

    // 新发布的数据两者都能读到。
    assert!(TestProducer::publish(
        &mut chan,
        &udp_frame([10, 0, 0, 9], 1, [10, 0, 0, 8], 2, 1),
        1,
        0
    ));
    let mut c = Consumer::resume(&mut chan);
    assert_eq!(c.drain(|_, _| {}).unwrap(), 1);
}

#[test]
fn producer_stops_at_capacity_and_accounts_the_loss() {
    // 契约行为：环满时丢弃**新**帧且不覆盖未消费槽位。
    //
    // 为什么丢新帧而不是覆盖旧帧：消费者把报文以借用形式交给回调（零拷贝），若允许覆盖，
    // 回调执行期间正在读的槽位就可能被改写。代价是「消费者卡住时丢的是最新流量」，
    // 因此必须把丢弃数如实上报 —— 否则这个代价就成了静默损失。
    let tmp = TempRegion::new("full");
    let mut chan = Channel::create(tmp.path(), 4, 512).expect("创建应成功");

    let mut ok = 0;
    for i in 0..10u16 {
        if TestProducer::publish(
            &mut chan,
            &udp_frame([10, 0, 0, 1], i, [10, 0, 0, 2], 2, 0),
            1,
            0,
        ) {
            ok += 1;
        }
    }
    assert_eq!(ok, 4, "环容量为 4");

    let st = chan.stats();
    assert_eq!(st.head, 4, "环满时不得推进 head");
    assert_eq!(st.published, 4);
    assert_eq!(st.dropped, 6, "6 帧被丢弃必须入账");
    assert_eq!(
        st.full_events, 6,
        "环满次数应单独计数，用于判断是否消费者太慢"
    );
    assert_eq!(st.tail, 0);

    // 已发布槽位不得被后来者覆盖：首帧序号仍是 0。
    let base = chan.layout().desc_off as usize;
    let bytes = chan.test_bytes_mut();
    let seq = u64::from_ne_bytes(bytes[base..base + 8].try_into().unwrap());
    assert_eq!(seq, 0, "已发布槽位不得被覆盖");

    // 已发布的 4 帧必须完整可读。
    let mut consumer = Consumer::resume(&mut chan);
    let mut seqs = Vec::new();
    assert_eq!(consumer.drain(|m, _| seqs.push(m.seq)).unwrap(), 4);
    assert_eq!(seqs, vec![0, 1, 2, 3]);
}

#[test]
fn overwriting_producer_is_detected_with_exact_loss() {
    // 故障注入：生产端越界覆盖了未消费槽位。这在生产者计数器上完全不可见
    // （dropped 保持 0），只能靠消费端自己算出来 —— 因此消费端必须算，且要算准。
    let tmp = TempRegion::new("overrun");
    let slots = 8u32;
    let mut chan = Channel::create(tmp.path(), slots, 512).expect("创建应成功");

    // 先发 1 帧，使序号从 1 起 —— 否则「从未被消费」的 tail=0 与「序号 0 那一帧」
    // 在断言里会混在一起，读的人无法分辨。
    assert!(TestProducer::publish(
        &mut chan,
        &udp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0),
        1,
        0
    ));

    // 消费者从未跟进（tail 始终为 0），生产端连续覆盖。
    let mut last_seq = 0;
    for i in 0..12u16 {
        last_seq = FaultyProducer::publish(
            &mut chan,
            &udp_frame([10, 0, 0, 1], 1000 + i, [10, 0, 0, 2], 7, 0),
            1,
        );
    }
    assert_eq!(last_seq, 12);
    assert_eq!(chan.stats().head, 13);
    assert_eq!(chan.stats().dropped, 0, "越界覆盖在生产者侧不留任何痕迹");

    let mut consumer = Consumer::resume(&mut chan);
    // 失效的静默性：pending 仍报 13，看上去只是「有数据待读」。
    assert_eq!(consumer.pending(), 13);

    let err = consumer
        .poll(|_, _| panic!("一圈以上的积压不该返回数据"))
        .unwrap_err();
    match err {
        ConsumeError::ProducerOverrun {
            head,
            tail,
            slot_count,
            skipped,
        } => {
            assert_eq!(slot_count, slots);
            assert_eq!(head, 13);
            assert_eq!(tail, 0);
            assert_eq!(skipped, 5, "13 - 8 = 5 个未读槽位已被覆盖");
        }
        other => panic!("应为 ProducerOverrun，实际 {other:?}"),
    }
    // 丢弃数必须记账：不记账的话「数据到哪去了」这个问题永远查不出来。
    assert_eq!(consumer.stats().overrun_skipped, 5);

    // 推进之后，读到的必须仍是**完整报文**：序号 5..12 共 8 帧。
    let mut seqs = Vec::new();
    assert_eq!(consumer.drain(|m, _| seqs.push(m.seq)).unwrap(), 8);
    assert_eq!(seqs, (5..13).collect::<Vec<u64>>());
}

#[test]
fn drain_continues_past_overrun_but_stops_on_corrupt_descriptor() {
    // 两种错误的中断策略刻意不同：
    //   越界覆盖 —— 丢包数已精确记账，剩余数据仍完整可读，中断只会让调用方提前放弃；
    //   描述符损坏 —— 继续读已无正确性可言，必须立即停。
    let tmp = TempRegion::new("drainpolicy");

    // (1) 越界覆盖不中断排空。
    let mut chan = Channel::create(tmp.path(), 4, 256).expect("创建应成功");
    for i in 0..10u16 {
        FaultyProducer::publish(
            &mut chan,
            &udp_frame([10, 0, 0, 1], i, [10, 0, 0, 2], 3, 0),
            1,
        );
    }
    assert_eq!(chan.stats().head, 10);
    let mut consumer = Consumer::resume(&mut chan);
    let mut seqs = Vec::new();
    let n = consumer
        .drain(|m, _| seqs.push(m.seq))
        .expect("有丢包也应排空成功");
    assert_eq!(n, 4, "仅环内最新 4 帧可读");
    assert_eq!(seqs, vec![6, 7, 8, 9], "读到的必须是环内仍然完好的那几帧");
    assert!(consumer.last_overrun().is_some(), "丢弃事件应被记录");
    assert_eq!(consumer.stats().overrun_skipped, 6);

    // (2) 描述符损坏立即中断，且已消费的记账不回退。
    let tmp2 = TempRegion::new("draincorrupt");
    let mut chan2 = Channel::create(tmp2.path(), 4, 256).expect("创建应成功");
    for i in 0..3u16 {
        assert!(TestProducer::publish(
            &mut chan2,
            &udp_frame([10, 0, 0, 1], i, [10, 0, 0, 2], 3, 0),
            1,
            0
        ));
    }
    // 篡改第 1 个槽位的序号。
    let base = chan2.layout().desc_off as usize;
    let bytes = chan2.test_bytes_mut();
    bytes[base + DESCRIPTOR_STEP as usize..base + DESCRIPTOR_STEP as usize + 8]
        .copy_from_slice(&42u64.to_ne_bytes());

    let mut consumer2 = Consumer::resume(&mut chan2);
    let mut seen = 0;
    let err = consumer2
        .drain(|_, _| seen += 1)
        .expect_err("描述符损坏必须中断排空");
    assert!(matches!(err, ConsumeError::CorruptDescriptor { .. }));
    assert_eq!(seen, 1, "损坏前的那一帧应已交付");
    assert_eq!(consumer2.stats().packets, 1);
    assert_eq!(consumer2.tail(), 1, "损坏帧不得被跳过");
}

#[test]
fn corrupt_descriptor_seq_mismatch_is_detected() {
    // 序号自检是整套索引算术最廉价也最有力的验证：序号与消费位置不符，
    // 说明两侧之一算错了，此时任何字段都不可信。
    let tmp = TempRegion::new("corrupt");
    let mut chan = Channel::create(tmp.path(), 8, 512).expect("创建应成功");
    assert!(TestProducer::publish(
        &mut chan,
        &udp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0),
        1,
        0
    ));

    // 篡改第 0 个描述符的 seq。
    let base = chan.layout().desc_off as usize;
    let bytes = chan.test_bytes_mut();
    bytes[base..base + 8].copy_from_slice(&999u64.to_ne_bytes());

    let mut consumer = Consumer::resume(&mut chan);
    let err = consumer
        .poll(|_, _| panic!("描述符损坏时不该交出数据"))
        .unwrap_err();
    match err {
        ConsumeError::CorruptDescriptor {
            index,
            expected_seq,
            actual_seq,
            reason,
            ..
        } => {
            assert_eq!((index, expected_seq, actual_seq), (0, 0, 999));
            assert_eq!(reason, CorruptReason::SeqMismatch);
        }
        other => panic!("应为 CorruptDescriptor，实际 {other:?}"),
    }
    // 损坏时不得推进 tail：否则那帧数据就被永久跳过了。
    assert_eq!(consumer.tail(), 0);
}

#[test]
fn corrupt_caplen_uses_the_shared_diagnostic_text() {
    // caplen 越界这条的文案直接复用真源生成的诊断，使两端说法一致。
    let tmp = TempRegion::new("caplen");
    let mut chan = Channel::create(tmp.path(), 8, 256).expect("创建应成功");
    assert!(TestProducer::publish(
        &mut chan,
        &udp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0),
        1,
        0
    ));

    let base = chan.layout().desc_off as usize;
    let bytes = chan.test_bytes_mut();
    bytes[base + doff::CAPLEN..base + doff::CAPLEN + 4].copy_from_slice(&999u32.to_ne_bytes());

    let mut consumer = Consumer::resume(&mut chan);
    let err = consumer.poll(|_, _| panic!("不该交出数据")).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("999"), "文案应含实际长度: {text}");
    assert!(
        text.contains(&abi_gen::diag::ChanTruncatedPacket::CODE.to_string())
            || text.contains("槽容量"),
        "应复用真源的截断诊断文案: {text}"
    );
    assert_eq!(consumer.tail(), 0);
}

#[test]
fn tail_ahead_of_head_is_caught_by_health() {
    // 这是本套设计里最阴的一种失效：tail > head 时 head-tail 饱和为 0，
    // 消费端**永远报告无数据**，不报错、不阻塞，而生产端在背后持续丢包。
    let tmp = TempRegion::new("tailahead");
    let mut chan = Channel::create(tmp.path(), 8, 512).expect("创建应成功");
    assert!(TestProducer::publish(
        &mut chan,
        &udp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0),
        1,
        0
    ));

    // 模拟「区域被上一版进程以不同配置写过」：把 tail 抬到 head 之前。
    chan.store_tail(128);

    let mut consumer = Consumer::resume(&mut chan);
    // 先确认这个失效确实是静默的：pending 恒为 0，poll 报告「无数据」。
    assert_eq!(consumer.pending(), 0);
    assert!(!consumer.poll(|_, _| panic!("不该有数据")).unwrap());

    // 健康检查必须把它抓出来。
    let err = consumer
        .health()
        .expect_err("tail 越过 head 应被健康检查拦下");
    assert_eq!(err.code(), "chan.tail_ahead_of_head");
    let text = err.to_string();
    assert!(text.contains("消费位置 128"), "文案应含实际 tail: {text}");
    assert!(text.contains("生产位置 1"), "文案应含实际 head: {text}");
    assert!(
        text.contains("恒为 0") || text.contains("静默"),
        "文案应说明该失效为何危险: {text}"
    );
}

#[test]
fn health_recheck_is_idempotent() {
    let tmp = TempRegion::new("healthy");
    let mut chan = Channel::create(tmp.path(), 8, 512).expect("创建应成功");
    assert!(TestProducer::publish(
        &mut chan,
        &udp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0),
        1,
        0
    ));
    let mut consumer = Consumer::resume(&mut chan);
    assert!(consumer.health().is_ok());
    assert!(
        consumer.health().is_ok(),
        "重复健康检查应保持通过（不得有累积副作用）"
    );
}

#[test]
fn decode_ignores_flags_and_trusts_bytes() {
    // 解码只看字节，不看生产端标的 flags。若反过来，生产端标错就会变成解码器的缺陷。
    let tmp = TempRegion::new("vlanflag");
    let mut chan = Channel::create(tmp.path(), 4, 512).expect("创建应成功");

    // 构造带 802.1Q 标签的帧，但**故意不设** VLAN_TAGGED 标志。
    let base = udp_frame([10, 0, 0, 1], 1234, [10, 0, 0, 2], 4321, 2);
    let mut tagged = base[..12].to_vec();
    tagged.extend_from_slice(&0x8100u16.to_be_bytes());
    tagged.extend_from_slice(&[0x00, 0x2A]); // VLAN 42
    tagged.extend_from_slice(&0x0800u16.to_be_bytes());
    tagged.extend_from_slice(&base[14..]);

    assert!(TestProducer::publish(&mut chan, &tagged, 1, 0));
    let mut consumer = Consumer::resume(&mut chan);
    consumer
        .drain(|meta, data| {
            assert!(!meta.is_vlan_tagged(), "标志位确实没设");
            let d = super::decode::decode_frame(data).expect("应能解出");
            assert_eq!(d.vlan_tags, 1, "但字节里确实有标签，解码必须按字节来");
            assert_eq!(d.key.dst_port, 4321);
            // 元数据与字节对照，正是调用方该做的交叉校验。
            assert_eq!(super::decode::frame_has_vlan_tag(data), Some(true));
        })
        .unwrap();
}

#[test]
fn truncated_capture_is_counted_and_caplen_used() {
    // 截断捕获（caplen < wirelen）：数据仍可用，且必须被单独计数 ——
    // 「多少流量没抓到」是判断采集点是否需要调 snaplen 的唯一依据。
    let tmp = TempRegion::new("truncapt");
    let mut chan = Channel::create(tmp.path(), 4, 512).expect("创建应成功");

    let frame = udp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0);
    assert!(TestProducer::publish(
        &mut chan,
        &frame,
        1,
        abi_gen::flag::TRUNCATED
    ));
    // 把 wirelen 改大，模拟「线上比抓到的长」
    let base = chan.layout().desc_off as usize;
    let bytes = chan.test_bytes_mut();
    bytes[base + doff::WIRELEN..base + doff::WIRELEN + 4].copy_from_slice(&1500u32.to_ne_bytes());

    let mut consumer = Consumer::resume(&mut chan);
    consumer
        .drain(|meta, _| {
            assert!(meta.is_truncated());
            assert_eq!(meta.wirelen, 1500);
            assert_eq!(meta.caplen, frame.len() as u32);
        })
        .unwrap();
    assert_eq!(consumer.stats().truncated, 1);
    // 字节统计按线上长度计：统计「流量」时应反映实际经过的字节，而非抓到的字节。
    assert_eq!(consumer.stats().bytes, 1500);
}

#[test]
fn ipv4_payload_len_drives_flow_byte_accounting() {
    // ip_payload_len 是从 IP 头长度字段算出的，不受捕获截断影响。
    // 这一点很关键：若按「数出来的字节」计，截断抓包会让流量统计系统性偏小。
    let frame = udp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 100);
    let d = super::decode::decode_frame(&frame).expect("应能解出");
    assert_eq!(d.ip_payload_len, 108, "UDP 头 8 + 载荷 100");

    // 截断到只够拿到端口（14 + 20 + 4 字节），IP 头里的长度字段仍完整。
    let cut = &frame[..38];
    let d2 = super::decode::decode_frame(cut).expect("端口可取即可解出五元组");
    assert_eq!(d2.ip_payload_len, 108, "长度来自头部字段，不因截断而变小");
    assert_eq!(d2.key.dst_port, 2);
}

#[test]
fn stats_snapshot_matches_header_fields() {
    let tmp = TempRegion::new("stats");
    let mut chan = Channel::create(tmp.path(), 8, 512).expect("创建应成功");
    for i in 0..5u16 {
        assert!(TestProducer::publish(
            &mut chan,
            &udp_frame([10, 0, 0, 1], i, [10, 0, 0, 2], 2, 0),
            1,
            0
        ));
    }
    let mut consumer = Consumer::resume(&mut chan);
    let _ = consumer.drain(|_, _| {}).unwrap();
    let st = consumer.channel_stats();
    assert_eq!((st.head, st.published, st.consumed), (5, 5, 5));
    assert_eq!(st.tail, 5);
    assert_eq!(st.backlog(), 0);
    assert_eq!(st.dropped, 0, "生产者未丢帧");
    assert_eq!(st.producer_pid, std::process::id());
    assert_eq!(st.consumer_pid, std::process::id());
}

#[test]
fn oversized_frame_is_rejected_not_truncated_silently() {
    // 帧比槽位大：生产端必须整帧丢弃并计数，而不是截断后当作正常帧发布 ——
    // 截断发布会让消费者解码出一个「看似正常」的五元组，而载荷已经不完整。
    let tmp = TempRegion::new("oversize");
    let mut chan = Channel::create(tmp.path(), 4, 64).expect("创建应成功");
    let big = udp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 200);
    assert!(big.len() > 64);
    assert!(
        !TestProducer::publish(&mut chan, &big, 1, 0),
        "超长帧应被拒"
    );

    let st = chan.stats();
    assert_eq!(st.head, 0, "拒绝时不得推进 head");
    assert_eq!(st.dropped, 1, "超长被拒同样是一次丢弃，必须入账");
    assert_eq!(st.full_events, 0, "超长不属于环满，不得混入 full_events");
}

#[test]
fn header_struct_size_matches_region_reservation() {
    // 头部结构体必须放得进预留的头部区。二者都是常量，但一个来自结构体布局、
    // 一个来自真源配置，若不同步就会静默越界写到描述符区。
    let hdr = std::mem::size_of::<ChannelHeader>();
    assert!(
        hdr < abi_gen::HEADER_REGION_SIZE as usize,
        "头部结构体 {hdr} 字节必须小于头部区 {} 字节",
        abi_gen::HEADER_REGION_SIZE
    );
    assert_eq!(hdr, 128);
    assert_eq!(
        std::mem::size_of::<PacketDescriptor>(),
        DESCRIPTOR_STEP as usize
    );
}
