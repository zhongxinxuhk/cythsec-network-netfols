// 由 tools/codegen/gen-channel-abi.py 生成，请勿手工修改。
// 真源：configs/registry/channel-abi.json（registry_version=1.0.0）
//
// 本文件是 C++ 生产端与 Rust 消费端共享的**冻结 ABI**。改动本文件而不动真源，
// 会被 scripts/verify/check-channel-abi.sh 拦下。
#![allow(dead_code)]

// ---- 真源标识 ----
pub const REGISTRY_VERSION: &str = "1.0.0";
pub const MAGIC_TEXT: &str = "CYTHSEC1";
pub const MAGIC_LEN: usize = 8;
pub const MAGIC: [u8; MAGIC_LEN] = [0x43, 0x59, 0x54, 0x48, 0x53, 0x45, 0x43, 0x31];
/// 魔数的 BE 解读值，仅用于日志与诊断打印（比较一律走字节，避免字节序歧义）。
pub const MAGIC_BE: u64 = 0x4359544853454331;

// ---- 通道常量 ----
pub const ABI_VERSION: u32 = 1;
pub const HEADER_REGION_SIZE: u32 = 4096;
pub const DESCRIPTOR_STEP: u32 = 64;
pub const REGION_ALIGNMENT: u32 = 4096;
pub const DEFAULT_SLOT_COUNT: u32 = 1024;
pub const DEFAULT_SLOT_SIZE: u32 = 2048;
pub const MIN_SLOT_COUNT: u32 = 2;
pub const MAX_SLOT_COUNT: u32 = 1048576;
pub const MIN_SLOT_SIZE: u32 = 64;
pub const MAX_SLOT_SIZE: u32 = 65536;

// ---- 字段偏移 ----
pub mod header_off {
    pub const MAGIC: usize = 0;
    pub const ABI_VERSION: usize = 8;
    pub const HEADER_SIZE: usize = 12;
    pub const DESC_OFF: usize = 16;
    pub const DATA_OFF: usize = 20;
    pub const SLOT_COUNT: usize = 24;
    pub const SLOT_SIZE: usize = 28;
    pub const FLAGS: usize = 32;
    pub const RESERVED0: usize = 36;
    pub const HEAD: usize = 40;
    pub const TAIL: usize = 48;
    pub const PUBLISHED: usize = 56;
    pub const CONSUMED: usize = 64;
    pub const DROPPED: usize = 72;
    pub const FULL_EVENTS: usize = 80;
    pub const CREATED_NS: usize = 88;
    pub const PRODUCER_PID: usize = 96;
    pub const CONSUMER_PID: usize = 100;
    pub const RESERVED1: usize = 104;
    pub const RESERVED2: usize = 112;
    pub const RESERVED3: usize = 120;
}
pub mod desc_off {
    pub const SEQ: usize = 0;
    pub const TIMESTAMP_NS: usize = 8;
    pub const CAPLEN: usize = 16;
    pub const WIRELEN: usize = 20;
    pub const IFINDEX: usize = 24;
    pub const DATA_OFF: usize = 28;
    pub const FLAGS: usize = 32;
    pub const RESERVED0: usize = 36;
    pub const RESERVED1: usize = 40;
    pub const RESERVED2: usize = 48;
    pub const RESERVED3: usize = 56;
}

// ---- 描述符 flags 位 ----
pub mod flag {
    /// 截断捕获（caplen < wirelen）
    pub const TRUNCATED: u32 = 1 << 0;
    /// 含 802.1Q / QinQ VLAN 标签
    pub const VLAN_TAGGED: u32 = 1 << 1;
    /// IPv6 报文
    pub const IPV6: u32 = 1 << 2;
    /// 合成报文（非真实抓包，供测试）
    pub const SYNTHETIC: u32 = 1 << 3;
}

// ---- 冻结结构体 ----
// 注意：`#[repr(C)]` 是硬要求 —— 默认 repr 的字段顺序由编译器决定，
// 与 C++ 端不保证一致。尺寸与偏移由 const 断言在编译期固定。

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelHeader {
    pub magic: [u8; 8],    // +0    魔数 ASCII，未初始化区域全零
    pub abi_version: u32,  // +8    ABI 版本，attach 期强校验
    pub header_size: u32,  // +12   头部区字节数（含预留），attach 期强校验
    pub desc_off: u32,     // +16   描述符区相对区域起点偏移
    pub data_off: u32,     // +20   数据区相对区域起点偏移
    pub slot_count: u32,   // +24   槽位数量（2 的幂非必需，但建议）
    pub slot_size: u32,    // +28   单槽容量（字节）
    pub flags: u32,        // +32   通道级标志位
    pub reserved0: u32,    // +36   预留
    pub head: u64,         // +40   生产者已发布总数，单调递增（不回绕）
    pub tail: u64,         // +48   消费者已消费总数，单调递增（不回绕）
    pub published: u64,    // +56   生产者累计成功发布（含已被消费）
    pub consumed: u64,     // +64   消费者累计成功消费
    pub dropped: u64,      // +72   生产者因环满/超长而丢弃的报文数
    pub full_events: u64,  // +80   生产者遇到环满的次数（非丢包数）
    pub created_ns: u64,   // +88   区域创建时间（epoch 纳秒）
    pub producer_pid: u32, // +96   生产者 pid，供排障识别残留进程
    pub consumer_pid: u32, // +100  消费者 pid，供排障识别残留进程
    pub reserved1: u64,    // +104  预留
    pub reserved2: u64,    // +112  预留
    pub reserved3: u64,    // +120  预留
}

// 编译期断言：字段偏移与结构体尺寸必须与真源一致。
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, magic) == 0,
    "ChannelHeader.magic 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, abi_version) == 8,
    "ChannelHeader.abi_version 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, header_size) == 12,
    "ChannelHeader.header_size 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, desc_off) == 16,
    "ChannelHeader.desc_off 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, data_off) == 20,
    "ChannelHeader.data_off 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, slot_count) == 24,
    "ChannelHeader.slot_count 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, slot_size) == 28,
    "ChannelHeader.slot_size 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, flags) == 32,
    "ChannelHeader.flags 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, reserved0) == 36,
    "ChannelHeader.reserved0 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, head) == 40,
    "ChannelHeader.head 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, tail) == 48,
    "ChannelHeader.tail 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, published) == 56,
    "ChannelHeader.published 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, consumed) == 64,
    "ChannelHeader.consumed 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, dropped) == 72,
    "ChannelHeader.dropped 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, full_events) == 80,
    "ChannelHeader.full_events 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, created_ns) == 88,
    "ChannelHeader.created_ns 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, producer_pid) == 96,
    "ChannelHeader.producer_pid 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, consumer_pid) == 100,
    "ChannelHeader.consumer_pid 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, reserved1) == 104,
    "ChannelHeader.reserved1 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, reserved2) == 112,
    "ChannelHeader.reserved2 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(ChannelHeader, reserved3) == 120,
    "ChannelHeader.reserved3 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::size_of::<ChannelHeader>() == 128,
    "ChannelHeader 尺寸与通道 ABI 不符"
);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketDescriptor {
    pub seq: u64,          // +0    全局单调序号，槽位索引 = seq % slot_count
    pub timestamp_ns: i64, // +8    抓包时间戳（epoch 纳秒）
    pub caplen: u32,       // +16   实际写入数据区的字节数
    pub wirelen: u32,      // +20   线上原始长度，caplen<wirelen 表示截断捕获
    pub ifindex: u32,      // +24   接收接口索引（pcap 文件后端为 0）
    pub data_off: u32,     // +28   数据相对数据区起点偏移
    pub flags: u32,        // +32   报文级标志位（见 flags 段）
    pub reserved0: u32,    // +36   预留
    pub reserved1: u64,    // +40   预留
    pub reserved2: u64,    // +48   预留
    pub reserved3: u64,    // +56   预留
}

// 编译期断言：字段偏移与结构体尺寸必须与真源一致。
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, seq) == 0,
    "PacketDescriptor.seq 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, timestamp_ns) == 8,
    "PacketDescriptor.timestamp_ns 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, caplen) == 16,
    "PacketDescriptor.caplen 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, wirelen) == 20,
    "PacketDescriptor.wirelen 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, ifindex) == 24,
    "PacketDescriptor.ifindex 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, data_off) == 28,
    "PacketDescriptor.data_off 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, flags) == 32,
    "PacketDescriptor.flags 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, reserved0) == 36,
    "PacketDescriptor.reserved0 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, reserved1) == 40,
    "PacketDescriptor.reserved1 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, reserved2) == 48,
    "PacketDescriptor.reserved2 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::offset_of!(PacketDescriptor, reserved3) == 56,
    "PacketDescriptor.reserved3 偏移与通道 ABI 不符"
);
const _: () = assert!(
    std::mem::size_of::<PacketDescriptor>() == 64,
    "PacketDescriptor 尺寸与通道 ABI 不符"
);

// ---- 布局计算（由真源生成，两端必须用同一套算术）----
// desc_off = align_up(header_region_size, region_alignment)
// data_off = desc_off + slot_count * descriptor_step
// required = data_off + slot_count * slot_size
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelLayout {
    pub desc_off: u32,
    pub data_off: u32,
    pub required: u64,
}

/// 布局计算失败的原因。变体自带诊断所需字段，可直接喂给 `diag` 模块。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    SlotCountOutOfRange {
        value: u32,
        min_value: u32,
        max_value: u32,
    },
    SlotSizeOutOfRange {
        value: u32,
        min_value: u32,
        max_value: u32,
    },
    SizeOverflow {
        slot_count: u32,
        slot_size: u32,
    },
}

/// 32 位可表示范围上限：区域各偏移都是 u32，超出的布局无法用现有头部表达。
pub const OVERFLOW_LIMIT: u64 = 0xFFFF_FFFF;

/// 计算通道布局。失败时不返回部分结果。
pub fn channel_layout(slot_count: u32, slot_size: u32) -> Result<ChannelLayout, LayoutError> {
    if slot_count < MIN_SLOT_COUNT || slot_count > MAX_SLOT_COUNT {
        return Err(LayoutError::SlotCountOutOfRange {
            value: slot_count,
            min_value: MIN_SLOT_COUNT,
            max_value: MAX_SLOT_COUNT,
        });
    }
    if slot_size < MIN_SLOT_SIZE || slot_size > MAX_SLOT_SIZE {
        return Err(LayoutError::SlotSizeOutOfRange {
            value: slot_size,
            min_value: MIN_SLOT_SIZE,
            max_value: MAX_SLOT_SIZE,
        });
    }
    let desc_off = ((HEADER_REGION_SIZE as u64 + REGION_ALIGNMENT as u64 - 1)
        / REGION_ALIGNMENT as u64)
        * REGION_ALIGNMENT as u64;
    let data_off = desc_off + slot_count as u64 * DESCRIPTOR_STEP as u64;
    let required = data_off + slot_count as u64 * slot_size as u64;
    if data_off > OVERFLOW_LIMIT || required > OVERFLOW_LIMIT {
        return Err(LayoutError::SizeOverflow {
            slot_count,
            slot_size,
        });
    }
    Ok(ChannelLayout {
        desc_off: desc_off as u32,
        data_off: data_off as u32,
        required,
    })
}

// ---- 诊断严重度 ----
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Error,
}

impl Severity {
    /// 严重度字符串：与 C++ 端 to_string() 一致，是 parity 校验的一部分。
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

// ---- 诊断（码 + 文案均由真源生成，保证两端逐字一致）----
pub mod diag {
    use super::Severity;
    use std::fmt;

    pub const CHANUNINITIALIZED_CODE: &str = "chan.uninitialized";
    pub const CHANMAGICMISMATCH_CODE: &str = "chan.magic_mismatch";
    pub const CHANABIVERSIONMISMATCH_CODE: &str = "chan.abi_version_mismatch";
    pub const CHANHEADERSIZEMISMATCH_CODE: &str = "chan.header_size_mismatch";
    pub const CHANLAYOUTMISMATCH_CODE: &str = "chan.layout_mismatch";
    pub const CHANSLOTCOUNTOUTOFRANGE_CODE: &str = "chan.slot_count_out_of_range";
    pub const CHANSLOTSIZEOUTOFRANGE_CODE: &str = "chan.slot_size_out_of_range";
    pub const CHANSIZEOVERFLOW_CODE: &str = "chan.size_overflow";
    pub const CHANREGIONTOOSMALL_CODE: &str = "chan.region_too_small";
    pub const CHANBASENOTALIGNED_CODE: &str = "chan.base_not_aligned";
    pub const CHANIOERROR_CODE: &str = "chan.io_error";
    pub const CHANTRUNCATEDPACKET_CODE: &str = "chan.truncated_packet";
    pub const CHANTAILAHEADOFHEAD_CODE: &str = "chan.tail_ahead_of_head";

    /// chan.uninitialized
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanUninitialized {
        pub local_magic: u64,
        pub remote_magic: u64,
    }

    impl ChanUninitialized {
        pub const CODE: &'static str = CHANUNINITIALIZED_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanUninitialized {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道区域未初始化：本端期望魔数 0x{:016x}，对端为 0x{:016x}；该区域可能尚未创建，或已被清零/截断（截断文件同样呈现全零）",
                self.local_magic,
                self.remote_magic,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chanuninitialized_sample() -> String {
        ChanUninitialized {
            local_magic: 4853002743079846705,
            remote_magic: 0,
        }
        .to_string()
    }

    /// chan.magic_mismatch
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanMagicMismatch {
        pub local_magic: u64,
        pub remote_magic: u64,
    }

    impl ChanMagicMismatch {
        pub const CODE: &'static str = CHANMAGICMISMATCH_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanMagicMismatch {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道魔数不匹配：本端 0x{:016x}，对端 0x{:016x}；该区域不是 CythSec 通道区域，或两端魔数约定不一致",
                self.local_magic,
                self.remote_magic,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chanmagicmismatch_sample() -> String {
        ChanMagicMismatch {
            local_magic: 4853002743079846705,
            remote_magic: 3549757155296172355,
        }
        .to_string()
    }

    /// chan.abi_version_mismatch
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanAbiVersionMismatch {
        pub local: u32,
        pub remote: u32,
    }

    impl ChanAbiVersionMismatch {
        pub const CODE: &'static str = CHANABIVERSIONMISMATCH_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanAbiVersionMismatch {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道 ABI 版本不匹配：本端 v{}，对端 v{}；契约语义已变更，两端必须同时升级（禁止跨版本共享区域）",
                self.local,
                self.remote,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chanabiversionmismatch_sample() -> String {
        ChanAbiVersionMismatch {
            local: 1,
            remote: 2,
        }
        .to_string()
    }

    /// chan.header_size_mismatch
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanHeaderSizeMismatch {
        pub local: u32,
        pub remote: u32,
    }

    impl ChanHeaderSizeMismatch {
        pub const CODE: &'static str = CHANHEADERSIZEMISMATCH_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanHeaderSizeMismatch {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道头部尺寸不匹配：本端 {} 字节，对端 {} 字节；描述符区与数据区偏移将随之错位",
                self.local, self.remote,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chanheadersizemismatch_sample() -> String {
        ChanHeaderSizeMismatch {
            local: 4096,
            remote: 2048,
        }
        .to_string()
    }

    /// chan.layout_mismatch
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanLayoutMismatch {
        pub local_desc: u32,
        pub remote_desc: u32,
        pub local_data: u32,
        pub remote_data: u32,
    }

    impl ChanLayoutMismatch {
        pub const CODE: &'static str = CHANLAYOUTMISMATCH_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanLayoutMismatch {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道布局偏移不一致：描述符区 本端 {} 对端 {}；数据区 本端 {} 对端 {}",
                self.local_desc, self.remote_desc, self.local_data, self.remote_data,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chanlayoutmismatch_sample() -> String {
        ChanLayoutMismatch {
            local_desc: 4096,
            remote_desc: 4128,
            local_data: 69632,
            remote_data: 69664,
        }
        .to_string()
    }

    /// chan.slot_count_out_of_range
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanSlotCountOutOfRange {
        pub value: u32,
        pub min_value: u32,
        pub max_value: u32,
    }

    impl ChanSlotCountOutOfRange {
        pub const CODE: &'static str = CHANSLOTCOUNTOUTOFRANGE_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanSlotCountOutOfRange {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道槽位数越界：请求 {}，允许区间 [{}, {}]",
                self.value, self.min_value, self.max_value,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chanslotcountoutofrange_sample() -> String {
        ChanSlotCountOutOfRange {
            value: 2097152,
            min_value: 2,
            max_value: 1048576,
        }
        .to_string()
    }

    /// chan.slot_size_out_of_range
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanSlotSizeOutOfRange {
        pub value: u32,
        pub min_value: u32,
        pub max_value: u32,
    }

    impl ChanSlotSizeOutOfRange {
        pub const CODE: &'static str = CHANSLOTSIZEOUTOFRANGE_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanSlotSizeOutOfRange {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道槽容量越界：请求 {} 字节，允许区间 [{}, {}]",
                self.value, self.min_value, self.max_value,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chanslotsizeoutofrange_sample() -> String {
        ChanSlotSizeOutOfRange {
            value: 131072,
            min_value: 64,
            max_value: 65536,
        }
        .to_string()
    }

    /// chan.size_overflow
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanSizeOverflow {
        pub slot_count: u32,
        pub slot_size: u32,
    }

    impl ChanSizeOverflow {
        pub const CODE: &'static str = CHANSIZEOVERFLOW_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanSizeOverflow {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道区域尺寸计算溢出：槽位数 {} × 槽容量 {} 超出可表示范围",
                self.slot_count, self.slot_size,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chansizeoverflow_sample() -> String {
        ChanSizeOverflow {
            slot_count: 1048576,
            slot_size: 65536,
        }
        .to_string()
    }

    /// chan.region_too_small
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanRegionTooSmall {
        pub required: u64,
        pub actual: u64,
    }

    impl ChanRegionTooSmall {
        pub const CODE: &'static str = CHANREGIONTOOSMALL_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanRegionTooSmall {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道区域过小：需要 {} 字节，实际 {} 字节；请用匹配的槽位配置创建或检查文件是否被截断",
                self.required,
                self.actual,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chanregiontoosmall_sample() -> String {
        ChanRegionTooSmall {
            required: 2166784,
            actual: 4096,
        }
        .to_string()
    }

    /// chan.base_not_aligned
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanBaseNotAligned {
        pub required: u32,
        pub remainder: u64,
    }

    impl ChanBaseNotAligned {
        pub const CODE: &'static str = CHANBASENOTALIGNED_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanBaseNotAligned {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道区域基址未对齐：要求 {} 字节对齐，实际余数 {}；未对齐会破坏缓存行隔离并可能触发未对齐原子访问",
                self.required,
                self.remainder,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chanbasenotaligned_sample() -> String {
        ChanBaseNotAligned {
            required: 4096,
            remainder: 24,
        }
        .to_string()
    }

    /// chan.io_error
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ChanIoError {
        pub detail: String,
        pub err_no: u32,
        pub path: String,
    }

    impl ChanIoError {
        pub const CODE: &'static str = CHANIOERROR_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanIoError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "通道区域 I/O 失败：{}（errno={}，路径={}）",
                self.detail, self.err_no, self.path,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chanioerror_sample() -> String {
        ChanIoError {
            detail: "mmap 失败".to_string(),
            err_no: 13,
            path: "/run/cythsec/chan0".to_string(),
        }
        .to_string()
    }

    /// chan.truncated_packet
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanTruncatedPacket {
        pub caplen: u32,
        pub slot_size: u32,
    }

    impl ChanTruncatedPacket {
        pub const CODE: &'static str = CHANTRUNCATEDPACKET_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanTruncatedPacket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "报文长度 {} 超过槽容量 {}：回放端应开启截断或调大 --slot-size",
                self.caplen, self.slot_size,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chantruncatedpacket_sample() -> String {
        ChanTruncatedPacket {
            caplen: 9000,
            slot_size: 2048,
        }
        .to_string()
    }

    /// chan.tail_ahead_of_head
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChanTailAheadOfHead {
        pub tail: u64,
        pub head: u64,
    }

    impl ChanTailAheadOfHead {
        pub const CODE: &'static str = CHANTAILAHEADOFHEAD_CODE;
        pub const SEVERITY: Severity = Severity::Error;
    }

    impl fmt::Display for ChanTailAheadOfHead {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "消费位置越过生产位置：消费位置 {} 大于生产位置 {}；此时「待消费数」恒为 0，消费端会一直报告无数据，而报文在背后持续堆积——不报错、不崩溃，只是全部静默丢弃。成因通常是区域被上一版进程以不同槽位配置写过、或该区域被手工清零过一半",
                self.tail,
                self.head,
            )
        }
    }

    /// parity 校验用的确定性样本（取值亦来自真源）。
    pub fn chantailaheadofhead_sample() -> String {
        ChanTailAheadOfHead { tail: 128, head: 0 }.to_string()
    }
} // pub mod diag
