// channel/region.rs —— 通道区域映射与 attach 期校验（CYS-PKT-024）。
//
// 本文件只做一件事：把「两端对同一块内存的理解是否一致」变成一个**显式结论**。
// 校验不通过就拒绝启动，绝不放行——因为跨语言偏移错位的表现是读到垃圾而不是崩溃。
//
// mmap 相关 POSIX 符号在本文件内自行声明：项目约定零第三方依赖，不引入 libc crate。
// std 本身已链接 libc，因此这两行声明不会带来新的链接依赖。
// 注意 mmap 的 offset 类型 off_t 在 macOS 与 Linux（64 位）上均为 i64，故此处写 i64。

use std::ffi::c_void;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::abi_gen::{
    channel_layout, diag, header_off, ChannelHeader, ChannelLayout, LayoutError,
    PacketDescriptor, Severity, ABI_VERSION, DESCRIPTOR_STEP, DEFAULT_SLOT_COUNT,
    DEFAULT_SLOT_SIZE, HEADER_REGION_SIZE, MAGIC, MAGIC_BE, MAGIC_LEN, REGION_ALIGNMENT,
};

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const MAP_SHARED: i32 = 0x1;

extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}

/// 区域映射权限。消费端需要写权限（要更新 tail 与 consumed），
/// 只读用于纯检查类工具（只看不改）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionPerm {
    /// 只读映射：适用于巡检、诊断打印。
    ReadOnly,
    /// 读写映射：消费端必须用此权限。
    ReadWrite,
}

/// 通道 attach 失败的原因。
///
/// 每个变体都对应 abi_gen 里一条由真源生成的诊断码与文案，因此本类型在显示时
/// 与 C++ 端输出逐字一致 —— 排障的人不该因为两侧措辞不同而以为遇到两个问题。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachError {
    Io {
        path: PathBuf,
        err_no: i32,
        detail: String,
    },
    Uninitialized {
        local_magic: u64,
        remote_magic: u64,
    },
    MagicMismatch {
        local_magic: u64,
        remote_magic: u64,
    },
    AbiVersionMismatch {
        local: u32,
        remote: u32,
    },
    HeaderSizeMismatch {
        local: u32,
        remote: u32,
    },
    LayoutMismatch {
        local_desc: u32,
        remote_desc: u32,
        local_data: u32,
        remote_data: u32,
    },
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
    RegionTooSmall {
        required: u64,
        actual: u64,
    },
    BaseNotAligned {
        required: u32,
        remainder: u64,
    },
    /// 消费位置越过生产位置。
    ///
    /// 单列为一种失败，是因为它的表现形式极具欺骗性：`head - tail` 用饱和减法恒为 0，
    /// 于是消费端**永远报告「当前无数据」**，既不报错也不阻塞，而生产端在背后持续丢包。
    /// 若不显式检查，一个「跑得好好的、就是没有流量」的采集端可以就这样挂上几天。
    TailAheadOfHead {
        tail: u64,
        head: u64,
    },
}

impl AttachError {
    /// 稳定诊断码，与 C++ 端同名同值。
    pub fn code(&self) -> &'static str {
        match self {
            AttachError::Io { .. } => diag::ChanIoError::CODE,
            AttachError::Uninitialized { .. } => diag::ChanUninitialized::CODE,
            AttachError::MagicMismatch { .. } => diag::ChanMagicMismatch::CODE,
            AttachError::AbiVersionMismatch { .. } => diag::ChanAbiVersionMismatch::CODE,
            AttachError::HeaderSizeMismatch { .. } => diag::ChanHeaderSizeMismatch::CODE,
            AttachError::LayoutMismatch { .. } => diag::ChanLayoutMismatch::CODE,
            AttachError::SlotCountOutOfRange { .. } => diag::ChanSlotCountOutOfRange::CODE,
            AttachError::SlotSizeOutOfRange { .. } => diag::ChanSlotSizeOutOfRange::CODE,
            AttachError::SizeOverflow { .. } => diag::ChanSizeOverflow::CODE,
            AttachError::RegionTooSmall { .. } => diag::ChanRegionTooSmall::CODE,
            AttachError::BaseNotAligned { .. } => diag::ChanBaseNotAligned::CODE,
            AttachError::TailAheadOfHead { .. } => diag::ChanTailAheadOfHead::CODE,
        }
    }

    /// 严重度。全部为 error：这些情形下「继续跑」只会产出错误结论。
    pub fn severity(&self) -> Severity {
        Severity::Error
    }

    /// 用当前区域路径替换 Io 变体里的路径占位，便于在调用处补上真实路径。
    fn with_path(self, path: &Path) -> AttachError {
        match self {
            AttachError::Io { err_no, detail, .. } => AttachError::Io {
                path: path.to_path_buf(),
                err_no,
                detail,
            },
            other => other,
        }
    }
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            AttachError::Io { path, err_no, detail } => diag::ChanIoError {
                detail: detail.clone(),
                err_no: *err_no as u32,
                path: path.display().to_string(),
            }
            .to_string(),
            AttachError::Uninitialized { local_magic, remote_magic } => diag::ChanUninitialized {
                local_magic: *local_magic,
                remote_magic: *remote_magic,
            }
            .to_string(),
            AttachError::MagicMismatch { local_magic, remote_magic } => diag::ChanMagicMismatch {
                local_magic: *local_magic,
                remote_magic: *remote_magic,
            }
            .to_string(),
            AttachError::AbiVersionMismatch { local, remote } => diag::ChanAbiVersionMismatch {
                local: *local,
                remote: *remote,
            }
            .to_string(),
            AttachError::HeaderSizeMismatch { local, remote } => diag::ChanHeaderSizeMismatch {
                local: *local,
                remote: *remote,
            }
            .to_string(),
            AttachError::LayoutMismatch {
                local_desc,
                remote_desc,
                local_data,
                remote_data,
            } => diag::ChanLayoutMismatch {
                local_desc: *local_desc,
                remote_desc: *remote_desc,
                local_data: *local_data,
                remote_data: *remote_data,
            }
            .to_string(),
            AttachError::SlotCountOutOfRange { value, min_value, max_value } => {
                diag::ChanSlotCountOutOfRange {
                    value: *value,
                    min_value: *min_value,
                    max_value: *max_value,
                }
                .to_string()
            }
            AttachError::SlotSizeOutOfRange { value, min_value, max_value } => {
                diag::ChanSlotSizeOutOfRange {
                    value: *value,
                    min_value: *min_value,
                    max_value: *max_value,
                }
                .to_string()
            }
            AttachError::SizeOverflow { slot_count, slot_size } => diag::ChanSizeOverflow {
                slot_count: *slot_count,
                slot_size: *slot_size,
            }
            .to_string(),
            AttachError::RegionTooSmall { required, actual } => diag::ChanRegionTooSmall {
                required: *required,
                actual: *actual,
            }
            .to_string(),
            AttachError::BaseNotAligned { required, remainder } => diag::ChanBaseNotAligned {
                required: *required,
                remainder: *remainder,
            }
            .to_string(),
            AttachError::TailAheadOfHead { tail, head } => {
                diag::ChanTailAheadOfHead {
                    tail: *tail,
                    head: *head,
                }
                .to_string()
            }
        };
        f.write_str(&text)
    }
}

impl std::error::Error for AttachError {}

/// 通道统计快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelStats {
    pub head: u64,
    pub tail: u64,
    pub published: u64,
    pub consumed: u64,
    pub dropped: u64,
    pub full_events: u64,
    pub producer_pid: u32,
    pub consumer_pid: u32,
}

impl ChannelStats {
    /// 未被消费的报文数。
    pub fn backlog(&self) -> u64 {
        self.head.saturating_sub(self.tail)
    }
}

/// 已映射的共享区域。Drop 时解除映射。
struct Region {
    base: *mut u8,
    len: usize,
    file: File,
    path: PathBuf,
}

// SAFETY: 区域是一段进程外可见的共享内存，跨线程只读访问是安全的；对 head/tail/计数器的
// 并发修改一律走原子操作（见 Channel::atomic_u64）。裸指针本身不实现 Send/Sync，此处显式
// 声明其可跨线程传递，是为了让「一个线程消费通道」这一常规用法不必包一层 wrapper。
unsafe impl Send for Region {}

impl Region {
    /// 映射文件。`create_len` 为 Some 时先按该长度创建/截断文件。
    fn map(path: &Path, perm: RegionPerm, create_len: Option<u64>) -> Result<Region, AttachError> {
        let mut opts = OpenOptions::new();
        opts.read(true);
        if perm == RegionPerm::ReadWrite {
            opts.write(true);
        }
        if create_len.is_some() {
            opts.create(true).truncate(true);
        }
        let file = opts.open(path).map_err(|e| io_error(path, "open 失败", &e))?;

        if let Some(len) = create_len {
            file.set_len(len).map_err(|e| io_error(path, "set_len 失败", &e))?;
        }

        let len = file
            .metadata()
            .map_err(|e| io_error(path, "stat 失败", &e))?
            .len();
        if len == 0 {
            return Err(AttachError::RegionTooSmall { required: 1, actual: 0 }.with_path(path));
        }

        let mut prot = PROT_READ;
        if perm == RegionPerm::ReadWrite {
            prot |= PROT_WRITE;
        }
        let addr = unsafe {
            mmap(
                ptr::null_mut(),
                len as usize,
                prot,
                MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        // mmap 失败返回 MAP_FAILED，即 (void*)-1。
        if addr as isize == -1 {
            return Err(io_error(path, "mmap 失败", &io::Error::last_os_error()));
        }

        Ok(Region {
            base: addr as *mut u8,
            len: len as usize,
            file,
            path: path.to_path_buf(),
        })
    }

    fn len(&self) -> u64 {
        self.len as u64
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe {
            munmap(self.base as *mut c_void, self.len);
        }
    }
}

fn io_error(path: &Path, detail: &str, e: &io::Error) -> AttachError {
    AttachError::Io {
        path: path.to_path_buf(),
        // errno 可能是 None（纯 std 构造的错误），此时用 0 表示「无系统错误码」。
        err_no: e.raw_os_error().unwrap_or(0),
        detail: detail.to_string(),
    }
}

/// 已 attach 的通道：持有映射、已校验的头部快照与布局。
pub struct Channel {
    region: Region,
    header: ChannelHeader,
    layout: ChannelLayout,
}

impl Channel {
    /// 以默认配置（`DEFAULT_SLOT_COUNT` × `DEFAULT_SLOT_SIZE`）为期望值 attach。
    pub fn attach(path: &Path) -> Result<Channel, AttachError> {
        Self::attach_with(path, RegionPerm::ReadWrite, None)
    }

    /// attach 并校验槽位配置确为期望值。
    ///
    /// 存在的理由：部署配置里写着「chan0 是 1024 × 2048」，而区域里可能是上一版配置
    /// 创建后未清理的旧区域。此时两端布局不同，读到的每个字段都无意义——
    /// 必须由配置层面的期望值把它拦下来，而不是靠运气。
    pub fn attach_expect(
        path: &Path,
        slot_count: u32,
        slot_size: u32,
        perm: RegionPerm,
    ) -> Result<Channel, AttachError> {
        Self::attach_with(path, perm, Some((slot_count, slot_size)))
    }

    fn attach_with(
        path: &Path,
        perm: RegionPerm,
        expected: Option<(u32, u32)>,
    ) -> Result<Channel, AttachError> {
        let region = Region::map(path, perm, None)?;
        let base = region.base as usize;

        // 头部必须用非对齐读：对齐检查本身要在读到头部之后才能做，
        // 因此这里不能假定对齐（否则在未对齐区域上是 UB）。
        let header: ChannelHeader = unsafe { ptr::read_unaligned(region.base as *const ChannelHeader) };

        if let Some((exp_count, exp_size)) = expected {
            if header.slot_count != exp_count {
                return Err(AttachError::SlotCountMismatch {
                    local: exp_count,
                    remote: header.slot_count,
                });
            }
            if header.slot_size != exp_size {
                return Err(AttachError::SlotSizeMismatch {
                    local: exp_size,
                    remote: header.slot_size,
                });
            }
        }

        let layout = validate(&header, base, region.len())?;
        Ok(Channel { region, header, layout })
    }

    /// 创建并 attach 一个全新区域。
    ///
    /// 生产端的创建路径在 C++（packet-engine）；本方法供 Rust 侧测试与自检使用，
    /// 它同样走完整校验，因此不会掩盖两端差异。
    pub fn create(path: &Path, slot_count: u32, slot_size: u32) -> Result<Channel, AttachError> {
        let layout = channel_layout(slot_count, slot_size).map_err(layout_error_to_attach)?;
        let region = Region::map(path, RegionPerm::ReadWrite, Some(layout.required))?;

        let created_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let header = ChannelHeader {
            magic: MAGIC,
            abi_version: ABI_VERSION,
            header_size: HEADER_REGION_SIZE,
            desc_off: layout.desc_off,
            data_off: layout.data_off,
            slot_count,
            slot_size,
            flags: 0,
            reserved0: 0,
            head: 0,
            tail: 0,
            published: 0,
            consumed: 0,
            dropped: 0,
            full_events: 0,
            created_ns,
            producer_pid: std::process::id(),
            consumer_pid: 0,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        };
        unsafe {
            ptr::write_unaligned(region.base as *mut ChannelHeader, header);
        }
        // 数据区清零，避免未初始化槽位被误当作有效描述符（诊断里也依赖「全零=未创建」）。
        unsafe {
            ptr::write_bytes(
                region.base.add(layout.data_off as usize),
                0,
                (layout.required - u64::from(layout.data_off)) as usize,
            );
        }

        let mut ch = Channel { region, header, layout };
        ch.refresh_header();
        // 对自己刚写入的头部再跑一遍完整校验：这不只是形式主义——校验逻辑本身若与写入
        // 逻辑不一致，会在这里立刻暴露，而不是等到消费端 attach 时才以一个难解的
        // 布局诊断出现。
        let verified = validate(&ch.header, ch.region.base as usize, ch.region.len())?;
        debug_assert_eq!(verified, layout, "创建后校验得到的布局应与计算结果一致");
        Ok(ch)
    }

    /// 头部快照（attach 时或最近一次 refresh 时读取）。
    pub fn header(&self) -> &ChannelHeader {
        &self.header
    }

    /// 布局（本端常量算出的结果，已与对端记录值校验一致）。
    pub fn layout(&self) -> ChannelLayout {
        self.layout
    }

    /// 该通道允许消费的槽位数。
    pub fn slot_count(&self) -> u32 {
        self.header.slot_count
    }

    /// 槽容量（字节）。
    pub fn slot_size(&self) -> u32 {
        self.header.slot_size
    }

    /// 区域路径。
    pub fn path(&self) -> &Path {
        &self.region.path
    }

    /// 重新读取头部快照与统计。
    pub fn refresh_header(&mut self) {
        self.header = unsafe { ptr::read_unaligned(self.region.base as *const ChannelHeader) };
    }

    /// 以区域**当前**内容重跑完整校验，并追加运行期一致性检查。
    ///
    /// 与 attach 期校验的区别在用途：attach 校验回答「这块内存是不是通道」，
    /// 而本方法回答「它现在还正常吗」——共享区域是外部可写的，一次误操作（手工清零、
    /// 旧版本进程写入、外部工具改配置后重建）会让原本正确的通道在运行中变得不一致。
    /// 这类变化不会自己报错，必须主动查。
    pub fn revalidate(&mut self) -> Result<(), AttachError> {
        self.refresh_header();
        let layout = validate(&self.header, self.region.base as usize, self.region.len())?;
        let head = self.load_u64(header_off::HEAD).unwrap_or(0);
        let tail = self.load_u64(header_off::TAIL).unwrap_or(0);
        if tail > head {
            return Err(AttachError::TailAheadOfHead { tail, head });
        }
        // 布局是 attach 时定下的，重校验若得出不同结果，说明头部在运行中被改过。
        if layout != self.layout {
            return Err(AttachError::LayoutMismatch {
                local_desc: self.layout.desc_off,
                remote_desc: layout.desc_off,
                local_data: self.layout.data_off,
                remote_data: layout.data_off,
            });
        }
        Ok(())
    }

    /// 读取统计（全部字段均从区域原子读取，可安全地在运行中调用）。
    ///
    /// 注意 pid 也必须从区域读，不能用 `self.header` 快照：快照是 attach（或上次
    /// refresh）时的值，而 `consumer_pid` 恰恰是**本端在 attach 之后**才写进去的。
    /// 用快照会稳定地返回 0，于是「谁在消费这个通道」这个排障时最该看到的信息永远为空。
    pub fn stats(&self) -> ChannelStats {
        ChannelStats {
            head: self.load_u64(header_off::HEAD).unwrap_or(0),
            tail: self.load_u64(header_off::TAIL).unwrap_or(0),
            published: self.load_u64(header_off::PUBLISHED).unwrap_or(0),
            consumed: self.load_u64(header_off::CONSUMED).unwrap_or(0),
            dropped: self.load_u64(header_off::DROPPED).unwrap_or(0),
            full_events: self.load_u64(header_off::FULL_EVENTS).unwrap_or(0),
            producer_pid: self.load_u32(header_off::PRODUCER_PID).unwrap_or(0),
            consumer_pid: self.load_u32(header_off::CONSUMER_PID).unwrap_or(0),
        }
    }

    // ---- 以下为消费端内部原语。集中在此，使内存序只有一处定义。----

    /// 取头部内某个 u64 字段的原子视图。
    ///
    /// 对齐由 attach 期校验保证（区域基址 4096 对齐 + 字段偏移 8 的倍数）。
    pub(crate) fn atomic_u64(&self, offset: usize) -> &AtomicU64 {
        debug_assert!(offset % 8 == 0, "u64 字段偏移必须 8 字节对齐");
        // SAFETY: 见文档注释；AtomicU64 与 u64 布局一致。
        unsafe { AtomicU64::from_ptr(self.region.base.add(offset) as *mut u64) }
    }

    /// 取头部内某个 u32 字段的原子视图（用于写 consumer_pid 这类 4 字节字段）。
    pub(crate) fn atomic_u32(&self, offset: usize) -> &AtomicU32 {
        debug_assert!(offset % 4 == 0, "u32 字段偏移必须 4 字节对齐");
        unsafe { AtomicU32::from_ptr(self.region.base.add(offset) as *mut u32) }
    }

    fn load_u64(&self, offset: usize) -> Option<u64> {
        if offset + 8 > HEADER_REGION_SIZE as usize {
            return None;
        }
        Some(self.atomic_u64(offset).load(Ordering::Acquire))
    }

    fn load_u32(&self, offset: usize) -> Option<u32> {
        if offset + 4 > HEADER_REGION_SIZE as usize {
            return None;
        }
        Some(self.atomic_u32(offset).load(Ordering::Relaxed))
    }

    /// 生产者已发布计数（Acquire 读）。
    pub(crate) fn load_head(&self) -> u64 {
        self.atomic_u64(header_off::HEAD).load(Ordering::Acquire)
    }

    /// 消费者已消费计数（本地缓存值，仅供校验用）。
    pub(crate) fn load_tail(&self) -> u64 {
        self.atomic_u64(header_off::TAIL).load(Ordering::Acquire)
    }

    /// 写入消费者已消费计数（Release 写，必须先于它把描述符内容读完）。
    pub(crate) fn store_tail(&self, v: u64) {
        self.atomic_u64(header_off::TAIL)
            .store(v, Ordering::Release);
    }

    /// 累加已消费计数。
    pub(crate) fn add_consumed(&self, n: u64) {
        self.atomic_u64(header_off::CONSUMED)
            .fetch_add(n, Ordering::Release);
    }

    /// 记录消费端 pid，供排障识别残留进程。
    pub(crate) fn set_consumer_pid(&self, pid: u32) {
        self.atomic_u32(header_off::CONSUMER_PID)
            .store(pid, Ordering::Release);
    }

    /// 读第 idx 个描述符。
    ///
    /// 用对齐读：attach 期已确认区域基址按 `REGION_ALIGNMENT` 对齐、且 desc_off 与
    /// DESCRIPTOR_STEP 均为其倍数，因此 `base + desc_off + idx*step` 必然 8 字节对齐。
    pub(crate) fn descriptor(&self, idx: u64) -> PacketDescriptor {
        let off = self.layout.desc_off as usize + (idx as usize) * (DESCRIPTOR_STEP as usize);
        debug_assert!(off + DESCRIPTOR_STEP as usize <= self.layout.data_off as usize);
        // SAFETY: 见文档注释；PacketDescriptor 是 #[repr(C)] 的 POD，尺寸由 const 断言固定。
        unsafe { ptr::read(self.region.base.add(off) as *const PacketDescriptor) }
    }

    /// 取某描述符指向的报文数据切片。
    ///
    /// 偏移取自描述符自身的 `data_off`（真源定义：相对数据区起点的偏移），而非按
    /// `seq % slot_count` 反推——后者只是生产端的惯用摆法，把它当契约会把「数据摆在哪」
    /// 与「槽位索引怎么算」耦合成一个不可分开修改的东西。
    ///
    /// 越界由调用方先行拒绝（见 consumer）：这里只做契约内的切片。
    pub(crate) fn slot_slice(&self, desc: &PacketDescriptor) -> &[u8] {
        let start = self.layout.data_off as usize + desc.data_off as usize;
        // SAFETY: 调用方保证 desc.data_off + caplen <= slot_size 且落在数据区内。
        unsafe { slice::from_raw_parts(self.region.base.add(start), desc.caplen as usize) }
    }

    /// 整块区域的原始可变切片。
    ///
    /// 仅用于 crate 内测试：测试需要一个「扮演 C++ 生产端」的写入路径，才能验证消费端
    /// 与 attach 校验。**刻意限定 `cfg(test)` 而非暴露为 API**——生产中生产端只有 C++
    /// 一个实现，若在此提供正式写入接口，会让人误以为存在一个 Rust 生产端，从而使
    /// 「两端是否真的一致」这个核心问题失去唯一答案。
    #[cfg(test)]
    pub(crate) fn test_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: 测试为单线程顺序访问，且不与其他借用重叠。
        unsafe { slice::from_raw_parts_mut(self.region.base, self.region.len) }
    }
}

impl fmt::Debug for Channel {
    /// 手写而非 derive：字段里有裸指针与映射长度，派生的 Debug 打印不出任何有用信息
    /// （地址每次运行都不同，无法用于比对）。排障真正要看的是「这个通道被理解成什么」——
    /// 即头部快照与依本端常量算出的布局，而这两者恰好就是校验的产物。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("path", &self.region.path)
            .field("region_len", &self.region.len)
            .field("magic", &String::from_utf8_lossy(&self.header.magic))
            .field("abi_version", &self.header.abi_version)
            .field("header_size", &self.header.header_size)
            .field(
                "slots",
                &format_args!("{} x {}", self.header.slot_count, self.header.slot_size),
            )
            .field("desc_off", &self.layout.desc_off)
            .field("data_off", &self.layout.data_off)
            .field("required", &self.layout.required)
            .finish()
    }
}

fn layout_error_to_attach(e: LayoutError) -> AttachError {
    match e {
        LayoutError::SlotCountOutOfRange { value, min_value, max_value } => {
            AttachError::SlotCountOutOfRange { value, min_value, max_value }
        }
        LayoutError::SlotSizeOutOfRange { value, min_value, max_value } => {
            AttachError::SlotSizeOutOfRange { value, min_value, max_value }
        }
        LayoutError::SizeOverflow { slot_count, slot_size } => {
            AttachError::SizeOverflow { slot_count, slot_size }
        }
    }
}

/// attach 期校验。顺序是刻意安排的：从「这块内存根本不是通道」到「通道对但布局不符」，
/// 先排除粗粒度问题，避免用「布局不符」这类细节诊断掩盖「拿错文件」这种根因。
fn validate(header: &ChannelHeader, base: usize, file_len: u64) -> Result<ChannelLayout, AttachError> {
    // 1. 全零魔数单独判定：文件被截断/刚创建未初始化时同样呈现全零，
    //    与「魔数不对」是两种完全不同的处置方向，不该合并。
    if header.magic == [0u8; MAGIC_LEN] {
        return Err(AttachError::Uninitialized {
            local_magic: MAGIC_BE,
            remote_magic: 0,
        });
    }
    let remote_magic = u64::from_be_bytes(header.magic);
    if header.magic != MAGIC {
        return Err(AttachError::MagicMismatch {
            local_magic: MAGIC_BE,
            remote_magic,
        });
    }

    // 2. 版本与头部尺寸：版本变了则语义整体不可比，头尺寸变了则后面所有偏移都无意义。
    if header.abi_version != ABI_VERSION {
        return Err(AttachError::AbiVersionMismatch {
            local: ABI_VERSION,
            remote: header.abi_version,
        });
    }
    if header.header_size != HEADER_REGION_SIZE {
        return Err(AttachError::HeaderSizeMismatch {
            local: HEADER_REGION_SIZE,
            remote: header.header_size,
        });
    }

    // 3. 用本端常量按对端记录的槽位配置算一遍布局；对端记录的偏移必须与之相符。
    //    这才是「两端常量是否一致」的真正检验 —— 只比常量本身无从发现差异。
    let local_layout = channel_layout(header.slot_count, header.slot_size)
        .map_err(layout_error_to_attach)?;

    // 说明：这里**刻意不**用 (data_off - desc_off) / slot_count 反推「对端步进」再与
    // DESCRIPTOR_STEP 比较。那个反推在数学上无法区分两种情形：「对端槽位数写错」与
    // 「对端描述符步进不同」在同一组数字下同样成立 —— 于是槽位数写错会被报成步进不符，
    // 把排障的人引到错误的字段上。既然布局相等性检查（下面那条）已经蕴含了步进一致
    // （布局相等则 span/slot_count 必然等于 DESCRIPTOR_STEP），就不再单独设一条会猜错的
    // 诊断；真出现差异时由 layout_mismatch 列出四个偏移值，足以直接看出问题所在。
    if header.desc_off != local_layout.desc_off || header.data_off != local_layout.data_off {
        return Err(AttachError::LayoutMismatch {
            local_desc: local_layout.desc_off,
            remote_desc: header.desc_off,
            local_data: local_layout.data_off,
            remote_data: header.data_off,
        });
    }

    // 4. 区域必须容得下完整布局。文件被截断是常见事故，且它不会自行报错。
    if file_len < local_layout.required {
        return Err(AttachError::RegionTooSmall {
            required: local_layout.required,
            actual: file_len,
        });
    }

    // 5. 基址对齐。mmap 本身返回页对齐地址，此检查保护两处现实场景：
    //    进程内匿名区域（测试用堆内存，通常只 16 字节对齐）与未来的偏移映射。
    let remainder = (base as u64) % u64::from(REGION_ALIGNMENT);
    if remainder != 0 {
        return Err(AttachError::BaseNotAligned {
            required: REGION_ALIGNMENT,
            remainder,
        });
    }

    Ok(local_layout)
}

/// 默认槽位配置，供工具与测试引用（与 C++ 端同一组常量）。
pub const DEFAULT_CONFIG: (u32, u32) = (DEFAULT_SLOT_COUNT, DEFAULT_SLOT_SIZE);
