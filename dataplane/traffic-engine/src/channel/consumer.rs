// channel/consumer.rs —— 共享环的 SPSC 消费端。
//
// 内存序约定（只有一处定义，改这里即改全局）：
//   生产者  写描述符与数据  ──release──▶  head
//   消费者  acquire 读 head ──读取描述符与数据──▶ tail（release）
//
// 消费者只读 head，只写 tail 与 consumed；生产者的职责在 C++ 侧。两侧各写各的计数器，
// 共享字段中没有任何一个被两端同时写 —— 这是本设计不依赖锁的前提。
//
// 一个刻意的选择：`poll` 把字节以借用形式交给回调，而不是复制进调用方缓冲。
// 这样既保住了零拷贝，又保证「回调返回之前槽位仍归消费者所有」，生产者不会在
// 处理中途覆盖它。返回借用型视图会把这个保证推给调用方，反而更容易写错。

use std::fmt;

use super::abi_gen::{diag, flag, PacketDescriptor};
use super::region::{AttachError, Channel};

/// 单个报文的元数据（不含负载）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    pub seq: u64,
    pub timestamp_ns: i64,
    pub caplen: u32,
    pub wirelen: u32,
    pub ifindex: u32,
    pub flags: u32,
}

impl PacketMeta {
    /// 截断捕获：caplen < wirelen，说明这份数据不完整。
    pub fn is_truncated(&self) -> bool {
        self.flags & flag::TRUNCATED != 0 || self.caplen < self.wirelen
    }

    /// 含 VLAN 标签。
    pub fn is_vlan_tagged(&self) -> bool {
        self.flags & flag::VLAN_TAGGED != 0
    }

    /// IPv6 报文。
    pub fn is_ipv6(&self) -> bool {
        self.flags & flag::IPV6 != 0
    }

    /// 合成报文（测试注入，非真实抓包）。
    pub fn is_synthetic(&self) -> bool {
        self.flags & flag::SYNTHETIC != 0
    }

    /// 时间戳（微秒）。流模型当前以微秒为单位。
    pub fn timestamp_us(&self) -> u64 {
        (self.timestamp_ns / 1_000).max(0) as u64
    }
}

/// 描述符内容自相矛盾的具体原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptReason {
    /// 序号与消费位置不符：说明索引计算或生产者写序错了位。
    SeqMismatch,
    /// caplen 超过槽容量。
    CaplenExceedsSlot,
    /// 数据区间未落在所属槽位内（data_off 是相对数据区起点的偏移）。
    DataRangeExceedsSlot,
}

impl CorruptReason {
    fn text(self) -> &'static str {
        match self {
            CorruptReason::SeqMismatch => {
                "描述符序号与消费位置不符：槽位索引计算或生产者写序已错位"
            }
            CorruptReason::CaplenExceedsSlot => "报文长度超过槽容量",
            CorruptReason::DataRangeExceedsSlot => {
                "数据区间未落在所属槽位内：data_off 应为相对数据区起点的偏移，                 且 [data_off, data_off+caplen) 必须落在本槽位的字节区间内"
            }
        }
    }
}

/// 消费过程中的错误。
///
/// 这些错误**不在**真源里，也不由 C++ 端产生：只有读的一方才能发现它们，因此没有
/// 跨语言一致性的要求。真源负责的是「两端都可能遇到」的 attach 期诊断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeError {
    /// 消费者落后生产者一圈以上，未读槽位已被覆盖，丢了多少可以精确算出。
    ProducerOverrun {
        head: u64,
        tail: u64,
        slot_count: u32,
        skipped: u64,
    },
    /// 描述符自相矛盾。继续读只会得到垃圾，因此中断。
    CorruptDescriptor {
        index: u64,
        expected_seq: u64,
        actual_seq: u64,
        caplen: u32,
        data_off: u32,
        slot_size: u32,
        reason: CorruptReason,
    },
}

impl fmt::Display for ConsumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsumeError::ProducerOverrun { head, tail, slot_count, skipped } => write!(
                f,
                "消费者落后超过一圈：head={head} tail={tail} 槽位数={slot_count}，\
                 已丢失 {skipped} 个未读报文（这些槽位已被生产者覆盖）"
            ),
            ConsumeError::CorruptDescriptor {
                index,
                expected_seq,
                actual_seq,
                caplen,
                data_off,
                slot_size,
                reason,
            } => {
                // 长度越界这条直接复用真源生成的文案，使两端说法一致。
                if *reason == CorruptReason::CaplenExceedsSlot {
                    return f.write_str(
                        &diag::ChanTruncatedPacket {
                            caplen: *caplen,
                            slot_size: *slot_size,
                        }
                        .to_string(),
                    );
                }
                write!(
                    f,
                    "{text}（槽位={index} 期望序号={expected_seq} 实际序号={actual_seq} \
                     caplen={caplen} data_off={data_off} 槽容量={slot_size}）",
                    text = reason.text()
                )
            }
        }
    }
}

impl std::error::Error for ConsumeError {}

/// 消费者累计统计。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConsumerStats {
    /// 成功取走的报文数。
    pub packets: u64,
    /// 累计线上字节数（按 wirelen，非截断后的 caplen）。
    pub bytes: u64,
    /// 其中被截断捕获的报文数。
    pub truncated: u64,
    /// 因落后一圈而永久丢失的报文数。
    pub overrun_skipped: u64,
}

/// SPSC 消费端。
pub struct Consumer<'a> {
    chan: &'a mut Channel,
    local_tail: u64,
    stats: ConsumerStats,
    /// 最近一次 `drain` 期间的丢弃事件。
    ///
    /// 单独保存而不是只累加进 `overrun_skipped`：调用方需要知道「丢了」这个事实本身
    /// 才能决定是否报警，而计数在跨批次累积后无法反推是哪一批丢的。
    last_overrun: Option<ConsumeError>,
}

impl<'a> Consumer<'a> {
    /// 从区域记录的 tail 位置继续消费，并登记消费者 pid。
    ///
    /// 这是「续跑」语义：进程重启后从上次停下的位置接着读，不重放已处理过的报文。
    pub fn resume(chan: &'a mut Channel) -> Self {
        let tail = chan.load_tail();
        chan.set_consumer_pid(std::process::id());
        Consumer {
            chan,
            local_tail: tail,
            stats: ConsumerStats::default(),
            last_overrun: None,
        }
    }

    /// 丢弃历史积压，从当前 head 开始消费。
    ///
    /// 与 `resume` 的区别是明确的：重放一段早已过期的积压数据通常毫无意义，
    /// 而「默默从 tail 开始读一小时前的报文」是很难被发现的错误。
    pub fn from_head(chan: &'a mut Channel) -> Self {
        let head = chan.load_head();
        chan.set_consumer_pid(std::process::id());
        chan.store_tail(head);
        Consumer {
            chan,
            local_tail: head,
            stats: ConsumerStats::default(),
            last_overrun: None,
        }
    }

    /// 当前未被消费的报文数。
    pub fn pending(&self) -> u64 {
        self.chan.load_head().saturating_sub(self.local_tail)
    }

    /// 本地已消费到的位置。
    pub fn tail(&self) -> u64 {
        self.local_tail
    }

    /// 累计统计。
    pub fn stats(&self) -> ConsumerStats {
        self.stats
    }

    /// 通道引用。
    pub fn channel(&self) -> &Channel {
        self.chan
    }

    /// 通道可变引用（供调用方在消费间隙读取头部快照）。
    pub fn channel_mut(&mut self) -> &mut Channel {
        self.chan
    }

    /// 取走一个报文，把字节以借用形式交给 `f`。
    ///
    /// 返回 `Ok(false)` 表示当前无可用报文（非错误）。`Err` 只在「继续读会得到错误
    /// 结论」时出现。
    pub fn poll<F>(&mut self, mut f: F) -> Result<bool, ConsumeError>
    where
        F: FnMut(PacketMeta, &[u8]),
    {
        let head = self.chan.load_head(); // Acquire：与生产者的 release 写配对
        let tail = self.local_tail;
        if head <= tail {
            return Ok(false);
        }

        let slot_count = self.chan.slot_count();
        let backlog = head - tail;
        if backlog > u64::from(slot_count) {
            // 未读槽位已被覆盖。精确算出丢了多少，并把本地位置推进到「仍可读的最早位置」，
            // 这样调用方若选择继续，读到的仍是完整报文而不是垃圾。
            let skipped = backlog - u64::from(slot_count);
            self.local_tail = head - u64::from(slot_count);
            self.stats.overrun_skipped += skipped;
            return Err(ConsumeError::ProducerOverrun {
                head,
                tail,
                slot_count,
                skipped,
            });
        }

        let slot_size = self.chan.slot_size();
        let index = tail % u64::from(slot_count);
        let desc = self.chan.descriptor(index);

        // 序号自检：这是整套索引算术最廉价也最有力的验证。生产者的序号与消费者推出的
        // 位置若不一致，说明其中一侧的算术已经错了，此时任何字段都不可信。
        if desc.seq != tail {
            return Err(corrupt(index, tail, &desc, slot_size, CorruptReason::SeqMismatch));
        }
        if desc.caplen > slot_size {
            return Err(corrupt(
                index,
                tail,
                &desc,
                slot_size,
                CorruptReason::CaplenExceedsSlot,
            ));
        }
        // data_off 的语义由真源固定为「**相对数据区起点**的偏移」
        // （见 configs/registry/channel-abi.json 的 descriptor_fields.data_off），
        // 因此这里必须按「该槽位在数据区中的区间」校验，而不是把它当槽内偏移。
        //
        // 两者混淆的代价非常隐蔽：若拿 idx*slot_size 去和 slot_size 比，则只有第 0 个
        // 槽位能读，其余槽位一律被判成损坏 —— 而错误文案（「超出槽边界」）看起来像是
        // 生产端摆位有问题，会把排障方向引到完全错误的地方。
        let slot_start = index * u64::from(slot_size);
        let slot_end = slot_start + u64::from(slot_size);
        let data_start = u64::from(desc.data_off);
        let data_end = data_start + u64::from(desc.caplen);
        if data_start < slot_start || data_end > slot_end {
            return Err(corrupt(
                index,
                tail,
                &desc,
                slot_size,
                CorruptReason::DataRangeExceedsSlot,
            ));
        }

        let meta = PacketMeta {
            seq: desc.seq,
            timestamp_ns: desc.timestamp_ns,
            caplen: desc.caplen,
            wirelen: desc.wirelen,
            ifindex: desc.ifindex,
            flags: desc.flags,
        };
        let data = self.chan.slot_slice(&desc);
        f(meta, data);

        // 提交顺序：先结算统计与 consumed，最后 release 写 tail。
        // 反过来的话，生产者可能在 tail 已发布、描述符尚未读全时覆盖该槽位。
        self.local_tail = tail + 1;
        self.stats.packets += 1;
        self.stats.bytes += u64::from(desc.wirelen);
        if meta.is_truncated() {
            self.stats.truncated += 1;
        }
        self.chan.add_consumed(1);
        self.chan.store_tail(self.local_tail);
        Ok(true)
    }

    /// 取走当前可用的全部报文，返回取走的数量。
    ///
    /// `ProducerOverrun` 不中断排空：丢包数已精确记账，中断只会让调用方在数据仍然
    /// 可读时提前放弃。`CorruptDescriptor` 则立即中断——那时继续读已无正确性可言。
    pub fn drain<F>(&mut self, mut f: F) -> Result<u64, ConsumeError>
    where
        F: FnMut(PacketMeta, &[u8]),
    {
        let mut n = 0u64;
        loop {
            match self.poll(|m, d| f(m, d)) {
                Ok(true) => n += 1,
                Ok(false) => break,
                Err(e @ ConsumeError::ProducerOverrun { .. }) => {
                    self.last_overrun = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(n)
    }

    /// 最近一次 `drain` 期间发生的丢弃事件（若有）。
    pub fn last_overrun(&self) -> Option<ConsumeError> {
        self.last_overrun
    }

    /// 把通道自身的累计统计与本次消费统计一起返回。
    pub fn channel_stats(&self) -> super::region::ChannelStats {
        self.chan.stats()
    }

    /// 校验通道当前可读：重跑完整校验，并检查消费位置未越过生产位置。
    ///
    /// 返回 `Ok(())` 才表示「现在读是安全的」。这个检查不是可选的礼貌动作——它拦下的
    /// `tail > head` 会让消费端此后永远返回「无数据」，且看不出任何异常。
    pub fn health(&mut self) -> Result<(), AttachError> {
        self.chan.revalidate()
    }
}

fn corrupt(
    index: u64,
    expected_seq: u64,
    desc: &PacketDescriptor,
    slot_size: u32,
    reason: CorruptReason,
) -> ConsumeError {
    ConsumeError::CorruptDescriptor {
        index,
        expected_seq,
        actual_seq: desc.seq,
        caplen: desc.caplen,
        data_off: desc.data_off,
        slot_size,
        reason,
    }
}
