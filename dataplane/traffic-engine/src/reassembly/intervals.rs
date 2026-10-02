// reassembly/intervals.rs —— 已接收数据的有序区间集（重叠裁剪 / 空洞追踪）。
//
// 这一层是整个重组的核心，也是最容易"看起来对、实际错"的一层。三条不变式：
//
//   1. `blocks` 按 `start` **严格递增**
//   2. 任意两块**互不相交**（重叠部分在插入时已被裁剪掉）
//   3. 任意两块**互不相邻**（相邻即合并，否则"有空洞"的判断会被邻接处误报）
//
// 有了这三条，"还有没有空洞"这个问题才有唯一答案：`base` 与最高字节之间只要
// 存在未被任何块覆盖的序号，就是一个空洞。否则每个空洞查询都要重新做一遍
// 区间归并，而两份实现只要有一处取舍不同就会给出不同的答案。
//
// 关于窗口裁剪：序号是循环的，"这段数据在 base 之前"必须用回绕比较判定，
// 并且**超窗的数据必须丢弃**而不是缓冲 —— 否则对端只要发一个序号很远的段，
// 就能让本端为这条流无限分配内存（省网入口上这是最廉价的攻击之一）。

use super::seq::{seq_add, seq_ge, seq_gt, seq_le, seq_lt, seq_max, seq_min, seq_offset, SeqRange};

/// 重叠数据的仲裁策略。
///
/// 两种语义在真实协议栈里都存在，且**行为相反**，因此必须显式选择而不是隐式固定：
///
/// - `KeepOld`（Linux `tcp_trim_head` 的语义）：先到的胜出，新段中与已收数据重叠的
///   部分被裁掉。含义是"流的内容一旦定下就不再被后续报文改写"，这直接决定了
///   旁路设备看到的内容是否与接收端一致 —— 中间人没法在数据流过半之后
///   再重发一段改写已交付的字节。
/// - `KeepNew`（BSD 语义）：后到的覆盖先到的。含义是"以最新所见为准"。
///
/// 省网旁路用 `KeepOld`：我们要复现的是**接收端真实收到的字节流**，而不是
/// "攻击者最后重发的那个版本"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverlapPolicy {
    /// 先到者胜（Linux 语义，默认）。
    #[default]
    KeepOld,
    /// 后到者胜（BSD 语义）。
    KeepNew,
}

/// 一段已接收的连续数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// 起始序号（绝对序号，未归一化）。
    pub start: u32,
    pub data: Vec<u8>,
}

impl Block {
    /// 结束序号（半开区间的右端）。
    pub fn end_seq(&self) -> u32 {
        seq_add(self.start, self.data.len() as u32)
    }

    /// 覆盖的序号区间。
    pub fn range(&self) -> SeqRange {
        SeqRange::new(self.start, self.data.len() as u32)
    }
}

/// 插入结果。刻意细分而不是只回 `bool`：省网要统计的恰恰是这些异常类别，
/// 合并成一个布尔值后，"重传率异常高"这类信号就再也拿不回来了。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertResult {
    /// 有新字节入库。`new_bytes` 是不含重叠部分的净增量。
    Accepted { new_bytes: usize },
    /// 整段都落在已收数据之内（纯重传），未产生新字节。
    Duplicate,
    /// 整段都在窗口起点之前（迟到的历史数据），已丢弃。
    BeforeWindow,
    /// 整段都在窗口之外（序号过远），已丢弃。
    BeyondWindow,
    /// 空载荷（纯 ACK / SYN 之类），不计入统计。
    Empty,
}

/// 区间集的运行统计。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SegmentStats {
    /// 收到的段数（含重传，不含空载荷）。
    pub segments: u64,
    /// 与已收数据发生过重叠的字节数。
    pub overlap_bytes: u64,
    /// 重叠但**内容不同**的字节数。
    ///
    /// 这是重传攻击/插入攻击的直接信号：正常的重传内容必然一致，
    /// 内容不一致说明有人在二次投递时改了字节。
    pub conflict_bytes: u64,
    /// 完整落在已收数据内的段数。
    pub duplicates: u64,
    /// 被窗口丢弃的段数（按方向分计）。
    pub before_window: u64,
    pub beyond_window: u64,
}

/// 单方向的已接收区间集。
#[derive(Debug, Clone)]
pub struct SegmentSet {
    /// 数据起点（通常是 ISN+1；未抓到 SYN 时以首个数据段的序号锚定）。
    base: u32,
    /// 从 `base` 起允许缓冲的最大序号跨度。超出即丢弃（防内存放大）。
    span: u32,
    /// 已接收区间，满足文件头的三条不变式。
    blocks: Vec<Block>,
    policy: OverlapPolicy,
    stats: SegmentStats,
}

impl SegmentSet {
    /// 以给定序号为数据起点构造空集。
    ///
    /// `span` 是序号跨度上限：一个序号距离 `base` 超过 `span` 的段会被直接丢弃。
    /// 它**不是**缓冲区大小（那是 `Stream` 的职责），而是"多远的序号还算这条流的
    /// 合法未来数据"。这个值必须远小于 2^31，否则回绕比较会退化（见 `seq.rs` 说明）。
    pub fn new(base: u32, span: u32, policy: OverlapPolicy) -> Self {
        Self {
            base,
            span,
            blocks: Vec::new(),
            policy,
            stats: SegmentStats::default(),
        }
    }

    pub fn base(&self) -> u32 {
        self.base
    }

    pub fn policy(&self) -> OverlapPolicy {
        self.policy
    }

    pub fn stats(&self) -> SegmentStats {
        self.stats
    }

    /// 直接查看内部块（测试与诊断用）。
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// 已缓冲字节总数（含乱序部分）。
    pub fn buffered(&self) -> usize {
        self.blocks.iter().map(|b| b.data.len()).sum()
    }

    /// 已收到数据的最高序号（没有任何数据时为 `base`）。
    pub fn highest_end(&self) -> u32 {
        self.blocks.last().map_or(self.base, |b| b.end_seq())
    }

    /// 从 `base` 起的**连续**字节数。
    ///
    /// 这是"现在可以交给上层解析的字节数"。乱序到达的数据即使已经收到，
    /// 只要前面还有空洞，就不算在这里 —— 上层拿到的必须永远是前缀连续的字节，
    /// 否则 DPI 会在流的中间某个位置开始解析，得出完全错误的结论。
    pub fn contiguous_len(&self) -> usize {
        match self.blocks.first() {
            Some(b) if b.start == self.base => b.data.len(),
            _ => 0,
        }
    }

    /// 窥视从 `base` 起最多 `n` 个连续字节，不消费。
    pub fn peek(&self, n: usize) -> &[u8] {
        let take = n.min(self.contiguous_len());
        match self.blocks.first() {
            Some(b) if b.start == self.base => &b.data[..take],
            _ => &[],
        }
    }

    /// 消费掉从 `base` 起最多 `n` 个连续字节并返回。
    ///
    /// 消费会推进 `base`；这是"窗口滑动"的唯一入口，
    /// 把推进逻辑收在一处，`base` 与 `blocks` 不会各自漂移。
    pub fn consume(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.contiguous_len());
        if n == 0 {
            return Vec::new();
        }
        let out = self.blocks[0].data[..n].to_vec();
        self.blocks[0].data = self.blocks[0].data[n..].to_vec();
        self.base = seq_add(self.base, n as u32);
        if self.blocks[0].data.is_empty() {
            self.blocks.remove(0);
        } else {
            // 就地推进块起点，维持"块起点 >= base"的不变式。
            self.blocks[0].start = self.base;
        }
        out
    }

    /// 当前缺口（空洞）列表，按序号升序。
    ///
    /// 只在 `base` 与已收到的最高序号之间找洞：**没收到过的未来数据不算洞**。
    /// 否则一条刚开始的流会被报成"从 base 到 2^32 全是洞"，这个输出没有任何用途。
    pub fn holes(&self) -> Vec<SeqRange> {
        let mut out = Vec::new();
        let mut cursor = self.base;
        for b in &self.blocks {
            if seq_gt(b.start, cursor) {
                out.push(SeqRange {
                    start: cursor,
                    end: b.start,
                });
            }
            if seq_gt(b.end_seq(), cursor) {
                cursor = b.end_seq();
            }
        }
        out
    }

    /// 插入一段数据。
    ///
    /// 传入的是**绝对序号 + 完整载荷**；窗口裁剪、重叠仲裁、块合并都在内部完成，
    /// 调用方不需要（也不应该）自己做偏移换算 —— 那正是这类代码历史上出错最多的地方。
    pub fn insert(&mut self, start: u32, payload: &[u8]) -> InsertResult {
        if payload.is_empty() {
            return InsertResult::Empty;
        }
        self.stats.segments += 1;

        // ---- 1) 窗口裁剪 ----
        // 载荷第 i 个字节的序号是 start+i，相对 base 的偏移是 off_start+i。
        // 保留偏移落在 [0, span) 内的字节。
        let off_start = seq_offset(start, self.base);
        let end_seq = seq_add(start, payload.len() as u32);
        let off_end = seq_offset(end_seq, self.base);
        if off_end <= 0 {
            self.stats.before_window += 1;
            return InsertResult::BeforeWindow;
        }
        if off_start >= i64::from(self.span) {
            self.stats.beyond_window += 1;
            return InsertResult::BeyondWindow;
        }
        let keep_from = if off_start < 0 {
            (-off_start) as usize
        } else {
            0
        };
        let keep_to = payload
            .len()
            .min((i64::from(self.span) - off_start) as usize);
        let body = &payload[keep_from..keep_to];
        if body.is_empty() {
            self.stats.before_window += 1;
            return InsertResult::BeforeWindow;
        }
        let new_start = seq_add(start, keep_from as u32);
        let range = SeqRange::new(new_start, body.len() as u32);

        // ---- 2) 重叠仲裁 ----
        match self.policy {
            OverlapPolicy::KeepOld => self.insert_keep_old(new_start, body, &range),
            OverlapPolicy::KeepNew => self.insert_keep_new(new_start, body, &range),
        }
    }

    /// KeepOld：先到者胜。算出新段中**未被已收数据覆盖**的若干片段，只插入这些。
    fn insert_keep_old(&mut self, new_start: u32, body: &[u8], r: &SeqRange) -> InsertResult {
        let mut pieces: Vec<(u32, u32)> = Vec::new();
        let mut cursor = r.start;
        let mut i = self.first_index_reaching(r.start);

        while i < self.blocks.len() && seq_lt(self.blocks[i].start, r.end) {
            let b_start = self.blocks[i].start;
            let b_end = self.blocks[i].end_seq();

            // 统计重叠与内容冲突。
            let is = seq_max(r.start, b_start);
            let ie = seq_min(r.end, b_end);
            if seq_lt(is, ie) {
                let n = seq_offset(ie, is) as usize;
                let old_off = seq_offset(is, b_start) as usize;
                let new_off = seq_offset(is, new_start) as usize;
                self.stats.overlap_bytes += n as u64;
                if self.blocks[i].data[old_off..old_off + n] != body[new_off..new_off + n] {
                    self.stats.conflict_bytes += n as u64;
                }
            }

            if seq_lt(cursor, b_start) {
                pieces.push((cursor, b_start));
            }
            if seq_gt(b_end, cursor) {
                cursor = b_end;
            }
            i += 1;
        }
        if seq_lt(cursor, r.end) {
            pieces.push((cursor, r.end));
        }

        if pieces.is_empty() {
            self.stats.duplicates += 1;
            return InsertResult::Duplicate;
        }

        // 从后往前插入，避免前面的插入影响后面片段的定位（区间互不重叠，
        // 但 `insert_piece` 内部的二分查找依赖不变式，正序插入会破坏它）。
        let mut new_bytes = 0usize;
        for (ps, pe) in pieces.iter().rev() {
            let from = seq_offset(*ps, new_start) as usize;
            let to = from + seq_offset(*pe, *ps) as usize;
            let slice = &body[from..to];
            new_bytes += slice.len();
            self.insert_piece(*ps, slice);
        }
        InsertResult::Accepted { new_bytes }
    }

    /// KeepNew：后到者胜。先把新段的区间从已有块中挖掉，再整段插入。
    fn insert_keep_new(&mut self, new_start: u32, body: &[u8], r: &SeqRange) -> InsertResult {
        let covered = self.carve(r, body);
        self.insert_piece(new_start, body);
        if covered == body.len() {
            // 整段都压在已收数据之上。注意与 KeepOld 的 `Duplicate` 含义不同：
            // 这里流的内容**可能被改写了**（只是净长度没变），冲突计数才是判断依据。
            self.stats.duplicates += 1;
            return InsertResult::Duplicate;
        }
        InsertResult::Accepted {
            new_bytes: body.len() - covered,
        }
    }

    /// 从已有块中挖掉区间 `r`，返回被挖掉的字节数（用于统计冲突）。
    fn carve(&mut self, r: &SeqRange, body: &[u8]) -> usize {
        let mut covered = 0usize;
        let mut i = self.first_index_reaching(r.start);

        while i < self.blocks.len() && seq_lt(self.blocks[i].start, r.end) {
            let b_start = self.blocks[i].start;
            let b_end = self.blocks[i].end_seq();

            let is = seq_max(r.start, b_start);
            let ie = seq_min(r.end, b_end);
            if seq_lt(is, ie) {
                let n = seq_offset(ie, is) as usize;
                let old_off = seq_offset(is, b_start) as usize;
                let new_off = seq_offset(is, r.start) as usize;
                self.stats.overlap_bytes += n as u64;
                covered += n;
                if self.blocks[i].data[old_off..old_off + n] != body[new_off..new_off + n] {
                    self.stats.conflict_bytes += n as u64;
                }
            }

            if r.contains_range(&self.blocks[i].range()) {
                self.blocks.remove(i);
                continue; // 不推进 i：后面的块前移到此位置
            }

            if seq_le(b_start, r.start) && seq_ge(b_end, r.end) {
                // r 落在块中间 → 分裂成左右两块。
                let cut_head = seq_offset(r.start, b_start) as usize;
                let tail = self.blocks[i].data[seq_offset(r.end, b_start) as usize..].to_vec();
                self.blocks[i].data.truncate(cut_head);
                self.blocks.insert(
                    i + 1,
                    Block {
                        start: r.end,
                        data: tail,
                    },
                );
                return covered; // r 已完整落在此块内，不会有别的块与之相交
            }

            if seq_lt(b_start, r.start) {
                // r 盖住块的尾部。
                let cut_head = seq_offset(r.start, b_start) as usize;
                self.blocks[i].data.truncate(cut_head);
                i += 1;
                continue;
            }

            // r 盖住块的头部（b_start >= r.start，且整块未被包含）。
            let cut = seq_offset(r.end, b_start) as usize;
            self.blocks[i].data = self.blocks[i].data[cut..].to_vec();
            self.blocks[i].start = r.end;
            i += 1;
        }
        covered
    }

    /// 第一个"末端序号超过 `seq`"的块下标。
    ///
    /// `blocks` 按 start 递增且互不重叠，因此 end 也递增，可以二分。
    fn first_index_reaching(&self, seq: u32) -> usize {
        self.blocks.partition_point(|b| seq_lt(b.end_seq(), seq))
    }

    /// 插入一个已确认与现有块不重叠的片段，并与左右邻居做必要的合并。
    fn insert_piece(&mut self, start: u32, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let end = seq_add(start, data.len() as u32);
        let idx = self.blocks.partition_point(|b| seq_lt(b.start, start));

        // 与左邻相邻 → 追加到左邻。
        if idx > 0 && self.blocks[idx - 1].end_seq() == start {
            self.blocks[idx - 1].data.extend_from_slice(data);
            let merged_end = self.blocks[idx - 1].end_seq();
            // 追加后可能与右邻也相邻 → 一并合并。
            if idx < self.blocks.len() && self.blocks[idx].start == merged_end {
                let tail = self.blocks.remove(idx);
                self.blocks[idx - 1].data.extend_from_slice(&tail.data);
            }
            return;
        }

        // 与右邻相邻 → 前插到右邻。
        if idx < self.blocks.len() && self.blocks[idx].start == end {
            let mut merged = data.to_vec();
            merged.extend_from_slice(&self.blocks[idx].data);
            self.blocks[idx].data = merged;
            self.blocks[idx].start = start;
            return;
        }

        self.blocks.insert(
            idx,
            Block {
                start,
                data: data.to_vec(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 1000;
    const SPAN: u32 = 1 << 20;

    fn set(policy: OverlapPolicy) -> SegmentSet {
        SegmentSet::new(BASE, SPAN, policy)
    }

    fn bytes(n: usize, fill: u8) -> Vec<u8> {
        vec![fill; n]
    }

    // ---- 基本插入与合并 ----

    #[test]
    fn in_order_segments_merge_into_one_block() {
        let mut s = set(OverlapPolicy::KeepOld);
        assert!(matches!(
            s.insert(BASE, &bytes(10, b'a')),
            InsertResult::Accepted { new_bytes: 10 }
        ));
        assert!(matches!(
            s.insert(BASE + 10, &bytes(10, b'b')),
            InsertResult::Accepted { new_bytes: 10 }
        ));
        assert_eq!(s.blocks().len(), 1, "相邻段必须合并成一块");
        assert_eq!(s.contiguous_len(), 20);
        let mut want = bytes(10, b'a');
        want.extend_from_slice(&bytes(10, b'b'));
        assert_eq!(s.peek(100), want.as_slice());
    }

    #[test]
    fn out_of_order_segment_does_not_extend_contiguous_prefix() {
        let mut s = set(OverlapPolicy::KeepOld);
        s.insert(BASE + 10, &bytes(10, b'b'));
        assert_eq!(s.contiguous_len(), 0, "前面有洞时不能交付任何字节");
        assert_eq!(s.buffered(), 10, "但数据确实收到了，应计入缓冲");
        assert_eq!(s.holes(), vec![SeqRange::new(BASE, 10)]);

        s.insert(BASE, &bytes(10, b'a'));
        assert_eq!(s.contiguous_len(), 20, "洞被填上后应立刻连续");
        assert!(s.holes().is_empty());
    }

    #[test]
    fn multiple_holes_are_reported_in_order() {
        let mut s = set(OverlapPolicy::KeepOld);
        s.insert(BASE + 10, &bytes(10, b'b'));
        s.insert(BASE + 30, &bytes(10, b'd'));
        s.insert(BASE + 20, &bytes(10, b'c'));
        assert_eq!(
            s.holes(),
            vec![SeqRange::new(BASE, 10)],
            "只报 base 与最高序号之间的洞；块之间已连续"
        );
    }

    // ---- 重叠：KeepOld ----

    #[test]
    fn keep_old_discards_overlapping_new_bytes() {
        let mut s = set(OverlapPolicy::KeepOld);
        s.insert(BASE, &bytes(20, b'a'));
        // 重传 [BASE+10, BASE+30)，前 10 字节重叠、后 10 字节是新的。
        let r = s.insert(BASE + 10, &bytes(20, b'b'));
        assert_eq!(r, InsertResult::Accepted { new_bytes: 10 });
        assert_eq!(s.contiguous_len(), 30);
        let got = s.peek(30);
        assert_eq!(&got[..20], &bytes(20, b'a'), "重叠部分必须保持先到的值");
        assert_eq!(&got[20..], &bytes(10, b'b'));
        assert_eq!(s.stats().overlap_bytes, 10);
    }

    #[test]
    fn keep_old_counts_conflicting_retransmission() {
        let mut s = set(OverlapPolicy::KeepOld);
        s.insert(BASE, &bytes(10, b'a'));
        s.insert(BASE, &bytes(10, b'z'));
        assert_eq!(s.stats().conflict_bytes, 10, "内容不同的重传必须被计数");
        assert_eq!(s.peek(10), bytes(10, b'a'), "但流内容仍以先到者为准");
        assert_eq!(s.stats().duplicates, 1);
    }

    #[test]
    fn identical_retransmission_is_not_a_conflict() {
        let mut s = set(OverlapPolicy::KeepOld);
        s.insert(BASE, &bytes(10, b'a'));
        s.insert(BASE, &bytes(10, b'a'));
        assert_eq!(s.stats().conflict_bytes, 0);
        assert_eq!(s.stats().overlap_bytes, 10);
        assert_eq!(s.stats().duplicates, 1);
    }

    #[test]
    fn segment_spanning_two_existing_blocks_keeps_only_the_gap() {
        // 已有 [0,10) 与 [20,30)；插入 [5,25)，只有 [10,20) 是新的。
        let mut s = set(OverlapPolicy::KeepOld);
        s.insert(BASE, &bytes(10, b'a'));
        s.insert(BASE + 20, &bytes(10, b'c'));
        let r = s.insert(BASE + 5, &bytes(20, b'B'));
        assert_eq!(r, InsertResult::Accepted { new_bytes: 10 });
        assert_eq!(s.blocks().len(), 1, "三个区间应连成一块");
        let got = s.peek(30);
        assert_eq!(&got[..10], &bytes(10, b'a'));
        assert_eq!(&got[10..20], &bytes(10, b'B'), "仅空隙部分采用新数据");
        assert_eq!(&got[20..], &bytes(10, b'c'));
    }

    // ---- 重叠：KeepNew ----

    #[test]
    fn keep_new_overwrites_existing_bytes() {
        let mut s = set(OverlapPolicy::KeepNew);
        s.insert(BASE, &bytes(10, b'a'));
        s.insert(BASE, &bytes(10, b'z'));
        assert_eq!(s.peek(10), bytes(10, b'z'), "后到者胜");
        assert_eq!(s.stats().conflict_bytes, 10);
    }

    #[test]
    fn keep_new_splits_a_block_when_overlap_is_in_the_middle() {
        let mut s = set(OverlapPolicy::KeepNew);
        s.insert(BASE, &bytes(30, b'a'));
        // 用 [BASE+10, BASE+20) 覆盖中间 10 字节 → 块应分裂成三块？不，两块 + 中间替换
        // 实际结果：carve 把原块分裂成 [0,10) 与 [20,30)，再插入 [10,20) → 合并成一块。
        s.insert(BASE + 10, &bytes(10, b'Z'));
        assert_eq!(s.blocks().len(), 1);
        let got = s.peek(30);
        assert_eq!(&got[..10], &bytes(10, b'a'));
        assert_eq!(&got[10..20], &bytes(10, b'Z'));
        assert_eq!(&got[20..], &bytes(10, b'a'));
    }

    #[test]
    fn keep_new_trims_tail_of_existing_block() {
        // 原块 [0,20)；新段 [15,25)：盖掉尾部 5 字节，并在其后追加 5 字节新数据。
        let mut s = set(OverlapPolicy::KeepNew);
        s.insert(BASE, &bytes(20, b'a'));
        s.insert(BASE + 15, &bytes(10, b'N'));
        assert_eq!(s.blocks().len(), 1);
        let got = s.peek(25);
        assert_eq!(&got[..15], bytes(15, b'a').as_slice());
        assert_eq!(&got[15..], bytes(10, b'N').as_slice());
    }

    #[test]
    fn keep_new_trims_head_of_existing_block() {
        // 已有连成一块的 [0,20)；新段 [5,15) 覆盖其中部 → 原块被分裂成首尾两段，
        // 新段插在中间，三者重新合并为一整块。
        let mut s = set(OverlapPolicy::KeepNew);
        s.insert(BASE, &bytes(10, b'a'));
        s.insert(BASE + 10, &bytes(10, b'b'));
        s.insert(BASE + 5, &bytes(10, b'N'));
        assert_eq!(s.blocks().len(), 1);
        let got = s.peek(20);
        assert_eq!(&got[..5], bytes(5, b'a').as_slice());
        assert_eq!(&got[5..15], bytes(10, b'N').as_slice());
        assert_eq!(&got[15..20], bytes(5, b'b').as_slice());
    }

    // ---- 窗口裁剪 ----

    #[test]
    fn data_before_base_is_clipped_not_buffered() {
        let mut s = set(OverlapPolicy::KeepOld);
        s.insert(BASE, &bytes(10, b'a'));
        // 迟到段：起点在 base 之前 5 字节，只有后 5 字节落在窗口内（但那 5 字节已有）。
        let r = s.insert(BASE - 5, &bytes(10, b'z'));
        assert!(matches!(r, InsertResult::Duplicate) || matches!(r, InsertResult::Accepted { .. }));
        assert_eq!(s.buffered(), 10, "base 之前的字节绝不能进缓冲");
        assert_eq!(s.peek(10), bytes(10, b'a'));
    }

    #[test]
    fn segment_entirely_before_base_is_dropped() {
        let mut s = set(OverlapPolicy::KeepOld);
        let r = s.insert(BASE - 100, &bytes(10, b'z'));
        assert_eq!(r, InsertResult::BeforeWindow);
        assert_eq!(s.buffered(), 0);
        assert_eq!(s.stats().before_window, 1);
    }

    #[test]
    fn segment_beyond_span_is_dropped() {
        let mut s = SegmentSet::new(BASE, 100, OverlapPolicy::KeepOld);
        let r = s.insert(BASE + 500, &bytes(10, b'z'));
        assert_eq!(r, InsertResult::BeyondWindow);
        assert_eq!(s.buffered(), 0, "超窗数据不得缓冲（否则可被用于内存放大）");
        assert_eq!(s.stats().beyond_window, 1);
    }

    #[test]
    fn segment_partially_beyond_span_is_clipped() {
        let mut s = SegmentSet::new(BASE, 20, OverlapPolicy::KeepOld);
        let r = s.insert(BASE + 15, &bytes(20, b'z'));
        assert_eq!(r, InsertResult::Accepted { new_bytes: 5 });
        assert_eq!(s.buffered(), 5);
    }

    #[test]
    fn empty_payload_is_not_counted() {
        let mut s = set(OverlapPolicy::KeepOld);
        assert_eq!(s.insert(BASE, &[]), InsertResult::Empty);
        assert_eq!(s.stats().segments, 0);
    }

    // ---- 消费 ----

    #[test]
    fn consume_advances_base_and_frees_memory() {
        let mut s = set(OverlapPolicy::KeepOld);
        s.insert(BASE, &bytes(10, b'a'));
        s.insert(BASE + 20, &bytes(10, b'c')); // 乱序，留一个洞
        let out = s.consume(4);
        assert_eq!(out, bytes(4, b'a'));
        assert_eq!(s.base(), BASE + 4);
        assert_eq!(s.contiguous_len(), 6);
        assert_eq!(s.buffered(), 16);
        assert_eq!(s.holes(), vec![SeqRange::new(BASE + 10, 10)]);
    }

    #[test]
    fn consume_more_than_available_returns_what_exists() {
        let mut s = set(OverlapPolicy::KeepOld);
        s.insert(BASE, &bytes(5, b'a'));
        let out = s.consume(100);
        assert_eq!(out, bytes(5, b'a'));
        assert_eq!(s.contiguous_len(), 0);
        assert!(s.blocks().is_empty());
    }

    #[test]
    fn consume_nothing_when_a_hole_blocks_the_head() {
        let mut s = set(OverlapPolicy::KeepOld);
        s.insert(BASE + 5, &bytes(5, b'b'));
        assert!(s.consume(10).is_empty());
        assert_eq!(s.base(), BASE);
    }

    // ---- 跨零回绕 ----

    #[test]
    fn wrap_around_zero_works() {
        let base = 0xFFFF_FFF0u32;
        let mut s = SegmentSet::new(base, 1 << 20, OverlapPolicy::KeepOld);
        // 乱序先到第二段（序号已绕回 0），再到第一段。
        s.insert(0x0000_0000, &bytes(16, b'b'));
        assert_eq!(s.contiguous_len(), 0);
        s.insert(base, &bytes(16, b'a'));
        assert_eq!(s.contiguous_len(), 32, "跨零点的两段应正确衔接");
        assert_eq!(s.highest_end(), 0x10);
        assert!(s.holes().is_empty());
    }

    #[test]
    fn retransmission_across_zero_is_recognized() {
        let base = 0xFFFF_FFF8u32;
        let mut s = SegmentSet::new(base, 1 << 20, OverlapPolicy::KeepOld);
        s.insert(base, &bytes(16, b'a')); // [FFFFFFF8, 00000008)
        let r = s.insert(base, &bytes(16, b'a')); // 同一段重传
        assert_eq!(r, InsertResult::Duplicate);
        assert_eq!(s.stats().conflict_bytes, 0);
    }

    // ---- 不变式 ----

    #[test]
    fn blocks_stay_sorted_disjoint_and_non_adjacent() {
        let mut s = SegmentSet::new(BASE, 1 << 16, OverlapPolicy::KeepOld);
        // 一批刻意打乱、互相重叠的段。
        let segs: [(u32, usize, u8); 8] = [
            (BASE + 40, 20, b'a'),
            (BASE + 0, 15, b'b'),
            (BASE + 30, 25, b'c'),
            (BASE + 10, 10, b'd'),
            (BASE + 55, 5, b'e'),
            (BASE + 5, 30, b'f'),
            (BASE + 58, 10, b'g'),
            (BASE + 20, 40, b'h'),
        ];
        for (off, len, fill) in segs {
            s.insert(off, &bytes(len, fill));
        }
        let bs = s.blocks();
        for w in bs.windows(2) {
            assert!(seq_lt(w[0].start, w[1].start), "块必须按 start 严格递增");
            assert!(seq_lt(w[0].end_seq(), w[1].start), "块必须既不重叠也不相邻");
        }
        for b in bs {
            assert!(seq_ge(b.start, s.base()), "块起点不得早于 base");
        }
    }
}
