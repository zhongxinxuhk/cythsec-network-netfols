// reassembly/stream.rs —— 单向 TCP 流（锚定、交付、内存上限、FIN 语义）。
//
// `intervals.rs` 解决"字节摆在哪"，这一层解决"什么时候能交给上层"以及
// "交不出去的时候怎么办"。三个必须显式回答的问题：
//
// 1. **基准从哪来**：抓到 SYN 就锚 ISN+1；没抓到（旁路中途接入）只能拿首个
//    见到的段当开头。后者是**固有限制而非 bug**，但必须可辨认 ——
//    否则"这条流的开头几 KB 我不确定是否完整"这个事实会在下游被抹掉。
//
// 2. **内存上限怎么降级**：乱序缓冲不可能无限大。上限触发时的取舍是
//    **保连续、弃乱序**：能推进连续前缀的段照收（它马上会被交付并释放），
//    只会加深空洞的段丢弃。这样即便在攻击流量下，DPI 依然能在流的开头
//    拿到完整前缀并出结果 —— 退化了但没瞎，这比"整体停摆"有用得多。
//
// 3. **FIN 是什么意思**：FIN 自身占一个序号，它的序号就是数据流的终点。
//    把 FIN 当成"连接结束"而不是"数据结束"会导致最后一段数据被判为缺失，
//    表现为每条流都差一个字节的空洞，且永远补不上。

use super::intervals::{InsertResult, OverlapPolicy, SegmentSet, SegmentStats};
use super::seq::{seq_add, seq_ge, seq_gt, seq_le, seq_lt, SeqRange};
use crate::dpi::{self, Outcome};

/// 单方向默认乱序缓冲上限（字节）。
pub const DEFAULT_MAX_BUFFERED: usize = 64 * 1024;

/// 单方向默认序号跨度上限（字节）。
///
/// 必须远小于 2^31：序号比较在恰好相距半个序号空间时是退化的（见 `seq.rs`）。
/// 4 MiB 意味着"距离基准 4 MiB 以外的序号不算这条流的合法未来数据"。
pub const DEFAULT_MAX_SPAN: u32 = 4 * 1024 * 1024;

/// 流重组配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    /// 乱序缓冲上限；达到后按"保连续、弃乱序"降级。
    pub max_buffered: usize,
    /// 序号跨度上限；超出的段直接丢弃。
    pub max_span: u32,
    /// 重叠仲裁策略。
    pub policy: OverlapPolicy,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            max_buffered: DEFAULT_MAX_BUFFERED,
            max_span: DEFAULT_MAX_SPAN,
            policy: OverlapPolicy::default(),
        }
    }
}

/// 一个数据段被处理后的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegAction {
    /// 入库；`new_bytes` 为净新增字节数（不含重叠部分）。
    Accepted { new_bytes: usize },
    /// 整段落在已收数据内（重传）。
    Duplicate,
    /// 整段在基准之前（迟到历史数据），已丢弃。
    BeforeWindow,
    /// 整段超出序号跨度，已丢弃。
    BeyondWindow,
    /// 空载荷（纯 ACK 等），未产生任何状态变化。
    Empty,
    /// 乱序缓冲已达上限，且本段无法推进连续前缀 → 丢弃。
    DroppedForMemory,
}

/// 流级统计。与 `SegmentStats` 的分工：这里统计"喂进来了什么"（含被丢弃的），
/// `SegmentStats` 统计"区间层真正处理了什么"。两者之差就是被上游策略丢掉的量。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamStats {
    /// 喂进来的数据段数（含被内存上限丢弃的）。
    pub segments: u64,
    /// 到达时无法立即推进连续前缀的段数。
    pub ooo_segments: u64,
    /// 已交付给上层的字节数。
    pub delivered_bytes: u64,
    /// 因内存上限被丢弃的段数。
    pub memory_drops: u64,
    pub fin_seen: bool,
    pub rst_seen: bool,
}

/// 单向流。
#[derive(Debug, Clone)]
pub struct Stream {
    cfg: StreamConfig,
    set: Option<SegmentSet>,
    /// FIN 的序号（= 数据流的终点）。
    fin_seq: Option<u32>,
    rst: bool,
    /// 基准是否由 SYN 锚定（false 表示中途接入，开头完整性未知）。
    anchored_by_syn: bool,
    stats: StreamStats,
}

impl Stream {
    pub fn new(cfg: StreamConfig) -> Self {
        Self {
            cfg,
            set: None,
            fin_seq: None,
            rst: false,
            anchored_by_syn: false,
            stats: StreamStats::default(),
        }
    }

    pub fn cfg(&self) -> StreamConfig {
        self.cfg
    }

    pub fn stats(&self) -> StreamStats {
        self.stats
    }

    /// 区间层统计；流尚未锚定时为 `None`。
    pub fn interval_stats(&self) -> Option<SegmentStats> {
        self.set.as_ref().map(|s| s.stats())
    }

    /// 基准是否由 SYN 锚定。
    ///
    /// 为 `false` 说明这条流是**中途接入**的：首个数据段之前是否还有数据，
    /// 我们无从得知。下游报告必须能看出这个区别，否则"开头不完整"会被
    /// 静默当成"开头就是这个字节"。
    pub fn anchored_by_syn(&self) -> bool {
        self.anchored_by_syn
    }

    pub fn rst(&self) -> bool {
        self.rst
    }

    pub fn fin_seq(&self) -> Option<u32> {
        self.fin_seq
    }

    /// 数据起点；尚未收到任何数据时为 `None`。
    pub fn base(&self) -> Option<u32> {
        self.set.as_ref().map(|s| s.base())
    }

    /// 连续前缀的终点序号（下一个待收字节的序号）。
    pub fn contiguous_end(&self) -> Option<u32> {
        self.set
            .as_ref()
            .map(|s| seq_add(s.base(), s.contiguous_len() as u32))
    }

    /// 当前可交付的连续字节数。
    pub fn contiguous_len(&self) -> usize {
        self.set.as_ref().map_or(0, |s| s.contiguous_len())
    }

    /// 已缓冲字节数（含乱序）。
    pub fn buffered(&self) -> usize {
        self.set.as_ref().map_or(0, |s| s.buffered())
    }

    /// 收到 SYN：以 ISN+1 锚定数据起点。
    ///
    /// 重复 SYN（重传）不会改变已锚定的基准 —— 若允许改写，攻击者只要在流中间
    /// 重发一个不同 ISN 的 SYN 就能让整条流错位。
    pub fn on_syn(&mut self, seq: u32) {
        if self.set.is_some() {
            return;
        }
        self.set = Some(SegmentSet::new(
            seq_add(seq, 1),
            self.cfg.max_span,
            self.cfg.policy,
        ));
        self.anchored_by_syn = true;
    }

    /// 收到一个数据段。
    pub fn on_data(&mut self, seq: u32, payload: &[u8]) -> SegAction {
        if payload.is_empty() {
            return SegAction::Empty;
        }
        self.stats.segments += 1;

        let cfg = self.cfg;
        let set = self.set.get_or_insert_with(|| {
            // 中途接入：以首个见到的段锚定。此处**不**置 `anchored_by_syn`，
            // 这个 false 是下游判断"开头完整性未知"的唯一依据。
            SegmentSet::new(seq, cfg.max_span, cfg.policy)
        });

        let head_before = seq_add(set.base(), set.contiguous_len() as u32);
        let seg_end = seq_add(seq, payload.len() as u32);
        // 是否推进连续前缀：段起点不晚于当前前缀末端，且段末端在其之后。
        let advances = seq_le(seq, head_before) && seq_gt(seg_end, head_before);

        if !advances && set.buffered() >= cfg.max_buffered {
            self.stats.memory_drops += 1;
            return SegAction::DroppedForMemory;
        }

        match set.insert(seq, payload) {
            InsertResult::Accepted { new_bytes } => {
                if !advances {
                    self.stats.ooo_segments += 1;
                }
                SegAction::Accepted { new_bytes }
            }
            InsertResult::Duplicate => SegAction::Duplicate,
            InsertResult::BeforeWindow => SegAction::BeforeWindow,
            InsertResult::BeyondWindow => SegAction::BeyondWindow,
            InsertResult::Empty => SegAction::Empty,
        }
    }

    /// 收到 FIN：`seq` 是 FIN 标志所在报文的**序号**（即数据结束位置）。
    pub fn on_fin(&mut self, seq: u32) {
        self.fin_seq = Some(seq);
        self.stats.fin_seen = true;
    }

    /// 收到 RST：连接被重置，后续数据不再有意义。
    pub fn on_rst(&mut self) {
        self.rst = true;
        self.stats.rst_seen = true;
    }

    /// 一次喂入一个完整的 TCP 段（载荷 + FIN 标志位）。
    ///
    /// 关于"先数据还是先 FIN"：**对最终状态没有影响** —— `on_fin` 只记一个序号，
    /// 与数据插入互不干扰。这一点是注入验证时发现的（把两行对调，76 项测试全绿），
    /// 因此这里不声称顺序敏感，避免留下一条"看起来很重要但其实无所谓"的规则。
    /// 真正敏感的是 FIN 的**序号**必须是 `seq + 载荷长度`：写成 `seq` 会让
    /// `is_finished()` 永远差一个载荷长度，`fin-with-payload` 向量会立刻报错。
    pub fn feed(&mut self, seq: u32, payload: &[u8], fin: bool) -> SegAction {
        let action = self.on_data(seq, payload);
        if fin {
            self.on_fin(seq_add(seq, payload.len() as u32));
        }
        action
    }

    /// 窥视从开头起最多 `n` 个连续字节，不消费。
    pub fn peek(&self, n: usize) -> &[u8] {
        match &self.set {
            Some(s) => s.peek(n),
            None => &[],
        }
    }

    /// 消费最多 `n` 个连续字节。
    pub fn take(&mut self, n: usize) -> Vec<u8> {
        let out = match &mut self.set {
            Some(s) => s.consume(n),
            None => Vec::new(),
        };
        self.stats.delivered_bytes += out.len() as u64;
        out
    }

    /// 消费当前全部连续字节。
    pub fn take_all(&mut self) -> Vec<u8> {
        self.take(self.contiguous_len())
    }

    /// 当前空洞列表。
    pub fn holes(&self) -> Vec<SeqRange> {
        self.set.as_ref().map_or_else(Vec::new, |s| s.holes())
    }

    /// 数据是否已完整收到（FIN 已见且连续前缀正好到达 FIN 的序号）。
    pub fn is_finished(&self) -> bool {
        match (self.fin_seq, self.contiguous_end()) {
            (Some(fin), Some(end)) => end == fin,
            _ => false,
        }
    }

    /// 用重组后的连续前缀做应用识别。
    ///
    /// 这是本模块与 DPI 的**唯一**衔接点，也是"重组到底有没有用"的判据：
    /// 同一个纯函数解析器，输入从"一个报文的载荷"换成"重组后的前缀"。
    /// 若这里需要为重组改动 DPI，说明分层串了。
    pub fn identify_app(&self, dst_port: u16) -> Outcome {
        dpi::identify(
            self.peek(dpi::DEFAULT_INSPECT_BYTES),
            dpi::IPPROTO_TCP,
            dst_port,
        )
    }

    /// 已收到数据的最高序号（用于对账与诊断）。
    pub fn highest_end(&self) -> Option<u32> {
        self.set.as_ref().map(|s| s.highest_end())
    }

    /// 连续前缀是否至少已有 `n` 字节（避免调用方反复取长度再比较）。
    pub fn has_prefix(&self, n: usize) -> bool {
        self.contiguous_len() >= n
    }

    /// 判断某个序号是否已在连续前缀之内（供 SACK 交叉验证等场景使用）。
    pub fn covers(&self, seq: u32) -> bool {
        match (self.base(), self.contiguous_end()) {
            (Some(b), Some(e)) => seq_ge(seq, b) && seq_lt(seq, e),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream() -> Stream {
        Stream::new(StreamConfig::default())
    }

    fn small() -> Stream {
        Stream::new(StreamConfig {
            max_buffered: 16,
            max_span: 1024,
            policy: OverlapPolicy::KeepOld,
        })
    }

    fn data(n: usize, fill: u8) -> Vec<u8> {
        vec![fill; n]
    }

    // ---- 锚定 ----

    #[test]
    fn syn_anchors_base_at_isn_plus_one() {
        let mut s = stream();
        s.on_syn(500);
        assert_eq!(s.base(), Some(501), "SYN 自身占一个序号");
        assert!(s.anchored_by_syn());
    }

    #[test]
    fn midstream_pickup_is_flagged_as_unanchored() {
        let mut s = stream();
        s.on_data(900, &data(10, b'a'));
        assert_eq!(s.base(), Some(900));
        assert!(!s.anchored_by_syn(), "中途接入必须可辨认");
    }

    #[test]
    fn duplicate_syn_does_not_rebase() {
        let mut s = stream();
        s.on_syn(500);
        s.on_data(501, &data(5, b'a'));
        s.on_syn(9999); // 重发一个不同 ISN 的 SYN
        assert_eq!(s.base(), Some(501), "已锚定的基准不得被改写");
        assert_eq!(s.contiguous_len(), 5);
    }

    // ---- 顺序与乱序 ----

    #[test]
    fn in_order_delivery() {
        let mut s = stream();
        s.on_syn(100);
        assert_eq!(
            s.on_data(101, &data(10, b'a')),
            SegAction::Accepted { new_bytes: 10 }
        );
        assert_eq!(
            s.on_data(111, &data(10, b'b')),
            SegAction::Accepted { new_bytes: 10 }
        );
        assert_eq!(s.contiguous_len(), 20);
        assert_eq!(s.stats().ooo_segments, 0);
        let mut want = data(10, b'a');
        want.extend_from_slice(&data(10, b'b'));
        assert_eq!(s.take_all(), want);
        assert_eq!(s.stats().delivered_bytes, 20);
    }

    #[test]
    fn reversed_arrival_reassembles_in_order() {
        let mut s = stream();
        s.on_syn(100);
        // 3 段完全逆序到达。
        s.on_data(121, &data(10, b'c'));
        s.on_data(111, &data(10, b'b'));
        assert_eq!(s.contiguous_len(), 0, "还缺第一段，不能交付");
        s.on_data(101, &data(10, b'a'));
        assert_eq!(s.contiguous_len(), 30);
        assert_eq!(s.stats().ooo_segments, 2, "前两段到达时都是乱序");
        let mut want = data(10, b'a');
        want.extend_from_slice(&data(10, b'b'));
        want.extend_from_slice(&data(10, b'c'));
        assert_eq!(s.take_all(), want);
    }

    #[test]
    fn interleaved_holes_fill_progressively() {
        let mut s = stream();
        s.on_syn(0);
        // 到达顺序：2,4,1,3（块号，每块 10 字节，起始 1）
        s.on_data(11, &data(10, b'2'));
        s.on_data(31, &data(10, b'4'));
        // 已收到 2 与 4，但 1、3 都缺 → 两个空洞。
        assert_eq!(s.holes(), vec![SeqRange::new(1, 10), SeqRange::new(21, 10)]);
        s.on_data(1, &data(10, b'1'));
        assert_eq!(s.contiguous_len(), 20);
        assert_eq!(s.holes(), vec![SeqRange::new(21, 10)]);
        s.on_data(21, &data(10, b'3'));
        assert_eq!(s.contiguous_len(), 40);
        assert!(s.holes().is_empty());
    }

    // ---- 重传与重叠 ----

    #[test]
    fn retransmission_of_missing_segment_completes_stream() {
        let mut s = stream();
        s.on_syn(0);
        s.on_data(1, &data(10, b'a'));
        s.on_data(21, &data(10, b'c'));
        // 中间段重传两次才到。
        assert_eq!(
            s.on_data(11, &data(10, b'b')),
            SegAction::Accepted { new_bytes: 10 }
        );
        assert_eq!(s.on_data(11, &data(10, b'b')), SegAction::Duplicate);
        assert_eq!(s.contiguous_len(), 30);
    }

    #[test]
    fn overlapping_retransmission_keeps_first_value() {
        let mut s = stream();
        s.on_syn(0);
        s.on_data(1, &data(20, b'a'));
        s.on_data(11, &data(20, b'b')); // 前 10 字节重叠
        let got = s.take_all();
        assert_eq!(&got[..20], data(20, b'a').as_slice());
        assert_eq!(&got[20..], data(10, b'b').as_slice());
        assert_eq!(s.interval_stats().unwrap().conflict_bytes, 10);
    }

    // ---- 内存上限降级 ----

    #[test]
    fn memory_cap_drops_only_hole_deepening_segments() {
        let mut s = small(); // max_buffered = 16
        s.on_syn(0);
        // 先塞满 16 字节乱序数据（第 1 段缺失，全部滞留在缓冲里）。
        s.on_data(11, &data(16, b'x'));
        assert_eq!(s.buffered(), 16);
        // 再来一个只会加深空洞的段 → 丢弃。
        assert_eq!(s.on_data(41, &data(10, b'y')), SegAction::DroppedForMemory);
        assert_eq!(s.stats().memory_drops, 1);
        assert_eq!(s.buffered(), 16, "被丢弃的段不得进入缓冲");
    }

    #[test]
    fn memory_cap_still_accepts_segments_that_advance_the_prefix() {
        let mut s = small();
        s.on_syn(0);
        s.on_data(11, &data(16, b'x'));
        assert_eq!(s.buffered(), 16);
        // 这一段填补了开头，能推进连续前缀 → 即便缓冲已满也照收。
        assert_eq!(
            s.on_data(1, &data(10, b'a')),
            SegAction::Accepted { new_bytes: 10 }
        );
        assert_eq!(s.contiguous_len(), 26);
        assert_eq!(s.stats().memory_drops, 0);
    }

    #[test]
    fn degraded_stream_still_delivers_a_usable_prefix() {
        // 降级语义的核心：即便乱序缓冲被打满，DPI 仍须在流的开头拿到完整前缀。
        let mut s = small(); // max_buffered = 16
        s.on_syn(0);
        s.on_data(1, &data(10, b'a')); // buffered = 10
        s.on_data(21, &data(10, b'y')); // buffered = 20，此时已越限
        s.on_data(41, &data(10, b'z')); // 越限后新增的乱序段 → 丢弃
        assert_eq!(s.stats().memory_drops, 1);
        assert_eq!(s.contiguous_len(), 10, "开头前缀不受降级影响");
        assert_eq!(s.peek(10), data(10, b'a').as_slice());
    }

    // ---- FIN ----

    #[test]
    fn fin_seq_is_the_end_of_data_not_the_start() {
        let mut s = stream();
        s.on_syn(0);
        s.feed(1, &data(10, b'a'), false);
        s.feed(11, b"", true); // FIN，序号 = 11
        assert_eq!(s.fin_seq(), Some(11));
        assert!(s.is_finished());
    }

    #[test]
    fn fin_with_payload_accounts_for_the_payload() {
        let mut s = stream();
        s.on_syn(0);
        s.on_data(1, &data(5, b'a'));
        s.feed(6, &data(5, b'b'), true); // 载荷 5 字节后带 FIN
        assert_eq!(s.fin_seq(), Some(11), "FIN 序号 = 6 + 5");
        assert!(s.is_finished());
    }

    #[test]
    fn stream_is_not_finished_while_a_hole_remains() {
        let mut s = stream();
        s.on_syn(0);
        s.on_data(1, &data(5, b'a'));
        s.on_data(21, &data(5, b'c'));
        s.feed(26, b"", true);
        assert!(!s.is_finished(), "中间还有空洞");
        assert_eq!(s.holes(), vec![SeqRange::new(6, 15)]);
        s.on_data(6, &data(15, b'b'));
        assert!(s.is_finished());
    }

    #[test]
    fn rst_is_recorded() {
        let mut s = stream();
        s.on_rst();
        assert!(s.rst());
        assert!(s.stats().rst_seen);
    }

    // ---- 跨零回绕 ----

    #[test]
    fn wrap_around_reassembles_across_zero() {
        let mut s = stream();
        let isn = 0xFFFF_FFF0u32;
        s.on_syn(isn);
        let base = 0xFFFF_FFF1u32; // ISN+1（已绕过 0）
        assert_eq!(s.base(), Some(base), "ISN+1 也会回绕");
        // 两段共 32 字节，第二段序号回到 0x11。
        s.on_data(0x01, &data(16, b'b'));
        s.on_data(base, &data(16, b'a'));
        assert_eq!(s.contiguous_len(), 32);
        let mut want = data(16, b'a');
        want.extend_from_slice(&data(16, b'b'));
        assert_eq!(s.take_all(), want);
    }

    // ---- 与 DPI 的衔接 ----

    #[test]
    fn split_client_hello_becomes_identifiable_after_reassembly() {
        // 这是本模块存在的理由：同一个 ClientHello 被切成两段时，
        // 单独看第一段只能得到 NeedMore，重组后才是 Identified。
        let payload = include_bytes!("../../../../datasets/dpi/payloads/tls-basic.bin");
        assert!(payload.len() > 40, "样本需要足够长才谈得上被切开");
        let cut = 40;

        let mut s = stream();
        s.on_syn(0);
        // 只有第一段：DPI 应判 NeedMore（握手长度声明的字节还没到齐）。
        s.on_data(1, &payload[..cut]);
        assert_eq!(
            s.identify_app(443).word(),
            "need_more",
            "仅首段时不可能识别出 TLS"
        );

        // 补上第二段。
        s.on_data(1 + cut as u32, &payload[cut..]);
        assert_eq!(
            s.identify_app(443).word(),
            "identified",
            "重组后必须能识别出 TLS"
        );
    }

    #[test]
    fn out_of_order_client_hello_still_identifies_once_complete() {
        let payload = include_bytes!("../../../../datasets/dpi/payloads/tls-basic.bin");
        let cut = 60;
        let mut s = stream();
        s.on_syn(0);
        // 后半段先到。
        s.on_data(1 + cut as u32, &payload[cut..]);
        assert_eq!(s.identify_app(443).word(), "need_more", "缺开头时不能识别");
        s.on_data(1, &payload[..cut]);
        assert_eq!(s.identify_app(443).word(), "identified");
    }

    #[test]
    fn reassembly_never_manufactures_an_identification() {
        // 反面用例：重组只是把字节摆整齐，**不产生**原本不存在的语义。
        // 垃圾拼起来仍然是垃圾。这条测试守的是"重组后被识别率上升"这个指标
        // 的另一半 —— 上升只能来自"原本被切开的包"，不能来自凭空命中。
        let mut s = stream();
        s.on_syn(0);
        s.on_data(1, &data(100, 0xAB));
        s.on_data(101, &data(100, 0xCD));
        assert_eq!(s.contiguous_len(), 200, "字节确实都到齐了");
        assert!(
            !matches!(s.identify_app(9999), Outcome::Identified(_)),
            "重组不得把垃圾流变成已识别"
        );
    }

    // ---- 杂项 ----

    #[test]
    fn empty_payload_changes_nothing() {
        let mut s = stream();
        assert_eq!(s.on_data(1, b""), SegAction::Empty);
        assert_eq!(s.stats().segments, 0);
        assert!(!s.anchored_by_syn());
    }

    #[test]
    fn take_more_than_available_returns_the_prefix() {
        let mut s = stream();
        s.on_syn(0);
        s.on_data(1, &data(5, b'a'));
        assert_eq!(s.take(100), data(5, b'a'));
        assert_eq!(s.contiguous_len(), 0);
    }

    #[test]
    fn covers_reports_whether_a_seq_is_in_the_prefix() {
        let mut s = stream();
        s.on_syn(0);
        s.on_data(1, &data(10, b'a'));
        assert!(s.covers(1));
        assert!(s.covers(10));
        assert!(!s.covers(11), "半开区间：前缀是 [1,11)");
        assert!(!s.covers(0));
    }

    #[test]
    fn has_prefix_is_a_convenience_bound() {
        let mut s = stream();
        s.on_syn(0);
        s.on_data(1, &data(10, b'a'));
        assert!(s.has_prefix(10));
        assert!(!s.has_prefix(11));
    }
}
