// reassembly/seq.rs —— TCP 32 位序号的回绕算术。
//
// 为什么这一层必须单独存在，而不是直接写 `a < b`：
//   TCP 序号是**模 2^32 的循环空间**。ISN 接近 0xFFFFFFFF 的连接，下一段数据序号就
//   绕回 0x0000000x，此时 `a < b` 会判定"新数据在旧数据之前"，于是整条流被当成
//   全部重传而丢弃。省网链路上的长连接跑满几 GB 是常态（2^32 字节 ≈ 4.3 GB），
//   回绕**不是边界情况而是必现情况** —— 一条 10 Gbps 链路跑满约 3.4 秒就绕一圈。
//
// 判定规则（RFC 793 / 9293 的隐含约定）：
//   把 `a - b` 当成**有符号 32 位**看。差为负则 a 在 b 之前，差为正则 a 在 b 之后。
//   这等价于"取模意义下距离小于半个序号空间"的那个方向。
//
// 由此产生一个**不可避免的退化点**，这里显式记录而不是藏着：
//   当 |a - b| 恰好等于 2^31 时，a 在 b 之前与 b 在 a 之前同时成立。
//   这不是实现缺陷，是循环空间的固有性质（地球上的"对跖点"往哪边走都一样远）。
//   真实窗口远小于 2^31（本模块用 `max_span` 硬限，默认远小于此），因此不可达；
//   下面 `distance_is_exactly_half_space_is_ambiguous` 这条测试把它固化成文档。

/// 序号空间的一半（2^31）。
pub const SEQ_HALF: u32 = 1 << 31;

/// 有符号距离：a 相对 b 的偏移量，范围 [-2^31, 2^31)。
///
/// 用 `i64` 而不是 `i32` 是为了让调用方可以放心地做 `+ len`、`* 2` 等算术而不溢出；
/// 取值范围本身仍被限制在一个 32 位循环周期内。
pub fn seq_offset(a: u32, b: u32) -> i64 {
    // `wrapping_sub` 得到模 2^32 的差；`as i32` 是按二进制补码重新解释（Rust 中
    // 整型 `as` 转换定义为按位截断，不是 UB）。这两步合起来就是"按有符号看差值"。
    i64::from(a.wrapping_sub(b) as i32)
}

/// a 是否严格在 b 之前。
pub fn seq_lt(a: u32, b: u32) -> bool {
    seq_offset(a, b) < 0
}

/// a 是否在 b 之前或相等。
pub fn seq_le(a: u32, b: u32) -> bool {
    seq_offset(a, b) <= 0
}

/// a 是否严格在 b 之后。
pub fn seq_gt(a: u32, b: u32) -> bool {
    seq_offset(a, b) > 0
}

/// a 是否在 b 之后或相等。
pub fn seq_ge(a: u32, b: u32) -> bool {
    seq_offset(a, b) >= 0
}

/// 序号加法（模 2^32）。
///
/// 参数取 `u32` 而非 `usize`：单个 TCP 段的载荷上限是 65535 - 20(IP) - 20(TCP)，
/// 远小于 2^32，调用方不可能需要一个真正超 32 位的增量。把它约束在类型里，
/// 比在文档里写"请不要传大数"可靠。
pub fn seq_add(a: u32, n: u32) -> u32 {
    a.wrapping_add(n)
}

/// 取两个序号中"更靠前"的那个。
pub fn seq_min(a: u32, b: u32) -> u32 {
    if seq_le(a, b) {
        a
    } else {
        b
    }
}

/// 取两个序号中"更靠后"的那个。
pub fn seq_max(a: u32, b: u32) -> u32 {
    if seq_ge(a, b) {
        a
    } else {
        b
    }
}

/// 半开序号区间 `[start, end)`。
///
/// 刻意用半开区间：TCP 里"长度"天然是 `end - start`，用闭区间会在每个调用点
/// 都冒出 `+1 / -1`，而这类差一错误在重组里表现为"流末端少一个字节"，
/// 只有跑完整条流才看得出来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqRange {
    pub start: u32,
    pub end: u32,
}

impl SeqRange {
    /// 由起点与长度构造。
    pub fn new(start: u32, len: u32) -> Self {
        Self {
            start,
            end: seq_add(start, len),
        }
    }

    /// 空区间（起点 == 终点）。
    pub fn empty_at(at: u32) -> Self {
        Self { start: at, end: at }
    }

    /// 区间长度（模 2^32 语义下的字节数）。
    pub fn len(&self) -> u32 {
        self.end.wrapping_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// 序号是否落在区间内。
    pub fn contains(&self, seq: u32) -> bool {
        seq_ge(seq, self.start) && seq_lt(seq, self.end)
    }

    /// `other` 是否被本区间完整包含。
    pub fn contains_range(&self, other: &SeqRange) -> bool {
        if other.is_empty() {
            return self.contains(other.start);
        }
        seq_ge(other.start, self.start) && seq_le(other.end, self.end)
    }

    /// 两区间是否有公共字节。空区间与任何区间都不重叠。
    pub fn overlaps(&self, other: &SeqRange) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        seq_lt(self.start, other.end) && seq_lt(other.start, self.end)
    }

    /// 是否相邻或重叠（即两者可以合并成一个连续区间）。
    pub fn touches(&self, other: &SeqRange) -> bool {
        if self.is_empty() || other.is_empty() {
            // 空区间贴在端点上：视作可"合并"（合并后等于另一个区间）。
            return self.start == other.start
                || self.end == other.end
                || self.end == other.start
                || other.end == self.start;
        }
        seq_le(self.start, other.end) && seq_le(other.start, self.end)
    }

    /// 交集；无公共字节返回 `None`。
    pub fn intersection(&self, other: &SeqRange) -> Option<SeqRange> {
        if !self.overlaps(other) {
            return None;
        }
        Some(SeqRange {
            start: seq_max(self.start, other.start),
            end: seq_min(self.end, other.end),
        })
    }

    /// 并集（外包）。仅在两区间重叠或相邻时语义正确；
    /// 其他情况下返回的是"覆盖两端点的最大区间"，会凭空吞掉中间从未收到的字节，
    /// 因此调用方必须先判 `touches`。
    pub fn union(&self, other: &SeqRange) -> SeqRange {
        SeqRange {
            start: seq_min(self.start, other.start),
            end: seq_max(self.end, other.end),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 基本比较 ----

    #[test]
    fn plain_ordering_without_wrap() {
        assert!(seq_lt(100, 200));
        assert!(!seq_lt(200, 100));
        assert!(seq_ge(200, 200));
        assert!(!seq_gt(200, 200));
    }

    #[test]
    fn wrap_makes_later_seq_numerically_smaller() {
        // ISN 在 0xFFFFFFF0 附近，绕回后序号数值变小但语义上更靠后。
        let a = 0xFFFF_FFF0u32;
        let b = 0x0000_0010u32; // a + 32（绕过 0）
        assert!(seq_lt(a, b), "绕回后 b 的序号数值更小，但语义上在 a 之后");
        assert!(seq_gt(b, a));
        assert_eq!(seq_offset(b, a), 32);
        assert_eq!(seq_offset(a, b), -32);
    }

    #[test]
    fn add_wraps_past_zero() {
        assert_eq!(seq_add(0xFFFF_FFF0, 0x20), 0x10);
        assert_eq!(seq_add(0, 0), 0);
    }

    #[test]
    fn distance_is_exactly_half_space_is_ambiguous() {
        // 见文件头说明：这是循环空间的固有性质，不是 bug。此测试把它固化成文档，
        // 防止有人"修好"它时把半空间之外的正确判定一起改坏。
        let a = 0u32;
        let b = SEQ_HALF;
        assert!(seq_lt(a, b));
        assert!(seq_lt(b, a), "恰好相距半个序号空间时两个方向都成立");
    }

    #[test]
    fn min_max_are_wrap_aware() {
        // 0xFFFFFFF0 与 0x10：语义上前者在前。
        assert_eq!(seq_min(0xFFFF_FFF0, 0x10), 0xFFFF_FFF0);
        assert_eq!(seq_max(0xFFFF_FFF0, 0x10), 0x10);
        // 普通情形不应被回绕规则扭曲。
        assert_eq!(seq_min(5, 9), 5);
        assert_eq!(seq_max(5, 9), 9);
    }

    // ---- 区间 ----

    #[test]
    fn range_len_is_modular() {
        let r = SeqRange::new(0xFFFF_FFF0, 0x20);
        assert_eq!(r.len(), 0x20);
        assert!(r.contains(0xFFFF_FFFF));
        assert!(r.contains(0x0F));
        assert!(!r.contains(0x10), "半开区间不含 end");
    }

    #[test]
    fn empty_range_overlaps_nothing() {
        let e = SeqRange::empty_at(10);
        let r = SeqRange::new(5, 100);
        assert!(e.is_empty());
        assert!(!e.overlaps(&r));
        assert!(!r.overlaps(&e));
        assert_eq!(e.intersection(&r), None);
    }

    #[test]
    fn overlap_and_intersection() {
        let a = SeqRange::new(100, 50); // [100,150)
        let b = SeqRange::new(120, 50); // [120,170)
        assert!(a.overlaps(&b));
        assert_eq!(a.intersection(&b), Some(SeqRange::new(120, 30)));

        let c = SeqRange::new(150, 10); // 紧邻 a 的尾
        assert!(!a.overlaps(&c), "半开区间 [100,150) 与 [150,160) 不重叠");
        assert!(a.touches(&c), "但相邻，可合并");
        assert_eq!(a.union(&c), SeqRange::new(100, 60));
    }

    #[test]
    fn disjoint_ranges_do_not_touch() {
        let a = SeqRange::new(100, 10); // [100,110)
        let b = SeqRange::new(111, 10); // [111,121)
        assert!(!a.overlaps(&b));
        assert!(!a.touches(&b), "中间缺 1 字节，不能合并");
    }

    #[test]
    fn contains_range_handles_full_cover() {
        let outer = SeqRange::new(100, 100); // [100,200)
        assert!(outer.contains_range(&SeqRange::new(120, 10)));
        assert!(!outer.contains_range(&SeqRange::new(190, 20)));
        assert!(outer.contains_range(&SeqRange::empty_at(150)));
    }

    // ---- 跨零点的重组场景（回归） ----

    #[test]
    fn segments_spanning_zero_keep_order() {
        // 一条流：base=0xFFFFFFF0，两段各 16 字节，第二段正好跨过 0。
        let base = 0xFFFF_FFF0u32;
        let s1 = SeqRange::new(base, 16); // [FFFFFFF0, 00000000)
        let s2 = SeqRange::new(seq_add(base, 16), 16); // [00000000, 00000010)
        assert_eq!(s1.end, s2.start, "两段应首尾相接");
        assert!(s1.touches(&s2));
        assert_eq!(s1.union(&s2).len(), 32);
        assert!(seq_ge(s2.start, s1.start));
    }
}
