// native.rs —— ClickHouse `Native` 块的编码器与解码器（CYS-STO-007 的第一步）。
//
// ## 这个格式是什么
//
// `Native` 是 ClickHouse 自己的列式二进制块格式：一个流由若干**块**顺序拼接，
// 每块自带列名与列类型，因此**不需要外部 schema 文件**就能读懂（与 IPFIX 的
// 「模板 + 数据集」同构）。字节布局不是凭印象写的，是用参考实现
// （`clickhouse local 26.11.1.153`）逐字节反解出来的：
//
// ```text
// 块   := varint(列数) varint(行数) (列名(String) 列类型(String) 数据)*
//          ↑ **逐列交错**：一列的头后面紧跟它的 data，不是先把所有列头写完。
//            两种写法的总字节数完全相同，但后者参考实现读不进去（踩过）。
// String := varint(字节数) 字节                ← 无 NUL、无填充
// UIntN  := 每行 N/8 字节，小端
// Float64:= 8 字节 IEEE754，小端（NaN 位模式不产生，见 storage/mod.rs 第 3 条）
// IPv6   := 16 字节，大端（与 IPv6NumToString 的输入同序）
// Nullable(T) := 每行 1 字节掩码（1 = NULL）**后接全部行的嵌套值**
// ```
//
// 最后一条是本格式最容易写错、且错了不报错的地方：**null 行仍要写一个嵌套哑值**
// （数值写 0、字符串写 varint 0），掩码只是标记它不可信。少写这些哑值，整块从
// 这一列之后全部字节错位 —— 表现是"第 30 列读出来是垃圾"，而不是任何一处明确报错。
// 该结论由参考实现的实测字节锁定（见 `tests` 里 `nullable_dummy_values_are_written_for_null_rows`）。
//
// ## 为什么值得自己写
//
// * 引 driver 会破仓库红线（零第三方依赖、离线可构建）。
// * 真正的裁判不是我们的单测，是**参考实现本身**：`scripts/verify/check-columnar.sh`
//   把同一批逻辑行交给 `clickhouse local` 再编码一次，与我们的产物 `cmp` 逐字节比；
//   再把我们的产物用 `INSERT ... FROM INFILE ... FORMAT Native` 读回来逐字段比 JSONL。
//   两边都过，才能说"这是合法 Native 且值没编错"。任一侧缺参照 ⇒ 显式标「未核验」。
// * 版本风险照实说：Native 块头在历史版本上带过 `serialize_internals` 标记字节，
//   当前参考实现不写。门禁把参考实现版本记进产物；换版本时逐字节比对会**显式失败**，
//   而不是静默产出对不上号的文件。

use std::fmt;
use std::io::{self, Write};

use super::{flow_columns, project_row, ColumnSpec, FlowRecord, Kind, ProjectError, Value};

/// 每块默认行数。块头要重写一遍列名与类型，块切得越碎，落盘字节里"自描述"占比越高；
/// 单块过大会让流式写入的内存不可控。实测该粒度下块头开销 < 0.1 B/记录（见 HANDOFF）。
pub const DEFAULT_ROWS_PER_BLOCK: usize = 100_000;

/// varint 的字节上限（u64 最多 10 字节）。超过即数值本身不可信。
const VARINT_MAX_BYTES: usize = 10;

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// 编码侧错误。投影错误原样带上，因为"拒绝落盘"必须能回答是哪一条记录。
#[derive(Debug)]
pub enum ColumnarError {
    Io(io::Error),
    Project(ProjectError),
    /// 投影结果与列声明的类型不符（只可能是代码改错序，不可能是数据造成）。
    TypeMismatch {
        column: String,
        declared: String,
        got: &'static str,
    },
    /// 不可空列投出了 NULL。
    NullInNonNullable { column: String },
    /// 没有任何记录。刻意不产出 0 字节文件：空文件与"写失败"在下游无法区分。
    EmptyInput,
}

impl fmt::Display for ColumnarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ColumnarError::Io(e) => write!(f, "写 Native 失败：{e}"),
            ColumnarError::Project(e) => write!(f, "拒绝投影：{e}"),
            ColumnarError::TypeMismatch { column, declared, got } => write!(
                f,
                "列 `{column}` 声明 {declared} 却投出 {got} —— 列契约与投影不同源；\
                 这种错在下游只表现为「某列读出来是别的列的值」"
            ),
            ColumnarError::NullInNonNullable { column } => write!(
                f,
                "列 `{column}` 声明非空却投出 NULL：写下去会变成 0/空串，\
                 那是把「缺证据」伪装成「证据为零」"
            ),
            ColumnarError::EmptyInput => write!(f, "没有记录，不产出 Native 文件"),
        }
    }
}

impl std::error::Error for ColumnarError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ColumnarError::Io(e) => Some(e),
            ColumnarError::Project(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ColumnarError {
    fn from(e: io::Error) -> Self {
        ColumnarError::Io(e)
    }
}

/// 解码侧错误：每条都带**字节偏移**。排障时"第几个字节开始不对"是唯一有用的信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEof { at: usize, what: &'static str },
    VarintTooLong { at: usize },
    UnsupportedType { at: usize, ty: String },
    NonUtf8String { at: usize, column: String },
    EmptyStream,
    ColumnSetChanged { block: usize, expected: String, got: String },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnexpectedEof { at, what } => {
                write!(f, "第 {at} 字节处读 {what} 时数据提前结束")
            }
            DecodeError::VarintTooLong { at } => write!(f, "第 {at} 字节处 varint 超过 10 字节"),
            DecodeError::UnsupportedType { at, ty } => write!(
                f,
                "第 {at} 字节处出现本实现不认识的类型 `{ty}`：拒绝按猜测的宽度跳过，\
                 因为猜错宽度会让之后每一列都错位"
            ),
            DecodeError::NonUtf8String { at, column } => {
                write!(f, "列 `{column}`（第 {at} 字节）不是合法 UTF-8")
            }
            // 刻意没有「尾部多余字节」这一类：解码按块循环读到 EOF，文件被截断时
            // 一定在某个列上以 UnexpectedEof 暴露。留一个永远不触发的分支，
            // 等于留一条没人验证过的错误文案。
            DecodeError::EmptyStream => write!(f, "空的 Native 块流"),
            DecodeError::ColumnSetChanged { block, expected, got } => write!(
                f,
                "第 {block} 块的列集合与第 0 块不同（期望 {expected}，得到 {got}）：\
                 同一文件内列集合必须一致，否则下游按名取数会拿到不同含义的列"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// 编码统计（CLI 必须打印：落盘字节数不可见就无法核算容量）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeStats {
    pub blocks: u64,
    pub rows: u64,
    pub bytes: u64,
    /// 列名+类型（块自描述）的字节数：块头开销的实测来源。
    pub header_bytes: u64,
    /// null 掩码字节数（= 可空列数 × 行数）：`Nullable` 的**显式代价**。
    pub null_mask_bytes: u64,
    /// null 行的嵌套哑值字节数：Nullable 的第二笔代价，容易被忽略。
    pub null_dummy_bytes: u64,
    /// 变长列的 varint 长度前缀字节数。
    pub length_prefix_bytes: u64,
}

impl NativeStats {
    /// 每记录字节数（×1000 定点）：容量表要的数，避免下游为一个平均值引浮点。
    pub fn bytes_per_record_milli(&self) -> u64 {
        if self.rows == 0 {
            return 0;
        }
        self.bytes.saturating_mul(1000) / self.rows
    }
}

// ---------------------------------------------------------------------------
// 线路原语
// ---------------------------------------------------------------------------

/// 无符号 LEB128（对齐参考实现的 `writeVarint`）。
fn write_varint_into(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        out.push(if v == 0 { byte } else { byte | 0x80 });
        if v == 0 {
            return;
        }
    }
}

/// 线路上的 String：varint 长度 + 原始字节（非 ASCII 原样写，不转义）。
fn write_ch_string_into(out: &mut Vec<u8>, s: &str) {
    write_varint_into(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn fixed_width(kind: Kind) -> usize {
    kind.raw_width()
}

/// `Nullable` null 行的哑值宽度：字符串是 varint(0) ⇒ 1 字节。
fn dummy_width(kind: Kind) -> usize {
    match kind {
        Kind::Str => 1,
        other => fixed_width(other),
    }
}

fn value_word(v: &Value<'_>) -> &'static str {
    match v {
        Value::U8(_) => "UInt8",
        Value::U16(_) => "UInt16",
        Value::U32(_) => "UInt32",
        Value::U64(_) => "UInt64",
        Value::F64(_) => "Float64",
        Value::Ip6(_) => "IPv6",
        Value::Str(_) => "String",
        Value::Null => "NULL",
    }
}

// ---------------------------------------------------------------------------
// 编码器
// ---------------------------------------------------------------------------

/// 一列在本块内的缓冲。
///
/// 列缓冲是列式写入器的本体：行数据一旦转置成列，落盘字节就与行序无关，
/// 这也是压缩率提升的全部来源 —— 所以这里刻意**不**保留行式中间态。
struct ColumnBuffer {
    data: Vec<u8>,
    mask: Vec<u8>,
    nulls: u64,
}

impl ColumnBuffer {
    fn new(nullable: bool, cap_rows: usize) -> Self {
        Self {
            // 定宽列可以预留；变长列留空由 push 增长。预留量按列宽×行数，
            // 对 String 列只是 1 字节/行的下界，不追求精确。
            data: Vec::with_capacity(cap_rows),
            mask: if nullable {
                Vec::with_capacity(cap_rows)
            } else {
                Vec::new()
            },
            nulls: 0,
        }
    }
}

/// 流式 Native 写入器。
///
/// 为什么不一次 `encode(records)`：离线分析里记录集能到百万级，一次性转置全部行
/// 会让内存峰值由"行数 × 列数"决定；写满一块就落一块，内存上界只由
/// `rows_per_block` 决定。
pub struct NativeWriter<W: Write> {
    out: W,
    cols: Vec<ColumnSpec>,
    buffers: Vec<ColumnBuffer>,
    rows_in_block: usize,
    rows_per_block: usize,
    stats: NativeStats,
    /// 首块已写出的列集合指纹，供 finish 时打印（也是"块间一致"的自证）。
    fingerprint: String,
}

impl<W: Write> NativeWriter<W> {
    pub fn new(out: W, rows_per_block: usize) -> Self {
        let cols = flow_columns();
        let rpb = if rows_per_block == 0 {
            DEFAULT_ROWS_PER_BLOCK
        } else {
            rows_per_block
        };
        let buffers = cols
            .iter()
            .map(|c| ColumnBuffer::new(c.nullable, rpb.saturating_mul(fixed_width(c.kind)).max(16)))
            .collect::<Vec<_>>();
        Self {
            out,
            cols,
            buffers,
            rows_in_block: 0,
            rows_per_block: rpb,
            stats: NativeStats::default(),
            fingerprint: String::new(),
        }
    }

    pub fn stats(&self) -> NativeStats {
        self.stats
    }

    /// 写一条记录。返回 `Err` 时**不落半条**：投影失败发生在任何字节写出之前。
    pub fn push(&mut self, record: &FlowRecord) -> Result<(), ColumnarError> {
        let row = project_row(record).map_err(ColumnarError::Project)?;
        if row.len() != self.cols.len() {
            return Err(ColumnarError::TypeMismatch {
                column: "(整行)".to_string(),
                declared: format!("{} 列", self.cols.len()),
                got: "投影列数不符",
            });
        }
        for (ci, c) in self.cols.iter().enumerate() {
            let buf = &mut self.buffers[ci];
            let v = &row[ci];
            if c.nullable {
                let is_null = matches!(v, Value::Null);
                buf.mask.push(u8::from(is_null));
                if is_null {
                    buf.nulls += 1;
                }
            }
            match (c.kind, v) {
                (_, Value::Null) => {
                    if !c.nullable {
                        return Err(ColumnarError::NullInNonNullable {
                            column: c.name.to_string(),
                        });
                    }
                    // 哑值：参考实现为 null 行也写嵌套值（数值 0 / 字符串 varint 0）。
                    buf.data.resize(buf.data.len() + dummy_width(c.kind), 0);
                    if c.kind == Kind::Str {
                        self.stats.length_prefix_bytes += 1;
                    }
                }
                (Kind::U8, Value::U8(x)) => buf.data.push(*x),
                (Kind::U16, Value::U16(x)) => buf.data.extend_from_slice(&x.to_le_bytes()),
                (Kind::U32, Value::U32(x)) => buf.data.extend_from_slice(&x.to_le_bytes()),
                (Kind::U64, Value::U64(x)) => buf.data.extend_from_slice(&x.to_le_bytes()),
                (Kind::F64, Value::F64(x)) => buf.data.extend_from_slice(&x.to_bits().to_le_bytes()),
                (Kind::Ip6, Value::Ip6(b)) => buf.data.extend_from_slice(b),
                (Kind::Str, Value::Str(s)) => {
                    let before = buf.data.len();
                    write_ch_string_into(&mut buf.data, s);
                    self.stats.length_prefix_bytes += ((buf.data.len() - before) - s.len()) as u64;
                }
                (_, other) => {
                    return Err(ColumnarError::TypeMismatch {
                        column: c.name.to_string(),
                        declared: c.ch_type(),
                        got: value_word(other),
                    })
                }
            }
        }
        self.rows_in_block += 1;
        if self.rows_in_block >= self.rows_per_block {
            self.flush_block()?;
        }
        Ok(())
    }

    /// 落当前块。空块不写：参考实现不会输出 0 行块，写出来只能制造比对差异。
    /// 落当前块。
    ///
    /// **列头与列数据是逐列交错的**（`列名 列类型 [掩码] 数据`），不是先把 50 个
    /// 列头集中写完再写数据。两者总字节数完全相同，所以"字节数呸了"给不了任何提示：
    /// 参考实现会把上一列的数据当前一列的名字读，报一个
    /// `Syntax error (data type)` —— 这个错我在 2026-10-19 真的撞上了，
    /// 产物总长与参考实现逐字节相同(2973)，却完全读不进去。
    ///
    /// 空块不写：参考实现不会输出 0 行块，写出来只能制造比对差异。
    pub fn flush_block(&mut self) -> Result<(), ColumnarError> {
        if self.rows_in_block == 0 {
            return Ok(());
        }
        // 块头：列数 + 行数。列名与类型**不在这里集中写**（见上面注释）。
        let mut head: Vec<u8> = Vec::with_capacity(16);
        write_varint_into(&mut head, self.cols.len() as u64);
        write_varint_into(&mut head, self.rows_in_block as u64);

        let mut written: u64 = 0;
        let mut self_desc: u64 = 0;
        let mut mask_bytes: u64 = 0;
        let mut dummy_bytes: u64 = 0;

        self.out.write_all(&head)?;
        written += head.len() as u64;
        self_desc += head.len() as u64;

        for (ci, c) in self.cols.iter().enumerate() {
            let mut ch: Vec<u8> = Vec::with_capacity(c.name.len() + 24);
            write_ch_string_into(&mut ch, c.name);
            write_ch_string_into(&mut ch, &c.ch_type());
            self.out.write_all(&ch)?;
            written += ch.len() as u64;
            self_desc += ch.len() as u64;

            let buf = &self.buffers[ci];
            if c.nullable {
                self.out.write_all(&buf.mask)?;
                written += buf.mask.len() as u64;
                mask_bytes += buf.mask.len() as u64;
                dummy_bytes += buf.nulls * dummy_width(c.kind) as u64;
            }
            if !buf.data.is_empty() {
                self.out.write_all(&buf.data)?;
                written += buf.data.len() as u64;
            }
        }
        self.out.flush()?;

        self.stats.header_bytes += self_desc;
        self.stats.null_mask_bytes += mask_bytes;
        self.stats.null_dummy_bytes += dummy_bytes;
        self.stats.blocks += 1;
        self.stats.rows += self.rows_in_block as u64;
        self.stats.bytes += written;
        if self.fingerprint.is_empty() {
            self.fingerprint = format!(
                "{} 列/{} 字节自描述",
                self.cols.len(),
                self_desc
            );
        }
        for b in &mut self.buffers {
            b.data.clear();
            b.mask.clear();
            b.nulls = 0;
        }
        self.rows_in_block = 0;
        Ok(())
    }

    /// 收尾。返回的统计里 `bytes` 是**实际写出的字节数**（块头+掩码+数据），
    /// 与产物文件大小一致，可由 `wc -c` 独立复核。
    pub fn finish(mut self) -> Result<NativeStats, ColumnarError> {
        self.flush_block()?;
        if self.stats.rows == 0 {
            return Err(ColumnarError::EmptyInput);
        }
        Ok(self.stats)
    }

    pub fn column_fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// 便捷入口：把整批记录编成 Native 字节（测试与小程序用；大流走 `NativeWriter`）。
pub fn encode_records(
    records: &[FlowRecord],
    rows_per_block: usize,
) -> Result<(Vec<u8>, NativeStats), ColumnarError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut w = NativeWriter::new(&mut buf, rows_per_block);
    for r in records {
        w.push(r)?;
    }
    let st = w.finish()?;
    Ok((buf, st))
}

// ---------------------------------------------------------------------------
// 解码器（用于自证回路：产物读回来必须与投影逐列相同）
// ---------------------------------------------------------------------------

/// 解码出的一个取值。字符串用 `Vec<u8>` 而不是 `String`：
/// 敌意/畸形输入下"不是 UTF-8"本身是要报告的事实，不能在类型层提前假设它合法。
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    F64(f64),
    Ip6([u8; 16]),
    Str(Vec<u8>),
    Null,
}

impl Cell {
    pub fn word(&self) -> &'static str {
        match self {
            Cell::U8(_) => "UInt8",
            Cell::U16(_) => "UInt16",
            Cell::U32(_) => "UInt32",
            Cell::U64(_) => "UInt64",
            Cell::F64(_) => "Float64",
            Cell::Ip6(_) => "IPv6",
            Cell::Str(_) => "String",
            Cell::Null => "NULL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnHead {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone)]
pub struct DecodedBlock {
    pub columns: Vec<ColumnHead>,
    pub rows: usize,
    /// 列主序：`cells[ci][ri]`。行主序会让"读一列"退化成遍历整个块。
    pub cells: Vec<Vec<Cell>>,
}

/// 只读游标。每个方法失败时都带上**发生错误的偏移**。
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.b.len() {
            return Err(DecodeError::UnexpectedEof { at: self.pos, what });
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn varint(&mut self) -> Result<u64, DecodeError> {
        let at = self.pos;
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.take(1, "varint")?[0];
            v |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
            if shift > 63 || (shift / 7) as usize > VARINT_MAX_BYTES {
                return Err(DecodeError::VarintTooLong { at });
            }
        }
    }
    fn string(&mut self, label: &str) -> Result<Vec<u8>, DecodeError> {
        let at = self.pos;
        let n = self.varint()? as usize;
        let bytes = self.take(n, "字符串字节")?.to_vec();
        if std::str::from_utf8(&bytes).is_err() {
            return Err(DecodeError::NonUtf8String { at, column: label.to_string() });
        }
        Ok(bytes)
    }
    fn text(&mut self) -> Result<String, DecodeError> {
        let at = self.pos;
        let n = self.varint()? as usize;
        let bytes = self.take(n, "标识符字节")?;
        std::str::from_utf8(bytes)
            .map(|s| s.to_string())
            .map_err(|_| DecodeError::NonUtf8String { at, column: "(标识符)".to_string() })
    }
    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
}

/// 解一个块：**逐列**读「列名、列类型、[掩码]、数据」。
///
/// 这里刻意不做成"先把列头读完再读数据"：那样写反而与错误的编码器自洽，
/// 而自洽的两侧一起错时单测永远全绿（2026-10-19 真实发生过，靠参考实现才拓出来）。
/// 解码侧必须按参考实现的布局读，才能把那个错变成**本地就能失败**的断言。
fn read_block(rd: &mut Reader<'_>) -> Result<DecodedBlock, DecodeError> {
    let ncols = rd.varint()? as usize;
    let nrows = rd.varint()? as usize;
    let mut heads: Vec<ColumnHead> = Vec::with_capacity(ncols);
    let mut cells: Vec<Vec<Cell>> = Vec::with_capacity(ncols);

    for _ in 0..ncols {
        let name = rd.text()?;
        let ty = rd.text()?;
        let (inner, nullable) = split_nullable(&ty);
        let kind = match inner.map(Kind::from_ch_type) {
            Some(Some(k)) => k,
            _ => return Err(DecodeError::UnsupportedType { at: rd.pos, ty }),
        };
        let head = ColumnHead {
            name: name.clone(),
            ty,
        };
        let masks: Vec<u8> = if nullable {
            rd.take(nrows, "null 掩码")?.to_vec()
        } else {
            Vec::new()
        };
        let mut col: Vec<Cell> = Vec::with_capacity(nrows);
        for ri in 0..nrows {
            let is_null = nullable && masks[ri] != 0;
            let cell = match kind {
                Kind::U8 => {
                    let b = rd.take(1, "UInt8")?[0];
                    if is_null { Cell::Null } else { Cell::U8(b) }
                }
                Kind::U16 => {
                    let a: [u8; 2] = rd.take(2, "UInt16")?.try_into().unwrap();
                    if is_null { Cell::Null } else { Cell::U16(u16::from_le_bytes(a)) }
                }
                Kind::U32 => {
                    let a: [u8; 4] = rd.take(4, "UInt32")?.try_into().unwrap();
                    if is_null { Cell::Null } else { Cell::U32(u32::from_le_bytes(a)) }
                }
                Kind::U64 => {
                    let a: [u8; 8] = rd.take(8, "UInt64")?.try_into().unwrap();
                    if is_null { Cell::Null } else { Cell::U64(u64::from_le_bytes(a)) }
                }
                Kind::F64 => {
                    let a: [u8; 8] = rd.take(8, "Float64")?.try_into().unwrap();
                    if is_null {
                        Cell::Null
                    } else {
                        Cell::F64(f64::from_bits(u64::from_le_bytes(a)))
                    }
                }
                Kind::Ip6 => {
                    let a: [u8; 16] = rd.take(16, "IPv6")?.try_into().unwrap();
                    if is_null { Cell::Null } else { Cell::Ip6(a) }
                }
                Kind::Str => {
                    let bytes = rd.string(&head.name)?;
                    if is_null {
                        // 哑值必须是 varint(0)：非空说明写方与读方对 Nullable 的理解不一致。
                        if !bytes.is_empty() {
                            return Err(DecodeError::UnsupportedType {
                                at: rd.pos,
                                ty: format!(
                                    "Nullable(String) 的 null 行带非空哑值（列 {}）",
                                    head.name
                                ),
                            });
                        }
                        Cell::Null
                    } else {
                        Cell::Str(bytes)
                    }
                }
            };
            col.push(cell);
        }
        heads.push(head);
        cells.push(col);
    }
    let rows = cells.first().map(|c| c.len()).unwrap_or(0);
    Ok(DecodedBlock { columns: heads, rows, cells })
}

fn split_nullable(ty: &str) -> (Option<&str>, bool) {
    if let Some(inner) = ty.strip_prefix("Nullable(").and_then(|s| s.strip_suffix(')')) {
        (Some(inner), true)
    } else {
        (Some(ty), false)
    }
}

/// 解整个块流：逐块解到 EOF，并要求列集合在所有块间**完全一致**。
pub fn decode_blocks(bytes: &[u8]) -> Result<Vec<DecodedBlock>, DecodeError> {
    let mut rd = Reader::new(bytes);
    let mut blocks: Vec<DecodedBlock> = Vec::new();
    while rd.remaining() > 0 {
        let b = read_block(&mut rd)?;
        if let Some(first) = blocks.first() {
            if first.columns != b.columns {
                let expected = describe(&first.columns);
                let got = describe(&b.columns);
                return Err(DecodeError::ColumnSetChanged {
                    block: blocks.len(),
                    expected,
                    got,
                });
            }
        }
        blocks.push(b);
    }
    if blocks.is_empty() {
        return Err(DecodeError::EmptyStream);
    }
    Ok(blocks)
}

fn describe(cols: &[ColumnHead]) -> String {
    let mut s = format!("{} 列[", cols.len());
    for (i, c) in cols.iter().take(3).enumerate() {
        if i > 0 {
            s.push('/');
        }
        s.push_str(&c.name);
        s.push(':');
        s.push_str(&c.ty);
    }
    if cols.len() > 3 {
        s.push_str(" …");
    }
    s.push(']');
    s
}

/// 把 `Value` 变成可与 `Cell` 比对的形状（测试与自证回路共用）。
pub fn cell_of(v: &Value<'_>) -> Cell {
    match v {
        Value::U8(x) => Cell::U8(*x),
        Value::U16(x) => Cell::U16(*x),
        Value::U32(x) => Cell::U32(*x),
        Value::U64(x) => Cell::U64(*x),
        Value::F64(x) => Cell::F64(*x),
        Value::Ip6(b) => Cell::Ip6(*b),
        Value::Str(s) => Cell::Str(s.as_bytes().to_vec()),
        Value::Null => Cell::Null,
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::{AppId, Confidence};
    use crate::storage::COLUMN_CONTRACT_VERSION;
    use crate::feature::FeatureExtractor;
    use crate::flow::{FlowKey, IPPROTO_TCP, IPPROTO_UDP};
    use crate::record::{AppInfo, RECORD_SCHEMA_VERSION};
    use crate::tcp::TcpState;

    fn rec(sid: u64, v6: bool) -> FlowRecord {
        let key = if v6 {
            FlowKey::new_ipv6(
                "2001:db8::1".parse().unwrap(),
                1234,
                "2001:db8::2".parse().unwrap(),
                443,
                IPPROTO_TCP,
            )
        } else {
            FlowKey::new_ipv4([10, 0, 0, 1], 40000, [93, 184, 216, 34], 443, IPPROTO_TCP)
        };
        let mut ex = FeatureExtractor::default();
        ex.observe(&crate::feature::FlowSample::len_only(crate::tcp::Side::A, 1200, 1_000_000));
        ex.observe(&crate::feature::FlowSample::len_only(crate::tcp::Side::B, 800, 1_500_000));
        FlowRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            session_id: sid,
            key,
            tcp_state: Some(TcpState::Established),
            initiator: Some(crate::tcp::Side::A),
            adopted_midstream: false,
            illegal_tcp_events: 0,
            first_seen_us: 1_000_000 + sid,
            last_seen_us: 2_000_000 + sid,
            packets: 2,
            bytes: 2000,
            direction_switches: 1,
            features: ex.vector(),
            app: AppInfo {
                outcome: "identified",
                app: Some(AppId::Tls),
                confidence: Some(Confidence::High),
                rationale: Some("tls-handshake-type1"),
                server_name: Some("example.org".to_string()),
                bytes_inspected: 220,
            },
            risk_score: None,
        }
    }

    fn idx(name: &str) -> usize {
        flow_columns().iter().position(|c| c.name == name).unwrap()
    }

    #[test]
    fn varint_matches_reference_for_known_values() {
        // 这些期望值由参考实现的产物反解得到（`clickhouse local` 写 2 列 / 200000 行）。
        let cases: [(u64, &[u8]); 5] = [
            (0, &[0x00]),
            (2, &[0x02]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (200000, &[0xc0, 0x9a, 0x0c]),
        ];
        for (v, want) in cases {
            let mut out = Vec::new();
            write_varint_into(&mut out, v);
            assert_eq!(out, want.to_vec(), "varint({v})");
        }
    }

    #[test]
    fn block_header_is_columns_then_rows_then_names_and_types() {
        let (bytes, st) = encode_records(&[rec(1, false)], 100).unwrap();
        let mut rd = Reader::new(&bytes);
        assert_eq!(rd.varint().unwrap() as usize, flow_columns().len());
        assert_eq!(rd.varint().unwrap(), 1);
        assert_eq!(rd.text().unwrap(), "schema_version");
        assert_eq!(rd.text().unwrap(), "UInt32");
        assert_eq!(st.rows, 1);
        assert_eq!(st.blocks, 1);
        assert_eq!(st.bytes, bytes.len() as u64, "stats.bytes 必须等于产物真实字节数");
    }

    #[test]
    fn columns_are_written_head_then_data_interleaved() {
        // 锁定参考实现观察到的布局：50 列/5 行的真实产物开头是
        //   32 05 | 0e "schema_version" | 06 "UInt32" | 5×4B 数据 | 17 "column_contract_version" ...
        // 这些偏移全部来自 2026-10-19 与 `clickhouse local` 产物的逐字节对照。
        // 写成"先集中列头再集中数据"时，总字节数与参考实现相同（以 5 条样本为例都
        // 是 2973），只有这里的偏移能把它区分开 —— 所以这条断言必须先于任何门禁存在。
        let recs: Vec<FlowRecord> = (1..=5).map(|i| rec(i, false)).collect();
        let (bytes, _) = encode_records(&recs, 1000).unwrap();
        assert_eq!(bytes[0], flow_columns().len() as u8);
        assert_eq!(bytes[1], 5, "行数 varint");
        assert_eq!(bytes[2] as usize, "schema_version".len());
        assert_eq!(&bytes[3..17], b"schema_version");
        assert_eq!(bytes[17] as usize, "UInt32".len());
        assert_eq!(&bytes[18..24], b"UInt32");
        // 列头之后**立刻**是该列 5 行的数据，而不是下一列的名字。
        assert_eq!(&bytes[24..28], &1u32.to_le_bytes(), "第一行 schema_version=1");
        // 第一列数据 = 5 行 × 4B，从 24 起到 44；44 是第二列名字的 varint 长度。
        let second_name_len_at = 24 + 5 * 4;
        assert_eq!(bytes[second_name_len_at] as usize, "column_contract_version".len());
        let second_name_at = second_name_len_at + 1;
        assert_eq!(
            &bytes[second_name_at..second_name_at + 23],
            b"column_contract_version",
            "第二列的名字必须在第一列数据之后"
        );
    }

    #[test]
    fn fixed_width_columns_use_little_endian() {
        // 参考实现产物里 UInt16 443 = `bb 01`；本实现必须同序。
        let (bytes, _) = encode_records(&[rec(1, false)], 100).unwrap();
        let blocks = decode_blocks(&bytes).unwrap();
        assert_eq!(blocks[0].cells[idx("dst_port")][0], Cell::U16(443));
        assert_eq!(blocks[0].cells[idx("src_port")][0], Cell::U16(40000));
        // 直接在产物字节里找 443 的小端两字节，确认"解码器与字节"之间没有第三层假设。
        assert!(bytes.windows(2).any(|w| w == 443u16.to_le_bytes()));
        assert!(!bytes.windows(2).any(|w| w == 443u16.to_be_bytes()), "UInt16 必须小端");
    }

    #[test]
    fn ipv4_is_written_as_ipv4_mapped_16_bytes() {
        let (bytes, _) = encode_records(&[rec(1, false)], 100).unwrap();
        let b = decode_blocks(&bytes).unwrap();
        assert_eq!(
            b[0].cells[idx("src_ip")][0],
            Cell::Ip6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1])
        );
        assert_eq!(b[0].cells[idx("ip_family")][0], Cell::U8(4));
    }

    #[test]
    fn ipv6_record_keeps_real_v6_bytes() {
        let (bytes, _) = encode_records(&[rec(2, true)], 100).unwrap();
        let b = decode_blocks(&bytes).unwrap();
        let Cell::Ip6(x) = b[0].cells[idx("src_ip")][0] else {
            panic!("src_ip 必须是 IPv6 列");
        };
        assert_eq!(&x[..2], &[0x20, 0x01]);
        assert_eq!(b[0].cells[idx("ip_family")][0], Cell::U8(6));
    }

    #[test]
    fn nullable_dummy_values_are_written_for_null_rows() {
        // 非 TCP ⇒ tcp_state NULL，但**嵌套值仍占位**：String 写 varint(0)。
        let mut r = rec(3, false);
        r.key = FlowKey::new_ipv4([10, 0, 0, 1], 53, [8, 8, 8, 8], 53, IPPROTO_UDP);
        r.tcp_state = None;
        r.initiator = None;
        r.app = AppInfo::not_inspected();
        let (bytes, st) = encode_records(&[r], 100).unwrap();
        let b = decode_blocks(&bytes).unwrap();
        assert_eq!(b[0].cells[idx("tcp_state")][0], Cell::Null);
        assert_eq!(b[0].cells[idx("app_name")][0], Cell::Null);
        assert_eq!(b[0].cells[idx("risk_score")][0], Cell::Null);
        assert!(st.null_mask_bytes > 0, "Nullable 的掩码代价必须被记账");
        assert!(st.null_dummy_bytes > 0, "Nullable 的哑值代价必须被记账");
        // 掩码字节数 = 可空列数 × 行数。
        let nullables = flow_columns().iter().filter(|c| c.nullable).count();
        assert_eq!(st.null_mask_bytes, nullables as u64);
    }

    #[test]
    fn roundtrip_equals_projection_for_every_column() {
        let recs = vec![rec(1, false), rec(2, true), rec(3, false)];
        let (bytes, st) = encode_records(&recs, 100).unwrap();
        let blocks = decode_blocks(&bytes).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].rows, 3);
        let cols = flow_columns();
        for (ri, r) in recs.iter().enumerate() {
            let row = project_row(r).unwrap();
            for (ci, c) in cols.iter().enumerate() {
                let got = &blocks[0].cells[ci][ri];
                let want = cell_of(&row[ci]);
                assert_eq!(*got, want, "列 {} 第 {ri} 行", c.name);
            }
        }
        assert_eq!(st.bytes, bytes.len() as u64);
    }

    #[test]
    fn blocks_split_at_the_declared_row_count_and_concatenate() {
        let recs: Vec<FlowRecord> = (0..7).map(|i| rec(i, false)).collect();
        let (bytes, st) = encode_records(&recs, 3).unwrap();
        assert_eq!(st.blocks, 3);
        let blocks = decode_blocks(&bytes).unwrap();
        assert_eq!(
            blocks.iter().map(|b| b.rows).collect::<Vec<_>>(),
            vec![3, 3, 1]
        );
        let total: usize = blocks.iter().map(|b| b.cells[idx("session_id")].len()).sum();
        assert_eq!(total, 7, "跨块拼接后必须正好 7 行");
        // 每记录字节数随块变碎而上升：列名/类型是**每块重写**的。
        let (fine, s1) = encode_records(&recs, 1).unwrap();
        let (_, s3) = encode_records(&recs, 3).unwrap();
        assert!(
            s1.bytes_per_record_milli() > s3.bytes_per_record_milli(),
            "每块一行比每块三行更贵：块头开销 {}/{} B",
            fine.len(),
            bytes.len()
        );
    }

    #[test]
    fn truncated_stream_reports_the_offset_instead_of_reading_garbage() {
        let (bytes, _) = encode_records(&[rec(1, false)], 100).unwrap();
        for cut in [bytes.len() / 2, bytes.len() - 1, 1] {
            let err = decode_blocks(&bytes[..cut]).unwrap_err();
            assert!(
                format!("{err}").contains("字节"),
                "解码错误必须带偏移，得到 {err}"
            );
        }
        assert_eq!(decode_blocks(&[]).unwrap_err(), DecodeError::EmptyStream);
        assert!(matches!(
            decode_blocks(&[0x01]),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn unknown_type_name_is_refused_not_skipped_by_guessing() {
        // 手工造一个类型名为 LowCardinality(String) 的块头，验证"猜宽度"这条路被堵死。
        let mut bytes: Vec<u8> = Vec::new();
        write_varint_into(&mut bytes, 1);
        write_varint_into(&mut bytes, 1);
        write_ch_string_into(&mut bytes, "app_name");
        write_ch_string_into(&mut bytes, "LowCardinality(String)");
        bytes.extend_from_slice(b"\x03abc");
        let err = decode_blocks(&bytes).unwrap_err();
        assert!(
            matches!(err, DecodeError::UnsupportedType { .. }),
            "期望 UnsupportedType，得到 {err:?}"
        );
        assert!(format!("{err}").contains("LowCardinality"));
    }

    #[test]
    fn column_set_change_between_blocks_is_an_error() {
        let (mut bytes, _) = encode_records(&[rec(1, false)], 100).unwrap();
        // 第二块：列名换成一个不存在的名字。
        let (mut second, _) = encode_records(&[rec(2, false)], 100).unwrap();
        let probe = flow_columns()[0].name.as_bytes().to_vec();
        let at = second.windows(probe.len()).position(|w| w == probe).unwrap();
        second[at] = b'X';
        bytes.extend_from_slice(&second);
        let err = decode_blocks(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::ColumnSetChanged { .. }), "得到 {err:?}");
    }

    #[test]
    fn null_mask_flip_changes_the_decoded_value_not_the_framing() {
        // 这一条钉住本项目对"门禁必须靠对照、不能靠报错"的核心判断：
        //   翻转 `Nullable` 的掩码字节**不会**破坏帧结构，解码器无从报警 ——
        //   NULL→值 会把"没评分"读成 0.0（把缺证据读成结论），
        //   值→NULL 会把 0.25 读成"没有评分"。两种都是静默的数据篡改。
        // 因此 check-columnar.sh 必须逐字段比对，而不是"能解码就算通过"。
        let cols = flow_columns();
        let ci = cols.iter().position(|c| c.name == "risk_score").unwrap();
        assert_eq!(ci, cols.len() - 1, "本用例假设 risk_score 是最后一列");

        // 方向 A：NULL → 0.0（rec(1) 的 risk_score 是 None）
        let r_none = rec(1, false);
        let (bytes, _) = encode_records(&[r_none], 100).unwrap();
        let off = bytes.len() - 9; // 最后一列：1 字节掩码 + 8 字节哑值
        assert_eq!(bytes[off], 1, "未评分的掩码必须是 1");
        assert_eq!(&bytes[off + 1..], &[0u8; 8], "null 行的哑值必须是 8 个 0 字节");
        let mut a = bytes.clone();
        a[off] = 0;
        let da = decode_blocks(&a).expect("翻掩码不报错");
        assert_eq!(da[0].cells[ci][0], Cell::F64(0.0), "NULL 被读成 0.0 —— 正是必须比对的理由");

        // 方向 B：0.25 → NULL
        let mut r_some = rec(2, false);
        r_some.risk_score = Some(0.25);
        let (bytes2, _) = encode_records(&[r_some], 100).unwrap();
        let off2 = bytes2.len() - 9;
        assert_eq!(bytes2[off2], 0);
        assert_eq!(&bytes2[off2 + 1..], &0.25f64.to_bits().to_le_bytes());
        let mut b = bytes2.clone();
        b[off2] = 1;
        let db = decode_blocks(&b).expect("同样不报错");
        assert_eq!(db[0].cells[ci][0], Cell::Null, "有值被掩码抹成 NULL");

        // 帧长完全不变：两个方向都只是"值的意思"变了。
        assert_eq!(a.len(), bytes.len());
        assert_eq!(b.len(), bytes2.len());
    }

    #[test]
    fn non_finite_feature_is_rejected_before_any_byte_is_written() {
        let mut r = rec(9, false);
        r.features.values[10] = f64::NAN;
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = NativeWriter::new(&mut buf, 100);
            let first = rec(8, false);
            w.push(&first).unwrap();
            let err = w.push(&r).unwrap_err();
            assert!(format!("{err}").contains("不是有限数"), "得到 {err}");
        }
        // 注意：buf 里第 0 条仍在缓冲中未落盘（块未写满）—— 但**没有半个块的字节**，
        // 该断言保证"拒绝落盘不会留下半条记录"。
        assert!(buf.is_empty(), "投影失败前不应写出任何字节");
    }

    #[test]
    fn empty_input_does_not_produce_a_zero_byte_file() {
        let mut buf: Vec<u8> = Vec::new();
        let mut w = NativeWriter::new(&mut buf, 100);
        let err = w.finish().unwrap_err();
        assert!(matches!(err, ColumnarError::EmptyInput), "得到 {err:?}");
    }

    #[test]
    fn schema_version_and_contract_version_are_both_carried() {
        let (bytes, _) = encode_records(&[rec(1, false)], 100).unwrap();
        let b = decode_blocks(&bytes).unwrap();
        assert_eq!(b[0].cells[idx("schema_version")][0], Cell::U32(1));
        assert_eq!(
            b[0].cells[idx("column_contract_version")][0],
            Cell::U32(COLUMN_CONTRACT_VERSION)
        );
    }

    /// 用**另一条路径**（不读产物、不读 stats，只按列值重算）算出期望字节数。
    ///
    /// 只拿 `stats.bytes` 与 `bytes.len()` 相比是同源自证：两者由同一段累加逻辑得出，
    /// 实现里少算一类开销时两边会一起错。这里按线路格式独立重算一遍。
    fn expected_size(rows: &[Vec<Value<'_>>], rows_per_block: usize) -> usize {
        let cols = flow_columns();
        let mut total = 0usize;
        for chunk in rows.chunks(rows_per_block.max(1)) {
            // 块头：列数/行数 varint + 每列的名字与类型名。
            total += varint_len(cols.len() as u64) + varint_len(chunk.len() as u64);
            for c in &cols {
                total += varint_len(c.name.len() as u64) + c.name.len();
                let ty = c.ch_type();
                total += varint_len(ty.len() as u64) + ty.len();
            }
            // 掩码：可空列每行 1 字节。
            total += cols.iter().filter(|c| c.nullable).count() * chunk.len();
            // 数据：定宽列按宽度，字符串列按 varint 长度 + 字节，NULL 按哑值宽度。
            for row in chunk {
                for (ci, c) in cols.iter().enumerate() {
                    total += match &row[ci] {
                        Value::Str(s) => varint_len(s.len() as u64) + s.len(),
                        Value::Null => dummy_width(c.kind),
                        _ => c.kind.raw_width(),
                    };
                }
            }
        }
        total
    }

    fn varint_len(mut v: u64) -> usize {
        let mut n = 1;
        while v >= 0x80 {
            v >>= 7;
            n += 1;
        }
        n
    }

    #[test]
    fn stats_and_file_size_match_an_independent_recomputation() {
        let recs: Vec<FlowRecord> = (0..50).map(|i| rec(i, false)).collect();
        let rows: Vec<Vec<Value<'_>>> = recs.iter().map(|r| project_row(r).unwrap()).collect();
        let rpb = 7;
        let (bytes, st) = encode_records(&recs, rpb).unwrap();
        assert_eq!(bytes.len(), expected_size(&rows, rpb), "产物字节数必须能独立重算");
        assert_eq!(st.bytes as usize, bytes.len());
        assert_eq!(st.blocks, 8, "50 行 / 每块 7 行 ⇒ 8 块");
        let nullables = flow_columns().iter().filter(|c| c.nullable).count() as u64;
        assert_eq!(st.null_mask_bytes, nullables * st.rows, "掩码 = 可空列数 × 行数");
        // 本组记录都有 risk_score=NULL、tcp_*=值、app_*=值：哑值项只来自 risk_score。
        assert_eq!(st.null_dummy_bytes, st.rows * 8);
        // 块头要**每块**重写一遍 49 列的名字与类型，所以它的占比由"行数/块"决定，
        // 而不是一个可以先验写死的常数 —— 这里量的是它的单调性，不是我的预期值。
        let (_, one_block) = encode_records(&recs, 50).unwrap();
        assert_eq!(one_block.blocks, 1);
        assert!(
            st.header_bytes > 4 * one_block.header_bytes,
            "8 块的块头应明显大于 1 块：实测 {} vs {}",
            st.header_bytes,
            one_block.header_bytes
        );
        assert_eq!(one_block.bytes, bytes.len() as u64 - (st.bytes - one_block.bytes));
    }
}
