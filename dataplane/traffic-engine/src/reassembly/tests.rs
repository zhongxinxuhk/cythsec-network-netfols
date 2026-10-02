// reassembly/tests.rs —— 用 datasets/reassembly 的向量驱动重组断言。
//
// 与 dpi/tests.rs 同一套方法论，同样三条约束：
//
//   1. 向量**编进二进制**（`include_bytes!` / `include_str!`）。运行时读文件的话，
//      路径写错或工作目录不对时测试会"安静地什么都测不到" —— 输出全绿，
//      实际一条断言都没跑。编进二进制后，路径错就是**编译失败**。
//   2. 期望值来自生成器**写死**的清单，不是"跑一遍实现记下来"。
//   3. 第三方复核由 scripts/verify/check-reassembly-vectors.sh（tshark）完成。
//      三方里任意一方出错，至少一处会对不上。
//
// 这里额外校验一条别处校验不了的：`split-clienthello` 在**只收到第一段**时必须
// 判 need_more、收齐后必须判 identified。这正是本模块存在的理由 ——
// 重组若没有真的把字节拼回去，这条会第一个失败。

use super::intervals::OverlapPolicy;
use super::stream::{Stream, StreamConfig};
use crate::dpi;
use crate::testjson::{Json, JsonParser};

const EXPECTED: &str = include_str!("../../../../datasets/reassembly/expected.json");

/// 全部向量的完整流。新增向量时**必须**同步到这里：
/// 没同步的话 `stream_of()` 会 panic，测试不会静默跳过。
const STREAMS: &[(&str, &[u8])] = &[
    (
        "in-order",
        include_bytes!("../../../../datasets/reassembly/streams/in-order.bin"),
    ),
    (
        "reversed",
        include_bytes!("../../../../datasets/reassembly/streams/reversed.bin"),
    ),
    (
        "interleaved",
        include_bytes!("../../../../datasets/reassembly/streams/interleaved.bin"),
    ),
    (
        "overlap-same",
        include_bytes!("../../../../datasets/reassembly/streams/overlap-same.bin"),
    ),
    (
        "overlap-conflict",
        include_bytes!("../../../../datasets/reassembly/streams/overlap-conflict.bin"),
    ),
    (
        "dup-retransmit",
        include_bytes!("../../../../datasets/reassembly/streams/dup-retransmit.bin"),
    ),
    (
        "wrap-around",
        include_bytes!("../../../../datasets/reassembly/streams/wrap-around.bin"),
    ),
    (
        "split-clienthello",
        include_bytes!("../../../../datasets/reassembly/streams/split-clienthello.bin"),
    ),
    (
        "memory-cap",
        include_bytes!("../../../../datasets/reassembly/streams/memory-cap.bin"),
    ),
    (
        "fin-with-payload",
        include_bytes!("../../../../datasets/reassembly/streams/fin-with-payload.bin"),
    ),
];

fn expected() -> Json {
    JsonParser::new(EXPECTED).value()
}

fn vectors() -> Vec<Json> {
    expected()
        .get("vectors")
        .and_then(Json::as_arr)
        .unwrap_or_else(|| panic!("expected.json 缺少 `vectors` 段"))
        .to_vec()
}

fn stream_of(name: &str) -> &'static [u8] {
    STREAMS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, s)| *s)
        .unwrap_or_else(|| panic!("向量 `{name}` 未编入 STREAMS 表（生成新向量后需同步）"))
}

fn num(v: &Json, key: &str) -> i64 {
    v.get(key)
        .and_then(Json::as_i64)
        .unwrap_or_else(|| panic!("缺 `{key}`"))
}

/// 十六进制解码（仅用于段载荷的显式覆盖值）。
fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex 长度必须为偶数：{s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("非法 hex"))
        .collect()
}

/// 构造该向量对应的 Stream（已按 isn 锚定，但尚未喂任何数据段）。
fn stream_for(v: &Json) -> Stream {
    let cfg = v.get("config").expect("缺 config");
    let policy = match cfg
        .get("policy")
        .and_then(Json::as_str)
        .unwrap_or("keep_old")
    {
        "keep_old" => OverlapPolicy::KeepOld,
        "keep_new" => OverlapPolicy::KeepNew,
        other => panic!("未知的仲裁策略：{other}"),
    };
    let mut s = Stream::new(StreamConfig {
        max_buffered: num(cfg, "max_buffered") as usize,
        max_span: num(cfg, "max_span") as u32,
        policy,
    });
    s.on_syn(num(v, "isn") as u32);
    s
}

/// 按到达顺序喂前 `upto` 个段（`upto = usize::MAX` 表示全部）。
fn feed_upto(v: &Json, upto: usize) -> Stream {
    let name = v.get("name").and_then(Json::as_str).expect("缺 name");
    let stream = stream_of(name);
    assert_eq!(
        stream.len(),
        num(v, "stream_len") as usize,
        "[{name}] 编入的流长度与 expected.json 不符（向量文件过时）"
    );

    let mut s = stream_for(v);
    // 数据起点 = ISN + 1（SYN 占一个序号）。
    let base = (num(v, "isn") as u32).wrapping_add(1);

    let segs = v
        .get("segments")
        .and_then(Json::as_arr)
        .expect("缺 segments");
    for (i, seg) in segs.iter().enumerate().take(upto.min(segs.len())) {
        let off = num(seg, "off") as usize;
        let len = num(seg, "len") as usize;
        let fin = seg
            .get("fin")
            .map_or(false, |f| matches!(f, Json::Bool(true)));
        let payload: Vec<u8> = match seg.get("data_hex") {
            Some(Json::Str(h)) => unhex(h),
            _ => stream[off..off + len].to_vec(),
        };
        assert_eq!(
            payload.len(),
            len,
            "[{name}] 段 {i} 的载荷长度与 len 字段不符"
        );
        s.feed(base.wrapping_add(off as u32), &payload, fin);
    }
    s
}

#[test]
fn every_vector_reassembles_to_the_expected_prefix() {
    for v in vectors() {
        let name = v.get("name").and_then(Json::as_str).expect("缺 name");
        let stream = stream_of(name);
        let exp = v.get("expect").expect("缺 expect");
        let s = feed_upto(&v, usize::MAX);

        let want_len = num(exp, "contiguous_len") as usize;
        assert_eq!(
            s.contiguous_len(),
            want_len,
            "[{name}] 连续前缀长度不符（note: {}）",
            v.get("note").and_then(Json::as_str).unwrap_or("")
        );

        // 逐字节比对前缀：比 sha256 更强，且失败时能直接看出差在哪。
        let prefix_len = num(exp, "prefix_len") as usize;
        assert_eq!(
            s.peek(prefix_len),
            &stream[..prefix_len],
            "[{name}] 重组出的前缀字节与原始流不符"
        );

        assert_eq!(
            s.holes().len(),
            num(exp, "holes") as usize,
            "[{name}] 空洞数不符"
        );
        assert_eq!(
            s.stats().memory_drops,
            num(exp, "memory_drops") as u64,
            "[{name}] 内存降级丢弃数不符"
        );
        assert_eq!(
            s.stats().ooo_segments,
            num(exp, "ooo_segments") as u64,
            "[{name}] 乱序段数不符"
        );
        assert_eq!(
            s.interval_stats().map(|st| st.conflict_bytes).unwrap_or(0),
            num(exp, "conflict_bytes") as u64,
            "[{name}] 重叠冲突字节数不符"
        );
        let want_finished = v
            .get("expect")
            .and_then(|e| e.get("finished"))
            .map(|f| matches!(f, Json::Bool(true)))
            .unwrap_or(false);
        assert_eq!(s.is_finished(), want_finished, "[{name}] 完成态不符");
    }
}

#[test]
fn every_vector_is_registered_in_the_stream_table() {
    // 编入 STREAMS 的表与 expected.json 必须一一对应：
    // 少一条就是"新增向量忘了同步"，测试会安静地少测一条。
    let names: Vec<String> = vectors()
        .iter()
        .map(|v| {
            v.get("name")
                .and_then(Json::as_str)
                .expect("缺 name")
                .to_string()
        })
        .collect();
    assert_eq!(
        STREAMS.len(),
        names.len(),
        "STREAMS 表与 expected.json 的向量数不一致（新增向量需同步 tests.rs）"
    );
    for n in &names {
        assert!(!stream_of(n).is_empty(), "向量 `{n}` 的流为空");
    }
}

#[test]
fn split_client_hello_needs_reassembly_before_it_is_identifiable() {
    // 本模块存在的理由：被切开的首包在拼好之前不可能被识别。
    let v = vectors()
        .into_iter()
        .find(|v| v.get("name").and_then(Json::as_str) == Some("split-clienthello"))
        .expect("缺 split-clienthello 向量");
    let dpi_exp = v.get("dpi").expect("该向量缺 dpi 期望");

    // 只喂第一段：必须判 need_more，且**不得**给出 SNI/JA3。
    let half = feed_upto(&v, 1);
    assert_eq!(
        half.identify_app(443).word(),
        dpi_exp
            .get("after_first")
            .and_then(Json::as_str)
            .expect("缺 after_first"),
        "仅收到第一段时不该识别出应用"
    );

    // 全部喂完：必须判 identified，且 SNI / JA3 与 datasets/dpi 的期望一致
    // （那个期望已被 tshark 独立核验过，这里是跨向量集的第二重校验）。
    let full = feed_upto(&v, usize::MAX);
    let out = full.identify_app(443);
    assert_eq!(
        out.word(),
        dpi_exp
            .get("after_all")
            .and_then(Json::as_str)
            .expect("缺 after_all"),
        "重组完成后必须能识别出应用"
    );
    match out {
        dpi::Outcome::Identified(d) => {
            assert_eq!(d.sni.as_deref(), dpi_exp.get("sni").and_then(Json::as_str));
            assert_eq!(d.ja3.as_deref(), dpi_exp.get("ja3").and_then(Json::as_str));
        }
        other => panic!("期望 Identified，实际 {other:?}"),
    }
}

#[test]
fn known_exceptions_are_explicitly_marked() {
    // 守的是"未核验冒充已核验"：tshark 复核不了的条目必须在 expected.json 里
    // 显式写 verified=false 并给出原因，不能靠默认值为 true 悄悄通过。
    for v in vectors() {
        let name = v.get("name").and_then(Json::as_str).expect("缺 name");
        let ts = v.get("tshark").expect("缺 tshark 段");
        let verified = ts
            .get("verified")
            .map(|b| matches!(b, Json::Bool(true)))
            .unwrap_or(true);
        if !verified {
            let note = ts.get("note").and_then(Json::as_str).unwrap_or("");
            assert!(
                !note.is_empty(),
                "[{name}] 已知例外必须写明原因，否则无法与「忘了核验」区分"
            );
        }
    }
}
