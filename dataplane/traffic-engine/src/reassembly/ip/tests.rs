// reassembly/ip/tests.rs —— IPv4/IPv6 分片重组的向量驱动测试。
//
// 期望值全部由本文件按 RFC 字段手写，不从实现输出反抄。重点不是“能拼起来”，
// 而是“拼不起来时绝不产出帧”：缺首片、缺尾、重叠、截断、超限都必须走显式的
// `Pending` / `Dropped`，并留下可核对的统计。

use super::*;
use crate::channel::decode_frame;

fn cksum(data: &[u8]) -> u16 {
    internet_checksum(data)
}

fn eth(payload: &[u8], ether_type: u16) -> Vec<u8> {
    let mut v = vec![0u8; 12];
    v.extend_from_slice(&ether_type.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn ipv4_fragment(
    src: [u8; 4],
    dst: [u8; 4],
    id: u16,
    proto: u8,
    offset_units: u16,
    more: bool,
    data: &[u8],
) -> Vec<u8> {
    let total = 20 + data.len();
    let mut hdr = vec![0u8; 20];
    hdr[0] = 0x45;
    hdr[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    hdr[4..6].copy_from_slice(&id.to_be_bytes());
    let mut frag = offset_units & 0x1fff;
    if more {
        frag |= 0x2000;
    }
    hdr[6..8].copy_from_slice(&frag.to_be_bytes());
    hdr[8] = 64;
    hdr[9] = proto;
    hdr[12..16].copy_from_slice(&src);
    hdr[16..20].copy_from_slice(&dst);
    let c = cksum(&hdr);
    hdr[10..12].copy_from_slice(&c.to_be_bytes());
    let mut out = hdr;
    out.extend_from_slice(data);
    out
}

fn ipv6_header(src: [u8; 16], dst: [u8; 16], next: u8, payload_len: usize) -> Vec<u8> {
    let mut h = vec![0u8; 40];
    h[0] = 0x60;
    h[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    h[6] = next;
    h[7] = 64;
    h[8..24].copy_from_slice(&src);
    h[24..40].copy_from_slice(&dst);
    h
}

fn ipv6_fragment(
    src: [u8; 16],
    dst: [u8; 16],
    id: u32,
    next: u8,
    offset_units: u16,
    more: bool,
    data: &[u8],
) -> Vec<u8> {
    let mut frag = vec![0u8; 8];
    frag[0] = next;
    let mut field = offset_units << 3;
    if more {
        field |= 1;
    }
    frag[2..4].copy_from_slice(&field.to_be_bytes());
    frag[4..8].copy_from_slice(&id.to_be_bytes());
    let mut payload = frag;
    payload.extend_from_slice(data);
    let mut out = ipv6_header(src, dst, 44, payload.len());
    out.extend_from_slice(&payload);
    out
}

fn udp(sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(data);
    out
}

const SRC4: [u8; 4] = [192, 0, 2, 1];
const DST4: [u8; 4] = [192, 0, 2, 2];
const SRC6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DST6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

#[test]
fn ipv4_out_of_order_reassembles_into_one_decodable_datagram() {
    let payload = udp(53000, 53, b"abcdefghijklmnopqrstuvwx");
    let first = eth(
        &ipv4_fragment(SRC4, DST4, 7, 17, 0, true, &payload[..16]),
        ETHERTYPE_IPV4,
    );
    let last = eth(
        &ipv4_fragment(SRC4, DST4, 7, 17, 2, false, &payload[16..]),
        ETHERTYPE_IPV4,
    );
    let mut r = IpReassembler::default();
    assert!(matches!(
        r.push(&last, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    let done = r.push(&first, LinkLayer::Ethernet, 2, false);
    let PushOutcome::Complete(d) = done else {
        panic!("两片齐全必须完成，实际 {done:?}");
    };
    assert_eq!(d.fragments, 2);
    assert_eq!(d.payload_bytes, payload.len());
    assert_eq!(d.timestamp_us, 2);
    let decoded = decode_frame(&d.frame).expect("重组后的数据报必须能解出五元组");
    assert_eq!(decoded.key.src_port, 53000);
    assert_eq!(decoded.key.dst_port, 53);
    assert_eq!(decoded.ip_payload_len as usize, payload.len());
    assert!(!decoded.is_fragmented);
    // IPv4 头校验和必须在清掉分片位之后重算，否则 tshark 会报 bad checksum。
    assert_eq!(internet_checksum(&d.frame[14..34]), 0);
    assert_eq!(r.stats().datagrams_completed, 1);
    assert_eq!(r.finish().pending_datagrams, 0);
}

#[test]
fn ipv4_overlap_is_rejected_instead_of_choosing_first_or_last() {
    let mut r = IpReassembler::default();
    let a = eth(
        &ipv4_fragment(SRC4, DST4, 9, 17, 0, true, &[1u8; 16]),
        ETHERTYPE_IPV4,
    );
    let b = eth(
        &ipv4_fragment(SRC4, DST4, 9, 17, 1, false, &[2u8; 16]),
        ETHERTYPE_IPV4,
    );
    assert!(matches!(
        r.push(&a, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    let got = r.push(&b, LinkLayer::Ethernet, 2, false);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::Overlap,
            ..
        }
    ));
    assert_eq!(r.stats().overlap_fragments, 1);
    assert_eq!(r.stats().datagrams_completed, 0);
    assert_eq!(r.pending_datagrams(), 0);
}

#[test]
fn identical_duplicate_fragment_is_not_double_counted() {
    let payload = udp(1000, 2000, b"0123456789abcdef");
    let a = eth(
        &ipv4_fragment(SRC4, DST4, 11, 17, 0, true, &payload[..8]),
        ETHERTYPE_IPV4,
    );
    let b = eth(
        &ipv4_fragment(SRC4, DST4, 11, 17, 1, false, &payload[8..]),
        ETHERTYPE_IPV4,
    );
    let mut r = IpReassembler::default();
    assert!(matches!(
        r.push(&a, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    assert!(matches!(
        r.push(&a, LinkLayer::Ethernet, 2, false),
        PushOutcome::Pending(_)
    ));
    assert_eq!(r.stats().duplicate_fragments, 1);
    let done = r.push(&b, LinkLayer::Ethernet, 3, false);
    let PushOutcome::Complete(d) = done else {
        panic!("重复片不应阻止完成，实际 {done:?}");
    };
    assert_eq!(d.fragments, 2);
}

#[test]
fn missing_first_fragment_stays_pending_and_finish_reports_non_initial() {
    let only_tail = eth(
        &ipv4_fragment(SRC4, DST4, 12, 17, 1, false, &[7u8; 8]),
        ETHERTYPE_IPV4,
    );
    let mut r = IpReassembler::default();
    assert!(matches!(
        r.push(&only_tail, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    let fin = r.finish();
    assert_eq!(fin.pending_datagrams, 1);
    assert_eq!(fin.pending_fragments, 1);
    assert_eq!(fin.non_initial_fragments, 1);
    assert_eq!(r.stats().datagrams_incomplete, 1);
    assert_eq!(r.stats().pending_fragments_at_eof, 1);
}

#[test]
fn missing_tail_stays_incomplete_and_never_creates_a_frame() {
    let first = eth(
        &ipv4_fragment(SRC4, DST4, 13, 17, 0, true, &[1u8; 16]),
        ETHERTYPE_IPV4,
    );
    let mut r = IpReassembler::default();
    assert!(matches!(
        r.push(&first, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    assert_eq!(r.finish().pending_datagrams, 1);
    assert_eq!(r.stats().datagrams_completed, 0);
}

#[test]
fn truncated_capture_is_rejected_without_zero_filling() {
    let full = ipv4_fragment(SRC4, DST4, 14, 17, 0, true, &[3u8; 16]);
    let cut = eth(&full[..28], ETHERTYPE_IPV4);
    let mut r = IpReassembler::default();
    let got = r.push(&cut, LinkLayer::Ethernet, 1, true);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::TruncatedCapture,
            ..
        }
    ));
    assert_eq!(r.stats().truncated_fragments, 1);
    assert_eq!(r.pending_datagrams(), 0);
}

#[test]
fn configured_payload_limit_rejects_oversized_fragment() {
    let big = eth(
        &ipv4_fragment(SRC4, DST4, 15, 17, 0, true, &[0u8; 32]),
        ETHERTYPE_IPV4,
    );
    let mut r = IpReassembler::new(IpFragConfig {
        max_datagram_payload: 24,
        ..IpFragConfig::default()
    });
    let got = r.push(&big, LinkLayer::Ethernet, 1, false);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::TooLarge,
            ..
        }
    ));
    assert_eq!(r.stats().oversized_fragments, 1);
}

#[test]
fn fragment_count_limit_is_explicit() {
    let mut r = IpReassembler::new(IpFragConfig {
        max_fragments_per_datagram: 1,
        ..IpFragConfig::default()
    });
    let a = eth(
        &ipv4_fragment(SRC4, DST4, 16, 17, 0, true, &[0u8; 8]),
        ETHERTYPE_IPV4,
    );
    let b = eth(
        &ipv4_fragment(SRC4, DST4, 16, 17, 1, true, &[0u8; 8]),
        ETHERTYPE_IPV4,
    );
    assert!(matches!(
        r.push(&a, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    let got = r.push(&b, LinkLayer::Ethernet, 2, false);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::TooManyFragments,
            ..
        }
    ));
    assert_eq!(r.pending_datagrams(), 0);
}

#[test]
fn queue_cap_evicts_oldest_and_counts_it() {
    let a = eth(
        &ipv4_fragment(SRC4, DST4, 17, 17, 0, true, &[0u8; 8]),
        ETHERTYPE_IPV4,
    );
    let b = eth(
        &ipv4_fragment([192, 0, 2, 3], DST4, 18, 17, 0, true, &[0u8; 8]),
        ETHERTYPE_IPV4,
    );
    let mut r = IpReassembler::new(IpFragConfig {
        max_datagrams: 1,
        ..IpFragConfig::default()
    });
    assert!(matches!(
        r.push(&a, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    assert!(matches!(
        r.push(&b, LinkLayer::Ethernet, 2, false),
        PushOutcome::Pending(_)
    ));
    assert_eq!(r.stats().evicted_datagrams, 1);
    assert_eq!(r.stats().datagrams_incomplete, 1);
    assert_eq!(r.pending_datagrams(), 1);
}

#[test]
fn idle_timeout_evicts_and_is_not_counted_as_complete() {
    let a = eth(
        &ipv4_fragment(SRC4, DST4, 19, 17, 0, true, &[0u8; 8]),
        ETHERTYPE_IPV4,
    );
    let b = eth(
        &ipv4_fragment([192, 0, 2, 4], DST4, 20, 17, 0, true, &[0u8; 8]),
        ETHERTYPE_IPV4,
    );
    let mut r = IpReassembler::new(IpFragConfig {
        timeout_us: 10,
        ..IpFragConfig::default()
    });
    assert!(matches!(
        r.push(&a, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    assert!(matches!(
        r.push(&b, LinkLayer::Ethernet, 20, false),
        PushOutcome::Pending(_)
    ));
    assert_eq!(r.stats().expired_datagrams, 1);
    assert_eq!(r.stats().datagrams_incomplete, 1);
    assert_eq!(r.pending_datagrams(), 1);
}

#[test]
fn ipv6_with_extension_header_reassembles_and_patches_payload_length() {
    // 逐跳选项：next=44, hdr ext len=0（8 字节），内容全 0。
    let ext = vec![44u8, 0, 0, 0, 0, 0, 0, 0];
    let payload = udp(1234, 5353, b"ipv6-fragment-payload");
    let split = 16;
    let first_data = &payload[..split];
    let last_data = &payload[split..];

    // 首片：IPv6 base(next=0) + 逐跳头 + 分片头 + 前 16 字节。
    let mut frag = vec![0u8; 8];
    frag[0] = 17;
    frag[2..4].copy_from_slice(&0x0001u16.to_be_bytes()); // offset 0 + M
    frag[4..8].copy_from_slice(&0x01020304u32.to_be_bytes());
    let mut body = ext.clone();
    body.extend_from_slice(&frag);
    body.extend_from_slice(first_data);
    let mut first = ipv6_header(SRC6, DST6, 0, body.len());
    first.extend_from_slice(&body);

    // 尾片：同样的逐跳头 + 分片头（offset=2, M=0） + 后 16 字节。
    let mut frag2 = vec![0u8; 8];
    frag2[0] = 17;
    frag2[2..4].copy_from_slice(&((2u16) << 3).to_be_bytes());
    frag2[4..8].copy_from_slice(&0x01020304u32.to_be_bytes());
    let mut body2 = ext;
    body2.extend_from_slice(&frag2);
    body2.extend_from_slice(last_data);
    let mut last = ipv6_header(SRC6, DST6, 0, body2.len());
    last.extend_from_slice(&body2);

    let mut r = IpReassembler::default();
    assert!(matches!(
        r.push(&eth(&last, ETHERTYPE_IPV6), LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    let got = r.push(&eth(&first, ETHERTYPE_IPV6), LinkLayer::Ethernet, 2, false);
    let PushOutcome::Complete(d) = got else {
        panic!("IPv6 两片齐全必须完成，实际 {got:?}");
    };
    // 重组帧：40 base + 8 hop-by-hop + 8 fragment + payload；payload length
    // 字段应等于 8+8+payload（不含 base 40）。
    let plen = u16::from_be_bytes([d.frame[18], d.frame[19]]) as usize;
    assert_eq!(plen, 8 + 8 + payload.len());
    let decoded = decode_frame(&d.frame).expect("IPv6 重组后必须能解出 UDP");
    assert_eq!(decoded.key.src_port, 1234);
    assert_eq!(decoded.key.dst_port, 5353);
    assert_eq!(decoded.ip_payload_len as usize, payload.len());
    assert!(!decoded.is_fragmented);
}

#[test]
fn ipv6_overlap_is_rejected() {
    let mut r = IpReassembler::default();
    let a = eth(
        &ipv6_fragment(SRC6, DST6, 0x01020304, 17, 0, true, &[1u8; 16]),
        ETHERTYPE_IPV6,
    );
    let b = eth(
        &ipv6_fragment(SRC6, DST6, 0x01020304, 17, 1, false, &[2u8; 16]),
        ETHERTYPE_IPV6,
    );
    assert!(matches!(
        r.push(&a, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    assert!(matches!(
        r.push(&b, LinkLayer::Ethernet, 2, false),
        PushOutcome::Dropped {
            error: IpFragError::Overlap,
            ..
        }
    ));
}

#[test]
fn atomic_ipv6_fragment_and_ordinary_packets_pass_through() {
    let atomic = eth(
        &ipv6_fragment(SRC6, DST6, 1, 17, 0, false, &udp(1, 2, b"x")),
        ETHERTYPE_IPV6,
    );
    let mut r = IpReassembler::default();
    assert_eq!(
        r.push(&atomic, LinkLayer::Ethernet, 1, false),
        PushOutcome::NotFragment
    );
    let v4 = eth(
        &ipv4_fragment(SRC4, DST4, 1, 17, 0, false, &udp(1, 2, b"x")),
        ETHERTYPE_IPV4,
    );
    assert_eq!(
        r.push(&v4, LinkLayer::Ethernet, 2, false),
        PushOutcome::NotFragment
    );
    assert_eq!(
        r.push(&eth(&[0u8; 28], 0x0806), LinkLayer::Ethernet, 3, false),
        PushOutcome::NotFragment
    );
}

#[test]
fn linux_sll_link_header_is_preserved_through_reassembly() {
    let payload = udp(40000, 53, b"sll-fragment");
    let first = ipv4_fragment(SRC4, DST4, 21, 17, 0, true, &payload[..8]);
    let last = ipv4_fragment(SRC4, DST4, 21, 17, 1, false, &payload[8..]);
    let sll = |ip: &[u8]| {
        let mut v = vec![0u8; 16];
        v[14..16].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        v.extend_from_slice(ip);
        v
    };
    let mut r = IpReassembler::default();
    assert!(matches!(
        r.push(&sll(&first), LinkLayer::LinuxSll, 1, false),
        PushOutcome::Pending(_)
    ));
    let got = r.push(&sll(&last), LinkLayer::LinuxSll, 2, false);
    let PushOutcome::Complete(d) = got else {
        panic!("SLL 分片必须能重组，实际 {got:?}");
    };
    let decoded = crate::channel::decode_frame_with_link(&d.frame, LinkLayer::LinuxSll)
        .expect("SLL 重组帧必须能解");
    assert_eq!(decoded.key.src_port, 40000);
    assert_eq!(decoded.key.dst_port, 53);
}

#[test]
fn misaligned_non_final_fragment_is_rejected() {
    let mut r = IpReassembler::default();
    let bad = eth(
        &ipv4_fragment(SRC4, DST4, 30, 17, 0, true, &[0u8; 9]),
        ETHERTYPE_IPV4,
    );
    let got = r.push(&bad, LinkLayer::Ethernet, 1, false);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::MisalignedFragment,
            ..
        }
    ));
    assert_eq!(r.pending_datagrams(), 0);
}

#[test]
fn empty_fragment_is_rejected() {
    let mut r = IpReassembler::default();
    let empty = eth(
        &ipv4_fragment(SRC4, DST4, 31, 17, 1, false, &[]),
        ETHERTYPE_IPV4,
    );
    let got = r.push(&empty, LinkLayer::Ethernet, 1, false);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::EmptyFragment,
            ..
        }
    ));
}

#[test]
fn conflicting_duplicate_is_rejected_not_last_wins() {
    let mut r = IpReassembler::default();
    let a = eth(
        &ipv4_fragment(SRC4, DST4, 32, 17, 0, true, &[1u8; 8]),
        ETHERTYPE_IPV4,
    );
    let b = eth(
        &ipv4_fragment(SRC4, DST4, 32, 17, 0, true, &[2u8; 8]),
        ETHERTYPE_IPV4,
    );
    assert!(matches!(
        r.push(&a, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    let got = r.push(&b, LinkLayer::Ethernet, 2, false);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::Overlap,
            ..
        }
    ));
}

#[test]
fn inconsistent_last_fragment_length_is_rejected() {
    let mut r = IpReassembler::default();
    let first = eth(
        &ipv4_fragment(SRC4, DST4, 33, 17, 0, true, &[0u8; 8]),
        ETHERTYPE_IPV4,
    );
    let last_a = eth(
        &ipv4_fragment(SRC4, DST4, 33, 17, 2, false, &[1u8; 8]),
        ETHERTYPE_IPV4,
    );
    let last_b = eth(
        &ipv4_fragment(SRC4, DST4, 33, 17, 1, false, &[2u8; 8]),
        ETHERTYPE_IPV4,
    );
    assert!(matches!(
        r.push(&first, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    assert!(matches!(
        r.push(&last_a, LinkLayer::Ethernet, 2, false),
        PushOutcome::Pending(_)
    ));
    let got = r.push(&last_b, LinkLayer::Ethernet, 3, false);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::InconsistentLength,
            ..
        }
    ));
}

#[test]
fn duplicate_first_fragment_with_different_header_is_rejected() {
    let mut r = IpReassembler::default();
    let first = eth(
        &ipv4_fragment(SRC4, DST4, 34, 17, 0, true, &[0u8; 16]),
        ETHERTYPE_IPV4,
    );
    let mut changed = first.clone();
    // Ethernet 14 + IPv4 TTL 偏移 8：只改首片的头，不改载荷。
    changed[22] = 63;
    assert!(matches!(
        r.push(&first, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    let got = r.push(&changed, LinkLayer::Ethernet, 2, false);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::InconsistentHeader,
            ..
        }
    ));
}

#[test]
fn ipv6_next_header_mismatch_is_rejected() {
    let mut r = IpReassembler::default();
    let first = eth(
        &ipv6_fragment(SRC6, DST6, 35, 17, 0, true, &[0u8; 8]),
        ETHERTYPE_IPV6,
    );
    // 同一个 Identification 的后片把 Next Header 改成 TCP：不能凭首片
    // 的 UDP 头把两者拼成一条数据报，也不能另起一条同键数据报。
    let conflicting = eth(
        &ipv6_fragment(SRC6, DST6, 35, 6, 1, false, &[1u8; 8]),
        ETHERTYPE_IPV6,
    );
    assert!(matches!(
        r.push(&first, LinkLayer::Ethernet, 1, false),
        PushOutcome::Pending(_)
    ));
    let got = r.push(&conflicting, LinkLayer::Ethernet, 2, false);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::InconsistentHeader,
            ..
        }
    ));
    assert_eq!(r.stats().datagrams_malformed, 1);
    assert_eq!(r.stats().datagrams_completed, 0);
}

#[test]
fn ipv6_jumbogram_fragment_is_explicitly_unsupported() {
    let mut frame = ipv6_header(SRC6, DST6, 44, 0);
    let mut frag = vec![0u8; 8];
    frag[0] = 17;
    frag[2..4].copy_from_slice(&0x0001u16.to_be_bytes());
    frag[4..8].copy_from_slice(&7u32.to_be_bytes());
    frame.extend_from_slice(&frag);
    let mut r = IpReassembler::default();
    let got = r.push(&eth(&frame, ETHERTYPE_IPV6), LinkLayer::Ethernet, 1, false);
    assert!(matches!(
        got,
        PushOutcome::Dropped {
            error: IpFragError::UnsupportedJumbogram,
            ..
        }
    ));
}

#[test]
fn stats_line_names_are_stable() {
    let mut r = IpReassembler::default();
    let first = eth(
        &ipv4_fragment(SRC4, DST4, 22, 17, 0, true, &[1u8; 8]),
        ETHERTYPE_IPV4,
    );
    let last = eth(
        &ipv4_fragment(SRC4, DST4, 22, 17, 1, false, &[2u8; 8]),
        ETHERTYPE_IPV4,
    );
    let _ = r.push(&first, LinkLayer::Ethernet, 1, false);
    let _ = r.push(&last, LinkLayer::Ethernet, 2, false);
    let line = r.stats().render_line();
    for key in [
        "ipfrag",
        "frags=",
        "v4=",
        "v6=",
        "datagrams=",
        "complete=",
        "incomplete=",
        "malformed=",
        "dup=",
        "overlap=",
        "truncated=",
        "oversize=",
        "evicted=",
        "expired=",
        "bytes=",
        "pending_at_eof=",
    ] {
        assert!(line.contains(key), "统计行缺 {key}: {line}");
    }
}
