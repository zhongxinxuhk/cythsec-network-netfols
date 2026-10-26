use super::*;
use crate::flow::FlowKey;
use crate::reassembly::tcp::TcpFlags;

fn packet(
    flow: u16,
    proto: u8,
    payload: &[u8],
    seq: u32,
    ack: u32,
    flags: u8,
    reverse: bool,
    now: u64,
) -> PcapRecord {
    let k = FlowKey::new_ipv4([192, 0, 2, 1], 10000 + flow, [198, 51, 100, 2], 443, proto);
    let k = if reverse { k.reverse() } else { k };
    let l4 = if proto == 6 { 20 } else { 8 };
    let mut p = vec![0; 34 + l4 + payload.len()];
    p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    p[14] = 0x45;
    p[16..18].copy_from_slice(&((20 + l4 + payload.len()) as u16).to_be_bytes());
    p[22] = 64;
    p[23] = proto;
    if let (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) = (k.src_ip, k.dst_ip) {
        p[26..30].copy_from_slice(&a.octets());
        p[30..34].copy_from_slice(&b.octets());
    }
    p[34..36].copy_from_slice(&k.src_port.to_be_bytes());
    p[36..38].copy_from_slice(&k.dst_port.to_be_bytes());
    if proto == 6 {
        p[38..42].copy_from_slice(&seq.to_be_bytes());
        p[42..46].copy_from_slice(&ack.to_be_bytes());
        p[46] = 0x50;
        p[47] = flags;
    } else {
        p[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    }
    p[34 + l4..].copy_from_slice(payload);
    PcapRecord {
        timestamp_us: now,
        orig_len: p.len() as u32,
        data: p,
    }
}
fn flags(bits: u8) -> TcpFlags {
    TcpFlags::from_bytes(0, bits)
}
fn json(w: &Window) -> String {
    let mut out = Vec::new();
    w.write_json(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}
fn base() -> Aggregator {
    Aggregator::new(Config::default()).unwrap()
}

#[test]
fn windows_are_coarse_and_configuration_cannot_disable_cohort_floor() {
    for cfg in [
        Config {
            window_seconds: 59,
            ..Config::default()
        },
        Config {
            minimum_flows: 1,
            ..Config::default()
        },
        Config {
            sampling_interval: 0,
            ..Config::default()
        },
        Config {
            max_flows: 19,
            ..Config::default()
        },
    ] {
        assert!(Aggregator::new(cfg).is_err());
    }
    let mut a = base();
    a.observe(&packet(0, 17, b"x", 0, 0, 0, false, 61_000_000));
    let w = a.finish().unwrap();
    assert_eq!(w.start_seconds, 60);
    assert!(w.suppressed);
    let s = json(&w);
    assert!(s.contains("\"statistics\":null"));
    assert!(!s.contains("records"));
    assert!(!s.contains("contributing_sampled_flows"));
}
#[test]
fn output_cannot_leak_identifiers_domains_payloads_or_individual_samples() {
    let mut a = base();
    let body = b"sensitive.example user-id=abcdef";
    let mut tls = vec![23, 3, 3, 0, body.len() as u8];
    tls.extend(body);
    for n in 0..20 {
        a.observe(&packet(n, 6, &tls, 1, 0, 0x18, false, 1_000_000 + n as u64));
    }
    let w = a.finish().unwrap();
    assert!(!w.suppressed);
    assert_eq!(w.tls_flows, 20);
    let s = json(&w);
    for forbidden in [
        "192.0.2.1",
        "198.51.100.2",
        "sensitive.example",
        "abcdef",
        "src_ip",
        "dst_ip",
        "src_port",
        "sni",
        "ja3",
        "flow_id",
        "payload",
        "vpn",
        "wireguard",
    ] {
        assert!(!s.contains(forbidden), "{forbidden}");
    }
    assert!(s.contains("\"tls_record_candidate_packets\":20"));
    assert!(s.contains("\"response_delay_samples\":null"));
}
#[test]
fn cohort_threshold_is_enforced_for_tcp_and_carrier_subgroups() {
    let mut a = base();
    for n in 0..20 {
        a.observe(&packet(n, 17, b"x", 0, 0, 0, false, 1_000_000));
    }
    a.observe(&packet(
        30,
        6,
        &[23, 3, 3, 0, 1, 0],
        1,
        0,
        0x18,
        false,
        1_000_001,
    ));
    let s = json(&a.finish().unwrap());
    assert!(s.contains("\"tcp_quality\":null"));
    assert!(s.contains("\"tls_record_candidate_packets\":null"));
}
#[test]
fn all_frame_counters_balance_and_invalid_udp_length_is_not_a_carrier() {
    let mut a = base();
    for n in 0..20 {
        a.observe(&packet(n, 17, b"x", 0, 0, 0, false, 1_000_000));
    }
    let mut p = packet(21, 17, b"data", 0, 0, 0, false, 1_000_001);
    p.data[38..40].copy_from_slice(&65535u16.to_be_bytes());
    a.observe(&p);
    let mut p = packet(22, 17, b"longer", 0, 0, 0, false, 1_000_002);
    p.data.truncate(p.data.len() - 2);
    a.observe(&p);
    a.observe(&PcapRecord {
        timestamp_us: 1_000_003,
        orig_len: 3,
        data: vec![0; 3],
    });
    let w = a.finish().unwrap();
    let i = w.integrity;
    assert_eq!(i.records, 23);
    assert_eq!(i.unusable_transport, 1);
    assert_eq!(i.snaplen_truncated, 1);
    assert_eq!(
        i.records,
        i.decoded
            + i.non_ip
            + i.decode_incomplete
            + i.unparsed_fragments
            + i.unsupported_or_bad_headers
            + i.late_records
    );
    assert_eq!(i.decoded, 22);
}
#[test]
fn window_transition_drops_tuple_state_and_does_not_fabricate_empty_windows() {
    let mut a = base();
    for n in 0..20 {
        a.observe(&packet(n, 17, b"x", 0, 0, 0, false, 1_000_000));
    }
    let old = a
        .observe(&packet(0, 17, b"x", 0, 0, 0, false, 3_600_000_000))
        .unwrap();
    assert_eq!(old.contributing_flows, 20);
    let next = a.finish().unwrap();
    assert_eq!(next.start_seconds, 3600);
    assert_eq!(next.contributing_flows, 1);
    assert!(next.suppressed);
    assert_eq!(a.window_counts(), (1, 1));
}
#[test]
fn late_packets_are_health_events_not_reassigned_traffic() {
    let mut a = base();
    a.observe(&packet(0, 17, b"x", 0, 0, 0, false, 120_000_000));
    a.observe(&packet(1, 17, b"x", 0, 0, 0, false, 1_000_000));
    let w = a.finish().unwrap();
    assert_eq!(w.integrity.records, 2);
    assert_eq!(w.integrity.late_records, 1);
    assert_eq!(w.udp_packets, 1);
}
#[test]
fn sampling_is_bidirectional_and_capacity_loss_is_explicit() {
    let mut a = Aggregator::new(Config {
        sampling_interval: 3,
        max_flows: 1000,
        ..Config::default()
    })
    .unwrap();
    for n in 0..1000 {
        for reverse in [false, true] {
            a.observe(&packet(n, 17, b"x", 0, 0, 0, reverse, 1_000_000));
        }
    }
    let w = a.finish().unwrap();
    assert_eq!(w.integrity.records, 2000);
    assert_eq!(w.integrity.sampled_packets % 2, 0);
    assert_eq!(w.integrity.unsampled_packets % 2, 0);
    assert_eq!(
        w.integrity.sampled_packets + w.integrity.unsampled_packets,
        2000
    );
    let mut a = Aggregator::new(Config {
        max_flows: 20,
        ..Config::default()
    })
    .unwrap();
    for n in 0..21 {
        a.observe(&packet(n, 17, b"x", 0, 0, 0, false, 1_000_000));
    }
    let w = a.finish().unwrap();
    assert_eq!(w.contributing_flows, 20);
    assert_eq!(w.integrity.capacity_rejected_packets, 1);
    assert_eq!(w.udp_packets, 21);
}
#[test]
fn tcp_sequence_quality_handles_retransmissions_gaps_and_wraparound() {
    let mut q = TcpQuality::default();
    let mut sum = Quality::default();
    for (seq, len) in [(100, 10), (110, 10), (100, 10), (140, 10), (120, 10)] {
        sum.merge(&q.observe(0, seq, 0, flags(0x18), len, 1));
    }
    assert_eq!(sum.retransmission_candidates, 1);
    assert_eq!(sum.forward_gaps, 1);
    assert_eq!(sum.out_of_order_candidates, 1);
    let mut q = TcpQuality::default();
    let mut sum = Quality::default();
    for (seq, len) in [(u32::MAX - 3, 4), (0, 4), (u32::MAX - 3, 4)] {
        sum.merge(&q.observe(0, seq, 0, flags(0x18), len, 1));
    }
    assert_eq!(sum.retransmission_candidates, 1);
    assert_eq!(sum.out_of_order_candidates, 0);
    assert_eq!(
        q.observe(0, 4u32.wrapping_add(1 << 31), 0, flags(0x18), 1, 1)
            .ambiguous_sequences,
        1
    );
}
#[test]
fn pure_ack_does_not_count_as_data_retransmission() {
    let mut q = TcpQuality::default();
    q.observe(0, 100, 0, flags(0x18), 10, 0);
    let o = q.observe(0, 100, 0, flags(0x10), 0, 1);
    assert_eq!(o.judged_segments, 0);
    assert_eq!(o.retransmission_candidates, 0);
}
#[test]
fn response_delay_requires_ack_direction_and_unambiguous_timing() {
    let mut q = TcpQuality::default();
    q.observe(0, 100, 0, flags(2), 0, 10_000);
    assert_eq!(
        q.observe(1, 900, 999, flags(0x12), 0, 15_000)
            .response_samples,
        0
    );
    let o = q.observe(1, 900, 101, flags(0x12), 0, 15_000);
    assert_eq!(o.response_samples, 1);
    assert_eq!(o.delay_histogram[1], 1);
    assert_eq!(
        q.observe(1, 900, 101, flags(0x12), 0, 16_000)
            .response_samples,
        0
    );
    let mut q = TcpQuality::default();
    q.observe(0, 100, 0, flags(2), 0, 10_000);
    q.observe(0, 100, 0, flags(2), 0, 11_000);
    let o = q.observe(1, 900, 101, flags(0x12), 0, 15_000);
    assert_eq!(o.response_samples, 0);
    assert_eq!(o.ambiguous_responses, 1);
    let mut q = TcpQuality::default();
    q.observe(0, 100, 0, flags(2), 0, 10_000);
    assert_eq!(
        q.observe(1, 900, 101, flags(0x12), 0, 1)
            .ambiguous_responses,
        1
    );
}
#[test]
fn source_counter_equation_cannot_turn_missing_information_into_zero_loss() {
    assert!(SourceCounters {
        eligible: 105,
        delivered: 100,
        dropped: 5
    }
    .validate(100));
    assert!(!SourceCounters {
        eligible: 100,
        delivered: 100,
        dropped: 5
    }
    .validate(100));
    assert!(!SourceCounters {
        eligible: u64::MAX,
        delivered: u64::MAX,
        dropped: 1
    }
    .validate(u64::MAX));
    assert!(!SourceCounters {
        eligible: 100,
        delivered: 100,
        dropped: 0
    }
    .validate(99));
}
#[test]
fn tls_quic_markers_have_bounds_and_do_not_identify_vpn_payloads() {
    assert_eq!(
        carrier::classify(6, &[23, 3, 3, 0, 1, 7], 6),
        Some(Carrier::TlsRecord)
    );
    assert_eq!(carrier::classify(6, &[23, 3, 3, 0, 2, 7], 7), None);
    let mut quic = vec![0xc0, 0, 0, 0, 1, 0, 0, 0, 17];
    quic.extend([0; 17]);
    assert_eq!(
        carrier::classify(17, &quic, quic.len()),
        Some(Carrier::QuicLongHeader)
    );
    quic[8] = 63;
    assert_eq!(carrier::classify(17, &quic, quic.len()), None);
    let mut arbitrary = vec![0; 148];
    arbitrary[0] = 1;
    assert_eq!(carrier::classify(17, &arbitrary, 148), None);
}

#[test]
fn new_syn_after_midstream_data_starts_fresh_quality_state() {
    let mut q = TcpQuality::default();
    q.observe(0, 900, 0, flags(0x18), 10, 1);
    let o = q.observe(0, 100, 0, flags(2), 0, 2);
    assert_eq!(o.reused_tuples, 1);
    assert_eq!(o.retransmission_candidates, 0);
    assert_eq!(
        q.observe(1, 500, 101, flags(0x12), 0, 1002)
            .response_samples,
        1
    );
}
#[test]
fn truncated_quic_ciphertext_is_not_counted_as_a_complete_header_candidate() {
    let p = [0xc0, 0, 0, 0, 1, 0, 0, 0, 17, 0];
    assert_eq!(carrier::classify(17, &p, 26), None);
}

#[test]
fn reused_tuple_cannot_supply_multiple_histogram_cohort_contributions() {
    let mut a = base();
    for n in 0..20 {
        a.observe(&packet(n, 6, b"", 100, 0, 0x10, false, 1_000_000));
    }
    for n in 0..20u32 {
        let seq = 1000 + n;
        let now = 1_001_000 + u64::from(n) * 2000;
        a.observe(&packet(0, 6, b"", seq, 0, 2, false, now));
        a.observe(&packet(0, 6, b"", 5000, seq + 1, 0x12, true, now + 1000));
    }
    let w = a.finish().unwrap();
    assert_eq!(w.quality.response_samples, 1);
    assert_eq!(w.quality.delay_histogram.iter().sum::<u64>(), 1);
    assert!(json(&w).contains("\"response_delay_histogram\":null"));
}

#[test]
fn first_ip_fragments_are_counted_but_never_used_as_complete_transport() {
    let mut a = base();
    let mut p = packet(1, 6, &[23, 3, 3, 0, 1, 0], 100, 0, 0x18, false, 1_000_000);
    p.data[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    assert!(decode_frame(&p.data).unwrap().is_fragmented);
    a.observe(&p);
    let w = a.finish().unwrap();
    assert_eq!(w.tcp_packets, 1);
    assert_eq!(w.integrity.fragmented_transport, 1);
    assert_eq!(w.quality.judged_segments, 0);
    assert_eq!(w.contributing_flows, 0);
    assert_eq!(w.tls_record_candidates, 0);
}

#[test]
fn ipv6_fragment_header_distinguishes_atomic_from_first_fragment() {
    let mut p = vec![0; 14 + 40 + 8 + 8];
    p[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    p[14] = 0x60;
    p[18..20].copy_from_slice(&16u16.to_be_bytes());
    p[20] = 44;
    p[21] = 64;
    p[29] = 1;
    p[45] = 2;
    p[54] = 17;
    p[62..64].copy_from_slice(&10000u16.to_be_bytes());
    p[64..66].copy_from_slice(&443u16.to_be_bytes());
    p[66..68].copy_from_slice(&8u16.to_be_bytes());
    assert!(!decode_frame(&p).unwrap().is_fragmented);
    let mut a = base();
    a.observe(&PcapRecord {
        timestamp_us: 1_000_000,
        orig_len: p.len() as u32,
        data: p.clone(),
    });
    p[57] = 1;
    assert!(decode_frame(&p).unwrap().is_fragmented);
    a.observe(&PcapRecord {
        timestamp_us: 1_000_001,
        orig_len: p.len() as u32,
        data: p,
    });
    let w = a.finish().unwrap();
    assert_eq!(w.udp_packets, 2);
    assert_eq!(w.integrity.fragmented_transport, 1);
    assert_eq!(w.integrity.sampled_packets, 1);
}
