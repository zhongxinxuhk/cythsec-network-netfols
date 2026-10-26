use super::evidence::{correlate, Evidence};
use super::probe::{Authorization, ProbePlanner, Target};
use super::wire::{inspect, Fact, Verdict};
use super::*;
use crate::flow::FlowKey;

fn wg(kind: u8, index: u32, peer: u32) -> Vec<u8> {
    let mut p = vec![
        0;
        match kind {
            1 => 148,
            2 => 92,
            3 => 64,
            _ => 32,
        }
    ];
    p[0] = kind;
    p[4..8].copy_from_slice(&index.to_le_bytes());
    if kind == 2 {
        p[8..12].copy_from_slice(&peer.to_le_bytes());
    }
    p
}
fn ike(response: bool, v2: bool) -> Vec<u8> {
    let mut p = vec![0; 36];
    p[0..8].copy_from_slice(&1u64.to_be_bytes());
    if response {
        p[8..16].copy_from_slice(&2u64.to_be_bytes());
    }
    p[16] = if v2 { 33 } else { 1 };
    p[17] = if v2 { 0x20 } else { 0x10 };
    p[18] = if v2 { 34 } else { 2 };
    p[19] = if response && v2 {
        0x20
    } else if v2 {
        8
    } else {
        0
    };
    p[24..28].copy_from_slice(&36u32.to_be_bytes());
    p[30..32].copy_from_slice(&8u16.to_be_bytes());
    p
}
fn frame(payload: &[u8], key: FlowKey, seq: u32, flags: u8) -> Vec<u8> {
    let tcp = key.proto.is_tcp();
    let l4 = if tcp {
        20
    } else if key.proto.is_udp() {
        8
    } else {
        0
    };
    let mut p = vec![0; 34 + l4 + payload.len()];
    p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    p[14] = 0x45;
    p[16..18].copy_from_slice(&((20 + l4 + payload.len()) as u16).to_be_bytes());
    p[22] = 64;
    p[23] = key.proto.number();
    if let (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) = (key.src_ip, key.dst_ip) {
        p[26..30].copy_from_slice(&a.octets());
        p[30..34].copy_from_slice(&b.octets());
    }
    if l4 > 0 {
        p[34..36].copy_from_slice(&key.src_port.to_be_bytes());
        p[36..38].copy_from_slice(&key.dst_port.to_be_bytes());
    }
    if tcp {
        p[38..42].copy_from_slice(&seq.to_be_bytes());
        p[46] = 0x50;
        p[47] = flags;
    } else if l4 == 8 {
        p[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    }
    p[34 + l4..].copy_from_slice(payload);
    p
}
fn key(proto: u8) -> FlowKey {
    FlowKey::new_ipv4([192, 0, 2, 1], 12345, [198, 51, 100, 2], 443, proto)
}
fn fact(p: &[u8], proto: u8) -> Fact {
    match inspect(p, proto, 12345, 443) {
        Verdict::Match(f) => f,
        r => panic!("expected match, got {r:?}"),
    }
}
fn ev(id: &str, root: &str, kind: &str, protocol: &str) -> Evidence {
    Evidence {
        id: id.into(),
        trust_root: root.into(),
        kind: kind.into(),
        protocol_id: protocol.into(),
        version: "test-version".into(),
        mode: "application_proxy".into(),
        key: {
            let entry = lookup(protocol).unwrap();
            let n = entry.ip_protocols.first().copied().unwrap_or(6);
            let mut k = key(n);
            if !k.proto.has_ports() {
                k.src_port = 0;
                k.dst_port = 0;
            }
            k
        },
        start_us: 0,
        end_us: 1000,
        deny: false,
    }
}
fn output(e: &Engine, context: &[Evidence]) -> String {
    let mut s = Vec::new();
    e.write_jsonl(&mut s, context).unwrap();
    String::from_utf8(s).unwrap()
}

#[test]
fn wireguard_requires_opposite_receiver_index_and_valid_layout() {
    let a = fact(&wg(1, 17, 0), 17);
    let b = fact(&wg(2, 99, 17), 17);
    assert!(a.confirms(b));
    assert!(!a.confirms(fact(&wg(2, 99, 18), 17)));
    assert!(!a.confirms(fact(&wg(1, 17, 0), 17)));
    let mut bad = wg(1, 17, 0);
    bad[1] = 1;
    assert!(!matches!(
        inspect(&bad, 17, 0, 51820),
        Verdict::Match(Fact { id: "V021", .. })
    ));
    assert!(!matches!(
        inspect(&wg(1, 17, 0), 6, 0, 51820),
        Verdict::Match(Fact { id: "V021", .. })
    ));
}
#[test]
fn ike_direction_spi_payload_length_and_natt_are_not_port_heuristics() {
    for v2 in [false, true] {
        let a = fact(&ike(false, v2), 17);
        let b = fact(&ike(true, v2), 17);
        assert!(a.confirms(b));
        let mut wrong = ike(true, v2);
        wrong[7] = 7;
        assert!(!a.confirms(fact(&wrong, 17)));
        let mut bad = ike(false, v2);
        bad[31] = 0xff;
        assert!(!matches!(inspect(&bad, 17, 500, 500), Verdict::Match(_)));
    }
    let mut natt = vec![0; 4];
    natt.extend(ike(false, true));
    assert!(matches!(
        inspect(&natt, 17, 4500, 4500),
        Verdict::Match(Fact { id: "V004", .. })
    ));
    assert!(!matches!(
        inspect(b"ordinary payload", 17, 4500, 4500),
        Verdict::Match(_)
    ));
}
#[test]
fn standalone_and_same_direction_handshakes_never_get_a() {
    for reverse in [false, true] {
        let mut e = Engine::default();
        let k = key(17);
        e.observe(&frame(&wg(1, 17, 0), k, 0, 0), 100);
        e.observe(
            &frame(&wg(2, 99, 17), if reverse { k.reverse() } else { k }, 0, 0),
            200,
        );
        let s = output(&e, &[]);
        assert_eq!(s.contains("\"confidence_level\":\"A\""), reverse);
    }
}
#[test]
fn stale_reply_duplicate_init_and_captured_truncation_cannot_confirm() {
    let k = key(17);
    let mut e = Engine::default();
    e.observe(&frame(&wg(1, 17, 0), k, 0, 0), 1);
    for _ in 0..3 {
        e.observe(&frame(&wg(1, 17, 0), k, 0, 0), 10);
    }
    e.observe(&frame(&wg(2, 99, 17), k.reverse(), 0, 0), 16_000_002);
    assert!(!output(&e, &[]).contains("wire_confirmed"));
    let mut e = Engine::default();
    let mut p = frame(&wg(1, 17, 0), k, 0, 0);
    p[16..18].copy_from_slice(&300u16.to_be_bytes());
    e.observe(&p, 0);
    e.observe(&frame(&wg(2, 99, 17), k.reverse(), 0, 0), 1);
    assert!(!output(&e, &[]).contains("wire_confirmed"));
}
#[test]
fn parser_covers_standard_tunnel_shapes_and_rejects_every_truncation_as_full_match() {
    let mut cases = vec![
        (17, wg(1, 17, 0), "V021"),
        (17, ike(false, true), "V004"),
        (17, ike(false, false), "V003"),
    ];
    cases.push((50, vec![0, 0, 0, 1, 0, 0, 0, 1], "V001"));
    cases.push((51, vec![6, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1], "V002"));
    let mut ip = vec![0; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&20u16.to_be_bytes());
    cases.push((4, ip.clone(), "V010"));
    let mut gre = vec![0, 0, 8, 0];
    gre.extend(ip);
    cases.push((47, gre, "V009"));
    let mut ip6 = vec![0; 40];
    ip6[0] = 0x60;
    cases.push((41, ip6, "V011"));
    let mut ether = vec![0; 16];
    ether[0] = 0x30;
    cases.push((97, ether, "V013"));
    let mut vx = vec![0; 22];
    vx[0] = 8;
    vx[20] = 8;
    cases.push((17, vx, "V014"));
    let mut ge = vec![0; 22];
    ge[2] = 0x65;
    ge[3] = 0x58;
    cases.push((17, ge, "V015"));
    let mut l2 = vec![
        0xc8, 2, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 8, 0, 0, 0, 0, 0, 1,
    ];
    cases.push((17, l2.clone(), "V006"));
    l2[13] = 0;
    assert!(!matches!(inspect(&l2, 17, 0, 0), Verdict::Match(_)));
    let mut pptp = vec![0; 156];
    pptp[..12].copy_from_slice(&[0, 156, 0, 1, 0x1a, 0x2b, 0x3c, 0x4d, 0, 1, 0, 0]);
    pptp[12] = 1;
    cases.push((6, pptp, "V008"));
    let mut ov = vec![0; 14];
    ov[0] = 7 << 3;
    ov[8] = 1;
    cases.push((17, ov.clone(), "V017"));
    let mut ovt = vec![0, 14];
    ovt.extend(ov);
    cases.push((6, ovt, "V018"));
    cases.push((6, vec![4, 1, 0, 80, 192, 0, 2, 1, 0], "P001"));
    cases.push((6, vec![5, 1, 0], "P002"));
    let mut dt = vec![0; 25];
    dt[..3].copy_from_slice(&[22, 0xfe, 0xfd]);
    dt[12] = 12;
    cases.push((17, dt, "T005"));
    for (proto, p, id) in cases {
        let expectedfact = fact(&p, proto);
        assert_eq!(expectedfact.id, id, "{id}");
        for n in 0..p.len() {
            assert!(
                !matches!(inspect(&p[..n],proto,0,0),Verdict::Match(f)if f.id==id && f.message==expectedfact.message),
                "{id} full match on truncated prefix {n}"
            );
        }
    }
}
#[test]
fn quic_v2_type_mapping_and_varint_bounds_keep_it_a_candidate() {
    for (v, first, id) in [(1u32, 0xc0, "T007"), (0x6b3343cf, 0xd0, "T008")] {
        let mut p = vec![first];
        p.extend(v.to_be_bytes());
        p.extend([0, 0, 0, 17]);
        p.extend([0; 17]);
        assert_eq!(fact(&p, 17).id, id);
        p[8] = 63;
        assert!(!matches!(
            inspect(&p, 17, 0, 443),
            Verdict::Match(Fact {
                id: "T007" | "T008",
                ..
            })
        ));
    }
}
#[test]
fn no_ciphertext_attribution_from_tls_ports_ech_fingerprint_or_entropy() {
    let mut e = Engine::default();
    e.observe(&frame(&[0x80; 148], key(17), 0, 0), 10);
    let s = output(&e, &[]);
    assert!(!s.contains("context_verified"));
    assert!(!s.contains("wire_confirmed"));
    assert!(s.contains("\"vendor_product\":null"));
    assert!(correlate(key(6), 0, 100, &[ev("one", "root", "endpoint", "P014")]).is_empty());
}
#[test]
fn every_catalog_object_has_a_reachable_context_algorithm_and_no_default_brand() {
    for entry in CATALOG {
        let a = ev("one", "edr-root", "endpoint", entry.id);
        let r = correlate(
            a.key,
            10,
            100,
            &[a, ev("two", "gw-root", "gateway", entry.id)],
        );
        assert_eq!(r.len(), 1, "{}", entry.id);
        assert_eq!(r[0].grade, "B");
        assert_eq!(r[0].id, entry.id);
        assert!(lookup(entry.id).is_some());
        if let Some(parent) = entry.parent {
            assert!(lookup(parent).is_some());
        }
    }
}
#[test]
fn evidence_requires_distinct_kind_root_id_tuple_window_version_and_mode() {
    let a = ev("one", "same-root", "endpoint", "P014");
    let mut b = ev("two", "same-root", "gateway", "P014");
    assert!(correlate(key(6), 10, 100, &[a.clone(), b.clone()]).is_empty());
    b.trust_root = "other".into();
    b.kind = "endpoint".into();
    assert!(correlate(key(6), 10, 100, &[a.clone(), b.clone()]).is_empty());
    b.kind = "gateway".into();
    b.id = "one".into();
    assert!(correlate(key(6), 10, 100, &[a.clone(), b.clone()]).is_empty());
    b.id = "two".into();
    for mutation in 0..4 {
        let mut x = b.clone();
        match mutation {
            0 => x.key.dst_port = 444,
            1 => x.start_us = 500,
            2 => x.version = "other".into(),
            _ => x.mode = "l3".into(),
        };
        assert!(correlate(key(6), 10, 100, &[a.clone(), x]).is_empty());
    }
    b.deny = true;
    let c = ev("three", "new-root", "gateway", "P014");
    assert_eq!(correlate(key(6), 10, 100, &[a, b, c])[0].grade, "U");
}
#[test]
fn conflicting_product_quorums_are_unknown_not_arbitrarily_first() {
    let e = [
        ev("a", "r1", "endpoint", "C001"),
        ev("b", "r2", "gateway", "C001"),
        ev("c", "r3", "endpoint", "C002"),
        ev("d", "r4", "gateway", "C002"),
    ];
    let r = correlate(key(6), 1, 2, &e);
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|r| r.grade == "U"));
}
#[test]
fn tcp_reassembly_handles_segmentation_retransmission_and_tuple_reuse() {
    let k = key(6);
    let mut e = Engine::default();
    let greeting = b"SSH-2.0-client\r\n";
    e.observe(&frame(&[], k, 100, 2), 1);
    e.observe(&frame(&greeting[5..], k, 106, 0x18), 2);
    e.observe(&frame(&greeting[..5], k, 101, 0x18), 3);
    e.observe(&frame(&greeting[..5], k, 101, 0x18), 4);
    assert!(output(&e, &[]).contains("T016"));
    assert_eq!(e.flows.len(), 1);
    e.observe(&frame(&[], k, 500, 2), 5);
    assert_eq!(e.flows.len(), 2);
}
#[test]
fn resource_limits_are_visible_and_do_not_grow_unbounded() {
    let mut e = Engine::new(1, 64);
    let k = key(6);
    e.observe(&frame(&[b'a'; 200], k, 1, 0x18), 1);
    e.observe(&frame(b"x", k.reverse(), 1, 0x18), 2);
    let mut other = k;
    other.src_port += 1;
    e.observe(&frame(b"x", other, 1, 0x18), 3);
    assert_eq!(e.flows.len(), 1);
    assert_eq!(e.stats.capacity_drops, 1);
    assert!(output(&e, &[]).contains("\"budget_or_capture_limited\":true"));
}
#[test]
fn active_plans_fail_closed_and_have_no_execution_side_effect() {
    let target = Target {
        ip: "192.0.2.1".parse().unwrap(),
        port: 443,
        protocol_id: "T022".into(),
    };
    let a = Authorization {
        id: "approved-test".into(),
        expires_us: 100,
        allowed: vec![target.clone()],
        total_budget: 1,
    };
    let mut p = ProbePlanner::new(a.clone());
    let mut outside = target.clone();
    outside.port = 444;
    assert!(p.plan(outside, 1).is_err());
    let plan = p.plan(target.clone(), 1).unwrap();
    assert!(!plan.executed);
    assert_eq!(plan.max_packets, 3);
    assert!(p.plan(target.clone(), 2).is_err());
    assert!(ProbePlanner::new(a).plan(target, 100).is_err());
}
#[test]
fn hostile_bytes_never_panic_or_read_beyond_buffers() {
    let mut state = 17u64;
    for n in 0..512 {
        let mut p = vec![0; n];
        for b in &mut p {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (state >> 32) as u8;
        }
        for proto in [4, 6, 17, 41, 47, 50, 51, 97, 115] {
            let _ = inspect(&p, proto, 500, 4500);
        }
    }
}

#[test]
fn arbitrary_tcp_fillers_are_not_incomplete_openvpn_frames() {
    for b in [b'A', b'B', b'@'] {
        let p = vec![b; 300];
        assert_eq!(
            crate::dpi::identify(&p, 6, 443),
            crate::dpi::Outcome::Unknown
        );
    }
}

#[test]
fn tcp_epoch_collision_at_maximum_timestamp_is_bounded() {
    let mut e = Engine::default();
    let k = key(6);
    e.observe(&frame(&[], k, 1, 2), u64::MAX);
    e.observe(&frame(&[], k, 2, 2), u64::MAX);
    assert_eq!(e.stats.capacity_drops, 1);
}
#[test]
fn tlcp_record_length_and_openvpn_remote_session_binding() {
    let p = [22, 1, 1, 0, 6, 1, 0, 0, 2, 1, 1];
    assert_eq!(fact(&p, 6).id, "T014");
    let mut p = p;
    p[8] = 3;
    assert!(!matches!(inspect(&p, 6, 0, 0), Verdict::Match(_)));
    let mut a = vec![0; 14];
    a[0] = 7 << 3;
    a[8] = 17;
    let mut b = vec![0; 26];
    b[0] = 8 << 3;
    b[8] = 99;
    b[9] = 1;
    b[21] = 17;
    assert!(fact(&a, 17).confirms(fact(&b, 17)));
    b[21] = 18;
    assert!(!fact(&a, 17).confirms(fact(&b, 17)));
}
#[test]
fn native_esp_reaches_the_existing_flowrecord_pipeline() {
    let p = frame(&[0, 0, 0, 1, 0, 0, 0, 1], key(50), 0, 0);
    let mut file = Vec::new();
    file.extend_from_slice(&[
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ]);
    for n in [1u32, 0, p.len() as u32, p.len() as u32] {
        file.extend(n.to_le_bytes());
    }
    file.extend(p);
    let (records, _) = crate::pipeline::analyze_pcap(
        std::io::Cursor::new(file),
        &crate::pipeline::AnalyzeOptions::default(),
    )
    .unwrap();
    assert_eq!(records[0].app.app, Some(crate::dpi::AppId::Esp));
}
