use super::*;
use crate::inner::{ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use std::net::Ipv4Addr;

fn mac(s: &str) -> [u8; 6] {
    let b: Vec<u8> = s
        .split(':')
        .map(|v| u8::from_str_radix(v, 16).expect("MAC 片段"))
        .collect();
    b.try_into().expect("MAC 长度")
}

fn eth(dst: &str, src: &str, ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = mac(dst).to_vec();
    v.extend_from_slice(&mac(src));
    v.extend_from_slice(&ether_type.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn tagged(dst: &str, src: &str, tags: &[u16], ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = mac(dst).to_vec();
    v.extend_from_slice(&mac(src));
    for id in tags {
        // 每个标签是 TPID + TCI；最后一个标签之后才是最终 EtherType。
        v.extend_from_slice(&0x8100u16.to_be_bytes());
        v.extend_from_slice(&(id & 0x0fff).to_be_bytes());
    }
    v.extend_from_slice(&ether_type.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x45, 0];
    v.extend_from_slice(&(20u16 + payload.len() as u16).to_be_bytes());
    v.extend_from_slice(&[0, 1, 0x40, 0]);
    v.push(64);
    v.push(proto);
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(payload);
    v
}

fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x60, 0, 0, 0];
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.push(next);
    v.push(64);
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(payload);
    v
}

fn vxlan(vni: u32, inner: &[u8]) -> Vec<u8> {
    vxlan_flags(0x08, vni, inner, 0)
}

fn vxlan_flags(flags: u8, vni: u32, inner: &[u8], reserved: u8) -> Vec<u8> {
    let mut v = vec![flags, 0, 0, 0];
    v.extend_from_slice(&vni.to_be_bytes()[1..]);
    v.push(reserved);
    v.extend_from_slice(inner);
    v
}

fn ipv4_inner() -> Vec<u8> {
    eth(
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        ETHERTYPE_IPV4,
        &ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &[0, 1, 2, 3]),
    )
}

fn ipv6_inner() -> Vec<u8> {
    eth(
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        ETHERTYPE_IPV6,
        &ipv6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            17,
            &[0; 8],
        ),
    )
}

#[test]
fn parses_inner_ipv4_and_keeps_vni() {
    let f = parse(&vxlan(100, &ipv4_inner())).expect("VXLAN 应成立");
    assert_eq!(f.vni, 100);
    assert_eq!(f.flags, 0x08);
    assert!(!f.inner_truncated);
    let i = f.inner.expect("内层以太头");
    assert_eq!(i.destination_mac(), "00:11:22:33:44:55");
    assert_eq!(i.source_mac(), "66:77:88:99:aa:bb");
    assert_eq!(i.ether_type, ETHERTYPE_IPV4);
    assert_eq!(i.ether_type_name(), "ipv4");
    assert_eq!(i.header_len, 14);
    assert_eq!(i.captured_len, 20 + 4);
    let ip = i.ip.expect("内层 IPv4");
    assert_eq!(ip.version, 4);
    assert_eq!(ip.source, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert_eq!(ip.destination, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    assert_eq!(ip.protocol, Some(17));
    assert_eq!(ip.declared_len, Some(24));
    assert_eq!(ip.header_len, Some(20));
    assert!(ip.complete_header);
}

#[test]
fn parses_inner_vlan_and_qinq() {
    let one = tagged(
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        &[10],
        ETHERTYPE_IPV4,
        &ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &[0; 20]),
    );
    let f = parse(&vxlan(1, &one)).expect("单层 VLAN");
    let i = f.inner.expect("内层");
    assert_eq!(i.vlan_ids, vec![10]);
    assert_eq!(i.header_len, 18);
    assert_eq!(i.ether_type, ETHERTYPE_IPV4);

    let two = tagged(
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        &[20, 30],
        ETHERTYPE_IPV6,
        &ipv6([0; 16], [0; 16], 59, &[]),
    );
    let f = parse(&vxlan(2, &two)).expect("QinQ");
    let i = f.inner.expect("内层");
    assert_eq!(i.vlan_ids, vec![20, 30]);
    assert_eq!(i.header_len, 22);
    assert_eq!(i.ether_type, ETHERTYPE_IPV6);
}

#[test]
fn parses_inner_ipv6() {
    let f = parse(&vxlan(0xabcdef, &ipv6_inner())).expect("IPv6 内层");
    let i = f.inner.expect("内层");
    assert_eq!(i.ether_type, ETHERTYPE_IPV6);
    let ip = i.ip.expect("内层 IPv6");
    assert_eq!(ip.version, 6);
    assert_eq!(ip.protocol, Some(17));
    assert_eq!(ip.header_len, Some(40));
    assert!(ip.complete_header);
    assert!(ip.source.is_some());
    assert!(ip.destination.is_some());
}

#[test]
fn parses_inner_arp_without_ip_guess() {
    let arp = eth(
        "ff:ff:ff:ff:ff:ff",
        "00:11:22:33:44:55",
        ETHERTYPE_ARP,
        &[0; 28],
    );
    let f = parse(&vxlan(7, &arp)).expect("ARP 内层");
    let i = f.inner.expect("内层");
    assert_eq!(i.ether_type_name(), "arp");
    assert!(i.ip.is_none(), "ARP 不能被猜成 IP");
    assert!(i.ip_header_complete());
}

#[test]
fn vni_zero_and_max_are_preserved_not_guessed() {
    for vni in [0, 0x00ff_ffff, 0x0012_3456] {
        let f = parse(&vxlan(vni, &ipv4_inner())).expect("VNI 应保留");
        assert_eq!(f.vni, vni);
    }
}

#[test]
fn rejects_short_header_with_stable_code() {
    let e = parse(&[0x08, 0, 0, 0, 0, 0, 0]).expect_err("7 字节头必须拒绝");
    assert_eq!(e.code(), "vxlan.truncated_header");
    assert!(e.to_string().contains("8"));
}

#[test]
fn rejects_missing_i_flag() {
    let e = parse(&vxlan_flags(0x00, 1, &ipv4_inner(), 0)).expect_err("I 位必须置位");
    assert_eq!(e.code(), "vxlan.missing_i_flag");
}

#[test]
fn rejects_reserved_bits_at_each_position() {
    let e = parse(&vxlan_flags(0x09, 1, &ipv4_inner(), 0)).expect_err("flags 保留位");
    assert_eq!(e.code(), "vxlan.reserved_nonzero");
    assert!(matches!(e, VxlanError::ReservedNonZero { offset: 0, .. }));

    let mut p = vxlan(1, &ipv4_inner());
    p[2] = 1;
    let e = parse(&p).expect_err("byte 2 保留位");
    assert!(matches!(e, VxlanError::ReservedNonZero { offset: 2, .. }));

    let mut p = vxlan(1, &ipv4_inner());
    p[7] = 1;
    let e = parse(&p).expect_err("byte 7 保留位");
    assert!(matches!(e, VxlanError::ReservedNonZero { offset: 7, .. }));
}

#[test]
fn rejects_too_many_inner_vlan_tags() {
    let inner = tagged(
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        &[1, 2, 3],
        ETHERTYPE_IPV4,
        &ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &[0; 20]),
    );
    let e = parse(&vxlan(1, &inner)).expect_err("三层 VLAN 必须拒绝");
    assert_eq!(e.code(), "vxlan.vlan_nesting");
}

#[test]
fn complete_short_inner_is_an_error_but_capture_short_is_not() {
    let short = vxlan(1, &ipv4_inner()[..10]);
    let e = parse(&short).expect_err("完整抓包下短内层是畸形");
    assert_eq!(e.code(), "vxlan.truncated_inner");

    let f = parse_with_complete(&short, false).expect("抓包截断应可解析头");
    assert!(f.inner.is_none());
    assert!(f.inner_truncated);
    assert_eq!(f.vni, 1);
}

#[test]
fn incomplete_inner_ip_header_is_visible_but_not_complete() {
    // 以太头完整，内层 IPv4 只给 10 字节。
    let inner = eth(
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        ETHERTYPE_IPV4,
        &[0x45; 10],
    );
    let f = parse(&vxlan(1, &inner)).expect("以太头成立");
    let i = f.inner.expect("内层");
    let ip = i.ip.expect("按 EtherType 识别为 IPv4");
    assert!(!ip.complete_header);
    assert!(ip.source.is_none());
    assert_eq!(ip.declared_len, None);
}

#[test]
fn stats_classify_and_render_contract_fields() {
    let mut s = VxlanStats::default();
    let f = parse(&vxlan(100, &ipv4_inner())).expect("IPv4");
    s.observe(&f);
    let f = parse(&vxlan(
        0,
        &tagged(
            "00:11:22:33:44:55",
            "66:77:88:99:aa:bb",
            &[10],
            ETHERTYPE_IPV6,
            &ipv6([0; 16], [0; 16], 59, &[]),
        ),
    ))
    .expect("IPv6");
    s.observe(&f);
    let f = parse(&vxlan(
        7,
        &eth(
            "ff:ff:ff:ff:ff:ff",
            "00:11:22:33:44:55",
            ETHERTYPE_ARP,
            &[0; 28],
        ),
    ))
    .expect("ARP");
    s.observe(&f);
    let mut f = parse(&vxlan(9, &ipv4_inner())).expect("抓包截断");
    f.capture_truncated = true;
    s.observe(&f);

    s.record_error(parse(&[0x08]).unwrap_err());
    s.record_error(parse(&vxlan_flags(0, 1, &ipv4_inner(), 0)).unwrap_err());
    s.record_error(parse(&vxlan_flags(0x09, 1, &ipv4_inner(), 0)).unwrap_err());

    assert_eq!(s.vxlan_frames, 4);
    assert_eq!(s.vni_zero, 1);
    assert_eq!(s.vlan_tagged, 1);
    assert_eq!(s.inner_ipv4, 2);
    assert_eq!(s.inner_ipv6, 1);
    assert_eq!(s.inner_arp, 1);
    assert_eq!(s.inner_complete, 4);
    assert_eq!(s.inner_incomplete, 0);
    assert_eq!(s.capture_truncated, 1);
    assert_eq!(s.truncated, 1);
    assert_eq!(s.malformed, 2);
    assert_eq!(s.missing_i_flag, 1);
    assert_eq!(s.reserved_nonzero, 1);
    let line = s.render_line();
    for key in [
        "vxlan_frames=4",
        "vni_zero=1",
        "vlan_tagged=1",
        "inner_ipv4=2",
        "inner_ipv6=1",
        "inner_arp=1",
        "inner_complete=4",
        "capture_truncated=1",
        "truncated=1",
        "malformed=2",
    ] {
        assert!(line.contains(key), "统计行缺 {key}: {line}");
    }
}

#[test]
fn json_line_has_stable_fields_and_nulls() {
    let f = parse(&vxlan(
        42,
        &tagged(
            "00:11:22:33:44:55",
            "66:77:88:99:aa:bb",
            &[10],
            ETHERTYPE_IPV4,
            &ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &[0; 4]),
        ),
    ))
    .expect("VXLAN");
    let line = f.to_json_line(
        1_700_000_000_000_000,
        9,
        100,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        55555,
        4789,
    );
    for key in [
        "\"frame\":9",
        "\"outer_src\":\"192.0.2.1\"",
        "\"vni\":42",
        "\"inner_dst_mac\":\"00:11:22:33:44:55\"",
        "\"inner_vlan_ids\":[10]",
        "\"inner_ether_type_name\":\"ipv4\"",
        "\"inner_src_ip\":\"10.0.0.1\"",
        "\"inner_ip_complete\":true",
    ] {
        assert!(line.contains(key), "JSON 缺 {key}: {line}");
    }
}

#[test]
fn ports_are_triggers_not_identity() {
    assert!(is_vxlan_port(UDP_PORT));
    assert!(is_vxlan_port(UDP_PORT_LEGACY));
    assert!(!is_vxlan_port(4788));
    let _ = vxlan_flags(0x08, 1, &[], 0);
}
