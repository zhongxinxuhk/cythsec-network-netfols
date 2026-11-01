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

fn option(class: u16, type_: u8, data: &[u8]) -> Vec<u8> {
    assert_eq!(data.len() % 4, 0, "Geneve 选项数据必须按 4 字节对齐");
    let mut v = Vec::new();
    v.extend_from_slice(&class.to_be_bytes());
    v.push(type_);
    v.push((data.len() / 4) as u8);
    v.extend_from_slice(data);
    v
}

fn geneve(flags: u8, protocol_type: u16, vni: u32, options: &[u8], body: &[u8]) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let mut v = vec![(options.len() / 4) as u8, flags];
    v.extend_from_slice(&protocol_type.to_be_bytes());
    v.extend_from_slice(&vni.to_be_bytes()[1..]);
    v.push(0);
    v.extend_from_slice(options);
    v.extend_from_slice(body);
    v
}

fn teb_ipv4() -> Vec<u8> {
    eth(
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        ETHERTYPE_IPV4,
        &ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &[0, 1, 2, 3]),
    )
}

#[test]
fn parses_teb_ipv4_without_options() {
    let f = parse(&geneve(0, ETHERTYPE_TEB, 100, &[], &teb_ipv4())).expect("Geneve");
    assert_eq!(f.vni, 100);
    assert_eq!(f.version, 0);
    assert_eq!(f.opt_len, 0);
    assert!(!f.control);
    assert!(!f.critical);
    assert!(f.options.is_empty());
    assert!(!f.reserved_nonzero);
    assert_eq!(f.protocol_type_name(), "ethernet");
    assert_eq!(f.inner_kind(), "ethernet");
    assert_eq!(f.inner_complete(), Some(true));
    let i = f.inner_ethernet().expect("TEB 内层");
    assert_eq!(i.destination_mac(), "00:11:22:33:44:55");
    assert_eq!(i.source_mac(), "66:77:88:99:aa:bb");
    assert_eq!(i.header_len, 14);
    let ip = i.ip.expect("内层 IPv4");
    assert_eq!(ip.source, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert_eq!(ip.protocol, Some(17));
}

#[test]
fn parses_teb_vlan_and_qinq() {
    let one = tagged(
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        &[10],
        ETHERTYPE_IPV4,
        &ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &[0; 20]),
    );
    let f = parse(&geneve(0, ETHERTYPE_TEB, 1, &[], &one)).expect("单层 VLAN");
    let i = f.inner_ethernet().expect("内层");
    assert_eq!(i.vlan_ids, vec![10]);
    assert_eq!(i.header_len, 18);

    let two = tagged(
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        &[20, 30],
        ETHERTYPE_IPV6,
        &ipv6([0; 16], [0; 16], 59, &[]),
    );
    let f = parse(&geneve(0, ETHERTYPE_TEB, 2, &[], &two)).expect("QinQ");
    let i = f.inner_ethernet().expect("内层");
    assert_eq!(i.vlan_ids, vec![20, 30]);
    assert_eq!(i.header_len, 22);
    assert_eq!(i.ether_type, ETHERTYPE_IPV6);
}

#[test]
fn parses_raw_ipv4_and_ipv6() {
    let v4 = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &[0; 8]);
    let f = parse(&geneve(0, ETHERTYPE_IPV4, 3, &[], &v4)).expect("裸 IPv4");
    assert_eq!(f.inner_kind(), "ipv4");
    assert_eq!(f.inner_complete(), Some(true));
    let i = f.inner_ip().expect("IPv4");
    assert_eq!(i.protocol, Some(17));
    assert_eq!(i.header_len, Some(20));

    let v6 = ipv6(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0; 16],
        59,
        &[],
    );
    let f = parse(&geneve(0, ETHERTYPE_IPV6, 4, &[], &v6)).expect("裸 IPv6");
    assert_eq!(f.inner_kind(), "ipv6");
    assert_eq!(f.inner_complete(), Some(true));
    assert_eq!(f.inner_ip().expect("IPv6").version, 6);
}

#[test]
fn parses_critical_option_and_c_bit() {
    let opts = option(0x0100, 0x81, &[1, 2, 3, 4]);
    let f = parse(&geneve(0x40, ETHERTYPE_TEB, 5, &opts, &teb_ipv4())).expect("关键选项");
    assert!(f.critical);
    assert_eq!(f.options.len(), 1);
    assert!(f.options[0].critical);
    assert_eq!(f.options[0].class, 0x0100);
    assert_eq!(f.options[0].type_, 0x81);
    assert_eq!(f.options[0].data_len, 4);
}

#[test]
fn control_packet_does_not_interpret_payload() {
    let opts = option(0x0200, 0x01, &[0; 4]);
    let f = parse(&geneve(0x80, ETHERTYPE_TEB, 6, &opts, &teb_ipv4())).expect("控制报文");
    assert!(f.control);
    assert!(f.inner.is_none(), "O=1 不得解释载荷");
    assert_eq!(f.inner_kind(), "control");
    assert_eq!(f.inner_complete(), None);
    assert_eq!(f.options.len(), 1);
}

#[test]
fn vni_zero_and_max_are_preserved() {
    for vni in [0, 0x00ff_ffff, 0x0012_3456] {
        let f = parse(&geneve(0, ETHERTYPE_TEB, vni, &[], &teb_ipv4())).expect("VNI");
        assert_eq!(f.vni, vni);
    }
}

#[test]
fn reserved_bits_are_counted_not_rejected() {
    let mut f = geneve(0x01, ETHERTYPE_TEB, 7, &[], &teb_ipv4());
    f[7] = 2;
    let f = parse(&f).expect("RFC 8926 要求接收时忽略保留位");
    assert!(f.reserved_nonzero);
    assert_eq!(f.vni, 7);

    let opts = option(0x0300, 0x81, &[0; 4]);
    let mut f = geneve(0x40, ETHERTYPE_TEB, 8, &opts, &teb_ipv4());
    f[1] |= 0x20; // 基础 flags 的保留位
    f[11] |= 0x20; // 选项长度字段的高 3 位
    let f = parse(&f).expect("保留位忽略");
    assert!(f.reserved_nonzero);
    assert_eq!(f.options[0].reserved, 0x20);
}

#[test]
fn rejects_short_header_with_stable_code() {
    let e = parse(&[0, 0, 0, 0, 0, 0, 0]).expect_err("7 字节头");
    assert_eq!(e.code(), "geneve.truncated_header");
}

#[test]
fn rejects_unknown_version() {
    let mut p = geneve(0, ETHERTYPE_TEB, 1, &[], &teb_ipv4());
    p[0] = 0x40;
    let e = parse(&p).expect_err("version 1");
    assert_eq!(e.code(), "geneve.unsupported_version");
    assert!(matches!(e, GeneveError::UnsupportedVersion { version: 1 }));
}

#[test]
fn rejects_truncated_options_in_complete_capture() {
    let mut p = geneve(0, ETHERTYPE_TEB, 1, &[0; 4], &[]);
    p[0] = 2; // optlen=2，但只给 4 字节选项
    let e = parse(&p).expect_err("完整抓包选项不足");
    assert_eq!(e.code(), "geneve.truncated_options");
}

#[test]
fn capture_truncated_options_keep_header() {
    let mut p = geneve(0, ETHERTYPE_TEB, 1, &[0; 4], &[]);
    p[0] = 2;
    let f = parse_with_complete(&p, false).expect("抓包截断");
    assert_eq!(f.vni, 1);
    assert!(f.options_truncated);
    assert!(f.inner.is_none());
    assert_eq!(f.inner_kind(), "options_truncated");
}

#[test]
fn rejects_option_overrun() {
    let mut p = geneve(0, ETHERTYPE_TEB, 1, &[0; 4], &teb_ipv4());
    p[0] = 1;
    p[11] = 0x01; // 选项头声明 4 字节数据，但选项区只有 4 字节
    let e = parse(&p).expect_err("选项越界");
    assert_eq!(e.code(), "geneve.option_overrun");
}

#[test]
fn rejects_critical_mismatch() {
    let opts = option(0x0100, 0x81, &[0; 4]);
    let e = parse(&geneve(0, ETHERTYPE_TEB, 1, &opts, &teb_ipv4())).expect_err("C=0 但选项关键");
    assert_eq!(e.code(), "geneve.critical_mismatch");

    let opts = option(0x0100, 0x01, &[0; 4]);
    let e = parse(&geneve(0x40, ETHERTYPE_TEB, 1, &opts, &teb_ipv4())).expect_err("C=1 无关键");
    assert_eq!(e.code(), "geneve.critical_mismatch");
}

#[test]
fn rejects_truncated_inner_for_teb() {
    let e = parse(&geneve(0, ETHERTYPE_TEB, 1, &[], &[0; 10])).expect_err("完整抓包内层短");
    assert_eq!(e.code(), "geneve.truncated_inner");
}

#[test]
fn capture_truncated_inner_is_not_malformed() {
    let f =
        parse_with_complete(&geneve(0, ETHERTYPE_TEB, 1, &[], &[0; 10]), false).expect("抓包截断");
    assert!(f.inner_truncated);
    assert!(f.inner.is_none());
    assert_eq!(f.inner_kind(), "truncated");
}

#[test]
fn rejects_three_vlan_tags() {
    let inner = tagged(
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        &[1, 2, 3],
        ETHERTYPE_IPV4,
        &ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &[0; 20]),
    );
    let e = parse(&geneve(0, ETHERTYPE_TEB, 1, &[], &inner)).expect_err("三层 VLAN");
    assert_eq!(e.code(), "geneve.vlan_nesting");
}

#[test]
fn unknown_protocol_type_is_visible_not_guessed() {
    let f = parse(&geneve(0, 0x1234, 9, &[], &[0; 8])).expect("未知 protocol type");
    assert_eq!(f.protocol_type_name(), "unknown");
    assert_eq!(f.inner_kind(), "other");
    assert!(f.inner.is_none());
}

#[test]
fn arp_inner_is_not_guessed_as_ip() {
    let inner = eth(
        "ff:ff:ff:ff:ff:ff",
        "00:11:22:33:44:55",
        ETHERTYPE_ARP,
        &[0; 28],
    );
    let f = parse(&geneve(0, ETHERTYPE_TEB, 10, &[], &inner)).expect("ARP");
    let e = f.inner_ethernet().expect("内层");
    assert_eq!(e.ether_type_name(), "arp");
    assert!(e.ip.is_none());
    assert_eq!(f.inner_complete(), Some(true));
}

#[test]
fn stats_classify_and_render_contract_fields() {
    let mut s = GeneveStats::default();
    let f = parse(&geneve(0, ETHERTYPE_TEB, 100, &[], &teb_ipv4())).expect("TEB");
    s.observe(&f);
    let opts = option(0x0100, 0x81, &[0; 4]);
    let f = parse(&geneve(0x40, ETHERTYPE_TEB, 0, &opts, &teb_ipv4())).expect("C");
    s.observe(&f);
    let v4 = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &[0; 4]);
    let f = parse(&geneve(0, ETHERTYPE_IPV4, 3, &[], &v4)).expect("裸 IP");
    s.observe(&f);
    let f = parse(&geneve(0x80, ETHERTYPE_TEB, 4, &[], &teb_ipv4())).expect("control");
    s.observe(&f);
    let f = parse(&geneve(0, 0x1234, 5, &[], &[0; 4])).expect("unknown");
    s.observe(&f);
    let mut f = parse(&geneve(0, ETHERTYPE_TEB, 6, &[], &teb_ipv4())).expect("capture");
    f.capture_truncated = true;
    s.observe(&f);

    s.record_error(parse(&[0; 7]).unwrap_err());
    s.record_error(GeneveError::OptionOverrun {
        offset: 8,
        length: 4,
        header_len: 12,
    });
    s.record_error(GeneveError::CriticalMismatch {
        c_bit: false,
        option_critical: true,
    });

    assert_eq!(s.geneve_frames, 6);
    assert_eq!(s.vni_zero, 1);
    assert_eq!(s.control, 1);
    assert_eq!(s.critical, 1);
    assert_eq!(s.options, 1);
    assert_eq!(s.options_critical, 1);
    assert_eq!(s.inner_ethernet, 3);
    assert_eq!(s.inner_ipv4, 4);
    assert_eq!(s.inner_ipv6, 0);
    assert_eq!(s.inner_other, 1);
    assert_eq!(s.inner_complete, 4);
    assert_eq!(s.inner_incomplete, 0);
    assert_eq!(s.capture_truncated, 1);
    assert_eq!(s.truncated, 1);
    assert_eq!(s.malformed, 2);
    assert_eq!(s.option_overrun, 1);
    assert_eq!(s.critical_mismatch, 1);
    let line = s.render_line();
    for key in [
        "geneve_frames=6",
        "vni_zero=1",
        "control=1",
        "critical=1",
        "options=1",
        "options_critical=1",
        "inner_ethernet=3",
        "inner_ipv4=4",
        "inner_other=1",
        "capture_truncated=1",
        "truncated=1",
        "malformed=2",
    ] {
        assert!(line.contains(key), "统计行缺 {key}: {line}");
    }
}

#[test]
fn json_line_has_stable_fields_and_nulls() {
    let opts = option(0x0100, 0x01, &[1, 2, 3, 4]);
    let f = parse(&geneve(0, ETHERTYPE_TEB, 42, &opts, &teb_ipv4())).expect("Geneve");
    let line = f.to_json_line(
        1_700_000_000_000_000,
        9,
        120,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        55555,
        6081,
    );
    for key in [
        "\"frame\":9",
        "\"outer_dst_port\":6081",
        "\"version\":0",
        "\"opt_len\":2",
        "\"header_len\":16",
        "\"protocol_type_name\":\"ethernet\"",
        "\"vni\":42",
        "\"options\":[{\"class\":256,\"type\":1,\"critical\":false,\"data_len\":4}]",
        "\"inner_kind\":\"ethernet\"",
        "\"inner_dst_mac\":\"00:11:22:33:44:55\"",
        "\"inner_src_ip\":\"10.0.0.1\"",
        "\"inner_ip_complete\":true",
    ] {
        assert!(line.contains(key), "JSON 缺 {key}: {line}");
    }
}

#[test]
fn ports_are_triggers_not_identity() {
    assert!(is_geneve_port(UDP_PORT));
    assert!(!is_geneve_port(4789));
    assert!(!is_geneve_port(6080));
}
