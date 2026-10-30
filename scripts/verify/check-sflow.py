#!/usr/bin/env python3
"""sFlow v5 (RFC 3176) collector regression with an independent tshark check.

The wire bytes are built here, not by the Rust encoder: a round-trip through our
own code would only prove that both sides share the same misunderstanding.
`--tshark` makes Wireshark decode the same pcap and compares the agent, sample
types, five-tuple, interface counters and VLANs with the JSONL produced by
`cythsec-sflow-collect`.
"""

import argparse
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get('SFLOW_COLLECT', ROOT / 'target/debug/cythsec-sflow-collect'))
SRC = bytes([192, 0, 2, 1])
DST = bytes([192, 0, 2, 2])
AGENT = bytes([192, 0, 2, 10])
PORT = 6343


def run(args, check=False):
    p = subprocess.run([str(v) for v in args], text=True, capture_output=True, timeout=30)
    if check and p.returncode:
        raise AssertionError(f'{args[0]} failed: {p.returncode}: {p.stderr[-500:]}')
    return p


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def pad4(data):
    return data + b'\0' * ((-len(data)) % 4)


def udp_frame(payload, sport=40000, dport=PORT):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, SRC, DST))
    ip[10:12] = struct.pack('!H', checksum(bytes(ip)))
    return bytes(12) + b'\x08\x00' + bytes(ip) + udp


def write_pcap(path, payloads, sport=40000, dport=PORT):
    out = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, payload in enumerate(payloads):
        frame = udp_frame(payload, sport=sport, dport=dport)
        out += struct.pack('<IIII', 1 + index, 0, len(frame), len(frame)) + frame
    path.write_bytes(out)


def sample(sample_type, body):
    return struct.pack('!II', sample_type, len(body)) + body


def record(rtype, body):
    return struct.pack('!II', rtype, len(body)) + body


def datagram(sequence, samples, sub_agent=1, agent=AGENT, agent_type=1):
    body = b''.join(samples)
    return (
        struct.pack('!II', 5, agent_type)
        + agent
        + struct.pack('!IIII', sub_agent, sequence, 1_234_567, len(samples))
        + body
    )


def ipv4_packet():
    tcp = struct.pack('!HHIIBBHHH', 1234, 80, 1, 0, 0x50, 0x18, 65535, 0, 0)
    ip = bytearray(
        struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                    bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    )
    ip[10:12] = struct.pack('!H', checksum(bytes(ip)))
    return bytes(12) + b'\x08\x00' + bytes(ip) + tcp


def raw_header_record(frame_length=1500):
    header = ipv4_packet()
    body = struct.pack('!IIII', 1, frame_length, 0, len(header)) + pad4(header)
    return record(1, body)


def ipv4_data_record():
    return record(
        3,
        struct.pack('!II4s4sIIII', 1500, 6, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
                    1234, 80, 0x18, 0),
    )


def ipv6_data_record():
    return record(
        4,
        struct.pack('!II16s16sIIII', 1500, 17, bytes(range(16)), bytes(range(16, 32)),
                    5353, 53, 0, 0),
    )


def switch_record():
    return record(1001, struct.pack('!IIII', 100, 3, 200, 4))


def generic_counter():
    body = struct.pack(
        '!IIQIIQIIIIIIQIIIIII',
        3, 6, 1_000_000_000, 1, 3, 123_456_789, 1000, 2, 3, 4, 5, 6,
        987_654_321, 2000, 7, 8, 9, 10, 0,
    )
    assert len(body) == 88
    return record(1, body)


def ethernet_counter():
    body = struct.pack('!13I', *range(1, 14))
    assert len(body) == 52
    return record(2, body)


def vlan_counter():
    body = struct.pack('!IQIIII', 100, 5555, 10, 20, 30, 40)
    assert len(body) == 28
    return record(5, body)


def flow_sample(sequence, records, source_id=5, sampling_rate=1000, sample_pool=123456, drops=2):
    body = struct.pack(
        '!IIIIIIII', sequence, source_id, sampling_rate, sample_pool, drops, 3, 4, len(records)
    ) + b''.join(records)
    return sample(1, body)


def expanded_flow_sample(sequence, records):
    body = struct.pack(
        '!IIIIIIIIIII', sequence, 0, 5, 1000, 123456, 2, 0, 3, 0, 4, len(records)
    ) + b''.join(records)
    return sample(3, body)


def counter_sample(sequence, records, source_id=3, expanded=False):
    if expanded:
        body = struct.pack('!IIII', sequence, 0, source_id, len(records))
        kind = 4
    else:
        body = struct.pack('!III', sequence, source_id, len(records))
        kind = 2
    return sample(kind, body + b''.join(records))


def collect(path, extra=()):
    flows_path = path.with_suffix('.flows.jsonl')
    counters_path = path.with_suffix('.counters.jsonl')
    proc = run([BIN, '--pcap', path, '-o', flows_path, '--counters', counters_path, *extra])
    flows = [json.loads(line) for line in flows_path.read_text().splitlines() if line.strip()]
    counters = [json.loads(line) for line in counters_path.read_text().splitlines() if line.strip()]
    stats = {}
    for line in proc.stderr.splitlines():
        if '[cythsec-sflow-collect] datagrams=' in line:
            body = line.split('] ', 1)[1]
            for item in body.split():
                if '=' in item:
                    key, value = item.split('=', 1)
                    stats[key] = value
    return proc.returncode, stats, flows, counters


def assert_stat(stats, key, expected):
    actual = stats.get(key)
    assert actual == str(expected), f'{key}={actual}, expected {expected}: {stats}'


def tshark_fields(path):
    fields = [
        'sflow_245.version',
        'sflow_245.agent',
        'sflow_245.sequence_number',
        'sflow_245.sampletype',
        'sflow_245.ipv4_src',
        'sflow_245.ipv4_dst',
        'sflow_245.ifindex',
        'sflow_245.ifinoct',
        'sflow_245.ifoutoct',
        'sflow_245.vlan.in',
        'sflow_245.vlan.out',
    ]
    out = run(['tshark', '-r', path, '-Y', 'sflow', '-T', 'fields',
               *sum((['-e', f] for f in fields), [])])
    if out.returncode:
        raise AssertionError(f'tshark failed: {out.stderr[-400:]}')
    rows = []
    for line in out.stdout.splitlines():
        cols = line.split('\t')
        if len(cols) == len(fields) and cols[1]:
            rows.append(dict(zip(fields, cols)))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tshark', action='store_true')
    args = parser.parse_args()
    if not BIN.exists():
        raise SystemExit(f'missing collector binary: {BIN}')

    with tempfile.TemporaryDirectory(prefix='cythsec-sflow-') as tmp:
        tmp = Path(tmp)

        # 1) 基本 flow + counter sample，字段与 tshark 对照。
        path = tmp / 'basic.pcap'
        write_pcap(path, [datagram(100, [
            flow_sample(7, [raw_header_record(), ipv4_data_record(), switch_record()]),
            counter_sample(8, [generic_counter(), ethernet_counter(), vlan_counter()]),
        ])])
        rc, stats, flows, counters = collect(path)
        assert rc == 0, (rc, stats)
        assert len(flows) == 1 and len(counters) == 3, (flows, counters)
        f = flows[0]
        assert f['agent'] == '192.0.2.10', f
        assert f['flow']['src_ip'] == '10.0.0.1' and f['flow']['dst_port'] == 80, f
        assert f['sampling_rate'] == 1000 and f['frame_length'] == 1500, f
        assert f['tcp_flags'] == 24 and f['src_vlan'] == 100 and f['dst_vlan'] == 200, f
        assert f['src_priority'] == 3 and f['dst_priority'] == 4, f
        assert counters[0]['record'] == 'generic_interface', counters
        assert counters[0]['if_index'] == 3 and counters[0]['in_octets'] == 123456789, counters
        assert counters[1]['record'] == 'ethernet' and counters[1]['fcs_errors'] == 2, counters
        assert counters[2]['record'] == 'vlan' and counters[2]['vlan_id'] == 100, counters
        assert_stat(stats, 'samples', 2)
        assert_stat(stats, 'flow_records', 3)
        assert_stat(stats, 'counter_records', 3)
        assert_stat(stats, 'delivered_flows', 1)
        assert_stat(stats, 'delivered_counters', 3)
        assert_stat(stats, 'gaps', 0)
        if args.tshark:
            rows = tshark_fields(path)
            assert rows, 'tshark found no sflow packet'
            row = rows[0]
            assert row['sflow_245.version'] == '5', row
            assert row['sflow_245.agent'] == '192.0.2.10', row
            assert row['sflow_245.sequence_number'] == '100', row
            assert row['sflow_245.sampletype'] == '1,2', row
            assert row['sflow_245.ipv4_src'] == '10.0.0.1', row
            assert row['sflow_245.ipv4_dst'] == '10.0.0.2', row
            assert row['sflow_245.ifindex'] == '3', row
            assert row['sflow_245.ifinoct'] == '123456789', row
            assert row['sflow_245.ifoutoct'] == '987654321', row
            assert row['sflow_245.vlan.in'] == '100' and row['sflow_245.vlan.out'] == '200', row

        # 2) expanded flow sample + IPv6 data record。
        path = tmp / 'ipv6.pcap'
        write_pcap(path, [datagram(101, [expanded_flow_sample(9, [ipv6_data_record()])])])
        rc, stats, flows, _ = collect(path)
        assert rc == 0, (rc, stats)
        assert len(flows) == 1, flows
        assert flows[0]['flow']['src_ip'] == '1:203:405:607:809:a0b:c0d:e0f', flows[0]
        assert flows[0]['flow']['dst_port'] == 53 and flows[0]['flow']['proto_name'] == 'udp', flows[0]
        assert_stat(stats, 'expanded_flow_samples', 1)

        # 3) 数据报序号缺口：seq 200 -> 203，丢 2 个数据报；分母 = 2 实收 + 2 丢失。
        path = tmp / 'gap.pcap'
        write_pcap(path, [
            datagram(200, [flow_sample(1, [ipv4_data_record()])]),
            datagram(203, [flow_sample(2, [ipv4_data_record()])]),
        ])
        rc, stats, flows, _ = collect(path)
        assert rc == 0, (rc, stats)
        assert_stat(stats, 'gaps', 1)
        assert_stat(stats, 'lost_datagrams', 2)
        assert_stat(stats, 'loss_ppm', 500000)
        assert len(flows) == 2, flows

        # 4) 重复数据报：同序号不算丢包；sample 去重后只交付一次。
        path = tmp / 'dup.pcap'
        packet = datagram(300, [flow_sample(1, [ipv4_data_record()])])
        write_pcap(path, [packet, packet])
        rc, stats, flows, _ = collect(path)
        assert rc == 0, (rc, stats)
        assert_stat(stats, 'duplicate_datagrams', 1)
        assert_stat(stats, 'duplicate_samples', 1)
        assert_stat(stats, 'lost_datagrams', 0)
        assert len(flows) == 1, flows

        # 5) 倒退/乱序：不推进基线，不算丢包。
        path = tmp / 'back.pcap'
        write_pcap(path, [datagram(400, []), datagram(399, [])])
        rc, stats, _, _ = collect(path)
        assert rc == 2, (rc, stats)  # 只有空数据报，没有 record
        assert_stat(stats, 'out_of_order', 1)
        assert_stat(stats, 'lost_datagrams', 0)

        # 6) 32 位回绕不算丢包。
        path = tmp / 'wrap.pcap'
        write_pcap(path, [
            datagram(0xFFFFFFFF, [flow_sample(1, [ipv4_data_record()])]),
            datagram(0, [flow_sample(2, [ipv4_data_record()])]),
        ])
        rc, stats, flows, _ = collect(path)
        assert rc == 0, (rc, stats)
        assert_stat(stats, 'lost_datagrams', 0)
        assert_stat(stats, 'out_of_order', 0)
        assert len(flows) == 2, flows

        # 7) sub-agent 独立序号状态。
        path = tmp / 'subagent.pcap'
        write_pcap(path, [
            datagram(1, [flow_sample(1, [ipv4_data_record()])], sub_agent=1),
            datagram(100, [flow_sample(2, [ipv4_data_record()])], sub_agent=2),
        ])
        rc, stats, flows, _ = collect(path)
        assert rc == 0, (rc, stats)
        assert_stat(stats, 'agents', 2)
        assert_stat(stats, 'lost_datagrams', 0)
        assert len(flows) == 2, flows

        # 8) 未知 sample/record 类型按长度跳过，后续有效记录不位移。
        unknown_sample = sample((1 << 12) | 99, b'\0' * 8)
        unknown_record = record((1 << 12) | 77, b'\0' * 8)
        path = tmp / 'unknown.pcap'
        write_pcap(path, [datagram(500, [
            unknown_sample,
            flow_sample(3, [unknown_record, ipv4_data_record()]),
        ])])
        rc, stats, flows, _ = collect(path)
        assert rc == 0, (rc, stats)
        assert_stat(stats, 'unknown_sample_types', 1)
        assert stats['unknown_flow_records'] == str((1 << 12) | 77), stats
        assert len(flows) == 1, flows

        # 9) 版本/agent 类型/截断/非零尾部：显式计入，不 panic。
        bad_version = bytearray(datagram(1, []))
        bad_version[0:4] = struct.pack('!I', 4)
        bad_agent = bytearray(datagram(1, []))
        bad_agent[4:8] = struct.pack('!I', 9)
        truncated = datagram(2, []) + struct.pack('!II', 1, 999)
        trailing = datagram(3, []) + b'\xff'
        path = tmp / 'bad.pcap'
        write_pcap(path, [bytes(bad_version), bytes(bad_agent), truncated, trailing])
        rc, stats, flows, counters = collect(path)
        assert rc == 2, (rc, stats)
        assert_stat(stats, 'version_mismatch', 1)
        assert int(stats['malformed']) >= 3, stats
        assert not flows and not counters

        # 10) 只有 counter sample 也是有效采集（不能因为 flow 为空就报 2）。
        path = tmp / 'counters-only.pcap'
        write_pcap(path, [datagram(600, [counter_sample(4, [generic_counter()], expanded=True)])])
        rc, stats, flows, counters = collect(path)
        assert rc == 0, (rc, stats)
        assert not flows and len(counters) == 1, (flows, counters)
        assert_stat(stats, 'expanded_counter_samples', 1)

        # 11) 只有 Ethernet frame 记录（无 IP）不造五元组，计 missing_key 并以 2 退出。
        eth = record(2, struct.pack('!I6s2x6s2xI', 1500, b'\x00' * 6, b'\x11' * 6, 0x0800))
        path = tmp / 'missing-key.pcap'
        write_pcap(path, [datagram(700, [flow_sample(5, [eth])])])
        rc, stats, flows, _ = collect(path)
        assert rc == 2, (rc, stats)
        assert_stat(stats, 'missing_key', 1)
        assert not flows

        # 12) 端口过滤：非 6343 的 UDP 默认跳过，--any-port 才收。
        path = tmp / 'port.pcap'
        write_pcap(path, [datagram(800, [flow_sample(6, [ipv4_data_record()])])], dport=9999)
        rc, stats, _, _ = collect(path)
        assert rc == 0, (rc, stats)  # 没有数据报，正常 0
        assert stats.get('datagrams') == '0', stats
        rc, stats, flows, _ = collect(path, ['--any-port'])
        assert rc == 0, (rc, stats)
        assert len(flows) == 1, flows

    print('sFlow v5 collector checks passed')


if __name__ == '__main__':
    main()
