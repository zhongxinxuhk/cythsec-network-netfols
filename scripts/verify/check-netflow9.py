#!/usr/bin/env python3
"""NetFlow v9 (RFC 3954) collector regression with an independent tshark check.

The wire bytes are built here, not by the Rust encoder: a round-trip through our
own code would only prove that both sides share the same misunderstanding.
`--tshark` makes Wireshark decode the same pcap and compares the five-tuple and
counters with the JSONL produced by `cythsec-netflow9-collect`.
"""

import argparse
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get('NETFLOW9_COLLECT', ROOT / 'target/debug/cythsec-netflow9-collect'))
SRC = bytes([192, 0, 2, 1])
DST = bytes([198, 51, 100, 2])
PORT = 2055


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


def udp_frame(payload, sport=40000, dport=PORT):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, SRC, DST))
    ip[10:12] = struct.pack('!H', checksum(bytes(ip)))
    return bytes(12) + b'\x08\x00' + bytes(ip) + udp


def write_pcap(path, payloads, sport=40000):
    out = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, payload in enumerate(payloads):
        frame = udp_frame(payload, sport=sport)
        out += struct.pack('<IIII', 1 + index, 0, len(frame), len(frame)) + frame
    path.write_bytes(out)


def template_flowset(tid, fields):
    body = struct.pack('!HH', tid, len(fields))
    for code, length in fields:
        body += struct.pack('!HH', code, length)
    return struct.pack('!HH', 0, 4 + len(body)) + body


def options_template_flowset(tid, scope, options):
    body = struct.pack('!HHH', tid, 4 * len(scope), 4 * len(options))
    for code, length in scope + options:
        body += struct.pack('!HH', code, length)
    return struct.pack('!HH', 1, 4 + len(body)) + body


def data_flowset(tid, body, pad=b''):
    payload = body + pad
    return struct.pack('!HH', tid, 4 + len(payload)) + payload


def message(sequence, sets, source_id=1, count=None, uptime=1_000_000, unix=1_700_000_000):
    body = b''.join(sets)
    if count is None:
        count = 1  # 本脚本的断言不依赖正确 count；需要时显式传入。
    return struct.pack('!HHIIII', 9, count, uptime, unix, sequence, source_id) + body


V4_FIELDS = [
    (8, 4),
    (12, 4),
    (7, 2),
    (11, 2),
    (4, 1),
    (1, 4),
    (2, 4),
    (152, 8),
    (153, 8),
    (148, 4),
    (34, 2),
]


def v4_record(src, dst, sport, dport, proto, flow_id, octets=1500, packets=10):
    return (
        bytes(src)
        + bytes(dst)
        + struct.pack('!HH', sport, dport)
        + bytes([proto])
        + struct.pack('!II', octets, packets)
        + struct.pack('!QQ', 1_700_000_000_000, 1_700_000_001_000)
        + struct.pack('!IH', flow_id, 1)
    )


def collect(path, extra=()):
    out = path.with_suffix('.jsonl')
    proc = run([BIN, '--pcap', path, '-o', out, *extra])
    flows = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    stats = {}
    for line in proc.stderr.splitlines():
        if '[cythsec-netflow9-collect] datagrams=' in line:
            body = line.split('datagrams=', 1)[1]
            for item in body.split():
                if '=' in item:
                    key, value = item.split('=', 1)
                    stats[key] = value
    return proc.returncode, stats, flows


def assert_stat(stats, key, expected):
    actual = stats.get(key)
    assert actual == str(expected), f'{key}={actual}, expected {expected}: {stats}'


def tshark_fields(path):
    fields = [
        'cflow.version',
        'cflow.template_id',
        'cflow.srcaddr',
        'cflow.dstaddr',
        'cflow.srcport',
        'cflow.dstport',
        'cflow.protocol',
        'cflow.octets',
        'cflow.packets',
    ]
    out = run(['tshark', '-r', path, '-Y', 'cflow', '-T', 'fields', *sum((['-e', f] for f in fields), [])])
    if out.returncode:
        raise AssertionError(f'tshark failed: {out.stderr[-400:]}')
    rows = []
    for line in out.stdout.splitlines():
        cols = line.split('\t')
        if len(cols) == len(fields) and cols[2]:
            rows.append(dict(zip(fields, cols)))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tshark', action='store_true')
    args = parser.parse_args()
    if not BIN.exists():
        raise SystemExit(f'missing collector binary: {BIN}')

    with tempfile.TemporaryDirectory(prefix='cythsec-netflow9-') as tmp:
        tmp = Path(tmp)
        path = tmp / 'v9.pcap'
        tpl = template_flowset(256, V4_FIELDS)
        rec1 = v4_record([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 6, 7)
        rec2 = v4_record([10, 0, 0, 3], [10, 0, 0, 4], 53, 53, 17, 8)
        data = data_flowset(256, rec1 + rec2)

        write_pcap(path, [message(1, [tpl], count=1), message(2, [data], count=2)])
        rc, stats, flows = collect(path)
        assert rc == 0, (rc, stats)
        assert len(flows) == 2, flows
        assert flows[0]['flow']['src_ip'] == '10.0.0.1'
        assert flows[0]['flow']['dst_port'] == 80
        assert flows[0]['counters'] == {'packets': 10, 'bytes': 1500, 'direction_switches': 0}
        assert flows[0]['time']['first_seen_us'] == 1_700_000_000_000_000
        assert flows[1]['flow']['proto_name'] == 'udp'
        assert_stat(stats, 'delivered', 2)
        assert_stat(stats, 'gaps', 0)
        assert_stat(stats, 'count_mismatches', 0)
        if args.tshark:
            rows = tshark_fields(path)
            assert len(rows) == 1, rows
            row = rows[0]
            assert row['cflow.version'] == '9'
            assert row['cflow.srcaddr'] == '10.0.0.1,10.0.0.3'
            assert row['cflow.dstaddr'] == '10.0.0.2,10.0.0.4'
            assert row['cflow.srcport'] == '1234,53'
            assert row['cflow.dstport'] == '80,53'
            assert row['cflow.protocol'] == '6,17'
            assert row['cflow.octets'] == '1500,1500'
            assert row['cflow.packets'] == '10,10'

        # 报文级丢包：seq 1 → 3 表示 2 号报文丢失；分母 2 收 + 1 丢。
        write_pcap(path, [message(1, [tpl], count=1), message(3, [data], count=2)])
        rc, stats, flows = collect(path)
        assert rc == 0, (rc, stats)
        assert_stat(stats, 'gaps', 1)
        assert_stat(stats, 'lost_export_packets', 1)
        assert_stat(stats, 'loss_ppm', 333333)
        assert_stat(stats, 'delivered', 2)

        # 重复序号：不是丢包。
        write_pcap(path, [message(5, [tpl, data], count=3), message(5, [data], count=2)])
        rc, stats, flows = collect(path)
        assert rc == 0, (rc, stats)
        assert_stat(stats, 'duplicate_datagrams', 1)
        assert_stat(stats, 'lost_export_packets', 0)
        assert len(flows) == 2

        # IPv6 + 缩减长度编码（octets 4 字节、packets 2 字节）。
        v6_fields = [(27, 16), (28, 16), (7, 2), (11, 2), (4, 1), (1, 4), (2, 2)]
        v6_tpl = template_flowset(257, v6_fields)
        v6_rec = (
            bytes.fromhex('20010db8000000000000000000000001')
            + bytes.fromhex('20010db8000000000000000000000002')
            + struct.pack('!HH', 1234, 443)
            + bytes([6])
            + struct.pack('!I', 900)
            + struct.pack('!H', 3)
        )
        write_pcap(path, [message(1, [v6_tpl, data_flowset(257, v6_rec)], count=2)])
        rc, stats, flows = collect(path)
        assert rc == 0, (rc, stats)
        assert flows[0]['flow']['src_ip'] == '2001:db8::1'
        assert flows[0]['flow']['dst_port'] == 443
        assert flows[0]['counters']['bytes'] == 900
        assert flows[0]['counters']['packets'] == 3

        # 未映射字段类型必须保留长度、不得让后续字段错位。
        mixed = [(9999, 3)] + V4_FIELDS
        rec = b'\xaa\xbb\xcc' + v4_record([10, 0, 0, 5], [10, 0, 0, 6], 7, 8, 17, 9)
        write_pcap(path, [message(1, [template_flowset(258, mixed), data_flowset(258, rec)], count=2)])
        rc, stats, flows = collect(path)
        assert rc == 0, (rc, stats)
        assert flows[0]['flow']['src_ip'] == '10.0.0.5'
        assert flows[0]['counters']['bytes'] == 1500
        assert_stat(stats, 'unknown_field_types', '9999')

        # 21/22 号字段：sysUpTime 相对值换算成绝对毫秒。
        up_fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (22, 4), (21, 4)]
        up_rec = (
            bytes([10, 0, 0, 7])
            + bytes([10, 0, 0, 8])
            + struct.pack('!HH', 1, 2)
            + bytes([6])
            + struct.pack('!II', 999_000, 1_000_000)
        )
        write_pcap(path, [message(1, [template_flowset(259, up_fields), data_flowset(259, up_rec)], count=2)])
        rc, stats, flows = collect(path)
        assert rc == 0, (rc, stats)
        assert flows[0]['time']['first_seen_us'] == 1_699_999_999_000_000
        assert flows[0]['time']['last_seen_us'] == 1_700_000_000_000_000

        # 选项模板 + 选项数据集：只跳过并计数，不硬解成流。
        opts = options_template_flowset(300, [(8, 4)], [(4, 2)])
        rec3 = v4_record([10, 0, 0, 9], [10, 0, 0, 10], 1, 2, 6, 10)
        write_pcap(
            path,
            [message(1, [tpl, opts, data_flowset(256, rec3), data_flowset(300, b'\0' * 6)], count=4)],
        )
        rc, stats, flows = collect(path)
        assert rc == 0, (rc, stats)
        assert len(flows) == 1
        assert_stat(stats, 'options_template_records', 1)
        assert_stat(stats, 'options_data_sets_skipped', 1)

        # 模板缺失：数据段无法解释，退出码 2，不能静默算成 0 条成功。
        write_pcap(path, [message(1, [data], count=2)])
        rc, stats, flows = collect(path)
        assert rc == 2, (rc, stats)
        assert_stat(stats, 'no_template_sets', 1)
        assert not flows

        # 截断的 FlowSet：整报文判畸形。
        bad = struct.pack('!HH', 256, 100) + rec1
        write_pcap(path, [message(1, [bad], count=1)])
        rc, stats, flows = collect(path)
        assert rc == 2, (rc, stats)
        assert int(stats['malformed']) >= 1, stats
        assert not flows

        # count 字段写错：报出来但不丢数据。
        write_pcap(path, [message(1, [tpl, data], count=99)])
        rc, stats, flows = collect(path)
        assert rc == 0, (rc, stats)
        assert_stat(stats, 'count_mismatches', 1)
        assert len(flows) == 2

    print(
        'NetFlow v9 CLI: template/data, sequence gaps, duplicate, IPv6, unknown field, '
        'sysUpTime, options-template, missing-template, truncated and count-mismatch cases passed; '
        + ('tshark fields matched' if args.tshark else 'independent reference not requested')
    )


if __name__ == '__main__':
    main()
