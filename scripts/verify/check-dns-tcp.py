#!/usr/bin/env python3
"""Offline DNS/TCP framing and main-pipeline reassembly regression.

两组用例分开：
1. 单包长度帧：既有 CLI 契约（无 SYN 时走弱判定）。
2. 主流水线重组：SYN 锚定 + 乱序/冲突/缺尾分片，验证 `pipeline::dns_tcp` 真的接进了
   `cythsec-analyze`，而不是只有单元测试绿。
`--tshark` 时由 Wireshark 独立重组同一批 TCP 字节并解出 DNS 字段。
"""

import argparse
import json
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / 'target/debug/cythsec-analyze'
SRC = bytes([192, 0, 2, 1])
DST = bytes([198, 51, 100, 2])


def run(args):
    p = subprocess.run([str(v) for v in args], text=True, capture_output=True, timeout=20)
    if p.returncode:
        raise AssertionError(f'{args[0]} failed: {p.returncode}: {p.stderr[-400:]}')
    return p.stdout


def frame_seq(src, dst, source_port, destination_port, seq, ack, flags, payload):
    tcp = struct.pack('!HHIIBBHHH', source_port, destination_port, seq, ack, 0x50, flags, 65535, 0, 0) + payload
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst))
    checksum = sum(struct.unpack('!10H', ip))
    checksum = (checksum & 65535) + (checksum >> 16)
    checksum = (checksum & 65535) + (checksum >> 16)
    ip[10:12] = struct.pack('!H', (~checksum) & 65535)
    return bytes(12) + b'\x08\x00' + ip + tcp


def frame(payload, source_port=40000, destination_port=53):
    return frame_seq(SRC, DST, source_port, destination_port, 100, 0, 0x18, payload)


def write_pcap_frames(path, frames):
    out = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, data in enumerate(frames):
        out += struct.pack('<IIII', 1, index * 1000, len(data), len(data)) + data
    path.write_bytes(out)


def write_pcap(path, payload, source_port=40000, destination_port=53):
    write_pcap_frames(path, [frame(payload, source_port, destination_port)])


def rows(path, *args):
    return [json.loads(line) for line in run([BIN, '-r', path, '-q', *args]).splitlines()]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tshark', action='store_true')
    args = parser.parse_args()
    qname = b'\x08resolver\x07example\x00'
    question = qname + struct.pack('!HH', 1, 1)
    query = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + question
    response = (
        struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)
        + question
        + b'\xc0\x0c'
        + struct.pack('!HHIH', 1, 1, 60, 4)
        + bytes([192, 0, 2, 42])
    )

    def packet(body):
        return struct.pack('!H', len(body)) + body

    with tempfile.TemporaryDirectory(prefix='cythsec-dns-tcp-') as tmp:
        path = Path(tmp) / 'dns.pcap'
        for body, sport, dport in [(query, 40000, 53), (response, 53, 40000)]:
            write_pcap(path, packet(body), sport, dport)
            actual = rows(path)
            assert len(actual) == 1 and actual[0]['app']['app'] == 'dns', actual
            assert actual[0]['app']['outcome'] == 'identified'
            if args.tshark:
                text = (
                    run(
                        [
                            'tshark',
                            '-r',
                            path,
                            '-T',
                            'fields',
                            '-e',
                            'dns.qry.name',
                            '-e',
                            'dns.qry.type',
                            '-e',
                            'dns.a',
                        ]
                    )
                    .strip()
                    .split('\t')
                )
                assert text[:2] == ['resolver.example', '1'], text
                if sport == 53:
                    assert text[2] == '192.0.2.42', text
        for body, forbidden in [
            (packet(query)[:-1], 'identified'),
            (packet(query[:-1]) + packet(query), 'identified'),
            (query, 'identified'),
        ]:
            write_pcap(path, body)
            actual = rows(path)
            assert not any(row['app']['app'] == 'dns' and row['app']['outcome'] == forbidden for row in actual)

        # ---- 主流水线重组：SYN 锚定 + 乱序分片 ----
        body = packet(query)
        resp = packet(response)
        handshake = [
            frame_seq(SRC, DST, 40000, 53, 1000, 0, 0x02, b''),
            frame_seq(DST, SRC, 53, 40000, 5000, 1001, 0x12, b''),
            frame_seq(SRC, DST, 40000, 53, 1001, 5001, 0x10, b''),
        ]
        split = handshake + [
            # 先到尾部、后到头部：洞被填上后才允许判定。
            frame_seq(SRC, DST, 40000, 53, 1010, 5001, 0x18, body[9:]),
            frame_seq(SRC, DST, 40000, 53, 1001, 5001, 0x18, body[:9]),
            frame_seq(DST, SRC, 53, 40000, 5001, 1001 + len(body), 0x18, resp[:10]),
            frame_seq(DST, SRC, 53, 40000, 5011, 1001 + len(body), 0x18, resp[10:]),
        ]
        write_pcap_frames(path, split)
        actual = rows(path)
        assert len(actual) == 1, actual
        assert actual[0]['app']['app'] == 'dns' and actual[0]['app']['confidence'] == 'high', actual
        assert actual[0]['app']['bytes_inspected'] == len(body), actual
        assert rows(path, '--workers', '2') == actual
        if args.tshark:
            text = run(['tshark', '-r', path, '-Y', 'dns', '-T', 'fields', '-e', 'dns.qry.name', '-e', 'dns.a']).strip()
            assert text == 'resolver.example\t192.0.2.42', text

        # 缺尾：长度帧声明 34 字节，只到 20 字节就必须是 need_more，不能猜成 dns。
        missing = handshake + [
            frame_seq(SRC, DST, 40000, 53, 1010, 5001, 0x18, body[9:20]),
            frame_seq(SRC, DST, 40000, 53, 1001, 5001, 0x18, body[:9]),
        ]
        write_pcap_frames(path, missing)
        actual = rows(path)
        assert actual and actual[0]['app']['outcome'] == 'need_more', actual

        # 冲突重叠：同一序号两种字节，补多少都救不回来。
        changed = bytearray(body[:9])
        changed[5] ^= 1
        conflict = handshake + [
            frame_seq(SRC, DST, 40000, 53, 1001, 5001, 0x18, body[:9]),
            frame_seq(SRC, DST, 40000, 53, 1001, 5001, 0x18, bytes(changed)),
        ]
        write_pcap_frames(path, conflict)
        actual = rows(path)
        assert actual and actual[0]['app']['outcome'] == 'need_more', actual

        # 无 SYN（中途接入）：保留单包弱判定，但置信度必须是 medium。
        write_pcap(path, body, 40000, 53)
        actual = rows(path)
        assert actual[0]['app']['app'] == 'dns' and actual[0]['app']['confidence'] == 'medium', actual
        assert actual[0]['app']['rationale'] == 'dns_tcp.unanchored_packet_only', actual

        # 端口上下文：非 53 端口不做跨段重组，乱序分片不得凭长度帧拼出 dns。
        drift = [
            frame_seq(SRC, DST, 40000, 54, 1010, 0, 0x18, body[9:]),
            frame_seq(SRC, DST, 40000, 54, 1001, 0, 0x18, body[:9]),
        ]
        write_pcap_frames(path, drift)
        actual = rows(path)
        assert not any(row['app']['app'] == 'dns' for row in actual), actual
    print(
        'DNS/TCP CLI: single-packet framing + split/out-of-order reassembly, '
        'missing-tail, conflict, midstream and port-context cases passed; '
        + ('tshark fields matched' if args.tshark else 'independent reference not requested')
    )


if __name__ == '__main__':
    main()
