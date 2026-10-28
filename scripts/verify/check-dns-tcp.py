#!/usr/bin/env python3
"""Offline DNS/TCP framing regression; independent tshark checks are explicit."""

import argparse
import json
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / 'target/debug/cythsec-analyze'


def run(args):
    p = subprocess.run([str(v) for v in args], text=True, capture_output=True, timeout=20)
    if p.returncode:
        raise AssertionError(f'{args[0]} failed: {p.returncode}: {p.stderr[-400:]}')
    return p.stdout


def frame(payload, source_port=40000, destination_port=53):
    tcp = struct.pack('!HHIIBBHHH', source_port, destination_port, 100, 0, 0x50, 0x18, 65535, 0, 0) + payload
    ip = bytearray(
        struct.pack(
            '!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2])
        )
    )
    checksum = sum(struct.unpack('!10H', ip))
    checksum = (checksum & 65535) + (checksum >> 16)
    checksum = (checksum & 65535) + (checksum >> 16)
    ip[10:12] = struct.pack('!H', (~checksum) & 65535)
    return bytes(12) + b'\x08\x00' + ip + tcp


def write_pcap(path, payload, source_port=40000, destination_port=53):
    data = frame(payload, source_port, destination_port)
    path.write_bytes(
        struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack('<IIII', 1, 0, len(data), len(data))
        + data
    )


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
            rows = [json.loads(line) for line in run([BIN, '-r', path, '-q']).splitlines()]
            assert len(rows) == 1 and rows[0]['app']['app'] == 'dns' and rows[0]['app']['outcome'] == 'identified'
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
            rows = [json.loads(line) for line in run([BIN, '-r', path, '-q']).splitlines()]
            assert not any(row['app']['app'] == 'dns' and row['app']['outcome'] == forbidden for row in rows)
    print(
        'DNS/TCP CLI: query/response and 3 framing mutations passed; '
        + ('tshark fields matched' if args.tshark else 'independent reference not requested')
    )


if __name__ == '__main__':
    main()
