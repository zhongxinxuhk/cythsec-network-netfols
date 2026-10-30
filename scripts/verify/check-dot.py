#!/usr/bin/env python3
"""B018: local MemoryBIO TLS fixtures, explicit plaintext CLI, optional tshark decryption.

Ephemeral fixture certificate/key/keylog live only in a private temporary directory.
No sockets, real resolver queries, user certificates, or retained TLS secrets.
"""

import argparse
import collections
import ipaddress
import json
import ssl
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / 'target/debug/cythsec-analyze'


def run(args, expected=0):
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=30)
    assert p.returncode == expected, f'{args[0]} exit={p.returncode}, expected={expected}: {p.stderr[-1000:]}'
    if expected:
        assert not p.stdout, p.stdout
    return p.stdout


def dns(identifier, label, response=False, ipv6=False):
    question = bytes([len(label)]) + label.encode() + b'\x07example\x00' + struct.pack('!HH', 28 if ipv6 else 1, 1)
    body = struct.pack('!6H', identifier, 0x8180 if response else 0x0100, 1, int(response), 0, 0) + question
    if response:
        value = ipaddress.ip_address('2001:db8::42').packed if ipv6 else bytes([192, 0, 2, 42])
        body += b'\xc0\x0c' + struct.pack('!HHIH', 28 if ipv6 else 1, 1, 60, len(value)) + value
    return struct.pack('!H', len(body)) + body


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(data, side, seq, ack, flags=0x18, server_port=853):
    src, dst = (
        (bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2]))
        if side == 0
        else (bytes([198, 51, 100, 2]), bytes([192, 0, 2, 1]))
    )
    sport, dport = (40000, server_port) if side == 0 else (server_port, 40000)
    tcp = bytearray(struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + data)
    tcp[16:18] = struct.pack('!H', checksum(src + dst + struct.pack('!BBH', 0, 6, len(tcp)) + tcp))
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst))
    ip[10:12] = struct.pack('!H', checksum(ip))
    return bytes(12) + b'\x08\x00' + ip + tcp


def pcap(path, events, server_port=853):
    frames = [
        packet(b'', 0, 1000, 0, 2, server_port),
        packet(b'', 1, 2000, 1001, 0x12, server_port),
        packet(b'', 0, 1001, 2001, 0x10, server_port),
    ]
    seq = [1001, 2001]
    for side, data in events:
        frames.append(packet(data, side, seq[side], seq[1 - side], server_port=server_port))
        seq[side] += len(data)
    with path.open('wb') as f:
        f.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            f.write(struct.pack('<IIII', 1, i * 1000, len(frame), len(frame)) + frame)


def tls_fixture(directory, version, query, response, alpn='dot'):
    cert, key = directory / 'cert.pem', directory / 'key.pem'
    keylog = directory / ('tls-' + version.name + '.keys')
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE  # Local fixture only; output authentication remains unknown.
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    for context in (client_ctx, server_ctx):
        context.minimum_version = version
        context.maximum_version = version
        context.set_alpn_protocols([alpn])
    client_ctx.keylog_filename = str(keylog)
    ins = [ssl.MemoryBIO(), ssl.MemoryBIO()]
    outs = [ssl.MemoryBIO(), ssl.MemoryBIO()]
    peers = [
        client_ctx.wrap_bio(ins[0], outs[0], server_hostname='dns.example'),
        server_ctx.wrap_bio(ins[1], outs[1], server_side=True),
    ]
    events = []

    def transfer():
        for side in (0, 1):
            if outs[side].pending:
                data = outs[side].read()
                events.append((side, data))
                ins[1 - side].write(data)

    done = [False, False]
    for _ in range(32):
        for side in (0, 1):
            if not done[side]:
                try:
                    peers[side].do_handshake()
                    done[side] = True
                except ssl.SSLWantReadError:
                    pass
            transfer()
        if all(done):
            break
    assert all(done), 'local TLS handshake did not finish'
    recovered = []
    for side, application in [(0, query), (1, response)]:
        body = b''
        for part in (application[:1], application[1:]):
            assert peers[side].write(part) == len(part)
            transfer()
        for _ in range(32):
            try:
                body += peers[1 - side].read(len(application) - len(body))
            except ssl.SSLWantReadError:
                transfer()
            if len(body) == len(application):
                break
        assert body == application, 'TLS application recovery changed bytes'
        recovered.append(body)
    return events, recovered, keylog


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tshark', action='store_true')
    args = parser.parse_args()
    if not ssl.HAS_TLSv1_3 or not hasattr(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), 'keylog_filename'):
        print('B018 TLS reference unverified: pinned Python requires TLS1.3 and keylog support')
        return 3
    query = dns(0x1234, 'resolver') + dns(0x5678, 'alternate', ipv6=True)
    response = dns(0x1234, 'resolver', True) + dns(0x5678, 'alternate', True, True)
    with tempfile.TemporaryDirectory(prefix='cythsec-dot-') as tmp:
        directory = Path(tmp)
        run(
            [
                'openssl',
                'req',
                '-x509',
                '-newkey',
                'rsa:2048',
                '-nodes',
                '-days',
                '1',
                '-subj',
                '/CN=dns.example',
                '-keyout',
                directory / 'key.pem',
                '-out',
                directory / 'cert.pem',
            ]
        )

        def cli(path, direction='client', *extra):
            return [
                BIN,
                'dot-plaintext',
                '-r',
                path,
                '--source-id',
                'fixture-tls-endpoint',
                '--session-id',
                'fixture-session',
                '--direction',
                direction,
                *extra,
            ]

        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            events, recovered, keylog = tls_fixture(directory, version, query, response)
            capture = directory / (version.name + '.pcap')
            pcap(capture, events)
            for body, direction, expected_ips in [
                (recovered[0], 'client', [[], []]),
                (recovered[1], 'server', [['192.0.2.42'], ['2001:db8::42']]),
            ]:
                path = directory / 'application.bin'
                path.write_bytes(body)
                rows = [json.loads(line) for line in run(cli(path, direction)).splitlines()]
                assert [row['dns']['id'] for row in rows] == [0x1234, 0x5678]
                assert [row['dns']['answer_ips'] for row in rows] == expected_ips
                assert [row['dns']['qname'] for row in rows] == ['resolver.example', 'alternate.example']
                assert rows[1]['stream_offset'] == len(dns(0x1234, 'resolver', direction == 'server'))
                assert all(
                    row['app_id'] == 65563
                    and row['app'] == 'dot'
                    and row['tls_peer_authenticated'] is None
                    and row['source_id'] == 'fixture-tls-endpoint'
                    and row['session_id'] == 'fixture-session'
                    and row['record_type'] == 'tls_plaintext_dns_message'
                    for row in rows
                )
            native = [json.loads(line) for line in run([BIN, '-r', capture, '-q']).splitlines()]
            assert native and all(row['app']['app'] != 'dot' for row in native)
            if args.tshark:
                values = run(
                    [
                        'tshark',
                        '-r',
                        capture,
                        '-o',
                        'tls.keylog_file:' + str(keylog),
                        '-d',
                        'tcp.port==853,tls',
                        '-Y',
                        'dns',
                        '-T',
                        'fields',
                        '-e',
                        'dns.id',
                        '-e',
                        'dns.qry.name',
                        '-e',
                        'dns.a',
                        '-e',
                        'dns.aaaa',
                    ]
                )
                ids, names, addresses = [], [], []
                for line in values.splitlines():
                    columns = line.split('\t')
                    assert len(columns) == 4, columns
                    ids.extend(int(v, 0) for v in columns[0].split(',') if v)
                    names.extend(v for v in columns[1].split(',') if v)
                    addresses.extend(v for column in columns[2:] for v in column.split(',') if v)
                assert collections.Counter(ids) == collections.Counter([0x1234, 0x5678] * 2), ids
                assert collections.Counter(names) == collections.Counter(
                    ['resolver.example', 'alternate.example'] * 2
                ), names
                assert sorted(addresses) == ['192.0.2.42', '2001:db8::42'], addresses

        path = directory / 'bad.bin'
        bad_frames = [
            b'',
            b'\x00',
            b'\x00\x00',
            b'\x00\x0b',
            b'\x20\x01',
            query[:-1],
            struct.pack('!H', len(query[: len(dns(0x1234, 'resolver')) - 1]) - 2)
            + query[2 : len(dns(0x1234, 'resolver')) - 1]
            + query,
            query + b'\x00',
            dns(1, 'resolver') * 129,
            b'\x16\x03\x03\x00\x00',
            b'HTTP/1.1 200 OK\r\n\r\n',
        ]
        for body in bad_frames:
            path.write_bytes(body)
            run(cli(path), expected=1)
        path.write_bytes(response)
        run(cli(path), expected=1)
        path.write_bytes(query)
        run([BIN, 'dot-plaintext', '-r', path], expected=1)
        run(cli(path, 'client', '--source-id', 'duplicate'), expected=1)
        run(cli(path, 'client', '-o', path), expected=1)
        assert path.read_bytes() == query, 'input overwritten'
        output = directory / 'out.jsonl'
        output.write_text('existing')
        run(cli(path, 'client', '-o', output), expected=1)
        assert output.read_text() == 'existing'
    print(
        'B018 DoT: TLS1.2/1.3 MemoryBIO application bytes, 8 DNS message events, raw-PCAP non-promotion and 16 CLI failure cases passed; '
        + ('tshark decrypted DNS fields matched' if args.tshark else 'independent reference not requested')
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
