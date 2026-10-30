#!/usr/bin/env python3
"""B017 offline mDNS CLI/reference checks. Advertisements are not verified assets."""

import argparse
import ipaddress
import json
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / 'target/debug/cythsec-analyze'


def run(args):
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f'{args[0]} exit={p.returncode}: {p.stderr[-1000:]}'
    return p.stdout


def name(text):
    result = b''
    for label in text.split('.'):
        raw = label.encode('utf-8')
        result += bytes([len(raw)]) + raw
    return result + b'\x00'


def header(flags=0, q=1, a=0, ns=0, ar=0, identifier=0):
    return struct.pack('!6H', identifier, flags, q, a, ns, ar)


def question(text='Host.local', kind=1, cls=1):
    return name(text) + struct.pack('!HH', kind, cls)


def record(owner, kind=1, cls=0x8001, ttl=120, value=b'\xc0\x00\x02\x09'):
    return owner + struct.pack('!HHIH', kind, cls, ttl, len(value)) + value


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(
    payload, ipv6=False, sport=5353, dport=5353, proto=17, udp_size=None, ip_size=None, fragment=None, extension=False
):
    legacy = dport != 5353
    src = ipaddress.ip_address('fe80::1' if ipv6 else '192.0.2.1').packed
    dst = ipaddress.ip_address(
        ('fe80::2' if legacy else 'ff02::fb') if ipv6 else ('192.0.2.2' if legacy else '224.0.0.251')
    ).packed
    if proto == 17:
        data = bytearray(
            struct.pack('!HHHH', sport, dport, len(payload) + 8 if udp_size is None else udp_size, 0) + payload
        )
        pseudo = (
            src + dst + (struct.pack('!I3xB', len(data), proto) if ipv6 else struct.pack('!BBH', 0, proto, len(data)))
        )
        data[6:8] = struct.pack('!H', checksum(pseudo + data) or 65535)
        data = bytes(data)
    else:
        data = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 0x50, 0x18, 65535, 0, 0) + payload
    size = len(data) if ip_size is None else ip_size
    if ipv6:
        if fragment is not None:
            data = struct.pack('!BBHI', proto, 0, fragment, 1) + data
            size += 8
            proto = 44
        if extension:
            data = bytes([proto, 0]) + bytes(6) + data
            size += 8
            proto = 60
        ip = struct.pack('!IHBB', 6 << 28, size, proto, 255) + src + dst
    else:
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, size + 20, 1, fragment or 0, 255, proto, 0, src, dst))
        ip[10:12] = struct.pack('!H', checksum(bytes(ip)))
    destination = (
        bytes.fromhex('3333000000fb' if ipv6 else '01005e0000fb') if not legacy else bytes.fromhex('020000000002')
    )
    return destination + bytes.fromhex('020000000001') + (b'\x86\xdd' if ipv6 else b'\x08\x00') + ip + data


def pcap(path, packet):
    path.write_bytes(
        struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack('<IIII', 1, 0, len(packet), len(packet))
        + packet
    )


def rows(path, *args):
    return [json.loads(line) for line in run([BIN, '-r', path, '-q', *args]).splitlines()]


def fields(path, names):
    args = ['tshark', '-r', path, '-T', 'fields']
    for field in names:
        args.extend(['-e', field])
    values = run(args).rstrip('\n').split('\t')
    assert len(values) == len(names), (names, values)
    return [
        (
            {'True': '1', 'False': '0'}.get(value, value)
            if field in {'dns.qry.qu', 'dns.resp.cache_flush', 'dns.flags.truncated'}
            else value
        )
        for field, value in zip(names, values)
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tshark', action='store_true')
    args = parser.parse_args()
    owner = name('Printer.local')
    query = header() + question(cls=0x8001)
    multi = header(q=2) + question() + b'\xc0\x0c' + struct.pack('!HH', 28, 1)
    answer = header(0x8400, q=0, a=1) + record(owner)
    srv = struct.pack('!HHH', 1, 2, 631) + name('Printer.local')
    instance = 'Office Printer._ipp._tcp.local'
    services = header(0x8400, q=0, a=1, ar=2) + record(name('_ipp._tcp.local'), 12, 1, 4500, name(instance))
    services += record(name(instance), 33, value=srv) + record(name(instance), 16, value=b'\x03a=b')
    cases = [
        (query, ['dns.qry.name', 'dns.qry.qu', 'dns.qry.class'], ['Host.local', '1', '0x0001']),
        (multi, ['dns.qry.name', 'dns.qry.type'], ['Host.local,Host.local', '1,28']),
        (answer, ['dns.a', 'dns.resp.cache_flush', 'dns.resp.class'], ['192.0.2.9', '1', '0x0001']),
        (
            header(0x8400, q=0, a=1) + record(owner, 28, value=ipaddress.ip_address('2001:db8::9').packed),
            ['dns.aaaa'],
            ['2001:db8::9'],
        ),
        (
            services,
            ['dns.ptr.domain_name', 'dns.srv.target', 'dns.srv.port', 'dns.txt'],
            [instance, 'Printer.local', '631', 'a=b'],
        ),
        (
            header(q=1, a=1) + question() + record(b'\xc0\x0c', cls=1),
            ['dns.count.queries', 'dns.count.answers'],
            ['1', '1'],
        ),
        (header(q=1, ns=1) + question(kind=255) + record(b'\xc0\x0c', cls=1), ['dns.count.auth_rr'], ['1']),
        (header(0x0200, q=0, a=1) + record(owner, cls=1), ['dns.flags.truncated'], ['1']),
        (header(0x8400, q=0, a=1) + record(owner, ttl=0), ['dns.resp.ttl'], ['0']),
        (header() + question('打印机.local', 255), ['dns.qry.name'], ['打印机.local']),
        (
            header(0x8400, q=1, a=1, identifier=0x1234) + question() + record(b'\xc0\x0c'),
            ['dns.id', 'dns.a'],
            ['0x1234', '192.0.2.9'],
        ),
        (header(identifier=0x1234) + question(), ['dns.id'], ['0x1234']),
    ]
    positive = 0
    negative = 0
    with tempfile.TemporaryDirectory(prefix='cythsec-mdns-') as tmp:
        path = Path(tmp) / 'mdns.pcap'
        for ipv6 in (False, True):
            for index, (body, names, expected) in enumerate(cases):
                sport, dport = (5353, 40000) if index == 10 else (40000, 5353) if index == 11 else (5353, 5353)
                pcap(path, frame(body, ipv6, sport, dport))
                actual = rows(path)
                assert len(actual) == 1 and actual[0]['app']['app'] == 'mdns', actual
                assert actual[0]['app']['app_id'] == 65562 and actual[0]['app']['confidence'] == 'medium'
                assert rows(path, '--workers', '2') == actual
                if args.tshark:
                    observed = fields(path, names)
                    assert observed == expected, (index, observed, expected)
                positive += 1
        pcap(path, frame(answer, True, extension=True))
        assert rows(path)[0]['app']['app'] == 'mdns'
        positive += 1
        negatives = [frame(query[:n]) for n in range(len(query))]
        negatives += [
            frame(query, dport=53),
            frame(query, sport=40000, dport=40001),
            frame(query, proto=6),
            frame(bytes(12)),
            frame(b'Host.local'),
        ]
        negatives += [
            frame(header(0x0800) + question()),
            frame(header(1) + question()),
            frame(header() + b'\xc0\x0c\x00\x01\x00\x01'),
        ]
        negatives += [
            frame(header(0x8400, q=0, a=1) + record(owner, value=b'abc')),
            frame(header(0x8400, q=0, a=1) + record(owner, 16, value=b'\x04ab')),
            frame(header(0x8400, q=0, a=2) + record(owner, 12, value=b'\x03a') + record(owner)),
            frame(answer[:-1]),
        ]
        negatives += [
            frame(query, udp_size=7),
            frame(query, udp_size=8),
            frame(query, udp_size=300),
            frame(query, ip_size=300),
            frame(query, fragment=0x2000),
        ]
        negatives += [frame(query, True, fragment=1), frame(query, True, fragment=8), frame(query, True, ip_size=300)]
        for packet in negatives:
            pcap(path, packet)
            actual = rows(path)
            assert all(row['app']['app'] != 'mdns' for row in actual), actual
            negative += 1
        pcap(path, frame(query + b'\x00'))
        assert rows(path, '--inspect-bytes', str(len(query)))[0]['app']['outcome'] == 'need_more'
    print(
        f'B017 mDNS: {positive} positive / {negative} negative CLI cases and inspection budget passed; '
        + ('tshark QU/cache-flush/records/UTF-8 matched' if args.tshark else 'independent reference not requested')
    )


if __name__ == '__main__':
    main()
