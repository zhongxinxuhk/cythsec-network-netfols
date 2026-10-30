#!/usr/bin/env python3
"""B016 offline IPv6/UDP/CLI reference checks. Synthetic data is not lease evidence."""

import argparse
import ipaddress
import json
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / 'target/debug/cythsec-analyze'
CLIENT = bytes.fromhex('00030001020000000001')
SERVER = bytes.fromhex('0004000102030405060708090a0b0c0d0e0f')


def run(args):
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f'{args[0]} exit={p.returncode}: {p.stderr[-1000:]}'
    return p.stdout


def option(code, value):
    return struct.pack('!HH', code, len(value)) + value


def message(kind=1):
    data = bytes([kind, 0x12, 0x34, 0x56])
    if kind != 11:
        data += option(1, CLIENT)
    if kind in (2, 3, 5, 7, 8, 9, 10):
        data += option(2, SERVER)
    if kind == 10:
        data += option(19, b'\x05')
    if kind == 11:
        data += option(6, bytes.fromhex('00170018'))
    return data


def relay(kind, inner, hop=0):
    return (
        bytes([kind, hop])
        + ipaddress.ip_address('2001:db8::1').packed
        + ipaddress.ip_address('fe80::2').packed
        + option(18, b'link')
        + option(9, inner)
    )


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def frame(payload, sport=546, dport=547, proto=17, udp_size=None, ip_size=None, fragment=None, extension=False):
    src = ipaddress.ip_address('2001:db8::1' if sport == 547 else 'fe80::10').packed
    dst = ipaddress.ip_address('fe80::10' if dport == 546 else '2001:db8::2' if sport == 547 else 'ff02::1:2').packed
    if proto == 17:
        segment = bytearray(
            struct.pack('!HHHH', sport, dport, len(payload) + 8 if udp_size is None else udp_size, 0) + payload
        )
        pseudo = src + dst + struct.pack('!I3xB', len(segment), proto)
        segment[6:8] = struct.pack('!H', checksum(pseudo + segment) or 65535)
        segment = bytes(segment)
    else:
        segment = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 0x50, 0x18, 65535, 0, 0) + payload
    size = len(segment) if ip_size is None else ip_size
    if fragment is not None:
        segment = struct.pack('!BBHI', proto, 0, fragment, 1) + segment
        size += 8
        proto = 44
    if extension:
        segment = bytes([proto, 0]) + bytes(6) + segment
        size += 8
        proto = 60
    return bytes(12) + b'\x86\xdd' + struct.pack('!IHBB', 6 << 28, size, proto, 64) + src + dst + segment


def pcap(path, packet):
    path.write_bytes(
        struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack('<IIII', 1, 0, len(packet), len(packet))
        + packet
    )


def rows(path, *args):
    return [json.loads(line) for line in run([BIN, '-r', path, '-q', *args]).splitlines()]


def fields(path, *names):
    args = ['tshark', '-r', path, '-T', 'fields']
    for name in names:
        args.extend(['-e', name])
    return run(args).strip().split('\t')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tshark', action='store_true')
    args = parser.parse_args()
    positive = 0
    negative = 0
    with tempfile.TemporaryDirectory(prefix='cythsec-dhcpv6-') as tmp:
        path = Path(tmp) / 'dhcpv6.pcap'
        for kind in range(1, 12):
            p = message(kind)
            sport, dport = (547, 546) if kind in (2, 7, 10) else (546, 547)
            pcap(path, frame(p, sport, dport))
            actual = rows(path)
            assert len(actual) == 1 and actual[0]['app']['app'] == 'dhcpv6', actual
            assert actual[0]['app']['app_id'] == 65561 and actual[0]['app']['confidence'] == 'high'
            assert rows(path, '--workers', '2') == actual
            if args.tshark:
                values = fields(path, 'dhcpv6.msgtype', 'dhcpv6.xid')
                assert values[0] == str(kind) and int(values[1], 0) == 0x123456, values
                if kind != 11:
                    duids = fields(path, 'dhcpv6.duid.bytes')[0].replace(':', '').split(',')
                    expected = [CLIENT.hex()] + ([SERVER.hex()] if kind in (2, 3, 5, 7, 8, 9, 10) else [])
                    assert duids == expected, duids
            positive += 1
        for kind, inner in [
            (12, message(1)),
            (13, message(7)),
            (12, relay(12, message(1))),
            (13, relay(13, message(7))),
        ]:
            pcap(path, frame(relay(kind, inner), 547, 547))
            assert rows(path)[0]['app']['app'] == 'dhcpv6'
            if args.tshark:
                values = fields(path, 'dhcpv6.msgtype', 'dhcpv6.linkaddr', 'dhcpv6.peeraddr', 'dhcpv6.xid')
                assert values[0].split(',')[0] == str(kind) and values[1].split(',')[0] == '2001:db8::1'
                assert values[2].split(',')[0] == 'fe80::2' and int(values[3], 0) == 0x123456, values
            positive += 1
        addr = ipaddress.ip_address('2001:db8::99').packed + struct.pack('!II', 300, 600)
        prefix = struct.pack('!IIB', 300, 600, 64) + ipaddress.ip_address('2001:db8:100::').packed
        ia = struct.pack('!III', 0x01020304, 60, 120) + option(5, addr)
        pd = struct.pack('!III', 0x05060708, 60, 120) + option(26, prefix)
        pcap(path, frame(message(7) + option(3, ia) + option(25, pd), 547, 546))
        assert rows(path)[0]['app']['app'] == 'dhcpv6'
        if args.tshark:
            values = fields(
                path,
                'dhcpv6.iaaddr.ip',
                'dhcpv6.iaaddr.pref_lifetime',
                'dhcpv6.iaaddr.valid_lifetime',
                'dhcpv6.iaprefix.pref_addr',
                'dhcpv6.iaprefix.pref_len',
                'dhcpv6.iaid.t1',
                'dhcpv6.iaid.t2',
            )
            assert values == ['2001:db8::99', '300', '600', '2001:db8:100::', '64', '60,60', '120,120'], values
        positive += 1
        for packet in [
            frame(message(), 40000, 40001),
            frame(message(), extension=True),
            frame(message(), fragment=0),
            frame(bytes([1, 0, 0, 0]) + option(1, bytes.fromhex('fedc01'))),
        ]:
            pcap(path, packet)
            assert rows(path)[0]['app']['app'] == 'dhcpv6'
            positive += 1
        base = message()
        cases = [frame(base[:n]) for n in range(len(base))]
        cases += [frame(bytes([99, 0, 0, 0])), frame(bytes([11, 0, 0, 0])), frame(bytes(64))]
        cases += [
            frame(base + option(1, CLIENT)),
            frame(bytes([1, 0, 0, 0]) + option(1, b'\x00\x01')),
            frame(base + option(6, b'\x00')),
            frame(base + option(2, SERVER)),
            frame(base + bytes.fromhex('ffff0080')),
        ]
        cases += [frame(relay(12, base, hop=9), 547, 547), frame(relay(12, b'\x01\x02\x03'), 547, 547)]
        cases += [
            frame(base, proto=6),
            frame(base, fragment=1),
            frame(base, fragment=8),
            frame(base, ip_size=300),
            frame(base, udp_size=8),
            frame(base, udp_size=7),
            frame(base, udp_size=300),
            frame(base, udp_size=8 + len(base) - 1),
        ]
        cases += [frame(message(7) + option(3, ia[:-1]) + option(65000, bytes(24)), 547, 546)]
        for packet in cases:
            pcap(path, packet)
            actual = rows(path)
            assert all(row['app']['app'] != 'dhcpv6' for row in actual), actual
            negative += 1
        pcap(path, frame(base + option(65000, b'future')))
        assert rows(path, '--inspect-bytes', str(len(base)))[0]['app']['outcome'] == 'need_more'
    print(
        f'B016 DHCPv6: {positive} positive / {negative} negative CLI cases and inspection budget passed; '
        + ('tshark fields/relays/IA matched' if args.tshark else 'independent reference not requested')
    )


if __name__ == '__main__':
    main()
