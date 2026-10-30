#!/usr/bin/env python3
"""B015 offline DHCPv4 CLI and independent field checks. No packets are sent."""

import argparse
import json
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / 'target/debug/cythsec-analyze'


def run(args):
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f'{args[0]} exit={p.returncode}: {p.stderr[-1000:]}'
    return p.stdout


def message(kind=1, options=b''):
    p = bytearray(236)
    p[:3] = bytes([2 if kind in (2, 5, 6) else 1, 1, 6])
    p[4:8] = struct.pack('!I', 0x12345678)
    p[28:34] = bytes.fromhex('020000000001')
    return p + bytes.fromhex('63825363') + bytes([53, 1, kind]) + options + b'\xff'


def frame(payload, sport=68, dport=67, proto=17, udp_size=None, ip_size=None, fragment=0):
    if proto == 17:
        segment = struct.pack('!HHHH', sport, dport, len(payload) + 8 if udp_size is None else udp_size, 0) + payload
    else:
        segment = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 0x50, 0x18, 65535, 0, 0) + payload
    header = bytearray(
        struct.pack(
            '!BBHHHBBH4s4s',
            0x45,
            0,
            20 + (len(segment) if ip_size is None else ip_size),
            1,
            fragment,
            64,
            proto,
            0,
            b'\xc0\x00\x02\x01',
            b'\xff\xff\xff\xff',
        )
    )
    checksum = sum(struct.unpack('!10H', header))
    checksum = (checksum & 65535) + (checksum >> 16)
    checksum = (checksum & 65535) + (checksum >> 16)
    header[10:12] = struct.pack('!H', (~checksum) & 65535)
    return bytes(12) + b'\x08\x00' + header + segment


def pcap(path, packet):
    path.write_bytes(
        struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack('<IIII', 1, 0, len(packet), len(packet))
        + packet
    )


def rows(path, *args):
    return [json.loads(line) for line in run([BIN, '-r', path, '-q', *args]).splitlines()]


def overload_hostname(pdml):
    """Read reference TLVs in RFC 3396 order, independent of tree display order."""
    protocol = ET.fromstring(pdml).find(".//proto[@name='dhcp']")
    assert protocol is not None, 'missing DHCP reference protocol'
    base = int(protocol.attrib['pos'])
    fragments = []
    for field in protocol.iter('field'):
        if field.get('name') != 'dhcp.option.type' or field.get('show') != '12':
            continue
        value = bytes.fromhex(field.attrib['value'])
        assert value[0] == 12 and value[1] == len(value) - 2, value
        offset = int(field.attrib['pos']) - base
        if offset >= 240:
            zone = 0  # options, then overloaded file, then overloaded sname
        elif 108 <= offset < 236:
            zone = 1
        else:
            assert 44 <= offset < 108, offset
            zone = 2
        fragments.append((zone, offset, value[2:]))
    assert len(fragments) == 3, fragments
    ordered = [value.decode('ascii') for _, _, value in sorted(fragments)]
    hostname = ''.join(ordered)
    # Older tshark emits separate occurrences in display-tree order; newer
    # versions expose a single reassembled field. Check either representation
    # against the same positioned TLVs, rather than accepting a different value.
    shown = [field.attrib['show'] for field in protocol.iter('field') if field.get('name') == 'dhcp.option.hostname']
    assert shown == [hostname] or sorted(shown) == sorted(ordered), (shown, ordered)
    return hostname


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tshark', action='store_true')
    args = parser.parse_args()
    options = bytes([50, 4, 192, 0, 2, 9, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 0x0E, 0x10, 12, 4]) + b'host'
    positive = 0
    negative = 0
    with tempfile.TemporaryDirectory(prefix='cythsec-dhcpv4-') as tmp:
        path = Path(tmp) / 'dhcp.pcap'
        for kind in range(1, 9):
            p = message(kind, options)
            sport, dport = (67, 68) if kind in (2, 5, 6) else (68, 67)
            pcap(path, frame(p, sport, dport))
            actual = rows(path)
            assert len(actual) == 1 and actual[0]['app']['app'] == 'dhcpv4', actual
            assert actual[0]['app']['confidence'] == 'high', actual
            assert rows(path, '--workers', '2') == actual
            if args.tshark:
                fields = [
                    'dhcp.id',
                    'dhcp.option.dhcp',
                    'dhcp.option.requested_ip_address',
                    'dhcp.option.dhcp_server_id',
                    'dhcp.option.ip_address_lease_time',
                    'dhcp.option.hostname',
                ]
                query = ['tshark', '-r', path, '-T', 'fields']
                for field in fields:
                    query.extend(['-e', field])
                values = run(query).strip().split('\t')
                assert int(values[0], 0) == 0x12345678 and values[1:] == [
                    str(kind),
                    '192.0.2.9',
                    '192.0.2.1',
                    '3600',
                    'host',
                ], values
            positive += 1
        for sport, dport in [(67, 67), (40000, 40001)]:
            pcap(path, frame(message(3), sport, dport))
            assert rows(path)[0]['app']['app'] == 'dhcpv4'
            positive += 1
        overloaded = message(5, bytes([52, 1, 3, 12, 1, ord('a')]))
        overloaded[108:112] = bytes([12, 1, ord('b'), 255])
        overloaded[44:48] = bytes([12, 1, ord('c'), 255])
        pcap(path, frame(overloaded, 67, 68))
        assert rows(path)[0]['app']['app'] == 'dhcpv4'
        if args.tshark:
            names = overload_hostname(run(['tshark', '-r', path, '-T', 'pdml']))
            assert names == 'abc', names
        positive += 1
        base = message()
        cases = [frame(base[:n]) for n in (1, 3, 235, 236, 237, 239, 240, 241, 242, 243)]
        no_cookie = bytearray(base)
        no_cookie[236] = 0
        wrong_op = bytearray(base)
        wrong_op[0] = 2
        wrong_hlen = bytearray(base)
        wrong_hlen[2] = 17
        cases += [frame(no_cookie), frame(wrong_op), frame(wrong_hlen), frame(base[:240] + b'\xff')]
        cases += [frame(message(9)), frame(message(1, bytes([53, 1, 1]))), frame(message(1, bytes([54, 3, 1, 2, 3])))]
        cases += [frame(base, proto=6), frame(base, udp_size=8), frame(base, udp_size=7)]
        cases += [
            frame(base, udp_size=300),
            frame(base, ip_size=300),
            frame(base, fragment=0x2000),
            frame(base, fragment=1),
        ]
        bad_overload = message(5, bytes([52, 1, 1]))
        bad_overload[108:110] = bytes([54, 127])
        cases += [frame(bad_overload, 67, 68)]
        for packet in cases:
            pcap(path, packet)
            actual = rows(path)
            assert all(row['app']['app'] != 'dhcpv4' for row in actual), actual
            negative += 1
        pcap(path, frame(message()))
        assert rows(path, '--inspect-bytes', '242')[0]['app']['outcome'] == 'need_more'
    print(
        f'B015 DHCPv4: {positive} positive / {negative} negative CLI cases and inspection budget passed; '
        + ('tshark fields/overload matched' if args.tshark else 'independent reference not requested')
    )


if __name__ == '__main__':
    main()
