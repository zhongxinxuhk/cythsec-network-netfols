#!/usr/bin/env python3
"""Account for all parser outcomes without treating rejected packets as successful IP."""

import argparse
import re
import struct
import subprocess
import tempfile
from pathlib import Path

FIELDS = {
    'total': r'^总包数\s*:\s*([0-9]+)\s*$',
    'parsed': r'^解析成功\s*:\s*([0-9]+)\s*$',
    'malformed': r'^解析失败/畸形\s*:\s*([0-9]+)\s*$',
    'unsupported': r'^不支持L2\s*:\s*([0-9]+)\s*$',
    'truncated': r'^截断包\(cap<wire\)\s*:\s*([0-9]+)\s*$',
    'l3': r'^L3:\s+IPv4=([0-9]+)\s+IPv6=([0-9]+)\s+Other=([0-9]+)\s*$',
}
PATTERNS = {key: re.compile(pattern) for key, pattern in FIELDS.items()}


def validate(lines, expected):
    fields = {}
    for line in lines:
        for key, pattern in PATTERNS.items():
            match = pattern.fullmatch(line.strip())
            if match:
                if key in fields:
                    raise ValueError('duplicate parser summary field')
                fields[key] = tuple(int(value) for value in match.groups())
    if set(fields) != set(FIELDS):
        raise ValueError('missing or invalid parser summary field')
    values = {key: value[0] for key, value in fields.items() if key != 'l3'}
    if values['total'] != expected or sum(values[key] for key in ('parsed', 'malformed', 'unsupported')) != expected:
        raise ValueError('capture/readback outcome counts disagree')
    if sum(fields['l3']) != values['parsed'] or values['truncated'] > expected:
        raise ValueError('parser distribution counts disagree')
    return values


def self_test(parser):
    eth = bytes.fromhex('00112233445566778899aabb0800')
    # One valid UDP frame, one unsupported LLC frame, one non-initial IPv4
    # fragment with one payload byte. The fragment is not a complete L4 header.
    udp = eth + bytes.fromhex('4500001c0001000040110000c0000201c6336402') + struct.pack('!HHHH', 10000, 443, 8, 0)
    llc = bytes.fromhex('0180c20000000011223344550026') + b'\x42\x42\x03' + bytes(35)
    fragment = eth + bytes.fromhex('450000150001000140110000c0000201c6336402') + b'x'
    with tempfile.TemporaryDirectory(prefix='cythsec-readback-') as directory:
        pcap = Path(directory) / 'synthetic.pcap'
        with pcap.open('wb') as out:
            out.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for frame in (udp, llc, fragment):
                out.write(struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame)
        result = subprocess.run([parser, '-r', pcap], text=True, capture_output=True, check=True)
        baseline = validate(result.stdout.splitlines(), 3)
        assert baseline == {'total': 3, 'parsed': 1, 'malformed': 1, 'unsupported': 1, 'truncated': 0}, baseline
        mutations = {
            'malformed': '解析失败/畸形 : 0',
            'unsupported': '不支持L2 : 2',
            'total': '总包数 : 2',
            'l3': 'L3: IPv4=0 IPv6=0 Other=0',
            'parsed': '',
        }
        for key, replacement in mutations.items():
            bad, count = re.subn(FIELDS[key], replacement, result.stdout, flags=re.MULTILINE)
            assert count == 1 and bad != result.stdout, 'fault injection did not modify summary'
            try:
                validate(bad.splitlines(), 3)
            except ValueError:
                continue
            raise AssertionError('readback count injection escaped detection')
    print(
        'readback self-test: real C++ parser accounts 3 frames (1 parsed/1 unsupported/1 rejected); 5 count/missing-field injections rejected'
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--summary', type=Path)
    ap.add_argument('--expected', type=int)
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--parser')
    args = ap.parse_args()
    if args.self_test:
        if not args.parser:
            ap.error('--self-test requires --parser')
        self_test(args.parser)
    else:
        if args.summary is None or args.expected is None or args.expected < 0:
            ap.error('--summary and nonnegative --expected are required')
        with args.summary.open(encoding='utf-8') as source:
            values = validate(source, args.expected)
        print('readback counts: ' + ' '.join(f'{key}={value}' for key, value in values.items()))


if __name__ == '__main__':
    main()
