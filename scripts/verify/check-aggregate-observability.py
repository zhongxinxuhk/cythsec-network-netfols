#!/usr/bin/env python3
"""Independent synthetic pcap -> aggregate CLI -> optional tshark quality reference."""

import argparse
import json
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / 'target/debug/cythsec-observe'


def packet(flow, proto, payload=b'', seq=0, ack=0, flags=0, reverse=False):
    src, dst = bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2])
    sport, dport = 10000 + flow, 443
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    if proto == 6:
        header = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    else:
        header = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    body = header + payload
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 1, 0, 64, proto, 0, src, dst))
    total = sum(struct.unpack('!10H', ip))
    total = (total & 65535) + (total >> 16)
    total = (total & 65535) + (total >> 16)
    ip[10:12] = struct.pack('!H', (~total) & 65535)
    return bytes(12) + b'\x08\x00' + ip + body


def write_pcap(path, frames):
    with path.open('wb') as out:
        out.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in sorted(frames):
            out.write(struct.pack('<IIII', ts // 1000000, ts % 1000000, len(data), len(data)) + data)


def run(args, expected=0):
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True)
    if result.returncode != expected:
        raise AssertionError(f'{args[0]} exit={result.returncode}, expected={expected}: {result.stderr[-800:]}')
    return result.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tshark', action='store_true')
    args = ap.parse_args()
    frames = []
    late_frames = []
    for flow in range(20):
        t = 1000000 + flow * 100000
        sequence = [
            (0, b'', 100, 0, 2, False),
            (4000, b'', 500, 101, 0x12, True),
            (8000, b'', 101, 501, 0x10, False),
            (10000, b'A' * 10, 101, 501, 0x18, False),
            (15000, b'A' * 10, 101, 501, 0x18, False),
            (20000, b'', 501, 111, 0x10, True),
            (25000, b'B' * 10, 131, 501, 0x18, False),
            (26000, b'', 501, 111, 0x10, True),
            # Keep the late segment within Wireshark's documented 3ms/iRTT
            # out-of-order threshold, rather than relying on version heuristics.
            (27000, b'C' * 10, 111, 501, 0x18, False),
        ]
        for delta, payload, seq, ack, flags, reverse in sequence:
            value = packet(flow, 6, payload, seq, ack, flags, reverse)
            frames.append((t + delta, value))
            # Retain the original >iRTT late-arrival case as an application
            # regression without claiming cross-version tshark label equality.
            late_frames.append((t + (35000 if delta == 27000 else delta), value))
        private = b'private.example user-marker-123'
        tls = bytes([23, 3, 3, 0, len(private)]) + private
        frames.append((t + 40000, packet(100 + flow, 6, tls, 1, 0, 0x18)))
        quic = bytes([0xC0, 0, 0, 0, 1, 0, 0, 0, 17]) + bytes(17)
        frames.append((t + 45000, packet(200 + flow, 17, quic)))
    with tempfile.TemporaryDirectory(prefix='cythsec-aggregate-') as tmp:
        tmp = Path(tmp)
        capture = tmp / 'aggregate.pcap'
        write_pcap(capture, frames)
        original = tmp / 'late-arrival.pcap'
        write_pcap(original, late_frames)
        original_quality = json.loads(run([BIN, '-r', original]).splitlines()[0])['statistics']['tcp_quality']
        assert original_quality['retransmission_candidates'] == 20
        assert original_quality['out_of_order_candidates'] == 20
        raw = run([BIN, '-r', capture])
        rows = [json.loads(line) for line in raw.splitlines()]
        assert len(rows) == 2 and rows[-1]['type'] == 'capture_status'
        status = rows[-1]
        assert status['input_complete'] and status['analysis_complete']
        assert status['capture_loss_status'] == 'unknown'
        stats = rows[0]['statistics']
        assert stats['contributing_sampled_flows'] == 60
        assert stats['tcp_packets'] == 200 and stats['udp_packets'] == 20
        assert stats['tls_record_candidate_packets'] == 20 and stats['quic_long_header_candidate_packets'] == 20
        quality = stats['tcp_quality']
        assert quality['retransmission_candidates'] == 20 and quality['out_of_order_candidates'] == 20
        assert quality['response_delay_samples'] == 20 and quality['response_delay_histogram'][1] == 20
        assert stats['integrity']['records'] == len(frames)
        for forbidden in [
            '192.0.2.1',
            '198.51.100.2',
            'private.example',
            'user-marker-123',
            'src_ip',
            'dst_ip',
            'src_port',
            'sni',
            'ja3',
            'flow_id',
            'vpn',
            'payload',
        ]:
            assert forbidden not in raw, forbidden
        counters = ['--source-eligible', len(frames) + 3, '--source-delivered', len(frames), '--source-dropped', 3]
        rows = [json.loads(line) for line in run([BIN, '-r', capture, *counters]).splitlines()]
        assert rows[-1]['source_counter_consistent'] and rows[-1]['capture_loss_status'] == 'declared_nonzero'
        run([BIN, '-r', capture, '--source-eligible', 10], 2)
        mismatch = [
            json.loads(line)
            for line in run(
                [BIN, '-r', capture, '--source-eligible', 1, '--source-delivered', 1, '--source-dropped', 0], 2
            ).splitlines()
        ]
        assert mismatch[-1]['source_counter_consistent'] is False
        bad = tmp / 'bad.pcap'
        bad.write_bytes(capture.read_bytes()[:-2])
        rows = [json.loads(line) for line in run([BIN, '-r', bad], 2).splitlines()]
        assert rows[-1]['input_complete'] is False and rows[-1]['analysis_complete'] is False
        run([BIN, '-r', capture, '-o', capture], 2)
        run([BIN, '-r', capture, '--minimum-flows', 1], 2)
        limited = [json.loads(line) for line in run([BIN, '-r', capture, '--max-flows', 20], 2).splitlines()]
        assert limited[-1]['analysis_complete'] is False
        small = tmp / 'small.pcap'
        write_pcap(small, frames[:1])
        rows = [json.loads(line) for line in run([BIN, '-r', small]).splitlines()]
        assert rows[0]['suppressed'] and rows[0]['statistics'] is None
        print(
            'aggregate CLI: 60 synthetic flows, exact counts/quality, cohort suppression, no identifiers, malformed/counter/capacity failures passed'
        )
        if args.tshark:
            fields = run(
                [
                    'tshark',
                    '-r',
                    capture,
                    '-o',
                    'tcp.relative_sequence_numbers:FALSE',
                    '-T',
                    'fields',
                    '-e',
                    'tcp.analysis.retransmission',
                    '-e',
                    'tcp.analysis.out_of_order',
                    '-e',
                    'tcp.flags.syn',
                    '-e',
                    'tcp.flags.ack',
                    '-e',
                    'tcp.analysis.ack_rtt',
                ]
            )
            cells = [line.split('\t') for line in fields.splitlines()]
            retrans = sum(bool(row[0]) for row in cells)
            ooo = sum(len(row) > 1 and bool(row[1]) for row in cells)
            samples = [
                float(row[4])
                for row in cells
                if len(row) > 4 and row[2].lower() in ('1', 'true') and row[3].lower() in ('1', 'true') and row[4]
            ]
            assert retrans == quality['retransmission_candidates'], (retrans, quality)
            assert ooo == quality['out_of_order_candidates'], (ooo, quality)
            assert len(samples) == 20 and all(abs(v - 0.004) < 0.000001 for v in samples), samples
            print('tshark reference: 20 retransmissions, 20 out-of-order events, 20 SYN/SYN-ACK deltas of 4ms agree')


if __name__ == '__main__':
    main()
