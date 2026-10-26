#!/usr/bin/env python3
"""Real Rust output -> Go HTTP -> disk -> restart -> bounded query verification."""

import importlib.util
import json
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    spec = importlib.util.spec_from_file_location('vectors', ROOT / 'scripts/verify/check-aggregate-observability.py')
    vectors = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vectors)
    with tempfile.TemporaryDirectory(prefix='cythsec-storage-') as tmp:
        tmp = Path(tmp)
        capture = tmp / 'synthetic.pcap'
        vectors.write_pcap(
            capture, [(ts + n, vectors.packet(n, 17, b'x')) for ts in (1000000, 61000000) for n in range(20)]
        )
        raw = subprocess.check_output([ROOT / 'target/debug/cythsec-observe', '-r', capture])
        rows = [json.loads(line) for line in raw.splitlines()]
        assert len(rows) == 3 and all(row['statistics']['udp_packets'] == 20 for row in rows[:-1])
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        archive = tmp / 'archive'
        proc = None
        log = (tmp / 'server.log').open('wb')

        def stop():
            nonlocal proc
            if proc is not None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    raise AssertionError('telemetryd failed to stop') from None
                assert proc.returncode == 0, 'telemetryd shutdown failed'
                proc = None

        def start():
            nonlocal proc
            proc = subprocess.Popen(
                [
                    ROOT / 'build/aggregate-storage/telemetryd',
                    '-addr',
                    f'127.0.0.1:{port}',
                    '-config',
                    tmp / 'absent.yaml',
                    '-aggregate-dir',
                    archive,
                ],
                cwd=ROOT,
                stdout=log,
                stderr=log,
            )
            for _ in range(100):
                if proc.poll() is not None:
                    raise AssertionError('telemetryd failed to start')
                try:
                    with urllib.request.urlopen(base + '/healthz', timeout=1) as response:
                        if response.status == 200:
                            return
                except (urllib.error.URLError, TimeoutError):
                    time.sleep(0.05)
            raise AssertionError('telemetryd readiness timed out')

        def call(path='', body=None, expected=200):
            req = urllib.request.Request(
                base + '/api/v1/analytics/imports' + path, data=body, headers={'Content-Type': 'application/x-ndjson'}
            )
            try:
                response = urllib.request.urlopen(req, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = json.load(response)
                assert response.status == expected, (response.status, expected, data)
                return data

        try:
            start()
            created = call(body=raw, expected=201)['data']
            assert created['durable'] and not created['duplicate']
            batch_id = created['import']['id']
            assert call(body=raw)['data']['duplicate']
            first = call('/' + batch_id + '?from=0&to=60&limit=1')['data']
            assert first['total'] == 1 and first['items'][0]['statistics']['udp_packets'] == 20
            assert first['import']['status']['capture_loss_status'] == 'unknown'
            assert call('/' + batch_id + '?from=60&to=120')['data']['items'][0]['window_start_seconds'] == 60
            assert call('/' + batch_id + '?offset=2')['data']['items'] == []
            call('/' + batch_id + '?limit=101', expected=400)
            call(body=b'\n'.join(raw.splitlines()[:-1]), expected=400)
            invalid = json.loads(raw.splitlines()[0])
            invalid['statistics']['src_ip'] = 'sensitive-marker'
            rejected = call(body=json.dumps(invalid).encode() + b'\n' + b'\n'.join(raw.splitlines()[1:]), expected=400)
            assert 'sensitive-marker' not in json.dumps(rejected)
            partial = [json.loads(line) for line in raw.splitlines()]
            partial[-1]['analysis_complete'] = False
            stored_partial = call(body=('\n'.join(json.dumps(v) for v in partial)).encode(), expected=201)['data']
            assert not stored_partial['import']['status']['analysis_complete']
            assert len(list(archive.glob('*.jsonl'))) == 2
            assert (archive / (batch_id + '.jsonl')).stat().st_mode & 0o777 == 0o600
            stop()
            start()
            assert call()['data']['total'] == 2
            after = call('/' + batch_id)['data']
            assert after['items'] == rows[:-1] and after['import']['status'] == rows[-1]
            stop()
            # Corrupt committed data must fail startup, not disappear into an empty result.
            (archive / (batch_id + '.jsonl')).write_text('{}\n')
            bad = subprocess.run(
                [
                    ROOT / 'build/aggregate-storage/telemetryd',
                    '-addr',
                    f'127.0.0.1:{port}',
                    '-config',
                    tmp / 'absent.yaml',
                    '-aggregate-dir',
                    archive,
                ],
                stdout=log,
                stderr=log,
                timeout=10,
            )
            assert bad.returncode != 0
            print(
                'aggregate storage E2E: real Rust JSONL, HTTP durable import, idempotent retry, range/pagination, strict rejection, partial/unknown preservation, restart equality and corruption failure passed'
            )
        finally:
            if proc is not None:
                stop()
            log.close()


if __name__ == '__main__':
    main()
