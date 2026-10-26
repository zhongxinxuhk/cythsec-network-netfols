#!/usr/bin/env python3
"""Real queue crash/replay verification with Rust aggregate data and real telemetryd."""

import importlib.util
import json
import os
import shutil
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
    with tempfile.TemporaryDirectory(prefix='cythsec-ingest-') as work:
        work = Path(work)
        pcap = work / 'synthetic.pcap'
        vectors.write_pcap(pcap, [(1000000 + n, vectors.packet(n, 17, b'x')) for n in range(20)])
        raw = subprocess.check_output([ROOT / 'target/debug/cythsec-observe', '-r', pcap])
        rows = [json.loads(line) for line in raw.splitlines()]
        partial = [json.loads(line) for line in raw.splitlines()]
        partial[-1]['analysis_complete'] = False
        raw_partial = ('\n'.join(json.dumps(row) for row in partial)).encode()
        archive, queue = work / 'history', work / 'queue'
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        proc = None
        log = (work / 'server.log').open('wb')

        def stop(crash=False):
            nonlocal proc
            if proc is None:
                return
            proc.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise AssertionError('ingest server did not stop') from None
            assert proc.returncode != 0 if crash else proc.returncode == 0
            proc = None

        def start():
            nonlocal proc
            proc = subprocess.Popen(
                [
                    ROOT / 'build/aggregate-storage/telemetryd',
                    '-addr',
                    f'127.0.0.1:{port}',
                    '-config',
                    work / 'absent.yaml',
                    '-aggregate-dir',
                    archive,
                    '-aggregate-queue-dir',
                    queue,
                ],
                cwd=ROOT,
                stdout=log,
                stderr=log,
            )
            for _ in range(100):
                if proc.poll() is not None:
                    raise AssertionError('ingest server startup failed')
                try:
                    with urllib.request.urlopen(base + '/healthz', timeout=1) as reply:
                        if reply.status == 200:
                            return
                except (urllib.error.URLError, TimeoutError):
                    time.sleep(0.05)
            raise AssertionError('ingest server readiness timed out')

        def call(path, body=None, expected=200):
            req = urllib.request.Request(
                base + '/api/v1/analytics/' + path, data=body, headers={'Content-Type': 'application/x-ndjson'}
            )
            try:
                reply = urllib.request.urlopen(req, timeout=5)
            except urllib.error.HTTPError as error:
                reply = error
            with reply:
                data = json.load(reply)
                assert reply.status == expected, (reply.status, expected, data)
                return data['data']

        def wait_for(predicate):
            for _ in range(100):
                value = call('ingest')
                if predicate(value):
                    return value
                time.sleep(0.05)
            raise AssertionError('queue state did not converge')

        try:
            start()
            # Simulate a transient unavailable destination, without touching unrelated files.
            os.rename(archive, work / 'history-held')
            accepted = call('ingest', raw, 202)
            assert accepted['durable'] and accepted['acknowledged_stage'] == 'queue'
            assert call('ingest', raw, 202)['duplicate']
            other = call('ingest', raw_partial, 202)
            blocked = wait_for(lambda value: value['state'] == 'backoff')
            assert blocked['last_error'] == 'storage_io' and blocked['pending_batches'] == 2
            assert blocked['next_retry_at'] is not None
            assert len(list(queue.glob('*.jsonl'))) == 2
            stop(crash=True)
            os.rename(work / 'history-held', archive)
            # Simulate destination committed but its acknowledgement was interrupted.
            # Restart must replay that batch as a duplicate and drain the other normally.
            shutil.copyfile(queue / (accepted['id'] + '.jsonl'), archive / (accepted['id'] + '.jsonl'))
            os.chmod(archive / (accepted['id'] + '.jsonl'), 0o600)
            start()
            finished = wait_for(lambda value: value['pending_batches'] == 0 and value['completed_this_process'] == 2)
            assert finished['duplicates_this_process'] == 1
            assert finished['last_error'] is None and finished['next_retry_at'] is None
            assert call('imports')['total'] == 2
            assert call('imports/' + accepted['id'])['items'] == rows[:-1]
            assert call('imports/' + other['id'])['import']['status']['analysis_complete'] is False
            assert call('imports/' + other['id'])['import']['status']['capture_loss_status'] == 'unknown'
            assert not list(queue.glob('*.jsonl'))
            stop()
            start()
            resumed = wait_for(lambda value: value['state'] == 'idle')
            assert resumed['pending_batches'] == 0 and resumed['completed_this_process'] == 0
            assert call('imports')['total'] == 2
            stop()
            print(
                'aggregate ingest E2E: durable 202, duplicate enqueue, storage failure/backoff, SIGKILL recovery, commit-before-ack replay, exact history, partial/unknown preservation and empty restart passed'
            )
        finally:
            if proc is not None:
                stop()
            log.close()


if __name__ == '__main__':
    main()
