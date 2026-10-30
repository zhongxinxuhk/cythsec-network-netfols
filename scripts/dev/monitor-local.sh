#!/usr/bin/env bash
# Local service liveness only; no subscriber records, credentials or packet payloads.
set -euo pipefail
[[ $# == 0 || ( $# == 1 && ( "$1" == --watch || "$1" == --self-test ) ) ]] || { echo 'Usage: monitor-local.sh [--watch|--self-test]' >&2; exit 2; }
exec python3 - "$@" <<'PY'
import datetime
import json
import sys
import time
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def probe(service, url):
    start = time.monotonic()
    result = {'service': service, 'url': url}
    try:
        with opener.open(url, timeout=2) as response:
            payload = json.loads(response.read(4097))
        data = payload.get('data', {})
        if data.get('status') != 'ok' or data.get('service') != service:
            raise ValueError('health identity mismatch')
        result['state'] = 'online'
    except Exception as error:
        result.update(state='unavailable', error=type(error).__name__)
    result.update(at=datetime.datetime.now(datetime.timezone.utc).isoformat(), latency_ms=round((time.monotonic() - start) * 1000, 2))
    return result


if '--self-test' in sys.argv:
    import http.server
    import threading

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', '/ok')
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            data = {'status': 'ok', 'service': 'routerd' if self.path == '/ok' else 'wrong'}
            self.wfile.write(json.dumps({'data': data}).encode())

    with http.server.HTTPServer(('127.0.0.1', 0), Fixture) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            assert probe('routerd', base + '/ok')['state'] == 'online'
            assert probe('routerd', base + '/wrong')['state'] == 'unavailable'
            assert probe('routerd', base + '/redirect')['state'] == 'unavailable'
        finally:
            server.shutdown()
            thread.join()
    assert probe('routerd', base + '/ok')['state'] == 'unavailable'
    print('Monitor: real HTTP health, wrong identity, redirect and stopped service checks passed')
    sys.exit(0)

watch = '--watch' in sys.argv[1:]
try:
    while True:
        healthy = True
        for service, port in [('routerd', 18080), ('policyd', 18081), ('dnsd', 18082), ('telemetryd', 18083)]:
            result = probe(service, f'http://127.0.0.1:{port}/healthz')
            healthy = healthy and result['state'] == 'online'
            print(json.dumps(result), flush=True)
        if not watch:
            sys.exit(0 if healthy else 1)
        time.sleep(5)
except KeyboardInterrupt:
    sys.exit(130)
PY
