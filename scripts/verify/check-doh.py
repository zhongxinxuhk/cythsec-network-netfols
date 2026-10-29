#!/usr/bin/env python3
"""B019 decoded HTTPS representations, local TLS fixtures, optional tshark reference."""

import argparse
import base64
import importlib.util
import json
import ssl
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('tls_fixture_support', ROOT / 'scripts/verify/check-dot.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
BIN = support.BIN


def split_http(data):
    head, body = data.split(b'\r\n\r\n', 1)
    lines = head.decode('ascii').split('\r\n')
    headers = {}
    for line in lines[1:]:
        key, value = line.split(':', 1)
        key = key.lower()
        assert key not in headers
        headers[key] = value.strip()
    assert int(headers.get('content-length', '0')) == len(body)
    return lines[0], headers, body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tshark', action='store_true')
    args = parser.parse_args()
    if not ssl.HAS_TLSv1_3:
        print('B019 HTTPS reference unverified: TLS1.3 required')
        return 3
    q = support.dns(0, 'resolver')[2:]
    r = support.dns(0, 'resolver', True)[2:]
    encoded = base64.urlsafe_b64encode(q).rstrip(b'=').decode()
    good_url = 'https://dns.example/custom?dns=' + encoded
    checks = 0
    with tempfile.TemporaryDirectory(prefix='cythsec-doh-') as tmp:
        directory = Path(tmp)
        support.run(
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
        body_file = directory / 'body.bin'

        def cli(direction='client', url='https://dns.example/custom', **metadata):
            values = {
                'source-id': 'local-https-fixture',
                'session-id': 'tls-fixture',
                'request-id': 'request-1',
                'direction': direction,
                'url': url,
                **metadata,
            }
            out = [BIN, 'doh-message']
            for key, value in values.items():
                out.extend(['--' + key, str(value)])
            return out

        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            for method in ('GET', 'POST'):
                target = '/custom?dns=' + encoded if method == 'GET' else '/custom'
                query = (
                    method + ' ' + target + ' HTTP/1.1\r\nHost: dns.example\r\nAccept: application/dns-message\r\n'
                ).encode()
                query += (
                    b'\r\n'
                    if method == 'GET'
                    else (
                        'Content-Type: application/dns-message\r\nContent-Length: ' + str(len(q)) + '\r\n\r\n'
                    ).encode()
                    + q
                )
                response = (
                    'HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: '
                    + str(len(r))
                    + '\r\n\r\n'
                ).encode() + r
                events, recovered, keylog = support.tls_fixture(directory, version, query, response, alpn='http/1.1')
                capture = directory / (version.name + '-' + method + '.pcap')
                support.pcap(capture, events, server_port=443)
                for index, application in enumerate(recovered):
                    start, headers, body = split_http(application)
                    body_file.write_bytes(body)
                    opts = {'read': body_file, 'content-length': len(body)}
                    if 'content-type' in headers:
                        opts['content-type'] = headers['content-type']
                    if index == 0:
                        command = cli(
                            url='https://dns.example' + start.split(' ')[1], method=start.split(' ')[0], **opts
                        )
                    else:
                        command = cli('server', status=start.split(' ')[1], **opts)
                    record = json.loads(support.run(command))
                    assert record['app'] == 'doh' and record['app_id'] == 65564
                    assert record['dns']['qname'] == 'resolver.example' and record['dns']['id'] == 0
                    assert record['dns']['answer_ips'] == (['192.0.2.42'] if index else [])
                    assert record['request_id'] == 'request-1' and record['tls_peer_authenticated'] is None
                    assert record['transport_evidence'] == 'caller_attested_decoded_https'
                    checks += 1
                native = [json.loads(v) for v in support.run([BIN, '-r', capture, '-q']).splitlines()]
                assert native and all(v['app']['app'] != 'doh' for v in native)
                if args.tshark:
                    common = [
                        'tshark',
                        '-r',
                        capture,
                        '-o',
                        'tls.keylog_file:' + str(keylog),
                        '-d',
                        'tcp.port==443,tls',
                        '-T',
                        'fields',
                    ]
                    actual = (
                        support.run(
                            common + ['-Y', 'http.request', '-e', 'http.request.method', '-e', 'http.request.uri']
                        )
                        .strip()
                        .split('\t')
                    )
                    assert actual == [method, target], actual
                    if method == 'GET':
                        raw = actual[1].split('?dns=')[1]
                        assert base64.urlsafe_b64decode(raw + '=' * ((-len(raw)) % 4)) == q
                    else:
                        observed = support.run(common + ['-Y', 'http.request', '-e', 'dns.qry.name']).strip()
                        assert observed == 'resolver.example', observed
                    observed = (
                        support.run(
                            common
                            + ['-Y', 'http.response', '-e', 'http.response.code', '-e', 'dns.qry.name', '-e', 'dns.a']
                        )
                        .strip()
                        .split('\t')
                    )
                    assert observed == ['200', 'resolver.example', '192.0.2.42'], observed
        body_file.write_bytes(q)
        post = cli(
            method='POST', read=body_file, **{'content-type': 'application/dns-message', 'content-length': len(q)}
        )
        failures = [
            cli(method='GET', url=good_url + '='),
            cli(method='GET', url=good_url + '&dns=AA'),
            cli(method='GET', url='https://dns.example/custom'),
            cli(method='GET', url='http://dns.example/custom?dns=' + encoded),
            cli(method='GET', url='https://user:pass@dns.example/custom?dns=' + encoded),
            cli(method='GET', url=good_url, read=body_file),
            cli(method='GET', url='https://dns.example/custom?dns=AB'),
        ]
        for metadata in [
            {'content-type': 'application/json'},
            {'content-type': 'application/dns-message; charset=utf-8'},
            {'content-encoding': 'gzip'},
            {'content-length': len(q) + 1},
            {'request-id': 'bad id'},
            {'status': 200},
            {'method': 'PUT'},
        ]:
            opts = {'method': 'POST', 'read': body_file, 'content-type': 'application/dns-message', **metadata}
            failures.append(cli(**opts))
        failures += [
            [BIN, 'doh-message', '--method', 'GET'],
            post + ['--request-id', 'duplicate'],
            post + ['-o', body_file],
        ]
        for command in failures:
            support.run(command, expected=1)
        body_file.write_bytes(r)
        support.run(cli(method='POST', read=body_file, **{'content-type': 'application/dns-message'}), expected=1)
        support.run(
            cli('server', status=500, read=body_file, **{'content-type': 'application/dns-message'}), expected=1
        )
        body_file.write_bytes(bytes(8193))
        support.run(post, expected=1)
    print(
        f'B019 DoH: {checks} TLS1.2/1.3 GET/POST/response events, 20 CLI failure cases and native-PCAP non-promotion passed; '
        + ('tshark HTTPS/DNS representations matched' if args.tshark else 'independent reference not requested')
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
