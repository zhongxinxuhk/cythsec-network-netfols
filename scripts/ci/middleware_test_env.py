#!/usr/bin/env python3
"""Prepare private, isolated test connection variables without production credentials."""

import argparse
import fcntl
import json
import os
import re
import secrets
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PREFIX = 'CYTHSEC_TEST_CLICKHOUSE_'
FIELDS = ('IMAGE', 'VERSION', 'HOST', 'PORT', 'USER', 'PASSWORD')


def load_private(path):
    if path.is_symlink():
        raise ValueError('test environment file must not be a symlink')
    try:
        info = path.stat()
    except FileNotFoundError:
        return {}
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 65536:
        raise ValueError('test environment file must be private, regular and at most 64KiB')
    result = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or key not in {PREFIX + name for name in FIELDS} or key in result:
            raise ValueError('invalid or duplicate test environment variable')
        result[key] = value
    return result


def prepare(environ=None):
    env = os.environ if environ is None else environ
    config = Path(env.get('CYTHSEC_MIDDLEWARE_TEST_CONFIG') or ROOT / 'configs/testing/middleware.json')
    profile = json.loads(config.read_text())
    if set(profile) != {'version', 'clickhouse'} or type(profile['version']) is not int or profile['version'] != 1:
        raise ValueError('invalid test middleware profile')
    section = profile['clickhouse']
    if set(section) != {'image', 'version', 'host', 'port', 'user'}:
        raise ValueError('unknown test middleware connection fields')
    path = Path(env.get('CYTHSEC_MIDDLEWARE_TEST_ENV_FILE') or ROOT / 'build/middleware-test.env')
    if any(char in str(path) for char in ('\n', '\r', '\x00')):
        raise ValueError('invalid test environment path')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = load_private(path)
        values = {PREFIX + key.upper(): str(value) for key, value in section.items()}
        values[PREFIX + 'PASSWORD'] = previous.get(PREFIX + 'PASSWORD') or secrets.token_hex(24)
        for key in list(values):
            if env.get(key):
                values[key] = env[key]
        # Test traffic can only reach the Compose service, never a production endpoint.
        if values[PREFIX + 'HOST'] != 'clickhouse':
            raise ValueError('test host must be the isolated clickhouse Compose service')
        if not values[PREFIX + 'PORT'].isdigit() or not 1024 <= int(values[PREFIX + 'PORT']) <= 65535:
            raise ValueError('invalid test native port')
        for key in ('USER', 'PASSWORD'):
            if not re.fullmatch(r'[A-Za-z0-9_.-]+', values[PREFIX + key]):
                raise ValueError('test username/password must be a single safe token')
        version = values[PREFIX + 'VERSION']
        image = values[PREFIX + 'IMAGE']
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', version):
            raise ValueError('test engine version must be pinned')
        if image != 'clickhouse/clickhouse-server:' + version and not re.fullmatch(
            r'clickhouse/clickhouse-server@sha256:[0-9a-f]{64}', image
        ):
            raise ValueError('test image must pin the official engine version or digest')
        if any('\n' in value or '\r' in value or '\x00' in value for value in values.values()):
            raise ValueError('multiline test connection values are not allowed')
        tmp_name = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.middleware-', delete=False) as stream:
                tmp_name = stream.name
                os.fchmod(stream.fileno(), 0o600)
                stream.write(''.join(f'{key}={value}\n' for key, value in values.items()))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_name, path)
        finally:
            if tmp_name and os.path.exists(tmp_name):
                os.unlink(tmp_name)
    env.update(values)
    return values, path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--github-env', action='store_true')
    args = parser.parse_args()
    if args.github_env and (os.environ.get('GITHUB_ACTIONS') != 'true' or not os.environ.get('GITHUB_ENV')):
        raise SystemExit('GitHub export requires an Actions job environment')
    values, path = prepare()
    if args.github_env:
        print('::add-mask::' + values[PREFIX + 'PASSWORD'], flush=True)
        with open(os.environ['GITHUB_ENV'], 'a') as output:
            output.write(f'CYTHSEC_MIDDLEWARE_TEST_ENV_FILE={path}\n')
            for key, value in values.items():
                output.write(f'{key}={value}\n')
    print('Isolated middleware test environment prepared; credentials are private and omitted from reports.')


if __name__ == '__main__':
    main()
