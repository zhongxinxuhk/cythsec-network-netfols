#!/usr/bin/env python3
"""CYS-MLT-001: metadata/lock injections and an isolated installed-wheel smoke test."""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def metadata(root):
    project = root / 'ml/training'
    config = tomllib.loads((project / 'pyproject.toml').read_text())
    lock = tomllib.loads((project / 'uv.lock').read_text())
    version = (root / 'VERSION').read_text().strip()
    pin = (project / '.python-version').read_text().strip()
    require(re.fullmatch(r'3\.11\.\d+', pin) is not None, 'Python pin must be an exact supported 3.11 patch')
    require(config['project']['requires-python'] == '>=3.11,<3.12', 'requires-python must match the pinned minor')
    require(config['project']['version'] == version, 'pyproject.toml version differs from root VERSION')
    require(
        config['project']['scripts']['cythsec-features'] == 'cythsec_training.features.dataset:main',
        'CLI entry point drift',
    )
    require(config['tool']['uv']['required-version'].startswith('=='), 'uv must have an exact version pin')
    backend = config['build-system']['requires']
    require(
        len(backend) == 1 and re.fullmatch(r'setuptools==\d+\.\d+\.\d+', backend[0]) is not None,
        'build backend must have an exact setuptools pin',
    )
    require(config['dependency-groups']['build'] == backend, 'locked build group differs from the backend requirement')
    packages = {item['name']: item for item in lock['package']}
    require(
        packages['cythsec-training']['version'] == version
        and packages['cythsec-training']['source'] == {'editable': '.'},
        'local project lock metadata drift',
    )
    require(packages['setuptools']['version'] == backend[0].split('==')[1], 'build backend lock version drift')
    archives = [packages['setuptools']['sdist'], *packages['setuptools']['wheels']]
    require(
        all(re.fullmatch(r'sha256:[a-f0-9]{64}', item.get('hash', '')) is not None for item in archives),
        'build backend archives must carry SHA-256 hashes',
    )
    return config, pin, version


def run(args, *, cwd=ROOT, offline=True, capture=False):
    env = os.environ.copy()
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONHOME', None)
    if offline:
        env['UV_OFFLINE'] = '1'
        env['UV_PYTHON_DOWNLOADS'] = 'never'
    result = subprocess.run([str(arg) for arg in args], cwd=cwd, env=env, text=True, capture_output=capture)
    if result.returncode:
        raise ValueError(f'command failed ({result.returncode}): {args[0:3]}\n' + (result.stderr or ''))
    return result


def self_test(offline):
    originals = {
        name: (ROOT / name).read_text()
        for name in ('VERSION', 'ml/training/pyproject.toml', 'ml/training/.python-version', 'ml/training/uv.lock')
    }
    config, _, version = metadata(ROOT)
    backend_version = config['build-system']['requires'][0].split('==')[1]
    cases = [
        ('project version', 'ml/training/pyproject.toml', f'version = "{version}"', 'version = "9.9.9"'),
        ('Python pin', 'ml/training/.python-version', originals['ml/training/.python-version'], '3.12.0\n'),
        ('backend lock', 'ml/training/uv.lock', f'version = "{backend_version}"', 'version = "999.0.0"'),
        ('unpinned backend', 'ml/training/pyproject.toml', 'setuptools==', 'setuptools>='),
        ('archive hashes', 'ml/training/uv.lock', 'sha256:', 'sha512:'),
        ('entry point', 'ml/training/pyproject.toml', '.dataset:main', '.missing:main'),
    ]
    with tempfile.TemporaryDirectory(prefix='cythsec-python-metadata-') as tmp:
        root = Path(tmp)
        for label, filename, old, new in cases:
            for name, value in originals.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value)
            require(old in originals[filename], f'injection target missing: {label}')
            (root / filename).write_text(originals[filename].replace(old, new))
            try:
                metadata(root)
            except ValueError:
                pass
            else:
                raise ValueError(f'metadata injection escaped: {label}')
        # Check the real uv freshness command, using an already cached dependency.
        project = root / 'ml/training'
        for name, value in originals.items():
            (root / name).write_text(value)
        shutil.copyfile(ROOT / 'ml/training/README.md', project / 'README.md')
        text = (project / 'pyproject.toml').read_text()
        (project / 'pyproject.toml').write_text(
            text.replace('dependencies = []', f'dependencies = ["setuptools=={backend_version}"]')
        )
        env = os.environ.copy()
        if offline:
            env.update(UV_OFFLINE='1', UV_PYTHON_DOWNLOADS='never')
        stale = subprocess.run(
            ['uv', 'lock', '--project', str(project), '--check', '--offline', '--no-python-downloads'],
            cwd=tmp,
            env=env,
            capture_output=True,
            text=True,
        )
        require(
            stale.returncode != 0 and 'lockfile' in stale.stderr.lower(),
            f'uv stale-lock injection escaped or failed for another reason: {stale.stderr}',
        )
        # The packaging-artifact whitelist must not hide real training sources.
        checker = root / 'scripts/verify/check-ignored-sources.sh'
        checker.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / 'scripts/verify/check-ignored-sources.sh', checker)
        run(['git', 'init', '-q', '-b', 'fixture', root], cwd=root, offline=offline, capture=True)
        ignore = root / '.gitignore'
        ignore.write_text('/ml/training/.venv/\n/ml/training/build/\n/ml/training/*.egg-info/\n')
        for name in (
            'ml/training/.venv/dependency.py',
            'ml/training/build/generated.py',
            'ml/training/cythsec_training.egg-info/SOURCES.txt',
        ):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('generated\n')
        run(['bash', checker], cwd=root, offline=offline, capture=True)
        source = root / 'ml/training/features/real-source.py'
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('# real source\n')
        ignore.write_text(ignore.read_text() + '*.py\n')
        rejected = subprocess.run(['bash', str(checker)], cwd=root, text=True, capture_output=True)
        require(
            rejected.returncode != 0 and 'features/real-source.py' in rejected.stdout + rejected.stderr,
            'packaging whitelist hid a real ignored training source',
        )
        # Exempt only this generated environment in the pre-commit scan, while
        # preserving real source detection and redaction of the matched value.
        scanner = ROOT / 'scripts/security/scan-secrets.sh'
        synthetic = 'pw' + 'd = "' + 'regression-only-value' + '"\n'
        (root / 'ml/training/.venv/dependency.py').write_text(synthetic)
        run(['bash', scanner, root], cwd=root, offline=offline, capture=True)
        source.write_text(synthetic)
        scan = subprocess.run(['bash', str(scanner), str(root)], cwd=root, text=True, capture_output=True)
        require(
            scan.returncode != 0
            and 'features/real-source.py' in scan.stdout
            and 'regression-only-value' not in scan.stdout + scan.stderr,
            'secret scan exemption hid a real source hit or leaked matched text',
        )
    print(
        '✓ training project self-test: baseline + 6 metadata + 1 stale-lock injection; artifact whitelist and redacted source scan rejection passed'
    )


def smoke(offline):
    _, pin, version = metadata(ROOT)
    require(sys.version.split()[0] == pin, f'gate must run on pinned Python {pin}, got {sys.version.split()[0]}')
    project = ROOT / 'ml/training'
    run(['uv', 'lock', '--project', project, '--check'], offline=offline)
    with tempfile.TemporaryDirectory(prefix='cythsec-installed-wheel-') as tmp:
        tmp = Path(tmp)
        # uv's default builds the wheel from the sdist, so missing source-archive
        # files cannot be hidden by an editable install in the repository.
        run(['uv', 'build', project, '--out-dir', tmp / 'dist'], offline=offline, capture=True)
        wheels = list((tmp / 'dist').glob('*.whl'))
        require(len(wheels) == 1, 'expected one training wheel')
        with zipfile.ZipFile(wheels[0]) as archive:
            names = set(archive.namelist())
            require(
                'cythsec_training/features/dataset.py' in names and 'cythsec_training/features/schema_gen.py' in names,
                'wheel misses runtime sources',
            )
        run(['uv', 'venv', '--python', pin, tmp / 'venv'], offline=offline, capture=True)
        python = tmp / 'venv/bin/python'
        console = tmp / 'venv/bin/cythsec-features'
        run(['uv', 'pip', 'install', '--python', python, '--no-deps', wheels[0]], offline=offline, capture=True)
        work = tmp / 'outside-repository'
        work.mkdir()
        for name in ('mlt006-observations.jsonl', 'mlt006-labels.jsonl'):
            shutil.copyfile(ROOT / 'tests/fixtures' / name, work / name)
        script = '''import importlib.metadata, json, pathlib, sys
import cythsec_training.features.extractor as extractor
import cythsec_training.features.dataset as dataset
prefix = pathlib.Path(sys.prefix).resolve()
for module in (extractor, dataset):
    if not pathlib.Path(module.__file__).resolve().is_relative_to(prefix):
        raise SystemExit('imported repository source instead of installed wheel')
if importlib.metadata.version('cythsec-training') != sys.argv[1]:
    raise SystemExit('installed version differs from root VERSION')
if importlib.metadata.requires('cythsec-training'):
    raise SystemExit('unexpected runtime dependencies in the standard-library baseline')
samples = [extractor.FlowSample('A', 2, 0, b'\\0\\1'), extractor.FlowSample('B', 4, 1000, b'\\0\\1\\0\\1')]
vector = extractor.extract(samples).by_name()
if (vector['packets'], vector['bytes'], vector['payload_entropy_bits']) != (2.0, 6.0, 1.0):
    raise SystemExit('installed extractor differs from hand-derived truth')
print(json.dumps({'installed_version': sys.argv[1], 'feature_count': len(vector), 'isolated_import': True}))
'''
        result = run([python, '-I', '-c', script, version], cwd=work, offline=offline, capture=True)
        print(result.stdout.strip())
        run(
            [
                console,
                'build',
                '--input',
                work / 'mlt006-observations.jsonl',
                '--output',
                work / 'dataset',
                '--source-id',
                'synthetic-installed-wheel',
                '--format',
                'observations',
                '--labels',
                work / 'mlt006-labels.jsonl',
                '--label-source',
                'synthetic smoke fixture only',
            ],
            cwd=work,
            offline=offline,
        )
        run([console, 'validate', work / 'dataset'], cwd=work, offline=offline)
    print('✓ clean wheel: source-archive build, isolated import, installed CLI build/validate passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--online', action='store_true', help='allow initial dependency/tool downloads')
    parser.add_argument('--self-test', action='store_true', help='only test metadata and rejection paths')
    args = parser.parse_args()
    self_test(not args.online)
    if not args.self_test:
        smoke(not args.online)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        print(f'✗ training project: {exc}', file=sys.stderr)
        sys.exit(1)
