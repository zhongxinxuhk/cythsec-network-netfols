#!/usr/bin/env python3
"""CYS-MLT-002: Ruff/Black/strict-mypy gate with real-tool failure injections."""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / 'ml/training/pyproject.toml'
BIN = ROOT / 'ml/training/.venv/bin'
GENERATED = {'features/attributes_gen.py', 'features/schema_gen.py'}
SUPPORT = (
    'scripts/verify/check-features.py',
    'scripts/verify/check-training-project.py',
    'scripts/verify/check-python-quality.py',
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def inventory(root: Path) -> tuple[list[Path], list[Path]]:
    project = root / 'ml/training'
    runtime = []
    for path in sorted(project.rglob('*.py')):
        parts = path.relative_to(project).parts
        if any(part in {'.venv', 'build', '__pycache__'} or part.endswith('.egg-info') for part in parts):
            continue
        runtime.append(path)
    for name in ('features/extractor.py', 'features/dataset.py'):
        require(project / name in runtime, f'quality inventory misses required runtime source: {name}')
    style = [path for path in runtime if path.relative_to(project).as_posix() not in GENERATED]
    style.extend(sorted((root / 'tests/ml').rglob('*.py')))
    style.extend(root / name for name in SUPPORT)
    require(all(path.is_file() for path in style), 'quality inventory contains missing support files')
    require(bool(list((root / 'tests/ml').glob('test_*.py'))), 'quality inventory has no training tests')
    return runtime, style


def tool_run(tool: str, paths: list[Path]) -> subprocess.CompletedProcess[str]:
    if tool == 'ruff':
        args = ['check', '--no-cache', '--config', str(CONFIG)]
    elif tool == 'black':
        args = ['--check', '--config', str(CONFIG)]
    else:
        args = ['--no-incremental', '--config-file', str(CONFIG)]
    env = os.environ.copy()
    env['BLACK_CACHE_DIR'] = str(ROOT / 'build/python-quality/black')
    return subprocess.run([str(BIN / tool), *args, *map(str, paths)], cwd=ROOT, env=env, text=True, capture_output=True)


def check_versions() -> None:
    config = tomllib.loads(CONFIG.read_text())
    require(config['tool']['mypy'].get('strict') is True, 'strict mypy must remain enabled')
    require(
        config['tool']['ruff']['line-length'] == config['tool']['black']['line-length'],
        'Ruff and Black must share a line-length policy',
    )
    expected = {}
    for requirement in config['dependency-groups']['quality']:
        match = re.fullmatch(r'(ruff|black|mypy)==([0-9.]+)', requirement)
        require(match is not None, 'quality tools must have exact version pins')
        if match is not None:
            expected[match[1]] = match[2]
    require(set(expected) == {'ruff', 'black', 'mypy'}, 'quality group must contain the three required tools')
    for name, version in expected.items():
        require(importlib.metadata.version(name) == version, f'{name} installed version differs from lock policy')
        print(f'  {name}=={version}')


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix='cythsec-python-quality-') as tmp:
        root = Path(tmp)
        probe = root / 'quality_probe.py'
        baseline = 'def value() -> int:\n    return 1\n'
        mutations = {
            'ruff': ('import os\n\n\n' + baseline, 'F401'),
            'black': ('def value( )->int:\n return 1\n', 'would reformat'),
            'mypy': ("def value() -> int:\n    return 'bad'\n", '[return-value]'),
        }
        for name, (bad, diagnostic) in mutations.items():
            probe.write_text(baseline)
            result = tool_run(name, [probe])
            require(result.returncode == 0, f'{name} rejected the valid baseline: {result.stdout}{result.stderr}')
            probe.write_text(bad)
            result = tool_run(name, [probe])
            require(
                result.returncode != 0 and diagnostic in result.stdout + result.stderr,
                f'{name} failed to detect its injection: {result.stdout}{result.stderr}',
            )
        # Newly added source must be discovered; generated outputs and the venv
        # must not be mistaken for hand-maintained source.
        for relative in (
            'ml/training/features/extractor.py',
            'ml/training/features/dataset.py',
            'tests/ml/test_example.py',
            *SUPPORT,
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(baseline)
        extra = root / 'ml/training/features/new_module.py'
        extra.write_text(mutations['ruff'][0])
        generated = root / 'ml/training/features/schema_gen.py'
        generated.write_text('# generated\n')
        vendor = root / 'ml/training/.venv/dependency.py'
        vendor.parent.mkdir()
        vendor.write_text('not Python code\n')
        runtime, style = inventory(root)
        require(
            extra in runtime and extra in style and generated in runtime and generated not in style,
            'quality inventory misses new modules or includes generated style targets',
        )
        require(vendor not in runtime and vendor not in style, 'quality inventory includes the virtual environment')
        result = tool_run('ruff', style)
        require(result.returncode != 0 and 'new_module.py' in result.stdout, 'new-source violation was not checked')
        # mypy ships C headers: exercise the actual C++ inventory implementation
        # so installing Python tools cannot add vendor code to clang-format.
        lint = root / 'scripts/lint/lint-all.sh'
        lint.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'scripts/lint/lint-all.sh', lint)
        vendor_cpp = root / 'ml/training/.venv/vendor.cpp'
        vendor_cpp.write_text('generated vendor code\n')
        nested_cpp = root / '.claude/worktrees/other/build/vendor.cpp'
        nested_cpp.parent.mkdir(parents=True)
        nested_cpp.write_text('different checkout generated C++\n')
        real_cpp = root / 'dataplane/real.cpp'
        real_cpp.parent.mkdir()
        real_cpp.write_text('real source\n')
        listed = subprocess.run(['bash', str(lint), '--list-cpp'], cwd=root, text=True, capture_output=True)
        require(
            listed.returncode == 0
            and './dataplane/real.cpp' in listed.stdout
            and './ml/training/.venv/vendor.cpp' not in listed.stdout
            and './.claude/worktrees/other/build/vendor.cpp' not in listed.stdout,
            'C++ inventory hid source or included the venv',
        )
    print(
        '✓ quality self-test: 3 valid baselines + 3 tool injections + new-source discovery/rejection + C++ inventory isolation'
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    check_versions()
    self_test()
    if args.self_test:
        return 0
    runtime, style = inventory(ROOT)
    failures = []
    for name, paths in (('ruff', style), ('black', style), ('mypy', runtime)):
        result = tool_run(name, paths)
        print(result.stdout, end='')
        print(result.stderr, end='', file=sys.stderr)
        if result.returncode:
            failures.append(name)
    require(not failures, f'Python quality checks failed: {", ".join(failures)}')
    print(f'✓ Python quality: Ruff/Black {len(style)} handwritten files; strict mypy {len(runtime)} package files')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, importlib.metadata.PackageNotFoundError) as exc:
        print(f'✗ Python quality: {exc}', file=sys.stderr)
        sys.exit(1)
