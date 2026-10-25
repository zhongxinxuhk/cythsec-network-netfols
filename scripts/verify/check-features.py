#!/usr/bin/env python3
"""CYS-TRF-028: independent Python/Rust vectors + hand-derived truth + gate injections."""
import copy
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ml.training.features.extractor import FlowSample, FeatureVector, extract
from ml.training.features.schema_gen import FEATURE_COUNT, FEATURE_NAMES, FEATURE_SCHEMA_VERSION


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def fixtures():
    cases = {}
    current = None
    for line in (ROOT / 'tests/fixtures/feature-samples.tsv').read_text().splitlines():
        fields = line.split()
        if not fields or fields[0].startswith('#'):
            continue
        if fields[0] == 'case':
            require(current is None and fields[1] not in cases, 'duplicate/nested fixture')
            current = fields[1]
            cases[current] = []
        elif fields == ['end']:
            require(current is not None, 'end without fixture')
            current = None
        else:
            require(current is not None, 'sample without fixture')
            side, length, ts, payload = fields
            cases[current].append(FlowSample(side, int(length), int(ts),
                                             b'' if payload == '-' else bytes.fromhex(payload)))
    require(current is None and bool(cases), 'empty/unterminated fixtures')
    return cases


def compare(rows, expected):
    require(len(rows) == len(expected) and bool(rows), 'missing or extra feature cases')
    seen = set()
    checks = 0
    for row in rows:
        name = row.get('case')
        require(name in expected and name not in seen, f'duplicate/unknown case: {name}')
        seen.add(name)
        require(type(row.get('schema_version')) is int and row['schema_version'] == FEATURE_SCHEMA_VERSION,
                f'{name}: version mismatch')
        require(row.get('names') == list(FEATURE_NAMES), f'{name}: names/order mismatch')
        values = row.get('values')
        require(isinstance(values, list) and len(values) == FEATURE_COUNT, f'{name}: dimension mismatch')
        for feature, got, want in zip(FEATURE_NAMES, values, expected[name].values):
            require(type(got) in (int, float) and math.isfinite(got), f'{name}.{feature}: not finite')
            require(math.isclose(got, want, rel_tol=1e-12, abs_tol=1e-9),
                    f'{name}.{feature}: Rust={got}, Python={want}')
            checks += 1
    return checks


def analytical_truth(expected):
    # Every value is derived from the fixture's three lengths [0,2,4], times
    # [0,1000,3000] and six equally split bytes [0,1,0,1,0,1]. Never captured from Rust.
    truth = [3, 6, 2, 4, 1, 2, 2/3, 3000, 16000, 1000, 2, 0, 4,
             math.sqrt(8/3), 1500, 1000, 2000, 500, 2, 1, 1]
    for name, actual, want in zip(FEATURE_NAMES, expected['hand_calculated'].values, truth):
        require(math.isclose(actual, want, rel_tol=1e-12, abs_tol=1e-9), f'hand truth: {name}')
    named = {key: value.by_name() for key, value in expected.items()}
    for key, feature, want in [('uniform_entropy', 'payload_entropy_bits', 8),
                               ('backward_timestamp', 'duration_us', 100),
                               ('backward_timestamp', 'mean_iat_us', 50),
                               ('integer_iat', 'mean_iat_us', 1),
                               ('ring_overwrite', 'mean_iat_us', 280),
                               ('ring_overwrite', 'stddev_iat_us', 360),
                               ('threshold', 'small_packet_ratio', 0.5),
                               ('single_truncated', 'bytes', 1500),
                               ('single_truncated', 'payload_entropy_bits', 2)]:
        require(math.isclose(named[key][feature], want, abs_tol=1e-9), f'hand truth: {key}.{feature}')
    require(all(v == 0 for v in expected['empty'].values), 'empty input must be all zeros')
    print('✓ hand-derived truth: 21 dimensions + 10 boundary checks')


def generator_selftest():
    generator = ROOT / 'tools/codegen/gen-features.py'
    registry = json.loads((ROOT / 'configs/registry/features.json').read_text())
    outputs = ['dataplane/traffic-engine/src/feature/schema_gen.rs', 'ml/training/features/schema_gen.py']
    def run(root, check):
        return subprocess.run([sys.executable, str(generator), '--root', str(root)] +
                              (['--check'] if check else []), capture_output=True, text=True)
    with tempfile.TemporaryDirectory(prefix='cythsec-feature-schema-') as tmp:
        root = Path(tmp)
        source = root / 'configs/registry/features.json'
        source.parent.mkdir(parents=True)
        def reset():
            source.write_text(json.dumps(registry))
            result = run(root, False)
            require(result.returncode == 0, result.stderr)
        reset()
        require(run(root, True).returncode == 0, 'valid registry must pass')
        mutations = [
            ('missing definition', lambda d: d['features'][0].pop('definition')),
            ('duplicate name', lambda d: d['features'][1].update(name=d['features'][0]['name'])),
            ('noncontiguous index', lambda d: d['features'][0].update(index=1)),
            ('unsupported dtype', lambda d: d.update(value_type='f32')),
            ('invalid version', lambda d: d.update(schema_version=True)),
            ('unsupported IAT policy', lambda d: d.update(iat_policy='last_64_only')),
            ('invalid threshold', lambda d: d.update(small_packet_max_len=-1)),
        ]
        count = 0
        for label, mutate in mutations:
            reset()
            doc = copy.deepcopy(registry)
            mutate(doc)
            source.write_text(json.dumps(doc))
            result = run(root, True)
            require(result.returncode == 2 and 'invalid' in result.stderr, f'injection escaped: {label}')
            count += 1
        for field in ('schema_version', 'small_packet_max_len'):
            reset()
            doc = copy.deepcopy(registry)
            doc[field] += 1
            source.write_text(json.dumps(doc))
            require(run(root, True).returncode == 1, f'stale {field} escaped')
            count += 1
        for output in outputs:
            reset()
            path = root / output
            path.write_text(path.read_text() + '\n// drift\n')
            require(run(root, True).returncode == 1, f'generated drift escaped: {output}')
            count += 1
    print(f'✓ generator self-test: valid baseline + {count}/{count} injections detected')
    return count


def comparison_selftest(rows, expected):
    def version(r):
        r[0]['schema_version'] += 1
    def order(r):
        r[0]['names'][0], r[0]['names'][1] = r[0]['names'][1], r[0]['names'][0]
    def value(r):
        r[0]['values'][0] += 1
    def swap(r):
        item = next(v for v in r if v['case'] == 'hand_calculated')
        item['values'][0], item['values'][1] = item['values'][1], item['values'][0]
    mutations = [version, order, value, swap, lambda r: r.pop(),
                 lambda r: r[0]['values'].pop(), lambda r: r[0].pop('values'),
                 lambda r: r[0]['values'].__setitem__(0, float('nan')),
                 lambda r: r[0].update(case=r[1]['case'])]
    for mutate in mutations:
        bad = copy.deepcopy(rows)
        mutate(bad)
        try:
            compare(bad, expected)
        except ValueError:
            pass
        else:
            raise ValueError(f'comparison injection escaped: {mutate}')
    for constructor in [lambda: FlowSample('uplink', 1, 0),
                        lambda: FlowSample('A', -1, 0),
                        lambda: FlowSample('A', 1, -1),
                        lambda: FeatureVector(FEATURE_SCHEMA_VERSION + 1, tuple([0.] * FEATURE_COUNT)),
                        lambda: FeatureVector(FEATURE_SCHEMA_VERSION, (0.,)),
                        lambda: FeatureVector(FEATURE_SCHEMA_VERSION, tuple([None] * FEATURE_COUNT)),
                        lambda: FeatureVector(True, tuple([0.] * FEATURE_COUNT))]:
        try:
            constructor()
        except ValueError:
            pass
        else:
            raise ValueError('invalid training input escaped')
    print(f'✓ parity self-test: {len(mutations)}/{len(mutations)} injections detected; 7 invalid inputs rejected')


def main():
    generator_selftest()
    cases = fixtures()
    expected = {name: extract(samples) for name, samples in cases.items()}
    analytical_truth(expected)
    result = subprocess.run(['cargo', 'run', '--offline', '--quiet', '--example', 'feature_vectors'],
                            cwd=ROOT, text=True, capture_output=True)
    require(result.returncode == 0, f'Rust fixture driver failed:\n{result.stderr}')
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    checks = compare(rows, expected)
    comparison_selftest(rows, expected)
    print(f'✓ feature parity: {len(cases)} cases × {FEATURE_COUNT} dimensions = {checks} values; version/names/order match')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f'✗ features: {exc}', file=sys.stderr)
        sys.exit(1)
