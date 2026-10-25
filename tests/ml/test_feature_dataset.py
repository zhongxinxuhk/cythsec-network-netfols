"""CYS-MLT-006 acceptance: source observations -> exported, versioned feature bundles."""
import copy
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ml.training.features import dataset
from ml.training.features.schema_gen import FEATURE_NAMES


class FeatureDatasetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cythsec-training-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.input = self.root / 'input.jsonl'
        self.rows = [{
            'schema_version': 1, 'sample_id': 'hand-calculated',
            'samples': [
                {'side': 'A', 'payload_len': 0, 'timestamp_us': 0, 'payload_hex': ''},
                {'side': 'B', 'payload_len': 2, 'timestamp_us': 1000, 'payload_hex': '0001'},
                {'side': 'A', 'payload_len': 4, 'timestamp_us': 3000, 'payload_hex': '00010001'},
            ],
        }]
        self.write_rows(self.rows)

    def write_rows(self, rows, path=None):
        path = path or self.input
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        return path

    def build(self, name='output', **kwargs):
        return dataset.build_bundle(self.input, self.root / name, source_id='synthetic-fixture',
                                    input_format=kwargs.pop('input_format', 'observations'), **kwargs)

    def matrix(self, name='output'):
        with (self.root / name / 'features.csv').open(newline='', encoding='utf-8') as stream:
            return list(csv.DictReader(stream))

    def record(self):
        # Hand-derived features for lengths [0,2,4], times [0,1000,3000],
        # canonical directions A/B/A and equally split captured bytes 0/1.
        truth = [3, 6, 2, 4, 1, 2, 2/3, 3000, 16000, 1000, 2, 0, 4,
                 (8/3)**0.5, 1500, 1000, 2000, 500, 2, 1, 1]
        return {'schema_version': 2, 'session_id': 9,
                'time': {'first_seen_us': 0, 'last_seen_us': 3000},
                'features': {'schema_version': 1, **dict(zip(FEATURE_NAMES, truth))},
                'app': {'app': 'http'}, 'risk_score': 0.99}

    def test_hand_derived_feature_matrix_and_source_fingerprint(self):
        manifest = self.build()
        row = self.matrix()[0]
        expected = self.record()['features']
        for name in FEATURE_NAMES:
            self.assertAlmostEqual(float(row[name]), expected[name], places=9, msg=name)
        self.assertEqual(row['first_seen_us'], '0')
        self.assertEqual(row['last_seen_us'], '3000')
        self.assertEqual(manifest['source']['sha256'], hashlib.sha256(self.input.read_bytes()).hexdigest())
        self.assertEqual(dataset.validate_bundle(self.root / 'output'), manifest)

    def test_reproducible_bundle_does_not_embed_output_paths_or_wall_clock(self):
        first = self.build('first')
        second = self.build('second')
        self.assertEqual(first, second)
        for name in ('features.csv', 'manifest.json'):
            self.assertEqual((self.root / 'first' / name).read_bytes(), (self.root / 'second' / name).read_bytes())

    def test_explicit_labels_have_provenance_and_complete_counts(self):
        labels = self.write_rows([{'sample_id': 'hand-calculated', 'label': 'fixture-class'}], self.root / 'labels.jsonl')
        manifest = self.build(labels_path=labels, label_source='synthetic test annotation; not ground truth')
        self.assertEqual(self.matrix()[0]['label'], 'fixture-class')
        self.assertEqual(manifest['labels']['class_counts'], {'fixture-class': 1})
        self.assertEqual(manifest['labels']['sha256'], hashlib.sha256(labels.read_bytes()).hexdigest())

    def test_unlabeled_record_does_not_infer_labels_from_dpi_or_risk(self):
        self.write_rows([self.record()])
        manifest = self.build(input_format='flow-record')
        self.assertEqual(self.matrix()[0]['sample_id'], '9')
        self.assertNotIn('label', self.matrix()[0])
        self.assertNotIn('risk_score', self.matrix()[0])
        self.assertEqual(manifest['labels']['status'], 'absent')
        self.assertEqual(manifest['labels']['class_counts'], {})

    def test_record_json_key_order_cannot_change_matrix_feature_order(self):
        row = self.record()
        row['features'] = dict(reversed(list(row['features'].items())))
        self.write_rows([row])
        self.build(input_format='flow-record')
        matrix = self.matrix()[0]
        self.assertEqual(list(matrix)[len(dataset.METADATA_COLUMNS):], list(FEATURE_NAMES))
        for name in FEATURE_NAMES:
            self.assertEqual(float(matrix[name]), row['features'][name])

    def test_arrival_order_is_preserved_instead_of_sorting_timestamps(self):
        row = copy.deepcopy(self.rows[0])
        for sample, ts in zip(row['samples'], [100, 50, 200]):
            sample['timestamp_us'] = ts
        self.write_rows([row])
        self.build()
        self.assertEqual(self.matrix()[0]['first_seen_us'], '100')
        self.assertEqual(float(self.matrix()[0]['duration_us']), 100)
        self.assertEqual(float(self.matrix()[0]['direction_switches']), 2)

    def test_bad_observation_inputs_are_rejected_without_publishing(self):
        mutations = [
            ('unknown observation version', lambda r: r.update(schema_version=2)),
            ('boolean version', lambda r: r.update(schema_version=True)),
            ('missing sample_id', lambda r: r.pop('sample_id')),
            ('empty samples', lambda r: r.update(samples=[])),
            ('wrong direction', lambda r: r['samples'][0].update(side='uplink')),
            ('negative length', lambda r: r['samples'][0].update(payload_len=-1)),
            ('negative time', lambda r: r['samples'][0].update(timestamp_us=-1)),
            ('odd hex', lambda r: r['samples'][0].update(payload_hex='0')),
            ('missing captured bytes', lambda r: r['samples'][0].pop('payload_hex')),
            ('capture longer than wire', lambda r: r['samples'][0].update(payload_hex='00')),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                row = copy.deepcopy(self.rows[0])
                mutate(row)
                self.write_rows([row])
                with self.assertRaises((ValueError, TypeError)):
                    self.build()
                self.assertFalse((self.root / 'output').exists())

    def test_bad_record_projection_is_rejected(self):
        mutations = [
            ('old record version', lambda r: r.update(schema_version=1)),
            ('unknown feature version', lambda r: r['features'].update(schema_version=2)),
            ('boolean feature version', lambda r: r['features'].update(schema_version=True)),
            ('text feature value', lambda r: r['features'].update(bytes='6')),
            ('null feature', lambda r: r['features'].update(bytes=None)),
            ('nonfinite feature', lambda r: r['features'].update(bytes=float('nan'))),
            ('boolean feature', lambda r: r['features'].update(bytes=True)),
            ('missing feature', lambda r: r['features'].pop('mean_iat_us')),
            ('extra feature', lambda r: r['features'].update(unknown=0)),
            ('negative feature', lambda r: r['features'].update(bytes=-1)),
            ('invalid ratio', lambda r: r['features'].update(fwd_byte_ratio=2)),
            ('empty observation', lambda r: r['features'].update(packets=0)),
            ('backward interval', lambda r: r['time'].update(last_seen_us=-1)),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                row = self.record()
                mutate(row)
                self.write_rows([row])
                with self.assertRaises((ValueError, TypeError)):
                    self.build(input_format='flow-record')
                self.assertFalse((self.root / 'output').exists())

    def test_duplicate_rows_and_ambiguous_json_are_rejected(self):
        self.write_rows(self.rows * 2)
        with self.assertRaisesRegex(ValueError, 'duplicate sample_id'):
            self.build()
        self.input.write_text('{"schema_version":1,"schema_version":2}\n')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            self.build()
        self.assertFalse((self.root / 'output').exists())

    def test_empty_blank_truncated_and_oversized_jsonl_are_rejected(self):
        for raw in ['', '\n', '{bad json', '[]\n']:
            with self.subTest(raw=raw):
                self.input.write_text(raw)
                with self.assertRaises(ValueError):
                    self.build()
                self.assertFalse((self.root / 'output').exists())
        self.write_rows(self.rows)
        with mock.patch.object(dataset, 'MAX_LINE_BYTES', 32):
            with self.assertRaisesRegex(ValueError, 'line exceeds'):
                self.build()

    def test_label_missing_extra_duplicate_or_no_provenance_is_rejected(self):
        cases = [[], [{'sample_id': 'other', 'label': 'x'}],
                 [{'sample_id': 'hand-calculated', 'label': 'x'}, {'sample_id': 'extra', 'label': 'x'}],
                 [{'sample_id': 'hand-calculated', 'label': 'x'}] * 2,
                 [{'sample_id': 'hand-calculated', 'label': ''}]]
        for rows in cases:
            with self.subTest(rows=rows):
                labels = self.write_rows(rows, self.root / 'labels.jsonl')
                with self.assertRaises(ValueError):
                    self.build(labels_path=labels, label_source='synthetic labels')
                self.assertFalse((self.root / 'output').exists())
        with self.assertRaisesRegex(ValueError, 'provided together'):
            self.build(labels_path=self.root / 'labels.jsonl')

    def test_typed_class_counts_and_incomplete_bundles_are_rejected(self):
        self.build(labels_path=self.write_rows([{'sample_id': 'hand-calculated', 'label': 'x'}], self.root / 'labels.jsonl'),
                   label_source='explicit synthetic annotation')
        bundle = self.root / 'output'
        manifest = json.loads((bundle / 'manifest.json').read_text())
        manifest['labels']['class_counts']['x'] = True
        (bundle / 'manifest.json').write_text(dataset.canonical_json(manifest))
        with self.assertRaisesRegex(ValueError, 'class counts'):
            dataset.validate_bundle(bundle)
        (bundle / 'manifest.json').unlink()
        with self.assertRaises(OSError):
            dataset.validate_bundle(bundle)

    def test_existing_output_is_never_overwritten(self):
        self.build()
        original = (self.root / 'output' / 'manifest.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.build()
        self.assertEqual((self.root / 'output' / 'manifest.json').read_bytes(), original)

    def test_publication_failure_rolls_back_new_bundle(self):
        real_replace = dataset.os.replace
        def fail_manifest(src, dest):
            if Path(src).name == 'manifest.json':
                raise OSError('injected manifest publication failure')
            return real_replace(src, dest)
        with mock.patch.object(dataset.os, 'replace', side_effect=fail_manifest):
            with self.assertRaises(OSError):
                self.build()
        self.assertFalse((self.root / 'output').exists())
        self.assertEqual(list(self.root.glob('.cythsec-features-*')), [])

    def test_bundle_validator_detects_tampering(self):
        self.build()
        bundle = self.root / 'output'
        manifest = json.loads((bundle / 'manifest.json').read_text())
        original_csv = (bundle / 'features.csv').read_text()
        def save_manifest(value):
            (bundle / 'manifest.json').write_text(dataset.canonical_json(value) + '\n')
        for label, mutate in [
            ('wrong contract', lambda m: m['feature_schema'].update(version=999)),
            ('boolean contract version', lambda m: m['feature_schema'].update(version=True)),
            ('float contract dimension', lambda m: m['feature_schema'].update(count=21.0)),
            ('wrong row count', lambda m: m['matrix'].update(rows=2)),
            ('path escape', lambda m: m['matrix'].update(file='../other.csv')),
            ('fake labels', lambda m: m['labels'].update(class_counts={'fake': 1})),
        ]:
            with self.subTest(label=label):
                changed = copy.deepcopy(manifest)
                mutate(changed)
                save_manifest(changed)
                with self.assertRaises(ValueError):
                    dataset.validate_bundle(bundle)
        save_manifest(manifest)
        (bundle / 'features.csv').write_text(original_csv.replace('3.0', '999.0', 1))
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            dataset.validate_bundle(bundle)
        # Rehashing a malformed artifact must not bypass structural validation.
        for mode in ['swapped header', 'duplicate row', 'wrong dimension', 'nonfinite value']:
            with self.subTest(mode=mode):
                rows = list(csv.reader(io.StringIO(original_csv)))
                changed = copy.deepcopy(manifest)
                if mode == 'swapped header':
                    rows[0][-1], rows[0][-2] = rows[0][-2], rows[0][-1]
                elif mode == 'duplicate row':
                    rows.append(rows[1]); changed['matrix']['rows'] = 2
                elif mode == 'wrong dimension':
                    rows[1].pop()
                else:
                    rows[1][-1] = 'NaN'
                stream = io.StringIO()
                csv.writer(stream, lineterminator='\n').writerows(rows)
                (bundle / 'features.csv').write_text(stream.getvalue())
                changed['matrix']['sha256'] = dataset.file_sha256(bundle / 'features.csv')
                save_manifest(changed)
                with self.assertRaises(ValueError):
                    dataset.validate_bundle(bundle)

    def test_cli_build_validate_and_failure_exit_codes(self):
        base = [sys.executable, '-m', 'ml.training.features.dataset']
        result = subprocess.run(base + ['build', '--input', str(self.input), '--output', str(self.root / 'cli'),
                                       '--source-id', 'synthetic-cli', '--format', 'observations'],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(base + ['validate', str(self.root / 'cli')], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.root / 'cli' / 'features.csv').write_text('damaged')
        result = subprocess.run(base + ['validate', str(self.root / 'cli')], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('SHA-256 mismatch', result.stderr)

    def test_exported_observation_vectors_match_the_compiled_rust_fixture_driver(self):
        helpers = runpy.run_path(str(ROOT / 'scripts/verify/check-features.py'))
        cases = helpers['fixtures']()
        rows = []
        for name, samples in cases.items():
            if samples:  # Empty observations are explicitly rejected as training rows.
                rows.append({'schema_version': 1, 'sample_id': name, 'samples': [
                    {'side': s.side, 'payload_len': s.payload_len, 'timestamp_us': s.timestamp_us,
                     'payload_hex': s.payload.hex()} for s in samples]})
        self.write_rows(rows)
        self.build()
        result = subprocess.run(['cargo', 'run', '--offline', '--quiet', '--example', 'feature_vectors'],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        rust = {row['case']: row for row in map(json.loads, result.stdout.splitlines())}
        matrix = self.matrix()
        self.assertEqual(len(matrix), 25)
        for row in matrix:
            for name, expected in zip(FEATURE_NAMES, rust[row['sample_id']]['values']):
                self.assertTrue(math.isclose(float(row[name]), expected, rel_tol=1e-12, abs_tol=1e-9), (row['sample_id'], name))
        print(f'  dataset/Rust parity: {len(matrix)} rows × {len(FEATURE_NAMES)} dimensions = {len(matrix)*len(FEATURE_NAMES)} values')

    def test_real_analyzer_flow_records_export_with_the_same_feature_order(self):
        result = subprocess.run(['cargo', 'run', '--offline', '--quiet', '--bin', 'cythsec-analyze', '--',
                                 '-r', str(ROOT / 'datasets/pcap/sample-session-tcp.pcap'), '-o', str(self.input), '-q'],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in self.input.read_text().splitlines()]
        self.build(input_format='flow-record')
        exported = self.matrix()
        self.assertGreater(len(exported), 0)
        self.assertEqual(len(exported), len(records))
        for record, row in zip(records, exported):
            self.assertEqual(row['sample_id'], str(record['session_id']))
            for name in FEATURE_NAMES:
                self.assertEqual(float(row[name]), float(record['features'][name]))



if __name__ == '__main__':
    unittest.main()
