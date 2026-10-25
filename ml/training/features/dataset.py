"""CYS-MLT-006: reproducible training feature bundles (standard library only).

Installed CLI: cythsec-features --help. Repository entry: python3 -m
ml.training.features.dataset --help (from the repository root).
A bundle is complete only after manifest.json is published and validate_bundle
passes. Labels are explicit annotations, never inferred from DPI or risk fields.
"""
import argparse
from collections import Counter
from contextlib import closing
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile

from .extractor import FeatureVector, FlowSample, extract
from .schema_gen import (FEATURE_COUNT, FEATURE_DEFINITIONS, FEATURE_NAMES,
                         FEATURE_SCHEMA_VERSION, FEATURE_UNITS, SMALL_PACKET_MAX_LEN, idx)

ARTIFACT_VERSION = 1
OBSERVATION_VERSION = 1
SUPPORTED_RECORD_VERSIONS = (2,)
MAX_LINE_BYTES = 16 * 1024 * 1024
METADATA_COLUMNS = ('sample_id', 'first_seen_us', 'last_seen_us')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'duplicate JSON key: {key}')
        result[key] = value
    return result


def _bad_constant(value):
    raise ValueError(f'nonfinite JSON number: {value}')


def strict_json(value):
    return json.loads(value, object_pairs_hook=_unique_keys, parse_constant=_bad_constant)


def _text(value, name):
    require(isinstance(value, str) and bool(value.strip()) and len(value) <= 512,
            f'{name} must be nonempty text of at most 512 characters')
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value), f'{name} contains a control character')
    return value


def _u64(value, name):
    require(type(value) is int and 0 <= value < 2**64, f'{name} must be u64')
    return value


def _objects(path, digest):
    # Hash the exact bytes consumed; do not reopen the source after processing.
    with Path(path).open('rb') as stream:
        line_no = 0
        while True:
            raw = stream.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            line_no += 1
            digest.update(raw)
            require(len(raw) <= MAX_LINE_BYTES, f'{path}:{line_no}: line exceeds {MAX_LINE_BYTES} bytes')
            try:
                require(bool(raw.strip()), 'blank JSONL row')
                obj = strict_json(raw.decode('utf-8'))
                require(isinstance(obj, dict), 'JSONL row must be an object')
                yield obj
            except (ValueError, TypeError, OverflowError) as exc:
                raise ValueError(f'{path}:{line_no}: {exc}') from exc


def contract():
    # Fingerprint the bindings actually used, rather than an unchecked source file.
    return {
        'version': FEATURE_SCHEMA_VERSION,
        'count': FEATURE_COUNT,
        'names': list(FEATURE_NAMES),
        'sha256': hashlib.sha256(canonical_json({
            'version': FEATURE_SCHEMA_VERSION, 'names': FEATURE_NAMES,
            'units': FEATURE_UNITS, 'definitions': FEATURE_DEFINITIONS,
            'small_packet_max_len': SMALL_PACKET_MAX_LEN,
        }).encode('utf-8')).hexdigest(),
    }


def _training_vector(version, values):
    require(all(type(value) in (int, float) for value in values), 'features must be numbers, not strings or booleans')
    vector = FeatureVector(version, tuple(float(value) for value in values))
    require(all(value >= 0 for value in vector.values), 'features must be nonnegative')
    require(vector.values[idx.PACKETS] > 0, 'training row has no observed packets')
    require(0 <= vector.values[idx.FWD_BYTE_RATIO] <= 1 and 0 <= vector.values[idx.SMALL_PACKET_RATIO] <= 1,
            'feature ratios must be in [0,1]')
    require(vector.values[idx.PAYLOAD_ENTROPY_BITS] <= 8 + 1e-12, 'payload entropy exceeds 8 bits/byte')
    return vector


def _observation_row(row):
    require(set(row) == {'schema_version', 'sample_id', 'samples'}, 'observation row keys do not match v1')
    require(type(row['schema_version']) is int and row['schema_version'] == OBSERVATION_VERSION,
            'unsupported observation schema_version')
    sample_id = _text(row['sample_id'], 'sample_id')
    samples = row['samples']
    require(isinstance(samples, list) and bool(samples), 'training row requires a nonempty samples list')
    first = last = None
    def observations():
        nonlocal first, last
        for item in samples:
            require(isinstance(item, dict) and set(item) == {'side', 'payload_len', 'timestamp_us', 'payload_hex'},
                    'sample requires side/payload_len/timestamp_us/payload_hex')
            hex_bytes = item['payload_hex']
            require(isinstance(hex_bytes, str) and len(hex_bytes) % 2 == 0 and
                    re.fullmatch(r'[0-9a-fA-F]*', hex_bytes) is not None, 'payload_hex must be even-length hex')
            sample = FlowSample(item['side'], item['payload_len'], item['timestamp_us'], bytes.fromhex(hex_bytes))
            require(len(sample.payload) <= sample.payload_len, 'captured payload exceeds declared payload_len')
            if first is None:
                first = sample.timestamp_us
            last = sample.timestamp_us if last is None else max(last, sample.timestamp_us)
            yield sample
    vector = extract(observations())
    return sample_id, first, last, _training_vector(vector.schema_version, vector.values)


def _record_row(row):
    require(type(row.get('schema_version')) is int and row['schema_version'] in SUPPORTED_RECORD_VERSIONS,
            'unsupported FlowRecord schema_version (supported: 2)')
    sample_id = str(_u64(row.get('session_id'), 'session_id'))
    time = row.get('time')
    require(isinstance(time, dict), 'FlowRecord requires time')
    first = _u64(time.get('first_seen_us'), 'first_seen_us')
    last = _u64(time.get('last_seen_us'), 'last_seen_us')
    require(last >= first, 'last_seen_us precedes first_seen_us')
    features = row.get('features')
    require(isinstance(features, dict) and set(features) == {'schema_version', *FEATURE_NAMES},
            'FlowRecord features keys differ from the feature contract')
    vector = _training_vector(features['schema_version'], [features[name] for name in FEATURE_NAMES])
    return sample_id, first, last, vector


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def build_bundle(input_path, output_path, *, source_id, input_format, labels_path=None, label_source=None):
    """Write an exclusive CSV+manifest bundle; duplicates and missing/unused labels fail.

    Source rows stream one at a time (16 MiB line limit). Identity and label joins
    use a temporary SQLite index on disk, rather than a dataset-sized Python set.
    The returned manifest is deterministic for the same bytes and configuration.
    """
    source_id = _text(source_id, 'source_id')
    require(input_format in ('observations', 'flow-record'), 'unknown input_format')
    require((labels_path is None) == (label_source is None), 'labels_path and label_source must be provided together')
    if label_source is not None:
        label_source = _text(label_source, 'label_source')
    destination = Path(output_path)
    require(not destination.exists() and not destination.is_symlink(), 'output already exists; choose a new directory')
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_hash, labels_hash = hashlib.sha256(), hashlib.sha256()
    columns = list(METADATA_COLUMNS) + (['label'] if labels_path is not None else []) + list(FEATURE_NAMES)
    with tempfile.TemporaryDirectory(prefix='.cythsec-features-', dir=destination.parent) as tmp:
        stage = Path(tmp)
        with closing(sqlite3.connect(stage / 'index.sqlite')) as index:
            index.execute('CREATE TABLE seen (id TEXT PRIMARY KEY)')
            index.execute('CREATE TABLE labels (id TEXT PRIMARY KEY, label TEXT NOT NULL)')
            if labels_path is not None:
                for row in _objects(labels_path, labels_hash):
                    require(set(row) == {'sample_id', 'label'}, 'label row requires exactly sample_id/label')
                    sample_id = _text(row['sample_id'], 'label sample_id')
                    label = _text(row['label'], 'label')
                    try:
                        index.execute('INSERT INTO labels VALUES (?,?)', (sample_id, label))
                    except sqlite3.IntegrityError as exc:
                        raise ValueError(f'duplicate label for sample_id {sample_id}') from exc
            count = 0
            with (stage / 'features.csv').open('w', encoding='utf-8', newline='') as matrix:
                writer = csv.writer(matrix, lineterminator='\n')
                writer.writerow(columns)
                convert = _observation_row if input_format == 'observations' else _record_row
                for line_no, row in enumerate(_objects(input_path, source_hash), 1):
                    try:
                        sample_id, first, last, vector = convert(row)
                        index.execute('INSERT INTO seen VALUES (?)', (sample_id,))
                    except sqlite3.IntegrityError as exc:
                        raise ValueError(f'{input_path}:{line_no}: duplicate sample_id {sample_id}') from exc
                    except (ValueError, TypeError, OverflowError) as exc:
                        raise ValueError(f'{input_path}:{line_no}: {exc}') from exc
                    metadata = [sample_id, first, last]
                    if labels_path is not None:
                        annotation = index.execute('SELECT label FROM labels WHERE id=?', (sample_id,)).fetchone()
                        require(annotation is not None, f'missing label for sample_id {sample_id}')
                        metadata.append(annotation[0])
                    writer.writerow(metadata + [repr(value) for value in vector.values])
                    count += 1
            require(count > 0, 'input dataset is empty')
            unused = index.execute('SELECT labels.id FROM labels LEFT JOIN seen ON labels.id=seen.id WHERE seen.id IS NULL LIMIT 1').fetchone()
            require(unused is None, f'unused label sample_id: {unused[0] if unused else ""}')
            classes = dict(index.execute('SELECT label,COUNT(*) FROM labels GROUP BY label ORDER BY label'))
        manifest = {
            'artifact_version': ARTIFACT_VERSION,
            'source': {'id': source_id, 'format': input_format, 'sha256': source_hash.hexdigest()},
            'feature_schema': contract(),
            'matrix': {'file': 'features.csv', 'columns': columns, 'rows': count,
                       'sha256': file_sha256(stage / 'features.csv')},
            'labels': {'status': 'provided' if labels_path is not None else 'absent',
                       'source': label_source, 'sha256': labels_hash.hexdigest() if labels_path is not None else None,
                       'class_counts': classes},
        }
        (stage / 'manifest.json').write_text(canonical_json(manifest) + '\n', encoding='utf-8')
        validate_bundle(stage)
        # Reserve the directory exclusively; publish the completion marker last.
        # Readers must validate the manifest before consuming the CSV.
        destination.mkdir()
        try:
            os.replace(stage / 'features.csv', destination / 'features.csv')
            os.replace(stage / 'manifest.json', destination / 'manifest.json')
        except OSError:
            for name in ('manifest.json', 'features.csv'):
                (destination / name).unlink(missing_ok=True)
            destination.rmdir()
            raise
    return manifest


def validate_bundle(directory):
    """Reject incomplete/tampered bundles before a downstream training job reads them."""
    directory = Path(directory)
    manifest = strict_json((directory / 'manifest.json').read_text(encoding='utf-8'))
    require(isinstance(manifest, dict) and set(manifest) == {'artifact_version', 'source', 'feature_schema', 'matrix', 'labels'},
            'invalid bundle manifest keys')
    require(type(manifest['artifact_version']) is int and manifest['artifact_version'] == ARTIFACT_VERSION,
            'unsupported artifact_version')
    require(canonical_json(manifest['feature_schema']) == canonical_json(contract()), 'feature contract mismatch')
    source, matrix, labels = manifest['source'], manifest['matrix'], manifest['labels']
    require(isinstance(source, dict) and source.get('format') in ('observations', 'flow-record'), 'invalid source metadata')
    _text(source.get('id'), 'source id')
    require(isinstance(labels, dict) and labels.get('status') in ('provided', 'absent'), 'invalid label status')
    class_counts = labels.get('class_counts')
    require(isinstance(class_counts, dict) and
            all(isinstance(name, str) and type(count) is int and count > 0 for name, count in class_counts.items()),
            'invalid label class counts')
    labeled = labels['status'] == 'provided'
    if labeled:
        _text(labels.get('source'), 'label source')
    else:
        require(labels.get('source') is None and labels.get('sha256') is None and labels.get('class_counts') == {},
                'unlabeled bundle has label metadata')
    for value in [source.get('sha256')] + ([labels.get('sha256')] if labeled else []):
        require(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None, 'invalid source SHA-256')
    columns = list(METADATA_COLUMNS) + (['label'] if labeled else []) + list(FEATURE_NAMES)
    require(isinstance(matrix, dict) and matrix.get('file') == 'features.csv' and matrix.get('columns') == columns,
            'matrix columns/file mismatch')
    require(type(matrix.get('rows')) is int and matrix['rows'] > 0, 'invalid row count')
    require(matrix.get('sha256') == file_sha256(directory / 'features.csv'), 'matrix SHA-256 mismatch')
    classes, count = Counter(), 0
    # An independent, disk-backed uniqueness check also protects imported bundles.
    with tempfile.TemporaryDirectory(prefix='cythsec-feature-validation-') as tmp:
        with closing(sqlite3.connect(Path(tmp) / 'ids.sqlite')) as index:
            index.execute('CREATE TABLE seen (id TEXT PRIMARY KEY)')
            with (directory / 'features.csv').open(encoding='utf-8', newline='') as stream:
                reader = csv.reader(stream)
                require(next(reader, None) == columns, 'CSV header/order mismatch')
                for row in reader:
                    require(len(row) == len(columns), 'CSV row dimension mismatch')
                    sample_id = _text(row[0], 'sample_id')
                    try:
                        index.execute('INSERT INTO seen VALUES (?)', (sample_id,))
                    except sqlite3.IntegrityError as exc:
                        raise ValueError(f'duplicate CSV sample_id {sample_id}') from exc
                    first, last = _u64(int(row[1]), 'first_seen_us'), _u64(int(row[2]), 'last_seen_us')
                    require(last >= first, 'CSV time interval invalid')
                    if labeled:
                        classes[_text(row[3], 'label')] += 1
                    _training_vector(FEATURE_SCHEMA_VERSION, [float(value) for value in row[len(METADATA_COLUMNS) + int(labeled):]])
                    count += 1
    require(count == matrix['rows'], 'matrix row count mismatch')
    require(dict(classes) == labels.get('class_counts'), 'label counts mismatch')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build', help='build a new CSV + manifest directory')
    build.add_argument('--input', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--source-id', required=True)
    build.add_argument('--format', dest='input_format', choices=('observations', 'flow-record'), required=True)
    build.add_argument('--labels', type=Path)
    build.add_argument('--label-source')
    check = commands.add_parser('validate', help='validate a complete bundle')
    check.add_argument('directory', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'build':
            manifest = build_bundle(args.input, args.output, source_id=args.source_id, input_format=args.input_format,
                                    labels_path=args.labels, label_source=args.label_source)
        else:
            manifest = validate_bundle(args.directory)
        print(canonical_json({'rows': manifest['matrix']['rows'], 'feature_count': FEATURE_COUNT,
                              'labels': manifest['labels']['status']}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, OverflowError, sqlite3.Error, csv.Error) as exc:
        print(f'feature dataset failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
