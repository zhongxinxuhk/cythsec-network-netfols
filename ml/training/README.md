# CythSec training

Python training feature tooling. Current functionality: versioned 21-dimensional
feature extraction and reproducible CSV/manifest bundles. No model training or
evaluation is included yet.

Developer environment: Python 3.11.15 and uv 0.12.1. From the repository root:

```bash
uv sync --project ml/training --locked
uv run --project ml/training --locked cythsec-features --help
```

Installed Python API: `cythsec_training.features.extractor` and
`cythsec_training.features.dataset`. Existing repository imports under
`ml.training.features` remain supported.

Runtime uses only the Python standard library. The exact setuptools build backend
is pinned separately in pyproject.toml; uv.lock records the local project and its
runtime dependency graph. Initial setup may download Python/build tooling; cached
verification uses offline mode and fails explicitly when prerequisites are absent.

See `features/README.md` for input/output contracts and synthetic examples.

## Commands and acceptance

The root `VERSION` is the release version source. Python's required PEP 621
metadata copy is checked by `scripts/release/check-version.sh` (including drift
and missing-file injections). Do not bump only the Python package version.

The lockfile includes the pinned setuptools build group and its archive hashes;
the published package has no third-party runtime dependencies. `uv sync --locked`
checks freshness rather than silently rewriting the lock. Changing dependencies
requires an explicit `uv lock --project ml/training` and review of uv.lock.

```bash
# Initial setup; may fetch the exact Python and build backend.
uv sync --project ml/training --locked
# Normal local packaging verification: requires the cached toolchain, no downloads.
bash scripts/verify/check-training-project.sh
# Initial verification with downloads allowed, if the cache is empty.
bash scripts/verify/check-training-project.sh --online
# Metadata, lock freshness and repository-whitelist rejection tests only.
bash scripts/verify/check-training-project.sh --self-test
```

The check runs on the pinned interpreter, builds an sdist and then a wheel from
that sdist, creates a separate clean environment, installs only that wheel, and
checks imports plus the installed CLI from outside the repository. It exercises
both the positive path and bad version/pin/backend/hash/entry/lock metadata. It
also proves that whitelisting packaging artifacts does not hide real source files.
The pre-commit scan exempts only this project's generated `.venv` dependency
tree; an injected match in real training source is still rejected without
printing the matched value. This boundary is covered by the same self-test.
A missing tool or empty cache is a failure, never a skipped success. The shell
verification entry targets Linux/macOS; wheel portability to other systems has
not been verified in this batch.

The default `scripts/test/test-all.sh` calls this check and requires uv. Selected
legacy groups (for example `--rust`) keep their original tool prerequisites and
feature tests. CI has an independent Python packaging job, so it does not need a
Rust toolchain for installed-package verification.

```bash
# Install/import namespace after sync (editable development install):
ml/training/.venv/bin/python -c 'from cythsec_training.features.dataset import build_bundle'
uv run --project ml/training --locked cythsec-features build \
  --input tests/fixtures/mlt006-observations.jsonl \
  --output build/training-features/installed-project-example \
  --source-id synthetic-installed-project --format observations
```

With the Rust toolchain and generated fixtures available, the existing dataset
suite can also run on this pinned interpreter (18 tests passed in this batch):

```bash
uv run --project ml/training --locked --offline python -m unittest \
  discover -s tests/ml -p test_feature_dataset.py -v
```

Generated environments, egg metadata and build directories are ignored using
paths anchored specifically to this project. Runtime source, lockfiles and pins
remain tracked. Multi-format loaders and models are not included here.

## Python quality gate (MLT-002)

The optional `quality` group pins Ruff 0.17.2, Black 26.10.1 and mypy 2.4.0.
The regular build-only sync remains lean; the quality gate explicitly installs
the locked quality group. After an initial online bootstrap:

```bash
uv sync --project ml/training --locked --group quality
bash scripts/verify/check-python-quality.sh
```

The gate is read-only for source files and defaults to offline mode. `--online`
allows initial downloads; `--self-test` runs real-tool acceptance/rejection
fixtures. It runs from the repository root with an explicit config path, so
configuration discovery cannot silently select a user's defaults.

Ruff/Black cover hand-maintained training code, training tests and the feature,
packaging and quality verifiers (currently 8 files). Black uses 120 columns and
preserves existing quote style. Generated bindings are regenerated and checked,
not hand-formatted. Strict mypy covers the entire runtime package (6 files,
including both generated bindings); JSON decoding boundaries remain explicitly
dynamic and are checked by the existing runtime validators.

Exceptions are narrow: E402 is waived at standalone-script bootstrap imports;
B905 is disabled because `zip(strict=...)` is unavailable to the retained Python
3.9 source entry points. E501 is delegated to Black rather than enforcing a
second, conflicting wrapping rule. No mypy error categories are disabled.

The self-test proves each tool accepts a valid baseline and rejects a specific
fault (unused import, wrong formatting, incompatible return type), then verifies
new-module discovery and C++ inventory isolation from the training `.venv`.
Both lint-all and the default test suite invoke the same gate, as do the lint
workflow and the Python CI job. Do not run separate sync/check processes against
the shared project environment concurrently.

Official configuration references:
[uv project sync](https://docs.astral.sh/uv/concepts/projects/sync/),
[setuptools pyproject configuration](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html),
[uv GitHub Actions integration](https://docs.astral.sh/uv/guides/integration/github/).
