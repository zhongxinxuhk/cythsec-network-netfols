#!/usr/bin/env bash
# CI only packages the exact revision after all mandatory tests; no deployment or tag creation.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { echo 'Linux x86_64 runner required' >&2; exit 2; }
test -f build/release/web/index.html
for binary in routerd policyd dnsd telemetryd cythsec-ch-write; do test -f "build/bin/${binary}"; done
cmake -S . -B build/package-cpp -DCMAKE_BUILD_TYPE=Release
cmake --build build/package-cpp --parallel 2
bash scripts/test/prepare-rust-fixtures.sh
cargo build --frozen --release --workspace --bins
PACKAGE_DIR="$(mktemp -d "${ROOT}/build/release/package.XXXXXX")"
trap 'rm -rf "${PACKAGE_DIR}"' EXIT
mkdir -p "${PACKAGE_DIR}/bin" "${PACKAGE_DIR}/web" "${PACKAGE_DIR}/storage" "${PACKAGE_DIR}/configs"
for binary in routerd policyd dnsd telemetryd cythsec-ch-write; do
  cp "build/bin/${binary}" "${PACKAGE_DIR}/bin/"
done
for binary in cythsec-capture cythsec-parse cythsec-dump-abi cythsec-ring-feed; do
  cp "build/package-cpp/dataplane/packet-engine/${binary}" "${PACKAGE_DIR}/bin/"
done
for binary in traffic-engine cythsec-analyze cythsec-ipfix-collect cythsec-bench cythsec-dump-ddl cythsec-identify cythsec-observe dump-abi ring-consume; do
  cp "target/release/${binary}" "${PACKAGE_DIR}/bin/"
done
chmod +x "${PACKAGE_DIR}"/bin/*
cp -R build/release/web/. "${PACKAGE_DIR}/web/"
cp -R configs/. "${PACKAGE_DIR}/configs/"
cp -R storage/clickhouse "${PACKAGE_DIR}/storage/"
cp VERSION LICENSE README.md "${PACKAGE_DIR}/"
export PACKAGE_DIR
python3 - <<'PY'
import json, os, pathlib, subprocess
root = pathlib.Path(os.environ['PACKAGE_DIR'])
manifest = {'version': pathlib.Path('VERSION').read_text().strip(),
            'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            'target': 'linux-amd64', 'toolchains': {name: subprocess.check_output(cmd, text=True).splitlines()[0] for name, cmd in [('rust', ['rustc','--version']), ('go', ['go','version']), ('cmake', ['cmake','--version'])]}, 'files': sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file())}
pathlib.Path('build/release/manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
(root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
tar -czf build/release/cythsec-linux-amd64.tar.gz -C "${PACKAGE_DIR}" .
(cd build/release && sha256sum cythsec-linux-amd64.tar.gz manifest.json > SHA256SUMS && sha256sum --check SHA256SUMS)
