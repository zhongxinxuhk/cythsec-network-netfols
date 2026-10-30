#!/usr/bin/env bash
# package-release.sh —— 构建各模块的可发布包（预发布资产）。
#
# 产物（输出目录默认 dist/release）：
#   cythsec-cpp-<ver>-<os>-<arch>.tar.gz       C++ 采集/解析/ABI/共享环工具
#   cythsec-rust-<ver>-<os>-<arch>.tar.gz      Rust 分析/采集/诊断二进制
#   cythsec-go-<ver>-<os>-<arch>.tar.gz        四个 Go 服务
#   cythsec-console-<ver>.tar.gz               前端生产构建
#   cythsec_training-<ver>-*.whl / *.tar.gz    Python 训练特征包
#   SHA256SUMS                                 以上资产的摘要
#
# 用法：
#   bash scripts/ci/package-release.sh [输出目录]
#   bash scripts/ci/package-release.sh --plan   # 只打印模块/产物名，供工作流契约测试
#
# 退出码：0 成功；1 构建/打包失败；2 参数错误。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ "${1:-}" == "--plan" ]]; then
  printf 'cpp\t%s\n' "cythsec-cpp-${VERSION}-${OS}-${ARCH}.tar.gz"
  printf 'rust\t%s\n' "cythsec-rust-${VERSION}-${OS}-${ARCH}.tar.gz"
  printf 'go\t%s\n' "cythsec-go-${VERSION}-${OS}-${ARCH}.tar.gz"
  printf 'console\t%s\n' "cythsec-console-${VERSION}.tar.gz"
  printf 'training\t%s\n' "cythsec_training-${VERSION}-*.whl"
  exit 0
fi
if [[ $# -gt 1 ]]; then
  echo "用法：$0 [输出目录|--plan]" >&2
  exit 2
fi

OUT="${1:-dist/release}"
rm -rf "$OUT"
mkdir -p "$OUT"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/cythsec-release.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

build_info() {
  local module="$1" dir="$2"
  cat >"$dir/BUILD-INFO.txt" <<INFO
module=${module}
version=${VERSION}
commit=${COMMIT}
built_at=${BUILT_AT}
target=${OS}-${ARCH}
INFO
}

require_file() {
  [[ -f "$1" ]] || { echo "✗ 缺少构建产物：$1" >&2; exit 1; }
}

echo "==> [cpp] 配置并构建 Release"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel "${JOBS:-2}"
mkdir -p "$STAGE/cpp/bin"
for bin in cythsec-capture cythsec-parse cythsec-dump-abi cythsec-ring-feed; do
  src="build/dataplane/packet-engine/${bin}"
  require_file "$src"
  cp "$src" "$STAGE/cpp/bin/"
done
cp VERSION "$STAGE/cpp/"
[[ -f README.md ]] && cp README.md "$STAGE/cpp/"
build_info cpp "$STAGE/cpp"
tar -C "$STAGE/cpp" -czf "$OUT/cythsec-cpp-${VERSION}-${OS}-${ARCH}.tar.gz" .
echo "  ✓ C++ 包：4 个二进制"

echo "==> [rust] cargo build --release"
cargo build --offline --release --workspace
mkdir -p "$STAGE/rust/bin"
rust_bins=(
  traffic-engine dump-abi ring-consume cythsec-analyze cythsec-ipfix-collect
  cythsec-netflow9-collect cythsec-bench cythsec-dump-ddl cythsec-identify cythsec-observe
)
for bin in "${rust_bins[@]}"; do
  if [[ -x "target/release/${bin}" ]]; then
    cp "target/release/${bin}" "$STAGE/rust/bin/"
  fi
done
require_file "$STAGE/rust/bin/cythsec-analyze"
cp VERSION "$STAGE/rust/"
build_info rust "$STAGE/rust"
tar -C "$STAGE/rust" -czf "$OUT/cythsec-rust-${VERSION}-${OS}-${ARCH}.tar.gz" .
echo "  ✓ Rust 包：$(find "$STAGE/rust/bin" -type f | wc -l | tr -d ' ') 个二进制"

echo "==> [go] 构建四个服务"
bash scripts/build/build-all.sh --go
mkdir -p "$STAGE/go/bin"
for svc in routerd policyd dnsd telemetryd; do
  require_file "build/bin/${svc}"
  cp "build/bin/${svc}" "$STAGE/go/bin/"
done
cp VERSION "$STAGE/go/"
build_info go "$STAGE/go"
tar -C "$STAGE/go" -czf "$OUT/cythsec-go-${VERSION}-${OS}-${ARCH}.tar.gz" .
echo "  ✓ Go 包：4 个服务"

echo "==> [console] 前端生产构建"
bash scripts/build/build-all.sh --node
mkdir -p "$STAGE/console"
cp -R web/console/dist/. "$STAGE/console/"
cp VERSION "$STAGE/console/"
build_info console "$STAGE/console"
tar -C "$STAGE/console" --exclude=.DS_Store -czf "$OUT/cythsec-console-${VERSION}.tar.gz" .
echo "  ✓ 前端包：web/console/dist"

echo "==> [training] Python wheel/sdist"
command -v uv >/dev/null 2>&1 || { echo "✗ 缺少 uv：无法构建 Python 包" >&2; exit 1; }
uv build --project ml/training --out-dir "$OUT"
echo "  ✓ Python 包：$(find "$OUT" -maxdepth 1 -name 'cythsec_training-*' | wc -l | tr -d ' ') 个"

(
  cd "$OUT"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum ./*.tar.gz ./*.whl >SHA256SUMS 2>/dev/null || true
  else
    shasum -a 256 ./*.tar.gz ./*.whl >SHA256SUMS 2>/dev/null || true
  fi
)

echo "==> 产物清单（${OUT}）"
ls -lh "$OUT"
echo "✓ 各模块发布包已生成（version=${VERSION} commit=${COMMIT} target=${OS}-${ARCH}）"
