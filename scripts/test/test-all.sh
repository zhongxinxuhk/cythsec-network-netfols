#!/usr/bin/env bash
# test-all.sh —— cythsec 统一测试脚本（C++ / Rust / Go / 前端四栈）。
#
# 用法：
#   bash scripts/test/test-all.sh            # 跑全部四栈测试
#   bash scripts/test/test-all.sh --go       # 只跑 Go 栈
#   bash scripts/test/test-all.sh --help
#
# 行为：
#   - 逐栈运行测试并汇总；任一栈失败整体以非 0 退出（退出码 = 失败栈数）。
#   - 幂等，可重复执行。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
用法: test-all.sh [--cpp] [--rust] [--go] [--node] [--help]

  --cpp   只跑 C/C++ 测试（ctest）
  --rust  只跑 Rust 测试（cargo test --offline）
  --go    只跑 Go 测试（go test ./...）
  --node  只跑前端测试（npm test = vitest run）
  --help  显示本帮助
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "✗ 工具链缺失: $1" >&2; exit 1; }
}
check_toolchain() {
  need_cmd cmake; need_cmd cargo; need_cmd go; need_cmd node; need_cmd npm
  echo "✓ 工具链可用"
}

test_cpp() {
  echo "==> [cpp] ctest"
  if [[ ! -d build ]]; then
    echo "  (首次无 build 目录，先配置 + 构建)"
    if ! cmake -S . -B build -DCMAKE_BUILD_TYPE=Release; then
      echo "✗ [cpp] 配置失败（dataplane/ 可能正由通信专家并行修改，属预期内）" >&2
      return 1
    fi
    if ! cmake --build build; then
      echo "✗ [cpp] 构建失败（dataplane/ 可能正由通信专家并行修改，属预期内）" >&2
      return 1
    fi
  fi
  if ! ctest --test-dir build --output-on-failure; then
    echo "✗ [cpp] 测试失败" >&2
    return 1
  fi
  echo "✓ [cpp] 测试通过"
}

test_rust() {
  echo "==> [rust] cargo test --offline --workspace"
  if ! cargo test --offline --workspace; then
    echo "✗ [rust] 测试失败" >&2
    return 1
  fi
  echo "✓ [rust] 测试通过"
}

test_go() {
  echo "==> [go] go test ./...（共享包 + 四个服务）"
  local rc=0
  # services/pkg 是共享库（属性字典、响应封装、控制面装配），有测试但原先不在门禁内；
  # 不入门的共享包会把缺陷推迟到「某个服务恰好用到它」时才暴露。
  for svc in pkg routerd policyd dnsd telemetryd; do
    echo "  -> services/$svc"
    # 空壳服务（尚无 Go 包）跳过，不判失败。
    local pkgs
    pkgs="$(cd "services/$svc" && GOWORK=off GOPROXY=off GOTOOLCHAIN=local go list ./... 2>/dev/null)"
    if [[ -z "$pkgs" ]]; then
      echo "    (无 Go 包，跳过)"
      continue
    fi
    if ! (cd "services/$svc" && GOWORK=off GOPROXY=off GOTOOLCHAIN=local go test ./...); then
      echo "✗ [go] services/$svc 测试失败" >&2
      rc=1
    fi
  done
  [[ $rc -eq 0 ]] && echo "✓ [go] 测试通过"
  return $rc
}

test_node() {
  echo "==> [node] web/console: npm ci + npm test"
  if ! (cd web/console && npm ci); then
    echo "✗ [node] npm ci 失败（可能需要网络）" >&2
    return 1
  fi
  if ! (cd web/console && npm test); then
    echo "✗ [node] 测试失败" >&2
    return 1
  fi
  echo "✓ [node] 测试通过"
}

BUILD_CPP=0; BUILD_RUST=0; BUILD_GO=0; BUILD_NODE=0; ALL=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cpp)  BUILD_CPP=1; ALL=0 ;;
    --rust) BUILD_RUST=1; ALL=0 ;;
    --go)   BUILD_GO=1; ALL=0 ;;
    --node) BUILD_NODE=1; ALL=0 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
if [[ $ALL -eq 1 ]]; then
  BUILD_CPP=1; BUILD_RUST=1; BUILD_GO=1; BUILD_NODE=1
fi

check_toolchain

failed=0
[[ $BUILD_CPP -eq 1 ]]   && { test_cpp   || failed=$((failed+1)); }
[[ $BUILD_RUST -eq 1 ]]  && { test_rust  || failed=$((failed+1)); }
[[ $BUILD_GO -eq 1 ]]    && { test_go    || failed=$((failed+1)); }
[[ $BUILD_NODE -eq 1 ]]  && { test_node  || failed=$((failed+1)); }

if [[ $failed -eq 0 ]]; then
  echo "测试汇总：全部通过 ✓"
  exit 0
fi
echo "测试汇总：$failed 个栈失败 ✗" >&2
exit 1
