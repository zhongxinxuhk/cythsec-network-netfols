#!/usr/bin/env bash
# test-all.sh —— cythsec 统一测试脚本（C++ / Rust / Go / 前端 四栈 + 通道 ABI parity + 跨语言 e2e）。
#
# 用法：
#   bash scripts/test/test-all.sh            # 跑全部
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
用法: test-all.sh [--cpp] [--rust] [--go] [--node] [--parity] [--e2e] [--help]

  --cpp     只跑 C/C++ 测试（ctest）
  --rust    只跑 Rust 测试（cargo test --offline）
  --go      只跑 Go 测试（go test ./...）
  --node    只跑前端测试（npm test = vitest run）
  --parity  只跑通道 ABI 跨语言 parity（需同时能构建 C++ 与 Rust）
  --e2e     只跑跨语言共享环端到端（C++ 写 → 环 → Rust 读，需 C++ 与 Rust）
  --help    显示本帮助

不带参数时跑全部；parity 与 e2e 都需要 C++ 与 Rust 两侧都可构建，因此仅在两者都跑时附带执行。
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
  echo "==> [cpp] cmake 配置 + 构建 + ctest"
  # 每次都必须重新配置并重新构建，不能只在「目录不存在」时做：
  #   - 不重新配置：新增目标后构建系统里没有它，ctest 会报 "Unable to find
  #     executable" / "Not Run" —— 那句话完全指不到「配置过期」这个真实原因；
  #   - 不重新构建：只跑 ctest 会拿**上一次构建的产物**去验当前源码，本地绿灯
  #     而实际验的是旧二进制。两条都是增量操作，代价可忽略。
  if ! cmake -S . -B build -DCMAKE_BUILD_TYPE=Release; then
    echo "✗ [cpp] 配置失败（dataplane/ 可能正由通信专家并行修改，属预期内）" >&2
    return 1
  fi
  if ! cmake --build build --parallel; then
    echo "✗ [cpp] 构建失败（dataplane/ 可能正由通信专家并行修改，属预期内）" >&2
    return 1
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

# 通道 ABI 跨语言 parity（CYS-PKT-024 第 3 层）。
#
# 为什么放在测试栈而不是 lint 栈：它需要**真实构建**两端的可执行产物 —— 校验的对象
# 是编译出来的取值，不是源码文本。放在 lint 里会让静态检查依赖编译器，语义错位。
test_parity() {
  echo "==> [parity] 通道 ABI 跨语言一致性"
  if ! bash scripts/verify/check-channel-parity.sh; then
    echo "✗ [parity] 两端通道 ABI 不一致" >&2
    return 1
  fi
  echo "✓ [parity] 通道 ABI 两端一致"
}

# 跨语言共享环端到端（CYS-TRF-034）。
#
# 与 parity 的区别：parity 比的是**契约取值**（两端对同一份 ABI 的常量理解是否一致），
# 本项比的是**运行行为**（C++ 进程写进去的报文，Rust 进程能不能正确读出来并解成流）。
# 两者不可互替：契约取值全对，仍可能因为写序、索引算术、偏移语义而读不到数据。
test_e2e() {
  echo "==> [e2e] 跨语言共享环端到端（C++ 生产端 → 环 → Rust 消费端）"
  if ! bash scripts/verify/e2e-shared-ring.sh; then
    echo "✗ [e2e] 跨语言端到端失败" >&2
    return 1
  fi
  echo "✓ [e2e] 跨语言端到端通过"
}

BUILD_CPP=0; BUILD_RUST=0; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_E2E=0; ALL=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cpp)  BUILD_CPP=1; ALL=0 ;;
    --rust) BUILD_RUST=1; ALL=0 ;;
    --go)   BUILD_GO=1; ALL=0 ;;
    --node) BUILD_NODE=1; ALL=0 ;;
    --parity) BUILD_PARITY=1; ALL=0 ;;
    --e2e) BUILD_E2E=1; ALL=0 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
if [[ $ALL -eq 1 ]]; then
  BUILD_CPP=1; BUILD_RUST=1; BUILD_GO=1; BUILD_NODE=1; BUILD_PARITY=1; BUILD_E2E=1
fi
# parity 与 e2e 都依赖两侧都能构建：只选了其一却要跑，是用法错误而非失败，
# 明确报错比静默跳过好 —— 静默跳过会让人以为验过了。
for pair in "parity:${BUILD_PARITY}" "e2e:${BUILD_E2E}"; do
  name="${pair%%:*}"; on="${pair##*:}"
  if [[ "${on}" -eq 1 && ( $BUILD_CPP -eq 0 || $BUILD_RUST -eq 0 ) ]]; then
    echo "✗ [${name}] 需要同时选中 --cpp 与 --rust（该项校验的是两端产物/进程）" >&2
    exit 2
  fi
done

check_toolchain

failed=0
[[ $BUILD_CPP -eq 1 ]]   && { test_cpp   || failed=$((failed+1)); }
[[ $BUILD_RUST -eq 1 ]]  && { test_rust  || failed=$((failed+1)); }
[[ $BUILD_GO -eq 1 ]]    && { test_go    || failed=$((failed+1)); }
[[ $BUILD_NODE -eq 1 ]]  && { test_node  || failed=$((failed+1)); }
[[ $BUILD_PARITY -eq 1 ]] && { test_parity || failed=$((failed+1)); }
[[ $BUILD_E2E -eq 1 ]]   && { test_e2e   || failed=$((failed+1)); }

if [[ $failed -eq 0 ]]; then
  echo "测试汇总：全部通过 ✓"
  exit 0
fi
echo "测试汇总：$failed 个栈失败 ✗" >&2
exit 1
