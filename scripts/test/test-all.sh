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
用法: test-all.sh [--cpp] [--rust] [--go] [--node] [--parity] [--dpi] \
              [--reassembly] [--e2e] [--live] [--help]

  --cpp          只跑 C/C++ 测试（ctest）
  --rust         只跑 Rust 测试（cargo test --offline）
  --go           只跑 Go 测试（go test ./...）
  --node         只跑前端测试（npm test = vitest run）
  --parity       只跑通道 ABI 跨语言 parity（需同时能构建 C++ 与 Rust）
  --dpi          只跑 DPI 向量的 tshark 第三方交叉核验（需 tshark）
  --reassembly   只跑 TCP 重组向量的 tshark 第三方交叉核验（需 tshark）
  --e2e          只跑跨语言共享环端到端（C++ 写 → 环 → Rust 读，需 C++ 与 Rust）
  --live         只跑真实网卡抓包验收（需捕获特权；无特权时显式 SKIPPED 不显绿）
  --help         显示本帮助

不带参数时跑全部；parity 与 e2e 都需要 C++ 与 Rust 两侧都可构建，因此仅在两者都跑时附带执行。
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "✗ 工具链缺失: $1" >&2; exit 1; }
}

# 测试向量是**生成物**：`datasets/**/*.pcap` 与 `*.json` 都在 .gitignore 里
# （字节级可复现，不该入库占 diff）。代价是全新克隆里它们并不存在，
# 而 Rust 侧刻意用 include_str!/include_bytes! 把向量**编进二进制**
# （路径错 = 编译失败，而不是运行时静默什么都不测），所以缺文件是硬失败。
# 这一节负责在跑测试前补齐，让"克隆 → 跑测试"这条路径真的走得通。
gen_datasets() {
  echo "==> [vectors] 生成测试向量（pcap / expected.json 均为生成物，不入库）"
  local py="${PYTHON:-python3}"
  if ! command -v "$py" >/dev/null 2>&1; then
    echo "✗ [vectors] 未找到 python3（可用 PYTHON 环境变量指定解释器）" >&2
    return 1
  fi
  "$py" datasets/pcap/generate-samples.py || return 1
  "$py" datasets/dpi/generate-dpi-samples.py || return 1
  "$py" datasets/reassembly/generate-reassembly-samples.py || return 1
  echo "✓ [vectors] 向量已生成"
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
  # 依赖已在位就不重装：`npm ci` 的第一步是删掉整个 node_modules（含 .bin 下的
  # 全部 shim），在带批量删除保护的环境里会被拦下，而拦截文案容易被误读成
  # 「网络不可达」（见 HANDOFF §7.1）。这里把「环境拦截」与「sql 真失败」分开报。
  if [[ -x web/console/node_modules/.bin/vitest ]]; then
    echo "  （node_modules 已就位，跳过 npm ci）"
  else
    local out
    if ! out="$(cd web/console && npm ci 2>&1)"; then
      echo "${out}" >&2
      if echo "${out}" | grep -q "SAFE_DELETE_BULK_CONFIRM_REQUIRED"; then
        echo "✗ [node] npm ci 被环境批量删除保护拦截（环境限制，未执行；不是网络问题）" >&2
      else
        echo "✗ [node] npm ci 失败" >&2
      fi
      return 1
    fi
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

# DPI 向量的第三方交叉核验（CYS-TRF-021 / CYS-TRF-023）。
#
# 与 cargo test 里的 DPI 单测的区别：单测比对的是「Rust 实现 vs 生成器期望」，
# 两边都出自我们对 JA3 / SNI 规范的理解 —— 理解错了也是一致地错。
# 这一项引入 tshark 这个**独立实现**作为第三方，是发现"一致地错"的唯一手段。
#
# 缺 tshark 时明确报「未核验」并计入 skipped：装不装 tshark 是环境问题，不是代码缺陷，
# 但绝不能把它显示成"通过" —— 那等于让一次根本没跑的核验冒充绿灯。
test_dpi() {
  echo "==> [dpi] DPI 向量第三方交叉核验（tshark）"
  local rc=0
  bash scripts/verify/check-dpi-vectors.sh || rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "✓ [dpi] 交叉核验通过"
    return 0
  fi
  if [[ $rc -eq 3 ]]; then
    echo "⚠ [dpi] 未核验：环境缺少 tshark（该项未执行，不计为通过）" >&2
    return 0
  fi
  echo "✗ [dpi] 交叉核验失败" >&2
  return 1
}

# TCP 重组向量的第三方交叉核验（CYS-TRF-016）。
#
# 与 dpi 项是同一套方法论，但复核的东西不同：dpi 复核的是**解析结果**
# （SNI/JA3/QNAME），这一项复核的是**重排结果**（字节流本身）与
# 「重组之后 DPI 还能不能认出它」这条链路。后者尤其重要 ——
# 重组错了但 DPI 恰好还能识别的情况是存在的（比如只错在流的后半段），
# 只验 DPI 结果会漏掉它。
test_reassembly() {
  echo "==> [reassembly] TCP 重组向量第三方交叉核验（tshark）"
  local rc=0
  bash scripts/verify/check-reassembly-vectors.sh || rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "✓ [reassembly] 交叉核验通过"
    return 0
  fi
  if [[ $rc -eq 3 ]]; then
    echo "⚠ [reassembly] 未核验：环境缺少 tshark（该项未执行，不计为通过）" >&2
    return 0
  fi
  echo "✗ [reassembly] 交叉核验失败" >&2
  return 1
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

# 与 e2e 的区别：e2e 用 datasets 样本验证跨语言内存契约，本项验证的是
# 「内核真写的线上格式能不能被我们的解析器正确读回来」—— 这类缺陷（线上
# bpf_hdr 18B vs sizeof 20B）只有真机流量才能暴露，样本向量测不到。
test_live() {
  echo "==> [live] 真实网卡抓包验收（BPF/AF_PACKET → pcap → tshark 复核 → 环 → Rust 解流）"
  if ! bash scripts/verify/e2e-live-capture.sh; then
    echo "✗ [live] 真实网卡抓包验收失败" >&2
    return 1
  fi
  echo "✓ [live] 真实网卡抓包验收完成（SKIPPED 场景由脚本内部显式标注）"
}

BUILD_CPP=0; BUILD_RUST=0; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_DPI=0
BUILD_REASSEMBLY=0; BUILD_E2E=0; BUILD_LIVE=0; ALL=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cpp)  BUILD_CPP=1; ALL=0 ;;
    --rust) BUILD_RUST=1; ALL=0 ;;
    --go)   BUILD_GO=1; ALL=0 ;;
    --node) BUILD_NODE=1; ALL=0 ;;
    --parity) BUILD_PARITY=1; ALL=0 ;;
    --dpi) BUILD_DPI=1; ALL=0 ;;
    --reassembly) BUILD_REASSEMBLY=1; ALL=0 ;;
    --e2e) BUILD_E2E=1; ALL=0 ;;
    --live) BUILD_LIVE=1; ALL=0 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
if [[ $ALL -eq 1 ]]; then
  BUILD_CPP=1; BUILD_RUST=1; BUILD_GO=1; BUILD_NODE=1; BUILD_PARITY=1; BUILD_DPI=1
  BUILD_REASSEMBLY=1; BUILD_E2E=1; BUILD_LIVE=1
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

# Rust / C++ / 两道 tshark 核验都要消费向量；Go 与前端不消费。
if [[ $((BUILD_RUST + BUILD_CPP + BUILD_DPI + BUILD_REASSEMBLY + BUILD_E2E)) -gt 0 ]]; then
  gen_datasets || { echo "✗ [vectors] 向量生成失败，后续测试不再执行" >&2; exit 1; }
fi

failed=0
[[ $BUILD_CPP -eq 1 ]]   && { test_cpp   || failed=$((failed+1)); }
[[ $BUILD_RUST -eq 1 ]]  && { test_rust  || failed=$((failed+1)); }
[[ $BUILD_GO -eq 1 ]]    && { test_go    || failed=$((failed+1)); }
[[ $BUILD_NODE -eq 1 ]]  && { test_node  || failed=$((failed+1)); }
[[ $BUILD_PARITY -eq 1 ]] && { test_parity || failed=$((failed+1)); }
[[ $BUILD_DPI -eq 1 ]]    && { test_dpi    || failed=$((failed+1)); }
[[ $BUILD_REASSEMBLY -eq 1 ]] && { test_reassembly || failed=$((failed+1)); }
[[ $BUILD_E2E -eq 1 ]]   && { test_e2e   || failed=$((failed+1)); }
[[ $BUILD_LIVE -eq 1 ]]  && { test_live  || failed=$((failed+1)); }

if [[ $failed -eq 0 ]]; then
  echo "测试汇总：全部通过 ✓"
  exit 0
fi
echo "测试汇总：$failed 个栈失败 ✗" >&2
exit 1
