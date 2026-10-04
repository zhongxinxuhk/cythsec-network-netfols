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
              [--reassembly] [--flows] [--e2e] [--live] [--bench] [--self-test] [--help]

  --cpp          只跑 C/C++ 测试（ctest）
  --rust         只跑 Rust 测试（cargo test --offline）
  --go           只跑 Go 测试（go test ./...）
  --node         只跑前端测试（npm test = vitest run）
  --parity       只跑通道 ABI 跨语言 parity（需同时能构建 C++ 与 Rust）
  --dpi          只跑 DPI 向量的 tshark 第三方交叉核验（需 tshark）
  --reassembly   只跑 TCP 重组向量的 tshark 第三方交叉核验（需 tshark）
  --flows        只跑 FlowRecord 的 tshark 第三方交叉核验 + 反向故障注入（需 tshark）
  --e2e          只跑跨语言共享环端到端（C++ 写 → 环 → Rust 读，需 C++ 与 Rust）
  --live         只跑真实网卡抓包验收（需捕获特权；无特权时显式 SKIPPED 不显绿）
  --bench        只跑数据面基准的回归门禁（CYS-TRF-037）+ 反向故障注入
  --self-test    自证本脚本自身的判定逻辑（npm ci 失败分类 + F1 拦截分支 + 工具链预检映射），不跑任何真实测试
  --help         显示本帮助

不带参数时跑全部；parity 与 e2e 都需要 C++ 与 Rust 两侧都可构建，因此仅在两者都跑时附带执行。

--bench 刻意**不在"全部"里**：它的回归下限标定在特定机器上（Apple M1 Pro/macOS 1M 条规模），
同机连跑两次都能差 20~30%，换机器/换核数/开省电模式都会变。放进默认集合只会变成
"随机红的门禁"，而随机红等于没有门禁。要跑就显式 --bench。
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "✗ 工具链缺失: $1" >&2
    echo "    它只为**本次所选分组**所需；不需要该分组时请只选所需分组（见 --help）" >&2
    exit 1
  }
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
# 本次运行**实际需要**的工具链（纯函数：只读 ${ALL} 与 ${BUILD_*}，因此能被 --self-test 自证）。
#
# 为什么不是"一律要求五个"：在最小化机器上只跑 `--rust` 时，缺 cmake/go/node 与本次运行
# 毫无关系，却会把它挡在门外 —— "选了什么"与"查了什么"不一致。这不是假想问题：
# 2026-10-05 在 2 vCPU / 3GB 的 Rocky Linux aarch64 测试机上 `--rust` 报「工具链缺失: cmake」，
# 而该机当时确实没装 cmake，且**本次运行根本不需要它**。
required_tools() {
  if [[ "${ALL}" == "1" ]]; then
    printf '%s\n' "${PYTHON:-python3}" cargo cmake c++ go node npm tshark
    return 0
  fi
  # 向量生成是 rust/cpp/dpi/reassembly/flows/e2e 的前置（生成器内部再查一次 python3）
  if [[ $((BUILD_RUST + BUILD_CPP + BUILD_DPI + BUILD_REASSEMBLY + BUILD_FLOWS + BUILD_E2E)) -gt 0 ]]; then
    printf '%s\n' "${PYTHON:-python3}"
  fi
  if [[ $((BUILD_RUST + BUILD_PARITY + BUILD_E2E + BUILD_BENCH + BUILD_FLOWS)) -gt 0 ]]; then
    printf 'cargo\n'
  fi
  if [[ $((BUILD_CPP + BUILD_PARITY + BUILD_E2E)) -gt 0 ]]; then
    printf 'cmake\n'
    printf 'c++\n'
  fi
  if [[ ${BUILD_GO} -eq 1 ]]; then
    printf 'go\n'
  fi
  if [[ ${BUILD_NODE} -eq 1 ]]; then
    printf 'node\n'
    printf 'npm\n'
  fi
  if [[ $((BUILD_DPI + BUILD_FLOWS + BUILD_LIVE)) -gt 0 ]]; then
    printf 'tshark\n'
  fi
  return 0
}

check_toolchain() {
  local tool
  while IFS= read -r tool; do
    need_cmd "${tool}"
  done < <(required_tools)
  echo "✓ 工具链可用（本次分组需要：$(required_tools | tr '\n' ' '))"
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

# 把 `npm ci` 的失败输出分成两类。**单独成函数是为了能自证**：写在 if 里就只能靠
# "真的去触发一次批量删除保护"来验证，而那正是我们不想做的事（它要删 7884 个文件）。
# 输入：stdin 上的 npm 输出；输出：ENV_INTERCEPTED 或 REAL_FAILURE。
classify_npm_ci_failure() {
  if grep -q "SAFE_DELETE_BULK_CONFIRM_REQUIRED"; then
    echo "ENV_INTERCEPTED"
  else
    echo "REAL_FAILURE"
  fi
}

test_node() {
  echo "==> [node] web/console: npm ci + npm test"
  # 依赖已在位就不重装：`npm ci` 的第一步是删掉整个 node_modules（含 .bin 下的
  # 全部 shim），在带批量删除保护的环境里会被拦下，而拦截文案容易被误读成
  # 「网络不可达」（见 HANDOFF §7.1）。这里把「环境拦截」与「真失败」分开报。
  #
  # CYTHSEC_FORCE_NPM_CI=1 强制走 npm ci 分支：`--self-test` 用它 + 一个 stub npm
  # 把这条分支真正跑一遍（它此前从未被执行过 —— 本机 node_modules 一直在位）。
  if [[ -x web/console/node_modules/.bin/vitest && "${CYTHSEC_FORCE_NPM_CI:-0}" != "1" ]]; then
    echo "  （node_modules 已就位，跳过 npm ci）"
  else
    local out kind
    if ! out="$(cd web/console && npm ci 2>&1)"; then
      printf '%s\n' "${out}" >&2
      kind="$(printf '%s\n' "${out}" | classify_npm_ci_failure)"
      if [[ "${kind}" == "ENV_INTERCEPTED" ]]; then
        echo "✗ [node] npm ci 被环境拦截（ENV_INTERCEPTED：批量删除保护，未执行；不是网络问题）" >&2
        echo "     node_modules 已在位时本脚本会自动跳过 npm ci；也可单独跑 (cd web/console && npm test)" >&2
      else
        echo "✗ [node] npm ci 真失败（REAL_FAILURE：输出里没有 SAFE_DELETE_BULK_CONFIRM_REQUIRED）" >&2
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

# 自证本脚本**自身的判定逻辑**（--self-test）。不跑任何真实测试：
# 它回答的是"我们用来判定的那段逻辑真的会判吗" —— 尤其包括那条在本机
# **从未被执行过**的 npm ci 环境拦截分支（node_modules 一直在位，所以永远走的是
# "跳过 npm ci"）。一个从不执行的分支，等于一段没人看过的代码。
self_test() {
  echo "==> [self-test] test-all.sh 自身判定逻辑（npm ci 失败分类 + 拦截分支 + 工具链预检映射）"
  local fails=0 got out rc
  # 场景计数**动态累加**：硬编码"4 个场景"在加了两个预检场景后就变成了假信息
  # （数字与实际不符的"通过"提示，比没有提示更糟）。
  local checks=0
  # 用全局名：trap 执行时 local 变量已出作用域，set -u 会把清理变成报错。
  ST_TMP="$(mktemp -d)"
  trap 'rm -rf "${ST_TMP}"' EXIT
  mkdir -p "${ST_TMP}/bin"
  # stub npm：STUB_NPM_CI_TEXT 非空 ⇒ npm ci 失败并原样打印该文本；空 ⇒ ci 成功。
  cat > "${ST_TMP}/bin/npm" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  ci)
    if [[ -n "${STUB_NPM_CI_TEXT:-}" ]]; then
      printf '%s\n' "${STUB_NPM_CI_TEXT}" >&2
      exit 1
    fi
    exit 0 ;;
  test)
    echo "stub npm test：通过"
    exit 0 ;;
esac
exit 0
STUB
  chmod +x "${ST_TMP}/bin/npm"

  # 1. 分类函数（单元级）：拦截标记 → ENV_INTERCEPTED，其余 → REAL_FAILURE
  checks=$((checks+1))
  got="$(printf '%s\n' 'npm error code 1' 'SAFE_DELETE_BULK_CONFIRM_REQUIRED' | classify_npm_ci_failure)"
  if [[ "${got}" == "ENV_INTERCEPTED" ]]; then
    echo "  ✓ 分类：输出含拦截标记 → ENV_INTERCEPTED"
  else
    echo "  ✗ 分类：含拦截标记却得到 ${got}" >&2; fails=$((fails+1))
  fi
  got="$(printf '%s\n' 'npm error network timeout' | classify_npm_ci_failure)"
  if [[ "${got}" == "REAL_FAILURE" ]]; then
    echo "  ✓ 分类：普通失败 → REAL_FAILURE"
  else
    echo "  ✗ 分类：普通失败却得到 ${got}" >&2; fails=$((fails+1))
  fi

  # 2. 拦截分支端到端：必须非 0 退出，且报"环境拦截"而不是"网络"
  checks=$((checks+1))
  rc=0
  out="$(export PATH="${ST_TMP}/bin:${PATH}" CYTHSEC_FORCE_NPM_CI=1
         export STUB_NPM_CI_TEXT='npm error SAFE_DELETE_BULK_CONFIRM_REQUIRED: bulk delete'
         test_node 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]] && printf '%s' "${out}" | grep -q 'ENV_INTERCEPTED'; then
    echo "  ✓ 拦截分支：非 0 退出且报「环境拦截（不是网络问题）」"
  else
    echo "  ✗ 拦截分支未被识别（退出 ${rc}）" >&2; printf '%s\n' "${out}" >&2; fails=$((fails+1))
  fi

  # 3. 工具链预检的**选择映射**：选了什么就只查什么（2026-10-05 在 2 核虚机上撞到的问题）
  checks=$((checks+1))
  local saved_all="${ALL}"
  local saved_flags="${BUILD_CPP}${BUILD_RUST}${BUILD_GO}${BUILD_NODE}${BUILD_PARITY}${BUILD_DPI}${BUILD_REASSEMBLY}${BUILD_FLOWS}${BUILD_E2E}${BUILD_LIVE}${BUILD_BENCH}"
  ALL=0; BUILD_CPP=0; BUILD_RUST=1; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_DPI=0
  BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0
  got="$(required_tools | tr '\n' ' ')"
  # 注意用「空格分词的整词」匹配：直接 grep 'go' 会被 "cargo" 命中（本自证第一次跑就抓到了
  # 这个假阳性 —— 断言写松了，等于没验）。
  if printf '%s' " ${got} " | grep -qE " cargo " \
     && printf '%s' " ${got} " | grep -qE " ${PYTHON:-python3} " \
     && ! printf '%s' " ${got} " | grep -qE ' (cmake|go|node|npm|tshark) '; then
    echo "  ✓ 预检映射：只选 --rust → 只要 cargo + ${PYTHON:-python3}（不要求 cmake/go/node）"
  else
    echo "  ✗ 预检映射：只选 --rust 却要求了「${got}」" >&2; fails=$((fails+1))
  fi

  # 端到端反向注入：在**只有 cargo/python3 替身**的 PATH 下
  #   (a) rust-only 必须通过（缺 cmake 不该挡住它）—— 这条就是本次修复要守的行为；
  #   (b) cpp-only 必须红，且报"工具链缺失: cmake"（改成"全都不查"也会被这条抓住）。
  cat > "${ST_TMP}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  cat > "${ST_TMP}/bin/python3" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  chmod +x "${ST_TMP}/bin/cargo" "${ST_TMP}/bin/python3"
  rc=0
  out="$(ALL=0; BUILD_CPP=0; BUILD_RUST=1; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_DPI=0
         BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0
         export PATH="${ST_TMP}/bin"
         check_toolchain 2>&1)" || rc=$?
  if [[ ${rc} -eq 0 ]]; then
    echo "  ✓ 预检反向注入：PATH 里没有 cmake 时，--rust 仍然通过"
  else
    echo "  ✗ 预检反向注入：PATH 里没有 cmake 就把 --rust 挡住了（退出 ${rc}）" >&2
    printf '%s\n' "${out}" >&2; fails=$((fails+1))
  fi
  rc=0
  out="$(ALL=0; BUILD_CPP=1; BUILD_RUST=0; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_DPI=0
         BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0
         export PATH="${ST_TMP}/bin"
         check_toolchain 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]] && printf '%s' "${out}" | grep -q '工具链缺失: cmake'; then
    echo "  ✓ 预检反向注入：--cpp 时缺 cmake 会被判红并点名"
  else
    echo "  ✗ 预检反向注入：--cpp 缺 cmake 未被判红（退出 ${rc}）" >&2
    printf '%s\n' "${out}" >&2; fails=$((fails+1))
  fi
  ALL="${saved_all}"
  BUILD_CPP="${saved_flags:0:1}"; BUILD_RUST="${saved_flags:1:1}"; BUILD_GO="${saved_flags:2:1}"
  BUILD_NODE="${saved_flags:3:1}"; BUILD_PARITY="${saved_flags:4:1}"; BUILD_DPI="${saved_flags:5:1}"
  BUILD_REASSEMBLY="${saved_flags:6:1}"; BUILD_FLOWS="${saved_flags:7:1}"; BUILD_E2E="${saved_flags:8:1}"
  BUILD_LIVE="${saved_flags:9:1}"; BUILD_BENCH="${saved_flags:10:1}"

  # 4. 真失败分支：同样非 0，但必须报"真失败"，不许拿环境当挡箭牌
  checks=$((checks+1))
  rc=0
  out="$(export PATH="${ST_TMP}/bin:${PATH}" CYTHSEC_FORCE_NPM_CI=1
         export STUB_NPM_CI_TEXT='npm error code EAI_AGAIN'
         test_node 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]] && printf '%s' "${out}" | grep -q 'REAL_FAILURE'; then
    echo "  ✓ 真失败分支：报「真失败」，没拿环境限制冒充"
  else
    echo "  ✗ 真失败分支分类错误（退出 ${rc}）" >&2; printf '%s\n' "${out}" >&2; fails=$((fails+1))
  fi

  # 5. 成功分支：强制走完 npm ci 后仍要继续跑到 npm test（否则"跳过 ci"会变成
  checks=$((checks+1))
  #    "跳过整段前端测试"而门禁全绿）
  rc=0
  out="$(export PATH="${ST_TMP}/bin:${PATH}" CYTHSEC_FORCE_NPM_CI=1
         test_node 2>&1)" || rc=$?
  if [[ ${rc} -eq 0 ]] && printf '%s' "${out}" | grep -q '测试通过'; then
    echo "  ✓ 成功分支：强制走 npm ci 后仍跑到 npm test 并通过"
  else
    echo "  ✗ 成功分支异常（退出 ${rc}）" >&2; printf '%s\n' "${out}" >&2; fails=$((fails+1))
  fi

  if [[ ${fails} -eq 0 ]]; then
    echo "自证通过：${checks} 个场景全部符合预期"
    return 0
  fi
  echo "自证失败：${fails} 个场景不符预期" >&2
  return 1
}

# 跑真实 node 测试之前先自证判定逻辑：判定逻辑坏了的话，后面的「✓ 测试通过」
# 本身也不可信。只挂在 --node 上（被验的就是这一栈的失败分类）。
test_selftest() {
  if ! self_test; then
    echo "✗ [self-test] test-all.sh 自身判定逻辑自证失败" >&2
    return 1
  fi
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

# FlowRecord 的第三方交叉核验（CYS-TRF-005/007/012/027/033/035 的验收口子）。
#
# 前两道 tshark 核验盯的是"解析"与"重组"；这一道盯的是**产出的记录**：
# 会话划分、包数/字节数、方向切换、TCP 末态、发起方、中途接入标记、应用识别。
# 它是整条数据链（decode → flow → session → feature → record）唯一的外部证据 ——
# 前面所有 Rust 单测的期望值都是手写的，只能证明"实现符合我的理解"。
#
# 另外它**默认带反向故障注入**：把每一项各改坏一次，要求核验器报错。
# 没有这一步，"绿色的通过"和"绿色的没跑"完全一样（核验器恒返回成功也会绿灯）。
test_flows() {
  echo "==> [flows] FlowRecord 第三方交叉核验（tshark）+ 反向故障注入"
  local rc=0
  bash scripts/verify/check-flow-records.sh || rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "✓ [flows] 交叉核验通过（含反向故障注入全部被检出）"
    return 0
  fi
  if [[ $rc -eq 3 ]]; then
    echo "⚠ [flows] 未核验：环境缺少 tshark/cargo/python3（该项未执行，不计为通过）" >&2
    return 0
  fi
  echo "✗ [flows] 交叉核验失败" >&2
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

# 数据面基准（CYS-TRF-037）。
#
# 为什么单独一项、且默认不跑：它量的是**吞吐/内存**，阈值必然带机器属性，
# 因此它的回归下限只对本机有意义。它回答两个问题：这一版有没有把上一版跑坏
# （决定退出码），以及现在离需求目标还差多少（只报告）。判定的判定本身也做
# 反向注入：把阈值放大 1000 倍必须报出"退步"。
test_bench() {
  echo "==> [bench] 数据面基准回归门禁（流表/逐出/超时/特征/重组/会话 + 反向故障注入）"
  if ! bash scripts/verify/check-flow-bench.sh; then
    echo "✗ [bench] 基准回归门禁失败" >&2
    return 1
  fi
  echo "✓ [bench] 基准回归门禁通过（需求目标的达成情况见上方输出，未达成项不计为本项失败）"
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
BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0; ALL=1
SELF_TEST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cpp)  BUILD_CPP=1; ALL=0 ;;
    --rust) BUILD_RUST=1; ALL=0 ;;
    --go)   BUILD_GO=1; ALL=0 ;;
    --node) BUILD_NODE=1; ALL=0 ;;
    --parity) BUILD_PARITY=1; ALL=0 ;;
    --dpi) BUILD_DPI=1; ALL=0 ;;
    --reassembly) BUILD_REASSEMBLY=1; ALL=0 ;;
    --flows) BUILD_FLOWS=1; ALL=0 ;;
    --e2e) BUILD_E2E=1; ALL=0 ;;
    --live) BUILD_LIVE=1; ALL=0 ;;
    --bench) BUILD_BENCH=1; ALL=0 ;;
    --self-test) SELF_TEST=1; ALL=0 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
# 自证只验判定逻辑，不碰工具链、不生成向量、不跑任何真实测试。
if [[ ${SELF_TEST} -eq 1 ]]; then
  self_test
  exit $?
fi
if [[ $ALL -eq 1 ]]; then
  BUILD_CPP=1; BUILD_RUST=1; BUILD_GO=1; BUILD_NODE=1; BUILD_PARITY=1; BUILD_DPI=1
  BUILD_REASSEMBLY=1; BUILD_FLOWS=1; BUILD_E2E=1; BUILD_LIVE=1
  # BUILD_BENCH 不进这里：机器相关，见 usage 末尾的说明。
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
if [[ $((BUILD_RUST + BUILD_CPP + BUILD_DPI + BUILD_REASSEMBLY + BUILD_FLOWS + BUILD_E2E)) -gt 0 ]]; then
  gen_datasets || { echo "✗ [vectors] 向量生成失败，后续测试不再执行" >&2; exit 1; }
fi

failed=0
[[ $BUILD_CPP -eq 1 ]]   && { test_cpp   || failed=$((failed+1)); }
[[ $BUILD_RUST -eq 1 ]]  && { test_rust  || failed=$((failed+1)); }
[[ $BUILD_GO -eq 1 ]]    && { test_go    || failed=$((failed+1)); }
[[ $BUILD_NODE -eq 1 ]]  && { test_selftest || failed=$((failed+1)); }
[[ $BUILD_NODE -eq 1 ]]  && { test_node  || failed=$((failed+1)); }
[[ $BUILD_PARITY -eq 1 ]] && { test_parity || failed=$((failed+1)); }
[[ $BUILD_DPI -eq 1 ]]    && { test_dpi    || failed=$((failed+1)); }
[[ $BUILD_REASSEMBLY -eq 1 ]] && { test_reassembly || failed=$((failed+1)); }
[[ $BUILD_FLOWS -eq 1 ]]  && { test_flows   || failed=$((failed+1)); }
[[ $BUILD_E2E -eq 1 ]]   && { test_e2e   || failed=$((failed+1)); }
[[ $BUILD_LIVE -eq 1 ]]  && { test_live  || failed=$((failed+1)); }
[[ $BUILD_BENCH -eq 1 ]] && { test_bench || failed=$((failed+1)); }

if [[ $failed -eq 0 ]]; then
  echo "测试汇总：全部通过 ✓"
  exit 0
fi
echo "测试汇总：$failed 个栈失败 ✗" >&2
exit 1
