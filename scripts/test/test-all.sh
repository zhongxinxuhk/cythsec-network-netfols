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
              [--reassembly] [--flows] [--ipfix] [--e2e] [--live] [--bench] [--plan] [--sampling] \
              [--columnar] [--branch-policy] [--self-test] [--help]

  --cpp          只跑 C/C++ 测试（ctest）
  --rust         只跑 Rust 测试（cargo test --offline）+ Rust/Python 特征 parity、训练特征产物验收与反向注入
  --go           只跑 Go 测试（go test ./...）
  --node         只跑前端测试（npm test = vitest run）
  --parity       只跑通道 ABI 跨语言 parity（需同时能构建 C++ 与 Rust）
  --dpi          只跑 DPI 向量的 tshark 第三方交叉核验（需 tshark）
  --reassembly   只跑 TCP 重组向量的 tshark 第三方交叉核验（需 tshark）
  --flows        只跑 FlowRecord 的 tshark 第三方交叉核验 + TCP 统计三方比对（CYS-TRF-015）+ 反向故障注入（需 tshark）
  --ipfix        只跑 IPFIX 导出的 tshark 第三方交叉核验 + UDP 通道字节比对 + 反向故障注入（需 tshark）
  --e2e          只跑跨语言共享环端到端（C++ 写 → 环 → Rust 读，需 C++ 与 Rust）
  --live         只跑真实网卡抓包验收（需捕获特权；无特权时显式 SKIPPED 不显绿）
  --bench        只跑数据面基准的回归门禁（CYS-TRF-037）+ 反向故障注入
  --plan         只跑采集容量模型的算术自证 + 反向注入（CYS-INF-040，纯 python3，秒级）
  --sampling     只跑流级采样的两道关口：「声明与执行一致」+「采样后的量级还原」（CYS-TRF-053，需 cargo 与 tshark）
  --columnar     只跑列式落盘（ClickHouse Native）的四道关口：生成物一致 / 独立解码逐格比对 /
                 7 项反向注入 / 真实 ClickHouse 逐字节 parity（CYS-STO-002、CYS-STO-007、CYS-TRF-033，
                 需 cargo + python3；D 组需要 clickhouse 二进制，缺则显式「未核验」）
  --branch-policy 只跑分支纪律钩子的自证与安装状态检查（一个问题一条分支，测绿才并入 main）：
                 pre-commit + Agent 侧 PreToolUse 钩子的 S1–S7 断言与 2 项反向注入（纯 git + python3，秒级）。
                 本克隆没装钩子（core.hooksPath 未设）时显式报「未核验」而不是通过 —— 装法：make hooks
  --self-test    自证本脚本自身的判定逻辑（npm ci 失败分类 + F1 拦截分支 + 工具链预检映射），不跑任何真实测试
  --help         显示本帮助

不带参数时跑全部，含 Python 工程锁定/隔离安装验收（需 uv，先 uv sync --project ml/training --locked）；
可单跑 bash scripts/verify/check-training-project.sh。parity 与 e2e 都需要 C++ 与 Rust 两侧都可构建，因此仅在两者都跑时附带执行。

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
  bash scripts/test/prepare-rust-fixtures.sh || return 1
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
    printf '%s\n' "${PYTHON:-python3}" cargo cmake c++ go node npm tshark git uv
    return 0
  fi
  # 向量生成是 rust/cpp/dpi/reassembly/flows/e2e 的前置（生成器内部再查一次 python3）。
  # --plan 不进这条：容量模型不消费向量（纯算术），要求它下载/生成样本是多余的耦合。
  if [[ $((BUILD_RUST + BUILD_CPP + BUILD_DPI + BUILD_REASSEMBLY + BUILD_FLOWS + BUILD_IPFIX + BUILD_E2E + BUILD_PLAN + BUILD_SAMPLING + BUILD_COLUMNAR)) -gt 0 ]]; then
    printf '%s\n' "${PYTHON:-python3}"
  fi
  if [[ $((BUILD_RUST + BUILD_PARITY + BUILD_E2E + BUILD_BENCH + BUILD_FLOWS + BUILD_IPFIX + BUILD_SAMPLING + BUILD_COLUMNAR)) -gt 0 ]]; then
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
  if [[ $((BUILD_DPI + BUILD_FLOWS + BUILD_IPFIX + BUILD_LIVE + BUILD_SAMPLING)) -gt 0 ]]; then
    printf 'tshark\n'
  fi
  # --branch-policy 只吃 git + python3（钩子读 PreToolUse 的 JSON 用 python3），
  # 刻意不要求任何编译器：它是「流程门禁」，不该因为机器缺 cargo 就退化成未核验。
  # 也只在这一组里要 git —— 把它塞进"所有 rust/cpp 分组都要 git"会让 --rust 在只有
  # cargo/python3 替身的自证场景里假红（本自证第一次跑就抓到了这种过度耦合）。
  if [[ ${BUILD_BRANCH} -eq 1 ]]; then
    printf '%s\n' "${PYTHON:-python3}" git
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
  echo "==> [rust] cargo test --frozen --workspace --all-targets --all-features"
  if ! cargo test --frozen --workspace --all-targets --all-features; then
    echo "✗ [rust] 测试失败" >&2
    return 1
  fi
  if ! cargo test --frozen --workspace --doc --all-features; then
    echo "✗ [rust] 文档测试失败" >&2
    return 1
  fi
  echo "==> [features] Rust/Python 特征契约与逐维向量一致性（含反向注入）"
  if ! bash scripts/verify/check-features.sh; then
    echo "✗ [features] 特征契约或双端数值不一致" >&2
    return 1
  fi
  echo "==> [training-features] 训练特征产物验收（CYS-MLT-006，含 CLI/反向注入/Rust parity）"
  if ! "${PYTHON:-python3}" -m unittest discover -s tests/ml -p 'test_feature_dataset.py' -v; then
    echo "✗ [training-features] 训练特征产物验收失败" >&2
    return 1
  fi
  if ! bash scripts/verify/check-vpn-identification.sh; then
    echo "✗ [vpn-identification] CLI、目录或证据裁决验收失败" >&2
    return 1
  fi
  if ! bash scripts/verify/check-aggregate-observability.sh; then
    echo "✗ [aggregate-observability] 聚合统计或完整性验收失败" >&2
    return 1
  fi
  if ! "${PYTHON:-python3}" tools/codegen/gen-protocol-adaptation.py --check --self-test || ! bash scripts/verify/check-dns-tcp.sh; then
    echo "✗ [protocol-adaptation] 清单或DNS/TCP回归失败" >&2
    return 1
  fi
  if ! bash scripts/verify/check-dhcpv4.sh; then
    echo "✗ [B015] DHCPv4回归失败" >&2
    return 1
  fi
  echo "✓ [rust] 测试通过（含特征 parity、识别 CLI 与独立聚合观测）"
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
  local saved_flags="${BUILD_CPP}${BUILD_RUST}${BUILD_GO}${BUILD_NODE}${BUILD_PARITY}${BUILD_DPI}${BUILD_REASSEMBLY}${BUILD_FLOWS}${BUILD_E2E}${BUILD_LIVE}${BUILD_BENCH}${BUILD_IPFIX}${BUILD_PLAN}${BUILD_SAMPLING}${BUILD_COLUMNAR}${BUILD_BRANCH}"
  ALL=0; BUILD_CPP=0; BUILD_RUST=1; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_DPI=0
  BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0; BUILD_IPFIX=0
  BUILD_PLAN=0; BUILD_SAMPLING=0; BUILD_COLUMNAR=0; BUILD_BRANCH=0
  got="$(required_tools | tr '\n' ' ')"
  # 注意用「空格分词的整词」匹配：直接 grep 'go' 会被 "cargo" 命中（本自证第一次跑就抓到了
  # 这个假阳性 —— 断言写松了，等于没验）。
  if printf '%s' " ${got} " | grep -qE " cargo " \
     && printf '%s' " ${got} " | grep -qE " ${PYTHON:-python3} " \
     && ! printf '%s' " ${got} " | grep -qE ' (cmake|go|node|npm|tshark|uv) '; then
    echo "  ✓ 预检映射：只选 --rust → 只要 cargo + ${PYTHON:-python3}（不要求 cmake/go/node）"
  else
    echo "  ✗ 预检映射：只选 --rust 却要求了「${got}」" >&2; fails=$((fails+1))
  fi

  # 3b. 新增分组的工具链映射：--ipfix 必须要求 cargo + python3 + tshark，且**不**要求 cmake。
  #     这条断言的价值在于：新分组最容易犯的错是"忘了把它接进 required_tools"，
  #     那样的门禁在缺 tshark 的机器上会假装跑过（tshark 缺失时脚本返回 3 = 未核验）。
  checks=$((checks+1))
  ALL=0; BUILD_CPP=0; BUILD_RUST=0; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_DPI=0
  BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0; BUILD_IPFIX=1
  BUILD_PLAN=0; BUILD_SAMPLING=0; BUILD_COLUMNAR=0; BUILD_BRANCH=0
  got="$(required_tools | tr '\n' ' ')"
  if printf '%s' " ${got} " | grep -qE " cargo " \
     && printf '%s' " ${got} " | grep -qE " tshark " \
     && printf '%s' " ${got} " | grep -qE " ${PYTHON:-python3} " \
     && ! printf '%s' " ${got} " | grep -qE ' (cmake|go|node|npm) '; then
    echo "  ✓ 预检映射：只选 --ipfix → 只要 cargo + tshark + ${PYTHON:-python3}"
  else
    echo "  ✗ 预检映射：只选 --ipfix 却要求了「${got}」" >&2; fails=$((fails+1))
  fi

  # 3c. --plan 只该要 python3（容量模型是纯算术，不碰 cargo/tshark/cmake）。
  #     新分组最容易犯的错就是忘了接 required_tools —— 那样它会在缺工具的机器上
  #     假装跑过。这条断言把"该要什么、不该要什么"都钉住。
  checks=$((checks+1))
  ALL=0; BUILD_CPP=0; BUILD_RUST=0; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_DPI=0
  BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0; BUILD_IPFIX=0
  BUILD_PLAN=1
  got="$(required_tools | tr '\n' ' ')"
  if printf '%s' " ${got} " | grep -qE " ${PYTHON:-python3} " \
     && ! printf '%s' " ${got} " | grep -qE ' (cargo|cmake|c\+\+|go|node|npm|tshark) '; then
    echo "  ✓ 预检映射：只选 --plan → 只要 ${PYTHON:-python3}（不要求 cargo/tshark/cmake）"
  else
    echo "  ✗ 预检映射：只选 --plan 却要求了「${got}」" >&2; fails=$((fails+1))
  fi

  # 3d. --sampling（流级采样关口）必须要求 cargo + tshark + python3，且**不**要求 cmake/go/node。
  #     这条断言的价值与 3b 相同：新分组最容易犯的错是"忘了接 required_tools"——那样它会在
  #     缺 tshark 的机器上返回 3（未核验）却被当成"跑过了"。
  checks=$((checks+1))
  ALL=0; BUILD_CPP=0; BUILD_RUST=0; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_DPI=0
  BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0; BUILD_IPFIX=0
  BUILD_PLAN=0; BUILD_SAMPLING=1
  got="$(required_tools | tr '\n' ' ')"
  if printf '%s' " ${got} " | grep -qE " cargo " \
     && printf '%s' " ${got} " | grep -qE " tshark " \
     && printf '%s' " ${got} " | grep -qE " ${PYTHON:-python3} " \
     && ! printf '%s' " ${got} " | grep -qE ' (cmake|go|node|npm) '; then
    echo "  ✓ 预检映射：只选 --sampling → 只要 cargo + tshark + ${PYTHON:-python3}"
  else
    echo "  ✗ 预检映射：只选 --sampling 却要求了「${got}」" >&2; fails=$((fails+1))
  fi

  # 3e. --columnar（列式落盘关口）必须要求 cargo + python3，且**不**要求 cmake/go/node/tshark。
  #     它不需要 tshark：第三方裁判是「独立解码器 + 真实 ClickHouse」，不是 pcap 解析器。
  #     把这一条钉住的价值：将来改 required_tools 时误把它归到 tshark 组，
  #     就会在没装 tshark 的机器上退到「未核验」而被当成跑过了。
  checks=$((checks+1))
  ALL=0; BUILD_CPP=0; BUILD_RUST=0; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_DPI=0
  BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0; BUILD_IPFIX=0
  BUILD_PLAN=0; BUILD_SAMPLING=0; BUILD_COLUMNAR=1; BUILD_BRANCH=0
  got="$(required_tools | tr '\n' ' ')"
  if printf '%s' " ${got} " | grep -qE " cargo " \
     && printf '%s' " ${got} " | grep -qE " ${PYTHON:-python3} " \
     && ! printf '%s' " ${got} " | grep -qE ' (cmake|c\+\+|go|node|npm|tshark) '; then
    echo "  ✓ 预检映射：只选 --columnar → 只要 cargo + ${PYTHON:-python3}（不要求 cmake/tshark）"
  else
    echo "  ✗ 预检映射：只选 --columnar 却要求了「${got}」" >&2; fails=$((fails+1))
  fi

  # 3f. --branch-policy（分支纪律钩子）必须只要求 git + python3，**不**要求编译器/节点/tshark。
  #     它是流程门禁：如果哪天有人把它塞进 cargo 组，缺 cargo 的机器就会把它退成「未核验」
  #     而被当成跑过 —— 那正是本钩子要防的那类事。
  checks=$((checks+1))
  ALL=0; BUILD_CPP=0; BUILD_RUST=0; BUILD_GO=0; BUILD_NODE=0; BUILD_PARITY=0; BUILD_DPI=0
  BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0; BUILD_IPFIX=0
  BUILD_PLAN=0; BUILD_SAMPLING=0; BUILD_COLUMNAR=0; BUILD_BRANCH=1
  got="$(required_tools | tr '\n' ' ')"
  if printf '%s' " ${got} " | grep -qE " git " \
     && printf '%s' " ${got} " | grep -qE " ${PYTHON:-python3} " \
     && ! printf '%s' " ${got} " | grep -qE ' (cmake|c\+\+|go|node|npm|tshark) '; then
    echo "  ✓ 预检映射：只选 --branch-policy → 只要 git + ${PYTHON:-python3}（不要求编译器/tshark）"
  else
    echo "  ✗ 预检映射：只选 --branch-policy 却要求了「${got}」" >&2; fails=$((fails+1))
  fi

  # CYS-MLT-001: the default suite requires uv; selected legacy groups do not.
  checks=$((checks+1))
  ALL=1
  got="$(required_tools | tr '\n' ' ')"
  if printf '%s' " ${got} " | grep -qE ' uv '; then
    echo "  ✓ 预检映射：默认全集要求 uv（Python 工程门禁）"
  else
    echo "  ✗ 默认全集漏查 uv" >&2; fails=$((fails+1))
  fi
  ALL=0

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
         BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0; BUILD_IPFIX=0
         BUILD_PLAN=0; BUILD_SAMPLING=0; BUILD_COLUMNAR=0; BUILD_BRANCH=0
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
         BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0; BUILD_IPFIX=0
         BUILD_PLAN=0; BUILD_SAMPLING=0; BUILD_COLUMNAR=0; BUILD_BRANCH=0
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
  BUILD_LIVE="${saved_flags:9:1}"; BUILD_BENCH="${saved_flags:10:1}"; BUILD_IPFIX="${saved_flags:11:1}"
  BUILD_PLAN="${saved_flags:12:1}"; BUILD_SAMPLING="${saved_flags:13:1}"; BUILD_COLUMNAR="${saved_flags:14:1}"
  BUILD_BRANCH="${saved_flags:15:1}"

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
  if [[ $rc -ne 0 && $rc -ne 3 ]]; then
    echo "✗ [flows] 交叉核验失败" >&2
    return 1
  fi
  local flows_rc=$rc
  # CYS-TRF-015 的 TCP 统计三方比对也在本组：同一条样本链、同一个第三方裁判。
  # 为什么单独成脚本而不是并进 check-flow-records.py：它验的不是“记录字段对不对”，
  # 而是“重传/乱序/RTT 的**定义**与独立实现能否对上”——注入集与失败含义都不同。
  rc=0
  bash scripts/verify/check-tcp-analysis.sh || rc=$?
  if [[ $rc -ne 0 && $rc -ne 3 ]]; then
    echo "✗ [flows] TCP 统计三方比对失败（check-tcp-analysis）" >&2
    return 1
  fi
  if [[ $rc -eq 3 || $flows_rc -eq 3 ]]; then
    echo "⚠ [flows] 未核验：环境缺少 tshark/cargo/python3（该项未执行，不计为通过）" >&2
    return 0
  fi
  echo "✓ [flows] 交叉核验通过（含反向故障注入全部被检出）"
  return 0
}

test_ipfix() {
  echo "==> [ipfix] IPFIX 导出第三方交叉核验（tshark）+ UDP 通道 + 反向故障注入"
  local rc=0
  bash scripts/verify/check-ipfix-export.sh || rc=$?
  if [[ $rc -eq 3 ]]; then
    echo "⚠ [ipfix] 未核验：环境缺少 tshark/cargo/python3（该项未执行，不计为通过）" >&2
    return 0
  fi
  if [[ $rc -ne 0 ]]; then
    echo "✗ [ipfix] 导出交叉核验失败" >&2
    return 1
  fi
  echo "  ✓ 导出侧：tshark 逐字段相符 + UDP 通道字节逐字节相同 + 5 项产物级注入全部被检出"

  # 采集回路（CYS-TRF-054）：导出侧只管"发得出去"，运营商口径考核的是
  # "对端收到多少、丢了多少" —— 这个数只有采集侧能算（RFC 7011 §3.1 序列号缺口）。
  echo "==> [ipfix] IPFIX 采集回路（回环还原 + 导出丢包率可证伪）"
  rc=0
  bash scripts/verify/check-ipfix-collect.sh || rc=$?
  if [[ $rc -eq 3 ]]; then
    echo "⚠ [ipfix] 采集回路未核验：环境缺少 cargo/python3（该项未执行，不计为通过）" >&2
    return 0
  fi
  if [[ $rc -ne 0 ]]; then
    echo "✗ [ipfix] 采集回路核验失败" >&2
    return 1
  fi
  # 异厂导出器互操作（CYS-TRF-054 未达成项 ④ 的离线替代）：前两个关口里，
  # 编码器与采集器**共用同一份模板定义**，定义读错 RFC 时两边会一起错且互相验证通过。
  # 这一道用只读 RFC 写出来的独立实现（模板 ID/字段序/长度/观测域全不同）补上第三方视角。
  echo "==> [ipfix] 异厂导出器互操作（独立实现 → 我们的采集器 + tshark 确认报文合法）"
  rc=0
  bash scripts/verify/check-ipfix-interop.sh || rc=$?
  if [[ $rc -eq 3 ]]; then
    echo "⚠ [ipfix] 异厂互操作未核验：环境缺少 tshark/python3（该项未执行，不计为通过）" >&2
    return 0
  fi
  if [[ $rc -ne 0 ]]; then
    echo "✗ [ipfix] 异厂互操作失败（独立实现的报文没被正确还原）" >&2
    return 1
  fi
  echo "✓ [ipfix] 交叉核验通过（导出：UDP 通道字节比对；采集：丢包率可复算；异厂：5 场景逐条相符；三处注入全部被检出）"
  return 0
}

# 采集容量模型（CYS-INF-040）。
#
# 为什么一份"文档脚本"也要进门禁：容量结论是对外承诺的依据，而**算式会腐烂** ——
# 改一个系数、把采样率漏除、把 ceil 写成 round，报告照样打印得出来、表格照样好看，
# 只有手算的期望值能抓住。故进默认集合（纯 python3、秒级）。
test_plan() {
  echo "==> [plan] 采集容量模型算术自证（CYS-INF-040）"
  if ! "${PYTHON:-python3}" scripts/plan/collector-capacity.py --self-test; then
    echo "✗ [plan] 容量模型自证失败（算式与手算期望值不符）" >&2
    return 1
  fi
  echo "  ✓ 容量模型：手算期望值 + 3 项反向注入均被检出"

  # 落盘字节/记录实测（CYS-INF-041）：把容量表里最后一个假设变成可复算的测量。
  echo "==> [plan] 落盘字节/记录实测脚本自证（CYS-INF-041）"
  if ! "${PYTHON:-python3}" scripts/plan/measure-storage.py --self-test; then
    echo "✗ [plan] 落盘测量脚本自证失败" >&2
    return 1
  fi
  echo "  ✓ 落盘测量：手算字节数 + gzip 往返校验 + 5 项反向注入均被检出"

  # 默认值与测量产物必须同步：只改一处时，"实测"这个词就变成假话。
  if ! "${PYTHON:-python3}" scripts/plan/collector-capacity.py --verify-defaults; then
    echo "✗ [plan] 容量模型默认落盘值与测量产物不一致" >&2
    return 1
  fi
  echo "✓ [plan] 容量模型 + 落盘实测自证通过（含默认值↔产物一致性核对）"
}

# 流级采样（CYS-TRF-053）：**声明（IE 34）与执行必须一致**。
#
# 为什么单独成一组而不是塞进 --flows：它验的不是"报文能不能被第三方解开"，
# 而是"我们声称的采样率是不是真的执行了"。这两件事的失败方式完全不同，
# 混在一起时"tshark 能解"会掩盖"采样的声明是假话"。
test_sampling() {
  # 两道：①"声明与执行一致"（采样的**真伪**）②"量级还原"（采样的**用途**）。
  # 分开跑是因为它们的失败方式不同：①错会让下游把采样当全量，②错会让估计值和区间本身失真。
  local rc=0
  echo "==> [sampling] 流级采样关口（CYS-TRF-053）"
  bash scripts/verify/check-sampling.sh || rc=$?
  if [[ $rc -eq 3 ]]; then
    echo "⚠ [sampling] 未核验：环境缺少 cargo/tshark（该项未执行，不计为通过）" >&2
    return 0
  fi
  [[ $rc -eq 0 ]] || return $rc
  echo "==> [estimate] 采样后的量级还原关口（CYS-TRF-053 ③）"
  bash scripts/verify/check-estimate.sh || rc=$?
  if [[ $rc -eq 3 ]]; then
    echo "⚠ [estimate] 未核验：环境缺少 cargo/tshark（该项未执行，不计为通过）" >&2
    return 0
  fi
  return $rc
}

# 列式落盘（ClickHouse `Native`）关口（CYS-STO-002 / CYS-STO-007 / CYS-TRF-033）。
#
# 为什么必须单独成一组、而且必须进默认集合：编码器与解码器在**同一个 crate** 里，
# 两边一起写错时 `cargo test` 永远全绿（2026-10-19 真实发生过：列头集中写完再写数据，
# 产物总字节与参考实现相同、自家 decode_blocks 照样解得出，而 ClickHouse 拒读）。
# 能裁判这件事的只有独立实现的解码器与真实 ClickHouse，它们都不在 Rust 测试里。
# 另一条教训是关于门禁本身的：`check-columnar.sh` 写完那天并没有被任何脚本调用，
# 「没人执行的检查器等于没有检查器」（同 §VERSION 那次事故）。
test_columnar() {
  local rc=0
  echo "==> [columnar] 列式落盘关口：生成物一致 + 独立解码逐格比对 + 反向注入（CYS-STO-002/007）"
  bash scripts/verify/check-columnar.sh || rc=$?
  if [[ $rc -eq 3 ]]; then
    echo "⚠ [columnar] 未核验：环境缺少 cargo/python3（该项未执行，不计为通过）" >&2
    return 0
  fi
  if [[ $rc -eq 2 ]]; then
    echo "✗ [columnar] 前置样本缺失（向量应由 [vectors] 阶段生成，见上方输出）" >&2
    return 1
  fi
  [[ $rc -eq 0 ]] || return $rc
  # 列式落盘的**字节实测**（CYS-INF-041 收尾）：容量表里「列式能压到几十 B/记录」本来是一个
  # 没人量过的假设。实测本身需要 cargo + clickhouse，不在默认集合里跑（分钟级），
  # 但它的**判定逻辑**（较差端规则 / 小样本不许当容量值 / 没 CODEC 对照就拒答）
  # 是纯 python，跟 measure-storage.py 同样进门禁：脚本烂了时数字仍会印得出来。
  echo "==> [columnar] 列式落盘字节/记录实测脚本自证（CYS-INF-041）"
  if ! "${PYTHON:-python3}" scripts/plan/measure-columnar.py --self-test; then
    echo "✗ [columnar] 列式实测脚本自证失败" >&2
    return 1
  fi
  echo "✓ [columnar] 列式落盘关口通过（A/B/C 全绿 + 实测脚本自证；D 组真实 ClickHouse 的结果见上方，缺参考实现时为「未核验」）"
  return 0
}

# 分支纪律钩子关口：「一个问题一条分支，测绿才并入 main」这条规则**真的在被执行**吗。
#
# 为什么它必须成组、还必须进默认集合：本仓库记过三次同一族的事故（§VERSION 检查器没人调用、
# bench-pipeline.sh 没人调用、check-columnar.sh 入库次日仍没人调用）。这次的风险多一层：
# git 钩子的"存在"与"会被调用"是两件事 —— core.hooksPath 是**本地配置**，不随克隆走，
# 换机器/新克隆时钩子文件还在、但一次都不执行。所以这道关口既自证钩子的判定逻辑（S1–S7 +
# 2 项反向注入），也检查本克隆的安装状态；没装就报「未核验」而不是通过。
test_branch_policy() {
  local rc=0
  echo "==> [branch-policy] 分支纪律钩子自证 + 安装状态（先分支、测绿、再 --no-ff 并入）"
  bash scripts/verify/check-branch-policy.sh || rc=$?
  if [[ $rc -eq 3 ]]; then
    echo "⚠ [branch-policy] 未核验：本克隆未安装钩子（core.hooksPath 未设）→ 规则目前无人执行" >&2
    echo "    装法：make hooks" >&2
    return 0
  fi
  [[ $rc -eq 0 ]] || { echo "✗ [branch-policy] 分支纪律钩子检查失败（退出 ${rc}）" >&2; return 1; }
  echo "✓ [branch-policy] 分支纪律钩子通过（钩子逻辑自证 + 本克隆已安装）"
  return 0
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
BUILD_REASSEMBLY=0; BUILD_FLOWS=0; BUILD_IPFIX=0; BUILD_E2E=0; BUILD_LIVE=0; BUILD_BENCH=0
BUILD_PLAN=0; BUILD_SAMPLING=0; BUILD_COLUMNAR=0; BUILD_BRANCH=0; ALL=1
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
    --ipfix) BUILD_IPFIX=1; ALL=0 ;;
    --e2e) BUILD_E2E=1; ALL=0 ;;
    --live) BUILD_LIVE=1; ALL=0 ;;
    --bench) BUILD_BENCH=1; ALL=0 ;;
    --plan)  BUILD_PLAN=1; ALL=0 ;;
    --sampling) BUILD_SAMPLING=1; ALL=0 ;;
    --columnar) BUILD_COLUMNAR=1; ALL=0 ;;
    --branch-policy) BUILD_BRANCH=1; ALL=0 ;;
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
  BUILD_REASSEMBLY=1; BUILD_FLOWS=1; BUILD_IPFIX=1; BUILD_E2E=1; BUILD_LIVE=1
  # CYS-INF-040 容量模型的算术自证：纯 python3、秒级、无外部工具 ⇒ 没有"随机红"的理由，进默认集合。
  BUILD_PLAN=1
  # CYS-TRF-053 采样关口：需要 cargo + tshark；缺任何一个都会显式「未核验」（退出 3），
  # 所以进默认集合不会造成"随机红"。
  BUILD_SAMPLING=1
  # CYS-STO-002/007 列式落盘关口：需要 cargo + python3；D 组（真实 ClickHouse）缺参考实现时
  # 脚本自己打印「未核验」并退出 0，不会造成随机红。它守的是「我们写的字节别人读不读得对」，
  # 编码器与解码器同仓 ⇒ cargo test 永远全绿，因此这道只能放在外部门禁里。
  BUILD_COLUMNAR=1
  # 分支纪律钩子：纯 git + python3、秒级、无外部工具 ⇒ 没有"随机红"的理由，进默认集合。
  # 它守的正是本仓库最容易腐烂的一类东西：**钩子/检查器装了没有**。core.hooksPath 不随克隆走，
  # 新克隆不跑 `make hooks` 的话，分支纪律一次都不会被执行 —— 本关口会把这种状态显式报成
  # 「未核验」（退出 3），而不是假装绿。
  BUILD_BRANCH=1
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

# Rust / C++ / 两道 tshark 核验 / 列式落盘都要消费向量；Go 与前端不消费。
if [[ $((BUILD_RUST + BUILD_CPP + BUILD_DPI + BUILD_REASSEMBLY + BUILD_FLOWS + BUILD_IPFIX + BUILD_E2E + BUILD_COLUMNAR)) -gt 0 ]]; then
  gen_datasets || { echo "✗ [vectors] 向量生成失败，后续测试不再执行" >&2; exit 1; }
fi

failed=0
[[ $BUILD_CPP -eq 1 ]]   && { test_cpp   || failed=$((failed+1)); }
[[ $BUILD_RUST -eq 1 ]]  && { test_rust  || failed=$((failed+1)); }
# CYS-MLT-001: isolated packaging gate runs in the default suite; standalone entry below.
if [[ ${ALL} -eq 1 ]]; then
  bash scripts/verify/check-dhcpv4.sh --tshark || failed=$((failed+1))
  bash scripts/verify/check-dns-tcp.sh --tshark || failed=$((failed+1))
  bash scripts/verify/check-vpn-identification.sh --tshark || failed=$((failed+1))
  bash scripts/verify/check-aggregate-observability.sh --tshark || failed=$((failed+1))
  bash scripts/verify/check-aggregate-storage.sh || failed=$((failed+1))
  echo "==> [training-project] 锁定环境与隔离安装包验收（CYS-MLT-001）"
  bash scripts/verify/check-training-project.sh || failed=$((failed+1))
  echo "==> [python-quality] 静态检查与故障注入（CYS-MLT-002）"
  bash scripts/verify/check-python-quality.sh || failed=$((failed+1))
fi
[[ $BUILD_GO -eq 1 ]]    && { test_go    || failed=$((failed+1)); }
[[ $BUILD_NODE -eq 1 ]]  && { test_selftest || failed=$((failed+1)); }
[[ $BUILD_NODE -eq 1 ]]  && { test_node  || failed=$((failed+1)); }
[[ $BUILD_PARITY -eq 1 ]] && { test_parity || failed=$((failed+1)); }
[[ $BUILD_DPI -eq 1 ]]    && { test_dpi    || failed=$((failed+1)); }
[[ $BUILD_REASSEMBLY -eq 1 ]] && { test_reassembly || failed=$((failed+1)); }
[[ $BUILD_FLOWS -eq 1 ]]  && { test_flows   || failed=$((failed+1)); }
[[ $BUILD_IPFIX -eq 1 ]]  && { test_ipfix   || failed=$((failed+1)); }
[[ $BUILD_PLAN -eq 1 ]]   && { test_plan    || failed=$((failed+1)); }
[[ $BUILD_SAMPLING -eq 1 ]] && { test_sampling || failed=$((failed+1)); }
[[ $BUILD_COLUMNAR -eq 1 ]] && { test_columnar || failed=$((failed+1)); }
[[ $BUILD_BRANCH -eq 1 ]] && { test_branch_policy || failed=$((failed+1)); }
[[ $BUILD_E2E -eq 1 ]]   && { test_e2e   || failed=$((failed+1)); }
[[ $BUILD_LIVE -eq 1 ]]  && { test_live  || failed=$((failed+1)); }
[[ $BUILD_BENCH -eq 1 ]] && { test_bench || failed=$((failed+1)); }

if [[ $failed -eq 0 ]]; then
  echo "测试汇总：全部通过 ✓"
  exit 0
fi
echo "测试汇总：$failed 个栈失败 ✗" >&2
exit 1
