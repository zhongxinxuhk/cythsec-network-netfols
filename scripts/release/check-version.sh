#!/usr/bin/env bash
# check-version.sh —— 校验版本号「单一真源」是否成立。
#
# 真源：仓库根 VERSION。
#
# 本脚本区分两类检查，这个区分是刻意的：
#
#   A. 必需副本（语言/工具链强制要求存在字面量，无法派生）
#      - 根 Cargo.toml 的 [workspace.package] version   （Cargo 不支持从文件读版本）
#      - web/console/package.json 的 version            （npm 不支持从文件读版本）
#      - ml/training/pyproject.toml 的 project.version （可独立构建的包元数据）
#      这三处**必须等于** VERSION。
#
#   B. 派生点（应当从 VERSION 派生，不得存在字面量）
#      - dataplane/packet-engine/CMakeLists.txt 的 project(... VERSION ...)
#        由根 CMakeLists 或本目录自行 READ VERSION 后传入
#      - dataplane/traffic-engine/Cargo.toml 的 version
#        走 workspace 继承（version.workspace = true）
#      - Go 四服务：构建期由 -ldflags 注入（scripts/build/build-all.sh）
#      - 前端：config/config.ts 构建期读取根 VERSION
#      这些位置**一旦出现版本字面量即为回归** —— 它意味着又多了一份要手工
#      同步的副本，而「忘了同步」的表现只是版本号悄悄不一致，极难察觉。
#
# 为什么要把 B 类也纳入检查：只校验 A 类（本脚本此前的行为）时，把版本号
# 硬编码回 packet-engine 里是「绿色通行」的 —— 检查器无法阻止真源被架空。
#
# 全部通过退出 0；任一不通过退出 1，并在 stderr 指出具体位置。
set -euo pipefail

SELF="${BASH_SOURCE[0]}"
SELF_TEST=0
case "${1:-}" in
  --self-test) SELF_TEST=1 ;;
  --help|-h)
    cat <<'EOF'
用法: check-version.sh [--self-test]

  （无参数）    校验根 VERSION 与各语言副本/派生点一致
  --self-test   自证：在临时目录里搭一份最小仓库树，注入五处不一致，
                要求检查器分别判红**并指出位置** —— 一个永远不会失败的
                检查器和没有检查器是一回事，绿色的「通过」与绿色的
                「没跑」必须能区分开
EOF
    exit 0
    ;;
  "") ;;
  *) echo "未知参数: ${1}（--help 查看用法）" >&2; exit 2 ;;
esac

# 允许指向另一棵树：只给 --self-test 用（真实运行下就是仓库根）。
ROOT="${CYTHSEC_VERSION_ROOT:-$(cd "$(dirname "${SELF}")/../.." && pwd)}"
cd "$ROOT"

# ---------- 自证（必须在真实检查之前定义并派发）----------
st_ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; }
st_bad() { printf '  \033[31m✗\033[0m %s\n' "$1" >&2; }

# 搭一份最小仓库树：只放检查器真正读的 9 个文件，内容恰好满足全部检查。
build_fixture() {
  local t="$1"
  mkdir -p "${t}/web/console/config" "${t}/dataplane/packet-engine" \
           "${t}/dataplane/traffic-engine" "${t}/scripts/build" "${t}/ml/training"
  printf '0.1.0\n' > "${t}/VERSION"
  printf '[project]\nversion = "0.1.0"\n' > "${t}/ml/training/pyproject.toml"
  printf '[workspace.package]\nversion = "0.1.0"\n' > "${t}/Cargo.toml"
  printf '{\n  "name": "console",\n  "version": "0.1.0"\n}\n' > "${t}/web/console/package.json"
  # 派生自 ${CYTHSEC_VERSION}：既无字面量，又确实引用了真源
  printf 'project(packet-engine LANGUAGES C CXX)\ntarget_compile_definitions(x PRIVATE CYTHSEC_VERSION="${CYTHSEC_VERSION}")\n' \
    > "${t}/dataplane/packet-engine/CMakeLists.txt"
  printf '[package]\nversion.workspace = true\n' > "${t}/dataplane/traffic-engine/Cargo.toml"
  printf '// 注入 CYTHSEC_VERSION\nfn main() { println!("cargo:rustc-env=CYTHSEC_VERSION=0.1.0"); }\n' \
    > "${t}/dataplane/traffic-engine/build.rs"
  printf 'ldflags="-X cythsec/services/pkg/versioninfo.Version=${ver}"\n' \
    > "${t}/scripts/build/build-all.sh"
  printf 'export default { define: { __APP_VERSION__: JSON.stringify(readRootVersion()) } }\n' \
    > "${t}/web/console/config/config.ts"
}

run_self_test() {
  local rc failures=0 out
  # 用全局名：`local` 变量在 trap 执行时已出作用域，set -u 会把清理动作变成报错。
  ST_TMP="$(mktemp -d)"
  trap 'rm -rf "${ST_TMP}"' EXIT
  build_fixture "${ST_TMP}"

  # S1 一致 —— 必须通过（否则自证本身在诬告）
  rc=0
  out="$(CYTHSEC_VERSION_ROOT="${ST_TMP}" bash "${SELF}" 2>&1)" || rc=$?
  if [[ ${rc} -eq 0 ]]; then
    st_ok "S1 一致的最小树 → 退出 0"
  else
    st_bad "S1 一致的最小树却退出 ${rc}（自证诬告，检查器逻辑有误）"
    printf '%s\n' "${out}" >&2
    failures=$((failures+1))
  fi

  # S2 A 类副本漂移：Cargo.toml 改了、VERSION 没改 → 必须判红并点名 Cargo.toml
  printf '[workspace.package]\nversion = "0.2.0"\n' > "${ST_TMP}/Cargo.toml"
  rc=0
  out="$(CYTHSEC_VERSION_ROOT="${ST_TMP}" bash "${SELF}" 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]] && printf '%s' "${out}" | grep -q 'Cargo.toml'; then
    st_ok "S2 注入「Cargo.toml 版本漂移」→ 判红且指出位置"
  else
    st_bad "S2 注入 Cargo.toml 漂移却未被检出（退出 ${rc}）"
    printf '%s\n' "${out}" >&2
    failures=$((failures+1))
  fi
  printf '[workspace.package]\nversion = "0.1.0"\n' > "${ST_TMP}/Cargo.toml"

  # S3 B 类派生点回退成字面量 → 必须判红（这就是 2ecf512 那类回归的样子）
  printf 'project(packet-engine VERSION 9.9.9 LANGUAGES C CXX)\n' \
    > "${ST_TMP}/dataplane/packet-engine/CMakeLists.txt"
  rc=0
  out="$(CYTHSEC_VERSION_ROOT="${ST_TMP}" bash "${SELF}" 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]] && printf '%s' "${out}" | grep -q '硬编码版本'; then
    st_ok "S3 注入「CMakeLists 硬编码 9.9.9」→ 判红且指出位置"
  else
    st_bad "S3 注入硬编码版本却未被检出（退出 ${rc}）"
    printf '%s\n' "${out}" >&2
    failures=$((failures+1))
  fi

  build_fixture "${ST_TMP}" # Restore S3 first; each injection must fail independently.

  # S4 注入实现被删掉（派生点既无字面量也无注入）→ 必须判红，否则「静默失效」无人发现
  : > "${ST_TMP}/dataplane/traffic-engine/build.rs"
  rc=0
  out="$(CYTHSEC_VERSION_ROOT="${ST_TMP}" bash "${SELF}" 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]] && printf '%s' "${out}" | grep -q 'build.rs'; then
    st_ok "S4 注入「版本注入实现被删」→ 判红且指出位置"
  else
    st_bad "S4 注入 build.rs 缺失却未被检出（退出 ${rc}）"
    printf '%s\n' "${out}" >&2
    failures=$((failures+1))
  fi

  # S5/S6: Python metadata drift and missing metadata must both fail explicitly.
  build_fixture "${ST_TMP}"
  printf '[project]\nversion = "9.9.9"\n' > "${ST_TMP}/ml/training/pyproject.toml"
  rc=0
  out="$(CYTHSEC_VERSION_ROOT="${ST_TMP}" bash "${SELF}" 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]] && printf '%s' "${out}" | grep -q 'ml/training/pyproject.toml'; then
    st_ok "S5 Python 包版本漂移 → 判红且指出位置"
  else
    st_bad "S5 Python 包版本漂移未被检出"; failures=$((failures+1))
  fi
  build_fixture "${ST_TMP}"
  rm "${ST_TMP}/ml/training/pyproject.toml"
  rc=0
  out="$(CYTHSEC_VERSION_ROOT="${ST_TMP}" bash "${SELF}" 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]] && printf '%s' "${out}" | grep -q 'ml/training/pyproject.toml'; then
    st_ok "S6 Python 包元数据缺失 → 判红且指出位置"
  else
    st_bad "S6 Python 包元数据缺失未被检出"; failures=$((failures+1))
  fi

  build_fixture "${ST_TMP}"
  printf '// VERSION is mentioned but not injected\nexport default {}\n' > "${ST_TMP}/web/console/config/config.ts"
  rc=0
  out="$(CYTHSEC_VERSION_ROOT="${ST_TMP}" bash "${SELF}" 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]] && printf '%s' "${out}" | grep -q 'web/console/config/config.ts'; then
    st_ok "S7 Umi 版本注入缺失（只有 VERSION 注释）→ 判红且指出位置"
  else
    st_bad "S7 Umi 注入缺失未被检出"; failures=$((failures+1))
  fi

  if [[ ${failures} -eq 0 ]]; then
    echo "自证通过：7 个场景（1 通过 + 6 注入判红）全部符合预期"
    return 0
  fi
  echo "自证失败：${failures} 个场景不符预期 —— 检查器不可信" >&2
  return 1
}

if [[ "${SELF_TEST}" -eq 1 ]]; then
  run_self_test
  exit $?
fi

VER="$(tr -d '[:space:]' < VERSION)"
fail=0

ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { printf '  \033[31m✗\033[0m %s\n' "$1" >&2; fail=1; }

# ---------- 0. 真源本身的合法性 ----------
if [[ -z "$VER" ]]; then
  echo "✗ 根 VERSION 为空 —— 版本真源缺失，无法继续。" >&2
  exit 1
fi
if [[ ! "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "✗ 根 VERSION 不是合法 semver: '${VER}'" >&2
  exit 1
fi
echo "根 VERSION = ${VER}（唯一真源）"
echo

# ---------- A. 必需副本必须与真源一致 ----------
echo "A. 必需副本（工具链强制存在字面量，必须等于真源）"

cargo_ver() { grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/'; }
node_ver() {
  grep -m1 '"version"' web/console/package.json \
    | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
}

check_copy() {
  local name="$1" actual="$2"
  if [[ "$actual" == "$VER" ]]; then
    ok "${name} = ${actual}"
  else
    bad "${name} = '${actual}'，期望 '${VER}'"
  fi
}

check_copy "Cargo.toml [workspace.package].version" "$(cargo_ver)"
check_copy "web/console/package.json version" "$(node_ver)"

python_ver() {
  if [[ ! -f ml/training/pyproject.toml ]]; then
    printf 'missing'
    return
  fi
  awk '/^\[project\]/{project=1; next} /^\[/{project=0}
       project && /^version[[:space:]]*=/{print; exit}' ml/training/pyproject.toml \
    | sed -E 's/.*"([^"]+)".*/\1/'
}
check_copy "ml/training/pyproject.toml project.version" "$(python_ver)"

# ---------- B. 派生点不得存在版本字面量 ----------
echo
echo "B. 派生点（应从真源派生，出现字面量即为回归）"

# B1: packet-engine CMakeLists 的 project() 不得带数字版本
cpp_literal="$(grep -m1 -E '^project\(packet-engine' dataplane/packet-engine/CMakeLists.txt || true)"
if [[ -z "$cpp_literal" ]]; then
  bad "dataplane/packet-engine/CMakeLists.txt 缺少 project(packet-engine ...) 行"
elif [[ "$cpp_literal" =~ VERSION[[:space:]]+[0-9] ]]; then
  bad "packet-engine/CMakeLists.txt 出现硬编码版本: ${cpp_literal}"
else
  ok "packet-engine/CMakeLists.txt 未硬编码版本（派生自 VERSION）"
fi
# 同时确认它确实引用了真源变量或 READ VERSION，避免「既没字面量也没派生」。
if grep -qE 'CYTHSEC_VERSION|/VERSION' dataplane/packet-engine/CMakeLists.txt; then
  ok "packet-engine/CMakeLists.txt 引用了 VERSION 真源"
else
  bad "packet-engine/CMakeLists.txt 既无版本字面量也未引用 VERSION 真源"
fi

# B2: traffic-engine Cargo.toml 必须走 workspace 继承
if grep -qE '^version\.workspace[[:space:]]*=[[:space:]]*true' dataplane/traffic-engine/Cargo.toml; then
  ok "traffic-engine/Cargo.toml 使用 version.workspace = true"
else
  bad "traffic-engine/Cargo.toml 未使用 version.workspace = true（存在版本字面量副本）"
fi

# B3: 版本注入实现齐备（缺任一项即为静默失效）
if [[ -f dataplane/traffic-engine/build.rs ]] \
   && grep -q 'CYTHSEC_VERSION' dataplane/traffic-engine/build.rs; then
  ok "traffic-engine/build.rs 已实现版本注入"
else
  bad "traffic-engine/build.rs 缺失或未注入 CYTHSEC_VERSION"
fi

if grep -q 'versioninfo.Version=' scripts/build/build-all.sh; then
  ok "scripts/build/build-all.sh 已用 -ldflags 注入 Go 版本"
else
  bad "scripts/build/build-all.sh 未注入 Go 版本（-X ...versioninfo.Version）"
fi

if grep -q '__APP_VERSION__.*readRootVersion' web/console/config/config.ts; then
  ok "web/console/config/config.ts 构建期读取 VERSION"
else
  bad "web/console/config/config.ts 未读取 VERSION"
fi

# ---------- 汇总 ----------
echo
if [[ $fail -ne 0 ]]; then
  echo "版本校验失败：请同步上列位置到 ${VER}，或消除 B 类位置的版本字面量。" >&2
  exit 1
fi
echo "版本单一真源校验通过：真源 ${VER}，各端（C++ / Rust / Go / 前端 / Python）均已派生或同步。"
