#!/usr/bin/env bash
# build-all.sh —— cythsec 统一构建脚本（C++ / Rust / Go / 前端四栈）。
#
# 用法：
#   bash scripts/build/build-all.sh              # 构建全部四栈
#   bash scripts/build/build-all.sh --cpp        # 只构建 C++ 栈
#   bash scripts/build/build-all.sh --rust --go # 构建多个指定栈
#   bash scripts/build/build-all.sh --help       # 查看帮助
#
# 行为：
#   - 开头做工具链版本预检（cmake≥3.20 / cargo / go≥1.22 / node≥22.12（或 ≥24）），不足则可读报错并退出。
#   - 任一栈失败不影响其它栈继续；结尾汇总，整体以「失败栈数」为退出码（全成功=0）。
#   - 幂等，可重复执行。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
用法: build-all.sh [--cpp] [--rust] [--go] [--node] [--help]

  --cpp    只构建 C/C++ 栈（CMake）
  --rust   只构建 Rust 栈（cargo, --offline）
  --go     只构建 Go 服务（routerd/policyd/dnsd/telemetryd）
  --node   只构建前端（web/console: npm ci + vite build）
  --help   显示本帮助

不带参数则构建全部四栈。
EOF
}

# ---------- 工具链版本预检 ----------
ver_ge() {
  # ver_ge <have> <min>：have >= min 返回 0
  local have="$1" min="$2"
  local smallest
  smallest="$(printf '%s\n%s\n' "$have" "$min" | sort -V | head -1)"
  [[ "$smallest" == "$min" ]]
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "✗ 工具链缺失: $1（请先安装）" >&2
    exit 1
  }
}

check_toolchain() {
  need_cmd cmake
  need_cmd cargo
  need_cmd go
  need_cmd node
  need_cmd npm

  local cmake_ver go_ver node_ver
  cmake_ver="$(cmake --version | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
  go_ver="$(go version | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
  node_ver="$(node --version | tr -d 'v')"

  local ok=1
  # 变量引用一律加花括号：macOS bash 3.2 会把紧跟 $VAR 的多字节字符并入变量名，
  # 在 set -u 下直接报 unbound variable 并中断（即在最需要提示时反而失去提示）。
  ver_ge "$cmake_ver" "3.20" || { echo "✗ cmake 版本过低: ${cmake_ver}（要求 ≥ 3.20）" >&2; ok=0; }
  ver_ge "$go_ver" "1.22" || { echo "✗ go 版本过低: ${go_ver}（要求 ≥ 1.22）" >&2; ok=0; }
  ver_ge "$node_ver" "22.12.0" && [[ "${node_ver%%.*}" != "23" ]] || { echo "✗ node 版本不满足前端要求: ${node_ver}（要求 ^22.12.0 或 ≥24；CI 版本见 .node-version）" >&2; ok=0; }
  if [[ $ok -eq 0 ]]; then
    echo "工具链预检未通过，终止构建。" >&2
    exit 1
  fi
  echo "✓ 工具链预检通过 (cmake $cmake_ver / go $go_ver / node $node_ver / cargo $(cargo --version | grep -oE '[0-9]+\.[0-9]+' | head -1))"
}

# ---------- 各栈构建 ----------
build_cpp() {
  echo "==> [cpp] CMake 配置并构建"
  if ! cmake -S . -B build -DCMAKE_BUILD_TYPE=Release; then
    echo "✗ [cpp] cmake 配置失败" >&2
    return 1
  fi
  if ! cmake --build build; then
    echo "✗ [cpp] 编译失败" >&2
    return 1
  fi
  echo "✓ [cpp] 构建完成"
}

build_rust() {
  echo "==> [rust] cargo build --offline --workspace"
  if ! cargo build --offline --workspace; then
    echo "✗ [rust] 构建失败（检查 Cargo 离线缓存 / 网络）" >&2
    return 1
  fi
  echo "✓ [rust] 构建完成"
}

build_go() {
  echo "==> [go] 构建四个 Go 服务"
  local ver commit build_time
  ver="$(tr -d '[:space:]' < VERSION)"
  # commit 取 git 短哈希；非 git 工作树（如源码包解压）回落 unknown，不阻断构建。
  commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # 注入点必须写全包路径。此前此处写的是 `-X main.version=$ver`，
  # 而版本变量实际位于共享包 cythsec/services/pkg/versioninfo ——
  # Go 链接器对不存在的符号**静默忽略**（构建照常成功、版本号却始终为空），
  # 属于典型的假绿：脚本报告成功，`-version` 却打印 dev。
  local ldflags="-X cythsec/services/pkg/versioninfo.Version=${ver}"
  ldflags="${ldflags} -X cythsec/services/pkg/versioninfo.Commit=${commit}"
  ldflags="${ldflags} -X cythsec/services/pkg/versioninfo.BuildTime=${build_time}"

  local rc=0
  # 第一轮：全包编译校验（不产出二进制，快速暴露编译错误）。
  for svc in routerd policyd dnsd telemetryd; do
    echo "  -> services/${svc}"
    if ! (cd "services/${svc}" && GOWORK=off GOPROXY=off GOTOOLCHAIN=local \
          go build ./...); then
      echo "✗ [go] services/${svc} 构建失败" >&2
      rc=1
    fi
  done
  [[ $rc -ne 0 ]] && return $rc

  # 第二轮：产出四个可执行文件，并注入版本信息。
  #
  # 输出到 build/bin/ 而非 build/ 本身：build/ 同时是 CMake 的构建目录
  # （build_cpp 用 `cmake -S . -B build`），两者混放会让 CMake 生成的
  # CMakeCache/Makefile 与自研二进制纠缠在一起，且一旦将来出现同名 CMake
  # 目标就会互相覆盖。分开一层目录是最低成本的隔离。
  mkdir -p build/bin
  for svc in routerd policyd dnsd telemetryd; do
    if ! (cd "services/${svc}" && GOWORK=off GOPROXY=off GOTOOLCHAIN=local \
          go build -ldflags "${ldflags}" -o "../../build/bin/${svc}" "./cmd/${svc}"); then
      echo "✗ [go] services/${svc} 二进制构建失败" >&2
      rc=1
    fi
  done
  if [[ $rc -eq 0 ]]; then
    echo "✓ [go] 四个二进制已生成 build/bin/{routerd,policyd,dnsd,telemetryd}"
    echo "        version=${ver} commit=${commit} build_time=${build_time}"
  fi
  return $rc
}

build_node() {
  echo "==> [node] web/console: npm ci + vite build"
  if ! (cd web/console && npm ci); then
    echo "✗ [node] npm ci 失败（可能需要网络或 npm registry 缓存）" >&2
    return 1
  fi
  if ! (cd web/console && npm run build); then
    echo "✗ [node] vite build 失败" >&2
    return 1
  fi
  echo "✓ [node] 构建完成"
}

# ---------- 参数解析 ----------
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
[[ $BUILD_CPP -eq 1 ]]   && { build_cpp   || failed=$((failed+1)); }
[[ $BUILD_RUST -eq 1 ]]  && { build_rust  || failed=$((failed+1)); }
[[ $BUILD_GO -eq 1 ]]    && { build_go    || failed=$((failed+1)); }
[[ $BUILD_NODE -eq 1 ]]  && { build_node  || failed=$((failed+1)); }

if [[ $failed -eq 0 ]]; then
  echo "构建汇总：全部成功 ✓"
  exit 0
fi
echo "构建汇总：$failed 个栈失败 ✗" >&2
exit 1
