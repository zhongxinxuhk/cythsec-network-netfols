#!/usr/bin/env bash
# lint-all.sh —— cythsec 统一静态检查（C++ clang-format / Rust cargo fmt / Go gofmt / 前端 eslint）。
# 只检查、不修改；发现问题则以非 0 退出。CI 的 lint.yml 直接调用本脚本。
#
# 用法：bash scripts/lint/lint-all.sh [--help]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

usage() { cat <<'EOF'
用法: lint-all.sh

  依次运行：
    - clang-format --dry-run --Werror（C/C++，基于仓库 .clang-format）
    - cargo fmt --all -- --check（Rust）
    - gofmt -l（Go，services/ 下）
    - 属性字典生成物一致性（scripts/verify/check-attributes.sh）
    - 通道 ABI 双端契约一致性（scripts/verify/check-channel-abi.sh）
    - 版本单一真源一致性 + 检查器自证（scripts/release/check-version.sh [--self-test]）
    - 有没有源码被 .gitignore 静默忽略（scripts/verify/check-ignored-sources.sh）
    - 前端类型检查（web/console：src/tests + 构建配置两份 tsconfig）
    - npm run lint（前端 eslint，web/console）
  任一检查未通过则整体非 0 退出。
EOF
}
[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && { usage; exit 0; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "✗ 工具链缺失: $1" >&2; exit 1; }; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
need_cmd cargo; need_cmd go; need_cmd node; need_cmd npm

failed=0

# ---------- C++ : clang-format ----------
echo "==> [cpp] clang-format --dry-run --Werror"
# clang-format 常随 Xcode CommandLineTools 一同安装，但**不在 PATH 上**；仅用
# `command -v clang-format` 会把它误判为「未安装」并静默跳过门禁 —— 制造「本地绿灯、
# CI 红灯」的假象（历史事故：29/30 个 C++ 文件不合规却从未被本地检查到）。
# 故显式探测常见安装位置，并把「找不到工具」视为门禁失败而非跳过。
CF_BIN=""
for cand in clang-format \
            /Library/Developer/CommandLineTools/usr/bin/clang-format \
            /opt/homebrew/bin/clang-format \
            /usr/local/bin/clang-format \
            /usr/bin/clang-format; do
  if command -v "$cand" >/dev/null 2>&1; then
    CF_BIN="$(command -v "$cand")"
    break
  fi
done
if [[ -z "$CF_BIN" ]]; then
  echo "✗ [cpp] 未找到 clang-format，无法验证 C/C++ 格式" >&2
  echo "     安装：brew install clang-format（或安装 Xcode CommandLineTools）" >&2
  failed=$((failed+1))
else
  echo "  (clang-format: $CF_BIN)"
  cpp_files="$(find . \( -path ./build -o -path ./target -o -path ./node_modules -o -path ./.git \
    -o -path ./cmake-build-debug -o -path ./web \) -prune -o \
    \( -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.c' \
       -o -name '*.h' -o -name '*.hpp' \) -print)"
  if [[ -z "$cpp_files" ]]; then
    echo "  (无 C/C++ 源文件，跳过)"
  elif ! echo "$cpp_files" | xargs "$CF_BIN" --dry-run --Werror; then
    echo "✗ [cpp] 存在未格式化文件（见上方 diff）" >&2
    failed=$((failed+1))
  else
    echo "✓ [cpp] 格式检查通过"
  fi
fi

# ---------- Rust : cargo fmt ----------
echo "==> [rust] cargo fmt --all -- --check"
if ! cargo fmt --all -- --check; then
  echo "✗ [rust] 存在未格式化文件（运行 make fmt 修复）" >&2
  failed=$((failed+1))
else
  echo "✓ [rust] 格式检查通过"
fi

# ---------- Go : gofmt ----------
echo "==> [go] gofmt -l services/"
go_unfmt="$(GOWORK=off gofmt -l services/ || true)"
if [[ -n "$go_unfmt" ]]; then
  echo "✗ [go] 未格式化文件：" >&2
  echo "$go_unfmt" >&2
  failed=$((failed+1))
else
  echo "✓ [go] 格式检查通过"
fi

# ---------- 生成物一致性 : 属性字典 ----------
# 四语言绑定（Go/Rust/TS/Python）由 configs/registry/attributes.json 生成。
# 归入 lint 而非 test：它校验的是「提交物与真源是否一致」，即生成物新鲜度，
# 与格式检查同类；跑测试永远发现不了「生成物过期」——过期绑定照样能编译通过。
echo "==> [codegen] 属性字典生成物一致性"
if ! bash scripts/verify/check-attributes.sh; then
  echo "✗ [codegen] 属性字典生成物与真源不一致" >&2
  failed=$((failed+1))
else
  echo "✓ [codegen] 属性字典生成物一致"
fi

# ---------- 生成物一致性 : 通道 ABI ----------
# 同理归入 lint：它校验的是「C++ / Rust 双端契约生成物与真源是否一致」。
# 通道 ABI 是**跨语言二进制契约**，漂移的表现不是编译失败而是静默错读内存，
# 因此这里的检查是本仓库最不能省的一条。除新鲜度外还校验诊断可达性 ——
# 真源登记了却无人构造的诊断会让读者误以为该条校验存在。
echo "==> [codegen] 通道 ABI 双端契约一致性"
if ! bash scripts/verify/check-channel-abi.sh; then
  echo "✗ [codegen] 通道 ABI 生成物与真源不一致，或存在不可达诊断" >&2
  failed=$((failed+1))
else
  echo "✓ [codegen] 通道 ABI 双端契约一致"
fi

# ---------- 生成物一致性 : 版本单一真源 ----------
# 归入 lint 而非 test：它校验的是「提交物里的版本副本/派生点是否与真源一致」，
# 与属性字典、通道 ABI 同类，都是"不跑测试也能判"的静态一致性。
#
# **为什么必须挂进门禁**：`scripts/release/check-version.sh` 早就存在，但此前
# 没有任何门禁调用它 —— 于是 2ecf512 把根 `VERSION` 改成 9.9.9 时 lint/test 全绿，
# 只有"发版前手动跑一次"才会发现四端版本号已经不一致。没人执行的检查器等于没有。
#
# 这一条跑两步：真实校验 + `--self-test`。后者在临时目录里构造最小仓库树并注入
# 三处不一致，要求检查器**分别判红并指出位置** —— 否则"检查器恒返回成功"也会
# 一路绿灯：绿色的「通过」与绿色的「没跑」长得一模一样。
echo "==> [version] 版本单一真源一致性"
if ! bash scripts/release/check-version.sh; then
  echo "✗ [version] 版本副本/派生点与根 VERSION 不一致（见上方具体位置）" >&2
  failed=$((failed+1))
else
  echo "✓ [version] 版本单一真源一致（四端已派生或同步）"
fi
if ! bash scripts/release/check-version.sh --self-test >/dev/null; then
  echo "✗ [version] 检查器自证失败：它对注入的不一致视而不见（见上方输出）" >&2
  failed=$((failed+1))
else
  echo "✓ [version] 检查器自证通过（注入不一致会被判红并指出位置）"
fi

# ---------- 仓库完整性 : 被 .gitignore 静默吃掉的源码 ----------
# 不带前导斜杠的目录名（`build/`、`target/`、`release/`）会匹配**任意层级**的同名目录，
# 于是同名的源码目录被整体忽略：文件在磁盘上、本地跑得通、`git status` 不提示，
# 但全新克隆里没有它。本仓库真实踩过三次（`scripts/release/` 的版本自检脚本、
# `scripts/build/build-all.sh`、`services/telemetryd/internal/target/` 这个被 import 的
# Go 包）。这类问题读代码发现不了，只能在「版本控制的事实」上查 —— 所以它必须进门禁。
echo "==> [repo] 有没有源码被 .gitignore 静默忽略"
if ! bash scripts/verify/check-ignored-sources.sh >/dev/null; then
  echo "✗ [repo] 有源码/脚本不在版本控制里（见上方命中规则）" >&2
  failed=$((failed+1))
else
  echo "✓ [repo] 没有被 .gitignore 吃掉的源码/脚本"
fi

# ---------- 前端 : 类型检查 ----------
# Pro tsconfig 覆盖 src/tests/config；npm ci 的 prepare 负责生成 Umi 类型。
echo "==> [node] 前端类型检查（src/tests + 构建配置）"
if ! (cd web/console && npm run typecheck:all); then
  echo "✗ [node] 类型检查未通过" >&2
  failed=$((failed+1))
else
  echo "✓ [node] 类型检查通过"
fi

# ---------- 前端 : Biome ----------
echo "==> [node] npm run lint (web/console)"
if ! (cd web/console && npm run lint); then
  echo "✗ [node] Biome 检查未通过" >&2
  failed=$((failed+1))
else
  echo "✓ [node] Biome 检查通过"
fi

if [[ $failed -eq 0 ]]; then
  echo "lint 汇总：全部通过 ✓"
  exit 0
fi
echo "lint 汇总：$failed 项检查未通过 ✗" >&2
exit 1
