#!/usr/bin/env bash
# check-sampling.sh —— 流级采样关口（CYS-TRF-053）：**声明（IE 34）与执行必须一致**。
#
# 这条关口要挡的是一个很隐蔽的错：导出器在 IPFIX 里声明"我按 1:1000 采样"，
# 实际一个包都没丢（或反过来丢了包却说没采）。一旦这样，采集侧会把采样流量当全量，
# 容量模型、丢包率、乃至"省网 20 Tbps 要几台"全部跟着错 —— 而**没有任何东西**
# 会自动把声明与执行对上，所以要把它们钉在同一份配置上，再用这条关口守着。
#
# 本脚本自己构建被测二进制（缺 cargo ⇒ 退出 3「未核验」）：用陈旧二进制跑出来的
# 结论毫无意义，本仓已经在这上面栽过一次（旧二进制让关口测了个不存在的东西）。
#
# 判定分两层：
#   1) 行为层（check-sampling.py，自造语料）：采样确实丢包、flow 模式留下的流**完整**、
#      IE 34 == 配置值、`--workers 4` 与 `--workers 1` 结果一致、逐包模式的包级精确；
#   2) 回归层（Rust 单测）：IE 34 真的来自配置（防止再被硬编码成 1）。
# 三层反向注入（keep-all / torn-flows / no-ipfix）必须全部判红。
#
# 退出码：0 通过 · 1 失败 · 2 参数错 · 3 未核验（缺工具，不算通过）
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 2

PY="${PYTHON:-python3}"
FLOWS="${FLOWS:-400}"

say() { printf '%s\n' "$*"; }
die_unverified() { say "⚠ [sampling] $*（未核验，不算通过）"; exit 3; }

command -v cargo >/dev/null 2>&1 || die_unverified "缺 cargo，无法构建被测二进制"
# IE 34 的读数必须来自第三方（tshark）：自己解自己的报文不能算"线路校验"。
command -v tshark >/dev/null 2>&1 || die_unverified "缺 tshark，IE 34 的线路校验无法进行"

say "==> [sampling] 构建被测二进制（绝不用陈旧二进制跑关口）"
if ! cargo build --offline --quiet --release --manifest-path dataplane/traffic-engine/Cargo.toml 2>&1 | tail -5; then
  say "✗ [sampling] cargo build 失败"
  exit 1
fi

say "==> [sampling] Rust 单测：IE 34 来自配置而不是硬编码"
if ! cargo test --offline --quiet --manifest-path dataplane/traffic-engine/Cargo.toml \
    --lib sampling_interval_is_written_into_records 2>&1 | tail -3; then
  say "✗ [sampling] IE 34 单测失败"
  exit 1
fi
say "  ✓ 编码器把配置里的采样间隔写进了记录（默认仍是 1）"

say "==> [sampling] 行为判定（自造 ${FLOWS} 条流 · 声明与执行一致）"
if ! "$PY" scripts/verify/check-sampling.py --check --flows "$FLOWS"; then
  say "✗ [sampling] 行为判定失败"
  exit 1
fi

say "==> [sampling] 反向注入（改坏被测的那次运行，判定必须判红）"
for inject in keep-all torn-flows no-ipfix; do
  if "$PY" scripts/verify/check-sampling.py --check --flows "$FLOWS" --inject "$inject" >/dev/null 2>&1; then
    say "✗ [sampling] 注入「$inject」未被检出（关口形同虚设）"
    exit 1
  fi
  say "  ✓ 注入已检出：$inject"
done

say "✓ [sampling] 流级采样关口通过（执行：真丢包 · 完整性：flow 模式逐字段一致 · 声明：IE 34 == 配置 · 并行一致 · 3 项注入全部被检出）"
exit 0
