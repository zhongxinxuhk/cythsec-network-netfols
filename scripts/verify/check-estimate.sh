#!/usr/bin/env bash
# check-estimate.sh —— 采样后的**量级还原**关口（`CYS-TRF-053` 缺口③）。
#
# 挡的错：采样只留下一部分记录，如果采集侧直接把它们当全量（少乘 N），或者在"按流聚合"的
# 样本上套用按包独立的方差式（区间假窄），那么对外的容量数字就会**错得很有说服力** ——
# 点估计错 N 倍、区间还很窄。这两件事都不会自己暴露，所以要把它们钉在手算真值上。
#
# 本脚本自己构建被测二进制（陈旧二进制跑出来的结论没有意义），缺 cargo/tshark 退 3「未核验」。
# 三项反向注入**真的改变那次运行**（改线路上的 IE 34 / 把 flowId 改掉让重放绕过去重），
# 判定必须判红。注入生效与否由脚本自身断言先验（"改了 0 条"直接失败）——注入没生效的红
# 是无意义的红。
#
# 退出码：0 通过 · 1 失败 · 2 参数错 · 3 未核验（缺工具，不算通过）
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 2

PY="${PYTHON:-python3}"

say() { printf '%s\n' "$*"; }
die_unverified() { say "⚠ [estimate] $*（未核验，不算通过）"; exit 3; }

command -v cargo >/dev/null 2>&1 || die_unverified "缺 cargo，无法构建被测二进制"
command -v tshark >/dev/null 2>&1 || die_unverified "缺 tshark，注入的线路复核无法进行"

say "==> [estimate] 构建被测二进制（分析器 + 采集器）"
if ! cargo build --offline --quiet --release --manifest-path dataplane/traffic-engine/Cargo.toml 2>&1 | tail -5; then
  say "✗ [estimate] cargo build 失败"
  exit 1
fi

say "==> [estimate] Rust 单测：手算的点估计/区间/方差退化"
if ! cargo test --offline --quiet --manifest-path dataplane/traffic-engine/Cargo.toml \
    --lib ipfix::estimate 2>&1 | tail -3; then
  say "✗ [estimate] estimate 单测失败"
  exit 1
fi

say "==> [estimate] 行为判定（对总体真值 · 区间覆盖 · 拒绝混合间隔 · 重放不翻倍）"
if ! "$PY" scripts/verify/check-estimate.py --check; then
  say "✗ [estimate] 判定失败"
  exit 1
fi

say "==> [estimate] 反向注入（改变那次运行，判定必须判红）"
for inject in under-declare over-declare replayed-new-flowid; do
  if "$PY" scripts/verify/check-estimate.py --check --inject "$inject" >/dev/null 2>&1; then
    say "✗ [estimate] 注入「$inject」未被检出（关口形同虚设）"
    exit 1
  fi
  say "  ✓ 注入已检出：$inject"
done

say "✓ [estimate] 量级还原关口通过（点估计对真值 · 24 种子覆盖率 ≥20/24 · 混合间隔拒绝给数 · 重放不翻倍 · 3 项注入全部被检出）"
exit 0
