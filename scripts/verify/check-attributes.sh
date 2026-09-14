#!/usr/bin/env bash
# check-attributes.sh —— 属性字典生成物一致性关口。
#
# 用法：
#   bash scripts/verify/check-attributes.sh          # 校验生成物与真源一致
#   bash scripts/verify/check-attributes.sh --help   # 查看帮助
#
# 行为：
#   - 调用 tools/codegen/gen-attributes.py --check，逐文件比对生成物与
#     configs/registry/attributes.json 是否一致（含 Go/Rust/TS/Python 四份绑定）。
#   - 真源本身非法（属性 id 不合规、类型未登记、Go 标识符冲突等）时同样非 0 退出，
#     并在错误里指出具体条目。
#   - 只读操作：不写任何文件（生成动作需显式执行 gen-attributes.py）。
#
# 退出码：0 = 一致；1 = 生成物过期；2 = 真源非法；3 = 环境不满足（缺 python3）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: check-attributes.sh

校验四语言属性绑定生成物是否与真源 configs/registry/attributes.json 一致。
若报告过期，执行以下命令修复后提交：

  python3 tools/codegen/gen-attributes.py

退出码：0 一致 / 1 生成物过期 / 2 真源非法 / 3 缺 python3
EOF
  exit 0
fi

PY="${PYTHON:-}"
if [[ -z "$PY" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PY="python3"
  else
    echo "环境检查失败：未找到 python3（可用 PYTHON 环境变量指定解释器）" >&2
    exit 3
  fi
fi

set +e
"$PY" tools/codegen/gen-attributes.py --check
rc=$?
set -e

case "$rc" in
  0) exit 0 ;;
  1)
    echo "" >&2
    echo "属性字典新登记了属性却未重新生成绑定（或生成物被手工改动）。" >&2
    exit 1
    ;;
  2) exit 2 ;;
  *)
    echo "属性字典校验异常退出，退出码 $rc" >&2
    exit "$rc"
    ;;
esac
