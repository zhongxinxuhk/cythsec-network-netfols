#!/usr/bin/env bash
# check-channel-abi.sh —— 通道 ABI 生成物一致性关口（CYS-PKT-024）。
#
# 用法：
#   bash scripts/verify/check-channel-abi.sh          # 校验生成物与真源一致
#   bash scripts/verify/check-channel-abi.sh --help   # 查看帮助
#
# 行为：
#   - 调用 tools/codegen/gen-channel-abi.py --check，逐文件比对生成物与
#     configs/registry/channel-abi.json 是否一致（C++ 侧 abi_gen.h + Rust 侧 abi_gen.rs）。
#   - 同时校验「诊断可达性」：真源里登记的每条诊断码都必须至少有一个构造点。
#     登记了却永远无人构造的诊断，在真源里读起来是一份能力、两端都会为它生成
#     结构体与渲染代码，但代码路径根本不会产生它 —— 读到的人会以为这条校验存在。
#   - 只读操作：不写任何文件（生成动作需显式执行 gen-channel-abi.py）。
#
# 为什么本脚本必须存在：
#   tools/codegen/gen-channel-abi.py 的文件头注释、以及它生成的两个产物
#   （abi_gen.h / abi_gen.rs）的头部注释，共 4 处都写着「改动会被
#   scripts/verify/check-channel-abi.sh 拦下」。本脚本此前**并不存在**，
#   于是这句话描述的约束从未生效，lint-all.sh 也没有挂载它 —— 结果是通道 ABI
#   的漂移检查（以及它早已报出的 11 条误报与 1 处真实缺口）长期无人看到。
#   凡在注释里声称「有脚本会拦下」的，该脚本就必须真实存在并挂在门禁上。
#
# 退出码：0 = 一致；1 = 生成物过期；2 = 诊断不可达；3 = 真源非法；4 = 环境不满足（缺 python3）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: check-channel-abi.sh

校验 C++ / Rust 双端通道 ABI 生成物是否与真源 configs/registry/channel-abi.json 一致，
并校验真源登记的每条诊断都存在构造点。

若报告「生成物过期」，执行以下命令修复后提交：

  python3 tools/codegen/gen-channel-abi.py

若报告「诊断不可达」，不要去改生成物 —— 那是真源与实现不一致，必须二选一：
实现该诊断的构造路径，或连同调用处一起从真源删除。

退出码：0 一致 / 1 生成物过期 / 2 诊断不可达 / 3 真源非法 / 4 缺 python3
EOF
  exit 0
fi

PY="${PYTHON:-}"
if [[ -z "${PY}" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PY="python3"
  else
    echo "环境检查失败：未找到 python3（可用 PYTHON 环境变量指定解释器）" >&2
    exit 4
  fi
fi

set +e
"${PY}" tools/codegen/gen-channel-abi.py --check
rc=$?
set -e

case "${rc}" in
  0) exit 0 ;;
  1)
    echo "" >&2
    echo "通道 ABI 真源变更后未重新生成双端契约（或生成物被手工改动）。" >&2
    echo "修复：python3 tools/codegen/gen-channel-abi.py" >&2
    exit 1
    ;;
  2)
    echo "" >&2
    echo "通道 ABI 登记了不可达的诊断。" >&2
    echo "不要改生成物：请在实现中真正构造该诊断，或连同调用处一起从真源删除。" >&2
    exit 2
    ;;
  3)
    echo "" >&2
    echo "通道 ABI 真源自身非法（详见上方 gen-channel-abi 报错）。" >&2
    exit 3
    ;;
  *)
    echo "通道 ABI 校验异常退出，退出码 ${rc}" >&2
    exit "${rc}"
    ;;
esac
