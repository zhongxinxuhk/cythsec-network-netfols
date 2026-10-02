#!/usr/bin/env bash
# check-reassembly-vectors.sh —— 重组测试向量的**第三方交叉核验**。
#
# 为什么需要这一步：
#   datasets/reassembly 的期望值是生成器按"自己放了什么"写死的，Rust 实现按同一份
#   期望值断言。只要这两方犯了同一个理解错误（比如都把 FIN 的序号当成载荷起点），
#   两边依然会完美一致 —— 一致性本身证明不了正确性。tshark 的 TCP 重组与 TLS
#   解析器是**独立实现**，是第三条证据。
#
# 用法：
#   bash scripts/verify/check-reassembly-vectors.sh          # 核验
#   bash scripts/verify/check-reassembly-vectors.sh --help   # 帮助
#
# 行为：
#   - mode=stream：用 tshark 的 follow stream 取出重组结果，与 expected.json 比对
#     字节长度与 sha256。tshark 的输出是"按序号顺序、已去重"的分块，
#     因此**逆序 / 重叠重传**这些用例同样能比对 —— 它自己会先把顺序摆对。
#   - mode=ja3：对"被切开的首包"用例，比对 tshark 重组后算出的 JA3 与 SNI。
#     这是对"重组 → DPI"这条链路最直接的第三方验证。
#   - expected.json 里 `tshark.verified=false` 的条目是**已知例外**，会显式打印为
#     `SKIP(已知例外)` 并计入统计 —— 静默跳过等于让"未被核验"的条目冒充
#     "已核验通过"，那正是本脚本要防的事。
#   - 只读操作：不写任何文件（向量需显式执行 generate-reassembly-samples.py 生成）。
#
# 退出码：0 = 全部一致；1 = 存在不一致；2 = 向量文件缺失；3 = 环境不满足（缺 python3/tshark）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: check-reassembly-vectors.sh

用 tshark（独立第三方实现）复核 datasets/reassembly 的期望值：
  mode=stream  比对重组后的字节流（长度 + sha256）
  mode=ja3     比对重组后算出的 JA3 与 SNI

退出码：0 一致 / 1 存在不一致 / 2 向量缺失 / 3 缺 python3 或 tshark
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

TSHARK="${TSHARK:-tshark}"
if ! command -v "$TSHARK" >/dev/null 2>&1; then
  echo "环境检查失败：未找到 tshark（可用 TSHARK 环境变量指定路径）" >&2
  exit 3
fi

if [[ ! -f datasets/reassembly/expected.json ]]; then
  echo "向量缺失：datasets/reassembly/expected.json（先执行 python3 datasets/reassembly/generate-reassembly-samples.py）" >&2
  exit 2
fi

"$PY" - <<'PYEOF'
import hashlib
import json
import subprocess
import sys

import os

TSHARK = "tshark"
BASE = "datasets/reassembly"
exp = json.load(open(os.path.join(BASE, "expected.json"), encoding="utf-8"))

missing = [e["pcap"] for e in exp["vectors"] if not os.path.isfile(os.path.join(BASE, e["pcap"]))]
if missing:
    print("向量缺失：" + ", ".join(missing[:5]) +
          "（先执行 python3 datasets/reassembly/generate-reassembly-samples.py）", file=sys.stderr)
    sys.exit(2)

checked = 0
skipped = 0
failures = []


def run(args):
    return subprocess.run([TSHARK] + args, capture_output=True, text=True)


def follow_stream(pcap):
    """取 tshark follow stream 的重组结果。

    输出形如（每个分块先一行十进制长度，再一行数据）：
        ===================================================================
        Follow: tcp,ascii
        Filter: tcp.stream eq 0
        Node 0: ...
        Node 1: ...
        10
        AAAAAAAAAA
        ===================================================================

    分块已由 tshark 按**序号顺序**排列并去重，因此逆序到达与重叠重传都能直接比对。
    """
    r = run(["-r", pcap, "-q", "-z", "follow,tcp,ascii,0"])
    lines = r.stdout.split("\n")
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("Node 1:"))
    except StopIteration:
        raise RuntimeError(f"tshark 未输出 follow 段：{r.stderr.strip()[:200]}")

    data = bytearray()
    i = start + 1
    while i < len(lines):
        line = lines[i]
        if line and set(line) == {"="}:
            break
        if line.isdigit():
            n = int(line)
            i += 1
            chunk = lines[i].encode() if i < len(lines) else b""
            if len(chunk) != n:
                raise RuntimeError(
                    f"follow 输出的分块长度声明 {n} 与实际 {len(chunk)} 不符"
                    "（载荷含换行时 ascii 模式无法按行还原）"
                )
            data += chunk
        i += 1
    return bytes(data)


def fields(pcap, *names):
    args = ["-r", pcap, "-T", "fields", "-E", "separator=|"]
    for n in names:
        args += ["-e", n]
    return [l.rstrip("\n") for l in run(args).stdout.split("\n") if l.strip()]


def check(name, field, got, want):
    global checked
    checked += 1
    if got != want:
        failures.append(f"[{name}] {field} 不一致：tshark={got!r} 期望={want!r}")


for e in exp["vectors"]:
    name = e["name"]
    ts = e.get("tshark", {})
    if not ts.get("verified", True):
        skipped += 1
        print(f"  SKIP(已知例外) {name}: {ts.get('note', '')}")
        continue

    mode = ts.get("mode", "stream")
    want = ts.get("expect", {})

    if mode == "stream":
        got = follow_stream(os.path.join(BASE, e["pcap"]))
        check(name, "重组长度", len(got), want.get("len"))
        check(name, "重组 sha256", hashlib.sha256(got).hexdigest(), want.get("sha256"))
    elif mode == "ja3":
        rows = fields(os.path.join(BASE, e["pcap"]), "tls.handshake.ja3", "tls.handshake.extensions_server_name")
        # 握手未完成的帧（SYN、只带前半段的帧）也会输出一行空字段，
        # 取第一个真正解出 JA3 的行 —— 它所在的那一帧，正是"重组完成"的那一帧。
        hit = next((r for r in rows if r.split("|")[0]), None)
        if hit is None:
            failures.append(f"[{name}] tshark 未从重组后的流里解出 JA3")
            continue
        ja3, sni = (hit.split("|") + ["", ""])[:2]
        check(name, "JA3", ja3 or None, want.get("ja3"))
        check(name, "SNI", sni or None, want.get("sni"))
    else:
        failures.append(f"[{name}] 未知的 tshark 核验模式：{mode}")

print(f"tshark 交叉核验：比对 {checked} 项，跳过 {skipped} 项（已知例外）")
if failures:
    print()
    for f in failures:
        print("FAIL " + f)
    sys.exit(1)
print("tshark 与生成器期望值一致")
PYEOF
