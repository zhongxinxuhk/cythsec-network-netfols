#!/usr/bin/env bash
# check-dpi-vectors.sh —— DPI 测试向量的**第三方交叉核验**。
#
# 为什么需要这一步：
#   datasets/dpi 的期望值是生成器按"自己放了什么"算出来的。只要生成器和 Rust 实现
#   犯的是同一个理解错误（比如都把 GREASE 算进 JA3），两边依然会完美一致 ——
#   一致性本身证明不了正确性。tshark 是**独立实现**，它的 JA3 / SNI / QNAME 是第三条证据。
#
# 用法：
#   bash scripts/verify/check-dpi-vectors.sh          # 核验
#   bash scripts/verify/check-dpi-vectors.sh --help   # 帮助
#
# 行为：
#   - 用 tshark 解析 datasets/dpi/*.pcap，与 expected.json 的期望值逐条比对 SNI / JA3 / QNAME。
#   - expected.json 里 `tshark.verified=false` 的条目是**已知例外**，会显式打印为
#     `SKIP(已知例外)` 并计入统计 —— 静默跳过等于让"未被核验"的条目冒充"已核验通过"，
#     那正是本脚本要防的事。
#   - 只读操作：不写任何文件（向量需显式执行 datasets/dpi/generate-dpi-samples.py 生成）。
#
# 退出码：0 = 全部一致；1 = 存在不一致；2 = 向量文件缺失；3 = 环境不满足（缺 python3/tshark）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
用法: check-dpi-vectors.sh

用 tshark（独立第三方实现）复核 datasets/dpi 的期望值，
比对 SNI / JA3 / QNAME / HTTP Host 是否与生成器算出的期望一致。

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

for f in datasets/dpi/tls-vectors.pcap datasets/dpi/dns-vectors.pcap \
         datasets/dpi/http-vectors.pcap datasets/dpi/expected.json; do
  if [[ ! -f "$f" ]]; then
    echo "向量缺失：$f（先执行 python3 datasets/dpi/generate-dpi-samples.py）" >&2
    exit 2
  fi
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 端口即索引：生成器按 40000+i / 41000+i / 50000+i 给每个用例编了不同的源端口，
# 因此可以用源端口把 tshark 的输出行对回 expected.json 里的条目。
"$TSHARK" -r datasets/dpi/tls-vectors.pcap -T fields -E separator='|' \
  -e tcp.srcport -e tls.handshake.extensions_server_name -e tls.handshake.ja3 \
  > "$TMP/tls.txt" 2>/dev/null || true
"$TSHARK" -r datasets/dpi/dns-vectors.pcap -T fields -E separator='|' \
  -e udp.srcport -e dns.qry.name -e dns.qry.type \
  > "$TMP/dns.txt" 2>/dev/null || true
"$TSHARK" -r datasets/dpi/http-vectors.pcap -T fields -E separator='|' \
  -e tcp.srcport -e http.request.method -e http.host \
  > "$TMP/http.txt" 2>/dev/null || true

"$PY" - "$TMP/tls.txt" "$TMP/dns.txt" "$TMP/http.txt" <<'PYEOF'
import json
import sys

tls_path, dns_path, http_path = sys.argv[1:4]
exp = json.load(open("datasets/dpi/expected.json"))


def load(path, base):
    """把 tshark 的输出按 (源端口 - base) 索引成列表。"""
    rows = {}
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("|")
        if not parts[0].isdigit():
            continue
        rows[int(parts[0]) - base] = parts[1:]
    return rows


tls = load(tls_path, 40000)
dns = load(dns_path, 50000)
http = load(http_path, 41000)

checked = 0
skipped = 0
failures = []


def cmp_value(name, field, got, want):
    global checked
    checked += 1
    if got != want:
        failures.append(f"[{name}] {field} 不一致：tshark={got!r} 期望={want!r}")


def strip_port(host):
    """tshark 的 http.host 保留端口（api.example.com:8443），我们的实现按规范剥离；
    比对时统一剥掉端口再比，否则会得到一个"看起来是 tshark 错了"的假失败。"""
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        return host.rsplit(":", 1)[0]
    return host


# ---- TLS ----
for i, e in enumerate(exp["tls"]):
    name = e["name"]
    verified = e.get("tshark", {}).get("verified", True)
    if e["expect"] != "identified":
        skipped += 1
        continue
    if not verified:
        skipped += 1
        print(f"  SKIP(已知例外) {name}: {e.get('tshark', {}).get('note', '')}")
        continue
    row = tls.get(i)
    if row is None:
        failures.append(f"[{name}] tshark 未解析出该帧（index={i}）")
        continue
    sni, ja3 = (row + ["", ""])[:2]
    cmp_value(name, "SNI", sni or None, e.get("sni"))
    cmp_value(name, "JA3", ja3 or None, e.get("ja3"))

# ---- DNS ----
for i, e in enumerate(exp["dns"]):
    name = e["name"]
    if e["expect"] != "identified":
        skipped += 1
        continue
    row = dns.get(i)
    if row is None:
        failures.append(f"[{name}] tshark 未解析出该帧（index={i}）")
        continue
    qname, qtype = (row + ["", ""])[:2]
    cmp_value(name, "QNAME", qname or None, e.get("qname"))
    cmp_value(name, "QTYPE", int(qtype) if qtype.isdigit() else None, e.get("qtype"))

# ---- HTTP ----
for i, e in enumerate(exp["http"]):
    name = e["name"]
    if e["expect"] != "identified":
        skipped += 1
        continue
    row = http.get(i)
    if row is None:
        failures.append(f"[{name}] tshark 未解析出该帧（index={i}）")
        continue
    method, host = (row + ["", ""])[:2]
    cmp_value(name, "METHOD", method or None, e.get("method"))
    cmp_value(name, "HOST", strip_port(host) or None, e.get("host"))

print(f"tshark 交叉核验：比对 {checked} 项，跳过 {skipped} 项（非 identified 或已知例外）")
if failures:
    print()
    for f in failures:
        print("FAIL " + f)
    sys.exit(1)
print("tshark 与生成器期望值一致")
PYEOF
