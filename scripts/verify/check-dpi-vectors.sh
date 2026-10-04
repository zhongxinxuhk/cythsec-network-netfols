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
#   - 先比对**入库的** payloads/*.bin 与生成器刚写出的字节是否一致（见下）。
#   - 用 tshark 解析 datasets/dpi/*.pcap，与 expected.json 的期望值逐条比对
#     SNI / JA3 / QNAME / QTYPE / RCODE / QCLASS / ANSWER 地址 / EDNS0 / HTTP 方法 /
#     Host / URI / UA / 状态码 / Content-Type。
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
用法: check-dpi-vectors.sh [--self-test]

1) 校验入库的 datasets/dpi/payloads/*.bin 与生成器输出**字节一致**
   （防止行尾归一化等把入库字节改掉，使期望值与被测字节不是同一份）；
2) 用 tshark（独立第三方实现）复核 datasets/dpi 的期望值，
   比对 SNI / JA3 / QNAME / QTYPE / RCODE / QCLASS / ANSWER / EDNS0 /
   HTTP 方法 / Host / URI / UA / 状态码 / Content-Type 是否一致。

--self-test 只跑第 1 步的比对自证：在临时仓库里真的制造一次行尾归一，
确认比对能判红；再加 -text 确认能判绿。（正常执行时也会先跑一遍。）

退出码：0 一致 / 1 存在不一致 / 2 向量缺失 / 3 缺 python3 或 tshark
EOF
  exit 0
fi

# 字节保真比对的自证。**在临时仓库里做**，不碰本仓库的索引。
#
# 为什么必须有这一步：本节的比对是"索引 blob 哈希 vs 未过滤的工作区哈希"。
# 若把哈希写反、字段取错、或 git 版本行为变了，比对会恒等于"一致" ——
# 于是"入库字节被改坏"这件事会一路绿灯，而绿灯的"通过"与绿灯的"没跑"长得一样。
byte_selftest() {
  local base="$1" d idx disk
  d="$base/selftest"
  mkdir -p "$d" || return 1
  git -C "$d" init -q || return 1
  git -C "$d" config core.autocrlf input || return 1
  printf 'GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n' > "$d/v.bin"

  # ① 无属性：crlf 归一必须**被检出**（索引 blob ≠ 未过滤的工作区字节）
  git -C "$d" add v.bin >/dev/null 2>&1
  idx="$(git -C "$d" ls-files -s -- v.bin | awk '{print $2}')"
  disk="$(git -C "$d" hash-object --no-filters -- v.bin)"
  if [[ -z "$idx" || -z "$disk" || "$idx" == "$disk" ]]; then
    echo "✗ [自证] 制造的行尾归一没被检出（比对逻辑恒等于通过）" >&2
    return 1
  fi

  # ② 加上 -text 后必须**判绿**（否则修复方案本身是错的）
  printf '*.bin -text\n' > "$d/.gitattributes"
  git -C "$d" add .gitattributes >/dev/null 2>&1
  git -C "$d" add --renormalize v.bin >/dev/null 2>&1
  idx="$(git -C "$d" ls-files -s -- v.bin | awk '{print $2}')"
  disk="$(git -C "$d" hash-object --no-filters -- v.bin)"
  if [[ "$idx" != "$disk" ]]; then
    echo "✗ [自证] 加了 -text 之后字节仍与入库 blob 不一致（修复无效）" >&2
    return 1
  fi
  return 0
}

if [[ "${1:-}" == "--self-test" ]]; then
  if ! command -v git >/dev/null 2>&1; then
    echo "环境检查失败：未找到 git（自证需要 git）" >&2
    exit 3
  fi
  ST="$(mktemp -d)"
  trap 'rm -rf "$ST"' EXIT
  byte_selftest "$ST" || exit 1
  echo "字节保真比对自证通过（临时仓库内注入行尾归一→判红；加 -text→判绿）✓"
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

# ── 入库字节与生成物一致性 ───────────────────────────────────────────────
#
# payloads/*.bin 是**入库**的字节，expected.json 是生成器按"自己放了什么"算出来的。
# 两者只要差一个字节，"测试读到的字节"与"期望值对应的字节"就不是同一份，
# 而 tshark 复核的是 pcap（生成物），也可能照样全绿 —— 假绿的一种。
#
# 真实踩过的成因：core.autocrlf=input 时 `git add` 会把 HTTP 向量里的 \r\n
# 归一成 \n（http.rs 正是用 `\r\n\r\n` 判头部结束）。修复是 .gitattributes 里
# 把 *.bin 标成 -text；这一节负责让它**不能悄悄回退** —— 宣称"有东西会拦下"
# 就必须真有东西在拦（且挂在这条门禁路径上）。
#
# 注意这里**不能用 `git diff`**：它比对的是"过了 clean 过滤之后"的内容，
# 而行尾归一恰恰发生在过滤这一步 —— 于是"索引里是 LF、磁盘上是 CRLF"这种
# 损坏在 `git diff` 眼里毫无差别（本次实测：`git diff --quiet` 报干净，
# 索引 blob 的 CRLF 计数是 0、磁盘是 5）。必须逐文件比对**未经过滤**的字节。
#
# 这一节自带 `--self-test`（每次正常执行也会先跑一遍）：在**临时仓库**里真的制造
# 一次行尾归一，确认上面的比对确实能判红；再加 `-text` 确认能判绿。
# 没有这一步，"比对通过"与"比对代码写错了、恒等于通过"长得一模一样。
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

byte_selftest "$TMP" || { echo "✗ 字节保真比对自证失败：拒绝在「不知道自己在测什么」的状态下报通过" >&2; exit 1; }
echo "  字节保真比对自证通过（临时仓库内注入行尾归一→判红；加 -text→判绿）✓"

if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
  drift=0
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    in_index="$(git ls-files -s -- "$f" | awk '{print $2}')"
    on_disk="$(git hash-object --no-filters -- "$f")"
    if [[ "$in_index" != "$on_disk" ]]; then
      echo "✗ 入库字节与生成物（磁盘）不一致：$f" >&2
      echo "    索引 blob ${in_index:0:12}… ≠ 未过滤工作区字节 ${on_disk:0:12}…" >&2
      drift=$((drift + 1))
    fi
  done < <(git ls-files datasets/dpi/payloads/)

  if [[ $drift -gt 0 ]]; then
    echo "  共 $drift 个向量文件的入库字节被改过（多为行尾被当文本归一）。" >&2
    echo "  确认为 .gitattributes 里 'datasets/**/*.bin -text'，再执行：" >&2
    echo "    git add --renormalize datasets/dpi/payloads/" >&2
    exit 1
  fi
  echo "  入库 payloads 与生成器输出字节一致 ✓（逐文件未经过滤比对）"
else
  echo "  SKIP(非 git 工作区)：无法比对入库字节与生成物（该项未执行，不计为通过）"
fi

# 端口即索引：生成器按 40000+i / 41000+i / 50000+i 给每个用例编了不同的源端口，
# 因此可以用源端口把 tshark 的输出行对回 expected.json 里的条目。
"$TSHARK" -r datasets/dpi/tls-vectors.pcap -T fields -E separator='|' \
  -e tcp.srcport -e tcp.dstport -e tls.handshake.extensions_server_name -e tls.handshake.ja3 \
  > "$TMP/tls.txt" 2>/dev/null || true
# DNS / HTTP 的源端口取值取决于报文方向（响应来自服务器端口），因此两个端口都取，
# Python 侧按 max(src,dst) 还原索引 —— 只按 srcport 索引的话，响应向量的行会落到
# 负索引上，于是"比对了 N 项"里的 N 会悄悄变小。
"$TSHARK" -r datasets/dpi/dns-vectors.pcap -T fields -E separator='|' \
  -e udp.srcport -e udp.dstport -e dns.qry.name -e dns.qry.type \
  -e dns.flags.rcode -e dns.qry.class -e dns.a -e dns.aaaa -e dns.rr.udp_payload_size \
  > "$TMP/dns.txt" 2>/dev/null || true
"$TSHARK" -r datasets/dpi/http-vectors.pcap -T fields -E separator='|' \
  -e tcp.srcport -e tcp.dstport -e http.request.method -e http.host \
  -e http.request.uri -e http.user_agent -e http.response.code -e http.content_type \
  > "$TMP/http.txt" 2>/dev/null || true

"$PY" - "$TMP/tls.txt" "$TMP/dns.txt" "$TMP/http.txt" <<'PYEOF'
import json
import sys

tls_path, dns_path, http_path = sys.argv[1:4]
exp = json.load(open("datasets/dpi/expected.json"))


def load(path, base):
    """把 tshark 的输出按 (端口对里属于生成器的那个 - base) 索引成列表。

    生成器给第 i 个用例分配的端口是 base+i，另一侧是协议周知端口（53/80）。
    因此取 max(src,dst) 就能还原索引，且与报文方向无关 —— 响应向量也必须能被索引到，
    否则"跳过"会伪装成"通过"。
    """
    rows = {}
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("|")
        if not parts[0].isdigit():
            continue
        src = int(parts[0])
        dst = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        rows[max(src, dst) - base] = parts[2:]
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


def as_int(s):
    """tshark 空字段 → None；十进制与 0x 十六进制都吃（qry.class 是 0x0001 形式）。"""
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def ips_of(row_a, row_aaaa):
    """tshark 把 A 与 AAAA 分在两个字段里（逗号分隔），我们是一条有序列表。

    因此按**集合**比对：这仍然能抓住地址读错、少读、多读，抓不住"顺序不同"——
    而顺序本来就不可比（tshark 的字段顺序由字段定义决定，不是报文顺序）。
    """
    out = set()
    for cell in (row_a or "", row_aaaa or ""):
        for v in cell.split(","):
            v = v.strip()
            if v:
                out.add(v)
    return out


def skip_marker(e):
    """返回已知例外的说明，非例外返回 None。"""
    m = e.get("tshark", {})
    if m.get("verified", True):
        return None
    return m.get("note", "")


# ---- TLS ----
for i, e in enumerate(exp["tls"]):
    name = e["name"]
    if e["expect"] != "identified":
        skipped += 1
        continue
    note = skip_marker(e)
    if note is not None:
        skipped += 1
        print(f"  SKIP(已知例外) {name}: {note}")
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
    note = skip_marker(e)
    if note is not None:
        skipped += 1
        print(f"  SKIP(已知例外) {name}: {note}")
        continue
    row = dns.get(i)
    if row is None:
        failures.append(f"[{name}] tshark 未解析出该帧（index={i}）")
        continue
    qname, qtype, rcode, qclass, a, aaaa, udp_size = (row + [""] * 7)[:7]
    cmp_value(name, "QNAME", qname or None, e.get("qname"))
    cmp_value(name, "QTYPE", as_int(qtype), e.get("qtype"))
    # rcode：tshark 在查询上报空、在响应上报数值 —— 与我们的"查询不产出 RCODE"一致
    cmp_value(name, "RCODE", as_int(rcode), e.get("rcode"))
    cmp_value(name, "QCLASS", as_int(qclass), e.get("qclass", 1))
    cmp_value(name, "ANSWER_IPS", ips_of(a, aaaa), set(e.get("answer_ips", [])))
    cmp_value(name, "EDNS0_UDP_SIZE", as_int(udp_size), e.get("edns0_udp_size"))

# ---- HTTP ----
for i, e in enumerate(exp["http"]):
    name = e["name"]
    if e["expect"] != "identified":
        skipped += 1
        continue
    note = skip_marker(e)
    if note is not None:
        skipped += 1
        print(f"  SKIP(已知例外) {name}: {note}")
        continue
    row = http.get(i)
    if row is None:
        failures.append(f"[{name}] tshark 未解析出该帧（index={i}）")
        continue
    method, host, uri, ua, status, ctype = (row + [""] * 6)[:6]
    cmp_value(name, "METHOD", method or None, e.get("method"))
    cmp_value(name, "HOST", strip_port(host) or None, e.get("host"))
    cmp_value(name, "URI", uri or None, e.get("uri"))
    cmp_value(name, "USER_AGENT", ua or None, e.get("user_agent"))
    cmp_value(name, "STATUS_CODE", as_int(status), e.get("status_code"))
    # 实现按策略把小写归一（同一类型不因写法裂成两个桶），tshark 报原样：
    # 比对时两边都归一，而不是把 tshark 的原始大小写当成它错了。
    want_ct = e.get("content_type")
    cmp_value(
        name, "CONTENT_TYPE",
        (ctype or None) and ctype.lower(),
        want_ct.lower() if want_ct else None,
    )

print(f"tshark 交叉核验：比对 {checked} 项，跳过 {skipped} 项（非 identified 或已知例外）")
if failures:
    print()
    for f in failures:
        print("FAIL " + f)
    sys.exit(1)
print("tshark 与生成器期望值一致")
PYEOF
