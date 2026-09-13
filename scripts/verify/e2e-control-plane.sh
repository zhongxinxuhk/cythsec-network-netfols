#!/usr/bin/env bash
# e2e-control-plane.sh —— 控制面四服务端到端验证。
#
# 这是 CYS-TEL-002「四服务 curl /metrics 均返回有效格式」的可执行验收：
#   1. 同时启动 routerd / policyd / dnsd / telemetryd
#   2. 逐个探测基础端点（/healthz、/api/v1/version、/metrics）
#   3. 逐个探测业务端点（/api/v1/{system,policies,zones,targets}）
#   4. 用独立实现的 Prometheus 文本格式校验器校验每份 /metrics
#   5. 用 jq 逐行解析日志（验证结构化日志契约）
#   6. 优雅关闭并确认端口已释放
#
# 为什么做成脚本而不是手工 curl：手工验证的结果无法复现、无法进 CI，
# 且「看起来通过」与「确实通过」之间缺少判据。本脚本对每项都给出明确
# 的通过/失败判定，并以失败项数作为退出码。
#
# 用法：
#   bash scripts/verify/e2e-control-plane.sh
#   bash scripts/verify/e2e-control-plane.sh --bin-dir build/bin
#   bash scripts/verify/e2e-control-plane.sh --help
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# 二进制默认位于 build/bin（build-all.sh 的 Go 输出目录）；
# build/ 本身是 CMake 的构建目录，两者刻意分离。
BIN_DIR="$ROOT/build/bin"
VALIDATOR="$ROOT/scripts/verify/check-prometheus-format.py"
PYTHON="${PYTHON:-python3}"

# 端口刻意避开默认值（8080-8083）：默认端口可能已被开发者的其他进程占用，
# 而本脚本的目的是验证服务本身，不是验证端口是否空闲。
BASE_PORT="${BASE_PORT:-18200}"

# 工作目录（测试夹具 + 四服务日志）。WORK_DIR 可用于 CI 指定固定路径，
# 便于失败时上传产物；KEEP_WORK=1 表示无条件保留。
WORK_DIR="${WORK_DIR:-}"
KEEP_WORK="${KEEP_WORK:-0}"

usage() {
  cat <<'EOF'
用法: e2e-control-plane.sh [--bin-dir DIR] [--help]

  --bin-dir DIR  二进制目录（默认 <repo>/build/bin）
  --help         显示本帮助

环境变量:
  PYTHON         用于运行指标校验器的 Python 解释器（默认 python3）
  BASE_PORT      起始端口（默认 18200，四服务依次 +0..+3）
  WORK_DIR       指定工作目录（默认自动创建临时目录）
  KEEP_WORK      设为 1 时无论成败都保留工作目录（含四服务日志）

前置条件:
  先执行 bash scripts/build/build-all.sh --go 生成四个二进制。

退出码:
  0 全部通过；1 存在失败项（具体项数见汇总行）；2 前置条件不满足（缺二进制/缺校验器）。
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# ---------- 判定与统计 ----------
PASSED=0
FAILED=0
SKIPPED=0

ok()   { PASSED=$((PASSED + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { FAILED=$((FAILED + 1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }
skip() { SKIPPED=$((SKIPPED + 1)); printf '  \033[33m-\033[0m %s（跳过）\n' "$1"; }

# 无代理直连：宿主机常设有 http_proxy，代理会让 127.0.0.1 也走代理而失败。
cget() { curl -s --noproxy '*' --max-time 5 "$@"; }

# ---------- 前置检查 ----------
echo "########## 0. 前置检查 ##########"

if [[ ! -f "$VALIDATOR" ]]; then
  echo "✗ 缺少指标格式校验器: $VALIDATOR" >&2
  exit 2
fi

missing_bins=""
for svc in routerd policyd dnsd telemetryd; do
  [[ -x "$BIN_DIR/$svc" ]] || missing_bins="${missing_bins} ${svc}"
done
if [[ -n "$missing_bins" ]]; then
  echo "✗ 缺少二进制:${missing_bins}" >&2
  echo "  请先执行: bash scripts/build/build-all.sh --go" >&2
  exit 2
fi
ok "四个二进制齐备 ($BIN_DIR)"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "✗ 找不到 Python 解释器: $PYTHON（可用 PYTHON=... 指定）" >&2
  exit 2
fi
ok "Python 校验器可用 ($PYTHON)"

HAVE_JQ=0
if command -v jq >/dev/null 2>&1; then
  HAVE_JQ=1
  ok "jq 可用（将逐行校验日志 JSON）"
else
  skip "jq 未安装，日志结构化校验被略过"
fi

# ---------- 测试夹具 ----------
# 为三个有状态服务提供最小合法输入，顺带端到端覆盖「文件载入」路径。
if [[ -n "$WORK_DIR" ]]; then
  mkdir -p "$WORK_DIR"
  WORK="$WORK_DIR"
else
  WORK="$(mktemp -d)"
fi

cat > "$WORK/policies.json" <<'EOF'
{"rules":[
  {"id":"r1","name":"默认放行","priority":10,"enabled":true,"expression":"true"},
  {"id":"r2","name":"阻断扫描源","priority":100,"enabled":true,"expression":"src in scanners"}
]}
EOF

cat > "$WORK/zones.json" <<'EOF'
{"zones":[
  {"name":"example.com","records":[
    {"name":"www","type":"A","ttl":300,"value":"192.0.2.1"},
    {"name":"@","type":"MX","ttl":3600,"value":"mail.example.com."}
  ]},
  {"name":"internal.test","records":[
    {"name":"api","type":"AAAA","ttl":60,"value":"2001:db8::1"}
  ]}
]}
EOF

cat > "$WORK/targets.json" <<'EOF'
{"targets":[
  {"name":"routerd","url":"http://127.0.0.1:8080/metrics","interval_seconds":15,"timeout_seconds":10,"enabled":true,"labels":{"env":"prod"}},
  {"name":"policyd","url":"http://127.0.0.1:8081/metrics","interval_seconds":30,"timeout_seconds":5,"enabled":false}
]}
EOF
ok "测试夹具已生成 ($WORK)"

# ---------- 启动四服务 ----------
echo
echo "########## 1. 启动四服务 ##########"

# 刻意使用「并行索引数组 + 查找函数」而非关联数组（declare -A）：
# macOS 自带 bash 3.2 不支持关联数组，用 -A 会在本地直接报
# "declare: -A: invalid option" 而 CI（bash 4+）却通过 —— 这类只在
# 开发者本机失败的门禁比没有门禁更糟。
declare -a PIDS=()
declare -a NAMES=(routerd policyd dnsd telemetryd)

# port_of <svc>：按服务在 NAMES 中的序位计算端口。
port_of() {
  local want="$1" i
  for i in "${!NAMES[@]}"; do
    if [[ "${NAMES[$i]}" == "$want" ]]; then
      echo "$((BASE_PORT + i))"
      return 0
    fi
  done
  return 1
}

# pid_of <svc>：PIDS 与 NAMES 下标一一对应。
pid_of() {
  local want="$1" i
  for i in "${!NAMES[@]}"; do
    if [[ "${NAMES[$i]}" == "$want" ]]; then
      echo "${PIDS[$i]:-}"
      return 0
    fi
  done
  return 1
}

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
}

# 退出时收尾。刻意在失败/显式要求时**保留**工作目录：各服务的完整日志都在
# 里面，那是排查失败原因的唯一线索 —— 若一律删除，CI 失败时只剩一句
# "退出码非 0"，等于把证据丢掉。KEEP_WORK=1 可无条件保留（本地调试用）。
finalize() {
  local rc=$?
  cleanup
  if [[ $rc -ne 0 || "$KEEP_WORK" == "1" ]]; then
    echo
    echo "工作目录已保留（含四服务完整日志）: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap finalize EXIT

for svc in "${NAMES[@]}"; do
  port="$(port_of "$svc")"
  log="$WORK/$svc.log"

  extra=()
  case "$svc" in
    routerd)    ;; # routerd 无外部状态文件
    policyd)    extra=(--policy-file "$WORK/policies.json") ;;
    dnsd)       extra=(--zone-file "$WORK/zones.json") ;;
    telemetryd) extra=(--target-file "$WORK/targets.json") ;;
  esac

  # 先把参数拼进一个非空数组再展开。不能直接写 `... "${extra[@]}"`：
  # set -u 下 bash 3.2 会把**空数组**的 "${arr[@]}" 判为 unbound variable，
  # 导致 routerd（唯一无需额外参数的）在启动行直接报错。
  args=(-addr "127.0.0.1:${port}" -log-format json)
  if [[ ${#extra[@]} -gt 0 ]]; then
    args+=("${extra[@]}")
  fi

  "$BIN_DIR/$svc" "${args[@]}" > "$log" 2>&1 &
  PIDS+=("$!")
  echo "  $svc -> 127.0.0.1:${port} (pid=${PIDS[${#PIDS[@]}-1]}, log=$svc.log)"
done

# 就绪等待：逐个服务等待，而非统一 sleep —— 统一 sleep 要么慢要么不稳。
for svc in "${NAMES[@]}"; do
  port="$(port_of "$svc")"
  pid="$(pid_of "$svc")"
  ready=0
  for _ in $(seq 1 60); do
    if cget -o /dev/null "http://127.0.0.1:${port}/healthz"; then
      ready=1
      break
    fi
    # 进程若已退出，再等也无意义 —— 立即暴露启动失败。
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  if [[ $ready -eq 1 ]]; then
    ok "$svc 就绪（端口 ${port}）"
  else
    bad "$svc 未就绪 —— 日志尾部："
    sed 's/^/      /' "$WORK/$svc.log" | tail -5
  fi
done

# ---------- 端点探测 ----------
echo
echo "########## 2. 基础端点与业务端点 ##########"

VERSION_FILE="$(tr -d '[:space:]' < VERSION)"

# 每个服务的业务端点路径。
biz_path() {
  case "$1" in
    routerd)    echo "/api/v1/system" ;;
    policyd)    echo "/api/v1/policies" ;;
    dnsd)       echo "/api/v1/zones" ;;
    telemetryd) echo "/api/v1/targets" ;;
  esac
}

idx=0
for svc in "${NAMES[@]}"; do
  port="$(port_of "$svc")"
  base="http://127.0.0.1:${port}"

  # --- /healthz ---
  body="$(cget "$base/healthz" || true)"
  if [[ "$body" == *"\"service\":\"${svc}\""* ]]; then
    ok "[$svc] /healthz 报出正确服务名"
  else
    bad "[$svc] /healthz 内容异常: ${body:-<空>}"
  fi

  # --- /api/v1/version（校验 ldflags 注入真的生效）---
  body="$(cget "$base/api/v1/version" || true)"
  if [[ "$body" == *"\"version\":\"${VERSION_FILE}\""* ]]; then
    ok "[$svc] /api/v1/version 版本号 = ${VERSION_FILE}"
  else
    bad "[$svc] /api/v1/version 版本号不符（期望 ${VERSION_FILE}）: ${body:-<空>}"
  fi
  if [[ "$body" == *"\"commit\":\"unknown\""* || "$body" == *"\"commit\":\"\""* ]]; then
    bad "[$svc] commit 未被注入（ldflags 未生效）: ${body:-<空>}"
  else
    ok "[$svc] commit 已注入"
  fi

  # --- 业务端点 ---
  p="$(biz_path "$svc")"
  code="$(cget -o /dev/null -w '%{http_code}' "$base$p" || true)"
  if [[ "$code" == "200" ]]; then
    ok "[$svc] $p 返回 200"
  else
    bad "[$svc] $p 返回 ${code}（期望 200）"
  fi

  # --- /metrics ---
  ctype="$(cget -o /dev/null -w '%{content_type}' "$base/metrics" || true)"
  cget "$base/metrics" -o "$WORK/$svc.metrics" || true
  if [[ -s "$WORK/$svc.metrics" ]]; then
    ok "[$svc] /metrics 返回非空内容（content-type=${ctype}）"
  else
    bad "[$svc] /metrics 内容为空"
  fi

  # --- 未知路径应为 404，而不是被兜底成 200 ---
  code="$(cget -o /dev/null -w '%{http_code}' "$base/definitely-not-a-route" || true)"
  if [[ "$code" == "404" ]]; then
    ok "[$svc] 未知路径返回 404"
  else
    bad "[$svc] 未知路径返回 ${code}（期望 404）"
  fi
done

# ---------- 指标格式独立校验 ----------
echo
echo "########## 3. Prometheus 文本格式独立校验（CYS-TEL-002） ##########"

for svc in "${NAMES[@]}"; do
  if PYTHONIOENCODING=utf-8 "$PYTHON" "$VALIDATOR" "$WORK/$svc.metrics" > "$WORK/$svc.validate" 2>&1; then
    families="$(grep -c '^# TYPE' "$WORK/$svc.metrics" || echo 0)"
    ok "[$svc] /metrics 格式合法（${families} 个指标族）"
  else
    bad "[$svc] /metrics 格式非法："
    sed 's/^/      /' "$WORK/$svc.validate" | head -6
  fi
done

# 交叉验证：四服务都应暴露同一套通用 HTTP 指标（命名约定一致性的证据）。
for metric in cythsec_http_requests_total cythsec_go_heap_alloc_bytes; do
  have=0
  for svc in "${NAMES[@]}"; do
    grep -q "^${metric}" "$WORK/$svc.metrics" && have=$((have + 1))
  done
  if [[ $have -eq 4 ]]; then
    ok "四服务均暴露 ${metric}（命名约定一致）"
  else
    bad "仅 ${have}/4 个服务暴露 ${metric}"
  fi
done

# 各服务自有指标应存在且非零。
check_gauge() {
  local svc="$1" metric="$2" want="$3"
  if grep -q "^${metric} ${want}\$" "$WORK/$svc.metrics"; then
    ok "[$svc] ${metric} = ${want}"
  else
    bad "[$svc] ${metric} 不等于 ${want}：$(grep "^${metric} " "$WORK/$svc.metrics" || echo '<缺失>')"
  fi
}
check_gauge policyd    cythsec_policyd_policies_entries        2
check_gauge dnsd       cythsec_dnsd_zones_entries              2
check_gauge dnsd       cythsec_dnsd_records_entries            3
check_gauge telemetryd cythsec_telemetryd_targets_entries      2
check_gauge telemetryd cythsec_telemetryd_targets_enabled_count 1

# ---------- 日志结构化校验 ----------
echo
echo "########## 4. 日志结构化校验 ##########"

if [[ $HAVE_JQ -eq 1 ]]; then
  for svc in "${NAMES[@]}"; do
    total="$(wc -l < "$WORK/$svc.log" | tr -d ' ')"
    parsable="$(jq -c . "$WORK/$svc.log" 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$total" -eq "$parsable" && "$total" -gt 0 ]]; then
      access="$(jq -r 'select(.msg=="http") | .request_id' "$WORK/$svc.log" 2>/dev/null | grep -c . || true)"
      ok "[$svc] ${total} 行日志全部可被 jq 解析（其中 ${access} 行访问日志）"
    else
      bad "[$svc] 日志 JSON 解析 ${parsable}/${total} 行（应全部可解析）"
    fi
  done

  # request_id 必须非空 —— 中间件顺序错误的典型症状就是它恒为空串。
  for svc in "${NAMES[@]}"; do
    empty="$(jq -r 'select(.msg=="http") | select(.request_id=="" or .request_id==null) | .request_id' \
      "$WORK/$svc.log" 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$empty" -eq 0 ]]; then
      ok "[$svc] 访问日志的 request_id 均非空"
    else
      bad "[$svc] 有 ${empty} 行访问日志的 request_id 为空（中间件顺序有误）"
    fi
  done
else
  skip "jq 不可用，跳过日志结构化校验"
fi

# ---------- 优雅关闭 ----------
echo
echo "########## 5. 优雅关闭与资源释放 ##########"

for svc in "${NAMES[@]}"; do
  pid="$(pid_of "$svc")"
  kill "$pid" 2>/dev/null || true
done

for svc in "${NAMES[@]}"; do
  pid="$(pid_of "$svc")"
  port="$(port_of "$svc")"

  gone=0
  for _ in $(seq 1 40); do
    if ! kill -0 "$pid" 2>/dev/null; then
      gone=1
      break
    fi
    sleep 0.25
  done

  if [[ $gone -eq 1 ]]; then
    if lsof -nP -iTCP:"$port" 2>/dev/null | grep -q LISTEN; then
      bad "[$svc] 进程已退出但端口 ${port} 仍被监听（未释放）"
    else
      ok "[$svc] 优雅退出且端口 ${port} 已释放"
    fi
  else
    bad "[$svc] 未在 10s 内退出（优雅关闭失效），强制终止"
    kill -9 "$pid" 2>/dev/null || true
  fi
done

# 关闭日志应存在（证明走的是优雅关闭路径而非被直接杀掉）。
if [[ $HAVE_JQ -eq 1 ]]; then
  for svc in "${NAMES[@]}"; do
    if jq -e 'select(.msg|test("关闭|停止|退出"))' "$WORK/$svc.log" >/dev/null 2>&1; then
      ok "[$svc] 日志记录了关闭过程"
    else
      bad "[$svc] 日志中没有关闭记录（可能未走优雅关闭路径）"
    fi
  done
fi

# ---------- 汇总 ----------
echo
echo "=================================================="
printf '端到端验证汇总：通过 %d，失败 %d，跳过 %d\n' "$PASSED" "$FAILED" "$SKIPPED"
echo "=================================================="

if [[ $FAILED -eq 0 ]]; then
  echo "全部通过 ✓"
  exit 0
fi
echo "存在失败项 ✗" >&2
exit 1
