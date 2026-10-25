#!/usr/bin/env bash
#
# scan-secrets.sh —— 仓库明文凭据/密钥兜底扫描器（CYS-SEC-003 / CYS-SEC-006）
#
# 设计原则：
#   1. 零外部依赖：仅用系统自带 grep（grep -rEn），不依赖 gitleaks / truffleHog 等工具。
#   2. 只报「文件:行号:模式名」，绝不在 stdout 打印密钥原文，避免把密钥二次泄露到
#      日志 / CI 输出 / 终端截图。
#   3. 命中任何一条即输出汇总并以非 0 退出码返回，便于接入 pre-commit 与 CI 门禁。
#   4. 正则使用 POSIX 扩展正则（ERE），兼容 BSD grep（macOS）与 GNU grep（Linux CI），
#      不使用 \s \w \b (?i) 等 GNU 扩展。
#
# 用法：
#   scripts/security/scan-secrets.sh [REPO_ROOT]
#   REPO_ROOT 缺省为脚本所在仓库根（../..）。
#
# 退出码：0 = 未发现命中；1 = 发现命中；2 = 用法/内部错误。
#

# 注：不启用 set -u。macOS 自带 bash 3.2 在 set -u 下存在已知缺陷，
# 会对已赋值变量误报 unbound variable；本脚本通过显式判空保证健壮性。
_script_dir="$(cd "$(dirname "${0:-.}")" && pwd)"
REPO="${1:-$(cd "$_script_dir/../.." && pwd)}"
if [ ! -d "$REPO" ]; then
  echo "ERROR: REPO_ROOT 不存在: $REPO" >&2
  exit 2
fi
if ! REPO="$(cd "$REPO" && pwd)"; then
  echo "ERROR: cannot normalize REPO_ROOT" >&2
  exit 2
fi

# 扫描排除项：构建产物、依赖、VCS、测试夹具、示例配置、文档。
EXCLUDES=(
  --exclude-dir=.git
  --exclude-dir=node_modules
  --exclude-dir=dist
  --exclude-dir=target
  --exclude-dir=build
  --exclude-dir=.idea
  --exclude-dir=cmake-build-debug
  --exclude-dir=docs
  --exclude=package-lock.json
  --exclude=Cargo.lock
  --exclude='*_test.go'
  --exclude='*_test.rs'
  --exclude='*.example'
  --exclude='.env.example'
  --exclude='*.pcap'
  --exclude='*.pcapng'
  --exclude='*.min.js'
)

# 命中结果收集到临时文件
HITS="$(mktemp)"
trap 'rm -f "$HITS"' EXIT

# scan_rule <模式名> <正则(ERE)> [<负向过滤正则,排除占位符/样例>] [<grep附加标志,如 i>]
# 用 -e 传递模式，避免以 "-" 开头的模式（如 PEM 头）被误判为选项。
# 负向过滤在纯 bash 内完成（不用第二根 grep 管道），避免 BSD/toybox grep 在管道
# 与递归扫描（遇到坏软链会向 stdout 吐错误行）下的非预期行为。
scan_rule() {
  local name="$1" pat="$2" neg="${3:-}" flags="${4:-}"
  local matches filtered line f rest ln m
  matches="$(grep -rIE${flags}n -e "$pat" "$REPO" "${EXCLUDES[@]}" 2>/dev/null)"
  if [ -n "$neg" ]; then
    # 负向过滤（纯 bash，避免管道/递归扫描下的非预期行为）。
    # 仅对「内容部分」（首个 file:line: 之后的文本）做占位符判定，避免文件名误判。
    filtered=""
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      content="${line#*:}"
      content="${content#*:}"
      # GitHub 的纯运行时引用不是明文值。仅放行 workflow 中整行、无拼接的
      # secrets.NAME / github.token 引用；后缀、条件表达式或同一行其他赋值仍扫描。
      local runtime_ref='^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:[[:space:]]*\$\{\{[[:space:]]*(secrets\.[A-Za-z_][A-Za-z0-9_]*|github\.token)[[:space:]]*\}\}[[:space:]]*$'
      if [[ "$name" == GENERIC_SECRET_ASSIGN && "$content" =~ $runtime_ref ]]; then
        case "${line%%:*}" in
          "$REPO"/.github/workflows/*.yml | "$REPO"/.github/workflows/*.yaml) continue ;;
        esac
      fi
      if [[ "$content" =~ $neg ]]; then
        continue
      fi
      filtered+="$line"$'\n'
    done <<< "$matches"
    matches="$filtered"
  fi
  if [ -n "$matches" ]; then
    # 只输出 文件:行号:模式名，剥离匹配文本（含密钥原文），避免二次泄露。
    printf '%s\n' "$matches" | while IFS= read -r m; do
      # 注意：bash 3.2 在单条 local 内多赋值会引用旧值，必须分行赋值。
      f="${m%%:*}"
      # CYS-MLT-001: this exact project-local environment contains installed
      # dependencies, not repository sources. Do not exempt other Python paths.
      case "$f" in
        "${REPO}/ml/training/.venv/"*) continue ;;
      esac
      rest="${m#*:}"
      ln="${rest%%:*}"
      # 仅当能解析出 文件:行号 时才记录，丢弃异常行。
      [ -z "$f" ] && continue
      printf '%s:%s:%s\n' "$f" "$ln" "$name"
    done >> "$HITS"
  fi
}

echo "==> 扫描明文密钥 / 凭据（仓库根: ${REPO}）"

# 1) AWS Access Key ID
scan_rule "AWS_ACCESS_KEY_ID" 'AKIA[0-9A-Z]{16}'

# 2) AWS Secret Access Key（赋值形态，大小写不敏感）
scan_rule "AWS_SECRET_ACCESS_KEY" '[Aa][Ww][Ss][_.]?secret[_ ]?access[_ ]?key[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9/+]{40}' '' 'i'

# 3) GitHub Personal Access Token（经典 ghp_ / 细粒度 github_pat_ 等）
scan_rule "GITHUB_PAT" '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'

# 4) Google API Key
scan_rule "GOOGLE_API_KEY" 'AIza[0-9A-Za-z_-]{35}'

# 5) Slack Token
scan_rule "SLACK_TOKEN" 'xox[baprs]-[0-9A-Za-z-]{10,}'

# 6) 微信 / 支付宝相关敏感键名（本项目上下文相关，大小写不敏感）
scan_rule "WECHAT_ALIPAY_KEY" '(wechat|weixin|alipay|app_?secret|mch_?id|api_?v3_?key|private_?key|cert_?key)[[:space:]]*[:=]' '' 'i'

# 7) PEM 私钥头（用 -e 传递，避免开头 ----- 被当成选项）
scan_rule "PEM_PRIVATE_KEY" '-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----'

# 8) JWT（三段式 eyJ...eyJ...签名）
scan_rule "JWT" 'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'

# 9) 通用凭据赋值（password/secret/token/api_key 等），排除占位符/样例/模板变量
scan_rule "GENERIC_SECRET_ASSIGN" \
  '(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)[[:space:]]*[:=]' \
  'example|sample|placeholder|changeme|xxxx|your[-_]|todo|fixme|dummy|<<|%[A-Z]|your-|xxxxx' \
  'i'

# 输出结果
if [ -s "$HITS" ]; then
  echo
  echo "!!! 发现疑似明文密钥 / 凭据（已隐去密钥原文，仅显示位置与模式名）："
  sort -u "$HITS" | while IFS= read -r line; do
    echo "    $line"
  done
  echo
  echo "==> 结论：命中 $(wc -l < "$HITS" | tr -d ' ') 处。请立即轮转相关凭据并从仓库移除。"
  exit 1
else
  echo
  echo "==> 结论：当前仓库未发现明文密钥 / 凭据（命中 0 处）。"
  exit 0
fi
