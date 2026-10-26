#!/usr/bin/env bash
# Shared CLion entrypoint: delegate builds/tests to the repository's real gates.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"
# Optional machine-only tool locations; never store credentials in this file.
[[ ! -f scripts/dev/config.local.env ]] || source scripts/dev/config.local.env
# IDE configurations never authorize privilege escalation.
export CYTHSEC_LIVE_SUDO=0
action="${1:-help}"
[[ $# == 0 ]] || shift
run_gate() {
  local evidence rc
  local -a statuses
  mkdir -p build/clion/runs
  evidence="$(mktemp -d "$ROOT/build/clion/runs/${action}.XXXXXX")"
  echo "Evidence: $evidence"
  set +e
  "$@" 2>&1 | tee "$evidence/output.log"
  statuses=("${PIPESTATUS[@]}")
  set -e
  rc="${statuses[0]}"
  [[ "$rc" != 0 || "${statuses[1]}" == 0 ]] || rc="${statuses[1]}"
  printf '%s\n' "$rc" > "$evidence/exit-code"
  return "$rc"
}
case "$action" in
  build) run_gate bash scripts/build/build-all.sh "$@" ;;
  lint) run_gate bash scripts/lint/lint-all.sh "$@" ;;
  test) run_gate bash scripts/test/test-all.sh "$@" ;;
  e2e-control) exec bash scripts/verify/e2e-control-plane.sh "$@" ;;
  check-ide) exec bash scripts/verify/check-clion-configs.sh "$@" ;;
  audit) exec npm --prefix web/console audit --package-lock-only --audit-level=low ;;
  preflight)
    failed=0
    for tool in cmake c++ cargo go node npm python3 uv tshark clang-format; do
      if command -v "$tool" >/dev/null 2>&1; then
        printf 'READY %-14s %s\n' "$tool" "$(command -v "$tool")"
      else
        printf 'MISSING %s\n' "$tool"; failed=1
      fi
    done
    exit "$failed" ;;
  run)
    service="${1:-}"; [[ $# == 0 ]] || shift
    case "$service" in
      routerd) port=18080 ;;
      policyd) port=18081 ;;
      dnsd) port=18082 ;;
      telemetryd) port=18083 ;;
      *) echo 'Expected routerd, policyd, dnsd or telemetryd' >&2; exit 2 ;;
    esac
    [[ -x "build/bin/$service" ]] || { echo 'Run CythSec Build Go first' >&2; exit 1; }
    args=(-config "services/$service/configs/config.yaml" -addr "127.0.0.1:$port")
    if [[ "$service" == telemetryd ]]; then
      args+=(-aggregate-dir build/clion/aggregate/archive -aggregate-queue-dir build/clion/aggregate/queue)
    fi
    # Use exec so CLion Stop reaches the actual service and graceful shutdown.
    exec "build/bin/$service" "${args[@]}" "$@" ;;
  console)
    [[ -d web/console/node_modules ]] || { echo 'Run CythSec Build Console first' >&2; exit 1; }
    export PORT=15174
    export VITE_ROUTERD_TARGET=http://127.0.0.1:18080
    export VITE_TELEMETRYD_TARGET=http://127.0.0.1:18083
    exec npm --prefix web/console run dev ;;
  observe-sample)
    bash scripts/test/prepare-rust-fixtures.sh
    mkdir -p build/clion/observations
    # The observer refuses overwrites; retain every local run as independent evidence.
    output="$(mktemp -d "$ROOT/build/clion/observations/run.XXXXXX")"
    exec cargo run --offline --bin cythsec-observe -- -r datasets/pcap/sample-session-tcp.pcap -o "$output/aggregate.jsonl" ;;
  monitor) exec bash scripts/dev/monitor-local.sh "$@" ;;
  help|--help|-h)
    echo 'Usage: clion.sh {preflight|build [--cpp|--rust|--go|--node]|lint|test [group]|e2e-control|check-ide|audit|run SERVICE|console|observe-sample|monitor [--watch]}' ;;
  *) echo "Unknown action: $action" >&2; exit 2 ;;
esac
