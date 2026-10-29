#!/usr/bin/env bash
# Dedicated Linux CI runner: deterministic traffic on an isolated veth pair.
# Run the default suite as the runner user; only capture subprocesses use sudo.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
[[ "$(uname -s)" == Linux ]] || { echo "Linux required" >&2; exit 2; }
namespace="cythsec-ci"
cleanup() {
  sudo ip netns del "$namespace" 2>/dev/null || true
  sudo ip link del cysci0 2>/dev/null || true
}
trap cleanup EXIT
sudo ip netns add "$namespace"
sudo ip link add cysci0 type veth peer name cysci1
sudo ip link set cysci1 netns "$namespace"
sudo ip addr add 198.18.0.1/30 dev cysci0
sudo ip link set cysci0 up
sudo ip -n "$namespace" addr add 198.18.0.2/30 dev cysci1
sudo ip -n "$namespace" link set lo up
sudo ip -n "$namespace" link set cysci1 up
export CYTHSEC_LIVE_IFACE=cysci0 CYTHSEC_LIVE_TARGET=198.18.0.2 CYTHSEC_LIVE_SUDO=1
if [[ $# -eq 0 ]]; then
  set -- bash scripts/verify/e2e-live-capture.sh
fi
"$@"
