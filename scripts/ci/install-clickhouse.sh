#!/usr/bin/env bash
# Official ClickHouse LTS binary used as an independent Native/MergeTree judge.
set -euo pipefail
[[ "$(uname -s)/$(uname -m)" == Linux/x86_64 ]] || { echo 'Linux x86_64 required' >&2; exit 2; }
version=25.8.1.5101
archive="clickhouse-common-static-${version}-amd64.tgz"
checksum=07260ddec510bddf0014c9429d5d77fe8a7d7f31a074637ad3c3e1057f72daecf481f271d9fb7c60b1592fe5cf86ea81050186a0fbf631ec2eeb9a7140dd2d01
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl --fail --show-error --location --retry 3 --connect-timeout 20 --max-time 300 \
  "https://packages.clickhouse.com/tgz/lts/${archive}" -o "$work/$archive"
(cd "$work" && printf '%s  %s\n' "$checksum" "$archive" | sha512sum --check)
tar -xzf "$work/$archive" -C "$work" "clickhouse-common-static-${version}/usr/bin/clickhouse"
sudo install -m 0755 "$work/clickhouse-common-static-${version}/usr/bin/clickhouse" /usr/local/bin/clickhouse
clickhouse local --version
