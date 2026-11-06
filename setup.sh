#!/usr/bin/env bash
# Create a virtualenv and download the free DB-IP Lite databases (CC BY 4.0).
set -euo pipefail
cd "$(dirname "$0")"

[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q maxminddb

mkdir -p data
fetch() {
  local name=$1
  if ls data/"$name"-*.mmdb >/dev/null 2>&1; then echo "have $name"; return; fi
  for m in "$(date +%Y-%m)" "$(date -v-1m +%Y-%m)"; do
    local url="https://download.db-ip.com/free/$name-$m.mmdb.gz"
    if curl -fsSL "$url" -o "data/$name-$m.mmdb.gz"; then
      gunzip -f "data/$name-$m.mmdb.gz"
      echo "downloaded $name-$m"
      return
    fi
  done
  echo "could not download $name" >&2
  exit 1
}
fetch dbip-city-lite
fetch dbip-asn-lite
echo "ready: .venv/bin/python netmap.py"
