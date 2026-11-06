#!/usr/bin/env bash
# One-time setup: download the free DB-IP Lite databases (CC BY 4.0) into data/, then build
# the netlog recorder and the Bun viewer.
set -euo pipefail
cd "$(dirname "$0")"

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

command -v cargo >/dev/null || { echo "need Rust (cargo) for netlog: https://rustup.rs" >&2; exit 1; }
command -v bun >/dev/null || { echo "need Bun for the viewer: https://bun.sh" >&2; exit 1; }
(cd netlog && cargo build --release)
(cd viewer && bun install && bun run build)
echo "ready: ./install-agents.sh   (or: netlog/target/release/netlog record &  then  cd viewer && bun run dev)"
