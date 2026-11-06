#!/usr/bin/env bash
# Install (or reinstall) launchd agents so the recorder, resolver and map viewer start at
# login and restart if they die. Logs go to ~/Library/Logs/netmap/.
#   ./install-agents.sh            install and start
#   ./install-agents.sh uninstall  stop and remove
#   VIEWER=bun ./install-agents.sh use the compiled Bun viewer (viewer/dist/netmap-viewer)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
NETLOG="$ROOT/netlog/target/release/netlog"
PY="$ROOT/.venv/bin/python"
BUN_VIEWER="$ROOT/viewer/dist/netmap-viewer"
AGENTS="$HOME/Library/LaunchAgents"
LOGS="$HOME/Library/Logs/netmap"
DOMAIN="gui/$(id -u)"
NAMES="com.tripp.netlog.record com.tripp.netlog.resolve com.tripp.netmap.viewer"

# bootout returns before the service is gone; bootstrapping too soon fails with "5: Input/output error".
stop_agent() {
  launchctl bootout "$DOMAIN/$1" 2>/dev/null || true
  for _ in $(seq 1 50); do
    launchctl print "$DOMAIN/$1" >/dev/null 2>&1 || return 0
    sleep 0.1
  done
}

if [[ "${1:-}" == "uninstall" ]]; then
  for name in $NAMES; do
    stop_agent "$name"
    rm -f "$AGENTS/$name.plist"
    echo "removed $name"
  done
  exit 0
fi

[[ -x "$NETLOG" ]] || { echo "build first: (cd netlog && cargo build --release)" >&2; exit 1; }
if [[ "${VIEWER:-python}" == "bun" ]]; then
  [[ -x "$BUN_VIEWER" ]] || { echo "build first: (cd viewer && bun install && bun run build)" >&2; exit 1; }
  VIEWER_CMD=("$BUN_VIEWER" --root "$ROOT")
else
  [[ -x "$PY" ]] || { echo "run ./setup.sh first" >&2; exit 1; }
  VIEWER_CMD=("$PY" "$ROOT/netmap.py" --viewer)
fi
mkdir -p "$AGENTS" "$LOGS"

# install NAME PROGRAM [ARGS...]
install() {
  local name=$1; shift
  local args=""
  for word in "$@"; do args+="    <string>$word</string>"$'\n'; done
  stop_agent "$name"
  cat > "$AGENTS/$name.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$name</string>
  <key>ProgramArguments</key>
  <array>
$args  </array>
  <key>WorkingDirectory</key><string>$ROOT</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>$LOGS/$name.log</string>
  <key>StandardErrorPath</key><string>$LOGS/$name.log</string>
</dict>
</plist>
EOF
  launchctl bootstrap "$DOMAIN" "$AGENTS/$name.plist"
  echo "started $name"
}

install com.tripp.netlog.record  "$NETLOG" record
install com.tripp.netlog.resolve "$NETLOG" resolve
install com.tripp.netmap.viewer  "${VIEWER_CMD[@]}"
