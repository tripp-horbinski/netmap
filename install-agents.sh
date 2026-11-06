#!/usr/bin/env bash
# Install (or reinstall) launchd agents so the recorder, resolver and map viewer start at
# login and restart if they die. Logs go to ~/Library/Logs/netmap/.
#   ./install-agents.sh            install and start (recorder, resolver, viewer as your user)
#   sudo ./install-agents.sh       same, but the recorder runs as root so pktap can name every
#                                  connection's process (short-lived ones and system daemons too)
#   ./install-agents.sh uninstall  stop and remove (sudo to also remove the root recorder)
# Rerun after rebuilding netlog or the viewer (`bun run build`).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
NETLOG="$ROOT/netlog/target/release/netlog"
BUN_VIEWER="$ROOT/viewer/dist/netmap-viewer"
# Under sudo, install the user agents for the invoking user and the recorder as a system daemon.
USER_NAME="${SUDO_USER:-$(id -un)}"
USER_HOME="$(dscl . -read "/Users/$USER_NAME" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
USER_HOME="${USER_HOME:-$HOME}"
USER_UID="$(id -u "$USER_NAME")"
AGENTS="$USER_HOME/Library/LaunchAgents"
DAEMONS="/Library/LaunchDaemons"
LOGS="$USER_HOME/Library/Logs/netmap"
DOMAIN="gui/$USER_UID"
NAMES="com.tripp.netlog.record com.tripp.netlog.resolve com.tripp.netmap.viewer"
RECORD_DAEMON="com.tripp.netlog.record"
AS_ROOT=0; [[ "$(id -u)" == 0 ]] && AS_ROOT=1
# Run a launchctl command as the user whose agents these are (matters under sudo).
as_user() { if [[ $AS_ROOT == 1 ]]; then sudo -u "$USER_NAME" "$@"; else "$@"; fi; }

# bootout returns before the service is gone; bootstrapping too soon fails with "5: Input/output error".
stop_agent() {
  as_user launchctl bootout "$DOMAIN/$1" 2>/dev/null || true
  for _ in $(seq 1 50); do
    as_user launchctl print "$DOMAIN/$1" >/dev/null 2>&1 || return 0
    sleep 0.1
  done
}
stop_daemon() {
  [[ $AS_ROOT == 1 ]] || return 0
  launchctl bootout "system/$1" 2>/dev/null || true
  for _ in $(seq 1 50); do
    launchctl print "system/$1" >/dev/null 2>&1 || return 0
    sleep 0.1
  done
}

if [[ "${1:-}" == "uninstall" ]]; then
  for name in $NAMES; do
    stop_agent "$name"
    rm -f "$AGENTS/$name.plist"
    echo "removed $name"
  done
  if [[ $AS_ROOT == 1 && -f "$DAEMONS/$RECORD_DAEMON.plist" ]]; then
    stop_daemon "$RECORD_DAEMON"; rm -f "$DAEMONS/$RECORD_DAEMON.plist"; echo "removed $RECORD_DAEMON (daemon)"
  fi
  exit 0
fi

[[ -x "$NETLOG" ]] || { echo "build first: (cd netlog && cargo build --release)" >&2; exit 1; }
[[ -x "$BUN_VIEWER" ]] || { echo "build first: (cd viewer && bun install && bun run build)" >&2; exit 1; }
VIEWER_CMD=("$BUN_VIEWER" --root "$ROOT")
mkdir -p "$AGENTS" "$LOGS"

# plist NAME PROGRAM [ARGS...]: the launchd job definition on stdout.
plist() {
  local name=$1; shift
  local args=""
  for word in "$@"; do args+="    <string>$word</string>"$'\n'; done
  cat <<EOF
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
}

# install NAME PROGRAM [ARGS...]: a per-user agent.
install() {
  local name=$1
  stop_agent "$name"
  plist "$@" > "$AGENTS/$name.plist"
  [[ $AS_ROOT == 1 ]] && chown "$USER_NAME" "$AGENTS/$name.plist"
  as_user launchctl bootstrap "$DOMAIN" "$AGENTS/$name.plist"
  echo "started $name"
}

# install_daemon NAME PROGRAM [ARGS...]: a system daemon (root), replacing the user agent of the same name.
install_daemon() {
  local name=$1
  stop_agent "$name"; rm -f "$AGENTS/$name.plist"
  stop_daemon "$name"
  plist "$@" > "$DAEMONS/$name.plist"
  chown root:wheel "$DAEMONS/$name.plist"; chmod 644 "$DAEMONS/$name.plist"
  launchctl bootstrap system "$DAEMONS/$name.plist"
  echo "started $name (root daemon: pktap names every connection)"
}

[[ $AS_ROOT == 1 ]] && chown -R "$USER_NAME" "$LOGS"
if [[ $AS_ROOT == 1 ]]; then
  install_daemon com.tripp.netlog.record "$NETLOG" record
else
  if [[ -f "$DAEMONS/$RECORD_DAEMON.plist" ]]; then
    echo "note: the recorder is installed as a root daemon; rerun with sudo to restart it on a new build" >&2
  else
    install com.tripp.netlog.record "$NETLOG" record
  fi
fi
install com.tripp.netlog.resolve "$NETLOG" resolve
install com.tripp.netmap.viewer  "${VIEWER_CMD[@]}"
