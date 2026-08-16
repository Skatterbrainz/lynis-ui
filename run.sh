#!/usr/bin/env bash
# Launches the Lynis Findings Web Dashboard.
#
# Runs the Flask app with sudo because it needs to:
#   - read /var/log/lynis-report.dat (root-owned)
#   - write /etc/lynis/custom.prf (root-owned)
#
# The server only binds to localhost, so it is not reachable from the network.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! python3 -c "import flask" 2>/dev/null; then
  echo "Flask not found for python3 — installing via apt (python3-flask)..."
  sudo apt-get update -qq
  sudo apt-get install -y python3-flask
fi

URL="http://localhost:5000"

# Prompt for the sudo password up front (before starting anything else) so the
# background browser-opener below isn't racing against an unanswered prompt.
sudo -v

wait_for_server_then_open() {
  local attempt
  for attempt in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/localhost/5000") 2>/dev/null; then
      exec 3>&- 3<&- 2>/dev/null || true
      break
    fi
    sleep 0.2
  done
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 || true
  fi
}

wait_for_server_then_open &

# Forward optional path overrides through sudo (which strips the environment
# by default). Set these before running ./run.sh to point at a different
# report.dat / custom.prf, e.g.:
#   LYNIS_REPORT_PATH=/path/to/lynis-report.dat ./run.sh
PRESERVE_ENV=""
if [ -n "${LYNIS_REPORT_PATH:-}" ]; then
  PRESERVE_ENV="LYNIS_REPORT_PATH"
fi
if [ -n "${LYNIS_CUSTOM_PROFILE_PATH:-}" ]; then
  PRESERVE_ENV="${PRESERVE_ENV:+$PRESERVE_ENV,}LYNIS_CUSTOM_PROFILE_PATH"
fi

echo "Starting Lynis Findings Dashboard at $URL (Ctrl+C to stop)..."
if [ -n "$PRESERVE_ENV" ]; then
  sudo --preserve-env="$PRESERVE_ENV" python3 "$SCRIPT_DIR/app.py"
else
  sudo python3 "$SCRIPT_DIR/app.py"
fi
