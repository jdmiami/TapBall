#!/usr/bin/env bash
# aios installer - current user only, no sudo.
#
# Creates ~/.aios/, copies agentd.py into it, writes a systemd *user* unit
# with Restart=on-failure, reloads the user daemon, and enables the unit.
# Prints every path it touches. Asks before overwriting an existing file.
#
# It writes only inside ~/.aios/ and the single systemd user unit file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_AGENTD="${SCRIPT_DIR}/agentd.py"

AIOS_HOME="${HOME}/.aios"
DEST_AGENTD="${AIOS_HOME}/agentd.py"
UNIT_DIR="${HOME}/.config/systemd/user"
UNIT_FILE="${UNIT_DIR}/aios.service"

say() { printf '%s\n' "$*"; }
touched() { printf 'touched: %s\n' "$1"; }

# Ask before overwriting. Returns 0 to proceed, 1 to skip.
confirm_overwrite() {
  local path="$1"
  if [ ! -e "$path" ]; then
    return 0
  fi
  printf 'File already exists: %s\n' "$path" >&2
  printf 'Overwrite? [y/N] ' >&2
  local reply=""
  read -r reply || reply=""
  case "$reply" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

if [ ! -f "$SRC_AGENTD" ]; then
  say "error: cannot find agentd.py next to this script (${SRC_AGENTD})" >&2
  exit 1
fi

say "aios install (user: $(id -un), no sudo)"

# 1. ~/.aios/ and subdirectories.
for d in "$AIOS_HOME" "$AIOS_HOME/boot" "$AIOS_HOME/logs" "$AIOS_HOME/work"; do
  if [ ! -d "$d" ]; then
    mkdir -p "$d"
    touched "$d"
  fi
done

# 2. Copy agentd.py.
if confirm_overwrite "$DEST_AGENTD"; then
  cp "$SRC_AGENTD" "$DEST_AGENTD"
  chmod 0755 "$DEST_AGENTD"
  touched "$DEST_AGENTD"
else
  say "skipped (kept existing): $DEST_AGENTD"
fi

# 3. systemd user unit.
if [ ! -d "$UNIT_DIR" ]; then
  mkdir -p "$UNIT_DIR"
  touched "$UNIT_DIR"
fi

if confirm_overwrite "$UNIT_FILE"; then
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=aios personal agent runtime (user-owned)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$(command -v python3) ${DEST_AGENTD}
Restart=on-failure
RestartSec=5
WorkingDirectory=${AIOS_HOME}

[Install]
WantedBy=default.target
EOF
  touched "$UNIT_FILE"
else
  say "skipped (kept existing): $UNIT_FILE"
fi

# 4. Reload + enable the user unit.
if command -v systemctl >/dev/null 2>&1; then
  if systemctl --user daemon-reload 2>/dev/null; then
    say "ran: systemctl --user daemon-reload"
    if systemctl --user enable aios.service 2>/dev/null; then
      say "ran: systemctl --user enable aios.service"
    else
      say "note: 'systemctl --user enable aios.service' did not complete"
      say "      (no user session bus?). Unit file is in place; enable it"
      say "      after login with: systemctl --user enable --now aios.service"
    fi
  else
    say "note: 'systemctl --user daemon-reload' did not complete (no user"
    say "      session bus?). Unit file is in place; reload+enable after login"
    say "      with: systemctl --user daemon-reload && systemctl --user enable --now aios.service"
  fi
else
  say "note: systemctl not found; unit file written to ${UNIT_FILE}"
fi

say ""
say "aios install complete."
say "Config expected at: ${AIOS_HOME}/config.json"
say "Stop any time by creating: ${AIOS_HOME}/STOP (or run uninstall.sh)"
