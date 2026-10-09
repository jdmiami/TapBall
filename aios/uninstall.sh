#!/usr/bin/env bash
# aios uninstaller - stops and disables the user unit, removes the unit file
# and ~/.aios/, and prints what it removed. It touches nothing else.
set -euo pipefail

AIOS_HOME="${HOME}/.aios"
UNIT_FILE="${HOME}/.config/systemd/user/aios.service"

say() { printf '%s\n' "$*"; }
removed() { printf 'removed: %s\n' "$1"; }

say "aios uninstall (user: $(id -un), no sudo)"

# 1. Stop and disable the unit (best effort; never fail the uninstall).
if command -v systemctl >/dev/null 2>&1; then
  if systemctl --user stop aios.service 2>/dev/null; then
    say "ran: systemctl --user stop aios.service"
  fi
  if systemctl --user disable aios.service 2>/dev/null; then
    say "ran: systemctl --user disable aios.service"
  fi
fi

# 2. Remove the unit file.
if [ -e "$UNIT_FILE" ]; then
  rm -f "$UNIT_FILE"
  removed "$UNIT_FILE"
else
  say "not present: $UNIT_FILE"
fi

# 3. Reload the user daemon so the removed unit is forgotten (best effort).
if command -v systemctl >/dev/null 2>&1; then
  if systemctl --user daemon-reload 2>/dev/null; then
    say "ran: systemctl --user daemon-reload"
  fi
fi

# 4. Remove ~/.aios/.
if [ -d "$AIOS_HOME" ]; then
  rm -rf "$AIOS_HOME"
  removed "$AIOS_HOME"
else
  say "not present: $AIOS_HOME"
fi

say ""
say "aios uninstall complete."
