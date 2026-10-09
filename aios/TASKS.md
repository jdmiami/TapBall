# aios — Milestone 1: boot skeleton

Each item is checked only after its verification output is pasted into `VERIFY.md`.

## 1. `agentd.py` (Python 3.10+, stdlib only)
- [x] Read `~/.aios/config.json` (`server_url`, `public_key_path`, `poll_seconds`, `max_backoff_seconds`, `run_timeout_seconds`) each cycle
- [x] Exit cleanly if `~/.aios/STOP` exists
- [x] Fetch `{server_url}/boot/manifest.json` and `manifest.sig` over HTTPS with exponential backoff + jitter capped at `max_backoff_seconds`
- [x] Verify Ed25519 signature over manifest bytes with pinned public key (`openssl pkeyutl -verify -rawin`) before reading any field; clear error if `openssl` missing
- [x] Download each boot file to `~/.aios/boot/<name>.part`, check sha256, rename into place only on match
- [x] Run only the verified entrypoint as a child process with `run_timeout_seconds`, cwd inside `~/.aios/`
- [x] Append one JSON line to `~/.aios/logs/agentd.log` per fetch, verification result, run, and error; update heartbeat each cycle
- [x] `python3 -m py_compile aios/agentd.py` passes

## 2. `install.sh`
- [x] Current user only, no sudo; creates `~/.aios/`, copies `agentd.py`
- [x] Writes `~/.config/systemd/user/aios.service` with `Restart=on-failure`
- [x] Runs `systemctl --user daemon-reload` and enables the unit (falls back with printed instructions where no user session bus is present)
- [x] Prints every path it touched; asks before overwriting an existing file

## 3. `uninstall.sh`
- [x] Stops and disables the unit, removes the unit file and `~/.aios/`, prints what it removed, touches nothing else

## 4. `tests/` (unittest, local HTTP server, throwaway key)
- [x] Confirm installed `openssl` supports `pkeyutl -verify -rawin` for Ed25519 (test)
- [x] Valid signature is accepted
- [x] Bad signature is rejected before any field is read
- [x] sha256 mismatch leaves no file in `boot/`
- [x] Stop file ends the loop
- [x] Backoff never exceeds the cap

## 5. Verification (`VERIFY.md`)
- [x] `python3 -m py_compile` output
- [x] `python3 -m unittest discover -s aios/tests -v` output
- [x] `shellcheck aios/*.sh` output (shellcheck unavailable; `bash -n` substitute recorded)
- [x] Full install-then-uninstall run under a temporary HOME

## 6. `TASKS.md` kept current
- [x] All items above checked
