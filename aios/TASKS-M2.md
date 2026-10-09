# aios — Milestone 2: harden the runtime

Builds on Milestone 1 without changing its guarantees: stdlib only, writes only
inside `~/.aios/`, transparent and user-owned, never hides anything, never
blocks the STOP file or uninstall. Each item is checked only after its
verification output is pasted into `VERIFY-M2.md`.

## 1. Log rotation (inside `~/.aios/logs/` only)
- [x] `agentd.log` rotates when it reaches `log_max_bytes`, keeping `log_backups` numbered files
- [x] Rotation never raises out of `log()`; the loop survives a rotation failure
- [x] New optional config keys default sensibly; a Milestone 1 config still loads

## 2. Structured run-result records (inside `~/.aios/results/` only)
- [x] Each entrypoint run writes one `results/<ts>.json`: entrypoint, returncode, started, duration, stdout/stderr tails (bounded), truncation flags
- [x] Old result files are pruned to `results_keep`

## 3. Richer heartbeat / status
- [x] Heartbeat includes version, consecutive_failures, last_error, last_outcome, next_delay
- [x] `agentd.py --status` prints current heartbeat + recent log tail as JSON and exits 0
- [x] `agentd.py --version` prints the version and exits 0

## 4. Child-process sandboxing (restricts the child; hides nothing)
- [x] Child runs with a scrubbed, minimal environment (no inherited secrets)
- [x] Child runs in its own session/process group; a timeout kills the whole group
- [x] Optional `child_cpu_seconds` / `child_memory_bytes` applied as RLIMITs on POSIX
- [x] Child cwd is a dedicated per-run directory inside `~/.aios/work/`

## 5. Invariants preserved from Milestone 1
- [x] STOP file still ends the loop promptly
- [x] Signature-before-any-field-read still holds
- [x] sha256 mismatch still leaves `boot/` clean
- [x] Backoff still capped
- [x] All Milestone 1 tests still pass unchanged

## 6. Verification (`VERIFY-M2.md`)
- [x] `python3 -m py_compile aios/agentd.py`
- [x] `python3 -m unittest discover -s aios/tests -v` (M1 + M2 tests)
- [x] `bash -n` on the shell scripts (shellcheck still unavailable)
- [x] `agentd.py --status` / `--version` sample output
