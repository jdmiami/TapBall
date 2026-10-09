# aios — Verification log (Milestone 2: harden the runtime)

Environment: Linux, Python 3.13.16, OpenSSL 3.0.13. Commands run from the
repository root. `shellcheck` is still not installed in this environment, so
`bash -n` was used in its place (the shell scripts are unchanged from
Milestone 1).

All Milestone 2 writes stay inside `~/.aios/` (`logs/`, `results/`, `work/`);
nothing hides any process or file, and the STOP file and `uninstall.sh` are
untouched.

---

## 1. `python3 -m py_compile aios/agentd.py`

```
$ python3 -m py_compile aios/agentd.py ; echo $?
0
```

No output on success.

---

## 2. `python3 -m unittest discover -s aios/tests -v`  (Milestone 1 + 2)

```
Ran 25 tests in 4.729s

OK
```

Full list (11 from Milestone 1, all still passing, plus 14 new):

```
test_backoff_grows_then_clamps ... ok
test_backoff_never_exceeds_cap ... ok
test_zero_cap_is_zero ... ok
test_sha256_match_lands_file ... ok
test_sha256_mismatch_leaves_boot_empty ... ok
test_openssl_present_and_supports_rawin_ed25519 ... ok
test_stop_file_ends_loop_after_config_error ... ok
test_stop_file_ends_loop_immediately ... ok
test_bad_signature_rejected ... ok
test_bad_signature_rejected_before_any_field_read ... ok
test_valid_signature_accepted ... ok
test_bad_m2_value_rejected ... ok
test_m2_keys_are_read ... ok
test_milestone1_config_still_loads_with_defaults ... ok
test_log_rotates_and_caps_backups ... ok
test_rotation_failure_does_not_raise ... ok
test_results_pruned_to_keep ... ok
test_successful_run_writes_result ... ok
test_child_cwd_is_dedicated_run_dir ... ok
test_child_env_is_scrubbed ... ok
test_cpu_rlimit_applied_to_child ... ok
test_timeout_kills_whole_process_group ... ok
test_heartbeat_has_rich_fields ... ok
test_status_flag_emits_json ... ok
test_version_flag ... ok
```

Coverage mapping for Milestone 2:

| Hardening item | Test(s) |
| --- | --- |
| Log rotation + backup cap | `LogRotationTest.test_log_rotates_and_caps_backups` |
| Rotation never crashes the loop | `LogRotationTest.test_rotation_failure_does_not_raise` |
| Backward-compatible config / new keys / validation | `ConfigCompatTest.*` |
| Run-result record written | `ResultRecordTest.test_successful_run_writes_result` |
| Result pruning | `ResultRecordTest.test_results_pruned_to_keep` |
| Scrubbed child environment | `SandboxTest.test_child_env_is_scrubbed` |
| Dedicated per-run cwd | `SandboxTest.test_child_cwd_is_dedicated_run_dir` |
| CPU RLIMIT applied | `SandboxTest.test_cpu_rlimit_applied_to_child` |
| Process-group kill on timeout | `SandboxTest.test_timeout_kills_whole_process_group` |
| Rich heartbeat fields | `StatusCliTest.test_heartbeat_has_rich_fields` |
| `--status` / `--version` CLI | `StatusCliTest.test_status_flag_emits_json`, `test_version_flag` |

Milestone 1 invariants are re-proved by the unchanged M1 tests above
(STOP ends the loop, verify-before-read, sha256 mismatch leaves `boot/` empty,
backoff capped).

---

## 3. Shell scripts

```
$ bash -n aios/install.sh   && echo "install.sh OK"
install.sh OK
$ bash -n aios/uninstall.sh && echo "uninstall.sh OK"
uninstall.sh OK
```

`shellcheck` remains unavailable in this environment; scripts are unchanged
from Milestone 1 (verified end-to-end under a temporary HOME there).

---

## 4. `--version` and `--status`

```
$ python3 aios/agentd.py --version
0.2.0
```

```
$ python3 aios/agentd.py --status
{
  "aios_home": "<TMP>/.aios",
  "heartbeat": {
    "consecutive_failures": 0,
    "cycle": 3,
    "last_error": null,
    "last_outcome": "ok",
    "next_delay": 30.0,
    "pid": 532,
    "status": "idle",
    "ts": 1791514053.07869,
    "version": "0.2.0"
  },
  "log_tail": [
    {
      "event": "agentd_start",
      "pid": 1234,
      "ts": 1791514053.0783675,
      "version": "0.2.0"
    },
    {
      "bytes": 120,
      "event": "fetch",
      "ts": 1791514053.0786145,
      "url": "https://example.invalid/boot/manifest.json"
    }
  ],
  "stop_file_present": false,
  "version": "0.2.0"
}
```

---

## 5. Codex review fixes (follow-up to PR #2)

Codex reviewed PR #2 (commit `6901fc7`) after it merged and raised four
findings in `agentd.py`. All four held up when checked against the code and
are fixed:

| Finding | Problem | Fix |
| --- | --- | --- |
| P1 | On timeout, SIGKILL went to the group only if the leader was still alive, so a grandchild that ignored SIGTERM survived | Always SIGKILL the group (pgid = child pid, from `setsid`) after the grace period |
| P2 | `Popen`/`preexec_fn` failures escaped as raw exceptions and crashed the daemon (a regression from M1) | Wrapped in `AiosError`, so the loop logs and backs off |
| P2 | `NaN`/`Infinity` in config (Python's json accepts both) passed validation, then crashed or were used | `math.isfinite` check on every numeric key, M1 keys included |
| P2 | `child_cpu_seconds: 0.5` became a 0s `RLIMIT_CPU` and killed the child at once | `math.ceil` |

Also fixed: `test_timeout_kills_whole_process_group` could not fail. Its
grandchild slept 10s but the test waited only 1.5s. It now uses a 2s
grandchild and checks at 3.5s.

New tests run first against the unfixed `agentd.py` (commit `abed304`):

```
test_fractional_cpu_limit_rounds_up ... ERROR
test_launch_failure_is_recoverable_error ... ERROR
test_non_finite_values_rejected_as_config_errors ...  (9 FAIL + 10 ERROR across 16 subtests)
test_timeout_kills_sigterm_ignoring_descendant ... FAIL
test_timeout_kills_whole_process_group ... ok
AssertionError: True is not false : grandchild survived group kill
FileNotFoundError: [Errno 2] No such file or directory: '.../no-such-python'
ValueError: cannot convert float NaN to integer
OverflowError: cannot convert float infinity to integer
AssertionError: AiosError not raised
FAILED (failures=9, errors=10)
```

Then against the fixed code:

```
test_non_finite_values_rejected_as_config_errors ... ok
test_fractional_cpu_limit_rounds_up ... ok
test_launch_failure_is_recoverable_error ... ok
test_timeout_kills_sigterm_ignoring_descendant ... ok
test_timeout_kills_whole_process_group ... ok
Ran 5 tests in 7.072s
OK
```

Full suite (M1 + M2 + M3), three consecutive runs:

```
Ran 46 tests in 11.607s  OK
Ran 46 tests in 12.075s  OK
Ran 46 tests in 12.266s  OK
```

---

## Summary

| Check | Result |
| --- | --- |
| `python3 -m py_compile aios/agentd.py` | PASS |
| `python3 -m unittest discover -s aios/tests -v` | PASS (25/25) |
| `bash -n aios/*.sh` | PASS (shellcheck unavailable) |
| `--status` / `--version` CLI | PASS |
