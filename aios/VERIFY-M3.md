# aios — Verification log (Milestone 3: signing/publish tooling)

Environment: Linux, Python 3.13.16, OpenSSL 3.0.13. Commands run from the
repository root unless shown otherwise. `agentd.py`, `install.sh` and
`uninstall.sh` are unchanged from Milestone 2 (`git diff --stat
claude/aios-m2-harden -- aios/agentd.py aios/install.sh aios/uninstall.sh` is
empty).

---

## 1. `python3 -m py_compile aios/agentd.py aios/publish.py`

```
$ python3 -m py_compile aios/agentd.py aios/publish.py ; echo $?
0
```

---

## 2. `python3 -m unittest discover -s aios/tests -v`  (M1 + M2 + M3)

Run three times in a row to check the end-to-end tests for flakiness:

```
Ran 38 tests in 7.604s  OK
Ran 38 tests in 6.995s  OK
Ran 38 tests in 6.987s  OK
```

Full verbose run (class/module suffixes trimmed):

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
run_cycle must refuse to json.loads the manifest when the sig fails. ... ok
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
test_output_verifies_with_agentd_and_hashes_match ... ok
test_refuses_existing_output_without_force ... ok
test_rejects_entrypoint_not_in_boot_files ... ok
test_rejects_reserved_name ... ok
test_rejects_subdirectory ... ok
test_agentd_fetches_verifies_runs_and_stops ... ok
test_agentd_rejects_untrusted_tls_cert ... ok
test_private_key_is_0600_and_public_key_written ... ok
test_refuses_overwrite ... ok
test_clean_output_passes ... ok
test_tampered_boot_file_fails ... ok
test_tampered_manifest_fails_on_signature ... ok
test_wrong_public_key_fails ... ok
Ran 38 tests in 7.001s
OK
```

Milestone 3 coverage (`tests/test_publish.py`, 13 tests):

| Item | Test(s) |
| --- | --- |
| keygen: private key 0600, public key written | `KeygenTest.test_private_key_is_0600_and_public_key_written` |
| keygen: refuses overwrite, key unchanged | `KeygenTest.test_refuses_overwrite` |
| build: output verifies via `agentd.verify_signature`; hashes and copies match | `BuildTest.test_output_verifies_with_agentd_and_hashes_match` |
| build: entrypoint must be a boot file | `BuildTest.test_rejects_entrypoint_not_in_boot_files` |
| build: subdirectories and reserved names rejected | `BuildTest.test_rejects_subdirectory`, `test_rejects_reserved_name` |
| build: existing output needs `--force` | `BuildTest.test_refuses_existing_output_without_force` |
| verify: clean / tampered boot file / tampered manifest / wrong key | `VerifyTest.*` |
| End to end, trusted cert: real `agentd.py` fetches over HTTPS, verifies, runs, records result, stops on STOP | `EndToEndTest.test_agentd_fetches_verifies_runs_and_stops` |
| End to end, untrusted cert: TLS fails, nothing fetched/verified/run, `boot/` and `results/` empty | `EndToEndTest.test_agentd_rejects_untrusted_tls_cert` |

The end-to-end tests trust the dev cert by setting `SSL_CERT_FILE` for the
agentd process only. agentd's TLS handling is unchanged, and the
untrusted-cert test shows it still enforces verification
(`CERTIFICATE_VERIFY_FAILED`).

---

## 3. Manual owner flow: keygen → build → verify → tamper → verify

Run in a scratch directory containing `src/main.py` and `src/helper.py`.

```
$ publish.py keygen --out-dir keys
wrote: keys/aios.key.pem (private, mode 0600)
wrote: keys/aios.pub.pem (public; set agentd public_key_path to this)
exit=0
$ stat -c '%a %n' keys/aios.key.pem
600 keys/aios.key.pem

$ publish.py keygen --out-dir keys   (again)
error: refusing to overwrite existing file: keys/aios.key.pem
exit=2

$ publish.py build --boot-dir src --entrypoint main.py --key keys/aios.key.pem --out-dir out
wrote: out/boot/helper.py
wrote: out/boot/main.py
wrote: out/boot/manifest.json
wrote: out/boot/manifest.sig
signature verified
exit=0

$ cat out/boot/manifest.json
{
  "boot_files": [
    {
      "name": "helper.py",
      "sha256": "8281c4379d823456b1776687734c071e7df7f61527328f6f94e59280bcdea4ea"
    },
    {
      "name": "main.py",
      "sha256": "4d568c171664493f1d754169a8447cd05d793c42832e84d437b49beb959c8a98"
    }
  ],
  "entrypoint": "main.py"
}

$ publish.py verify --dir out --pubkey keys/aios.pub.pem
OK: signature and all sha256 hashes verify
exit=0

$ echo "# x" >> out/boot/helper.py          # tamper a boot file
$ publish.py verify --dir out --pubkey keys/aios.pub.pem
FAIL: sha256 mismatch: helper.py
exit=1

$ publish.py build ... --force && sed -i 's/main.py/evil.py/' out/boot/manifest.json   # tamper the manifest
$ publish.py verify --dir out --pubkey keys/aios.pub.pem
FAIL: signature does not verify against the public key
exit=1

$ publish.py build --boot-dir src --entrypoint nope.py --key keys/aios.key.pem --out-dir out2
error: entrypoint 'nope.py' is not one of the boot files
exit=2
```

A tampered manifest is reported only as a signature failure. As in agentd,
no field of an unverified manifest is read.

---

## 4. Shell scripts and CLI help

```
$ bash -n aios/install.sh && bash -n aios/uninstall.sh && echo "scripts OK"
scripts OK
```

(`shellcheck` is still unavailable in this environment; the scripts are
unchanged.)

```
$ python3 aios/publish.py --help
usage: publish.py [-h] {keygen,build,verify,dev-cert,serve} ...

aios publish - owner-side signing/publish tooling (Milestone 3).

positional arguments:
  {keygen,build,verify,dev-cert,serve}
    keygen              generate an Ed25519 signing keypair
    build               hash, write, and sign a boot manifest
    verify              check a published directory
    dev-cert            self-signed TLS cert for local testing
    serve               serve a published directory over HTTPS
```

---

## Summary

| Check | Result |
| --- | --- |
| `py_compile` (agentd.py, publish.py) | PASS |
| `unittest` (M1 + M2 + M3) | PASS 38/38, 3 consecutive runs |
| Manual keygen → build → verify → tamper | PASS (all exits as expected) |
| `bash -n aios/*.sh` | PASS (shellcheck unavailable) |
| agentd.py / install.sh / uninstall.sh unchanged | Confirmed (empty diff vs M2) |
