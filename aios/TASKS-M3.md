# aios — Milestone 3: signing/publish tooling

Owner-side tooling that produces what `agentd` consumes. `aios/publish.py`:
one Python 3.10+ file, standard library only, signing through the `openssl`
CLI (Ed25519, `pkeyutl -sign -rawin`). It runs on demand from the owner's
checkout; it is not installed, not a service, and writes only to the paths the
owner passes it. `agentd.py`, `install.sh` and `uninstall.sh` are unchanged.
Each item is checked only after its verification output is in `VERIFY-M3.md`.

## 1. `publish.py keygen`
- [x] Generates an Ed25519 keypair with `openssl`; private key file mode 0600
- [x] Refuses to overwrite an existing key file; never prints the private key

## 2. `publish.py build`
- [x] Hashes every regular file in a boot directory; rejects subdirectories and unsafe names
- [x] Rejects an entrypoint that is not one of the boot files
- [x] Writes `boot/manifest.json` (`entrypoint`, `boot_files` with `name` + `sha256`), copies boot files to `boot/`
- [x] Signs the exact manifest bytes into `boot/manifest.sig`, then verifies the signature before reporting success

## 3. `publish.py verify`
- [x] Checks a published directory: signature against a public key, then every file's sha256
- [x] Reports a tampered manifest or boot file and exits non-zero

## 4. `publish.py dev-cert` and `serve` (local testing only)
- [x] `dev-cert` makes a short-lived self-signed cert for `localhost` / `127.0.0.1`
- [x] `serve` serves a published directory over HTTPS, bound to 127.0.0.1 by default, no directory listings

## 5. Tests (`tests/test_publish.py`)
- [x] keygen: mode 0600, refuses overwrite
- [x] build: output verifies with `agentd.verify_signature`; hashes match; bad entrypoint and subdirectory rejected
- [x] verify: passes clean output; fails on a tampered manifest and on a tampered boot file
- [x] End to end: real `agentd.py` process fetches from `serve` over HTTPS, verifies, runs the entrypoint, records a result, then stops on the STOP file

## 6. Verification (`VERIFY-M3.md`)
- [x] `python3 -m py_compile aios/agentd.py aios/publish.py`
- [x] `python3 -m unittest discover -s aios/tests -v` (M1 + M2 + M3)
- [x] A manual keygen → build → verify → tamper → verify run

## 7. Codex review on PR #3
- [x] P1: `build --force` stages and verifies before replacing `boot/`; a failed rebuild leaves `boot/` intact
- [x] P2: `verify` validates manifest structure and agentd's name/sha256 rules before touching files
