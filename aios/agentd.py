#!/usr/bin/env python3
"""aios agentd - boot skeleton (Milestone 1).

A transparent, user-owned agent runtime loop. Runs as the owner's own user,
logs what it does, and stops when the STOP file appears. Standard library only.

Each cycle:
  1. Read ~/.aios/config.json.
  2. Exit cleanly if ~/.aios/STOP exists.
  3. Fetch {server_url}/boot/manifest.json and manifest.sig over HTTPS, with
     exponential backoff and jitter capped at max_backoff_seconds.
  4. Verify the Ed25519 signature over the raw manifest bytes against the
     pinned public key BEFORE reading any manifest field.
  5. Download each listed boot file to boot/<name>.part, check sha256 against
     the verified manifest, rename into place only on a match.
  6. Run only the entrypoint the verified manifest names, as a child process
     with run_timeout_seconds and a working directory inside ~/.aios/.
  7. Append one JSON line to ~/.aios/logs/agentd.log for each fetch,
     verification result, run, and error; update a heartbeat file each cycle.

Security posture: nothing fetched is run until its signature AND its hash both
pass. Network calls go only to server_url. Writes happen only inside ~/.aios/.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# --- Fixed layout under the aios home directory -----------------------------

AIOS_HOME = Path(os.environ.get("AIOS_HOME", str(Path.home() / ".aios")))
CONFIG_PATH = AIOS_HOME / "config.json"
STOP_PATH = AIOS_HOME / "STOP"
BOOT_DIR = AIOS_HOME / "boot"
LOG_DIR = AIOS_HOME / "logs"
LOG_PATH = LOG_DIR / "agentd.log"
HEARTBEAT_PATH = AIOS_HOME / "heartbeat.json"
WORK_DIR = AIOS_HOME / "work"

CONFIG_KEYS = (
    "server_url",
    "public_key_path",
    "poll_seconds",
    "max_backoff_seconds",
    "run_timeout_seconds",
)


class AiosError(Exception):
    """A recoverable error worth logging and backing off on."""


# --- Logging & heartbeat ----------------------------------------------------


def _ensure_dirs() -> None:
    for d in (AIOS_HOME, BOOT_DIR, LOG_DIR, WORK_DIR):
        d.mkdir(parents=True, exist_ok=True)


def log(event: str, **fields: object) -> None:
    """Append one JSON line describing an event. Never raises."""
    record = {"ts": time.time(), "event": event}
    record.update(fields)
    line = json.dumps(record, sort_keys=True, default=str)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        # Logging must never take the loop down.
        sys.stderr.write(line + "\n")


def write_heartbeat(cycle: int, status: str) -> None:
    data = {"ts": time.time(), "pid": os.getpid(), "cycle": cycle, "status": status}
    try:
        tmp = HEARTBEAT_PATH.with_suffix(".json.part")
        tmp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        tmp.replace(HEARTBEAT_PATH)
    except OSError as exc:
        log("heartbeat_error", error=str(exc))


# --- Config -----------------------------------------------------------------


def load_config() -> dict:
    """Read and validate ~/.aios/config.json."""
    try:
        raw = CONFIG_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise AiosError(f"cannot read config {CONFIG_PATH}: {exc}") from exc
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AiosError(f"config is not valid JSON: {exc}") from exc
    if not isinstance(cfg, dict):
        raise AiosError("config must be a JSON object")
    missing = [k for k in CONFIG_KEYS if k not in cfg]
    if missing:
        raise AiosError(f"config missing keys: {', '.join(missing)}")

    server_url = str(cfg["server_url"]).rstrip("/")
    parsed = urllib.parse.urlparse(server_url)
    if parsed.scheme != "https":
        raise AiosError("server_url must be an https:// URL")
    if not parsed.netloc:
        raise AiosError("server_url has no host")

    try:
        poll_seconds = float(cfg["poll_seconds"])
        max_backoff_seconds = float(cfg["max_backoff_seconds"])
        run_timeout_seconds = float(cfg["run_timeout_seconds"])
    except (TypeError, ValueError) as exc:
        raise AiosError(f"numeric config value invalid: {exc}") from exc
    for name, val in (
        ("poll_seconds", poll_seconds),
        ("max_backoff_seconds", max_backoff_seconds),
        ("run_timeout_seconds", run_timeout_seconds),
    ):
        if val <= 0:
            raise AiosError(f"{name} must be positive")

    return {
        "server_url": server_url,
        "server_host": parsed.netloc,
        "public_key_path": os.path.expanduser(str(cfg["public_key_path"])),
        "poll_seconds": poll_seconds,
        "max_backoff_seconds": max_backoff_seconds,
        "run_timeout_seconds": run_timeout_seconds,
    }


# --- Networking (only ever to server_url) -----------------------------------


def _check_same_origin(url: str, server_url: str) -> None:
    a = urllib.parse.urlparse(url)
    b = urllib.parse.urlparse(server_url)
    if (a.scheme, a.hostname, a.port) != (b.scheme, b.hostname, b.port):
        raise AiosError(f"refusing request to non-server origin: {url}")


def fetch_bytes(url: str, server_url: str, timeout: float = 30.0) -> bytes:
    """HTTPS GET, restricted to the configured server origin."""
    if not url.startswith("https://"):
        raise AiosError(f"refusing non-HTTPS url: {url}")
    _check_same_origin(url, server_url)
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "aios-agentd/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310 (https enforced above)
            return resp.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise AiosError(f"fetch failed for {url}: {exc}") from exc


def backoff_delay(attempt: int, base: float, cap: float) -> float:
    """Exponential backoff with full jitter, hard-capped at `cap`.

    attempt is 1-based. The returned delay is always in [0, cap].
    """
    if cap <= 0:
        return 0.0
    exp = base * (2 ** max(0, attempt - 1))
    ceiling = min(cap, exp)
    if ceiling < 0:
        ceiling = 0.0
    return random.uniform(0, ceiling)


# --- Signature verification (openssl CLI, Ed25519, raw bytes) ---------------


def _require_openssl() -> str:
    path = shutil.which("openssl")
    if not path:
        raise AiosError(
            "openssl CLI not found on PATH; aios requires OpenSSL 3.x "
            "(pkeyutl -verify -rawin) to verify boot manifests"
        )
    return path


def verify_signature(manifest_bytes: bytes, signature: bytes, public_key_path: str) -> bool:
    """Verify an Ed25519 signature over the raw manifest bytes.

    Uses `openssl pkeyutl -verify -rawin`. Returns True only on a verified
    signature; returns False for any verification failure. Raises AiosError
    only for environment problems (missing openssl, unreadable key).
    """
    openssl = _require_openssl()
    if not os.path.isfile(public_key_path):
        raise AiosError(f"pinned public key not found: {public_key_path}")

    with tempfile.TemporaryDirectory(prefix="aios-verify-") as td:
        msg_path = os.path.join(td, "manifest.bin")
        sig_path = os.path.join(td, "manifest.sig")
        with open(msg_path, "wb") as fh:
            fh.write(manifest_bytes)
        with open(sig_path, "wb") as fh:
            fh.write(signature)
        cmd = [
            openssl,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            public_key_path,
            "-rawin",
            "-in",
            msg_path,
            "-sigfile",
            sig_path,
        ]
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AiosError(f"openssl invocation failed: {exc}") from exc
        return proc.returncode == 0


# --- Boot-file download & hash check ----------------------------------------


def _safe_boot_name(name: str) -> str:
    """Reject anything that is not a plain filename living in boot/."""
    if not name or name in (".", ".."):
        raise AiosError(f"invalid boot file name: {name!r}")
    if "/" in name or "\\" in name or os.path.sep in name:
        raise AiosError(f"boot file name may not contain path separators: {name!r}")
    if os.path.isabs(name):
        raise AiosError(f"boot file name may not be absolute: {name!r}")
    return name


def download_boot_file(entry: dict, server_url: str, timeout: float) -> Path:
    """Download one boot file to boot/<name>.part, verify sha256, rename on match.

    On a hash mismatch the .part file is removed and nothing lands in boot/.
    Returns the final Path on success.
    """
    try:
        name = _safe_boot_name(str(entry["name"]))
        expected_sha = str(entry["sha256"]).lower()
    except KeyError as exc:
        raise AiosError(f"manifest boot entry missing key: {exc}") from exc
    if len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
        raise AiosError(f"invalid sha256 for {name!r}")

    url = f"{server_url}/boot/{urllib.parse.quote(name)}"
    data = fetch_bytes(url, server_url, timeout=timeout)
    actual_sha = hashlib.sha256(data).hexdigest()

    part_path = BOOT_DIR / (name + ".part")
    final_path = BOOT_DIR / name
    try:
        part_path.write_bytes(data)
    except OSError as exc:
        raise AiosError(f"cannot write {part_path}: {exc}") from exc

    if actual_sha != expected_sha:
        try:
            part_path.unlink()
        except OSError:
            pass
        log("boot_hash_mismatch", name=name, expected=expected_sha, actual=actual_sha)
        raise AiosError(f"sha256 mismatch for {name!r}; discarded")

    part_path.replace(final_path)
    log("boot_file_ready", name=name, sha256=actual_sha, bytes=len(data))
    return final_path


# --- Entrypoint execution ----------------------------------------------------


def run_entrypoint(entrypoint: str, run_timeout_seconds: float) -> None:
    """Run the verified entrypoint as a child process inside ~/.aios/work.

    The entrypoint must be one of the boot files that already passed hash
    verification and landed in boot/.
    """
    name = _safe_boot_name(entrypoint)
    target = BOOT_DIR / name
    if not target.is_file():
        raise AiosError(f"entrypoint {name!r} not present in boot/ after verification")

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-I", str(target)]
    log("run_start", entrypoint=name, timeout=run_timeout_seconds)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(WORK_DIR),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=run_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log("run_timeout", entrypoint=name, timeout=run_timeout_seconds)
        raise AiosError(f"entrypoint {name!r} timed out") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise AiosError(f"entrypoint {name!r} failed to launch: {exc}") from exc
    log(
        "run_end",
        entrypoint=name,
        returncode=proc.returncode,
        stdout_bytes=len(proc.stdout or b""),
        stderr_bytes=len(proc.stderr or b""),
    )


# --- One cycle ---------------------------------------------------------------


def run_cycle(cfg: dict) -> None:
    """Fetch, verify, download, and run once. Raises AiosError on failure."""
    server_url = cfg["server_url"]
    timeout = min(30.0, cfg["run_timeout_seconds"])

    manifest_url = f"{server_url}/boot/manifest.json"
    sig_url = f"{server_url}/boot/manifest.sig"

    manifest_bytes = fetch_bytes(manifest_url, server_url, timeout=timeout)
    log("fetch", url=manifest_url, bytes=len(manifest_bytes))
    signature = fetch_bytes(sig_url, server_url, timeout=timeout)
    log("fetch", url=sig_url, bytes=len(signature))

    # Verify BEFORE parsing or reading any manifest field.
    verified = verify_signature(manifest_bytes, signature, cfg["public_key_path"])
    log("verify", url=manifest_url, verified=verified)
    if not verified:
        raise AiosError("manifest signature verification failed; refusing to read it")

    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise AiosError(f"verified manifest is not valid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise AiosError("manifest must be a JSON object")

    boot_files = manifest.get("boot_files", [])
    if not isinstance(boot_files, list):
        raise AiosError("manifest boot_files must be a list")
    for entry in boot_files:
        if not isinstance(entry, dict):
            raise AiosError("each boot_files entry must be an object")
        download_boot_file(entry, server_url, timeout)

    entrypoint = manifest.get("entrypoint")
    if entrypoint is None:
        log("no_entrypoint")
        return
    run_entrypoint(str(entrypoint), cfg["run_timeout_seconds"])


# --- Main loop ---------------------------------------------------------------


def main(argv: list | None = None) -> int:
    _ensure_dirs()
    log("agentd_start", pid=os.getpid(), aios_home=str(AIOS_HOME))

    cycle = 0
    attempt = 0  # consecutive failures, drives backoff
    while True:
        cycle += 1
        if STOP_PATH.exists():
            log("stop_requested", path=str(STOP_PATH))
            write_heartbeat(cycle, "stopped")
            return 0

        try:
            cfg = load_config()
        except AiosError as exc:
            attempt += 1
            log("error", phase="config", error=str(exc), attempt=attempt)
            write_heartbeat(cycle, "error")
            delay = backoff_delay(attempt, base=1.0, cap=_fallback_cap())
            if STOP_PATH.exists():
                log("stop_requested", path=str(STOP_PATH))
                return 0
            time.sleep(delay)
            continue

        write_heartbeat(cycle, "running")
        try:
            run_cycle(cfg)
            attempt = 0
            log("cycle_ok", cycle=cycle)
            write_heartbeat(cycle, "idle")
            delay = cfg["poll_seconds"]
        except AiosError as exc:
            attempt += 1
            log("error", phase="cycle", error=str(exc), attempt=attempt)
            write_heartbeat(cycle, "error")
            delay = backoff_delay(attempt, base=1.0, cap=cfg["max_backoff_seconds"])

        # Sleep, but wake promptly if a stop is requested.
        if STOP_PATH.exists():
            log("stop_requested", path=str(STOP_PATH))
            write_heartbeat(cycle, "stopped")
            return 0
        time.sleep(delay)


def _fallback_cap() -> float:
    """Backoff cap used when config itself is unreadable."""
    return 60.0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("interrupted")
        raise SystemExit(130)
