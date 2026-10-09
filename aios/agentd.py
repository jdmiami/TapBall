#!/usr/bin/env python3
"""aios agentd - boot loop (Milestones 1-2).

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
  6. Run only the entrypoint the verified manifest names, as a sandboxed child
     process with run_timeout_seconds and a working directory inside ~/.aios/.
  7. Append one JSON line to ~/.aios/logs/agentd.log for each fetch,
     verification result, run, and error; update a heartbeat file each cycle.

Milestone 2 (hardening) adds, without changing any of the above guarantees:
  * size-based rotation of the log file (inside logs/ only);
  * a structured result record per run (inside results/ only);
  * a richer heartbeat plus `--status` / `--version` CLI;
  * child-process sandboxing: scrubbed environment, its own process group
    (so a timeout kills the whole group), optional CPU/memory RLIMITs, and a
    dedicated per-run working directory.

Security posture: nothing fetched is run until its signature AND its hash both
pass. Network calls go only to server_url. Writes happen only inside ~/.aios/.
Nothing here hides processes or files, or blocks the STOP file or uninstall.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:  # POSIX-only; used for optional child resource limits.
    import resource
except ImportError:  # pragma: no cover - non-POSIX
    resource = None

VERSION = "0.2.0"

# --- Fixed layout under the aios home directory -----------------------------

AIOS_HOME = Path(os.environ.get("AIOS_HOME", str(Path.home() / ".aios")))
CONFIG_PATH = AIOS_HOME / "config.json"
STOP_PATH = AIOS_HOME / "STOP"
BOOT_DIR = AIOS_HOME / "boot"
LOG_DIR = AIOS_HOME / "logs"
LOG_PATH = LOG_DIR / "agentd.log"
HEARTBEAT_PATH = AIOS_HOME / "heartbeat.json"
WORK_DIR = AIOS_HOME / "work"
RESULTS_DIR = AIOS_HOME / "results"

CONFIG_KEYS = (
    "server_url",
    "public_key_path",
    "poll_seconds",
    "max_backoff_seconds",
    "run_timeout_seconds",
)

# Defaults for the Milestone 2 optional config keys. Kept in module globals so
# log() (which runs before any config is loaded) has sane values, and so a
# Milestone 1 config with none of these keys still loads unchanged.
DEFAULT_LOG_MAX_BYTES = 1_000_000
DEFAULT_LOG_BACKUPS = 5
DEFAULT_RESULTS_KEEP = 50

_LOG_MAX_BYTES = DEFAULT_LOG_MAX_BYTES
_LOG_BACKUPS = DEFAULT_LOG_BACKUPS

# Output captured from a child run is bounded before it is recorded.
RESULT_OUTPUT_TAIL_BYTES = 16_384


class AiosError(Exception):
    """A recoverable error worth logging and backing off on."""


# --- Logging & heartbeat ----------------------------------------------------


def _ensure_dirs() -> None:
    for d in (AIOS_HOME, BOOT_DIR, LOG_DIR, WORK_DIR, RESULTS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def _rotate_log_if_needed() -> None:
    """Size-based rotation entirely inside logs/. Best effort; never raises."""
    try:
        if _LOG_MAX_BYTES <= 0:
            return
        try:
            size = LOG_PATH.stat().st_size
        except FileNotFoundError:
            return
        if size < _LOG_MAX_BYTES:
            return
        # Drop the oldest, shift the rest up: .(_LOG_BACKUPS-1) -> .(_LOG_BACKUPS) ...
        if _LOG_BACKUPS <= 0:
            LOG_PATH.unlink(missing_ok=True)
            return
        oldest = LOG_DIR / f"agentd.log.{_LOG_BACKUPS}"
        oldest.unlink(missing_ok=True)
        for i in range(_LOG_BACKUPS - 1, 0, -1):
            src = LOG_DIR / f"agentd.log.{i}"
            dst = LOG_DIR / f"agentd.log.{i + 1}"
            if src.exists():
                src.replace(dst)
        LOG_PATH.replace(LOG_DIR / "agentd.log.1")
    except OSError:
        # Rotation must never take the loop down.
        pass


def log(event: str, **fields: object) -> None:
    """Append one JSON line describing an event. Never raises."""
    record = {"ts": time.time(), "event": event}
    record.update(fields)
    line = json.dumps(record, sort_keys=True, default=str)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        _rotate_log_if_needed()
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        # Logging must never take the loop down.
        sys.stderr.write(line + "\n")


# Mutable heartbeat state, surfaced in the heartbeat file and via --status.
_STATE = {
    "version": VERSION,
    "consecutive_failures": 0,
    "last_error": None,
    "last_outcome": None,
    "next_delay": None,
}


def write_heartbeat(cycle: int, status: str) -> None:
    data = {
        "ts": time.time(),
        "pid": os.getpid(),
        "cycle": cycle,
        "status": status,
        "version": _STATE["version"],
        "consecutive_failures": _STATE["consecutive_failures"],
        "last_error": _STATE["last_error"],
        "last_outcome": _STATE["last_outcome"],
        "next_delay": _STATE["next_delay"],
    }
    try:
        tmp = HEARTBEAT_PATH.with_suffix(".json.part")
        tmp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        tmp.replace(HEARTBEAT_PATH)
    except OSError as exc:
        log("heartbeat_error", error=str(exc))


# --- Config -----------------------------------------------------------------


def _opt_positive_number(cfg: dict, key: str, default):
    """Read an optional numeric config value; default when absent/None."""
    if key not in cfg or cfg[key] is None:
        return default
    try:
        val = float(cfg[key])
    except (TypeError, ValueError) as exc:
        raise AiosError(f"{key} must be a number: {exc}") from exc
    # Python's json accepts NaN and Infinity; neither is a usable setting.
    if not math.isfinite(val) or val <= 0:
        raise AiosError(f"{key} must be a positive finite number")
    return val


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
        if not math.isfinite(val) or val <= 0:
            raise AiosError(f"{name} must be a positive finite number")

    # Milestone 2 optional keys (backward compatible).
    log_max_bytes = _opt_positive_number(cfg, "log_max_bytes", DEFAULT_LOG_MAX_BYTES)
    log_backups_raw = _opt_positive_number(cfg, "log_backups", DEFAULT_LOG_BACKUPS)
    results_keep_raw = _opt_positive_number(cfg, "results_keep", DEFAULT_RESULTS_KEEP)
    child_cpu_seconds = (
        None if cfg.get("child_cpu_seconds") is None
        else _opt_positive_number(cfg, "child_cpu_seconds", None)
    )
    child_memory_bytes = (
        None if cfg.get("child_memory_bytes") is None
        else _opt_positive_number(cfg, "child_memory_bytes", None)
    )

    # Keep the log-rotation globals in step with the live config.
    global _LOG_MAX_BYTES, _LOG_BACKUPS
    _LOG_MAX_BYTES = int(log_max_bytes)
    _LOG_BACKUPS = int(log_backups_raw)

    return {
        "server_url": server_url,
        "server_host": parsed.netloc,
        "public_key_path": os.path.expanduser(str(cfg["public_key_path"])),
        "poll_seconds": poll_seconds,
        "max_backoff_seconds": max_backoff_seconds,
        "run_timeout_seconds": run_timeout_seconds,
        "log_max_bytes": int(log_max_bytes),
        "log_backups": int(log_backups_raw),
        "results_keep": int(results_keep_raw),
        "child_cpu_seconds": None if child_cpu_seconds is None else float(child_cpu_seconds),
        "child_memory_bytes": None if child_memory_bytes is None else int(child_memory_bytes),
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


# --- Entrypoint execution (sandboxed child) ---------------------------------


def _scrubbed_env(run_dir: Path) -> dict:
    """A minimal environment for the child: no inherited secrets."""
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(run_dir),
        "TMPDIR": str(run_dir),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "AIOS_RUN_DIR": str(run_dir),
    }


def _child_preexec(cpu_seconds, memory_bytes):
    """Return a preexec_fn that isolates the child into its own session and
    applies optional resource limits. POSIX only."""

    def _preexec():  # pragma: no cover - runs in the forked child
        os.setsid()  # own session + process group, so we can kill the whole tree
        if resource is not None:
            if cpu_seconds is not None:
                c = math.ceil(cpu_seconds)  # RLIMIT_CPU is whole seconds; never round to 0
                resource.setrlimit(resource.RLIMIT_CPU, (c, c + 1))
            if memory_bytes is not None:
                m = int(memory_bytes)
                resource.setrlimit(resource.RLIMIT_AS, (m, m))

    return _preexec


def _tail_bytes(data: bytes, limit: int = RESULT_OUTPUT_TAIL_BYTES):
    """Return (text_tail, truncated) for a bounded, decoded view of output."""
    if data is None:
        return "", False
    truncated = len(data) > limit
    view = data[-limit:] if truncated else data
    return view.decode("utf-8", errors="replace"), truncated


def _write_result(record: dict) -> None:
    """Persist one run result into results/, then prune to results_keep."""
    try:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(record["started"]))
        # Millisecond suffix keeps names unique within a second.
        ms = int((record["started"] % 1) * 1000)
        path = RESULTS_DIR / f"{stamp}.{ms:03d}.json"
        path.write_text(json.dumps(record, sort_keys=True, default=str), encoding="utf-8")
    except OSError as exc:
        log("result_write_error", error=str(exc))


def _prune_results(keep: int) -> None:
    try:
        files = sorted(RESULTS_DIR.glob("*.json"))
        excess = len(files) - max(0, keep)
        for old in files[:excess]:
            old.unlink(missing_ok=True)
    except OSError as exc:
        log("result_prune_error", error=str(exc))


def run_entrypoint(entrypoint: str, run_timeout_seconds: float, limits: dict | None = None) -> dict:
    """Run the verified entrypoint as a sandboxed child, record the result.

    The entrypoint must be one of the boot files that already passed hash
    verification and landed in boot/. Returns the result record dict.
    """
    limits = limits or {}
    name = _safe_boot_name(entrypoint)
    target = BOOT_DIR / name
    if not target.is_file():
        raise AiosError(f"entrypoint {name!r} not present in boot/ after verification")

    # Dedicated per-run working directory inside ~/.aios/work/.
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    started = time.time()
    run_dir = WORK_DIR / time.strftime("run-%Y%m%dT%H%M%S", time.gmtime(started))
    suffix = 0
    base = run_dir
    while run_dir.exists():
        suffix += 1
        run_dir = Path(f"{base}-{suffix}")
    run_dir.mkdir(parents=True, exist_ok=True)

    # `-I` isolates the interpreter (ignores PYTHON* env, no cwd on sys.path,
    # no user site) as a defence against planted modules.
    cmd = [sys.executable, "-I", str(target)]
    preexec = None
    start_new_session = False
    if os.name == "posix":
        preexec = _child_preexec(limits.get("child_cpu_seconds"), limits.get("child_memory_bytes"))
    else:
        start_new_session = True  # best effort on non-POSIX

    log("run_start", entrypoint=name, timeout=run_timeout_seconds, run_dir=str(run_dir))
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(run_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_scrubbed_env(run_dir),
            preexec_fn=preexec,
            start_new_session=start_new_session,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        # Includes a failing setrlimit in preexec_fn. Keep it recoverable so
        # the loop logs it and backs off instead of exiting.
        raise AiosError(f"entrypoint {name!r} failed to launch: {exc}") from exc
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=run_timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(proc)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = b"", b""
    finally:
        if proc.poll() is None:
            _kill_process_group(proc)

    duration = time.time() - started
    out_tail, out_trunc = _tail_bytes(stdout)
    err_tail, err_trunc = _tail_bytes(stderr)
    record = {
        "entrypoint": name,
        "returncode": proc.returncode,
        "timed_out": timed_out,
        "started": started,
        "duration_seconds": round(duration, 3),
        "run_dir": str(run_dir),
        "stdout_tail": out_tail,
        "stdout_truncated": out_trunc,
        "stderr_tail": err_tail,
        "stderr_truncated": err_trunc,
    }
    _write_result(record)
    _prune_results(int(limits.get("results_keep", DEFAULT_RESULTS_KEEP)))

    if timed_out:
        log("run_timeout", entrypoint=name, timeout=run_timeout_seconds)
        raise AiosError(f"entrypoint {name!r} timed out")
    log("run_end", entrypoint=name, returncode=proc.returncode,
        duration_seconds=record["duration_seconds"])
    return record


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Terminate the child and (on POSIX) its whole process group."""
    try:
        if os.name == "posix":
            # The child called setsid(), so its pid is the process-group id.
            pgid = proc.pid
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                return  # the whole group is already gone
            time.sleep(0.2)
            # SIGKILL the group even if the leader already exited: a
            # descendant may have ignored SIGTERM.
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:  # pragma: no cover - non-POSIX
            proc.terminate()
            time.sleep(0.2)
            if proc.poll() is None:
                proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


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
    limits = {
        "child_cpu_seconds": cfg.get("child_cpu_seconds"),
        "child_memory_bytes": cfg.get("child_memory_bytes"),
        "results_keep": cfg.get("results_keep", DEFAULT_RESULTS_KEEP),
    }
    run_entrypoint(str(entrypoint), cfg["run_timeout_seconds"], limits)


# --- Status CLI --------------------------------------------------------------


def _read_log_tail(max_lines: int = 20) -> list:
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out = []
    for line in lines[-max_lines:]:
        line = line.strip()
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"raw": line})
    return out


def print_status() -> int:
    heartbeat = None
    try:
        heartbeat = json.loads(HEARTBEAT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        heartbeat = None
    report = {
        "version": VERSION,
        "aios_home": str(AIOS_HOME),
        "stop_file_present": STOP_PATH.exists(),
        "heartbeat": heartbeat,
        "log_tail": _read_log_tail(),
    }
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0


# --- Main loop ---------------------------------------------------------------


def main(argv: list | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--version" in args:
        print(VERSION)
        return 0
    if "--status" in args:
        return print_status()

    _ensure_dirs()
    log("agentd_start", pid=os.getpid(), aios_home=str(AIOS_HOME), version=VERSION)

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
            _STATE["consecutive_failures"] = attempt
            _STATE["last_error"] = str(exc)
            _STATE["last_outcome"] = "config_error"
            log("error", phase="config", error=str(exc), attempt=attempt)
            delay = backoff_delay(attempt, base=1.0, cap=_fallback_cap())
            _STATE["next_delay"] = round(delay, 3)
            write_heartbeat(cycle, "error")
            if STOP_PATH.exists():
                log("stop_requested", path=str(STOP_PATH))
                return 0
            time.sleep(delay)
            continue

        write_heartbeat(cycle, "running")
        try:
            run_cycle(cfg)
            attempt = 0
            _STATE["consecutive_failures"] = 0
            _STATE["last_error"] = None
            _STATE["last_outcome"] = "ok"
            delay = cfg["poll_seconds"]
            _STATE["next_delay"] = round(delay, 3)
            log("cycle_ok", cycle=cycle)
            write_heartbeat(cycle, "idle")
        except AiosError as exc:
            attempt += 1
            _STATE["consecutive_failures"] = attempt
            _STATE["last_error"] = str(exc)
            _STATE["last_outcome"] = "cycle_error"
            log("error", phase="cycle", error=str(exc), attempt=attempt)
            delay = backoff_delay(attempt, base=1.0, cap=cfg["max_backoff_seconds"])
            _STATE["next_delay"] = round(delay, 3)
            write_heartbeat(cycle, "error")

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
