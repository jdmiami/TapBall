"""Tests for aios agentd Milestone 2 (hardening).

Covers: log rotation; structured run-result records and pruning; richer
heartbeat; the --status / --version CLI; and child-process sandboxing
(scrubbed env, resource limits, dedicated cwd, process-group kill on timeout).

Each test points AIOS_HOME at a fresh temp dir and reloads the module.
"""

import importlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
AIOS_DIR = HERE.parent


def _load_agentd(aios_home: str):
    os.environ["AIOS_HOME"] = aios_home
    if str(AIOS_DIR) not in sys.path:
        sys.path.insert(0, str(AIOS_DIR))
    mod = importlib.import_module("agentd")
    importlib.reload(mod)
    return mod


def _write_config(home: str, **overrides) -> None:
    cfg = {
        "server_url": "https://example.invalid",
        "public_key_path": os.path.join(home, "pub.pem"),
        "poll_seconds": 1.0,
        "max_backoff_seconds": 1.0,
        "run_timeout_seconds": 5.0,
    }
    cfg.update(overrides)
    Path(home, "config.json").write_text(json.dumps(cfg), encoding="utf-8")


class ConfigCompatTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = os.path.join(self.td, "h")
        os.makedirs(self.home)
        self.agentd = _load_agentd(self.home)

    def test_milestone1_config_still_loads_with_defaults(self):
        _write_config(self.home)  # no M2 keys at all
        cfg = self.agentd.load_config()
        self.assertEqual(cfg["log_max_bytes"], self.agentd.DEFAULT_LOG_MAX_BYTES)
        self.assertEqual(cfg["log_backups"], self.agentd.DEFAULT_LOG_BACKUPS)
        self.assertEqual(cfg["results_keep"], self.agentd.DEFAULT_RESULTS_KEEP)
        self.assertIsNone(cfg["child_cpu_seconds"])
        self.assertIsNone(cfg["child_memory_bytes"])

    def test_m2_keys_are_read(self):
        _write_config(self.home, log_max_bytes=2048, log_backups=3,
                      results_keep=7, child_cpu_seconds=2, child_memory_bytes=200_000_000)
        cfg = self.agentd.load_config()
        self.assertEqual(cfg["log_max_bytes"], 2048)
        self.assertEqual(cfg["log_backups"], 3)
        self.assertEqual(cfg["results_keep"], 7)
        self.assertEqual(cfg["child_cpu_seconds"], 2.0)
        self.assertEqual(cfg["child_memory_bytes"], 200_000_000)

    def test_bad_m2_value_rejected(self):
        _write_config(self.home, log_max_bytes=-1)
        with self.assertRaises(self.agentd.AiosError):
            self.agentd.load_config()

    def test_non_finite_values_rejected_as_config_errors(self):
        # Python's json accepts NaN/Infinity; they must be config errors, not
        # crashes outside the AiosError path (Codex P2 on PR #2).
        for key in ("poll_seconds", "max_backoff_seconds", "run_timeout_seconds",
                    "log_max_bytes", "log_backups", "results_keep",
                    "child_cpu_seconds", "child_memory_bytes"):
            for bad in (float("nan"), float("inf")):
                with self.subTest(key=key, value=bad):
                    _write_config(self.home, **{key: bad})
                    with self.assertRaises(self.agentd.AiosError):
                        self.agentd.load_config()


class LogRotationTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = os.path.join(self.td, "h")
        self.agentd = _load_agentd(self.home)
        self.agentd._ensure_dirs()

    def test_log_rotates_and_caps_backups(self):
        # Tiny cap so a few writes trigger rotation; keep 2 backups.
        self.agentd._LOG_MAX_BYTES = 200
        self.agentd._LOG_BACKUPS = 2
        for i in range(200):
            self.agentd.log("spam", i=i, filler="x" * 50)
        logdir = Path(self.home) / "logs"
        backups = sorted(p.name for p in logdir.glob("agentd.log.*"))
        # Never more than _LOG_BACKUPS numbered files.
        self.assertLessEqual(len(backups), 2, backups)
        self.assertTrue((logdir / "agentd.log").exists())
        # The live log stays under (cap + one line) worth of bytes.
        self.assertLess((logdir / "agentd.log").stat().st_size, 200 + 500)

    def test_rotation_failure_does_not_raise(self):
        # Point the log dir at a path that cannot be rotated; log() must survive.
        self.agentd._LOG_MAX_BYTES = 1
        # Should not raise even though rotation runs on every call.
        self.agentd.log("ok", a=1)
        self.agentd.log("ok", a=2)


class ResultRecordTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = os.path.join(self.td, "h")
        self.agentd = _load_agentd(self.home)
        self.agentd._ensure_dirs()

    def _install_entrypoint(self, body: str, name: str = "entry.py") -> None:
        (Path(self.home) / "boot" / name).write_text(body, encoding="utf-8")

    def test_successful_run_writes_result(self):
        self._install_entrypoint("print('hello from child')\n")
        rec = self.agentd.run_entrypoint("entry.py", 10.0, {})
        self.assertEqual(rec["returncode"], 0)
        self.assertFalse(rec["timed_out"])
        self.assertIn("hello from child", rec["stdout_tail"])
        results = list((Path(self.home) / "results").glob("*.json"))
        self.assertEqual(len(results), 1)
        on_disk = json.loads(results[0].read_text())
        self.assertEqual(on_disk["returncode"], 0)

    def test_results_pruned_to_keep(self):
        self._install_entrypoint("pass\n")
        for _ in range(6):
            self.agentd.run_entrypoint("entry.py", 10.0, {"results_keep": 3})
            time.sleep(0.005)
        results = list((Path(self.home) / "results").glob("*.json"))
        self.assertLessEqual(len(results), 3, results)


class SandboxTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = os.path.join(self.td, "h")
        self.agentd = _load_agentd(self.home)
        self.agentd._ensure_dirs()

    def _install_entrypoint(self, body: str, name: str = "entry.py") -> None:
        (Path(self.home) / "boot" / name).write_text(body, encoding="utf-8")

    def test_child_env_is_scrubbed(self):
        os.environ["AIOS_SECRET_SENTINEL"] = "must-not-leak"
        self.addCleanup(os.environ.pop, "AIOS_SECRET_SENTINEL", None)
        self._install_entrypoint(
            "import os, json\n"
            "open('env.json','w').write(json.dumps(sorted(os.environ.keys())))\n"
        )
        rec = self.agentd.run_entrypoint("entry.py", 10.0, {})
        env_file = Path(rec["run_dir"]) / "env.json"
        keys = json.loads(env_file.read_text())
        self.assertNotIn("AIOS_SECRET_SENTINEL", keys)
        self.assertIn("AIOS_RUN_DIR", keys)

    def test_child_cwd_is_dedicated_run_dir(self):
        self._install_entrypoint(
            "import os\nopen('cwd.txt','w').write(os.getcwd())\n"
        )
        rec = self.agentd.run_entrypoint("entry.py", 10.0, {})
        cwd = (Path(rec["run_dir"]) / "cwd.txt").read_text()
        work = str((Path(self.home) / "work").resolve())
        self.assertTrue(os.path.realpath(cwd).startswith(work), cwd)

    @unittest.skipUnless(os.name == "posix", "RLIMIT only on POSIX")
    def test_cpu_rlimit_applied_to_child(self):
        self._install_entrypoint(
            "import resource\n"
            "soft, hard = resource.getrlimit(resource.RLIMIT_CPU)\n"
            "open('rlim.txt','w').write(str(soft))\n"
        )
        rec = self.agentd.run_entrypoint("entry.py", 10.0, {"child_cpu_seconds": 3})
        soft = int((Path(rec["run_dir"]) / "rlim.txt").read_text())
        self.assertEqual(soft, 3)

    def _assert_timeout_kills_grandchild(self, grandchild_prelude: str) -> None:
        """The entrypoint starts a grandchild that writes a marker 2s later,
        then sleeps. The run times out after 1s. If the whole group was
        killed, the marker never appears, even after waiting past 2s."""
        marker = os.path.join(self.home, "grandchild-marker")
        grandchild = (f"{grandchild_prelude}import time; time.sleep(2); "
                      f"open({marker!r}, 'w').write('x')")
        self._install_entrypoint(
            "import subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, '-c', {grandchild!r}],"
            " stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "time.sleep(10)\n"
        )
        started = time.time()
        # A timeout surfaces as AiosError (same contract as Milestone 1), and
        # the run result on disk records timed_out=True.
        with self.assertRaises(self.agentd.AiosError):
            self.agentd.run_entrypoint("entry.py", 1.0, {})
        results = sorted((Path(self.home) / "results").glob("*.json"))
        self.assertTrue(results)
        self.assertTrue(json.loads(results[-1].read_text())["timed_out"])
        # Wait until well past the grandchild's 2s sleep before checking.
        time.sleep(max(0.0, started + 3.5 - time.time()))
        self.assertFalse(os.path.exists(marker), "grandchild survived group kill")

    @unittest.skipUnless(os.name == "posix", "process groups only on POSIX")
    def test_timeout_kills_whole_process_group(self):
        self._assert_timeout_kills_grandchild("")

    @unittest.skipUnless(os.name == "posix", "process groups only on POSIX")
    def test_timeout_kills_sigterm_ignoring_descendant(self):
        # The leader exits on SIGTERM but the grandchild ignores it; the group
        # must still get SIGKILL after the grace period (Codex P1 on PR #2).
        self._assert_timeout_kills_grandchild(
            "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); ")

    def test_launch_failure_is_recoverable_error(self):
        # A launch failure must surface as AiosError (logged, backed off),
        # not escape the main loop and crash the daemon (Codex P2 on PR #2).
        self._install_entrypoint("pass\n")
        with mock.patch.object(sys, "executable", os.path.join(self.home, "no-such-python")):
            with self.assertRaises(self.agentd.AiosError):
                self.agentd.run_entrypoint("entry.py", 5.0, {})

    @unittest.skipUnless(os.name == "posix", "RLIMIT only on POSIX")
    def test_fractional_cpu_limit_rounds_up(self):
        # 0.5s must not become a 0s RLIMIT_CPU (Codex P2 on PR #2).
        self._install_entrypoint(
            "import resource\n"
            "soft, hard = resource.getrlimit(resource.RLIMIT_CPU)\n"
            "open('rlim.txt','w').write(str(soft))\n"
        )
        rec = self.agentd.run_entrypoint("entry.py", 10.0, {"child_cpu_seconds": 0.5})
        self.assertEqual(int((Path(rec["run_dir"]) / "rlim.txt").read_text()), 1)


class StatusCliTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = os.path.join(self.td, "h")
        self.agentd = _load_agentd(self.home)

    def test_version_flag(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.agentd.main(["--version"])
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().strip(), self.agentd.VERSION)

    def test_status_flag_emits_json(self):
        self.agentd._ensure_dirs()
        self.agentd.log("agentd_start", pid=1)
        self.agentd.write_heartbeat(1, "idle")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.agentd.main(["--status"])
        self.assertEqual(rc, 0)
        report = json.loads(buf.getvalue())
        self.assertEqual(report["version"], self.agentd.VERSION)
        self.assertIn("heartbeat", report)
        self.assertIn("log_tail", report)
        self.assertFalse(report["stop_file_present"])

    def test_heartbeat_has_rich_fields(self):
        self.agentd._ensure_dirs()
        self.agentd._STATE["consecutive_failures"] = 2
        self.agentd._STATE["last_error"] = "boom"
        self.agentd._STATE["last_outcome"] = "cycle_error"
        self.agentd._STATE["next_delay"] = 1.5
        self.agentd.write_heartbeat(7, "error")
        hb = json.loads((Path(self.home) / "heartbeat.json").read_text())
        self.assertEqual(hb["consecutive_failures"], 2)
        self.assertEqual(hb["last_error"], "boom")
        self.assertEqual(hb["last_outcome"], "cycle_error")
        self.assertEqual(hb["next_delay"], 1.5)
        self.assertEqual(hb["version"], self.agentd.VERSION)


if __name__ == "__main__":
    unittest.main(verbosity=2)
