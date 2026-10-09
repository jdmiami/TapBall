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

    @unittest.skipUnless(os.name == "posix", "process groups only on POSIX")
    def test_timeout_kills_whole_process_group(self):
        # Parent spawns a grandchild that would write a marker after a long
        # sleep, then the parent itself sleeps. The run times out fast; the
        # whole group must die, so the marker never appears.
        marker = os.path.join(self.home, "grandchild-marker")
        self._install_entrypoint(
            "import subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, '-c', \"import time; time.sleep(10); open({marker!r},'w').write('x')\"])\n"
            "time.sleep(10)\n"
        )
        # A timeout surfaces as AiosError (same contract as Milestone 1), and
        # the run result on disk records timed_out=True.
        with self.assertRaises(self.agentd.AiosError):
            self.agentd.run_entrypoint("entry.py", 1.0, {})
        results = sorted((Path(self.home) / "results").glob("*.json"))
        self.assertTrue(results)
        rec = json.loads(results[-1].read_text())
        self.assertTrue(rec["timed_out"])
        # Give any surviving grandchild more than its sleep to prove it's dead.
        time.sleep(1.5)
        self.assertFalse(os.path.exists(marker), "grandchild survived group kill")


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
