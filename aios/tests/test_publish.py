"""Tests for aios publish.py (Milestone 3: signing/publish tooling).

Covers keygen, build, verify, and an end-to-end run in which a real agentd.py
process fetches a published directory from publish.py's HTTPS server, verifies
it, runs the entrypoint, records a result, and stops on the STOP file.

The end-to-end test trusts the self-signed dev cert by pointing the agentd
process's SSL_CERT_FILE at it; agentd's own TLS handling is unchanged.
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
AIOS_DIR = HERE.parent
if str(AIOS_DIR) not in sys.path:
    sys.path.insert(0, str(AIOS_DIR))

import agentd  # noqa: E402
import publish  # noqa: E402

PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


class _TempDirCase(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)

    def make_src(self, files=None) -> Path:
        src = self.td / "src"
        src.mkdir(exist_ok=True)
        for name, body in (files or {"main.py": "print('hi')\n", "lib.py": "X = 1\n"}).items():
            (src / name).write_text(body, encoding="utf-8")
        return src


class KeygenTest(_TempDirCase):
    def test_private_key_is_0600_and_public_key_written(self):
        priv, pub = publish.keygen(self.td / "keys")
        self.assertEqual(stat.S_IMODE(priv.stat().st_mode), 0o600)
        self.assertIn("PUBLIC KEY", pub.read_text())

    def test_refuses_overwrite(self):
        priv, _ = publish.keygen(self.td / "keys")
        before = priv.read_bytes()
        with self.assertRaises(publish.PublishError):
            publish.keygen(self.td / "keys")
        self.assertEqual(priv.read_bytes(), before)


class BuildTest(_TempDirCase):
    def setUp(self):
        super().setUp()
        self.priv, self.pub = publish.keygen(self.td / "keys")

    def test_output_verifies_with_agentd_and_hashes_match(self):
        src = self.make_src()
        dest = publish.build(src, "main.py", self.priv, self.td / "out")
        manifest = (dest / "manifest.json").read_bytes()
        sig = (dest / "manifest.sig").read_bytes()
        self.assertTrue(agentd.verify_signature(manifest, sig, str(self.pub)))
        data = json.loads(manifest)
        self.assertEqual(data["entrypoint"], "main.py")
        for e in data["boot_files"]:
            expected = hashlib.sha256((src / e["name"]).read_bytes()).hexdigest()
            self.assertEqual(e["sha256"], expected)
            self.assertEqual((dest / e["name"]).read_bytes(), (src / e["name"]).read_bytes())

    def test_rejects_entrypoint_not_in_boot_files(self):
        src = self.make_src()
        with self.assertRaises(publish.PublishError):
            publish.build(src, "missing.py", self.priv, self.td / "out")
        self.assertFalse((self.td / "out" / "boot").exists())

    def test_rejects_subdirectory(self):
        src = self.make_src()
        (src / "nested").mkdir()
        with self.assertRaises(publish.PublishError):
            publish.build(src, "main.py", self.priv, self.td / "out")

    def test_rejects_reserved_name(self):
        src = self.make_src({"main.py": "pass\n", "manifest.json": "{}"})
        with self.assertRaises(publish.PublishError):
            publish.build(src, "main.py", self.priv, self.td / "out")

    def test_refuses_existing_output_without_force(self):
        src = self.make_src()
        publish.build(src, "main.py", self.priv, self.td / "out")
        with self.assertRaises(publish.PublishError):
            publish.build(src, "main.py", self.priv, self.td / "out")
        publish.build(src, "main.py", self.priv, self.td / "out", force=True)

    def _leftovers(self, out):
        return sorted(p.name for p in out.iterdir() if p.name != "boot")

    def test_force_rebuild_replaces_output(self):
        src = self.make_src()
        out = self.td / "out"
        publish.build(src, "main.py", self.priv, out)
        (src / "main.py").write_text("print('v2')\n")
        publish.build(src, "main.py", self.priv, out, force=True)
        self.assertEqual((out / "boot" / "main.py").read_text(), "print('v2')\n")
        self.assertEqual(publish.verify(out, self.pub), [])
        self.assertEqual(self._leftovers(out), [])

    def test_failed_force_rebuild_keeps_existing_output(self):
        # A rebuild that fails at signing must leave the served boot/ intact.
        src = self.make_src()
        out = self.td / "out"
        publish.build(src, "main.py", self.priv, out)
        before = {p.name: p.read_bytes() for p in (out / "boot").iterdir()}
        bad_key = self.td / "not-a-key.pem"
        bad_key.write_text("not a key\n")
        (src / "main.py").write_text("print('v2')\n")
        with self.assertRaises(publish.PublishError):
            publish.build(src, "main.py", bad_key, out, force=True)
        after = {p.name: p.read_bytes() for p in (out / "boot").iterdir()}
        self.assertEqual(after, before)
        self.assertEqual(publish.verify(out, self.pub), [])
        self.assertEqual(self._leftovers(out), [])


class VerifyTest(_TempDirCase):
    def setUp(self):
        super().setUp()
        self.priv, self.pub = publish.keygen(self.td / "keys")
        self.out = self.td / "out"
        publish.build(self.make_src(), "main.py", self.priv, self.out)

    def test_clean_output_passes(self):
        self.assertEqual(publish.verify(self.out, self.pub), [])

    def test_tampered_boot_file_fails(self):
        with open(self.out / "boot" / "lib.py", "a") as fh:
            fh.write("# tampered\n")
        problems = publish.verify(self.out, self.pub)
        self.assertEqual(problems, ["sha256 mismatch: lib.py"])

    def test_tampered_manifest_fails_on_signature(self):
        path = self.out / "boot" / "manifest.json"
        path.write_bytes(path.read_bytes().replace(b"main.py", b"evil.py"))
        problems = publish.verify(self.out, self.pub)
        self.assertEqual(problems, ["signature does not verify against the public key"])

    def test_wrong_public_key_fails(self):
        _, other_pub = publish.keygen(self.td / "other", name="other")
        problems = publish.verify(self.out, other_pub)
        self.assertEqual(problems, ["signature does not verify against the public key"])

    def _sign_manifest(self, data) -> None:
        """Replace boot/manifest.json with `data`, correctly signed."""
        boot = self.out / "boot"
        (boot / "manifest.json").write_bytes(json.dumps(data).encode())
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(self.priv), "-rawin",
             "-in", str(boot / "manifest.json"), "-out", str(boot / "manifest.sig")],
            check=True, capture_output=True,
        )

    def test_signed_manifest_with_bad_structure_is_reported_not_raised(self):
        self._sign_manifest({"entrypoint": "main.py", "boot_files": None})
        self.assertEqual(publish.verify(self.out, self.pub),
                         ["manifest is malformed: boot_files must be a list"])
        self._sign_manifest({"entrypoint": None, "boot_files": ["main.py"]})
        self.assertEqual(publish.verify(self.out, self.pub),
                         ["manifest entry is not an object: 'main.py'"])

    def test_signed_manifest_with_path_traversal_name_fails(self):
        # A file outside boot/ whose hash matches must not make verify pass:
        # agentd refuses this name, so verify has to as well.
        payload = self.out / "payload"
        payload.write_text("outside boot\n")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        self._sign_manifest({"entrypoint": None,
                             "boot_files": [{"name": "../payload", "sha256": digest}]})
        self.assertEqual(publish.verify(self.out, self.pub),
                         ["unsafe or missing boot file name: '../payload'"])


class EndToEndTest(_TempDirCase):
    """Real agentd process <- HTTPS <- publish.py server, all on 127.0.0.1."""

    MARKER = "hello from a signed boot file"

    def _publish_and_serve(self):
        priv, pub = publish.keygen(self.td / "keys")
        src = self.make_src({"main.py": f"print({self.MARKER!r})\n"})
        out = self.td / "out"
        publish.build(src, "main.py", priv, out)
        cert, key = publish.dev_cert(self.td / "tls")
        httpd = publish.make_server(out, "127.0.0.1", 0, cert, key, quiet=True)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return pub, cert, httpd.server_address[1]

    def _run_agentd(self, pub, port, trusted_cert, until):
        """Start agentd, wait until `until(home)` or 20s, then STOP it.

        Returns (returncode, home, log events, diagnostics text).
        """
        home = self.td / "home" / ".aios"
        home.mkdir(parents=True)
        (home / "config.json").write_text(json.dumps({
            "server_url": f"https://127.0.0.1:{port}",
            "public_key_path": str(pub),
            "poll_seconds": 0.5,
            "max_backoff_seconds": 1,
            "run_timeout_seconds": 10,
        }))
        env = {k: v for k, v in os.environ.items() if k not in PROXY_VARS}
        env.update({
            "AIOS_HOME": str(home),
            "SSL_CERT_FILE": str(trusted_cert),
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        })
        stderr_path = self.td / "agentd.stderr"
        with open(stderr_path, "wb") as stderr_fh:
            proc = subprocess.Popen(
                [sys.executable, str(AIOS_DIR / "agentd.py")],
                env=env, stdout=subprocess.DEVNULL, stderr=stderr_fh,
            )
        self.addCleanup(lambda: proc.poll() is None and proc.kill())

        deadline = time.time() + 20
        while time.time() < deadline and proc.poll() is None and not until(home):
            time.sleep(0.1)
        (home / "STOP").write_text("stop")
        try:
            rc = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            self.fail("agentd did not exit after STOP")
        log_text = (home / "logs" / "agentd.log").read_text()
        events = [json.loads(line) for line in log_text.splitlines()]
        return rc, home, events, log_text + stderr_path.read_text(errors="replace")

    def test_agentd_fetches_verifies_runs_and_stops(self):
        pub, cert, port = self._publish_and_serve()
        rc, home, events, diag = self._run_agentd(
            pub, port, cert, until=lambda h: list((h / "results").glob("*.json")))
        self.assertEqual(rc, 0, diag)

        results = sorted((home / "results").glob("*.json"))
        self.assertTrue(results, f"no run result recorded:\n{diag}")
        record = json.loads(results[0].read_text())
        self.assertEqual(record["entrypoint"], "main.py")
        self.assertEqual(record["returncode"], 0)
        self.assertIn(self.MARKER, record["stdout_tail"])

        self.assertIn(True, [e["verified"] for e in events if e["event"] == "verify"])
        self.assertTrue(any(e["event"] == "stop_requested" for e in events))
        self.assertEqual((home / "boot" / "main.py").read_text(), f"print({self.MARKER!r})\n")

    def test_agentd_rejects_untrusted_tls_cert(self):
        # agentd trusts an unrelated cert, so the server's cert must fail TLS
        # verification: nothing is fetched, verified, downloaded, or run.
        pub, _, port = self._publish_and_serve()
        other_cert, _ = publish.dev_cert(self.td / "other-tls")

        def saw_fetch_error(home):
            try:
                return "fetch failed" in (home / "logs" / "agentd.log").read_text()
            except OSError:
                return False

        rc, home, events, diag = self._run_agentd(pub, port, other_cert, until=saw_fetch_error)
        self.assertEqual(rc, 0, diag)
        errors = [e["error"] for e in events if e["event"] == "error"]
        self.assertTrue(errors, diag)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", errors[0])
        self.assertFalse(any(e["event"] in ("fetch", "verify", "run_start") for e in events), diag)
        self.assertEqual(list((home / "boot").iterdir()), [])
        self.assertEqual(list((home / "results").iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
