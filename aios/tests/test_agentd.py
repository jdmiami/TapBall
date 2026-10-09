"""Tests for aios agentd (Milestone 1).

These run against a local HTTP server serving a manifest signed with a
throwaway Ed25519 key. They cover:

  * the installed openssl supports `pkeyutl -verify -rawin` for Ed25519;
  * a valid signature is accepted;
  * a bad signature is rejected before any manifest field is read;
  * a sha256 mismatch leaves no file in boot/;
  * the stop file ends the loop;
  * backoff never exceeds the cap.

The agentd module keys its paths off the AIOS_HOME environment variable, so
each test points it at a fresh temporary directory. No network call leaves
localhost; signature verification shells out to the real openssl binary.
"""

import hashlib
import importlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
AIOS_DIR = HERE.parent  # .../aios


def _load_agentd(aios_home: str):
    """Import agentd.py fresh with AIOS_HOME pointed at a temp dir."""
    os.environ["AIOS_HOME"] = aios_home
    # Make the sibling agentd.py importable.
    import sys

    if str(AIOS_DIR) not in sys.path:
        sys.path.insert(0, str(AIOS_DIR))
    mod = importlib.import_module("agentd")
    importlib.reload(mod)  # re-read AIOS_HOME each time
    return mod


def _make_keypair(dirpath: str):
    """Generate a throwaway Ed25519 keypair with openssl. Returns (priv, pub)."""
    priv = os.path.join(dirpath, "key.pem")
    pub = os.path.join(dirpath, "pub.pem")
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", priv],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", priv, "-pubout", "-out", pub],
        check=True, capture_output=True,
    )
    return priv, pub


def _sign(priv: str, data: bytes, dirpath: str) -> bytes:
    msg = os.path.join(dirpath, "msg.bin")
    sig = os.path.join(dirpath, "msg.sig")
    with open(msg, "wb") as fh:
        fh.write(data)
    subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", priv, "-rawin", "-in", msg, "-out", sig],
        check=True, capture_output=True,
    )
    with open(sig, "rb") as fh:
        return fh.read()


class _BootServer:
    """Serves a fixed set of byte blobs at /boot/<name> on localhost."""

    def __init__(self, files: dict):
        self.files = files  # path -> bytes
        handler = self._make_handler()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def _make_handler(self):
        files = self.files

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = files.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # silence
                pass

        return Handler

    def __enter__(self):
        self.thread.start()
        host, port = self.httpd.server_address
        self.base = f"http://{host}:{port}"
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class OpensslFlagTest(unittest.TestCase):
    def test_openssl_present_and_supports_rawin_ed25519(self):
        self.assertIsNotNone(shutil.which("openssl"), "openssl CLI must be installed")
        with tempfile.TemporaryDirectory() as td:
            priv, pub = _make_keypair(td)
            data = b"confirm rawin flags against the installed binary"
            sig = _sign(priv, data, td)
            msg = os.path.join(td, "verify.bin")
            sigf = os.path.join(td, "verify.sig")
            with open(msg, "wb") as fh:
                fh.write(data)
            with open(sigf, "wb") as fh:
                fh.write(sig)
            proc = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub,
                 "-rawin", "-in", msg, "-sigfile", sigf],
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = os.path.join(self.td, "aios_home")
        self.agentd = _load_agentd(self.home)
        self.agentd._ensure_dirs()
        self.keydir = os.path.join(self.td, "keys")
        os.makedirs(self.keydir)
        self.priv, self.pub = _make_keypair(self.keydir)

    def test_valid_signature_accepted(self):
        data = b'{"entrypoint": null, "boot_files": []}'
        sig = _sign(self.priv, data, self.keydir)
        self.assertTrue(self.agentd.verify_signature(data, sig, self.pub))

    def test_bad_signature_rejected(self):
        data = b'{"entrypoint": null, "boot_files": []}'
        sig = _sign(self.priv, data, self.keydir)
        tampered = data.replace(b"null", b"\"evil.py\"")
        # Signature no longer matches the (tampered) bytes.
        self.assertFalse(self.agentd.verify_signature(tampered, sig, self.pub))

    def test_bad_signature_rejected_before_any_field_read(self):
        """run_cycle must refuse to json.loads the manifest when the sig fails."""
        manifest = b'{"entrypoint": "evil.py", "boot_files": [{"name": "evil.py", "sha256": "0"}]}'
        good_sig = _sign(self.priv, b"a totally different message", self.keydir)
        with _BootServer({
            "/boot/manifest.json": manifest,
            "/boot/manifest.sig": good_sig,
        }) as srv:
            cfg = {
                "server_url": srv.base,
                "server_host": srv.base.split("//", 1)[1],
                "public_key_path": self.pub,
                "poll_seconds": 1.0,
                "max_backoff_seconds": 1.0,
                "run_timeout_seconds": 5.0,
            }
            # fetch_bytes enforces https; patch it to allow the http test server.
            orig_fetch = self.agentd.fetch_bytes

            def http_fetch(url, server_url, timeout=30.0):
                import urllib.request
                with urllib.request.urlopen(url, timeout=timeout) as resp:
                    return resp.read()

            self.agentd.fetch_bytes = http_fetch
            try:
                with self.assertRaises(self.agentd.AiosError) as ctx:
                    self.agentd.run_cycle(cfg)
            finally:
                self.agentd.fetch_bytes = orig_fetch
            self.assertIn("verification failed", str(ctx.exception))
            # Nothing was downloaded or run.
            self.assertEqual(list((Path(self.home) / "boot").iterdir()), [])


class HashMismatchTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = os.path.join(self.td, "aios_home")
        self.agentd = _load_agentd(self.home)
        self.agentd._ensure_dirs()

    def test_sha256_mismatch_leaves_boot_empty(self):
        payload = b"print('hi')\n"
        wrong_sha = "0" * 64
        with _BootServer({"/boot/good.py": payload}) as srv:
            entry = {"name": "good.py", "sha256": wrong_sha}
            # Patch fetch to the http test server.
            def http_fetch(url, server_url, timeout=30.0):
                import urllib.request
                with urllib.request.urlopen(url, timeout=timeout) as resp:
                    return resp.read()

            self.agentd.fetch_bytes = http_fetch
            with self.assertRaises(self.agentd.AiosError):
                self.agentd.download_boot_file(entry, srv.base, 5.0)
        boot = Path(self.home) / "boot"
        self.assertEqual(list(boot.iterdir()), [], "no file (not even .part) must remain")

    def test_sha256_match_lands_file(self):
        payload = b"print('ok')\n"
        good_sha = hashlib.sha256(payload).hexdigest()
        with _BootServer({"/boot/good.py": payload}) as srv:
            entry = {"name": "good.py", "sha256": good_sha}

            def http_fetch(url, server_url, timeout=30.0):
                import urllib.request
                with urllib.request.urlopen(url, timeout=timeout) as resp:
                    return resp.read()

            self.agentd.fetch_bytes = http_fetch
            final = self.agentd.download_boot_file(entry, srv.base, 5.0)
        self.assertTrue(final.is_file())
        self.assertEqual(final.read_bytes(), payload)


class StopFileTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = os.path.join(self.td, "aios_home")
        self.agentd = _load_agentd(self.home)

    def test_stop_file_ends_loop_immediately(self):
        # Create the stop file before main() runs; the loop must return 0
        # on its first check without doing any network work.
        os.makedirs(self.home, exist_ok=True)
        Path(self.home, "STOP").write_text("stop")
        rc = self.agentd.main([])
        self.assertEqual(rc, 0)

    def test_stop_file_ends_loop_after_config_error(self):
        # No config.json -> config error path -> but STOP short-circuits.
        self.agentd._ensure_dirs()
        Path(self.home, "STOP").write_text("stop")
        rc = self.agentd.main([])
        self.assertEqual(rc, 0)


class BackoffTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = os.path.join(self.td, "aios_home")
        self.agentd = _load_agentd(self.home)

    def test_backoff_never_exceeds_cap(self):
        cap = 7.5
        for attempt in range(1, 40):
            for _ in range(50):
                d = self.agentd.backoff_delay(attempt, base=1.0, cap=cap)
                self.assertGreaterEqual(d, 0.0)
                self.assertLessEqual(d, cap)

    def test_backoff_grows_then_clamps(self):
        cap = 1000.0
        # Upper bound of the jitter window is min(cap, base*2^(n-1)).
        # With enough attempts, the window saturates at cap.
        saw_large = False
        for _ in range(200):
            d = self.agentd.backoff_delay(attempt=20, base=1.0, cap=cap)
            self.assertLessEqual(d, cap)
            if d > cap / 2:
                saw_large = True
        self.assertTrue(saw_large, "backoff should be able to approach the cap")

    def test_zero_cap_is_zero(self):
        self.assertEqual(self.agentd.backoff_delay(5, base=1.0, cap=0.0), 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
