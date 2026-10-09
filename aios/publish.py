#!/usr/bin/env python3
"""aios publish - owner-side signing/publish tooling (Milestone 3).

Produces the signed boot directory that agentd consumes. Standard library
only; all key and signature work goes through the openssl CLI (Ed25519,
`pkeyutl -sign -rawin`), the same way agentd verifies.

This tool runs on demand from the owner's checkout. It is not installed and
not a service, makes no network calls except `serve` (which only listens,
on 127.0.0.1 by default), and writes only to the paths it is given.

Subcommands:
  keygen   --out-dir DIR [--name aios]
           Ed25519 keypair: DIR/<name>.key.pem (mode 0600) and
           DIR/<name>.pub.pem. Refuses to overwrite.
  build    --boot-dir SRC --entrypoint NAME --key PRIV --out-dir OUT [--force]
           Hashes every file in SRC, writes OUT/boot/manifest.json, copies the
           files to OUT/boot/, signs the manifest bytes into
           OUT/boot/manifest.sig, then verifies the signature.
  verify   --dir OUT --pubkey PUB
           Checks OUT/boot/: signature first, then every file's sha256.
  dev-cert --out-dir DIR [--days 7]
           Self-signed TLS cert for localhost/127.0.0.1, for local testing.
  serve    --dir OUT --cert CERT --key KEY [--host 127.0.0.1] [--port 8443]
           Serves OUT over HTTPS so agentd's server_url can point at it.

Point agentd's config at the result: server_url = https://<host>:<port> and
public_key_path = the .pub.pem from keygen.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agentd  # noqa: E402  (reuse the daemon's exact verification path)

RESERVED_NAMES = {"manifest.json", "manifest.sig"}


class PublishError(Exception):
    """A problem the owner needs to fix; reported without a traceback."""


def _openssl() -> str:
    path = shutil.which("openssl")
    if not path:
        raise PublishError(
            "openssl CLI not found on PATH; aios requires OpenSSL 3.x "
            "(pkeyutl -sign/-verify -rawin)"
        )
    return path


def _run(cmd: list) -> None:
    proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, check=False)
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip()
        raise PublishError(f"{cmd[0]} {cmd[1]} failed: {detail}")


def _refuse_existing(*paths: Path) -> None:
    for p in paths:
        if p.exists():
            raise PublishError(f"refusing to overwrite existing file: {p}")


def _private_umask():
    """Context manager: create files readable by the owner only."""

    class _Umask:
        def __enter__(self):
            self.old = os.umask(0o077)

        def __exit__(self, *exc):
            os.umask(self.old)

    return _Umask()


def _check_boot_name(name: str) -> str:
    """Boot file names must be plain names agentd will accept and not collide."""
    if not name or name in (".", "..") or name.startswith("."):
        raise PublishError(f"unsupported boot file name: {name!r}")
    if "/" in name or "\\" in name:
        raise PublishError(f"boot file name may not contain path separators: {name!r}")
    if name in RESERVED_NAMES:
        raise PublishError(f"boot file name is reserved: {name!r}")
    if name.endswith(".part"):
        raise PublishError(f"boot file name may not end in .part: {name!r}")
    return name


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --- keygen -------------------------------------------------------------------


def keygen(out_dir: Path, name: str = "aios") -> tuple:
    openssl = _openssl()
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = out_dir / f"{name}.key.pem"
    pub = out_dir / f"{name}.pub.pem"
    _refuse_existing(priv, pub)
    with _private_umask():
        _run([openssl, "genpkey", "-algorithm", "ed25519", "-out", str(priv)])
    os.chmod(priv, 0o600)
    _run([openssl, "pkey", "-in", str(priv), "-pubout", "-out", str(pub)])
    return priv, pub


# --- build --------------------------------------------------------------------


def _verify_with_private_key(manifest: bytes, sig: bytes, priv: Path) -> bool:
    """Derive the public key from `priv` and verify through agentd's code path."""
    openssl = _openssl()
    with tempfile.TemporaryDirectory(prefix="aios-publish-") as td:
        pub = Path(td) / "pub.pem"
        _run([openssl, "pkey", "-in", str(priv), "-pubout", "-out", str(pub)])
        return agentd.verify_signature(manifest, sig, str(pub))


def build(boot_src: Path, entrypoint: str, key: Path, out_dir: Path, force: bool = False) -> Path:
    openssl = _openssl()
    if not boot_src.is_dir():
        raise PublishError(f"boot directory not found: {boot_src}")
    if not key.is_file():
        raise PublishError(f"private key not found: {key}")

    entries = []
    for p in sorted(boot_src.iterdir()):
        if not p.is_file() or p.is_symlink():
            raise PublishError(f"boot directory may contain only regular files: {p}")
        name = _check_boot_name(p.name)
        entries.append({"name": name, "sha256": _sha256_file(p)})
    if not entries:
        raise PublishError(f"boot directory is empty: {boot_src}")
    if entrypoint not in {e["name"] for e in entries}:
        raise PublishError(f"entrypoint {entrypoint!r} is not one of the boot files")

    dest = out_dir / "boot"
    if dest.exists() and not force:
        raise PublishError(f"{dest} already exists; pass --force to replace it")

    # Build and verify in a staging directory next to boot/, and swap it in
    # only after the signature checks out, so a failed rebuild never leaves a
    # served boot/ partial or empty.
    out_dir.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="boot.staging-", dir=out_dir))
    try:
        for e in entries:
            shutil.copyfile(boot_src / e["name"], stage / e["name"])
            if _sha256_file(stage / e["name"]) != e["sha256"]:
                raise PublishError(f"{e['name']} changed while it was being copied")

        manifest = json.dumps(
            {"entrypoint": entrypoint, "boot_files": entries}, indent=2, sort_keys=True
        ).encode("utf-8") + b"\n"
        manifest_path = stage / "manifest.json"
        sig_path = stage / "manifest.sig"
        manifest_path.write_bytes(manifest)
        _run([openssl, "pkeyutl", "-sign", "-inkey", str(key), "-rawin",
              "-in", str(manifest_path), "-out", str(sig_path)])
        if not _verify_with_private_key(manifest, sig_path.read_bytes(), key):
            raise PublishError("signature did not verify after signing; boot/ left unchanged")

        os.chmod(stage, 0o755)  # mkdtemp creates 0700; match a normal mkdir
        if dest.exists():
            old = Path(tempfile.mkdtemp(prefix="boot.old-", dir=out_dir))
            old.rmdir()
            dest.rename(old)
            try:
                stage.rename(dest)
            except OSError:
                old.rename(dest)
                raise
            shutil.rmtree(old, ignore_errors=True)
        else:
            stage.rename(dest)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return dest


# --- verify -------------------------------------------------------------------


def verify(pub_dir: Path, pubkey: Path) -> list:
    """Return a list of problems; empty means the directory is good."""
    boot = pub_dir / "boot"
    try:
        manifest = (boot / "manifest.json").read_bytes()
        sig = (boot / "manifest.sig").read_bytes()
    except OSError as exc:
        return [f"cannot read manifest or signature: {exc}"]
    try:
        ok = agentd.verify_signature(manifest, sig, str(pubkey))
    except agentd.AiosError as exc:
        return [str(exc)]
    if not ok:
        # Same rule as agentd: no field is read from an unverified manifest.
        return ["signature does not verify against the public key"]

    # Apply agentd's structure and name rules before touching any file, so
    # verify never passes a manifest agentd would refuse and never reads a
    # path outside boot/.
    try:
        data = json.loads(manifest)
    except json.JSONDecodeError as exc:
        return [f"manifest is malformed: {exc}"]
    if not isinstance(data, dict) or not isinstance(data.get("boot_files"), list):
        return ["manifest is malformed: boot_files must be a list"]

    problems = []
    names = set()
    for e in data["boot_files"]:
        if not isinstance(e, dict):
            problems.append(f"manifest entry is not an object: {e!r}")
            continue
        name, expected = e.get("name"), e.get("sha256")
        try:
            agentd._safe_boot_name(name if isinstance(name, str) else "")
        except agentd.AiosError:
            problems.append(f"unsafe or missing boot file name: {name!r}")
            continue
        if not isinstance(expected, str) or len(expected) != 64 or any(
                c not in "0123456789abcdef" for c in expected.lower()):
            problems.append(f"invalid sha256 for {name}")
            continue
        names.add(name)
        path = boot / name
        if not path.is_file():
            problems.append(f"missing boot file: {name}")
        elif _sha256_file(path) != expected.lower():
            problems.append(f"sha256 mismatch: {name}")
    entrypoint = data.get("entrypoint")
    if entrypoint is not None and entrypoint not in names:
        problems.append(f"entrypoint {entrypoint!r} is not a listed boot file")
    return problems


# --- dev-cert -----------------------------------------------------------------


def dev_cert(out_dir: Path, days: int = 7) -> tuple:
    openssl = _openssl()
    out_dir.mkdir(parents=True, exist_ok=True)
    cert = out_dir / "dev-cert.pem"
    key = out_dir / "dev-key.pem"
    _refuse_existing(cert, key)
    with _private_umask():
        _run([
            openssl, "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", str(days),
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ])
    os.chmod(key, 0o600)
    return cert, key


# --- serve --------------------------------------------------------------------


class _Handler(SimpleHTTPRequestHandler):
    quiet = False

    def list_directory(self, path):  # no directory listings
        self.send_error(404)
        return None

    def log_message(self, fmt, *args):
        if not self.quiet:
            super().log_message(fmt, *args)


def make_server(directory: Path, host: str, port: int, certfile: Path, keyfile: Path,
                quiet: bool = False) -> ThreadingHTTPServer:
    if not (directory / "boot" / "manifest.json").is_file():
        raise PublishError(f"{directory} has no boot/manifest.json; run build first")
    handler = functools.partial(
        type("Handler", (_Handler,), {"quiet": quiet}), directory=str(directory)
    )
    httpd = ThreadingHTTPServer((host, port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certfile), str(keyfile))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


# --- CLI ----------------------------------------------------------------------


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="publish.py", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="generate an Ed25519 signing keypair")
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--name", default="aios")

    p = sub.add_parser("build", help="hash, write, and sign a boot manifest")
    p.add_argument("--boot-dir", required=True, type=Path)
    p.add_argument("--entrypoint", required=True)
    p.add_argument("--key", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--force", action="store_true", help="replace an existing OUT/boot/")

    p = sub.add_parser("verify", help="check a published directory")
    p.add_argument("--dir", required=True, type=Path)
    p.add_argument("--pubkey", required=True, type=Path)

    p = sub.add_parser("dev-cert", help="self-signed TLS cert for local testing")
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--days", type=int, default=7)

    p = sub.add_parser("serve", help="serve a published directory over HTTPS")
    p.add_argument("--dir", required=True, type=Path)
    p.add_argument("--cert", required=True, type=Path)
    p.add_argument("--key", required=True, type=Path)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)

    args = parser.parse_args(argv)
    try:
        if args.cmd == "keygen":
            priv, pub = keygen(args.out_dir, args.name)
            print(f"wrote: {priv} (private, mode 0600)")
            print(f"wrote: {pub} (public; set agentd public_key_path to this)")
        elif args.cmd == "build":
            dest = build(args.boot_dir, args.entrypoint, args.key, args.out_dir, args.force)
            for p in sorted(dest.iterdir()):
                print(f"wrote: {p}")
            print("signature verified")
        elif args.cmd == "verify":
            problems = verify(args.dir, args.pubkey)
            for msg in problems:
                print(f"FAIL: {msg}")
            if problems:
                return 1
            print("OK: signature and all sha256 hashes verify")
        elif args.cmd == "dev-cert":
            cert, key = dev_cert(args.out_dir, args.days)
            print(f"wrote: {cert}")
            print(f"wrote: {key} (private, mode 0600)")
        elif args.cmd == "serve":
            httpd = make_server(args.dir, args.host, args.port, args.cert, args.key)
            print(f"serving {args.dir} at https://{args.host}:{httpd.server_address[1]} (Ctrl-C stops)")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                httpd.server_close()
    except PublishError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
