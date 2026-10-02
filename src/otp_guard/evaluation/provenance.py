"""Provenance of evaluation runs: a hash of everything that can change a run's result (the package
source, the configuration and protocol files, the driving script) and the environment. Checkpointed
and reused runs carry the hash and are accepted only when it matches the current tree, so a code
change can never let stale results into a later invocation."""
import hashlib
import importlib.metadata
import pathlib
import platform
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]


def source_files(extra=()):
    files = sorted((ROOT / "src" / "otp_guard").rglob("*.py")) + sorted((ROOT / "config").glob("*.json"))
    return files + [ROOT / e for e in extra]


def code_hash(extra=()):
    """SHA-256 over the relative path and bytes of every file that can change a simulation result."""
    h = hashlib.sha256()
    for f in source_files(extra):
        if f.exists() and "__pycache__" not in f.parts:
            h.update(str(f.relative_to(ROOT)).encode() + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()


def environment():
    pkgs = {}
    for name in ("redis", "fakeredis", "numpy", "scipy", "matplotlib", "fastapi", "cbor2", "cryptography"):
        try:
            pkgs[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            pkgs[name] = None
    return {"python": sys.version.split()[0], "implementation": platform.python_implementation(),
            "platform": platform.platform(), "packages": pkgs}
