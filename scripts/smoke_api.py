#!/usr/bin/env python3
"""Boot the real HTTP service (uvicorn) on fakes and drive one full flow over HTTP.
Writes results/api_smoke.txt.

    python3 scripts/smoke_api.py
"""
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = os.environ.get("SMOKE_PORT", "8765")
BASE = f"http://127.0.0.1:{PORT}"


def call(method, path, body=None, headers=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main():
    env = dict(os.environ, PORT=PORT, RESPONSE_FLOOR_MS="0", PYTHONPATH=str(ROOT / "src"),
               PREFIX_TABLE_PATH=str(ROOT / "config" / "prefixes.json"),
               SOURCE_LIMITS_PATH=str(ROOT / "config" / "source_limits.json"),
               ATTESTATION_GRACE_UNTIL="2030-01-01T00:00:00Z", INTERNAL_SERVICE_CREDENTIALS="svc")
    srv = subprocess.Popen([sys.executable, "-m", "otp_guard.api"], env=env, cwd=ROOT,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines = []
    def log(label, value):
        lines.append(f"{label}: {json.dumps(value)}"); print(lines[-1])
    try:
        for _ in range(100):
            try:
                call("GET", "/healthz"); break
            except Exception:
                time.sleep(0.1)
        log("GET /healthz", call("GET", "/healthz"))
        log("POST /session web bad token", call("POST", "/session", {"platform": "web", "fingerprint": "f", "recaptcha_token": "x"}))
        st, body = call("POST", "/session", {"platform": "android", "fingerprint": "fp1", "app_version": "3.0"})
        log("POST /session legacy app", (st, sorted(body)))
        tok = body["session_token"]
        log("POST /otp/request", call("POST", "/otp/request", {"mobile": "966501234567", "nonce": "n1"},
                                       {"Authorization": "Bearer " + tok, "X-App-Version": "3.0"}))
        log("POST /otp/request (replayed nonce)", call("POST", "/otp/request", {"mobile": "966501234567", "nonce": "n1"},
                                                        {"Authorization": "Bearer " + tok, "X-App-Version": "3.0"}))
        log("POST /otp/verify wrong code", call("POST", "/otp/verify", {"mobile": "966501234567", "code": "0000"}, {"Authorization": "Bearer " + tok}))
        log("POST /internal/timeouts/run no credential", call("POST", "/internal/timeouts/run")[0])
        log("POST /internal/timeouts/run with credential", call("POST", "/internal/timeouts/run", headers={"X-Service-Credential": "svc"})[0])
    finally:
        srv.terminate()
        out = srv.communicate(timeout=10)[0]
    lines += ["", "--- server log tail ---"] + out.strip().splitlines()[-8:]
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "api_smoke.txt").write_text("\n".join(lines) + "\n")
    print(f"wrote {ROOT / 'results' / 'api_smoke.txt'}")


if __name__ == "__main__":
    main()
