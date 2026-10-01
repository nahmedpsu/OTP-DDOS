#!/usr/bin/env python3
"""Performance and timing-leak measurement against a real Redis.

Phase 1 (in process): the pipeline on RedisStore, 3 000 mixed requests; per-step and end-to-end
latency percentiles; Redis commands per request from INFO commandstats.
Phase 2 (HTTP): uvicorn serving the API on Redis, 16 concurrent clients; end-to-end latency by
server-side outcome (from the opt-in X-Debug-Outcome header); two-sample KS tests between
outcomes with the 400 ms response floor on, and with it off as the control.

    python3 scripts/load_test.py [--requests 3000] [--http-requests 800] [--concurrency 16]

Writes results/performance.md and results/performance.json. Needs redis-server and uvicorn.
"""
import argparse
import collections
import itertools
import json
import os
import pathlib
import random
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

REDIS_PORT = int(os.environ.get("LOAD_TEST_REDIS_PORT", "6390"))
API_PORT = int(os.environ.get("LOAD_TEST_API_PORT", "8766"))


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def start_redis():
    p = subprocess.Popen(["redis-server", "--port", str(REDIS_PORT), "--save", "", "--appendonly", "no", "--loglevel", "warning"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import redis
    for _ in range(50):
        try:
            r = redis.Redis(port=REDIS_PORT); r.ping(); r.flushall(); return p, r
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("redis did not start")


# ---------------- phase 1: in-process ----------------

def phase1(n, redis_client):
    import redis
    from otp_guard.config import Config
    from otp_guard.pipeline import Pipeline, Request
    from otp_guard.services import Services
    from otp_guard.store import RedisStore, SystemClock
    cfg = Config(); cfg.response_floor_ms = 0
    sl = cfg.source_limits["App/RegisterOTP"]
    for k in list(sl):
        if k.startswith("per_"): sl[k] = 10 ** 9
    sl["per_country"] = {}
    cfg.asn_limit_default = 10 ** 9; cfg.ip_limit = (10 ** 9, 60); cfg.subnet_limit = (10 ** 9, 60)
    svc = Services(); svc.recaptcha.scores["good"] = 0.9
    for p in ("96650", "96655", "97150"): svc.prefixes.add(p)
    store = RedisStore(redis.Redis(port=REDIS_PORT), SystemClock())
    pipe = Pipeline(cfg, svc, SystemClock(), store=store)
    redis_client.config_resetstat()
    store.round_trips = 0
    rng = random.Random(1); nonce = itertools.count()
    step_t = collections.defaultdict(list); e2e = collections.defaultdict(list)
    kinds = ["happy"] * 55 + ["no_session"] * 15 + ["bad_country"] * 15 + ["repeat_number"] * 15
    last_mobile = "966501234567"
    for i in range(n):
        kind = rng.choice(kinds)
        tok = pipe.sessions.issue("web", f"fp{i}", 1800) if kind != "no_session" else ""
        mobile = {"happy": f"96650{rng.randrange(10**7):07d}", "no_session": "966501234567",
                  "bad_country": f"1415{rng.randrange(10**7):07d}", "repeat_number": last_mobile}[kind]
        if kind == "happy": last_mobile = mobile
        req = Request(mobile=mobile, session_token=tok, nonce=f"n{next(nonce)}", ip=f"198.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}",
                      post={"g-recaptcha-response": "good"}, origin="https://example.com/x")
        t0 = time.perf_counter(); r = pipe.process(req); dt = (time.perf_counter() - t0) * 1000
        e2e[r.rejected_at or "sent"].append(dt)
        for s, ms in (r.timings_ms or {}).items(): step_t[s].append(ms)
    stats = redis_client.info("commandstats")
    total_cmds = sum(v["calls"] for k, v in stats.items())
    per_cmd = {k.replace("cmdstat_", ""): v["calls"] / n for k, v in sorted(stats.items(), key=lambda kv: -kv[1]["calls"])[:12]}
    return {"requests": n,
            "per_step_ms": {s: {"p50": pct(v, 50), "p95": pct(v, 95), "p99": pct(v, 99), "n": len(v)} for s, v in sorted(step_t.items())},
            "end_to_end_ms": {k: {"p50": pct(v, 50), "p95": pct(v, 95), "p99": pct(v, 99), "n": len(v)} for k, v in sorted(e2e.items())},
            "redis_commands_per_request": total_cmds / n, "redis_round_trips_per_request": store.round_trips / n,
            "redis_top_commands_per_request": per_cmd}


# ---------------- phase 2: HTTP ----------------

LIMITS_PATH = pathlib.Path("/tmp/otp-guard-load-test-limits.json")


def start_api(floor_ms):
    LIMITS_PATH.write_text(json.dumps({"App/RegisterOTP": {f"per_{p}_{plat}": 10 ** 9 for p in ("minute", "hour")
                                                            for plat in ("web", "ios", "android", "legacy_app")}}))
    env = dict(os.environ, PORT=str(API_PORT), REDIS_URL=f"redis://127.0.0.1:{REDIS_PORT}/1", RESPONSE_FLOOR_MS=str(floor_ms),
               LOAD_TEST_DEBUG_HEADER="1", PYTHONPATH=str(ROOT / "src"), PREFIX_TABLE_PATH=str(ROOT / "config" / "prefixes.json"),
               SOURCE_LIMITS_PATH=str(LIMITS_PATH), ATTESTATION_GRACE_UNTIL="2030-01-01T00:00:00Z", SESSION_HMAC_KEY="load-test-key",
               WORKERS=os.environ.get("LOAD_TEST_WORKERS", "4"), ASN_LIMIT_DEFAULT="1000000000", IP_LIMIT_PER_MINUTE="1000000000")
    p = subprocess.Popen([sys.executable, "-m", "otp_guard.api"], env=env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import httpx
    for _ in range(100):
        try:
            httpx.get(f"http://127.0.0.1:{API_PORT}/healthz", timeout=1); return p
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("api did not start")


def phase2(n, concurrency, floor_ms, redis_client):
    import httpx
    from otp_guard.evaluation.stats import ks_2samp
    redis_client.flushall()
    api = start_api(floor_ms)
    try:
        base = f"http://127.0.0.1:{API_PORT}"
        # sessions are issued by the server; the fake recaptcha in the API has no scores, so patch via the store:
        # instead, use legacy-app sessions (no captcha) which the grace window permits
        client = httpx.Client(base_url=base, timeout=30)
        local = threading.local()
        def thread_client():
            if not hasattr(local, "c"):
                local.c = httpx.Client(base_url=base, timeout=30)
            return local.c
        import redis as _redis
        r1 = _redis.Redis(port=REDIS_PORT, db=1)
        def session():
            fp = f"fp{random.random()}"
            r1.set("fp_first_seen:" + fp, json.dumps(time.time() - 7200))      # a browser seen two hours ago
            r = client.post("/session", json={"platform": "android", "fingerprint": fp, "app_version": "3.0"})
            return r.json()["session_token"]
        # the per-session cap is 3 requests per 10 minutes: one session per three requests
        toks = [session() for _ in range(n // 3 + 1)]
        nonce = itertools.count(); lock = threading.Lock()
        kinds = ["happy"] * 55 + ["no_session"] * 15 + ["bad_country"] * 15 + ["repeat_number"] * 15
        out = []
        def one(i):
            rng = random.Random(i)
            kind = rng.choice(kinds)
            with lock: nn = next(nonce)
            mobile = {"happy": f"96650{rng.randrange(10**7):07d}", "no_session": "966501234567",
                      "bad_country": f"1415{rng.randrange(10**7):07d}", "repeat_number": "966501234567"}[kind]
            headers = {"X-App-Version": "3.0", "X-Forwarded-For": f"198.{(i >> 8) & 255}.{i & 255}.7"}
            if kind != "no_session": headers["Authorization"] = "Bearer " + toks[i // 3]
            c = thread_client()
            t0 = time.perf_counter()
            r = c.post("/otp/request", json={"mobile": mobile, "nonce": f"n{nn}"}, headers=headers)
            dt = (time.perf_counter() - t0) * 1000
            dbg = json.loads(r.headers.get("x-debug-outcome", "{}"))
            return kind, dbg.get("rejected_at") or "sent", dt, dbg.get("timings_ms") or {}
        t0 = time.perf_counter()
        with ThreadPoolExecutor(concurrency) as ex:
            out = list(ex.map(one, range(n)))
        wall = time.perf_counter() - t0
        by_outcome = collections.defaultdict(list)
        over_floor = 0
        for _, outcome, dt, timings in out:
            by_outcome[outcome].append(dt)
            over_floor += floor_ms > 0 and sum(timings.values()) > floor_ms
        ks = {}
        outcomes = sorted(by_outcome)
        from otp_guard.evaluation.stats import tost_mean_diff
        for a in outcomes:
            for b in outcomes:
                if a < b and len(by_outcome[a]) >= 20 and len(by_outcome[b]) >= 20:
                    stat, pv = ks_2samp(by_outcome[a], by_outcome[b])
                    ks[f"{a} vs {b}"] = {"statistic": stat, "p_value": pv, "n_a": len(by_outcome[a]), "n_b": len(by_outcome[b]),
                                         "tost_2ms": tost_mean_diff(by_outcome[a], by_outcome[b], margin=2.0)}
        return {"requests": n, "concurrency": concurrency, "workers": int(os.environ.get("LOAD_TEST_WORKERS", "4")),
                "floor_ms": floor_ms, "wall_s": wall, "throughput_rps": n / wall,
                "throughput_note": ("bounded by concurrency / floor = %.1f req/s, not server capacity" % (concurrency / (floor_ms / 1000.0))) if floor_ms else "server capacity at this concurrency",
                "pipeline_time_over_floor_fraction": over_floor / n if floor_ms else None,
                "latency_by_outcome_ms": {k: {"p50": pct(v, 50), "p95": pct(v, 95), "p99": pct(v, 99), "mean": statistics.fmean(v), "n": len(v)} for k, v in by_outcome.items()},
                "ks_tests": ks}
    finally:
        api.terminate(); api.wait(timeout=10)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=3000)
    ap.add_argument("--http-requests", type=int, default=6000)
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--out", default=str(ROOT / "results"))
    a = ap.parse_args()
    out = pathlib.Path(a.out); out.mkdir(exist_ok=True)
    rp, rc = start_redis()
    try:
        R = {"phase1_in_process": phase1(a.requests, rc)}
        print("phase 1 done", flush=True)
        R["phase2_http_floor_400"] = phase2(a.http_requests, a.concurrency, 400, rc)
        print("phase 2 (floor 400) done", flush=True)
        R["phase2_http_floor_0"] = phase2(a.http_requests, a.concurrency, 0, rc)
        print("phase 2 (floor 0) done", flush=True)
    finally:
        rp.terminate(); rp.wait(timeout=5)
    (out / "performance.json").write_text(json.dumps(R, indent=1) + "\n")
    write_md(R, out / "performance.md")
    print("wrote", out / "performance.md")


def write_md(R, path):
    p1 = R["phase1_in_process"]
    L = ["# Performance and timing-leak measurement", "",
         f"Generated by `scripts/load_test.py` against a real `redis-server` on the same {os.cpu_count()}-vCPU container, "
         f"{os.environ.get('LOAD_TEST_WORKERS', '4')} uvicorn workers; "
         "vendors are fakes, so the numbers are the pipeline's own overhead plus Redis round trips, not vendor latency.", "",
         f"## Phase 1: pipeline in process on Redis, {p1['requests']} mixed requests", "",
         f"Redis round trips per request: **{p1['redis_round_trips_per_request']:.1f}** (commands: {p1['redis_commands_per_request']:.1f}; "
         "the 24 hourly reputation buckets of a key are one pipelined round trip). Top commands per request: " +
         ", ".join(f"`{k}` {v:.2f}" for k, v in p1["redis_top_commands_per_request"].items()), "",
         "| Step | n | p50 (ms) | p95 (ms) | p99 (ms) |", "|---|---:|---:|---:|---:|"]
    for s, v in p1["per_step_ms"].items():
        L.append(f"| {s} | {v['n']} | {v['p50']:.2f} | {v['p95']:.2f} | {v['p99']:.2f} |")
    L += ["", "| Outcome | n | p50 (ms) | p95 (ms) | p99 (ms) |", "|---|---:|---:|---:|---:|"]
    for k, v in p1["end_to_end_ms"].items():
        L.append(f"| {k} | {v['n']} | {v['p50']:.2f} | {v['p95']:.2f} | {v['p99']:.2f} |")
    for key, title in (("phase2_http_floor_400", "with the 400 ms response floor"), ("phase2_http_floor_0", "floor disabled (control)")):
        p2 = R[key]
        cov = "" if p2.get("pipeline_time_over_floor_fraction") is None else \
              f" Pipeline processing exceeded the floor in {100 * p2['pipeline_time_over_floor_fraction']:.2f} % of requests (those leak timing)."
        L += ["", f"## Phase 2: HTTP through uvicorn ({p2.get('workers', 1)} worker processes), {p2['requests']} requests at concurrency {p2['concurrency']}, {title}", "",
              f"Throughput {p2['throughput_rps']:.1f} requests/s over {p2['wall_s']:.1f} s ({p2['throughput_note']}).{cov}", "",
              "| Server-side outcome | n | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) |", "|---|---:|---:|---:|---:|---:|"]
        for k, v in sorted(p2["latency_by_outcome_ms"].items()):
            L.append(f"| {k} | {v['n']} | {v['p50']:.1f} | {v['p95']:.1f} | {v['p99']:.1f} | {v['mean']:.1f} |")
        L += ["", "Two-sample Kolmogorov-Smirnov tests on client-observed latency (an attacker's view): a small p-value means the outcomes "
              "are distinguishable by timing. The TOST column is an equivalence test on the mean difference with a +/-2 ms margin: "
              "a small p-value there means the means are demonstrably within 2 ms of each other.", "",
              "| Pair | n | KS statistic | KS p-value | mean diff (ms) | TOST p (equivalent within 2 ms) |", "|---|---:|---:|---:|---:|---:|"]
        for k, v in p2["ks_tests"].items():
            t = v["tost_2ms"]
            L.append(f"| {k} | {v['n_a']} / {v['n_b']} | {v['statistic']:.3f} | {v['p_value']:.2e} | {t['mean_diff']:.2f} | {t['p_value']:.2e} |")
    path.write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
