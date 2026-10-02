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


def start_api(floor_ms, latency_ms=0, sigma=0.5, timeout_prob=0.0, timeout_ms=2000):
    LIMITS_PATH.write_text(json.dumps({"App/RegisterOTP": {f"per_{p}_{plat}": 10 ** 9 for p in ("minute", "hour")
                                                            for plat in ("web", "ios", "android", "legacy_app")}}))
    env = dict(os.environ, PORT=str(API_PORT), REDIS_URL=f"redis://127.0.0.1:{REDIS_PORT}/1", RESPONSE_FLOOR_MS=str(floor_ms),
               LOAD_TEST_DEBUG_HEADER="1", PYTHONPATH=str(ROOT / "src"), PREFIX_TABLE_PATH=str(ROOT / "config" / "prefixes.json"),
               SOURCE_LIMITS_PATH=str(LIMITS_PATH), ATTESTATION_GRACE_UNTIL="2030-01-01T00:00:00Z", SESSION_HMAC_KEY="load-test-key",
               WORKERS=os.environ.get("LOAD_TEST_WORKERS", "4"), ASN_LIMIT_DEFAULT="1000000000", IP_LIMIT_PER_MINUTE="1000000000",
               FAKE_RECAPTCHA_SCORES="good:0.9,mid:0.6", FAKE_VENDOR_LATENCY_MS=str(latency_ms) if latency_ms else "",
               FAKE_VENDOR_LATENCY_SIGMA=str(sigma), FAKE_VENDOR_TIMEOUT_PROB=str(timeout_prob), FAKE_VENDOR_TIMEOUT_MS=str(timeout_ms))
    p = subprocess.Popen([sys.executable, "-m", "otp_guard.api"], env=env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import httpx
    for _ in range(100):
        try:
            httpx.get(f"http://127.0.0.1:{API_PORT}/healthz", timeout=1); return p
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("api did not start")


UNIFORM_EXCLUDED = ("challenge", "step0", "server_error")     # outcomes whose response differs anyway (body or status)


def threshold_accuracy(a, b):
    """Observer model: a remote client that sees only its own response times and must tell two
    outcome classes apart with one latency threshold (either direction), with the classes equally
    likely. Returns the best balanced accuracy over all thresholds (0.5 = no information)."""
    xs = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    na, nb = len(a), len(b)
    best, ca, cb = 0.5, 0, 0
    for v, lab in xs:
        if lab == 0:
            ca += 1
        else:
            cb += 1
        acc = 0.5 * (ca / na + (nb - cb) / nb)          # predict class a below the threshold
        best = max(best, acc, 1 - acc)
    return best


def phase2(n, concurrency, floor_ms, redis_client, latency_ms=0, mix="default", sigma=0.5, timeout_prob=0.0, timeout_ms=2000):
    import httpx
    from otp_guard.evaluation.stats import ks_2samp
    redis_client.flushall()
    api = start_api(floor_ms, latency_ms, sigma, timeout_prob, timeout_ms)
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
        def web_session_fresh():
            # a browser never seen before: +20 points; with a 0.6 captcha (+10) and an unknown prefix (+10) it is challenged
            r = client.post("/session", json={"platform": "web", "fingerprint": f"wfp{random.random()}", "recaptcha_token": "good"})
            return r.json()["session_token"]
        # the per-session cap is 3 requests per 10 minutes: one session per three requests
        toks = [session() for _ in range(n // 3 + 1)]
        wtoks = [web_session_fresh() for _ in range(n // 10 + 1)]
        nonce = itertools.count(); lock = threading.Lock()
        if mix == "adversarial":
            # attack load built to reach the expensive path (fresh web session, valid CAPTCHA, a new number: an
            # HLR lookup and an SMS each), challenge traffic, 403s from a foreign host, and ordinary requests
            kinds = ["expensive"] * 55 + ["challenge"] * 15 + ["foreign_host"] * 10 + ["happy"] * 20
            xtoks = [web_session_fresh() for _ in range(n + 1)]
        else:
            kinds = ["happy"] * 45 + ["no_session"] * 12 + ["bad_country"] * 12 + ["repeat_number"] * 12 + ["challenge"] * 19
        out = []
        def one(i):
            rng = random.Random(i)
            kind = rng.choice(kinds)
            with lock: nn = next(nonce)
            mobile = {"happy": f"96650{rng.randrange(10**7):07d}", "no_session": "966501234567",
                      "bad_country": f"1415{rng.randrange(10**7):07d}", "repeat_number": "966501234567",
                      "challenge": f"96652{rng.randrange(10**7):07d}",            # 96652: not in the prefix table
                      "expensive": f"96655{rng.randrange(10**7):07d}", "foreign_host": f"96650{rng.randrange(10**7):07d}"}[kind]
            headers = {"X-Forwarded-For": f"198.{(i >> 8) & 255}.{i & 255}.7"}
            body = {"mobile": mobile, "nonce": f"n{nn}"}
            if kind == "challenge":
                headers["Authorization"] = "Bearer " + wtoks[(i // 10) % len(wtoks)]
                headers["Origin"] = "https://example.com"
                headers["Host"] = "example.com"              # step 0 rejects web requests for any other host
                body["recaptcha_token"] = "mid"
            elif kind in ("expensive", "foreign_host"):
                headers["Authorization"] = "Bearer " + xtoks[i]
                headers["Origin"] = "https://example.com"
                headers["Host"] = "example.com" if kind == "expensive" else "evil.example.net"
                body["recaptcha_token"] = "good"
            else:
                headers["X-App-Version"] = "3.0"
                if kind != "no_session": headers["Authorization"] = "Bearer " + toks[i // 3]
            c = thread_client()
            t0 = time.perf_counter()
            r = c.post("/otp/request", json=body, headers=headers)
            dt = (time.perf_counter() - t0) * 1000
            dbg = json.loads(r.headers.get("x-debug-outcome", "{}"))
            if r.status_code >= 500:
                outcome = "server_error"
            else:
                outcome = "challenge" if dbg.get("tier") == "challenge" and dbg.get("rejected_at") == "step7" else (dbg.get("rejected_at") or "sent")
            return kind, outcome, dt, dbg.get("timings_ms") or {}
        t0 = time.perf_counter()
        with ThreadPoolExecutor(concurrency) as ex:
            out = list(ex.map(one, range(n)))
        wall = time.perf_counter() - t0
        by_outcome = collections.defaultdict(list)
        by_kind = collections.defaultdict(collections.Counter)      # offered kind -> outcome counts (admission under load)
        over_floor = 0
        for kind, outcome, dt, timings in out:
            by_outcome[outcome].append(dt)
            by_kind[kind][outcome] += 1
            over_floor += floor_ms > 0 and sum(timings.values()) > floor_ms
        ks = {}
        outcomes = sorted(by_outcome)
        from otp_guard.evaluation.stats import tost_mean_diff
        for a in outcomes:
            for b in outcomes:
                if a < b and len(by_outcome[a]) >= 20 and len(by_outcome[b]) >= 20:
                    stat, pv = ks_2samp(by_outcome[a], by_outcome[b])
                    ks[f"{a} vs {b}"] = {"statistic": stat, "p_value": pv, "n_a": len(by_outcome[a]), "n_b": len(by_outcome[b]),
                                         "tost_2ms": tost_mean_diff(by_outcome[a], by_outcome[b], margin=2.0),
                                         "uniform_body_pair": a not in UNIFORM_EXCLUDED and b not in UNIFORM_EXCLUDED,
                                         "threshold_balanced_accuracy": threshold_accuracy(by_outcome[a], by_outcome[b])}
        srv = collections.defaultdict(list)
        for kind, outcome, dt, timings in out:
            srv[outcome].append(sum(timings.values()))
        over_by_outcome = {k: sum(1 for v in vs if v > floor_ms) / len(vs) for k, vs in srv.items()} if floor_ms else None
        return {"requests": n, "concurrency": concurrency, "workers": int(os.environ.get("LOAD_TEST_WORKERS", "4")),
                "floor_ms": floor_ms, "vendor_latency_ms": latency_ms, "mix": mix, "vendor_sigma": sigma,
                "vendor_timeout_prob": timeout_prob, "wall_s": wall, "throughput_rps": n / wall,
                "by_kind": {k: dict(v) for k, v in by_kind.items()},
                "throughput_note": ("bounded by concurrency / floor = %.1f req/s, not server capacity" % (concurrency / (floor_ms / 1000.0))) if floor_ms else "server capacity at this concurrency",
                "pipeline_time_over_floor_fraction": over_floor / n if floor_ms else None,
                "latency_by_outcome_ms": {k: {"p50": pct(v, 50), "p95": pct(v, 95), "p99": pct(v, 99), "mean": statistics.fmean(v), "n": len(v)} for k, v in by_outcome.items()},
                "ks_tests": ks, "client_over_floor_by_outcome": over_by_outcome}
    finally:
        api.terminate(); api.wait(timeout=10)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=3000)
    ap.add_argument("--http-requests", type=int, default=6000)
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--vendor-latency-ms", type=float, default=50.0, help="phase 3: median blocking time of each fake vendor call")
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
        # phase 3: capacity as deployed (floor on) with vendors that take time, at rising concurrency
        R["phase3_capacity"] = []
        for c in (32, 64, 128):
            R["phase3_capacity"].append(phase2(a.requests, c, 400, rc, latency_ms=a.vendor_latency_ms))
            print(f"phase 3 (concurrency {c}) done", flush=True)
        # phase 4: adversarial mixture, heavy-tailed vendors (sigma 1.2) with 1 % timeouts of 2 s
        R["phase4_adversarial"] = []
        for c in (32, 128):
            R["phase4_adversarial"].append(phase2(a.requests, c, 400, rc, latency_ms=a.vendor_latency_ms, mix="adversarial",
                                                  sigma=1.2, timeout_prob=0.01, timeout_ms=2000))
            print(f"phase 4 (concurrency {c}) done", flush=True)
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
              "| Pair | n | KS statistic | KS p-value | mean diff (ms) | TOST p (equivalent within 2 ms) | Best threshold accuracy |", "|---|---:|---:|---:|---:|---:|---:|"]
        for k, v in p2["ks_tests"].items():
            t = v["tost_2ms"]
            L.append(f"| {k} | {v['n_a']} / {v['n_b']} | {v['statistic']:.3f} | {v['p_value']:.2e} | {t['mean_diff']:.2f} | {t['p_value']:.2e} | "
                     f"{v.get('threshold_balanced_accuracy', float('nan')):.3f} |")
    if R.get("phase3_capacity"):
        p3 = R["phase3_capacity"]
        L += ["", f"## Phase 3: capacity as deployed, {p3[0]['requests']} requests per row", "",
              f"The 400 ms floor on, and every fake vendor call (reCAPTCHA, HLR, the SMS provider) blocking for a lognormal "
              f"{p3[0]['vendor_latency_ms']:.0f} ms median (sigma 0.5), so a full send makes about three such calls; "
              f"{p3[0].get('workers', 1)} worker processes. Throughput under the floor is bounded by concurrency / 0.4 s until the "
              "server saturates; the *over floor* column is the share of requests whose processing exceeded the floor (those leak "
              "timing and are the first sign of saturation); *admission* is the share of the happy-path requests that were sent, "
              "which under fair admission does not move with load (a drop means saturation is refusing real users).", "",
              "| Concurrency | Throughput (req/s) | Bound (concurrency / floor) | Sent p50 / p95 / p99 (ms) | Over floor | Happy path sent | Server errors |",
              "|---:|---:|---:|---:|---:|---:|---:|"]
        for p in p3:
            sent = p["latency_by_outcome_ms"].get("sent", {"p50": 0, "p95": 0, "p99": 0})
            happy = p["by_kind"].get("happy", {}); n_h = sum(happy.values()) or 1
            errs = sum(v.get("server_error", 0) for v in p["by_kind"].values())
            L.append(f"| {p['concurrency']} | {p['throughput_rps']:.1f} | {p['concurrency'] / 0.4:.0f} | {sent['p50']:.0f} / {sent['p95']:.0f} / {sent['p99']:.0f} | "
                     f"{100 * (p['pipeline_time_over_floor_fraction'] or 0):.1f} % | {100 * happy.get('sent', 0) / n_h:.1f} % | {errs} |")
    if R.get("phase4_adversarial"):
        p4 = R["phase4_adversarial"]
        L += ["", f"## Phase 4: adversarial mixture, heavy-tailed vendors, {p4[0]['requests']} requests per row", "",
              "55 % of requests are built to reach the expensive path (a fresh web session, a valid CAPTCHA token and a new number "
              "in an allowed prefix: an HLR lookup and an SMS each), 15 % land in the challenge tier, 10 % come from a foreign host "
              "(rejected at Step 0 with 403, which the floor does not pad by design) and 20 % are ordinary app requests whose "
              f"admission is tracked. Vendor calls: lognormal, median {p4[0]['vendor_latency_ms']:.0f} ms, sigma {p4[0]['vendor_sigma']}, "
              f"and {100 * p4[0]['vendor_timeout_prob']:.0f} % of calls time out after 2 s. The floor is on.", "",
              "| Concurrency | Throughput (req/s) | Over floor | Ordinary requests sent | Sent p50 / p95 / p99 (ms) | Challenge p50 / p99 (ms) | 403 p50 (ms) | Server errors |",
              "|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for p in p4:
            lat = p["latency_by_outcome_ms"]
            sent = lat.get("sent", {"p50": 0, "p95": 0, "p99": 0}); chal = lat.get("challenge", {"p50": 0, "p99": 0})
            s0 = lat.get("step0", {"p50": 0})
            happy = p["by_kind"].get("happy", {}); n_h = sum(happy.values()) or 1
            errs = sum(v.get("server_error", 0) for v in p["by_kind"].values())
            L.append(f"| {p['concurrency']} | {p['throughput_rps']:.1f} | {100 * (p['pipeline_time_over_floor_fraction'] or 0):.1f} % | "
                     f"{100 * happy.get('sent', 0) / n_h:.1f} % | {sent['p50']:.0f} / {sent['p95']:.0f} / {sent['p99']:.0f} | "
                     f"{chal['p50']:.0f} / {chal['p99']:.0f} | {s0['p50']:.0f} | {errs} |")
        L += ["", "Timing by outcome under this mixture. Observer model: a remote client that sees only the response times of its own "
              "requests and wants to tell two server-side outcomes apart whose responses are otherwise identical (same status and "
              "body: an SMS sent, or a refusal at a hard step), with the two equally likely. *Over floor*: share of the class whose "
              "server-side pipeline time exceeded the floor, so its response could not be padded to it. *Best threshold accuracy*: the balanced accuracy of "
              "the best single latency threshold between the two classes on these samples (0.5 = no information; optimistic, since "
              "the threshold is chosen on the same data). A KS p-value above 0.05 is a failure to detect a difference, not evidence "
              "of none.", ""]
        for p in p4:
            lat = p["latency_by_outcome_ms"]
            ob = p.get("client_over_floor_by_outcome") or {}
            L += [f"Concurrency {p['concurrency']}:", "", "| Outcome | n | Client p50 / p95 / p99 (ms) | Over floor (server time) |", "|---|---:|---:|---:|"]
            for k in sorted(lat):
                v = lat[k]
                L.append(f"| {k} | {v['n']} | {v['p50']:.0f} / {v['p95']:.0f} / {v['p99']:.0f} | {100 * ob.get(k, 0):.1f} % |")
            L += ["", "| Uniform-body pair | n | KS p-value | Best threshold accuracy |", "|---|---:|---:|---:|"]
            for pair, t in sorted(p["ks_tests"].items()):
                if t.get("uniform_body_pair"):
                    L.append(f"| {pair} | {t['n_a']} / {t['n_b']} | {t['p_value']:.2g} | {t['threshold_balanced_accuracy']:.3f} |")
            L.append("")
        L += ["Exceeding the floor removes the guarantee of equal completion times for those requests; how much it reveals about "
              "the protected outcome is the accuracy column, under the observer model stated, not a general side-channel bound."]
    path.write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
