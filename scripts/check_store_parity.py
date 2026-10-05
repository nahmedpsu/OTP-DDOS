#!/usr/bin/env python3
"""Seventh-round review, M1: the simulator's results do not depend on which store keeps its state.

Runs a stratified sample of the recorded study specs (one per study, the shortest-running spec of a
random seed, up to --max-minutes simulated minutes) twice, on the in-memory store every recorded run
used and on RedisStore over fakeredis driven by the simulated clock, and compares every recorded field
except wall time. tests/unit/test_store_parity.py compares the two stores operation by operation, and
tests/integration/test_real_redis.py checks the expiry rules on a real redis-server.

    python3 scripts/check_store_parity.py [--per-study 1] [--max-minutes 200] [--out results/store_parity_check.md]"""
import argparse
import pathlib
import random
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import check_reproduction as CR                                      # noqa: E402
from otp_guard.evaluation.jobs import spec_hash                      # noqa: E402
from otp_guard.evaluation.sim import run_sim                         # noqa: E402

IGNORE = {"wall_s"}


def diff(a, b, path=""):
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if k not in IGNORE:
                out += diff(a.get(k), b.get(k), f"{path}/{k}")
    elif isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, f"{path}[{i}]")
    elif a != b:
        out.append(path)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-study", type=int, default=1)
    ap.add_argument("--max-minutes", type=int, default=200)
    ap.add_argument("--out", default=str(ROOT / "results" / "store_parity_check.md"))
    a = ap.parse_args()
    rng = random.Random(20261004)
    by = {}
    for label, jobs in (("evaluation", CR.evaluation_jobs()), ("counter study", CR.counter_jobs())):
        for study, spec in jobs:
            if spec.minutes + spec.warmup_minutes <= a.max_minutes and not spec.profile_weeks:
                by.setdefault((label, study), []).append(spec)
    rows, same, t0 = [], 0, time.time()
    for (label, study), specs in sorted(by.items()):
        for spec in rng.sample(specs, min(a.per_study, len(specs))):
            m, r = run_sim(spec, "memory"), run_sim(spec, "redis")
            d = diff(m, r)
            same += not d
            rows.append(f"| {label} | {study} | {spec_hash(spec)} | {spec.seed} | {spec.warmup_minutes + spec.minutes} | "
                        f"{m['attack']['leaked_total']} | {'identical' if not d else ', '.join(d[:3])} |")
            print(rows[-1], flush=True)
    L = ["# The simulator on both stores (seventh-round review, M1)", "",
         f"{len(rows)} recorded study specs, {a.per_study} per study (seed 20261004; specs of at most {a.max_minutes} simulated "
         "minutes, no multi-week baselines), each run on the in-memory store and on RedisStore over fakeredis driven by the "
         f"simulated clock. Every recorded field except wall time is compared. **{same} of {len(rows)} identical.** "
         f"Wall time {time.time() - t0:.0f} s.", "",
         "| Results file | Study | Spec hash | Seed | Simulated minutes | Leaked | Outcome |", "|---|---|---|---:|---:|---:|---|"] + rows
    pathlib.Path(a.out).write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
