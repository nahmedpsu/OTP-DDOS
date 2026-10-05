#!/usr/bin/env python3
"""Seventh-round review, M1: which of the store rules aligned in 2.9.0 changes the recorded runs.

On a stratified sample of the recorded runs (three per study, seed 20261003; runs of at most 200 simulated
minutes), each run is replayed with
the 2.9.0 memory store and with variants that restore one 2.8.x rule, and compared with the 2.8.x record
(results/historical_2.8/) and the 2.9.0 record:

  2.9.0               the released store (its replay must equal the 2.9.0 record);
  2.9.0 but boundary  a key expires at its expiry instant (2.8.x) instead of once the clock passes it;
  2.9.0 but order     equal-score members in insertion order (2.8.x) instead of member order.

The refresh-only variant (the 2.8.x store with only the sorted-set TTL refreshed on every write) was
measured in 2.8.2: results/historical_2.8/store_expiry_check.md. Writes results/store_rule_ablation.md. Variants are monkeypatched here; the library is unchanged."""
import gzip
import json
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import check_reproduction as CR                                  # noqa: E402
from otp_guard import store as S                                 # noqa: E402
from otp_guard.evaluation.jobs import spec_hash                  # noqa: E402
from otp_guard.evaluation.sim import run_sim                     # noqa: E402

SKIP = {"wall_s", "code_hash", "index", "study", "spec_hash", "block_state_at_first_attack", "attacker_sms_exempt"}
NEW = {k: getattr(S.MemoryStore, k) for k in ("_live", "zadd", "zadd_max", "zrangebyscore")}


def live_at_instant(self, key):                       # 2.8.x: expired when expiry <= now
    v = self._d.get(key)
    if v is None:
        return None
    if v[1] is not None and v[1] <= self.clock.now():
        del self._d[key]
        return None
    return v


def zrange_insertion(self, key, lo, hi):              # 2.8.x: equal scores in insertion order
    with self.lock:
        v = self._live(key)
        if v is None:
            return []
        return [m for m, s in sorted(v[0].items(), key=lambda kv: kv[1]) if lo <= s <= hi]


def restore():
    for k, f in NEW.items():
        setattr(S.MemoryStore, k, f)


def variant(name):
    restore()
    if name == "2.9.0 but boundary":
        S.MemoryStore._live = live_at_instant
    elif name == "2.9.0 but order":
        S.MemoryStore.zrangebyscore = zrange_insertion


def flat(v, p=""):
    if isinstance(v, dict):
        o = {}
        for k, x in v.items():
            o.update(flat(x, f"{p}/{k}"))
        return o
    return {p: v}


def same(a, b):
    fa = flat({k: v for k, v in a.items() if k not in SKIP})
    fb = flat({k: v for k, v in b.items() if k not in SKIP})
    return fa == fb, fa.get("/attack/leaked_total") == fb.get("/attack/leaked_total")


def records(path):
    out = {}
    with gzip.open(path, "rt") as f:
        for line in f:
            r = json.loads(line)
            out[(r["spec_hash"], r["spec"]["seed"])] = r
    return out


def main():
    old, new = {}, {}
    for f in ("evaluation_runs.jsonl.gz", "counter_study_runs.jsonl.gz"):
        old.update(records(ROOT / "results" / "historical_2.8" / f))
        new.update(records(ROOT / "results" / f))
    jobs = CR.evaluation_jobs() + CR.counter_jobs()
    by = {}
    for study, spec in jobs:
        by.setdefault(study, []).append(spec)
    rng = random.Random(20261003)
    sample = [s for study in sorted(by) for s in rng.sample(by[study], min(3, len(by[study])))]
    sample = [s for s in sample if s.minutes + s.warmup_minutes <= 200 and not s.profile_weeks]    # no 24-hour runs
    variants = ["2.9.0", "2.9.0 but boundary", "2.9.0 but order"]
    res = {v: {"same_as_2.8": 0, "leak_as_2.8": 0, "same_as_2.9": 0} for v in variants}
    res["2.9.0 record vs 2.8.x record"] = {"same_as_2.8": 0, "leak_as_2.8": 0}
    n = 0
    for spec in sample:
        k = (spec_hash(spec), spec.seed)
        if k not in old or k not in new:
            continue
        n += 1
        s28, l28 = same(new[k], old[k])
        res["2.9.0 record vs 2.8.x record"]["same_as_2.8"] += s28
        res["2.9.0 record vs 2.8.x record"]["leak_as_2.8"] += l28
        for v in variants:
            variant(v)
            r = json.loads(json.dumps(run_sim(spec), default=str))      # as recorded: tuples become lists
            a, la = same(r, old[k])
            b, _ = same(r, new[k])
            res[v]["same_as_2.8"] += a
            res[v]["leak_as_2.8"] += la
            res[v]["same_as_2.9"] += b
        print(n, k, flush=True)
    restore()
    L = ["# Which aligned store rule changes the recorded runs (seventh-round review, M1)", "",
         f"A stratified sample of {n} recorded runs (three per study, seed 20261003, at most 200 simulated minutes), replayed under each variant and "
         "compared with the 2.8.x record (`results/historical_2.8/`) and the 2.9.0 record. 'Identical' compares every recorded field "
         "except bookkeeping and the fields added in 2.9.0; 'same leakage' compares `attack.leaked_total`. The refresh-only "
         "measurement (the 2.8.x store with only the sorted-set TTL refreshed) is in `results/historical_2.8/store_expiry_check.md`: "
         "75 of 102 identical.", "",
         "| Variant | Identical to 2.8.x | Same leakage as 2.8.x | Identical to 2.9.0 |", "|---|---:|---:|---:|"]
    for v, c in res.items():
        L.append(f"| {v} | {c['same_as_2.8']} | {c['leak_as_2.8']} | {c.get('same_as_2.9', '–')} |")
    neutral = [v for v in variants[1:] if res[v]["same_as_2.9"] == n]
    if neutral:
        L += ["", f"Restoring the 2.8.x {' or the '.join(v.replace('2.9.0 but ', '') for v in neutral)} rule changes none of the {n} runs: "
              "the changes come from the other aligned rules, above all the sorted-set TTL refresh "
              "(`results/outage_mechanism_check.md` traces one run)."]
    (ROOT / "results" / "store_rule_ablation.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
