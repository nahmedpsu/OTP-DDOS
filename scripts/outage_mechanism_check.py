#!/usr/bin/env python3
"""Seventh-round review, M1: why the E5 sequential winners' leakage against the instant verifier fell
(2.8.x 49 and 50, 2.9.0 15 and 16). Replays one recorded E5 evaluation run (200 blocks, sequential
T300 c0, instant verifier, seed 301) on the 2.9.0 store and on the 2.9.0 store with only the 2.8.x
sorted-set rule restored (the TTL set by the first write and never refreshed), and prints every outage
alert with the counts the detector saw. Writes results/outage_mechanism_check.md. The library is unchanged."""
import gzip
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import check_reproduction as CR                                  # noqa: E402
from otp_guard import services as SV                             # noqa: E402
from otp_guard import store as S                                 # noqa: E402
from otp_guard.evaluation.jobs import spec_hash                  # noqa: E402
from otp_guard.evaluation.sim import run_sim                     # noqa: E402

WANT = ["attack", "200", "sequential T300 c0", "concentrated_pumper_verifies_instantly", 301]


def record(path):
    with gzip.open(path, "rt") as f:
        for line in f:
            d = json.loads(line)
            if d["study"] == "E5_eval" and d["index"] == WANT:
                return d


def zadd_28(self, key, score, member, ttl=None):          # 2.8.x: the TTL is set by the first write only
    ttl = S._ttl_s(ttl)
    with self.lock:
        v = self._live(key)
        if v is None:
            self._put(key, {member: score}, ttl=ttl)
        else:
            v[0][member] = score


def main():
    new, old = record(ROOT / "results" / "counter_study_runs.jsonl.gz"), record(ROOT / "results" / "historical_2.8" / "counter_study_runs.jsonl.gz")
    spec = next(s for _, s in CR.counter_jobs() if spec_hash(s) == new["spec_hash"] and s.seed == new["spec"]["seed"])
    got, orig, released = [], SV.AlertSink.alert, S.MemoryStore.zadd

    def capture(self, msg, detail=None):
        got.append((msg, dict(detail) if isinstance(detail, dict) else detail))
        return orig(self, msg, detail)
    SV.AlertSink.alert = capture
    L = ["# Why the sequential tests' leakage against the instant verifier fell (seventh-round review, M1)", "",
         f"One E5 evaluation run ({', '.join(map(str, WANT[1:]))}), replayed by `scripts/outage_mechanism_check.py`. "
         f"Recorded leakage: 2.8.x {old['attack']['leaked_total']}, 2.9.0 {new['attack']['leaked_total']}.", "",
         "| Store | Leaked | Outage alerts | Counts the detector saw at each alert |", "|---|---:|---:|---|"]
    try:
        for name in ("2.9.0", "2.9.0 with the 2.8.x sorted-set TTL (first write only)"):
            S.MemoryStore.zadd = released if name == "2.9.0" else zadd_28
            got.clear()
            r = run_sim(spec)
            seen = "; ".join(("conversion collapse: " if "conversion" in m else "delivery collapse: ") +
                             ", ".join(f"{k} {d.get(k)}" for k in ("blocks", "kg_verified", "kg_failed", "delivered", "undelivered"))
                             for m, d in got if "outage" in m) or "none"
            L.append(f"| {name} | {r['attack']['leaked_total']} | {r['outage_alerts']} | {seen} |")
    finally:
        S.MemoryStore.zadd, SV.AlertSink.alert = released, orig
    L += ["", "With the TTL set by the first write, the set of known-good verifications on the carrier emptied while "
          "failures written later were kept, so the detector saw conversion collapse across many blocks, inferred a carrier "
          "outage and suspended the block tests for its hold time; the pumper's requests went through meanwhile."]
    (ROOT / "results" / "outage_mechanism_check.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
