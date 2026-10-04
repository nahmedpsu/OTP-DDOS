#!/usr/bin/env python3
"""Sixth-round review (M1, M2, the closing question): the operating condition of Section 5 evaluated
from inputs that were not fitted to the E4 security map, and compared with it.

For every recorded E4 security run (results/counter_study_runs.jsonl.gz), on the run's own inputs:
  N        attack requests offered in the attack window (recorded),
  B        destination blocks the attacker requested (recorded),
  lambda   N / attack minutes (the offered rate, which also covers the quota-paced pumper),
  T        attack minutes (20 or 60), w = ceil(T / 10) counter windows of 10 minutes,
the two estimates of total SMS to the attacker's numbers over the attack window are
  sequential tests (Equation 2): min(N, k B + lambda tau), k = 5, tau = resolution timeout + delivery
           delay + half the timeout worker's period = (120 + 3 + 30) s, from the configuration
           (otp_guard.evaluation.model.predicted_leak; nothing is fitted to E4);
  counter  (Equation 3, s = 0):    min(N, q B w), q = 4.
The tests' estimate is leakage to the first verdict; it is a campaign total only while the attacker,
once judged, stays contained for the rest of the window (true here: T <= the one-hour verdict, the
never-verifying pumper solves no challenge, and nothing it does buys an exemption).
Writes results/condition_check.md and .json."""
import gzip
import json
import math
import pathlib
import statistics
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from otp_guard.config import Config                                      # noqa: E402
from otp_guard.evaluation.model import predicted_leak, sends_to_verdict  # noqa: E402

Q, WINDOW_MIN = 4, 10


def main():
    cfg = Config()
    k, _ = sends_to_verdict(cfg)
    rows = {}
    with gzip.open(ROOT / "results" / "counter_study_runs.jsonl.gz", "rt") as f:
        for line in f:
            r = json.loads(line)
            if r.get("study") != "E4" or r["index"][0] != "security":
                continue
            _, nb, kind, mins, pol, seed = r["index"]
            N, B = r["attack"]["requests"], r["attacker_blocks_requested"]
            lam = N / mins
            w = math.ceil(mins / WINDOW_MIN)
            rows.setdefault((nb, kind, mins), {}).setdefault(pol, []).append({
                "leaked": r["attack"]["leaked_total"], "N": N, "B": B, "lambda": lam,
                "tests_estimate": predicted_leak(cfg, B, lam * 1.0, N, False),
                "counter_bound": min(N, Q * B * w)})
    out, lines = [], []
    for (nb, kind, mins), pols in sorted(rows.items()):
        seq, cnt = pols["sequential T1000 c1"], pols["counter graded 4/10 min"]
        m = lambda xs, key: statistics.fmean(x[key] for x in xs)
        e = {"blocks": nb, "pumper": kind, "minutes": mins,
             "lambda_tau": m(seq, "lambda") * (cfg.resolution_timeout_s + 3 + 30) / 60,
             "tests_measured": m(seq, "leaked"), "tests_estimate": m(seq, "tests_estimate"),
             "counter_measured": m(cnt, "leaked"), "counter_bound": m(cnt, "counter_bound"),
             "none_measured": m(pols["none"], "leaked")}
        e["tie"] = abs(e["counter_bound"] - e["tests_estimate"]) < 0.5          # both estimates at N: no prediction
        e["predicted_counter_less"] = None if e["tie"] else e["counter_bound"] < e["tests_estimate"]
        e["measured_counter_less"] = e["counter_measured"] < e["tests_measured"]
        out.append(e)
    decisive = [e for e in out if not e["tie"]]
    agree = sum(e["predicted_counter_less"] == e["measured_counter_less"] for e in decisive)
    L = ["# Operating condition from unfitted inputs (sixth-round review, M1, M2)", "",
         f"k = {k}; tau = {cfg.resolution_timeout_s} + 3 + 30 s; q = {Q} per {WINDOW_MIN} minutes; lambda = offered requests / attack minutes, "
         "per run; N = offered requests, per run. Means over five seeds (300-304). Nothing below is fitted to E4.", "",
         f"In the {len(decisive)} cells where the two estimates differ, the predicted ordering (counter bound below the tests' "
         f"estimate) matches the measured ordering in {agree}; in the other {len(out) - len(decisive)} both estimates equal N "
         "and no ordering is predicted.", "",
         "| Blocks | Pumper | Minutes | lambda tau | Tests: estimate | Tests: measured | Counter: bound | Counter: measured | No policy | Counter less: predicted / measured |",
         "|---:|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for e in out:
        L.append(f"| {e['blocks']} | {e['pumper']} | {e['minutes']} | {e['lambda_tau']:.0f} | {e['tests_estimate']:.0f} | {e['tests_measured']:.0f} | "
                 f"{e['counter_bound']:.0f} | {e['counter_measured']:.0f} | {e['none_measured']:.0f} | "
                 f"{'tie' if e['tie'] else 'yes' if e['predicted_counter_less'] else 'no'} / {'yes' if e['measured_counter_less'] else 'no'} |")
    (ROOT / "results" / "condition_check.md").write_text("\n".join(L) + "\n")
    (ROOT / "results" / "condition_check.json").write_text(json.dumps({"k": k, "q": Q, "cells": out, "decisive": len(decisive), "agree": agree}, indent=1))
    print("\n".join(L))


if __name__ == "__main__":
    main()
