#!/usr/bin/env python3
"""The leakage estimates of Section 5 evaluated on the E4 boundary runs from inputs that are not
fitted to them, with the counter's bound checked against its own assumptions (sixth-round review, M1,
M2; seventh-round review, M2, M3).

For every E4 security run (results/counter_study_runs.jsonl.gz), on the run's own inputs:
  N        attack requests offered in the attack window,
  B        destination blocks the pumper requested,
  lambda   N / attack minutes (the offered rate, which also covers the quota-paced pumper),
  T        attack minutes (20 or 60), w = ceil(T / 10) windows of 10 minutes,
  state    for each block, the destination counter's count c and the seconds left in its window when
           the pumper's first attack request reached it (block_state_at_first_attack, recorded by
           the simulator since 2.9.0; legitimate warm-up traffic may have opened a window).
Estimates of the SMS sent to the pumper's numbers over the attack window:
  sequential tests (Equation 2)  min(N, k B + lambda tau), k = 5, tau = (120 + 3 + 30) s from the
                                 configuration (otp_guard.evaluation.model.predicted_leak);
  counter, cold start (Eq. 3)    min(N, q B w): every block's counter empty when the pumper arrives;
  counter, warm start (Eq. 4)   min(N, q B w + sum over blocks with an open window of (q - c)+):
                                 a block's open window adds at most its residual quota, after which
                                 at most ceil((T - remaining) / 10) <= w windows open during the attack;
  counter, any state             min(N, q B w + B (q - 1)): a window opened by a legitimate send has
                                 used a slot, so at most q - 1 remain (the conservative form).
A bound is checked on every counter run (measured <= bound). The ordering check compares the tests'
estimate with the counter's cold and warm estimates, per cell (means over the five seeds) and per
seed (seeds pair the two policies' workloads); a comparison is decisive when the two estimates differ
by 0.5 messages or more. Paired differences (tests minus counter, measured) carry 95% percentile-
bootstrap intervals over the five seeds. Writes results/condition_check.md and .json."""
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
from otp_guard.evaluation.stats import boot_ci                           # noqa: E402

Q, WINDOW_MIN = 4, 10
TESTS, COUNTER, NONE = "sequential T1000 c1", "counter graded 4/10 min", "none"


def counter_bounds(N, B, mins, state):
    w = math.ceil(mins / WINDOW_MIN)
    residual = sum(max(0, Q - c) for c, left in state if left is None or left > 0)
    open_blocks = sum(1 for c, left in state if left is None or left > 0)
    return {"cold": min(N, Q * B * w), "warm": min(N, Q * B * w + residual), "any": min(N, Q * B * w + B * (Q - 1)),
            "open_blocks": open_blocks, "residual": residual}


def load(path):
    cfg = Config()
    runs = {}
    with gzip.open(path, "rt") as f:
        for line in f:
            r = json.loads(line)
            if r.get("study") != "E4" or r["index"][0] != "security":
                continue
            _, nb, kind, mins, pol, seed = r["index"]
            N, B = r["attack"]["requests"], r["attacker_blocks_requested"]
            e = {"seed": seed, "leaked": r["attack"]["leaked_total"], "exempt": r.get("attacker_sms_exempt", 0),
                 "N": N, "B": B, "lambda": N / mins,
                 "tests_estimate": predicted_leak(cfg, B, N / mins, N, False)}
            if pol == COUNTER:
                e.update(counter_bounds(N, B, mins, r["block_state_at_first_attack"]))
            runs.setdefault((nb, kind, mins), {}).setdefault(pol, {})[seed] = e
    return cfg, runs


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=str(ROOT / "results" / "counter_study_runs.jsonl.gz"))
    ap.add_argument("--out", default=str(ROOT / "results"))
    a = ap.parse_args()
    cfg, runs = load(a.runs)
    k, _ = sends_to_verdict(cfg)
    m = lambda xs, key: statistics.fmean(x[key] for x in xs)                      # noqa: E731
    cells, seed_rows = [], []
    counter_runs = [e for pols in runs.values() for e in pols[COUNTER].values()]
    over = {b: [] for b in ("cold", "warm", "any")}
    for (nb, kind, mins), pols in sorted(runs.items()):
        for e in pols[COUNTER].values():
            for b in over:          # exempt sends (verified history) are outside every form of the bound
                if e["leaked"] - e["exempt"] > e[b]:
                    over[b].append({"blocks": nb, "pumper": kind, "minutes": mins, "seed": e["seed"], "leaked": e["leaked"],
                                    "exempt": e["exempt"], "bound": e[b], "open_blocks": e["open_blocks"], "B": e["B"]})
        seq, cnt = pols[TESTS], pols[COUNTER]
        seeds = sorted(set(seq) & set(cnt))
        diffs = [seq[s]["leaked"] - cnt[s]["leaked"] for s in seeds]
        d = boot_ci(diffs)
        c = {"blocks": nb, "pumper": kind, "minutes": mins, "seeds": len(seeds),
             "lambda_tau": m(seq.values(), "lambda") * (cfg.resolution_timeout_s + 3 + 30) / 60,
             "tests_estimate": m(seq.values(), "tests_estimate"), "tests_measured": m(seq.values(), "leaked"),
             "counter_cold": m(cnt.values(), "cold"), "counter_warm": m(cnt.values(), "warm"), "counter_any": m(cnt.values(), "any"),
             "open_blocks": m(cnt.values(), "open_blocks"), "B": m(cnt.values(), "B"),
             "counter_measured": m(cnt.values(), "leaked"), "none_measured": m(pols[NONE].values(), "leaked"),
             "paired_diff": d[0], "paired_lo": d[1], "paired_hi": d[2],
             "measured_counter_less": m(cnt.values(), "leaked") < m(seq.values(), "leaked")}
        for b in ("cold", "warm"):
            tie = abs(c[f"counter_{b}"] - c["tests_estimate"]) < 0.5
            c[f"pred_{b}"] = None if tie else c[f"counter_{b}"] < c["tests_estimate"]
        cells.append(c)
        for s in seeds:
            row = {"blocks": nb, "pumper": kind, "minutes": mins, "seed": s, "tests_estimate": seq[s]["tests_estimate"],
                   "tests_measured": seq[s]["leaked"], "counter_measured": cnt[s]["leaked"]}
            for b in ("cold", "warm"):
                row[f"counter_{b}"] = cnt[s][b]
                tie = abs(cnt[s][b] - seq[s]["tests_estimate"]) < 0.5
                row[f"pred_{b}"] = None if tie else cnt[s][b] < seq[s]["tests_estimate"]
            seed_rows.append(row)

    def agreement(rows, b, measured_key):
        dec = [r for r in rows if r[f"pred_{b}"] is not None]
        bad = [r for r in dec if r[f"pred_{b}"] != (r["counter_measured"] < r["tests_measured"] if measured_key == "seed"
                                                     else r["measured_counter_less"])]
        return len(dec), bad
    summary = {}
    for b in ("cold", "warm"):
        nd, bad = agreement(cells, b, "cell")
        ns, sbad = agreement(seed_rows, b, "seed")
        summary[b] = {"cells": len(cells), "cells_decisive": nd, "cells_disagree": len(bad),
                      "seeds": len(seed_rows), "seeds_decisive": ns, "seeds_disagree": len(sbad),
                      "seed_disagreements": sbad}
    cold_only = [e for e in counter_runs if e["open_blocks"] == 0]
    exempt_runs = [e for e in counter_runs if e["exempt"]]
    out = {"k": k, "q": Q, "window_min": WINDOW_MIN, "tau_s": cfg.resolution_timeout_s + 3 + 30,
           "counter_runs": len(counter_runs), "runs_all_blocks_cold": len(cold_only),
           "runs_over_bound": {b: len(v) for b, v in over.items()}, "over_bound": over,
           "cold_start_runs_over_eq3": sum(1 for e in cold_only if e["leaked"] - e["exempt"] > e["cold"]),
           "runs_with_exempt_sends": len(exempt_runs), "exempt_sends": sum(e["exempt"] for e in counter_runs),
           "summary": summary, "cells": cells}

    L = ["# Leakage estimates and the counter's bound on the E4 runs (seventh-round review, M2, M3)", "",
         f"k = {k}; tau = {out['tau_s']} s; q = {Q} per {WINDOW_MIN} minutes; per run: N offered requests, B blocks requested, "
         "lambda = N / attack minutes, and each block's counter state at the pumper's first attack request. "
         "Five seeds (300-304) per cell. Nothing is fitted to E4 leakage.", "",
         "## The counter's bound on every counter run", "",
         f"{len(counter_runs)} counter runs; in {len(cold_only)} every block was empty when the pumper arrived (cold start), "
         f"and {out['cold_start_runs_over_eq3']} of those exceed Equation 3. In {len(exempt_runs)} runs the pumper drew "
         f"{out['exempt_sends']} SMS in all as a client with verified history (a real user's trusted number inside its block), "
         "which no form of the bound covers; they are subtracted before the comparison. "
         f"Runs over the bound: cold-start form (Eq. 3) {len(over['cold'])}, warm-start form with each block's residual "
         f"quota (Eq. 4) {len(over['warm'])}, state-free form q B w + B (q - 1) {len(over['any'])}.", ""]
    if over["cold"]:
        L += ["Runs over the cold-start form (every one has blocks with a window already open):", "",
              "| Blocks | Pumper | Minutes | Seed | Leaked | Exempt | Cold bound | Blocks with an open window |", "|---:|---|---:|---:|---:|---:|---:|---:|"]
        L += [f"| {v['blocks']} | {v['pumper']} | {v['minutes']} | {v['seed']} | {v['leaked']} | {v['exempt']} | {v['bound']} | {v['open_blocks']} of {v['B']} |"
              for v in over["cold"]]
        L.append("")
    L += ["## Ordering", ""]
    for b, name in (("cold", "cold-start counter estimate (Eq. 3)"), ("warm", "warm-start counter estimate (Eq. 4)")):
        s = summary[b]
        L.append(f"- With the {name}: the predicted ordering matches the measured one in {s['cells_decisive'] - s['cells_disagree']} "
                 f"of {s['cells_decisive']} decisive cell-mean comparisons ({s['cells'] - s['cells_decisive']} ties), and in "
                 f"{s['seeds_decisive'] - s['seeds_disagree']} of {s['seeds_decisive']} decisive seed-level comparisons.")
    L.append("")
    for b in ("cold", "warm"):
        for r in summary[b]["seed_disagreements"]:
            L.append(f"  - {b}: {r['blocks']} blocks, {r['pumper']}, {r['minutes']} min, seed {r['seed']}: estimates "
                     f"{r['tests_estimate']:.1f} (tests) against {r[f'counter_{b}']:.0f} (counter); measured {r['tests_measured']} against {r['counter_measured']}.")
    L += ["", "| Blocks | Pumper | Min | lambda tau | Tests est. | Tests meas. | Counter cold | Counter warm | Open blocks | Counter meas. | None | Tests - counter, paired [95% CI] | Counter less: cold / warm / measured |",
          "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|"]
    yn = lambda v: "tie" if v is None else "yes" if v else "no"                     # noqa: E731
    for c in cells:
        L.append(f"| {c['blocks']} | {c['pumper']} | {c['minutes']} | {c['lambda_tau']:.0f} | {c['tests_estimate']:.0f} | {c['tests_measured']:.1f} | "
                 f"{c['counter_cold']:.0f} | {c['counter_warm']:.1f} | {c['open_blocks']:.1f} of {c['B']:.0f} | {c['counter_measured']:.1f} | {c['none_measured']:.0f} | "
                 f"{c['paired_diff']:.1f} [{c['paired_lo']:.1f}, {c['paired_hi']:.1f}] | {yn(c['pred_cold'])} / {yn(c['pred_warm'])} / {yn(c['measured_counter_less'])} |")
    pathlib.Path(a.out, "condition_check.md").write_text("\n".join(L) + "\n")
    pathlib.Path(a.out, "condition_check.json").write_text(json.dumps(out, indent=1))
    print("\n".join(L[:20]))


if __name__ == "__main__":
    main()
