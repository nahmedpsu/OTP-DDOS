#!/usr/bin/env python3
"""Analyses for the fifth-round review, from the recorded 2.8.0 runs plus one new set of attack-free
runs. Nothing here changes a recorded result.

  A  (M1) Selection repeated under each objective on the E5 tuning runs, over every setting at the
     service target (not only the original shortlist): mean and worst-case leakage, a first-time-loss
     constraint, each attacker, 2,000 random attacker mixes. The original rule's tie-break (lower
     leakage, then higher completion) applies throughout. The union of winners is compared on the E5
     evaluation runs.
  B  (M6) Claims K1-K5 by attacker, from the recorded failing cells.
  C  (M2, M3) Attacked service at 200 shared blocks, side by side, from the E1 runs: leakage; loss
     against the attacked 'none' arm (all, first-time, returning, attacked-block users; gross lost
     and gained); and, from new attack-free runs on the same legitimate traces, degradation against
     attack-free operation under the same policy, and the benign cost against attack-free 'none'.
  D  (M5) The operating condition: the counter's leakage envelope q * B * w (q sends per block per
     window, B blocks, w windows touched; twice that for a pumper that solves challenges) against the
     sequential tests' estimate k * B + lambda * tau (Equation 1), checked on the E3/E4 runs; and the
     attack-free cost to a block's users against the share of its sends beyond the quota.

    python3 scripts/run_round5_analyses.py [--procs 2]

Writes results/round5_analyses.md and results/round5_analyses.json, and the new attack-free runs to
results/round5_attack_free_runs.jsonl.gz."""
import argparse
import gzip
import json
import math
import pathlib
import random
import statistics as st
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from otp_guard.evaluation import counter_study as C                                   # noqa: E402
from otp_guard.evaluation.jobs import JobRunner                                        # noqa: E402
from otp_guard.evaluation.provenance import environment                               # noqa: E402
from otp_guard.evaluation.runner import DEFAULT_SETTING, MATCHED, PUMPING_ATTACKERS, randomised  # noqa: E402
from otp_guard.evaluation.sim import unbits                                             # noqa: E402
from otp_guard.evaluation.stats import boot_ci                                          # noqa: E402

CARRIERS = ["concentrated_pumper_no_verify", "concentrated_pumper_verifies_instantly",
            "concentrated_pumper_verifies_humanlike", "concentrated_pumper_solves_challenges"]
SHORT = {"concentrated_pumper_no_verify": "NV", "concentrated_pumper_verifies_instantly": "IV",
         "concentrated_pumper_verifies_humanlike": "HL", "concentrated_pumper_solves_challenges": "CB", "block_poisoner": "poisoner"}


def load_runs(path, studies):
    out = []
    with gzip.open(path, "rt") as f:
        for line in f:
            r = json.loads(line)
            if r["study"] in studies:
                out.append(r)
    return out


def m(t, d=1):
    return None if t[0] is None else round(t[0], d)


def ci(t, d=2):
    return {"mean": t[0], "lo": t[1], "hi": t[2], "n": t[3]}


# ---------------------------------------------------------------- A: selection under each objective
def first_time_loss(pol_runs, none_runs):
    by = {r["spec"]["seed"]: r for r in none_runs}
    vals = []
    for r in pol_runs:
        ref = by[r["spec"]["seed"]]
        n = r["requests"]["n"]
        ret = unbits(r["requests"]["returning"])
        ft = set(range(n)) - ret
        cp, cr = unbits(r["requests"]["completed"]), unbits(ref["requests"]["completed"])
        vals.append(100.0 * (len((cr - cp) & ft) - len((cp - cr) & ft)) / max(len(ft), 1))
    return st.mean(vals)


def analysis_a(runs, n_draws=2000):
    leg, att = {}, {}
    for r in runs:
        kind, d, name, a, s = r["index"]
        if kind == "legit":
            leg.setdefault((d, name), []).append(r)
        else:
            att.setdefault((d, name, a), []).append(r["attack"]["leaked_total"])
    out = {}
    for d in sorted({k[0] for k in leg}):
        comp = {n: st.mean(r["friction"]["completed_pct"] for r in leg[(d, n)]) for n in MATCHED}
        target = comp[DEFAULT_SETTING] - 0.5
        elig = [n for n in MATCHED if comp[n] >= target]
        leak = {n: {a: st.mean(att[(d, n, a)]) for a in CARRIERS} for n in elig}
        ft = {n: first_time_loss(leg[(d, n)], leg[(d, "none")]) for n in elig}

        def pick(cands, f):
            return min(cands, key=lambda n: (round(f(n), 6), -comp[n]))     # the 2.7.0 rule's tie-break
        win = {"sum (original objective)": pick(elig, lambda n: sum(leak[n].values())),
               "worst case": pick(elig, lambda n: max(leak[n].values())),
               "sum, first-time loss <= 0.5 pp": pick([n for n in elig if ft[n] <= 0.5], lambda n: sum(leak[n].values()))}
        for a in CARRIERS:
            win[f"{SHORT[a]} alone"] = pick(elig, lambda n, a=a: leak[n][a])
        rng = random.Random(7)
        mixes = {}
        for _ in range(n_draws):
            w = [rng.expovariate(1.0) for _ in CARRIERS]
            t = sum(w)
            b = pick(elig, lambda n: sum(wi / t * leak[n][a] for wi, a in zip(w, CARRIERS)))
            mixes[b] = mixes.get(b, 0) + 1
        out[d] = {"settings": len(MATCHED), "eligible": len(elig), "target_pct": target, "winners": win,
                  "random_mix_wins": mixes, "union": sorted(set(win.values()) | set(mixes)),
                  "tuning_leakage": {n: leak[n] for n in sorted(set(win.values()) | set(mixes))},
                  "tuning_first_time_loss": {n: ft[n] for n in sorted(set(win.values()) | set(mixes))}}
    return out


def evaluation_in_union(sel, eval_runs):
    """Leakage, completion and the paired evaluation check for the union of winners, on fresh seeds."""
    att, leg = {}, {}
    for r in eval_runs:
        kind, d, name, x, s = r["index"]
        if kind == "attack":
            att.setdefault((d, name, x), []).append(r["attack"]["leaked_total"])
        else:
            leg.setdefault((d, name, x), {})[s] = r["friction"]["completed_pct"]
    out = {}
    for d, v in sel.items():
        rows = {}
        for n in v["union"]:
            if all((d, n, a) in att for a in CARRIERS):
                c65 = leg.get((d, n, 0.65), {})
                cells = [(s, conv) for conv in (0.65, 0.8) for s in leg.get((d, n, conv), {})]
                below = sum(1 for s, conv in cells if leg[(d, n, conv)][s] < leg[(d, DEFAULT_SETTING, conv)][s] - 0.5)
                rows[n] = {**{SHORT[a]: st.mean(att[(d, n, a)]) for a in CARRIERS},
                           "completion_65": st.mean(c65.values()) if c65 else None,
                           "margin_to_tuning_target": (st.mean(c65.values()) - v["target_pct"]) if c65 else None,
                           "paired_check_cells_below": [below, len(cells)]}
        out[d] = {"evaluated": rows, "not_evaluated": [n for n in v["union"] if n not in rows],
                  "best_per_attacker": {SHORT[a]: min(rows, key=lambda n: rows[n][SHORT[a]]) for a in CARRIERS} if rows else {}}
    return out


def missing_union_specs(sel, eval_runs):
    have = {(r["index"][1], r["index"][2]) for r in eval_runs}
    specs, index = [], []
    for d, v in sel.items():
        for n in v["union"]:
            if (d, n) not in have:
                sp, ix = C.study_e5_eval({d: {"chosen": {"union": n}}})
                specs += sp; index += ix
    return specs, index


# ---------------------------------------------------------------- B: claims by attacker
def analysis_b(e2):
    out = {}
    for k in ("K1", "K3", "K4", "K5"):
        c = e2["claims"][k]
        fails = {}
        for p, a, s in c["failing"]:
            fails[a] = fails.get(a, 0) + 1
        per = c["cells"] // len(CARRIERS)
        out[k] = {"pooled": [c["true"], c["cells"]], "by_attacker": {SHORT[a]: [per - fails.get(a, 0), per] for a in CARRIERS},
                  "failing_points": sorted({p for p, a, s in c["failing"]})}
    out["K2"] = {"pooled": [e2["claims"]["K2"]["true"], e2["claims"]["K2"]["cells"]], "by_attacker": "attack-free"}
    return out


# ---------------------------------------------------------------- C: attacked service, three questions
def attack_free_specs(densities, seeds):
    run = C.CP["experiments"]["E1_attacked_service"]["run"]
    specs, index = [], []
    for d in densities:
        for pol in C.e1_arms(d):
            for s in seeds:
                a = randomised(PUMPING_ATTACKERS["concentrated_pumper_no_verify"], s)
                specs.append(C._spec(pol, a, C._legit(d, run["conversion"]), run["attack_minutes"], run["warmup_minutes"], s,
                                     legit_only=True))
                index.append((d, pol, s))
    return specs, index


def paired(pol_run, ref_run, cohort_run):
    """Net completions lost in pol_run against ref_run (same legitimate trace), by cohort, in % of the cohort."""
    assert pol_run["legit_workload_digest"] == ref_run["legit_workload_digest"]
    n = pol_run["requests"]["n"]
    cp, cr = unbits(pol_run["requests"]["completed"]), unbits(ref_run["requests"]["completed"])
    ret = unbits(cohort_run["requests"]["returning"])
    groups = {"all": set(range(n)), "first_time": set(range(n)) - ret, "returning": ret,
              "attacked_block": unbits(cohort_run["requests"]["attacked_block"])}
    out = {}
    for g, ids in groups.items():
        lost, gained = len((cr - cp) & ids), len((cp - cr) & ids)
        out[g] = {"net_pct": 100.0 * (lost - gained) / len(ids) if ids else None, "lost": lost, "gained": gained, "users": len(ids)}
    return out


def analysis_c(e1_runs, free_runs, condition="200 shared"):
    free = {(d, pol, s): r for (d, pol, s), r in free_runs}
    att = {}
    for r in e1_runs:
        cond, a, pol, s = r["index"]
        if cond == condition:
            att[(a, pol, s)] = r
    density = C.E1_CONDITIONS[condition][0]
    out = {}
    for a in CARRIERS + ["block_poisoner"]:
        for pol in C.e1_arms(density):
            seeds = sorted(s for (aa, p, s) in att if aa == a and p == pol)
            if not seeds:
                continue
            leak = [att[(a, pol, s)]["attack"]["leaked_total"] for s in seeds]
            q = {"leaked": boot_ci(leak)}
            for label, ref_of in (("vs_attacked_none", lambda s: att[(a, "none", s)]),
                                  ("vs_attack_free_same_policy", lambda s: free[(density, pol, s)]),
                                  ("benign_cost", None)):
                rows = []
                for s in seeds:
                    if label == "benign_cost":
                        rows.append(paired(free[(density, pol, s)], free[(density, "none", s)], att[(a, pol, s)]))
                    else:
                        rows.append(paired(att[(a, pol, s)], ref_of(s), att[(a, pol, s)]))
                q[label] = {g: {"net_pct": boot_ci([x[g]["net_pct"] for x in rows if x[g]["net_pct"] is not None]),
                                "gross_lost": boot_ci([x[g]["lost"] for x in rows]),
                                "gross_gained": boot_ci([x[g]["gained"] for x in rows]),
                                "users": boot_ci([x[g]["users"] for x in rows])} for g in rows[0]}
            out.setdefault(SHORT[a], {})[pol] = q
    return out


# ---------------------------------------------------------------- D: the operating condition
def poisson_excess(mean, q):
    """E[(N - q)+] / mean for N ~ Poisson(mean): the share of a block's sends in a window beyond its quota."""
    if mean <= 0:
        return 0.0
    p, cdf_part, tail = math.exp(-mean), 0.0, 0.0
    e_min = 0.0                                    # E[min(N, q)]
    for n in range(0, q):
        e_min += n * p
        cdf_part += p
        p *= mean / (n + 1)
    e_min += q * (1 - cdf_part)
    return (mean - e_min) / mean


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--procs", type=int, default=2)
    ap.add_argument("--checkpoint", default=None)
    a = ap.parse_args()
    t0 = time.time()
    cs = json.loads((ROOT / "results" / "counter_study.json").read_text())
    runs = load_runs(ROOT / "results" / "counter_study_runs.jsonl.gz", {"E5_tuning", "E5_eval", "E1", "E3", "E4"})
    tuning = [r for r in runs if r["study"] == "E5_tuning"]
    evaluation = [r for r in runs if r["study"] == "E5_eval"]
    e1 = [r for r in runs if r["study"] == "E1"]
    sel = analysis_a(tuning)
    runner = JobRunner(a.procs, a.checkpoint, None, code_extra=("scripts/run_round5_analyses.py",))
    mspecs, mindex = missing_union_specs(sel, evaluation)          # winners the original shortlist did not contain
    mres = runner.run(mspecs)
    with gzip.open(ROOT / "results" / "round5_union_eval_runs.jsonl.gz", "wt") as f:
        for i, r in zip(mindex, mres):
            f.write(json.dumps(dict(r, index=list(i), code_hash=runner.code), default=str) + "\n")
    union_eval = evaluation_in_union(sel, evaluation + [dict(r, index=list(i)) for i, r in zip(mindex, mres)])
    claims = analysis_b(cs["E2"])

    # new attack-free runs on the E1 legitimate traces (same specs as E1, without the attacker)
    specs, index = attack_free_specs(["200", "1000", "uniform"], C.FRESH)
    free = runner.run(specs)
    with gzip.open(ROOT / "results" / "round5_attack_free_runs.jsonl.gz", "wt") as f:
        for i, r in zip(index, free):
            f.write(json.dumps(dict(r, index=list(i), code_hash=runner.code), default=str) + "\n")
    attacked = {c: analysis_c(e1, list(zip(index, free)), c) for c in ("200 shared", "200 independent")}

    # D: envelope against the measured security map (E4) and the service map
    q = 4
    grid = {}
    for key, v in cs["E4"]["security"].items():
        nb, kind, mins, pol = key.split("|")
        grid.setdefault((int(nb), kind, int(mins)), {})[pol] = v["leaked_total"][0]
    env = []
    for (nb, kind, mins), pols in sorted(grid.items()):
        w = mins // 10
        env.append({"blocks": nb, "pumper": kind, "minutes": mins, **pols,
                    "counter_envelope": min(pols["none"], q * nb * w), "sequential_estimate": 5 * nb + 95})
    service = []
    for rate in (0.5, 1, 2, 4, 8):
        service.append({"legit_per_window": rate, "share_beyond_quota": poisson_excess(rate, q),
                        "share_beyond_twice_quota": poisson_excess(rate, 2 * q)})
    out = {"meta": {"code_hash": runner.code, "environment": environment(), "new_runs": len(specs) + len(mspecs),
                    "new_attack_free_runs": len(specs), "new_union_eval_runs": len(mspecs), "wall_s": time.time() - t0},
           "A_selection": sel, "A_evaluation_in_union": union_eval, "B_claims_by_attacker": claims,
           "C_attacked_service": attacked, "D_security_map": env, "D_service_model": service}
    (ROOT / "results" / "round5_analyses.json").write_text(json.dumps(out, indent=1, default=str))
    write_md(out, ROOT / "results" / "round5_analyses.md")
    print(f"done in {time.time() - t0:.0f}s")


def write_md(o, path):
    L = ["# Fifth-round analyses", "",
         f"Generated by `scripts/run_round5_analyses.py` from the recorded 2.8.0 runs (`results/counter_study_runs.jsonl.gz`) "
         f"and {o['meta']['new_runs']} new runs ({o['meta']['new_attack_free_runs']} attack-free, `results/round5_attack_free_runs.jsonl.gz`; "
         f"{o['meta']['new_union_eval_runs']} evaluating winners outside the original shortlist, `results/round5_union_eval_runs.jsonl.gz`; code hash "
         f"`{o['meta']['code_hash'][:16]}...`; `results/reproduction_check.md` shows the current code reproduces recorded runs exactly). "
         "Means over ten seeds with 95 % percentile-bootstrap intervals where shown.", "",
         "## A. Selection repeated under each objective (M1)", "",
         "Every setting meeting the service target on the E5 tuning runs is a candidate (not only the original shortlist); "
         "each objective selects on tuning data, with the original rule's tie-break (lower leakage, then higher completion). "
         "The union of winners is then compared on the E5 evaluation runs (fresh seeds).", ""]
    for d, v in o["A_selection"].items():
        L.append(f"**Density {d}**: {v['eligible']} of {v['settings']} settings meet the target ({v['target_pct']:.2f} %).")
        L.append("")
        L.append("| Objective (tuning data) | Selected |")
        L.append("|---|---|")
        for obj, w in v["winners"].items():
            L.append(f"| {obj} | `{w}` |")
        L.append(f"| 2,000 random mixes | " + ", ".join(f"`{n}` {c}" for n, c in sorted(v["random_mix_wins"].items(), key=lambda x: -x[1])) + " |")
        ue = o["A_evaluation_in_union"][d]
        L.append("")
        L.append("Evaluation runs, leaked SMS (mean of ten seeds) for the union of winners:")
        L.append("")
        L.append("| Setting | NV | IV | HL | CB | Completion at 65 % | Margin to tuning target (pp) | Paired check: cells > 0.5 pp below default |")
        L.append("|---|---:|---:|---:|---:|---:|---:|---:|")
        for n, row in ue["evaluated"].items():
            L.append(f"| `{n}` | " + " | ".join(f"{row[x]:.1f}" for x in ("NV", "IV", "HL", "CB"))
                     + f" | {row['completion_65']:.2f} | {row['margin_to_tuning_target']:+.2f} | {row['paired_check_cells_below'][0]}/{row['paired_check_cells_below'][1]} |")
        if ue["not_evaluated"]:
            L.append(f"| not evaluated: {', '.join(ue['not_evaluated'])} | | | | |")
        L.append("")
    L += ["## B. Claims K1-K5 by attacker (M6)", "",
          "Cells true / cells. The 144 cells are 12 workload points x 3 seeds x 4 attackers; they are not independent samples.", "",
          "| Claim | Pooled | NV | IV | HL | CB | Points with a failing cell |", "|---|---:|---:|---:|---:|---:|---|"]
    for k, v in o["B_claims_by_attacker"].items():
        if k == "K2":
            L.append(f"| K2 | {v['pooled'][0]}/{v['pooled'][1]} | attack-free | | | | |")
            continue
        b = v["by_attacker"]
        L.append(f"| {k} | {v['pooled'][0]}/{v['pooled'][1]} | " + " | ".join(f"{b[x][0]}/{b[x][1]}" for x in ("NV", "IV", "HL", "CB"))
                 + f" | {', '.join(map(str, v['failing_points'])) or '-'} |")
    L += ["", "## C. Attacked service: three questions (M2, M3)", "",
          "60-minute attacks, 200 legitimate blocks, 65 % conversion, 70 % WhatsApp (E1 runs). For each policy: leakage; "
          "net completions lost against the attacked `none` arm on the same trace (extra harm relative to another attacked "
          "policy); against attack-free operation under the same policy (degradation the attack causes); and the attack-free "
          "cost against `none` (benign cost). Net loss in percentage points of the cohort (negative = gain); gross lost / gained "
          "in requests.", ""]
    for cond, block in o["C_attacked_service"].items():
        L.append(f"### {cond}")
        L.append("")
        L.append("| Attacker | Policy | Leaked | vs attacked none: all / first-time / attacked-block (gross lost/gained, all) | "
                 "vs attack-free, same policy: all / attacked-block | Benign cost: all |")
        L.append("|---|---|---:|---|---|---:|")
        for a, pols in block.items():
            for pol, q in pols.items():
                v1, v2, v3 = q["vs_attacked_none"], q["vs_attack_free_same_policy"], q["benign_cost"]
                f = lambda t: "–" if t[0] is None else f"{t[0]:+.2f}"
                L.append(f"| {a} | `{pol}` | {q['leaked'][0]:.0f} | {f(v1['all']['net_pct'])} / {f(v1['first_time']['net_pct'])} / "
                         f"{f(v1['attacked_block']['net_pct'])} ({v1['all']['gross_lost'][0]:.1f}/{v1['all']['gross_gained'][0]:.1f}) | "
                         f"{f(v2['all']['net_pct'])} / {f(v2['attacked_block']['net_pct'])} | {f(v3['all']['net_pct'])} |")
        L.append("")
    L += ["## D. Operating condition (M5)", "",
          "Security map (E4, leaked SMS, means): the counter's envelope is q x B x w with q = 4 sends per block per 10-minute "
          "window, B blocks and w windows (2 in 20 minutes, 6 in 60), capped by what the pumper sends; the sequential tests' "
          "estimate (Equation 1) is k x B + lambda x tau with k = 5.", "",
          "| Blocks, pumper, minutes | none | sequential default | counter | envelope q B w (capped by none) | k B + intercept |",
          "|---|---:|---:|---:|---:|---:|"]
    for row in o["D_security_map"]:
        L.append(f"| {row['blocks']}, {row['pumper']}, {row['minutes']} | {row['none']:.0f} | {row['sequential T1000 c1']:.0f} | "
                 f"{row['counter graded 4/10 min']:.0f} | {row['counter_envelope']:.0f} | {row['sequential_estimate']:.0f} |")
    L += ["", "Service model: share of a block's sends in a 10-minute window beyond the quota (Poisson arrivals at the stated "
          "mean), the requests a graded counter challenges (beyond q) or moves off SMS (beyond 2q):", "",
          "| Legitimate sends per block per window | Beyond q = 4 | Beyond 2q = 8 |", "|---:|---:|---:|"]
    for s in o["D_service_model"]:
        L.append(f"| {s['legit_per_window']} | {100 * s['share_beyond_quota']:.2f} % | {100 * s['share_beyond_twice_quota']:.3f} % |")
    path.write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
