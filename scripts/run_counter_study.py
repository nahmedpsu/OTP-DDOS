#!/usr/bin/env python3
"""The destination-counter study (config/counter_protocol.json), in two stages.

Stage 1 runs E1 (attacked service), E2 (held-out family, claims K1-K5), E3 (adaptive family),
E4 (operating boundary) and the tuning stage of E5 (density-complete selection). The selection rule
is then applied per density, and stage 2 evaluates the selected settings on fresh seeds.

    python3 scripts/run_counter_study.py [--procs 4] [--checkpoint FILE] [--quick]

Writes results/counter_study.md, counter_study.json, counter_study_runs.jsonl.gz,
counter_study_per_seed.csv and counter_study_specs.json. Deterministic.
"""
import argparse
import csv
import hashlib
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from otp_guard.evaluation import counter_study as C                                   # noqa: E402
from otp_guard.evaluation.calibration import value as cal                             # noqa: E402
from otp_guard.evaluation.jobs import JobRunner, spec_key, spec_hash                  # noqa: E402
from otp_guard.evaluation.provenance import environment                               # noqa: E402
from otp_guard.evaluation.runner import (DEFAULT_SETTING, DENSITIES, MATCHED_ATTACKERS, attacker_bill, attributable_loss,  # noqa: E402
                                         paired_difference, robustness_points, summarise, summarise_legit_only)
from otp_guard.evaluation.stats import boot_ci                                        # noqa: E402


def ci(t, d=1):
    m, lo, hi, n = t
    return "n/a" if m is None else f"{m:.{d}f} [{lo:.{d}f}, {hi:.{d}f}]"


def diff(t, d=1):
    m, lo, hi, n = t
    return "n/a" if m is None else f"{m:+.{d}f} [{lo:+.{d}f}, {hi:+.{d}f}]" + (" *" if (lo > 0 or hi < 0) else "")


def group(results, index, keyfn):
    g = {}
    for r, idx in zip(results, index):
        g.setdefault(keyfn(idx), []).append(r)
    return g


def loss_fields(al):
    """The attributable-loss summary used in the tables (percentage points of offered users)."""
    if not al:
        return None
    out = {k: al[k] for k in ("net_lost", "net_lost_pct", "gross_lost", "gross_gained", "n_pairs", "per_seed_net_lost_pct")}
    for g in ("first_time", "returning", "attacked_block", "hot_block", "after_stop"):
        if g in al:
            out[g] = al[g]
    return out


def breakeven(summ):
    leaked = summ["leaked_total"][0] or 0.0
    bill = attacker_bill(summ)["cost_usd"]
    return None if leaked <= 0 else bill / (leaked * cal("sms_unit_cost_usd"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--procs", type=int, default=None)
    ap.add_argument("--checkpoint", default=None)
    ap.add_argument("--reuse", default=None)
    ap.add_argument("--quick", action="store_true", help="two seeds, two held-out points, short legitimate runs: for CI")
    ap.add_argument("--out", default=str(ROOT / "results"))
    a = ap.parse_args()
    out = pathlib.Path(a.out); out.mkdir(exist_ok=True)
    runner = JobRunner(a.procs, a.checkpoint, a.reuse, code_extra=("scripts/run_counter_study.py",))
    seeds = C.FRESH[:2] if a.quick else C.FRESH
    day = 60 if a.quick else None
    pts = robustness_points()[:2] if a.quick else None

    jobs = []

    def add(study, specs, index):
        for s, i in zip(specs, index):
            jobs.append((study, i, s))
    add("E1", *C.study_e1(seeds))
    add("E2", *C.study_e2(pts, 1 if a.quick else 3))
    add("E3", *C.study_e3(seeds))
    sp, ix = C.study_e4()
    if a.quick:
        keep = [k for k, i in enumerate(ix) if i[-1] in seeds]
        sp, ix = [sp[k] for k in keep], [ix[k] for k in keep]
    add("E4", sp, ix)
    add("E5_tuning", *C.study_e5_tuning(C.CP["seeds"]["density_selection_tuning"][:1] if a.quick else None, day))
    print(f"stage 1: {len(jobs)} runs", flush=True)
    t0 = time.time()
    res = runner.run([j[2] for j in jobs])
    print(f"stage 1 done in {time.time() - t0:.0f}s", flush=True)
    by = {}
    for (study, idx, _), r in zip(jobs, res):
        by.setdefault(study, ([], []))
        by[study][0].append(r); by[study][1].append(idx)

    tuning = group(*by["E5_tuning"], lambda i: (i[0], i[1], i[2]))
    sel = C.select_e5(tuning)
    jobs2 = []
    sp, ix = C.study_e5_eval(sel, seeds, day)
    for s, i in zip(sp, ix):
        jobs2.append(("E5_eval", i, s))
    print(f"stage 2: {len(jobs2)} runs", flush=True)
    res2 = runner.run([j[2] for j in jobs2])
    wall = time.time() - t0
    by["E5_eval"] = (res2, [j[1] for j in jobs2])
    all_jobs, all_res = jobs + jobs2, res + res2
    runner.write_runs(out / "counter_study_runs.jsonl.gz", all_jobs, all_res)
    specs = {}
    for study, idx, spec in all_jobs:
        k = spec_hash(spec)
        if k not in specs:
            specs[k] = {"study": study, "spec": json.loads(spec_key(spec)), "seeds": []}
        specs[k]["seeds"].append(spec.seed)
    (out / "counter_study_specs.json").write_text(json.dumps(specs, indent=0, sort_keys=True))

    R = {"meta": {"runs": len(all_jobs), "wall_s": wall, "quick": a.quick, "seeds": seeds,
                  "protocol_sha256": hashlib.sha256(C.PROTOCOL_PATH.read_bytes()).hexdigest(),
                  "provenance": dict(runner.meta(), environment=environment())}}

    # ---- E1
    E1 = {}
    g = group(*by["E1"], lambda i: (i[0], i[1], i[2]))
    for (cond, aname, pol), rs in g.items():
        none = g[(cond, aname, "none")]
        d = summarise(rs)
        d["attributable_loss_vs_none"] = loss_fields(attributable_loss(rs, none)) if pol != "none" else None
        E1.setdefault(cond, {}).setdefault(aname, {})[pol] = d
    for cond, dd in E1.items():
        density = C.E1_CONDITIONS[cond][0]
        ref = C.DENSITY_COUNTER[density]
        for aname, pols in dd.items():
            rref = g[(cond, aname, ref)]
            for pol in pols:
                if pol != ref:
                    pols[pol]["paired_leak_vs_counter"] = paired_difference(g[(cond, aname, pol)], rref, ("attack", "leaked_total"))
    R["E1"] = E1

    # ---- E2
    cells = {i: r for r, i in zip(*by["E2"])}
    R["E2"] = {"claims": C.judge_e2(cells), "points": pts or robustness_points()}
    g2 = group(*by["E2"], lambda i: (i[0], i[2], i[3]))
    E2 = {}
    for (kind, aname, pol), rs in g2.items():
        none = g2[(kind, aname, "none")]
        d = summarise(rs) if kind == "attack" else summarise_legit_only(rs)
        d["attributable_loss_vs_none"] = loss_fields(attributable_loss(rs, none)) if pol != "none" else None
        E2.setdefault(kind, {}).setdefault(aname or "benign", {})[pol] = d
    R["E2"]["summary"] = E2

    # ---- E3
    E3 = {}
    g3 = group(*by["E3"], lambda i: (i[0], i[1]))
    for (name, pol), rs in g3.items():
        d = summarise(rs)
        d["attributable_loss_vs_none"] = loss_fields(attributable_loss(rs, g3[(name, "none")])) if pol != "none" else None
        if pol != C.PRINCIPAL:
            d["paired_leak_vs_counter"] = paired_difference(rs, g3[(name, C.PRINCIPAL)], ("attack", "leaked_total"))
        mins = rs[0]["spec"]["minutes"]
        d["leaked_per_hour"] = d["leaked_total"][0] * 60.0 / mins
        d["breakeven_share"] = breakeven(d)
        E3.setdefault(name, {})[pol] = d
    R["E3"] = E3

    # ---- E4
    E4 = {"service": {}, "stress": {}, "security": {}}
    g4 = group(*by["E4"], lambda i: i[:-1])
    for key, rs in g4.items():
        part = key[0]
        pol = key[-1]
        none = g4[key[:-1] + ("none",)]
        cond_attacked = part in ("service", "stress") and key[3] == "attacked"
        d = summarise(rs) if (part == "security" or cond_attacked) else summarise_legit_only(rs)
        d["attributable_loss_vs_none"] = loss_fields(attributable_loss(rs, none)) if pol != "none" and part != "security" else None
        E4[part]["|".join(str(x) for x in key[1:])] = d
    R["E4"] = E4

    # ---- E5
    E5 = {"selection": sel, "legit": {}, "attack": {}, "paired": {}, "preferences": {}, "violations": {}}
    g5 = group(*by["E5_eval"], lambda i: (i[0], i[1], i[2], i[3]))
    for (kind, density, name, x), rs in g5.items():
        if kind == "legit":
            d = summarise_legit_only(rs)
            none = g5[("legit", density, "none", x)]
            d["attributable_loss_vs_none"] = loss_fields(attributable_loss(rs, none)) if name != "none" else None
            dflt = g5[("legit", density, DEFAULT_SETTING, x)]
            d["completed_diff_vs_default"] = paired_difference(rs, dflt, ("friction", "completed_pct"))
            by_seed_def = {r["spec"]["seed"]: r["friction"]["completed_pct"] for r in dflt}
            viol = [r["friction"]["completed_pct"] < by_seed_def[r["spec"]["seed"]] - 0.5 for r in rs]
            d["cells_violating_paired_target"] = sum(viol)
            d["cells"] = len(viol)
            E5["legit"].setdefault(density, {}).setdefault(name, {})[str(x)] = d
        else:
            d = summarise(rs)
            none = g5[("attack", density, "none", x)]
            d["attributable_loss_vs_none"] = loss_fields(attributable_loss(rs, none)) if name != "none" else None
            d["paired_leak_vs_default"] = paired_difference(rs, g5[("attack", density, DEFAULT_SETTING, x)], ("attack", "leaked_total"))
            E5["attack"].setdefault(density, {}).setdefault(name, {})[x] = d
    for density in sel:
        names = sorted(set(sel[density]["chosen"].values()))
        leak = {n: {x: E5["attack"][density][n][x]["leaked_total"][0] for x in MATCHED_ATTACKERS} for n in names}
        ftl = {n: (E5["legit"][density][n]["0.65"]["attributable_loss_vs_none"] or {}).get("first_time", {}).get("net_lost_pct_of_group", (0.0,))[0]
               for n in names}
        E5["preferences"][density] = C.preferences(leak, None, ftl)
        tgt = sel[density]["service_target_completion_pct"]
        E5["violations"][density] = {n: {"evaluation_completion_65": E5["legit"][density][n]["0.65"]["legit_completed_pct"],
                                          "margin_to_tuning_target_pp": E5["legit"][density][n]["0.65"]["legit_completed_pct"][0] - tgt,
                                          "cells_violating_paired_target": sum(E5["legit"][density][n][c]["cells_violating_paired_target"] for c in E5["legit"][density][n]),
                                          "cells": sum(E5["legit"][density][n][c]["cells"] for c in E5["legit"][density][n])}
                                     for n in names}
    R["E5"] = E5

    (out / "counter_study.json").write_text(json.dumps(R, indent=1, default=str))
    write_per_seed_csv(by, out / "counter_study_per_seed.csv")
    write_markdown(R, out / "counter_study.md")
    print(f"wrote {out / 'counter_study.md'}", flush=True)


def write_per_seed_csv(by, path):
    """M11: per-seed outcomes of the central comparisons (E1 and the E5 evaluation)."""
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["study", "condition_or_density", "attacker_or_conversion", "policy", "seed", "leaked", "attack_requests",
                    "legit_users", "legit_completed_pct", "first_time_completed_pct", "returning_completed_pct", "challenged_pct"])
        for study in ("E1", "E5_eval"):
            for r, i in zip(*by[study]):
                if study == "E1":
                    cond, x, pol, seed = i
                else:
                    kind, cond, pol, x, seed = i
                fr = r["friction"]
                w.writerow([study, cond, x, pol, seed, r["attack"]["leaked_total"], r["attack"]["requests"], fr["users"],
                            round(fr["completed_pct"], 4), round(fr["first_time"]["completed_pct"], 4),
                            round(fr["returning"]["completed_pct"], 4), round(fr["challenge_rate_pct"], 4)])


def _loss(d, key="net_lost_pct", group=None, digits=2):
    al = d.get("attributable_loss_vs_none")
    if not al:
        return "–"
    if group:
        g = al.get(group)
        return diff(g["net_lost_pct_of_group"], digits) if g else "–"
    return diff(al[key], digits)


def write_markdown(R, path):
    meta = R["meta"]
    pv = meta["provenance"]
    L = ["# Destination-counter study", "",
         f"Generated by `scripts/run_counter_study.py` under `config/counter_protocol.json` (SHA-256 `{meta['protocol_sha256'][:16]}...`, "
         f"committed before these runs): {meta['runs']} simulation runs, {meta['wall_s']:.0f} s wall time, "
         + ("a clean invocation" if pv["invocation"] == "clean" else f"{pv['resumed']} runs resumed from this invocation's checkpoint and "
            f"{pv['reused']} reused, all produced by the same code")
         + f"; code hash `{pv['code_hash'][:16]}...`. Fresh seeds {meta['seeds'][0]}-{meta['seeds'][-1]}; held-out family seeds 6000 + 100 x point + k "
         "(six of them, 6000-6002 and 6100-6102, were also the main evaluation's robustness seeds for points 10 and 11, contrary to the "
         "protocol's seed note; see the erratum in CHANGELOG.md). "
         "Means with 95 % percentile-bootstrap intervals over seeds; paired differences are bootstrapped per seed and marked * when the "
         "interval excludes zero. *Attributable loss* is net completions lost because of the policy, per request against `none` on the "
         "same offered trace, in percentage points of offered users (positive = lost); *gross* counts are lost and gained separately. "
         "Intervals describe variation under this generator, not uncertainty about real traffic. The simulation is single-threaded, so "
         "the concurrency fix of 2.8.0 does not change these numbers; the deployed counter now enforces the same policy under concurrency "
         "(tests/unit/test_fourth_round.py, tests/integration/test_real_redis.py).", ""]

    # ---------------- E2 claims first
    L += ["## Claims K1-K5 on the held-out family (E2)", "",
          f"The principal counter (`{C.PRINCIPAL}`) on the 12 shifted operating points of `config/evaluation_protocol.json` with held-out "
          "attack rates and pools, the pumper on 3 blocks that real users also use, 200 legitimate blocks. A claim holds if true in at "
          "least 90 % of its cells.", "",
          "| Claim | Cells | True | Share | Holds | Failing cells (point, attacker, seed) |", "|---|---:|---:|---:|---|---|"]
    for k, v in R["E2"]["claims"].items():
        fails = ", ".join(str(tuple(c)) for c in v["failing"][:12]) + (" ..." if len(v["failing"]) > 12 else "")
        L.append(f"| {k} | {v['cells']} | {v['true']} | {v['share']:.2f} | {'yes' if v['holds'] else 'no'} | {fails or '–'} |")
    L += ["", "Claim texts: `config/counter_protocol.json`. Means over the family:", "",
          "| Policy | " + " | ".join(f"Leaked: `{x}`" for x in MATCHED_ATTACKERS) + " | Attributable loss under attack (pp, mean over pumpers) | Benign attributable loss (pp) |",
          "|---|" + "---:|" * (len(MATCHED_ATTACKERS) + 2)]
    E2 = R["E2"]["summary"]
    for pol in C.E2["arms"]:
        cellsL = [ci(E2["attack"][x][pol]["leaked_total"], 0) for x in MATCHED_ATTACKERS]
        losses = [E2["attack"][x][pol]["attributable_loss_vs_none"]["net_lost_pct"][0] for x in MATCHED_ATTACKERS] if pol != "none" else None
        row = f"| `{pol}` | " + " | ".join(cellsL) + " | "
        row += f"{sum(losses) / len(losses):+.2f} | " if losses else "– | "
        L.append(row + f"{_loss(E2['benign']['benign'][pol])} |")
    L.append("")

    # ---------------- E1
    L += ["## E1. Leakage and service on the same attacked trace", "",
          "60-minute attacks after a 30-minute warm-up, legitimate traffic at 65 % conversion and 70 % WhatsApp reachability (stable per "
          "number). *Shared*: the pumper's 3 blocks are blocks real users use; *independent*: other blocks. Leakage and service come from "
          "the same runs. *Attacked-block users*: real users whose number is in a block the attacker requested. The 2.7.0 service target "
          "(default completion minus 0.5 pp on benign tuning runs) is a benign target; the losses here are measured under attack.", ""]
    for cond, dd in R["E1"].items():
        density = C.E1_CONDITIONS[cond][0]
        arms = C.e1_arms(density)
        atts = [x for x in C.E1_ATTACKERS if x in dd]
        L += [f"### {cond}", "", "Leaked SMS (paired difference to the density's counter):", "",
              "| Policy | " + " | ".join(f"`{x}`" for x in atts) + " |", "|---|" + "---:|" * len(atts)]
        for pol in arms:
            row = []
            for x in atts:
                d = dd[x][pol]
                row.append(ci(d["leaked_total"], 0) + (f" ({diff(d['paired_leak_vs_counter'], 0)})" if "paired_leak_vs_counter" in d else ""))
            L.append(f"| `{pol}` | " + " | ".join(row) + " |")
        L += ["", "Attributable loss under attack, pp of offered users (all users / first-time / returning / attacked-block users):", "",
              "| Policy | " + " | ".join(f"`{x}`" for x in atts) + " |", "|---|" + "---:|" * len(atts)]
        for pol in arms[1:]:
            row = []
            for x in atts:
                d = dd[x][pol]
                row.append(f"{_loss(d)} / {_loss(d, group='first_time')} / {_loss(d, group='returning')} / {_loss(d, group='attacked_block')}")
            L.append(f"| `{pol}` | " + " | ".join(row) + " |")
        L.append("")

    # ---------------- E3
    L += ["## E3. The adaptive family against the counter", "",
          "Caps lifted, 200 legitimate blocks at 65 % conversion. Total leaked SMS, and for long attacks the sustained rate and the "
          "break-even revenue share (scenario accounting: retail price, event-level bill, preparation and contracts excluded, so a lower "
          "bound conditional on those assumptions).", "",
          "| Attacker | " + " | ".join(f"`{p}`" for p in C.E3_ARMS) + " |", "|---|" + "---:|" * len(C.E3_ARMS)]
    for name, pols in R["E3"].items():
        L.append(f"| {name} | " + " | ".join(ci(pols[p]["leaked_total"], 0) for p in C.E3_ARMS) + " |")
    L += ["", "Codes entered by the attacker, legitimate completion, and for 360-minute attacks leaked SMS per hour / break-even share:", "",
          "| Attacker | Policy | Codes entered | Legit completed % | Attributable loss (pp) | Per hour | Break-even share |", "|---|---|---:|---:|---:|---:|---:|"]
    for name, pols in R["E3"].items():
        for p in C.E3_ARMS:
            d = pols[p]
            be = d["breakeven_share"]
            L.append(f"| {name} | `{p}` | {ci(d['attacker_verifications'], 0)} | {ci(d['legit_completed_pct'])} | {_loss(d)} | "
                     f"{d['leaked_per_hour']:.0f} | {'–' if be is None else f'{be:.3f}'} |")
    L.append("")

    # ---------------- E4
    sm = C.E4["service_map"]
    L += ["## E4. Operating boundary", "",
          f"*Service map.* {sm['hot_blocks']} hot blocks receive the stated legitimate rate; the rest of the legitimate traffic is "
          "uniform. *Attacked*: a pumper that never verifies uses the hot blocks. Attributable loss against `none` on the same trace, in pp "
          "of all offered users and (in brackets) of the hot blocks' users. The counter's quota is 4 sends per 10 minutes per block.", "",
          "| Legit rate per hot block (per 10 min) | WhatsApp | Condition | " + " | ".join(f"`{p}`" for p in C.E4_ARMS[1:]) + " | Hot-block users |",
          "|---:|---:|---|" + "---:|" * len(C.E4_ARMS[1:]) + "---:|"]
    for key, d in R["E4"]["service"].items():
        r, wa, cond, pol = key.split("|")
        if pol != C.E4_ARMS[1]:
            continue
        cellsS = []
        for p in C.E4_ARMS[1:]:
            dd = R["E4"]["service"][f"{r}|{wa}|{cond}|{p}"]
            cellsS.append(f"{_loss(dd)} ({_loss(dd, group='hot_block')})")
        hb = d["attributable_loss_vs_none"].get("hot_block", {}).get("users", (None,))[0] if d["attributable_loss_vs_none"] else None
        L.append(f"| {r} | {float(wa):.0%} | {cond} | " + " | ".join(cellsS) + f" | {'–' if hb is None else f'{hb:.0f}'} |")
    L += ["", "*Stress rows* (1 legitimate send per hot block per 10 minutes, 70 % WhatsApp):", "",
          "| Stress | Condition | " + " | ".join(f"`{p}`" for p in C.E4_ARMS[1:]) + " |", "|---|---|" + "---:|" * len(C.E4_ARMS[1:])]
    for key, d in R["E4"]["stress"].items():
        sname, _, cond, pol = key.split("|")
        if pol != C.E4_ARMS[1]:
            continue
        L.append(f"| {sname} | {cond} | " + " | ".join(f"{_loss(R['E4']['stress'][f'{sname}|None|{cond}|{p}'])} "
                                                         f"({_loss(R['E4']['stress'][f'{sname}|None|{cond}|{p}'], group='hot_block')})"
                                                         for p in C.E4_ARMS[1:]) + " |")
    L += ["", "*Security map.* A pumper spreading over B blocks (never verifies), or quota-aware (at most 4 sends per block per 10 "
          "minutes, the counter's own quota), uniform legitimate traffic. Leaked SMS:", "",
          "| Blocks | Pumper | Attack (min) | " + " | ".join(f"`{p}`" for p in C.E4_ARMS) + " |", "|---:|---|---:|" + "---:|" * len(C.E4_ARMS)]
    seen = set()
    for key in R["E4"]["security"]:
        nb, kind, mins, pol = key.split("|")
        if (nb, kind, mins) in seen:
            continue
        seen.add((nb, kind, mins))
        L.append(f"| {nb} | {kind} | {mins} | " + " | ".join(ci(R['E4']['security'][f'{nb}|{kind}|{mins}|{p}']['leaked_total'], 0) for p in C.E4_ARMS) + " |")
    L.append("")

    # ---------------- E5
    E5 = R["E5"]
    L += ["## E5. The selection rule at every density, with density-specific attack runs", "",
          "The 2.7.0 rule (`config/evaluation_protocol.json`) with the full sequential grid at every density and attack runs whose "
          "legitimate background is at that density; selected on tuning seeds 100-102, evaluated on the fresh seeds. The aggregate score "
          "(leakage summed over four scripted pumpers) is a declared experimental score, not a utility: the preference table shows how the "
          "choice changes under worst-case leakage, a first-time-user loss constraint, single attackers and random attacker mixes.", ""]
    for density, s in E5["selection"].items():
        L += [f"### Density {density}", "", f"Service target {s['service_target_completion_pct']:.2f} % (default {s['default_completion_pct']:.2f} % "
              "on the tuning seeds). Selected: " + "; ".join(f"{k}: `{v}`" for k, v in s["chosen"].items()), "",
              "| Setting | Completed % (65 %) | Margin to target (pp) | Cells below default - 0.5 pp (of seed x conversion) | "
              "Attributable loss, benign (pp): all / first-time / returning | " + " | ".join(f"Leaked `{x}` (vs default)" for x in MATCHED_ATTACKERS)
              + " | Attributable loss under attack (pp, mean over pumpers) |", "|---|---:|---:|---:|---:|" + "---:|" * (len(MATCHED_ATTACKERS) + 1)]
        for name, v in E5["violations"][density].items():
            lg = E5["legit"][density][name]["0.65"]
            att = E5["attack"][density][name]
            losses = [att[x]["attributable_loss_vs_none"]["net_lost_pct"][0] for x in MATCHED_ATTACKERS] if name != "none" else None
            L.append(f"| `{name}` | {ci(v['evaluation_completion_65'], 2)} | {v['margin_to_tuning_target_pp']:+.2f} | "
                     f"{v['cells_violating_paired_target']}/{v['cells']} | {_loss(lg)} / {_loss(lg, group='first_time')} / {_loss(lg, group='returning')} | "
                     + " | ".join(f"{ci(att[x]['leaked_total'], 0)} ({diff(att[x]['paired_leak_vs_default'], 0)})" for x in MATCHED_ATTACKERS)
                     + (f" | {sum(losses) / len(losses):+.2f} |" if losses else " | – |"))
        p = E5["preferences"][density]
        L += ["", f"Preferred (lowest) under mean leakage: `{p['mean_leakage']}`; worst-case leakage: `{p['worst_case_leakage']}`; mean "
              f"leakage with first-time-user loss at most 0.5 pp: `{p['mean_leakage_with_first_time_loss_at_most_0.5pp']}`; per attacker: "
              + "; ".join(f"`{x}`: `{w}`" for x, w in p["single_attacker"].items()) + ". Share of random attacker mixes won: "
              + "; ".join(f"`{k}` {v:.2f}" for k, v in sorted(p["random_mix_win_share"].items(), key=lambda kv: -kv[1]) if v > 0) + ".", ""]
    L += ["Per-seed outcomes of E1 and E5: `results/counter_study_per_seed.csv`. Every configuration: `results/counter_study_specs.json`.", ""]
    path.write_text("\n".join(L))


if __name__ == "__main__":
    main()
