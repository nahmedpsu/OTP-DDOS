#!/usr/bin/env python3
"""Full evaluation, in two stages.

Stage 1 runs every study that does not depend on another's outcome, together with the tuning
stage of the predeclared matched comparison (config/evaluation_protocol.json). The protocol's
selection rules are then applied to the tuning results, and stage 2 runs the selected settings on
the evaluation seeds, which the selection never saw.

    python3 scripts/run_evaluation.py [--seeds 30] [--sweep-seeds 10] [--procs 4] [--quick]

Writes results/evaluation.md, results/evaluation.json, results/evaluation_runs.jsonl.gz,
results/study_specs.json, results/attacker_profiles.md and results/tradeoff.png|svg,
results/pumper_spread.png|svg. Deterministic for a given seed set.
"""
import argparse
import gzip
import hashlib
import json
import multiprocessing as mp
import pathlib
import sys
import time
from dataclasses import asdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from otp_guard.config import ALL_FEATURES, Config                                          # noqa: E402
from otp_guard.evaluation import runner as R_                                                 # noqa: E402
from otp_guard.evaluation.calibration import CALIBRATION, legit_fast_share                  # noqa: E402
from otp_guard.evaluation.model import sends_to_verdict, evasion_share, predicted_leak, blocks_touched   # noqa: E402
from otp_guard.evaluation.runner import (ATTACKERS, ADAPTIVE_ATTACKERS, PUMPING_ATTACKERS, MODES, DESIGNS,   # noqa: E402
                                         summarise, summarise_legit_only, paired_difference, attributable_loss, economics,
                                         attacker_bill, ECON_SHARES, ECON_PRICE_MULTIPLES)
from otp_guard.evaluation.sim import run_sim                                                 # noqa: E402
from otp_guard.evaluation.stats import boot_ci, mean_ci                                      # noqa: E402

PALETTE = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7"]


def ci(t, d=1):
    """Mean [lo, hi] from a (mean, lo, hi, n) summary (percentile bootstrap: inside the data range)."""
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


def _job(spec):
    return run_sim(spec)


REUSE = {}
REUSED = [0, 0.0]      # runs taken from --reuse, wall time of the invocation that produced them


def spec_key(spec):
    d = asdict(spec)
    d.pop("seed")
    d["features"] = sorted(d["features"])
    return json.dumps(d, sort_keys=True, default=str)


def spec_hash(spec):
    return hashlib.sha1(spec_key(spec).encode()).hexdigest()[:12]


def load_reuse(path):
    out = {}
    prior = pathlib.Path(path).with_name("evaluation.json")
    if prior.exists():
        REUSED[1] = json.loads(prior.read_text())["meta"].get("wall_s", 0.0)
    with gzip.open(path, "rt") as f:
        for line in f:
            r = json.loads(line)
            key = (r.pop("spec_hash"), r["spec"]["seed"])
            r.pop("study", None); r.pop("index", None)
            out[key] = r
    return out


def run_jobs(specs, procs):
    """Longest runs first (24-hour runs dominate), results returned in the input order. Runs whose
    spec and seed match a row of --reuse are taken from it."""
    res = [None] * len(specs)
    todo = []
    for i, sp in enumerate(specs):
        hit = REUSE.get((spec_hash(sp), sp.seed))
        if hit is not None:
            res[i] = hit
        else:
            todo.append(i)
    if REUSE:
        REUSED[0] += len(specs) - len(todo)
        print(f"  reused {len(specs) - len(todo)}, running {len(todo)}", flush=True)
    order = sorted(todo, key=lambda i: -(specs[i].minutes + specs[i].warmup_minutes + 60 * 24 * 7 * specs[i].profile_weeks / 60))
    with mp.Pool(procs or mp.cpu_count()) as pool:
        out = pool.map(_job, [specs[i] for i in order], chunksize=1)
    for i, r in zip(order, out):
        res[i] = r
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=30)
    ap.add_argument("--sweep-seeds", type=int, default=10)
    ap.add_argument("--procs", type=int, default=None)
    ap.add_argument("--quick", action="store_true", help="few seeds, short legitimate runs: for CI")
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--reuse", default=None, help="an earlier evaluation_runs.jsonl.gz: runs with an identical spec (same "
                    "spec_hash and seed) are taken from it instead of rerun; the simulation is deterministic, so this only saves time")
    a = ap.parse_args()
    global REUSE
    REUSE = load_reuse(a.reuse) if a.reuse else {}
    out = pathlib.Path(a.out); out.mkdir(exist_ok=True)
    seeds = list(range(3 if a.quick else a.seeds))
    sseeds = list(range(2 if a.quick else a.sweep_seeds))
    day = 60 if a.quick else 24 * 60
    tuning_seeds = R_.TUNING_SEEDS[:1] if a.quick else R_.TUNING_SEEDS
    eval_seeds = R_.EVAL_SEEDS[:2] if a.quick else R_.EVAL_SEEDS

    # ---- stage 1 ----
    jobs = []

    def add(study, specs, index):
        for s, i in zip(specs, index):
            jobs.append((study, i, s))
    for design, feats in DESIGNS.items():
        add(design, *R_.study_multi_seed(seeds, feats, design=design))
    add("variance", *R_.study_variance(seeds))
    add("cadence", *R_.study_cadence(sseeds))
    add("ablation", *R_.study_ablation(sseeds))
    add("sweep", *R_.study_sweep(sseeds))
    add("capsweep", *R_.study_cap_sweep(sseeds))
    add("adaptive", *R_.study_adaptive(sseeds))
    add("poisoner", *R_.study_poisoner(sseeds))
    add("alternatives", *R_.study_alternatives(sseeds))
    add("alternatives_fp", *R_.study_alternatives_fp(list(range(2 if a.quick else 5)), minutes=day))
    add("baseline", *R_.study_baseline(sseeds))
    add("pumping", *R_.study_pumping(sseeds))
    add("long_attack", *R_.study_long_attack(sseeds))
    add("spread", *R_.study_spread(sseeds))
    add("dilution", *R_.study_dilution(list(range(2 if a.quick else 5))))
    add("legit24h", *R_.study_legit_only_24h(list(range(2 if a.quick else 5)), minutes=day))
    add("outage", *R_.study_outage(list(range(2 if a.quick else 8))))
    add("fallback", *R_.study_fallback(list(range(2 if a.quick else 5)), minutes=day))
    if not a.quick:
        add("robustness", *R_.study_robustness())
    add("matched_tuning", *R_.study_matched_tuning(tuning_seeds, legit_minutes=day))
    print(f"stage 1: {len(jobs)} runs on {a.procs or 'all'} processes", flush=True)
    t0 = time.time()
    results = run_jobs([j[2] for j in jobs], a.procs)
    print(f"stage 1 done in {time.time() - t0:.0f}s", flush=True)

    by = {}
    for (study, idx, _), r in zip(jobs, results):
        by.setdefault(study, ([], []))
        by[study][0].append(r); by[study][1].append(idx)

    # ---- selection, then stage 2 ----
    tuning = {}
    for r, (kind, density, name, x, s) in zip(*by["matched_tuning"]):
        key = ("legit", density, name) if kind == "legit" else ("attack", name, x)
        tuning.setdefault(key, []).append(r)
    selection, evaluate = R_.select_matched(tuning)
    jobs2 = []
    specs2, index2 = R_.study_matched_eval(evaluate, eval_seeds, legit_minutes=day)
    for s, i in zip(specs2, index2):
        jobs2.append(("matched_eval", i, s))
    print(f"stage 2: {len(jobs2)} runs", flush=True)
    t1 = time.time()
    results2 = run_jobs([j[2] for j in jobs2], a.procs)
    wall = time.time() - t0
    print(f"stage 2 done in {time.time() - t1:.0f}s; total {wall:.0f}s", flush=True)
    all_jobs = jobs + jobs2
    all_results = results + results2
    by["matched_eval"] = (results2, [j[1] for j in jobs2])

    with gzip.open(out / "evaluation_runs.jsonl.gz", "wt") as f:
        for (study, idx, spec), r in zip(all_jobs, all_results):
            r = dict(r); r["study"] = study; r["index"] = idx
            r["spec_hash"] = spec_hash(spec)
            f.write(json.dumps(r, default=str) + "\n")
    write_study_specs(all_jobs, out / "study_specs.json")
    write_attacker_profiles(out / "attacker_profiles.md")

    cfg_default = Config()
    cfg_default.sprt_legit_fast = max(0.005, legit_fast_share(cfg_default.fast_verify_seconds))   # as the sim sets it
    k_conv, k_fast = sends_to_verdict(cfg_default)
    protocol_sha = hashlib.sha256(R_.PROTOCOL_PATH.read_bytes()).hexdigest()
    R = {"meta": {"seeds": len(seeds), "sweep_seeds": len(sseeds), "runs": len(all_jobs), "wall_s": wall + (REUSED[1] if REUSED[0] else 0.0),
                  "reused_runs": REUSED[0],
                  "calibration": CALIBRATION, "quick": a.quick, "protocol_sha256": protocol_sha,
                  "tuning_seeds": tuning_seeds, "evaluation_seeds": eval_seeds, "legit_day_minutes": day,
                  "intervals": "95 % percentile bootstrap over runs (2000 resamples); paired differences likewise",
                  "model": {"k_conv": k_conv, "k_fast": k_fast, "evasion_share": evasion_share(cfg_default),
                            "sprt_legit_fast": cfg_default.sprt_legit_fast}}}

    # A. multi-seed, every design, two modes
    A = {}
    for design in DESIGNS:
        g = group(*by[design], lambda i: (i[0], i[1]))
        for (mode, name), rs in g.items():
            A.setdefault(mode, {}).setdefault(name, {})[design] = summarise(rs)
    R["multi_seed"] = A
    V = {}
    g = group(*by["variance"], lambda i: (i[0], i[1]))
    for (name, kind), rs in g.items():
        V.setdefault(name, {})[kind] = summarise(rs)
    R["variance"] = V

    # B. ablation with paired differences for every layer
    B = {}
    g = group(*by["ablation"], lambda i: (i[0], i[1]))
    for (name, flag), rs in g.items():
        B.setdefault(name, {})[flag] = summarise(rs)
    for name in B:
        full = [r for r, i in zip(*by["ablation"]) if i[0] == name and i[1] == "full"]
        for flag in B[name]:
            if flag == "full":
                continue
            rs = [r for r, i in zip(*by["ablation"]) if i[0] == name and i[1] == flag]
            B[name][flag]["paired_leak_diff"] = paired_difference(rs, full, ("attack", "leaked_total"))
            B[name][flag]["paired_completed_diff"] = paired_difference(rs, full, ("friction", "completed_pct"))
            B[name][flag]["paired_delivered_diff"] = paired_difference(rs, full, ("friction", "delivered_pct"))
    R["ablation"] = B

    Cd = {}
    g = group(*by["cadence"], lambda i: (i[0], i[1], i[2], i[3]))
    for (name, cname, pname, mins), rs in g.items():
        Cd.setdefault(name, {})[f"{cname}|{pname}|{mins}"] = summarise(rs)
    R["cadence"] = Cd

    Bj = {}
    g = group(*by["baseline"], lambda i: (i[0], i[1]))
    for (name, vname), rs in g.items():
        Bj.setdefault(name, {})[vname] = summarise(rs)
    for name in Bj:
        ref = [r for r, i in zip(*by["baseline"]) if i[0] == name and i[1] == R_.BASELINE_REFERENCE]
        for vname in Bj[name]:
            rs = [r for r, i in zip(*by["baseline"]) if i[0] == name and i[1] == vname]
            Bj[name][vname]["paired_vs_reference"] = {
                "leaked_total": paired_difference(rs, ref, ("attack", "leaked_total")),
                "legit_completed_pct": paired_difference(rs, ref, ("friction", "completed_pct")),
                "first_time_refusal_rate_pct": paired_difference(rs, ref, ("friction", "first_time", "refusal_rate_pct"))}
    R["baseline_job"] = Bj

    C = {}
    g = group(*by["sweep"], lambda i: (i[0], i[1], i[2]))
    for (name, axis, val), rs in g.items():
        C.setdefault(name, {}).setdefault(axis, {})[str(val)] = summarise(rs)
    R["weight_sweep"] = C
    Ccap = {}
    g = group(*by["capsweep"], lambda i: (i[0], i[1], i[2]))
    for (name, floor, mult), rs in g.items():
        Ccap.setdefault(name, {})[f"floor={floor},mult={mult}"] = summarise(rs)
    R["cap_sweep"] = Ccap

    D = {}
    g = group(*by["adaptive"], lambda i: (i[0], i[1]))
    for (mode, name), rs in g.items():
        D.setdefault(mode, {})[name] = summarise(rs)
    R["adaptive_attackers"] = D

    Po = {}
    g = group(*by["poisoner"], lambda i: i[0])
    for vname, rs in g.items():
        Po[vname] = summarise(rs)
        ref = R_.poisoner_reference(vname)
        if ref is not None:
            Po[vname]["attributable_loss_vs_observe"] = attributable_loss(rs, g[ref])
            Po[vname]["observe_reference"] = ref
    R["poisoner"] = Po

    Al = {}
    g = group(*by["alternatives"], lambda i: (i[0], i[1], i[2]))
    for (mode, aname, vname), rs in g.items():
        Al.setdefault(mode, {}).setdefault(aname, {})[vname] = summarise(rs)
    for mode in Al:
        for aname in Al[mode]:
            ref = [r for r, i in zip(*by["alternatives"]) if i[:3] == (mode, aname, "default")]
            for vname in Al[mode][aname]:
                rs = [r for r, i in zip(*by["alternatives"]) if i[:3] == (mode, aname, vname)]
                Al[mode][aname][vname]["paired_leak_vs_default"] = paired_difference(rs, ref, ("attack", "leaked_total"))
    g = group(*by["alternatives_fp"], lambda i: i[0])
    R["alternatives"] = {"attack": Al, "legit": {v: summarise_legit_only(rs) for v, rs in g.items()}}

    F = {}
    g = group(*by["pumping"], lambda i: (i[0], i[1]))
    for (aname, vname), rs in g.items():
        F.setdefault(aname, {})[vname] = summarise(rs)
    R["pumping"] = F
    g = group(*by["long_attack"], lambda i: i[0])
    R["long_attack"] = {aname: summarise(rs) for aname, rs in g.items()}

    # F2. matched comparison
    M = {"selection": selection, "evaluate": evaluate, "legit": {}, "attack": {}, "paired": {}}
    g = group(*by["matched_eval"], lambda i: i[:4])
    for (kind, density, name, x), rs in g.items():
        if kind == "legit":
            M["legit"].setdefault(density, {}).setdefault(name, {})[str(x)] = summarise_legit_only(rs)
        else:
            M["attack"].setdefault(name, {})[x] = summarise(rs)
    for density, names in evaluate.items():
        for conv in R_.MC["legitimate_runs"]["conversion_evaluation"]:
            sel = lambda nm: [r for r, i in zip(*by["matched_eval"]) if i[0] == "legit" and i[1] == density and i[2] == nm and i[3] == conv]
            none, default = sel("none"), sel(R_.DEFAULT_SETTING)
            for name in names:
                rs = sel(name)
                M["paired"].setdefault(density, {}).setdefault(name, {})[str(conv)] = {
                    "attributable_loss_vs_none": attributable_loss(rs, none) if name != "none" else None,
                    "completed_diff_vs_default": paired_difference(rs, default, ("friction", "completed_pct")),
                    "challenge_diff_vs_default": paired_difference(rs, default, ("friction", "challenge_rate_pct"))}
    for name in M["attack"]:
        ref = {x: [r for r, i in zip(*by["matched_eval"]) if i[0] == "attack" and i[2] == R_.DEFAULT_SETTING and i[3] == x] for x in R_.MATCHED_ATTACKERS}
        for x in M["attack"][name]:
            rs = [r for r, i in zip(*by["matched_eval"]) if i[0] == "attack" and i[2] == name and i[3] == x]
            M["attack"][name][x]["paired_leak_vs_default"] = paired_difference(rs, ref[x], ("attack", "leaked_total"))
    R["matched"] = M

    # G. spread with per-run residuals, dilution
    G = {}
    g = group(*by["spread"], lambda i: (i[0], i[1], i[2]))
    for (verify, nb, digits), rs in g.items():
        k = f"verify={verify},blocks={nb},digits={digits}"
        G[k] = summarise(rs)
        G[k]["predicted"] = boot_ci([predicted_leak(cfg_default, r["attacker_blocks_requested"], r["spec"]["attacker"]["rate_per_min"],
                                                    r["attack"]["requests"], verify > 0) for r in rs])
        G[k]["blocks_nominal"] = blocks_touched(nb, digits)
        res = []
        for r in rs:
            pred = predicted_leak(cfg_default, r["attacker_blocks_requested"], r["spec"]["attacker"]["rate_per_min"], r["attack"]["requests"], verify > 0)
            res.append((pred - r["attack"]["leaked_total"], pred >= r["attack"]["requests"] - 0.5, r["attack"]["leaked_total"]))
        unsat = [d for d, sat, _ in res if not sat]
        G[k]["residuals"] = {
            "mean": sum(d for d, _, _ in res) / len(res), "max_abs": max(abs(d) for d, _, _ in res),
            "n_saturated": sum(1 for _, sat, _ in res if sat), "n": len(res),
            "unsaturated_mean_abs": (sum(abs(d) for d in unsat) / len(unsat)) if unsat else None,
            "unsaturated_mean_rel_pct": (100 * sum(abs(d) / max(m, 1) for d, sat, m in res if not sat) / len(unsat)) if unsat else None,
            "per_run": [round(d, 1) for d, _, _ in res]}
    R["spread"] = G
    g = group(*by["dilution"], lambda i: i[0])
    R["dilution"] = {str(m): summarise(rs) for m, rs in g.items()}

    # H. false positives, outage, fallback
    H = {"monte_carlo": {f"{n},{p},{f}": v for (n, p, f), v in
                         R_.block_test_false_positives(cfg_default, trials=2_000 if a.quick else 20_000).items()}}
    g = group(*by["legit24h"], lambda i: (i[0], i[1], i[2], i[3]))
    H["legit_only"] = {f"calib={cal_},blocks={b},conv={c},autofill={af}": summarise_legit_only(rs) for (cal_, b, c, af), rs in g.items()}
    H["legit_only_seeds"] = len({i[4] for i in by["legit24h"][1]})
    g = group(*by["outage"], lambda i: (i[0], i[1]))
    H["outage"] = {f"{kind}|{v}": summarise_legit_only(rs) for (kind, v), rs in g.items()}
    g = group(*by["fallback"], lambda i: (i[0], i[1]))
    H["fallback"] = {f"{name}|{w}": summarise_legit_only(rs) for (name, w), rs in g.items()}
    R["false_positives"] = H

    # E. economics
    E = {}
    for mode in MODES:
        for name, att in ATTACKERS.items():
            E.setdefault(mode, {})[name] = economics(A[mode][name]["v1"], A[mode][name]["v2"], name, att.earns_revenue)
    for name, att in PUMPING_ATTACKERS.items():
        if att.earns_revenue:
            E.setdefault("pumping_study", {})[name] = economics(F[name]["v1"], F[name]["fine_key_plus_fast_resolution (default)"], name, True)
    R["economics"] = E

    # Robustness (predeclared claims)
    if "robustness" in by:
        cells = {i: r for r, i in zip(*by["robustness"])}
        R["robustness"] = R_.judge_robustness(cells)
        g = group(*by["robustness"], lambda i: (i[0], i[1]))
        R["robustness"]["by_point"] = {f"{p}|{sc}": (summarise_legit_only(rs) if rs[0]["spec"]["attacker"]["name"] == "naive_single_client"
                                                     and sc in ("no_attack", "legit_6h_200_blocks") else summarise(rs))
                                       for (p, sc), rs in g.items()}

    (out / "evaluation.json").write_text(json.dumps(R, indent=1, default=str) + "\n")
    write_tradeoff_chart(R, out)
    write_spread_chart(R, out)
    write_markdown(R, out / "evaluation.md")
    print("wrote", out / "evaluation.md")


def write_study_specs(jobs, path):
    """Table-to-run specification: every distinct configuration (all fields but the seed) per study,
    with its hash (the spec_hash of its rows in evaluation_runs.jsonl.gz) and seeds."""
    studies = {}
    for study, idx, spec in jobs:
        k = spec_key(spec)
        h = hashlib.sha1(k.encode()).hexdigest()[:12]
        entry = studies.setdefault(study, {}).setdefault(h, {"spec": json.loads(k), "seeds": [], "index_examples": []})
        entry["seeds"].append(spec.seed)
        if len(entry["index_examples"]) < 1:
            entry["index_examples"].append(list(idx) if isinstance(idx, tuple) else idx)
    path.write_text(json.dumps(studies, indent=1, default=str) + "\n")


def write_attacker_profiles(path):
    """Every attacker profile the evaluation runs, machine-readable name first, with its parameters."""
    L = ["# Attacker profiles", "",
         "Every profile run by `scripts/run_evaluation.py`, by catalogue. Per-seed randomisation (`runner.randomised`) varies the "
         "pool size, the rate and the CAPTCHA class within the profile's allowed classes; the robustness study draws rates and pools "
         "from the held-out ranges in `config/evaluation_protocol.json`.", ""]
    fields = ["network", "fp_mode", "numbers", "n_blocks", "verify_fraction", "verify_delay_s", "verify_policy", "solves_challenges",
              "platform_spoof", "trust_building_minutes", "fake_failed_receipts", "earns_revenue", "captcha_classes"]
    n = 0
    for cat, profiles in (("ATTACKERS (main study)", ATTACKERS), ("ADAPTIVE_ATTACKERS", ADAPTIVE_ATTACKERS),
                          ("PUMPING_ATTACKERS", {k: v for k, v in PUMPING_ATTACKERS.items() if k not in ATTACKERS})):
        L += [f"## {cat}", "", "| Profile | " + " | ".join(fields) + " | Description |", "|---|" + "---|" * (len(fields) + 1)]
        for name, a in profiles.items():
            d = asdict(a)
            L.append(f"| `{name}` | " + " | ".join(str(d[f]) for f in fields) + f" | {a.description} |")
            n += 1
        L.append("")
    L += [f"{n} named profiles. The spread sweep adds 18 generated `spread_<ranges>x<digits>` pumpers and the dilution study "
          "runs `residential_captcha_farm` at five rate multiples."]
    path.write_text("\n".join(L) + "\n")


def friction_of(s):
    return s["legit_refusal_rate_pct"][0] + s["legit_challenge_rate_pct"][0]


def write_tradeoff_chart(R, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.6), dpi=150, sharey=True)
    fig.patch.set_facecolor("#fcfcfb")
    series = [("Cap floor x base multiple", R["cap_sweep"]["residential_captcha_farm"]),
              ("Tier boundary scale", R["weight_sweep"]["residential_captcha_farm"]["tier_scale"]),
              ("Fresh-fingerprint weight", R["weight_sweep"]["residential_captcha_farm"]["fresh_fp_weight"]),
              ("Conversion weight", R["weight_sweep"]["residential_captcha_farm"]["conversion_weight"])]
    for ax, metric, xl in ((axes[0], "legit_refusal_rate_pct", "legitimate requests refused (%)"),
                           (axes[1], "legit_challenge_rate_pct", "legitimate requests challenged (%)")):
        ax.set_facecolor("#fcfcfb")
        for i, (label, pts) in enumerate(series):
            ax.scatter([s[metric][0] for s in pts.values()], [s["steady_state_leak_per_min"][0] for s in pts.values()], s=40,
                       color=PALETTE[i], label=label, edgecolors="#fcfcfb", linewidths=1.2, zorder=3)
        ax.set_xlabel(xl, color="#0b0b0b")
        ax.grid(True, color="#e6e5e0", linewidth=0.8); ax.set_axisbelow(True)
        for sp in ("top", "right"): ax.spines[sp].set_visible(False)
        for sp in ("left", "bottom"): ax.spines[sp].set_color("#c3c2b7")
        ax.tick_params(colors="#52514e")
    axes[0].set_ylabel("attacker late-window leakage (SMS / min)", color="#0b0b0b")
    axes[0].legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "tradeoff.png"); fig.savefig(out / "tradeoff.svg")
    plt.close(fig)


def write_spread_chart(R, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.4), dpi=150, sharey=True)
    fig.patch.set_facecolor("#fcfcfb")
    for ax, verify, title in ((axes[0], 0.0, "carrier does not verify"), (axes[1], 1.0, "carrier verifies within 1 s")):
        ax.set_facecolor("#fcfcfb")
        for i, digits in enumerate(R_.SPREAD_RANGE_DIGITS):
            xs, ys, lo, hi = [], [], [], []
            for nb in R_.SPREAD_BLOCKS:
                s = R["spread"][f"verify={verify},blocks={nb},digits={digits}"]
                xs.append(nb * 10 ** (12 - digits)); m, l, h_, _ = s["leaked_total"]; ys.append(m); lo.append(l); hi.append(h_)
            ax.plot(xs, ys, color=PALETTE[i], linewidth=2, marker="o", markersize=5, label=f"ranges of {R_.SPREAD_RANGE_DIGITS[digits]} numbers")
            ax.fill_between(xs, lo, hi, color=PALETTE[i], alpha=0.15, linewidth=0)
        ax.set_xscale("log"); ax.set_title(title, loc="left", color="#0b0b0b", fontsize=10)
        ax.set_xlabel("distinct destination numbers the pumper spreads over", color="#0b0b0b")
        ax.grid(True, color="#e6e5e0", linewidth=0.8); ax.set_axisbelow(True)
        for sp in ("top", "right"): ax.spines[sp].set_visible(False)
        for sp in ("left", "bottom"): ax.spines[sp].set_color("#c3c2b7")
        ax.tick_params(colors="#52514e")
    axes[0].set_ylabel("SMS leaked in 20 minutes", color="#0b0b0b")
    axes[0].legend(frameon=False, fontsize=8, loc="upper left")
    fig.tight_layout()
    fig.savefig(out / "pumper_spread.png"); fig.savefig(out / "pumper_spread.svg"); plt.close(fig)


def write_markdown(R, path):
    meta = R["meta"]
    L = ["# Evaluation", "",
         f"Generated by `scripts/run_evaluation.py`: {meta['runs']} simulation runs in two stages, {meta['seeds']} seeds for the main "
         f"study and {meta['sweep_seeds']} for most other studies, {meta['wall_s']:.0f} s wall time"
         + (f" (of which {meta['reused_runs']} runs were taken unchanged, by spec hash and seed, from an earlier invocation)" if meta.get("reused_runs") else "")
         + ". Values are means with 95 % "
         "percentile-bootstrap intervals over runs in brackets (they stay inside the range of the data); paired differences are "
         "bootstrapped per seed and marked * when the interval excludes zero (many differences are inspected, so an isolated * is not "
         "evidence by itself). Metric definitions and limitations: `docs/evaluation.md`. Every configuration behind a table is in "
         "`results/study_specs.json` (its hash is the `spec_hash` of its rows in `evaluation_runs.jsonl.gz`); attacker profiles are "
         "listed in `results/attacker_profiles.md`. The matched comparison and the robustness study follow "
         f"`config/evaluation_protocol.json` (SHA-256 `{meta['protocol_sha256'][:16]}...`), committed before they were run.", "",
         "Each attack run: a legitimate-only warm-up (10 minutes unless stated), then the attack with legitimate traffic (20 requests/min, "
         "80 % conversion, verification delay lognormal median 25 s, 70 % of numbers reachable on WhatsApp, 20 % of requests from "
         "existing account holders with verified history) in the background. The observation window is the attack's minutes; every run "
         "then drains to a declared horizon so late receipts, entries and resolutions are observed (pending outcomes at the end are "
         "counted and were zero in every run). *Contained* means leakage stayed at or below 5 % of the attack rate from some minute "
         "to the end of the run with at least five such minutes: a property of the finite window, not a guarantee beyond it.", ""]

    # ---------------- A
    L += ["## A. Attacker profiles across designs", "",
          "Designs: `v1` (header-trusted platform, static caps); `v1_corrected` (v1 with attestation-derived platform); "
          "`budget_only`; `block_limit_only` (attestation, sessions, a refusing counter of 5 SMS sends per destination block per day, no "
          "scoring); `conversion_only` and `speed_only` (v2 with one block test off: component variants, not independent detectors); `v2`.", "",
          "Columns: *contained* is seeds contained / seeds run; *time to containment* is over contained seeds only; *leak %* is leaked SMS "
          "as a share of the run's attack requests (removes the variation in attack volume); legitimate outcomes are per offered user: "
          "*completed* (code entered), *challenged*, *refused* (never delivered), and *first-time refused* among users without verified history.", ""]
    for mode in MODES:
        L += [f"### Mode: {mode.replace('_', ' ')}", "",
              "| Attacker | Design | Contained | Time to containment over contained seeds (min) | Total leaked | Leak % of requests | Legit completed % | Legit challenged % | Legit refused % | First-time refused % | Returning refused % |",
              "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for name in ATTACKERS:
            for design in DESIGNS:
                s = R["multi_seed"][mode][name][design]
                L.append(f"| `{name}` | {design} | {s['n_contained']}/{s['n']} | {ci(s['time_to_containment_if_contained_min'])} | "
                         f"{ci(s['leaked_total'],0)} | {ci(s['leak_fraction_pct'])} | {ci(s['legit_completed_pct'])} | {ci(s['legit_challenge_rate_pct'])} | "
                         f"{ci(s['legit_refusal_rate_pct'])} | {ci(s['first_time_refusal_rate_pct'])} | {ci(s['returning_refusal_rate_pct'])} |")
        L.append("")
    L += ["### A2. Where the spread comes from (with adaptive caps, v2)", "",
          "The main study draws each seed's pool size, attack rate and CAPTCHA class (*randomised*). With those fixed at the profile's own "
          "parameters (*fixed*), the remaining spread is simulation noise alone. Intervals mixing both should not be read as Monte Carlo error.", "",
          "| Attacker | Attacker parameters | Total leaked | Leak % of requests | Legit completed % | Leaked: 90th percentile / max over seeds |", "|---|---|---:|---:|---:|---:|"]
    for name, d in R["variance"].items():
        for kind, s in d.items():
            t = s["tails"]["leaked_total"]
            L.append(f"| `{name}` | {kind} | {ci(s['leaked_total'],0)} | {ci(s['leak_fraction_pct'])} | {ci(s['legit_completed_pct'])} | {t['p90']:.0f} / {t['max']:.0f} |")
    L += ["", "Attacker descriptions: `results/attacker_profiles.md`.", ""]

    # ---------------- B
    flags = sorted(ALL_FEATURES)
    L += ["## B. Ablation: leave one layer out (with adaptive caps)", "",
          f"Total leaked SMS over 20 minutes, mean over the same {meta['sweep_seeds']} seeds in every column, on an identical offered trace "
          "(asserted by the workload hash). `full v2` is the complete design. One factor at a time: interactions are not estimated.", "",
          "| Attacker | full v2 | " + " | ".join(f"-{f}" for f in flags) + " |", "|---|---:|" + "---:|" * len(flags)]
    for name in ATTACKERS:
        ref = R["ablation"][name]["full"]["leaked_total"][0]
        L.append(f"| `{name}` | {ref:.0f} | " + " | ".join(f"{R['ablation'][name][f]['leaked_total'][0]:.0f}" for f in flags) + " |")
    L += ["", "Every paired per-seed difference against full v2 (all predeclared comparisons, none suppressed): leaked SMS, and "
          "legitimate completion in percentage points.", "",
          "| Attacker | Layer removed | Leaked: difference to full v2 | Legit completed (pp): difference to full v2 |", "|---|---|---:|---:|"]
    for name in ATTACKERS:
        for f in flags:
            s = R["ablation"][name][f]
            L.append(f"| `{name}` | -{f} | {diff(s['paired_leak_diff'],0)} | {diff(s['paired_completed_diff'],2)} |")
    L += ["", "### B2. Controller cadence, tick phase and attack length (with adaptive caps)", "",
          "The oracle baseline job at five cadences, with the tick aligned with the attack start and offset by half a period, for a 20-minute "
          "attack and (hourly job) a 60-minute one. The job accumulates the volume since its last tick, so cadence changes both when and on what it acts.", "",
          "| Attacker | Cadence | Tick phase | Attack length (min) | Total leaked | Leak % | Legit completed % | First-time refused % |", "|---|---|---|---:|---:|---:|---:|---:|"]
    for name in R["cadence"]:
        for key, s in R["cadence"][name].items():
            cname, pname, mins = key.split("|")
            L.append(f"| `{name}` | {cname} | {pname} | {mins} | {ci(s['leaked_total'],0)} | {ci(s['leak_fraction_pct'])} | {ci(s['legit_completed_pct'])} | {ci(s['first_time_refusal_rate_pct'])} |")
    L += ["", "### B3. The deployed baseline job (with adaptive caps)", "",
          f"The main study hands the adaptive job the modelled legitimate rate (oracle). Here the deployed `BaselineJob` learns from the "
          f"pipeline's own counters, which include refused attack volume. *Weekly profile*: the attack's hour of the week was simulated in "
          f"three previous weeks, so the job has the weekly median it is designed to use; *stale*: legitimate volume in those weeks was twice "
          f"or half today's; *schedule-aware poisoning*: an attacker at the legitimate rate ran in that hour every previous week; two workers "
          f"tick concurrently; a worker restarts mid-attack. Paired differences are against `{R_.BASELINE_REFERENCE}` on the same seeds; "
          f"a difference whose interval includes zero is not evidence of equivalence.", "",
          "| Attacker | Baseline | Total leaked | Legit completed % | First-time refused % | Leaked: paired diff. | Completed (pp): paired diff. | First-time refused (pp): paired diff. |",
          "|---|---|---:|---:|---:|---:|---:|---:|"]
    for name in R["baseline_job"]:
        for vname in R_.BASELINE_VARIANTS:
            s = R["baseline_job"][name][vname]
            p = s["paired_vs_reference"]
            L.append(f"| `{name}` | {vname} | {ci(s['leaked_total'],0)} | {ci(s['legit_completed_pct'])} | {ci(s['first_time_refusal_rate_pct'])} | "
                     f"{diff(p['leaked_total'],0)} | {diff(p['legit_completed_pct'])} | {diff(p['first_time_refusal_rate_pct'])} |")
    L.append("")

    # ---------------- C
    L += ["## C. Sensitivity and the leakage-friction trade-off", "", "![leakage vs friction](tradeoff.png)", "",
          "### C1. Risk weights, tier boundaries and the resolution timeout (behavioural-only mode)", "",
          "One-at-a-time sensitivity around the defaults, not a joint search: each row changes one parameter. Every tested value is shown.", ""]
    for name in R["weight_sweep"]:
        L += [f"Attacker `{name}`:", "", "| Axis | Value | Late leak (SMS/min) | Total leaked | Leak % | Legit completed % | Legit challenged % | Legit refused % |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for axis, vals in R["weight_sweep"][name].items():
            for v, s in vals.items():
                L.append(f"| {axis} | {v} | {ci(s['steady_state_leak_per_min'])} | {ci(s['leaked_total'],0)} | {ci(s['leak_fraction_pct'])} | {ci(s['legit_completed_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} |")
        L.append("")
    L += ["### C2. Adaptive cap floor and base multiple (with adaptive caps)", ""]
    for name in R["cap_sweep"]:
        L += [f"Attacker `{name}`:", "", "| Floor | Base multiple | Total leaked | Leak % | Legit completed % | Legit refused % |", "|---:|---:|---:|---:|---:|---:|"]
        for floor in R_.CAP_SWEEP["adaptive_floor"]:
            for mult in R_.CAP_SWEEP["base_cap_multiple"]:
                s = R["cap_sweep"][name][f"floor={floor},mult={mult}"]
                L.append(f"| {floor} | {mult} | {ci(s['leaked_total'],0)} | {ci(s['leak_fraction_pct'])} | {ci(s['legit_completed_pct'])} | {ci(s['legit_refusal_rate_pct'])} |")
        L.append("")

    # ---------------- D
    L += ["## D. Adaptive attackers", "",
          "Scripted adaptations, not an optimised adversary: fixed verification fractions, delays, pools and phase lengths, except "
          "`threshold_aware_carrier`, which reacts to its own outcomes using white-box knowledge of the deployed parameters. The leakages "
          "are observations for these scripts, not worst-case bounds.", ""]
    for mode in MODES:
        L += [f"### Mode: {mode.replace('_', ' ')}", "",
              "| Attacker | Run (min) | Contained | Total leaked | Leak % | Codes the attacker entered | Challenges solved | Verdict events (window) | Legit completed % | Legit challenged % | Legit refused % | Legit requests hit % |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for name in ADAPTIVE_ATTACKERS:
            s = R["adaptive_attackers"][mode][name]
            run_min = len(s["containment_survival"]) - 1
            L.append(f"| `{name}` | {run_min} | {s['n_contained']}/{s['n']} | {ci(s['leaked_total'],0)} | {ci(s['leak_fraction_pct'])} | "
                     f"{ci(s['attacker_verifications'],0)} | {ci(s['attacker_challenges_solved'],0)} | {ci(s['block_verdicts'])} | "
                     f"{ci(s['legit_completed_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} | {ci(s['legit_hit_by_verdict_pct'],2)} |")
        L += ["", "Trust-building attackers by phase (requests / SMS leaked / codes entered):", "",
              "| Attacker | Preparation | Flood |", "|---|---:|---:|"]
        for name in ("trust_building_pumper", "trust_building_concentrated", "trust_building_long"):
            s = R["adaptive_attackers"][mode][name]
            L.append(f"| `{name}` | {s['prep_requests'][0]:.0f} / {s['prep_leaked'][0]:.0f} / {s['prep_verified'][0]:.0f} | "
                     f"{s['flood_requests'][0]:.0f} / {s['flood_leaked'][0]:.0f} / {s['flood_verified'][0]:.0f} |")
        L.append("")

    L += ["### D2. Poisoning the destination blocks real users share (behavioural-only mode)", "",
          "The poisoner floods the 20 blocks legitimate users concentrate on. *Requests hit*: legitimate requests that met a verdict, by "
          "stage; *hit and never completed* is descriptive (it includes people who would not have entered the code anyway). "
          "*Attributable loss* is causal on the same offered trace: requests that completed with verdicts recorded but not enforced "
          "(the observe-only counterfactual with the same fallback reachability and run length) and did not complete under the variant, "
          "net of the reverse. The recovery variant stops the attack after 10 minutes of a 70-minute run, longer than the verdicts' "
          "one-hour lifetime. Observe-only rows are the counterfactuals.", "",
          "| Variant | Run (min) | WhatsApp reachable | Verdict events | Blocks with a verdict | Stage 1 / stage 2 | Block-minutes under verdict | Requests hit | Hit and never completed | Attributable loss (requests) | Attributable loss (% of users) | Hit after the attack stopped | Legit completed % | Legit challenged % |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for vname, (cfg, active, minutes, wa) in R_.POISONER_VARIANTS.items():
        s = R["poisoner"][vname]
        al = s.get("attributable_loss_vs_observe")
        L.append(f"| {vname} | {minutes} | {wa:.0%} | {ci(s['block_verdicts'])} | {ci(s['blocks_with_verdict'])} | {s['verdicts_stage1'][0]:.1f} / {s['verdicts_stage2'][0]:.1f} | "
                 f"{ci(s['verdict_exposure_block_min'],0)} | {ci(s['legit_hit_by_verdict'])} | {ci(s['legit_hit_lost'])} | "
                 f"{diff(al['net_lost'],1) if al else '–'} | {diff(al['net_lost_pct'],2) if al else '–'} | {ci(s['legit_hit_after_stop'])} | "
                 f"{ci(s['legit_completed_pct'])} | {ci(s['legit_challenge_rate_pct'])} |")
    L.append("")

    L += ["### D3. Two design alternatives against the attacks that defeat the default", "",
          "*Trust budget*: at most 8 requests per minute per (source, country) are granted the verified-history exemption, about twice "
          "the modelled returning rate; beyond it they are treated as first-time clients. *Receipt-robust block tests*: a failed delivery "
          "receipt counts as a block-test failure unless the carrier is in an outage. Attack side: 10 seeds; legitimate side: 24 hours on "
          "200 blocks, 80 % conversion, caps on, with 5 % of blocks on a poor route that loses half its messages.", ""]
    for mode in MODES:
        L += [f"Mode: {mode.replace('_', ' ')}", "",
              "| Attacker | Variant | Total leaked | Leaked: paired diff. to default | Codes entered | Verdict events |", "|---|---|---:|---:|---:|---:|"]
        for aname in R_.ALTERNATIVE_ATTACKERS:
            for vname in R_.ALTERNATIVES:
                s = R["alternatives"]["attack"][mode][aname][vname]
                L.append(f"| `{aname}` | {vname} | {ci(s['leaked_total'],0)} | {diff(s['paired_leak_vs_default'],0)} | {ci(s['attacker_verifications'],0)} | {ci(s['block_verdicts'])} |")
        L.append("")
    L += ["Legitimate cost:", "", "| Variant | Legit completed % | Returning users completed % | Verdict events (24 h) | Requests hit | Legit refused % |",
          "|---|---:|---:|---:|---:|---:|"]
    for vname in R_.ALTERNATIVES:
        s = R["alternatives"]["legit"][vname]
        L.append(f"| {vname} | {ci(s['legit_completed_pct'],2)} | {ci(s['returning_completed_pct'],2)} | {ci(s['block_verdicts'])} | {ci(s['legit_hit_by_verdict'])} | {ci(s['legit_refusal_rate_pct'],2)} |")
    L.append("")

    # ---------------- F
    L += ["## F. Pumping on concentrated destination blocks (behavioural-only mode, 130-minute warm-up)", "",
          "Each attacker targets 3 blocks of 10 000 numbers inside a standard prefix. *Time to first verdict* is when the block tests first "
          "fired; *containment* is when leakage stopped (graded verdicts can fire before containment). *Codes entered* are successful OTP "
          "verifications by the carrier (no account system is modelled).", "",
          "| Attacker | Variant | Contained | Time to containment over contained seeds (min) | Time to first verdict (min) | Total leaked | Leak % | Codes entered | Verdict events (window) | Verdict events incl. drain | Legit completed % | Legit challenged % |",
          "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for aname in PUMPING_ATTACKERS:
        for vname in R_.PUMPING_VARIANTS:
            s = R["pumping"][aname][vname]
            L.append(f"| `{aname}` | {vname} | {s['n_contained']}/{s['n']} | {ci(s['time_to_containment_if_contained_min'])} | {ci(s['first_verdict_min'])} | "
                     f"{ci(s['leaked_total'],0)} | {ci(s['leak_fraction_pct'])} | {ci(s['attacker_verifications'],0)} | {ci(s['block_verdicts'])} | "
                     f"{ci(s['block_verdicts_incl_drain'])} | {ci(s['legit_completed_pct'])} | {ci(s['legit_challenge_rate_pct'])} |")
    L += ["", f"### F1. A {R_.LONG_ATTACK_MIN}-minute attack against the default (survival of containment)", "",
          "Share of seeds not yet contained at each minute (contained = from that minute to the end of the run, at least five quiet minutes).", "",
          "| Attacker | Contained | Leaked | " + " | ".join(f"min {m}" for m in (5, 10, 20, 30, 45, 55)) + " |", "|---|---:|---:|" + "---:|" * 6]
    for aname, s in R["long_attack"].items():
        surv = s["containment_survival"]
        L.append(f"| `{aname}` | {s['n_contained']}/{s['n']} | {ci(s['leaked_total'],0)} | " + " | ".join(f"{surv[m]:.1f}" for m in (5, 10, 20, 30, 45, 55)) + " |")
    L.append("")

    # ---------------- F2 matched comparison
    M = R["matched"]
    L += ["### F2. Destination policies on a common pipeline, selected on tuning seeds, evaluated on held-out seeds", "",
          "Protocol: `config/evaluation_protocol.json`. Every row runs the full pipeline; only the destination admission policy differs "
          "(sequential tests, a per-block counter of SMS *sends* with a daily or short refilling window and a graded or refusing action, or "
          "none). Counter units are sends: a refused or challenged request and its retry cost nothing unless an SMS goes out. For each "
          "family and density, the setting with the lowest leakage among those whose completion on the tuning seeds was within 0.5 pp of the "
          "default's was selected; at 200 blocks, for each credit value the lowest threshold whose false verdict events did not exceed the "
          "default's was also selected (matched false-alarm burden). Selection used only the tuning seeds; the tables below are the "
          "evaluation seeds. Legitimate side: 24 hours, 65 % and 80 % conversion, 20 % autofill, 70 % WhatsApp reachability. Attack side: "
          "the four concentrated pumpers, 20 minutes after a 130-minute warm-up. *Attributable loss* is per request on the same offered "
          "trace against `none`; positive = completions lost because of the policy.", ""]
    for density, sel in M["selection"].items():
        L += [f"Density {density} ({R_.MC['densities'][density]}): service target {sel['service_target_completion_pct']:.2f} % completion "
              f"(default {sel['default_completion_pct']:.2f} %, {sel['default_verdict_events']:.1f} verdict events per day on the tuning seeds). Selected:", ""]
        for role, name in sel["chosen"].items():
            L.append(f"- {role}: `{name}`")
        L += ["", "| Setting | Completed % (65 %) | Completed: diff. to default (pp) | Attributable loss (% of users) | Challenged % | Refused % | Verdict events / day | Block-minutes under verdict | Completed % (80 %) | Attributable loss at 80 % (%) |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for name in M["evaluate"][density]:
            s65, s80 = M["legit"][density][name]["0.65"], M["legit"][density][name]["0.8"]
            p65, p80 = M["paired"][density][name]["0.65"], M["paired"][density][name]["0.8"]
            al65 = p65["attributable_loss_vs_none"]; al80 = p80["attributable_loss_vs_none"]
            L.append(f"| `{name}` | {ci(s65['legit_completed_pct'],2)} | {diff(p65['completed_diff_vs_default'],2)} | {diff(al65['net_lost_pct'],2) if al65 else '–'} | "
                     f"{ci(s65['legit_challenge_rate_pct'],2)} | {ci(s65['legit_refusal_rate_pct'],2)} | {ci(s65['block_verdicts'])} | {ci(s65['verdict_exposure_block_min'],0)} | "
                     f"{ci(s80['legit_completed_pct'],2)} | {diff(al80['net_lost_pct'],2) if al80 else '–'} |")
        L.append("")
    names = sorted(M["attack"])
    L += ["Attack side (evaluation seeds): SMS leaked of about 600 requests, and the paired difference to the default.", "",
          "| Setting | " + " | ".join(f"`{x}`" for x in R_.MATCHED_ATTACKERS) + " | Codes entered (human-like carrier) |", "|---|" + "---:|" * (len(R_.MATCHED_ATTACKERS) + 1)]
    for name in names:
        cells = [f"{ci(M['attack'][name][x]['leaked_total'],0)} ({diff(M['attack'][name][x]['paired_leak_vs_default'],0)})" for x in R_.MATCHED_ATTACKERS]
        L.append(f"| `{name}` | " + " | ".join(cells) + f" | {ci(M['attack'][name]['concentrated_pumper_verifies_humanlike']['attacker_verifications'],0)} |")
    L += ["", "#### F3. Every setting on the tuning seeds (sampled operating points, not an optimised frontier)", "",
          "Density 200, 65 % conversion, tuning seeds: completion, false verdict events per day, and leakage summed over the four pumpers.", "",
          "| Setting | Completed % | Verdict events / day | Leakage, four pumpers |", "|---|---:|---:|---:|"]
    sel200 = M["selection"][R_.MC["full_grid_density"]]
    for name in sel200["tuning_completion_pct"]:
        L.append(f"| `{name}` | {sel200['tuning_completion_pct'][name]:.2f} | {sel200['tuning_verdict_events'][name]:.1f} | {sel200['tuning_leak_sum'][name]:.0f} |")
    L.append("")

    # ---------------- G
    L += ["## G. Pumper destination spread, and the dilution curve", "", "![pumper spread](pumper_spread.png)", "",
          f"The closed-form model (`evaluation/model.py`): leak = min(N, k B + in-flight), with B the 8-digit blocks a run actually touched, "
          f"k = {meta['model']['k_conv']} sends per block for a carrier that never verifies and {meta['model']['k_fast']} for one that verifies within "
          f"a second, under no pre-existing credit on the blocks, no solved challenges, no verified-history exemptions and no outage "
          f"suspension. It is a consistency check of the mechanism on each run's observed blocks, not a forecast and not a bound. The "
          f"conversion statistic's expected increment is zero when the carrier verifies {100 * meta['model']['evasion_share']:.0f} % of its codes. "
          "*Residual* = predicted − measured per run; *saturated* runs are those where the model predicts that every request leaks. "
          "Means are rounded independently.", "",
          "| Carrier verifies | Ranges | Numbers per range | Nominal blocks | Blocks requested (observed) | Total leaked (measured) | Model | Mean residual | Max abs residual | Saturated runs | Unsaturated: mean abs / mean rel. error | Contained |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for verify in (0.0, 1.0):
        for nb in R_.SPREAD_BLOCKS:
            for digits, label in R_.SPREAD_RANGE_DIGITS.items():
                s = R["spread"][f"verify={verify},blocks={nb},digits={digits}"]
                rsd = s["residuals"]
                uns = (f"{rsd['unsaturated_mean_abs']:.1f} / {rsd['unsaturated_mean_rel_pct']:.0f} %" if rsd["unsaturated_mean_abs"] is not None else "–")
                L.append(f"| {'yes, within 1 s' if verify else 'no'} | {nb} | {label} | {s['blocks_nominal']} | {ci(s['attacker_blocks_requested'],0)} | "
                         f"{ci(s['leaked_total'],0)} | {s['predicted'][0]:.1f} | {rsd['mean']:+.1f} | {rsd['max_abs']:.0f} | {rsd['n_saturated']}/{rsd['n']} | {uns} | {s['n_contained']}/{s['n']} |")
    L += ["", "Dilution curve (behavioural-only, 60-minute attack, 5 seeds): the captcha-farm attacker at multiples of the legitimate rate. "
          "The leak share is computed per run, then bootstrapped.", "",
          "| Attack rate / legitimate rate | Requests | Leaked | Leak % of requests | Legit completed % | Legit challenged % | Legit refused % |",
          "|---:|---:|---:|---:|---:|---:|---:|"]
    for m in R_.DILUTION_MULTIPLES:
        s = R["dilution"][str(m)]
        L.append(f"| {m} | {ci(s['requests'],0)} | {ci(s['leaked_total'],0)} | {ci(s['leak_fraction_pct'])} | {ci(s['legit_completed_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} |")
    L.append("")

    # ---------------- H
    H = R["false_positives"]
    L += ["## H. False positives of the destination-block tests", "",
          "### H1. Monte Carlo of the tests on one block seeing only legitimate traffic", "",
          f"Tests as deployed: P(verify | user) = {Config().sprt_legit_conversion}, P(fast | user) = {meta['model']['sprt_legit_fast']:.3f}, where "
          "*fast* is a verification within 5 s of delivery, conditional on verifying. The block starts with empty statistics and receives "
          "exactly the stated number of resolved sends; the quantity is P(at least one verdict in that sequence). Cells: events / trials, the "
          "estimate, and its 95 % Wilson interval; a zero count bounds the probability at about 3 / trials. One block's hazard for a fixed "
          "sequence, not the day's harm process, which H2 simulates.", ""]
    for n in R_.FP_SENDS_PER_BLOCK:
        L += [f"{n} legitimate sends on the block:", "", "| True conversion | " + " | ".join(f"fast share {f:.0%}" for f in R_.FP_FAST_SHARES) + " |",
              "|---:|" + "---:|" * len(R_.FP_FAST_SHARES)]
        for pconv in R_.FP_CONVERSIONS:
            cells = []
            for f in R_.FP_FAST_SHARES:
                v = H["monte_carlo"][f"{n},{pconv},{f}"]
                cells.append(f"{v['events']}/{v['trials']} = {100 * (v['never_verified'] + v['machine_verified']):.2f} % [{100 * v['p_lo']:.2f}, {100 * v['p_hi']:.2f}]")
            L.append(f"| {pconv:.0%} | " + " | ".join(cells) + " |")
        L.append("")
    L += ["### H2. Twenty-four hours of legitimate traffic only, default tests", "",
          f"{H['legit_only_seeds']} seeds per cell; distinct blocks with their observed occupancy; 90th percentile and maximum over seeds "
          "for the verdict events. Hits are requests that met a verdict; *hit and never completed* is descriptive.", "",
          "| Calibration | Sends per block per day | Occupancy median / max | Conversion | Autofill | Verdict events (24 h) | P90 / max | Blocks with a verdict | Requests hit | Hit and never completed | Completed % |",
          "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for calib in R_.LEGIT_ONLY_CALIBRATION:
        for b, label in R_.LEGIT_ONLY_BLOCKS.items():
            for c in R_.LEGIT_ONLY_CONVERSIONS:
                for af in R_.LEGIT_ONLY_AUTOFILL:
                    s = H["legit_only"][f"calib={calib},blocks={b},conv={c},autofill={af}"]
                    occ = f"{s['occupancy_median'][0]:.0f} / {s['occupancy_max'][0]:.0f}" if b else "–"
                    t = s["tails"]["block_verdicts"]
                    L.append(f"| {calib} | {label} | {occ} | {c:.0%} | {af:.0%} | {ci(s['block_verdicts'])} | {t['p90']:.0f} / {t['max']:.0f} | {ci(s['blocks_with_verdict'])} | "
                             f"{ci(s['legit_hit_by_verdict'])} | {ci(s['legit_hit_lost'])} | {ci(s['legit_completed_pct'])} |")
    L += ["", "### H3. A 30-minute carrier outage during legitimate traffic", "",
          "| Outage | Variant | Verdict events | Requests hit | Outage alerts | Completed % |", "|---|---|---:|---:|---:|---:|"]
    for kind in ("failed_receipts", "silent"):
        for v in R_.OUTAGE_VARIANTS:
            s = H["outage"][f"{kind}|{v}"]
            L.append(f"| {kind} | {v} | {ci(s['block_verdicts'])} | {ci(s['legit_hit_by_verdict'])} | {ci(s['outage_alerts'])} | {ci(s['legit_completed_pct'])} |")
    L += ["", "### H4. Fallback availability", "",
          "The share of numbers reachable on WhatsApp, written into the channel registry the selector reads, at 0 %, the modelled 70 % and "
          "100 % (24 hours, 200 blocks, 65 % conversion). A downgraded first-time user without WhatsApp is refused.", "",
          "| Setting | WhatsApp reachable | Completed % | Served over WhatsApp % | Refused for want of a channel % | Challenged % |", "|---|---:|---:|---:|---:|---:|"]
    for name in R_.FALLBACK_SETTINGS:
        for w in R_.FALLBACK_LEVELS:
            s = H["fallback"][f"{name}|{w}"]
            L.append(f"| `{name}` | {w:.0%} | {ci(s['legit_completed_pct'],2)} | {ci(s['legit_whatsapp_pct'],2)} | {ci(s['legit_no_channel_pct'],2)} | {ci(s['legit_challenge_rate_pct'],2)} |")
    L.append("")

    # ---------------- E
    L += ["## E. Attacker economics (scenario accounting, 20-minute window)", "",
          "Not measured profit. Revenue = leaked SMS x retail termination price x revenue share, credited only to pumping profiles; the share "
          "is unknown, so each row gives the **break-even share** (the share at which revenue equals the attacker's bill) instead of a sign "
          "for one assumed share. The bill is event-level: a CAPTCHA token for every session attempt (refused ones included) and every "
          "request, a paid solution per interactive challenge, and proxy traffic per request; identity preparation, numbers, carrier "
          "contracts and fixed costs are not included, so break-even shares are lower bounds on what the attacker needs. The spend ceiling "
          "bounds SMS count and abstract cost units only, not lookups, CAPTCHA assessments or fallback channels.", ""]
    for mode in list(MODES) + ["pumping_study"]:
        names = ATTACKERS if mode in MODES else {n: a for n, a in PUMPING_ATTACKERS.items() if a.earns_revenue}
        L += [f"### {'Mode: ' + mode.replace('_', ' ') if mode in MODES else 'Pumping study (v1 versus the v2 default)'}", "",
              "| Attacker | Design | Leaked SMS | Requests | Tokens | Attacker bill (USD) | Break-even share | Profit at share 0.2 / 0.5 (USD) | Defender cost (USD) | Codes entered |",
              "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for name in names:
            for row in R["economics"][mode][name]:
                be = "–" if row["breakeven_share"] is None else f"{row['breakeven_share']:.3f}"
                prof = f"{row['profit_surface_usd']['share=0.2,price x1.0']:.2f} / {row['profit_surface_usd']['share=0.5,price x1.0']:.2f}"
                L.append(f"| `{name}` | {row['design']} | {row['leaked_sms']:.0f} | {row['requests']:.0f} | {row['tokens']:.0f} | {row['attacker_cost_usd']:.2f} | "
                         f"{be} | {prof} | {row['defender_cost_usd']:.2f} | {row['verified_codes']:.0f} |")
        L.append("")

    # ---------------- Robustness
    if "robustness" in R:
        rb = R["robustness"]
        L += ["## R. Predeclared robustness study", "",
              "Claims, thresholds, the parameter ranges, the held-out scenario family and the Latin-hypercube design were fixed in "
              "`config/evaluation_protocol.json` and committed before these runs. A claim *holds* if it is true in at least 90 % of its cells.", "",
              "| Claim | Cells | True | Share | Holds |", "|---|---:|---:|---:|---|"]
        for c in ("C1", "C2", "C3", "C4", "C5", "C4_points_below_0.75"):
            v = rb[c]
            L.append(f"| {c}{' (reported, not judged)' if c.endswith('0.75') else ''} | {v['cells']} | {v['true']} | {v['share']:.2f} | {'yes' if v['holds'] else 'no'}{'' if not c.endswith('0.75') else ' (n/a)'} |")
        L += ["", "Claim texts:", ""] + [f"- **{k}**: {t}" for k, t in R_.ROB["claims"].items()] + ["", "Points:", "",
              "| Point | " + " | ".join(R_.ROB["ranges"]) + " |", "|---:|" + "---:|" * len(R_.ROB["ranges"])]
        for i, pt in enumerate(rb["points"]):
            L.append(f"| {i} | " + " | ".join(f"{pt[k]:.2f}" for k in R_.ROB["ranges"]) + " |")
        L.append("")

    L += ["## Calibration sources", "", "| Parameter | Value | Source |", "|---|---|---|"]
    for k, v in CALIBRATION.items():
        L.append(f"| `{k}` | `{json.dumps(v['value'])}` | {v['source']} |")
    path.write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
