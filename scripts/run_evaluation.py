#!/usr/bin/env python3
"""Full evaluation: multi-seed runs with confidence intervals (v1 and v2, behavioural-only and
with adaptive caps), leave-one-layer-out ablation, weight/boundary and cap sweeps with the
leakage-versus-friction trade-off, adaptive attackers, and attacker economics.

    python3 scripts/run_evaluation.py [--seeds 30] [--sweep-seeds 10] [--procs 4] [--quick]

Writes results/evaluation.md, results/evaluation.json, results/evaluation_runs.jsonl.gz and
results/tradeoff.png|svg. Deterministic for a given seed set.
"""
import argparse
import gzip
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from otp_guard.config import ALL_FEATURES, V1_FEATURES                                   # noqa: E402
from otp_guard.evaluation.calibration import CALIBRATION                                  # noqa: E402
from otp_guard.evaluation.runner import (ATTACKERS, ADAPTIVE_ATTACKERS, MODES, SWEEP_AXES, CAP_SWEEP,   # noqa: E402
                                         study_multi_seed, study_ablation, study_sweep, study_cap_sweep,
                                         study_adaptive, run_all, summarise, economics)
from otp_guard.evaluation.stats import mean_ci                                            # noqa: E402

PALETTE = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7"]


def ci(t, d=1):
    """Mean [lo, hi]; the lower bound of a count or rate is clamped at 0 (t-intervals on skewed counts can dip below)."""
    m, lo, hi, n = t
    return "n/a" if m is None else f"{m:.{d}f} [{max(lo, 0):.{d}f}, {hi:.{d}f}]"


def group(results, index, keyfn):
    g = {}
    for r, idx in zip(results, index):
        g.setdefault(keyfn(idx), []).append(r)
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=30)
    ap.add_argument("--sweep-seeds", type=int, default=10)
    ap.add_argument("--procs", type=int, default=None)
    ap.add_argument("--quick", action="store_true", help="3 seeds everywhere, for CI")
    ap.add_argument("--out", default=str(ROOT / "results"))
    a = ap.parse_args()
    out = pathlib.Path(a.out); out.mkdir(exist_ok=True)
    seeds = list(range(3 if a.quick else a.seeds))
    sseeds = list(range(3 if a.quick else a.sweep_seeds))

    # ---- build every run up front so one pool does all the work ----
    jobs = []
    def add(study, specs, index):
        for s, i in zip(specs, index):
            jobs.append((study, i, s))
    add("v2", *study_multi_seed(seeds, ALL_FEATURES))
    add("v1", *study_multi_seed(seeds, V1_FEATURES))
    add("ablation", *study_ablation(sseeds))
    add("sweep", *study_sweep(sseeds))
    add("capsweep", *study_cap_sweep(sseeds))
    add("adaptive", *study_adaptive(sseeds))
    print(f"{len(jobs)} runs on {a.procs or 'all'} processes", flush=True)
    t0 = time.time()
    results = run_all([j[2] for j in jobs], a.procs)
    wall = time.time() - t0
    print(f"done in {wall:.0f}s", flush=True)

    with gzip.open(out / "evaluation_runs.jsonl.gz", "wt") as f:
        for (study, idx, _), r in zip(jobs, results):
            r = dict(r); r["study"] = study; r["index"] = idx
            r["attack"] = {k: v for k, v in r["attack"].items() if k != "leaked_per_min"} | {"leaked_per_min": r["attack"]["leaked_per_min"]}
            f.write(json.dumps(r) + "\n")

    by = {}
    for (study, idx, _), r in zip(jobs, results):
        by.setdefault(study, ([], []))
        by[study][0].append(r); by[study][1].append(idx)

    R = {"meta": {"seeds": len(seeds), "sweep_seeds": len(sseeds), "runs": len(jobs), "wall_s": wall,
                  "calibration": CALIBRATION}}

    # A. multi-seed, v1 vs v2, two modes
    A = {}
    for design in ("v2", "v1"):
        g = group(*by[design], lambda i: (i[0], i[1]))
        for (mode, name), rs in g.items():
            A.setdefault(mode, {}).setdefault(name, {})[design] = summarise(rs)
    R["multi_seed"] = A

    # B. ablation (adaptive-caps mode): leaked total per (attacker, removed flag) vs full v2
    B = {}
    g = group(*by["ablation"], lambda i: (i[0], i[1]))
    for (name, flag), rs in g.items():
        B.setdefault(name, {})[flag] = summarise(rs)
    R["ablation"] = B

    # C. sweeps
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

    # D. adaptive attackers
    D = {}
    g = group(*by["adaptive"], lambda i: (i[0], i[1]))
    for (mode, name), rs in g.items():
        D.setdefault(mode, {})[name] = summarise(rs)
    R["adaptive_attackers"] = D

    # E. economics (behavioural-only and caps modes, v1 vs v2)
    E = {}
    for mode in MODES:
        for name in ATTACKERS:
            E.setdefault(mode, {})[name] = economics(A[mode][name]["v1"], A[mode][name]["v2"], name)
    R["economics"] = E

    (out / "evaluation.json").write_text(json.dumps(R, indent=1, default=str) + "\n")
    write_tradeoff_chart(R, out)
    write_markdown(R, out / "evaluation.md")
    print("wrote", out / "evaluation.md")


def friction_of(s):
    return s["legit_refusal_rate_pct"][0] + s["legit_challenge_rate_pct"][0]


def write_tradeoff_chart(R, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(8, 5.2), dpi=150)
    fig.patch.set_facecolor("#fcfcfb"); ax.set_facecolor("#fcfcfb")
    series = []
    for i, (label, points) in enumerate([
        ("Cap sweep (floor x base multiple)", [(friction_of(s), s["steady_state_leak_per_min"][0], k)
                                               for k, s in R["cap_sweep"]["residential_captcha_farm"].items()]),
        ("Tier boundary scale", [(friction_of(s), s["steady_state_leak_per_min"][0], k)
                                 for k, s in R["weight_sweep"]["residential_captcha_farm"]["tier_scale"].items()]),
        ("Fresh-fingerprint weight", [(friction_of(s), s["steady_state_leak_per_min"][0], k)
                                      for k, s in R["weight_sweep"]["residential_captcha_farm"]["fresh_fp_weight"].items()]),
        ("Conversion weight", [(friction_of(s), s["steady_state_leak_per_min"][0], k)
                               for k, s in R["weight_sweep"]["residential_captcha_farm"]["conversion_weight"].items()]),
    ]):
        xs = [p[0] for p in points]; ys = [p[1] for p in points]
        ax.scatter(xs, ys, s=42, color=PALETTE[i], label=label, edgecolors="#fcfcfb", linewidths=1.2, zorder=3)
        series += [(x, y, label) for x, y in zip(xs, ys)]
    # Pareto frontier: lowest leakage for each friction level
    pts = sorted(series)
    frontier, best = [], float("inf")
    for x, y, _ in pts:
        if y < best:
            frontier.append((x, y)); best = y
    if len(frontier) > 1:
        ax.plot([p[0] for p in frontier], [p[1] for p in frontier], color="#52514e", linewidth=2, zorder=2, label="Pareto frontier")
    ax.set_xlabel("Friction for real users: refused + challenged (% of legitimate requests)", color="#0b0b0b")
    ax.set_ylabel("Attacker steady-state leakage (SMS per minute)", color="#0b0b0b")
    ax.set_title("Residential captcha-farm attacker: leakage vs. friction across sweeps", color="#0b0b0b", loc="left")
    ax.grid(True, color="#e6e5e0", linewidth=0.8); ax.set_axisbelow(True)
    for sp in ("top", "right"): ax.spines[sp].set_visible(False)
    for sp in ("left", "bottom"): ax.spines[sp].set_color("#c3c2b7")
    ax.tick_params(colors="#52514e")
    ax.legend(frameon=False, fontsize=8, loc="upper right")
    fig.tight_layout()
    fig.savefig(out / "tradeoff.png"); fig.savefig(out / "tradeoff.svg")
    plt.close(fig)


def write_markdown(R, path):
    meta = R["meta"]
    L = ["# Evaluation", "",
         f"Generated by `scripts/run_evaluation.py`: {meta['runs']} simulation runs, {meta['seeds']} seeds for the main "
         f"study and {meta['sweep_seeds']} for sweeps, {meta['wall_s']:.0f} s wall time. Values are means with 95 % "
         "t-confidence intervals in brackets. Metric definitions and limitations: `docs/evaluation.md`.", "",
         "Each run: 10 minutes of legitimate-only warm-up, then 20 minutes of attack with legitimate traffic "
         "(20 requests/min, 80 % conversion, verification delay lognormal median 25 s) in the background. Per seed the "
         "attacker's pool size (500 to 50 000 addresses), rate (10 to 60 requests/min) and CAPTCHA score class are "
         "randomised. Modes: **behavioural only** lifts the source caps so the other layers are visible; "
         "**with adaptive caps** runs the source cap at 3x the legitimate rate with the adaptive baseline job.", ""]

    L += ["## A. Attacker profiles, v1 versus v2", ""]
    for mode in MODES:
        L += [f"### Mode: {mode.replace('_', ' ')}", "",
              "| Attacker | Design | Contained (fraction of seeds) | Time to containment (min) | Leaked before containment | Steady-state leak (SMS/min) | Total leaked / 20 min | Defender cost (USD) | Legit delivered % | Legit challenged % | Legit refused % | Added delay (s) |",
              "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for name in ATTACKERS:
            for design in ("v1", "v2"):
                s = R["multi_seed"][mode][name][design]
                L.append(f"| `{name}` | {design} | {s['contained_fraction']:.2f} | {ci(s['time_to_containment_min'])} | {ci(s['leaked_before_containment'],0)} | "
                         f"{ci(s['steady_state_leak_per_min'])} | {ci(s['leaked_total'],0)} | {ci(s['attacker_cost_usd'],1)} | "
                         f"{ci(s['legit_delivered_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} | {ci(s['legit_mean_added_delay_s'])} |")
        L.append("")
    L += ["Attacker descriptions:", ""] + [f"- `{n}`: {a.description}" for n, a in ATTACKERS.items()] + [""]

    L += ["## B. Ablation: leave one layer out (with adaptive caps)", "",
          "Total leaked SMS over 20 minutes (mean over seeds) with the named layer switched off. The `full v2` column is the reference; a cell much larger than it names the layer that stops that attacker.", ""]
    flags = sorted(ALL_FEATURES)
    L.append("| Attacker | full v2 | " + " | ".join(f"-{f}" for f in flags) + " |")
    L.append("|---|---:|" + "---:|" * len(flags))
    for name in ATTACKERS:
        ref = R["multi_seed"]["with_adaptive_caps"][name]["v2"]["leaked_total"][0]
        cells = []
        for f in flags:
            v = R["ablation"][name][f]["leaked_total"][0]
            mark = " **" if v > ref * 1.5 + 5 else " "
            cells.append(f"{mark.strip()}{v:.0f}{mark.strip()}")
        L.append(f"| `{name}` | {ref:.0f} | " + " | ".join(cells) + " |")
    L.append("")

    L += ["## C. Sensitivity and the leakage-friction trade-off", "",
          "![leakage vs friction](tradeoff.png)", "",
          "### C1. Risk weights and tier boundaries (behavioural-only mode)", ""]
    for name in R["weight_sweep"]:
        L += [f"Attacker `{name}`:", "", "| Axis | Value | Steady-state leak (SMS/min) | Total leaked | Legit delivered % | Legit challenged % | Legit refused % |", "|---|---:|---:|---:|---:|---:|---:|"]
        for axis, vals in R["weight_sweep"][name].items():
            for v, s in vals.items():
                L.append(f"| {axis} | {v} | {ci(s['steady_state_leak_per_min'])} | {ci(s['leaked_total'],0)} | {ci(s['legit_delivered_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} |")
        L.append("")
    L += ["### C2. Adaptive cap floor and base multiple (with adaptive caps)", ""]
    for name in R["cap_sweep"]:
        L += [f"Attacker `{name}`:", "", "| Floor | Base multiple | Steady-state leak (SMS/min) | Total leaked | Legit delivered % | Legit refused % |", "|---:|---:|---:|---:|---:|---:|"]
        for floor in CAP_SWEEP["adaptive_floor"]:
            for mult in CAP_SWEEP["base_cap_multiple"]:
                s = R["cap_sweep"][name][f"floor={floor},mult={mult}"]
                L.append(f"| {floor} | {mult} | {ci(s['steady_state_leak_per_min'])} | {ci(s['leaked_total'],0)} | {ci(s['legit_delivered_pct'])} | {ci(s['legit_refusal_rate_pct'])} |")
        L.append("")

    L += ["## D. Adaptive attackers", ""]
    for mode in MODES:
        L += [f"### Mode: {mode.replace('_', ' ')}", "",
              "| Attacker | Contained | Time to containment (min) | Steady-state leak (SMS/min) | Total leaked | Attacker verifications | Challenges solved | Legit delivered % | Legit challenged % | Legit refused % |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for name in ADAPTIVE_ATTACKERS:
            s = R["adaptive_attackers"][mode][name]
            L.append(f"| `{name}` | {s['contained_fraction']:.2f} | {ci(s['time_to_containment_min'])} | {ci(s['steady_state_leak_per_min'])} | {ci(s['leaked_total'],0)} | "
                     f"{ci(s['attacker_verifications'],0)} | {ci(s['attacker_challenges_solved'],0)} | {ci(s['legit_delivered_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} |")
        L.append("")
    L += ["Adaptive attacker descriptions:", ""] + [f"- `{n}`: {a.description}" for n, a in ADAPTIVE_ATTACKERS.items()] + [""]

    L += ["## E. Attacker economics (20-minute window)", "",
          "Revenue = leaked SMS x SMS termination price x revenue share (share is ASSUMED, low 0.2 and high 0.5). "
          "Attacker cost = proxies (bytes x price per GB) + CAPTCHA tokens + solved challenges. Defender cost = SMS + HLR lookups + reCAPTCHA assessments attributable to the attacker. Only pumping attackers earn revenue; the others are pure cost to the defender.", ""]
    for mode in MODES:
        L += [f"### Mode: {mode.replace('_', ' ')}", "",
              "| Attacker | Design | Share | Leaked SMS | Attacker revenue (USD) | Attacker cost (USD) | Attacker profit (USD) | Defender cost (USD) |",
              "|---|---|---:|---:|---:|---:|---:|---:|"]
        for name in ATTACKERS:
            for row in R["economics"][mode][name]:
                L.append(f"| `{name}` | {row['design']} | {row['share']} | {row['leaked_sms']:.0f} | {row['attacker_revenue_usd']:.2f} | {row['attacker_cost_usd']:.2f} | {row['attacker_profit_usd']:.2f} | {row['defender_cost_usd']:.2f} |")
        L.append("")

    L += ["## Calibration sources", "", "| Parameter | Value | Source |", "|---|---|---|"]
    for k, v in CALIBRATION.items():
        L.append(f"| `{k}` | `{json.dumps(v['value'])}` | {v['source']} |")
    path.write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
