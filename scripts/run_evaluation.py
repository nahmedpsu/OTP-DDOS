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

from otp_guard.config import ALL_FEATURES, V1_FEATURES, Config                           # noqa: E402
from otp_guard.evaluation.calibration import CALIBRATION                                  # noqa: E402
from otp_guard.evaluation.runner import (ATTACKERS, ADAPTIVE_ATTACKERS, MODES, SWEEP_AXES, CAP_SWEEP,   # noqa: E402
                                         PUMPING_ATTACKERS, PUMPING_VARIANTS, SPREAD_BLOCKS, SPREAD_RANGE_DIGITS,
                                         DILUTION_MULTIPLES, DESIGNS, CADENCES, LEGIT_ONLY_CALIBRATION, paired_difference,
                                         study_cadence, study_multi_seed, study_ablation, study_sweep,
                                         study_cap_sweep, study_adaptive, study_pumping, study_spread,
                                         study_dilution, run_all, summarise, economics,
                                         FP_CONVERSIONS, FP_FAST_SHARES, FP_SENDS_PER_BLOCK, block_test_false_positives,
                                         LEGIT_ONLY_BLOCKS, LEGIT_ONLY_CONVERSIONS, LEGIT_ONLY_AUTOFILL, study_legit_only_24h,
                                         OUTAGE_VARIANTS, study_outage, summarise_legit_only)
from otp_guard.evaluation.calibration import legit_fast_share                             # noqa: E402
from otp_guard.evaluation.model import sends_to_verdict, evasion_share, predicted_leak, blocks_touched   # noqa: E402
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
    for design, feats in DESIGNS.items():
        add(design, *study_multi_seed(seeds, feats, design=design))
    add("cadence", *study_cadence(sseeds))
    add("ablation", *study_ablation(sseeds))
    add("sweep", *study_sweep(sseeds))
    add("capsweep", *study_cap_sweep(sseeds))
    add("adaptive", *study_adaptive(sseeds))
    add("pumping", *study_pumping(sseeds))
    add("spread", *study_spread(sseeds))
    add("dilution", *study_dilution(list(range(3 if a.quick else 5))))
    add("legit24h", *study_legit_only_24h(list(range(2 if a.quick else 5)), minutes=120 if a.quick else 24 * 60))
    add("outage", *study_outage(list(range(3 if a.quick else 8))))
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

    cfg_default = Config()
    cfg_default.sprt_legit_fast = max(0.005, legit_fast_share(cfg_default.fast_verify_seconds))   # as the sim sets it
    k_conv, k_fast = sends_to_verdict(cfg_default)
    R = {"meta": {"seeds": len(seeds), "sweep_seeds": len(sseeds), "runs": len(jobs), "wall_s": wall,
                  "calibration": CALIBRATION, "quick": a.quick,
                  "model": {"k_conv": k_conv, "k_fast": k_fast, "evasion_share": evasion_share(cfg_default),
                            "sprt_legit_fast": cfg_default.sprt_legit_fast}}}

    # A. multi-seed, every design, two modes
    A = {}
    for design in DESIGNS:
        g = group(*by[design], lambda i: (i[0], i[1]))
        for (mode, name), rs in g.items():
            A.setdefault(mode, {}).setdefault(name, {})[design] = summarise(rs)
    R["multi_seed"] = A

    # B. ablation (adaptive-caps mode): per (attacker, removed flag), with paired differences to full v2
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
            B[name][flag]["paired_delivered_diff"] = paired_difference(rs, full, ("friction", "delivered_pct"))
    R["ablation"] = B

    # B2. controller cadence
    Cd = {}
    g = group(*by["cadence"], lambda i: (i[0], i[1]))
    for (name, cname), rs in g.items():
        Cd.setdefault(name, {})[cname] = summarise(rs)
    R["cadence"] = Cd

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

    # F. pumping study: concentrated destination blocks, with and without a verifying carrier
    F = {}
    g = group(*by["pumping"], lambda i: (i[0], i[1]))
    for (aname, vname), rs in g.items():
        F.setdefault(aname, {})[vname] = summarise(rs)
    R["pumping"] = F

    # G. spread sweep and dilution curve
    G = {}
    g = group(*by["spread"], lambda i: (i[0], i[1], i[2]))
    for (verify, nb, digits), rs in g.items():
        G[f"verify={verify},blocks={nb},digits={digits}"] = summarise(rs)
        # the model takes the blocks the attack actually touched (requested), not the nominal pool
        G[f"verify={verify},blocks={nb},digits={digits}"]["predicted"] = mean_ci(
            [predicted_leak(cfg_default, r["attacker_blocks_requested"], r["spec"]["attacker"]["rate_per_min"], r["attack"]["requests"], verify > 0) for r in rs])
        G[f"verify={verify},blocks={nb},digits={digits}"]["blocks_nominal"] = blocks_touched(nb, digits)
    R["spread"] = G
    Dl = {}
    g = group(*by["dilution"], lambda i: i[0])
    for m, rs in g.items():
        Dl[str(m)] = summarise(rs)
    R["dilution"] = Dl

    # H. false positives of the block tests
    H = {"monte_carlo": {f"{n},{p},{f}": v for (n, p, f), v in
                         block_test_false_positives(cfg_default, trials=2_000 if a.quick else 20_000).items()}}
    g = group(*by["legit24h"], lambda i: (i[0], i[1], i[2], i[3]))
    H["legit_only"] = {f"calib={cal_},blocks={b},conv={c},autofill={af}": summarise_legit_only(rs) for (cal_, b, c, af), rs in g.items()}
    H["legit_only_seeds"] = len({i[4] for i in by["legit24h"][1]})
    g = group(*by["outage"], lambda i: (i[0], i[1]))
    H["outage"] = {f"{kind}|{v}": summarise_legit_only(rs) for (kind, v), rs in g.items()}
    R["false_positives"] = H

    # E. economics: only pumping attackers earn; v1 vs v2 default
    E = {}
    for mode in MODES:
        for name, a in ATTACKERS.items():
            E.setdefault(mode, {})[name] = economics(A[mode][name]["v1"], A[mode][name]["v2"], name, a.earns_revenue)
    for name, a in PUMPING_ATTACKERS.items():
        if a.earns_revenue:
            E.setdefault("pumping_study", {})[name] = economics(F[name]["v1"], F[name]["fine_key_plus_fast_resolution (default)"], name, True)
    R["economics"] = E

    (out / "evaluation.json").write_text(json.dumps(R, indent=1, default=str) + "\n")
    write_tradeoff_chart(R, out)
    write_spread_chart(R, out)
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


def write_spread_chart(R, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.4), dpi=150, sharey=True)
    fig.patch.set_facecolor("#fcfcfb")
    for ax, verify, title in ((axes[0], 0.0, "carrier does not verify"), (axes[1], 1.0, "carrier verifies within 1 s")):
        ax.set_facecolor("#fcfcfb")
        for i, digits in enumerate(SPREAD_RANGE_DIGITS):
            xs, ys, lo, hi = [], [], [], []
            for nb in SPREAD_BLOCKS:
                s = R["spread"][f"verify={verify},blocks={nb},digits={digits}"]
                xs.append(nb * 10 ** (12 - digits)); m, l, h_, _ = s["leaked_total"]; ys.append(m); lo.append(max(l, 0)); hi.append(h_)
            ax.plot(xs, ys, color=PALETTE[i], linewidth=2, marker="o", markersize=5, label=f"ranges of {SPREAD_RANGE_DIGITS[digits]} numbers")
            ax.fill_between(xs, lo, hi, color=PALETTE[i], alpha=0.15, linewidth=0)
        ax.set_xscale("log"); ax.set_title(title, loc="left", color="#0b0b0b", fontsize=10)
        ax.set_xlabel("distinct destination numbers the pumper spreads over", color="#0b0b0b")
        ax.grid(True, color="#e6e5e0", linewidth=0.8); ax.set_axisbelow(True)
        for sp in ("top", "right"): ax.spines[sp].set_visible(False)
        for sp in ("left", "bottom"): ax.spines[sp].set_color("#c3c2b7")
        ax.tick_params(colors="#52514e")
    axes[0].set_ylabel("SMS leaked in 20 minutes (of ~600 requests)", color="#0b0b0b")
    axes[0].legend(frameon=False, fontsize=8, loc="upper left")
    fig.suptitle("Pumper destination spread vs leakage (reputation key: 8 digits = 10 000 numbers)", x=0.01, ha="left", color="#0b0b0b", fontsize=11)
    fig.tight_layout()
    fig.savefig(out / "pumper_spread.png"); fig.savefig(out / "pumper_spread.svg"); plt.close(fig)


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
         "**with source caps** runs the source cap at 3x the legitimate rate: adaptive (baseline job and known-good "
         "exemption) for v2, static for v1, since the adaptive cap is v2's Step 9 and is behind the `adaptive_caps` flag.", ""]

    L += ["## A. Attacker profiles across designs", "",
          "Designs: `v1` (header-trusted platform, static caps); `v1_corrected` (v1 with attestation-derived platform); "
          "`budget_only` (attestation, sessions, static caps and the hard hourly budget, no scoring); `block_limit_only` "
          "(attestation, sessions, a flat 5-sends-per-destination-block-per-day limit, no scoring); `conversion_only` and "
          "`speed_only` (v2 with one of the two block tests off); `v2`.", "",
          "Columns: *contained* is the fraction of seeds in which leakage fell to 5 % of the attack rate and stayed there to the end of "
          "the run; *time to containment* is the mean over contained seeds only (uncontained runs are censored at 20 min and excluded); "
          "*late leak* is the mean leakage per minute after containment, or over the final five minutes of an uncontained run. "
          "Legitimate outcomes: *dispatched* (a channel was chosen), *delivered* (provider receipt), *completed* (code entered); "
          "*refused* includes undelivered sends. *First-time refused* is the refusal rate among clients without verified history.", ""]
    for mode in MODES:
        L += [f"### Mode: {mode.replace('_', ' ')}", "",
              "| Attacker | Design | Contained | Time to containment if contained (min) | Late leak (SMS/min) | Total leaked / 20 min | Defender cost (USD) | Legit dispatched % | Legit delivered % | Legit completed % | Legit challenged % | Legit refused % | First-time refused % | Returning refused % |",
              "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for name in ATTACKERS:
            for design in DESIGNS:
                s = R["multi_seed"][mode][name][design]
                L.append(f"| `{name}` | {design} | {s['contained_fraction']:.2f} | {ci(s['time_to_containment_if_contained_min'])} | "
                         f"{ci(s['steady_state_leak_per_min'])} | {ci(s['leaked_total'],0)} | {ci(s['attacker_cost_usd'],1)} | "
                         f"{ci(s['legit_dispatched_pct'])} | {ci(s['legit_delivered_pct'])} | {ci(s['legit_completed_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} | "
                         f"{ci(s['first_time_refusal_rate_pct'])} | {ci(s['returning_refusal_rate_pct'])} |")
        L.append("")
    L += ["Attacker descriptions:", ""] + [f"- `{n}`: {a.description}" for n, a in ATTACKERS.items()] + [""]

    L += ["## B. Ablation: leave one layer out (with adaptive caps)", "",
          f"Total leaked SMS over 20 minutes, mean over the same {meta['sweep_seeds']} seeds in every column, with the named layer switched off. "
          "`full v2` is the complete design on those seeds. Bold: removal raises leakage by more than 25 % (and at least 5 SMS).", ""]
    flags = sorted(ALL_FEATURES)
    L.append("| Attacker | full v2 | " + " | ".join(f"-{f}" for f in flags) + " |")
    L.append("|---|---:|" + "---:|" * len(flags))
    for name in ATTACKERS:
        ref = R["ablation"][name]["full"]["leaked_total"][0]
        cells = []
        for f in flags:
            v = R["ablation"][name][f]["leaked_total"][0]
            cells.append(f"**{v:.0f}**" if v > ref * 1.25 + 5 else f"{v:.0f}")
        L.append(f"| `{name}` | {ref:.0f} | " + " | ".join(cells) + " |")
    L += ["", "Paired per-seed differences against full v2 (same seeds, same offered workload): leaked SMS and legitimate "
          "delivery. A layer whose removal lowers leakage or raises delivery is costing something; a layer that blocks the same "
          "requests as another shows no difference here, so this is a marginal, not a total, contribution.", "",
          "| Attacker | Layer removed | Leaked: difference to full v2 | Legit delivered %: difference to full v2 | Legit delivered % without the layer |",
          "|---|---|---:|---:|---:|"]
    for name in ATTACKERS:
        for f in flags:
            s = R["ablation"][name][f]
            d1, d2 = s["paired_leak_diff"], s["paired_delivered_diff"]
            if abs(d1[0]) < 1 and abs(d2[0]) < 0.5:
                continue
            L.append(f"| `{name}` | -{f} | {d1[0]:+.0f} [{d1[1]:+.0f}, {d1[2]:+.0f}] | {d2[0]:+.1f} [{d2[1]:+.1f}, {d2[2]:+.1f}] | {ci(s['legit_delivered_pct'])} |")
    L += ["", "### B2. Controller cadence (with adaptive caps)", "",
          "The adaptive baseline job as the default worker runs it (every minute) against slower cadences. A 20-minute attack seen by an hourly job is a static cap.", "",
          "| Attacker | Cadence | Total leaked | Legit delivered % | First-time refused % |", "|---|---|---:|---:|---:|"]
    for name in R["cadence"]:
        for cname in CADENCES:
            s = R["cadence"][name][cname]
            L.append(f"| `{name}` | {cname} | {ci(s['leaked_total'],0)} | {ci(s['legit_delivered_pct'])} | {ci(s['first_time_refusal_rate_pct'])} |")
    L.append("")

    L += ["## C. Sensitivity and the leakage-friction trade-off", "",
          "![leakage vs friction](tradeoff.png)", "",
          "### C1. Risk weights, tier boundaries and the resolution timeout (behavioural-only mode)", "",
          "`resolution_timeout_s` is the reputation resolution window (an earlier version swept OTP validity instead, which left the "
          "effective window at 120 s throughout).", ""]
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
              "| Attacker | Contained | Time to containment if contained (min) | Late leak (SMS/min) | Total leaked | Attacker verifications | Challenges solved | Sessions refused at the gate | Blocks under verdict | Legit delivered % | Legit challenged % | Legit refused % | Legit hit by a verdict % |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for name in ADAPTIVE_ATTACKERS:
            s = R["adaptive_attackers"][mode][name]
            L.append(f"| `{name}` | {s['contained_fraction']:.2f} | {ci(s['time_to_containment_if_contained_min'])} | {ci(s['steady_state_leak_per_min'])} | {ci(s['leaked_total'],0)} | "
                     f"{ci(s['attacker_verifications'],0)} | {ci(s['attacker_challenges_solved'],0)} | {ci(s['attacker_sessions_refused'],0)} | {ci(s['block_verdicts'])} | "
                     f"{ci(s['legit_delivered_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} | {ci(s['legit_hit_by_verdict_pct'],2)} |")
        L.append("")
    L += ["Adaptive attacker descriptions:", ""] + [f"- `{n}`: {a.description}" for n, a in ADAPTIVE_ATTACKERS.items()] + [""]

    L += ["## F. Pumping on concentrated destination blocks (behavioural-only mode, 130-minute warm-up)", "",
          "The one key a pumper cannot rotate is the destination: it is paid only on the numbers its partner carrier terminates. "
          "Each attacker targets 3 blocks of 10 000 numbers inside a standard prefix. Variants: v1; the 24-hour cumulative ratio with a "
          "10-minute resolution timeout (the design as first written); the 8-digit destination-block key with sequential "
          "probability-ratio denylists; a 2-minute resolution timeout (late verifications are reclassified); both (the default); "
          "a relative baseline (recent hour versus the key's own history, which needs the long warm-up); all three.", "",
          "| Attacker | Variant | Contained | Time to containment (min) | Steady-state leak (SMS/min) | Total leaked | Attacker verifications (verified fake accounts) | Blocks under verdict | Legit delivered % | Legit challenged % | Legit refused % | Legit hit by a verdict |",
          "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for aname in PUMPING_ATTACKERS:
        for vname in PUMPING_VARIANTS:
            s = R["pumping"][aname][vname]
            L.append(f"| `{aname}` | {vname} | {s['contained_fraction']:.2f} | {ci(s['time_to_containment_min'])} | {ci(s['steady_state_leak_per_min'])} | {ci(s['leaked_total'],0)} | "
                     f"{ci(s['attacker_verifications'],0)} | {ci(s['block_verdicts'])} | {ci(s['legit_delivered_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} | {ci(s['legit_hit_by_verdict'])} |")
    L += ["", "Attacker descriptions:", ""] + [f"- `{n}`: {a.description}" for n, a in PUMPING_ATTACKERS.items()] + [""]

    L += ["## G. Pumper destination spread, and the dilution curve", "",
          "![pumper spread](pumper_spread.png)", "",
          "Spread sweep (behavioural-only, 10 seeds): the pumper's carrier serves 3, 30 or 300 ranges of 1 000, 10 000 or 100 000 "
          "numbers; the reputation key is the 8-digit block (10 000 numbers), so 1 000-number ranges sit inside one key, 10 000-number "
          "ranges align with it, and 100 000-number ranges span ten keys each. At the far end the pumper is the diluting flooder.", "",
          f"The closed-form model (`evaluation/model.py`): leak = min(N, k B + in-flight), with B the 8-digit blocks touched, "
          f"k = {R['meta']['model']['k_conv']} sends per block for a carrier that never verifies and k = {R['meta']['model']['k_fast']} for one "
          f"that verifies within a second (speed test calibrated to P(fast | real user) = {R['meta']['model']['sprt_legit_fast']:.3f}), and "
          f"in-flight = rate x (resolution timeout + delivery) for the former. A carrier evades the conversion test by verifying at least "
          f"{100 * R['meta']['model']['evasion_share']:.0f} % of its codes, at that many verified fake accounts per pumped SMS.", "",
          "Ranges are drawn without replacement across the seven standard prefixes. *Blocks requested* is the observed number of distinct "
          "8-digit blocks the attack actually touched in its ~600 requests (the model uses this, not the nominal pool); *blocks leaked* "
          "those that received at least one SMS.", "",
          "| Carrier verifies | Ranges | Numbers per range | Nominal blocks | Blocks requested (observed) | Blocks leaked | Total leaked (measured) | Model (observed blocks) | Error | Contained |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for verify in (0.0, 1.0):
        for nb in SPREAD_BLOCKS:
            for digits, label in SPREAD_RANGE_DIGITS.items():
                s = R["spread"][f"verify={verify},blocks={nb},digits={digits}"]
                L.append(f"| {'yes, within 1 s' if verify else 'no'} | {nb} | {label} | {s['blocks_nominal']} | {ci(s['attacker_blocks_requested'],0)} | {ci(s['attacker_blocks_leaked'],0)} | "
                         f"{ci(s['leaked_total'],0)} | {s['predicted'][0]:.0f} | {s['predicted'][0] - s['leaked_total'][0]:+.0f} | {s['contained_fraction']:.2f} |")
    L += ["", "Dilution curve (behavioural-only, 60-minute attack, 5 seeds): the captcha-farm attacker at multiples of the legitimate rate. "
          "The conversion penalty starts once the attacker exceeds about 1.8x the legitimate volume on the shared keys, but starting is not separating.", "",
          "| Attack rate / legitimate rate | Requests | Leaked | Leaked % of requests | Legit delivered % | Legit challenged % | Legit refused % |",
          "|---:|---:|---:|---:|---:|---:|---:|"]
    for m in DILUTION_MULTIPLES:
        s = R["dilution"][str(m)]
        pct = 100 * s["leaked_total"][0] / max(s["requests"][0], 1)
        L.append(f"| {m} | {ci(s['requests'],0)} | {ci(s['leaked_total'],0)} | {pct:.0f} % | {ci(s['legit_delivered_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} |")
    L.append("")

    H = R["false_positives"]
    L += ["## H. False positives of the destination-block tests", "",
          "The block tests were calibrated to the modelled legitimate population; this section asks what they do to real users "
          "when the population differs, over 24 hours, and during a carrier outage. A verdict in graded mode (the default) means "
          "the block's first-time clients must solve a challenge for an hour (a second verdict: non-SMS channels only); clients "
          "with verified history are never affected.", "",
          "### H1. Monte Carlo of the tests on one block seeing only legitimate traffic (one 24-hour window)", "",
          f"Tests as deployed: P(verify | user) = {Config().sprt_legit_conversion}, P(fast | user) = {R['meta']['model']['sprt_legit_fast']:.3f} "
          f"(5 s from delivery, 20 % autofill). Rows vary the true conversion and the true share of fast verifications. "
          f"Cells: probability that the block reaches a verdict (by conversion / by speed).", ""]
    for n in FP_SENDS_PER_BLOCK:
        L += [f"{n} legitimate sends on the block per day:", "", "| True conversion | " + " | ".join(f"fast share {f:.0%}" for f in FP_FAST_SHARES) + " |",
              "|---:|" + "---:|" * len(FP_FAST_SHARES)]
        for pconv in FP_CONVERSIONS:
            cells = []
            for f in FP_FAST_SHARES:
                v = H["monte_carlo"][f"{n},{pconv},{f}"]
                cells.append(f"{100 * (v['never_verified'] + v['machine_verified']):.2f} % ({100 * v['never_verified']:.2f} / {100 * v['machine_verified']:.2f})")
            L.append(f"| {pconv:.0%} | " + " | ".join(cells) + " |")
        L.append("")
    L += ["### H2. Twenty-four hours of legitimate traffic only, in the simulation", "",
          f"{H['legit_only_seeds']} seeds per cell, 20 requests/min, {'2 hours (quick run)' if R['meta']['quick'] else '24 hours'}; legitimate numbers drawn from a fixed set of blocks so that each block "
          "sees a realistic number of sends per day. Returning clients (20 %) carry verified history and are exempt from verdicts. "
          "Two calibration protocols: the speed test's legitimate-fast rate *fixed* at the deployed calibration (robustness to a population "
          "that differs from the assumption) and *recalibrated* to each population. Zero observed verdicts across a few seeds is an upper "
          "bound, not a zero risk; the Monte Carlo above gives the per-block probability.", "",
          "| Calibration | Sends per block per day | True conversion | Autofill share | Legit requests | Blocks under verdict (24 h) | Real users hit by a verdict | Delivered % | Challenged % | Refused % |",
          "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for calib in LEGIT_ONLY_CALIBRATION:
        for b, label in LEGIT_ONLY_BLOCKS.items():
            for c in LEGIT_ONLY_CONVERSIONS:
                for af in LEGIT_ONLY_AUTOFILL:
                    s = H["legit_only"][f"calib={calib},blocks={b},conv={c},autofill={af}"]
                    L.append(f"| {calib} | {label} | {c:.0%} | {af:.0%} | {ci(s['legit_users'],0)} | {ci(s['block_verdicts'])} | {ci(s['legit_hit_by_verdict'])} | "
                             f"{ci(s['legit_delivered_pct'])} | {ci(s['legit_challenge_rate_pct'])} | {ci(s['legit_refusal_rate_pct'])} |")
    L += ["", "### H3. A 30-minute carrier outage during legitimate traffic", "",
          "One prefix (a seventh of the traffic) stops delivering from minute 10 to 40 of a 60-minute run at 144 sends per block per day. "
          "`failed_receipts`: the provider reports every send as failed. `silent`: the provider reports delivery and nobody receives "
          "anything. With receipts, an undelivered send resolves as neither verified nor failed; the detector suspends the block tests "
          "on a carrier whose delivery collapses across many blocks, or whose returning clients stop verifying across many blocks.", "",
          "| Outage | Variant | Blocks under verdict | Real users hit by a verdict | Outage alerts | Delivered % |",
          "|---|---|---:|---:|---:|---:|"]
    for kind in ("failed_receipts", "silent"):
        for v in OUTAGE_VARIANTS:
            s = H["outage"][f"{kind}|{v}"]
            L.append(f"| {kind} | {v} | {ci(s['block_verdicts'])} | {ci(s['legit_hit_by_verdict'])} | {ci(s['outage_alerts'])} | {ci(s['legit_delivered_pct'])} |")
    L.append("")

    L += ["## E. Attacker economics (20-minute window)", "",
          "Revenue = leaked SMS x SMS termination price x revenue share (share is ASSUMED, low 0.2 and high 0.5), and only for "
          "pumping attackers: a flooder on random numbers is paid nothing, whatever leaks. Attacker cost = proxies (bytes x price per GB) "
          "+ CAPTCHA tokens + solved challenges. Defender cost = SMS + HLR lookups + reCAPTCHA assessments attributable to the attacker. "
          "Verified fake accounts: codes the attacker's carrier entered, each a registered account the defender now holds.", ""]
    for mode in list(MODES) + ["pumping_study"]:
        names = ATTACKERS if mode in MODES else {n: a for n, a in PUMPING_ATTACKERS.items() if a.earns_revenue}
        L += [f"### {'Mode: ' + mode.replace('_', ' ') if mode in MODES else 'Pumping study (v1 versus the v2 default: block key + 2-minute resolution)'}", "",
              "| Attacker | Design | Share | Leaked SMS | Attacker revenue (USD) | Attacker cost (USD) | Attacker profit (USD) | Defender cost (USD) | Verified fake accounts |",
              "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
        for name in names:
            for row in R["economics"][mode][name]:
                if not row["share"] and row is not R["economics"][mode][name][0]:
                    continue                                   # flooders: one row, no revenue
                L.append(f"| `{name}` | {row['design']} | {row['share'] or '–'} | {row['leaked_sms']:.0f} | {row['attacker_revenue_usd']:.2f} | {row['attacker_cost_usd']:.2f} | {row['attacker_profit_usd']:.2f} | {row['defender_cost_usd']:.2f} | {row['verified_fake_accounts']:.0f} |")
        L.append("")

    L += ["## Calibration sources", "", "| Parameter | Value | Source |", "|---|---|---|"]
    for k, v in CALIBRATION.items():
        L.append(f"| `{k}` | `{json.dumps(v['value'])}` | {v['source']} |")
    path.write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
