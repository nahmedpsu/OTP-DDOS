#!/usr/bin/env python3
"""Manuscript figures, drawn from the recorded results only (results/evaluation.json).

    python3 paper/figures.py [--results results] [--out paper/figures]

See paper/README.md for the figure-to-input mapping. Figures carry no titles: captions live in the
manuscript. Colours: a categorical palette checked for colour-vision-deficiency separation (blue,
orange, green, yellow, pink), a diverging blue/grey/orange scale for the ablation matrix; text in
ink colours, never in series colours; every series is also identified by a label or a legend.
Intervals are the 95 % percentile-bootstrap intervals recorded in evaluation.json.
"""
import argparse
import csv
import json
import pathlib

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                                          # noqa: E402
from matplotlib.colors import TwoSlopeNorm, LinearSegmentedColormap      # noqa: E402
from matplotlib.lines import Line2D                                      # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
SURFACE, INK, INK2, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#e6e5e0", "#c3c2b7"
C = {"blue": "#2a78d6", "orange": "#eb6834", "green": "#1baf7a", "yellow": "#eda100", "pink": "#e87ba4"}
plt.rcParams.update({"font.size": 9, "axes.titlesize": 9, "axes.labelsize": 9, "xtick.labelsize": 8.5, "ytick.labelsize": 8.5})
ATTACKER_LABELS = {
    "naive_single_client": "single client", "datacenter_rotation": "datacenter rotation",
    "residential_bot": "residential, bot CAPTCHA", "residential_captcha_farm": "residential, farmed CAPTCHA",
    "residential_aged_fps": "residential, aged fingerprints", "residential_reused_profile": "residential, reused profile",
    "sequential_numbers": "sequential numbers", "premium_pumping": "premium-prefix pumping", "spoofed_platform": "spoofed platform header",
}
LAYER_CODES = {"attestation": "L0 attestation", "session": "L1 session", "network_subnet_asn": "L2 network", "number_intelligence": "L5 numbers",
               "risk_engine": "L7 risk", "backoff": "L8 backoff", "adaptive_caps": "L9 adaptive caps", "circuit_breaker": "L10 breaker",
               "feedback": "FB loop", "fine_destination_key": "FB block key"}


def style(ax, title=None):
    ax.set_facecolor(SURFACE)
    ax.grid(True, color=GRID, linewidth=0.8); ax.set_axisbelow(True)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    for sp in ("left", "bottom"):
        ax.spines[sp].set_color(AXIS)
    ax.tick_params(colors=INK2)
    if title:
        ax.set_title(title, loc="left", color=INK)       # panel labels only; figure captions are in the manuscript


def save(fig, out, name):
    fig.patch.set_facecolor(SURFACE)
    fig.tight_layout()
    fig.savefig(out / f"{name}.png", dpi=220); fig.savefig(out / f"{name}.svg")
    plt.close(fig)


def err(v):
    m, lo, hi, _ = v
    return [[m - lo], [hi - m]]


def fig1_leakage(R, out):
    """Leak share (removes attack-volume variation) caps lifted and caps on, and completion caps on."""
    ms = R["multi_seed"]
    names = [n for n in ATTACKER_LABELS if n in ms["behavioural_only"]]
    y = list(range(len(names)))
    fig, axes = plt.subplots(1, 3, figsize=(11.5, 4.8), sharey=True)
    panels = [("behavioural_only", "leak_fraction_pct", "(a) SMS leaked, % of attack requests, caps lifted"),
              ("with_adaptive_caps", "leak_fraction_pct", "(b) SMS leaked, % of attack requests, with source caps"),
              ("with_adaptive_caps", "legit_completed_pct", "(c) legitimate users completing, %, with source caps")]
    designs = (("v1", C["orange"], "v1 (header-trusted platform, static caps)"), ("v2", C["blue"], "v2 (full design, adaptive caps)"))
    for ax, (mode, metric, title) in zip(axes, panels):
        style(ax, title)
        for k, (design, col, label) in enumerate(designs):
            vals = [ms[mode][n][design][metric] for n in names]
            ax.barh([yy + (0.19 if k else -0.19) for yy in y], [v[0] for v in vals], height=0.34, color=col, label=label,
                    xerr=[[v[0] - v[1] for v in vals], [v[2] - v[0] for v in vals]],
                    error_kw=dict(ecolor=INK2, elinewidth=0.8, capsize=2), edgecolor=SURFACE, linewidth=1)
        ax.set_yticks(y); ax.set_yticklabels([ATTACKER_LABELS[n] for n in names], color=INK)
        ax.invert_yaxis(); ax.set_xlim(0, 105)
    axes[0].legend(frameon=False, fontsize=8, loc="lower right")
    save(fig, out, "fig1_leakage")


def fig2_ablation(R, out):
    """Paired difference in leaked SMS, layer removed minus full design, every cell labelled; * marks
    cells whose bootstrap interval excludes zero. The full matrix with intervals goes to a CSV."""
    B = R["ablation"]
    names = [n for n in ATTACKER_LABELS if n in B]
    layers = [l for l in LAYER_CODES if l in next(iter(B.values()))]
    d = [[B[n][l]["paired_leak_diff"] for l in layers] for n in names]
    vmax = max(5.0, max(abs(v[0]) for row in d for v in row))
    cmap = LinearSegmentedColormap.from_list("div", [C["blue"], "#d7d6d1", C["orange"]])
    fig, ax = plt.subplots(figsize=(10.5, 5.2))
    style(ax); ax.grid(False)
    im = ax.imshow([[v[0] for v in row] for row in d], cmap=cmap, norm=TwoSlopeNorm(vcenter=0, vmin=-vmax, vmax=vmax), aspect="auto")
    for i, row in enumerate(d):
        for j, (m, lo, hi, _) in enumerate(row):
            sig = lo > 0 or hi < 0
            ax.text(j, i, f"{m:+.0f}{'*' if sig else ''}", ha="center", va="center", fontsize=7.5, color=INK,
                    fontweight="bold" if sig else "normal")
    ax.set_xticks(range(len(layers))); ax.set_xticklabels([LAYER_CODES[l] for l in layers], rotation=30, ha="right", color=INK)
    ax.set_yticks(range(len(names))); ax.set_yticklabels([ATTACKER_LABELS[n] for n in names], color=INK)
    cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02); cb.set_label("SMS leaked: layer removed − full design", color=INK2); cb.ax.tick_params(colors=INK2)
    save(fig, out, "fig2_ablation")
    with open(out / "fig2_ablation_matrix.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attacker", "layer_removed", "leak_diff_mean", "leak_diff_lo", "leak_diff_hi", "completed_pp_diff_mean", "completed_pp_diff_lo", "completed_pp_diff_hi", "n_seeds"])
        for n in names:
            for l in layers:
                a, c = B[n][l]["paired_leak_diff"], B[n][l]["paired_completed_diff"]
                w.writerow([n, l, f"{a[0]:.2f}", f"{a[1]:.2f}", f"{a[2]:.2f}", f"{c[0]:.3f}", f"{c[1]:.3f}", f"{c[2]:.3f}", a[3]])


def fig3_dilution(R, out):
    D = R["dilution"]
    keys = sorted(D, key=float)
    xs = [float(k) for k in keys]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
    style(axes[0], "(a) SMS leaked, % of attack requests (per-run share)")
    style(axes[1], "(b) legitimate harm, % of users")
    fr = [D[k]["leak_fraction_pct"] for k in keys]
    axes[0].errorbar(xs, [v[0] for v in fr], yerr=[[v[0] - v[1] for v in fr], [v[2] - v[0] for v in fr]], color=C["blue"],
                     linewidth=2, marker="o", markersize=6, capsize=3)
    for x, v in zip(xs, fr):
        axes[0].annotate(f"{v[0]:.0f} %", (x, v[0]), textcoords="offset points", xytext=(0, 8), ha="center", fontsize=8, color=INK2)
    axes[0].set_xscale("log"); axes[0].set_ylim(0, 110); axes[0].set_xlabel("attack rate / legitimate rate", color=INK)
    for metric, col, label in (("legit_challenge_rate_pct", C["orange"], "challenged"), ("legit_refusal_rate_pct", C["green"], "refused")):
        m = [D[k][metric] for k in keys]
        axes[1].plot(xs, [v[0] for v in m], color=col, linewidth=2, marker="o", markersize=6, label=label)
        axes[1].fill_between(xs, [v[1] for v in m], [v[2] for v in m], color=col, alpha=0.15, linewidth=0)
    axes[1].set_xscale("log"); axes[1].set_xlabel("attack rate / legitimate rate", color=INK); axes[1].legend(frameon=False)
    save(fig, out, "fig3_dilution")


def fig4_tradeoff(R, out):
    """Every one-at-a-time sweep point for the farm attacker, with intervals and setting labels; the
    default is marked. Sampled points, not an optimised frontier."""
    farm_w = R["weight_sweep"]["residential_captcha_farm"]
    series = [("cap floor x base multiple", C["blue"], R["cap_sweep"]["residential_captcha_farm"], lambda k: k.replace("floor=", "f").replace(",mult=", " m")),
              ("tier boundary scale", C["orange"], farm_w["tier_scale"], lambda k: f"x{k}"),
              ("fresh-fingerprint weight", C["green"], farm_w["fresh_fp_weight"], lambda k: f"w{k}"),
              ("conversion weight", C["yellow"], farm_w["conversion_weight"], lambda k: f"c{k}")]
    defaults = {"cap floor x base multiple": "floor=0.25,mult=3.0", "tier boundary scale": "1.0", "fresh-fingerprint weight": "20",
                "conversion weight": "25"}
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8), sharey=True)
    style(axes[0], "(a) against legitimate users refused, %"); style(axes[1], "(b) against legitimate users challenged, %")
    for ax, metric in ((axes[0], "legit_refusal_rate_pct"), (axes[1], "legit_challenge_rate_pct")):
        for label, col, pts, short in series:
            for k, s in pts.items():
                x, y = s[metric], s["leak_fraction_pct"]
                is_def = k == defaults[label]
                ax.errorbar(x[0], y[0], xerr=err(x), yerr=err(y), fmt="*" if is_def else "o", color=col, markersize=11 if is_def else 5,
                            elinewidth=0.6, capsize=0, markeredgecolor=INK if is_def else SURFACE, zorder=4 if is_def else 3)
                if ax is axes[0]:
                    ax.annotate(short(k), (x[0], y[0]), textcoords="offset points", xytext=(4, 2), fontsize=6, color=INK2)
    axes[0].set_ylabel("SMS leaked, % of attack requests", color=INK)
    handles = [Line2D([], [], marker="o", color=c, linestyle="", label=l) for l, c, _, _ in series] + \
              [Line2D([], [], marker="*", color=INK2, markersize=10, linestyle="", label="default setting")]
    axes[1].legend(handles=handles, frameon=False, fontsize=8, loc="upper right")
    save(fig, out, "fig4_tradeoff")


def fig5_spread(R, out):
    """Measured leakage against the model on observed blocks, and every run's residual."""
    G = R["spread"]
    fig, axes = plt.subplots(2, 2, figsize=(10.5, 6.6), sharex="col", gridspec_kw={"height_ratios": [3, 1.6]})
    cols = {9: C["blue"], 8: C["orange"], 7: C["green"]}
    labels = {9: "ranges of 1 000", 8: "ranges of 10 000", 7: "ranges of 100 000"}
    jitter = {9: 0.94, 8: 1.0, 7: 1.06}
    for j, (verify, title) in enumerate(((0.0, "(a) carrier does not verify"), (1.0, "(b) carrier verifies within 1 s"))):
        style(axes[0][j], title); style(axes[1][j])
        for digits, col in cols.items():
            keys = sorted([k for k in G if k.startswith(f"verify={verify},") and k.endswith(f"digits={digits}")],
                          key=lambda k: G[k]["attacker_blocks_requested"][0])
            xs = [G[k]["attacker_blocks_requested"][0] * jitter[digits] for k in keys]
            meas = [G[k]["leaked_total"] for k in keys]
            axes[0][j].errorbar(xs, [m[0] for m in meas], yerr=[[m[0] - m[1] for m in meas], [m[2] - m[0] for m in meas]],
                                fmt="o", color=col, markersize=6, capsize=2, elinewidth=0.8, label=f"{labels[digits]}: measured")
            axes[0][j].plot(xs, [G[k]["predicted"][0] for k in keys], color=col, linewidth=1.4, linestyle="--", label=f"{labels[digits]}: model")
            for x, k in zip(xs, keys):
                sat = G[k]["residuals"]["n_saturated"] == G[k]["residuals"]["n"]
                axes[1][j].scatter([x] * len(G[k]["residuals"]["per_run"]), G[k]["residuals"]["per_run"], s=12, color=col,
                                   marker="x" if sat else "o", alpha=0.75, zorder=3)
        axes[0][j].set_xscale("log"); axes[1][j].axhline(0, color=INK2, linewidth=0.8)
        axes[1][j].set_xlabel("distinct 8-digit blocks the attack touched (observed; an input to the model)", color=INK)
    axes[0][0].set_ylabel("SMS leaked in 20 min", color=INK); axes[1][0].set_ylabel("per-run residual\n(model − measured)", color=INK)
    axes[0][0].legend(frameon=False, fontsize=7, loc="upper left")
    axes[1][1].legend(handles=[Line2D([], [], marker="o", color=INK2, linestyle="", label="unsaturated configuration"),
                               Line2D([], [], marker="x", color=INK2, linestyle="", label="saturated (model predicts every request leaks)")],
                      frameon=False, fontsize=7, loc="upper left")
    save(fig, out, "fig5_spread")


def fig6_matched(R, out):
    """The matched comparison at 200 blocks: completion (with interval) against leakage summed over the
    four pumpers (with interval), for the settings evaluated on the held-out seeds; challenge burden in a
    separate panel; a numbered key instead of stacked labels."""
    M = R["matched"]
    density = "200"
    names = M["evaluate"][density]
    fam_col = {"none": INK2, "sequential": C["blue"], "counter_graded_daily": C["orange"], "counter_graded_short": C["green"],
               "counter_refuse_daily": C["pink"]}

    def family(n):
        if n == "none":
            return "none"
        if n.startswith("sequential"):
            return "sequential"
        if "refuse" in n:
            return "counter_refuse_daily"
        return "counter_graded_short" if "min" in n else "counter_graded_daily"
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8))
    style(axes[0], "(a) leakage against legitimate completion"); style(axes[1], "(b) leakage against legitimate challenge burden")
    key = []
    labels = {0: {}, 1: {}}                                  # coincident points share one label
    for i, n in enumerate(names, 1):
        leg = M["legit"][density][n]["0.65"]
        att = [M["attack"][n][x]["leaked_total"] for x in M["attack"][n]]
        y = sum(a[0] for a in att); ylo = sum(a[1] for a in att); yhi = sum(a[2] for a in att)
        col = fam_col[family(n)]
        for k, (ax, metric) in enumerate(((axes[0], "legit_completed_pct"), (axes[1], "legit_challenge_rate_pct"))):
            x = leg[metric]
            ax.errorbar(x[0], y, xerr=err(x), yerr=[[y - ylo], [yhi - y]], fmt="*" if n == "sequential T1000 c1" else "o", color=col,
                        markersize=11 if n == "sequential T1000 c1" else 6, elinewidth=0.7, capsize=2, zorder=3)
            labels[k].setdefault((round(x[0], 2), round(y, 0)), []).append(str(i))
        key.append(f"{i}: {n}")
    for k, ax in enumerate(axes):
        for (x, y), ids in labels[k].items():
            ax.annotate(",".join(ids), (x, y), textcoords="offset points", xytext=(5, 3), fontsize=7.5, color=INK)
    axes[0].set_xlabel("legitimate users completing, % (65 % conversion, 144 sends/block/day, 24 h)", color=INK)
    axes[1].set_xlabel("legitimate users challenged, %", color=INK)
    axes[0].set_ylabel("SMS leaked in 20 min, four concentrated pumpers combined", color=INK)
    handles = [Line2D([], [], marker="o", color=c, linestyle="", label=f.replace("_", " ")) for f, c in fam_col.items()] + \
              [Line2D([], [], marker="*", color=C["blue"], markersize=10, linestyle="", label="default (T1000 c1)")]
    axes[1].legend(handles=handles, frameon=False, fontsize=7.5, loc="upper right")
    rows = [key[i:i + 4] for i in range(0, len(key), 4)]
    fig.text(0.01, -0.02 - 0.035 * (len(rows) - 1), "\n".join("     ".join(r) for r in rows), fontsize=7, color=INK2, va="top")
    fig.tight_layout()
    fig.patch.set_facecolor(SURFACE)
    fig.savefig(out / "fig6_matched.png", dpi=220, bbox_inches="tight"); fig.savefig(out / "fig6_matched.svg", bbox_inches="tight")
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--out", default=str(ROOT / "paper" / "figures"))
    a = ap.parse_args()
    R = json.loads((pathlib.Path(a.results) / "evaluation.json").read_text())
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("fig6_detectors.*"):
        old.unlink()
    for fn in (fig1_leakage, fig2_ablation, fig3_dilution, fig4_tradeoff, fig5_spread, fig6_matched):
        fn(R, out)
        print("wrote", fn.__name__)


if __name__ == "__main__":
    main()
