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
    """Leak share (mean of per-run shares, which removes attack-volume variation) with caps lifted and
    with source caps, and completion with source caps. Two rows of panels so the attacker labels have room."""
    ms = R["multi_seed"]
    names = [n for n in ATTACKER_LABELS if n in ms["behavioural_only"]]
    y = list(range(len(names)))
    fig, axes = plt.subplots(1, 3, figsize=(13.5, 6.0), sharey=True)
    panels = [("behavioural_only", "leak_fraction_pct", "(a) caps lifted: source caps removed,\nbehavioural layers only",
               "SMS leaked, mean of per-run % of attack requests"),
              ("with_adaptive_caps", "leak_fraction_pct", "(b) caps on: per-minute web caps at 3x legitimate,\nv1 static, v2 adaptive",
               "SMS leaked, mean of per-run % of attack requests"),
              ("with_adaptive_caps", "legit_completed_pct", "(c) caps on: legitimate users\ncompleting registration",
               "% of offered legitimate users completing")]
    designs = (("v1", C["orange"], "v1 (header-trusted platform, static caps)"), ("v2", C["blue"], "v2 (full design, adaptive caps)"))
    for ax, (mode, metric, title, xl) in zip(axes, panels):
        style(ax, title)
        for k, (design, col, label) in enumerate(designs):
            vals = [ms[mode][n][design][metric] for n in names]
            ax.barh([yy + (0.2 if k else -0.2) for yy in y], [v[0] for v in vals], height=0.36, color=col, label=label,
                    xerr=[[v[0] - v[1] for v in vals], [v[2] - v[0] for v in vals]],
                    error_kw=dict(ecolor=INK, elinewidth=1.1, capsize=3), edgecolor=SURFACE, linewidth=1.5)
        ax.set_yticks(y); ax.set_yticklabels([ATTACKER_LABELS[n] for n in names], color=INK, fontsize=10)
        ax.invert_yaxis(); ax.set_xlim(0, 105); ax.set_xlabel(xl, color=INK, fontsize=9.5)
    axes[0].legend(frameon=False, fontsize=9, loc="lower right")
    save(fig, out, "fig1_leakage")


def fig2_ablation(R, out):
    """Paired difference in leaked SMS, layer removed minus full design, every cell labelled; * marks
    cells whose bootstrap interval excludes zero (not adjusted for the 90 comparisons). The full matrix
    with intervals goes to a CSV, and the few large effects to a companion table."""
    B = R["ablation"]
    names = [n for n in ATTACKER_LABELS if n in B]
    layers = [l for l in LAYER_CODES if l in next(iter(B.values()))]
    d = [[B[n][l]["paired_leak_diff"] for l in layers] for n in names]
    vmax = max(5.0, max(abs(v[0]) for row in d for v in row))
    cmap = LinearSegmentedColormap.from_list("div", [C["blue"], "#d7d6d1", C["orange"]])
    fig, ax = plt.subplots(figsize=(13, 6.2))
    style(ax); ax.grid(False)
    im = ax.imshow([[v[0] for v in row] for row in d], cmap=cmap, norm=TwoSlopeNorm(vcenter=0, vmin=-vmax, vmax=vmax), aspect="auto")
    for i, row in enumerate(d):
        for j, (m, lo, hi, _) in enumerate(row):
            sig = lo > 0 or hi < 0
            txt = "0" if abs(m) < 0.5 and not sig else f"{m:+.0f}{'*' if sig else ''}"
            ax.text(j, i, txt, ha="center", va="center", fontsize=9.5, color=INK, fontweight="bold" if sig else "normal")
    ax.set_xticks(range(len(layers))); ax.set_xticklabels([LAYER_CODES[l].replace(" ", "\n", 1) for l in layers], color=INK, fontsize=9.5)
    ax.set_yticks(range(len(names))); ax.set_yticklabels([ATTACKER_LABELS[n] for n in names], color=INK, fontsize=10)
    ax.set_xlabel("layer removed (one at a time; conditional effects in this pipeline, they do not add up)", color=INK2)
    cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cb.set_label("SMS leaked: layer removed − full design\n* = paired 95 % interval excludes zero (unadjusted)", color=INK2)
    cb.ax.tick_params(colors=INK2)
    save(fig, out, "fig2_ablation")
    with open(out / "fig2_ablation_matrix.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attacker", "layer_removed", "leak_diff_mean", "leak_diff_lo", "leak_diff_hi", "completed_pp_diff_mean", "completed_pp_diff_lo", "completed_pp_diff_hi", "n_seeds"])
        for n in names:
            for l in layers:
                a, c = B[n][l]["paired_leak_diff"], B[n][l]["paired_completed_diff"]
                w.writerow([n, l, f"{a[0]:.2f}", f"{a[1]:.2f}", f"{a[2]:.2f}", f"{c[0]:.3f}", f"{c[1]:.3f}", f"{c[2]:.3f}", a[3]])
    # companion table: the effects that matter (interval excludes zero and at least 10 SMS)
    rows = []
    for n in names:
        for l in layers:
            a, c = B[n][l]["paired_leak_diff"], B[n][l]["paired_completed_diff"]
            if (a[1] > 0 or a[2] < 0) and abs(a[0]) >= 10:
                rows.append((abs(a[0]), n, l, a, c))
    rows.sort(reverse=True)
    L = ["| Attacker | Layer removed | Leaked SMS: paired difference [95 % interval] | Legitimate completion (pp) [95 % interval] |",
         "|---|---|---:|---:|"]
    for _, n, l, a, c in rows:
        L.append(f"| {ATTACKER_LABELS[n]} | {LAYER_CODES[l]} | {a[0]:+.0f} [{a[1]:+.0f}, {a[2]:+.0f}] | {c[0]:+.2f} [{c[1]:+.2f}, {c[2]:+.2f}] |")
    (out / "fig2_key_effects.md").write_text("Effects in Figure 2 whose paired interval excludes zero and whose mean is at least 10 SMS "
                                             "(unadjusted for multiplicity; all 90 cells are in fig2_ablation_matrix.csv).\n\n" + "\n".join(L) + "\n")


def fig3_dilution(R, out):
    D = R["dilution"]
    keys = sorted(D, key=float)
    xs = [float(k) for k in keys]
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.0))
    style(axes[0], "(a) SMS leaked, % of ATTACK requests (mean of per-run shares)")
    style(axes[1], "(b) legitimate harm, % of OFFERED LEGITIMATE users")
    fr = [D[k]["leak_fraction_pct"] for k in keys]
    axes[0].errorbar(xs, [v[0] for v in fr], yerr=[[v[0] - v[1] for v in fr], [v[2] - v[0] for v in fr]], color=C["blue"],
                     linewidth=2, marker="o", markersize=8, capsize=3, ecolor=INK)
    for x, v in zip(xs, fr):
        axes[0].annotate(f"{v[0]:.0f} %", (x, v[0]), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=10, color=INK)
    for ax in axes:
        ax.set_xscale("log")
        ax.set_xticks(xs); ax.set_xticklabels([f"{x:g}x" for x in xs], fontsize=10)
        ax.set_xlabel("attack rate as a multiple of the legitimate rate (log scale)", color=INK, fontsize=10)
    axes[0].set_ylim(0, 112)
    for metric, col, label in (("legit_challenge_rate_pct", C["orange"], "challenged"), ("legit_refusal_rate_pct", C["green"], "refused (never delivered)")):
        m = [D[k][metric] for k in keys]
        axes[1].plot(xs, [v[0] for v in m], color=col, linewidth=2, marker="o", markersize=8, label=label)
        axes[1].fill_between(xs, [v[1] for v in m], [v[2] for v in m], color=col, alpha=0.15, linewidth=0)
        axes[1].annotate(label, (xs[-1], m[-1][0]), textcoords="offset points", xytext=(-4, 8), ha="right", fontsize=10, color=INK)
    axes[1].legend(frameon=False, fontsize=10, loc="upper left")
    save(fig, out, "fig3_dilution")


class _Labels:
    """Places point labels, skipping any that would overlap one already placed (axes-fraction distance)."""
    def __init__(self, ax, dx=0.16, dy=0.05):
        self.ax, self.dx, self.dy, self.placed = ax, dx, dy, []

    def add(self, text, xy, force=False, **kw):
        ax = self.ax
        x0, x1 = ax.get_xlim(); y0, y1 = ax.get_ylim()
        fx, fy = (xy[0] - x0) / (x1 - x0), (xy[1] - y0) / (y1 - y0)
        if not force and any(abs(fx - px) < self.dx and abs(fy - py) < self.dy for px, py in self.placed):
            return False
        self.placed.append((fx, fy))
        ax.annotate(text, xy, textcoords="offset points", xytext=kw.pop("xytext", (6, 4)), fontsize=kw.pop("fontsize", 8.5), color=INK, **kw)
        return True


def _pareto(points):
    """Indices of points not dominated (lower x and lower y are better)."""
    keep = []
    for i, (x, y) in enumerate(points):
        if not any((x2 <= x and y2 <= y) and (x2 < x or y2 < y) for j, (x2, y2) in enumerate(points) if j != i):
            keep.append(i)
    return keep


def fig4_tradeoff(R, out):
    """The two families as separate panels: the source caps against refusal, the risk-score settings
    against challenge. Only decision-relevant points are labelled (the default and the points no other
    point beats on both axes); every point keeps its interval. Sampled points, not an optimised frontier."""
    farm_w = R["weight_sweep"]["residential_captcha_farm"]
    caps = R["cap_sweep"]["residential_captcha_farm"]
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.6))
    style(axes[0], "(a) source caps: floor x base multiple (16 settings)")
    style(axes[1], "(b) risk-score settings, one at a time")
    # (a) caps
    keys = list(caps)
    pts = [(caps[k]["legit_refusal_rate_pct"][0], caps[k]["leak_fraction_pct"][0]) for k in keys]
    front = set(_pareto(pts))
    for i, k in enumerate(keys):
        s = caps[k]
        is_def = k == "floor=0.25,mult=3.0"
        axes[0].errorbar(s["legit_refusal_rate_pct"][0], s["leak_fraction_pct"][0], xerr=err(s["legit_refusal_rate_pct"]),
                         yerr=err(s["leak_fraction_pct"]), fmt="*" if is_def else "o", color=C["blue"], ecolor=INK2, elinewidth=0.9,
                         markersize=14 if is_def else 7, markeredgecolor=INK if is_def else SURFACE, zorder=4 if is_def else 3)
    lab = _Labels(axes[0])
    order = sorted(range(len(keys)), key=lambda i: (keys[i] != "floor=0.25,mult=3.0", i not in front))
    for i in order:
        k = keys[i]
        if k == "floor=0.25,mult=3.0" or i in front:
            f, m = k.replace("floor=", "").split(",mult=")
            lab.add(("default: " if k == "floor=0.25,mult=3.0" else "") + f"floor {f}, x{m}", pts[i], force=k == "floor=0.25,mult=3.0")
    axes[0].set_xlabel("legitimate users refused, % of offered users", color=INK, fontsize=10)
    axes[0].set_ylabel("SMS leaked, % of attack requests (farm attacker)", color=INK, fontsize=10)
    # (b) risk-score families
    series = [("tier boundary scale", C["orange"], farm_w["tier_scale"], lambda k: f"tiers x{k}", "1.0"),
              ("fresh-fingerprint weight", C["green"], farm_w["fresh_fp_weight"], lambda k: f"fresh-fp weight {k}", "20"),
              ("conversion weight", C["yellow"], farm_w["conversion_weight"], lambda k: f"conversion weight {k}", "25")]
    allpts, allkeys = [], []
    for label, col, P, short, dflt in series:
        for k, s in P.items():
            allpts.append((s["legit_challenge_rate_pct"][0], s["leak_fraction_pct"][0])); allkeys.append((label, k))
    front = set(_pareto(allpts))
    todo = []
    for label, col, P, short, dflt in series:
        for k, s in P.items():
            idx = allkeys.index((label, k))
            is_def = k == dflt
            axes[1].errorbar(s["legit_challenge_rate_pct"][0], s["leak_fraction_pct"][0], xerr=err(s["legit_challenge_rate_pct"]),
                             yerr=err(s["leak_fraction_pct"]), fmt="*" if is_def else "o", color=col, ecolor=INK2, elinewidth=0.9,
                             markersize=14 if is_def else 7, markeredgecolor=INK if is_def else SURFACE, zorder=4 if is_def else 3)
            if (idx in front or k in ("40", "0.6", "30")) and not is_def:
                todo.append((short(k), allpts[idx]))
    lab = _Labels(axes[1])
    lab.add("defaults (coincide)", allpts[allkeys.index(("tier boundary scale", "1.0"))], force=True, xytext=(10, -16))
    for text, xy in todo:
        lab.add(text, xy)
    axes[1].set_xlabel("legitimate users challenged, % of offered users", color=INK, fontsize=10)
    handles = [Line2D([], [], marker="o", color=c, linestyle="", markersize=8, label=l) for l, c, _, _, _ in series] + \
              [Line2D([], [], marker="*", color=INK2, markersize=12, linestyle="", label="default setting")]
    axes[1].legend(handles=handles, frameon=False, fontsize=9, loc="center right")
    save(fig, out, "fig4_tradeoff")


def fig5_spread(R, out):
    """Measured leakage against the model on observed blocks, and every run's residual. A mechanism check
    on each run's observed blocks, not an independent forecast."""
    G = R["spread"]
    fig, axes = plt.subplots(2, 2, figsize=(13, 8.2), sharex="col", gridspec_kw={"height_ratios": [3, 2]})
    cols = {9: C["blue"], 8: C["orange"], 7: C["green"]}
    labels = {9: "ranges of 1 000 numbers", 8: "ranges of 10 000", 7: "ranges of 100 000"}
    jitter = {9: 0.94, 8: 1.0, 7: 1.06}
    for j, (verify, title) in enumerate(((0.0, "(a) carrier does not verify"), (1.0, "(b) carrier verifies within 1 s"))):
        style(axes[0][j], title); style(axes[1][j])
        for digits, col in cols.items():
            keys = sorted([k for k in G if k.startswith(f"verify={verify},") and k.endswith(f"digits={digits}")],
                          key=lambda k: G[k]["attacker_blocks_requested"][0])
            xs = [G[k]["attacker_blocks_requested"][0] * jitter[digits] for k in keys]
            meas = [G[k]["leaked_total"] for k in keys]
            axes[0][j].errorbar(xs, [m[0] for m in meas], yerr=[[m[0] - m[1] for m in meas], [m[2] - m[0] for m in meas]],
                                fmt="o", color=col, markersize=8, capsize=3, elinewidth=1, ecolor=INK2, label=f"{labels[digits]}: measured")
            axes[0][j].plot(xs, [G[k]["predicted"][0] for k in keys], color=col, linewidth=1.6, linestyle="--", label=f"{labels[digits]}: model (observed blocks)")
            for x, k in zip(xs, keys):
                sat = G[k]["residuals"]["n_saturated"] == G[k]["residuals"]["n"]
                axes[1][j].scatter([x] * len(G[k]["residuals"]["per_run"]), G[k]["residuals"]["per_run"], s=26, color=col,
                                   marker="x" if sat else "o", alpha=0.8, zorder=3)
        axes[0][j].set_xscale("log"); axes[1][j].axhline(0, color=INK, linewidth=1.6, zorder=2)
        axes[1][j].annotate("model = measured", (axes[1][j].get_xlim()[0], 0), textcoords="offset points", xytext=(4, 4), fontsize=9, color=INK)
        axes[1][j].set_xlabel("distinct 8-digit blocks the attack touched (observed; an input to the model)", color=INK, fontsize=10)
    axes[0][0].set_ylabel("SMS leaked in 20 minutes", color=INK, fontsize=10)
    axes[1][0].set_ylabel("per-run residual, SMS\n(model − measured)", color=INK, fontsize=10)
    axes[0][0].legend(frameon=False, fontsize=8.5, loc="upper left")
    axes[1][1].legend(handles=[Line2D([], [], marker="o", color=INK2, linestyle="", label="unsaturated (used for the error summaries)"),
                               Line2D([], [], marker="x", color=INK2, linestyle="", label="saturated: model predicts every request leaks")],
                      frameon=False, fontsize=9, loc="upper left")
    save(fig, out, "fig5_spread")


SHORT = {"none": "none", "sequential T1000 c1": "default (T1000, credit 1)"}


def _short(n):
    if n in SHORT:
        return SHORT[n]
    if n.startswith("sequential"):
        _, t, c = n.split()
        return f"T{t[1:]}, credit {c[1:]}"
    return n.replace("counter ", "").replace("/day", " a day").replace("/10 min", " per 10 min").replace("/60 min", " per hour")


def fig6_matched(R, out):
    """The matched comparison at 200 blocks. (a) every evaluated setting: benign completion (separate
    24-hour attack-free runs) against leakage summed over four attack-profile means (separate attack runs),
    with the benign service target; direct labels. (b) per-attacker paired differences in leakage against
    the default for the selected settings, so pairing is shown rather than inferred from marginal intervals."""
    M = R["matched"]
    density = "200"
    names = M["evaluate"][density]
    sel = M["selection"][density]
    fam_col = {"none": INK2, "sequential": C["blue"], "counter graded, daily": C["orange"], "counter graded, short window": C["green"],
               "counter refusing, daily": C["pink"]}

    def family(n):
        if n == "none":
            return "none"
        if n.startswith("sequential"):
            return "sequential"
        if "refuse" in n:
            return "counter refusing, daily"
        return "counter graded, short window" if "min" in n else "counter graded, daily"
    fig, axes = plt.subplots(1, 2, figsize=(15, 6.6), gridspec_kw={"width_ratios": [1.15, 1]})
    style(axes[0], "(a) benign completion against leakage, every evaluated setting")
    style(axes[1], "(b) leakage: paired difference to the default, per attacker")
    groups = {}
    for n in names:
        leg = M["legit"][density][n]["0.65"]["legit_completed_pct"]
        att = [M["attack"][n][x]["leaked_total"] for x in M["attack"][n]]
        y = sum(a[0] for a in att); ylo = sum(a[1] for a in att); yhi = sum(a[2] for a in att)
        col = fam_col[family(n)]
        is_def = n == "sequential T1000 c1"
        axes[0].errorbar(leg[0], y, xerr=err(leg), yerr=[[y - ylo], [yhi - y]], fmt="*" if is_def else "o", color=col, ecolor=INK2,
                         markersize=15 if is_def else 9, elinewidth=0.9, capsize=2, markeredgecolor=INK if is_def else SURFACE, zorder=3)
        for gk, members in groups.items():                  # points closer than the label size share one label
            if abs(gk[0] - leg[0]) < 0.06 and abs(gk[1] - y) < 120:
                members.append((n, leg[0], y))
                break
        else:
            groups[(leg[0], y)] = [(n, leg[0], y)]
    for (x0, y0), members in groups.items():
        axes[0].annotate("\n".join(_short(n) for n, _, _ in sorted(members, key=lambda m: -m[2])), (x0, y0), textcoords="offset points",
                         xytext=(9, 4), fontsize=9, color=INK, va="center")
    tgt = sel["service_target_completion_pct"]
    axes[0].axvline(tgt, color=INK, linestyle=":", linewidth=1.4)
    lo_y = axes[0].get_ylim()[0]
    axes[0].annotate("benign service target\n(default − 0.5 pp,\ntuning seeds)", (tgt, lo_y + 0.45 * (axes[0].get_ylim()[1] - lo_y)),
                     textcoords="offset points", xytext=(-6, 0), ha="right", fontsize=9, color=INK)
    axes[0].set_xlabel("legitimate users completing, %  (separate 24-hour ATTACK-FREE runs, 65 % conversion, 144 sends/block/day)",
                       color=INK, fontsize=9.5)
    axes[0].set_ylabel("SMS leaked in 20 min: SUM of four attack-profile means\n(separate attack runs)", color=INK, fontsize=10)
    # (b) paired differences for the selected settings
    chosen = [v for k, v in sel["chosen"].items() if v not in ("sequential T1000 c1",) and not k.startswith("matched false")]
    chosen = list(dict.fromkeys(chosen))
    atts = list(M["attack"]["none"])
    alab = {"concentrated_pumper_no_verify": "never verifies", "concentrated_pumper_verifies_instantly": "verifies instantly",
            "concentrated_pumper_verifies_humanlike": "verifies 60 %, human-like", "concentrated_pumper_solves_challenges": "solves challenges"}
    yy = 0
    yt, yl = [], []
    for a in atts:
        for n in chosen:
            d = M["attack"][n][a]["paired_leak_vs_default"]
            axes[1].errorbar(d[0], yy, xerr=err(d), fmt="o", color=fam_col[family(n)], ecolor=INK2, markersize=8, capsize=2)
            yt.append(yy); yl.append(f"{alab[a]} — {_short(n)}")
            yy += 1
        yy += 0.8
    axes[1].axvline(0, color=INK, linewidth=1.4)
    axes[1].set_yticks(yt); axes[1].set_yticklabels(yl, fontsize=8.5, color=INK); axes[1].invert_yaxis()
    axes[1].set_xlabel("SMS leaked: setting − default, paired per seed (negative = leaks less)", color=INK, fontsize=10)
    handles = [Line2D([], [], marker="o", color=c, linestyle="", markersize=9, label=f) for f, c in fam_col.items()] + \
              [Line2D([], [], marker="*", color=C["blue"], markersize=13, linestyle="", label="default")]
    axes[0].legend(handles=handles, frameon=False, fontsize=9, loc="upper left")
    save(fig, out, "fig6_matched")


def fig7_counter_boundary(CS, out):
    """The counter study's operating boundary (results/counter_study.json, E4): (a) completion lost
    because of the policy among the hot blocks' users, against the legitimate rate on those blocks,
    attack-free and under a pumper on the same blocks, at the modelled WhatsApp reachability; (b) leakage
    against the number of blocks a pumper spreads over, for the counter, the default and no policy."""
    E4 = CS["E4"]
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.4))
    style(axes[0], "(a) service: loss among the hot blocks' users (70 % WhatsApp)")
    style(axes[1], "(b) security: leakage against the pumper's spread")
    rates = sorted({float(k.split("|")[0]) for k in E4["service"]})
    for pol, col in (("counter graded 4/10 min", C["green"]), ("sequential T1000 c1", C["blue"])):
        for cond, ls in (("benign", "--"), ("attacked", "-")):
            ys, lo, hi = [], [], []
            for r in rates:
                key = f"{r:g}|0.7|{cond}|{pol}"
                key = key if key in E4["service"] else f"{r}|0.7|{cond}|{pol}"
                g = (E4["service"][key]["attributable_loss_vs_none"] or {}).get("hot_block", {}).get("net_lost_pct_of_group", (0, 0, 0, 0))
                ys.append(g[0]); lo.append(g[1]); hi.append(g[2])
            axes[0].plot(rates, ys, color=col, linestyle=ls, marker="o", markersize=7, linewidth=2,
                         label=f"{_short(pol)}, {'attack-free' if cond == 'benign' else 'pumper on the same blocks'}")
            axes[0].fill_between(rates, lo, hi, color=col, alpha=0.12, linewidth=0)
    axes[0].axvline(4, color=INK2, linestyle=":", linewidth=1.2)
    axes[0].annotate("counter quota:\n4 sends per 10 min", (4, axes[0].get_ylim()[1]), textcoords="offset points", xytext=(5, -26),
                     fontsize=9, color=INK)
    axes[0].set_xscale("log"); axes[0].set_xticks(rates); axes[0].set_xticklabels([f"{r:g}" for r in rates])
    axes[0].set_xlabel("legitimate sends per hot block per 10 minutes", color=INK, fontsize=10)
    axes[0].set_ylabel("completions lost because of the policy,\npp of the hot blocks' users", color=INK, fontsize=10)
    axes[0].legend(frameon=False, fontsize=8.5, loc="upper left")
    blocks = sorted({int(k.split("|")[0]) for k in E4["security"]})
    for pol, col in (("none", INK2), ("sequential T1000 c1", C["blue"]), ("counter graded 4/10 min", C["green"])):
        for kind, mk in (("spreading, never verifies", "o"), ("quota-aware", "s")):
            ys = [E4["security"][f"{b}|{kind}|60|{pol}"]["leaked_total"][0] for b in blocks]
            axes[1].plot(blocks, ys, color=col, marker=mk, markersize=7, linewidth=2, linestyle="-" if mk == "o" else "--",
                         label=f"{_short(pol)}: {kind}")
    axes[1].set_xscale("log"); axes[1].set_xticks(blocks); axes[1].set_xticklabels([str(b) for b in blocks])
    axes[1].set_xlabel("blocks the pumper spreads over (60-minute attack)", color=INK, fontsize=10)
    axes[1].set_ylabel("SMS leaked in 60 minutes", color=INK, fontsize=10)
    axes[1].legend(frameon=False, fontsize=8.5, loc="upper left")
    save(fig, out, "fig7_counter_boundary")


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
    cs = pathlib.Path(a.results) / "counter_study.json"
    if cs.exists():
        fig7_counter_boundary(json.loads(cs.read_text()), out)
        print("wrote fig7_counter_boundary")


if __name__ == "__main__":
    main()
