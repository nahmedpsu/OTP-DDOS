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
from matplotlib.ticker import NullFormatter                              # noqa: E402

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


def save(fig, out, name, rect=None, tight=True):
    fig.patch.set_facecolor(SURFACE)
    if tight:
        fig.tight_layout(rect=rect) if rect else fig.tight_layout()
    fig.savefig(out / f"{name}.png", dpi=220); fig.savefig(out / f"{name}.svg"); fig.savefig(out / f"{name}.pdf")
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
    h, lab = axes[0].get_legend_handles_labels()            # below the panels: no bar is covered
    fig.legend(h, lab, frameon=False, fontsize=9.5, loc="lower center", ncol=2)
    save(fig, out, "fig1_leakage", rect=(0, 0.06, 1, 1))


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
    fig, ax = plt.subplots(figsize=(10.5, 6.0))
    style(ax); ax.grid(False)
    im = ax.imshow([[v[0] for v in row] for row in d], cmap=cmap, norm=TwoSlopeNorm(vcenter=0, vmin=-vmax, vmax=vmax), aspect="auto")
    for i, row in enumerate(d):
        for j, (m, lo, hi, _) in enumerate(row):
            sig = lo > 0 or hi < 0
            txt = "0" if abs(m) < 0.5 and not sig else f"{m:+.0f}{'*' if sig else ''}"
            ax.text(j, i, txt, ha="center", va="center", fontsize=11, color=INK, fontweight="bold" if sig else "normal")
    ax.set_xticks(range(len(layers))); ax.set_xticklabels([LAYER_CODES[l].replace(" ", "\n") for l in layers], color=INK, fontsize=9.5)
    ax.set_yticks(range(len(names))); ax.set_yticklabels([ATTACKER_LABELS[n] for n in names], color=INK, fontsize=11)
    ax.set_xlabel("layer removed (one at a time; conditional effects in this pipeline, they do not add up)", color=INK2, fontsize=10.5)
    cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cb.set_label("SMS leaked: layer removed − full design\n* = paired 95 % interval excludes zero (unadjusted)", color=INK2, fontsize=10)
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
        ax.annotate(text, xy, textcoords="offset points", xytext=kw.pop("xytext", (6, 4)), fontsize=kw.pop("fontsize", 10), color=INK, **kw)
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
    fig, axes = plt.subplots(2, 1, figsize=(9.5, 10.5))
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


# Plain-language names for the matched-comparison settings (Figures 6 and 7 of revision 8). The body text
# keeps the short notation (T300, c0) beside these names, so a reader can move between figure and text.
PLAIN = {"none": "no policy",
         "sequential T1000 c1": "default tests (threshold 1 000, credit 1)",
         "sequential T300 c0": "tests selected at the target (threshold 300, no credit)",
         "counter graded 160/day": "graded counter, 160 sends a day",
         "counter graded 4/10 min": "graded counter, 4 sends per 10 minutes",
         "counter refuse 320/day": "refusing counter, 320 sends a day"}
# one hue per family (tests blue, graded counters green, the refusing counter orange, no policy grey:
# three hues pass the all-pairs colour-vision check) and one marker shape per setting kind
FAMILY = {"none": ("no destination policy", INK2, "o"),
          "sequential": ("sequential tests of code outcomes", C["blue"], "o"),
          "counter graded, daily": ("graded counter, quota per day", C["green"], "s"),
          "counter graded, short window": ("graded counter, quota per 10 minutes", C["green"], "^"),
          "counter refusing, daily": ("refusing counter, quota per day", C["orange"], "D")}
PLAIN_SHORT = {"none": "no policy", "sequential T300 c0": "selected tests (threshold 300, no credit)",
               "counter graded 160/day": "graded counter, 160 a day", "counter graded 4/10 min": "graded counter, 4 per 10 minutes",
               "counter refuse 320/day": "refusing counter, 320 a day"}
CARRIER = {"concentrated_pumper_no_verify": "the pumper's carrier never enters a code",
           "concentrated_pumper_verifies_instantly": "the carrier enters every code within a second",
           "concentrated_pumper_verifies_humanlike": "the carrier enters 60 % of codes, human-like delay",
           "concentrated_pumper_solves_challenges": "the pumper buys every challenge solution"}


def _family(n):
    if n == "none":
        return "none"
    if n.startswith("sequential"):
        return "sequential"
    if "refuse" in n:
        return "counter refusing, daily"
    return "counter graded, short window" if "min" in n else "counter graded, daily"


def _plain(n):
    if n in PLAIN:
        return PLAIN[n]
    if n.startswith("sequential"):
        _, t, c = n.split()
        credit = "no credit" if c == "c0" else "unbounded credit" if c == "cinf" else f"credit {c[1:]}"
        return f"tests (threshold {int(t[1:]):,}, {credit})".replace(",", " ")
    return n


def _matched_sums(runs_path):
    """Per setting: leakage summed over the four pumpers' runs of each evaluation seed, with a 95 %
    percentile-bootstrap interval over the seeds (the vertical bars of fig6_matched_a)."""
    import gzip, sys
    sys.path.insert(0, str(ROOT / "src"))
    from otp_guard.evaluation.stats import boot_ci
    acc = {}
    with gzip.open(runs_path, "rt") as f:
        for line in f:
            r = json.loads(line)
            if r.get("study") != "matched_eval" or r["index"][0] != "attack":
                continue
            _, _, setting, attacker, seed = r["index"]
            acc.setdefault(setting, {}).setdefault(seed, []).append(r["attack"]["leaked_total"])
    return {n: boot_ci([sum(v) for v in by.values() if len(v) == 4]) for n, by in acc.items()}


def fig6_matched(R, out, runs_path=ROOT / "results" / "evaluation_runs.jsonl.gz"):
    """The matched comparison at 200 blocks, as two figures so each has the full text width.
    fig6_matched_a: every evaluated setting, benign completion (separate 24-hour attack-free runs)
    against leakage summed over the four pumpers' runs of a seed (separate attack runs), with the
    tuning target; the reference and selected settings carry plain-language labels and the three
    settings matched to the default's false alarms share one note. fig6_matched_b: per-carrier paired
    differences in leakage against the default for the selected settings, grouped by carrier."""
    M = R["matched"]
    density = "200"
    names = M["evaluate"][density]
    sel = M["selection"][density]
    chosen = [v for k, v in sel["chosen"].items() if v not in ("sequential T1000 c1",) and not k.startswith("matched false")]
    chosen = list(dict.fromkeys(chosen))
    labelled = set(chosen) | {"none", "sequential T1000 c1"}
    matched = [v for k, v in sel["chosen"].items() if k.startswith("matched false") and v != "sequential T1000 c1"]
    sums = _matched_sums(runs_path) if pathlib.Path(runs_path).exists() else {}
    # (a) completion against leakage
    fig, ax = plt.subplots(figsize=(8.6, 5.5))
    style(ax)
    ax.tick_params(labelsize=10.5)
    pts = {}
    for n in names:
        leg = M["legit"][density][n]["0.65"]["legit_completed_pct"]
        att = [M["attack"][n][x]["leaked_total"] for x in M["attack"][n]]
        y, ylo, yhi = sums[n][:3] if n in sums else (sum(a[0] for a in att), sum(a[1] for a in att), sum(a[2] for a in att))
        _, col, mk = FAMILY[_family(n)]
        is_def = n == "sequential T1000 c1"
        ax.errorbar(leg[0], y, xerr=err(leg), yerr=[[y - ylo], [yhi - y]], fmt="*" if is_def else mk, color=col, ecolor=AXIS,
                    markersize=16 if is_def else 9.5, elinewidth=0.9, capsize=2, markeredgecolor=INK if is_def else SURFACE,
                    markeredgewidth=0.8, zorder=3)
        pts[n] = (leg[0], y)
    # direct labels, offset so that the two coinciding points (no policy and the refusing counter) both read
    offsets = {"none": (10, 13), "counter refuse 320/day": (10, -9), "sequential T1000 c1": (12, -13),
               "sequential T300 c0": (10, 11), "counter graded 160/day": (10, 7), "counter graded 4/10 min": (10, 7)}
    for n in labelled:
        ax.annotate(_plain(n), pts[n], textcoords="offset points", xytext=offsets.get(n, (9, 5)), fontsize=10.5, color=INK, va="center",
                    bbox=dict(boxstyle="round,pad=0.12", fc=SURFACE, ec="none", alpha=0.9))
    # the three settings matched to the default's false alarms, one note for all three
    if matched:
        mx = sum(pts[n][0] for n in matched) / len(matched); my = max(pts[n][1] for n in matched)
        ax.annotate("test settings matched to the default's\nfalse alarms at other credits (one under the star)", (mx, my),
                    textcoords="offset points", xytext=(28, 64), fontsize=10, color=INK2, ha="left", va="bottom",
                    arrowprops=dict(arrowstyle="-", color=INK2, linewidth=0.8, shrinkB=6))
    tgt = sel["service_target_completion_pct"]
    ax.axvline(tgt, color=INK, linestyle=":", linewidth=1.4)
    y0, y1 = ax.get_ylim()
    ax.annotate("tuning target:\nthe default's completion\nminus 0.5 points", (tgt, y0 + 0.47 * (y1 - y0)),
                textcoords="offset points", xytext=(-7, 0), ha="right", va="center", fontsize=10, color=INK)
    ax.set_xlabel("legitimate users who complete registration, %  (attack-free, 24 hours, 65 % conversion)", color=INK, fontsize=11)
    ax.set_ylabel("SMS leaked to the four pumpers in 20 minutes\n(the four attacks of a seed, summed)", color=INK, fontsize=11)
    x0, x1 = ax.get_xlim()
    ax.set_xlim(x0, x1 + 0.34 * (x1 - x0))
    handles = [Line2D([], [], marker=mk, color=col, linestyle="", markersize=9, label=lab) for lab, col, mk in FAMILY.values()] + \
              [Line2D([], [], marker="*", color=C["blue"], markeredgecolor=INK, markersize=14, linestyle="", label="the default tests")]
    ax.legend(handles=handles, frameon=False, fontsize=10, loc="upper left", title="bars: 95 % intervals over the ten evaluation seeds",
              title_fontsize=9.5, alignment="left")
    save(fig, out, "fig6_matched_a")
    # (b) each selected setting against the default, carrier by carrier
    atts = list(M["attack"]["none"])
    fig, ax = plt.subplots(figsize=(9.0, 6.4))
    style(ax)
    ax.tick_params(labelsize=10.5)
    yy = 0.0
    yt, yl, heads = [], [], []
    for a in atts:
        heads.append((yy, CARRIER[a]))
        yy += 1
        for n in chosen:
            d = M["attack"][n][a]["paired_leak_vs_default"]
            _, col, mk = FAMILY[_family(n)]
            ax.errorbar(d[0], yy, xerr=err(d), fmt=mk, color=col, ecolor=INK2, markersize=8.5, capsize=2, markeredgecolor=SURFACE,
                        markeredgewidth=0.8, zorder=3)
            yt.append(yy); yl.append(PLAIN_SHORT.get(n, _plain(n)))
            yy += 1
        yy += 0.6
    ax.axvline(0, color=INK, linewidth=1.4)
    ax.set_yticks(yt); ax.set_yticklabels(yl, fontsize=11, color=INK)
    ax.set_ylim(yy - 0.6, -0.8); ax.tick_params(axis="y", length=0)
    for y, text in heads:
        ax.text(-0.012, y, text, transform=ax.get_yaxis_transform(), ha="right", va="center", fontsize=11, color=INK, fontweight="bold")
    ax.annotate("the default tests", (0, -0.75), textcoords="offset points", xytext=(0, 2), ha="center", va="bottom", fontsize=10, color=INK)
    ax.set_xlabel("SMS leaked to the pumper in 20 minutes, setting minus the default tests\n"
                  "(left of zero: leaks less than the default; paired per seed; bars: 95 % intervals over ten seeds)",
                  color=INK, fontsize=10.5, loc="right")
    save(fig, out, "fig6_matched_b")


def unfitted_estimates(runs_path, kind="spreading, never verifies", minutes=60):
    """Equations 2 and 3 for the E4 security runs, from each run's offered requests N, requested blocks B
    and offered rate N / minutes, with tau from the configuration (otp_guard.evaluation.model); means over
    seeds per block count. Nothing is fitted to E4."""
    import gzip, math, sys
    sys.path.insert(0, str(ROOT / "src"))
    from otp_guard.config import Config
    from otp_guard.evaluation.model import predicted_leak
    cfg, acc = Config(), {}
    with gzip.open(runs_path, "rt") as f:
        for line in f:
            r = json.loads(line)
            if r.get("study") != "E4" or r["index"][0] != "security":
                continue
            _, nb, k, mins, pol, _s = r["index"]
            if k != kind or mins != minutes or pol != "counter graded 4/10 min":
                continue
            N, B = r["attack"]["requests"], r["attacker_blocks_requested"]
            acc.setdefault(nb, []).append((predicted_leak(cfg, B, N / mins, N, False), min(N, 4 * B * math.ceil(mins / 10))))
    return {nb: {"tests_estimate": sum(x for x, _ in v) / len(v), "counter_bound": sum(y for _, y in v) / len(v)} for nb, v in acc.items()}


def fig7_counter_boundary(CS, out, runs_path=ROOT / "results" / "counter_study_runs.jsonl.gz", cond_path=None):
    """The counter study's operating boundary (results/counter_study.json, E4): (a) completion lost
    because of the policy among the hot blocks' users, against the legitimate rate on those blocks,
    attack-free and under a pumper on the same blocks, at the modelled WhatsApp reachability; (b, c)
    leakage in 20 and 60 minutes against the number of blocks a pumper spreads over, for the counter, the
    default and no policy (means over five seeds with 95 % bootstrap intervals), with Equation 2's
    estimate for the tests and Equations 3 (cold start) and 4 (warm start) for the counter, from each
    run's inputs (results/condition_check.json; seventh-round review, M2)."""
    import matplotlib.gridspec as gridspec
    E4 = CS["E4"]
    cond = json.loads(pathlib.Path(cond_path).read_text()) if cond_path and pathlib.Path(cond_path).exists() else None
    # Printed at the text width (5.4 in), so the figure is drawn at 7.6 in and fonts of 12-13 pt print at about 9 pt; its
    # height keeps it within 0.82 of the text height (eighth-round review: legend and panel text enlarged; estimates
    # drawn hollow and dotted, measurements filled and solid).
    fig = plt.figure(figsize=(7.6, 8.8))
    gs = gridspec.GridSpec(2, 2, height_ratios=[0.8, 1.1], hspace=0.42, wspace=0.34, left=0.115, right=0.985, top=0.962, bottom=0.28)
    ax0 = fig.add_subplot(gs[0, :])
    axes = [ax0, fig.add_subplot(gs[1, 0]), fig.add_subplot(gs[1, 1])]
    style(axes[0], "(a) service: the hot blocks' users (70 % WhatsApp)")
    style(axes[1], "(b) security, 20-minute attack")
    style(axes[2], "(c) security, 60-minute attack")
    for ax in axes:
        ax.tick_params(labelsize=11.5); ax._left_title.set_fontsize(12.5); ax._left_title.set_fontweight("bold")
    rates = sorted({float(k.split("|")[0]) for k in E4["service"]})
    for pol, col in (("counter graded 4/10 min", C["green"]), ("sequential T1000 c1", C["blue"])):
        for cnd, ls in (("benign", "--"), ("attacked", "-")):
            ys, lo, hi = [], [], []
            for r in rates:
                key = f"{r:g}|0.7|{cnd}|{pol}"
                key = key if key in E4["service"] else f"{r}|0.7|{cnd}|{pol}"
                g = (E4["service"][key]["attributable_loss_vs_none"] or {}).get("hot_block", {}).get("net_lost_pct_of_group", (0, 0, 0, 0))
                ys.append(g[0]); lo.append(g[1]); hi.append(g[2])
            axes[0].plot(rates, ys, color=col, linestyle=ls, marker="o", markersize=7, linewidth=2,
                         label=f"{'counter' if 'counter' in pol else 'tests'}, {'attack-free' if cnd == 'benign' else 'with pumper'}")
            axes[0].fill_between(rates, lo, hi, color=col, alpha=0.12, linewidth=0)
    axes[0].axvline(4, color=INK2, linestyle=":", linewidth=1.4)
    axes[0].annotate("quota: 4 per 10 min", (4, axes[0].get_ylim()[0]), textcoords="offset points", xytext=(5, 8), fontsize=12, color=INK)
    axes[0].set_xscale("log"); axes[0].set_xticks(rates); axes[0].set_xticklabels([f"{r:g}" for r in rates])
    axes[0].xaxis.set_minor_formatter(NullFormatter())
    axes[0].set_xlabel("legitimate sends per hot block per 10 minutes (log scale)", color=INK, fontsize=12)
    axes[0].set_ylabel("completions lost, pp\nof the hot blocks' users", color=INK, fontsize=12)
    axes[0].legend(frameon=False, fontsize=11.5, loc="upper left", ncol=2, columnspacing=1.0, handlelength=1.8)
    blocks = sorted({int(k.split("|")[0]) for k in E4["security"]})
    measured, estimated = [], []
    for ax, mins in ((axes[1], 20), (axes[2], 60)):
        for pol, col in (("none", INK2), ("sequential T1000 c1", C["blue"]), ("counter graded 4/10 min", C["green"])):
            for kind, mk in (("spreading, never verifies", "o"), ("quota-aware", "s")):
                v = [E4["security"][f"{b}|{kind}|{mins}|{pol}"]["leaked_total"] for b in blocks]
                h = ax.errorbar(blocks, [x[0] for x in v], yerr=[[x[0] - x[1] for x in v], [x[2] - x[0] for x in v]], color=col,
                                marker=mk, markersize=6.5, linewidth=2, linestyle="-" if mk == "o" else "--", capsize=2.5,
                                elinewidth=1, label=f"{ {'none': 'no policy', 'sequential T1000 c1': 'tests'}.get(pol, 'counter')}, "
                                                    f"{'full rate' if mk == 'o' else 'paced to the quota'}")
                if mins == 60:
                    measured.append(h)
        if cond:
            cells = {c["blocks"]: c for c in cond["cells"] if c["minutes"] == mins and c["pumper"] == "spreading, never verifies"}
            for key, col, lab, mk, ls in (("tests_estimate", C["blue"], "Eq. 2: tests", "D", ":"),
                                          ("counter_cold", C["green"], "Eq. 3: counter, cold", "^", ":"),
                                          ("counter_warm", C["orange"], "Eq. 4: counter, warm", "v", "-.")):
                h, = ax.plot(blocks, [cells[b][key] for b in blocks], color=col, linestyle=ls, linewidth=1.6, marker=mk, markersize=9,
                             markerfacecolor="none", markeredgewidth=1.6, label=lab)
                if mins == 60:
                    estimated.append(h)
        ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xticks(blocks); ax.set_xticklabels([str(b) for b in blocks])
        ax.xaxis.set_minor_formatter(NullFormatter())
        ax.set_xlabel("blocks the pumper uses (log)", color=INK, fontsize=12)
        ax.set_ylabel(f"SMS leaked in {mins} min (log)", color=INK, fontsize=12)
    order = [0, 2, 4, 1, 3, 5]                     # columns: full rate, paced
    l1 = fig.legend(handles=[measured[i] for i in order], frameon=False, fontsize=11.5, loc="upper left", ncol=2,
                    bbox_to_anchor=(0.01, 0.185), title="Measured (filled markers): mean over five seeds, 95 % interval",
                    title_fontsize=11.5, alignment="left", columnspacing=1.5, handlelength=2.2, labelspacing=0.3)
    fig.legend(handles=estimated, frameon=False, fontsize=11.5, loc="upper left", ncol=3, bbox_to_anchor=(0.01, 0.068),
               title="Estimated for the full-rate pumper (hollow markers), from each run's inputs", title_fontsize=11.5,
               alignment="left", columnspacing=1.0, handlelength=2.2)
    fig.add_artist(l1)
    save(fig, out, "fig7_counter_boundary", tight=False)


def plain(ax):
    """The plain style of the boundary figures: white, four spines, a faint grid, legend inside the axes."""
    ax.set_facecolor("white")
    ax.grid(True, color="#d9d9d9", linewidth=0.6, linestyle="-"); ax.set_axisbelow(True)
    for sp in ax.spines.values():
        sp.set_color("black"); sp.set_linewidth(0.8)
    ax.tick_params(colors="black", labelsize=9, direction="out")


def fig7_panels(CS, out, runs_path=ROOT / "results" / "counter_study_runs.jsonl.gz", cond_path=None):
    """The counter's operating boundary (results/counter_study.json, E4) as three plain column-width
    figures: fig7a_service, the hot blocks' users' attributable loss against their legitimate rate,
    attack-free and under a pumper on the same blocks; fig7b_security20, leakage in 20 minutes against
    the blocks a pumper spreads over, at full rate and paced to the quota; fig7c_security60, leakage in
    60 minutes at full rate against the estimates of Equations 2-4 (results/condition_check.json).
    Means over five seeds; the error bars are the recorded 95 % bootstrap intervals. The legends name
    the series in words; the conditions they share are stated in the text that cites each figure."""
    E4 = CS["E4"]
    cond = json.loads(pathlib.Path(cond_path).read_text()) if cond_path and pathlib.Path(cond_path).exists() else None
    POL = {"none": ("no destination policy", "black", "o"), "sequential T1000 c1": ("sequential tests (default)", "tab:blue", "s"),
           "counter graded 4/10 min": ("counter, 4 per 10 min", "tab:green", "^")}
    # (a) service
    fig, ax = plt.subplots(figsize=(4.6, 3.4))
    plain(ax)
    rates = sorted({float(k.split("|")[0]) for k in E4["service"]})
    for pol in ("counter graded 4/10 min", "sequential T1000 c1"):
        lab, col, mk = POL[pol]
        for cnd, ls, word in (("benign", "--", "no attack"), ("attacked", "-", "pumper on the block")):
            ys, lo, hi = [], [], []
            for r in rates:
                key = f"{r:g}|0.7|{cnd}|{pol}"
                key = key if key in E4["service"] else f"{r}|0.7|{cnd}|{pol}"
                g = (E4["service"][key]["attributable_loss_vs_none"] or {}).get("hot_block", {}).get("net_lost_pct_of_group", (0, 0, 0, 0))
                ys.append(g[0]); lo.append(g[1]); hi.append(g[2])
            ax.errorbar(rates, ys, yerr=[[y - l for y, l in zip(ys, lo)], [h - y for y, h in zip(ys, hi)]], color=col, linestyle=ls,
                        marker=mk, markersize=4.5, linewidth=1.3, capsize=2, elinewidth=0.8, markerfacecolor=col if cnd == "attacked" else "white",
                        label=f"{lab.split(' (')[0]}, {word}")
    ax.axvline(4, color="black", linestyle=":", linewidth=1.0, label="the counter's quota")
    ax.axhline(0, color="black", linewidth=0.6)
    ax.set_xscale("log"); ax.set_xticks(rates); ax.set_xticklabels([f"{r:g}" for r in rates])
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.set_xlabel("legitimate sends per block per 10 min", fontsize=9)
    ax.set_ylabel("completions lost by the block's users (points)", fontsize=9)
    h, l = ax.get_legend_handles_labels()
    ax.legend(h[1:] + h[:1], l[1:] + l[:1], loc="upper left", fontsize=7.5, frameon=True, framealpha=1, edgecolor="#bbbbbb", handlelength=2.2)
    fig.subplots_adjust(left=0.13, right=0.98, top=0.97, bottom=0.15)
    save(fig, out, "fig7a_service", tight=False)
    # (b) 20 minutes: measured, at full rate and paced to the quota
    blocks = sorted({int(k.split("|")[0]) for k in E4["security"]})

    def series(ax, pol, kind, mins, ls, fill, label):
        lab, col, mk = POL[pol]
        v = [E4["security"][f"{b}|{kind}|{mins}|{pol}"]["leaked_total"] for b in blocks]
        ax.errorbar(blocks, [x[0] for x in v], yerr=[[x[0] - x[1] for x in v], [x[2] - x[0] for x in v]], color=col, marker=mk,
                    markersize=4.5, linewidth=1.3, linestyle=ls, capsize=2, elinewidth=0.8, markerfacecolor=col if fill else "white", label=label)

    def axes_log(ax, mins):
        ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xticks(blocks); ax.set_xticklabels([str(b) for b in blocks])
        ax.xaxis.set_minor_formatter(NullFormatter())
        ax.set_xlabel("blocks the pumper spreads over", fontsize=9)
        ax.set_ylabel(f"SMS leaked in {mins} minutes", fontsize=9)

    fig, ax = plt.subplots(figsize=(4.6, 3.4))
    plain(ax)
    for pol in ("none", "sequential T1000 c1", "counter graded 4/10 min"):
        series(ax, pol, "spreading, never verifies", 20, "-", True, f"{POL[pol][0]}, pumper at full rate")
    for pol in ("sequential T1000 c1", "counter graded 4/10 min"):
        series(ax, pol, "quota-aware", 20, "--", False, f"{POL[pol][0]}, pumper paced to the quota")
    axes_log(ax, 20)
    ax.legend(loc="lower right", fontsize=7.5, frameon=True, framealpha=1, edgecolor="#bbbbbb", handlelength=2.4)
    fig.subplots_adjust(left=0.13, right=0.98, top=0.97, bottom=0.15)
    save(fig, out, "fig7b_security20", tight=False)
    # (c) 60 minutes: measured at full rate, against the estimates from the rules
    fig, ax = plt.subplots(figsize=(4.6, 3.4))
    plain(ax)
    for pol in ("none", "sequential T1000 c1", "counter graded 4/10 min"):
        series(ax, pol, "spreading, never verifies", 60, "-", True, f"{POL[pol][0]}, measured")
    if cond:
        cells = {c["blocks"]: c for c in cond["cells"] if c["minutes"] == 60 and c["pumper"] == "spreading, never verifies"}
        for key, col, lab, mk, ls in (("tests_estimate", "tab:blue", "tests, estimate from the rules (Eq. 2)", "D", ":"),
                                      ("counter_cold", "tab:green", "counter, cold-start bound (Eq. 3)", "v", ":"),
                                      ("counter_warm", "tab:red", "counter, warm-start bound (Eq. 4)", "x", "-.")):
            ax.plot(blocks, [cells[b][key] for b in blocks], color=col, linestyle=ls, linewidth=1.2, marker=mk, markersize=6,
                    markerfacecolor="white", markeredgewidth=1.2, label=lab)
    axes_log(ax, 60)
    ax.legend(loc="lower right", fontsize=7.5, frameon=True, framealpha=1, edgecolor="#bbbbbb", handlelength=2.4)
    fig.subplots_adjust(left=0.13, right=0.98, top=0.97, bottom=0.15)
    save(fig, out, "fig7c_security60", tight=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--out", default=str(ROOT / "paper" / "figures"))
    a = ap.parse_args()
    R = json.loads((pathlib.Path(a.results) / "evaluation.json").read_text())
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    for old in list(out.glob("fig6_detectors.*")) + list(out.glob("fig6_matched.*")):
        old.unlink()
    for fn in (fig1_leakage, fig2_ablation, fig3_dilution, fig4_tradeoff, fig5_spread):
        fn(R, out)
        print("wrote", fn.__name__)
    for fn in (fig6_matched,):                              # artifact only since revision 8 (Table 5 carries the comparison)
        fn(R, out, pathlib.Path(a.results) / "evaluation_runs.jsonl.gz")
        print("wrote", fn.__name__, "(artifact only)")
    cs = pathlib.Path(a.results) / "counter_study.json"
    if cs.exists():
        fig7_counter_boundary(json.loads(cs.read_text()), out, pathlib.Path(a.results) / "counter_study_runs.jsonl.gz",
                              pathlib.Path(a.results) / "condition_check.json")
        print("wrote fig7_counter_boundary (artifact only)")
        fig7_panels(json.loads(cs.read_text()), out, pathlib.Path(a.results) / "counter_study_runs.jsonl.gz",
                    pathlib.Path(a.results) / "condition_check.json")
        print("wrote fig7a_service, fig7b_security20, fig7c_security60")


if __name__ == "__main__":
    main()
