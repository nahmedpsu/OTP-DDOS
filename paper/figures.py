#!/usr/bin/env python3
"""Manuscript figures, drawn from the recorded results only (results/evaluation.json).

    python3 paper/figures.py [--results results] [--out paper/figures]

See paper/README.md for the figure-to-input mapping. Colours: a validated categorical palette
(blue, orange, green, yellow, pink; checked for colour-vision deficiency separation), a diverging
pair with a grey midpoint for the ablation matrix, text in ink tokens never in series colours.
"""
import argparse
import json
import pathlib

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                      # noqa: E402
from matplotlib.colors import TwoSlopeNorm, LinearSegmentedColormap   # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
SURFACE, INK, INK2, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#e6e5e0", "#c3c2b7"
C = {"blue": "#2a78d6", "orange": "#eb6834", "green": "#1baf7a", "yellow": "#eda100", "pink": "#e87ba4"}
ATTACKER_LABELS = {
    "naive_single_client": "single client", "datacenter_rotation": "datacenter rotation",
    "residential_bot": "residential, bot CAPTCHA", "residential_captcha_farm": "residential, farmed CAPTCHA",
    "residential_aged_fps": "residential, aged fingerprints", "residential_reused_profile": "residential, reused profile",
    "sequential_numbers": "sequential numbers", "premium_pumping": "premium-prefix pumping", "spoofed_platform": "spoofed platform header",
}
LAYER_CODES = {"attestation": "L0 attestation", "session": "L1 session", "network_subnet_asn": "L2 network", "number_intelligence": "L5 numbers",
               "risk_engine": "L7 risk engine", "backoff": "L8 backoff", "adaptive_caps": "L9 adaptive caps", "circuit_breaker": "L10 breaker",
               "feedback": "FB feedback", "fine_destination_key": "FB block key"}


def style(ax, title=None):
    ax.set_facecolor(SURFACE)
    ax.grid(True, color=GRID, linewidth=0.8); ax.set_axisbelow(True)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    for sp in ("left", "bottom"):
        ax.spines[sp].set_color(AXIS)
    ax.tick_params(colors=INK2, labelsize=8)
    if title:
        ax.set_title(title, loc="left", color=INK, fontsize=10)


def save(fig, out, name):
    fig.patch.set_facecolor(SURFACE)
    fig.tight_layout()
    fig.savefig(out / f"{name}.png", dpi=200); fig.savefig(out / f"{name}.svg")
    plt.close(fig)


def fig1_leakage(R, out):
    ms = R["multi_seed"]
    names = [n for n in ATTACKER_LABELS if n in ms["behavioural_only"]]
    y = list(range(len(names)))
    fig, axes = plt.subplots(1, 3, figsize=(11, 4.6), sharey=True)
    panels = [("behavioural_only", "leaked_total", "SMS leaked, caps lifted"),
              ("with_adaptive_caps", "leaked_total", "SMS leaked, caps on"),
              ("with_adaptive_caps", "legit_completed_pct", "Legitimate completion %, caps on")]
    for ax, (mode, metric, title) in zip(axes, panels):
        style(ax, title)
        for k, (design, col) in enumerate((("v1", C["orange"]), ("v2", C["blue"]))):
            vals = [ms[mode][n][design][metric] for n in names]
            m = [v[0] for v in vals]; lo = [v[0] - max(v[1], 0) for v in vals]; hi = [v[2] - v[0] for v in vals]
            ax.barh([yy + (0.19 if k else -0.19) for yy in y], m, height=0.34, color=col, label=design, xerr=[lo, hi],
                    error_kw=dict(ecolor=INK2, elinewidth=0.8, capsize=2), edgecolor=SURFACE, linewidth=1)
        ax.set_yticks(y); ax.set_yticklabels([ATTACKER_LABELS[n] for n in names], color=INK, fontsize=8)
        ax.invert_yaxis()
    axes[0].legend(frameon=False, fontsize=8, loc="lower right")
    axes[2].set_xlim(0, 100)
    fig.suptitle("Figure 1. Attack leakage and legitimate completion by design (30 seeds, 95 % t-intervals)", x=0.01, ha="left", color=INK, fontsize=11)
    save(fig, out, "fig1_leakage")


def fig2_ablation(R, out):
    B = R["ablation"]
    names = [n for n in ATTACKER_LABELS if n in B]
    layers = [l for l in LAYER_CODES if l in next(iter(B.values()))]
    data = [[B[n][l]["paired_leak_diff"][0] for l in layers] for n in names]
    vmax = max(5.0, max(abs(v) for row in data for v in row))
    cmap = LinearSegmentedColormap.from_list("div", [C["blue"], "#cfcfcb", C["orange"]])
    fig, ax = plt.subplots(figsize=(9.5, 5))
    style(ax, "Leaked SMS with the layer removed minus the full design (paired, same seeds, 10 seeds)")
    ax.grid(False)
    im = ax.imshow(data, cmap=cmap, norm=TwoSlopeNorm(vcenter=0, vmin=-vmax, vmax=vmax), aspect="auto")
    for i, row in enumerate(data):
        for j, v in enumerate(row):
            if abs(v) >= 5:
                ax.text(j, i, f"{v:+.0f}", ha="center", va="center", fontsize=8, color=INK)
    ax.set_xticks(range(len(layers))); ax.set_xticklabels([LAYER_CODES[l] for l in layers], rotation=35, ha="right", fontsize=8, color=INK)
    ax.set_yticks(range(len(names))); ax.set_yticklabels([ATTACKER_LABELS[n] for n in names], fontsize=8, color=INK)
    cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02); cb.set_label("SMS leaked: removed − full", color=INK2, fontsize=8); cb.ax.tick_params(colors=INK2, labelsize=8)
    fig.suptitle("Figure 2. Leave-one-layer-out ablation (with adaptive caps)", x=0.01, ha="left", color=INK, fontsize=11)
    save(fig, out, "fig2_ablation")


def fig3_dilution(R, out):
    D = R["dilution"]
    xs = sorted(float(k) for k in D)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
    style(axes[0], "Attack leaked, % of its requests (60-minute attack, 5 seeds)")
    style(axes[1], "Legitimate harm, % of requests")
    pct = [100 * D[str(int(x) if x == int(x) else x)]["leaked_total"][0] / max(D[str(int(x) if x == int(x) else x)]["requests"][0], 1) for x in xs]
    axes[0].plot(xs, pct, color=C["blue"], linewidth=2, marker="o", markersize=6)
    for x, p in zip(xs, pct):
        axes[0].annotate(f"{p:.0f} %", (x, p), textcoords="offset points", xytext=(0, 7), ha="center", fontsize=8, color=INK2)
    axes[0].set_xscale("log"); axes[0].set_ylim(0, 105); axes[0].set_xlabel("attack rate / legitimate rate", color=INK)
    for metric, col, label in (("legit_challenge_rate_pct", C["orange"], "challenged"), ("legit_refusal_rate_pct", C["green"], "refused")):
        m = [D[str(int(x) if x == int(x) else x)][metric] for x in xs]
        axes[1].plot(xs, [v[0] for v in m], color=col, linewidth=2, marker="o", markersize=6, label=label)
        axes[1].fill_between(xs, [max(v[1], 0) for v in m], [v[2] for v in m], color=col, alpha=0.15, linewidth=0)
    axes[1].set_xscale("log"); axes[1].set_xlabel("attack rate / legitimate rate", color=INK); axes[1].legend(frameon=False, fontsize=8)
    fig.suptitle("Figure 3. Dilution: a residential attacker with human-like CAPTCHA scores at rising volume", x=0.01, ha="left", color=INK, fontsize=11)
    save(fig, out, "fig3_dilution")


def fig4_tradeoff(R, out):
    series = [("Cap floor x base multiple", C["blue"], R["cap_sweep"]["residential_captcha_farm"].values()),
              ("Tier boundary scale", C["orange"], R["weight_sweep"]["residential_captcha_farm"]["tier_scale"].values()),
              ("Fresh-fingerprint weight", C["green"], R["weight_sweep"]["residential_captcha_farm"]["fresh_fp_weight"].values()),
              ("Conversion weight", C["yellow"], R["weight_sweep"]["residential_captcha_farm"]["conversion_weight"].values())]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.4), sharey=True)
    style(axes[0], "against legitimate requests refused (%)"); style(axes[1], "against legitimate requests challenged (%)")
    for label, col, pts in series:
        pts = list(pts)
        y = [p["steady_state_leak_per_min"][0] for p in pts]
        axes[0].scatter([p["legit_refusal_rate_pct"][0] for p in pts], y, s=34, color=col, label=label, edgecolors=SURFACE, linewidths=1, zorder=3)
        axes[1].scatter([p["legit_challenge_rate_pct"][0] for p in pts], y, s=34, color=col, label=label, edgecolors=SURFACE, linewidths=1, zorder=3)
    axes[0].set_ylabel("attacker late-window leakage (SMS / min)", color=INK)
    axes[0].legend(frameon=False, fontsize=8)
    fig.suptitle("Figure 4. Leakage against legitimate harm, every sweep point (residential farm attacker, 10 seeds)", x=0.01, ha="left", color=INK, fontsize=11)
    save(fig, out, "fig4_tradeoff")


def fig5_spread(R, out):
    G = R["spread"]
    fig, axes = plt.subplots(2, 2, figsize=(10, 6.4), sharex="col", gridspec_kw={"height_ratios": [3, 1.3]})
    cols = {9: C["blue"], 8: C["orange"], 7: C["green"]}
    labels = {9: "ranges of 1 000", 8: "ranges of 10 000", 7: "ranges of 100 000"}
    for j, (verify, title) in enumerate(((0.0, "carrier does not verify"), (1.0, "carrier verifies within 1 s"))):
        style(axes[0][j], title); style(axes[1][j])
        for digits, col in cols.items():
            keys = [k for k in G if k.startswith(f"verify={verify},") and k.endswith(f"digits={digits}")]
            xs = [G[k]["attacker_blocks_requested"][0] for k in keys]
            meas = [G[k]["leaked_total"] for k in keys]
            pred = [G[k]["predicted"][0] for k in keys]
            order = sorted(range(len(xs)), key=lambda i: xs[i])
            axes[0][j].errorbar([xs[i] for i in order], [meas[i][0] for i in order],
                                yerr=[[meas[i][0] - max(meas[i][1], 0) for i in order], [meas[i][2] - meas[i][0] for i in order]],
                                fmt="o", color=col, markersize=6, capsize=2, elinewidth=0.8, label=f"{labels[digits]}: measured")
            axes[0][j].plot([xs[i] for i in order], [pred[i] for i in order], color=col, linewidth=1.5, linestyle="--", label=f"{labels[digits]}: model")
            axes[1][j].scatter([xs[i] for i in order], [G[keys[i]]["residuals"]["mean"] for i in order], color=col, s=28, edgecolors=SURFACE, linewidths=1, zorder=3)
        axes[0][j].set_xscale("log"); axes[1][j].axhline(0, color=INK2, linewidth=0.8)
        axes[1][j].set_xlabel("distinct 8-digit blocks the attack touched (observed)", color=INK)
    axes[0][0].set_ylabel("SMS leaked in 20 min", color=INK); axes[1][0].set_ylabel("model − measured", color=INK)
    axes[0][0].legend(frameon=False, fontsize=7, loc="upper left")
    fig.suptitle("Figure 5. Pumper spread: measured leakage, closed-form model on observed blocks, and residuals (10 seeds)", x=0.01, ha="left", color=INK, fontsize=11)
    save(fig, out, "fig5_spread")


def fig6_detectors(R, out):
    Dt, Dfp = R["detectors"], R["detector_fp"]
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.6))
    style(axes[0], "human-like verifying carrier"); style(axes[1], "carrier that never verifies")
    groups = {"sequential": (C["blue"], "sequential tests"), "counter": (C["orange"], "flat counter")}
    for ax, aname in zip(axes, ("concentrated_pumper_verifies_humanlike", "concentrated_pumper_no_verify")):
        pts = []
        for dname in Dt[aname]:
            g = "counter" if dname.startswith("counter") else "sequential"
            col, _ = groups[g]
            x = Dfp[dname]["0.65"]["legit_completed_pct"][0]
            y = Dt[aname][dname]["leaked_total"][0]
            marker = "s" if "graded" in dname else ("^" if "refuse" in dname else "o")
            ax.scatter(x, y, s=46, color=col, marker=marker, edgecolors=SURFACE, linewidths=1, zorder=3)
            short = dname.replace("sequential, threshold ", "T").replace(", credit ", " c").replace(" (default)", "*").replace(" (Page's CUSUM)", "") \
                         .replace("counter, ", "N").replace(" per block per day, ", " ").replace("unbounded credit (SPRT)", "SPRT")
            pts.append((x, y, short))
        # direct labels, spread vertically where points stack (same x, close y)
        pts.sort(key=lambda t: (round(t[0]), t[1]))
        yspan = max(p[1] for p in pts) - min(p[1] for p in pts) or 1
        last = None
        for x, y, short in pts:
            ty = y
            if last is not None and abs(x - last[0]) < 3 and (ty - last[1]) < 0.035 * yspan:
                ty = last[1] + 0.035 * yspan
            ax.annotate(short, (x, y), xytext=(x + 1.2, ty), fontsize=6.5, color=INK2,
                        arrowprops=dict(arrowstyle="-", color=AXIS, linewidth=0.5) if abs(ty - y) > 0.01 * yspan else None)
            last = (x, ty)
        ax.set_ylim(top=max(ax.get_ylim()[1], last[1] + 0.06 * yspan))      # room for the stacked labels
        ax.set_xlim(right=max(ax.get_xlim()[1], max(p[0] for p in pts) + 22))
        ax.set_xlabel("legitimate completion % at 65 % conversion, 144 sends/block/day (24 h)", color=INK, fontsize=8)
    axes[0].set_ylabel("SMS leaked by the pumper in 20 min", color=INK)
    from matplotlib.lines import Line2D
    handles = [Line2D([], [], marker="o", color=C["blue"], linestyle="", label="sequential tests (T threshold, c credit; * default)"),
               Line2D([], [], marker="^", color=C["orange"], linestyle="", label="counter, refusing (N per block per day)"),
               Line2D([], [], marker="s", color=C["orange"], linestyle="", label="counter, graded action")]
    axes[1].legend(handles=handles, frameon=False, fontsize=7, loc="upper left")
    fig.suptitle("Figure 6. Detector settings: pumper leakage against legitimate completion at matched traffic (10 and 5 seeds)", x=0.01, ha="left", color=INK, fontsize=11)
    save(fig, out, "fig6_detectors")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--out", default=str(ROOT / "paper" / "figures"))
    a = ap.parse_args()
    R = json.loads((pathlib.Path(a.results) / "evaluation.json").read_text())
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    for fn in (fig1_leakage, fig2_ablation, fig3_dilution, fig4_tradeoff, fig5_spread, fig6_detectors):
        fn(R, out)
        print("wrote", fn.__name__)


if __name__ == "__main__":
    main()
