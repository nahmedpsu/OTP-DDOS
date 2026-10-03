#!/usr/bin/env python3
"""Regenerate the manuscript's figures from ../results. Run after `make evaluation` in the
repository root. Palette: a two-series grey/blue for v1/v2, one sequential blue ramp for the
heatmap; identity is also carried by direct labels so colour is never the only cue."""
import collections, gzip, json, pathlib, shutil
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = pathlib.Path(__file__).resolve().parent / "figures"
OUT.mkdir(exist_ok=True)
BLUE, ORANGE, GRAY = "#2a78d6", "#eb6834", "#7a7a76"
plt.rcParams.update({"font.size": 8, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.edgecolor": "#c3c2b7", "axes.labelcolor": "#333", "xtick.color": "#555", "ytick.color": "#555"})
runs = [json.loads(l) for l in gzip.open(ROOT / "results/evaluation_runs.jsonl.gz", "rt")]
R = json.load(open(ROOT / "results/evaluation.json"))

# Figure: per-minute leakage, v1 vs v2, caps lifted
sel = {"datacenter_rotation": "Datacenter rotation", "premium_pumping": "Premium-prefix pumping",
       "spoofed_platform": "Spoofed platform header", "sequential_numbers": "Sequential numbers",
       "residential_reused_profile": "Residential, reused profile", "residential_captcha_farm": "Residential, farmed CAPTCHA"}
series = collections.defaultdict(list)
for r in runs:
    if r["study"] in ("v1", "v2") and r["index"][0] == "behavioural_only":
        series[(r["index"][1], r["study"])].append(r["attack"]["leaked_per_min"])
fig, axes = plt.subplots(2, 3, figsize=(7.0, 3.8), sharex=True, sharey=True)
for ax, (name, title) in zip(axes.flat, sel.items()):
    for design, col in (("v1", GRAY), ("v2", BLUE)):
        m = np.mean(series[(name, design)], axis=0)
        ax.plot(range(1, 21), m, color=col, lw=1.8)
        ax.text(20.3, m[-1], design, color=col, va="center", fontsize=7)
    ax.set_title(title, fontsize=8, loc="left"); ax.grid(axis="y", color="#e8e7e2", lw=0.6); ax.set_xlim(1, 22)
for ax in axes[1]: ax.set_xlabel("minute of attack")
for ax in axes[:, 0]: ax.set_ylabel("SMS leaked per minute")
fig.tight_layout(); fig.savefig(OUT / "leakage_per_minute.pdf")

# Figure: ablation heatmap, same seeds
abl = R["ablation"]; attackers = list(abl)
flags = ["full"] + sorted(f for f in abl[attackers[0]] if f != "full")
M = np.array([[abl[a][f]["leaked_total"][0] for f in flags] for a in attackers])
fig, ax = plt.subplots(figsize=(7.0, 3.4))
cmap = matplotlib.colors.LinearSegmentedColormap.from_list("b", ["#f4f8fd", "#cde2fb", "#6da7ec", "#256abf", "#0d366b"])
im = ax.imshow(M, cmap=cmap, aspect="auto", vmin=0, vmax=600)
ax.set_xticks(range(len(flags))); ax.set_xticklabels(["full v2"] + [f"without {f.replace('_', ' ')}" for f in flags[1:]], rotation=35, ha="right", fontsize=7)
ax.set_yticks(range(len(attackers))); ax.set_yticklabels([a.replace("_", " ") for a in attackers], fontsize=7)
for i in range(len(attackers)):
    for j in range(len(flags)):
        v = M[i, j]; ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=6.5, color="white" if v > 300 else "#333")
ax.axvline(0.5, color="white", lw=2)
cb = fig.colorbar(im, ax=ax, shrink=0.8); cb.set_label("SMS leaked in 20 min (mean over the same 10 seeds)", fontsize=7)
fig.tight_layout(); fig.savefig(OUT / "ablation.pdf")

# Figure: dilution curve
D = R["dilution"]; keys = sorted(D, key=float); xs = [float(k) for k in keys]
leak = [100 * D[k]["leaked_total"][0] / max(D[k]["requests"][0], 1) for k in keys]
chal = [D[k]["legit_challenge_rate_pct"][0] for k in keys]
fig, ax = plt.subplots(figsize=(3.4, 2.6))
ax.plot(xs, leak, color=BLUE, lw=1.8, marker="o", ms=4); ax.text(xs[-1], leak[-1] + 3, "attack leaked, %", color=BLUE, ha="right", fontsize=7)
ax.plot(xs, chal, color=ORANGE, lw=1.8, marker="o", ms=4); ax.text(xs[-1], chal[-1] + 3, "real users challenged, %", color=ORANGE, ha="right", fontsize=7)
ax.set_xscale("log"); ax.set_xticks(xs); ax.set_xticklabels([k for k in keys]); ax.set_xlabel("attack rate / legitimate rate"); ax.set_ylabel("percent")
ax.set_ylim(0, 105); ax.grid(axis="y", color="#e8e7e2", lw=0.6)
fig.tight_layout(); fig.savefig(OUT / "dilution.pdf")

for f in ("tradeoff.png", "pumper_spread.png"):
    shutil.copy(ROOT / "results" / f, OUT / f)
print("figures written to", OUT)
