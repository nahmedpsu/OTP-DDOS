# Manuscript figures

`figures.py` draws every figure of the manuscript from the recorded results, nothing else:

| Figure | Input | Output |
|---|---|---|
| 1. Leakage by attacker, v1 against v2, caps lifted and caps on, with legitimate completion | `results/evaluation.json` → `multi_seed` | `paper/figures/fig1_leakage.{png,svg}` |
| 2. Ablation: leaked SMS relative to the full design, one layer removed at a time (paired, same seeds) | `multi_seed`, `ablation` | `paper/figures/fig2_ablation.{png,svg}` |
| 3. Dilution: leaked share and legitimate harm against the attack-to-legitimate ratio | `dilution` | `paper/figures/fig3_dilution.{png,svg}` |
| 4. Leakage against legitimate refusal and challenge, every sweep point, with completion | `cap_sweep`, `weight_sweep` | `paper/figures/fig4_tradeoff.{png,svg}` |
| 5. Pumper spread: measured leakage, model, and residuals | `spread` | `paper/figures/fig5_spread.{png,svg}` |
| 6. Destination policies on a common pipeline: every setting on the tuning seeds (completion against leakage), the selected settings on the held-out seeds | `matched` | `paper/figures/fig6_matched.{png,svg}` |

Figure 2's numbers are also written to `paper/figures/fig2_ablation_matrix.csv`. The figures carry no embedded titles; captions belong in the manuscript.

Regenerate with `python3 paper/figures.py` (after `make evaluation`); `--results` and `--out`
override the directories. Every number printed in the manuscript's tables comes from
`results/evaluation.json` and `results/performance.json`; `scripts/headline_numbers.py`
writes `results/headline_numbers.md`, which maps each headline figure of the README to its
study, configuration, seed count, metric and JSON path.
