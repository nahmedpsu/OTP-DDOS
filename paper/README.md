# Manuscript

`main.tex` is the manuscript for Computers & Security (Elsevier `elsarticle` class and
`elsarticle-num` style, vendored here), with `refs.bib`. `make` builds `main.pdf`; `make rebuttal`
builds the current response letter (`rebuttal_round5.js` -> `rebuttal_round5.docx`, with Node and
the `docx` package). Earlier letters are kept as `rebuttal*.js` / `.docx`.

## Figures

`figures.py` draws every figure of the manuscript from the recorded results, nothing else. File names keep the
numbering of revision 4; the first column gives the figure's number in revision 5:

| Figure | Input | Output |
|---|---|---|
| 1. Leakage by attacker, v1 against v2, caps lifted and caps on, with legitimate completion | `results/evaluation.json` → `multi_seed` | `paper/figures/fig1_leakage.{png,svg,pdf}` |
| 2. Ablation: leaked SMS relative to the full design, one layer removed at a time (paired, same seeds) | `multi_seed`, `ablation` | `paper/figures/fig2_ablation.{png,svg,pdf}` |
| 3. Dilution: leaked share and legitimate harm against the attack-to-legitimate ratio | `dilution` | `paper/figures/fig3_dilution.{png,svg,pdf}` |
| 4. Leakage against legitimate refusal and challenge, every sweep point, with completion | `cap_sweep`, `weight_sweep` | `paper/figures/fig4_tradeoff.{png,svg,pdf}` |
| artifact only (revision 4: Figure 5). Pumper spread: measured leakage, model, and residuals | `spread` | `paper/figures/fig5_spread.{png,svg,pdf}` |
| 5. Destination policies on a common pipeline at 200 blocks, evaluation seeds: (a) benign completion (separate 24-hour attack-free runs) against leakage summed over four attack-profile means (separate attack runs), with the benign service target; (b) per-attacker leakage differences to the default, paired per seed | `matched` | `paper/figures/fig6_matched.{png,svg,pdf}` |
| 6. The destination counter's operating boundary: loss among hot-block users against the legitimate rate on those blocks, and leakage against the pumper's spread, with two simplified estimates evaluated at the sampled spreads only: the counter's allowance capped at the offered volume (Equation 3) and the sequential tests' first-verdict estimate with its intercept fitted on the 3-block cell (Equation 2) | `results/counter_study.json` → `E4` | `paper/figures/fig7_counter_boundary.{png,svg,pdf}` |

Figure 2's numbers are also written to `paper/figures/fig2_ablation_matrix.csv`, and its large effects (interval excluding zero, at least 10 SMS) to `paper/figures/fig2_key_effects.md`. The figures carry no embedded titles; captions belong in the manuscript, which includes the vector PDFs.

Regenerate with `python3 paper/figures.py` (after `make evaluation`); `--results` and `--out`
override the directories. Every number printed in the manuscript's tables comes from
`results/evaluation.json`, `results/counter_study.json`, `results/round5_analyses.json`, `results/performance.json`
and `results/performance_holdout.json`; `scripts/headline_numbers.py`
writes `results/headline_numbers.md`, which maps each headline figure of the README to its
study, configuration, seed count, metric and JSON path.
