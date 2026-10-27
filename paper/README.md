# Manuscript

`main.tex` is the manuscript in the format of the IEEE Open Journal of the Communications Society:
`ojcoms.sty` gives the journal's look on the standard `article` class (two columns, Times, `I. SECTION`
headings, `FIGURE 1.` and `TABLE 1.` captions, a title block with ABSTRACT and INDEX TERMS) and
`IEEEtranN-doi.bst` prints the numeric IEEE reference list (both vendored here; see the note in
`ojcoms.sty` for switching to `IEEEtran.cls`, which could not be installed in the build sandbox). The
Elsevier files of the earlier Computers & Security version (`elsarticle.cls`, `elsarticle-*.bst`) are
kept for the revision history. `refs.bib` holds the references, each checked against its publisher's
record. `make` builds `main.pdf`; `make rebuttal`
builds the current response letter (`rebuttal_round8.js` -> `rebuttal_round8.docx`, with Node and
the `docx` package). Earlier letters are kept as `rebuttal*.js` / `.docx`.

## Figures

`figures.py` draws every figure of the manuscript from the recorded results, nothing else. File names keep the
numbering of revision 4; the first column gives the figure's number in the current manuscript. Figures 1 to 5 are
the author's own drawings (PNG, a word or two per element); the paragraph before each figure explains what it
shows, so the figures carry no detail of their own.

| Figure in revision 8 | Input | Output |
|---|---|---|
| 1. The path of an OTP request, and where the money goes (Section 2) | none (the author's drawing) | `paper/figures/fig8_defense_path.png` |
| 2. The two attackers on the path of a request (Section 3.2) | none (the author's drawing) | `paper/figures/fig9_threat_model.png` |
| 3. How the implementation fits together (Section 3.3) | none (the author's drawing, after `src/otp_guard`) | `paper/figures/fig12_architecture.png` |
| 4. The twelve steps and the feedback loop (Section 3.3; the figure's stages are numbered 1 to 12 in reading order, the text's Steps 0 to 11) | none (the author's drawing) | `paper/figures/fig10_steps.png` |
| Algorithm 1. The v1 baseline (Section 3.1) | none | `paper/figures/alg1_v1_body.tex`, included by `main.tex`; `alg1_v1.tex` renders it for the Word version |
| Algorithm 2. The v2 pipeline and its feedback loop (Section 3.3) | none | `paper/figures/alg2_v2_body.tex`, included by `main.tex`; `alg2_v2.tex` renders it for the Word version |
| 5. How we evaluated the design (Section 4) | none (the author's drawing) | `paper/figures/fig11_method.png` |
| Algorithm 3. One simulation run (Section 4.2) | none | `paper/figures/alg3_sim_body.tex`, included by `main.tex`; `alg3_sim.tex` renders it for the Word version |
| artifact only. Leakage by attacker, v1 against v2, caps lifted and caps on, with legitimate completion | `results/evaluation.json` → `multi_seed` | `paper/figures/fig1_leakage.{png,svg,pdf}` |
| artifact only. Ablation: leaked SMS relative to the full design, one layer removed at a time (paired, same seeds) | `multi_seed`, `ablation` | `paper/figures/fig2_ablation.{png,svg,pdf}` |
| artifact only. Dilution: leaked share and legitimate harm against the attack-to-legitimate ratio | `dilution` | `paper/figures/fig3_dilution.{png,svg,pdf}` |
| artifact only. Leakage against legitimate refusal and challenge, every sweep point, with completion | `cap_sweep`, `weight_sweep` | `paper/figures/fig4_tradeoff.{png,svg,pdf}` |
| artifact only. Pumper spread: measured leakage, model, and residuals | `spread` | `paper/figures/fig5_spread.{png,svg,pdf}` |
| 6. Matched comparison at 200 blocks, evaluation seeds: benign completion (separate 24-hour attack-free runs) against leakage summed over four attack-profile means (separate attack runs), with the tuning target | `matched` | `paper/figures/fig6_matched_a.{png,svg,pdf}` |
| 7. The same comparison: each selected setting's leakage minus the default's, paired per seed, grouped by the pumper's carrier | `matched` | `paper/figures/fig6_matched_b.{png,svg,pdf}` |
| 8, 9, 10. The destination counter's operating boundary, one figure per panel: loss among hot-block users against the legitimate rate on those blocks (6), and leakage in 20 and 60 minutes against the pumper's spread (7, 8), with the counter's bounds (Equations 3 and 4) and the tests' first-verdict estimate (Equation 2) evaluated per run from offered requests, offered rate and the configured timeouts, nothing fitted | `results/counter_study.json` → `E4`; `results/counter_study_runs.jsonl.gz`; `results/condition_check.json` | `paper/figures/fig7a_service`, `fig7b_security20`, `fig7c_security60` `.{png,svg,pdf}` |
| artifact only. The same three panels as one figure | as above | `paper/figures/fig7_counter_boundary.{png,svg,pdf}` |

The ablation figure's numbers are also written to `paper/figures/fig2_ablation_matrix.csv`, and its large effects (interval excluding zero, at least 10 SMS) to `paper/figures/fig2_key_effects.md`. The figures carry no embedded titles; captions belong in the manuscript, which includes the vector PDFs.

Regenerate with `python3 paper/figures.py` (after `make evaluation`); `--results` and `--out`
override the directories. Every number printed in the manuscript's tables comes from
`results/evaluation.json`, `results/counter_study.json`, `results/round5_analyses.json`, `results/performance.json`
and `results/performance_holdout.json`; `scripts/headline_numbers.py`
writes `results/headline_numbers.md`, which maps each headline figure of the README to its
study, configuration, seed count, metric and JSON path.
