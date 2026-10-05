#!/usr/bin/env python3
"""Provenance of every headline number: which study, configuration, seed set, metric and JSON path
each figure quoted in the README comes from. Writes results/headline_numbers.md from
results/evaluation.json, results/counter_study.json, results/round5_analyses.json and the
performance results; the README is written from this table.

    python3 scripts/headline_numbers.py [--results results]
"""
import argparse
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def get(obj, path):
    for p in path:
        obj = obj[p]
    return obj


ENTRIES = [
    # (label, file, path, seeds description)
    ("Farm attacker, v1 static caps: leak % of requests", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v1", "leak_fraction_pct"), "30 seeds"),
    ("Farm attacker, v1 static caps: first-time users refused %", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v1", "first_time_refusal_rate_pct"), "30 seeds"),
    ("Farm attacker, v2 adaptive caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v2", "leaked_total"), "30 seeds"),
    ("Farm attacker, v2 adaptive caps: leak % of requests", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v2", "leak_fraction_pct"), "30 seeds"),
    ("Farm attacker, v2 adaptive caps: first-time users refused %", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v2", "first_time_refusal_rate_pct"), "30 seeds"),
    ("Farm attacker, v2 adaptive caps: legitimate completed %", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v2", "legit_completed_pct"), "30 seeds"),
    ("Farm attacker, v1 static caps: legitimate completed %", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v1", "legit_completed_pct"), "30 seeds"),
    ("Farm attacker, v2 caps lifted: leak % of requests", "evaluation.json", ("multi_seed", "behavioural_only", "residential_captcha_farm", "v2", "leak_fraction_pct"), "30 seeds"),
    ("Datacenter rotation, v2 caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "datacenter_rotation", "v2", "leaked_total"), "30 seeds"),
    ("Datacenter rotation, v2 caps: legitimate completed %", "evaluation.json", ("multi_seed", "with_adaptive_caps", "datacenter_rotation", "v2", "legit_completed_pct"), "30 seeds"),
    ("Premium pumping, v2 caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "premium_pumping", "v2", "leaked_total"), "30 seeds"),
    ("Single client, v2 caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "naive_single_client", "v2", "leaked_total"), "30 seeds"),
    ("Sequential walk, v2 caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "sequential_numbers", "v2", "leaked_total"), "30 seeds"),
    ("Sequential walk, refusing counter alone: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "sequential_numbers", "block_limit_only", "leaked_total"), "30 seeds"),
    ("Spoofed header, v1 static caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "spoofed_platform", "v1", "leaked_total"), "30 seeds"),
    ("Spoofed header, v2 adaptive caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "spoofed_platform", "v2", "leaked_total"), "30 seeds"),
    ("Ablation, farm: without adaptive caps, paired difference", "evaluation.json", ("ablation", "residential_captcha_farm", "adaptive_caps", "paired_leak_diff"), "10 seeds, paired"),
    ("Ablation, sequential walk: without the feedback loop, paired difference", "evaluation.json", ("ablation", "sequential_numbers", "feedback", "paired_leak_diff"), "10 seeds, paired"),
    ("Cadence, farm: every minute: leaked", "evaluation.json", ("cadence", "residential_captcha_farm", "every minute (worker default)|tick aligned with the attack start|20", "leaked_total"), "10 seeds"),
    ("Cadence, farm: every 5 minutes, aligned: leaked", "evaluation.json", ("cadence", "residential_captcha_farm", "every 5 minutes|tick aligned with the attack start|20", "leaked_total"), "10 seeds"),
    ("Cadence, farm: every 5 minutes, offset: leaked", "evaluation.json", ("cadence", "residential_captcha_farm", "every 5 minutes|tick offset by half a period|20", "leaked_total"), "10 seeds"),
    ("Baseline job, farm: learned weekly profile: leaked", "evaluation.json", ("baseline_job", "residential_captcha_farm", "learned, weekly profile (3 previous weeks)", "leaked_total"), "10 seeds"),
    ("Baseline job, farm: schedule-aware poisoning, paired leak difference", "evaluation.json", ("baseline_job", "residential_captcha_farm", "learned, weekly profile poisoned at that hour each week (schedule-aware)", "paired_vs_reference", "leaked_total"), "10 seeds, paired"),
    ("Baseline job, farm: cold start: leaked", "evaluation.json", ("baseline_job", "residential_captcha_farm", "learned, cold start: no closed hour of history", "leaked_total"), "10 seeds"),
    ("Pumper never verifies, default: leaked", "evaluation.json", ("pumping", "concentrated_pumper_no_verify", "fine_key_plus_fast_resolution (default)", "leaked_total"), "10 seeds"),
    ("Pumper never verifies, default: contained seeds", "evaluation.json", ("pumping", "concentrated_pumper_no_verify", "fine_key_plus_fast_resolution (default)", "n_contained"), "10 seeds"),
    ("Pumper never verifies, 60-minute attack: contained seeds", "evaluation.json", ("long_attack", "concentrated_pumper_no_verify", "n_contained"), "10 seeds"),
    ("Pumper verifies instantly, default: leaked", "evaluation.json", ("pumping", "concentrated_pumper_verifies_instantly", "fine_key_plus_fast_resolution (default)", "leaked_total"), "10 seeds"),
    ("Human-like carrier, default: leaked", "evaluation.json", ("pumping", "concentrated_pumper_verifies_humanlike", "fine_key_plus_fast_resolution (default)", "leaked_total"), "10 seeds"),
    ("Matched comparison, 200 blocks: selected settings", "evaluation.json", ("matched", "selection", "200", "chosen"), "tuning seeds 100-102"),
    ("Matched comparison, 200 blocks, default: completed % at 65 %", "evaluation.json", ("matched", "legit", "200", "sequential T1000 c1", "0.65", "legit_completed_pct"), "evaluation seeds 0-9"),
    ("Matched comparison, 200 blocks, none: completed % at 65 %", "evaluation.json", ("matched", "legit", "200", "none", "0.65", "legit_completed_pct"), "evaluation seeds 0-9"),
    ("Matched comparison, 200 blocks, default: attributable loss % at 65 %", "evaluation.json", ("matched", "paired", "200", "sequential T1000 c1", "0.65", "attributable_loss_vs_none", "net_lost_pct"), "evaluation seeds, paired per request"),
    ("Matched comparison, 200 blocks, default: verdict events per day at 65 %", "evaluation.json", ("matched", "legit", "200", "sequential T1000 c1", "0.65", "block_verdicts"), "evaluation seeds 0-9"),
    ("Matched comparison, default: human-like carrier leaked", "evaluation.json", ("matched", "attack", "sequential T1000 c1", "concentrated_pumper_verifies_humanlike", "leaked_total"), "evaluation seeds 0-9"),
    ("Matched comparison, short counter 4/10 min: human-like carrier leaked", "evaluation.json", ("matched", "attack", "counter graded 4/10 min", "concentrated_pumper_verifies_humanlike", "leaked_total"), "evaluation seeds 0-9"),
    ("Matched comparison, 200 blocks, short counter 4/10 min: attributable loss % at 65 %", "evaluation.json", ("matched", "paired", "200", "counter graded 4/10 min", "0.65", "attributable_loss_vs_none", "net_lost_pct"), "evaluation seeds, paired per request"),
    ("Matched comparison, short counter 1/10 min: human-like carrier leaked", "evaluation.json", ("matched", "attack", "counter graded 1/10 min", "concentrated_pumper_verifies_humanlike", "leaked_total"), "evaluation seeds 0-9"),
    ("Matched comparison, uniform, short counter 1/10 min: attributable loss % at 65 %", "evaluation.json", ("matched", "paired", "uniform", "counter graded 1/10 min", "0.65", "attributable_loss_vs_none", "net_lost_pct"), "evaluation seeds, paired per request"),
    ("Matched comparison, no credit T300: human-like carrier leaked", "evaluation.json", ("matched", "attack", "sequential T300 c0", "concentrated_pumper_verifies_humanlike", "leaked_total"), "evaluation seeds 0-9"),
    ("Matched comparison, 200 blocks, no credit T300: verdict events per day at 65 %", "evaluation.json", ("matched", "legit", "200", "sequential T300 c0", "0.65", "block_verdicts"), "evaluation seeds 0-9"),
    ("Matched comparison, none: human-like carrier leaked", "evaluation.json", ("matched", "attack", "none", "concentrated_pumper_verifies_humanlike", "leaked_total"), "evaluation seeds 0-9"),
    ("Threshold-aware carrier, caps lifted: leaked", "evaluation.json", ("adaptive_attackers", "behavioural_only", "threshold_aware_carrier", "leaked_total"), "10 seeds"),
    ("Threshold-aware carrier, caps lifted: codes entered", "evaluation.json", ("adaptive_attackers", "behavioural_only", "threshold_aware_carrier", "attacker_verifications"), "10 seeds"),
    ("Receipt-faking carrier, robust receipts: paired leak difference", "evaluation.json", ("alternatives", "attack", "behavioural_only", "receipt_faking_carrier", "receipt-robust block tests", "paired_leak_vs_default"), "10 seeds, paired"),
    ("Trust builder, trust budget, caps: paired leak difference", "evaluation.json", ("alternatives", "attack", "with_adaptive_caps", "trust_building_pumper", "trust budget (8 exempt requests/min)", "paired_leak_vs_default"), "10 seeds, paired"),
    ("Poisoner, graded: attributable loss (requests)", "evaluation.json", ("poisoner", "graded verdicts (default)", "attributable_loss_vs_observe", "net_lost"), "10 seeds, paired per request"),
    ("Poisoner, graded, no fallback channel: attributable loss (requests)", "evaluation.json", ("poisoner", "graded, no fallback channel", "attributable_loss_vs_observe", "net_lost"), "10 seeds, paired per request"),
    ("Poisoner, recovery run (70 min): attributable loss (requests)", "evaluation.json", ("poisoner", "graded, attacker stops after 10 min (recovery, 70-minute run)", "attributable_loss_vs_observe", "net_lost"), "10 seeds, paired per request"),
    ("Poisoner, hard deny: attributable loss (requests)", "evaluation.json", ("poisoner", "hard deny (24 h denylist)", "attributable_loss_vs_observe", "net_lost"), "10 seeds, paired per request"),
    ("Fallback 0 %: graded 20/day counter completed %", "evaluation.json", ("false_positives", "fallback", "counter graded 20/day|0.0", "legit_completed_pct"), "5 seeds"),
    ("Fallback 70 %: graded 20/day counter completed %", "evaluation.json", ("false_positives", "fallback", "counter graded 20/day|0.7", "legit_completed_pct"), "5 seeds"),
    ("Dilution x10: leak % of requests", "evaluation.json", ("dilution", "10", "leak_fraction_pct"), "5 seeds, 60 min"),
    ("Spread: configurations in the sweep", "evaluation.json", ("spread",), "count of cells"),
    ("Fallback 100 %: graded 20/day counter completed %", "evaluation.json", ("false_positives", "fallback", "counter graded 20/day|1.0", "legit_completed_pct"), "5 seeds"),
    ("Poisoner, recovery run (70 min): requests hit after the attack stopped", "evaluation.json", ("poisoner", "graded, attacker stops after 10 min (recovery, 70-minute run)", "legit_hit_after_stop"), "10 seeds"),
    ("Economics, human-like carrier under v2: break-even revenue share", "evaluation.json", ("economics", "pumping_study", "concentrated_pumper_verifies_humanlike", 1, "breakeven_share"), "10 seeds, scenario accounting"),
    ("Economics, non-verifying carrier under v2: break-even revenue share", "evaluation.json", ("economics", "pumping_study", "concentrated_pumper_no_verify", 1, "breakeven_share"), "10 seeds, scenario accounting"),
    ("Poisoner, recovery run: attributable loss after the attack stopped (requests)", "evaluation.json", ("poisoner", "graded, attacker stops after 10 min (recovery, 70-minute run)", "attributable_loss_vs_observe", "after_stop", "net_lost"), "10 seeds, paired per request"),
    ("Nested variance: farm leakage, between-configuration share", "evaluation.json", ("variance_nested", "residential_captcha_farm", "leaked_total", "between_share"), "10 configurations x 3 seeds"),
    ("Counter study: claims K1-K5", "counter_study.json", ("E2", "claims"), "12 points x 3 seeds (fresh)"),
    ("Counter study E1, 200 shared: principal counter leaked (human-like carrier)", "counter_study.json", ("E1", "200 shared", "concentrated_pumper_verifies_humanlike", "counter graded 4/10 min", "leaked_total"), "seeds 300-309"),
    ("Counter study E1, 200 shared: default leaked (human-like carrier)", "counter_study.json", ("E1", "200 shared", "concentrated_pumper_verifies_humanlike", "sequential T1000 c1", "leaked_total"), "seeds 300-309"),
    ("Counter study E1, 200 shared: principal counter attributable loss, % of users (no-verify pumper)", "counter_study.json", ("E1", "200 shared", "concentrated_pumper_no_verify", "counter graded 4/10 min", "attributable_loss_vs_none", "net_lost_pct"), "seeds 300-309, paired per request"),
    ("Counter study E1, 200 shared: poisoner leaked under the counter", "counter_study.json", ("E1", "200 shared", "block_poisoner", "counter graded 4/10 min", "leaked_total"), "seeds 300-309"),
    ("Counter study E3: trust-building pumper leaked under the counter", "counter_study.json", ("E3", "trust_building_pumper", "counter graded 4/10 min", "leaked_total"), "seeds 300-309"),
    ("Counter study E3: spread over 300 blocks, counter leaked", "counter_study.json", ("E3", "spread over 300 blocks, never verifies", "counter graded 4/10 min", "leaked_total"), "seeds 300-309"),
    ("Counter study E3: spread over 300 blocks, no policy leaked", "counter_study.json", ("E3", "spread over 300 blocks, never verifies", "none", "leaked_total"), "seeds 300-309"),
    ("Counter study E3: quota-aware over 300 blocks, counter leaked", "counter_study.json", ("E3", "quota-aware over 300 blocks (4 per 10 min each)", "counter graded 4/10 min", "leaked_total"), "seeds 300-309"),
    ("Counter study E3: threshold-aware carrier, counter leaked", "counter_study.json", ("E3", "threshold_aware_carrier", "counter graded 4/10 min", "leaked_total"), "seeds 300-309"),
    ("Counter study E3: 360-min human-like carrier, counter leaked per hour", "counter_study.json", ("E3", "concentrated_pumper_verifies_humanlike, 360 minutes", "counter graded 4/10 min", "leaked_per_hour"), "seeds 300-309"),
    ("Counter study E3: 360-min human-like carrier, default leaked per hour", "counter_study.json", ("E3", "concentrated_pumper_verifies_humanlike, 360 minutes", "sequential T1000 c1", "leaked_per_hour"), "seeds 300-309"),
    ("Counter study E4: 8 sends/hot block/10 min, attack-free, counter loss among hot-block users (pp)", "counter_study.json", ("E4", "service", "8|0.7|benign|counter graded 4/10 min", "attributable_loss_vs_none", "hot_block", "net_lost_pct_of_group"), "seeds 300-304"),
    ("Robustness claims", "evaluation.json", ("robustness",), "12 points x 3 seeds"),
    ("Re-selection, 200 blocks: winners under every objective (tuning runs, all eligible settings)", "round5_analyses.json", ("A_selection", "200", "union"), "tuning seeds 100-102"),
    ("Re-selection, 1000 blocks: winners under every objective", "round5_analyses.json", ("A_selection", "1000", "union"), "tuning seeds 100-102"),
    ("Re-selection, uniform: winners under every objective", "round5_analyses.json", ("A_selection", "uniform", "union"), "tuning seeds 100-102"),
    ("Re-selection, 200 blocks: counter 4/10 min on fresh seeds, leaked by carrier", "round5_analyses.json", ("A_evaluation_in_union", "200", "evaluated", "counter graded 4/10 min"), "seeds 300-309"),
    ("Re-selection, 200 blocks: sequential T300 cinf on fresh seeds, leaked by carrier", "round5_analyses.json", ("A_evaluation_in_union", "200", "evaluated", "sequential T300 cinf"), "seeds 300-309"),
    ("Re-selection, 1000 blocks: counter 3/60 min margin to the tuning target (pp)", "round5_analyses.json", ("A_evaluation_in_union", "1000", "evaluated", "counter graded 3/60 min", "margin_to_tuning_target"), "seeds 300-309"),
    ("Claim K4 by attacker", "round5_analyses.json", ("B_claims_by_attacker", "K4", "by_attacker"), "12 points x 3 seeds"),
    ("E1 200 shared, poisoner: combination's extra harm, % of all users", "round5_analyses.json", ("C_attacked_service", "200 shared", "poisoner", "counter 4/10 min + sequential", "vs_attacked_none", "all", "net_pct"), "seeds 300-309, paired per request"),
    ("E1 200 shared, poisoner: counter's extra harm, % of all users", "round5_analyses.json", ("C_attacked_service", "200 shared", "poisoner", "counter graded 4/10 min", "vs_attacked_none", "all", "net_pct"), "seeds 300-309, paired per request"),
    ("E1 200 shared, human-like carrier: counter's extra harm, % of attacked blocks' users", "round5_analyses.json", ("C_attacked_service", "200 shared", "HL", "counter graded 4/10 min", "vs_attacked_none", "attacked_block", "net_pct"), "seeds 300-309, paired per request"),
    ("E1 200 shared, never-verifying carrier: counter's degradation, % of attacked blocks' users", "round5_analyses.json", ("C_attacked_service", "200 shared", "NV", "counter graded 4/10 min", "vs_attack_free_same_policy", "attacked_block", "net_pct"), "seeds 300-309, paired per request"),
    ("Timing: threshold fitted on one run, balanced accuracy on other runs (per pair)", "performance_holdout.json", ("pairs",), "3 runs, ordered pairs"),
    ("Counter bound: E4 counter runs over the cold-start form (Eq. 3)", "condition_check.json", ("runs_over_bound", "cold"), "E4, seeds 300-304"),
    ("Counter bound: E4 counter runs over the warm-start form (Eq. 4)", "condition_check.json", ("runs_over_bound", "warm"), "E4, seeds 300-304"),
    ("Counter bound: cold-start runs over Eq. 3", "condition_check.json", ("cold_start_runs_over_eq3",), "E4, seeds 300-304"),
    ("Ordering, warm-start estimates: decisive cell-mean comparisons", "condition_check.json", ("summary", "warm", "cells_decisive"), "E4, seeds 300-304"),
    ("Ordering, warm-start estimates: cell-mean disagreements", "condition_check.json", ("summary", "warm", "cells_disagree"), "E4, seeds 300-304"),
    ("Ordering, warm-start estimates: decisive seed-level comparisons", "condition_check.json", ("summary", "warm", "seeds_decisive"), "E4, seeds 300-304"),
    ("Ordering, warm-start estimates: seed-level disagreements", "condition_check.json", ("summary", "warm", "seeds_disagree"), "E4, seeds 300-304"),
    ("Estimates: 3 blocks, never verifies, 60 min", "condition_check.json", ("cells", 3), "E4, seeds 300-304"),
    ("Estimates: 10 blocks, never verifies, 60 min", "condition_check.json", ("cells", 7), "E4, seeds 300-304"),
    ("Estimates: 30 blocks, never verifies, 60 min", "condition_check.json", ("cells", 11), "E4, seeds 300-304"),
    ("Performance: in-process send p50 ms", "performance.json", ("phase1_in_process", "end_to_end_ms", "sent", "p50"), "3000 requests"),
    ("Performance: HTTP throughput without the floor (req/s)", "performance.json", ("phase2_http_floor_0", "throughput_rps"), "6000 requests, concurrency 32"),
]


def fmt(v):
    if isinstance(v, list) and v and isinstance(v[0], dict) and "held_out_accuracy" in v[0]:
        h = [p["held_out_accuracy"] for p in v if p["held_out_accuracy"] is not None]
        return f"held-out {min(h):.3f} to {max(h):.3f} over {len(h)} pairs" if h else "n/a"
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return "; ".join(v)
    if isinstance(v, (list, tuple)) and len(v) == 4:
        m, lo, hi, n = v
        return "n/a" if m is None else f"{m:.2f} [{lo:.2f}, {hi:.2f}] (n={n})"
    if isinstance(v, dict):
        if "tests_estimate" in v:
            return (f"tests: estimate {v['tests_estimate']:.0f} vs measured {v['tests_measured']:.1f}; counter: cold bound "
                    f"{v['counter_cold']:.0f}, warm bound {v['counter_warm']:.1f} vs measured {v['counter_measured']:.1f}; none {v['none_measured']:.0f}")
        if all(isinstance(x, str) for x in v.values()):
            return "; ".join(f"{k}: {x}" for k, x in v.items())
        if "C1" in v:
            return "; ".join(f"{c} {'holds' if v[c]['holds'] else 'fails'} ({v[c]['true']}/{v[c]['cells']})" for c in ("C1", "C2", "C3", "C4", "C5"))
        if all(isinstance(x, list) and len(x) == 2 for x in v.values()):
            return "; ".join(f"{k} {x[0]}/{x[1]}" for k, x in v.items())
        if all(isinstance(x, (int, float, list)) for x in v.values()):
            return "; ".join(f"{k} {x:.2f}" if isinstance(x, float) else f"{k} {x}" for k, x in v.items())
        if "K1" in v:
            return "; ".join(f"{c} {'holds' if v[c]['holds'] else 'fails'} ({v[c]['true']}/{v[c]['cells']})" for c in ("K1", "K2", "K3", "K4", "K5"))
        return f"{len(v)} cells"
    if isinstance(v, float):
        return f"{v:.2f}"
    return str(v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(ROOT / "results"))
    a = ap.parse_args()
    res = pathlib.Path(a.results)
    files = {f: json.loads((res / f).read_text()) for f in ("evaluation.json", "performance.json", "counter_study.json", "round5_analyses.json", "performance_holdout.json", "condition_check.json") if (res / f).exists()}
    L = ["# Headline numbers and where they come from", "",
         "Every figure quoted in the README resolves to one entry here: the file under `results/`, the JSON path, the seed set and "
         "the value (mean with 95 % percentile-bootstrap interval and n, where the metric is an interval). Regenerate with `python3 scripts/headline_numbers.py` "
         "after `make evaluation` and `make load-test`.", "",
         "| Headline | File | JSON path | Seeds | Value |", "|---|---|---|---|---:|"]
    for label, f, path, seeds in ENTRIES:
        if f not in files:
            continue
        try:
            v = get(files[f], path)
        except (KeyError, TypeError):
            v = "missing"
        L.append(f"| {label} | `{f}` | `{' / '.join(str(p) for p in path)}` | {seeds} | {fmt(v)} |")
    (res / "headline_numbers.md").write_text("\n".join(L) + "\n")
    print("wrote", res / "headline_numbers.md")


if __name__ == "__main__":
    main()
