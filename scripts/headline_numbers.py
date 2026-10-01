#!/usr/bin/env python3
"""Provenance of every headline number: which study, configuration, seed set, metric and JSON path
each figure quoted in the README comes from. Writes results/headline_numbers.md from
results/evaluation.json and results/performance.json; the README is written from this table.

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
    ("Farm attacker, v1 static caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v1", "leaked_total"), "30 seeds"),
    ("Farm attacker, v1 static caps: first-time users refused %", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v1", "first_time_refusal_rate_pct"), "30 seeds"),
    ("Farm attacker, v2 adaptive caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v2", "leaked_total"), "30 seeds"),
    ("Farm attacker, v2 adaptive caps: first-time users refused %", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v2", "first_time_refusal_rate_pct"), "30 seeds"),
    ("Farm attacker, v2 adaptive caps: legitimate completed %", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v2", "legit_completed_pct"), "30 seeds"),
    ("Farm attacker, v2 adaptive caps: returning users delivered %", "evaluation.json", ("multi_seed", "with_adaptive_caps", "residential_captcha_farm", "v2", "returning_delivered_pct"), "30 seeds"),
    ("Farm attacker, v2 caps lifted: SMS leaked", "evaluation.json", ("multi_seed", "behavioural_only", "residential_captcha_farm", "v2", "leaked_total"), "30 seeds"),
    ("Single client, v2: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "naive_single_client", "v2", "leaked_total"), "30 seeds"),
    ("Datacenter rotation, v2: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "datacenter_rotation", "v2", "leaked_total"), "30 seeds"),
    ("Premium pumping, v2: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "premium_pumping", "v2", "leaked_total"), "30 seeds"),
    ("Sequential walk, v2 caps lifted: SMS leaked", "evaluation.json", ("multi_seed", "behavioural_only", "sequential_numbers", "v2", "leaked_total"), "30 seeds"),
    ("Sequential walk, v2 adaptive caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "sequential_numbers", "v2", "leaked_total"), "30 seeds"),
    ("Sequential walk, block counter alone (5/day, refuse): SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "sequential_numbers", "block_limit_only", "leaked_total"), "30 seeds"),
    ("Premium pumping, block counter alone: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "premium_pumping", "block_limit_only", "leaked_total"), "30 seeds"),
    ("Spoofed header, v1 static caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "spoofed_platform", "v1", "leaked_total"), "30 seeds"),
    ("Spoofed header, v2 adaptive caps: SMS leaked", "evaluation.json", ("multi_seed", "with_adaptive_caps", "spoofed_platform", "v2", "leaked_total"), "30 seeds"),
    ("Ablation, farm: full v2 leaked", "evaluation.json", ("ablation", "residential_captcha_farm", "full", "leaked_total"), "10 seeds"),
    ("Ablation, farm: without adaptive caps, paired difference", "evaluation.json", ("ablation", "residential_captcha_farm", "adaptive_caps", "paired_leak_diff"), "10 seeds, paired"),
    ("Ablation, sequential walk: without the feedback loop, paired difference", "evaluation.json", ("ablation", "sequential_numbers", "feedback", "paired_leak_diff"), "10 seeds, paired"),
    ("Ablation, sequential walk: without the block key, paired difference", "evaluation.json", ("ablation", "sequential_numbers", "fine_destination_key", "paired_leak_diff"), "10 seeds, paired"),
    ("Cadence, farm: every minute, aligned, 20-min attack: leaked", "evaluation.json", ("cadence", "residential_captcha_farm", "every minute (worker default)|tick aligned with the attack start|20", "leaked_total"), "10 seeds"),
    ("Cadence, farm: every 5 minutes, half-period offset: leaked", "evaluation.json", ("cadence", "residential_captcha_farm", "every 5 minutes|tick offset by half a period|20", "leaked_total"), "10 seeds"),
    ("Cadence, farm: hourly, 60-min attack, aligned: leaked", "evaluation.json", ("cadence", "residential_captcha_farm", "hourly|tick aligned with the attack start|60", "leaked_total"), "10 seeds"),
    ("Baseline job, farm: learned with three closed hours: leaked", "evaluation.json", ("baseline_job", "residential_captcha_farm", "learned, three closed hours", "leaked_total"), "5 seeds"),
    ("Baseline job, farm: learned, cold start: leaked", "evaluation.json", ("baseline_job", "residential_captcha_farm", "learned, cold start: no closed hour of history", "leaked_total"), "5 seeds"),
    ("Baseline job, farm: three hours poisoned: leaked", "evaluation.json", ("baseline_job", "residential_captcha_farm", "learned, three hours poisoned at the legitimate rate", "leaked_total"), "5 seeds"),
    ("Pumper, no verify, default: leaked", "evaluation.json", ("pumping", "concentrated_pumper_no_verify", "fine_key_plus_fast_resolution (default)", "leaked_total"), "10 seeds"),
    ("Pumper, no verify, default: contained seeds", "evaluation.json", ("pumping", "concentrated_pumper_no_verify", "fine_key_plus_fast_resolution (default)", "n_contained"), "10 seeds"),
    ("Pumper, no verify, default: containment time over contained seeds (min)", "evaluation.json", ("pumping", "concentrated_pumper_no_verify", "fine_key_plus_fast_resolution (default)", "time_to_containment_if_contained_min"), "contained seeds only"),
    ("Pumper, instant verifier, default: leaked", "evaluation.json", ("pumping", "concentrated_pumper_verifies_instantly", "fine_key_plus_fast_resolution (default)", "leaked_total"), "10 seeds"),
    ("Pumper, human-like verifier, default (credit 1): leaked", "evaluation.json", ("detectors", "concentrated_pumper_verifies_humanlike", "sequential, threshold 1000, credit 1 (default)", "leaked_total"), "10 seeds"),
    ("Pumper, human-like verifier, credit 0: leaked", "evaluation.json", ("detectors", "concentrated_pumper_verifies_humanlike", "sequential, threshold 1000, credit 0 (Page's CUSUM)", "leaked_total"), "10 seeds"),
    ("Pumper, human-like verifier, unbounded credit: leaked", "evaluation.json", ("detectors", "concentrated_pumper_verifies_humanlike", "sequential, threshold 1000, unbounded credit (SPRT)", "leaked_total"), "10 seeds"),
    ("Pumper, human-like verifier, counter 5/day graded: leaked", "evaluation.json", ("detectors", "concentrated_pumper_verifies_humanlike", "counter, 5 per block per day, graded", "leaked_total"), "10 seeds"),
    ("Legit 24 h at 65 %, default: verdict events", "evaluation.json", ("detector_fp", "sequential, threshold 1000, credit 1 (default)", "0.65", "block_verdicts"), "5 seeds, 24 h, 200 blocks"),
    ("Legit 24 h at 65 %, default: requests hit", "evaluation.json", ("detector_fp", "sequential, threshold 1000, credit 1 (default)", "0.65", "legit_hit_by_verdict"), "5 seeds, 24 h, 200 blocks"),
    ("Legit 24 h at 65 %, credit 0: verdict events", "evaluation.json", ("detector_fp", "sequential, threshold 1000, credit 0 (Page's CUSUM)", "0.65", "block_verdicts"), "5 seeds, 24 h, 200 blocks"),
    ("Legit 24 h at 65 %, credit 0: requests hit", "evaluation.json", ("detector_fp", "sequential, threshold 1000, credit 0 (Page's CUSUM)", "0.65", "legit_hit_by_verdict"), "5 seeds, 24 h, 200 blocks"),
    ("Legit 24 h at 65 %, counter 5/day refuse: completed %", "evaluation.json", ("detector_fp", "counter, 5 per block per day, refuse", "0.65", "legit_completed_pct"), "5 seeds, 24 h, 200 blocks"),
    ("Legit 24 h at 65 %, default: completed %", "evaluation.json", ("detector_fp", "sequential, threshold 1000, credit 1 (default)", "0.65", "legit_completed_pct"), "5 seeds, 24 h, 200 blocks"),
    ("Trust-building pumper (caps): leaked", "evaluation.json", ("adaptive_attackers", "with_adaptive_caps", "trust_building_pumper", "leaked_total"), "10 seeds"),
    ("Trust-building pumper (caps): flood-phase leaked", "evaluation.json", ("adaptive_attackers", "with_adaptive_caps", "trust_building_pumper", "flood_leaked"), "10 seeds"),
    ("Trust-building, concentrated (caps lifted): flood-phase leaked", "evaluation.json", ("adaptive_attackers", "behavioural_only", "trust_building_concentrated", "flood_leaked"), "10 seeds"),
    ("Receipt-faking carrier (caps): leaked", "evaluation.json", ("adaptive_attackers", "with_adaptive_caps", "receipt_faking_carrier", "leaked_total"), "10 seeds"),
    ("Poisoner, graded: legitimate requests hit", "evaluation.json", ("poisoner", "graded verdicts (default)", "legit_hit_by_verdict"), "10 seeds"),
    ("Poisoner, graded: hit and never completed", "evaluation.json", ("poisoner", "graded verdicts (default)", "legit_hit_lost"), "10 seeds"),
    ("Poisoner, hard deny: hit and never completed", "evaluation.json", ("poisoner", "hard deny (24 h denylist)", "legit_hit_lost"), "10 seeds"),
    ("Poisoner, recovery: hits after the attack stopped", "evaluation.json", ("poisoner", "graded, attacker stops after 10 min (recovery)", "legit_hit_after_stop"), "10 seeds"),
    ("Dilution x10: leaked", "evaluation.json", ("dilution", "10", "leaked_total"), "5 seeds, 60 min"),
    ("Dilution x10: legit challenged %", "evaluation.json", ("dilution", "10", "legit_challenge_rate_pct"), "5 seeds, 60 min"),
    ("Outage, failed receipts, default: verdict events", "evaluation.json", ("false_positives", "outage", "failed_receipts|receipts + outage detector (default)", "block_verdicts"), "8 seeds"),
    ("Outage, silent, default: verdict events", "evaluation.json", ("false_positives", "outage", "silent|receipts + outage detector (default)", "block_verdicts"), "8 seeds"),
    ("Spread: configurations in the sweep", "evaluation.json", ("spread",), "count of cells"),
    ("Performance: in-process send p50 ms", "performance.json", ("phase1_in_process", "end_to_end_ms", "sent", "p50"), "3000 requests"),
    ("Performance: Redis round trips per request", "performance.json", ("phase1_in_process", "redis_round_trips_per_request"), "3000 requests"),
    ("Performance: HTTP throughput without the floor (req/s)", "performance.json", ("phase2_http_floor_0", "throughput_rps"), "6000 requests, concurrency 32"),
    ("Performance: HTTP throughput with the floor (req/s)", "performance.json", ("phase2_http_floor_400", "throughput_rps"), "6000 requests, concurrency 32"),
]


def fmt(v):
    if isinstance(v, (list, tuple)) and len(v) == 4:
        m, lo, hi, n = v
        return "n/a" if m is None else f"{m:.2f} [{lo:.2f}, {hi:.2f}] (n={n})"
    if isinstance(v, dict):
        return f"{len(v)} cells"
    if isinstance(v, float):
        return f"{v:.2f}"
    return str(v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(ROOT / "results"))
    a = ap.parse_args()
    res = pathlib.Path(a.results)
    files = {f: json.loads((res / f).read_text()) for f in ("evaluation.json", "performance.json") if (res / f).exists()}
    L = ["# Headline numbers and where they come from", "",
         "Every figure quoted in the README resolves to one entry here: the file under `results/`, the JSON path, the seed set and "
         "the value (mean with 95 % t-interval and n, where the metric is an interval). Regenerate with `python3 scripts/headline_numbers.py` "
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
