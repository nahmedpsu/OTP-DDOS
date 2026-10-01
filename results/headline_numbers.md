# Headline numbers and where they come from

Every figure quoted in the README resolves to one entry here: the file under `results/`, the JSON path, the seed set and the value (mean with 95 % percentile-bootstrap interval and n, where the metric is an interval). Regenerate with `python3 scripts/headline_numbers.py` after `make evaluation` and `make load-test`.

| Headline | File | JSON path | Seeds | Value |
|---|---|---|---|---:|
| Farm attacker, v1 static caps: leak % of requests | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v1 / leak_fraction_pct` | 30 seeds | 96.19 [93.77, 98.14] (n=30) |
| Farm attacker, v1 static caps: first-time users refused % | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v1 / first_time_refusal_rate_pct` | 30 seeds | 4.17 [2.26, 6.54] (n=30) |
| Farm attacker, v2 adaptive caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v2 / leaked_total` | 30 seeds | 240.13 [227.46, 253.63] (n=30) |
| Farm attacker, v2 adaptive caps: leak % of requests | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v2 / leak_fraction_pct` | 30 seeds | 48.17 [40.78, 56.00] (n=30) |
| Farm attacker, v2 adaptive caps: first-time users refused % | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v2 / first_time_refusal_rate_pct` | 30 seeds | 51.32 [43.41, 58.65] (n=30) |
| Farm attacker, v2 adaptive caps: legitimate completed % | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v2 / legit_completed_pct` | 30 seeds | 46.99 [42.34, 52.05] (n=30) |
| Farm attacker, v1 static caps: legitimate completed % | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v1 / legit_completed_pct` | 30 seeds | 76.96 [75.06, 78.54] (n=30) |
| Farm attacker, v2 caps lifted: leak % of requests | `evaluation.json` | `multi_seed / behavioural_only / residential_captcha_farm / v2 / leak_fraction_pct` | 30 seeds | 99.54 [99.45, 99.63] (n=30) |
| Datacenter rotation, v2 caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / datacenter_rotation / v2 / leaked_total` | 30 seeds | 0.00 [0.00, 0.00] (n=30) |
| Datacenter rotation, v2 caps: legitimate completed % | `evaluation.json` | `multi_seed / with_adaptive_caps / datacenter_rotation / v2 / legit_completed_pct` | 30 seeds | 79.71 [78.96, 80.35] (n=30) |
| Premium pumping, v2 caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / premium_pumping / v2 / leaked_total` | 30 seeds | 0.00 [0.00, 0.00] (n=30) |
| Single client, v2 caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / naive_single_client / v2 / leaked_total` | 30 seeds | 1.83 [1.30, 2.40] (n=30) |
| Sequential walk, v2 caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / sequential_numbers / v2 / leaked_total` | 30 seeds | 62.30 [54.30, 70.53] (n=30) |
| Sequential walk, refusing counter alone: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / sequential_numbers / block_limit_only / leaked_total` | 30 seeds | 4.97 [4.90, 5.00] (n=30) |
| Spoofed header, v1 static caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / spoofed_platform / v1 / leaked_total` | 30 seeds | 100.00 [100.00, 100.00] (n=30) |
| Spoofed header, v2 adaptive caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / spoofed_platform / v2 / leaked_total` | 30 seeds | 240.13 [227.46, 253.63] (n=30) |
| Ablation, farm: without adaptive caps, paired difference | `evaluation.json` | `ablation / residential_captcha_farm / adaptive_caps / paired_leak_diff` | 10 seeds, paired | 307.10 [184.07, 424.11] (n=10) |
| Ablation, sequential walk: without the feedback loop, paired difference | `evaluation.json` | `ablation / sequential_numbers / feedback / paired_leak_diff` | 10 seeds, paired | 159.50 [148.10, 171.20] (n=10) |
| Cadence, farm: every minute: leaked | `evaluation.json` | `cadence / residential_captcha_farm / every minute (worker default)|tick aligned with the attack start|20 / leaked_total` | 10 seeds | 246.80 [222.00, 273.80] (n=10) |
| Cadence, farm: every 5 minutes, aligned: leaked | `evaluation.json` | `cadence / residential_captcha_farm / every 5 minutes|tick aligned with the attack start|20 / leaked_total` | 10 seeds | 400.60 [338.39, 467.42] (n=10) |
| Cadence, farm: every 5 minutes, offset: leaked | `evaluation.json` | `cadence / residential_captcha_farm / every 5 minutes|tick offset by half a period|20 / leaked_total` | 10 seeds | 553.90 [427.06, 683.54] (n=10) |
| Baseline job, farm: learned weekly profile: leaked | `evaluation.json` | `baseline_job / residential_captcha_farm / learned, weekly profile (3 previous weeks) / leaked_total` | 10 seeds | 200.30 [170.20, 234.50] (n=10) |
| Baseline job, farm: schedule-aware poisoning, paired leak difference | `evaluation.json` | `baseline_job / residential_captcha_farm / learned, weekly profile poisoned at that hour each week (schedule-aware) / paired_vs_reference / leaked_total` | 10 seeds, paired | 16.70 [-19.00, 55.40] (n=10) |
| Baseline job, farm: cold start: leaked | `evaluation.json` | `baseline_job / residential_captcha_farm / learned, cold start: no closed hour of history / leaked_total` | 10 seeds | 553.90 [427.06, 683.54] (n=10) |
| Pumper never verifies, default: leaked | `evaluation.json` | `pumping / concentrated_pumper_no_verify / fine_key_plus_fast_resolution (default) / leaked_total` | 10 seeds | 84.60 [66.00, 104.50] (n=10) |
| Pumper never verifies, default: contained seeds | `evaluation.json` | `pumping / concentrated_pumper_no_verify / fine_key_plus_fast_resolution (default) / n_contained` | 10 seeds | 10 |
| Pumper never verifies, 60-minute attack: contained seeds | `evaluation.json` | `long_attack / concentrated_pumper_no_verify / n_contained` | 10 seeds | 10 |
| Pumper verifies instantly, default: leaked | `evaluation.json` | `pumping / concentrated_pumper_verifies_instantly / fine_key_plus_fast_resolution (default) / leaked_total` | 10 seeds | 17.00 [15.70, 18.20] (n=10) |
| Human-like carrier, default: leaked | `evaluation.json` | `pumping / concentrated_pumper_verifies_humanlike / fine_key_plus_fast_resolution (default) / leaked_total` | 10 seeds | 450.00 [352.98, 547.05] (n=10) |
| Matched comparison, 200 blocks: selected settings | `evaluation.json` | `matched / selection / 200 / chosen` | tuning seeds 100-102 | default: sequential T1000 c1; none: none; best sequential at the service target: sequential T300 c0; best counter_graded_daily at the service target: counter graded 160/day; best counter_graded_short at the service target: counter graded 4/10 min; best counter_refuse_daily at the service target: counter refuse 320/day; matched false alarms, credit 0.5: sequential T10000 c0.5; matched false alarms, credit 1: sequential T1000 c1; matched false alarms, credit 2: sequential T1000 c2; matched false alarms, credit inf: sequential T1000 cinf |
| Matched comparison, 200 blocks, default: completed % at 65 % | `evaluation.json` | `matched / legit / 200 / sequential T1000 c1 / 0.65 / legit_completed_pct` | evaluation seeds 0-9 | 64.17 [64.08, 64.28] (n=10) |
| Matched comparison, 200 blocks, none: completed % at 65 % | `evaluation.json` | `matched / legit / 200 / none / 0.65 / legit_completed_pct` | evaluation seeds 0-9 | 64.18 [64.09, 64.28] (n=10) |
| Matched comparison, 200 blocks, default: attributable loss % at 65 % | `evaluation.json` | `matched / paired / 200 / sequential T1000 c1 / 0.65 / attributable_loss_vs_none / net_lost_pct` | evaluation seeds, paired per request | 0.01 [0.00, 0.01] (n=10) |
| Matched comparison, 200 blocks, default: verdict events per day at 65 % | `evaluation.json` | `matched / legit / 200 / sequential T1000 c1 / 0.65 / block_verdicts` | evaluation seeds 0-9 | 6.00 [4.60, 7.40] (n=10) |
| Matched comparison, default: human-like carrier leaked | `evaluation.json` | `matched / attack / sequential T1000 c1 / concentrated_pumper_verifies_humanlike / leaked_total` | evaluation seeds 0-9 | 450.00 [352.98, 547.05] (n=10) |
| Matched comparison, none: human-like carrier leaked | `evaluation.json` | `matched / attack / none / concentrated_pumper_verifies_humanlike / leaked_total` | evaluation seeds 0-9 | 555.80 [411.99, 710.32] (n=10) |
| Threshold-aware carrier, caps lifted: leaked | `evaluation.json` | `adaptive_attackers / behavioural_only / threshold_aware_carrier / leaked_total` | 10 seeds | 572.20 [419.90, 738.26] (n=10) |
| Threshold-aware carrier, caps lifted: codes entered | `evaluation.json` | `adaptive_attackers / behavioural_only / threshold_aware_carrier / attacker_verifications` | 10 seeds | 289.60 [192.30, 402.34] (n=10) |
| Receipt-faking carrier, robust receipts: paired leak difference | `evaluation.json` | `alternatives / attack / behavioural_only / receipt_faking_carrier / receipt-robust block tests / paired_leak_vs_default` | 10 seeds, paired | -555.90 [-722.05, -404.29] (n=10) |
| Trust builder, trust budget, caps: paired leak difference | `evaluation.json` | `alternatives / attack / with_adaptive_caps / trust_building_pumper / trust budget (8 exempt requests/min) / paired_leak_vs_default` | 10 seeds, paired | -21.40 [-35.80, -8.70] (n=10) |
| Poisoner, graded: attributable loss (requests) | `evaluation.json` | `poisoner / graded verdicts (default) / attributable_loss_vs_observe / net_lost` | 10 seeds, paired per request | 10.90 [4.80, 17.20] (n=10) |
| Poisoner, graded, no fallback channel: attributable loss (requests) | `evaluation.json` | `poisoner / graded, no fallback channel / attributable_loss_vs_observe / net_lost` | 10 seeds, paired per request | 24.20 [10.50, 39.10] (n=10) |
| Poisoner, recovery run (70 min): attributable loss (requests) | `evaluation.json` | `poisoner / graded, attacker stops after 10 min (recovery, 70-minute run) / attributable_loss_vs_observe / net_lost` | 10 seeds, paired per request | 47.90 [19.20, 79.10] (n=10) |
| Poisoner, hard deny: attributable loss (requests) | `evaluation.json` | `poisoner / hard deny (24 h denylist) / attributable_loss_vs_observe / net_lost` | 10 seeds, paired per request | 90.20 [45.19, 138.90] (n=10) |
| Fallback 0 %: graded 20/day counter completed % | `evaluation.json` | `false_positives / fallback / counter graded 20/day|0.0 / legit_completed_pct` | 5 seeds | 27.42 [27.29, 27.55] (n=5) |
| Fallback 70 %: graded 20/day counter completed % | `evaluation.json` | `false_positives / fallback / counter graded 20/day|0.7 / legit_completed_pct` | 5 seeds | 52.71 [52.53, 52.91] (n=5) |
| Dilution x10: leak % of requests | `evaluation.json` | `dilution / 10 / leak_fraction_pct` | 5 seeds, 60 min | 68.11 [67.19, 69.01] (n=5) |
| Spread: configurations in the sweep | `evaluation.json` | `spread` | count of cells | 18 cells |
| Robustness claims | `evaluation.json` | `robustness` | 12 points x 3 seeds | C1 fails (76/108); C2 holds (34/36); C3 holds (36/36); C4 holds (18/18); C5 holds (36/36) |
| Performance: in-process send p50 ms | `performance.json` | `phase1_in_process / end_to_end_ms / sent / p50` | 3000 requests | 13.91 |
| Performance: HTTP throughput without the floor (req/s) | `performance.json` | `phase2_http_floor_0 / throughput_rps` | 6000 requests, concurrency 32 | 234.98 |
