# Headline numbers and where they come from

Every figure quoted in the README resolves to one entry here: the file under `results/`, the JSON path, the seed set and the value (mean with 95 % t-interval and n, where the metric is an interval). Regenerate with `python3 scripts/headline_numbers.py` after `make evaluation` and `make load-test`.

| Headline | File | JSON path | Seeds | Value |
|---|---|---|---|---:|
| Farm attacker, v1 static caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v1 / leaked_total` | 30 seeds | 562.50 [485.06, 639.94] (n=30) |
| Farm attacker, v1 static caps: first-time users refused % | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v1 / first_time_refusal_rate_pct` | 30 seeds | 4.12 [2.04, 6.21] (n=30) |
| Farm attacker, v2 adaptive caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v2 / leaked_total` | 30 seeds | 235.77 [221.37, 250.16] (n=30) |
| Farm attacker, v2 adaptive caps: first-time users refused % | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v2 / first_time_refusal_rate_pct` | 30 seeds | 53.74 [46.77, 60.70] (n=30) |
| Farm attacker, v2 adaptive caps: legitimate completed % | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v2 / legit_completed_pct` | 30 seeds | 42.11 [37.21, 47.01] (n=30) |
| Farm attacker, v2 adaptive caps: returning users delivered % | `evaluation.json` | `multi_seed / with_adaptive_caps / residential_captcha_farm / v2 / returning_delivered_pct` | 30 seeds | 78.19 [74.46, 81.92] (n=30) |
| Farm attacker, v2 caps lifted: SMS leaked | `evaluation.json` | `multi_seed / behavioural_only / residential_captcha_farm / v2 / leaked_total` | 30 seeds | 599.00 [501.49, 696.51] (n=30) |
| Single client, v2: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / naive_single_client / v2 / leaked_total` | 30 seeds | 1.90 [1.33, 2.47] (n=30) |
| Datacenter rotation, v2: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / datacenter_rotation / v2 / leaked_total` | 30 seeds | 0.00 [0.00, 0.00] (n=30) |
| Premium pumping, v2: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / premium_pumping / v2 / leaked_total` | 30 seeds | 0.00 [0.00, 0.00] (n=30) |
| Sequential walk, v2 caps lifted: SMS leaked | `evaluation.json` | `multi_seed / behavioural_only / sequential_numbers / v2 / leaked_total` | 30 seeds | 70.00 [58.35, 81.65] (n=30) |
| Sequential walk, v2 adaptive caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / sequential_numbers / v2 / leaked_total` | 30 seeds | 63.07 [53.97, 72.16] (n=30) |
| Sequential walk, block counter alone (5/day, refuse): SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / sequential_numbers / block_limit_only / leaked_total` | 30 seeds | 5.00 [5.00, 5.00] (n=30) |
| Premium pumping, block counter alone: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / premium_pumping / block_limit_only / leaked_total` | 30 seeds | 5.00 [5.00, 5.00] (n=30) |
| Spoofed header, v1 static caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / spoofed_platform / v1 / leaked_total` | 30 seeds | 100.00 [100.00, 100.00] (n=30) |
| Spoofed header, v2 adaptive caps: SMS leaked | `evaluation.json` | `multi_seed / with_adaptive_caps / spoofed_platform / v2 / leaked_total` | 30 seeds | 235.77 [221.37, 250.16] (n=30) |
| Ablation, farm: full v2 leaked | `evaluation.json` | `ablation / residential_captcha_farm / full / leaked_total` | 10 seeds | 233.30 [205.78, 260.82] (n=10) |
| Ablation, farm: without adaptive caps, paired difference | `evaluation.json` | `ablation / residential_captcha_farm / adaptive_caps / paired_leak_diff` | 10 seeds, paired | 312.90 [181.32, 444.48] (n=10) |
| Ablation, sequential walk: without the feedback loop, paired difference | `evaluation.json` | `ablation / sequential_numbers / feedback / paired_leak_diff` | 10 seeds, paired | 152.50 [137.44, 167.56] (n=10) |
| Ablation, sequential walk: without the block key, paired difference | `evaluation.json` | `ablation / sequential_numbers / fine_destination_key / paired_leak_diff` | 10 seeds, paired | 123.20 [100.97, 145.43] (n=10) |
| Cadence, farm: every minute, aligned, 20-min attack: leaked | `evaluation.json` | `cadence / residential_captcha_farm / every minute (worker default)|tick aligned with the attack start|20 / leaked_total` | 10 seeds | 233.30 [205.78, 260.82] (n=10) |
| Cadence, farm: every 5 minutes, half-period offset: leaked | `evaluation.json` | `cadence / residential_captcha_farm / every 5 minutes|tick offset by half a period|20 / leaked_total` | 10 seeds | 546.20 [392.89, 699.51] (n=10) |
| Cadence, farm: hourly, 60-min attack, aligned: leaked | `evaluation.json` | `cadence / residential_captcha_farm / hourly|tick aligned with the attack start|60 / leaked_total` | 10 seeds | 1527.90 [1114.87, 1940.93] (n=10) |
| Baseline job, farm: learned with three closed hours: leaked | `evaluation.json` | `baseline_job / residential_captcha_farm / learned, three closed hours / leaked_total` | 5 seeds | 246.60 [185.01, 308.19] (n=5) |
| Baseline job, farm: learned, cold start: leaked | `evaluation.json` | `baseline_job / residential_captcha_farm / learned, cold start: no closed hour of history / leaked_total` | 5 seeds | 649.20 [345.62, 952.78] (n=5) |
| Baseline job, farm: three hours poisoned: leaked | `evaluation.json` | `baseline_job / residential_captcha_farm / learned, three hours poisoned at the legitimate rate / leaked_total` | 5 seeds | 205.60 [124.20, 287.00] (n=5) |
| Pumper, no verify, default: leaked | `evaluation.json` | `pumping / concentrated_pumper_no_verify / fine_key_plus_fast_resolution (default) / leaked_total` | 10 seeds | 87.70 [60.99, 114.41] (n=10) |
| Pumper, no verify, default: contained seeds | `evaluation.json` | `pumping / concentrated_pumper_no_verify / fine_key_plus_fast_resolution (default) / n_contained` | 10 seeds | 10 |
| Pumper, no verify, default: containment time over contained seeds (min) | `evaluation.json` | `pumping / concentrated_pumper_no_verify / fine_key_plus_fast_resolution (default) / time_to_containment_if_contained_min` | contained seeds only | 3.60 [3.10, 4.10] (n=10) |
| Pumper, instant verifier, default: leaked | `evaluation.json` | `pumping / concentrated_pumper_verifies_instantly / fine_key_plus_fast_resolution (default) / leaked_total` | 10 seeds | 17.60 [15.16, 20.04] (n=10) |
| Pumper, human-like verifier, default (credit 1): leaked | `evaluation.json` | `detectors / concentrated_pumper_verifies_humanlike / sequential, threshold 1000, credit 1 (default) / leaked_total` | 10 seeds | 445.20 [344.68, 545.72] (n=10) |
| Pumper, human-like verifier, credit 0: leaked | `evaluation.json` | `detectors / concentrated_pumper_verifies_humanlike / sequential, threshold 1000, credit 0 (Page's CUSUM) / leaked_total` | 10 seeds | 151.90 [131.12, 172.68] (n=10) |
| Pumper, human-like verifier, unbounded credit: leaked | `evaluation.json` | `detectors / concentrated_pumper_verifies_humanlike / sequential, threshold 1000, unbounded credit (SPRT) / leaked_total` | 10 seeds | 556.20 [368.83, 743.57] (n=10) |
| Pumper, human-like verifier, counter 5/day graded: leaked | `evaluation.json` | `detectors / concentrated_pumper_verifies_humanlike / counter, 5 per block per day, graded / leaked_total` | 10 seeds | 13.70 [13.02, 14.38] (n=10) |
| Legit 24 h at 65 %, default: verdict events | `evaluation.json` | `detector_fp / sequential, threshold 1000, credit 1 (default) / 0.65 / block_verdicts` | 5 seeds, 24 h, 200 blocks | 7.40 [4.28, 10.52] (n=5) |
| Legit 24 h at 65 %, default: requests hit | `evaluation.json` | `detector_fp / sequential, threshold 1000, credit 1 (default) / 0.65 / legit_hit_by_verdict` | 5 seeds, 24 h, 200 blocks | 39.60 [19.32, 59.88] (n=5) |
| Legit 24 h at 65 %, credit 0: verdict events | `evaluation.json` | `detector_fp / sequential, threshold 1000, credit 0 (Page's CUSUM) / 0.65 / block_verdicts` | 5 seeds, 24 h, 200 blocks | 150.60 [134.40, 166.80] (n=5) |
| Legit 24 h at 65 %, credit 0: requests hit | `evaluation.json` | `detector_fp / sequential, threshold 1000, credit 0 (Page's CUSUM) / 0.65 / legit_hit_by_verdict` | 5 seeds, 24 h, 200 blocks | 777.60 [674.48, 880.72] (n=5) |
| Legit 24 h at 65 %, counter 5/day refuse: completed % | `evaluation.json` | `detector_fp / counter, 5 per block per day, refuse / 0.65 / legit_completed_pct` | 5 seeds, 24 h, 200 blocks | 2.27 [2.22, 2.33] (n=5) |
| Legit 24 h at 65 %, default: completed % | `evaluation.json` | `detector_fp / sequential, threshold 1000, credit 1 (default) / 0.65 / legit_completed_pct` | 5 seeds, 24 h, 200 blocks | 64.43 [63.83, 65.02] (n=5) |
| Trust-building pumper (caps): leaked | `evaluation.json` | `adaptive_attackers / with_adaptive_caps / trust_building_pumper / leaked_total` | 10 seeds | 244.00 [204.85, 283.15] (n=10) |
| Trust-building pumper (caps): flood-phase leaked | `evaluation.json` | `adaptive_attackers / with_adaptive_caps / trust_building_pumper / flood_leaked` | 10 seeds | 82.50 [64.88, 100.12] (n=10) |
| Trust-building, concentrated (caps lifted): flood-phase leaked | `evaluation.json` | `adaptive_attackers / behavioural_only / trust_building_concentrated / flood_leaked` | 10 seeds | 163.60 [107.04, 220.16] (n=10) |
| Receipt-faking carrier (caps): leaked | `evaluation.json` | `adaptive_attackers / with_adaptive_caps / receipt_faking_carrier / leaked_total` | 10 seeds | 236.70 [207.98, 265.42] (n=10) |
| Poisoner, graded: legitimate requests hit | `evaluation.json` | `poisoner / graded verdicts (default) / legit_hit_by_verdict` | 10 seeds | 100.30 [43.18, 157.42] (n=10) |
| Poisoner, graded: hit and never completed | `evaluation.json` | `poisoner / graded verdicts (default) / legit_hit_lost` | 10 seeds | 49.10 [16.12, 82.08] (n=10) |
| Poisoner, hard deny: hit and never completed | `evaluation.json` | `poisoner / hard deny (24 h denylist) / legit_hit_lost` | 10 seeds | 118.80 [52.45, 185.15] (n=10) |
| Poisoner, recovery: hits after the attack stopped | `evaluation.json` | `poisoner / graded, attacker stops after 10 min (recovery) / legit_hit_after_stop` | 10 seeds | 150.50 [60.12, 240.88] (n=10) |
| Dilution x10: leaked | `evaluation.json` | `dilution / 10 / leaked_total` | 5 seeds, 60 min | 8269.60 [8042.00, 8497.20] (n=5) |
| Dilution x10: legit challenged % | `evaluation.json` | `dilution / 10 / legit_challenge_rate_pct` | 5 seeds, 60 min | 18.44 [17.54, 19.35] (n=5) |
| Outage, failed receipts, default: verdict events | `evaluation.json` | `false_positives / outage / failed_receipts|receipts + outage detector (default) / block_verdicts` | 8 seeds | 0.12 [-0.17, 0.42] (n=8) |
| Outage, silent, default: verdict events | `evaluation.json` | `false_positives / outage / silent|receipts + outage detector (default) / block_verdicts` | 8 seeds | 0.88 [0.05, 1.70] (n=8) |
| Spread: configurations in the sweep | `evaluation.json` | `spread` | count of cells | 18 cells |
| Performance: in-process send p50 ms | `performance.json` | `phase1_in_process / end_to_end_ms / sent / p50` | 3000 requests | 12.58 |
| Performance: Redis round trips per request | `performance.json` | `phase1_in_process / redis_round_trips_per_request` | 3000 requests | 47.85 |
| Performance: HTTP throughput without the floor (req/s) | `performance.json` | `phase2_http_floor_0 / throughput_rps` | 6000 requests, concurrency 32 | 255.95 |
| Performance: HTTP throughput with the floor (req/s) | `performance.json` | `phase2_http_floor_400 / throughput_rps` | 6000 requests, concurrency 32 | 69.74 |
