# Which aligned store rule changes the recorded runs (seventh-round review, M1)

A stratified sample of 86 recorded runs (three per study, seed 20261003, at most 200 simulated minutes), replayed under each variant and compared with the 2.8.x record (`results/historical_2.8/`) and the 2.9.0 record. 'Identical' compares every recorded field except bookkeeping and the fields added in 2.9.0; 'same leakage' compares `attack.leaked_total`. The refresh-only measurement (the 2.8.x store with only the sorted-set TTL refreshed) is in `results/historical_2.8/store_expiry_check.md`: 75 of 102 identical.

| Variant | Identical to 2.8.x | Same leakage as 2.8.x | Identical to 2.9.0 |
|---|---:|---:|---:|
| 2.9.0 | 78 | 83 | 86 |
| 2.9.0 but boundary | 78 | 83 | 86 |
| 2.9.0 but order | 78 | 83 | 86 |
| 2.9.0 record vs 2.8.x record | 78 | 83 | – |

Restoring the 2.8.x boundary or the order rule changes none of the 86 runs: the changes come from the other aligned rules, above all the sorted-set TTL refresh (`results/outage_mechanism_check.md` traces one run).
