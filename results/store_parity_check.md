# The simulator on both stores (seventh-round review, M1)

31 recorded study specs, 1 per study (seed 20261004; specs of at most 200 simulated minutes, no multi-week baselines), each run on the in-memory store and on RedisStore over fakeredis driven by the simulated clock. Every recorded field except wall time is compared. **31 of 31 identical.** Wall time 1939 s.

| Results file | Study | Spec hash | Seed | Simulated minutes | Leaked | Outcome |
|---|---|---|---:|---:|---:|---|
| counter study | E1 | a8fb7e2e0a88 | 307 | 90 | 73 | identical |
| counter study | E2 | 1666b36d865b | 6002 | 50 | 17 | identical |
| counter study | E3 | 7653bbd7efc9 | 302 | 50 | 436 | identical |
| counter study | E4 | ac247a12680a | 300 | 90 | 0 | identical |
| counter study | E5_eval | 161039c5d958 | 301 | 150 | 57 | identical |
| counter study | E5_tuning | 7fabd4856254 | 102 | 150 | 773 | identical |
| evaluation | ablation | ab9e2c212f99 | 5 | 30 | 171 | identical |
| evaluation | adaptive | 6a07e30b2521 | 8 | 30 | 43 | identical |
| evaluation | alternatives | b54916012594 | 4 | 50 | 536 | identical |
| evaluation | baseline | 29c338b9db38 | 0 | 30 | 64 | identical |
| evaluation | block_limit_only | 65ed6db11408 | 28 | 30 | 578 | identical |
| evaluation | budget_only | ede3e5b57586 | 12 | 30 | 398 | identical |
| evaluation | cadence | 6853a2b6b495 | 2 | 30 | 136 | identical |
| evaluation | capsweep | 609ae52391d1 | 4 | 30 | 106 | identical |
| evaluation | conversion_only | 6d7ba0561fcc | 3 | 30 | 0 | identical |
| evaluation | dilution | 7eb8196fb597 | 1 | 70 | 1180 | identical |
| evaluation | interactions | ff1656390a75 | 6 | 30 | 205 | identical |
| evaluation | long_attack | 25ba5656fcc4 | 5 | 190 | 18 | identical |
| evaluation | matched_tuning | c06702d42ffc | 101 | 150 | 140 | identical |
| evaluation | outage | f97f4221a2a4 | 1 | 90 | 0 | identical |
| evaluation | poisoner | 85cb71e8b18e | 0 | 80 | 363 | identical |
| evaluation | pumping | 941a44006e2f | 3 | 150 | 1031 | identical |
| evaluation | robustness | 7cbf76f3b192 | 5400 | 30 | 0 | identical |
| evaluation | speed_only | a652079d33d0 | 8 | 30 | 70 | identical |
| evaluation | spread | 426dd14ae50c | 4 | 30 | 679 | identical |
| evaluation | sweep | 6f4d0cfd7a0c | 6 | 30 | 395 | identical |
| evaluation | v1 | 1da3cc8b4880 | 15 | 30 | 54 | identical |
| evaluation | v1_corrected | 46d504ae2a23 | 1 | 30 | 649 | identical |
| evaluation | v2 | a228efdc4817 | 10 | 30 | 83 | identical |
| evaluation | variance | 57b8189b11ed | 19 | 30 | 64 | identical |
| evaluation | variance_nested | 112f4820ec03 | 2091 | 30 | 217 | identical |
