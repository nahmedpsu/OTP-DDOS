# Robustness study: first run (superseded)

The first full run of the predeclared robustness study (`config/evaluation_protocol.json`, unchanged),
kept here because its result differs from the published one and the protocol was fixed in advance.

**What changed and why.** Claim C1 failed (76 of 108 cells, 0.70). Every failing cell failed the
service clause (completion at least the no-attack completion at the same point and seed minus 2
points); none failed on leakage (all at most 5 %). Diagnosis: the simulator drew legitimate and
attacker requests from one random stream, so the attack run and the no-attack run at the same seed
offered *different* legitimate users (for example 368 against 347 at point 10, seed 2). The clause
was meant as a paired comparison; unpaired, the difference of two completion rates over about 350
users each has a standard deviation near 3.4 points, so a 2-point margin fails in a large share of
cells by chance alone. The simulator now draws legitimate traffic from its own stream
(`tests/unit/test_simulator_invariants.py::test_legitimate_traffic_is_the_same_with_and_without_an_attack`)
and every study was rerun; `results/evaluation.md` section R is that rerun. Claims, thresholds,
points and seeds are unchanged.

## Section R as first generated

Claims, thresholds, the parameter ranges, the held-out scenario family and the Latin-hypercube design were fixed in `config/evaluation_protocol.json` and committed before these runs. A claim *holds* if it is true in at least 90 % of its cells.

| Claim | Cells | True | Share | Holds |
|---|---:|---:|---:|---|
| C1 | 108 | 76 | 0.70 | no |
| C2 | 36 | 34 | 0.94 | yes |
| C3 | 36 | 36 | 1.00 | yes |
| C4 | 18 | 18 | 1.00 | yes |
| C5 | 36 | 36 | 1.00 | yes |
| C4_points_below_0.75 (reported, not judged) | 18 | 10 | 0.56 | no (n/a) |

Claim texts:

- **C1**: Signature attacks (datacenter rotation, premium-prefix pumping, single client) with adaptive caps: leaked <= 5 % of attack requests and legitimate completion >= the no-attack completion at the same point and seed minus 2 percentage points. Holds if true in >= 90 % of (point, seed, attacker) cells.
- **C2**: Residential farm (human-like CAPTCHA scores), caps lifted: leaked >= 90 % of attack requests. Holds if true in >= 90 % of cells.
- **C3**: Concentrated pumper whose carrier never verifies, caps lifted: contained (5 sustained quiet minutes) with leaked <= 30 % of attack requests. Holds if true in >= 90 % of cells.
- **C4**: Default sequential tests, 6 hours of legitimate traffic on 200 blocks: at points with conversion >= 0.75, verdict events <= 1 per 1000 legitimate requests. Holds if true in >= 90 % of those cells; points below 0.75 are reported, not judged.
- **C5**: Residential farm with caps: v2 (adaptive) leaks <= 0.7 x v1 (static) on the same point and seed, and refuses at least 10 percentage points more first-time users. Holds if both are true in >= 90 % of cells.

Points:

| Point | conversion | autofill_fraction | human_captcha_mean | whatsapp_fraction | returning_fraction | legit_rate_per_min |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 0.62 | 0.30 | 0.68 | 0.31 | 0.38 | 26.88 |
| 1 | 0.76 | 0.11 | 0.67 | 0.70 | 0.11 | 19.89 |
| 2 | 0.66 | 0.28 | 0.71 | 0.36 | 0.37 | 16.67 |
| 3 | 0.69 | 0.07 | 0.77 | 0.60 | 0.22 | 34.09 |
| 4 | 0.85 | 0.23 | 0.87 | 0.47 | 0.33 | 22.89 |
| 5 | 0.72 | 0.13 | 0.73 | 0.53 | 0.14 | 30.78 |
| 6 | 0.79 | 0.01 | 0.89 | 0.87 | 0.12 | 21.46 |
| 7 | 0.90 | 0.32 | 0.74 | 0.59 | 0.18 | 36.92 |
| 8 | 0.84 | 0.06 | 0.82 | 0.79 | 0.05 | 29.87 |
| 9 | 0.82 | 0.25 | 0.79 | 0.89 | 0.31 | 38.73 |
| 10 | 0.73 | 0.20 | 0.81 | 0.75 | 0.24 | 14.30 |
| 11 | 0.63 | 0.16 | 0.84 | 0.97 | 0.27 | 10.34 |

