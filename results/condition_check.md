# Leakage estimates and the counter's bound on the E4 runs (seventh-round review, M2, M3)

k = 5; tau = 153 s; q = 4 per 10 minutes; per run: N offered requests, B blocks requested, lambda = N / attack minutes, and each block's counter state at the pumper's first attack request. Five seeds (300-304) per cell. Nothing is fitted to E4 leakage.

## The counter's bound on every counter run

100 counter runs; in 44 every block was empty when the pumper arrived (cold start), and 0 of those exceed Equation 3. In 7 runs the pumper drew 7 SMS in all as a client with verified history (a real user's trusted number inside its block), which no form of the bound covers; they are subtracted before the comparison. Runs over the bound: cold-start form (Eq. 3) 3, warm-start form with each block's residual quota (Eq. 4) 0, state-free form q B w + B (q - 1) 0.

Runs over the cold-start form (every one has blocks with a window already open):

| Blocks | Pumper | Minutes | Seed | Leaked | Exempt | Cold bound | Blocks with an open window |
|---:|---|---:|---:|---:|---:|---:|---:|
| 3 | spreading, never verifies | 20 | 302 | 30 | 0 | 24 | 2 of 3 |
| 3 | spreading, never verifies | 60 | 302 | 78 | 0 | 72 | 2 of 3 |
| 10 | spreading, never verifies | 20 | 302 | 85 | 0 | 80 | 2 of 10 |

## Ordering

- With the cold-start counter estimate (Eq. 3): the predicted ordering matches the measured one in 18 of 18 decisive cell-mean comparisons (2 ties), and in 76 of 78 decisive seed-level comparisons.
- With the warm-start counter estimate (Eq. 4): the predicted ordering matches the measured one in 17 of 18 decisive cell-mean comparisons (2 ties), and in 76 of 78 decisive seed-level comparisons.

  - cold: 3 blocks, quota-aware, 20 min, seed 302: estimates 18.1 (tests) against 24 (counter); measured 24 against 22.
  - cold: 10 blocks, quota-aware, 20 min, seed 301: estimates 60.2 (tests) against 80 (counter); measured 79 against 78.
  - warm: 3 blocks, quota-aware, 20 min, seed 302: estimates 18.1 (tests) against 24 (counter); measured 24 against 22.
  - warm: 10 blocks, quota-aware, 20 min, seed 301: estimates 60.2 (tests) against 80 (counter); measured 79 against 78.

| Blocks | Pumper | Min | lambda tau | Tests est. | Tests meas. | Counter cold | Counter warm | Open blocks | Counter meas. | None | Tests - counter, paired [95% CI] | Counter less: cold / warm / measured |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 3 | quota-aware | 20 | 3 | 18 | 23.2 | 24 | 24.0 | 0.4 of 3 | 23.6 | 24 | -0.4 [-2.4, 1.2] | no / no / no |
| 3 | quota-aware | 60 | 3 | 18 | 23.2 | 72 | 72.0 | 0.4 of 3 | 71.2 | 72 | -48.0 [-50.2, -46.2] | no / no / no |
| 3 | spreading, never verifies | 20 | 89 | 104 | 109.6 | 24 | 25.2 | 0.4 of 3 | 25.4 | 342 | 84.2 [42.4, 130.2] | yes / yes / yes |
| 3 | spreading, never verifies | 60 | 90 | 105 | 109.6 | 72 | 73.2 | 0.4 of 3 | 71.0 | 365 | 38.6 [-5.6, 89.0] | yes / yes / yes |
| 10 | quota-aware | 20 | 10 | 60 | 76.4 | 80 | 80.0 | 0.4 of 10 | 79.0 | 80 | -2.6 [-6.0, 0.4] | no / no / no |
| 10 | quota-aware | 60 | 10 | 60 | 76.4 | 240 | 240.0 | 0.4 of 10 | 238.0 | 239 | -161.6 [-165.0, -158.8] | no / no / no |
| 10 | spreading, never verifies | 20 | 91 | 141 | 144.2 | 80 | 81.2 | 0.4 of 10 | 80.8 | 700 | 63.4 [23.4, 102.6] | yes / yes / yes |
| 10 | spreading, never verifies | 60 | 89 | 139 | 144.2 | 240 | 241.2 | 0.4 of 10 | 239.8 | 1088 | -95.6 [-134.6, -57.4] | no / no / no |
| 30 | quota-aware | 20 | 31 | 181 | 217.2 | 240 | 240.0 | 0.6 of 30 | 237.8 | 239 | -20.6 [-33.2, -7.6] | no / no / no |
| 30 | quota-aware | 60 | 31 | 181 | 217.2 | 720 | 720.0 | 0.6 of 30 | 714.8 | 716 | -497.6 [-509.0, -485.4] | no / no / no |
| 30 | spreading, never verifies | 20 | 91 | 241 | 241.6 | 240 | 241.8 | 0.6 of 30 | 235.0 | 710 | 6.6 [-27.2, 42.4] | yes / no / yes |
| 30 | spreading, never verifies | 60 | 90 | 240 | 241.8 | 720 | 721.8 | 0.6 of 30 | 678.6 | 2014 | -436.8 [-453.0, -423.0] | no / no / no |
| 100 | quota-aware | 20 | 74 | 503 | 508.6 | 582 | 582.4 | 3.2 of 99 | 578.6 | 580 | -70.0 [-125.0, -17.6] | no / no / no |
| 100 | quota-aware | 60 | 75 | 575 | 592.8 | 1755 | 1755.2 | 3.2 of 100 | 1742.0 | 1746 | -1149.2 [-1561.8, -735.2] | no / no / no |
| 100 | spreading, never verifies | 20 | 91 | 520 | 502.6 | 582 | 585.4 | 3.0 of 99 | 536.4 | 712 | -33.8 [-66.6, -8.4] | no / no / no |
| 100 | spreading, never verifies | 60 | 92 | 592 | 598.0 | 1755 | 1758.2 | 3.0 of 100 | 1543.2 | 2149 | -945.2 [-1267.8, -633.0] | no / no / no |
| 300 | quota-aware | 20 | 90 | 703 | 686.2 | 703 | 703.0 | 6.2 of 252 | 696.6 | 699 | -10.4 [-23.8, -0.2] | tie / tie / no |
| 300 | quota-aware | 60 | 92 | 1437 | 1338.2 | 2155 | 2154.6 | 7.4 of 296 | 2135.6 | 2140 | -797.4 [-1492.4, -139.4] | no / no / no |
| 300 | spreading, never verifies | 20 | 90 | 703 | 676.0 | 703 | 703.0 | 6.2 of 251 | 672.8 | 699 | 3.2 [1.2, 6.2] | tie / tie / yes |
| 300 | spreading, never verifies | 60 | 92 | 1437 | 1340.2 | 2155 | 2154.6 | 7.4 of 296 | 2051.8 | 2140 | -711.6 [-1313.0, -136.6] | no / no / no |
