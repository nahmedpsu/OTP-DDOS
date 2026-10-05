# Operating condition from unfitted inputs (sixth-round review, M1, M2)

k = 5; tau = 120 + 3 + 30 s; q = 4 per 10 minutes; lambda = offered requests / attack minutes, per run; N = offered requests, per run. Means over five seeds (300-304). Nothing below is fitted to E4.

In the 18 cells where the two estimates differ, the predicted ordering (counter bound below the tests' estimate) matches the measured ordering in 18; in the other 2 both estimates equal N and no ordering is predicted.

| Blocks | Pumper | Minutes | lambda tau | Tests: estimate | Tests: measured | Counter: bound | Counter: measured | No policy | Counter less: predicted / measured |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---|
| 3 | quota-aware | 20 | 3 | 18 | 23 | 24 | 24 | 24 | no / no |
| 3 | quota-aware | 60 | 3 | 18 | 23 | 72 | 71 | 72 | no / no |
| 3 | spreading, never verifies | 20 | 89 | 104 | 110 | 24 | 25 | 342 | yes / yes |
| 3 | spreading, never verifies | 60 | 90 | 105 | 110 | 72 | 71 | 366 | yes / yes |
| 10 | quota-aware | 20 | 10 | 60 | 76 | 80 | 79 | 80 | no / no |
| 10 | quota-aware | 60 | 10 | 60 | 76 | 240 | 238 | 239 | no / no |
| 10 | spreading, never verifies | 20 | 91 | 141 | 144 | 80 | 81 | 700 | yes / yes |
| 10 | spreading, never verifies | 60 | 89 | 139 | 144 | 240 | 240 | 1088 | no / no |
| 30 | quota-aware | 20 | 31 | 181 | 217 | 240 | 238 | 239 | no / no |
| 30 | quota-aware | 60 | 31 | 181 | 217 | 720 | 715 | 716 | no / no |
| 30 | spreading, never verifies | 20 | 91 | 241 | 242 | 240 | 235 | 710 | yes / yes |
| 30 | spreading, never verifies | 60 | 90 | 240 | 242 | 720 | 679 | 2014 | no / no |
| 100 | quota-aware | 20 | 74 | 503 | 509 | 582 | 579 | 580 | no / no |
| 100 | quota-aware | 60 | 75 | 575 | 594 | 1755 | 1742 | 1746 | no / no |
| 100 | spreading, never verifies | 20 | 91 | 520 | 503 | 582 | 536 | 712 | no / no |
| 100 | spreading, never verifies | 60 | 92 | 592 | 603 | 1755 | 1543 | 2149 | no / no |
| 300 | quota-aware | 20 | 90 | 703 | 686 | 703 | 697 | 699 | tie / no |
| 300 | quota-aware | 60 | 92 | 1437 | 1344 | 2155 | 2136 | 2140 | no / no |
| 300 | spreading, never verifies | 20 | 90 | 703 | 676 | 703 | 673 | 699 | tie / yes |
| 300 | spreading, never verifies | 60 | 92 | 1437 | 1347 | 2155 | 2052 | 2140 | no / no |
