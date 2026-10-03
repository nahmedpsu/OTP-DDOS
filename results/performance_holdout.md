# Held-out timing check (fifth-round review, M10)

3 independent phase-4 runs (adversarial mixture, heavy-tailed vendors, floor 400 ms, concurrency 128, 3000 requests each) on a machine with 2 CPUs and 4 API workers. For each ordered pair of runs, the single latency threshold that best separates sends from Step 1 refusals (balanced accuracy, either direction) is fitted on the first run's client-side end-to-end times and applied unchanged to the second run's. Fitted accuracy is the resubstitution value, as reported for the original run in performance.md (a descriptive maximum); held-out accuracy is the threshold's accuracy on requests it was not fitted to.

Fitted (same samples): mean 0.996; held-out (other runs): mean 0.981, range 0.953 to 0.999.

| Fit run | Eval run | Threshold (ms) | Sends below | Fitted | Held-out | Sends / refusals (eval run) | Over floor, sends (eval run, server time) |
|---:|---:|---:|---|---:|---:|---|---:|
| 1 | 2 | 496 | False | 0.992 | 0.976 | 2498 / 22 | 99.9 % |
| 1 | 3 | 496 | False | 0.992 | 0.953 | 2497 / 22 | 99.8 % |
| 2 | 1 | 502 | False | 0.999 | 0.991 | 2497 / 22 | 99.0 % |
| 2 | 3 | 502 | False | 0.999 | 0.976 | 2497 / 22 | 99.8 % |
| 3 | 1 | 503 | False | 0.998 | 0.991 | 2497 / 22 | 99.0 % |
| 3 | 2 | 503 | False | 0.998 | 0.999 | 2498 / 22 | 99.9 % |
