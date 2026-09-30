# Results

Recorded outputs, regenerated with `make results`. Everything here is deterministic
(seeded RNG, fake clock, fakes for vendors), so a diff in this directory means behaviour changed.

| File | Produced by | What it shows |
|---|---|---|
| `test_report.txt` | `make test-report` | Full pytest output, every test on the memory and the Redis backend. |
| `scenarios.md`, `scenarios.json` | `make scenarios` | The attack and user scenarios from the problem statement: requests in, SMS out, and the mechanism that stopped each one. |
| `evaluation.md`, `evaluation.json`, `evaluation_runs.jsonl.gz`, `tradeoff.png` | `make evaluation` | The main evaluation: 30-seed randomised runs with 95 % CIs for v1 and v2 in two modes, ablation, weight and cap sweeps with the leakage-friction trade-off, adaptive attackers, attacker economics, calibration sources. Raw per-run records in the gzip. |
| `performance.md`, `performance.json` | `make load-test` | Pipeline on a real Redis: per-step and end-to-end latency percentiles, Redis commands per request, HTTP throughput, KS timing-leak tests with and without the 400 ms floor. |
| `analysis.md`, `analysis.json` | `make analysis` | A: attacker profiles against each layer. B: legitimate use cases and false positives. C: v1 versus v2 SMS and cost under the same attacks. D: sensitivity to OTP timeout and denylist sample size. |
| `api_smoke.txt` | `make smoke` | The real HTTP service booted with uvicorn and driven through a session, an OTP request, a replay, a verify and the feedback tick. |
