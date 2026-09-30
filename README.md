# OTP Guard: OTP flood protection

A layered SMS validation, risk-scoring and rate-limiting pipeline that stops OTP flood
abuse against a registration endpoint. This repository holds the problem statement, the
design with pseudocode, a full implementation with real vendor adapters, a test suite, and
recorded results.

[![CI](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml/badge.svg)](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml)

## Known weak spots, stated first

The evaluation is entirely simulated (see "Status and artifact availability" below). Within
that simulation, these are the measured limits of the design; each is quantified in
[`results/evaluation.md`](results/evaluation.md) and discussed in
[`docs/evaluation.md`](docs/evaluation.md).

- **Dilution.** A residential attacker with human-like CAPTCHA scores whose volume stays
  below about 1.8 times the legitimate traffic on the same country and prefix keys is not
  separated from real users by any behavioural signal. Containment then comes only from the
  adaptive volume caps and the circuit breaker, which also refuse legitimate users.
- **Exposure before feedback.** Until codes have had time to be entered, leakage equals the
  attack rate times the OTP timeout: 300 SMS at 30 requests a minute and a 10-minute timeout.
- **Sequential-number walks** from many networks are flagged (+15), not stopped.
- **Carrier-grade NAT** delivers only 50 % of a normal sign-up flow until the carrier ASN is
  listed in `CGNAT_ASNS`.
- **Campaign bursts** deliver 12.5 % under the default source caps until the cap is raised.
- **VPN users are blocked** by policy, as the problem statement asked.
- **A colluding carrier that verifies codes** with human-like delay on a range missing from
  the prefix table is indistinguishable from real traffic; only per-prefix caps and the
  spend breaker bound it.
- **Bought challenge solutions** earn the `challenge_passed` credit and can move an attacker
  from `challenge` back to `delay`.

## Repository layout

```
docs/
  problem_statement.md          the incident, the v1 mitigation, gaps A to H, v2 objectives
  sms_validation_process.md     the v2 design: 12 steps, feedback loop, defaults and reasons
  pseudocode/                   one file per step, extracted from the design, mapped to code
  architecture.md               components, request flow, state keys
  api.md                        HTTP endpoints
  deployment.md                 environment variables, adapters, failure policies, operations
  use_cases.md                  flows, operational situations, internal callers, staged rollout
  evaluation.md                 weak spots, metric definitions, statistical method, calibration, limitations
  privacy_and_ethics.md         data inventory and retention, GDPR and PDPL notes, approvals still needed
  replay_schema.md              CSV schema for replaying anonymised production logs
  original/                     the three source documents this work started from
src/otp_guard/
  pipeline.py                   Steps 0 to 11, one method each
  store.py                      MemoryStore and RedisStore behind one interface; atomic RateLimit
  reputation.py                 rolling reputation counters, conversion ratio, adaptive limits
  feedback.py                   verification feedback loop, verify endpoint limits, auto-denylist
  services.py                   fakes and shared dataclasses
  providers/                    real adapters: reCAPTCHA, Play Integrity, App Attest, ipinfo,
                                AbuseIPDB, Twilio Lookup, Twilio SMS/WhatsApp, FCM, Slack
  factory.py                    build a pipeline from the environment; wiring report
  api.py                        FastAPI service       worker.py   background tick
  testing.py                    harness shared by tests and scripts
  evaluation/                   calibrated simulation, metrics, statistics, study runner
tests/
  unit/                         per step, per adapter, factory
  integration/                  HTTP API, end-to-end attack and user scenarios
scripts/
  run_scenarios.py              attack scenarios -> results/scenarios.{md,json}
  run_analysis.py               single-seed walkthrough of attacker profiles and use cases -> results/analysis.{md,json}
  run_evaluation.py             30-seed evaluation with CIs, ablation, sweeps, adaptive attackers -> results/evaluation.*
  load_test.py                  latency on a real Redis and KS timing-leak test -> results/performance.*
  replay_logs.py                replay anonymised logs (docs/replay_schema.md) through v1 and v2
  generate_synthetic_logs.py    synthetic logs in the replay schema
  extract_pseudocode.py         design -> docs/pseudocode/ (CI checks it is in sync)
  smoke_api.py                  boots the real service and drives a flow -> results/api_smoke.txt
results/                        recorded outputs of the above (deterministic)
config/                         sample prefix cost table and source limits
```

## Quick start

```
make install        # pip install -e ".[dev,google]"
make test           # every pipeline test on both memory and Redis backends; see results/test_report.txt for the count
make scenarios      # the attack scenarios, written to results/
make analysis       # single-seed walkthrough of attacker profiles and use cases
make evaluation     # the 30-seed evaluation (about 5 minutes on 4 cores)
make load-test      # needs redis-server; about 2 minutes
make replay-demo    # synthetic logs through the replay tool
make smoke          # boot the HTTP service on fakes and drive one flow
make results        # regenerate everything under results/
```

## The pipeline in one table

| Step | Check | Problem it addresses |
|---|---|---|
| 0 | Connection and client integrity: proxy block, platform from attestation | VPN/proxy, header spoofing |
| 1 | Signed session token, fingerprint, nonce replay, per-session cap | IP rotation, replay |
| 2 | IP, subnet and ASN throttles, atomic | IP rotation, race conditions |
| 3 | reCAPTCHA v3 with score threshold | Bots |
| 4 | Origin validation | Domain whitelisting |
| 5 | Number intelligence: country, prefix cost class, pattern detection, HLR | Random numbers, SMS pumping |
| 6 | Text validation | Body restrictions |
| 7 | Risk score engine: allow, delay, challenge, downgrade, block | Probeable binary decisions |
| 8 | Per-number progressive backoff and daily cap | Per-number flooding |
| 9 | Adaptive limits per source, platform, country | Aggregate caps |
| 10 | Global circuit breaker on count and spend | No global cap |
| 11 | Channel selection, audit log, uniform response | Enumeration |
| FB | Verification feedback loop: verify-to-send ratio feeds reputation | Separates attackers only on keys they dominate; see the evaluation |

Full detail, pseudocode and the reasoning behind every default: `docs/sms_validation_process.md`.

## Headline results

From `results/evaluation.md`: 30 seeds per attacker with randomised pool size, attack rate and
CAPTCHA class; 20 requests/min of legitimate traffic in the background; means with 95 %
confidence intervals in the full tables. v1 is the original design run through the same code
with the v2 layers switched off. "Behavioural only" lifts the source caps; "with adaptive
caps" runs them at 3x the legitimate rate.

| Attacker (600 requests over 20 min) | v1 leaked | v2 leaked, behavioural only | v2 leaked, with caps | v2 legit delivered, with caps |
|---|---:|---:|---:|---:|
| One client, random numbers | 29 | 2 | 2 | 99.5 % |
| Datacenter rotation, fresh fingerprints | 410 | 0 | 0 | 99.5 % |
| Premium-prefix pumping | 597 | 0 | 0 | 99.5 % |
| Spoofed platform header | 601 | 0 | 0 | 99.5 % |
| Residential pool, bot CAPTCHA scores | 212 | 212 | 154 | 85.6 % |
| Residential pool, reused browser profile | 593 | 352 | 171 | 68.9 % |
| Sequential numbers | 597 | 379 | 200 | 65.4 % |
| Residential pool, farmed CAPTCHA, fresh or pre-aged fingerprints | 593 | **593** | 245 | **47.4 %** |

The last row is the honest headline. Against a residential attacker with human-like
CAPTCHA scores at a rate comparable to legitimate traffic, no behavioural signal separates
the two, and the volume cap that does contain it refuses half of the real sign-ups. The
trade-off is measurable and is the design's main open problem:

![leakage vs friction](results/tradeoff.png)

Other things the evaluation established:

- **Which layer stops what** (ablation): the per-session cap is the single most valuable
  layer; removing it raises leakage for five of nine attackers. The risk engine stops
  datacenter rotation, number intelligence stops premium pumping. Removing the feedback loop
  changes nothing under dilution, which is the point of weak spot 1.
- **Weights**: raising the fresh-fingerprint weight to 40 stops the farm attacker outright
  but challenges 60 % of legitimate new users; the tier boundaries scaled to 0.6 cut leakage
  by a third for a 21 % challenge rate. OTP timeout has no effect on this attacker because
  the conversion signal never fires.
- **Adaptive attackers**: a colluding carrier that verifies its own codes on a listed range
  is held to 20 SMS by the per-prefix cap whether it verifies instantly or with human-like
  delay; on an unlisted range it is indistinguishable from real traffic. Low-and-slow attacks
  under the dilution bound leak in full.
- **Economics**: premium pumping is profitable under v1 (14 to 38 USD per 20 minutes at 20
  to 50 % revenue share) and loses money under v2.
- **Performance** (`results/performance.md`, real Redis, one uvicorn process on 4 vCPUs):
  a full send costs 7.2 ms p50 / 14.1 ms p99 in
  process and 40 Redis round trips. Over HTTP at concurrency 16 the service
  sustains 135 requests/s without the floor and 39 with it. With the 400 ms
  floor, Kolmogorov-Smirnov tests cannot tell a sent code from a number-related rejection
  (p = 0.37 and 0.72); without it every pair is distinguishable (p < 10⁻⁶). A
  residual ~1 ms difference remains for requests that present no session at all (p < 0.01),
  which tells an attacker nothing they did not already know.

`results/analysis.md` is an earlier single-seed walkthrough without background traffic; it
overstates containment for residential attackers and is kept for the use-case tables.

## Status and artifact availability

**What this is.** A design, a working implementation with real vendor adapters, and a
simulated evaluation. Everything in `results/` is reproducible from this repository with
`make results`; the simulation is deterministic for a given seed set.

**What it is not.** No production data was used. No anonymised logs from the original
incident or the v1 period were available, and no live call to any vendor has been made
from this repository. The evaluation is calibrated to published prices and measurements
where they exist and to stated assumptions where they do not (`docs/evaluation.md`,
"Calibration"; the full table with sources is at the end of `results/evaluation.md`).
The biggest single improvement available is to replay real logs through
`scripts/replay_logs.py` under the schema in `docs/replay_schema.md`; that requires the
approvals listed in `docs/privacy_and_ethics.md`.

**Archiving.** `CITATION.cff` and `.zenodo.json` are in place; the author name is a
placeholder until the author fills it in. Releases are tagged (`git tag`); to obtain a DOI,
enable the repository in Zenodo's GitHub integration and publish a release, which Zenodo
archives automatically. Record the DOI here once minted: _(none yet)_.

**Ethics and permissions.** See `docs/privacy_and_ethics.md` for the data-retention
statement and the approvals still to be recorded (ethics approval for any production-log
replay; employer permission to describe the incident).
