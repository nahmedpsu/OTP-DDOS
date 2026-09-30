# OTP Guard: OTP flood protection

A layered SMS validation, risk-scoring and rate-limiting pipeline that stops OTP flood
abuse against a registration endpoint. This repository holds the problem statement, the
design with pseudocode, a full implementation with real vendor adapters, a test suite, and
recorded results.

[![CI](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml/badge.svg)](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml)

## What the evaluation shows, in three results

The evaluation is entirely simulated (see "Status and artifact availability"). Within it,
the thesis the results support is this: **a reputation signal separates attackers from
users only on keys the attacker dominates.** Every client-side key (IP, fingerprint,
session) can be rotated for almost nothing and a CAPTCHA solve costs about 0.003 USD, so
the attacker decides how pure those keys are. What a pumper cannot rotate is the
destination: it is paid only on the number blocks its partner carrier terminates.

1. **Positive.** Attacks that can be recognised per request are stopped completely with
   99 % of real users still delivered: a spoofed platform header, datacenter IP rotation,
   a premium-rate range, a single client, and now a sequential-number walk (a walk stays
   inside one destination block, which the feedback loop denylists).
2. **Negative, and general.** A residential flooder that looks like a real user (farmed
   CAPTCHA scores, fresh or pre-aged fingerprints, valid numbers) at a rate comparable to
   legitimate traffic leaves nothing but rationing. Its leakage and the friction for real
   users trade off along the measured frontier; the volume cap that holds it to 40 % of
   the requests refuses half of the real sign-ups.
3. **Open, and now partly measured.** Pumping is separable on the destination block.
   With the block key, the 2-minute resolution timeout and the relative baseline, a
   concentrated pumper whose carrier does not verify is contained in every seed
   (leak 220 of 600, median containment at minute 10); one whose carrier
   submits every code within a second is denylisted as machine-verified by minute
   8. A carrier that verifies 60 % of codes with a 30-second delay defeats both and
   leaves 324 verified fake accounts per run: the cost moves downstream to whatever the
   account is for, and measuring it there is the next experiment.

## Known weak spots

Each is quantified in [`results/evaluation.md`](results/evaluation.md) and discussed in
[`docs/evaluation.md`](docs/evaluation.md).

- **Dilution.** A residential attacker with human-like CAPTCHA scores whose volume stays
  below about 1.8 times the legitimate traffic on the shared country and prefix keys is
  not separated by any behavioural signal, including the relative baseline; it leaks
  582 of 600 with caps lifted and 244 with adaptive caps at 49 % delivery for real users.
- **Human-like verifying carrier.** Indistinguishable from real traffic on any key; only
  per-prefix caps and the spend breaker bound it.
- **Bought challenge solutions.** A datacenter attacker that pays for interactive-challenge
  solutions turns 0 leaked SMS into 50 per run; the `challenge_passed` credit reduces
  friction for people and is not a defence against solvers.
- **Carrier-grade NAT** delivers only 50 % of a normal sign-up flow until the carrier ASN is
  listed in `CGNAT_ASNS`.
- **Campaign bursts** deliver 12.5 % under the default source caps until the cap is raised.
- **VPN users are blocked** by policy, as the problem statement asked.
- **A single uvicorn worker under load exceeds the 400 ms floor** by wall time even though
  pipeline time stays under it; with four workers the floor holds
  (`results/performance.md`). Size workers so that it does.

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
| One client, random numbers | 31 | 2 | 2 | 99.2 % |
| Datacenter rotation, fresh fingerprints | 412 | 0 | 0 | 99.3 % |
| Premium-prefix pumping | 593 | 0 | 0 | 99.1 % |
| Spoofed platform header | 597 | 0 | 0 | 99.2 % |
| Sequential numbers | 593 | 75 | 67 | 90.7 % |
| Residential pool, reused browser profile | 597 | 122 | 94 | 93.6 % |
| Residential pool, bot CAPTCHA scores | 221 | 219 | 153 | 82.9 % |
| Residential pool, farmed CAPTCHA, fresh or pre-aged fingerprints | 597 | **582** | 244 | **48.8 %** |

![leakage vs friction](results/tradeoff.png)

Other things the evaluation established:

- **Which layer stops what** (ablation, same seeds in every column): the per-session cap
  stops the naive client; the risk engine stops datacenter rotation; number intelligence
  stops premium pumping; the feedback loop stops the reused-profile attacker
  (92 leaked with it, 245 without) and, with the destination-block key, the sequential walk
  (66 with both, 217 without the loop, 185 without the block key). No layer changes the diluted
  residential attackers.
- **Weights**: raising the fresh-fingerprint weight to 40 stops the farm attacker outright
  but challenges 60 % of legitimate new users; tier boundaries scaled to 0.6 cut its
  leakage by a third for a 21 % challenge rate. The OTP timeout does not move this
  attacker because the conversion signal never fires on shared keys.
- **Graded response**: about 2 % of legitimate requests (corporate, roaming and
  cloud-abroad egress) are challenged and 90 % of those complete it; the tier is exercised.
- **Low-and-slow**: attacks under the dilution bound leak in full at their own rate.
- **Economics**: premium pumping is profitable under v1 (14 to 38 USD per 20 minutes at 20
  to 50 % revenue share) and loses money under v2.
- **Performance**: see the section in `results/performance.md` and the note below.

- **Performance** (`results/performance.md`, real Redis, 4 uvicorn workers on 4 vCPUs, vendors
  faked): a full send costs 8.3 ms p50 / 16.6 ms p99 in process with
  41 Redis round trips. Over HTTP at concurrency 32 the service serves 303 requests/s
  without the floor; with it, throughput is concurrency divided by the floor (69 requests/s here)
  and is not a capacity figure. Timing leak, 6000 requests (3263 sent, 930 no session,
  925 disallowed country, 882 repeated number): with the 400 ms floor no pair of outcomes is
  distinguishable by Kolmogorov-Smirnov test (smallest p = 0.07) and every pair is equivalent within
  2 ms by TOST (largest p = 0.000; largest mean difference 0.32 ms); pipeline time exceeded the floor in
  0.0 % of requests. Without the floor every pair is distinguishable (p < 10⁻⁶).
  A single worker at this concurrency does exceed the floor by wall time; size workers so it does not.

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
