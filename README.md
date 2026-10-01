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
   a premium-rate range, a single client, and a sequential-number walk (a walk stays
   inside one destination block, which reaches a verdict after five unverified sends).
2. **Negative, and general.** A residential flooder that looks like a real user (farmed
   CAPTCHA scores, fresh or pre-aged fingerprints, valid numbers) leaves nothing but
   rationing. Against it v1 with static caps leaks 563 of 600 at 4 % refusal of
   real users; v2's adaptive cap leaks 241 at 42 % refusal (first-time users; returning
   users are exempt). All of v2's gain against this attacker is rationing, along the
   measured frontier. Raising the attack to 10 times the legitimate volume for an hour does
   not change the picture: the conversion penalty starts firing but 71 % of the attack
   still leaks while 18 % of real users are challenged.
3. **Pumping is separable on the destination block, and the cost has a closed form.**
   Against the block tests a pumper's leakage depends only on how many 8-digit blocks it
   touches, B: about 5 B + rate x 2.5 min for a carrier that never verifies, and 5 B for
   one that verifies within a second (`src/otp_guard/evaluation/model.py`; the spread sweep
   in section G matches it to within a few SMS at every point). On three blocks that is
   104 and 18 leaked of 600; on 300 blocks the pumper is the flooder again
   (`results/pumper_spread.png`). A carrier evades the conversion test by verifying at
   least 42 % of its codes, each a verified fake account: the 60 %-verifying carrier leaks
   everything under every variant and leaves 323 fake accounts per run. The cost moves
   downstream to whatever the account is for, and measuring it there is the next experiment.
4. **What the block tests cost real users is now measured** (section H). Twenty-four hours
   of legitimate traffic at 80 % conversion produce 0 to 2 block verdicts a day and touch
   at most one or two real users; at 65 % conversion (Twilio's global figure) 3 to 18
   blocks a day reach a verdict and 1 to 22 of 29 000 real users meet a challenge, with
   delivery unchanged at 99.3 %. A 30-minute carrier outage produces no verdict when the
   provider's delivery receipts gate the tests and a carrier-wide collapse suspends them;
   the earlier send-clocked design flagged 1.4 blocks per outage. A verdict is graded
   (a challenge for the block's first-time clients for an hour, then non-SMS channels),
   and clients with verified history are never affected; the 24-hour denylist is kept as
   an option and buys a challenge-solving pumper's containment 18 SMS sooner.

## Known weak spots

Each is quantified in [`results/evaluation.md`](results/evaluation.md) and discussed in
[`docs/evaluation.md`](docs/evaluation.md).

- **Dilution.** A residential attacker with human-like CAPTCHA scores is not separated by
  any behavioural signal at any volume tested. Below about 1.8 times the legitimate
  traffic on the shared country and prefix keys the conversion penalty does not fire; above
  it, it fires on everyone sharing the key. It leaks 597 of 600 with caps lifted and
  241 with adaptive caps at 58 % delivery for real users.
- **The block tests are only as good as their calibration.** They assume the deployment's
  legitimate conversion and its share of fast (autofill) verifications; at a true
  conversion of 50 % they flag 9 to 25 % of blocks a day (section H1). `sprt_legit_conversion`
  and `sprt_legit_fast` must be set from measured traffic, and the Monte Carlo in
  `evaluation/runner.py` rerun for the result.
- **The outage detector's conversion signal needs returning users.** It takes ten resolved
  sends from clients with verified history to see a silent outage; the delivery-receipt
  signal is faster and only as honest as the provider's reports.
- **Pumper spread.** Block-level containment holds while the carrier's ranges fit inside
  10 000-number blocks; 100 000-number ranges or hundreds of ranges leak like the flooder.
- **Human-like verifying carrier.** Indistinguishable from real traffic on any key once it
  verifies more than 42 % of its codes; only per-prefix caps and the spend breaker bound it.
- **Bought challenge solutions.** A datacenter attacker that pays for interactive-challenge
  solutions turns 0 leaked SMS into about 50 per run; the `challenge_passed` credit reduces
  friction for people and is not a defence against solvers. A pumper that solves its way
  past a stage-1 block verdict earns a second verdict and is moved off SMS (122 leaked
  against 104 under the hard denylist).
- **Carrier-grade NAT** delivers only 50 % of a normal sign-up flow until the carrier ASN is
  listed in `CGNAT_ASNS`.
- **Campaign bursts** deliver 12.5 % under the default source caps until the cap is raised.
- **VPN users are blocked** by policy, as the problem statement asked.
- **A single uvicorn worker under load exceeds the 400 ms floor** by wall time even though
  pipeline time stays under it; with one worker per vCPU the floor holds
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
with the v2 layers switched off. "Behavioural only" lifts the source caps; "with source caps"
runs them at 3x the legitimate rate, adaptive for v2 and static for v1 (the adaptive cap is
v2's Step 9).

| Attacker (600 requests over 20 min) | v1 leaked, caps lifted | v2 leaked, caps lifted | v1 with static caps: leaked / real users refused | v2 with adaptive caps: leaked / real users refused |
|---|---:|---:|---:|---:|
| One client, random numbers | 31 | 2 | 31 / 1 % | 2 / 1 % |
| Datacenter rotation, fresh fingerprints | 416 | 0 | 400 / 2 % | 0 / 1 % |
| Premium-prefix pumping | 595 | 0 | 558 / 4 % | 0 / 1 % |
| Spoofed platform header | 599 | 0 | 100 / 0 % | 0 / 1 % |
| Sequential numbers | 595 | 70 | 558 / 4 % | 63 / 2 % |
| Residential pool, reused browser profile | 593 | 126 | 563 / 4 % | 93 / 6 % |
| Residential pool, bot CAPTCHA scores | 219 | 221 | 219 / 1 % | 160 / 12 % |
| Residential pool, farmed CAPTCHA, fresh or pre-aged fingerprints | 593 | 597 | 563 / 4 % | 241 / 42 % |

![leakage vs friction](results/tradeoff.png)

Other things the evaluation established:

- **Which layer stops what** (ablation, same seeds in every column): the per-session cap
  stops the naive client; the risk engine stops datacenter rotation; number intelligence
  stops premium pumping; the feedback loop stops the reused-profile attacker
  (98 leaked with it, 246 without) and, with the destination-block key, the sequential walk
  (61 with both, 231 without the loop, 178 without the block key). Against the diluted
  residential attackers only the adaptive cap changes anything (246 with it, 550 without),
  and it does so by refusing real users.
- **Weights**: raising the fresh-fingerprint weight to 40 stops the farm attacker outright
  but challenges 60 % of legitimate new users; tier boundaries scaled to 0.6 cut its
  leakage by a third for a 21 % challenge rate. The OTP timeout does not move this
  attacker because the conversion signal never fires on shared keys.
- **Delivery receipts**: a send counts as failed only after the carrier confirmed delivery
  and two minutes passed; a send with no receipt, or a failed one, is undelivered and
  feeds nothing. Verification speed is clocked from the receipt. Post the provider's
  reports to `POST /internal/delivery` (`docs/deployment.md`).
- **Graded response**: about 2 % of legitimate requests (corporate, roaming and
  cloud-abroad egress) are challenged and 90 % of those complete it; the tier is exercised.
- **Low-and-slow**: attacks under the dilution bound leak in full at their own rate.
- **Economics** (revenue credited only to pumping attackers): premium pumping is profitable
  under v1 and loses money under v2; a concentrated pumper whose carrier verifies with
  human-like delay stays profitable under both and additionally hands the defender
  323 verified fake accounts per 20 minutes; the instant verifier loses money under v2.
- **Performance** (`results/performance.md`, real Redis, 2 uvicorn workers on 2 vCPUs, vendors
  faked): a full send costs 9.0 ms p50 / 16.3 ms p99 in process with
  46 Redis round trips (41 before delivery receipts, the block-test counters and the outage
  windows were added). Over HTTP at concurrency 32 the service serves 210 requests/s
  without the floor; with it, throughput is concurrency divided by the floor (70 requests/s here)
  and is not a capacity figure. Timing leak, 6000 requests (3264 sent, 930 no session,
  925 disallowed country, 881 repeated number): with the 400 ms floor no pair of outcomes is
  distinguishable by Kolmogorov-Smirnov test (smallest p = 0.33) and every pair is equivalent within
  2 ms by TOST (largest mean difference 0.62 ms); pipeline time exceeded the floor in
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
