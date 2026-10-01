# OTP Guard: OTP flood protection

A layered SMS validation, risk-scoring and rate-limiting pipeline that stops OTP flood
abuse against a registration endpoint. This repository holds the problem statement, the
design with pseudocode, a full implementation with real vendor adapters, a test suite, and
recorded results.

[![CI](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml/badge.svg)](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml)

## What the evaluation shows, in four results

The evaluation is entirely simulated (see "Status and artifact availability"). Within it,
the thesis the results support is this: **a reputation signal separates attackers from
users only on keys the attacker dominates.** Every client-side key (IP, fingerprint,
session) can be rotated for almost nothing and a CAPTCHA solve costs about 0.003 USD, so
the attacker decides how pure those keys are. What a pumper cannot rotate is the
destination: it is paid only on the number blocks its partner carrier terminates.

1. **Positive, with the residue stated.** Attacks that can be recognised per request are
   contained with 98 to 100 % of real users still delivered: datacenter IP rotation and
   premium-rate pumping leak 0 of 600, a single client leaks 2, and a sequential-number
   walk leaks 65 to 71 before its destination block reaches a verdict. A plain limit of
   five sends per destination block per day (`block_limit_only` in section A) stops the
   walk and the premium pumper at 5 SMS each; the sequential tests buy nothing over it
   there and earn their place only against carriers that verify (result 3).
2. **Negative, and general.** A residential flooder that looks like a real user (farmed
   CAPTCHA scores, fresh or pre-aged fingerprints, valid numbers) leaves nothing but
   rationing. Against it v1 with static caps leaks 563 of 600 and refuses 4 % of first-time
   users; v2's adaptive cap leaks 243 and refuses 51 % of first-time users (returning users
   are exempt and 99.5 % of them are delivered; 60 % of all real requests are delivered).
   All of v2's gain against this attacker is rationing, along the measured frontier, and it
   exists only because the controller runs every minute: run hourly, the same design leaks
   575 at 1.3 % refusal (section B2). Raising the attack to 10 times the legitimate volume
   for an hour does not change the picture: 70 % of the attack still leaks while 17 % of
   real users are challenged. A forged platform header buys this attacker nothing under v2
   (243, the same as without the header); under v1 the header is believed and the
   attacker lands in the app bucket, where the static app cap holds it to 100 without
   touching web users. Attestation removes the attacker's choice of bucket; it does not
   reduce leakage.
3. **Pumping is separable on the destination block, the cost has a closed form, and the
   test's memory is a dial.** Against the block tests a pumper's leakage depends on how
   many 8-digit blocks it touches, B: about 5 B + rate x 2.5 min for a carrier that never
   verifies and 5 B for one that verifies within a second (`src/otp_guard/evaluation/model.py`;
   section G matches it to within a few SMS at every point of the spread sweep). On three
   blocks that is 99 and 36 leaked of 600; on 300 blocks the pumper is the flooder again
   (`results/pumper_spread.png`). A carrier that verifies 60 % of its codes with human-like
   delay is the hard case, and how the test treats its history decides it: with the default
   one threshold of credit it leaks 440 and leaves 264 verified fake accounts per run; with
   no credit (Page's CUSUM) 158 and 93; with unbounded credit (plain SPRT) 575. The credit
   setting is paid for in false positives (result 4). A carrier that fakes failed delivery
   receipts never reaches a verdict (255 leaked under caps, 567 without) and is bounded only
   by the caps; so is a pumper that builds trust first (349 and 511). The cost of the
   human-like case moves downstream to whatever the account is for.
4. **What the block tests cost real users is measured, and it set the default** (section
   H). Twenty-four hours of legitimate traffic at 80 % conversion produce 0 to 2 block
   verdicts a day on realistic block densities and touch at most a couple of real users; at
   65 % conversion (Twilio's global figure) 6 to 21 blocks a day reach a verdict and 20 to
   43 of about 29 000 real users meet a challenge, with delivery unchanged at 99.3 %. With
   no credit the same 65 % population produced 103 to 139 verdicts and 700 to 870 users hit
   a day, which is why one threshold of credit is the default even though it costs the
   human-like pumper case above. A 30-minute carrier outage produces 0.5 to 0.75 verdicts
   touching 1 to 2 users when receipts gate the tests (1.5 and 3 without receipts). A
   verdict is graded (a challenge for the block's first-time clients for an hour, then
   non-SMS channels), and clients with verified history are never affected.

## Known weak spots

Each is quantified in [`results/evaluation.md`](results/evaluation.md) and discussed in
[`docs/evaluation.md`](docs/evaluation.md).

- **Dilution.** A residential attacker with human-like CAPTCHA scores is not separated by
  any behavioural signal at any volume tested. Below about 1.8 times the legitimate
  traffic on the shared country and prefix keys the conversion penalty does not fire; above
  it, it fires on everyone sharing the key. It leaks 595 of 600 with caps lifted and
  243 with adaptive caps at 60 % delivery for real users (51 % of first-time users refused).
- **Rationing needs a fast controller.** The adaptive cap's whole effect against the
  diluted attackers comes from running every minute; every 10 minutes it leaks 565, hourly
  575 (section B2). The worker runs it every minute by default.
- **The block tests are only as good as their calibration.** They assume the deployment's
  legitimate conversion and its share of fast (autofill) verifications; at a true
  conversion of 50 % they flag 9 to 41 % of blocks with 10 to 100 sends a day (section H1),
  at 65 %, 1 to 3 %. `sprt_legit_conversion` and `sprt_legit_fast` must be set from
  measured traffic, and the Monte Carlo in `evaluation/runner.py` rerun for the result.
- **Memory is a trade-off, not a free parameter.** `block_credit_thresholds` decides how
  much goodwill a block banks: 0 catches the human-like concentrated carrier (158 leaked)
  but flags a 65 %-converting legitimate block about a hundred times a day; the default of
  1 flags it 6 to 21 times and lets that carrier leak 440.
- **Faked receipts and bought trust defeat the block tests outright.** A carrier that
  reports every delivery as failed feeds the tests nothing and leaks 255 (caps) or 567 (no
  caps) with no verdict ever; a pumper whose identities and numbers verify everything for
  ten minutes and then flood leaks 349 or 511 and keeps 194 to 262 verified fake accounts.
  Only the caps and the spend breaker bound either.
- **The block key can be turned on real users.** An attacker that floods the blocks real
  users concentrate on earns them verdicts: 8 to 12 blocks per run, 11 to 25 % of real
  users made to solve a challenge, 11 to 20 % of requests challenged (section D). The
  graded verdict keeps this at a challenge rather than a refusal; the hard denylist would
  not.
- **The outage detector's conversion signal needs returning users.** It takes ten resolved
  sends from clients with verified history to see a silent outage; the delivery-receipt
  signal is faster and only as honest as the provider's reports.
- **Pumper spread.** Block-level containment holds while the carrier's ranges fit inside
  10 000-number blocks; 100 000-number ranges or hundreds of ranges leak like the flooder.
- **Bought challenge solutions.** A datacenter attacker that pays for interactive-challenge
  solutions turns 0 leaked SMS into 53 to 56 per run; the `challenge_passed` credit reduces
  friction for people and is not a defence against solvers. A pumper that solves its way
  past a stage-1 block verdict earns a second verdict and is moved off SMS (115 leaked
  against 102 under the hard denylist).
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
with the v2 layers switched off. "Caps lifted" removes the source caps; "with source caps"
runs them at 3x the legitimate rate, static for v1 and adaptive (re-learned every minute by
the baseline job, v2's Step 9) for v2. Refusal is reported for first-time users, the only
group the caps touch; returning users are exempt and 99 % or more of them are delivered in
every cell.

| Attacker (600 requests over 20 min) | v1 leaked, caps lifted | v2 leaked, caps lifted | v1 with static caps: leaked / first-time users refused | v2 with adaptive caps: leaked / first-time users refused |
|---|---:|---:|---:|---:|
| One client, random numbers | 28 | 2 | 28 / 1 % | 2 / 1 % |
| Datacenter rotation, fresh fingerprints | 410 | 0 | 396 / 2 % | 0 / 1 % |
| Premium-prefix pumping | 554 | 0 | 550 / 4 % | 0 / 1 % |
| Spoofed platform header (valid host and session, forged header only) | 594 | 595 | 100 / 1 % | 243 / 51 % |
| Sequential numbers | 596 | 71 | 563 / 4 % | 65 / 3 % |
| Residential pool, reused browser profile | 591 | 128 | 565 / 3 % | 95 / 7 % |
| Residential pool, bot CAPTCHA scores | 217 | 214 | 217 / 1 % | 152 / 15 % |
| Residential pool, farmed CAPTCHA, fresh or pre-aged fingerprints | 591 | 595 | 563 / 4 % | 243 / 51 % |

Section A also runs four reduced designs on the same seeds: a budget ceiling alone stops
the single client (1.7 leaked); a limit of five sends per destination block per day alone
stops the sequential walk and the premium pumper at 5 each, which the full v2 does not
better (65 and 0); the conversion test alone equals v2 everywhere; the speed test alone
differs only on the walk (78).

![leakage vs friction](results/tradeoff.png)

Other things the evaluation established:

- **Which layer stops what** (ablation, 10 seeds, paired per-seed differences against the
  full design on the same seeds): the per-session cap stops the naive client (2 to 30
  without it); the risk engine stops datacenter rotation (0 to 83) and most of the
  sequential walk (62 to 241); number intelligence stops premium pumping (0 to 74); the
  feedback loop stops the reused-profile attacker (94 to 244) and, with the
  destination-block key, the walk (62 with both, 225 without the loop, 183 without the
  block key). Against the diluted residential attackers only the adaptive cap changes
  anything (256 with it, 553 without), and it does so by refusing real users. Removing
  attestation makes the spoofed-header attacker leak 0 instead of 256: the believed header
  drops it into an app bucket with no legitimate traffic to hide in, which is a property
  of this cap table, not a defence.
- **Weights**: raising the fresh-fingerprint weight to 40 stops the farm attacker outright
  but challenges 60 % of legitimate new users; tier boundaries scaled to 0.6 cut its
  leakage by a third for a 21 % challenge rate. The resolution timeout (60 s to 600 s) does
  not move this attacker because the conversion signal never fires on shared keys.
- **Delivery receipts**: a send counts as failed only after the carrier confirmed delivery
  and two minutes passed; a send with no receipt, or a failed one, is undelivered and
  feeds nothing. Verification speed is clocked from the receipt. Post the provider's
  reports to `POST /internal/delivery` (`docs/deployment.md`).
- **Graded response**: about 2 % of legitimate requests (corporate, roaming and
  cloud-abroad egress) are challenged and 90 % of those complete it; the tier is exercised.
- **Low-and-slow**: attacks under the dilution bound leak in full at their own rate (198 of
  200 in 20 minutes).
- **Economics** (revenue credited only to pumping attackers): premium pumping is profitable
  under v1 and loses money under v2 when the carrier verifies instantly (about -0.7 to
  +0.8 USD per 20 minutes) and clears 1 to 5 USD when it never verifies; a concentrated
  pumper whose carrier verifies with human-like delay stays profitable under both (11 to
  30 USD) and additionally hands the defender 264 verified fake accounts per 20 minutes.
- **Performance** (`results/performance.md`, real Redis, 4 uvicorn workers on 4 vCPUs, idle box,
  vendors faked): a full send costs 11.0 ms p50 / 18.9 ms p99 in process with
  48 Redis round trips. Over HTTP at concurrency 32 the service serves 248 requests/s
  without the floor; with it, throughput is bounded by concurrency divided by the floor
  (80 requests/s; 69 measured) and is not a capacity figure. Timing leak, 6000 requests in
  five server-side outcome classes (2665 sent, 1044 challenged, 788 no session, 763
  disallowed country, 740 repeated number): with the 400 ms floor the Kolmogorov-Smirnov
  test finds no difference for any of the 10 pairs (smallest p = 0.32) and TOST shows every
  pair equivalent within 2 ms (largest p = 1.7e-13, largest mean difference 0.22 ms);
  pipeline time exceeded the floor in 0.00 % of requests. Without the floor 9 of 10 pairs
  are distinguishable (p < 10⁻⁸⁷); the exception is challenge against repeated number, which
  do the same work (p = 0.05). A single worker at this concurrency does exceed the floor by
  wall time; size workers so it does not.

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
