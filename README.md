# OTP Guard: OTP flood protection

A layered SMS validation, risk-scoring and rate-limiting pipeline that stops OTP flood
abuse against a registration endpoint. This repository holds the problem statement, the
design with pseudocode, a full implementation with real vendor adapters, a test suite, and
recorded results.

[![CI](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml/badge.svg)](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml)

## What the evaluation shows, in four results

The evaluation is entirely simulated (see "Status and artifact availability"); every number
below resolves to a study, seed set and JSON path in `results/headline_numbers.md`, and the
simulator's own invariants (identical offered traffic across designs, cohort conservation,
clock progression, drain) are asserted by tests. Within it, the thesis the results support is
narrower than a theorem: **in this design, outcome-based reputation separated an attacker
from users in the tested settings only when the attacker dominated the key it was judged
on.** Client-side keys (IP, fingerprint, session) can be rotated for almost nothing and a
CAPTCHA solve costs about 0.003 USD, so the attacker decides how pure those keys are. What a
pumper cannot rotate is the destination: it is paid only on the number blocks its partner
carrier terminates.

1. **Positive, with the residue stated.** Attacks that leave a signature in the request are
   contained in every seed with 77 to 80 % of simulated users completing registration, the
   same as with no attack: datacenter IP rotation and premium-rate pumping leak 0 of 600, a
   single client leaks 2, a sequential-number walk 63 to 70 before its destination block
   reaches a verdict. The cost is not zero: 1 to 3 % of first-time users are refused and
   about 2 % challenged under these attacks, against 1 % with no attack. A flat limit of
   five sends per destination block per day stops the walk and the premium pumper at 5 SMS
   each, better than the sequential tests; what it costs is in result 3.
2. **Negative, and general.** A residential flooder that looks like a real user (farmed
   CAPTCHA scores, fresh or pre-aged fingerprints, valid numbers) leaves nothing but
   rationing. Against it v1 with static caps leaks 562 of 600 and refuses 4 % of first-time
   users; v2's adaptive cap leaks 236 and refuses 54 % of first-time users, so 42 % of all
   simulated users complete instead of 77 %. That gain is rationing, and it depends on the
   controller's cadence and phase (section B2): every 2 minutes it is nearly the same (285
   leaked), every 5 minutes it is 398 or 546 depending on the tick phase, every 10 minutes
   521 or 427, and an hourly job sees a 20-minute attack as a static cap (546) and a
   60-minute attack almost as one (88 to 94 % leaked). The deployed baseline job, learning
   from the pipeline's own counters, reproduces the oracle's rationing once it has one
   closed hour of history (242 to 247 leaked); with none it leaves the static cap (649). At
   10 times the legitimate volume for an hour, 69 % of the attack still leaks while 18 % of
   real users are challenged. One sweep point does contain this attacker without the cap:
   a fresh-fingerprint weight of 40 leaks 0 but challenges 46 % and refuses 10 % of real
   users. A forged platform header buys the attacker nothing under v2 (236, as without the
   header); under v1 the header is believed and the attacker lands in the app bucket, where
   the static app cap holds it to 100 without touching web users.
3. **Pumping on a few destination blocks is contained, the cost has a closed form, and the
   test's memory is a trade-off, not a free parameter.** Against a carrier that never
   verifies, the default leaks 88 of 600 (contained in 10 of 10 seeds, in 3.6 minutes); an
   instant verifier 18. The closed-form model predicts leakage from the blocks a run touched
   with a mean absolute error of 1 to 9 SMS (1 to 15 % relative) across the ten unsaturated
   spread configurations, and overstates by up to 22 on average in the eight saturated ones
   (section G, 18 configurations). A carrier that verifies 60 % of its codes with human-like
   delay is the hard case, and the detector comparison at matched legitimate traffic
   (section F2) says what each setting costs: the default (threshold 1000, one threshold of
   credit) leaks 445 of 600 and produces 7 verdict events a day on 200 busy blocks at 65 %
   conversion (40 requests hit, 17 never completed); no credit (Page's CUSUM) leaks 152 but
   produces 151 events a day hitting 778 requests; unbounded credit leaks 556. A flat
   counter of 5 to 20 sends per block per day leaks 14 to 58 against every carrier, but on
   blocks that legitimately receive 144 sends a day it completes 2 to 21 % of real
   registrations, whichever action it takes. Faked failed receipts leave the tests nothing
   to judge (575 leaked without caps, 237 with); a carrier that builds trust first leaks 250
   in its flood phase after 264 verified codes (82 after 162 under caps). What the
   human-like carrier leaves behind is 268 verified codes per run, each of which the
   registration flow would turn into an account.
4. **What the block tests cost real users is measured, and it set the default.** Twenty-four
   hours of legitimate traffic on 200 distinct busy blocks at 80 % conversion produce 0 to
   1.4 verdict events a day; at 65 % (Twilio's global figure), 7 to 8 events on 7 blocks,
   38 to 42 requests hit of about 29 000 and 16 to 18 that never complete, with completion
   unchanged at 64 %. The per-block Monte Carlo at 30 sends and 65 % gives a 1.8 % chance of
   a verdict per block per window (378 of 20 000 trials, interval 1.7 to 2.1 %). A 30-minute
   carrier outage produces 0.1 verdict events when the provider reports failures and 0.9
   when it is silent, against 1.9 send-clocked: reduced, not removed. A poisoner that floods
   the blocks real users share earns 19 verdict events on 14 blocks, hits 100 requests (69
   at stage 1, 31 at stage 2) of which 49 never complete, and its verdicts keep hitting
   users for an hour after it stops (150 requests); the hard denylist would have lost all
   119 it hit. Grading limits the damage, it does not cap it at a challenge.

## Known weak spots

Each is quantified in [`results/evaluation.md`](results/evaluation.md) and discussed in
[`docs/evaluation.md`](docs/evaluation.md).

- **Dilution.** A residential attacker with human-like CAPTCHA scores was not separated by
  any behavioural signal at any volume tested. Below about 1.8 times the legitimate
  traffic on the shared country and prefix keys the conversion penalty does not fire; above
  it, it fires on everyone sharing the key. It leaks 599 of 600 with caps lifted and
  236 with adaptive caps at 42 % completion for real users (54 % of first-time users refused).
- **Rationing depends on the controller's cadence and phase.** Section B2: 2-minute ticks
  ration almost like 1-minute ones; 5- and 10-minute ticks ration or do not depending on
  where the tick falls; hourly ticks do not for attacks under an hour. The worker's default
  is one minute. The learned baseline needs one closed hour before it rations at all.
- **The block tests are only as good as their calibration.** At a true conversion of 50 %
  the per-block Monte Carlo flags 9 to 41 % of blocks with 10 to 100 sends a window; at
  65 %, 1 to 3 %. `sprt_legit_conversion` and `sprt_legit_fast` must be set from measured
  traffic and the Monte Carlo rerun.
- **Memory is a trade-off.** Section F2 spans thresholds 100 to 10 000 and credit 0 to
  unbounded: every setting that catches the human-like concentrated carrier (152 leaked or
  less) flags a 65 %-converting legitimate block population 150 to 400 times a day; every
  setting that keeps those false verdicts under 10 a day leaks 445 or more against it.
  The default sits at the low-harm end; the choice belongs to the deployment.
- **Faked receipts and bought trust defeat the block tests.** A carrier that reports every
  delivery as failed feeds the tests nothing (575 leaked, 237 with caps, no verdict); a
  pumper whose 500 identity/number pairs verify everything for ten minutes then flood leaks
  250 (82 under caps) in the flood phase on top of 264 verified codes in preparation. Only
  the caps and the spend ceiling bound either.
- **The block key can be turned on real users.** Section D2: 19 verdict events on 14 shared
  blocks per 20-minute poisoning run, 100 requests hit, 49 lost; hits continue for the
  verdict's hour after the attack stops. The second stage moves first-time clients off SMS,
  which 30 % of modelled users cannot use.
- **The outage detector's conversion signal needs returning users.** It takes ten resolved
  sends from clients with verified history to see a silent outage; the receipt signal is
  faster and only as honest as the provider's reports. Residual verdicts: 0.1 to 0.9 per
  outage.
- **Pumper spread.** Block-level containment holds while the carrier's ranges fit inside
  10 000-number blocks; 100 000-number ranges or hundreds of ranges leak like the flooder.
- **Bought challenge solutions.** A datacenter attacker that pays for interactive-challenge
  solutions turns 0 leaked SMS into 54 to 57 per run; a pumper that solves its way past a
  stage-1 block verdict leaks 101 against 88 under the hard denylist.
- **Carrier-grade NAT** delivers only 50 % of a normal sign-up flow until the carrier ASN is
  listed in `CGNAT_ASNS`.
- **Campaign bursts** deliver 12.5 % under the default source caps until the cap is raised.
- **VPN users are blocked** by policy, as the problem statement asked.
- **Capacity.** With vendor calls that take 50 ms and the 400 ms floor on, four workers on
  four vCPUs saturate near 130 requests/s; at concurrency 128 a quarter of requests exceed
  the floor and leak timing, with admission still fair (`results/performance.md`).

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
  unit/                         per step, per adapter, factory, the review counterexamples, simulator invariants
  integration/                  HTTP API, end-to-end scenarios, concurrency on a real redis-server (two instances)
paper/
  figures.py                    the manuscript figures, drawn from results/ (see paper/README.md)
scripts/
  run_scenarios.py              attack scenarios -> results/scenarios.{md,json}
  run_analysis.py               single-seed walkthrough of attacker profiles and use cases -> results/analysis.{md,json}
  run_evaluation.py             30-seed evaluation with CIs, ablation, sweeps, adaptive attackers -> results/evaluation.*
  load_test.py                  latency on a real Redis, KS timing-leak test, capacity with the floor -> results/performance.*
  headline_numbers.py           every README number -> study, seeds, JSON path (results/headline_numbers.md)
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
make load-test      # needs redis-server; about 10 minutes
make replay-demo    # synthetic logs through the replay tool
make smoke          # boot the HTTP service on fakes and drive one flow
make figures        # manuscript figures -> paper/figures/
make headline       # provenance of every README number -> results/headline_numbers.md
make results        # regenerate everything under results/
```

**What the tests establish, and where.** The unit suite runs every test on the memory store
and on fakeredis. Concurrency properties are established only in
`tests/integration/test_real_redis.py`, on a real `redis-server` across two pipeline
instances: the hourly budget ceiling and the per-number claim under concurrent requests,
concurrent verification callbacks counting once, concurrent block-test events counting
exactly and crossing the threshold once, and compare-and-set serialisation. The simulator's
invariants (identical offered workload across designs, cohort conservation, clock
progression, drain) are in `tests/unit/test_simulator_invariants.py`. No test calls a live
vendor; App Attest assertion checking depends on an enrollment flow this repository does
not implement.

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
| 10 | Global circuit breaker: operating mode from the hourly count and spend budgets | No global cap |
| 11 | Atomic budget reservation (the hard ceiling), channel selection, audit log, uniform response | No global cap, enumeration |
| FB | Verification feedback loop: verify-to-send ratio feeds reputation | Separates attackers only on keys they dominate; see the evaluation |

Full detail, pseudocode and the reasoning behind every default: `docs/sms_validation_process.md`.

## Headline results

From `results/evaluation.md`: 30 seeds per attacker with randomised pool size, attack rate and
CAPTCHA class; 20 requests/min of legitimate traffic in the background; means with 95 %
confidence intervals in the full tables. v1 is the original design run through the same code
with the v2 layers switched off. "Caps lifted" removes the source caps; "with source caps"
runs them at 3x the legitimate rate, static for v1 and adaptive (re-learned every minute, v2's
Step 9) for v2. Refusal is reported for first-time users, the only group the caps touch;
completion is over all simulated users (79 % with no attack, since 20 % never enter a code).

| Attacker (600 requests over 20 min) | v1 leaked, caps lifted | v2 leaked, caps lifted | v1 with static caps: leaked / first-time refused | v2 with adaptive caps: leaked / first-time refused / all users completed |
|---|---:|---:|---:|---:|
| One client, random numbers | 31 | 2 | 31 / 1 % | 2 / 1 % / 79 % |
| Datacenter rotation, fresh fingerprints | 412 | 0 | 392 / 3 % | 0 / 1 % / 80 % |
| Premium-prefix pumping | 591 | 0 | 558 / 4 % | 0 / 1 % / 79 % |
| Spoofed platform header (valid host and session, forged header only) | 602 | 599 | 100 / 1 % | 236 / 54 % / 42 % |
| Sequential numbers | 591 | 70 | 558 / 4 % | 63 / 3 % / 77 % |
| Residential pool, reused browser profile | 599 | 124 | 562 / 4 % | 94 / 7 % / 75 % |
| Residential pool, bot CAPTCHA scores | 210 | 210 | 210 / 1 % | 154 / 15 % / 69 % |
| Residential pool, farmed CAPTCHA, fresh or pre-aged fingerprints | 599 | 599 | 562 / 4 % | 236 / 54 % / 42 % |

Section A also runs four reduced designs on the same seeds: a budget ceiling alone stops
the single client (2 leaked); a limit of five sends per destination block per day alone
stops the sequential walk and the premium pumper at 5 each, which the full v2 does not
better (63 and 0); the conversion test alone equals v2 everywhere; the speed test alone
differs only on the walk.

![leakage vs friction](results/tradeoff.png)

Other things the evaluation established:

- **Which layer stops what** (ablation, 10 seeds, paired per-seed differences on an
  identical offered trace): removing the per-session cap adds 28 leaked SMS for the naive
  client; the risk engine 86 for datacenter rotation and 174 for the sequential walk; number
  intelligence 76 for premium pumping; the feedback loop 140 for the reused-profile attacker
  and 152 for the walk; the block key 123 for the walk. Against the diluted residential
  attackers only the adaptive cap changes anything (313 more without it), by refusing real
  users. Removing attestation makes the spoofed-header attacker leak 0 instead of 233: the
  believed header drops it into an app bucket with no legitimate traffic to hide in, a
  property of this cap table, not a defence. Removing the circuit breaker now removes the
  hard ceiling too (the earlier ablation kept it) and changes nothing at these volumes.
- **Weights**: a fresh-fingerprint weight of 40 contains the farm attacker (0 leaked) at
  46 % of real users challenged and 10 % refused; tier boundaries scaled to 0.6 cut its
  leakage by a third for an 18 % challenge rate. The resolution timeout (60 s to 600 s)
  does not move this attacker because the conversion signal never fires on shared keys.
- **Delivery receipts**: a send counts as failed only after the carrier confirmed delivery
  and two minutes passed; a send with no receipt, or a failed one, is undelivered and
  feeds nothing. The receipt rules for duplicates, conflicts and late reports are defined
  at the top of `src/otp_guard/feedback.py`. Post the provider's reports to
  `POST /internal/delivery` (`docs/deployment.md`).
- **Low-and-slow**: attacks under the dilution bound leak in full at their own rate (194 of
  200 in 20 minutes).
- **Economics** (retail-price revenue credited only to pumping attackers, a scenario
  account, not measured profit): premium pumping is profitable under v1 and loses money
  under v2 when the carrier verifies instantly; a concentrated pumper whose carrier verifies
  with human-like delay stays profitable under both (11 to 30 USD per 20 minutes) and leaves
  268 verified codes per run.
- **Performance** (`results/performance.md`, real Redis, 4 uvicorn workers on 4 vCPUs,
  vendors faked): a full send costs 12.6 ms p50 / 19.2 ms p99 in process with 48 Redis round
  trips. Over HTTP at concurrency 32 the service serves 256 requests/s without the floor and
  the floor-bounded 70 with it (bound 80). Timing, 6000 requests in five server-side outcome
  classes (sent, challenged, no session, disallowed country, repeated number): with the
  400 ms floor the Kolmogorov-Smirnov test finds no difference for any of the 10 pairs
  (smallest p = 0.16) and TOST shows every pair's mean within 2 ms; that is a failure to
  detect a difference with these tests at this sample size, not proof that a response time
  carries no information. Without the floor 9 of 10 pairs are distinguishable. With 50 ms
  vendor calls and the floor on, capacity is about 130 requests/s; at concurrency 128 a
  quarter of requests exceed the floor.

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
