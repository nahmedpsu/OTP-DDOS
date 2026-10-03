# OTP Guard: OTP flood protection

A layered SMS validation, risk-scoring and rate-limiting pipeline that stops OTP flood
abuse against a registration endpoint. This repository holds the problem statement, the
design with pseudocode, a full implementation with real vendor adapters, a test suite, and
recorded results.

[![CI](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml/badge.svg)](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml)

## What the evaluation shows, in four results

The evaluation is entirely simulated (see "Status and artifact availability"); every number
below resolves to a study, seed set and JSON path in `results/headline_numbers.md`, and the
simulator's own invariants (identical offered traffic across designs, identical legitimate
traffic across attack scenarios, cohort conservation, clock progression, drain) are asserted by
tests. Within it, the thesis the results support is narrower than a theorem: **in this design,
outcome-based reputation separated an attacker from users in the tested settings only when the
attacker dominated the key it was judged on.** Client-side keys (IP, fingerprint, session) can be
rotated for almost nothing and a CAPTCHA solve costs about 0.003 USD, so the attacker decides how
pure those keys are. A pumper is paid only on the ranges its partner carrier terminates, so it can
rotate numbers and blocks only within those ranges; protection keyed on 8-digit destination
blocks therefore scales with how many blocks the pumper can use.

1. **Positive, with the residue stated.** Attacks that leave a signature in the request are
   contained in all 30 seeds with 77.5 to 79.1 % of simulated users completing registration,
   against 79.3 % with no attack: datacenter IP rotation and premium-rate pumping leak 0 of
   about 600 requests, a single client 2, a sequential-number walk 61 to 69 before its
   destination block reaches a verdict. The cost is not zero: 1.1 to 3.5 % of first-time users
   are refused and 1.6 % challenged, against 0.9 % refused with no attack. In the predeclared
   robustness study (`config/evaluation_protocol.json`: held-out attack rates and pools, 12
   jointly shifted operating points) all five claims hold, including "leak at most 5 % and lose
   at most 2 points of completion against no attack at the same point and seed" in 108 of 108
   cells.
2. **Negative, and general.** A residential flooder that looks like a real user (farmed
   CAPTCHA scores, fresh or pre-aged fingerprints, valid numbers) leaves nothing but rationing.
   Against it v1 with static caps leaks 555 of about 590 and refuses 4.5 % of first-time users;
   v2's adaptive cap leaks 229 and refuses 54 % of first-time users, so 45.5 % of all simulated
   users complete instead of 79 %. That gain is rationing, and it depends on the controller's
   cadence and phase (section B2: 223 leaked at one-minute ticks, 276 at two minutes, 386 or 533
   at five depending on the tick phase, 533 for a 20-minute attack under an hourly job) and on
   its history (section B3: 533 with no closed hour, 235 with three, 193 with a weekly profile; a
   profile poisoned at the attack's hour every previous week costs 45 more [10, 77], a stale
   profile whose legitimate rate has since halved 106 more). At 10 times the legitimate volume
   for an hour, 70 % of the attack still leaks while 17 % of real users are challenged. One sweep
   point contains this attacker without the cap: a fresh-fingerprint weight of 40 leaks 0 but
   challenges 47 % and refuses 9 % of real users.
3. **Destination pumping: the sequential tests are beaten by a short-window send counter in a
   bounded region, and the region is mapped.** Against a carrier that never verifies, the
   default sequential tests leak 90 (contained in 10 of 10 seeds, in 3.5 minutes); an instant
   verifier 19; a carrier that verifies 60 % of its codes with human-like delay 452 (contained in
   0 of 10) with 272 codes entered. A counter of SMS sends per block over a short refilling window
   (4 per 10 minutes, selected in 2.7.0 against a benign service target) was then frozen and
   tested under a separate protocol committed before its runs (`config/counter_protocol.json`,
   fresh seeds; `results/counter_study.md`):
   - Across four concentrated pumping profiles on the held-out family, it leaked at most 10 % of
     attack requests in 144 of 144 cells (K1; means 33 to 62 SMS per 20 minutes against 36 to
     344 for the default), cost at most 0.5 points of completion on attack-free traffic in 36 of
     36 (K2), and leaked no more than the default in 131 of 144 (K4; the exceptions are the
     instant verifier, which the default stops slightly earlier).
   - **It failed both service-under-attack claims**: with the pumper on blocks real users share,
     its completion loss against no policy exceeded 0.5 points in 17 of 144 cells, at five of the
     twelve shifted points (K3, 127/144),
     and exceeded the default's by more than 0.25 points in 51 of 144 (K5, 93/144).
   - On the same attacked traces (E1, 60 minutes), it held each concentrated pumper to 71 to 158
     SMS against 20 to 897 for the default; under no policy a pumper on shared blocks also
     exhausts the hourly SMS budget, so the counter *raised* completion among the attacked
     blocks' users (by 11 points against the no-verify pumper).
   - **Where it loses** (E3, E4): a trust-building pumper on random numbers (577 leaked, the same
     as no policy; its verified identities are also exempt from the graded counter); spreading
     over 30 blocks (233 against 237 for the default) and over 300 blocks (637 against 655 for no
     policy); a quota-aware pumper that sends 4 per block per 10 minutes over 30 or 300 blocks
     (238 and 654, no better than no policy, while the default stops it at 221 and 648); a
     poisoner spreading over the 200 shared blocks (1 662 against 1 976 for no policy). On the
     legitimate side it starts to cost real users once a block's legitimate rate approaches its
     quota: at 8 sends per block per 10 minutes, 5.5 points of the hot blocks' users at 70 %
     WhatsApp reachability and 13 at none, attack-free; a product launch on three blocks costs
     16 points of their users.
   - Where it wins it does so by rate, not by judging intent: a concentrated pumper sends about
     ninety messages per block per ten minutes against about one for a busy legitimate block,
     and the graded counter rations a shared destination for clients without verified history.
4. **What the block tests cost real users is measured, and it set the default.** Twenty-four
   hours of legitimate traffic on 200 distinct busy blocks at 80 % conversion produce 0.6 to
   3.2 verdict events a day (OTP autofill 0 to 30 %); at 65 % (Twilio's global figure), 6.4 to
   9.2 events, 31 to 42 requests hit of about 29 000; the completion loss attributable to the
   default tests against no policy is 0.01 % of users. The per-block Monte Carlo at 30 sends and
   65 % gives a 1.9 % chance of a verdict per block per window (377 of 20 000 trials, interval
   1.7 to 2.1 %). A 30-minute carrier outage produces 0.6 verdict events when the provider
   reports failures and 0.8 when it is silent, against 1.8 send-clocked. A poisoner that floods
   the blocks real users share earns 16 verdict events on 13 blocks and hits 98 requests; the
   completion loss attributable to enforcing those verdicts, against the same trace with
   verdicts recorded but not enforced, is 12.7 requests (3.1 % of users), 25.8 (6.3 %) without
   a fallback channel and 97.7 (24 %) under the hard denylist. Verdicts outlive the attack: in
   a 70-minute run whose poisoner stops after 10 minutes, verdicts hit 406 requests after it
   stopped; the loss attributable to enforcement among requests after the stop is 46.2 (48.2
   over the whole run). Grading limits the damage, it does not cap it at a challenge.

## Known weak spots

Each is quantified in [`results/evaluation.md`](results/evaluation.md),
[`results/counter_study.md`](results/counter_study.md) and discussed in
[`docs/evaluation.md`](docs/evaluation.md).

- **Dilution.** A residential attacker with human-like CAPTCHA scores was not separated by
  any behavioural signal at any volume tested. Below about 1.8 times the legitimate traffic on
  the shared country and prefix keys the conversion penalty does not fire; above it, it fires
  on everyone sharing the key. It leaks 589 of 592 with caps lifted and 229 with adaptive caps
  at 45.5 % completion for real users (54 % of first-time users refused).
- **Rationing depends on the controller's cadence, phase and history** (sections B2, B3).
- **The block tests are only as good as their calibration.** At a true conversion of 50 % the
  per-block Monte Carlo flags 9 to 41 % of blocks with 10 to 100 sends a window; at 65 %, 1 to
  3 %. In the robustness study the false-alarm bound held at every cell with conversion of 0.75
  or more and at 8 of 18 cells below it.
- **The human-like carrier defeats the default tests** (452 leaked, 272 codes entered per 20
  minutes). The short-window counter stops it on a few blocks, at the costs and within the
  limits of result 3; neither policy stops a pumper that spreads over hundreds of blocks or
  paces itself under the quota.
- **The counter's service cost is borne under attack.** It met the benign service target in
  every attack-free cell, but its loss under a shared-block attack broke the predeclared bounds
  in 12 % (absolute) and 35 % (relative to the default) of held-out cells; it depends on a
  fallback channel (a daily counter of 20 completes 27 % of registrations on busy blocks with
  no WhatsApp, 53 % at 70 % and 64 % at 100 %).
- **Faked receipts, white-box carriers and bought trust defeat the block tests**: a carrier that
  reports every delivery as failed, or one that knows the thresholds, leaks 570 with no verdict;
  a trust-building pumper leaks 516 after 263 verified codes. The counter stops the first two on
  concentrated blocks (24 each) and not the third (577 on random numbers).
- **The block key can be turned on real users** (result 4).
- **The outage detector's conversion signal needs returning users.** The receipt signal is
  faster and only as honest as the provider's reports. Residual verdicts: 0.6 to 0.8 per outage.
- **Bought challenge solutions.** A datacenter attacker that pays for interactive-challenge
  solutions turns 0 leaked SMS into 51 to 55 per run; a pumper that solves its way past a
  stage-1 block verdict leaks 105 against 90 under the hard denylist.
- **Carrier-grade NAT** delivers only 50 % of a normal sign-up flow until the carrier ASN is
  listed in `CGNAT_ASNS`.
- **Campaign bursts** deliver 12.5 % under the default source caps until the cap is raised.
- **VPN users are blocked** by policy, as the problem statement asked.
- **Two feedback races are open** (bounded and disclosed, not closed): the reversal-recovery
  window and the timeout-worker/correcting-receipt interleaving under "Delivery receipts and
  state" below.
- **Capacity and timing under load.** Under an adversarial mixture at concurrency 128 the
  400 ms floor no longer bounds 81 % of sends, and response time then separates a send from a
  refusal for an observer (88 % best-threshold accuracy on a small sample); see "Performance".

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
CAPTCHA class; 20 requests/min of legitimate traffic in the background, identical across attack
scenarios at a given seed; means with 95 % percentile-bootstrap intervals in the full tables.
v1 is the original design run through the same code with the v2 layers switched off. "Caps
lifted" removes the source caps; "with source caps" runs them at 3x the legitimate rate, static
for v1 and adaptive (re-learned every minute, v2's Step 9) for v2. Refusal is reported for
first-time users, the only group the caps touch; completion is over all simulated users (79 %
with no attack, since 20 % never enter a code).

| Attacker (about 600 requests over 20 min) | v1 leaked, caps lifted | v2 leaked, caps lifted | v1 with static caps: leaked / first-time refused | v2 with adaptive caps: leaked / first-time refused / all users completed |
|---|---:|---:|---:|---:|
| One client, random numbers | 30 | 2 | 30 / 1 % | 2 / 1 % / 79 % |
| Datacenter rotation, fresh fingerprints | 412 | 0 | 392 / 3 % | 0 / 1 % / 79 % |
| Premium-prefix pumping | 599 | 0 | 562 / 5 % | 0 / 1 % / 79 % |
| Spoofed platform header (valid host and session, forged header only) | 592 | 589 | 100 / 1 % | 229 / 54 % / 46 % |
| Sequential numbers | 599 | 69 | 562 / 5 % | 61 / 4 % / 78 % |
| Residential pool, reused browser profile | 589 | 122 | 555 / 4 % | 88 / 9 % / 74 % |
| Residential pool, bot CAPTCHA scores | 214 | 214 | 214 / 1 % | 153 / 16 % / 70 % |
| Residential pool, farmed CAPTCHA, fresh or pre-aged fingerprints | 589 | 589 | 555 / 4 % | 229 / 54 % / 46 % |

Section A also runs four reduced designs on the same seeds: a budget ceiling alone stops the
single client (2 leaked); a limit of five sends per destination block per day alone stops the
sequential walk and the premium pumper at 5 each; the conversion test alone equals v2
everywhere; the speed test alone differs only on the walk. These are component variants of one
design, not independent detectors.

![leakage vs friction](results/tradeoff.png)

Other things the evaluation established:

- **Which layer stops what** (ablation, 10 seeds, paired per-seed differences on an identical
  offered trace): removing the per-session cap adds 29 leaked SMS for the naive client; the
  risk engine 80 for datacenter rotation and 166 for the sequential walk; number intelligence
  73 for premium pumping; the feedback loop 138 for the reused-profile attacker and 152 for the
  walk; the block key 121 for the walk. Against the diluted residential attackers only the
  adaptive cap changes anything (310 more without it), by refusing real users. Removing
  attestation makes the spoofed-header attacker leak 0 instead of 223: the believed header
  drops it into an app bucket with no legitimate traffic to hide in, a property of this cap
  table, not a defence. One factor at a time; interactions are not estimated.
- **Weights**: a fresh-fingerprint weight of 40 contains the farm attacker (0 leaked) at 47 %
  of real users challenged and 9 % refused; tier boundaries scaled to 0.6 cut its leakage by a
  third for an 18 % challenge rate. The resolution timeout (60 s to 600 s) does not move this
  attacker because the conversion signal never fires on shared keys.
- **Delivery receipts and state**: a send counts as failed only after the carrier confirmed
  delivery and two minutes passed; a negative receipt resolves the send as undelivered in the
  same atomic transition. The graded destination counter decides its stage on the count its
  reservation changes, so concurrent requests cannot pass its first boundary without a
  challenge (tested across two instances on a real Redis). The simulation is single-threaded,
  so its numbers are those of the policy as specified; concurrency evidence comes from the
  tests, which cover specific interleavings, not all of them. Every compound transition (receipt, timeout, code entry) is one
  compare-and-set, its effects are recorded in that write and applied at most once (exactly
  once if the recovery sweep runs within a 20-minute replay horizon), and the sweep finishes
  them after a crash; graded escalation and crash recovery are tested
  across two instances on a real Redis (`docs/sms_validation_process.md`, "State machine").
  Two bounded races remain open and are stated at the top of `feedback.py`: a reversal (late
  verification) that is recovered more than about 13 minutes after it arrived can leave the
  failure it reverses counted, and a correcting receipt that lands between the timeout worker's
  transition and its bookkeeping loses that send's resolution timeout (its failure is lost, not
  doubled). Neither is reached by the single-threaded simulation.
- **Containment is a property of a finite window**: a run counts as contained only if leakage
  stays at or below 5 % of the attack rate to the end of the run for at least five minutes;
  60-minute runs report survival curves (section F1) and time to first verdict is reported
  beside containment.
- **Low-and-slow**: attacks under the dilution bound leak in full at their own rate (203 of
  about 204 in 20 minutes).
- **Economics** (scenario accounting at assumed retail prices, not measured profit): instead
  of assuming a revenue share, each row reports the share of the retail termination fee at which
  the pumper breaks even on an event-level bill (tokens for every session attempt and request,
  paid challenge solutions, proxy traffic; identity preparation, numbers and contracts excluded,
  so these are lower bounds only under the other assumptions). Premium pumping breaks even under
  v1 at 4.3 %; under v2 a carrier that never verifies needs 27 %, an instant verifier more than
  the whole fee (131 %), and the human-like carrier only 5.4 %. Over a 360-minute attack the
  human-like carrier sustains 789 SMS an hour against the default and 81 against the
  short-window counter (break-even above the whole fee); a pumper spreading over 300 blocks
  sustains about 1 900 an hour against either.
- **Performance** (`results/performance.md`, real Redis, 4 uvicorn workers on 4 vCPUs, vendors
  faked): a full send costs 13.8 ms p50 / 21.1 ms p99 in process with 49.5 Redis round trips.
  Over HTTP at concurrency 32 the service serves 217 requests/s without the response floor and
  the floor-bounded 70 with it (bound 80). Timing, 6000 requests in five server-side outcome
  classes: with the 400 ms floor the Kolmogorov-Smirnov test finds no difference for any of the
  10 pairs at 0.05 (smallest p = 0.051), every pair's mean is within 1.2 ms, and the best single
  latency threshold tells no pair apart better than 53 % balanced accuracy; that is a failure to
  detect a difference with these tests at this sample size, not proof that a response time
  carries no information. Without the floor 9 of 10 pairs are distinguishable (up to 99 %
  accuracy). With vendor calls of a 50 ms median and the floor on, four workers serve 67, 118
  and 133 requests/s at concurrency 32, 64 and 128, with 0.1, 0.7 and 30 % of requests over the
  floor. Under an adversarial mixture (55 % of requests built to reach the SMS path, heavy-tailed
  vendors, 1 % two-second timeouts) the floor stops bounding the response time for 24 % of sends
  at concurrency 32 and 81 % at 128; an observer who sees only response times then tells a send
  from a hard-step refusal with a best single-threshold balanced accuracy of 62 % and 88 % (only
  22 refusals in that mixture, so the estimate is rough and optimistic). No server errors, and
  every ordinary request was still sent.
- **App Attest enrolment** (`POST /attest/enroll`) follows Apple's published validation steps
  (certificate chain to the App Attest root, nonce, key identifier, RP ID hash, counter, AAGUID);
  it is tested against synthetic certificate chains only, not a real device.

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

**Testing.** `make test` runs 393 tests (`results/test_report.txt`): unit tests of every
step, the state machine's interleavings and crash points on the in-memory store and on
fakeredis, simulator invariants, and the App Attest enrolment verifier against
synthetic certificate chains. `tests/integration/test_real_redis.py` repeats the concurrency,
graded-escalation, crash-recovery, replay and destination-counter cases across two pipeline
instances on a real `redis-server` when one is available (CI starts one). These are specific
interleavings and crash points, not a proof over all of them. No test calls a real vendor.

**Corrections.** Defects found by review are listed with their effect in
`docs/evaluation.md` ("What changed after ..." sections) and `CHANGELOG.md`. The most
consequential in the third round: from 2.6.0 until 2.7.0 the simulator never wrote the drawn
WhatsApp reachability into the channel registry, so no downgraded user was served over
WhatsApp and every service figure for a downgrading policy was too low; and legitimate traffic
was drawn from the attacker's random stream, so cross-scenario service comparisons were
unpaired (the first robustness run is kept in `results/robustness_first_run.md`). In the fourth
round: the graded destination counter did not enforce its first boundary under concurrent
requests (the simulation, being single-threaded, was unaffected); a block remembered only its
last 256 event ids, so a recovered failure could be counted twice; and a reversal applied
before the failure it reverses left the failure counted. All three are fixed and covered by
regression tests (`tests/unit/test_fourth_round.py`, `tests/integration/test_real_redis.py`).
Erratum: `config/counter_protocol.json` (seed note) and the header of `results/counter_study.md`
say the 6000-series seeds were never used before that protocol; six of them (6000-6002 and
6100-6102) had served as the main evaluation's robustness seeds for points 10 and 11
(`5000 + 100 x point + seed`). The protocol file is kept as committed, because its recorded hash
would otherwise change; the overlap is stated here, in `CHANGELOG.md`, in `docs/evaluation.md`
and in a marked line of the generated report. The 300-series seeds are fresh.

**Provenance of the results.** `results/evaluation.json` and `results/counter_study.json` record
the hash of the code that produced every run, the environment, and whether the invocation was
clean or resumed from a checkpoint (resumed and reused runs are accepted only from the same
code). The counter study follows `config/counter_protocol.json`, committed before its runs;
the chronology is stated in that file.

**Archiving.** `CITATION.cff` and `.zenodo.json` are in place; the author name is a
placeholder until the author fills it in. Releases are tagged (`git tag`); to obtain a DOI,
enable the repository in Zenodo's GitHub integration and publish a release, which Zenodo
archives automatically. Record the DOI here once minted: _(none yet)_.

**Ethics and permissions.** See `docs/privacy_and_ethics.md` for the data-retention
statement and the approvals still to be recorded (ethics approval for any production-log
replay; employer permission to describe the incident).
