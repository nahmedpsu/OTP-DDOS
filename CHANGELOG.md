# Changelog

## 2.8.1 (2026-10-03)

Implementation repairs and analyses from the fifth-round review. The recorded 2.8.0 results stand:
the simulator is single-threaded and never crashes a process, so none of the repaired paths is
reached in a simulated run, and 102 recorded runs (three per study, every study of both result
files, long runs included) replayed with 2.8.1 are identical in every recorded field
(`scripts/check_reproduction.py`, `results/reproduction_check.md`). The code hashes recorded in
the 2.8.0 results identify commit 1c277a0 (tag v2.8.0).

- **Event time on replay (M8).** A replayed effect batch is applied at its transition's time: an
  outage observation is inserted at its own time and judged against the window ending now (a
  replay 601 s later used to move an old delivery failure into the current 600-s window), and a
  replayed reputation increment lands in its own hour.
- **Late reversal after the failure's identifier expired (closed; was disclosed in 2.8.0).**
  Block-event ids are kept for the replay horizon plus the code lifetime plus 60 s.
- **Timeout worker (closed; was disclosed in 2.8.0).** A timeout member is removed only if its
  due time is unchanged (`store.zrem_if_score`), so a correcting receipt that reschedules the send
  during the worker's transition keeps its timeout.
- **Step 11 challenges and the source caps.** A request that Step 11 turns into a challenge gives
  back the source-cap counts it took at Step 9, as a request challenged at Step 7 never takes them.
  Other later refusals keep request-rate semantics (documented).
- **Release of an expired claim on Redis** gives nothing back instead of creating a negative
  counter without a TTL.
- **Tests**: `tests/unit/test_fifth_round.py` (the reviewer's replay diagnostic, the two closed
  races, the source caps, expired release, the app stage-1 path serially and at Step 11, Step 11's
  crash semantics; memory and fakeredis), four more real-Redis tests (unsolved requests at the
  counter's second boundary, replayed outage time, the timeout race, the late reversal), and the
  HTTP stage-1 path in `tests/integration/test_api.py`. Each new defect test fails on 2.8.0.
- **Analyses** (`scripts/run_round5_analyses.py`, `results/round5_analyses.md`): selection repeated
  under each objective on the tuning runs over every setting, with winners outside the original
  shortlist evaluated on the fresh seeds; claims K1-K5 by attacker; attacked service answered three
  ways (extra harm against the attacked no-policy arm, degradation against attack-free operation
  under the same policy, benign cost) with gross losses, gains and cohorts, from 240 new attack-free
  runs on the E1 traces; the counter's leakage envelope against Equation 1 on the security map.
- **Timing**: `scripts/load_test.py --holdout N` fits the best latency threshold on one phase-4 run
  and evaluates it on independent runs (`results/performance_holdout.md`).
- **Timing result**: three new runs on a 2-vCPU machine (99 % of sends over the floor); a
  threshold fitted on one run scored 95 to 99.9 % balanced accuracy on each other run.
- **Dated protocol corrections** in `config/counter_protocol_erratum.md` (the seed note; the
  burst-12 label); `config/counter_protocol.json` is unchanged, so its recorded hash stands.
- **Provenance**: `scripts/headline_numbers.py` also maps the re-selection, per-attacker claims,
  attacked-service and held-out timing numbers (`results/headline_numbers.md`).
- **Figures** 2, 4, 6 and 7 redrawn for legibility (Figures 4, 6 and 7 stacked to full width;
  Figure 7 shows the counter's envelope and the leakage estimate). In manuscript revision 5 they
  are Figures 2, 4, 5 and 6; the spread figure (`fig5_spread`) is kept in the artifact only.

## 2.8.0 (2026-10-03)

Repairs and studies from the fourth-round review (`docs/evaluation.md`, "What changed after the
fourth-round report"):

- **The graded destination counter enforces its first boundary under concurrency.** Step 5 read
  the count; Step 11 reserved against twice the limit, so requests that all read a count below the
  limit could fill the second tier without a challenge (eight concurrent requests: eight sends, no
  challenge, against four and four serially). The stage is now decided atomically on the count the
  reservation changes; regression tests on both backends and across two instances on a real Redis.
- **Replay after many later block events.** A block remembered only its last 256 event ids, so a
  recovered failure could be counted twice. Ids are now kept for the replay horizon by age, and a
  batch older than the horizon is skipped (and counted) rather than applied twice. The guarantee is
  stated as at most once, and exactly once if the sweep runs within the horizon.
- **Reversal before failure.** A late verification (or a corrected receipt) that reached a block
  before the failure it reverses left the failure counted; reversals now name the failure and
  leave a tombstone, so the order no longer matters.
- **Token-bucket destination limiter** (rate and burst separate), an exploratory alternative.
- **Counter study** under a fresh protocol committed before its runs (`config/counter_protocol.json`):
  claims K1-K5 on the held-out family, service and leakage on the same attacked traces, the
  adaptive family (white-box, receipt-faking, trust-building, spreading, quota-aware, 360-minute),
  the operating boundary with stress rows, and the selection rule at every density with
  density-specific attack runs (`results/counter_study.md`).
- **Simulator realism**: WhatsApp reachability stable per number; returning account holders carry
  verified fingerprint history; hot blocks, a product launch, correlated challenge failure, poor
  routes on hot blocks; shared-block and quota-aware pumpers.
- **Statistics**: a nested variance design beside the fixed-parameter comparison (now named as
  such), selected two-layer interactions, attributable loss with gross losses and gains by cohort,
  for attacked-block users and after the attack stopped.
- **Provenance**: checkpointed and reused runs carry a code hash and are rejected when it differs;
  results record the environment and whether the invocation was clean or resumed.
- **Timing**: per-outcome distributions under the adversarial load mixture with a stated observer
  model and threshold-classifier accuracy.
- **Figures** redrawn for legibility; Figure 7 (counter boundary); Figure 2 key-effects table.
- **Open, bounded races (disclosed, not closed; M15).** A reversal recovered after the reversed
  failure's block-event id has expired (a sweep gap of about 13 minutes or more after a late
  verification, in the worst case) leaves the failure counted; and a correcting receipt that
  reopens a send between the timeout worker's transition and its removal of the send from the
  timeout set loses the rescheduled resolution timeout (the failure is lost, not doubled). Both are
  stated at the top of `feedback.py` with the fix each would take.
- **Erratum (seeds).** `config/counter_protocol.json` says the 6000-series held-out seeds were
  never used before; six of them (6000-6002, 6100-6102) had been the main evaluation's robustness
  seeds for points 10 and 11 (`5000 + 100 x point + seed`). The protocol file is unchanged so that
  its recorded hash stands; the overlap is stated in the README, `docs/evaluation.md`, a marked
  line of `results/counter_study.md` and the report generator. Seeds 300-309 are fresh.
- **Documentation after the runs.** The simulator docstring says reachability is stable per
  number (it still said "drawn per request"); the legitimate-conversion calibration cites Twilio's
  Verify page, which states 68 %+, instead of the blog post, which states no figure. These edits
  to source text change the code hash relative to the ones recorded in the 2.8.0 results
  (`ec40cf34...`, `fbf12e7f...`), which identify the code at commit 1c277a0; no behaviour changed,
  and a `--reuse` of those checkpoints is rejected by design.

## 2.7.0

Repairs from the third-round review (`docs/evaluation.md`, "What changed after the third-round
report"):

- **Fallback channels exist in the simulation.** The per-request WhatsApp reachability was drawn
  and hashed but never written into the channel registry, so every downgraded user was refused
  (a regression introduced in 2.6.0). It is now registered before each request; studies at 0 %,
  70 % and 100 % reachability are reported.
- **Verdict estimands.** Incidence inside the observation window, exposure as the union of active
  intervals intersected with the window (inherited verdicts included, never negative) and
  eventual events including the drain are reported separately.
- **Legitimate traffic is paired across scenarios.** Legitimate requests come from their own
  random stream, independent of the attacker; previously an attack run and the no-attack run at
  the same seed offered different users, which failed the predeclared robustness claim C1 on its
  service clause in 32 of 108 cells (first run kept in `results/robustness_first_run.md`). All
  studies were rerun; all five claims hold.
- **Reversed finding.** With the counter charged per send and the fallback channel working, a
  short-window send counter (for example 4 per 10 minutes on busy blocks) stops every pumper
  tested, the human-like carrier included, at an attributable completion loss of 0.06 to 0.35 %
  of users; the second-round conclusion that counters cost 2 to 21 % completion does not hold.
- **Compound transitions are atomic, effects exactly once.** A negative receipt resolves
  undelivered in the same write; timeouts and code entries decide inside one compare-and-set;
  effects are recorded in that write and applied idempotently with a recovery sweep; the block
  verdict and its stage live in the block document (graded escalation under concurrency).
  Crash-injection tests; graded escalation and crash recovery on a real Redis.
- **The destination counter counts sends**, reserved at Step 11; a challenge and its retry are not
  charged. Daily and short refilling windows.
- **Matched comparison on a common pipeline**, selected on tuning seeds against a predeclared
  service target and evaluated on held-out seeds at three densities, with attributable loss
  per request against no policy; a full threshold x credit grid with matched false-alarm burden.
- **Predeclared robustness study** (`config/evaluation_protocol.json`, committed before the runs):
  held-out attack rates and pools, heterogeneous legitimate traffic, a 12-point joint parameter
  shift, five claims with pass thresholds.
- Weekly-profile baseline study (stale profiles, schedule-aware poisoning, two workers, restart)
  with paired effects; baseline job safe across workers and restarts; partial hours skipped.
- Threshold-aware carrier and long-preparation trust builder; two design alternatives (trust
  budget, receipt-robust tests) evaluated against them and for their legitimate cost.
- Containment needs five sustained quiet minutes; 60-minute attacks with survival curves; time to
  first verdict. Poisoning against an observe-only counterfactual; recovery over a full verdict
  lifetime.
- Statistics: percentile-bootstrap intervals (inside the data range), tail summaries, leak share,
  variance decomposition; event-level attacker bill with break-even revenue shares.
- App Attest enrolment endpoint to Apple's published steps (synthetic-chain tests).
- Load test: heavy-tailed and timing-out vendors, adversarial mixture.
- `scripts/run_evaluation.py --checkpoint` resumes an interrupted run; `--reuse` takes runs with
  an identical spec hash and seed from an earlier run file.
- Artifact: `results/study_specs.json` (every run's configuration and hash),
  `results/attacker_profiles.md`, manuscript figures without embedded titles, headline map.

## 2.6.0

Implementation and evaluation repairs from the second-round review (`docs/evaluation.md`,
"What changed after the second-round report"):

- OTP state is written before the sender is called, so a synchronous sender callback or an
  immediate provider receipt lands on registered state. Receipt, verification and block-test
  transitions are atomic read-modify-writes (a lock in memory, WATCH/MULTI/EXEC on Redis;
  `store.update`); the receipt rules (duplicate, conflicting, late and corrected reports) are
  defined at the top of `feedback.py`. The memory store returns copies on read, as Redis does.
- The verdict log records every verdict event with its stage; results report events, distinct
  blocks, stage counts, requests hit by stage, lost completions and block-minutes under verdict.
- Simulator: the offered workload is drawn entirely before the policy sees a request (including
  retry tokens and returning-identity choice) and hashed, with a test that the hash is
  identical across designs; requests are bound to immutable cohorts with conservation asserted;
  users are counted before the session gate and losses named by stage; arrivals carry
  timestamps and the clock advances independently of acceptance; runs drain to a declared
  horizon; legitimate blocks are distinct; trust-building pools are one-to-one pairs with
  per-phase accounting; attacks can stop early for recovery studies.
- Evaluation: detector comparison on matched traffic (thresholds, credit floors, flat counters
  with refusing and graded actions, against four pumpers and 24 hours of legitimate traffic at
  two conversions); cadence grid with tick phases and a 60-minute attack; the deployed baseline
  job against the oracle (cold start, one and three hours, poisoned); poisoner variants (hard
  deny, recovery); Monte Carlo counts with Wilson intervals; spread residuals per run;
  conditional containment time with contained counts in every table.
- The hard budget ceiling belongs to the `circuit_breaker` flag (the ablation now removes the
  whole layer); the baseline job's fallback averages the closed hours it has instead of 24;
  a graded per-block counter (`block_count_action = "graded"`) exists as a comparator.
- Tests on a real `redis-server` across two pipeline instances (budget ceiling, per-number
  claim, concurrent callbacks, block events, compare-and-set); the fakes can simulate vendor
  latency and the load test has a capacity phase with the floor on.
- `paper/figures.py` draws the manuscript figures from the recorded results;
  `scripts/headline_numbers.py` maps every README number to its study, seeds and JSON path.

## 2.5.0

Implementation and evaluation fixes from the Reviewer 2 report (`docs/evaluation.md`, "What
changed after the Reviewer 2 report"): the code travels in the message; the challenge proof
goes through the CAPTCHA adapter; the hourly budget is an atomic hard ceiling; per-number
claims are atomic with release on later refusal; callbacks are idempotent; block tests of
the CUSUM form with bounded credit (`block_credit_thresholds`, the dial between trust-building
resistance and false positives, with the no-credit and plain-SPRT variants evaluated
alongside); the default worker runs a real baseline job from the pipeline's counters. Simulation:
same destination on challenge retry, delivered means a receipt, first-time versus returning
friction, split random streams, events at their timestamps, session acquisition through the
CAPTCHA gate, spread ranges without replacement with observed block counts, a corrected
resolution-timeout sweep, a controller-cadence study, six baseline designs, paired ablation
with user harm, trust-building and receipt-faking carriers and a block poisoner, five-seed
24-hour cells under fixed and recalibrated speed-test calibration, the challenge class in
the timing test.

## 2.4.0

- Delivery receipts gate the feedback loop: a send counts as failed only after the
  provider confirmed delivery and the resolution timeout passed; no receipt, or a failed
  one, resolves as `undelivered` and feeds neither the conversion ratio nor the block
  tests. `POST /internal/delivery` takes the provider's reports; a provider without them
  is run with `delivery_receipts = false`. Verification speed is clocked from the receipt.
- Carrier outage detector: the block tests are suspended on a prefix whose receipts
  collapse across many blocks, or whose returning clients (verified history) stop
  verifying across many blocks; an alert names the carrier.
- Graded block verdicts (default): a first verdict makes the block's first-time clients
  solve a challenge for an hour, a second moves them to non-SMS channels; clients with
  verified history are never affected. The 24-hour denylist remains as `block_action = deny`.
  Sequential-test counters live apart from the reputation hash and restart after a verdict.
- The speed test's legitimate rate defaults to 20 % (OS autofill) and must be set from
  measured traffic; the evaluation sets it from the calibrated legitimate model.
- Design fix found by the evaluation: downgrade-tier requests no longer consume the SMS
  source cap (Step 9), so an attacker moved off SMS cannot ration real users through it.
- Evaluation: false-positive study of the block tests (Monte Carlo over conversion and
  autofill share; 24 hours of legitimate traffic at realistic sends per block; a carrier
  outage in three variants), a challenge-solving pumper, the hard-deny variant, returning
  users and autofill in the legitimate model, and the closed-form leakage model
  (`evaluation/model.py`) checked against the spread sweep.

## 2.3.0 (unreleased)

- Review round 2: `adaptive_caps` is a feature flag (v1 runs static caps; the adaptive cap
  gets an ablation column); the relative baseline is opt-in and evaluated with a 130-minute
  warm-up; destination blocks use sequential probability-ratio tests instead of fixed
  50/100-send thresholds; a "block key + 2-minute resolution" variant is the default and is
  reported separately; a destination-spread sweep (3 to 300 ranges of 1 000 to 100 000
  numbers) and a dilution curve (0.5x to 10x legitimate volume for an hour); economics
  credit revenue only to pumping attackers and include the concentrated pumpers and their
  verified fake accounts.

- Fixes from review: the ablation baseline now runs on the same seeds as the ablation
  columns; client identities are preserved when the session layer is switched off; numpy,
  scipy and matplotlib are declared (`eval` and `dev` extras); MIT licence added.
- New mechanisms, each tested in the pumping study: a destination-block reputation key
  (first 8 digits) with denylisting of blocks that never verify or are machine-verified; a
  2-minute resolution timeout with reclassification of late verifications; a relative
  conversion baseline (recent hour against the key's own history).
- Evaluation: concentrated-pumper study with and without a verifying carrier; the
  challenge tier is now exercised (legitimate sub-populations on corporate, roaming and
  cloud-abroad egress; a challenge solver that is actually challenged); timing-leak tests
  with thousands of samples per outcome, a TOST equivalence test, the fraction of requests
  over the floor, and honest throughput labelling.
- Documentation reframed around what the reputation signal can and cannot separate.

## 2.2.0

- Evaluation framework (`src/otp_guard/evaluation/`, `scripts/run_evaluation.py`,
  `results/evaluation.md`): calibrated synthetic traffic with sources, properly defined
  metrics (time to containment, leaked before containment, steady-state leakage, total
  cost including lookups and CAPTCHA, friction), 30 seeds with randomised pool size, rate
  and CAPTCHA class and 95 % confidence intervals, leave-one-layer-out ablation, weight and
  boundary sweeps with the leakage-friction trade-off chart, adaptive attackers (verifying
  pumpers, challenge solvers, low-and-slow), attacker economics.
- Log replay tool (`scripts/replay_logs.py`, `docs/replay_schema.md`) and a synthetic log
  generator in the same schema.
- Load test and timing-leak test against a real Redis (`scripts/load_test.py`,
  `results/performance.md`): per-step p50/p95/p99, Redis commands per request, KS tests on
  client-observed latency across outcomes with and without the 400 ms floor.
- Design changes found by the evaluation: risk weights are configuration; the reduced
  adaptive cap rations the delay and downgrade tiers and spares clean traffic; the adaptive
  baseline job counts requests that reach the cap; an instant-verification signal for
  colluding carriers.
- `docs/evaluation.md` states the weak spots up front and the limitations; `docs/privacy_and_ethics.md`;
  `CITATION.cff`; `.zenodo.json`; artifact-availability statement in the README.

## 2.1.0

- Analysis runner (`scripts/run_analysis.py`, `results/analysis.md`): attacker profiles per
  layer, legitimate use cases, v1 versus v2 cost, sensitivity to OTP timeout.
- `docs/use_cases.md`.
- Feature flags (`Config.features`, `V1_FEATURES`) for staged rollout and the v1 baseline.
- Design changes found by the analysis: the auto-denylist no longer applies to residential
  ASNs (only IP, subnet, fingerprint and datacenter ASNs); a sustained-flood bonus (+15 at
  100 resolved sends under 10 % conversion) moves rotating residential attacks to the
  challenge tier instead; listed carrier-grade NAT ASNs get a 30/min per-IP cap.

## 2.0.0

- v2 design (`docs/sms_validation_process.md`): 12-step pipeline addressing gaps A to H from
  the problem statement, plus a verification feedback loop, risk score engine, progressive
  backoff, adaptive limits, global circuit breaker, channel downgrade and uniform responses.
- Implementation in `src/otp_guard/` with one store interface (memory and Redis backends).
- Real provider adapters: Google reCAPTCHA, Play Integrity, App Attest assertions, ipinfo,
  AbuseIPDB, Twilio Lookup, Twilio SMS/WhatsApp, FCM push, Slack alerts.
- FastAPI service, environment-driven factory with wiring report, background worker.
- Test suite (159 tests) on both backends; scenario runner; recorded results.
- Design fixes found by testing: conversion ratio counts resolved sends only; the manual
  kill switch stops all SMS while automatic emergency mode keeps prioritising clean traffic.

## 1.0.0

- Reconciled the original v1 documents (`docs/original/`) into one consistent design:
  per-number limit aligned to 1 SMS/minute, IP throttling step added, Step 0 logic corrected,
  reCAPTCHA score threshold added, pseudocode parameters completed, counter ordering fixed.
