# Changelog

## 2.5.0 (unreleased)

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
