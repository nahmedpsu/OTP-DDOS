# Evaluation method, metrics and limitations

Results: [`results/evaluation.md`](../results/evaluation.md) (simulation),
[`results/performance.md`](../results/performance.md) (load test and timing-leak test).

## Known weak spots, stated first

These are measured, not hypothetical. Each one is in `results/evaluation.md`; every number
quoted here and in the README has a row in `results/headline_numbers.md`.

1. **A residential attacker with human-like CAPTCHA scores was not separated from real
   users by any behavioural signal at any volume tested.** The conversion penalty attaches
   to keys the attacker shares with real users (country, prefix, residential ASN), so it
   raises everyone's score by the same amount: it rations rather than separates. Below
   about 1.8 times the legitimate volume it does not fire at all; the dilution curve
   (section G) shows that at 10 times the legitimate volume for an hour 70 % of the attack
   still leaks while 17 % of real users are challenged. With the source caps lifted such an
   attacker leaks at close to its full request rate. The containment the design offers
   comes from the volume caps and the spend ceiling, which refuse real users (54 % of
   first-time users; 45.5 % of all users complete). One sweep point contains it without the
   cap, a fresh-fingerprint weight of 40, at 47 % challenged and 9 % refused.
2. **Exposure before the feedback loop has data equals the attack rate times the
   resolution window**, plus delivery. Only a shorter window moves this (section C1).
3. **A sequential-number walk is contained, not stopped** (61 to 69 leaked of about 600,
   every seed contained). A flat limit of five sends per block per day does better (5
   leaked) and also stops the premium pumper at 5.
3b. **The adaptive cap's rationing depends on the controller's cadence, phase and history.**
   Section B2: 2-minute ticks ration nearly like 1-minute ones (276 against 223 leaked);
   5-minute ticks leak 386 or 533 depending on whether the tick lands at the attack's start
   or half a period later; 10-minute ticks 504 or 446; an hourly job sees a 20-minute attack
   as a static cap (533) and lets 91 to 96 % of a 60-minute attack through. Section B3: the
   deployed job learning from the pipeline's own counters leaves the static cap with no
   closed hour (533), rations with three closed hours (235) and with a weekly profile of the
   attack's hour in three previous weeks (193). Against that weekly profile, paired: a
   profile poisoned at the attack's hour every week +45 leaked [+10, +77]; a stale profile
   whose legitimate rate has halved since +106, doubled -30 (at 4.8 points less
   completion); two workers and a mid-attack restart, no difference. Intervals that include
   zero are not evidence of equivalence.
4. **Carrier-grade NAT delivers only 50 % without configuration** (`CGNAT_ASNS`).
5. **A campaign burst delivers 12.5 % under the default source caps** unless the cap is
   raised beforehand.
6. **VPN users are blocked by policy**, as the problem statement asked.
7. **Pumper containment depends on how many destination blocks the carrier's ranges touch,
   and the closed form is a consistency check, not a forecast.** Leakage is about
   5 B + rate x 2.5 min for a carrier that never verifies and 5 B for one that verifies
   within a second, with B the 8-digit blocks a run actually touched. Over the eighteen
   spread configurations the model's mean absolute error is 1.6 to 7.9 SMS (1 to 13 %) in
   the ten unsaturated ones and it overstates by 3 to 19 on average in the eight saturated
   ones, where it predicts that every request leaks (section G, per-run residuals); it uses
   each run's observed blocks, so it is a mechanism check, not a forecast. 300 blocks leak like
   the flooder. **A colluding carrier that verifies 60 % of its codes with human-like delay**
   leaks 452 of about 560 under the default (contained in 0 of 10 seeds) and leaves 272
   verified codes per run (not distinct accounts; no account system is modelled); over 60
   minutes it leaks 1 067 and 8 of 10 seeds are never contained (section F1).
7b. **The block tests are calibrated, and a wrong calibration costs real users.** They
   assume 80 % legitimate conversion and 20 % of verifications within 5 s of delivery.
   Section H1 (per block, empty history, a fixed number of sends; counts with Wilson
   intervals): at 65 % conversion 1 to 3 % of blocks with 10 to 100 sends reach a verdict,
   at 50 %, 9 to 41 %. Section H2 (24 hours, 200 distinct busy blocks, five seeds): at 80 %
   conversion 0.6 to 3.2 verdict events a day (autofill 0 to 30 %); at 65 %, 6.4 to 9.2
   events, 31 to 42 requests hit of about 29 000. The completion loss attributable to the
   default tests (section F2, per request against no policy) is 0.01 % of users. In the
   robustness study the false-alarm bound of claim C4 held at every cell with conversion of
   0.75 or more and at 8 of 18 cells below it (reported, not judged).
7c. **A carrier outage looks like a pumper unless receipts and the outage detector say
   otherwise.** Section H3: send-clocked, a 30-minute outage on one prefix produced 1.8
   verdict events touching 5.0 requests; with receipts gating the tests and the detector,
   0.6 (reported failures) and 0.8 (silent outage). Reduced, not removed.
7d. **Destination policies on a common pipeline (section F2) and the counter study.** Every
   row runs the full pipeline; only the destination policy differs. Settings were selected on
   tuning seeds against a benign service target (the default's completion minus 0.5 points on
   attack-free tuning runs) and evaluated on held-out seeds at three service-calibration
   settings (legitimate densities); in the predeclared 2.7.0 study only density 200 had the full
   sequential grid and attack runs were shared across densities, a gap the counter study's E5
   closes (full grid and density-specific attack runs everywhere; the same counters are selected).
   Across the four concentrated 20-minute pumping profiles, the selected short-window counters
   leaked 24 (4 per 10 minutes, 200 busy blocks), 6 (1 per 10 minutes, uniform) and 9 (3 per
   hour, 29 sends a block a day), and in separate 24-hour attack-free runs their net
   attributable completion loss was 0.06, 0.15 and 0.35 points of offered users. Under the
   counter protocol (`results/counter_study.md`) the principal counter held its security and
   benign-service claims on the held-out family (K1, K2, K4) and failed both service-under-
   attack claims (K3: 127 of 144 cells; K5: 93 of 144); E3 and E4 map where it loses (spreading
   over 30 or more blocks, quota-aware pacing, trust-building pumpers on random numbers, a
   poisoner spread over the shared blocks, legitimate rates near its quota, product launches).
   The comparison scores leakage summed over four scripted pumpers: a declared experimental
   score, not a utility; under worst-case leakage, a first-time-user loss constraint, each
   single pumper and random attacker mixes the same counter is preferred at each density (E5),
   which says nothing about attackers outside the four. The sequential tests without credit (threshold 300) leak 118
   against the human-like carrier at 0.34 % and 314 verdict events a day; at matched
   false-alarm burden, credit of two thresholds or more leaks 538 to 560. A credit floor of
   -c x log(threshold) is a zero-floor CUSUM with threshold (1 + c) x log(threshold) and
   head start c x log(threshold), so the grid is a threshold and head-start sweep. Every
   service figure assumes 70 % WhatsApp reachability; section H4 shows the graded counter's
   completion moving from 27 % to 64 % as reachability goes from 0 to 100 %. The second-round
   version of this comparison charged challenged attempts to the counter and ran with the
   fallback regression described below; its conclusion (counters cost 2 to 21 % completion)
   does not survive.
7e. **Faked receipts, white-box carriers and bought trust defeat the block tests.** A carrier
   that reports every delivery as failed feeds the tests nothing: 570 leaked without caps,
   no verdict ever. A threshold-aware carrier that replays its own pending outcomes in the
   deployed order and enters a code only when its block nears the threshold leaks 570 with no
   verdict and 286 codes entered. The short-window counter holds both to 24 on concentrated
   blocks (counter study E3), and does nothing against a trust-building pumper on random
   numbers (577, as with no policy). A pumper whose 500 identity/number pairs
   verify everything for ten minutes and then flood leaks 253 in its flood phase (81 under
   caps) after 263 verified codes in preparation; over 30 + 30 minutes, 628 after 763.
   Receipt-robust tests stop the receipt faker (16 leaked) at 30 false verdict events a day
   on 200 blocks with a poor route, against 1; a trust budget of 8 exempt requests a minute
   trims the trust builders by 23 to 40 SMS; neither touches the threshold-aware carrier
   (section D3).
7f. **The block key can be turned against real users, and grading limits the damage without
   capping it at a challenge.** Section D2: a poisoner on the 20 blocks real users share
   earns 16 verdict events on 13 blocks and hits 98 requests (stage 1 and stage 2, where
   first-time clients are moved off SMS). Against the observe-only counterfactual on the same
   trace, the loss attributable to enforcement is 12.7 requests (3.1 % of users) at 70 %
   WhatsApp reachability, 25.8 (6.3 %) at none, 6.4 (1.6 %) at full, and 97.7 (24 %) under
   the hard denylist. In a 70-minute run whose poisoner stops after 10 minutes, verdicts hit
   406 requests after it stopped; the loss attributable to enforcement among requests after
   the stop is 46.2, and 48.2 over the whole run (two windows, reported separately).
8. **A challenge solver who buys interactive-challenge solutions receives the -20
   `challenge_passed` credit** and can move from `challenge` back to `delay`; a datacenter
   attacker that does so turns 0 leaked SMS into 51 to 55 per run (section D). A pumper
   that solves the challenge of a stage-1 block verdict leaks 104 against 88 under the hard
   denylist (section F).
9. **The feedback loop separated attackers only on keys they dominated, in these runs.** On
   an identical offered trace, removing it adds 138 leaked SMS for the reused-profile
   attacker (it dominates its fingerprint key) and 152 for the sequential walk (it dominates
   a destination block), and changes nothing for the diluted residential attackers. This is
   what the tested settings showed, not a necessity result; "dominates" is not defined per
   detector beyond those settings.
10. **The per-session cap is the cheapest layer to defeat** (a new session per request costs
    one call to `/session`) and the evaluation's attackers already do this; its 29 SMS of
    value in the ablation is against the naive client.
11. **The robustness study's claims hold in a bounded region.** All five predeclared claims
    hold (C1 108/108, C2 34/36, C3 36/36, C4 18/18, C5 36/36) over 12 jointly shifted
    operating points and held-out attack rates and pools; outside the protocol's ranges
    nothing is claimed.

## What changed after the Reviewer 2 report (implementation and evaluation)

- The sent message carries the verification code; the simulation verifies with the code
  read from the message, not from the store.
- The challenge proof is checked through the CAPTCHA adapter's `verify_challenge`, which
  the Google adapter implements against the interactive site key.
- A challenged party retries with the same session, number and address.
- Legitimate outcomes are *dispatched* (channel chosen), *delivered* (provider receipt) and
  *completed* (code entered); an undelivered send counts as refused. Friction is reported
  for all requests and for first-time (no verified history) and returning clients.
- The timeout sweep varies the resolution timeout, not OTP validity.
- The adaptive job runs in the simulation at the worker's cadence (every minute) and the
  default worker implements it from the pipeline's own counters; a cadence study shows the
  hourly alternative.
- The spoofed-header attacker uses a valid host and session; only the header is forged.
- Sessions are acquired through the CAPTCHA gate; refused attempts and their token cost are
  counted.
- Random streams are split: the offered workload is drawn at request creation and does not
  depend on the defence, so same-seed runs are paired.
- Events are processed at their own timestamps; receipt timing includes the sender's queue
  delay.
- Spread ranges are drawn without replacement; the observed count of blocks requested is
  reported and used by the model.
- Block tests are CUSUM with bounded credit (evidence floored at minus one threshold;
  the no-credit and unbounded variants are evaluated side by side); a trust-building pumper, a
  receipt-faking carrier and a block poisoner are evaluated; six baseline designs are
  compared; the ablation reports paired per-seed differences and legitimate delivery.
- The hourly budget is an atomic hard ceiling; per-number claims are atomic with release
  on later refusal; delivery and verification callbacks are idempotent.
- The timing test includes the challenge response class. Containment time is reported over
  contained seeds only, with the contained fraction alongside; the late-window leakage is
  labelled as such.

## What changed after the second-round report

- **Offered workload.** Every exogenous quantity of a request, including the CAPTCHA token
  a challenge retry would present and which returning identity a returning request uses, is
  drawn from the workload stream when the request is created; returning identities come from
  the identities the trace itself offered earlier, not from what the defence verified. The
  result carries a hash of the offered trace, and `tests/unit/test_simulator_invariants.py`
  asserts it is identical across designs and cap modes for the same seed.
- **Cohorts.** A request is bound at creation to one immutable pair of accumulators; warm-up
  requests go to discarded ones. Conservation (subgroups add to the whole; completed <=
  delivered <= dispatched <= users) is asserted at the end of every run.
- **Funnel.** A legitimate request is counted as a user when offered, before the session
  gate; losses are named by stage (gate, hard step, no channel, undelivered).
- **Clock.** Arrivals carry timestamps inside their minute; the clock moves to each arrival
  and each minute boundary whatever the pipeline decides. The run drains to a declared
  horizon (receipt grace + resolution timeout + the slowest modelled entry) and reports
  anything still pending (zero in every recorded run).
- **Verdicts are events.** The verdict log has one member per verdict (block, stage, time);
  tables report events, distinct blocks, stage-1 and stage-2 counts, the requests hit by
  stage, those that never completed, and block-minutes under a verdict.
- **Containment time** is the mean over contained seeds, printed with "contained k/n"; the
  horizon-filled mean is kept in the JSON under its own name.
- **Legitimate blocks** are sampled without replacement; occupancy (median and maximum
  sends a block actually received) is reported.
- **Detector comparison (F2).** The sequential tests at thresholds 100 / 1000 / 10000 and
  credit 0 / 0.5 / 1 / 2 / unbounded, and the flat per-block counter at 5 / 10 / 20 per
  day with a refusing and a graded action, all on the same seeds against the four
  concentrated pumpers and for 24 hours of legitimate traffic at 80 % and 65 % conversion.
  A credit floor of -c x log(threshold) is a zero-floor CUSUM with threshold
  (1 + c) x log(threshold) and head start c x log(threshold); the grid spans both.
- **Cadence (B2)** at 1, 2, 5, 10 and 60 minutes, two tick phases, and a 60-minute attack
  for the hourly job. **Baseline job (B3)**: the deployed job against the oracle, with cold
  start, one and three closed hours, and a poisoned learning period.
- **Trust builders** keep one-to-one identity/number pairs, are reported by phase
  (preparation / flood), and a concentrated variant puts the pairs' numbers inside three
  destination blocks. **Poisoning (D2)**: graded, hard-deny and recovery variants with
  stage counts, lost completions and hits after the attack stopped.
- **Monte Carlo (H1)** reports event counts, trials and Wilson intervals, and states its
  initialisation. **Spread (G)** reports per-run residuals, saturated runs apart.
- **Implementation.** OTP state is written before the sender is called; receipt,
  verification and block-test transitions are atomic (compare-and-set), with the receipt
  rules defined in `feedback.py`; the hard ceiling belongs to the `circuit_breaker` flag;
  the baseline job's fallback divides by the hours it has; the graded per-block counter
  exists as a comparator. Concurrency is tested on a real Redis across two instances
  (`tests/integration/test_real_redis.py`), which is the only place those properties are
  established; vendors remain untested live.

## What changed after the sixth-round report

Repository-side items of the sixth-round report (2.8.2). The manuscript's analytical claims (M1,
Q1-Q10) are the author's; the repository supplies the corrected analysis and semantics they rest on.

- **Outage block recency under replay (M4).** The distinct-block set of the outage detector held
  one member per block and a replay assigned it the replayed event's time, so an older replayed
  failure erased a newer one's recency (the reviewer's two-send case: 900 moved back to 0, and the
  1800-s window lost the block). The member now keeps the block's newest failure time
  (`store.zadd_max`, one script on Redis). Regression: `tests/unit/test_sixth_round.py`,
  `tests/integration/test_real_redis.py`; the test fails on 2.8.1.
- **Block-test events at their transition's time (M5).** `_block_event` took the clock's time for
  the active-verdict check, the verdict's time and its expiry, so a crossing replayed 600 s late was
  dated 600 s late. The event's time is now passed in and the semantics are defined at the top of
  `feedback.py`: an event counts toward the test running at its time (one dated before the last
  crossing is recorded, not counted), a crossing issues its verdict at the event's time and escalates
  against the verdict active then, and a reversal subtracts its failure only if the test now running
  is the one that counted it (2.8.3; 2.8.2 compared the failure's event time with the last crossing,
  which reversed a failure counted before a replayed, earlier-dated crossing against the new test;
  regression test `test_reversal_of_a_failure_the_concluded_test_counted_leaves_the_next_test`, failing
  on 2.8.2). Tests cover the replayed crossing, escalation near a verdict's expiry,
  a reordered old event, and documents written by 2.8.1. The live path is unchanged (its event time
  is the clock's), so no simulated number moves.
- **Operating condition (M2).** Part D of `scripts/run_round5_analyses.py` now caps the counter's
  allowance at the volume the pumper offered (N, from the same E4 cells) instead of the no-policy
  arm's leakage, caps the sequential first-verdict estimate at N as well, computes the intercept
  from the 3-block, 60-minute cell and marks that row as the fit and every other row as a check,
  and states the horizon mismatch (whole attack against first verdict) in the report. Manuscript
  revision 6 (Figure 4(b), file `fig7_counter_boundary`) draws instead the unfitted per-run estimates
  of `scripts/check_condition.py` (tau from the configuration, lambda and N from each run), at the
  sampled spreads only (`results/condition_check.md`). `results/round5_analyses.{md,json}` part D was recomputed from the recorded
  files (`--refresh-d`); no run changed.
- **Service model (M3).** The share of a block's sends beyond the quota is reported under both
  window models: exogenous fixed windows (E[(n-q)+]/m, the figures the fifth revision quoted) and the
  implemented arrival-anchored window (E[(1+X-q)+]/(1+m): 7.27 % at m = 2 and 26.96 % at m = 4 for
  q = 4, against 3.76 % and 19.54 %). The anchoring is now stated wherever the counter is described.
- **Found, disclosed, not changed: sorted-set expiry in the memory store.** The simulator's memory
  store keeps a sorted set's expiry from its creation; the Redis store refreshes it on every write.
  The outage detector's per-carrier sets therefore empty 2 x window after their first write in a
  simulated run and are recreated, which can suppress or delay a suspension that a Redis deployment
  would have issued. Measured on the 102-run reproduction sample (`results/store_expiry_check.md`):
  refreshing only the distinct-block set changes 18 runs, 16 of them only in the outage-alert count;
  refreshing every sorted set as Redis does, which also reaches Step 5's number-pattern sets, changes
  27, four of them in leakage (a matched-comparison tuning run, 268 messages against 21). The recorded results and `zadd_max` keep the
  memory store's rule; aligning it with Redis means rerunning the outage-related studies
  (`CHANGELOG.md`, 2.8.2).

## What changed after the fifth-round report

Release 2.8.1. The 2.8.0 results stand; `scripts/check_reproduction.py` replays three recorded runs
from every study of both result files with the final code and finds them identical in every
recorded field (`results/reproduction_check.md`).

- **Selection under each objective (M1).** `scripts/run_round5_analyses.py` (part A) makes every
  setting that meets the tuning target on the E5 tuning runs a candidate, selects under each
  objective on the tuning runs (summed leakage, worst case, a first-time-loss limit, each attacker
  alone, 2,000 random mixes) with the original tie-break, freezes the union of winners and
  evaluates it on the fresh seeds; the 60 union members that had no evaluation runs were run
  (`results/round5_union_eval_runs.jsonl.gz`). The random mixes are a tuning-data selection only:
  on evaluation data, a policy with the lowest point estimate for every attacker minimises every
  nonnegative mixture.
- **Claims by attacker (M6)** (part B): K1-K5 per carrier, with the points of the failing cells.
  The 144 cells share workloads and seeds and are not independent samples.
- **Attacked service, three questions (M2, M3)** (part C): for every E1 arm, extra harm against
  the attacked no-policy arm, degradation against attack-free operation under the same policy
  (240 new attack-free runs on the E1 traces, `results/round5_attack_free_runs.jsonl.gz`) and the
  benign cost, by cohort (all, first-time, returning, the attacked blocks' users) with gross
  losses and gains.
- **Operating condition (M5)** (part D): the counter's envelope (quota x blocks x windows) and the
  Equation 2 estimate against the E4 security map, and the Poisson share of a block's sends
  beyond the quota and twice the quota.
- **Timing (M10).** `scripts/load_test.py --holdout N` fits the best latency threshold on one
  phase-4 run and applies it to independent runs (`results/performance_holdout.md`); the
  phase-4 accuracy in `results/performance.md` is a resubstitution value.
- **Implementation (M8, M9).** Replayed effects at their transition's time (block-test verdicts
  followed in 2.8.2, sixth round M5); failure ids kept for
  the replay horizon plus the code lifetime; conditional removal of timeouts; Step 11 challenges
  give back their source-cap counts; tests on memory, fakeredis, a real Redis and over HTTP. See
  `CHANGELOG.md`.
- **Protocol corrections.** `config/counter_protocol_erratum.md` attaches dated corrections (the
  seed note, the burst-12 label) to the frozen protocol, which is unchanged.

## What changed after the fourth-round report

- **Concurrent counter semantics (M5).** The graded counter's first boundary was read at Step 5
  and not re-decided at the Step 11 reservation; under concurrency requests could fill the second
  tier without a challenge. The reservation now decides the stage atomically (a two-tier Lua
  reservation on Redis, a lock in memory; the token bucket by compare-and-set). The simulation is
  single-threaded, so this fix does not move any simulated number; it makes the deployed policy
  the one that was evaluated.
- **Replay horizon (M6) and reversal ordering (M15).** Block-event ids are kept by age for the
  replay horizon rather than the last 256; a batch older than the horizon is skipped and counted,
  never applied twice; a reversal reaching a block before the failure it reverses leaves a
  tombstone. The guarantee is at most once, and exactly once if the sweep runs within the horizon.
  Two races remained open in 2.8.0 and are closed in 2.8.1 (below): a reversal recovered after
  the reversed failure's event id had expired, and a correcting receipt landing between the
  timeout worker's transition and its bookkeeping.
- **The counter study (M1-M4, M7-M9, M13, M16)** follows `config/counter_protocol.json`, a fresh
  protocol committed and pushed before its runs. It freezes the policies the 2.7.0 comparison
  selected and does not relabel the earlier predeclared study. Chronology: written after the 2.7.0
  results were known; only the seeds (300-309, 6000+) and the shifted workloads it names are new,
  and the generator and attacker family are those developed over the earlier revisions.
  Results: `results/counter_study.md`. Erratum: the protocol's seed note says the 6000-series
  seeds were never used before; six of them (6000-6002, 6100-6102) had been the main
  evaluation's robustness seeds for points 10 and 11 (`5000 + 100 x point + seed`). The
  protocol file is kept as committed (its recorded hash would otherwise change); the overlap is
  stated here, in the README, in `CHANGELOG.md` and in a marked line of the generated report.
  The 300-series seeds are fresh.
- **Simulator realism (M13).** WhatsApp reachability is a stable property of the number (a hash
  of seed and number) instead of a per-request draw; returning account holders carry verified
  fingerprint history as well as a trusted number; the counter study adds hot blocks, a product
  launch, correlated challenge failure for users without a fallback, and poor routes on the hot
  blocks. Every study was rerun with these defaults.
- **Variance (M12).** The fixed-versus-randomised comparison is named a fixed-parameter
  sensitivity comparison; a nested design (10 attacker configurations x 3 simulation seeds)
  estimates between- and within-configuration variance components.
- **Ablation (M14).** Four selected two-layer removals with paired interaction contrasts; the
  matrix is described as conditional effects that do not add up.
- **Attributable loss** now reports gross losses and gains, first-time and returning users,
  users of the attacked blocks, and (for the recovery variant) the window after the attack
  stopped separately from the whole run (Q7).
- **Provenance (M18).** Every checkpointed or reused run carries a hash of the source and
  configuration; rows from other code are rejected; results state the code hash, the environment
  and whether the invocation was clean or resumed.
- **Timing (M17).** Under the adversarial load mixture, timing by outcome class, the share of each
  class over the floor, and an explicit observer model (best single-threshold balanced accuracy
  between outcome classes whose responses are otherwise identical).
- **Figures.** Larger labels and direct labels (Figures 1-6), the benign service target and the
  provenance of each axis on Figure 6 with a paired-difference panel, separate families in Figure
  4, a key-effects table for Figure 2, and Figure 7 for the counter's boundary.

## What changed after the third-round report

- **Fallback.** The simulator drew each request's WhatsApp reachability, stored it and hashed it,
  but never wrote it into the registry the channel selector reads, so no downgraded user was ever
  served over WhatsApp. That regression came from the second-round rewrite of the simulator and
  invalidated every service figure for policies that downgrade (the graded counter above all).
  The draw now reaches the selector before each request; `tests/unit/test_simulator_invariants.py`
  asserts dispatch and completion at 0 %, 70 % and 100 % reachability.
- **Verdict estimands.** Three quantities, reported separately: incidence (verdict events issued
  inside the observation window), exposure (block-minutes under a verdict inside the window: the
  union of active intervals intersected with the window, including verdicts issued before it, never
  negative) and eventual events (issued at or after the attack start including the drain, i.e.
  caused by sends inside the window). The second-round exposure clipped interval ends to the window
  but kept drain-time starts, which produced negative block-minutes.
- **Atomic compound transitions and recorded effects** (`feedback.py`): a negative receipt
  marks the send failed and resolves it as undelivered in one compare-and-set; a timeout decides
  inside the compare-and-set; a code entry counts the attempt and closes the send together; the
  effects of a transition are recorded in the same write and applied idempotently, with a
  write-ahead intent and a recovery sweep for a process that dies in between. The block verdict
  lives in the block's document, so the stage is decided in the crossing write. Interleaving and
  crash-injection tests on both backends; graded escalation and crash recovery across two
  instances on a real Redis.
- **The destination counter counts SMS sends** to the block in its window (stage read at Step 5,
  send reserved atomically at Step 11); a refused or challenged request and its retry cost nothing
  unless an SMS goes out. Windows: daily, or short and refilling. The window is arrival-anchored:
  it opens at the block's first accepted send and later sends do not restart it, so a reset cycle
  holds that send plus whatever arrives in the window's length (not a fixed clock window).
- **Matched comparison on a common pipeline** (section F2): every row runs the full pipeline with
  only the destination policy changed; settings are selected on tuning seeds against a predeclared
  service target and evaluated on held-out seeds, at three block densities, at 65 % and 80 %
  conversion, with completion attributable to the policy measured per request against no policy
  on the same offered trace. The second-round "system comparison" (counter rows without the risk
  engine and feedback) is replaced.
- **Predeclared robustness study** (section R; `config/evaluation_protocol.json`, committed and
  pushed before any run that uses it).
- **Attributable versus descriptive harm.** "Hit and never completed" is kept as a descriptive
  count; attributable loss compares the same requests with the intervention enabled and disabled
  (none, or observe-only verdicts for the poisoner).
- **Learned baseline over its own timescale** (section B3): three previous weeks of the attack's
  hour, stale profiles, schedule-aware poisoning, two workers, a restart; paired differences
  against the clean weekly profile with bootstrap intervals, no equivalence claims.
- **Containment** needs five sustained quiet minutes; a 60-minute attack reports survival; time to
  first verdict is reported beside containment.
- **Adaptive attackers**: a white-box threshold-aware carrier that replays its own pending outcomes
  in the deployed application order, and a 30-minute trust builder; two design alternatives
  (trust budget, receipt-robust tests) evaluated against them and for their legitimate cost.
- **Statistics**: percentile-bootstrap intervals over runs (inside the data range) everywhere,
  90th percentile and maximum for counts, leak share per run, and a variance decomposition
  (randomised versus fixed attacker parameters).
- **Economics**: an event-level bill (every session attempt's token, every request, every solved
  challenge, proxy traffic) and the break-even revenue share instead of one assumed share.
- **Legitimate traffic is paired across scenarios.** Legitimate requests are drawn from their own
  random stream, independent of the attacker, so at a given seed every scenario (no attack included)
  offers the same legitimate users. Before this, an attack run and the no-attack run at the same
  seed offered different users, and the first full run of the robustness study failed claim C1 on
  its service clause in 32 of 108 cells for that reason alone (no cell failed on leakage); that run
  is kept in `results/robustness_first_run.md`, and every study was rerun.
- **Returning users** are a pre-existing population of account holders with stable identity and
  number and verified history written before the run; whether a request was actually treated as
  known-good is recorded separately.

## Metric definitions

All per-run metrics are computed from one simulated attack window (20 minutes unless the
table says otherwise, after a legitimate-only warm-up so that history and baselines exist).

| Metric | Definition |
|---|---|
| **Time to containment** | The earliest minute *m* such that for every minute ≥ *m* the attacker's leaked SMS are at most 5 % of the attacker's request rate in that minute, with at least five such minutes before the run ends, in minutes from attack start. A run that never satisfies the condition within its 20 minutes is censored: it is reported through the *contained fraction*, and the mean time is taken over contained seeds only. Because the condition is checked to the end of a finite run, a quiet final minute can satisfy it; the late-leak column shows what followed. |
| **SMS leaked before containment** | Sum of the attacker's leaked SMS over minutes before *m* (all leaked SMS if not contained). |
| **Late leak** (formerly "steady state") | Mean leaked SMS per minute over minutes ≥ *m*; over the last 5 minutes if not contained. It is a late-window rate, not evidence of stationarity: hourly budgets, daily reputation, expiring verdicts and the controller all keep moving. |
| **Total leaked** | Sum over the 20-minute window. |
| **Defender cost** | Leaked SMS × SMS price + attacker-attributable HLR lookups × lookup price + attacker-attributable reCAPTCHA assessments × assessment price. Prices in `src/otp_guard/evaluation/calibration.py`. |
| **Friction: dispatched / delivered / completed %** | Dispatched: a channel was chosen and the message handed to the sender. Delivered: the provider's receipt said delivered. Completed: the person entered the code. All over legitimate requests *offered* (counted before the session gate). |
| **Friction, stratified** | The same outcomes for first-time clients and returning clients, where *returning* is a property of the offered trace (an identity the trace offered before). Whether that identity holds verified history depends on what the defence did with its earlier request, so a returning client refused earlier is counted here as a returning client refused again. The headline refusal figure for a design is the first-time rate. |
| **Friction: challenge rate %** | Legitimate requests that were shown an interactive challenge (90 % of simulated users then solve it). |
| **Friction: refusal rate %** | Legitimate requests lost at the session gate, refused by a hard step, downgraded with no channel, or whose delivery failed (`refused_by` names the stage). |
| **Verdict incidence / exposure / eventual** | Incidence: events issued inside [attack start, end of the last minute]. Exposure: block-minutes under a verdict inside that window (union of active intervals intersected with the window, including verdicts issued before it). Eventual: events issued at or after the attack start, including the drain. |
| **Attributable loss** | Requests that completed in the paired run without the intervention (no destination policy, or verdicts recorded but not enforced) and did not complete with it, minus the reverse, on the same offered trace (request ids aligned; the workload hash is asserted equal). |
| **Intervals** | 95 % percentile bootstrap over runs (2 000 resamples); paired differences are bootstrapped per seed. |
| **Verdict events / blocks with a verdict** | Events: every verdict the block tests issued in the window (a block can be judged more than once; a second verdict inside the TTL escalates to stage 2). Blocks: distinct blocks among them. *Requests hit*: legitimate requests that met a verdict (by stage); *never completed*: those among them whose code was never entered. *Block-minutes under verdict*: the union of the verdict intervals per block, capped at the run's end. |
| **Friction: added delay** | Mean seconds of queueing added by the `delay` tier over delivered legitimate requests. |
| **Attacker profit** | Leaked SMS × SMS price × revenue share − (proxy bytes × price per GB + CAPTCHA tokens + solved challenges) × prices. Only pumping profiles earn revenue. |

## Statistical method

- Every attacker profile is run with 30 seeds. Per seed the pool size (log-uniform 500 to
  50 000 addresses), attack rate (uniform 10 to 60 requests per minute) and CAPTCHA score
  class (from the profile's allowed classes) are drawn independently.
- Legitimate traffic is a Poisson process at 20 requests per minute with 80 % conversion
  and a lognormal verification delay (median 25 s, σ 0.6); 60 % of users present a
  fingerprint never seen before.
- Tables report the mean and a 95 % percentile-bootstrap interval across seeds (2 000
  resamples), which stays inside the range of the data; counts that matter in the tail
  also report the 90th percentile and the maximum. Sweeps and ablation use 10 seeds.
- Two modes are reported: **behavioural only** (source caps lifted, so the score, feedback
  and number layers are visible) and **with source caps** (per-minute web cap at 3 times
  the legitimate rate). In the second mode v2 runs the adaptive baseline job and the
  known-good exemption; v1 runs static caps, because the adaptive cap is v2's Step 9 and is
  behind the `adaptive_caps` feature flag. An earlier version gave v1 the adaptive cap as
  well, which made the two designs look tied against the residential attackers.
- The pumping study uses a 130-minute legitimate warm-up so that the opt-in relative
  baseline has the history it needs; the main study's 10-minute warm-up cannot exercise it.
- Destination-block decisions use sequential probability-ratio tests rather than fixed
  sample sizes, so a pumper's leakage no longer scales as 50 SMS per block.
- The ablation switches off one layer at a time via `Config.features`. Its `full v2`
  baseline is run on the same seeds as every ablation column; the 30-seed main study is
  not used as the baseline. When the session layer is off, client identities are still
  read from the token so the other layers see the same traffic (an earlier version
  collapsed all traffic into one fingerprint, which made the sequential detector fire on
  everything).
- The weight sweep varies each risk weight and the tier boundaries one at a time; the cap
  sweep varies the adaptive floor and the base cap multiple. The trade-off chart plots
  legitimate friction against attacker steady-state leakage for every setting, with the
  Pareto frontier.

## Calibration

The synthetic traffic is calibrated to published figures where they exist and to stated
assumptions where they do not. The table at the end of `results/evaluation.md` lists every
parameter, its value and its source, and marks assumptions. The important ones:

- SMS price 0.1422 USD (Twilio, Saudi Arabia); HLR lookup 0.008 USD; reCAPTCHA Enterprise
  0.001 USD per assessment.
- Legitimate OTP conversion 80 % (Twilio's Verify product page reports 68 %+ globally; assumed within range).
- reCAPTCHA v3 human score distribution Beta(9, 1.5) (assumed; Google publishes none).
- CAPTCHA solving 0.003 USD per v3 token; residential proxies 3 USD per GB; pumping
  revenue share 20 to 50 % of the termination fee (assumed; public reports give no figure).
- 94 % of mobile data networks use carrier-grade NAT (Richter et al. 2016).

## Delivery receipts, outages and graded verdicts (method)

The destination-block tests are the one part of the design that acts on a key real users
share by the thousand, so section H of `results/evaluation.md` measures what they do to
real users under three conditions:

- **A population unlike the calibration.** The tests as deployed assume 80 % conversion and
  20 % of verifications within 5 s of delivery (OS autofill). H1 is a Monte Carlo of the
  exact tests on one block seeing only legitimate traffic, over true conversion 50 to 90 %
  and true autofill share 0 to 30 %, at 10, 30 and 100 sends per block per day: the chance
  that the block reaches a verdict in a day.
- **Twenty-four hours of real traffic.** H2 runs the simulation with no attacker at all for
  24 hours, with legitimate numbers drawn from a fixed set of blocks (200, 1 000, or the
  whole range) so that a block sees 144, 29 or about 4 sends a day, over the same
  conversion and autofill shares. It counts blocks that reached a verdict and the real
  users a verdict touched (a first-time client on a flagged block who was challenged or
  moved off SMS; returning clients are exempt).
- **A carrier outage.** H3 stops one prefix for 30 minutes inside an hour of legitimate
  traffic, in two forms: the provider reports every send failed, or reports delivery while
  nobody receives anything. Three variants: receipts with the outage detector (the
  default), receipts without it, and no receipts at all (the design as first written,
  where a send that is not verified is a failure).

The mechanisms under test (`src/otp_guard/feedback.py`): a send resolves as *failed* only
after a delivery receipt and the resolution timeout; a send with no receipt inside 60 s,
or a failed one, is *undelivered* and feeds nothing; verification speed is clocked from
the receipt; the tests are suspended on a carrier whose receipts collapse across many
blocks or whose *returning* clients (verified history, which an attacker cannot
impersonate) stop verifying across many blocks; a verdict makes the block's first-time
clients solve a challenge for an hour and, on a second verdict, moves them off SMS, while
clients with verified history are never affected. The simulation delivers receipts after
a lognormal delivery delay (median 3 s), gives 20 % of legitimate requests a returning
fingerprint, and gives 20 % of legitimate verifications an autofill entry delay (median
2 s from delivery); the speed test's legitimate rate is set from that model, as a
deployment would set it from its own measurements.

## The closed-form leakage model

`src/otp_guard/evaluation/model.py`. Against the block tests a pumper's leakage depends
on the number of 8-digit blocks it touches, B, not on how many numbers it uses:

    leak ~= min(N, k * B + lambda * tau)

with N its requests, lambda its rate, k the sends one block costs before its verdict
(5 for a carrier that never verifies: ceil(ln 1000 / ln(0.9 / 0.2)); 5 for one that
verifies within a second at P(fast | user) = 0.2: ceil(ln 1000 / ln(0.9 / 0.2)); 3 at
the 0.5 % of an autofill-free population) and tau the time a send stays unresolved
(resolution timeout + delivery delay + half the worker's period for the non-verifier;
delivery plus the carrier's own delay for the instant verifier). Section G compares the
model with the spread sweep. A carrier evades the conversion test by verifying at least
s* = ln(0.9/0.2) / (ln(0.9/0.2) + ln(0.8/0.1)) = 42 % of its codes, each a verified fake
account the defender now holds.

## Limitations

- **No production data.** The whole evaluation is simulated. No anonymised logs from the
  original incident or the v1 period were available to the authors, and no live vendor
  call was made. `scripts/replay_logs.py` and `docs/replay_schema.md` exist so that logs
  can be replayed through v1 and v2 when they become available; until then every absolute
  number here is conditional on the calibration.
- **The number-lookup fake says every number is live.** A real HLR would reject a share of
  random numbers; the attacker profiles here are therefore harder than reality on that
  axis.
- **The prefix table is a sample.** Random attacker numbers are drawn from the standard
  ranges in it; a production table is the operator's, and an incomplete one leaks premium
  ranges (weak spot 7).
- **Fakes have zero latency.** Performance numbers cover the pipeline and Redis only.
- **Legitimate behaviour is stylised.** No abandonment, no retries after a delivery
  failure, one request per user, and every user is on the same ISP as the residential
  attacker (the worst case for dilution).
- **Attackers do not adapt within a run**, apart from the adaptive profiles in section D.
- **Autofill share and returning-user share are assumed** (20 % each). The false-positive
  study sweeps the autofill share because the speed test's calibration depends on it; a
  deployment must measure its own.
- **The outage detector's conversion signal needs returning users.** On a prefix with
  little traffic it takes most of half an hour to see ten of them, during which a silent
  outage can produce verdicts; the delivery-receipt signal is faster and is what a
  provider with honest reports gives you.
- **A colluding carrier can fake failed receipts.** For its own sends this is the
  `receipt_faking_carrier` profile in section D (no verdict ever); for other people's
  sends on its prefix it would suspend the tests there and raise an outage alert on every
  such window. The simulation models the first, not the second.
- **The confidence intervals cover seed-to-seed variation only**, not calibration error.

## Performance and timing-leak method

`scripts/load_test.py` runs against a real `redis-server` on the same container (the report header states its vCPUs and worker count).
Phase 1 drives the pipeline in process with 3 000 mixed requests (55 % sent, 15 % no
session, 15 % disallowed country, 15 % repeated number) and records per-step and
end-to-end latency percentiles, plus Redis round trips and commands per request from
`INFO commandstats`. Phase 2 serves the API with uvicorn (`LOAD_TEST_WORKERS` processes, sync handlers in
the default thread pool) and fires 6 000 requests at concurrency 32, once with the 400 ms
response floor and once with it disabled as the control. The server labels each response
with its true outcome through an opt-in debug header that exists only for this test.
Client-observed latencies are compared across outcomes with two-sample
Kolmogorov-Smirnov tests (about 900 to 3 300 samples per outcome): a p-value below 0.05
means an attacker measuring only response time could tell those two outcomes apart. A KS
test cannot show equivalence, so each pair also gets a two-one-sided-tests (TOST) check on
the mean difference with a 2 ms margin; a small TOST p-value means the means are
demonstrably within 2 ms. The report also states the fraction of requests whose pipeline
processing exceeded the floor (those leak timing whatever the floor) and labels the
with-floor throughput for what it is: concurrency divided by the floor, not capacity.
Results: `results/performance.md`.

Measured with 2 workers on 2 vCPUs and 6000 requests (an earlier run with 4 workers on 4
vCPUs gave the same picture): with the floor, no pair of outcomes is distinguishable by KS
test (smallest p = 0.33) and every pair is equivalent within 2 ms by TOST (largest mean
difference 0.62 ms); no request's pipeline time exceeded the floor. Without the floor every
pair is distinguishable. With one worker at concurrency 32 the sent path reached about
650 ms of wall time through GIL contention while its pipeline time stayed under 400 ms, and
the floor did not hold: the floor must exceed the deployment's wall-time p99 under load,
which is a worker-count question. Capacity: 210 requests/s at concurrency 32 on 2 workers
with faked vendors (303 on 4). A full send costs 46 Redis round trips: 41 before delivery
receipts, the block-test counters and the outage windows, which add a receipt write, a
counter hash, a verdict read and two pipelined window counts.

