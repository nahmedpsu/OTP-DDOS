# Evaluation method, metrics and limitations

Results: [`results/evaluation.md`](../results/evaluation.md) (simulation),
[`results/performance.md`](../results/performance.md) (load test and timing-leak test).

## Known weak spots, stated first

These are measured, not hypothetical. Each one is in `results/evaluation.md` or
`results/analysis.md`.

1. **A residential attacker with human-like CAPTCHA scores is not separated from real
   users by any behavioural signal at any volume tested.** The conversion penalty attaches
   to keys the attacker shares with real users (country, prefix, residential ASN), so it
   raises everyone's score by the same amount: it rations rather than separates. Below
   about 1.8 times the legitimate volume it does not fire at all; the dilution curve
   (section G) shows that at 10 times the legitimate volume for an hour it still lets
   most of the attack through while challenging a fifth of real users. With the source
   caps lifted such an attacker leaks at close to its full request rate. The only
   containment comes from the volume caps and the circuit breaker, and those also refuse
   legitimate users. Section C2 quantifies that trade-off.
2. **Exposure before the feedback loop has data equals the attack rate times the OTP
   timeout.** With a 10-minute timeout an attacker at 30 requests a minute is paid 300 SMS
   before any conversion signal exists. Only a shorter timeout moves this (section C1).
3. **A sequential-number walk is now stopped** (about 60 leaked of 600, every seed
   contained) because it stays inside one destination block, which reaches a verdict after
   five unverified sends. An earlier version of the design leaked 300 of 600 on this
   attacker; the fix is the block key, not the narrow-range signal, which alone lands in
   the `delay` tier.
4. **Carrier-grade NAT delivers only 50 % without configuration** (`CGNAT_ASNS`).
5. **A campaign burst delivers 12.5 % under the default source caps** unless the cap is
   raised beforehand.
6. **VPN users are blocked by policy**, as the problem statement asked. That is a product
   decision the design makes visible, not a bug, but it is friction.
7. **Pumper containment depends on how many destination blocks the carrier's ranges
   touch, and the cost has a closed form.** Leakage is about 5 B + rate x 2.5 min for a
   carrier that never verifies and 5 B for one that verifies within a second, with B the
   8-digit blocks touched (section G matches the model to within a few SMS at every
   point of the spread sweep). Three blocks cost 104 and 18 SMS; 300 blocks leak like the
   flooder. **A colluding carrier that verifies at least 42 % of its codes with human-like
   delay is indistinguishable from real traffic on any key**, including the destination
   block (559 of 600 leaked, 323 verified fake accounts per run). The human-like case
   moves the cost downstream into fake accounts.
7b. **The block tests are calibrated, and a wrong calibration costs real users.** They
   assume 80 % legitimate conversion and 20 % of verifications within 5 s of delivery
   (OS autofill). Section H1: at a true conversion of 65 % about 2 % of blocks with
   30 or more sends a day reach a verdict; at 50 %, 9 to 25 %. Section H2 (24 hours of
   legitimate traffic): at 80 % conversion 0 to 2 verdicts a day touching at most a
   couple of real users; at 65 %, 3 to 18 verdicts touching 1 to 22 of 29 000 users, who
   meet a challenge rather than a refusal (delivery stays at 99.3 %). The speed test is
   the lesser risk: even a 30 % autofill share against a 20 % calibration adds under
   1 % of blocks. `sprt_legit_conversion` and `sprt_legit_fast` must come from measured
   traffic.
7c. **A carrier outage looks like a pumper unless receipts and the outage detector say
   otherwise.** Section H3: with the send-clocked design a 30-minute outage on one prefix
   flagged 1.4 blocks and touched 1.8 real users; with delivery receipts gating the tests
   and the carrier-wide suspension, none. The receipt signal is only as honest as the
   provider's reports, and the conversion signal (returning clients only, so a decoy
   flood cannot buy a suspension) needs ten of them.
8. **A challenge solver who buys interactive-challenge solutions receives the -20
   `challenge_passed` credit** and can move from `challenge` back to `delay`; a datacenter
   attacker that does so turns 0 leaked SMS into about 50 per run (section D). A pumper
   that solves the challenge of a stage-1 block verdict earns a second verdict and is
   moved off SMS: 122 leaked against 104 under the hard denylist (section F).
9. **The feedback loop separates attackers only on keys they dominate.** With the
   ablation baseline on the same seeds, removing it raises leakage for the reused-profile
   attacker (it dominates its fingerprint key) and for the sequential walk (it dominates a
   destination block), and changes nothing for the diluted residential attackers. An
   earlier version of this document compared the ablation against the 30-seed main study
   and concluded the loop "contributes nothing"; that comparison mixed seed sets and was
   wrong.
10. **The per-session cap is the most valuable single layer** in the ablation, which is
    also the layer an attacker defeats most cheaply (a new session per request costs one
    call to `/session`). The evaluation's attackers already do this; the cap's value is
    against the naive ones.

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
- Block tests are CUSUM (evidence floored at zero); a trust-building pumper, a
  receipt-faking carrier and a block poisoner are evaluated; six baseline designs are
  compared; the ablation reports paired per-seed differences and legitimate delivery.
- The hourly budget is an atomic hard ceiling; per-number claims are atomic with release
  on later refusal; delivery and verification callbacks are idempotent.
- The timing test includes the challenge response class. Containment time is reported over
  contained seeds only, with the contained fraction alongside; the late-window leakage is
  labelled as such.

## Metric definitions

All per-run metrics are computed from one simulated attack window (20 minutes, after a
10-minute legitimate-only warm-up so that history and baselines exist).

| Metric | Definition |
|---|---|
| **Time to containment** | The earliest minute *m* such that for every minute ≥ *m* the attacker's leaked SMS are at most 5 % of the attacker's request rate in that minute, in minutes from attack start. A run that never satisfies the condition within its 20 minutes is censored: it is reported through the *contained fraction*, and the mean time is taken over contained seeds only. Because the condition is checked to the end of a finite run, a quiet final minute can satisfy it; the late-leak column shows what followed. |
| **SMS leaked before containment** | Sum of the attacker's leaked SMS over minutes before *m* (all leaked SMS if not contained). |
| **Late leak** (formerly "steady state") | Mean leaked SMS per minute over minutes ≥ *m*; over the last 5 minutes if not contained. It is a late-window rate, not evidence of stationarity: hourly budgets, daily reputation, expiring verdicts and the controller all keep moving. |
| **Total leaked** | Sum over the 20-minute window. |
| **Defender cost** | Leaked SMS × SMS price + attacker-attributable HLR lookups × lookup price + attacker-attributable reCAPTCHA assessments × assessment price. Prices in `src/otp_guard/evaluation/calibration.py`. |
| **Friction: dispatched / delivered / completed %** | Dispatched: a channel was chosen and the message handed to the sender. Delivered: the provider's receipt said delivered. Completed: the person entered the code. All over legitimate requests. |
| **Friction, stratified** | The same outcomes for first-time clients (no verified history) and returning clients (a fingerprint that verified before). The headline refusal figure for a design is the first-time rate, since returning clients are exempt from rationing and verdicts. |
| **Friction: challenge rate %** | Legitimate requests that were shown an interactive challenge (90 % of simulated users then solve it). |
| **Friction: refusal rate %** | Legitimate requests refused by a hard step, downgraded with no channel, or whose delivery failed. |
| **Friction: added delay** | Mean seconds of queueing added by the `delay` tier over delivered legitimate requests. |
| **Attacker profit** | Leaked SMS × SMS price × revenue share − (proxy bytes × price per GB + CAPTCHA tokens + solved challenges) × prices. Only pumping profiles earn revenue. |

## Statistical method

- Every attacker profile is run with 30 seeds. Per seed the pool size (log-uniform 500 to
  50 000 addresses), attack rate (uniform 10 to 60 requests per minute) and CAPTCHA score
  class (from the profile's allowed classes) are drawn independently.
- Legitimate traffic is a Poisson process at 20 requests per minute with 80 % conversion
  and a lognormal verification delay (median 25 s, σ 0.6); 60 % of users present a
  fingerprint never seen before.
- Tables report the mean and a 95 % t-interval across seeds. The lower bound of a count
  or rate is clamped at 0. Sweeps and ablation use 10 seeds.
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
- Legitimate OTP conversion 80 % (Twilio reports 65 %+ globally; assumed within range).
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
- **A colluding carrier can fake failed receipts** for other people's sends on its prefix
  to suspend the tests there; every such window raises an outage alert. The simulation
  does not model this.
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

