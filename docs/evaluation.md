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
3. **A sequential-number walk is now stopped** (66 leaked of 600, every seed contained)
   because it stays inside one destination block, which the feedback loop denylists. An
   earlier version of the design leaked 300 of 600 on this attacker; the fix is the block
   key, not the narrow-range signal, which alone lands in the `delay` tier.
4. **Carrier-grade NAT delivers only 50 % without configuration** (`CGNAT_ASNS`).
5. **A campaign burst delivers 12.5 % under the default source caps** unless the cap is
   raised beforehand.
6. **VPN users are blocked by policy**, as the problem statement asked. That is a product
   decision the design makes visible, not a bug, but it is friction.
7. **Pumper containment depends on how narrowly the carrier's ranges concentrate.** The
   block key separates a pumper whose ranges fit inside 8-digit blocks; ranges of 100 000
   numbers span ten keys each and leak several times more, and at 300 ranges the pumper
   leaks like the diluting flooder (section G, figure). **A colluding carrier that submits
   codes with human-like delay is indistinguishable from real traffic on any key**,
   including the destination block (557 of 600 leaked,
   324 verified fake accounts per run). A carrier that verifies instantly is denylisted
   as machine-verified by minute 8; one that does not verify is contained by minute
   10 (section F). The human-like case moves the cost downstream into fake accounts.
8. **A challenge solver who buys interactive-challenge solutions receives the -20
   `challenge_passed` credit** and can move from `challenge` back to `delay`. In the
   evaluation this attacker never even reaches the challenge tier (dilution keeps its score
   low), so the credit is not what leaks; the mitigation still is to cap the credit per
   session.
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

## Metric definitions

All per-run metrics are computed from one simulated attack window (20 minutes, after a
10-minute legitimate-only warm-up so that history and baselines exist).

| Metric | Definition |
|---|---|
| **Time to containment** | The earliest minute *m* such that for every minute ≥ *m* the attacker's leaked SMS are at most 5 % of the attacker's request rate in that minute. Reported in minutes from attack start. A run that never satisfies the condition is "not contained"; its value is the run length (20) in averages and the *contained fraction* column shows how many seeds were contained. |
| **SMS leaked before containment** | Sum of the attacker's leaked SMS over minutes before *m* (all leaked SMS if not contained). |
| **Steady-state leakage** | Mean leaked SMS per minute over minutes ≥ *m*; over the last 5 minutes if not contained. This replaces the earlier "sustained rate over the last 10 minutes", which straddled the containment point. |
| **Total leaked** | Sum over the 20-minute window. |
| **Defender cost** | Leaked SMS × SMS price + attacker-attributable HLR lookups × lookup price + attacker-attributable reCAPTCHA assessments × assessment price. Prices in `src/otp_guard/evaluation/calibration.py`. |
| **Friction: delivered %** | Legitimate requests that received a code on any channel, over legitimate requests. |
| **Friction: challenge rate %** | Legitimate requests that were shown an interactive challenge (90 % of simulated users then solve it). |
| **Friction: refusal rate %** | Legitimate requests refused by a hard step or downgraded with no channel. |
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
- **The confidence intervals cover seed-to-seed variation only**, not calibration error.

## Performance and timing-leak method

`scripts/load_test.py` runs against a real `redis-server` on the same 4-vCPU container.
Phase 1 drives the pipeline in process with 3 000 mixed requests (55 % sent, 15 % no
session, 15 % disallowed country, 15 % repeated number) and records per-step and
end-to-end latency percentiles, plus Redis round trips and commands per request from
`INFO commandstats`. Phase 2 serves the API with uvicorn (one process, sync handlers in
the default thread pool) and fires 800 requests at concurrency 16, once with the 400 ms
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

Measured with 4 workers and 6000 requests: with the floor, no pair of outcomes is
distinguishable by KS test (smallest p = 0.07) and every pair is equivalent within 2 ms by
TOST (largest p = 0.000, largest mean difference 0.32 ms); no request's pipeline time
exceeded the floor. Without the floor every pair is distinguishable. With one worker at
concurrency 32 the sent path reached about 650 ms of wall time through GIL contention while
its pipeline time stayed under 400 ms, and the floor did not hold: the floor must exceed the
deployment's wall-time p99 under load, which is a worker-count question. Capacity: 303
requests/s at concurrency 32 on 4 workers with faked vendors.

