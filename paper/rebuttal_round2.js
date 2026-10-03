// Response to the second-round Reviewer 2 report. Build: node rebuttal_round2.js -> rebuttal_round2.docx
const fs = require("fs");
const { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType,
        AlignmentType, BorderStyle, ShadingType, LevelFormat } = require("docx");

function runs(text) {
  const out = []; const re = /(\*\*[^*]+\*\*|_[^_]+_)/g; let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(new TextRun(text.slice(last, m.index)));
    const t = m[0];
    if (t.startsWith("**")) out.push(new TextRun({ text: t.slice(2, -2), bold: true }));
    else out.push(new TextRun({ text: t.slice(1, -1), italics: true }));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(new TextRun(text.slice(last)));
  return out;
}
const P = (text, opts = {}) => new Paragraph({ spacing: { after: 120 }, ...opts, children: runs(text) });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const Quote = (t) => new Paragraph({ indent: { left: 540 }, spacing: { after: 100 }, children: [new TextRun({ text: t, italics: true, color: "444444" })] });
const Bullet = (t) => new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 60 }, children: runs(t) });

// status: "Fixed", "Fixed and verified", "Partly addressed", "Not done"
function item(num, title, status, objection, response, where) {
  const ps = [H2(`${num}. ${title}`),
              new Paragraph({ spacing: { after: 80 }, children: [new TextRun({ text: "Status: ", bold: true }), new TextRun({ text: status, bold: true, color: status.startsWith("Not") ? "9C2B1E" : status.startsWith("Partly") ? "8A5A00" : "1E6B3A" })] }),
              Quote(objection)];
  for (const r of response) ps.push(P(r));
  if (where) ps.push(P(`_Where:_ ${where}`, { spacing: { after: 200 } }));
  return ps;
}

const border = { style: BorderStyle.SINGLE, size: 4, color: "BFBFBF" };
const borders = { top: border, bottom: border, left: border, right: border };
function table(widths, rows) {
  const total = widths.reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: total, type: WidthType.DXA }, columnWidths: widths,
    rows: rows.map((r, i) => new TableRow({ tableHeader: i === 0, children: r.map((c, j) => new TableCell({
      borders, width: { size: widths[j], type: WidthType.DXA },
      shading: i === 0 ? { fill: "E8EEF7", type: ShadingType.CLEAR } : undefined,
      margins: { top: 60, bottom: 60, left: 100, right: 100 },
      children: [new Paragraph({ children: i === 0 ? [new TextRun({ text: c, bold: true, size: 18 })] : runs(c).map(r => r) , spacing: { after: 0 } })] })) }))
  });
}

const children = [
  new Paragraph({ children: [new TextRun({ text: "Response to the second-round report of Reviewer 2", bold: true, size: 32 })], spacing: { after: 120 } }),
  P("**Manuscript:** From a Production OTP Flood to a Layered Defence: Measured Limits of Risk-Scored SMS Verification Against Residential Flooders and Colluding Carriers"),
  P("**Journal:** Computers & Security. **Reviewed artifact:** commit f457f31 (release 2.5.0) and manuscript revision 1. **Revised artifact:** release 2.6.0 on the same branch (commits 3fea11f and b28b69c for the code and evaluation; the manuscript commit that accompanies this letter). Section, table and figure numbers below refer to revision 2 unless marked otherwise."),

  H1("Summary"),
  P("We thank the reviewer for a second report that again read the code more closely than we had. The reviewer was right that revision 1 did not establish what it claimed: the offered workload still depended on the defence, cohort accounting could report more deliveries than dispatches, a synchronous sender could call back before the OTP state existed, callbacks were neither idempotent nor atomic, the verdict metric counted blocks rather than verdicts, and Table 8 printed horizon-filled times under a caption that promised conditional ones. We reproduced each of the reviewer's Appendix B counterexamples before repairing it."),
  P("We have not tried to answer this report with prose. The simulator, the callback state machine and the metrics were repaired first and now carry invariant checks that run on every simulation or in the test suite: an offered-trace hash that is identical across designs, cohort conservation, a clock that advances whatever the pipeline decides, a declared drain horizon with pending events reported, atomic receipt, verification and block-test transitions, and verdicts logged as events with their stage. Concurrency is now tested on a real redis-server across two pipeline instances, and the five properties those tests establish are listed in the paper, nothing more. Only then was the evaluation regenerated (7,543 runs) and the manuscript rewritten from the regenerated numbers. Every headline number resolves to a study, seed set, metric and JSON path in results/headline_numbers.md, and every figure is drawn by paper/figures.py from results/evaluation.json alone."),
  P("The comparison the reviewer said was missing is now the paper's central table (Table 8): nine sequential settings spanning thresholds and head starts, and a flat per-block counter with a refusing and a graded action, on the same seeds against the concentrated pumpers and against 24 hours of legitimate traffic at matched density. Its answer does not favour our detector, and we report it that way. The flat counter leaks less than every sequential setting against the human-like, never-verifying and challenge-buying carriers (14 to 88 messages, against 86 to 556), and against the instant verifier its five-a-day form matches them; on blocks receiving 144 legitimate sends a day it completes 2 to 17 % of legitimate registrations at 65 % conversion (3 to 21 % at 80 %), against 64 % (79 %) for the sequential settings. Among the sequential settings there is no free point: those that hold the human-like verifying carrier to 152 messages or fewer produce 151 to 407 false verdict events a day at 65 % conversion, and those under ten events a day leak 445 or more. The paper now presents the detector's memory as this measured frontier and the counter as its extreme point, not as an advance."),
  P("The manuscript was also shortened from about 12,000 to about 7,300 words (abstract to declarations, tables and captions included; just under 8,000 with the title and the reference list) without dropping any research question, experiment or attacker family. Correction history has been moved out of the text and into this letter, as the reviewer asked."),

  H1("What we could not do, or did only in part"),
  Bullet("**Independently sourced traffic or an independently specified benchmark (M18, Section 7).** We still have no production logs. Held-out scenario families, joint distribution shifts and heterogeneous legitimate populations were not run. The limitations now name the design-selection risk explicitly: profiles and defaults were refined against the same generator."),
  Bullet("**A comparison tuned to matched in-control average run length (M14, Section 5).** The grid spans thresholds ln 100, ln 1000 and ln 10000 and credits 0, 0.5, 1, 2 and unbounded, which by the reviewer's algebra spans threshold and head start, but it is nine cells, not the full 3 × 5 cross, and no setting was tuned to a matched run length. The refusing counter was run at 5 and 20 per block per day, not 10."),
  Bullet("**Windowed, exponentially weighted and time-uniform detectors (Section 5).** Not run. The paper no longer claims a necessary memory trade-off beyond the examined family."),
  Bullet("**The counter at sparser legitimate densities (M13).** The matched comparison is at 144 sends per block per day, where the counter costs most; sparser blocks were not run for the counter, and the paper says so."),
  Bullet("**Sensitivity to fallback availability and challenge success (M25).** Completion is now reported throughout, but the 70 % fallback and 90 % challenge completion were not swept."),
  Bullet("**The learned baseline job over days (M11).** Cold start, one and three closed hours and a poisoned learning period were run; multi-day poisoning, restarts and weekly drift were not."),
  Bullet("**Live vendors and App Attest enrolment (M28).** No live vendor call has been made, and validation of Apple's attestation object at enrolment is not implemented; both are stated in Section 6."),
  Bullet("**A supervised model, client puzzles, revocable or decaying trust exemptions (Section 5).** Not evaluated; listed as gaps, without claims of irrelevance."),
  Bullet("**Permission and affiliation (M29).** Written permission to describe the incident is still being sought, and the affiliation must be completed by the author before submission; the manuscript says the first and marks the second as a placeholder rather than a TODO."),
  Bullet("**Two residuals found while verifying the repairs.** (i) The trust builder's identity/number pairs are drawn with replacement, so about 1 % of pairs in the concentrated variant share a number; the paper states this. (ii) A negative receipt is applied as two atomic updates (mark failed, then resolve undelivered); by code reading, a positive receipt arriving between them could leave a send marked delivered but resolved undelivered until the user verifies. Neither changes a reported number; both are disclosed rather than claimed fixed."),

  H1("Section 2.A: defects that invalidated or weakened the evidence"),
  ...item("M1", "The offered workload was not identical across designs", "Fixed and verified",
    "Challenge retries drew from the workload generator; returning identities came from verified_fps; seed-0 traces diverged at request 36.",
    ["We reproduced the divergence. Every exogenous quantity of a request is now drawn from the workload stream when the request is created: arrival offset, identity and age, address, number, all CAPTCHA scores the session gate and any challenge retry will consume, latent verification outcome and delay, delivery delay and WhatsApp reachability. Returning requests reuse identities the trace itself offered earlier, not identities the defence verified; verified_fps no longer exists. Each result carries a hash of the offered trace, and tests/unit/test_simulator_invariants.py asserts that it is identical across designs and cap modes for the same seed.",
     "Beyond that test, we checked the hash for all 19 main-study and adaptive profiles against five feature configurations (including the empty feature set), oracle and learned baselines, cadences of 1, 10 and 60 minutes with phase offsets, the hard-deny action and the graded counter: one digest per seed in every case. The paired ablation (Figure 2) and the detector comparison (Table 8) are therefore paired on one trace, and the text says so only now that it is true."],
    "evaluation/sim.py make_attacker_ctx, make_legit_ctx, _digest; tests/unit/test_simulator_invariants.py. Manuscript Section 6 (Simulation), Figure 2 caption."),
  ...item("M2", "Warm-up outcomes contaminated the measurement cohort", "Fixed",
    "Queued events from warm-up incremented the current accumulator but an old subgroup; 407 dispatched, 409 delivered.",
    ["Each request is bound at creation to one immutable pair of accumulators (all users and its first-time or returning subgroup); warm-up requests go to discarded accumulators. Every run asserts at the end that subgroup totals equal the whole for users, dispatched, delivered, completed, challenged and refused, that completed ≤ delivered ≤ dispatched ≤ users, and that refusals equal the sum of their named stages. A run that violated conservation would now fail rather than print."],
    "evaluation/sim.py cohort binding and _check_cohorts; test_cohorts_reconcile_and_the_funnel_is_monotone. Manuscript Section 6."),
  ...item("M3", "Session-gate losses left the denominators", "Fixed",
    "A legitimate request refused at session acquisition was never counted as a user.",
    ["Users are counted when offered, before the session gate, and every loss is named by stage (gate, hard step, no channel, undelivered). Results carry an end-to-end funnel from offered to completed. All legitimate percentages in the paper are over offered requests, and the metrics paragraph of Section 6 says so."],
    "evaluation/sim.py handle_legit, _refuse; result funnel; test_gate_losses_are_in_the_denominator."),
  ...item("M4", "A rejected session stopped simulated time", "Fixed",
    "With every gate attempt failing, a nominal 30 minutes advanced 1,056.56 s.",
    ["Arrivals carry timestamps inside their minute; the clock advances to each arrival and to every minute boundary whatever the pipeline decides, including for empty minutes. The reviewer's stress case is now a regression test: with every CAPTCHA attempt failing, the clock still advances the nominal duration."],
    "evaluation/sim.py run, process_due_events; test_clock_advances_the_nominal_duration_whatever_the_gate_does."),
  ...item("M5", "Final outcomes were right-censored without a label", "Fixed",
    "The drain advanced only max(60, 4 × median entry delay).",
    ["Runs drain to a declared horizon, receipt grace plus resolution timeout plus 600 s for the slowest modelled entry, and report the events and timeouts still pending. Pending was zero in every recorded run. The 600 s allowance is a constant rather than a quantile of the entry-delay distribution; any run it did not cover would show non-zero pending."],
    "evaluation/sim.py drain; pending_at_end in every summary; test_run_drains_to_its_horizon."),
  ...item("M6", "The callback could run before the OTP state existed", "Fixed",
    "Step 11 called sender.enqueue before feedback.on_sent; a zero-delay sender dropped the receipt.",
    ["We reproduced it with the actual RoutingSender. Step 11 now writes the audit record, the reputation counters, the last-send and latest-OTP keys and the feedback entry before the sender is called. An immediate provider failure or a missing sender reports through the same callback and resolves the send as failed and undelivered. Both orderings are regression tests."],
    "pipeline.py step11_log_and_send; providers/senders.py RoutingSender.enqueue; test_synchronous_sender_callback_lands_on_registered_state, test_synchronous_provider_failure_is_classified. Manuscript Sections 4.1 and 6."),
  ...item("M7", "Delivery callbacks were not idempotent", "Fixed, with one residual stated",
    "Repeating a positive receipt 30 s later moved delivered_at by 30 s.",
    ["The receipt rules are now written at the top of feedback.py and summarised in Section 4.2: the first positive receipt fixes the delivery time and a repeated one changes nothing; a negative receipt after a positive one is recorded as a conflict and counted; a positive receipt after a failure reopens the send and restarts its resolution clock; a receipt after resolution is ignored; an expired send stays expired. The reviewer's 30-second test is a regression test, alongside duplicate, conflicting and out-of-order cases.",
     "Residual: a negative receipt is applied as two atomic updates (mark failed, then resolve undelivered). By code reading, a positive receipt landing between them could leave the send marked delivered with an undelivered resolution until the user verifies. We have not tested this interleaving and disclose it rather than claim it fixed."],
    "feedback.py on_delivery; tests/unit/test_second_round.py receipt tests."),
  ...item("M8", "Verification and block-state transitions were not atomic", "Fixed and tested on real Redis",
    "Two threads with copied reads gave verified = 2 for one message; CUSUM updates and resets could lose increments.",
    ["Receipt, verification, resolution and block-test transitions each run inside one store.update: a lock on the memory backend, which now returns copies on read as Redis does, and WATCH/MULTI/EXEC with retry on Redis. The block-event closure recomputes from fresh state on retry and resets on crossing inside the same transaction.",
     "tests/integration/test_real_redis.py runs two pipeline instances against a real redis-server (CI installs it) and establishes, on that backend only: the hourly ceiling holds under 24 concurrent sends split across instances; one number is claimed once under 16 concurrent requests; six concurrent verification callbacks per message count once across ten messages; 23 concurrent block events are all counted and issue exactly the expected verdicts and log entries; and eight writers × 50 compare-and-set updates give exactly 400. The two instances share in-process fake services and a clock; only the Redis-held state is under test, and the test's docstring now says so. Section 6 lists these five properties and claims nothing beyond them."],
    "store.py update (memory and Redis); feedback.py _finish, on_verified, _block_event; tests/integration/test_real_redis.py. Manuscript Section 6."),
  ...item("M9", "'Verdicts' counted distinct blocks", "Fixed",
    "VERDICT_LOG was keyed by block; a second verdict overwrote the first.",
    ["The verdict log has one member per event (block, stage, time, sequence). Results report verdict events, distinct blocks with a verdict, stage-1 and stage-2 events, legitimate requests hit by stage, those that never completed, and block-minutes under a verdict. Every table in the paper that reports verdicts names which of these it shows (Tables 7, 8 and 10)."],
    "feedback.py _issue_verdict, verdict_events; evaluation/sim.py result; test_verdict_log_records_every_event_with_its_stage."),
  ...item("M10", "The no-credit 24-hour experiment was not reproducible", "Fixed",
    "The study deciding the default varied calibration, density, conversion and autofill, not credit.",
    ["The reviewer was right that the advertised command did not produce those numbers. The comparison is now study F2 of the standard regeneration path (make results): the detector grid on the same seeds against the four concentrated pumpers and over 24 hours of legitimate traffic at 80 % and 65 % conversion, with events, blocks, requests hit, lost completions and completion. The numbers revision 1 quoted (103 to 139 verdicts, 700 to 870 users) are gone; the regenerated no-credit cell at 65 % is 150.6 events on 107.8 blocks, 778 requests hit and 327 never completed (Table 8), and results/headline_numbers.md gives its JSON path."],
    "scripts/run_evaluation.py; evaluation/runner.py DETECTOR_SETTINGS, study_detectors, study_detector_fp. Manuscript Table 8."),
  ...item("M11", "The production baseline and the evaluated baseline were different systems", "Partly addressed",
    "The oracle baseline was evaluated; the deployed job's fallback divided by 24 hours whatever the history.",
    ["The fallback now averages only the closed hours that were actually recorded and returns nothing on cold start, leaving the static cap in place (the reviewer's 1,200-per-hour case is a regression test: 20 per minute, not 0.833). The deployed job is now evaluated against the oracle (Table 6): with no closed hour it leaves the static cap (649 [346, 953] leaked); with one or three closed hours it matches the oracle (242 and 247 against 259); with three hours poisoned by an attack at the legitimate rate it is indistinguishable from the clean job at five seeds (206 [124, 287]). The main study still uses the oracle, and the paper says so in Section 6. Multi-day poisoning, restarts and weekly drift were not run."],
    "baseline.py expected; evaluation/runner.py study_baseline; test_baseline_job_cold_start_uses_only_recorded_hours. Manuscript Section 7.4, Table 6."),
  ...item("M12", "The cadence experiment did not establish the one-minute claim", "Fixed",
    "Only 1, 10 and 60 minutes, one alignment, one attack length.",
    ["The grid now covers 1, 2, 5, 10 and 60 minutes, ticks aligned with the attack start and offset by half a period, and a 60-minute attack for the hourly job (Table 6). Two-minute ticks ration almost as one-minute ones (285 and 286 leaked against 233); five- and ten-minute ticks ration or not depending on phase (398 or 546; 521 or 427); hourly ticks leave the static cap for a 20-minute attack in either phase and leak 88 to 94 % of a 60-minute one. The paper states this as the dependence at these settings and explicitly not as proof that only a one-minute controller works; Section 7.4 says that every two minutes rations nearly as the default does, and the conclusion that rationing works only with a fast controller that has history."],
    "evaluation/runner.py CADENCES, CADENCE_PHASES. Manuscript Section 7.4, Table 6."),

  H1("Section 2.B: scientific design and inference"),
  ...item("M13", "The simple counter was missing where the sequential detector was said to add value", "Fixed for one density",
    "Compare all methods on the same workloads at matched legitimate service.",
    ["Done, and the result changed the paper's claim. Table 8 and Figure 6 put the flat counter (5, 10 and 20 per block per day, refusing and graded) and nine sequential settings on the same seeds against the never-verifying and human-like carriers, and on the same 24-hour legitimate population. The counter leaks less than every sequential setting against the human-like, never-verifying and challenge-buying carriers (14 to 88 against 86 to 556); against the instant verifier only its five-a-day form matches the sequential tests (14 against 14 to 24). At 144 legitimate sends per block per day it completes 2 to 17 % of legitimate registrations at 65 % conversion (3 to 21 % at 80 %), against 64 % (79 %) for the sequential settings. The sentence 'the sequential tests earn their place only against carriers that verify' is deleted. The lessons now say that a five-a-day counter was the strongest destination limiter we ran and the costliest on busy blocks. Sparser densities were not run for the counter, and the paper says the comparison is at the density where the counter costs most."],
    "Manuscript Section 7.5, Table 8, Figure 6, Section 8."),
  ...item("M14", "The bounded-credit default is a reparameterised CUSUM", "Partly addressed",
    "S floored at −h is Y = S + h with threshold 2h and head start h; compare against an equivalently calibrated CUSUM.",
    ["We agree with the algebra and now state it in Section 4.3 and Section 2: a floor at c thresholds is a zero-floor CUSUM with threshold (1 + c)h and head start ch, so 'memory' is a threshold-and-head-start choice and not a new statistic. The detector grid treats it that way, with thresholds ln 100, ln 1000 and ln 10000 and credits 0, 0.5, 1, 2 and unbounded. The grid has nine cells, not the full cross, and no setting was tuned to a matched in-control run length; we list that as not done. What the grid shows is a frontier: no cell both holds the human-like carrier to 152 messages or fewer and keeps false verdicts under ten a day."],
    "Manuscript Sections 2, 4.3, 7.5, Table 8."),
  ...item("M15", "Three settings cannot establish 'no setting does both'", "Fixed",
    "Report a measured trade-off, not an impossibility.",
    ["The sentence is gone. The paper reports the frontier in the grid run, with its endpoints and the intermediate c = 0.5 cell (273 leaked, 20 events), and says 'no free point in the grid'. The 60 % carrier against a 65 % population is described as the hard case, not as a general operating region."],
    "Manuscript Sections 7.5 and 8."),
  ...item("M16", "Finite-horizon outcomes were turned into eventual detection", "Fixed",
    "Unbounded credit delays detection; a floor changes hitting times.",
    ["'Never caught' and 'ever caught' are removed. Section 4.3 says a hundred verified sends postpone a later flood's detection until about 143 failures; Section 5 says that above σ* a verdict within a finite window depends on the floor, the window and runs of failures, 'delayed, not excluded'. Results report the contained fraction and the conditional delay in the twenty-minute window, and long-run false verdicts separately from the 24-hour runs."],
    "Manuscript Sections 4.3, 5, 7.5."),
  ...item("M17", "Separability language outran the experiment", "Fixed",
    "'Only' asserts necessity; Table 7 had zero leakage at fresh-fingerprint weight 40.",
    ["Every 'only' about separation is now qualified 'in the settings run'. Section 7.3 says the three experiments show failure at the settings run, not that no setting separates, and reports the weight-40 point as separation at a price (zero leaked, 46 % challenged, 10 % refused) for a service to judge. Douceur is cited for client-side identity only. The contribution list no longer claims a separability result."],
    "Manuscript Sections 1, 7.3, 8."),
  ...item("M18", "Calibration uncertainty, selection and correlation", "Not done",
    "Hold out scenario families, test joint shifts, correlated failures, heterogeneous populations.",
    ["We have not done this and do not claim to. The limitations now say that several results follow from the generator (premium numbers in a perfect list, a datacenter attacker that declines challenges, a farm with human-like scores), that profiles and defaults were refined against the same generator, and that this is a design-selection risk we did not control. What the revision does vary is conversion and autofill (Table 9 and the 24-hour cells), carrier outage, controller cadence and learning history."],
    "Manuscript Section 8 (Limitations)."),
  ...item("M19", "The 24-hour block populations were not distinct", "Fixed",
    "The legitimate block list was sampled with replacement.",
    ["Legitimate blocks are sampled without replacement and the observed occupancy is reported: median 144 and 29 sends per block per day, maximum 181 and 49, in the two concentrated populations (Section 7.6)."],
    "evaluation/sim.py legit_blocks; test_legitimate_blocks_are_distinct_and_occupancy_is_reported."),
  ...item("M20", "Monte Carlo error bars and target quantity", "Fixed",
    "Report counts and binomial intervals; state initialisation; zero is not below 1/20,000.",
    ["Table 9 reports events over trials with 95 % Wilson intervals, states that the block starts from empty statistics and receives exactly 30 resolved sends, defines the quantity as the probability of at least one verdict in that sequence (one block's hazard per window, not the daily harm), and says a zero count bounds the probability below about 0.02 %, not at zero. The 24-hour paragraph says five seeds bound a mean, not rare cascades."],
    "evaluation/runner.py block_test_false_positives. Manuscript Section 7.6, Table 9."),
  ...item("M21", "The leakage equation was checked on realised inputs and means", "Fixed",
    "Report per-run residuals, relative errors and unsaturated cases; 'within 7' rounded 7.39 down; eighteen configurations, not nineteen.",
    ["Section 5 now calls Equation 2 a consistency check of the per-block mechanism on the blocks each run touched, not a forecast, and says that once kB exceeds N it only says everything leaks. Figure 5 has a residual panel per configuration. The text reports 18 configurations; mean absolute per-run error 1 to 9 messages (1 to 15 %) in the ten unsaturated ones with a largest single-run residual of 21; and in the eight saturated ones an average overstatement of 2.5 to 22 with single runs up to 92. 'Within 7' and 'within 19' are gone, and the paper says the estimate carries no per-run guarantee."],
    "scripts/run_evaluation.py spread residuals. Manuscript Section 7.5, Figure 5."),
  ...item("M22", "The trust-building attack did not isolate trust or block credit", "Fixed, with one residual stated",
    "No one-to-one identity/number pairs; preparation mixed with flood; no concentrated variant.",
    ["The trust builder now uses identity/number pairs and is reported by phase: with caps lifted it leaks 264 in preparation, all verified, and 250 of 281 flood requests; with caps on, 162 and 82. A concentrated variant puts the pairs' numbers in three blocks: its flood phase is held to 164 with caps lifted because the blocks it trained earn 28 verdict events, which isolates what the bounded floor does against banked credit. Residual: numbers are drawn with replacement, so about 1 % of the concentrated pool's pairs share a number; the limitations state it."],
    "evaluation/sim.py _trust_pool, phase accounting; runner trust_building_concentrated. Manuscript Section 7.7."),
  ...item("M23", "Poisoning harm was measured for one attack; grading does not cap harm at a challenge", "Fixed",
    "Test second-stage escalation, refresh and recovery; measure the hard-deny counterfactual.",
    ["Table 10 reports the poisoner with graded verdicts, with the 24-hour hard denylist, and with an attacker that stops after ten minutes of a thirty-minute run. Graded: 18.8 events (13.9 stage 1, 4.9 stage 2) on 13.9 blocks, 100 requests hit, 49 never completed. Hard deny: all 119 requests hit are lost. Recovery: 150 requests hit after the attacker stopped. The sentence 'the graded verdict keeps the harm at a challenge' is replaced by 'grading limits the harm but caps it neither at a challenge nor at the attack's duration'."],
    "evaluation/runner.py POISONER_VARIANTS. Manuscript Section 7.6, Table 10."),
  ...item("M24", "Receipt handling needed a defined state machine", "Partly addressed",
    "Delayed positive receipts, duplicates, conflicts, missing callbacks, late verification after a verdict.",
    ["The rules are defined (M7) and tested for duplicate, conflicting, out-of-order and late receipts, and for a late verification after a failure, which reclassifies the send on the counters while a verdict already issued stands until it expires (test_late_verification_after_failed_is_reclassified_but_a_verdict_stands). Section 4.2 says exactly this instead of 'late outcomes are reclassified'. We did not separately measure the residual harm of verdicts that late reclassification would have prevented."],
    "feedback.py rules header; tests/unit/test_second_round.py. Manuscript Section 4.2."),
  ...item("M25", "Security was not evaluated at matched completed verification", "Partly addressed",
    "Delivery is not completion; the friction index double-counts; fallback and challenge success drive the harm.",
    ["Completion (code entered) is now reported in Tables 4, 6, 7, 8 and 10 and Figures 1 and 6; the friction index is gone, and Figure 4 plots refusal and challenge on separate axes so no request is counted twice. The detector comparison is at the same legitimate population for every setting. The 70 % fallback and 90 % challenge completion were not swept; the limitations say so."],
    "Manuscript Section 7, Figure 4."),
  ...item("M26", "Economics and overhead were partial", "Partly addressed",
    "Retail revenue is not profit; the ceiling is not on all costs; capacity was measured without the floor and with instant vendors.",
    ["Economics are labelled scenario accounting in the text, not profit. Section 4.4 states that the ceiling bounds SMS count and configured spend units, not vendor, lookup or fallback costs. The load test now has a capacity phase with the 400 ms floor on and every fake vendor call blocking for a lognormal 50 ms: 68, 115 and 131 requests per second at concurrency 32, 64 and 128; at 128 the server saturates and 25 % of requests exceed the floor, while 99.9 % of happy-path requests are still sent. The timing sentence now reads 'a failure to detect a difference, not proof that timing carries no information'. Vendor failures and heavier latency tails were not run."],
    "scripts/load_test.py phase 3; results/performance.md. Manuscript Section 7.7."),
  ...item("M27", "Baseline and ablation labels did not isolate mechanisms", "Fixed",
    "Removing circuit_breaker left the hard ceiling in place.",
    ["The hard ceiling now belongs to the circuit_breaker flag, so the ablation removes Step 10 and the ceiling together; it still changes no row, and the text gives the reason (no twenty-minute attack reaches the hourly budget). Conversion-only and speed-only are described as component variants of v2, not independent detectors. Table 2 places the budget reservation in Step 11, where the code makes it, and the design text no longer calls Steps 0 to 5 'local'."],
    "pipeline.py reserve_budget; test_circuit_breaker_off_removes_the_hard_ceiling_too. Manuscript Sections 4.1, 6, 7.2."),
  ...item("M28", "Integration completeness and test evidence were overstated", "Fixed in the text",
    "No live vendor test; App Attest enrolment delegated; the 'Redis' fixture was fakeredis.",
    ["Section 6 now says which properties were tested on a real Redis (the five listed under M8) and that the rest of the suite runs on memory and fakeredis stores; that App Attest assertions are verified against enrolled keys while enrolment is not implemented; and that no live vendor call has been made. The test count (273) is no longer offered as evidence of coverage."],
    "Manuscript Section 6."),
  ...item("M29", "The incident is motivation, not a result", "Fixed in the text; permission pending",
    "Do not let the title carry evidential weight; settle permission, affiliation and authorship.",
    ["Section 3 opens with 'This section is motivation, not evidence', followed by what we do not have. The contribution list calls it an operator's account. 'One of us' is gone; the CRediT statement names the single author without a TODO. The affiliation is marked as a placeholder to be completed before submission, and permission is still being sought, which the paper says. We have kept the title, which names where the work started rather than claiming a case study; if the editor prefers, we would retitle it 'From an OTP Flood to a Layered Defence: Measured Limits of Risk-Scored SMS Verification Against Residential Flooders and Colluding Carriers'."],
    "Manuscript Section 3, front matter, declarations."),
  ...item("M30", "Table 8 reported the wrong containment statistic", "Fixed",
    "18.8 and 10.3 were horizon-filled; the conditional means were 14.0 and 9.22.",
    ["Every containment time in the paper is now the mean over contained seeds, printed next to 'contained k/10' and with its interval, and no time is printed where no seed was contained. The horizon-filled mean is kept in the JSON under its own name. In the regenerated Table 7 the no-credit setting is contained in 7 of 10 seeds at 6.1 [3.6, 8.7] minutes, and the default is contained in none, so no time is shown. The generated results table no longer says 'steady state'."],
    "evaluation/runner.py summarise. Manuscript Table 7."),

  H1("Section 3: the sentences that exceeded the evidence"),
  table([900, 3900, 4300], [
    ["Item", "Revision 1", "Revision 2"],
    ["Q1", "Same seed, same traffic.", "True and tested: the trace hash is asserted identical across designs (Section 6)."],
    ["Q2", "Callbacks are idempotent.", "Transitions are atomic read-modify-writes; receipt rules stated; five properties tested on real Redis (Sections 4.2, 6)."],
    ["Q3", "Pipeline running as deployed.", "'Executes the pipeline inside a simulated environment' with the substitutions enumerated (Section 6)."],
    ["Q4", "Trust from things the client cannot set.", "'Evidence the client cannot forge; such evidence can still be manufactured' (Section 4)."],
    ["Q5", "Never caught after 143 failures.", "'Postpone a later flood's detection until about 143 failures' (Section 4.3)."],
    ["Q6", "A hundred false verdicts a day per block.", "Replaced by measured population figures: events, blocks, requests hit (Table 8)."],
    ["Q7", "Sequential tests earn their place.", "Deleted; the matched comparison shows the five-a-day counter leaks least and completes least (Section 7.5)."],
    ["Q8", "Separates only on dominated keys.", "'In the settings run … only where its sends dominated the key' (Section 7.3)."],
    ["Q9", "Hourly controller does not see the attack.", "Both phases and a 60-minute attack measured; 'leaves the static cap for a 20-minute attack in either phase' (Section 7.4)."],
    ["Q10", "No setting does both.", "'No free point in the grid' (Sections 7.5, 8)."],
    ["Q11", "Outage false positives removed.", "'Receipts reduce the effect, they do not remove it' with event counts (Section 7.6)."],
    ["Q12", "One response time tells nothing.", "'A failure to detect a difference, not proof that timing carries no information' (Section 7.7)."],
    ["Q13", "No measured cost; nineteen configurations.", "Completion within five points of no attack, refusals stated; eighteen configurations (Sections 7.1, 7.5, 9)."],
    ["Q14", "Only containment is the cap; one-minute only.", "Weight-40 separation reported; 'at a cost a service would accept'; two-minute ticks reported as nearly equivalent (Sections 7.3, 7.4, 9)."],
    ["Q15", "Each verified code is an account.", "'We count verifications, not accounts' (Section 5)."],
    ["Q16", "Figure script in paper/.", "paper/figures.py draws all six figures from results/evaluation.json; the older script is removed (Artifact section)."],
    ["Q17", "Grading keeps harm at a challenge.", "'Caps it neither at a challenge nor at the attack's duration', hard deny measured (Section 7.6)."],
    ["Q18", "The floor decides whether a block is ever caught.", "'Delayed, not excluded' (Section 5)."],
    ["Q19", "Every defect fixed (response letter).", "This letter separates fixed, partly addressed and not done for every item."],
    ["Q20", "Conditional time in the caption.", "Conditional means with contained counts (Table 7)."],
  ]),
  P(""),

  H1("Section 4: numerical contradictions"),
  P("Each listed contradiction was resolved from the regenerated results. The configuration count is 18 everywhere. The per-block 'hundred verdicts' and the unreproducible 103 to 139 range are replaced by Table 8. 'Removed' outage false positives became 'reduced', with event counts. 'No measured cost' became completion within five points of the no-attack rate, with the first-time refusal rates that are above it (3 % and 7 %). 'Only a cap contains' is qualified by the weight-40 point. 'Within 7' is replaced by per-run residuals with a defined sign. The cohort accounting that produced 409 deliveries from 407 dispatches is now asserted impossible at the end of every run. Where the same attacker appears in different studies (the farm at 236 in the 30-seed main study, 233 in the 10-seed cadence grid, 259 in the 5-seed baseline study), each table states its seed set. The Monte Carlo prints counts and Wilson intervals. The test count is reported with the properties it does and does not establish."),

  H1("Section 5: related work and competing approaches"),
  Bullet("**Huh et al.** Section 2 now states the concrete empirical question this paper answers beside theirs: for the feature family they found strongest, outcomes per destination key, where an explicit detector separates, what it costs legitimate users, how its memory trades evasion against false verdicts, and how it compares with a flat destination limiter at the same legitimate service. A supervised model trained on our generator was not built."),
  Bullet("**Commercial destination risk scoring.** Twilio's score is described with its inputs (carrier, traffic pattern, conversion), which are the inputs of our block tests, and its graded guidance; the paper states that graded destination action is established practice and that our contribution is the measured behaviour of one explicit detector, which a deployment could combine with the commercial score in Step 7."),
  Bullet("**Conventional CUSUM design.** The equivalence is explicit (Section 4.3) and the grid spans thresholds and head starts. Matched run-length tuning was not done."),
  Bullet("**Windowed and time-uniform alternatives.** Not run; the paper no longer claims a memory trade-off beyond the examined family, and the 'no change-detection alternative' sentence is gone."),
  Bullet("**Simple destination admission policies.** Run: the counter with a refusing action and with the graded action the verdicts use (challenge, then non-SMS, first-time clients only), which is the reviewer's 'per-block challenge threshold followed by a quota'. Matching the actions means the comparison does not attribute a policy difference to the statistic."),
  Bullet("**Economic friction.** Client puzzles are listed as unevaluated, with the reviewer's point that they raise the marginal cost of a request even when the attacker earns from SMS; the earlier argument for their irrelevance is removed."),
  Bullet("**Identity and receipt trust.** Revocable or decaying exemptions and receipt-robust policies were not compared. The trust builder (M22) and the receipt faker quantify the exposure that motivates them."),

  H1("Section 6: presentation, figures and tables"),
  Bullet("**Structure.** Review narration ('whose story changed under review', the old sweep, the missing cadence) is removed from the text and kept here. Results are organised by research question, and the detector comparison is a central table (Table 8)."),
  Bullet("**Title and highlights.** Highlights use 'simulated' and avoid universal 'contained'; all five are within 85 characters. On the title, see M29."),
  Bullet("**Figure 1.** Now three panels: leakage with caps lifted, leakage with caps on, and legitimate completion with caps on, with intervals; the caption says spread in leakage is mostly the per-seed attack size."),
  Bullet("**Figure 2.** Short numbered layer labels (L0 to L10, FB), a diverging scale centred at zero, unlabelled cells within ±5, the attestation bucket effect stated in the caption, and the identical-trace claim restored only because it is now tested."),
  Bullet("**Figure 3.** A separate harm panel on its own scale; the caption states that the leaked share is the ratio of mean leaked to mean offered; no universal boundary is drawn."),
  Bullet("**Figure 4.** The friction index is replaced by refusal and challenge on separate axes; the default point is identified in the caption with its coordinates; seed count stated."),
  Bullet("**Figure 5.** Residual panels per configuration with the sign defined; configuration identities kept by colour."),
  Bullet("**Figure 6 (new).** The detector comparison as points, leakage against legitimate completion."),
  Bullet("All figures are drawn by paper/figures.py from results/evaluation.json, with larger fonts and titles moved to the captions."),
  Bullet("**Table 2.** Budget reservation placed in Step 11; Step 10 is the operating mode."),
  Bullet("**Table 4 (old Table 5).** Uniform columns, completion added, the non-shown designs stated in the caption; intervals in Figure 1."),
  Bullet("**Old Table 6 (paired ablation).** Replaced by a statement of all ninety cells: 73 unchanged, seventeen with paired intervals in the supplementary results, all excluding zero except the residential bot's two."),
  Bullet("**Table 5 (old Table 7).** The full tested grid is in the caption, the denominator is all users, and the rule for rows not shown is stated."),
  Bullet("**Table 7 (old Table 8).** Separate columns for contained seeds and conditional minutes with intervals; 'codes entered' instead of 'fake accounts'; verdict events and distinct blocks named; legitimate completion stated. The counter and the conversion-only and speed-only controls are in Table 8 and Table 4."),
  Bullet("**Old Table 9 (spread).** Replaced by the residual panels of Figure 5 and per-run statistics in the text."),
  Bullet("**Table 9 (old Table 10).** Counts, Wilson intervals, initialisation and the meaning of zero."),
  Bullet("**Submission readiness.** No TODO remains; 'one of us' is gone; the reference access date is corrected to 1 October 2026; the generative-AI declaration no longer asserts that every number was verified, but says what the author checked."),

  H1("Section 7: the single question"),
  Quote("After repairing the simulator and callback state machine, can you show, on one immutable offered workload and an independently specified set of scenarios, that the destination sequential detector provides a reproducible security–service advantage over a tuned simple destination limiter and an equivalently calibrated conventional CUSUM, at the same legitimate completed-verification rate, including concentrated verifying carriers and earned-trust attackers?"),
  P("Our answer, which the revised paper states, is no, and the paper no longer claims it. On one immutable offered workload and one legitimate population, the flat destination limiter has the better security against every carrier we ran except the instant verifier, where only its five-a-day form matches the sequential tests, and the sequential detector has the better service on busy blocks: 64 % completion against 2 to 17 % at 65 % conversion. Neither dominates. Against conventional CUSUM settings, the default is itself a CUSUM with a larger threshold and a head start, and within the grid no setting both catches the human-like verifying carrier and keeps false verdicts under ten a day. The receipt-faking carrier and the spread trust builder defeat the sequential tests and are bounded only by the caps and the budget; the concentrated trust builder is slowed by them, not stopped (164 leaked in its flood phase). The scenarios are not independently specified, and the settings were not tuned to a matched run length."),
  P("What the paper now offers is therefore not a better detector but a measured account, on a repaired and checked simulator, of where one explicit destination-keyed detector sits relative to the simplest alternative, what its memory setting trades, what it costs the people in the blocks it judges, and how it is defeated. We think that account is useful to practitioners who are deploying exactly this kind of control with commercial scores whose behaviour is not published, and we leave the editor to judge whether it meets the journal's bar."),

  H1("Appendix A of the report: disposition of the original objections"),
  P("Of the items the reviewer marked open or partial: B19 (workload) and B20 (containment censoring) are closed by M1 and M30; B22 (event time) by M4 and M5; A4, A5 and A11 (delivery, denominators, gate losses) by M2 and M3; A7 and A8 (cadence and baseline job) are partly closed by M11 and M12; B12, B14, B15, B16 and B21 are closed in the text by M16, M17, M20 and M21; B13 and C26 are addressed by the matched comparison (M10, M13, M14), with the run-length tuning not done; B18 remains partly open (five seeds for the 24-hour cells); B23 is closed for legitimate blocks (M19); C24 and C38 remain open (M18); C28 is addressed by M22; C30 and C32 by M7, M8 and M24; C31 and C34 to C35 by M26; C33 and C37 by M23 and M25 in part; C29 by Q4; C25 and C39 by M29."),

  H1("Appendix B of the report: the independent checks"),
  table([2400, 6700], [
    ["Reviewer's check", "Status in release 2.6.0"],
    ["Identical workload", "Trace hash identical across designs and cap modes (test); we also confirmed one digest per seed for the 19 main-study and adaptive profiles under five feature configurations and the baseline, cadence and action variants."],
    ["Cohort conservation", "Asserted at the end of every run; the funnel is monotone by construction and by test."],
    ["Receipt idempotence", "Repeated positive receipt 30 s later leaves the delivery time unchanged (test)."],
    ["Concurrent verification", "Six concurrent callbacks per message across two instances count once on a real redis-server (integration test)."],
    ["Immediate sender callback", "The receipt lands on registered state; an immediate provider failure resolves as failed and undelivered (tests)."],
    ["Verdict counting", "Ten failures on one block log two events with their stages (test)."],
    ["Simulator clock", "With every gate attempt failing, the clock still advances the nominal duration (test)."],
    ["Baseline cold start", "1,200 in one closed hour gives 20 per minute; no closed hour leaves the static cap (test)."],
    ["Existing regression checks", "273 tests pass, including the five real-Redis integration tests; the paper lists what the integration tests establish and no more."],
  ]),
  P(""),
  P("We are grateful for the time this report took. It changed the paper's central claim for the better."),
];

const doc = new Document({
  styles: { default: { document: { run: { font: "Calibri", size: 22 } } },
            paragraphStyles: [
              { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 28, bold: true, color: "1F3864" }, paragraph: { spacing: { before: 360, after: 120 }, outlineLevel: 0 } },
              { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 23, bold: true, color: "2E5496" }, paragraph: { spacing: { before: 240, after: 60 }, outlineLevel: 1 } }] },
  numbering: { config: [{ reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } }] }] },
  sections: [{ properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1250, bottom: 1250, left: 1300, right: 1300 } } }, children }]
});

Packer.toBuffer(doc).then(buf => { fs.writeFileSync("rebuttal_round2.docx", buf); console.log("wrote rebuttal_round2.docx"); });
