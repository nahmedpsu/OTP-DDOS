// Response to the third-round Reviewer 2 report. Build: node rebuttal_round3.js -> rebuttal_round3.docx
const fs = require("fs");
const { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType,
        AlignmentType, BorderStyle, ShadingType, LevelFormat, Footer, PageNumber } = require("docx");

function runs(text, size) {
  const out = []; const re = /(\*\*[^*]+\*\*|_[^_]+_)/g; let last = 0, m;
  const T = (o) => new TextRun(size ? { ...o, size } : o);
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(T({ text: text.slice(last, m.index) }));
    const t = m[0];
    if (t.startsWith("**")) out.push(T({ text: t.slice(2, -2), bold: true }));
    else out.push(T({ text: t.slice(1, -1), italics: true }));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(T({ text: text.slice(last) }));
  return out;
}
const P = (text, opts = {}) => new Paragraph({ spacing: { after: 120 }, ...opts, children: runs(text) });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const Quote = (t) => new Paragraph({ indent: { left: 540 }, spacing: { after: 100 }, children: [new TextRun({ text: t, italics: true, color: "444444" })] });
const Bullet = (t) => new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 60 }, children: runs(t) });

// status: "Fixed ...", "Partly ...", "Not done"
function item(num, title, status, objection, response, where) {
  const color = status.startsWith("Not") ? "9C2B1E" : status.startsWith("Partly") ? "8A5A00" : "1E6B3A";
  const ps = [H2(`${num}. ${title}`),
              new Paragraph({ spacing: { after: 80 }, children: [new TextRun({ text: "Status: ", bold: true }), new TextRun({ text: status, bold: true, color })] }),
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
      children: [new Paragraph({ spacing: { after: 0 }, children: i === 0 ? [new TextRun({ text: c, bold: true, size: 18 })] : runs(c, 18) })] })) }))
  });
}

const children = [
  new Paragraph({ children: [new TextRun({ text: "Response to the third-round report of Reviewer 2", bold: true, size: 32 })], spacing: { after: 120 } }),
  P("**Manuscript:** From a Production OTP Flood to a Layered Defence: Measured Limits of Risk-Scored SMS Verification Against Residential Flooders and Colluding Carriers"),
  P("**Journal:** Computers & Security. **Reviewed:** manuscript revision 2 and release 2.6.0 (commit b28b69c). **Revised:** manuscript revision 3 and release 2.7.0 on the same branch: the predeclared protocol (0038946), the implementation repairs (40a2d25), the pairing repair (ce90ad9), the full rerun of 9,759 runs (cba5d96), documentation (732e430), and the manuscript commit that accompanies this letter. Section, table and figure numbers refer to revision 3 unless marked otherwise."),

  H1("Summary"),
  P("We thank the reviewer for a third report that again found what we had missed. The most serious finding was right and was ours to catch: release 2.6.0 drew each simulated user's WhatsApp reachability, hashed it, and never registered it with the channel selector, so every downgraded user was refused. Revision 2's service figures for the graded counter (2 to 17 % completion) were therefore wrong, and so was the comparison built on them. The reviewer was also right that verdict exposure mixed the observation window with the drain, that graded escalation was not atomic, that the counter charged attempts rather than sends, that the comparison changed more than the detector and was not matched for service, and that 'hit and never completed' is descriptive, not causal. We confirmed R1 and R4 by running release 2.6.0 beside the repaired code, and R2 and R3 by test."),
  P("We then did what the report asked for in its closing section, in this order. First, the implementation repairs (fallback wired and tested at 0, 70 and 100 % reachability; three verdict estimands; graded escalation decided inside the block document's atomic write; the counter reserved per SMS send at Step 11; attributable loss per request on the same offered trace). Second, before any rerun, we committed a protocol (config/evaluation_protocol.json, commit 0038946; its SHA-256 is recorded in results/evaluation.json) that fixes a matched comparison on a common pipeline, with tuning and evaluation seeds, a service target, a selection rule and false-alarm matching, and a robustness study with a held-out scenario family, a joint parameter shift and five claims with pass thresholds. Third, the full evaluation was rerun and the manuscript rewritten from it."),
  P("The predeclared robustness study caught a defect of its own. In the first run, claim C1 failed in 32 of 108 cells, all on its service clause and none on leakage: the simulator drew legitimate and attacker requests from one random stream, so an attack run and the no-attack run at the same seed offered different legitimate users, and the paired clause compared unpaired samples. We fixed the pairing (ce90ad9), left the protocol unchanged, and reran every study; all five claims now hold (C1 108/108, C2 34/36, C3 36/36, C4 18/18, C5 36/36). That repair came after seeing a failed claim, which is a forking path. We disclose it in Section 6 of the paper and keep the first run in results/robustness_first_run.md. The matched comparison did not depend on it: the first run selected the same settings at all three densities, and the short-window counter leaked the same 24/24/24/48 messages, at 0.07 % attributable loss (0.06 % in the rerun)."),
  P("**The answer to the single question changed the paper.** On a common pipeline, at a predeclared service target, a tuned short-window counter of SMS sends per destination block beat the sequential detector in total leakage at every density, and against each pumper except one. At 200 busy blocks, four sends per block per ten minutes leaked 24 messages against the never-verifying, instant and human-like carriers and 48 against the challenge buyer, at an attributable completion loss of 0.06 % of users (0.07 % at 80 % conversion). The default sequential setting leaked 89, 17, 405 and 104, so it did better only against the instant verifier, which its speed test catches. The best sequential setting at the service target leaked 118 against the human-like carrier only by raising 314 false verdict events a day. The selected short-window counters at the other two densities leaked 6 to 18 at 0.15 to 0.35 % (up to 0.43 % at 80 %). Section 7.6 and the conclusion now say this plainly, with that exception, and the abstract reports the counter's leakage and cost: counting the destination did better overall than testing its outcomes. This is a negative result for our detector, and we report it that way."),
  P("**Manuscript.** Revision 3 is rewritten from the 2.7.0 numbers, with the scope unchanged: the same research questions, designs, attacker families and studies. The first-page highlights are removed, as the author asked. Elsevier collects highlights as a separate file at submission. The paper is 7,953 words from the title to the end of the reference list, counting tables, captions and declarations (alphanumeric tokens in the compiled PDF with figures replaced by placeholders). It compiles without overfull boxes. Every number was rechecked against results/evaluation.json and results/performance.json in a separate audit pass."),

  H1("What we could not do, or did only in part"),
  Bullet("**Independent traffic (R10).** We still have no production or third-party traces. The held-out family and the joint shift were fixed before the runs, but the generator is still ours, and Section 8 says so."),
  Bullet("**A forking path in the robustness study.** The pairing repair followed the first run's failure of C1. The claims, thresholds, points and seeds did not change; the first run is published."),
  Bullet("**The counter against harder pumpers.** The winning short-window counter was not run against spread pumpers, 60-minute attacks, the threshold-aware carrier, the receipt faker or the trust builders, and only the graded daily counter was run at 0 and 100 % reachability. By construction, its allowance grows with the blocks touched and the windows elapsed: four per ten minutes allows 72 messages an hour on three blocks, and twice that for a pumper that buys challenges. Sections 7.6, 7.8 and 8 state these limits."),
  Bullet("**Attributable loss in the matched comparison** was measured on legitimate-only runs, because attack runs do not record per-request outcomes. It is the false-alarm cost, not the cost during an attack. The poisoner study measures the cost during an attack, against an observe-only counterfactual."),
  Bullet("**Two state-machine interleavings remain open (R7, R8).** While verifying the repairs we found two. (i) The timeout worker removes the scheduled timeout after its compare-and-set, in a separate call; a correcting receipt that lands between the two reopens the send, and its re-added timeout is then deleted, so the send never resolves. (ii) Undo effects are idempotent but not order-independent: a late verification or correcting receipt that races a failure can leave a block's failure count one too high, and the statistic keeps +1.50 when the credit is zero. The single-threaded simulator exercises neither, so no reported number changes. Section 6 names both, and the changelog now does too."),
  Bullet("**Step 11 is not one transaction.** The reservations are atomic; the audit record, reputation 'sent' counts, last-send and latest-OTP keys, the feedback entry and the enqueue are separate writes. A crash between them leaks reserved slots or resolves the send as undelivered, and 'sent' counts are not exactly-once. Section 6 says this."),
  Bullet("**Simulation modelling residuals.** WhatsApp reachability is drawn per request, not per number, so a returning user's number can flip between requests. The returning population has a stable fingerprint and a trusted number but no fingerprint verification history (we corrected the simulator docstring and docs/evaluation.md, which had said otherwise). Both are in the limitations."),
  Bullet("**Live integration (R18).** No live vendor was called. The App Attest enrolment endpoint follows Apple's published steps but is tested only against synthetic certificate chains; the HTTP endpoint itself has no test. Network partitions and vendor retries were not tested."),
  Bullet("**Provenance detail.** 322 of the 9,759 runs were resumed from a checkpoint keyed by specification hash, without a code-version guard. Only documentation commits fall between the interrupted and resumed runs, so we believe this is benign, but the artifacts cannot prove it."),
  Bullet("**Not evaluated.** Windowed, exponentially weighted and time-uniform sequential statistics; a supervised model; client puzzles; long-term drift of the learned baseline beyond a three-week profile."),
  Bullet("**Author actions before submission (R19).** Written permission to describe the incident, the affiliation, and confirmation of Table 1's new Source column (below). The title is kept at the author's choice; an alternative is offered under R19."),

  H1("Section 2: methodological weaknesses"),
  ...item("R1", "The advertised fallback population did not exist in the executed simulation", "Fixed and verified",
    "make_legit_ctx draws whatsapp … nothing in this simulator transfers that value to h.svc.channels.whatsapp_numbers.",
    ["Confirmed and repaired. The regression entered in 2.6.0, when the workload was made immutable. sim.py now registers each legitimate number with the channel registry, or removes it, according to its pre-drawn reachability before the request is processed, and always removes attacker numbers. The test test_fallback_availability_reaches_the_channel_selector asserts WhatsApp dispatches, no-channel losses and the order of completion at 0, 70 and 100 %. In a verification run of our own (30 minutes, 20 blocks, the graded five-per-day counter; not part of the artifact), release 2.6.0 completed 24.8 % at every reachability and release 2.7.0 completes 34.4, 63.8 and 77.3 %.",
     "Every downgrade-, trust-, poisoning- and budget-sensitive study was rerun, together with all the others. The paper reports the dependence directly. The graded daily counter of 20 completes 27.45, 52.81 and 63.52 % at 0, 70 and 100 % reachability, against 64.23 % for the sequential default at each (Section 7.6). The poisoner's attributable loss is 6.26, 2.80 and 1.56 % of users at 0, 70 and 100 % (Table 9). Revision 2's service range for the counter is gone from every part of the paper."],
    "evaluation/sim.py _register_channels; tests/unit/test_simulator_invariants.py; results section H4. Manuscript Sections 6 (Simulation), 7.6, 7.7 and Table 9."),
  ...item("R2", "Verdict counts and exposure mixed the observation window with the drain", "Fixed",
    "Exposure clips the end of each interval to t_end while retaining a start after t_end. That produces negative durations.",
    ["The simulator now reports three estimands, labelled separately: verdict incidence (events with w0 ≤ t < w1); exposure (per block, the union of active intervals intersected with the window, including verdicts issued before it, kept only when positive); and eventual events including the drain. A recursive scan of results/evaluation.json finds 5,920 exposure values and none negative. The test test_verdict_estimands_are_bounded_by_the_window covers the reviewer's one-minute case. The paper uses window incidence ('verdict events inside the window', Section 6) and reports time to first verdict separately (Table 7)."],
    "evaluation/sim.py _verdict_estimands. Manuscript Section 6 (Designs and metrics), Tables 7 to 9."),
  ...item("R3", "Graded verdict escalation remained non-atomic", "Fixed and tested on real Redis",
    "Two workers can both read no existing verdict and both write stage 1.",
    ["The verdict and its stage now live in the block's own document, and the decision (stage 2 if a verdict is active, else stage 1) is made inside the same store.update as the threshold crossing: a lock on the memory backend, WATCH/MULTI/EXEC on Redis. With the reviewer's barrier after the reads, two simultaneous crossings give stages [1, 2]. In our verification so did 200 repeated trials of ten threads and 30 trials across two pipeline instances on a real redis-server; the committed tests run one trial of each (tests/unit/test_third_round.py and test_graded_escalation_across_instances, which uses the default graded action, not the deny action)."],
    "feedback.py _block_event; tests/integration/test_real_redis.py. Manuscript Sections 4.3 and 6."),
  ...item("R4", "The counter was described as counting sends but charged attempts", "Fixed",
    "Two offered requests have advanced the counter three times.",
    ["Step 5 now only reads the count. Step 11 reserves a slot atomically when, and only when, an SMS is about to be sent, and releases it on a no-channel or budget refusal. The reviewer's diagnostic (limit one, graded) now gives: request 1 sends, counter 1; request 2 is challenged, counter stays 1; the retry with a valid proof sends at stage 1, counter 2. The test is test_graded_counter_charges_sends_not_attempts, with refusing, refilling-window, release and concurrency cases. The units and retry treatment are stated in Section 4.3 ('The counter comparator')."],
    "pipeline.py reserve_block_count. Manuscript Section 4.3."),
  ...item("R5", "Matching offered traffic did not match legitimate service", "Fixed by a predeclared experiment",
    "Add a predeclared service target and tune on separate data … across multiple densities.",
    ["Done, as specified in the committed protocol. Every destination policy family (sequential tests on the full 5 × 5 threshold-by-credit grid; graded daily counters of 5 to 160; graded short-window refilling counters of 1, 2 and 4 per ten minutes and 3, 6 and 12 per hour; refusing daily counters of 20, 80 and 320) was run on tuning seeds 100 to 102: the full sequential grid at 200 blocks, and at the other densities the counters, the default and no policy. Within each family and density, the setting with the lowest leakage summed over the four pumpers was selected among those whose completion was at least the default's minus 0.5 points. The selection was then evaluated on seeds 0 to 9, which it never saw. Three densities were run: 144, 29 and about 4 legitimate sends per block per day. Re-running the selection on the stored tuning runs reproduces the recorded choices.",
     "The result is in Table 8 and Figure 6, and summarised in our answer to the single question. The sentence promising 'the same legitimate service' is gone. The paper says 'at a matched service target' and defines the target in Section 6. Service differences are reported as attributable loss with paired intervals, not as equality."],
    "config/evaluation_protocol.json; evaluation/runner.py matched_settings, select_matched, study_matched_tuning, study_matched_eval. Manuscript Sections 6 and 7.6, Table 8, Figure 6."),
  ...item("R6", "The detector comparison changed more than the detector", "Fixed",
    "Add a common-pipeline experiment in which only destination admission/detection changes.",
    ["Every row of the matched comparison runs the full feature set with caps lifted. Counter rows turn the block tests off and add only the counter; 'none' has neither. One residual dependence remains: the block's conversion still enters the risk score as one of the request's keys in every row, including 'none', so attributable loss isolates the verdict or counter action, not every use of the block key. Section 6 says this. The revision-2 system comparison has been removed."],
    "Manuscript Section 6 (Predeclared protocol), Table 8."),
  ...item("R7", "The acknowledged receipt race was a real semantic failure", "Partly fixed; one new race disclosed",
    "Negative receipt marks delivery failed; positive receipt arrives; negative path then resolves undelivered.",
    ["The reviewer's interleaving is fixed. A negative receipt now sets delivery failed and resolution undelivered in one compare-and-set. A later positive receipt reopens the send while its code is valid: delivered, unresolved, the undelivered count reversed and a new resolution timeout scheduled. If the code has expired, the send stays expired. Re-running the reviewer's sequence ends delivered and unresolved with undelivered 0. Tests cover the timeout worker and a correcting receipt in either order.",
     "Residual: the timeout worker removes the scheduled timeout after its compare-and-set, in a separate call. A correcting receipt landing between the two re-adds a timeout that the worker then deletes, so the send never resolves and a delivered, unentered code is lost as evidence. The same interleaving under the receipt-robust policy leaves one spurious block failure. The simulator is single-threaded and does not exercise either, so no reported number is affected. Section 6 names the race. The changelog no longer says the timeout decision is entirely inside one compare-and-set."],
    "feedback.py on_delivery, run_due_timeouts. Manuscript Section 6 (Implementation), Section 8 (Limitations)."),
  ...item("R8", "Atomic state claims were broader than the implemented transaction boundaries", "Partly fixed; claims narrowed to what holds",
    "Either narrow the implementation claims to the tested guarantees or add an idempotent, recoverable event/outbox scheme and crash-injection tests.",
    ["We did both, as far as they go. Each compound transition writes a write-ahead intent and then records its effect batch in the same compare-and-set as the state change. Effects are applied idempotently (reputation increments carry a per-send marker; block events carry ids). A recovery sweep replays pending batches older than 30 s. Crash-injection tests stop the process part-way through a transition's effects (on both the verification and the failure path), between the audit record and the enqueue, and across instances on a real Redis; each completes exactly once.",
     "What does not hold, and is now stated: Step 11 remains a sequence of separate writes. Its reservations are atomic, but a crash leaks reserved slots or resolves the send as undelivered, and 'sent' reputation counts are not exactly-once. Undo effects are not order-independent (see 'What we could not do'). The replay memory per block holds 256 event ids, increments land in the hour bucket current at apply time, and effects are lost if the entry expires before the sweep. Section 4.1 no longer calls whole steps atomic; it names the atomic operations and says the enclosing steps also make separate writes."],
    "feedback.py _transition, recover; store.py; tests/unit crash-injection tests; tests/integration/test_real_redis.py. Manuscript Sections 4.1, 4.2 and 6."),
  ...item("R9", "The 'lost' measure was descriptive, not causal", "Fixed",
    "Use immutable request IDs to compare completion with the verdict intervention enabled versus disabled, and report both.",
    ["Attributable loss is now computed per request, on the same offered trace. It counts the requests that completed without the intervention (no destination policy in the matched comparison; verdicts recorded but not enforced in the poisoner study) and did not complete with it, net of the reverse. The workload digest is asserted equal across the pair. 'Hit and never completed' is kept and labelled descriptive. Both appear in Table 9, and the paper uses the two words consistently (Sections 6, 7.6 and 7.7)."],
    "evaluation/runner.py attributable_loss. Manuscript Section 6 (Designs and metrics), Tables 8 and 9."),
  ...item("R10", "Calibration and selection remained the principal validity gaps", "Partly addressed",
    "A held-out scenario family and joint parameter-shift study, specified before tuning, could establish bounded robustness.",
    ["Done, as a predeclared study. It uses twelve Latin-hypercube points over conversion (0.6 to 0.9), autofill, human CAPTCHA scores, WhatsApp reachability (0.3 to 1.0), returning share and legitimate rate. Its held-out family, applied in every cell, has attack rates of 60 to 120 per minute and pools of 50,000 to 500,000 addresses, outside every range the defaults were developed on, plus heterogeneous legitimate traffic. It runs three seeds per point and tests five claims that hold if true in 90 % of cells. All five hold after the pairing repair described in the summary.",
     "The paper bounds its claims to these ranges and this family. It also names the results the generator constructs: the premium list, the datacenter attacker that declines challenges, and the farm's human scores. Independent traces remain unavailable."],
    "config/evaluation_protocol.json; results section R; results/robustness_first_run.md. Manuscript Sections 6, 7.1, 7.3, 7.5, 7.7 and 8."),
  ...item("R11", "Legitimate traffic was too homogeneous for a collateral-damage claim", "Partly addressed",
    "Test heterogeneous blocks rather than only a population-wide conversion shift; keep the cohort label distinct from verified-history status.",
    ["The held-out family adds block-level conversion heterogeneity (standard deviation 0.1), 5 % of blocks on poor routes that lose half their messages, a resend probability of 0.3, and a demand burst. Claims C1 to C5 are evaluated under it, and C4 (false verdicts) holds in 18 of 18 judged cells. The design-alternatives study adds 5 % poor-route blocks to its 24-hour legitimate runs. Returning users are now a pre-existing population of 5,000 account holders with a stable fingerprint and number and a trusted number. The cohort is fixed at creation, and whether each request was treated as known-good is recorded separately.",
     "Not done: the main tables use the homogeneous population; there are no correlated vendor failures beyond the outage study; reachability is drawn per request; and returning users carry no fingerprint verification history. All are stated."],
    "evaluation/sim.py _seed_population, legitimate heterogeneity options. Manuscript Sections 6 and 8."),
  ...item("R12", "Statistical precision and operating targets remained inadequate", "Mostly fixed",
    "Separate per-seed variation … from Monte Carlo sampling variation; report paired differences and uncertainty at predeclared operating targets.",
    ["Intervals are now 95 % percentile-bootstrap intervals (2,000 resamples), which stay inside the data range, so non-negative counts no longer get negative lower limits. Paired differences are bootstrapped per seed. The artifact reports tail summaries (90th percentile and maximum) for verdict events, exposure, hits and leakage. A variance decomposition separates attacker-parameter spread from simulation noise: with the farm's pool, rate and CAPTCHA class fixed, its interval narrows from [215, 244] to [223, 232] (Section 6). The sequential grid is the full 5 × 5 cross, and the comparison is at a predeclared operating target. 'Under ten events per day' and 'acceptable cost' are gone.",
     "Still limited: the 24-hour legitimate cells use five seeds. Their tails are in the artifact, but five runs are not a tail guarantee, and the paper does not claim one."],
    "evaluation/runner.py bootstrap; results section A2. Manuscript Section 6."),
  ...item("R13", "Containment is a finite-window retrospective property", "Fixed",
    "Require a minimum sustained interval, show survival/censoring information, and test a longer active attack.",
    ["Containment now requires at least five sustained quiet minutes. All 9,759 runs used that setting. 60-minute attacks report survival curves, and the human-like carrier is contained in only 3 of 10 (Table 7). Time to first verdict is reported separately from containment. The recovery run, in which the attacker stops, is interpreted as harm over a full verdict lifetime, not as containment. The paper defines containment as a finite-window property (Section 6) and says 'contained in all ten windows' rather than 'contains'."],
    "evaluation/metrics.py containment(min_sustain); runner.py study_long_attack. Manuscript Sections 6 and 7.5, Table 7."),
  ...item("R14", "The learned baseline was only briefly exercised", "Mostly fixed",
    "Restart behaviour, partial first-hour samples, stale profiles and multiple concurrent baseline workers remain untested; deserve uncertainty on paired effects.",
    ["Table 6(b) now evaluates the deployed job against a weekly profile learned over three previous weeks. It covers a cold start, three closed hours, stale profiles (legitimate rate halved or doubled since), schedule-aware poisoning at the attack's hour every week, two concurrent workers, and a restart at minute 10, each as a paired difference with an interval. Partial hours are skipped. Poisoning raises leakage by 45 [10, 77] messages, and the paper reports that as a difference, not as robustness. 'Indistinguishable' and 'matches' are gone. Not run: drift or contamination sustained beyond the three-week profile."],
    "baseline.py; evaluation/runner.py study_baseline. Manuscript Section 7.4, Table 6."),
  ...item("R15", "The leakage equation has narrow status", "Fixed in the text",
    "Spell out no pre-existing credit, no successfully solved challenges, no exemptions, and no suspension … Distinguish first verdict from effective containment.",
    ["Section 5 now reads: 'It assumes no pre-existing credit on the blocks, no successfully solved challenges, no verified-history exemptions and no outage suspension, and predicts the first verdict, not containment under graded action.' It calls the equation a consistency check of the per-block mechanism on each run's observed blocks, not a forecast. It says that once kB > N the equation only says everything leaks. Figure 5 shows every run's residual, not means."],
    "Manuscript Section 5, Section 7.5, Figure 5."),
  ...item("R16", "Adaptive attacks do not establish an adversarial optimum", "Partly addressed",
    "Compare at least a bounded/decaying exemption and a receipt-robust admission policy.",
    ["Added: a threshold-aware carrier that knows the deployed parameters and enters a code only when its block nears a verdict (560 leaked, no verdict), and a trust builder with 30 minutes of preparation. Both alternatives were evaluated, together with their legitimate cost. Receipt-robust tests stop the receipt faker (16 leaked) but raise 30.4 false verdict events a day instead of 1.0 on 200 blocks with 5 % poor routes. A trust budget of eight exempt requests a minute trims three of the four trust-builder cells by 23 to 40 messages at no measured cost; it does not change the dispersed trust builder with caps lifted. Neither touches the threshold-aware carrier. Section 7.8 calls these scripted adaptations, not an optimised adversary, and their leakages observations, not bounds. The winning counter was not run against these carriers, as stated."],
    "Manuscript Section 7.8."),
  ...item("R17", "Economics cannot support an unconditional profitability conclusion", "Fixed",
    "Provide a break-even relation or sensitivity surface rather than turning one retail price/share choice into a security conclusion.",
    ["The bill is now event-level: a token for every session attempt, refused ones included, and every request; a paid solution for every challenge; and proxy traffic. Each row reports the break-even revenue share instead of a profit at an assumed share: 0.04 under v1; under v2, 0.27 for the never-verifying pumper, 0.23 for the challenge buyer and 0.06 for the human-like carrier; and 1.39, more than the whole price, for the instant verifier. Preparation, numbers and carrier contracts are omitted, so these are lower bounds, and the paper says so. 'Runs at a loss' is gone."],
    "evaluation/economics; results section E. Manuscript Section 7.8."),
  ...item("R18", "Deployment and timing evidence remained limited", "Partly addressed",
    "Do not generalize the throughput result to adversarial mixed traffic, heavy tails, timeouts, or 403 paths that were not tested.",
    ["The load test adds an adversarial mixture: 55 % expensive-path requests, heavy-tailed vendors (lognormal σ = 1.2), 1 % timeouts and 403 paths. Then 21 % of requests exceed the floor at concurrency 32 and 63 % at 128, while ordinary requests are still all sent. The timing sentence now reads 'a failure to detect a difference, not proof of none; requests over the floor are distinguishable by construction', and the limitations exclude heavy tails and 403 responses from the timing tests. Crash recovery and graded concurrency are tested on a real Redis.",
     "Not done: an App Attest enrolment endpoint now follows Apple's published steps, but it is tested only against synthetic chains, and the HTTP endpoint is untested. No live vendor, network partition or vendor-retry test."],
    "scripts/load_test.py phase 4; results/performance.md. Manuscript Sections 6, 7.8 and 8."),
  ...item("R19", "The production incident cannot carry the contribution", "Partly addressed; author actions remain",
    "Identify which are operator recollections and which were reconstructed vulnerabilities … Resolve permission and affiliation before submission.",
    ["Table 1 now has a Source column. **Proposed classification, which the author must confirm before submission:** recalled from the incident: A (header trusted), B (address limits), C (generated numbers) and E (wide attack under per-key caps); found in the design review that followed: D (premium ranges in allowed countries), F (check-then-increment), G (bulk and test flags) and H (failure-specific responses). Section 3 opens by saying that it is motivation, not evidence. No result depends on the incident.",
     "The title is kept at the author's choice. If the editor prefers a simulation-led title, we suggest: 'Counting Versus Testing the Destination: A Predeclared Simulation Study of Layered Defences Against SMS OTP Flooding and Pumping'. The affiliation placeholder and the permission remain with the author."],
    "Manuscript Section 3, Table 1; title page."),

  H1("Section 3: sentences that overstated the evidence"),
  table([900, 8200], [
    ["Item", "What changed"],
    ["Q1", "The abstract sentence is removed. The abstract now reports the regenerated matched comparison: 'At a matched service target, a short-window counter of SMS sends per block leaked 6 to 48 messages against every pumper tested, at an attributable completion loss of 0.06 to 0.43 % of users.' The ranges are the exact extremes of the three selected short-window counters, at 65 and 80 % conversion."],
    ["Q2", "The 'same legitimate service' sentence is gone. Section 2 now compares our detector with Huh et al. by feature family, learning and action unit, and calls ours 'one transparent, evaluated instance, not a representative of the family'. The comparison is 'at a matched service target', defined in Section 6."],
    ["Q3", "Section 4.1 names the atomic operations (each address limit, the per-number slot, the budget reservation and the per-block counter slot) and says the enclosing steps also make separate writes. Section 6 states the crash behaviour."],
    ["Q4", "Section 4.3: 'a second within the hour moves them off SMS, refusing those without another channel.' Fallback is now wired and measured at 0, 70 and 100 %, and escalation is atomic and tested."],
    ["Q5", "Section 4.4: 'Verified history avoids the adaptive reduction, not the static caps or budget.'"],
    ["Q6", "Section 6 separates what is atomic from what is not, and names the two interleavings still open."],
    ["Q7", "'Acceptable' is gone. Abstract: 'was not separated by any tested signal without challenging nearly half of legitimate users'. Section 7.3 gives the 46.6 % challenged / 8.6 % refused point and says that whether it is worth paying depends on a service objective we did not define."],
    ["Q8", "'Matches' and 'indistinguishable' are gone. Table 6(b) reports paired differences with intervals, and poisoning is reported as +45 [+10, +77] messages."],
    ["Q9", "The sentence is removed. The new experiment (Table 8) is run with fallback wired and the counter charged per send."],
    ["Q10", "The 'share one completion' wording is gone. Table 8 gives completion to two decimals (63.79 to 64.13 %), and Figure 6's caption says its intervals are unpaired."],
    ["Q11", "'Runs at a loss' is gone. Section 7.5 says 'contained in all ten windows', and economics is reported as break-even shares (Section 7.8)."],
    ["Q12", "The conclusion opens 'under the tested settings'. It says the design 'rations, rather than separates, a residential attacker that looks like a person, refusing half of first-time users', with no 'only'; the lessons say rationing 'at the tested settings, depended on a fast controller with history'. Section 7.4 says the cadence results are 'tested settings, not proof that only a fast controller works'."],
    ["Q13", "The frontier sentence is gone. Figures 4 and 6 are captioned as sampled points, and the counter is compared as a separate policy family at a common service target, not as a memory setting."],
  ]),
  P(""),

  H1("Section 4: numerical contradictions"),
  table([3000, 6100], [
    ["Reviewer's finding", "Status in revision 3 and release 2.7.0"],
    ["30 % without an alternate channel vs zero WhatsApp dispatches", "Fixed (R1). Dispatch, no-channel losses and completion are asserted at 0, 70 and 100 %."],
    ["Graded-counter completion of 2 to 17 % in the abstract and Table 8", "Removed. Regenerated with fallback wired and the counter charged per send. The graded daily counter of 20 completes 27.45 / 52.81 / 63.52 % at 0 / 70 / 100 % reachability."],
    ["Figure 6 'one completion' vs 63.8 to 64.4 %", "Removed. Table 8 reports completion to two decimals, and attributable loss with paired intervals."],
    ["Negative exposure (−95.3, −1.0, −0.2)", "Fixed (R2). None of 5,920 exposure values is negative."],
    ["Two simultaneous stage-1 verdicts", "Fixed (R3). Stages are [1, 2] in barrier, threaded and real-Redis tests."],
    ["Counter charged three increments for two offered requests", "Fixed (R4). Two increments for two sends."],
    ["Zero 'hit'/'lost' for refusing counters", "Table 8 now reports attributable loss for every policy, on the same footing, and 'verdict events' only as what they are (zero for counters, which issue none)."],
  ]),
  P(""),
  P("We have taken the reviewer's list of differences that are not contradictions as guidance. In revision 3, the 30-seed main study and the 10-seed studies are labelled, and paired and unpaired intervals are distinguished in the captions."),

  H1("Section 5: related work and competing approaches"),
  Bullet("**Huh et al.** Section 2 now compares the two detectors by feature family, training and action unit, and says that we did not reproduce theirs. The new empirical knowledge this paper adds is stated as measurements of where outcome reputation separates, what rationing depends on, and how a destination detector compares with a tuned destination limiter. The last of these went against our detector."),
  Bullet("**Quickest change detection.** Veeravalli and Banerjee and the NIST CUSUM handbook are cited for detection delay under false-alarm constraints and for setting CUSUM parameters from error rates. We read only the abstract of the former and the handbook section of the latter, and the paper cites them for nothing more. The paper says that an unconstrained grid is a set of sampled operating points. The matched comparison adds false-alarm matching per credit value; no credit-zero setting met it."),
  Bullet("**Simple destination controls.** A correctly implemented short-window refilling limiter was included and tuned to the service target, as the reviewer asked. It leaked less in total than every sequential setting at the target, though more than the default against the instant verifier at 200 blocks (24 against 17)."),
  Bullet("**Other sequential policies.** Windowed, exponentially weighted and time-uniform statistics were not run; the paper says so and claims no memory trade-off beyond the examined family."),
  Bullet("**Trust and receipt policies.** A trust budget and receipt-robust tests were evaluated, with their legitimate cost (R16)."),
  Bullet("**Commercial approaches.** Twilio's Fraud Guard and SMS Pumping Risk Score are cited as established practice for graded destination action. No benchmark was run, and no superiority is claimed."),
  Bullet("**Economic friction.** Client puzzles are listed as not evaluated. The practical lessons are narrowed to counting on the destination and to what rationing needs."),

  H1("Section 6: presentation"),
  Bullet("**Front matter.** The first-page highlights are removed at the author's request. Elsevier collects them as a separate file at submission. The title is kept (R19), and the affiliation placeholder remains for the author."),
  Bullet("**Figure 1.** Panels (a) and (b) now show leakage as a share of attack requests, which removes the attack-volume mixing. Panel (c) shows legitimate completion. v1 and v2 are defined in the legend and the caption, and the labels are larger."),
  Bullet("**Figure 2.** Every cell is labelled; nothing is suppressed. * marks a paired interval excluding zero, and the caption notes that 19 of 90 cells are marked, so an isolated * is weak evidence. The complete matrix with intervals is in paper/figures/fig2_ablation_matrix.csv."),
  Bullet("**Figure 3.** Panel (a) is the per-run leaked share with bootstrap intervals, and the caption says where they are narrower than the markers. Panel (b) is harm with interval bands."),
  Bullet("**Figure 4.** Defaults are starred. Settings are labelled (f, m for cap floor and multiple; x, w for score settings), with intervals on both axes. The caption reads 'sampled points, not an optimised frontier'."),
  Bullet("**Figure 5.** Per-run residuals, not means. Saturated runs are marked with crosses. The axis says that observed blocks are a model input. The text gives the unsaturated mean absolute error and the largest single-run residuals."),
  Bullet("**Figure 6.** Rebuilt as the matched comparison: leakage against completion and against challenge burden in separate panels, numbered points with a key, and intervals."),
  Bullet("**Table 1.** Source column (R19). **Table 2.** Matches the text on atomic reservations; the quota units are in Section 4.3. **Table 3.** Machine-readable profile names for all 25 profiles, with every parameter in results/attacker_profiles.md."),
  Bullet("**Table 4.** Leak percentages with a block-limit column. The other designs' differences are spelled out in the caption, and intervals are in Figure 1."),
  Bullet("**Table 5.** Captioned 'one-at-a-time sensitivity (not a joint search)', with the full grid and the rule for unlisted rows."),
  Bullet("**Table 6.** Split into panel (a), cadence, with phase and attack-length columns, and panel (b), the learned baseline, with paired differences and intervals."),
  Bullet("**Table 7.** Units in every header (messages, seeds, minutes, codes entered), a column for time to first verdict, the meaning of dashes stated, and 'contained within the attack window (a finite-window property)' in the caption."),
  Bullet("**Table 8.** Rebuilt as the matched comparison: a common pipeline, attributable loss for every policy, and verdict events only. The 80 % conversion figures are in the text beside the 65 % ones."),
  Bullet("**Old Table 9 (Monte Carlo).** Moved to prose in Section 7.7 to stay within the word limit. The counts and Wilson intervals remain in results/evaluation.md, section H1. 'Fast' is defined as entry of a verified code within five seconds (Section 4.3)."),
  Bullet("**Table 9 (old Table 10).** Run durations are in the caption, and the recovery row covers a 70-minute run, longer than a verdict's one-hour lifetime. Descriptive and attributable loss are separate columns."),
  Bullet("**Artifact.** results/study_specs.json gives every run's configuration and hash: fallback wiring, action policy, feature set and observation window. results/headline_numbers.md maps headline numbers to JSON paths. paper/figures.py contains no embedded titles, and the submitted figures are built by it."),

  H1("Section 7: the single question"),
  Quote("After making the simulator actually provide the fallback channels it claims, correcting event windows and graded-policy state transitions, what nontrivial security–service conclusion still survives a common-pipeline comparison against a tuned simple destination limiter at matched completed service—and remains true on scenarios specified independently of the tuning generator?"),
  P("After those repairs, and on a common pipeline at a predeclared service target, the conclusion that survives is the opposite of the one our detector would have wanted. **Counting SMS sends per destination block in a short refilling window did better than sequential tests of verification outcomes, in total leakage at every density and against every pumper but one.** At 200 busy blocks, the selected counter of four sends per ten minutes leaked 24 against the never-verifying, instant and human-like carriers and 48 against the challenge buyer. Its attributable completion loss was 0.06 % of users at 65 % conversion and 0.07 % at 80 %. The default sequential setting leaked 89, 17, 405 and 104: better only against the instant verifier, which its speed test catches at 17. The sequential setting that met the service target with the least leakage held the human-like carrier to 118, but only by raising 314 false verdict events a day; at the default's false-alarm burden, every credit leaked 405 or more against that carrier. At 29 and about 4 legitimate sends per block per day the selected counters (three per hour; one per ten minutes) leaked 9 and 6 against each outcome-reading carrier and 18 and 12 against the challenge buyer, below the default against all four, with attributable losses of 0.35 and 0.15 % (0.43 and 0.18 % at 80 %). The selections were made on tuning seeds and evaluated on seeds the selection never saw, and the first run, before the pairing repair, selected the same settings."),
  P("The mechanism is simple enough to expect it to generalise in direction, though not in magnitude: a concentrated pumper sends about ninety messages per block per ten minutes and a busy legitimate block about one, so a volume limit on the key the pumper cannot rotate separates them whatever its carrier does with the codes. The sequential tests read outcomes the carrier controls."),
  P("On the second half of the question: the robustness study is predeclared and includes a held-out family, but it is still our generator, so it is not independent in the strong sense. Its claims about the rest of the design (C1 to C5) hold under that family. The counter result was evaluated at three densities but not under the held-out family, not against spread or adaptive pumpers, and not at reachabilities other than 70 %, and its cost depends on a fallback channel (the graded daily counter completes 27 % without one). The paper states these limits next to the result rather than in a footnote."),
  P("We think this is the nontrivial, reproducible security–service conclusion the reviewer asked for. It is a negative result for the detector we built, and the paper is now organised around it."),

  H1("Appendix A of the report: disposition of the second-round objections"),
  table([1500, 2000, 5600], [
    ["Item", "Reviewer's status", "This round"],
    ["M5 drain", "Substantially closed", "Window and drain estimands now separate (R2)."],
    ["M7 receipt clock", "Partly closed", "The mixed-sign interleaving is fixed. A timeout-worker race remains and is disclosed (R7)."],
    ["M8 concurrency", "Partly closed", "Graded issuance is atomic, and effects are recorded and applied exactly once with recovery (R3, R8). Undo order dependence and Step 11 remain, as disclosed."],
    ["M9 verdict events", "Partly closed", "Three labelled estimands (R2)."],
    ["M10 no-credit harm", "Experiment added", "Superseded by the full grid in the matched comparison, with attributable loss (R5, R9)."],
    ["M11 learned baseline", "Partly closed", "Weekly profile, stale, poisoned, two workers and restart, with paired effects (R14). Long-term drift not run."],
    ["M12 cadence", "Substantially closed", "Unchanged design, regenerated. Universal cadence language stays removed."],
    ["M13 counter comparison", "Still open materially", "Closed by the predeclared matched comparison on a common pipeline (R4 to R6). The result reversed the paper's claim."],
    ["M14 CUSUM equivalence", "Textual point closed", "Full 5 × 5 grid with false-alarm matching per credit value."],
    ["M15 separation claim", "Partly closed", "Acceptability language removed (Q7, Q12)."],
    ["M17 dominated key", "Substantially closed in text", "Unchanged: 'in the settings run'."],
    ["M18 held-out design", "Open", "Predeclared robustness study with a held-out family (R10). No independent traces."],
    ["M22 trust builder", "Partly closed", "30-minute preparation variant and trust budget alternative added (R16)."],
    ["M23 poisoning", "Partly closed", "Observe-only counterfactual and attributable loss; fallback at 0, 70 and 100 %; recovery over a full verdict lifetime."],
    ["M24 late receipts", "Partly closed", "As for M7."],
    ["M25 fallback", "Open, new critical regression", "Fixed and tested (R1)."],
    ["M26 cost/performance", "Partly closed", "Event-level bill, break-even shares, adversarial load phase (R17, R18)."],
    ["M28 real Redis", "Partly closed", "Eight real-Redis tests, including graded escalation and crash recovery. Live vendors still absent; enrolment tested on synthetic chains only."],
    ["M29 incident", "Partly closed", "Source column added. Permission and affiliation remain with the author."],
    ["M1–M4, M6, M16, M19–M21, M27, M30", "Closed", "Unchanged and regenerated. Pairing across scenarios is now also asserted."],
  ]),
  P(""),

  H1("Appendix B of the report: the reviewer's independent checks"),
  table([3000, 6100], [
    ["Reviewer's check", "Result on release 2.7.0"],
    ["Fallback wired to the per-request draw", "Wired in the simulator itself and tested at 0, 70 and 100 %. The artifact's 24-hour fallback runs (results/evaluation.md, section H4) serve 38.87 % of legitimate users over WhatsApp under the graded counter of 20 at 70 % reachability."],
    ["Two simultaneous graded crossings", "Stages [1, 2] in barrier, threaded and real-Redis tests."],
    ["Mixed receipts", "The reviewer's sequence ends delivered and unresolved. The timeout-worker variant is a disclosed residual."],
    ["Drain-time exposure", "Never negative; three estimands."],
    ["Counter retry with limit one", "Two increments for two sends; the retry after a solved challenge sends at stage 1."],
    ["Regression checks", "353 tests pass (re-run for this letter), including eight real-Redis integration tests."],
  ]),
  P(""),
  P("We are grateful for the time this report took. Its central objection exposed a defect that had made our own comparison wrong. Repairing it, and then letting a predeclared protocol choose the comparators, produced the most useful result in the paper."),
];

const doc = new Document({
  styles: { default: { document: { run: { font: "Calibri", size: 22 } } },
            paragraphStyles: [
              { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 28, bold: true, color: "1F3864" }, paragraph: { spacing: { before: 360, after: 120 }, outlineLevel: 0 } },
              { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 23, bold: true, color: "2E5496" }, paragraph: { spacing: { before: 240, after: 60 }, outlineLevel: 1 } }] },
  numbering: { config: [{ reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } }] }] },
  sections: [{
    properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1250, bottom: 1250, left: 1300, right: 1300 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], size: 18, color: "666666" })] })] }) },
    children }]
});

Packer.toBuffer(doc).then(buf => { fs.writeFileSync("rebuttal_round3.docx", buf); console.log("wrote rebuttal_round3.docx"); });
