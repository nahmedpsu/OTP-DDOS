// Response to the fifth-round Reviewer 2 report. Build: node rebuttal_round5.js -> rebuttal_round5.docx
const fs = require("fs");
const { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType,
        AlignmentType, BorderStyle, ShadingType, LevelFormat, Footer, PageNumber } = require("docx");

// **bold** and _italic_; an underscore inside a word (a file name such as counter_study_per_seed.csv) is literal.
function runs(text, size) {
  const out = []; const re = /(\*\*[^*]+\*\*|(?<![A-Za-z0-9])_[^_]+_(?![A-Za-z0-9]))/g; let last = 0, m;
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

// status: "Fixed ...", "Done ...", "Partly ...", "Not done ..."
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
  new Paragraph({ children: [new TextRun({ text: "Response to the fifth-round report of Reviewer 2", bold: true, size: 32 })], spacing: { after: 120 } }),
  P("**Manuscript:** Counting Versus Testing the Destination: A Simulation Study of Layered Defences Against SMS OTP Flooding and Pumping. **Journal:** Computers & Security."),
  P("**Reviewed:** manuscript revision 4, repository snapshot ed2d6c3, results produced by release 2.8.0 (commit 1c277a0). **Revised:** manuscript revision 5 and release 2.8.1 on the same branch. The implementation repairs and their tests are in 767fd9c, the new analyses, timing check and their recorded results in 6f0fc2a, and documentation, dated protocol corrections and release metadata in c34375f; the manuscript and this letter are in the commit that accompanies it. The 2.8.0 results are unchanged and still identify commit 1c277a0. Table and figure numbers refer to revision 5 unless marked 'old'; Section 6 of this letter maps old numbers to new ones."),

  H1("Summary"),
  P("We thank the reviewer for a fifth careful report and for reproduction steps precise enough to rerun as written. The new recovery defect (M8) reproduced exactly on 2.8.0: after a crash between the outage write and the batch clear, and 601 seconds, recovery moved the old delivery failure into the current 600-second window, 0 to 1. The shortlist objection (M1) was also right. Revision 4's alternative objectives ranked the policies the original rule had shortlisted; they did not select again."),
  P("**What changed.** (1) Release 2.8.1 applies a replayed effect at its transition's time and closes the four implementation defects that revision 4 disclosed. Each repair has a regression test that fails on 2.8.0, on the in-memory store, on fakeredis and, for the replay and race cases, across two instances on a real Redis; the HTTP and app stage-1 paths now have tests of their own (M8, M9). The simulation is unaffected: 102 recorded runs, three from every study of both result files, replay identically under 2.8.1. (2) Selection was repeated under each objective on the tuning runs over every setting that meets the target; the winners were frozen and evaluated on the fresh seeds, with 60 new runs for winners the first shortlist lacked (M1). (3) The attacked-service results are now one table that answers three separate questions (benign cost, extra harm against the attacked no-policy arm, degradation against attack-free operation) for all users and for the attacked blocks' users, with the combination's poisoner cost beside its leakage (M2, M3). (4) Section 5 states a closed-form operating condition, which the measured boundary matches (M5 and the single question). (5) Claims are reported by attacker (M6); the tuning target and the paired evaluation check are named separately (M7); the timing accuracy is reported as a resubstitution value, with a held-out check across runs (M10)."),
  P("**The single question.** Our answer is a bounded condition, not a general preference; Section 7 of this letter gives it in full. Against our outcome tests, a pumper on B blocks leaks about kB + λτ before the first verdict (k = 5; λτ ≈ 95 messages for a never-verifying carrier at E4's attack rate). A counter of q sends per block per window lets it send (1+s)qBw over w windows, s = 1 if it solves challenges, whatever its carrier does with the codes. Against a never-verifying carrier the counter therefore leaks less only while B(qw − k) < λτ, which at q = 4 means fewer than about five blocks for an hour or 30 for twenty minutes; against carriers that game outcomes, until its envelope reaches their volume. Its benign cost follows the share of a block's own sends beyond q, E[(n − q)+]/E[n]: with Poisson sends, 0.4 % at one send per window and 20 % at four. The measured map sits on these curves (the counter leaked 71, 240 and 679 messages on 3, 10 and 30 blocks over an hour against an envelope of 72, 240 and 720; the default leaked 110, 144 and 242 against 5B + 95). The envelope and the crossover are mechanical. What needed the simulation is k and λτ, the cost of an excess send to a user (about 0.12 points of a block's users per point of excess, at 70 % WhatsApp reachability), competition under attack (where K3 and K5 fail) and exemption abuse. Per-block load and attacker spread are in an operator's own logs, so the condition can be checked without our calibration; its constants are not externally validated."),
  P("**Manuscript.** Revision 5 keeps the scope: the same research questions, designs, attacker families and studies. To add Section 5's condition, the study map the reviewer asked for (Table 3) and the attacked-service table (Table 9) within 8,000 words, we folded three context tables into the text with their key numbers and intervals (old Table 5, layer effects; old Table 6, baseline-job cadence and learned history; old Table 10, the poisoner), moved the spread figure (old Figure 5) to the artifact, merged the artifact statement into Data availability, and shortened captions. The paper is 7,996 words from the title to the end of the reference list, counting tables, captions, declarations and references (alphanumeric tokens in the compiled PDF, figures as placeholders); a whitespace count gives 7,937. It compiles without overfull boxes in 26 pages. Every number in the revision and in this letter was checked against results/evaluation.json, results/counter_study.json, results/round5_analyses.json and the performance results in a separate audit pass, and the passages it questioned were corrected (for example, the Poisson shares in Section 5 are now stated for q = 4, and each target margin names its seeds)."),

  H1("What we could not do, or did only in part"),
  Bullet("**Real traffic (M5).** We still have no production or third-party traces. The operating condition is analytic, with constants from the simulation. We ran no extra seeds and do not present seeds as validation."),
  Bullet("**Token-bucket calibration (M4).** Rate and burst were not tuned under the declared service objective. The two settings remain exploratory comparators, and the paper says that neither limiter dominates and that two settings cannot rank refilling limiters against expiring counters."),
  Bullet("**Hierarchical controls.** Per-client quotas inside a block, carrier spend ceilings and bounded exemptions are outside the evaluated policies, and Section 8 says so."),
  Bullet("**Returning people without a trusted identity (M12).** Not simulated as a separate cohort. To the pipeline they are first-time users; Section 6 says that results for returning users describe trusted identities only. New devices, lost fingerprint history, changed numbers and depleted exemption budgets are not modelled."),
  Bullet("**Step 11 (M9).** Still not one transaction. Its crash semantics are now documented in feedback.py and tested; it was not redesigned."),
  Bullet("**Live vendors.** Vendor adapters remain untested against live services; App Attest enrolment is tested only on synthetic certificate chains. Section 8 says both."),
  Bullet("**Author actions before submission (M15, M16).** Pushing the tags v2.8.0 (on 1c277a0) and v2.8.1 to GitHub, which this session cannot do; optionally an archive DOI; the affiliation; written permission to describe the incident; confirmation of Table 1's Source column; the highlights file. Reference 23 and the Data availability statement now name the immutable commit 1c277a0, so the citation does not depend on the tag being public."),

  H1("Section 2: methodological weaknesses"),
  ...item("M1", "The alternative objective study does not rerun the claimed selection", "Done: selection repeated under each objective",
    "Say 'among the shortlisted policies' throughout, or select under each objective using tuning data, freeze the resulting union, and evaluate that union independently.",
    ["We took the second option. Part A of scripts/run_round5_analyses.py makes every setting that meets the tuning target on the E5 tuning runs a candidate, not only the original shortlist: 30 of 41 settings at 200 blocks, 36 at 1,000 and 40 with uniform traffic. Each objective selects on the tuning runs with the original tie-break (lower leakage, then higher completion): summed leakage (the original), worst case, summed leakage under a first-time-loss limit of 0.5 points, each attacker alone, and 2,000 random mixes. The union of winners is frozen and evaluated on the fresh seeds 300–309.",
     "At 1,000 blocks and with uniform traffic every objective selects the same counter (three sends per 60 minutes; one per 10 minutes). At 200 blocks every objective selects the four-per-ten-minute counter except two: the instant verifier alone selects sequential T300 with unbounded credit, and 3 of the 2,000 mixes select T300 c0. T300 with unbounded credit was not in revision 4's shortlist, so we ran it on the ten evaluation seeds (60 new runs cover the union members that had no evaluation runs). On those seeds the counter leaked least of the union against every attacker: 24.3, 24.9, 24.7 and 48.7 messages against the never-verifying, instant, human-like and challenge-buying carriers, where T300 c0 leaked 127.3, 48.9, 171.1 and 133.8 and T300 with unbounded credit 127.3, 49.8, 644.2 and 133.8.",
     "We agree about the random mixes. Once one policy has the lowest point estimate for each attacker, it minimises every nonnegative mixture of those estimates, so on evaluation data the mixes add nothing. They are reported only as a selection on tuning data, where 3 of 2,000 chose differently, and the paper does not use them to quantify uncertainty or to cover an omitted attacker. The union also excludes the default. On the fresh seeds the counter leaked less than the default against the instant verifier too (24.9 against 52.4; paired difference −28 [−63, +6]), but on the first protocol's seeds 0–9 it leaked more (24 against 19), the paper says so in the same paragraph, and K4 failed in 13 of the instant verifier's 36 held-out cells (M6). The conclusion therefore says 'not reliably against an instantly verifying carrier'.",
     "Section 7.6 now reads: 'With the full grid and density-specific attacks (E5) the rule selects the same counters, and so does every other objective we tried on the tuning runs over every setting meeting the target (worst-case leakage, a first-time-loss constraint, each attacker alone, 2,000 random mixes), except that at 200 blocks the instant verifier alone, and 3 mixes, favour a sequential setting; on fresh seeds the counter still leaked least of the winners against every attacker (25, against 49 and 50, for the instant verifier).'"],
    "scripts/run_round5_analyses.py (part A); results/round5_analyses.md, section A; results/round5_union_eval_runs.jsonl.gz. Manuscript Section 7.6, 'At a benign service target'."),
  ...item("M2", "The combined policy is promoted beyond its demonstrated trade-off", "Done",
    "Present its leakage and service together, restrict the least-leakage claim to the stated four-carrier aggregate, and call the operational recommendation a hypothesis.",
    ["Table 9 puts the combination's leakage and service on the same row. Against the four concentrated carriers it leaked 190 messages in total (29, 28, 82 and 51), against 403 for the counter alone (80, 83, 82 and 158). Against the shared-block poisoner it cost all users 1.35 points and first-time users 1.70, against 0.72 and 0.91 for the counter, and it leaked 1,311 messages, more than the tuned sequential setting (871) and less than the counter (1,662).",
     "Section 7.6 says that counter and tests together 'leaked least against the four carriers', gives the poisoner cost in the same sentence, and notes that the combination 'was explored outside the frozen claims'. Section 8 no longer recommends it: 'Counter and tests together, with a quota set from each block's traffic, is a hypothesis for real traffic, not a recommendation.' Per-block quotas and spread detection are no longer presented as findings (Q2)."],
    "results/round5_analyses.md, section C. Manuscript Section 7.6, Table 9, Section 8 ('Lessons')."),
  ...item("M3", "Net attributable service loss is useful but not a service guarantee", "Done",
    "Bring the existing gross-loss, gross-gain and affected-cohort measures into the central comparison, and distinguish three questions: benign cost, extra harm relative to another attacked policy, and degradation relative to attack-free operation.",
    ["We kept the estimand and now say what it answers. Section 6 defines the three quantities on paired traces: benign cost (attack-free traffic, policy against no policy), extra harm (the attacked trace, policy against the attacked no-policy arm) and degradation (the attacked trace against attack-free operation under the same policy). Table 9 reports all three for seven of the eight E1 arms at 200 shared blocks (the eighth, the counter with a trust budget on its exemption, matched the counter except for 0.04 points among returning users, and is in the artifact), for all users and for the attacked blocks' users (about 18 a run), and the poisoner's harm for all and first-time users. Gross losses and gains, and the first-time and returning cohorts, for every arm and carrier are in results/round5_analyses.md (section C). Degradation needed 240 new attack-free runs on the E1 traces.",
     "The result is the one the reviewer anticipated. Against the attacked no-policy arm the counter gained the attacked blocks' users 3.2 points on average over the carriers, because without a destination policy the pumper exhausts their blocks and the hourly budget. Against attack-free operation every policy still left those users worse off: 4.8 points under the counter, 7.0 under the default, 8.9 under the tuned sequential setting and 8.0 with no policy. Section 7.6 states the consequence: 'no policy shields a block an attacker shares'. The reviewer's example is in the per-carrier table: with the human-like carrier the counter costs 0.09 points of all users and 1.92 [0.53, 4.04] of the attacked blocks' users."],
    "scripts/run_round5_analyses.py (part C); results/round5_analyses.md, section C; results/round5_attack_free_runs.jsonl.gz. Manuscript Section 6 ('Designs and metrics'), Section 7.6, Table 9."),
  ...item("M4", "The token bucket comparison does not identify a generally inferior limiter", "Partly done: kept exploratory, not calibrated",
    "Keep this as an exploratory trade-off, or calibrate rate and burst under the same declared service objective.",
    ["We kept it exploratory. Table 9 gives both bucket settings beside the counter; Section 7.6 says that the burst-4 bucket cost the poisoner's users 0.12 points only by letting 1,877 messages through, and that 'with two untuned settings, neither limiter dominates'. Section 4.3 states that the bucket's challenge tier refills independently, unlike RFC 2697's excess bucket. The protocol's label for the burst-12 arm ('tolerates a legitimate burst of 12') is corrected in config/counter_protocol_erratum.md: it tolerates any burst of 12. We did not calibrate rate and burst under the service objective."],
    "config/counter_protocol_erratum.md. Manuscript Sections 4.3 and 7.6, Table 9."),
  ...item("M5", "The operating boundary is sampled rather than externally established", "Done as an analytic condition; real traces unavailable",
    "State a compact, quantitative operating condition in terms of legitimate load per block, attacker spread and fallback, and identify which assumptions have empirical support.",
    ["Section 5 is now 'Leakage estimates and an operating condition'. Equation 3 gives the counter's envelope, (1+s)qBw; Equation 4 the crossover against the tests for a never-verifying carrier, B(qw − k) < λτ; and the paragraph after it the service side, the share of a block's own sends beyond the quota, E[(n − q)+]/E[n]. The section ends by separating what follows from the rules (Equations 3 and 4) from what needs the simulation (k, λτ and what an excess send costs a user). Section 7.6 checks the condition against E4: the counter's measured leakage is near its envelope, the default's is close to Equation 2 with λτ ≈ 95, and the measured maps cross where Equation 4 puts the crossover. Attack-free, the measured cost is about 0.12 points of a block's users per point of sends beyond the quota at 70 % WhatsApp reachability. Beyond twice the quota users without another channel are refused, so fallback matters there: at eight sends per window the cost is 13.2 points without WhatsApp against 5.5 with 70 %, while at four it is 2.5 against 2.3.",
     "Section 8 names what comes from the simulation (the cost of an excess send, the tests' constants, competition under attack and exemption abuse) and says that an operator can check the condition from its own logs of per-block load and attacker spread. Of the behavioural assumptions behind the constants, only the conversion rate has a published source (one provider's global figure of 68 % or more, Section 6); autofill, challenge completion, WhatsApp reachability, the returning share and the arrival process are assumptions. Five rates and five spreads remain sampled points, and Figure 6's caption says the lines join sampled settings."],
    "results/round5_analyses.md, section D. Manuscript Section 5 (Equations 3 and 4), Section 7.6 (paragraph beginning 'Attack-free'), Figure 6, Section 8."),
  ...item("M6", "The pooled pass rule conceals an attacker-specific exception", "Done",
    "Report results by attacker as well as pooled.",
    ["Table 8 now gives each claim's true cells with the percentage, a column for the instant verifier's cells, and the result 'holds pooled, not for IV' for K4. By attacker (never-verifying, instant, human-like, challenge-buying): K1 36 of 36 for each; K3 34, 32, 30 and 31 of 36; K4 36, 23, 36 and 36; K5 27, 23, 22 and 21. The caption says that a claim holds if true in 90 % of cells and that cells share workloads and seeds and are not independent; Section 6 calls the rule a benchmark convention, not a confidence level. The text says 'K4 held in only 23 of the instant verifier's 36 cells'."],
    "results/round5_analyses.md, section B. Manuscript Section 7.6, Table 8."),
  ...item("M7", "Service target language still mixes a tuning threshold with evaluation differences", "Done",
    "Use 'selected at the tuning target', show a separate evaluation margin, and give the paired evaluation constraint its own name.",
    ["Table 7 labels T300 c0 'selected at tuning target' and the counters 'selected'. The text gives the evaluation margin separately: the sequential setting 'falls 0.16 points below the target on seeds 0–9', and 'on seeds 300–309 the 1,000-block counter falls 0.12 points below its target, yet no seed-and-conversion cell fails the paired check (the evaluation default minus 0.5 points)'. Each statement now names its seeds, density and reference value. The evaluation margins of every winner are in results/round5_analyses.md (section A). Section 8 says that selection used a mean service target; we make no claim of a high-probability guarantee."],
    "Manuscript Section 7.6, Table 7, Section 8."),
  ...item("M8", "A further recovery effect is not idempotent in event time", "Fixed and tested, including on a real Redis",
    "Preserve transition time and define replay-safe event insertion, expiry and block-occupancy updates. Add a regression that checks window membership, not just unique member counts.",
    ["Reproduced on 2.8.0 exactly as described (0 before recovery, 1 after), then repaired. A transition already recorded its time with its effect batch; the replay ignored it. In 2.8.1 the batch is applied at that time. The outage detector inserts the observation, and the block it occurred on, at the transition's time, while trimming and window counts use the current time, so a replayed old observation cannot enter the current window and one inside its window counts once at its own time. A replayed reputation increment lands in the hour of the event, not of the replay.",
     "Regression tests check window membership and event time, not member counts: test_replayed_outage_event_keeps_its_time (the reviewer's steps: 0 at 601 s, still 0 after recovery, batch cleared), test_replayed_outage_event_inside_its_window_still_counts (counted once, with the event's own score), test_replayed_reputation_effect_lands_in_its_own_hour, and test_replayed_outage_event_keeps_its_time_across_instances on a real Redis. Each fails on 2.8.0 for that reason.",
     "Section 4.2 now states the event-time condition (Q7): replayed effects apply at the transition's time, each effect type at most once, and exactly once if a sweep runs within 20 minutes. The simulator never kills a process, so no recorded result could change; the reproduction check confirms it."],
    "feedback.py (_apply, _outage_record, module notes); reputation.py (incr_batch_once); tests/unit/test_fifth_round.py; tests/integration/test_real_redis.py. Manuscript Sections 4.2 and 6."),
  ...item("M9", "The disclosed implementation defects still limit the artifact claim", "Fixed: all four, with targeted tests",
    "Keep the artifact explicitly a research prototype, separate validated logical policy behavior from concurrent service behavior, and turn the known cases into targeted regression failures or fixes.",
    ["All four cases are now targeted tests and, where a fix exists, fixed:",
     "**The timeout worker.** The worker removes a send's timeout only if its due time is unchanged (store.zrem_if_score, one script on Redis), so a correcting receipt that reschedules the send during the worker's transition keeps its timeout. The test interleaves exactly that receipt between the transition and the removal, in memory, on fakeredis and on a real Redis.",
     "**The late reversal.** Block-event identifiers are kept for the replay horizon plus the code lifetime plus 60 seconds, so a failure's identifier outlives every replay of its reversal. The test verifies a code at the latest valid moment, kills the process before its block effect and recovers 14 minutes later; the failure is found and reversed (also on a real Redis).",
     "**Step 11 and the source caps.** A request that Step 11 turns into a challenge gives back the source-cap counts it took at Step 9, as a request challenged at Step 7 never takes them. With eight concurrent requests at the four-per-ten-minute counter, four are sent, four are challenged, and the source cap shows four. Writing this release exposed one more Redis case, fixed with it: releasing a claim whose window had expired created a negative counter without a TTL.",
     "**Step 11 is not one transaction.** Not redesigned. Its crash semantics are documented in feedback.py and tested: a crash after the entry is written and before the hand-off leaves the reserved budget unit reserved, sends nothing, and resolves as undelivered at the grace period without feeding the block test.",
     "**Stage-1 paths.** Last round we wrote that the HTTP application's stage-1 path had no test of its own. It now has one over HTTP (test_stage_one_challenge_over_http), and the app path, which has no challenge surface and moves clients to non-SMS channels, is tested serially (Step 7) and concurrently (Step 11). A further real-Redis test covers unsolved requests at the counter's second boundary.",
     "Section 6 lists the four repairs, calls the implementation a research prototype, says that the real-Redis tests cover specific interleavings, not all, and keeps Step 11's crash behaviour as a stated limit. The suite has 418 tests, sixteen of them on a real Redis; we do not present the count as evidence of end-to-end correctness."],
    "store.py (zscore, zrem_if_score, release); feedback.py (run_due_timeouts, id_retention_s); pipeline.py (release_source_caps); tests/unit/test_fifth_round.py; tests/integration/test_real_redis.py; tests/integration/test_api.py. Manuscript Section 6 ('Implementation')."),
  ...item("M10", "The timing classification result is an optimistic fitted statistic", "Done",
    "State explicitly that fitting and evaluation reuse the same data. Either report it as a descriptive maximum or fit on separate requests and evaluate on new requests, preferably across runs.",
    ["Both. Section 7.8 now says that the threshold was 'fitted to one run's 2,497 sends and 22 refusals' and reached 88 % balanced accuracy 'on that run, a resubstitution value'. scripts/load_test.py --holdout 3 then ran three new phase-4 runs (adversarial mixture, heavy-tailed vendors, 400 ms floor, concurrency 128, 3,000 requests each), fitted the best threshold on each run's client-side end-to-end times and applied it unchanged to the other two. Applied to a run it was not fitted on, the threshold reached 95.3 to 99.9 % balanced accuracy (mean 98.1 %; the fitted values were 99.2 to 99.9 %). Each run had about 2,497 sends and 22 refusals, the same class counts as the original. These runs used a 2-vCPU machine, on which 99.0 to 99.9 % of sends overran the floor in server time, against 81 % in the original 4-vCPU run; they show that the separation is not a fitting artefact on that machine, but they do not re-estimate the 88 % figure. The paper reports both, with the class counts and the machine.",
     "The smallest Kolmogorov–Smirnov p-value is given as 0.051, with 'no difference detected, not none'. The paper distinguishes server time (81 % of sends overran the floor in server time) from the client's end-to-end response time, which the threshold uses. The latency study does not establish behaviour under live vendors, networks or outages, and Section 8 says that the timing result holds only for the observer model tested."],
    "scripts/load_test.py (holdout, fit_threshold, apply_threshold); results/performance_holdout.md and .json. Manuscript Section 7.8."),
  ...item("M11", "Resampling quantifies run variation rather than uncertainty in the model", "Done (wording); no new sampling",
    "Keep zero-width intervals, zero observed returning-user loss and small mean differences tied to their sampled model. Use the already available paired differences for important rankings.",
    ["Section 6 keeps 'they describe variation under this generator, not uncertainty about real traffic', and Section 8 says that close rankings rest on ten or fewer seeds. Figure 2's caption keeps the unadjusted-interval statement, and Section 7.2 calls each cell a conditional effect. The ranking that matters most, the counter against the default per attacker, is shown as paired differences in Figure 5(b). The zero returning-user loss is tied to the model in Section 6 and in the limitations (M12)."],
    "Manuscript Sections 6, 7.2, 7.6 and 8; Figures 2 and 5."),
  ...item("M12", "The trust and fallback model makes some user protection partly structural", "Partly done: stated as outside scope",
    "Separate results that rely on a trusted returning identity from results for a person who is returning but cannot present one. If that scenario remains outside scope, say so.",
    ["Section 6 now says: 'a returning person without them is, to the pipeline, a first-time user, so results for returning users describe trusted identities only'. Section 7.6 ties the zero loss to the exemption: 'Returning users, exempt through verified history, lost nothing under these policies' (the policies of Table 9; with a trust budget on the exemption they lost 0.04 points). The limitations list 'returning users who always present verified history' among the results that follow from the generator. We did not simulate a returning person with a new device, lost history, a changed number or a depleted exemption budget."],
    "Manuscript Sections 6, 7.6 and 8."),
  ...item("M13", "The ablation still overinterprets a small interaction estimate", "Fixed",
    "'The estimated interaction was small in this configuration' is supported. 'Does not depend' is not established by this interval.",
    ["Section 7.2 now reads: 'the estimated interaction of the farm's adaptive caps with the risk engine is small in this configuration (+4 [−0.1, +9.5])', with the interval at its recorded precision."],
    "Manuscript Section 7.2."),
  ...item("M14", "Learning and economics remain conditional rather than deployment evidence", "Done",
    "A one-minute oracle-like baseline result should not stand for the learned deployment procedure. Keep these calculations subordinate to the experimentally observed limitations.",
    ["Section 7.4 now separates the two. The default and tightest cap settings of Figure 4(a) both 'assume a job told the legitimate rate, an oracle'; the deployed job that learns the rate from the pipeline's counters leaks 193 [161, 229] messages with a clean three-week profile, 340 [239, 441] more on a cold start, which leaves the static cap, 106 [62, 151] more with a stale profile and 45 [10, 77] more with one poisoned at the attack's hour. The economics paragraph calls the figures break-even shares under an assumed bill that 'do not measure criminal profit', and says that a share above one under the counter 'says nothing about spreading or exemption reuse'."],
    "Manuscript Sections 7.4 and 7.8."),
  ...item("M15", "Artifact provenance is stronger but the named release is not yet public", "Done in the manuscript; tag push is an author action",
    "Cite the immutable generating commit now and publish the named tag/archive before relying on the release citation. Correct the response's references to the CSV filename.",
    ["Reference 23 and the Data availability statement now give commit 1c277a0 for the results (release 2.8.0) and name release 2.8.1 for the repairs and later analyses; the promise of an archive DOI is removed. The tag is not yet on GitHub because this session cannot push; pushing v2.8.0 (1c277a0) and v2.8.1 is listed as an author action. The per-seed file is counter_study_per_seed.csv, as the Data availability statement gives it. Last round's letter garbled that name in one place; our letter generator treated the underscores as italics markers, which is fixed."],
    "paper/refs.bib (otpguard2026). Manuscript, Data availability."),
  ...item("M16", "The motivating incident supplies no validation", "Partly done: author actions remain",
    "Keep the Source column distinctions and finish the affiliation and operator-confirmation checks.",
    ["Table 1 keeps the Recalled and Review sources, and Section 3 opens with 'This section is motivation, not evidence'. The affiliation, written permission and the operator's confirmation of the Source column remain with the author before submission."],
    "Manuscript Section 3, Table 1."),

  H1("Section 3: exact wording"),
  table([900, 3800, 4400], [
    ["Item", "Revision 4", "Revision 5"],
    ["Q1", "Rerun on fresh seeds with the full sequential grid at every density, the rule selects the same counters under mean or worst-case leakage, a first-time-loss constraint, any single attacker or random mix …", "With the full grid and density-specific attacks (E5) the rule selects the same counters, and so does every other objective we tried on the tuning runs over every setting meeting the target (…), except that at 200 blocks the instant verifier alone, and 3 mixes, favour a sequential setting; on fresh seeds the counter still leaked least of the winners against every attacker … On seeds 300–309 the 1,000-block counter falls 0.12 points below its target, yet no seed-and-conversion cell fails the paired check (the evaluation default minus 0.5 points). (M1, M7)"],
    ["Q2", "For an operator, the results point to a quota set from each block's own traffic, the counter and tests together, which leaked least, and watching for spread, which neither contains.", "Counter and tests together, with a quota set from each block's traffic, is a hypothesis for real traffic, not a recommendation. Section 7.6 gives the four-carrier qualifier and the 1.35-point poisoner cost. (M2)"],
    ["Q3", "… while the farm's adaptive-cap effect does not depend on the risk engine (+4 [−0, +10]).", "… the estimated interaction of the farm's adaptive caps with the risk engine is small in this configuration (+4 [−0.1, +9.5])."],
    ["Q4", "… an observer seeing only its own response times told a send from a refusal with 88 % balanced accuracy (threshold fitted to 22 refusals).", "… a threshold on client response times fitted to one run's 2,497 sends and 22 refusals separated them with 88 % balanced accuracy on that run, a resubstitution value; on three new runs (two vCPUs, nearly every send over the floor), thresholds fitted on one run scored 95 to 99.9 % on the others."],
    ["Q5", "Each address limit, per-number slot, budget reservation and per-block counter slot is one atomic Redis operation, released if a later step refuses …", "Per-number claims and the per-block counter slot are released if a later step refuses, and the hourly budget is reserved only for a message that is sent; address limits and source caps count requests, except that a request Step 11 challenges gives its source-cap count back."],
    ["Q6", "… returns one HTTP 200 body padded to 400 ms.", "… returns one HTTP 200 body after at least 400 ms, a floor that cannot hide longer work."],
    ["Q7", "… so effects apply at most once, and exactly once if the sweep runs within 20 minutes, with one exception (Section 6).", "Each transition records its effects and its time in the same compare-and-set, and a recovery sweep finishes a dead process's work: reputation counts, block-test events and outage observations apply at the transition's time, at most once, and exactly once if the sweep runs within 20 minutes."],
    ["Q8", "… selected at a benign service target, leaked 6 to 48 messages …, against 19 to 452 for sequential tests of verification outcomes …", "… each selected at a benign service target for one traffic density, leaked 6 to 48 messages against four concentrated 20-minute pumpers at 0.06 to 0.43 points of attack-free completion; at the busiest density the default sequential tests of verification outcomes leaked 19 to 452."],
    ["Q9", "Counting sends on the destination beat testing outcomes against concentrated pumpers …", "Counting sends on the destination leaked less in aggregate than our outcome tests against concentrated pumpers, though not reliably against an instantly verifying carrier, and only within the condition of Section 5; …"],
  ]),
  P(""),

  H1("Section 4: numerical consistency audit"),
  table([2600, 6500], [
    ["Reviewer's row", "What changed"],
    ["Old Table 9 caption: 'three new seeds each'", "Table 8's caption now says 'three seeds each'; Section 6 keeps 'six of its seed values had served other robustness points, never selection'; the abstract says 'on seeds and shifted workloads unseen by selection'."],
    ["Protocol seed note", "The protocol file stays as committed (its SHA-256 is recorded). config/counter_protocol_erratum.md, dated, corrects the note beside it and distinguishes new seed-and-workload combinations from new seed values; the README points to it."],
    ["Old Table 8 'best at target'", "'Selected at tuning target', with the 0.16-point evaluation shortfall stated in the text (M7)."],
    ["E5 at 1,000 blocks: −0.1245 against 0/20", "Both references stated in one sentence: the tuning target and the paired check against each evaluation default (M7)."],
    ["Old Table 9 counts", "Table 8 adds percentages: 100, 100, 88, 91 and 65 %."],
    ["K4 for the instant verifier", "An IV column (23/36) and 'holds pooled, not for IV' (M6)."],
    ["Abstract and old Table 8", "The abstract labels the default sequential tests and the density of the 19–452 range, and says each counter was selected for one density (Q8)."],
    ["Old Table 4 against old Table 6a (45.6 against 47.2 %)", "Old Table 6 is now text (Section 7.4); the thirty-seed 45.6 % stays in Table 5 and the ten-seed sweep in Figure 4."],
    ["Section 7.7 against old Table 10", "Old Table 10 is now text; the post-stop loss (46.2 [16.9, 79.8], 406.5 requests hit) and the whole-run loss (48.2) stay separate."],
    ["9,919 against 7,925 runs", "Section 6 calls them two clean invocations and adds that 300 later runs use 2.8.1."],
    ["KS p = 0.05", "0.051."],
    ["E1 combination against the discussion", "M2."],
  ]),
  P(""),

  H1("Section 5: related work and competing approaches"),
  Bullet("**Learned detection (Huh et al.).** Section 2 compares the two on required data (their detector needs labelled traffic; our policies need none), action granularity (per request against per destination block) and observability (request, history and country features against send counts or code outcomes), and says that theirs was not reproduced, so the two are not ranked."),
  Bullet("**Rate and burst policing (RFC 2697).** Kept as an exploratory trade-off (M4)."),
  Bullet("**Hierarchical destination controls.** Section 8: 'Per-client quotas within a block, carrier spend ceilings, bounded exemptions and other sequential statistics lie outside the evaluated policies.'"),
  Bullet("**Other outcome-based detectors.** Section 2 keeps 'so ‘testing’ below means our conversion and speed tests only', and Section 8 and the conclusion say 'our outcome tests'."),
  Bullet("**Counting combined with outcomes.** Reported with its poisoner cost and its exploratory status (M2)."),
  Bullet("**Novelty.** The introduction now lists the contribution as the comparison, its failures and a closed-form condition for when counting beats testing. We claim no new principle for the counter, the tests, the exemption or their combination."),

  H1("Section 6: presentation"),
  Bullet("**Order.** The introduction ends: 'Sections 7.1–7.4 are context for the destination results (Sections 7.5–7.7)'. The condition that explains the destination results now comes before them, in Section 5. We kept Section 7's order so that RQ1–RQ5 stay in sequence, and framed the earlier studies as context, the alternative the reviewer offered."),
  Bullet("**Abstract.** It names the comparator (the default sequential tests), the workload (the busiest density) and that each counter was selected for one density (Q8), and states the closed-form condition."),
  Bullet("**Figure 2.** Enlarged: cell values at 11 pt and tick labels wrapped at 9.5 pt. The material effects are promoted into the text of Section 7.2 with their intervals; the caption keeps the unadjusted-interval statement, and the text no longer reads unique contributions from the heatmap."),
  Bullet("**Figures 4 and 5 (old 4 and 6).** Each panel now has the full text width (panels stacked). Figure 5's caption names the protocol, the density and the evaluation seeds."),
  Bullet("**Figure 6 (old 7).** The caption gives the denominator ('points of the three hot blocks' users'), five seeds, 95 % bootstrap bands, and 'lines join sampled settings'. Panel (b) adds the counter's envelope and the Equation 2 estimate as dotted lines."),
  Bullet("**Old Figure 5 (spread).** Moved to the artifact (paper/figures/fig5_spread.*); its numbers stay in Section 7.5, and Figure 6(b) now carries the same mechanism check for both policies."),
  Bullet("**Tables.** Table 7 (old 8): 'selected at tuning target', units in the caption and 'none by construction for counters' for verdict events. Table 8 (old 9): percentages and the IV column. Table 9 (new): the central attacked-service table the reviewer described, with the counter, the default, the tuned sequential setting, the combination and both buckets. Table 3 (new): the study map, one row per study with its seeds, attack duration and where its results appear; Section 6's protocol paragraph now points to it. Captions of Tables 5, 6 and 7 (old 4, 7 and 8) are shorter, and Table 5 dropped v1's caps-on columns, which Figure 1 shows."),
  Bullet("**Submission readiness.** Reference 23 cites the commit; the DOI promise is gone; the CSV name is correct. The affiliation remains for the author."),
  table([4550, 4550], [
    ["Revision 4", "Revision 5"],
    ["Tables 1, 2, 3, 4", "Tables 1, 2, 4, 5 (Table 3 is the new study map)"],
    ["Table 5 (layer effects)", "Text of Section 7.2"],
    ["Table 6 (cadence, learned baseline)", "Text of Section 7.4"],
    ["Tables 7, 8, 9", "Tables 6, 7, 8"],
    ["Table 10 (poisoner)", "Text of Section 7.7"],
    ["—", "Table 9 (attacked service, new)"],
    ["Figures 1–4", "Figures 1–4"],
    ["Figure 5 (spread)", "Artifact; numbers in Section 7.5"],
    ["Figures 6, 7", "Figures 5, 6"],
    ["Equations 1, 2", "Equations 1, 2; Equations 3 and 4 are new (Section 5)"],
  ]),
  P(""),

  H1("Section 7: the single question"),
  Quote("What nontrivial, externally defensible operating condition does this study establish under which an operator should prefer your selected destination policy at an acceptable service cost, beyond the mechanically obvious fact that a small quota limits traffic to a few blocks?"),
  P("We answer with a bounded condition, part mechanical and part simulated, and say which part is which."),
  P("**Leakage.** Against our sequential tests a pumper on B blocks leaks about L = min(N, kB + λτ) before its first verdict, with k = ⌈h/1.50⌉ = 5 failures per block and τ the time a send stays unresolved (about 2.5 minutes if the carrier never verifies). The default's measured leakage in E4 implies λτ ≈ 95 at that study's attack rate (110 − 5 × 3 on three blocks). Above a verified share of 0.42 with human-like delay, the conversion statistic drifts away from a verdict. A counter of q sends per block per window lets a pumper send at most (1+s)qBw over w windows, whatever the carrier does with the codes. So against a never-verifying carrier the counter leaks less only while B(qw − k) < λτ: at q = 4, fewer than about five blocks over an hour (w = 6) or about 30 over twenty minutes (w = 2). Against outcome-gaming carriers it leaks less until (1+s)qBw reaches their volume. E4 sits on these lines: the counter leaked 71, 240 and 679 messages on 3, 10 and 30 blocks over an hour against an envelope of 72, 240 and 720, and the default 110, 144 and 242 against 5B + 95 = 110, 145 and 245; the maps cross between 3 and 10 blocks over an hour and near 30 over twenty minutes."),
  P("**Service.** A graded counter challenges the share of a block's own sends beyond q in a window, E[(n − q)+]/E[n]. With Poisson sends that share is 0.04 % at half a send per window, 0.43 % at one, 3.8 % at two and 20 % at four (the quota); beyond 2q, where users without another channel are refused, it is 0.84 % at four and 14 % at eight. The simulation converts the share into lost completions: about 0.12 points of a block's users per point of excess at 70 % WhatsApp reachability (0.5, 2.3 and 5.5 points at two, four and eight sends per window), 13.2 points at eight without WhatsApp, and 16 points of the launch blocks' users in a 30-minute launch at three times the normal rate. The cost per point of excess does not rise beyond twice the quota at 70 % reachability (0.13, 0.12 and 0.11 at two, four and eight sends); it rises without WhatsApp (0.13 at four, 0.26 at eight). The same declared criterion (attack-free attributable loss against no policy, on paired traces) is used for every policy compared."),
  P("**Sharing, trust and fallback.** When the pumper shares the blocks with users, users and pumper compete for one quota: K3 and K5 fail, 13 of K3's 17 failing cells at the three busiest points. Every policy leaves the shared blocks' users 5 to 9 points worse off than without the attack. Verified history exempts returning users, which is why they lost nothing under the policies of Table 9 and also why trust builders verifying on random numbers escape the counter (577 messages, as under the default). Fallback matters beyond twice the quota, where users without another channel are refused: at eight sends per window, removing WhatsApp raises the cost from 5.5 to 13.2 points; at four, from 2.3 to 2.5."),
  P("**What is evidence and what is construction.** The envelope (Equation 3) and the crossover (Equation 4) follow from the rules; the paper says so. The constants k and λτ, the cost of an excess send, the effect of competition under attack and the exemption failure are simulation results under assumed behaviour; none is externally validated. The condition's inputs, legitimate sends per block per window and the number of blocks an attack spans, are in an operator's own logs, so an operator can check whether it is inside the region before adopting the counter, and should not adopt it on our calibration alone."),
  P("**So the answer is:** prefer the short-window counter over our outcome tests when (i) legitimate traffic per block stays well below the quota (the share beyond q is small: 0.4 % at a quarter of it), (ii) campaigns are concentrated, B(qw − k) < λτ, or the carrier games outcomes, and (iii) exemptions cannot be bought cheaply. Outside that region the default tests leak less or the counter costs users more. This is a conditional, simulation-supported statement, which is how the paper now makes it (Sections 5, 7.6 and 8)."),

  H1("Appendix A of the report: the reviewer's reproduction"),
  table([3200, 5900], [
    ["Reviewer's check", "Result"],
    ["Pending-batch replay after 601 s (memory store)", "2.8.0: 0 before recovery, 1 after (reproduced). 2.8.1: 0 before and after, batch cleared; an event inside its window counts once at its own time. Repeated on fakeredis and across two instances on a real Redis."],
    ["Previous 256-event crash path", "Still 257 after replay (unchanged test, passing)."],
    ["Simulator invariants and memory-store regressions", "The full suite: 418 tests pass, sixteen of them against a real redis-server (re-run for this letter)."],
    ["Recorded results unchanged by 2.8.1", "scripts/check_reproduction.py replays 102 recorded runs (three per study, both result files, long runs included) with the final 2.8.1 code (package and configuration hash b54e79ea…): all identical in every recorded field (results/reproduction_check.md). The re-selection and attack-free runs were rerun with the same code and give the same numbers; their records carry b54e79ea's hash extended by the driving script (2178bf4a…)."],
  ]),
  P(""),

  H1("Appendix B of the report: disposition of the fourth-round items"),
  table([2300, 1900, 4900], [
    ["Item", "Reviewer's status", "This round"],
    ["M1 Counter outside robustness protocol", "Closed", "Claims now reported by attacker (M6)."],
    ["M2 Service measured only without attack", "Closed", "Three questions separated, with cohorts (M3)."],
    ["M3 Rate separation supplies the answer", "Substantially addressed", "Closed-form condition and its check against E4 (M5, single question)."],
    ["M4 Counter missing from adaptive family", "Closed", "Unchanged."],
    ["M5 Concurrent challenge bypass", "Closed for reproduced path", "Unsolved requests at the second boundary now also tested on a real Redis."],
    ["M6 Replay after 256 later events", "Closed for reproduced path", "Event-time defect fixed (M8); identifiers outlive reversals (M9)."],
    ["M7 Unequal density/grid coverage", "Closed", "Unchanged."],
    ["M8 Arbitrary aggregate objective", "Partly addressed", "Selection repeated under each objective over every eligible setting, union evaluated on fresh seeds (M1)."],
    ["M9 Mean service target", "Partly addressed", "Tuning target, evaluation margin and paired check named separately (M7)."],
    ["M10 Discovery and holdout chronology", "Substantially addressed", "Caption corrected; dated protocol erratum."],
    ["M11 Intervals and model uncertainty", "Addressed as limitation", "Unchanged (M11)."],
    ["M12 Variance decomposition", "Closed", "Unchanged."],
    ["M13 Behavioural realism", "Partly addressed", "Returning-user scope stated (M12); parameters remain assumed."],
    ["M14 Conditional ablation", "Mostly closed", "Independence sentence corrected (M13)."],
    ["M15 Implementation outside simulation", "Open, now disclosed", "Timeout race, reversal and source-cap cases fixed with tests; Step 11 crash semantics tested; M8 fixed (M9)."],
    ["M16 Learning and economics", "Substantially addressed", "Oracle and learned job separated in the text; economics subordinate (M14)."],
    ["M17 Performance and timing scope", "Partly addressed", "Resubstitution stated; held-out check across runs (M10)."],
    ["M18 Provenance", "Mostly closed", "Commit cited; reproduction check; tag push remains an author action (M15)."],
    ["M19 Incident as evidence", "Closed by reframing", "Author checks remain (M16)."],
  ]),
  P(""),
  P("We are grateful for the time this report took. The replay diagnostic found a defect our tests had missed because they counted members rather than times, and the single question made us write down the condition the results had been circling. The paper is more conditional as a result, and we think more useful to an operator who has to decide whether it applies to them."),
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

Packer.toBuffer(doc).then(buf => { fs.writeFileSync("rebuttal_round5.docx", buf); console.log("wrote rebuttal_round5.docx"); });
