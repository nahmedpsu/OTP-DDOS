// Response to the seventh-round Reviewer 2 report. Build: node rebuttal_round7.js -> rebuttal_round7.docx
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

function item(num, title, status, objection, response, where) {
  const color = status.startsWith("Not") ? "9C2B1E" : status.startsWith("Partly") || status.startsWith("Acknowledged") || status.startsWith("Scoped") ? "8A5A00" : "1E6B3A";
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

const REL = "the commit accompanying this letter, tag v2.9.0";

const M1 = item("M1", "The simulator and Redis implement different policies", "Done: stores aligned, differential tests, every study rerun, change report",
    "Choose and justify the intended semantics; make the two backends agree for the behavior being evaluated; add a differential regression that spans expiry while new members keep arriving; regenerate affected raw runs, tuning eligibility, selection, held-out summaries and figures. Publish a change report that identifies which rankings and claims survive. Preserve the old results as historical artifacts.",
    ["**Intended semantics.** Redis's. It is the deployed backend, and a detector that forgets observations still inside its window is a defect, not a design choice. We did not take the alternative of declaring the in-memory rule the algorithm.",
     "**Backends agree.** Release 2.9.0 changes MemoryStore, the store every simulated run uses, to keep state as RedisStore does. Comparing the two stores rule by rule found six more differences that no test had compared, and we aligned those too: a key now lives until the clock passes its expiry time (Redis expires a key when now > expiry; the memory store had expired it at that instant); TTLs are whole seconds and a zero TTL means none; HINCRBY with a TTL gives one only to a hash without one (EXPIRE NX); zadd_max refreshes the TTL even when the score is not raised; a sorted set left empty is deleted; members with equal scores come in member order; scan returns keys sorted, on both stores. The sorted-set expiry the reviewer reproduced is the first of these rules.",
     "**Differential regression.** tests/unit/test_store_parity.py runs every operation on a MemoryStore and on a RedisStore over fakeredis driven by one clock, and compares every result. It includes the reviewer's case (members arriving every 300 s while the first write's 1,200-s TTL runs out), one test per rule above, six random sequences of 400 operations over every store method the pipeline uses, with clock steps that land on expiry instants, and a whole simulation run on both stores. 13 of its 14 tests fail on 2.8.3. tests/integration/test_real_redis.py adds the TTL refresh and EXPIRE 0 on a real redis-server. scripts/check_store_parity.py runs one recorded spec per study on both stores (31 specs, every study, up to 200 simulated minutes): 31 of 31 records are identical in every field (results/store_parity_check.md). The reviewer's two tuning cases now leak 21 and 127 messages, the values the reviewer's intervention produced, and the same on both stores.",
     "**Every study rerun.** Both protocols' studies, the later analyses, the scenarios and the analysis tables were rerun with 2.9.0, with the same seeds, protocols and selection rules; no study was excluded. The 2.8.x results are kept unchanged in results/historical_2.8/.",
     "**What changed, and why.** Of 17,964 runs matched by spec hash and seed, 11,042 are identical, 5,195 differ only in counts outside leakage and legitimate outcomes (outage alerts above all), 810 in legitimate outcomes, and 917 in a leakage count. Total leakage changed in 855 runs and fell in 805 of them. The change concentrates in the sequential-test arms: 472 runs, 288 of them tuning runs of settings that no rule selected, with a median relative change of 43 %. In 471 of those 472 runs, 2.8.x had raised more outage alerts (761 in all, against 50 in 2.9.0), and each alert suspends the block tests. Elsewhere the changes are small: median 2.1 % without a destination policy, 1.4 % for the counters, 1.1 % for the token buckets. The 120 runs without a counterpart belong to the one auxiliary setting whose selection changed (below).",
     "**Which rule mattered.** scripts/store_rule_ablation.py replays 86 recorded runs (three per study, at most 200 simulated minutes) with one 2.8.x rule restored at a time. The released store reproduces all 86 2.9.0 records; restoring the expiry-boundary rule or the tie-order rule changes none of them (results/store_rule_ablation.md). scripts/outage_mechanism_check.py then traces one E5 run whose leakage fell from 115 to 13. Restoring only the 2.8.x sorted-set TTL reproduces 115. The set of known-good verifications on the carrier emptied while failures written later were kept, so the outage detector saw 1 verification against 9 failures across 24 blocks, inferred a carrier outage and suspended the block tests while the pumper's requests went through (results/outage_mechanism_check.md). This is the defect the reviewer reproduced, acting through the outage detector rather than through the block statistic.",
     "**Change report.** scripts/compare_store_change.py writes results/store_change_report.md: every run matched by spec hash and seed and classified (identical; other counts only; legitimate outcomes; leakage), the largest leakage changes, both protocols' selections role by role, the settings whose eligibility at the tuning target changed, the claims C1–C5 and K1–K5, and every entry of the headline-number map, before and after."],
    "store.py (MemoryStore); tests/unit/test_store_parity.py; tests/integration/test_real_redis.py; scripts/check_store_parity.py, compare_store_change.py, store_rule_ablation.py, outage_mechanism_check.py; results/store_change_report.md, store_parity_check.md, store_rule_ablation.md, outage_mechanism_check.md, historical_2.8/. Manuscript Sections 6 and 7, abstract.");

const M2 = item("M2", "The counter bound is applied outside its cold-start assumptions", "Done: warm-start bound derived; both bounds checked on every run",
    "Either validate the cold-start statement on truly empty destination state, or derive and evaluate the warm-start allowance using each block's residual quota and actual overlapping windows. Keep cold-start and warm-start results separate ... Recompute the crossover check after this correction.",
    ["The reviewer's diagnosis is right: a window opened by a legitimate send during the warm-up lets the pumper take its remaining quota before two more windows open in twenty minutes. Section 5 now keeps the two cases apart. Equation 3 is the cold-start bound, stated for 'a pumper that finds its blocks' counters empty'. The new Equation 4 adds, for each block whose window is already open with c_b ≥ 1 slots used, the residual (q − c_b)+: L_c ≤ min(N, qBw + Σ_open (q − c_b)+) ≤ min(N, B(qw + q − 1)). The last form needs no state: a window opened by a legitimate send has used a slot, and after it closes at most w windows open during the attack.",
     "To check each bound against its own assumptions, the simulator now records each attacked block's counter state when the pumper first reaches it (count and seconds left in its window) and the pumper's SMS sent as a client with verified history (block_state_at_first_attack, attacker_sms_exempt; neither changes a run). scripts/check_condition.py checks both bounds on all 100 E4 counter runs (results/condition_check.md). Of the 44 runs in which every block was empty when the pumper arrived, none exceeds Equation 3. Three of the 56 warm runs do, all at seed 302: 30 against 24 (3 blocks, 20 minutes; two of the three blocks held one reservation, as the reviewer found), 78 against 72 (3 blocks, 60 minutes) and 85 against 80 (10 blocks, 20 minutes). No run exceeds Equation 4. One more effect explains the reviewer's seed-303 cases (25 against 24, 73 against 72): in 7 runs the pumper drew 7 SMS in all on numbers that a real user in the same block had verified, so they went out as exempt sends, which no form of the bound covers. Section 7.6 reports both counts.",
     "The crossover check is recomputed with both estimates, per cell and per seed (M3)."],
    "sim.py (block_state_at_first_attack, attacker_sms_exempt); scripts/check_condition.py; results/condition_check.md. Manuscript Section 5 (Equations 3–5), Section 7.6, Figure 3.");

const M3 = item("M3", "Eighteen correct cell means are a limited descriptive result", "Done (wording and analysis)",
    "Say '18 of 18 decisive cell-mean comparisons,' report paired differences near the crossover, and distinguish the algebraic crossover of two simplified quantities from an empirically established switching point.",
    ["On the 2.9.0 runs, with the cold-start estimates, the predicted ordering matches the measured one in 18 of 18 decisive cell-mean comparisons (two ties at N). With the warm-start term it matches in 17 of 18. The miss is the 30-block, 20-minute cell, where the two estimates differ by 0.8 messages and the measured paired difference is 6.6 [−27.2, 42.4]. At the seed level, 76 of 78 decisive comparisons agree under either estimate; the two misses are the quota-paced cases the reviewer identified (3 blocks, seed 302: 24 against 22; 10 blocks, seed 301: 79 against 78). results/condition_check.md gives every cell's paired difference (tests minus counter, measured) with its 95 % bootstrap interval over the five seeds. Near the algebraic crossing these intervals include zero: 38.6 [−5.6, 89.0] at three blocks over an hour.",
     "Section 7.6 now reads: 'With these unfitted inputs Equation 5 ordered the policies' mean leakage in 18 of 18 decisive cells (two ties at N), and with the warm-start term in 17, missing where the estimates differ by 0.8 messages (30 blocks, 20 minutes; measured difference 6.6 [−27.2, 42.4]); per seed, 76 of 78 decisive comparisons agree. The algebraic crossing lies near five blocks for an hour and 30 for twenty minutes, where the nearest measured differences (three and 30 blocks) do not exclude zero; it is not a measured switching point.' Section 5 calls Equation 5 'the algebraic crossing of two simplified quantities, neither an empirically established switching point nor a necessary condition'. The abstract says 'mean leakage' and 'decisive', and the conclusion says 'an algebraic crossing, not a measured switching point'."],
    "scripts/check_condition.py; results/condition_check.md. Manuscript abstract, Sections 5, 7.6, 9.");

const M7 = item("M7", "Statistical units and service costs require restrained interpretation", "Done",
    "Keep uncertainty and cohort sizes alongside any decision-oriented use of this table ... Close rankings and zero-looking rounded costs should not be treated as established equivalence.",
    ["Table 9(a) now gives 95 % bootstrap intervals for leakage and for the attacked-block effects, computed per seed over the four carriers (scripts/run_round5_analyses.py, 'four carriers'), and its caption gives the cohort sizes (all users, about 1,200 a run; the attacked blocks' users, about 18). The text keeps 'on average' for both averages and the human-like carrier's positive harm (1.9 points). The K4 exception stays visible in Table 8's IV column and in the abstract ('all but 13 of 144 cells, all against an instantly verifying carrier'). The limitations now add that 'costs that round to zero are not shown equivalent'."],
    "scripts/run_round5_analyses.py; results/round5_analyses.md. Manuscript Table 9, Sections 7.6 and 8.");

const QS = [
  H1("Section 3: exact sentences"),
  table([700, 3700, 4700], [
    ["Item", "Revision 6", "Revision 7"],
    ["Q1", "We contribute eight gaps recalled from the incident, as motivation only, …", "We contribute eight gaps identified through recollection and subsequent design review, as motivation only, … (the reviewer's wording; Table 1 marks four as Recalled and four as Review)."],
    ["Q2", "A heuristic with constants from the configuration, not fitted, ordered the two policies correctly in all 18 boundary cells where its estimates differ: … so it loses to paced pumpers and to wide, long campaigns.", "For attacks of up to an hour, unfitted estimates ordered the two policies' mean leakage in all 18 decisive boundary cells: the counter loses its advantage against paced or widely spread pumpers."],
    ["Q3", "… each effect type applies at most once, and exactly once if the sweep runs within 20 minutes, at the transition's time: … and a verdict is dated at the event that triggers it.", "… exactly once if the sweep runs within 20 minutes. Reputation counts land in the transition's hour and a block keeps its latest outage failure time, but a block's statistic accumulates in processing order and a verdict is dated at the event that completes the crossing, so a late event can backdate a verdict that contains later evidence, moving its expiry and the next test's start (by ten minutes in one diagnostic). Events arrive in time order on the live path and in every simulated run."],
    ["Q3 (letter)", "… what a replay can still differ in is when the operator learns of the verdict.", "Withdrawn (M4): a replay can also change the verdict's expiry."],
    ["Q4", "Per-number claims and the per-block counter slot are released if a later step refuses, and the hourly budget is reserved only for a message that is sent; …", "Each limit and reservation is one atomic Redis operation, but the enclosing steps are not one transaction: on the normal path a refused request gives back its per-number claims and counter slot, and the hourly budget is reserved only for a message about to be enqueued, a reservation rather than a completed dispatch; a crash between them can leak reservations (Section 6)."],
    ["Q5", "… Equation (4) ordered the policies correctly in all 18 E4 cells where the estimates differ …, and puts the crossover near five blocks for an hour and 30 for twenty minutes, between sampled spreads.", "… ordered the policies' mean leakage in 18 of 18 decisive cells (two ties at N), and with the warm-start term in 17 …; per seed, 76 of 78 decisive comparisons agree. The algebraic crossing lies near five blocks for an hour and 30 for twenty minutes, where the nearest measured differences (three and 30 blocks) do not exclude zero; it is not a measured switching point."],
    ["Q6", "… and the share beyond q, which a graded counter challenges, is E[(1+X−q)+]/(1+m) …", "… and the idealized share beyond the quota is E[(1+X−q)+]/(1+m): 7.3 % at m = q/2 and 27 % at m = q for q = 4. It is not a challenge rate: exempt clients take slots without challenge, and challenge failures, the second tier and earlier gates are ignored."],
    ["Q7", "Carriers that verify with human-like delay, fake receipts or know the thresholds defeated our outcome tests but not a short-window counter, whose allowance, unlike the tests', grows with the windows an attack spans.", "In the scripted workloads, carriers that … defeated our outcome tests but not a short-window counter. Within a verdict's hour the counter's allowance, unlike the tests', grows with the windows an attack spans; over longer campaigns verdicts expire and the tests leak again."],
  ]),
];

const M4 = item("M4", "Backdating a crossing does not establish chronological replay equivalence", "Done: semantics stated, equivalence withdrawn, diagnostic pinned by a test",
    "Explicitly document processing-order accumulation with event-dated verdicts and withdraw equivalence to chronological execution, or implement the stronger semantics and test reordered histories ... Do not claim a stronger guarantee than the algorithm provides.",
    ["We took the first option. The reviewer's diagnostic reproduces: failures dated 0, 1, 2, 3 and 603 s give a crossing dated 603 s in time order, and a crossing dated 3 s, expiring 600 s earlier, when the failure dated 3 s is processed last. Section 4.2 now states the semantics instead of an equivalence: 'Reputation counts land in the transition's hour and a block keeps its latest outage failure time, but a block's statistic accumulates in processing order and a verdict is dated at the event that completes the crossing, so a late event can backdate a verdict that contains later evidence, moving its expiry and the next test's start (by ten minutes in one diagnostic). Events arrive in time order on the live path and in every simulated run.'",
     "The module notes of feedback.py now say the same, with the reviewer's example and its effect on expiry, the next test's start, escalation (judged against the verdict active at the earlier date) and later evidence dated before the crossing (recorded, not counted). test_block_statistic_accumulates_in_processing_order (tests/unit/test_seventh_round.py) pins both orders on the memory store and fakeredis, so the behaviour cannot change silently. The sentence of the sixth-round letter that the reviewer quoted ('what a replay can still differ in is when the operator learns of the verdict') was wrong, and we withdraw it: a replay can also change the verdict's expiry."],
    "feedback.py (module notes, _block_event); tests/unit/test_seventh_round.py. Manuscript Section 4.2.");

const M5 = item("M5", "Simulation realism remains the limiting scientific scope", "Acknowledged: conditional claims kept",
    "Retain those [missing-fallback and launch stresses] prominently and avoid general service-cost recommendations. The defensible contribution is a conditional comparison inside this generator.",
    ["We agree, and the paper claims no more. Section 7.6 keeps both stresses in the paragraph that reports the counter's service cost ('without WhatsApp eight sends cost …', 'A 30-minute launch at three times the normal rate costs its blocks' users … points'). Section 8 calls the combined policy 'a hypothesis for real traffic, not a recommendation' and ends the limitations with 'Replaying real traffic is the experiment this paper most needs.' Every service figure is reported for the simulated users and the stated recovery channels."],
    "Manuscript Sections 6, 7.6 and 8.");

const M6 = item("M6", "The evaluated attacker set is extensive but not an optimization result", "Done (wording)",
    "Keep that qualification attached to economic and operational conclusions as well ... the abstract's 'wide, long campaigns' still compresses that distinction too aggressively.",
    ["The abstract no longer says 'wide, long campaigns'; it bounds the heuristic to attacks of up to an hour ('For attacks of up to an hour, unfitted estimates ordered the two policies' mean leakage in all 18 decisive boundary cells: the counter loses its advantage against paced or widely spread pumpers'), and Section 8 names the attackers it concerns (pumpers that solve no challenge and hold no exemption). The economics paragraph now reads 'These are break-even shares for scripted attackers under assumed prices, not bounds or criminal profit'. Section 7.8 opens with 'These scripted adaptations' leakages are not bounds.' The 360-minute human-like result is reported separately in Section 7.6 and is not used to extend the one-hour heuristic."],
    "Manuscript abstract, Sections 7.6, 7.8 and 8.");

const M8 = item("M8", "Competing mechanisms remain incompletely compared", "Scoped (the reviewer's second option)",
    "A matched service-constrained token-bucket comparison would be the most useful additional baseline ... If that is outside scope, the present explicit restriction to the implemented policies is acceptable.",
    ["We kept the restriction and made it explicit where the token buckets are reported: 'with two untuned settings neither limiter dominates, and we rank only the implemented policies.' Section 2 restricts 'testing' to our conversion and speed tests, and the abstract and conclusion compare the counter with 'our tests'. A tuned token bucket would need its own selection under the first protocol; we name it in Section 8 among the policies outside the evaluation rather than add an unselected arm."],
    "Manuscript Sections 2, 7.6 and 8.");

const M9 = item("M9", "Implementation evidence supports a prototype only", "Done (wording)",
    "The unconditional reservation wording in Section 4.1 is therefore still too strong.",
    ["Section 4.1 now reads: 'On the normal path a refused request gives back its per-number claims and counter slot, and the hourly budget is reserved only for a message about to be enqueued, a reservation rather than a completed dispatch; a crash between them can leak reservations (Section 6).' Section 6 keeps 'Step 11 is still not one transaction' and 'The implementation is a research prototype', and states that the real-Redis tests cover 'specific interleavings of two instances, not all'. The timing paragraph is unchanged in substance."],
    "Manuscript Sections 4.1, 6 and 7.8.");

const RELATED = [
  H1("Section 5: related work and competing approaches"),
  Bullet("**Huh et al.: incremental knowledge.** Section 2 now states it: 'Their data show that destination aggregation is informative; what we add is a controlled comparison of two label-free ways to act on it per block, from send counts or code outcomes, and of their cost to users who share a block. Theirs was not reproduced, so the two are not ranked.' The constraint that keeps their detector from answering our question is in the preceding sentence: it needs labelled traffic and acts per request, whereas the policies compared here need no labels and act per destination block. No superiority claim is made."),
  Bullet("**Rate-limiting alternatives.** See M8: the restriction to the implemented policies is now explicit, and tuned token buckets are named among the policies outside the evaluation."),
  Bullet("**Outcome-based alternatives.** Unchanged: Section 2 says windowed statistics and confidence sequences 'were not evaluated, so 'testing' below means our conversion and speed tests only', and the claims compare the counter with our tests."),
  Bullet("**Allocation within shared destinations.** Section 8 names per-client quotas within a block, carrier spend ceilings and bounded exemptions as outside the evaluated policies, and Section 7.6 concludes only that no evaluated policy shields a block an attacker shares."),
];

const PRESENTATION = [
  H1("Section 6: presentation and organisation"),
  Bullet("**Figure 2 (now Figure 1).** The caption now defines the bars on both axes ('Bars: 95 % bootstrap intervals over seeds', resampling the seed) and the vertical quantity ('its 20-minute leakage summed over the four concentrated pumpers' runs of a seed (not one combined attack)'). The vertical bars were previously the sums of the four attackers' interval endpoints, which is not an interval of the sum; paper/figures.py now bootstraps the per-seed sum. 'Unlabelled points: other sequential settings' explains the cluster near the default. To make room within the word limit, revision 6's Figure 1, whose numbers duplicated Table 5, is now supplementary Table S1 (results/design_table.md) with its 95 % intervals for every design and attacker."),
  Bullet("**Figure 3 (now Figure 2).** The caption stands alone: 'Matched comparison, first protocol, 200 blocks, evaluation seeds 0–9, 20-minute attacks: for each selected setting and each concentrated pumper, the setting's leakage minus the default's, paired per seed (negative: leaks less), with 95 % bootstrap intervals over seeds.'"),
  Bullet("**Figure 4 (now Figure 3).** Panels (b) and (c) now show both attack durations, 20 and 60 minutes, with 95 % bootstrap intervals over seeds on every measured point, and the estimates for the full-rate pumper: Equation 2 for the tests and both counter bounds, cold start (Equation 3) and warm start (Equation 4). The twenty-minute cells the reviewer found above the old bound are therefore visible, together with the bound that covers them. The caption keeps 'lines join sampled settings and do not locate a crossover', and the prose follows it (Q5)."),
  Bullet("**Table 9.** The caption now says which quantities carry intervals ('Brackets: 95 % bootstrap intervals over seeds'), defines every column (all users, about 1,200 a run; 'block', the attacked blocks' users, about 18 a run; 'Benign', the attack-free cost against no policy), and says that in (a) leakage is summed and harm averaged over the four carriers. Panel (a) now gives intervals for leakage and for the block-level effects, computed per seed over the four carriers (scripts/run_round5_analyses.py, 'four carriers')."),
  Bullet("**Table 5.** The body is now a clean comparison without exceptions in the caption: v1, the block-limit design and v2 with caps lifted, and v2 with caps on, for all nine attackers (the aged-fingerprint row is now in the body). Every design against every attacker, with caps lifted and on, is supplementary Table S1 (results/design_table.md), referenced from the caption."),
  Bullet("**Generated tables.** Tables 5, 6, 7, 8 and 9 are now written by scripts/paper_tables.py from the result files and input by the manuscript, so no result table is copied by hand."),
  Bullet("**Table order and front matter.** Tables now appear in numerical order. The abstract is shorter and the keywords stay on the first page. The affiliation remains for the author."),
  Bullet("**Section 3 and Table 1.** The introduction now matches Table 1's provenance (Q1). Permission for the incident narrative, or its removal, remains an author action."),
  Bullet("**Artifact provenance.** Reference 22 now cites version 2.9.0 (tag v2.9.0), notes that it produced the results and that the 2.8.0 results (commit 1c277a0) are kept in results/historical_2.8. Every run record carries the code hash of the code that produced it."),
];

const children = [
  new Paragraph({ children: [new TextRun({ text: "Response to the seventh-round report of Reviewer 2", bold: true, size: 32 })], spacing: { after: 120 } }),
  P("**Manuscript:** Counting Versus Testing the Destination: A Simulation Study of Layered Defences Against SMS OTP Flooding and Pumping. **Journal:** Computers & Security."),
  P(`**Reviewed:** manuscript revision 6 and the 2.8.3 bundle (aaf5c36). **Revised:** manuscript revision 7 and release 2.9.0 (${REL}). Every simulated result in revision 7 comes from 2.9.0; the 2.8.x results are kept unchanged in results/historical_2.8/. Table, figure and equation numbers refer to revision 7: Equation 4 is new (the warm-start bound), so the crossing of revision 6's Equation 4 is now Equation 5. Revision 6's Figure 1 (leaked share by design) is now supplementary Table S1 with its intervals, so its Figures 2, 3 and 4 are now Figures 1, 2 and 3; table numbers are unchanged.`),

  H1("Summary"),
  P("We thank the reviewer for a seventh report, and for saying plainly what would settle the matter. We did what the closing question asks. The in-memory store now keeps state as Redis does, differential tests show the two stores agree operation by operation and on whole simulations, every study was rerun, and a change report compares every run, selection, claim and headline number before and after. The counter's bound is now checked against its own assumptions, with a warm-start form for windows that were already open when an attack began."),

  P("**Manuscript.** Revision 7 has 7,992 words from title to references inclusive (7,938 by a whitespace count; 24 pages in the review format), within the 8,000-word limit, with the same scope, studies and claims as revision 6. The highlights are not in the manuscript. Five result tables are now generated from the result files (Section 6 of this letter)."),

  H1("Answer to the closing question"),
  Quote("After you make the simulator and the claimed implementation obey the same state-retention rules, and account for the counter windows already active when attacks begin, do the selected policies, service-target conclusions and counting-versus-testing crossover still hold?"),
  P("**Yes, the selected policies, the service-target conclusions and the crossover hold. One secondary result changed, in the tests' favour.**"),
  Bullet("**Selections.** Under both protocols and at every density the selection rule picks the same settings, and no setting gained or lost eligibility at the tuning target (30, 12 and 16 eligible settings under the first protocol, as before). The alternative objectives of the fifth-round analysis pick the same winners. One auxiliary comparison setting moved: the sequential setting matched to the default's false alarms at unbounded credit is now T300 cinf instead of T1000 cinf. No claim in the paper uses it; it appears only as an unlabelled point in Figure 1 (revision 6's Figure 2)."),
  Bullet("**Claims.** Every claim keeps its count: C1–C5 108/108, 34/36, 36/36, 18/18, 36/36; K1–K5 144/144, 36/36, 127/144 (fails), 131/144 (holds pooled, 23/36 for the instant verifier), 93/144 (fails)."),
  Bullet("**Service-target conclusions.** The selected counters' benign costs are unchanged (0.06 to 0.43 points). The counter still fails both service-under-attack claims. The first protocol's tuned sequential setting still misses the target on the evaluation seeds: by 0.18 points instead of 0.16, while raising 334 false verdict events a day instead of 314. Table 9's attacked-service effects move by at most 0.12 points."),
  Bullet("**Crossover.** With the cold-start estimate, the check orders the policies' mean leakage correctly in 18 of 18 decisive cells. With the warm-start term it does so in 17 of 18 (M2, M3). Per seed, 76 of 78 decisive comparisons agree. The crossover is stated as an algebraic crossing, not a measured switching point."),
  Bullet("**What changed.** On the second protocol's evaluation seeds, the sequential settings re-selected under other objectives now leak 15 and 16 messages against the instantly verifying carrier, where 2.8.x recorded 49 and 50. The counter leaks 25. So the counter no longer 'leaked least of the winners against every attacker'. Section 7.6 now reads 'against every attacker but the instant verifier (25, against 15 and 16)'. This agrees with the first protocol, where the default already stopped that carrier at 19 against the counter's 24, and with K4's instant-verifier exception. The old figures came from the store defect: with the sorted-set TTL set by the first write, the outage detector's set of known-good verifications emptied, the detector saw conversion collapse, and it suspended the block tests (M1 traces one run: 115 messages with the 2.8.x rule, 13 without)."),
  table([4300, 2400, 2400], [
    ["Quantity (results/store_change_report.md)", "2.8.x", "2.9.0"],
    ["Runs: identical / other counts only / legitimate outcomes / leakage (17,964 matched; 120 without a counterpart)", "–", "11,042 / 5,195 / 810 / 917"],
    ["Selections and eligibility at the tuning targets, both protocols", "–", "unchanged (one auxiliary setting, above)"],
    ["Claims C1–C5, K1–K5", "–", "unchanged counts"],
    ["Matched tuning, seed 101, T3000 cinf, instant verifier (reviewer's case)", "268", "21"],
    ["E5 tuning, seed 101, uniform, T100 c1, never verifies (reviewer's case)", "218", "127"],
    ["Default verdict events a day, 200 blocks, 65 % conversion", "5.8", "6.5"],
    ["Selected T300 c0: verdict events a day; miss of the tuning target", "314; 0.16 pp", "334; 0.18 pp"],
    ["E1 no-policy leakage, four carriers summed; default", "5,785; 1,164", "5,509; 1,149"],
    ["E1 poisoner, extra harm to all users: default; counter + tests", "0.97; 1.35", "1.09; 1.43"],
    ["E3, 360 minutes, human-like carrier under the default (SMS an hour)", "789", "753"],
    ["E5 re-selected sequential winners vs the instant verifier, fresh seeds (counter 25)", "49, 50", "15, 16"],
    ["Headline-number map entries changed", "–", "10 of 85"],
  ]),
  P("The other entries of the headline-number map are unchanged, and the manuscript uses the 2.9.0 values throughout. Total leakage changed in 855 runs and fell in 805; most of these are sequential-test runs in which 2.8.x had raised false outage alerts (M1).", { spacing: { before: 160, after: 120 } }),


  H1("Section 2: methodological weaknesses"),
  ...M1, ...M2, ...M3, ...M4, ...M5, ...M6, ...M7, ...M8, ...M9,
  ...QS,
  H1("Section 4: numerical consistency audit"),
  table([2600, 3200, 3300], [
    ["Row", "Finding", "Resolution"],
    ["Introduction vs Table 1", "Eight recalled gaps vs four Recalled and four Review", "Q1: 'eight gaps identified through recollection and subsequent design review'."],
    ["Equation 3, 3 blocks, 20 min", "Bound 24; seed 302 leaks 30; seed 303 leaks 25", "Seed 302 started warm (two blocks with one reservation each): within Equation 4. Seed 303's extra message went to a real user's trusted number in the pumper's block, an exempt send no bound covers. Both now reported (M2)."],
    ["Equation 3, 3 blocks, 60 min", "Bound 72; seeds 302 and 303 leak 78 and 73", "Same two causes; no run exceeds Equation 4."],
    ["Equation 3, 10 blocks, 20 min", "Bound 80; seed 302 leaks 85; mean 80.8", "Warm start (two of ten blocks open); within Equation 4."],
    ["Reference 22", "Stale version", "Now cites 2.9.0 (tag v2.9.0) as producing the results and keeps the 2.8.0 commit for the historical results."],
  ]),
  P("The rows the reviewer marked as differences, not contradictions, remain consistent after the rerun: 18 of 18 cell means and 76 of 78 seed comparisons are both reported, with their units; the 0.16-point target miss is now 0.18 and still stated; K4's 131/144 pooled and 23/36 for the instant verifier both stand; Table 7's twenty-minute counter leakage (24) and Table 9a's sixty-minute four-carrier sum (403) are different estimands, now said in Table 9's caption; the reference arms of Table 9 are named in its caption."),
  ...RELATED,
  ...PRESENTATION,
  H1("Appendix: disposition of the sixth-round items"),
  table([2400, 2300, 4400], [
    ["Item", "Reviewer's status", "Now"],
    ["M1 Unequal stopping times", "Substantially repaired", "Warm-start validation done (M2)."],
    ["M2 Fitted crossover constants", "Repaired as to fitting", "Uncertainty reported per cell (paired intervals) and per seed; applicable state checked on every run (M2, M3)."],
    ["M3 Poisson window model", "Repaired in the formula", "Exemption qualification added (Q6)."],
    ["M4 Outage replay", "Closed", "Unchanged."],
    ["M5 Verdict time", "Repaired for the reported case", "Equivalence wording withdrawn; processing-order semantics stated and tested (M4)."],
    ["M6–M9", "Limitations / scoped", "Kept conditional; restrictions made explicit (M5–M9)."],
    ["New: backend expiry", "Publication blocker", "Stores aligned, differential tests, every study rerun, change report (M1)."],
  ]),
  H1("What remains with the author"),
  Bullet("The affiliation on the title page."),
  Bullet("Written permission to describe the incident, or removal of the incident narrative (Section 3, Table 1); Table 1's Source column to be confirmed."),
  Bullet("The highlights file, and the tag v2.9.0 with a release carrying results/CHECKSUMS.sha256."),
];

const end = [
  P(""),
  P("We are grateful for a report that named the experiment it needed. Running it took longer than another rewording would have, and it is the answer we should have given in the sixth round."),
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
    children: children.concat(end) }]
});

Packer.toBuffer(doc).then(buf => { fs.writeFileSync("rebuttal_round7.docx", buf); console.log("wrote rebuttal_round7.docx"); });
