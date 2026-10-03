// Response to the sixth-round Reviewer 2 report. Build: node rebuttal_round6.js -> rebuttal_round6.docx
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

const R1 = "[2.8.2 commit]";   // fill in: the repository commit with the M4 repair, the M5 documentation and scripts/check_condition.py
const children = [
  new Paragraph({ children: [new TextRun({ text: "Response to the sixth-round report of Reviewer 2", bold: true, size: 32 })], spacing: { after: 120 } }),
  P("**Manuscript:** Counting Versus Testing the Destination: A Simulation Study of Layered Defences Against SMS OTP Flooding and Pumping. **Journal:** Computers & Security."),
  P(`**Reviewed:** manuscript revision 5, bundle branch 1383589 and tag v2.8.1 (c34375f); results produced by release 2.8.0 (commit 1c277a0). **Revised:** manuscript revision 6, in the commit that accompanies this letter, and release 2.8.2 (${R1}), which carries the implementation repair for M4, the documented verdict semantics for M5, and scripts/check_condition.py with its output results/condition_check.md. No simulated result changes. Table, figure and equation numbers refer to revision 6 unless marked 'old'; Section 6 of this letter maps old figure numbers to new ones.`),

  H1("Summary"),
  P("We thank the reviewer for a sixth report and for two more counterexamples precise enough to rerun. Both reproduced. An older outage observation replayed after a newer failure on the same block moved the block's latest failure time from 900 back to 0, so at 1,801 seconds the 1,800-second distinct-block window counted no block (M4). A replayed failure that completed a crossing issued its verdict at the recovery time, not the transition's (M5). The principal objection was also right. Revision 5 presented an inequality between the counter's bound and the tests' first-verdict estimate as a necessary condition, used an intercept inferred from the same E4 runs it was said to predict, and attached a Poisson service share to windows the code does not use."),
  P("**What changed.** (1) Section 5 is now 'Leakage estimates and a heuristic crossover'. It defines one estimand, the SMS sent to a pumper's numbers over an attack of T minutes from a cold start by a pumper that solves no challenge and holds no verified history; states the counter's actual windows (opened by a block's first reserved SMS); writes Equation 3 as a bound (≤); and calls Equation 4 a heuristic crossover between a bound and an approximation, 'not a necessary condition'. (2) Nothing is fitted any more. τ comes from the configuration (resolution timeout, delivery delay and half the timeout worker's period: 2.55 minutes) and λ and N from each run's offered requests. With these inputs Equation 2 gives 105, 139 and 240 messages against the measured 110, 144 and 242 on 3, 10 and 30 blocks, and Equation 4 orders the two policies correctly in 19 of the 20 E4 cells. Figure 4's overlays are now these per-run estimates. (3) The service share is derived for the implemented, arrival-anchored windows (7.3 % and 27 % at m = q/2 and m = q, not 3.8 % and 20 %), and the 0.12-point conversion factor is gone. (4) Section 4.2 states each effect type's semantics separately. Verdicts start at processing time, by design and now documented; M4 is repaired in 2.8.2 with a two-send regression test. (5) The wording items Q1–Q10 are corrected. Table 9 is split into a four-carrier panel and a poisoner panel with named reference arms and intervals, and Figure 5 is split into two full-width figures. The ablation grid, dilution and trade-off figures move to the artifact, so that the destination comparison comes sooner."),
  P("**The closing question.** We give a narrow answer, separating the algebraic part from the behavioural part, and Section 7 of this letter sets it out. Within its stated scope, the heuristic predicts something the elementary quota argument does not. A slow or paced pumper on a few blocks is held more tightly by the tests than by the counter (23 against 71 messages on three blocks in an hour), because the tests' leakage is dominated by sends in flight, λτ, and that term shrinks with the rate. A fast pumper on the same blocks is held more tightly by the counter (71 against 110). The crossover moves as λτ/(qw − k) with the horizon. The check that it is not a restatement of the simulation is that every constant comes from the configuration or the run's own offered requests, none from E4's leakage, and the ordering still matches in 19 of 20 cells from 3 to 300 blocks and 20 to 60 minutes. The same unfitted Equation 2 was checked earlier on a different study (the main evaluation's 18 spread configurations, seeds 0–9), where it erred by 1.6 to 7.9 messages per run in the ten unsaturated ones. It remains a check inside one simulator, not external validation, and the paper says so."),
  P("**Manuscript.** The scope is unchanged. The paper is 7,996 words from the title to the end of the reference list, counting tables, captions, declarations and references (alphanumeric tokens in the compiled PDF, figures as placeholders); a whitespace count gives 7,932. It compiles without overfull boxes in 24 pages."),

  H1("What we could not do, or did only in part"),
  Bullet("**External validation (M6).** No incident logs or real traffic. The new check fixes the constants independently of E4, but it runs on the same generator; it shows the heuristic is not fitted, not that it transfers."),
  Bullet("**Event-time verdicts (M5).** Not implemented. We chose processing-time verdicts and narrowed the claims to match (M5)."),
  Bullet("**A comparison matrix (related work).** Not added, to stay within the word limit. Section 8's limitations name the policy classes outside the evaluation, and the conclusions refer only to the policies evaluated."),
  Bullet("**Token-bucket calibration and other comparators (M8).** Unchanged: exploratory, untuned, and not used for a ranking."),
  Bullet("**Author actions before submission.** The affiliation; written permission to describe the incident, or removal of the incident narrative; confirmation of Table 1's Source column; the highlights file; pushing the tags v2.8.0 (1c277a0), v2.8.1 (c34375f) and v2.8.2, and publishing a release with checksums of the results files (optionally a Zenodo DOI)."),

  H1("Section 2: methodological weaknesses"),
  ...item("M1", "The central comparison uses different stopping times", "Done: claim repaired",
    "Define one estimand ... Either derive both policies under those conditions, with appropriate bounds, or call Equation (4) a heuristic crossover between simplified estimates. Replace 'only while,' 'decides' and 'follow from the rules' accordingly. Explain explicitly that the tests also incur a cost proportional to B.",
    ["**Estimand and assumptions.** Section 5 opens: 'We compare the SMS sent to a pumper's numbers over an attack of T minutes from a cold start, by a pumper that solves no challenge and holds no verified history.' The counter's windows are stated as the code implements them ('opens a window with a block's first reserved SMS and closes it after the window length'). Equation 3 is now a bound, L_c ≤ min(N, qBw) with w = ⌈T / window⌉, for that pumper; the text adds that 'solving challenges doubles the bound, and verified history exempts a client from it'. The challenge multiplier is therefore fixed at zero in the displayed algebra.",
     "**Stopping time.** Equation 2 is leakage before the first verdict. Section 5 now says when it is also the campaign total: 'Judged, such a pumper is held for the verdict's hour, so for T ≤ 60 Equation 2 also estimates the attack's total; it ignores prior credit and outage suspension.' The E4 records support this within scope. The default leaked the same over 20 and over 60 minutes on 3, 10 and 30 blocks (110, 144 and 242 both times), because a pumper that declines challenges stays held by the first stage. For longer attacks, challenge solvers or exempt identities the statement is not made.",
     "**The inequality.** Equation 4 is introduced with 'While neither reaches N', which restores the truncation. It is followed by 'a heuristic crossover between a bound and an approximation, not a necessary condition: other limits can hold either policy below its estimate.' 'Only while', 'decides' and 'follow from the rules' are gone; the last now reads 'The forms of Equations 3 and 4 and k follow from the rules, τ from the configuration and λ from the attack'. 'Both estimates grow with B' states the tests' kB term, and the abstract's 'while the tests' does not' is removed (Q1)."],
    "Manuscript Section 5 (Equations 2–4), Section 7.6 (paragraph beginning 'Attack-free'), Section 8, abstract and conclusion."),
  ...item("M2", "The operating map partly calibrates the explanation used to explain it", "Done: no fitted constant; independent inputs",
    "Label the 95-message intercept as fitted from E4 ... Make the script and equations use the same N and horizon, or disclose the empirical cap in the caption. If predictive validity remains a contribution, estimate constants on one subset and report errors on genuinely separate rates, delays and durations.",
    ["We removed the fit instead of labelling it. τ is now taken from the configuration: the resolution timeout (120 s), the delivery delay (3 s) and half the timeout worker's period (30 s), 2.55 minutes in all. λ and N are each run's own offered requests over the attack minutes, and B is the blocks it requested. This is the parameterisation the main evaluation's spread study already used (otp_guard.evaluation.model.predicted_leak). E4's attack rate is randomised per seed (about 18 to 59 requests a minute), so λτ is about 90 on average, not a constant fitted to one point.",
     `scripts/check_condition.py (${R1}) evaluates Equations 2, 3 and 4 for every recorded E4 security run from these inputs. It uses N, not the no-policy arm's measured leakage, as the cap, and min(N, …) in both equations, and writes results/condition_check.md. Results: the tests' estimate is 105, 139 and 240 against measured 110, 144 and 242 at 3, 10 and 30 blocks over an hour, and the counter's bound 72, 240 and 720 against 71, 240 and 679. The predicted ordering matches the measured ordering in 19 of 20 cells: 3 to 300 blocks, 20 and 60 minutes, full-rate and quota-paced pumpers. The exception is 300 blocks over 20 minutes, where both estimates equal N and the measured totals are 673 and 676. For paced pumpers the tests' estimate is low by about 20 % (18 against 23 on three blocks), and the ordering still holds.`,
     "Figure 4's dotted lines are now Equation 3's bound and Equation 2's first-verdict estimate, evaluated per run from these inputs ('nothing fitted'). The caption says that lines join sampled settings and do not locate a crossover. The text places the crossover 'between sampled spreads'. Part D of scripts/run_round5_analyses.py, which used the empirical cap and the fitted intercept, is superseded by this check; its table remains labelled 'capped by none'.",
     "The main evaluation's spread study is a separate check with the same unfitted τ: 18 configurations on seeds 0–9, errors of 1.6 to 7.9 messages per run (1 to 13 %) in the ten unsaturated ones (Section 7.5). These are different seeds, attack rates and range layouts from E4. We still regard all of this as internal evidence."],
    `scripts/check_condition.py and results/condition_check.md (${R1}); paper/figures.py (unfitted_estimates). Manuscript Section 5, Section 7.6, Figure 4.`),
  ...item("M3", "The Poisson service calculation does not describe the implemented windows", "Done",
    "Specify whether n means offered requests, eligible attempts or admitted SMS, and whether its window is exogenous or arrival-anchored ... Reassess the approximately 0.12 conversion factor.",
    ["Section 5 now says what the code counts and when its window starts: 'In the code every send takes a slot, verified clients' included.' The window opens with a block's first reserved SMS. Under the idealisation the reviewer described (a homogeneous Poisson stream with mean m per window, every send reaching the counter), a window holds 1 + X sends and the share beyond q is E[(1 + X − q)+]/(1 + m): 7.3 % at m = q/2 and 27 % at m = q for q = 4, matching the reviewer's 7.27 % and 26.96 %. The text adds: 'This idealization ignores challenge failures, which take no slot, and earlier gates.'",
     "The 0.12-points-per-point factor is removed. Section 7.6 now reports the measured losses (2.3 points at four sends per window and 5.5 at eight) as 'far below the idealized share beyond the quota (27 % at four), since most challenged users complete or switch to WhatsApp'. It no longer converts one into the other."],
    "Manuscript Section 5 (last paragraph), Section 7.6."),
  ...item("M4", "Replay can erase the recency of a newer failure on the same block", `Fixed in 2.8.2 (${R1})`,
    "Preserve the maximum relevant event timestamp per block atomically ... Add a two-send, same-block delayed-replay regression. Preserve the already-fixed behavior that an old observation alone cannot re-enter the short receipt window.",
    ["Reproduced on 2.8.1 as described: the block's score went from 900 back to 0, and at 1,801 seconds the distinct-block window counted no block. In 2.8.2 the distinct-block set keeps the larger time when a block's member already exists: ZADD with GT on Redis, the same rule on the memory store. A replayed older failure therefore cannot move a block's latest failure time back. Per-send observations keep their own time, as in 2.8.1.",
     "Tests: test_replayed_older_failure_keeps_the_blocks_latest_failure_time (the reviewer's two-send sequence; it fails on 2.8.1) and test_replayed_older_failure_alone_does_not_refresh_its_block (the 2.8.1 behaviour is kept), both on the memory store and fakeredis, and test_replayed_older_failure_keeps_the_blocks_latest_failure_time_across_instances on a real Redis. The simulator never crashes a process and its event times are monotonic, so the change cannot alter a recorded result; the reproduction check was rerun on 2.8.2.",
     "Section 4.2 says: 'Reputation counts and outage observations apply at the transition's time, a block keeping its latest failure time'. Section 6 lists the repair."],
    `store.py (zadd, gt); feedback.py (_outage_record); tests/unit/test_sixth_round.py; tests/integration/test_real_redis.py (${R1}). Manuscript Sections 4.2 and 6.`),
  ...item("M5", "Block-test verdicts still use recovery time", "Done: processing-time semantics chosen and documented",
    "Choose and document the intended semantics. If verdicts intentionally begin at processing time, narrow the manuscript and rebuttal while retaining event-time accounting for reputation and outage windows.",
    ["We chose processing-time verdicts. A failure that reaches the block late is applied once, and a verdict it triggers starts when it is applied, with its full lifetime from then. A late observation can reasonably trigger action now, and replaying the block statistic at event time would need reordering rules we have not specified or tested. Section 4.2 now separates the components: 'each effect type applies at most once, and exactly once if the sweep runs within 20 minutes. Reputation counts and outage observations apply at the transition's time, a block keeping its latest failure time; block-test events apply when processed, so a verdict they trigger starts then.'",
     `feedback.py's module notes state the same, and test_replayed_failure_that_completes_a_crossing_starts_its_verdict_when_applied pins it (${R1}). In that test four failures are applied, the fifth transition dies before its effects, and recovery 600 seconds later applies it once. The verdict starts at the recovery time with the configured lifetime from then, and a second sweep changes nothing. We claim exactly-once application, not equivalence to timely processing.`],
    `feedback.py (module notes); tests/unit/test_sixth_round.py (${R1}). Manuscript Section 4.2.`),
  ...item("M6", "Simulation realism remains the limit on usefulness", "Partly done: scope stated; no new data",
    "Keep every practical conclusion conditional on them. In particular, 'returning users lost nothing' describes the exempt identities simulated.",
    ["Section 7.6 now reads 'Returning users, simulated as identities with verified history, lost nothing under these policies.' Section 6 now names the parameters with published counterparts and those without. Genuine conversion matches one provider's 68 % or more. The never-converting attack destinations and identity churn of Huh et al. are shared by our non-verifying pumpers and one-use farm. The rest are assumptions. Section 3 still says the incident is motivation, not evidence. The contribution list calls it 'eight gaps recalled from the incident, as motivation only' and lists the heuristic last, as a heuristic checked against the simulation (Q2)."],
    "Manuscript Sections 1, 6, 7.6 and 8."),
  ...item("M7", "Selection robustness and uncertainty are still conditional", "Done (wording)",
    "Avoid turning 'leaked least' into demonstrated statistical superiority for close comparisons ... describe averages as averages. A net gain does not imply that nobody was denied service.",
    ["The re-selection paragraph keeps 'leaked least of the winners', with the instant-verifier numbers (25 against 49 and 50), and makes no claim of statistical superiority. Table 8's caption keeps the dependent-cell warning. Section 7.6 now says the counter 'cost all users nothing on average and gained the attacked blocks' users 3 points on average', adds 'with the human-like carrier alone it cost them 1.9', and says 'none [of the evaluated policies] shields a block an attacker shares'. Table 9's caption names its averages and points to the per-carrier values and the gross losses and gains in the artifact."],
    "Manuscript Section 7.6, Tables 8 and 9."),
  ...item("M8", "The competing policy space remains limited", "Partly done: scope stated",
    "They do preclude a general conclusion that counting beats testing or that the window counter is the best limiter available.",
    ["No new comparator. The abstract, Section 8 and the conclusion compare the counter with 'our tests' or 'our outcome tests'. Section 2 keeps ''testing' below means our conversion and speed tests only'. The limitations list per-client quotas, carrier spend ceilings, bounded exemptions and other sequential statistics as outside the evaluated policies. The token buckets stay exploratory ('with two untuned settings, neither limiter dominates')."],
    "Manuscript Sections 2, 7.6, 8 and 9."),
  ...item("M9", "Timing and deployment evidence remain narrow", "Done (wording); author items remain",
    "Six ordered train/test pairs reuse three runs; they are not six independent replications. The results establish an observable separation in that setup, not its general accuracy in deployment.",
    ["Section 7.8 now ends: 'thresholds fitted on one run scored 95 to 99.9 % on the others (six ordered pairs of three runs): a separation on that machine, not a deployment accuracy.' The prototype limits (Step 11, live vendors, App Attest enrolment) stay in Section 8. The affiliation and the incident permission remain author actions; before submission the author will either obtain permission or remove the incident narrative, on which no result depends."],
    "Manuscript Sections 7.8 and 8."),

  H1("Section 3: exact sentences"),
  table([700, 3900, 4500], [
    ["Item", "Revision 5", "Revision 6"],
    ["Q1", "A closed-form condition explains the result: the counter's allowance grows with the blocks and windows an attack spans while the tests' does not, so it leaks less only for short campaigns …", "A heuristic with constants from the configuration, not fitted, ordered the two policies correctly in 19 of 20 boundary cells: our tests leak about five messages a block plus those sent while early failures are unresolved, the counter its quota per block in every window, so it loses to paced pumpers and to wide, long campaigns."],
    ["Q2", "We contribute the incident as eight named gaps, … a closed-form condition for when counting beats testing, …", "We contribute eight gaps recalled from the incident, as motivation only, …, both destination-policy comparisons with their failures and collateral damage, and a heuristic, checked against the simulation, for when counting leaks less than our tests; …"],
    ["Q3", "… reputation counts, block-test events and outage observations apply at the transition's time, at most once, and exactly once …", "… each effect type applies at most once, and exactly once if the sweep runs within 20 minutes. Reputation counts and outage observations apply at the transition's time, a block keeping its latest failure time; block-test events apply when processed, so a verdict they trigger starts then."],
    ["Q4", "Unlike Equation (2), this grows with the attack's length and ignores what the carrier does with the codes.", "… by a pumper that solves no challenge and holds no verified history … whatever its carrier does with the codes; solving challenges doubles the bound, and verified history exempts a client from it."],
    ["Q5", "… E[(n−q)+]/E[n] for per-window sends n; with Poisson sends at mean m and q = 4 that share is 3.8 % … and 20 % …", "In the code every send takes a slot … a window holds 1 + X of them, X ~ Poisson(m), and the share beyond q … is E[(1+X−q)+]/(1+m): 7.3 % at m = q/2 and 27 % at m = q for q = 4. This idealization ignores challenge failures, which take no slot, and earlier gates."],
    ["Q6", "… the counter leaks less than the tests only while B(qw − k) < λτ … Equations (3) and (4) follow from the rules; …", "While neither reaches N, the counter's bound lies below the tests' estimate when B(qw − k) < λτ, a heuristic crossover between a bound and an approximation, not a necessary condition … The forms of Equations 3 and 4 and k follow from the rules, τ from the configuration and λ from the attack; …"],
    ["Q7", "… the counter cost all users nothing and gained the attacked blocks' users 3 points … no policy shields a block an attacker shares.", "… cost all users nothing on average and gained the attacked blocks' users 3 points on average …; with the human-like carrier alone it cost them 1.9. Against attack-free operation every evaluated policy still left those users 5 to 9 points worse off (8 with none): none shields a block an attacker shares."],
    ["Q8", "A pumper pacing to the quota leaks what it leaks with no policy.", "A pumper paced to the quota leaks about as much under the counter as with no policy (71 against 72 on three blocks in an hour), and 23 under the tests."],
    ["Q9", "Equation (4) decides the comparison: … the counter leaks less only for campaigns on few blocks …", "Equation 4, a heuristic between the counter's bound and the tests' first-verdict estimate, summarizes the trade-off for pumpers that solve no challenge, hold no exemption and attack within a verdict's hour. Its inputs, per-block load, attack rate and spread, are in an operator's logs, and τ follows its own timeouts; the cost of an excess send, competition under attack and exemption abuse come only from the simulation."],
    ["Q10", "… and only within the condition of Section 5; … and loses to wide, paced and trust-building pumpers.", "… and a heuristic from Section 5 ordered the two in 19 of 20 boundary cells; a frozen counter failed its service claims when the attacker shares blocks with real users, and lost its advantage against wide, paced and trust-building pumpers."],
  ]),
  P(""),

  H1("Section 4: numerical consistency audit"),
  P("We thank the reviewer for separating inconsistency from changed scope. The two analytic rows are repaired: both estimates now grow with B in the text (row 1), and the service share is derived for arrival-anchored windows (row 2, M3). The near-equality row is softened (Q8). The other rows needed no change."),

  H1("Section 5: related work and competing approaches"),
  Bullet("**Huh et al. as external grounding.** Section 6 now maps published observations to our assumptions. Genuine conversion matches one provider's 68 % or more. The never-converting attack destinations and identity churn that Huh et al. report are shared by our non-verifying pumpers and one-use farm. Autofill, challenge completion, WhatsApp reachability, the returning share and arrivals have no published counterpart and are called assumptions. Block concentration has no published distribution we could cite, so E4 maps it instead."),
  Bullet("**RFC 2697.** Section 4.3 now cites it where the bucket is defined: 'its challenge-tier bucket refills independently, whereas RFC 2697's excess bucket fills only from the committed one'. The paper does not call the bucket an implementation of the RFC."),
  Bullet("**Scope of 'testing'.** The conclusion and abstract refer to 'our outcome tests' and 'the default sequential tests'; Section 2 restricts 'testing' to our conversion and speed tests. The title's 'testing' is read through that definition."),
  Bullet("**Comparison matrix.** Not added (word limit). The limitations name the unevaluated classes: per-client fairness, carrier spend limits, bounded exemptions and other sequential statistics."),

  H1("Section 6: presentation"),
  Bullet("**Title page.** The affiliation placeholder remains for the author."),
  Bullet("**Section 5.** Equation 3 uses ≤, Equation 2 uses ≈, and Equation 4 is called a heuristic. N, w, T and the starting state are defined locally, and the first-verdict scope is stated where the comparison is made."),
  Bullet("**Figure 2 (old).** Moved to the artifact (paper/figures/fig2_ablation.*, with its matrix and key-effects files). Section 7.2 keeps the material effects with their intervals and calls each a conditional effect with unadjusted intervals."),
  Bullet("**Figure 5 (old).** Split into Figures 2 and 3, each at full text width. Figure 2 labels only the reference and selected settings, so the clustered sequential variants no longer collide. Figure 3 holds the paired per-attacker differences."),
  Bullet("**Table 8.** The caption expands IV ('IV: the instant verifier's cells'), and the Result column keeps 'holds pooled, not for IV'."),
  Bullet("**Table 9.** Split into (a) the four concentrated carriers and (b) the block poisoner, with the reference arm under each harm heading ('vs attacked none', 'vs attack-free'). The caption states the poisoner's population (all 200 blocks) and the attacked-block cohort (about 18 users a run). Panel (b) gives 95 % intervals for the principal paired comparison, and per-carrier values with intervals and gross losses and gains are in the artifact."),
  Bullet("**Figure 4 (old 6).** The overlays are Equation 3's bound and Equation 2's first-verdict estimate, evaluated per run from offered requests, offered rate and the configured τ, capped by N and with nothing fitted. The caption says that lines join sampled settings and do not locate a crossover, and the legend moves below the panels."),
  Bullet("**Organisation.** The dilution and trade-off figures (old 3 and 4) move to the artifact with their numbers kept in Sections 7.3 and 7.4, and the context sections are shortened. The destination results now start on page 13 rather than 15."),
  Bullet("**Release information.** The citation identifies 2.8.0 as the result-generating release and 2.8.1 and 2.8.2 as the repairs. Publishing the tags and a release with checksums is an author action before submission."),
  table([4550, 4550], [
    ["Revision 5", "Revision 6"],
    ["Figure 1", "Figure 1"],
    ["Figure 2 (ablation grid)", "Artifact; effects in Section 7.2"],
    ["Figures 3, 4 (dilution, trade-off)", "Artifact; numbers in Sections 7.3, 7.4"],
    ["Figure 5 (matched comparison)", "Figures 2 (scatter) and 3 (paired differences)"],
    ["Figure 6 (boundary)", "Figure 4"],
    ["Tables 1–9", "Tables 1–9 (Table 9 in two panels)"],
    ["Equations 1–4", "Equations 1–4 (Equation 3 now a bound)"],
  ]),
  P(""),

  H1("Section 7: the closing question"),
  Quote("When both policies are evaluated over the same attack horizon and under the actual quota, trust and replay semantics, what does your proposed operating condition predict correctly beyond the elementary fact that a small quota limits traffic to a few blocks—and which independent check shows that the prediction is not merely a restatement of the simulation used to fit its constants?"),
  P("**Same horizon, actual semantics.** The estimand is the total SMS sent to the pumper's numbers over T ≤ 60 minutes from a cold start. The pumper declines challenges and holds no verified history. The counter's windows open with each block's first reserved SMS, and every send takes a slot. Under these conditions the tests' first verdict holds the pumper for the rest of the horizon, so their first-verdict leakage is their total (E4: identical at 20 and 60 minutes on 3, 10 and 30 blocks). The counter's total is at most min(N, qBw). The replay semantics do not enter, because the simulator never crashes a process."),
  P("**The algebraic part.** k = ⌈h/1.50⌉ = 5 follows from the test's increments, and min(N, qBw) from the counter's rule. So does the form of the comparison: the counter's bound lies below the tests' estimate when B(qw − k) < λτ, while neither is saturated."),
  P("**The behavioural part.** τ is the time a send stays unresolved: 2.55 minutes from the configuration's resolution timeout, delivery delay and timeout worker period. λ is the attack's offered rate."),
  P("**What it predicts beyond 'a small quota limits a few blocks'.** First, the tests' advantage or disadvantage at small B is set by λτ, the sends in flight before failures resolve, not by the quota. A pumper that slows down (a paced pumper, λτ ≈ 3) is held better by the tests than by the counter even on three blocks: predicted 18 against 72, measured 23 against 71. A full-rate pumper on the same blocks (λτ ≈ 90) is held better by the counter: predicted 105 against 72, measured 110 against 71. Second, the crossover moves with the horizon as λτ/(qw − k): near 30 blocks at 20 minutes and near five at 60. The measured order flips between 30 and 100 blocks at 20 minutes and between 3 and 10 at 60. Third, it predicts that wide campaigns favour the tests: from 100 blocks the counter's bound exceeds the tests' estimate except where both reach N, and the measured order agrees in every such cell."),
  P("**Independent check.** No constant is fitted to the outcomes it predicts. τ comes from the configuration, and λ, N and B from each run's offered requests and requested blocks. With these inputs the predicted ordering matches the measured ordering in 19 of the 20 E4 security cells (3 to 300 blocks, 20 and 60 minutes, full-rate and paced), and the tie it misses is a cell where both estimates equal N. Equation 2 with the same τ was also checked on the main evaluation's spread study (18 configurations, seeds 0–9, different attack rates and range layouts), with errors of 1 to 13 % in the unsaturated configurations. What this does not show is transfer to real traffic: both studies run in one simulator, and the paper says the heuristic is a summary under stated assumptions for operators to check against their own timeouts, rates and block loads."),

  H1("Appendix A of the report: the reviewer's verification"),
  table([3300, 5800], [
    ["Reviewer's check", "Result"],
    ["Two-send, same-block replay (memory store)", `Reproduced on 2.8.1 (score 900 → 0; zero blocks at 1,801 s). Fixed in 2.8.2: one block in the window; regression tests on the memory store, fakeredis and a real Redis (${R1}).`],
    ["Verdict time after a 600-s delayed recovery", "Reproduced; kept by design as processing-time semantics, documented and pinned by a test (M5)."],
    ["Re-execution of the round-5 analyses", "We thank the reviewer for recomputing A–C from the raw records."],
    ["Poisson diagnostics (7.27 %, 26.96 %)", "Adopted (M3)."],
    ["Recorded results unchanged", "The simulator never crashes a process and its event times are monotonic, so 2.8.2 cannot change a recorded run; scripts/check_reproduction.py was rerun on 2.8.2."],
  ]),
  P(""),

  H1("Appendix B of the report: disposition of the fifth-round items"),
  table([2600, 2200, 4300], [
    ["Item", "Reviewer's status", "This round"],
    ["M5 Useful operating region", "Still open in a narrower form", "Section 5 rewritten as a heuristic with one estimand, actual windows, a bound, and constants not fitted; ordering checked in 19 of 20 E4 cells (M1–M3)."],
    ["M8 Event-time replay defect", "Specific case fixed; guarantee still open", "Same-block reordering fixed in 2.8.2 (M4); verdict timing documented as processing time and the guarantee narrowed (M5)."],
    ["M3 Service estimand confusion", "Substantially closed", "Absolute wording made precise (Q7)."],
    ["M9 Disclosed implementation gaps", "Substantially addressed", "Unchanged; Step 11 remains documented as non-transactional."],
    ["M11, M14", "Addressed / substantially closed", "Unchanged."],
    ["M15 Release and chronology", "Substantially addressed", "Tags and a release with checksums are author actions before submission."],
    ["M16 Incident and administrative material", "Partly open", "Contribution list calls the incident motivation only; permission and affiliation remain with the author."],
    ["Other items", "Closed", "Unchanged."],
  ]),
  P(""),
  P("We are grateful for another precise report. The two counterexamples were in exactly the places where our guarantee had outrun our tests, and the closing question made us take the fitted constant out of the operating condition. What remains is a narrower claim, and we think a more honest one."),
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

Packer.toBuffer(doc).then(buf => { fs.writeFileSync("rebuttal_round6.docx", buf); console.log("wrote rebuttal_round6.docx"); });
