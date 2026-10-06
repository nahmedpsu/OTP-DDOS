// Response to the eighth-round Reviewer 2 report. Build: node rebuttal_round8.js -> rebuttal_round8.docx
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

const REL = "the commit accompanying this letter, tag v2.9.1";

// ---------------------------------------------------------------- items
const M1 = item("M1", "The applicable heuristic is less perfect than the headline", "Done: abstract and conclusion give both counts",
    "Specify cold and warm results in the headline, and retain the statement that the crossing is algebraic rather than an established operating threshold.",
    ["The abstract and the conclusion now give both counts and the expression behind each (Q1, Q2). Abstract: 'For attacks of up to an hour, unfitted estimates whose crossing is algebraic, not a measured switching point, ordered the policies' mean leakage in 18 of 18 decisive boundary cells with the counter's cold-start bound and 17 with its warm-start bound: the counter loses its advantage against paced or widely spread pumpers.' Conclusion: 'Within an hour, unfitted estimates ordered the policies' mean leakage in 18 of 18 decisive boundary cells with the cold-start bound and 17 with the warm-start bound, missing a near tie; the crossing was algebraic, not a measured switching point.'",
     "Section 5.6 still reports the 30-block, 20-minute cell where the warm estimates differ by 0.8 messages and the measured difference is 6.6 [−27.2, 42.4]. It now places the exemption qualifier on both bounds, as the check computes them: 'Once 7 messages sent, exempt, to real users' trusted numbers are set aside, no counter run that started cold (44 of 100) exceeded Equation 3; three warm ones did, by 5 or 6 messages, and none exceeded Equation 4.' Two of those exempt sends are the seed-303 one-message excesses the reviewer identified (3 blocks, 25 against 24 and 73 against 72, one exempt send each; results/condition_check.md). We do not treat the missed cell as evidence against the estimates, and the paper does not call it one."],
    "Manuscript abstract, Sections 5.6 and 8.");

const M2 = item("M2", "The experiment remains conditional on one assumed generator", "Acknowledged: qualification kept with the cost claims",
    "Keep that qualification attached to claims of low user cost; do not turn these results into a deployment recommendation.",
    ["Agreed, and nothing in revision 8 widens the claims. Every cost claim is stated for simulated users (abstract: 'at a low cost to simulated users'; Section 4.2: results for returning users 'describe trusted identities only'). Section 5.1 gives the model rule behind each contained attack (the datacenter attacker 'scores in the challenge tier and declines challenges'; 'Step 5 refuses the premium range'). The limitations list the generator's favourable assumptions, and Section 6 calls the combined policy 'a hypothesis for real traffic, not a recommendation'. The conclusion still names replaying real traffic as 'the experiment this paper most needs'."],
    "Manuscript abstract, Sections 4.2, 5.1, 6 and 7.");

const M3 = item("M3", "Predeclaration does not make this an independent external validation", "Done (wording)",
    "The abstract's 'unseen seeds and workloads' is broader than that explanation. Use 'held out from selection' or equivalent wording.",
    ["The abstract now reads 'Under a second predeclared protocol on seeds and workloads held out from selection, …' (Q3). Section 4.3 keeps the chronology: the second protocol 'was written after the matched comparison had selected three counters and committed before its runs; six of its seed values had served other robustness points, never selection', and the rerun with 2.9.0 is reported there with its accounting."],
    "Manuscript abstract, Section 4.3.");

const M4 = item("M4", "A tuning constraint is not a guaranteed service constraint", "Done (wording)",
    "Do not describe a setting merely selected at a target as having demonstrated reliable service compliance outside tuning.",
    ["The limitations now say that selection used 'an unweighted sum of four scripted pumpers' leakage and a mean service target met on tuning seeds, which guarantees no service level elsewhere'. Both misses stay in Section 5.6: the selected sequential setting misses the first protocol's target by 0.18 points on seeds 0–9, and the 1,000-block counter falls 0.12 points below its target while passing the paired check. The instant-verifier exception is kept in the abstract ('all but 13 of 144 cells, all against an instantly verifying carrier') and in Section 5.6 ('against every attacker but the instant verifier (25, against 15 and 16)')."],
    "Manuscript Sections 5.6 and 7.");

const M5 = item("M5", "Small seed sets limit close comparisons", "Done (one aggregate statement qualified)",
    "The unweighted four-carrier aggregate in Table 9(a) should remain subordinate to the carrier-specific results when discussing a policy choice.",
    ["We checked each statement that Section 5.6 draws from the four-carrier table against the per-carrier values (results/round5_analyses.md). Two needed qualifying. Counter and tests together leak least in the sum, but against the instant verifier the tuned sequential setting leaks less (22 against 28); Section 5.6 now reads 'Counter and tests together, explored outside the frozen claims, leaked least summed over the four carriers but not against the instant verifier (28; T300, c0: 22), …'. The degradation range '5 to 9 points' was a carrier average; it now reads 'every evaluated policy left those users 5 to 9 points worse off on average (2 to 12 per carrier; 8 with none)', and the conclusion that 'none shields a block an attacker shares' holds for every carrier. The human-like carrier's exception to the counter's gain was already stated ('with the human-like carrier alone, it cost them 1.9'). The paragraph that introduces the attacked-service table (now Table 9) adds that the sum 'can hide a carrier on which a policy loses (per carrier: artifact)'. The limitations keep 'Close rankings rest on ten or fewer seeds, and costs that round to zero are not shown equivalent.'"],
    "Manuscript Section 5.6 (the text introducing Table 9), Section 7; results/round5_analyses.md (per carrier).");

const M6 = item("M6", "Live execution is not proven to preserve event-time order", "Done: claim withdrawn in the paper and in the code notes",
    "The simplest correction is to say that simulated runs are time-ordered and that concurrent live execution can also exhibit processing-order dependence unless explicitly serialized.",
    ["The reviewer is right, and the inference matches the code: _transition commits a send's transition with store.update and only then calls _apply, so an instance paused between the two steps can apply an earlier transition after another instance has applied a later one on the same block. Section 3.4 now reads: 'Simulated runs apply events in time order, but concurrent live instances may not, because a transition is committed before its effects apply; thus, the same dependence holds live unless a block's effects are serialized.'",
     "The module notes of feedback.py made the same claim ('On the live path events are processed in time order'). Release 2.9.1 replaces it with the same correction. Because every run record carries a hash of the source bytes, docstrings included, we checked that this changes no code: scripts/check_code_identity.py compares each of the 39 files that can change a result with commit 9af3100 (release 2.9.0, which produced the results). 38 are byte-identical, and feedback.py has the same syntax tree once docstrings are removed (results/code_identity.md). No recorded run is affected, since the simulator is one process that applies events in time order."],
    "Manuscript Section 3.4; feedback.py module notes; scripts/check_code_identity.py; results/code_identity.md; docs/evaluation.md.");

const M7 = item("M7", "Backend parity evidence has a finite scope", "Acknowledged (one sentence narrowed)",
    "It is not a complete parity proof for all durations, states or interleavings ... They are not grounds to demand an impossible proof of all executions.",
    ["Agreed. Section 4.1 now says that release 2.9.0 'follows Redis in every rule compared, checked by differential tests', rather than that it keeps state as Redis does in general. It keeps 'The implementation was a research prototype', 'Step 11 was still not one transaction', and the scope of the real-Redis tests ('specific interleavings of two instances, not all'). We make no production-correctness claim."],
    "Manuscript Section 4.1.");

const M8 = item("M8", "The attacks are scripted strategies rather than an adversarial optimum", "Acknowledged: no change needed",
    "The revised text calls them scripted results, limits the heuristic to its assumptions, and reports failures against paced, spread and trust-building attackers. That closes the former overclaim.",
    ["We kept that wording: 'The leakages of these scripted adaptations are not bounds' (Section 5.8), 'break-even shares for scripted attackers under assumed prices, not bounds or criminal profit', and the heuristic limited to 'pumpers that solve no challenge and hold no exemption' (Section 6). No attack profile was added."],
    "Manuscript Sections 5.8 and 6.");

const M9 = item("M9", "Competing policies remain incompletely evaluated", "Scoped: restriction kept, literature added",
    "The outstanding literature omission below should be repaired by an accurate comparison of scope and contribution, not automatically by adding another large experiment.",
    ["The restriction to the implemented policies stays in Section 5.6 ('we ranked only the implemented policies'), and Section 7 still lists tuned token buckets, other sequential statistics, per-client quotas within a block, carrier spend ceilings and bounded exemptions as outside the evaluation. The 2026 prefix/window paper is now positioned in Section 2 (Section 5 of this letter); no experiment was added."],
    "Manuscript Sections 2, 5.6 and 7.");

const M10 = item("M10", "Incident motivation and submission provenance are unfinished", "Done: incident removed, affiliation, citation and tags complete; release published with the resubmission",
    "Complete those actions or remove the unsupported incident material ... Publish the named tag and release with the checksum manifest, or cite the actual immutable commit accurately. Complete the highlights file.",
    ["**Incident material removed.** We took the reviewer's second option. Section 3 ('Threat model and design') now opens with 'The v1 baseline and its gaps', which describes v1 by its seven controls and its bulk and test paths, and Table 2, without a Source column, 'lists eight assumptions behind these rules and how an attacker within the threat model breaks each; the gaps follow from the rules, not observed abuse'. The introduction now reads 'We study the defenses of a registration flow: a baseline of seven controls (v1) and a twelve-step redesign …' and contributes 'an analysis of eight gaps in the baseline'. No result depended on the incident, so no number changed. In the repository, the problem statement, README and ethics notes no longer describe an incident, and the original incident write-up (docs/original/problem_statement.pdf) is removed from the tree.",
     "**Release and submission items.** Reference 23 (revision 7's 22) now cites release 2.9.1 (tag v2.9.1) and the commit that produced every result, 9af3100 (release 2.9.0), so the results are identified by an immutable commit whether or not a tag is present. The title page now carries the affiliation, the tags v2.9.0 and v2.9.1 are public, and the highlights are supplied as a separate file (paper/highlights.txt). The GitHub release carrying results/CHECKSUMS.sha256 is published by the author with this resubmission."],
    "Manuscript Sections 1 and 3, Table 2, reference 23, data availability; docs/problem_statement.md, docs/original/, README.md, docs/privacy_and_ethics.md; paper/highlights.txt.");

const QS = [
  H1("Section 3: exact sentences"),
  table([600, 4100, 4400], [
    ["Item", "Revision 7", "Revision 8"],
    ["Q1", "For attacks of up to an hour, unfitted estimates ordered the two policies' mean leakage in all 18 decisive boundary cells: the counter loses its advantage against paced or widely spread pumpers.", "For attacks of up to an hour, unfitted estimates whose crossing is algebraic, not a measured switching point, ordered the policies' mean leakage in 18 of 18 decisive boundary cells with the counter's cold-start bound and 17 with its warm-start bound: the counter loses its advantage against paced or widely spread pumpers."],
    ["Q2", "Within an hour, unfitted estimates order the two policies in every decisive boundary cell, as an algebraic crossing, not a measured switching point.", "Within an hour, unfitted estimates ordered the policies' mean leakage in 18 of 18 decisive boundary cells with the cold-start bound and 17 with the warm-start bound, missing a near tie; the crossing was algebraic, not a measured switching point."],
    ["Q3", "Under a second predeclared protocol on unseen seeds and workloads, …", "Under a second predeclared protocol on seeds and workloads held out from selection, …"],
    ["Q4", "Events arrive in time order on the live path and in every simulated run.", "Simulated runs apply events in time order, but concurrent live instances may not, because a transition is committed before its effects apply; thus, the same dependence holds live unless a block's effects are serialized."],
    ["Q5", "… while the carrier verifying 60% with human-like delay is never contained: its first verdict comes at minute 11.6 on average and 452 messages leak (1 067 in an hour).", "… while the carrier verifying 60% with human-like delay is contained in none of the ten 20-minute runs: its first verdict comes at minute 11.6 on average and 452 messages leak; in an hour, 1 067 leak and two of ten runs are contained, at minute 47.0 on average."],
    ["Q6", "… against 2.8.0, total leakage changed in 855 of 17 964 comparable runs, but no claim, eligibility or selection used here did (change report in the artifact).", "… against 2.8.0, total leakage changed in 855 of 17 964 comparable runs, but the principal selections, eligibility decisions, and claim counts did not; one auxiliary setting (false alarms matched at unbounded credit) moved from T1000 to T300 under both protocols (artifact change report)."],
  ]),
  P("Q6 also completes our seventh-round letter, which reported the auxiliary change without saying that it occurred under both protocols. It occurred at 200 blocks under both, as results/store_change_report.md shows; the new supplementary key to the matched comparison, Figure 2 (results/figure1_key.md, named for the figure's revision 7 number), names the setting that holds the role in 2.8.x and in 2.9.0.", { spacing: { before: 160, after: 120 } }),
];

const AUDIT = [
  H1("Section 4: numerical consistency audit"),
  table([3000, 3100, 3000], [
    ["Row", "Finding", "Resolution"],
    ["Abstract and Section 8 vs Section 5.6", "Every decisive cell / 18 of 18 vs warm-start 17 of 18", "Both counts in the abstract and conclusion (Q1, Q2)."],
    ["Section 5.5 vs revision 7's Table 6 (now Table 6)", "Never contained vs 2/10 at 60 minutes", "Restricted to the twenty-minute runs; the two contained one-hour runs and their mean containment time, 47.0 minutes, reported (Q5)."],
  ]),
  P("The rows marked as legitimate differences of unit or estimand are unchanged and still stated with their units: cold 18/18 and warm 17/18 cells against 76/78 seeds; the 0.18-point miss of the tuning target; K4's 131/144 pooled and 23/36 for the instant verifier; the 24 per outcome-reading carrier of revision 7's Table 7 (now Table 7) against the 403 summed over four carriers in the attacked-service table; the Equation 3 excesses covered by Equation 4; and the run accounting (9,919 + 7,925 + 240 = 18,084 = 17,964 matched + 120 unmatched; 11,042 identical + 5,195 other counts only + 810 legitimate outcomes + 917 any leakage count = 17,964; 855 with total leakage changed, 805 of them lower).", { spacing: { before: 160, after: 120 } }),
];

const RELATED = [
  H1("Section 5: related work"),
  P("**Zaliskyi and Odarchenko (2026).** We read the article (Science-Based Technologies 69(1), 89–98, DOI 10.18372/2310-5461.69.20735) before writing about it. It aggregates A2P delivery metadata (timestamps and destination numbers only) by prefix, a number without its last three digits, counts messages, and optionally unique recipients, in fixed or rolling five-minute windows against day and night thresholds, and quarantines a prefix for 24 hours once a threshold is crossed. On two confirmed AIT incidents fixed windows blocked 95.29 % and 63.15 % of the traffic, but the same thresholds blocked 57.66 % of a legitimate marketing campaign. Counting unique recipients reduced that to 2.36 %, but it blocked none of the first incident. The authors conclude that message counts alone cannot safely separate AIT from legitimate campaigns. The paper does not use verification outcomes, and it measures harm as legitimate messages blocked, not as users who fail to register."),
  P("Section 2 now positions it after Huh et al.: 'Zaliskyi and Odarchenko count A2P sends per prefix (a number less its last three digits) in fixed or rolling five-minute windows and quarantine a prefix for 24 hours past a day or night threshold. On metadata of two confirmed incidents fixed windows blocked 95% and 63% of the traffic, and 58% of a legitimate marketing campaign; counting unique recipients blocked 2% of the campaign and none of the first incident. Theirs is a send counter judged on real traffic by messages blocked; ours compares a counter with outcome tests at a service target, in simulation, by what users sharing a block lose; the numbers are not comparable.' We make no claim that either result is stronger, and we compare no percentages across the two studies. Their false-positive finding is of the same kind as one of ours, without being comparable to it: a short-window counter costs users when legitimate traffic bursts (a 30-minute launch at three times the normal rate costs its blocks' users 16 points, Section 5.6)."),
  Bullet("**Huh et al.** Closed by the reviewer; unchanged."),
  Bullet("**Competing approaches.** Tuned token buckets, other windowed or sequential outcome statistics, per-client allocation within a block, carrier spend ceilings and bounded exemptions remain named in Section 7 as outside the evaluated policies; no claim covers all counting or all testing methods."),
];

const PRESENTATION = [
  H1("Section 6: presentation"),
  P("**Numbering in revision 8.** To keep the body compact, revision 7's Table 3 (the study map) is now a supplementary map (results/study_map.md), cited in Section 4.3; supplementary Table S1 is unchanged. A comparison of related work is new Table 1 and a figure of the request path is new Figure 1, both in Section 2. Revision 7's Tables 1 and 2 are therefore Tables 2 and 3, revision 7's Tables 4 to 8 are Tables 4 to 8, and revision 7's Table 9 is split into Tables 9 (pumper on shared blocks) and 10 (poisoner); revision 7's Figures 1 to 3 are Figures 2 to 4. Equation numbers are unchanged. The sections now follow the journal's article structure: Introduction (1, with the contributions and an outline), Related work (2, in thematic subsections with a comparison table and a figure), Threat model and design (3, which holds revision 7's Sections 3 to 5: the v1 baseline and its gaps, the threat model, the pipeline, the feedback loop, the destination policies, the capacity controls and the leakage estimates, as Sections 3.1 to 3.7), Methodology (4, revision 7's Section 6), Results (5, revision 7's Section 7), Discussion (6), Limitations (7) and Conclusions and future work (8); the run-in paragraph headings are numbered subsections, and the declarations, CRediT statement and data availability precede the references. Citations and the reference list use the journal's author-year style, and the manuscript is set in its two-column layout. This letter cites manuscript sections by the revision 8 numbering."),
  Bullet("**Table order.** The attacker-profile table (now Table 4) was a fixed-position float; it is now a top float like its neighbours. In the compiled PDF, Tables 1 to 10 appear in order on pages 5, 6, 7, 8, 8, 9, 9, 9, 10 and 11, and Figures 1 to 4 on pages 3, 10, 11 and 12, which we checked page by page."),
  Bullet("**Figure 4 (revision 7's Figure 3).** Redrawn to print at the full text width with larger text (8 to 9 pt as printed). Measurements have filled markers and solid or dashed lines; the estimates (Equations 2, 3 and 4) have hollow markers and dotted or dash-dot lines. The figure has two separate legends, one for measurements ('mean over five seeds, 95 % interval') and one for estimates, and every axis label says when the scale is logarithmic. The text that introduces the figure adds 'All horizontal axes and the vertical axes of (b, c) are logarithmic'. The warm-start curve is kept."),
  Bullet("**Table 9 (now Tables 9 and 10).** The pumper and the poisoner are two tables in larger type. The column headers carry the reference conditions ('Extra harm against attacked, no policy'; 'Degradation against attack-free, same policy'; 'Benign cost') and the cohorts ('all users (≈1,200)', 'attacked blocks (≈18)'). In Table 9 each interval sits under its mean; Table 10 has one interval column. The paragraph that introduces both tables says which entries carry intervals: in Table 9, leakage and the attacked blocks; in Table 10, all users' extra harm."),
  Bullet("**Figure 2 (revision 7's Figure 1).** The text that introduces the figure now says what the unlabelled points are: 'sequential settings matched to the default's false alarms at other credits (key: results/figure1_key.md)'. The new supplementary key lists every plotted setting with its completion, its summed leakage with interval and its roles in the selection. It names the auxiliary setting that changed in 2.9.0, T1000 cinf to T300 cinf, which is also identified in Section 4.3 (Q6)."),
  Bullet("**The boundary narrative.** Tables 9 and 10 are now introduced and discussed before the boundary discussion, which has its own heading (Section 5.6.3). The boundary paragraph, including the 18/18 and 17/18 results, the near-tie qualification and the algebraic-crossing statement, starts on page 10 and runs onto page 11 with no float inside it; the two tables, introduced on page 9, are set at the foot of page 10 and the head of page 11, and Figure 4 follows on page 12. The adaptive-attacker results (E3), which followed in the same paragraph, are now a paragraph of their own."),
  Bullet("**Captions.** Every table and figure caption is now a short title. The descriptions that the items above require (intervals, units, reference conditions, the log-scale axes, the key to Figure 2 and the abbreviations used in the tables) are stated in the text where each table or figure is first discussed."),
  Bullet("**Front matter.** The title page now carries the affiliation (M10)."),
  P("**Completed in the previous round, not repeated here:** Figure 2's interval construction, Figure 3's description (now stated in the text), the attacker row of revision 7's Table 5 (now Table 5) and the cohort definitions of the attacked-service table. **Completed in this round:** M1, M3 to M7, Q1 to Q6, the related-work paragraph, the removal of the incident material, the presentation items above, reference 23 with the immutable commit, the affiliation, the public tags, and the highlights file. **Completed by the author at resubmission:** the GitHub release with the checksum manifest.", { spacing: { before: 160, after: 120 } }),
];

const children = [
  new Paragraph({ children: [new TextRun({ text: "Response to the eighth-round report of Reviewer 2", bold: true, size: 32 })], spacing: { after: 120 } }),
  P("**Manuscript:** Counting Versus Testing the Destination: A Simulation Study of Layered Defences Against SMS OTP Flooding and Pumping. **Journal:** Computers & Security."),
  P(`**Reviewed:** manuscript revision 7 and commit 9af3100 (release 2.9.0). **Revised:** manuscript revision 8 (the commit accompanying this letter) and release 2.9.1 (tag v2.9.1). No simulated result changed. Every result was produced by 2.9.0, and 2.9.1 runs the same code: it changes comments, documentation and the manuscript only (results/code_identity.md). Section, table and figure numbers refer to revision 8. Where the reviewer's revision 7 table numbers are quoted, the revision 8 number follows ('now Table n'). Revision 7's reference 22, the software, is reference 23 in revision 8.`),

  H1("Summary"),
  P("We thank the reviewer for an eighth report, for the independent checks behind it, and for setting out bounded conditions for closing the review. We made the corrections the report lists and added no experiment. The abstract and conclusion now give the cold-start and warm-start counts. 'Unseen' is replaced by 'held out from selection'. The containment sentence is restricted to the twenty-minute runs. The live event-order claim is withdrawn from the paper and from the code notes. The auxiliary selection change is stated. The 2026 prefix/window paper is positioned in Section 2. The floats, Figure 4 and the attacked-service table are reworked. The incident narrative is removed."),
  P("**Manuscript.** Revision 8 has 10,844 words from the title to the references inclusive (10,798 by a whitespace count) and 15 pages in the journal's two-column layout. Its scope, studies and claims are those of revision 7, and it has no highlights page. The abstract, introduction, related work and conclusions were rewritten to the structure of the journal's recent articles: the introduction now states the problem, the existing defenses, their documented limits, the two closest studies and the gap before the approach and contributions; the related work is organized by where each defense acts, with a comparison table (Table 1) and a figure of the request path (Figure 1); the conclusions answer the research questions in turn. Every work cited was read, no experiment was added, and no number or claim changed."),
  table([3600, 5500], [
    ["Condition for closing (Section 7 of the report)", "What was done"],
    ["1. Cold 18/18 and warm 17/18 in the abstract and conclusion; replace 'unseen'", "Done (Q1, Q2, Q3; M1, M3)."],
    ["2. Restrict 'never contained'; acknowledge the two contained one-hour runs", "Done (Q5): none of ten twenty-minute runs; two of ten in an hour, at 47.0 minutes on average."],
    ["3. Remove the live event-order guarantee; clarify the auxiliary selection change", "Done (Q4, M6; Q6): the paper and feedback.py's notes now say the opposite of the old claim, and the code is unchanged (results/code_identity.md)."],
    ["4. Add and position the 2026 prefix/window paper", "Done (Section 5 of this letter): read, positioned in Section 2, with no numerical comparison."],
    ["5. Float order and dense figure/table; affiliation, incident permission or removal, the cited release", "Floats, Figure 4, Tables 9 and 10 and the Figure 2 key are done (Section 6 of this letter). The incident material is removed (M10). Reference 23 cites the immutable commit, the affiliation is complete and the tags are public; the release is published with the resubmission."],
  ]),

  H1("Answer to the closing question"),
  Quote("When the implementation semantics, starting state and user-service constraint are stated correctly, what reproducible advantage remains for counting, and exactly where does that advantage end?"),
  P("**The advantage at the stated service target.** Under the first protocol the selection rule picks settings at a stated benign target: the default's completion minus 0.5 points, met on tuning seeds. At that target the selected short-window counters leaked 6 to 48 messages against four concentrated 20-minute pumpers, at 0.06 to 0.43 points of attack-free completion. At the busiest density the default sequential tests leaked 19 to 452 (Table 7). Frozen and run under the second protocol on seeds and workloads held out from selection, the counter leaked no more than the tests in 131 of 144 cells. The run records, the store repair and the selection analyses reproduce, as the reviewer's independent checks confirmed."),
  P("**Where the advantage ends.** Each of these is stated in revision 8, with its number:"),
  Bullet("**An instantly verifying carrier.** Under the first protocol the default stops it at 19 messages against the counter's 24. On fresh seeds the re-selected sequential winners leak 15 and 16 against the counter's 25. All 13 of K4's failing cells are this carrier's (23/36)."),
  Bullet("**Blocks shared with real users.** The frozen counter fails both service-under-attack claims (K3 127/144, K5 93/144), and against attack-free operation every evaluated policy leaves the attacked blocks' users 5 to 9 points worse off on average (2 to 12 per carrier)."),
  Bullet("**A pumper paced to the quota.** It leaks 71 messages under the counter against 72 with no policy, and 23 under the tests (three blocks, one hour)."),
  Bullet("**A widely spread pumper.** The counter's allowance grows as qBw with the blocks used. The algebraic crossing lies near five blocks for an hour and 30 for twenty minutes, where the measured differences do not exclude zero. It is not an operating threshold."),
  Bullet("**Trust builders on random numbers.** They leak 577 messages under the counter, as under the default."),
  P("**Cold and warm bounds.** Once the 7 exempt sends are set aside, the cold-start bound, Equation 3, holds on every run that starts cold (44 of 100), and the warm-start bound, Equation 4, holds on every run. The estimates order mean leakage in 18 of 18 decisive cells with the cold-start term and 17 of 18 with the warm-start term. The abstract, Section 5.6 and the conclusion now tell this qualified story, and the paper presents the twelve-step architecture as context for the destination comparison (Sections 5.1–5.4)."),

  H1("Section 2: methodological weaknesses"),
  ...M1, ...M2, ...M3, ...M4, ...M5, ...M6, ...M7, ...M8, ...M9, ...M10,
  ...QS,
  ...AUDIT,
  ...RELATED,
  ...PRESENTATION,
];

const end = [
  P(""),
  P("We are grateful for a review that kept the evidence and the claims apart through eight rounds and named the checks it ran. Revision 8 makes the bounded corrections the reviewer set out and adds no new experiment."),
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

Packer.toBuffer(doc).then(buf => { fs.writeFileSync("rebuttal_round8.docx", buf); console.log("wrote rebuttal_round8.docx"); });
