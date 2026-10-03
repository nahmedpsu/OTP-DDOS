// Response to the fourth-round Reviewer 2 report. Build: node rebuttal_round4.js -> rebuttal_round4.docx
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
  new Paragraph({ children: [new TextRun({ text: "Response to the fourth-round report of Reviewer 2", bold: true, size: 32 })], spacing: { after: 120 } }),
  P("**Manuscript (new title):** Counting Versus Testing the Destination: A Simulation Study of Layered Defences Against SMS OTP Flooding and Pumping. **Previous title:** From a Production OTP Flood to a Layered Defence: Measured Limits of Risk-Scored SMS Verification Against Residential Flooders and Colluding Carriers."),
  P("**Journal:** Computers & Security. **Reviewed:** manuscript revision 3 and release 2.7.0 (commit 732e430). **Revised:** manuscript revision 4 and release 2.8.0 on the same branch. The repairs are in 441e4f0 (counter staging), 1f0b212 (replay horizon) and 703fbd8 (reversal order). The token bucket and simulator realism are in 6967208. The counter-study protocol is 2a91d78, committed before its driver (c6ebf50) and its runs (8faaa11). The full rerun of the main evaluation (9,919 runs) is a68599a, documentation is in eded092, 0f71757, c41ea58 and 1c277a0, and the manuscript commit accompanies this letter. A documentation commit made after the runs (802464d) discloses the two open races and the seed overlap in the repository and fixes a docstring and a citation. It changes comments only, so the v2.8.0 tag stays on 1c277a0, the code that produced the results. Section, table and figure numbers refer to revision 4 unless marked otherwise."),

  H1("Summary"),
  P("We thank the reviewer for a fourth careful report. Both counterexamples were right, and we reproduced each before touching the code. Eight concurrent requests at the four-per-ten-minute counter sent eight SMS and no challenge, against four and four when serial. A recovered block failure was counted a second time, 257 to 258, once 256 later events had pushed its identifier out. The central objection was also right. Revision 3 let a result measured on four concentrated, twenty-minute pumpers, with service measured separately and without an attack, stand for a security–service conclusion it had not tested."),
  P("We followed the order in the report's closing paragraph. First, the two defects were repaired and tested, and a third ordering defect that the replay repair exposed was fixed with them. Second, we froze the selected counters and their comparators in a new protocol (config/counter_protocol.json), committed before its driver and before any run that uses it. It has five claims, K1 to K5, and five experiments: E1, leakage and service on the same attacked trace; E2, the held-out family; E3, the adaptive family; E4, the operating boundary; E5, the selection rule at every density with the full sequential grid and density-specific attack runs. Third, the main evaluation was rerun as a clean invocation whose runs carry a code hash, and the manuscript was rewritten from both sets of results."),
  P("**The answer to the single question is partly yes and partly no, and the paper now says both.** The counter's leakage advantage survived the frozen comparison. On the held-out family it leaked 33, 34, 33 and 62 messages on average against the four carriers, where the default sequential tests leaked 287, 36, 344 and 287. K1 (at most 10 % leaked) held in 144 of 144 cells, and K4 (no more than the default) in 131 of 144, all 13 misses being the instant verifier. The attack-free cost claim K2 held in 36 of 36 cells, at 0.13 points [0.09, 0.17]. But both claims about service while the pumper competes with real users for the same quota failed: K3 in 127 of 144 cells and K5 in 93 of 144. The counter also does not stop pumpers that spread over many blocks (over an hour, the default sequential tests leak less once a pumper uses ten or more), pace themselves to its quota, or build trust on random numbers. It costs real users once their own traffic on a block approaches the quota, and a product launch costs the launch blocks' users 16 points. With no destination policy, a pumper on shared blocks exhausts them and the hourly budget, so there the counter helped the attacked blocks' users, by 11 points against the never-verifying carrier."),
  P("**Manuscript.** Revision 4 has a simulation-led title. The abstract, discussion and conclusion are narrowed to these claims, including the K3 and K5 failures and the region where the counter loses. Section 6 states the chronology of both protocols. Section 7.2 presents the ablation as conditional effects with measured interactions. Section 7.6 adds the claims table (Table 9) and the boundary figure (Figure 7). The scope is unchanged: the same research questions, designs, attacker families and studies. The first-page highlights are removed, as the author asked; Elsevier collects them as a separate file at submission."),
  P("The paper is 7,987 words from the title to the end of the reference list, counting tables, captions, declarations and references. This is the number of alphanumeric tokens in the compiled PDF with figures replaced by placeholders; a whitespace count gives 7,925, and the count without references is 7,270. It compiles without overfull boxes, in 25 pages. Every number was rechecked against results/evaluation.json, results/counter_study.json and results/performance.json in a separate audit pass."),

  H1("What we could not do, or did only in part"),
  Bullet("**Independent traffic.** We still have no production or third-party traces. Both protocols were written by the author for the author's generator, and the second was written knowing which counters had won. Section 8 says this."),
  Bullet("**Seed reuse in the held-out family.** Seeds 300 to 309 are new. Of the held-out family's seeds, six (6000 to 6002 and 6100 to 6102) had been used before at other robustness points, for evaluation only, never for selection. Section 6 says so. Two artifact sentences said otherwise: the description inside config/counter_protocol.json ('never used before this protocol') and the header of results/counter_study.md. The protocol file is kept as committed so that its recorded hash stands. The erratum is stated in the README, the CHANGELOG, docs/evaluation.md, the report generator and a marked line of results/counter_study.md (802464d)."),
  Bullet("**The replay guarantee has a horizon.** Effects are applied at most once, and exactly once if a recovery sweep runs within the horizon of 20 minutes (twice the code lifetime). In verification we found one more edge case: a late verification whose own recovery runs more than about 13 minutes (790 s) after it arrived can leave the failure it reverses counted. Batches older than the horizon are skipped and counted in the store key otp:fx:abandoned, but that count is not reported in the results. The simulator never crashes a process, so it is zero there by construction. The repository now states the edge case precisely (feedback.py module notes, README, documentation; 802464d). A failure's block-event identifier lives 21 minutes from the failure, a reversal stays replayable for 20 minutes from the verification, and a verification can arrive up to about 8 minutes after the failure. In the worst case, therefore, a first sweep more than about 13 minutes after the verification finds the identifier gone; there is no gap when the verification follows the failure within 60 s. The fix is small (keep failure identifiers for the horizon plus the code lifetime plus 60 s). We left it open so that the released code stays the code that produced the results."),
  Bullet("**Concurrency residuals.** The timeout-worker race reported last round is still open: a correcting receipt that lands between the worker's compare-and-set and its removal of the timeout leaves the send unresolved. Step 11 is still a sequence of separate writes after atomic reservations. A request challenged at Step 11 keeps the source-cap slot it took at Step 9. Section 6 names all four. The repository now describes both races, with the fix each would take, at the top of feedback.py, in the README and in the CHANGELOG (802464d). For the timeout race the fix is to remove the timeout only if its score is unchanged. Neither fix is applied, for the reason given above; the failure in the timeout race is lost, not doubled."),
  Bullet("**Test gaps.** No real-Redis test covers unsolved requests at the counter's second boundary (the in-process and fakeredis tests do), and the HTTP application's stage-1 path has no test of its own."),
  Bullet("**Token bucket.** Our bucket is not RFC 2697's marker: its challenge-tier bucket refills at the same rate independently, whereas the RFC's excess bucket fills only from the committed bucket's overflow. The protocol labels the burst-12 arm as one that 'tolerates a legitimate burst of 12'. It tolerates any burst of 12, an attacker's included, and the results show it. The label is in the hashed protocol file, so we left it and correct it here and in the paper's wording."),
  Bullet("**Small artifact mismatches, fixed after the runs.** The simulator's module docstring said WhatsApp reachability is drawn per request; the code draws it once per number. calibration.py cited a blog post that states no figure and annotated the conversion assumption with '65 %+'. It now cites Twilio's Verify product page, which says '68 %+ global conversion rate' (re-checked on 3 October 2026), and the paper quotes the same page. Both edits are in 802464d. Because they edit source files, the hash of the current tree differs from the code hashes recorded in the results, which identify the code at 1c277a0 (the v2.8.0 tag). The CHANGELOG says so; no behaviour changed and no number depends on either string."),
  Bullet("**Not evaluated.** Windowed, exponentially weighted and time-uniform sequential statistics; a supervised model on the available features; client puzzles; per-client quotas inside a block and carrier spend ceilings as combinations; long-term co-adaptation of attacker and baseline; live vendors."),
  Bullet("**Author actions before submission (M19).** The affiliation; written permission to describe the incident; confirmation of Table 1's Source column; the highlights file; and pushing the v2.8.0 tag (on 1c277a0), which exists only in a local clone."),

  H1("Section 2: methodological weaknesses"),
  ...item("M1", "The principal result is outside the robustness protocol", "Done, under a fresh protocol",
    "Freeze the selected policies and evaluate their leakage and service cost on the held-out family already implemented. Add an explicit counter claim with a stated failure criterion. Report failures as well as averages.",
    ["We did this as a separate protocol, as the reviewer suggested, and did not relabel it as part of the first one. config/counter_protocol.json freezes the principal counter (graded, four sends per block per ten minutes) and the two counters selected at the sparser settings (one per ten minutes; three per hour). Its comparators are the default sequential tests, the best sequential setting at the target, no policy, a token bucket at two bursts, the counter combined with the sequential tests, and the counter with a trust budget. E2 runs them on the first protocol's held-out family: 12 shifted points, held-out attack rates and pools, three seeds each, with the pumper on three blocks that real users also use. The claims and their pass rule (true in at least 90 % of cells) are:",
     "K1, leaks at most 10 % of attack requests: 144 of 144, holds. K2, attack-free attributable loss at most 0.5 points: 36 of 36, holds. K3, attributable loss under attack at most 0.5 points: 127 of 144, **fails**. K4, leaks no more than the default sequential tests: 131 of 144, holds; all 13 misses are the instant verifier. K5, attributable loss under attack at most the default's plus 0.25 points: 93 of 144, **fails**.",
     "Thirteen of the 17 cells that broke K3 lie at the three points with the most legitimate traffic (34 to 39 requests a minute), where users and pumper compete for one quota. K5 failed at 11 of 12 points. The counters chosen for sparser traffic cost 4.66 and 5.77 points at this density even without an attack. Every failing cell is listed in results/counter_study.md, and per-seed outcomes are in results/counter_study_per_seed.csv."],
    "config/counter_protocol.json; scripts/run_counter_study.py; results/counter_study.md, 'Claims K1–K5'. Manuscript Section 6 ('Two protocols and their chronology'), Section 7.6 ('Under a second protocol'), Table 9."),
  ...item("M2", "The service constraint is measured without the adversary", "Done",
    "Compare counter, sequential, and no-destination-policy arms on the same attacked legitimate trace. Include shared hot blocks, independent blocks, a poisoner, and stable fallback availability. Report net attributable loss, gross losses and gains, and first-time and returning-user outcomes.",
    ["E1 does this. It runs 60-minute attacks after a 30-minute warm-up, with leakage and service taken from the same runs. Pumpers act on blocks real users use (shared) or on other blocks (independent), at 200 and 1,000 blocks and with uniform traffic. The poisoner floods the shared blocks. WhatsApp reachability is now a stable property of each number. Attributable loss is reported for all users, first-time users, returning users and the attacked blocks' users. Gross losses and gains are in results/counter_study.json (gross_lost, gross_gained).",
     "At 200 shared blocks the counter leaked 80, 83, 82 and 158 against the four carriers; the default leaked 112, 31, 897 and 123, and no policy 587 to 1,981. Attributable loss over all users ranged from −0.16 to +0.09 points under the counter and from −0.21 to +0.04 under the default (negative is a gain). Returning users lost nothing in any arm except the counter with a trust budget (+0.04). Against the never-verifying carrier the counter gained the attacked blocks' users 11.14 points [7.34, 15.12]: with no destination policy, the pumper exhausts their blocks and the hourly budget. The poisoner is where the counter does worst. It leaked 1,662 messages under the counter at a loss of 0.72 points, against 1,388 and 0.97 under the default and 871 and 2.45 under the best sequential setting.",
     "Fallback availability at 0, 70 and 100 % is covered by E4 (M3). The 2.7.0 service target stays labelled as a benign target everywhere it appears."],
    "results/counter_study.md, 'E1'. Manuscript Section 7.6 (paragraph beginning 'On 60-minute attacks'), Table 9."),
  ...item("M3", "The rate separation largely supplies the answer", "Done: the boundary is mapped",
    "The required result is the operating boundary: at what overlap between legitimate and malicious block rates does the counter cease to meet the service target?",
    ["E4 maps it in three parts. The service map puts 0.5, 1, 2, 4 and 8 legitimate sends per ten minutes on three hot blocks, at 0, 70 and 100 % WhatsApp reachability, with and without a never-verifying pumper on the same blocks. The stress rows are a product launch (30 minutes at three times the rate, all first-time users with fresh fingerprints, on the hot blocks), correlated fallback failure (users without WhatsApp solve challenges with probability 0.5 instead of 0.9) and a poor route (the hot blocks lose half their messages). The security map spreads a pumper over 3 to 300 blocks, at full rate or paced to the counter's quota, for 20 and 60 minutes. Figure 7 shows the service map at 70 % and the security map.",
     "**Where the service target fails.** Among the hot blocks' own users, attack-free, the counter costs nothing at 0.5 and 1 send per ten minutes, 0.5 points (interval includes zero) at 2, 2.30 at 4 (the quota) and 5.54 at 8; at 8 the cost is 13.19 without WhatsApp and 1.73 when every number has it. Measured over all users, the 0.5-point target fails only at 8 sends per ten minutes with 0 or 70 % reachability (1.67 and 0.71 points attack-free; 2.20 and 0.57 with the pumper) and in the product launch (3.69 points, 16.10 for the launch blocks' users, against 0.03 for the default). Correlated fallback failure and poor routes cost nothing attack-free. With a pumper on the same blocks the counter usually helped those users, because without a policy the pumper consumes the block.",
     "**Where the security advantage fails.** Over 60 minutes the counter leaked 71, 240, 679, 1,543 and 2,052 messages as the pumper used 3, 10, 30, 100 and 300 blocks; the default leaked 110, 144, 242, 603 and 1,347. From ten blocks on, the default leaks less. A pumper paced to the quota leaks what it leaks with no policy (238 against 239 at 30 blocks in 20 minutes).",
     "Per-block occupancy (median and maximum) is recorded for every cell in results/counter_study.json. We did not publish arrival histograms, and the paper reports rates per hot block rather than distributions."],
    "results/counter_study.md, 'E4'. Manuscript Section 7.6 (paragraph beginning 'Attack-free'), Figure 7."),
  ...item("M4", "The new counter is not challenged by the adaptive family", "Done",
    "The counter is omitted from the threshold-aware, receipt-faking, trust-building, spreading and prolonged attacks used to expose the sequential policy's weaknesses.",
    ["E3 runs the whole adaptive family against the counter, the default and no policy. Leaked messages, counter against default:",
     "threshold-aware carrier 24 against 665; receipt faker 24 against 665; concentrated trust builder 36 against 502; trust builder on random numbers 577 against 577; long trust builder 1,507 against 1,507; spread over 3, 30 and 300 blocks 24, 233 and 637 against 107, 237 and 640 (no policy 339, 673 and 655); quota-aware over 30 and 300 blocks 238 and 654 against 221 and 648; the human-like carrier over 360 minutes 484 (81 an hour) against 4,737 (789 an hour), and 11,868 with no policy.",
     "So the counter defeats the outcome-gaming attackers, as expected, because it does not read outcomes. It does not defeat the trust builders that verify on random numbers: their verified identities are exempt from the counter, which is the exemption boundary the reviewer pointed to. Section 4.3 now states the exemption and its consequence ('a code entered on a pumper's number can buy that number an exemption'). Adding a trust budget of eight exempt requests a minute did not change the counter's leakage in E1. The reviewer's own diagnostic (40, 41 and 28 against 628, 481 and 183) agrees with our 36 against 502."],
    "results/counter_study.md, 'E3'. Manuscript Sections 4.3 and 7.6 (last paragraph)."),
  ...item("M5", "The graded counter has a concurrent challenge bypass", "Fixed and tested on real Redis",
    "Enforce admission stage and slot reservation together, then test unsolved and solved concurrent requests at both boundaries on real Redis.",
    ["Confirmed and repaired (441e4f0). Step 5 still reads the count, but only for routing. reserve_block_count now decides the graded stage inside the same atomic operation that takes the slot, on the count that operation changes. A request that has not solved a challenge cannot take a slot past the limit, and a solved one cannot take a slot past twice the limit. The token bucket does the same by compare-and-set.",
     "We re-ran the reviewer's diagnostic with a barrier before Step 11. Serial and concurrent runs now both give four SMS and four challenges, on the in-memory store, on fakeredis and across two instances on a real redis-server. The regression tests are test_counter_concurrent_first_boundary_is_enforced, test_counter_concurrent_solved_challenges_fill_the_second_tier_only and test_counter_concurrent_unsolved_at_second_boundary (tests/unit/test_fourth_round.py), with test_graded_counter_first_boundary_across_instances and test_graded_counter_second_tier_across_instances on real Redis, and token-bucket equivalents. Unsolved requests at the second boundary are not yet tested on real Redis.",
     "The simulator is single-threaded, so the defect could not change a reported number, but every study was rerun on the repaired code regardless. The residual that a request challenged at Step 11 keeps its Step 9 source-cap slot is disclosed in Section 6."],
    "pipeline.py reserve_block_count; tests/unit/test_fourth_round.py; tests/integration/test_real_redis.py. Manuscript Sections 4.3 and 6."),
  ...item("M6", "Bounded replay memory does not give unconditional idempotence", "Fixed with a stated horizon; one edge case disclosed",
    "A per-event durable deduplication record lasting through the recovery horizon, or an equivalent replay protocol, is needed for the stated guarantee. Otherwise state the conditional guarantee and evaluate the exceptional path.",
    ["Confirmed and repaired (1f0b212), and the guarantee narrowed. Event identifiers are now kept by age, not by count: a block remembers each one for the replay horizon H plus 60 s, where H is twice the code lifetime (20 minutes at the default). No volume of later events can push one out early. A batch older than H is not applied: its counting effects are skipped and counted in otp:fx:abandoned. The stated guarantee is that every recorded effect is applied at most once, and exactly once if a sweep runs within H. The reviewer's reproduction now ends at 257 failures, and test_replay_after_many_later_block_events_across_instances repeats it on real Redis.",
     "The repair exposed an ordering problem, which we fixed in the same round (703fbd8, see M15). One edge case remains. A late verification whose recovery runs more than about 13 minutes after it arrived can leave the failure it reverses counted, because the reversal's record has aged out by then. Section 6 states it. The abandoned-batch count is kept in the store but not reported in the results; it is zero in the simulation, which never kills a process."],
    "feedback.py (module notes, replay_horizon_s, recover, _block_event); tests/unit/test_fourth_round.py. Manuscript Sections 4.2 and 6."),
  ...item("M7", "The density comparison is narrower than its wording", "Done",
    "Say this directly or run the same policy search and attacked traffic density at each condition.",
    ["We did both. Section 6 now says the first protocol searched the full sequential grid only at the busiest setting, and calls the densities 'three calibration settings of legitimate block density'. E5 then reruns the selection rule with the full sequential grid at every density, with attack runs whose legitimate background is at that density, on fresh seeds. It selects the same counters (four per ten minutes at 200 blocks, three per hour at 1,000, one per ten minutes with uniform traffic). The paper says 'at every density' only for E5, where it is literally true."],
    "results/counter_study.md, 'E5'. Manuscript Sections 6 and 7.6 ('At a benign service target')."),
  ...item("M8", "Aggregate leakage is an arbitrary utility function", "Done",
    "Show per-attacker paired differences and sensitivity to attacker mix. Distinguish the preferred policy under average leakage from the preferred policy under worst-case leakage, spend, or a first-time-user loss constraint.",
    ["E5 reports the preferred policy at each density under mean leakage, worst-case leakage, mean leakage with first-time-user loss at most 0.5 points, each single attacker, and random attacker mixes. At every density the same counter is preferred under all of them and wins every random mix. Figure 6(b) shows per-attacker paired differences against the default. The aggregate is described as a declared experimental score in the artifact, and as 'an unweighted sum of four scripted pumpers' leakage' in the limitations. The instant-verifier exception is stated wherever the counter's leakage is (Table 8, K4). We did not add a spend-weighted criterion; the profiles do not differ enough in cost class for it to separate the arms, and we have not shown that, so we make no claim about spend."],
    "results/counter_study.md, 'E5' (preference rows). Manuscript Section 7.6, Figure 6(b), Table 9, Section 8."),
  ...item("M9", "Mean service matching is not an operational guarantee", "Done",
    "Report the target, each selected policy's evaluation margin to it, and uncertainty in the paired difference. Give the fraction of evaluation cells that violate the target and the affected cohorts.",
    ["E5 reports, for every setting at every density, the target, the evaluation margin, the number of seed-and-conversion cells more than 0.5 points below the default, and benign attributable loss for all, first-time and returning users with paired intervals. The selected counters' margins are +0.17 points (200 blocks), −0.12 (1,000) and +0.19 (uniform). The middle setting's counter therefore misses its target on the fresh seeds, and the paper says so. No cell at any density falls more than 0.5 points below the default (0 of 20 each). The loss falls entirely on first-time users (0.44 points for the middle counter); returning users lose nothing.",
     "The false-alarm matching is a budget on mean verdict events a day, not equal achieved error rates or average run length, and the paper calls it a budget."],
    "results/counter_study.md, 'E5'. Manuscript Section 7.6, Table 8."),
  ...item("M10", "The holdout protects selection more than it protects model discovery", "Done (chronology stated); independent traces unavailable",
    "State the chronology and the precise scope of predeclaration. A final frozen comparison on new seeds and prespecified shifted workloads would strengthen the current claim.",
    ["Section 6 ('Two protocols and their chronology') states it in order. The first protocol was committed before its runs. Its first run failed C1 in 32 of 108 cells because attack and no-attack runs drew different users, and the pairing fix followed that result. The second protocol was written after the matched comparison had selected three counters, and committed before its driver and runs. It uses new seeds 300 to 309 and the held-out family, six of whose seeds had served other robustness points. The limitations say that both protocols were written by the author for the author's generator, the second knowing which counters had won. The frozen comparison the reviewer asked for is E2. Independent traces remain the experiment the paper most needs, and the paper ends its limitations by saying so."],
    "config/counter_protocol.json (git history: 2a91d78 before c6ebf50 and 8faaa11). Manuscript Sections 6 and 8."),
  ...item("M11", "Bootstrap intervals do not quantify model uncertainty", "Partly done",
    "Show per-seed outcomes for the central comparison and paired differences in the main results. Preserve the caveat that an interval of zero width is not proof of zero real-world risk.",
    ["Per-seed outcomes of E1 and E5 are in results/counter_study_per_seed.csv, and every paired difference in Section 7.6 is bootstrapped per seed. Section 6 keeps the caveat that intervals 'describe variation under this generator, not uncertainty about real traffic', and that covers the zero-width intervals too. We did not study the coverage of percentile intervals at these sample sizes."],
    "results/counter_study_per_seed.csv. Manuscript Section 6 ('Simulation')."),
  ...item("M12", "The variance decomposition is only an informal comparison", "Done",
    "Use a nested design with multiple simulation seeds per attacker configuration and report between- and within-configuration variance.",
    ["A nested design now runs ten attacker configurations with three simulation seeds each. The between-configuration share of the variance of leakage is 0.92 [0.80, 0.98] for the farm, 0.90 for the walk and 0.96 for the residential bot. Section 6 reports the farm's share. The interval-narrowing comparison is kept in the artifact and named a fixed-parameter comparison, and 'most spread' is gone."],
    "results/evaluation.md (nested variance). Manuscript Section 6 ('Simulation')."),
  ...item("M13", "Behavioural realism remains the main modelling risk", "Partly done",
    "Prioritize stable identities and correlated stress workloads for the winning policy rather than indiscriminately expanding every experiment.",
    ["Both were done for the winning policy, and the identity changes apply to every study. WhatsApp reachability is a stable property of each number, and returning account holders carry verified fingerprint history. E4 adds three correlated stress rows: a product launch that correlates new accounts, fresh fingerprints and high block volume; correlated fallback failure, where users without WhatsApp also fail challenges more often; and poor routes on the hot blocks. The launch is the one that hurts: 3.69 points of all users and 16.10 of the launch blocks' users under the counter, against 0.03 under the default. The other two cost nothing attack-free.",
     "Conversion, CAPTCHA scores, autofill and challenge completion remain assumptions, and joint failures beyond these three rows are not explored."],
    "evaluation/sim.py; results/counter_study.md, 'E4' (stress rows). Manuscript Sections 6 and 7.6."),
  ...item("M14", "The ablation supports conditional effects rather than unique attribution", "Done",
    "For the few mechanisms central to the explanation, examine selected interactions or construct direct counterfactuals.",
    ["Section 7.2 is retitled 'conditional effects of each layer' and says that overlapping effects do not add up. Four interactions were measured. Against the walk, removing the feedback loop and the block key together costs what removing the loop alone does, an interaction of −121 [−141, −101], because the key acts only through the loop. The risk engine and the loop overlap likewise (−152), as do the loop and the session against the reused profile (−40). The farm's adaptive-cap effect does not depend on the risk engine (+4 [−0, +10]). A new table (Table 5) lists the effects of at least ten messages with intervals excluding zero. It replaces the earlier language of shares."],
    "results/evaluation.md (interactions); paper/figures/fig2_key_effects.md. Manuscript Section 7.2, Figure 2, Table 5."),
  ...item("M15", "Important implementation failures remain outside simulation", "Partly fixed; residuals disclosed",
    "Close or bound the known races before describing the artifact as deployment-ready. Add the two new local counterexamples to targeted regression coverage.",
    ["Both counterexamples are now regression tests, on real Redis as well (M5, M6). The ordering problem disclosed last round is fixed (703fbd8). A late verification or corrected receipt that reaches a block before the failure it reverses now names that failure and leaves a tombstone, so the order no longer matters (test_late_verification_reversal_before_the_failure_is_applied, test_corrected_receipt_reversal_before_the_failure_is_applied).",
     "Still open: the timeout-worker race, Step 11's separate writes, the source-cap slot of a request challenged at Step 11, and the replay edge case of M6. The two races are bounded and documented with their fixes in feedback.py, the README and the CHANGELOG (802464d), but not closed, so that the released code stays the code the results were run on. The paper keeps the simulated algorithm apart from implementation assurance. Section 6 lists the open defects and says that none is exercised by the single-threaded simulator. Twelve real-Redis tests are described as tests of specific cases, not all interleavings, and nowhere is the artifact called deployment-ready."],
    "feedback.py; tests/unit/test_fourth_round.py; tests/integration/test_real_redis.py. Manuscript Section 6 ('Implementation')."),
  ...item("M16", "Learning and attacker economics remain conditional", "Partly done",
    "The short-window winner is not evaluated over long horizons, even though its allowance replenishes. Tie any economic recommendation to sustained leakage for the selected counter.",
    ["The counter now faces the human-like carrier for 360 minutes. It leaks 81 messages an hour, against 789 under the default, and the break-even revenue share for that attacker under the counter is 1.048 of the retail price, so it would lose money. Section 7.8 calls these figures scenario accounting at assumed prices that omit preparation and contracts, and says they do not measure criminal profit. Long-term co-adaptation between an attacker and a drifting baseline was not run."],
    "results/counter_study.md, 'E3'; results/evaluation.md (economics). Manuscript Sections 7.6 and 7.8."),
  ...item("M17", "Performance and timing experiments answer a narrower question", "Done",
    "Report timing distributions by outcome under the adversarial mixture and a clearly stated observer model if making a side-channel claim.",
    ["The load test now reports timing by outcome under the adversarial mixture, with the observer model stated: a remote client that sees only its own requests' response times and wants to tell two outcomes with identical responses apart (an SMS sent, or a refusal at a hard step), equally likely. At concurrency 128, 80.9 % of sends exceeded the floor in server time. The best single threshold separated sends from refusals with balanced accuracy 0.881, fitted to the same samples and from only 22 refusals, so the figure is optimistic. At concurrency 32 it was 0.624. With fast vendors no pair of outcome classes was distinguished (smallest Kolmogorov–Smirnov p = 0.05; best accuracy 0.53). Section 7.8 reports exactly this and makes no general side-channel claim."],
    "scripts/load_test.py; results/performance.md, 'Phase 4'. Manuscript Section 7.8."),
  ...item("M18", "Artifact provenance can still be made safer", "Done",
    "Record and validate a source-tree or executable-code hash, dependency versions and protocol hash for each checkpoint. Distinguish a clean rerun from a resumed one.",
    ["Every run and checkpoint now carries a code hash, and a checkpoint whose hash differs is rejected. The results record the environment and whether the invocation was clean or resumed. Both studies in this round are clean invocations: the main evaluation (9,919 runs, code hash ec40cf34…) and the counter study (7,925 runs, code hash fbf12e7f…). The counter protocol's SHA-256 (4282e483…) is stored in the results and matches the committed file. Those code hashes identify the tagged release at 1c277a0. The later documentation commit (802464d) changes comments only, so its tree hashes differently and would be refused as a source for reusing these checkpoints, which is the guard working as intended; the CHANGELOG records this."],
    "scripts/run_evaluation.py; scripts/run_counter_study.py; results/*.json 'meta'. Manuscript Section 6 and the artifact statement."),
  ...item("M19", "The incident remains motivation rather than evidence", "Partly done; two items remain with the author",
    "A simulation-led title would match the evidence better. Verify the recalled/design-review classification and resolve permission before submission.",
    ["The title is now simulation-led. Table 1's Source column is spelled out ('Recalled' or 'Review'), and its caption says the recollection is not supported by logs. Section 3 opens by saying the section is motivation, not evidence, that permission is being sought, and that no result depends on it. The affiliation and the written permission are for the author to complete before submission, and the author should confirm the Recalled/Review classification of each gap."],
    "Manuscript title, Section 3, Table 1."),

  H1("Section 3: claims that exceeded the evidence"),
  ...item("Q1", "'Every pumper tested' in the abstract", "Fixed",
    "Replace with: 'Across four concentrated 20-minute pumping profiles, three selected short-window counters leaked 6–48 SMS messages; in separate 24-hour attack-free runs, their net attributable completion loss was 0.06–0.43 percentage points of offered users.'",
    ["The abstract now reads: 'On the destination, short-window counters of SMS sends per number block, selected at a benign service target, leaked 6 to 48 messages across four concentrated 20-minute pumping profiles, against 19 to 452 for sequential tests of verification outcomes, at 0.06 to 0.43 points of attack-free completion loss.' It goes on to report the second protocol, the failed service-under-attack claims, and the spread, paced and trust-building pumpers that the counter did not stop."]),
  ...item("Q2", "The discussion compared different attack sets", "Fixed",
    "Separate the two findings and state the counter's four-profile scope and benign-only cost.",
    ["The lesson now reads: 'Outcome-based destination tests were defeated by carriers that verify with human-like delay, fake receipts or know the thresholds. A short-window send counter was not, but it lost to wide, paced and trust-building pumpers and cost users whose own traffic on a block neared its quota or was shared with an attacker.' Both halves now rest on the same attack sets, because the counter faced the adaptive family (M4)."]),
  ...item("Q3", "The destination key is not literally unrotatable", "Fixed",
    "State that a pumper is constrained to its paid ranges and that block-based protection scales with the number of usable blocks.",
    ["Section 4.3: 'A pumper is confined to the ranges its partner terminates but can rotate numbers and blocks within them. Destination policies are keyed on the 8-digit block (10,000 numbers), so their protection weakens as a pumper spreads over more blocks.' E4's security map measures how far it weakens."]),
  ...item("Q4", "Code outcomes do affect the deployed counter policy", "Fixed",
    "'Whatever' is too broad because the graded counter exempts trusted numbers and verified fingerprints … State the traffic and exemption assumptions.",
    ["The sentence is gone. Section 4.3 states the exemption and what it allows: 'Clients with verified history are exempt from both policies, so a code entered on a pumper's number can buy that number an exemption.' The paper no longer says the counter separates attackers. The discussion describes its cost to users who share a block with an attacker, which is rationing."]),
  ...item("Q5", "Idempotence needs a recovery horizon", "Fixed",
    "Narrow the guarantee or repair the protocol.",
    ["Both. Section 4.2: 'Each transition records its effects in the same compare-and-set and a recovery sweep finishes a dead process's work, so effects apply at most once, and exactly once if the sweep runs within 20 minutes, with one exception (Section 6).'"]),
  ...item("Q6", "Interval narrowing is not a variance decomposition", "Fixed",
    "Replace the ending … or quantify the variance components.",
    ["Quantified (M12). Section 6: 'in a nested design (ten configurations, three seeds each) these draws account for 92 % [80, 98] of the variance of the farm's leakage.'"]),
  ...item("Q7", "Recovery harm was attached to the wrong time scope", "Fixed",
    "State both windows separately or compute post-stop attributable loss.",
    ["Post-stop attributable loss is now computed. Section 7.7: 'A poisoner that stops after ten minutes leaves verdicts that meet 406.5 requests after the stop, an attributable loss of 46.2 in that period (48.2 over the whole run).' Table 10 has a separate 'after the stop' row with its own interval [16.9, 79.8]. The whole-run figure moved from 47.6 to 48.2 because the simulator changed (stable reachability, returning users with history)."]),
  ...item("Q8", "Timing variation is not established outcome identifiability", "Fixed",
    "Say the floor no longer forces equal completion times for those requests; measure class leakage separately if intended.",
    ["Class leakage is now measured under a stated observer model (M17), and the phrase 'distinguishable by construction' is gone. Section 7.8: 'Under an adversarial mixture with heavy-tailed vendors at concurrency 128, 81 % of sends overran the floor, and an observer seeing only its own response times told a send from a refusal with 88 % balanced accuracy (threshold fitted to 22 refusals).'"]),
  ...item("Q9", "Every density needs its experimental qualifier", "Fixed",
    "Replace 'at every density' with the precise three service-calibration settings and identify the candidate sets and four-profile aggregate.",
    ["The conclusion now reads: 'Counting sends on the destination beat testing outcomes against concentrated pumpers, but a frozen counter failed its service claims when the attacker shares blocks with real users, and loses to wide, paced and trust-building pumpers.' Section 6 describes the four-profile aggregate and where the full sequential grid was searched; the candidate grids are listed in config/evaluation_protocol.json. 'At every density' appears only for E5, which ran the full grid and density-specific attacks at each setting (M7)."]),
  ...item("Q10", "Exactly once in the rebuttal", "Fixed",
    "Exactly-once block effects are not unconditional under identifier eviction.",
    ["This letter, the manuscript, the README and the module notes in feedback.py now state the narrowed guarantee: at most once, and exactly once if a sweep runs within the 20-minute horizon (twice the code lifetime). The edge case in M6 is the one exception, and since 802464d it is stated in the module notes, the README and the documentation as well as in the manuscript."]),

  H1("Section 4: numerical consistency audit"),
  P("We went through each row of the reviewer's table. Several numbers moved in 2.8.0 because the simulator changed for every study (stable reachability per number; returning users with verified history). For example, the default's leakage against the four matched pumpers is now 90, 19, 452 and 105 (89, 17, 405 and 104 in 2.7.0), and the human-like carrier's first verdict now comes at minute 11.6."),
  table([2500, 6600], [
    ["Reviewer's row", "What changed"],
    ["Section 7.7 versus Table 9: 406 post-stop hits; 47.6 whole-run loss", "Post-stop attributable loss computed: 46.2 [16.9, 79.8] after the stop, 48.2 [17.1, 84.3] over the whole run, in separate rows of Table 10 and stated separately in the text."],
    ["Abstract and Section 8: 'every pumper tested'", "Removed. The abstract names the four concentrated profiles, and the counter was run against the adaptive and spread profiles (M4)."],
    ["Abstract: 0.06–0.43 % beside attack leakage", "Labelled 'attack-free completion loss'. The cost under attack is reported separately (E1, K3, K5)."],
    ["Table 8 versus 'at every density'", "First protocol: full grid at the busiest setting only, stated. E5: full grid and density-specific attacks at all three settings."],
    ["'All hold' and the pass rule", "The abstract no longer summarises the first protocol's claims. Section 6 states the pass rule, and each claim is reported with its cell count."],
    ["Loss up to 0.43 % versus 0.06 %", "The text says 0.06 is the busiest setting at 65 % conversion and the upper end (0.43) is a sparser setting at 80 %."],
    ["Table 4 versus Table 6a: farm 46 % versus 47 %", "Different studies: 45.6 % over thirty seeds (Table 4), 47.2 % over ten (Table 6a). Both captions give their seed counts, Table 4's says 'mean of per-run shares', and Table 6a now uses one decimal throughout."],
    ["Table 7: first verdict 15.2 min, containment 9 min", "Denominators are now beside each time: containment over contained seeds, first verdict over seeds with a verdict. In 2.8.0 the human-like carrier has no contained seed in twenty minutes, so containment is a dash and its first verdict is 11.6."],
    ["Farm share versus ratio of means", "Table 4's caption says 'mean of per-run shares'."],
    ["Table 9: hard deny 121 versus 121.2", "Both shown as 121.2 in Table 10, and hits and never-completed counts use one decimal throughout."],
    ["Metadata: 9,759 runs, 322 resumed", "2.8.0: 9,919 runs, clean invocation, none resumed; code hash on every run (M18)."],
  ]),
  P(""),

  H1("Section 5: related work and competing approaches"),
  Bullet("**Rate and burst controls (RFC 2697).** Implemented and evaluated. Section 2 now cites RFC 2697 for separating a sustained rate from a burst allowance. Our token bucket keeps the counter's rate with a burst of 4 or 12, and Section 4.3 says how it differs from the RFC's marker. On shared blocks it leaked 84 to 212 against the four carriers, more than the TTL-reset counter (80 to 158). Against the poisoner, a burst of 12 cost users nothing only because it let the flood through: 1,974 messages, as with no policy. A burst of 4 leaked 1,877 at 0.12 points. Section 7.6 reports this."),
  Bullet("**Counting combined with outcome evidence.** The counter combined with the sequential tests leaked least in total on shared blocks (29, 28, 82 and 51), and Section 7.6 says so. It is not free: against the poisoner it cost 1.35 points, against 0.72 for the counter alone. A trust budget on the counter's exemption changed neither leakage nor service in E1, apart from 0.04 points for returning users. The paper's lesson is no longer a choice between volume and outcomes. It recommends the counter and the tests together, with a quota set from each block's own traffic."),
  Bullet("**Hierarchical and trust-aware controls.** Every arm keeps the per-number backoff, the session cap and the hourly budget, but per-client quotas inside a block and carrier spend ceilings were not compared as combinations. This is listed as not evaluated."),
  Bullet("**Learned features (Huh et al.).** Section 2 says that their detector learns from labelled traffic and acts per request, that our policies are hand-specified per destination block, and that theirs was not reproduced. The conclusions are limited to the implemented policies."),
  Bullet("**Other sequential policies.** Windowed statistics and confidence sequences are named in Section 2 as not evaluated. The paper does not claim that verification outcomes are unhelpful in general; in E1 the best total leakage came from using them alongside the counter."),
  Bullet("**Commercial graded protection.** Twilio's Fraud Guard and SMS Pumping Risk Score are cited as established practice for graded destination action, with no benchmark and no claim of superiority. The paper's contribution is the measured boundary and the failure analysis, as the reviewer suggested."),

  H1("Section 6: presentation"),
  Bullet("**Front matter and structure.** Simulation-led title; first-page highlights removed. The introduction now says that the destination became the centre of the study and states the counter finding and its failures before Section 7. Table 3 (the coverage matrix) is introduced in Section 6. The affiliation remains for the author."),
  Bullet("**Figure 1.** Redrawn larger, with the legend below the panels. Panel titles and the caption define 'caps lifted' (behavioural layers only) and 'caps on' (per-minute source caps at three times the legitimate rate). The manuscript now includes vector PDFs of all figures, so error bars stay sharp at any zoom."),
  Bullet("**Figure 2.** Larger labels. The caption says that * marks an unadjusted bootstrap interval excluding zero (19 of 90 cells). The companion Table 5 gives the larger effects with intervals, and the full interval matrix is in paper/figures/fig2_ablation_matrix.csv."),
  Bullet("**Figure 3.** Larger labels. The caption separates shares of attack requests (a) from shares of legitimate users (b)."),
  Bullet("**Figure 4.** The cap family and the risk-score family are in separate panels, with decision-relevant points labelled and larger type. The caption still reads 'sampled points, not an optimised frontier'."),
  Bullet("**Figure 5.** A labelled 'model = measured' line and units (SMS) in the residual panels, with the unsaturated runs used for the error summaries marked. The text gives the unsaturated subset's error, and the caption keeps 'a mechanism check on observed blocks, not a forecast'."),
  Bullet("**Figure 6.** Points are labelled directly with short policy names instead of a numbered key. The benign service target is drawn on panel (a), the axes say that leakage sums four attack-profile means and that completion comes from separate attack-free runs, and panel (b) shows paired differences per attacker."),
  Bullet("**Figure 7 (new).** The counter's operating boundary: service among hot-block users against their legitimate rate, and leakage against the pumper's spread."),
  Bullet("**Table 1.** Source spelled out as 'Recalled' or 'Review'. The caption says the recollection is not supported by logs, and Section 3's first paragraph is about permission."),
  Bullet("**Table 3.** Profiles grouped by capability, with a Policies column showing which destination policies each faced."),
  Bullet("**Table 4.** The caption says 'mean of per-run shares'."),
  Bullet("**Old Table 5 (one-at-a-time sensitivity).** Removed to stay within the word limit. Figure 4(b) and the text of Section 7.3 carry it, and the full grid is in the artifact. The new Table 5 is the key-effects table of Figure 2."),
  Bullet("**Table 6.** The panel header states the attack duration ('20-minute attack unless stated'), the caption gives seeds and history generation, and percentages use one decimal."),
  Bullet("**Table 7.** Denominators beside each time estimate, and a two-row header with units."),
  Bullet("**Table 8.** Five rows: no policy, the default, the best sequential setting at the target, the selected counter, the best daily counter. The caption says 'net loss attributable to the policy (points)', 'attack-free runs' and 'Benign target: 63.95 %'. The matched-false-alarm settings are in Figure 6(a) and the artifact."),
  Bullet("**Table 9 (new).** The second protocol's claims with cell counts and results."),
  Bullet("**Table 10 (poisoner).** Precision standardised, and separate rows for the whole run and after the stop."),

  H1("Section 7: the single question"),
  Quote("After enforcing the selected counter correctly under concurrency, can you show that its leakage advantage survives a frozen comparison on heterogeneous traffic where the attacker competes with real users for the same destination quotas, while those users still meet the stated service target?"),
  P("The counter is now enforced correctly under concurrency (M5), and the comparison was frozen and run on the held-out family's heterogeneous traffic, with the pumper on blocks real users share (E2) and on the same attacked trace (E1)."),
  P("**The leakage advantage survives.** On the held-out family the counter leaked 33, 34, 33 and 62 messages on average against the four carriers, against 287, 36, 344 and 287 for the default and 470 to 1,857 with no policy. It met K1 and K4; in the 13 cells where it leaked more than the default, the carrier was always the instant verifier. On 60-minute shared-block attacks it leaked 80 to 158, against 31 to 897 for the default."),
  P("**The service target, under attack, does not survive in general.** K3 (attributable loss under attack at most 0.5 points) failed in 17 of 144 cells, 13 of them at the three points with the most legitimate traffic. K5 (no more than 0.25 points above the default's loss) failed in 51 of 144. When a block's own traffic nears the quota, users and pumper compete for it, and the counter cannot tell them apart. When the pumper is on the users' blocks and their traffic is light, the counter protects them, because without it the pumper consumes the block and the hourly budget."),
  P("**The region where it loses** is mapped (E3, E4, Figure 7): pumpers spread over ten or more blocks for an hour, pumpers paced to the quota, trust builders verifying on random numbers, and the poisoner on shared blocks, which still leaked 1,662 messages under the counter. Its cost to users rises from 2.3 points at the quota to 5.5 at twice it (13.2 without WhatsApp), and a product launch costs the launch blocks' users 16 points."),
  P("So the paper's claim is now narrower and, we think, defensible. A short-window counter is a cheap and strong limit on concentrated pumping that outcome-reading carriers cannot game. It rations the block it protects, and its quota has to be set from that block's own traffic. The counter and the sequential tests together leaked least. This is the result the abstract, Section 7.6, the discussion and the conclusion now state."),

  H1("Appendix A of the report: disposition of the third-round findings"),
  table([1900, 2000, 5200], [
    ["Item", "Reviewer's status", "This round"],
    ["R1 Fallback wiring", "Closed", "Reachability is now stable per number as well (M13)."],
    ["R2 Exposure windows", "Closed", "Unchanged."],
    ["R3 Graded escalation", "Closed for stated race", "Unchanged; the counter admission race is fixed separately (M5)."],
    ["R4 Counter units", "Closed for retries", "Concurrent first-stage enforcement fixed and tested on real Redis (M5)."],
    ["R5 Matched service", "Substantially repaired", "Service under attack (E1), held-out claims (E2), margins and cohorts (E5). K3 and K5 fail and are reported (M1, M2, M9)."],
    ["R6 Common pipeline", "Closed", "Unchanged."],
    ["R7 Mixed receipts", "Partly closed", "Timeout-worker race still open, disclosed (M15)."],
    ["R8 Atomicity and recovery", "Partly closed", "Identifiers kept for the replay horizon; at most once, exactly once within 20 minutes; one edge case disclosed (M6)."],
    ["R9 Attributable loss", "Substantially repaired", "Post-stop loss computed (Q7); gross losses and gains and cohorts recorded (M2)."],
    ["R10 Held-out study", "Partly closed", "The counter is evaluated on the held-out family under its own protocol (M1)."],
    ["R11 Heterogeneity", "Partly closed", "Stable identities and three correlated stress rows for the counter (M13)."],
    ["R12 Precision", "Partly closed", "Nested variance design (M12)."],
    ["R13 Containment", "Closed", "Unchanged."],
    ["R14 Learned history", "Substantially repaired", "Unchanged; long-term co-adaptation not run (M16)."],
    ["R15 Leakage equation", "Closed", "Unchanged."],
    ["R16 Adaptive attackers", "Partly closed", "The counter faced the whole adaptive family (M4)."],
    ["R17 Economics", "Substantially repaired", "Break-even under the counter over 360 minutes (M16)."],
    ["R18 Performance", "Substantially repaired", "Timing by outcome with an observer model (M17). Live vendors still untested."],
    ["R19 Incident and title", "Partly closed", "Simulation-led title. Permission and affiliation remain with the author (M19)."],
  ]),
  P(""),

  H1("Appendix B of the report: the reviewer's reproductions"),
  table([3000, 6100], [
    ["Reviewer's check", "Result on release 2.8.0"],
    ["Concurrent counter: eight requests, barrier before Step 11", "Four SMS and four challenges, serial or concurrent, in memory, on fakeredis and across two instances on real Redis."],
    ["Recovery after 256 later block events", "257 stays 257; repeated across instances on real Redis. Batches older than the 20-minute horizon are skipped and counted, never applied twice."],
    ["Concentrated trust builder, three paired seeds", "Consistent with E3: 36 under the counter against 502 under the default (ten seeds). Trust builders on random numbers are not stopped (577 against 577)."],
    ["Protocol hash and headline values", "Counter protocol SHA-256 4282e483… recorded and matching; headline numbers mapped to JSON paths in results/headline_numbers.md."],
    ["Regression suite", "393 tests pass, including twelve real-Redis integration tests (re-run for this letter)."],
  ]),
  P(""),
  P("We are grateful for the time this report took. The two counterexamples were exactly where the new claim depended on enforcement, and the single question made us run the experiment that shows where the counter stops working. The paper is narrower as a result, and we think more useful."),
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

Packer.toBuffer(doc).then(buf => { fs.writeFileSync("rebuttal_round4.docx", buf); console.log("wrote rebuttal_round4.docx"); });
