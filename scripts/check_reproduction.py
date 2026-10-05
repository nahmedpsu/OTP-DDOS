#!/usr/bin/env python3
"""Replay a stratified sample of the recorded simulation runs with the current code and compare every
recorded field. Used for 2.8.1 to 2.8.3, whose implementation repairs (event time on replay, identifier
retention, the timeout worker's conditional removal, Step 11 challenges and the source caps) must not
change any simulated result: the simulator is single-threaded and never crashes a process, so the
repaired paths are either not reached or reached with identical outcomes.

    python3 scripts/check_reproduction.py [--per-study 2] [--procs 2] [--out results/reproduction_check.md]

Specs are rebuilt with the same study builders as scripts/run_evaluation.py (stage 1) and
scripts/run_counter_study.py (stage 1 and E5 evaluation), matched to the recorded runs by spec hash
and seed, and run again. Only wall time, provenance and bookkeeping fields are excluded from the
comparison."""
import argparse
import gzip
import json
import multiprocessing as mp
import pathlib
import random
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from otp_guard.evaluation import counter_study as C                     # noqa: E402
from otp_guard.evaluation import runner as R_                           # noqa: E402
from otp_guard.evaluation.jobs import spec_hash                         # noqa: E402
from otp_guard.evaluation.provenance import code_hash                   # noqa: E402
from otp_guard.evaluation.runner import DESIGNS, robustness_points       # noqa: E402
from otp_guard.evaluation.sim import run_sim                            # noqa: E402

IGNORE = {"wall_s", "code_hash", "study", "index", "spec_hash"}


def evaluation_jobs():
    seeds, sseeds, day = list(range(30)), list(range(10)), 24 * 60
    jobs = []

    def add(study, specs, index):
        jobs.extend((study, s) for s in specs)
    for design, feats in DESIGNS.items():
        add(design, *R_.study_multi_seed(seeds, feats, design=design))
    add("variance", *R_.study_variance(seeds))
    add("variance_nested", *R_.study_variance_nested())
    add("cadence", *R_.study_cadence(sseeds))
    add("ablation", *R_.study_ablation(sseeds))
    add("interactions", *R_.study_interactions(sseeds))
    add("sweep", *R_.study_sweep(sseeds))
    add("capsweep", *R_.study_cap_sweep(sseeds))
    add("adaptive", *R_.study_adaptive(sseeds))
    add("poisoner", *R_.study_poisoner(sseeds))
    add("alternatives", *R_.study_alternatives(sseeds))
    add("alternatives_fp", *R_.study_alternatives_fp(list(range(5)), minutes=day))
    add("baseline", *R_.study_baseline(sseeds))
    add("pumping", *R_.study_pumping(sseeds))
    add("long_attack", *R_.study_long_attack(sseeds))
    add("spread", *R_.study_spread(sseeds))
    add("dilution", *R_.study_dilution(list(range(5))))
    add("legit24h", *R_.study_legit_only_24h(list(range(5)), minutes=day))
    add("outage", *R_.study_outage(list(range(8))))
    add("fallback", *R_.study_fallback(list(range(5)), minutes=day))
    add("robustness", *R_.study_robustness())
    add("matched_tuning", *R_.study_matched_tuning(R_.TUNING_SEEDS, legit_minutes=day))
    return jobs


def counter_jobs():
    jobs = []
    for study, (specs, _) in (("E1", C.study_e1()), ("E2", C.study_e2(robustness_points())), ("E3", C.study_e3()),
                              ("E4", C.study_e4()), ("E5_tuning", C.study_e5_tuning())):
        jobs.extend((study, s) for s in specs)
    rec = json.loads((ROOT / "results" / "counter_study.json").read_text())
    sel = {d: {"chosen": v["chosen"]} for d, v in rec["E5"]["selection"].items()}
    jobs.extend(("E5_eval", s) for s in C.study_e5_eval(sel)[0])
    return jobs


def recorded(path):
    out = {}
    with gzip.open(path, "rt") as f:
        for line in f:
            r = json.loads(line)
            out[(r["spec_hash"], r["spec"]["seed"])] = r
    return out


def compare(a, b, path=""):
    """Paths at which two JSON-like values differ."""
    if isinstance(a, dict) and isinstance(b, dict):
        diffs = []
        for k in sorted(set(a) | set(b)):
            if path == "" and k in IGNORE:
                continue
            diffs += compare(a.get(k), b.get(k), f"{path}/{k}")
        return diffs
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [path]
        return [d for x, y in zip(a, b) for d in compare(x, y, path)][:1]
    if isinstance(a, float) or isinstance(b, float):
        return [] if (a is None) == (b is None) and (a is None or abs(a - b) <= 1e-9 * max(1.0, abs(a))) else [path]
    return [] if a == b else [path]


def _run(item):
    i, spec = item
    return i, json.loads(json.dumps(run_sim(spec), default=str))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-study", type=int, default=2)
    ap.add_argument("--procs", type=int, default=2)
    ap.add_argument("--max-minutes", type=int, default=400, help="skip runs longer than this (the 24-hour legitimate runs)")
    ap.add_argument("--out", default=str(ROOT / "results" / "reproduction_check.md"))
    a = ap.parse_args()
    rng = random.Random(20261003)
    sample = []
    for label, jobs, recs in (("evaluation", evaluation_jobs(), recorded(ROOT / "results" / "evaluation_runs.jsonl.gz")),
                              ("counter study", counter_jobs(), recorded(ROOT / "results" / "counter_study_runs.jsonl.gz"))):
        by_study = {}
        for study, spec in jobs:
            key = (spec_hash(spec), spec.seed)
            if key in recs and spec.minutes + spec.warmup_minutes <= a.max_minutes:
                by_study.setdefault(study, []).append((spec, recs[key]))
        for study in sorted(by_study):
            for spec, rec in rng.sample(by_study[study], min(a.per_study, len(by_study[study]))):
                sample.append((label, study, spec, rec))
    t0 = time.time()
    with mp.Pool(a.procs) as pool:
        fresh = dict(pool.imap_unordered(_run, [(i, s[2]) for i, s in enumerate(sample)]))
    rows, mismatched = [], 0
    for i, (label, study, spec, rec) in enumerate(sample):
        d = compare({k: v for k, v in rec.items() if k not in IGNORE}, {k: v for k, v in fresh[i].items() if k not in IGNORE})
        mismatched += bool(d)
        rows.append(f"| {label} | {study} | {rec['spec_hash']} | {spec.seed} | {'identical' if not d else ', '.join(d[:3])} |")
    rec_hashes = sorted({s[3]["code_hash"][:12] for s in sample})
    text = [f"# Reproduction check ({time.strftime('%Y-%m-%d')})", "",
            f"{len(sample)} recorded runs, {a.per_study} per study (stratified, seed 20261003; runs longer than "
            f"{a.max_minutes} simulated minutes skipped), replayed with the current code (code hash `{code_hash()[:16]}...`) "
            f"against the records produced by `{'`, `'.join(rec_hashes)}...`. Every recorded field is compared except "
            f"{', '.join(sorted(IGNORE))}. **{len(sample) - mismatched} of {len(sample)} identical.** "
            f"Wall time {time.time() - t0:.0f} s.", "",
            "| Results file | Study | Spec hash | Seed | Outcome |", "|---|---|---|---:|---|"] + rows
    pathlib.Path(a.out).write_text("\n".join(text) + "\n")
    print(f"{len(sample) - mismatched}/{len(sample)} identical -> {a.out}")
    sys.exit(1 if mismatched else 0)


if __name__ == "__main__":
    main()
