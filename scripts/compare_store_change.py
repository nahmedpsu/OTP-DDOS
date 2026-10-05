#!/usr/bin/env python3
"""Seventh-round review, M1: what changed when the in-memory store was made to keep state as Redis
does (release 2.9.0). Compares the 2.8.x results kept in results/historical_2.8/ with the regenerated
results/ and writes results/store_change_report.md and .json:

  1. every recorded run, matched by spec hash and seed: identical, or changed only in counts outside
     leakage and legitimate outcomes (outage alerts, block verdicts, which step stopped a request),
     changed in legitimate outcomes (friction, funnel, users hit), or changed in leakage;
  2. the two protocols' selections and the settings whose eligibility at the tuning target changed;
  3. the claims C1-C5 and K1-K5;
  4. every entry of the headline-number map (scripts/headline_numbers.py).

Fields added in 2.9.0 (block_state_at_first_attack, attacker_sms_exempt) and bookkeeping fields are
not compared."""
import gzip
import json
import pathlib
import statistics
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import headline_numbers as H                                                 # noqa: E402

OLD, NEW = ROOT / "results" / "historical_2.8", ROOT / "results"
SKIP = {"wall_s", "code_hash", "index", "study", "spec_hash", "block_state_at_first_attack", "attacker_sms_exempt"}
LEGIT = ("friction", "funnel", "legit_hit_by_verdict", "legit_hit_stage1", "legit_hit_stage2", "legit_hit_refused",
         "legit_hit_lost", "legit_hit_per_min", "requests", "reactions")
RUN_FILES = ("evaluation_runs.jsonl.gz", "counter_study_runs.jsonl.gz", "round5_attack_free_runs.jsonl.gz",
             "round5_union_eval_runs.jsonl.gz")


def flat(v, path=""):
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            out.update(flat(x, f"{path}/{k}"))
        return out
    return {path: v}


def load_runs(path):
    out = {}
    with gzip.open(path, "rt") as f:
        for line in f:
            r = json.loads(line)
            key = (r.get("spec_hash"), r["spec"]["seed"] if "spec" in r else r.get("seed"), json.dumps(r.get("index")))
            out[key] = r
    return out


def classify(a, b):
    fa = {k: v for k, v in flat({k: v for k, v in a.items() if k not in SKIP}).items()}
    fb = {k: v for k, v in flat({k: v for k, v in b.items() if k not in SKIP}).items()}
    diff = sorted(k for k in set(fa) | set(fb) if fa.get(k) != fb.get(k))
    if not diff:
        return "identical", diff
    if any(k.startswith("/attack/leaked") for k in diff):
        return "leakage", diff
    if any(k.split("/")[1] in LEGIT for k in diff):
        return "legitimate outcomes", diff
    return "other counts only", diff


def arm(r):
    """The destination policy of a run, read from its index (first-protocol design studies run the default tests)."""
    words = [str(x) for x in (r.get("index") or [])]
    j = " ".join(words)
    if "counter" in j and "sequential" in j:
        return "counter + tests"
    if "sequential" in j:
        return "sequential tests"
    if "counter" in j:
        return "counter"
    if "token bucket" in j:
        return "token bucket"
    if "none" in words:
        return "no policy"
    return "first-protocol designs (default tests)"


def by_arm(leak):
    out = []
    for a in sorted({x["arm"] for x in leak}):
        xs = [x for x in leak if x["arm"] == a and x["new"] != x["old"]]
        if not xs:
            continue
        rel = [abs(x["new"] - x["old"]) / max(x["old"], 1) for x in xs]
        out.append({"arm": a, "runs": len(xs), "decreased": sum(x["new"] < x["old"] for x in xs),
                    "tuning_runs": sum("tuning" in str(x["study"]) for x in xs),
                    "median_relative_change_pct": round(100 * statistics.median(rel), 1),
                    "leaked_old": sum(x["old"] for x in xs), "leaked_new": sum(x["new"] for x in xs),
                    "fewer_outage_alerts": sum((x["alerts_new"] or 0) < (x["alerts_old"] or 0) for x in xs),
                    "outage_alerts_old": sum(x["alerts_old"] or 0 for x in xs), "outage_alerts_new": sum(x["alerts_new"] or 0 for x in xs)})
    return out


def runs_section():
    rows, changed_leak, total = [], [], {}
    for fname in RUN_FILES:
        if not (OLD / fname).exists() or not (NEW / fname).exists():
            continue
        old, new = load_runs(OLD / fname), load_runs(NEW / fname)
        by = {}
        for key, b in new.items():
            a = old.get(key)
            study = b.get("study") or (b.get("index") or ["?"])[0]
            if a is None:
                by.setdefault(study, {}).setdefault("unmatched", 0)
                by[study]["unmatched"] += 1
                continue
            cat, diff = classify(a, b)
            by.setdefault(study, {}).setdefault(cat, 0)
            by[study][cat] += 1
            if cat == "leakage":
                la, lb = a["attack"]["leaked_total"], b["attack"]["leaked_total"]
                changed_leak.append({"file": fname, "study": study, "spec_hash": key[0], "seed": key[1], "old": la, "new": lb,
                                     "arm": arm(b), "alerts_old": a.get("outage_alerts"), "alerts_new": b.get("outage_alerts")})
        for study, c in sorted(by.items(), key=lambda kv: str(kv[0])):
            n = sum(c.values())
            rows.append({"file": fname, "study": study, "runs": n, **c})
            for k, v in c.items():
                total[k] = total.get(k, 0) + v
    return rows, changed_leak, total


def selections():
    out = []
    eo, en = json.loads((OLD / "evaluation.json").read_text()), json.loads((NEW / "evaluation.json").read_text())
    co, cn = json.loads((OLD / "counter_study.json").read_text()), json.loads((NEW / "counter_study.json").read_text())
    for proto, so, sn, comp in (("first protocol (matched)", eo["matched"]["selection"], en["matched"]["selection"], "tuning_completion_pct"),
                                ("second protocol (E5)", co["E5"]["selection"], cn["E5"]["selection"], "tuning_completion")):
        for d in sorted(set(so) | set(sn), key=str):
            a, b = so.get(d, {}), sn.get(d, {})
            for role in sorted(set(a.get("chosen", {})) | set(b.get("chosen", {}))):
                out.append({"protocol": proto, "density": d, "role": role, "old": a.get("chosen", {}).get(role),
                            "new": b.get("chosen", {}).get(role)})
            ta, tb = a.get("service_target_completion_pct"), b.get("service_target_completion_pct")
            ea = {s for s, v in a.get(comp, {}).items() if ta is not None and v >= ta}
            eb = {s for s, v in b.get(comp, {}).items() if tb is not None and v >= tb}
            out.append({"protocol": proto, "density": d, "role": "eligible settings at the tuning target",
                        "old": len(ea), "new": len(eb), "lost": sorted(ea - eb), "gained": sorted(eb - ea),
                        "target_old": ta, "target_new": tb})
    return out


def claims():
    eo, en = json.loads((OLD / "evaluation.json").read_text()), json.loads((NEW / "evaluation.json").read_text())
    co, cn = json.loads((OLD / "counter_study.json").read_text()), json.loads((NEW / "counter_study.json").read_text())
    out = []
    for c in ("C1", "C2", "C3", "C4", "C5"):
        a, b = eo["robustness"][c], en["robustness"][c]
        out.append({"claim": c, "old": f"{a['true']}/{a['cells']}", "new": f"{b['true']}/{b['cells']}", "holds_old": a["holds"], "holds_new": b["holds"]})
    for c in ("K1", "K2", "K3", "K4", "K5"):
        a, b = co["E2"]["claims"][c], cn["E2"]["claims"][c]
        out.append({"claim": c, "old": f"{a['true']}/{a['cells']}", "new": f"{b['true']}/{b['cells']}", "holds_old": a["holds"], "holds_new": b["holds"]})
    return out


def headlines():
    def table(res):
        files = {f: json.loads((res / f).read_text()) for f in ("evaluation.json", "performance.json", "counter_study.json",
                                                                 "round5_analyses.json", "performance_holdout.json") if (res / f).exists()}
        vals = {}
        for label, f, path, seeds in H.ENTRIES:
            if f in files:
                try:
                    vals[label] = H.fmt(H.get(files[f], path))
                except (KeyError, TypeError, IndexError):
                    vals[label] = "missing"
        return vals
    a, b = table(OLD), table(NEW)
    return [{"headline": k, "old": a.get(k), "new": b.get(k), "changed": a.get(k) != b.get(k)} for k in a]


def main():
    rows, leak, total = runs_section()
    sel, cl, hd = selections(), claims(), headlines()
    arms = by_arm(leak)
    out = {"runs": rows, "totals": total, "leakage_changes": leak, "leakage_by_arm": arms, "selections": sel, "claims": cl, "headlines": hd}
    (NEW / "store_change_report.json").write_text(json.dumps(out, indent=1))
    unmatched = total.pop("unmatched", 0)
    n = sum(total.values())
    L = ["# What changed when the memory store was aligned with Redis (2.9.0; seventh-round review, M1)", "",
         "The 2.8.x results are kept in `results/historical_2.8/`; every study was rerun with release 2.9.0, whose memory store "
         "keeps state as Redis does (`tests/unit/test_store_parity.py`). Generated by `scripts/compare_store_change.py`.", "",
         "## Every run", "",
         f"{n} runs matched by spec hash and seed: " + ", ".join(f"{v} {k}" for k, v in sorted(total.items(), key=lambda kv: -kv[1])) +
         f". {unmatched} runs of 2.9.0 have no 2.8.x counterpart (a comparison setting whose selection changed; see below).", "",
         "| Results file | Study | Runs | Identical | Other counts only | Legitimate outcomes | Leakage |", "|---|---|---:|---:|---:|---:|---:|"]
    for r in rows:
        L.append(f"| {r['file']} | {r['study']} | {r['runs']} | {r.get('identical', 0)} | {r.get('other counts only', 0)} | "
                 f"{r.get('legitimate outcomes', 0)} | {r.get('leakage', 0)} |")
    big = sorted(leak, key=lambda x: -abs(x["new"] - x["old"]))
    tot = [x for x in leak if x["new"] != x["old"]]
    L += ["", "## Where leakage changed", "",
          f"A leakage count (the total or a block's) changed in {len(leak)} runs; the total changed in {len(tot)}, and fell in "
          f"{sum(x['new'] < x['old'] for x in tot)}. By destination policy (runs whose total changed; outage alerts suspend the "
          "block tests, so they matter to the arms that run them):", "",
          "| Policy | Runs | Fell | Tuning runs | Median relative change | Leaked, 2.8.x / 2.9.0 | Fewer outage alerts | Outage alerts, 2.8.x / 2.9.0 |",
          "|---|---:|---:|---:|---:|---|---:|---|"]
    L += [f"| {a['arm']} | {a['runs']} | {a['decreased']} | {a['tuning_runs']} | {a['median_relative_change_pct']} % | "
          f"{a['leaked_old']:,} / {a['leaked_new']:,} | {a['fewer_outage_alerts']} | {a['outage_alerts_old']} / {a['outage_alerts_new']} |" for a in arms]
    L += ["", "The largest changes:", "",
          "| Study | Spec hash | Seed | 2.8.x | 2.9.0 |", "|---|---|---:|---:|---:|"]
    L += [f"| {x['study']} | {x['spec_hash']} | {x['seed']} | {x['old']} | {x['new']} |" for x in big[:25]]
    L += ["", "## Selections and eligibility", "", "| Protocol | Density | Role | 2.8.x | 2.9.0 |", "|---|---|---|---|---|"]
    for s in sel:
        if s["role"] == "eligible settings at the tuning target":
            extra = (f" (lost: {', '.join(s['lost']) or 'none'}; gained: {', '.join(s['gained']) or 'none'}; target "
                     f"{s['target_old']:.2f} / {s['target_new']:.2f})") if s["target_old"] is not None else ""
            L.append(f"| {s['protocol']} | {s['density']} | {s['role']} | {s['old']} | {s['new']}{extra} |")
        else:
            L.append(f"| {s['protocol']} | {s['density']} | {s['role']} | {s['old']} | {s['new']}{'' if s['old'] == s['new'] else ' (changed)'} |")
    L += ["", "## Claims", "", "| Claim | 2.8.x | 2.9.0 |", "|---|---|---|"]
    L += [f"| {c['claim']} | {c['old']} ({'holds' if c['holds_old'] else 'fails'}) | {c['new']} ({'holds' if c['holds_new'] else 'fails'}) |" for c in cl]
    ch = [h for h in hd if h["changed"]]
    L += ["", f"## Headline numbers ({len(ch)} of {len(hd)} changed)", "", "| Headline | 2.8.x | 2.9.0 |", "|---|---|---|"]
    L += [f"| {h['headline']} | {h['old']} | {h['new']} |" for h in hd]
    (NEW / "store_change_report.md").write_text("\n".join(L) + "\n")
    print("\n".join(L[:12]))


if __name__ == "__main__":
    main()
