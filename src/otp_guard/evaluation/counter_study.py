"""The destination-counter study of the fourth review round (config/counter_protocol.json).

Five experiments around the policies the 2.7.0 matched comparison selected, all on seeds that
selection never saw:

  E1  attacked service: competitors on the same attacked legitimate trace, pumper on blocks real users
      use or on other blocks, a poisoner; leakage and attributable loss from the same runs.
  E2  the held-out family of config/evaluation_protocol.json, judged by the protocol's claims K1-K5.
  E3  the adaptive family: white-box, receipt-faking and trust-building carriers, spreading and
      quota-aware pumpers, 360-minute attacks.
  E4  the operating boundary: service against the legitimate rate on the attacked blocks and fallback
      reachability; leakage against the number of blocks the pumper spreads over.
  E5  the 2.7.0 selection rule with the full sequential grid at every density and density-specific
      attack runs, evaluated on fresh seeds; mean, worst-case and constrained preferences.

Spec builders return (specs, index) like runner.study_*; summaries take the results grouped by index."""
import json
import math
import pathlib
import random
import statistics as st
from dataclasses import replace

from ..config import ALL_FEATURES
from .runner import (ADAPTIVE_ATTACKERS, DEFAULT_SETTING, DENSITIES, MATCHED, MATCHED_ATTACKERS, MATCHED_FAMILIES, PUMPING_ATTACKERS,
                     _COUNTER_FEATS, _NO_TESTS, _credit_label, _held_out_attacker, _rob_legit, attacker_bill, attributable_loss,
                     paired_difference, randomised, robustness_points, summarise, summarise_legit_only, MC)
from .calibration import value as cal
from .sim import AttackerSpec, LegitSpec, SimSpec
from .stats import boot_ci

PROTOCOL_PATH = pathlib.Path(__file__).resolve().parents[3] / "config" / "counter_protocol.json"
CP = json.loads(PROTOCOL_PATH.read_text())
FRESH = CP["seeds"]["fresh_evaluation"]
PRINCIPAL = CP["principal_counter"]
DENSITY_COUNTER = CP["density_counters"]
SEQ_BEST = "sequential T300 c0"

_C410 = dict(block_count_limit=(4, 600), block_count_action="graded")
EXPLORATORY = {
    "token bucket 4/10 min burst 4": (_COUNTER_FEATS, dict(_NO_TESTS, block_count_mode="token_bucket", block_bucket_burst=4, **_C410)),
    "token bucket 4/10 min burst 12": (_COUNTER_FEATS, dict(_NO_TESTS, block_count_mode="token_bucket", block_bucket_burst=12, **_C410)),
    "counter 4/10 min + sequential": (_COUNTER_FEATS, dict(_C410)),
    "counter 4/10 min + trust budget": (_COUNTER_FEATS, dict(_NO_TESTS, known_good_budget_per_min=8, **_C410)),
}


def policy(name):
    """(features, cfg overrides) of a frozen policy or an exploratory alternative."""
    if name in EXPLORATORY:
        f, c = EXPLORATORY[name]
        return f, dict(c)
    _, f, c = MATCHED[name]
    return f, dict(c)


def _spec(pol, attacker, legit, minutes, warmup, seed, legit_only=False):
    feats, cfg = policy(pol)
    return SimSpec(attacker=attacker, legit=legit, minutes=minutes, warmup_minutes=warmup, features=feats, cfg_overrides=cfg,
                   caps_lifted=True, seed=seed, legit_only=legit_only, record_requests=True)


def _legit(density, conversion=0.65, **kw):
    return LegitSpec(conversion=conversion, autofill_fraction=0.2, blocks=DENSITIES[density], whatsapp_fraction=0.7, **kw)


# ---------------------------------------------------------------- E1 attacked service
E1_CONDITIONS = {"200 independent": ("200", False), "200 shared": ("200", True), "1000 independent": ("1000", False),
                 "1000 shared": ("1000", True), "uniform independent": ("uniform", False)}
E1_ATTACKERS = CP["experiments"]["E1_attacked_service"]["attackers"]


def e1_arms(density):
    return ["none", DEFAULT_SETTING, SEQ_BEST, DENSITY_COUNTER[density]] + list(EXPLORATORY)


def study_e1(seeds=FRESH):
    run = CP["experiments"]["E1_attacked_service"]["run"]
    specs, index = [], []
    for cond, (density, shared) in E1_CONDITIONS.items():
        for aname in E1_ATTACKERS:
            if aname == "block_poisoner" and not shared:
                continue                                    # the poisoner targets the blocks real users use by construction
            for pol in e1_arms(density):
                for s in seeds:
                    base = ADAPTIVE_ATTACKERS[aname] if aname == "block_poisoner" else PUMPING_ATTACKERS[aname]
                    a = randomised(base, s)
                    if shared and aname != "block_poisoner":
                        a = replace(a, shared_blocks=True)
                    specs.append(_spec(pol, a, _legit(density, run["conversion"]), run["attack_minutes"], run["warmup_minutes"], s))
                    index.append((cond, aname, pol, s))
    return specs, index


# ---------------------------------------------------------------- E2 held-out family
E2 = CP["experiments"]["E2_held_out_family"]


def study_e2(points=None, seeds_per_point=3):
    pts = points if points is not None else robustness_points()
    specs, index = [], []
    for i, pt in enumerate(pts):
        for k in range(seeds_per_point):
            seed = 6000 + 100 * i + k
            for pol in E2["arms"]:
                specs.append(_spec(pol, PUMPING_ATTACKERS["concentrated_pumper_no_verify"], _rob_legit(pt, blocks=200),
                                   E2["benign_runs"]["minutes"], 0, seed, legit_only=True))
                index.append(("benign", i, None, pol, seed))
                for aname in MATCHED_ATTACKERS:
                    a = replace(_held_out_attacker(PUMPING_ATTACKERS[aname], seed), shared_blocks=True)
                    specs.append(_spec(pol, a, _rob_legit(pt, blocks=200), E2["attack_runs"]["attack_minutes"],
                                       E2["attack_runs"]["warmup_minutes"], seed))
                    index.append(("attack", i, aname, pol, seed))
    return specs, index


def _net_pct(pol_run, none_run):
    return attributable_loss([pol_run], [none_run])["net_lost_pct"][0]


def judge_e2(by_cell):
    """by_cell: {(kind, point, attacker, policy, seed): result}. Applies K1-K5; lists failing cells."""
    def verdict(cells):
        ok = [c for c, t in cells if t]
        bad = [c for c, t in cells if not t]
        return {"cells": len(cells), "true": len(ok), "share": len(ok) / max(len(cells), 1),
                "holds": len(cells) > 0 and len(ok) >= 0.9 * len(cells), "failing": bad}
    k1, k2, k3, k4, k5 = [], [], [], [], []
    for (kind, i, aname, pol, seed), r in by_cell.items():
        if pol != PRINCIPAL:
            continue
        none = by_cell[(kind, i, aname, "none", seed)]
        if kind == "benign":
            k2.append(((i, seed), _net_pct(r, none) <= 0.5))
            continue
        cell = (i, aname, seed)
        req = max(r["attack"]["requests"], 1)
        k1.append((cell, r["attack"]["leaked_total"] <= 0.10 * req))
        loss = _net_pct(r, none)
        k3.append((cell, loss <= 0.5))
        dflt = by_cell[(kind, i, aname, DEFAULT_SETTING, seed)]
        k4.append((cell, r["attack"]["leaked_total"] <= dflt["attack"]["leaked_total"]))
        k5.append((cell, loss <= _net_pct(dflt, none) + 0.25))
    return {"K1": verdict(k1), "K2": verdict(k2), "K3": verdict(k3), "K4": verdict(k4), "K5": verdict(k5)}


# ---------------------------------------------------------------- E3 adaptive family
E3_ARMS = CP["experiments"]["E3_adaptive_family"]["arms"]


def e3_attackers():
    out = {n: ADAPTIVE_ATTACKERS[n] for n in ("threshold_aware_carrier", "receipt_faking_carrier", "trust_building_pumper",
                                              "trust_building_concentrated", "trust_building_long")}
    for nb in (3, 30, 300):
        for vname, vf, vd in (("never verifies", 0.0, 1.0), ("verifies 60 % human-like", 0.6, 30.0)):
            out[f"spread over {nb} blocks, {vname}"] = AttackerSpec(f"spread_{nb}_{int(vf * 100)}", numbers="concentrated", n_blocks=nb,
                                                                   fp_mode="aged", captcha_beta=(9, 1.5), verify_fraction=vf,
                                                                   verify_delay_s=vd, earns_revenue=True)
    for nb in (30, 300):
        out[f"quota-aware over {nb} blocks (4 per 10 min each)"] = AttackerSpec(f"quota_aware_{nb}", numbers="concentrated", n_blocks=nb,
                                                                               fp_mode="aged", captcha_beta=(9, 1.5), quota=(4, 600),
                                                                               earns_revenue=True)
    for n in ("concentrated_pumper_no_verify", "concentrated_pumper_verifies_humanlike"):
        out[f"{n}, 360 minutes"] = PUMPING_ATTACKERS[n]
    return out


def e3_minutes(name, a):
    if name.endswith("360 minutes"):
        return 360, 30
    if a.trust_building_minutes:
        return (a.trust_building_minutes + 30 if a.trust_building_minutes >= 20 else 20), 30
    return 20, 30


def study_e3(seeds=FRESH):
    specs, index = [], []
    for name, a in e3_attackers().items():
        minutes, warm = e3_minutes(name, a)
        for pol in E3_ARMS:
            for s in seeds:
                specs.append(_spec(pol, randomised(a, s), _legit("200"), minutes, warm, s))
                index.append((name, pol, s))
    return specs, index


# ---------------------------------------------------------------- E4 operating boundary
E4 = CP["experiments"]["E4_operating_boundary"]
E4_ARMS = E4["service_map"]["arms"]


def _hot_legit(rate_per_10, whatsapp, **kw):
    base = cal("legit_traffic_rate_per_min")
    hot = E4["service_map"]["hot_blocks"]
    return LegitSpec(conversion=0.65, autofill_fraction=0.2, whatsapp_fraction=whatsapp, hot_blocks=hot,
                     hot_fraction=rate_per_10 * hot / (10.0 * base), **kw)


def study_e4():
    sm, sec = E4["service_map"], E4["security_map"]
    specs, index = [], []
    pumper = PUMPING_ATTACKERS["concentrated_pumper_no_verify"]
    for r in sm["legit_rate_per_hot_block_per_10min"]:
        for wa in sm["whatsapp_fraction"]:
            for cond in ("benign", "attacked"):
                for pol in E4_ARMS:
                    for s in sm["seeds"]:
                        a = replace(randomised(pumper, s), shared_blocks=True)
                        specs.append(_spec(pol, a, _hot_legit(r, wa), sm["run"]["minutes"], sm["run"]["warmup_minutes"], s,
                                           legit_only=cond == "benign"))
                        index.append(("service", r, wa, cond, pol, s))
    stresses = {"product launch": dict(launch=(10, 40, 3.0, 0.3), bursts=((10, 40, 3.0),)),
                "correlated fallback": dict(no_whatsapp_solves=0.5),
                "poor route": dict(hot_bad_route=True, bad_route_failure=0.5)}
    for sname, kw in stresses.items():
        for cond in ("benign", "attacked"):
            for pol in E4_ARMS:
                for s in sm["seeds"]:
                    a = replace(randomised(pumper, s), shared_blocks=True)
                    specs.append(_spec(pol, a, _hot_legit(1, 0.7, **kw), sm["run"]["minutes"], sm["run"]["warmup_minutes"], s,
                                       legit_only=cond == "benign"))
                    index.append(("stress", sname, None, cond, pol, s))
    for nb in sec["attacker_blocks"]:
        for kind in sec["pumper"]:
            a0 = AttackerSpec(f"e4_{kind[:5]}_{nb}", numbers="concentrated", n_blocks=nb, fp_mode="aged", captcha_beta=(9, 1.5),
                              quota=(4, 600) if kind == "quota-aware" else None, earns_revenue=True)
            for mins in sec["attack_minutes"]:
                for pol in sec["arms"]:
                    for s in sec["seeds"]:
                        specs.append(_spec(pol, randomised(a0, s), _legit("uniform"), mins, 30, s))
                        index.append(("security", nb, kind, mins, pol, s))
    return specs, index


# ---------------------------------------------------------------- E5 density-complete selection
def _e5_legit_spec(setting, density, conversion, seed, minutes):
    return _spec(setting, PUMPING_ATTACKERS["concentrated_pumper_no_verify"], _legit(density, conversion), minutes, 0, seed, legit_only=True)


def _e5_attack_spec(setting, density, aname, seed):
    ar = MC["attack_runs"]
    return _spec(setting, randomised(PUMPING_ATTACKERS[aname], seed), _legit(density), ar["minutes"], ar["warmup_minutes"], seed)


def study_e5_tuning(seeds=None, legit_minutes=None):
    seeds = seeds or CP["seeds"]["density_selection_tuning"]
    minutes = legit_minutes or MC["legitimate_runs"]["minutes"]
    specs, index = [], []
    for density in DENSITIES:
        for name in MATCHED:
            for s in seeds:
                specs.append(_e5_legit_spec(name, density, MC["legitimate_runs"]["conversion_tuning"], s, minutes))
                index.append(("legit", density, name, None, s))
                for aname in MATCHED_ATTACKERS:
                    specs.append(_e5_attack_spec(name, density, aname, s))
                    index.append(("attack", density, name, aname, s))
    return specs, index


def select_e5(tuning):
    """The 2.7.0 rule per density, with density-specific leakage and the full grid everywhere.
    tuning: {(kind, density, name): [results]} with attack results pooled over attackers."""
    completion = {(d, n): st.mean(r["friction"]["completed_pct"] for r in rs) for (k, d, n), rs in tuning.items() if k == "legit"}
    events = {(d, n): st.mean(r["block_verdicts"] for r in rs) for (k, d, n), rs in tuning.items() if k == "legit"}
    leak = {}
    for (k, d, n), rs in tuning.items():
        if k == "attack":
            by_a = {}
            for r in rs:
                by_a.setdefault(r["spec"]["attacker"]["name"], []).append(r["attack"]["leaked_total"])
            leak[(d, n)] = sum(st.mean(v) for v in by_a.values())
    sel = {}
    for density in DENSITIES:
        target = completion[(density, DEFAULT_SETTING)] - 0.5
        chosen = {"default": DEFAULT_SETTING, "none": "none"}
        for fam in MATCHED_FAMILIES:
            cands = [n for n in MATCHED if MATCHED[n][0] == fam and completion[(density, n)] >= target]
            if cands:
                chosen[f"best {fam} at the service target"] = min(cands, key=lambda n: (round(leak[(density, n)], 6), -completion[(density, n)]))
        fa = events[(density, DEFAULT_SETTING)]
        for c in MC["grids"]["sequential_credits"]:
            row = [n for n in MATCHED if MATCHED[n][0] == "sequential" and n.endswith(f" c{_credit_label(c)}")]
            ok = [n for n in row if events[(density, n)] <= fa]
            if ok:
                chosen[f"matched false alarms, credit {_credit_label(c)}"] = min(ok, key=lambda n: float(n.split()[1][1:]))
        sel[density] = {"service_target_completion_pct": target, "default_completion_pct": completion[(density, DEFAULT_SETTING)],
                        "chosen": chosen, "tuning_completion": {n: completion[(density, n)] for n in MATCHED},
                        "tuning_leak_sum": {n: leak[(density, n)] for n in MATCHED},
                        "tuning_events": {n: events[(density, n)] for n in MATCHED}}
    return sel


def study_e5_eval(sel, seeds=FRESH, legit_minutes=None):
    minutes = legit_minutes or MC["legitimate_runs"]["minutes"]
    specs, index = [], []
    for density, d in sel.items():
        for name in sorted(set(d["chosen"].values())):
            for s in seeds:
                for conv in MC["legitimate_runs"]["conversion_evaluation"]:
                    specs.append(_e5_legit_spec(name, density, conv, s, minutes))
                    index.append(("legit", density, name, conv, s))
                for aname in MATCHED_ATTACKERS:
                    specs.append(_e5_attack_spec(name, density, aname, s))
                    index.append(("attack", density, name, aname, s))
    return specs, index


def preferences(attack_by_policy, loss_by_policy, first_time_loss_by_policy, n_draws=2000, seed=7):
    """M8: the preferred policy under mean leakage, worst-case (max over attackers) leakage, mean leakage
    subject to a first-time-user loss of at most 0.5 pp, each single attacker, and random attacker mixes
    (Dirichlet(1, 1, 1, 1)): the share of mixes each policy wins.
    attack_by_policy: {policy: {attacker: mean leaked}}."""
    pols = list(attack_by_policy)
    atts = sorted(next(iter(attack_by_policy.values())))
    mean_leak = {p: st.mean(attack_by_policy[p][a] for a in atts) for p in pols}
    worst = {p: max(attack_by_policy[p][a] for a in atts) for p in pols}
    ok = [p for p in pols if first_time_loss_by_policy.get(p, 0.0) <= 0.5]
    out = {"mean_leakage": min(pols, key=lambda p: mean_leak[p]), "worst_case_leakage": min(pols, key=lambda p: worst[p]),
           "mean_leakage_with_first_time_loss_at_most_0.5pp": min(ok, key=lambda p: mean_leak[p]) if ok else None,
           "single_attacker": {a: min(pols, key=lambda p: attack_by_policy[p][a]) for a in atts},
           "mean": mean_leak, "worst": worst}
    rng = random.Random(seed)
    wins = {p: 0 for p in pols}
    for _ in range(n_draws):
        w = [rng.expovariate(1.0) for _ in atts]
        tot = sum(w)
        best = min(pols, key=lambda p: sum(wi / tot * attack_by_policy[p][a] for wi, a in zip(w, atts)))
        wins[best] += 1
    out["random_mix_win_share"] = {p: wins[p] / n_draws for p in pols}
    return out
