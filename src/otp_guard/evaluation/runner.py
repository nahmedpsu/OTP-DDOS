"""Studies built on the simulation: attacker catalogue, randomised multi-seed runs with
confidence intervals, leave-one-layer-out ablation, weight and boundary sweeps, adaptive
attackers, and attacker economics."""
import copy
import math
import multiprocessing as mp
import random
from dataclasses import replace

from ..config import ALL_FEATURES, V1_FEATURES, OPTIONAL_FEATURES, BASELINE_DESIGNS, BASELINE_CFG
from .calibration import value as cal
from .sim import AttackerSpec, LegitSpec, SimSpec, run_sim
from .stats import mean_ci, boot_ci, tail, fraction_ci

BOT_CAPTCHA = cal("recaptcha_bot_scores")

ATTACKERS = {
    "naive_single_client": AttackerSpec("naive_single_client", "One IP, one session, random numbers, basic bot captcha",
                                        network="single_ip", pool_size=1, fp_mode="single", captcha_beta=tuple(BOT_CAPTCHA["basic_bot"]),
                                        captcha_classes=("basic_bot", "headless_browser")),
    "datacenter_rotation": AttackerSpec("datacenter_rotation", "Hosting ASN abroad, fresh fingerprint per request, headless-browser captcha",
                                        network="datacenter", ip_country="DE", captcha_beta=tuple(BOT_CAPTCHA["headless_browser"]),
                                        captcha_classes=("basic_bot", "headless_browser", "captcha_farm")),
    "residential_bot": AttackerSpec("residential_bot", "Residential pool in-country, fresh fingerprint, basic or headless-browser captcha",
                                    captcha_beta=tuple(BOT_CAPTCHA["headless_browser"]), captcha_classes=("basic_bot", "headless_browser")),
    "residential_captcha_farm": AttackerSpec("residential_captcha_farm", "Residential pool, fresh fingerprint, farmed captcha (human-like scores)",
                                             captcha_beta=tuple(BOT_CAPTCHA["captcha_farm"])),
    "residential_aged_fps": AttackerSpec("residential_aged_fps", "Residential pool, unique fingerprints pre-aged 2 h, farmed captcha",
                                         fp_mode="aged", captcha_beta=tuple(BOT_CAPTCHA["captcha_farm"])),
    "residential_reused_profile": AttackerSpec("residential_reused_profile", "Residential pool, one 48 h old browser profile reused",
                                               fp_mode="reused", captcha_beta=tuple(BOT_CAPTCHA["captcha_farm"])),
    "sequential_numbers": AttackerSpec("sequential_numbers", "Residential pool, numbers walked upward",
                                       numbers="sequential", captcha_beta=tuple(BOT_CAPTCHA["captcha_farm"])),
    "premium_pumping": AttackerSpec("premium_pumping", "Residential pool, premium-rate prefix", numbers="premium",
                                    captcha_beta=tuple(BOT_CAPTCHA["captcha_farm"]), earns_revenue=True),
    "spoofed_platform": AttackerSpec("spoofed_platform", "Residential pool, HTTP_PLATFORM: ios without attestation; valid host and session (only the header is spoofed)",
                                     platform_spoof=True, captcha_beta=tuple(BOT_CAPTCHA["captcha_farm"])),
}

ADAPTIVE_ATTACKERS = {
    "pumper_verifies_instantly": AttackerSpec("pumper_verifies_instantly",
        "Colluding carrier on the elevated range submits every code within 1 s (conversion 100 %)",
        numbers="elevated", fp_mode="aged", verify_fraction=1.0, verify_delay_s=1.0, captcha_beta=(9, 1.5), earns_revenue=True),
    "pumper_verifies_humanlike": AttackerSpec("pumper_verifies_humanlike",
        "Colluding carrier submits 60 % of codes after 30 s (looks like real conversion)",
        numbers="elevated", fp_mode="aged", verify_fraction=0.6, verify_delay_s=30.0, captcha_beta=(9, 1.5), earns_revenue=True),
    "pumper_standard_range_humanlike": AttackerSpec("pumper_standard_range_humanlike",
        "Random numbers across all standard prefixes, 60 % verified after 30 s: a flooder that verifies, not a pumper (it earns nothing)",
        numbers="random", fp_mode="aged", verify_fraction=0.6, verify_delay_s=30.0, captcha_beta=(9, 1.5)),
    "challenge_solver": AttackerSpec("challenge_solver",
        "Datacenter rotation abroad (score lands in the challenge tier) and pays a solving service for every challenge",
        network="datacenter", ip_country="DE", fp_mode="fresh", solves_challenges=True,
        captcha_beta=tuple(BOT_CAPTCHA["headless_browser"]), captcha_classes=("headless_browser", "captcha_farm")),
    "low_and_slow_20_asns": AttackerSpec("low_and_slow_20_asns",
        "2 requests/min spread over 20 residential ASNs, aged fingerprints, under legitimate volume",
        network="multi_asn", n_asns=20, rate_per_min=2.0, fp_mode="aged", captcha_beta=(9, 1.5)),
    "trust_building_pumper": AttackerSpec("trust_building_pumper",
        "Builds trust first: 500 identities and numbers verify everything (human-like delay) for 10 minutes, then the same "
        "identities flood without verifying, so verified-history exemptions and trusted numbers work in its favour",
        fp_mode="aged", captcha_beta=(9, 1.5), trust_building_minutes=10, trust_pool=500, verify_fraction=0.0, earns_revenue=True),
    "trust_building_concentrated": AttackerSpec("trust_building_concentrated",
        "Same preparation (500 identity/number pairs verify everything for 10 minutes), but the numbers lie in 3 destination "
        "blocks the carrier terminates, so the block memory is what the flood phase must get past",
        numbers="concentrated", n_blocks=3, fp_mode="aged", captcha_beta=(9, 1.5), trust_building_minutes=10, trust_pool=500,
        trust_concentrated=True, verify_fraction=0.0, earns_revenue=True),
    "trust_building_long": AttackerSpec("trust_building_long",
        "Trust building for 30 minutes (500 identity/number pairs verify everything), then 30 minutes of flood with the same pairs",
        fp_mode="aged", captcha_beta=(9, 1.5), trust_building_minutes=30, trust_pool=500, verify_fraction=0.0, earns_revenue=True),
    "threshold_aware_carrier": AttackerSpec("threshold_aware_carrier",
        "Concentrated pumper on 3 blocks whose carrier knows the deployed test parameters and the worker's timing, replays its "
        "own pending outcomes in the order the deployment applies them, and enters a code (100 s after delivery) only when not "
        "doing so would bring its block within 1 log unit of the threshold",
        numbers="concentrated", n_blocks=3, fp_mode="aged", captcha_beta=(9, 1.5), verify_policy="threshold_aware",
        verify_delay_s=100.0, threshold_margin=1.0, earns_revenue=True),
    "receipt_faking_carrier": AttackerSpec("receipt_faking_carrier",
        "Concentrated pumper whose carrier reports every delivery as failed: the sends are billed but feed no block test",
        numbers="concentrated", n_blocks=3, fp_mode="aged", captcha_beta=(9, 1.5), fake_failed_receipts=True, earns_revenue=True),
    "block_poisoner": AttackerSpec("block_poisoner",
        "Floods the destination blocks that real users concentrate on, to get them a verdict (collateral-damage attack)",
        numbers="poison", fp_mode="aged", captcha_beta=(9, 1.5)),
    "low_and_slow_below_dilution": AttackerSpec("low_and_slow_below_dilution",
        "10 requests/min over 20 ASNs against 20/min legitimate: under the 1.8x dilution bound",
        network="multi_asn", n_asns=20, rate_per_min=10.0, fp_mode="aged", captcha_beta=(9, 1.5)),
}


def randomised(spec: AttackerSpec, seed: int) -> AttackerSpec:
    """Per-seed variation of pool size, rate and captcha class, as the review asked."""
    rng = random.Random(seed * 7919 + 13)
    s = replace(spec)
    if spec.network != "single_ip":
        s.pool_size = int(10 ** rng.uniform(2.7, 4.7))       # 500 .. 50 000 addresses
    s.rate_per_min = rng.uniform(10, 60)
    s.captcha_beta = tuple(BOT_CAPTCHA[rng.choice(list(spec.captcha_classes))])
    return s


def _job(args):
    spec = args
    return run_sim(spec)


def run_all(specs, processes=None):
    with mp.Pool(processes or mp.cpu_count()) as pool:
        return pool.map(_job, specs, chunksize=2)


CI = boot_ci        # every summary interval: percentile bootstrap over runs (stays inside the data range)


def _verdict_fields(results):
    """Verdict accounting shared by every summary. Incidence: verdict events issued inside the
    observation window; exposure: block-minutes under a verdict inside the window (including
    verdicts issued before it); eventual: events at or after the attack start including the drain.
    Hits are requests that met any destination-policy intervention (verdict or counter); 'lost' is
    descriptive (hit and never completed), not attributable harm (see attributable_loss)."""
    def col(f):
        return [f(r) for r in results]
    out = {
        "block_verdicts": CI(col(lambda r: r["block_verdicts"])),
        "blocks_with_verdict": CI(col(lambda r: r["blocks_with_verdict"])),
        "verdicts_stage1": CI(col(lambda r: r["verdicts_stage1"])),
        "verdicts_stage2": CI(col(lambda r: r["verdicts_stage2"])),
        "verdict_exposure_block_min": CI(col(lambda r: r["verdict_exposure_block_min"])),
        "block_verdicts_incl_drain": CI(col(lambda r: r["block_verdicts_incl_drain"])),
        "first_verdict_min": CI([r["first_verdict_min"] for r in results if r["first_verdict_min"] is not None]),
        "legit_hit_by_verdict": CI(col(lambda r: r["legit_hit_by_verdict"])),
        "legit_hit_stage1": CI(col(lambda r: r["legit_hit_stage1"])),
        "legit_hit_stage2": CI(col(lambda r: r["legit_hit_stage2"])),
        "legit_hit_refused": CI(col(lambda r: r.get("legit_hit_refused", 0))),
        "legit_hit_lost": CI(col(lambda r: r["legit_hit_lost"])),
        "legit_hit_by_verdict_pct": CI([100.0 * r["legit_hit_by_verdict"] / max(r["friction"]["users"], 1) for r in results]),
        "pending_at_end": sum(sum(r["pending_at_end"].values()) for r in results),
    }
    out["tails"] = {k: tail(col(f)) for k, f in (
        ("block_verdicts", lambda r: r["block_verdicts"]), ("verdict_exposure_block_min", lambda r: r["verdict_exposure_block_min"]),
        ("legit_hit_by_verdict", lambda r: r["legit_hit_by_verdict"]), ("legit_hit_lost", lambda r: r["legit_hit_lost"]))}
    return out


def _friction_fields(results):
    def col(*path):
        out = []
        for r in results:
            v = r
            for p in path:
                v = v[p]
            out.append(v)
        return out
    return {
        "legit_users": CI(col("friction", "users")),
        "legit_dispatched_pct": CI(col("friction", "dispatched_pct")),
        "legit_delivered_pct": CI(col("friction", "delivered_pct")),
        "legit_completed_pct": CI(col("friction", "completed_pct")),
        "legit_challenge_rate_pct": CI(col("friction", "challenge_rate_pct")),
        "legit_refusal_rate_pct": CI(col("friction", "refusal_rate_pct")),
        "legit_mean_added_delay_s": CI(col("friction", "mean_added_delay_s")),
        "legit_whatsapp_pct": CI([100.0 * r["friction"]["by_channel"].get("whatsapp", 0) / max(r["friction"]["users"], 1) for r in results]),
        "legit_no_channel_pct": CI([100.0 * r["friction"]["refused_by"].get("no_channel", 0) / max(r["friction"]["users"], 1) for r in results]),
        "legit_gate_loss_pct": CI([100.0 * r["friction"]["refused_by"].get("gate", 0) / max(r["friction"]["users"], 1) for r in results]),
        "legit_undelivered_pct": CI([100.0 * r["friction"]["refused_by"].get("undelivered", 0) / max(r["friction"]["users"], 1) for r in results]),
        "first_time_refusal_rate_pct": CI(col("friction", "first_time", "refusal_rate_pct")),
        "first_time_delivered_pct": CI(col("friction", "first_time", "delivered_pct")),
        "first_time_completed_pct": CI(col("friction", "first_time", "completed_pct")),
        "first_time_challenge_rate_pct": CI(col("friction", "first_time", "challenge_rate_pct")),
        "returning_refusal_rate_pct": CI(col("friction", "returning", "refusal_rate_pct")),
        "returning_delivered_pct": CI(col("friction", "returning", "delivered_pct")),
        "returning_completed_pct": CI(col("friction", "returning", "completed_pct")),
        "returning_users": CI(col("friction", "returning", "users")),
        "returning_known_good_pct": CI([100.0 * r["friction"]["returning"]["known_good"] / max(r["friction"]["returning"]["dispatched"], 1) for r in results]),
        "resends": CI([r.get("reactions", {}).get("resend", 0) for r in results]),
    }


def summarise_legit_only(results):
    """Aggregate legitimate-only runs: service, verdict events and the requests they touched."""
    out = {"n": len(results),
           "outage_alerts": CI([r["outage_alerts"] for r in results]),
           "occupancy_median": CI([r["legit_block_occupancy"]["median"] for r in results]),
           "occupancy_max": CI([r["legit_block_occupancy"]["max"] for r in results]),
           "blocks_touched": CI([r["legit_block_occupancy"]["touched"] for r in results])}
    out.update(_friction_fields(results))
    out.update(_verdict_fields(results))
    return out


def summarise(results):
    """Aggregate a list of run results: means with 95 % bootstrap intervals, tails, containment."""
    def col(path):
        out = []
        for r in results:
            v = r
            for p in path:
                v = v[p]
            out.append(v)
        return out
    ttc = col(("attack", "time_to_containment_min"))
    n_contained = sum(1 for t in ttc if t is not None)
    minutes = results[0]["spec"]["minutes"]
    active = results[0]["spec"]["attacker"].get("active_minutes")
    out = {
        "n": len(results),
        "n_contained": n_contained,
        "contained_fraction": n_contained / len(results),
        "containment_survival": [sum(1 for t in ttc if t is None or t > m) / len(ttc) for m in range(minutes + 1)],
        # horizon-filled mean (uncontained runs counted as `minutes`); the tables report the conditional one below
        "time_to_containment_horizon_filled_min": CI([t if t is not None else minutes for t in ttc]),
        "time_to_containment_if_contained_min": CI([t for t in ttc if t is not None]),
        "leaked_before_containment": CI(col(("attack", "leaked_before_containment"))),
        "leaked_total": CI(col(("attack", "leaked_total"))),
        "leak_fraction_pct": CI([100.0 * r["attack"]["leaked_total"] / max(r["attack"]["requests"], 1) for r in results]),
        "steady_state_leak_per_min": CI(col(("attack", "steady_state_leak_per_min"))),
        "attacker_cost_usd": CI(col(("attack", "cost_usd"))),
        "requests": CI(col(("attack", "requests"))),
        "attacker_session_attempts": CI(col(("attacker_session_attempts",))),
        "attacker_sessions_refused": CI(col(("attacker_sessions_refused",))),
        "attacker_blocks_requested": CI(col(("attacker_blocks_requested",))),
        "attacker_blocks_leaked": CI(col(("attacker_blocks_leaked",))),
        "attacker_verifications": CI(col(("attacker_verifications",))),
        "attacker_challenges_solved": CI(col(("attacker_challenges_solved",))),
        "prep_requests": CI([r["attack_phase"]["prep"].get("requests", 0) for r in results]),
        "prep_leaked": CI([r["attack_phase"]["prep"].get("leaked", 0) for r in results]),
        "prep_verified": CI([r["attack_phase"]["prep"].get("verified", 0) for r in results]),
        "flood_requests": CI([r["attack_phase"]["flood"].get("requests", 0) for r in results]),
        "flood_leaked": CI([r["attack_phase"]["flood"].get("leaked", 0) for r in results]),
        "flood_verified": CI([r["attack_phase"]["flood"].get("verified", 0) for r in results]),
        "legit_hit_after_stop": CI([sum(r["legit_hit_per_min"][active:]) if active else 0 for r in results]),
    }
    out.update(_friction_fields(results))
    out.update(_verdict_fields(results))
    out["tails"].update({"leaked_total": tail(col(("attack", "leaked_total"))),
                         "first_time_refusal_rate_pct": tail(col(("friction", "first_time", "refusal_rate_pct")))})
    return out


MODES = {"behavioural_only": True, "with_adaptive_caps": False}     # name -> caps_lifted

DESIGNS = dict(BASELINE_DESIGNS, v2=ALL_FEATURES)    # every design the main study runs


def study_multi_seed(seeds, features=ALL_FEATURES, attackers=None, minutes=20, modes=MODES, design="v2"):
    specs, index = [], []
    cfg = BASELINE_CFG.get(design, {})
    for mode, lifted in modes.items():
        for name, a in (attackers or ATTACKERS).items():
            for s in seeds:
                specs.append(SimSpec(attacker=randomised(a, s), minutes=minutes, features=features, caps_lifted=lifted,
                                     cfg_overrides=dict(cfg), seed=s))
                index.append((mode, name, s))
    return specs, index


def paired_difference(results_a, results_b, path):
    """Mean and CI of per-seed differences a - b (same seeds, same offered workload)."""
    def get(r):
        v = r
        for p in path:
            v = v[p]
        return v
    by_seed_b = {r["spec"]["seed"]: get(r) for r in results_b}
    diffs = [get(r) - by_seed_b[r["spec"]["seed"]] for r in results_a if r["spec"]["seed"] in by_seed_b]
    return boot_ci(diffs)


def attributable_loss(results_policy, results_none):
    """Completion lost *because of* a policy, per request, against the same seed's run without it
    (identical offered trace, request ids aligned): requests completed without the policy and not
    with it, minus the reverse (a policy can also help, e.g. through feedback). Also how many of the
    requests lost because of it had met an intervention, and the descriptive 'hit and not completed'."""
    from .sim import unbits
    by_seed = {r["spec"]["seed"]: r for r in results_none}
    net, pct, hit_lost, desc, gross_lost, gross_gained = [], [], [], [], [], []
    groups = {g: {"net": [], "pct": [], "users": []} for g in ("first_time", "returning", "attacked_block", "after_stop", "hot_block")}
    for r in results_policy:
        ref = by_seed.get(r["spec"]["seed"])
        if ref is None or "requests" not in r or "requests" not in ref:
            continue
        assert r["workload_digest"] == ref["workload_digest"], "paired runs must offer the same trace"
        n = r["requests"]["n"]
        c_pol, c_ref = unbits(r["requests"]["completed"]), unbits(ref["requests"]["completed"])
        hit = unbits(r["requests"]["hit"])
        lost, gained = c_ref - c_pol, c_pol - c_ref
        net.append(len(lost) - len(gained))
        pct.append(100.0 * (len(lost) - len(gained)) / max(n, 1))
        gross_lost.append(len(lost)); gross_gained.append(len(gained))
        hit_lost.append(len(lost & hit))
        desc.append(r["legit_hit_lost"])
        if "returning" in r["requests"]:
            ret = unbits(r["requests"]["returning"])
            members = {"returning": ret, "first_time": set(range(n)) - ret,
                       "attacked_block": unbits(r["requests"]["attacked_block"]),
                       "after_stop": unbits(r["requests"]["after_stop"]),
                       "hot_block": unbits(r["requests"].get("hot_block", ""))}
            for g, ids in members.items():
                d = len(lost & ids) - len(gained & ids)
                groups[g]["net"].append(d)
                groups[g]["pct"].append(100.0 * d / len(ids) if ids else 0.0)
                groups[g]["users"].append(len(ids))
    out = {"net_lost": boot_ci(net), "net_lost_pct": boot_ci(pct), "lost_among_hit": boot_ci(hit_lost),
           "gross_lost": boot_ci(gross_lost), "gross_gained": boot_ci(gross_gained),
           "descriptive_hit_and_not_completed": boot_ci(desc), "n_pairs": len(net), "per_seed_net_lost_pct": pct}
    for g, d in groups.items():
        if d["net"]:
            out[g] = {"net_lost": boot_ci(d["net"]), "net_lost_pct_of_group": boot_ci(d["pct"]), "users": boot_ci(d["users"])}
    return out


def study_ablation(seeds, attackers=None, minutes=20, caps_lifted=False):
    """Leave one layer out. The 'full' pseudo-flag runs the complete v2 on the same seeds so the
    baseline column is comparable (an earlier version compared against the 30-seed main study)."""
    specs, index = [], []
    for name, a in (attackers or ATTACKERS).items():
        for flag in ["full"] + sorted(ALL_FEATURES):
            feats = ALL_FEATURES if flag == "full" else frozenset(ALL_FEATURES - {flag})
            for s in seeds:
                specs.append(SimSpec(attacker=randomised(a, s), minutes=minutes, features=feats, caps_lifted=caps_lifted, seed=s))
                index.append((name, flag, s))
    return specs, index


PUMPING_ATTACKERS = {
    "concentrated_pumper_no_verify": AttackerSpec("concentrated_pumper_no_verify",
        "Pumper on 3 destination blocks of 10 000 numbers inside a standard prefix; aged fingerprints, farmed captcha; carrier does not verify",
        numbers="concentrated", n_blocks=3, fp_mode="aged", captcha_beta=(9, 1.5), earns_revenue=True),
    "concentrated_pumper_verifies_instantly": AttackerSpec("concentrated_pumper_verifies_instantly",
        "Same blocks; the carrier submits every code within 1 s",
        numbers="concentrated", n_blocks=3, fp_mode="aged", captcha_beta=(9, 1.5), verify_fraction=1.0, verify_delay_s=1.0, earns_revenue=True),
    "concentrated_pumper_verifies_humanlike": AttackerSpec("concentrated_pumper_verifies_humanlike",
        "Same blocks; the carrier submits 60 % of codes after 30 s",
        numbers="concentrated", n_blocks=3, fp_mode="aged", captcha_beta=(9, 1.5), verify_fraction=0.6, verify_delay_s=30.0, earns_revenue=True),
    "concentrated_pumper_solves_challenges": AttackerSpec("concentrated_pumper_solves_challenges",
        "Same blocks, carrier does not verify; the pumper buys a solution for every interactive challenge",
        numbers="concentrated", n_blocks=3, fp_mode="aged", captcha_beta=(9, 1.5), solves_challenges=True, earns_revenue=True),
    "residential_captcha_farm": ATTACKERS["residential_captcha_farm"],
}

_NO_FINE = frozenset(ALL_FEATURES - {"fine_destination_key"})
PUMPING_VARIANTS = {
    # name -> (features, cfg overrides). Runs use a 2-hour legitimate warm-up so the relative baseline has history.
    "v1": (V1_FEATURES, {"resolution_timeout_s": 600}),
    "baseline_24h_cumulative_10min": (_NO_FINE, {"resolution_timeout_s": 600}),
    "fine_destination_key": (ALL_FEATURES, {"resolution_timeout_s": 600}),
    "fast_resolution_2min": (_NO_FINE, {"resolution_timeout_s": 120}),
    "fine_key_plus_fast_resolution (default)": (ALL_FEATURES, {"resolution_timeout_s": 120}),
    "relative_baseline": (frozenset(_NO_FINE | {"relative_baseline"}), {"resolution_timeout_s": 600}),
    "all_three": (frozenset(ALL_FEATURES | {"relative_baseline"}), {"resolution_timeout_s": 120}),
    "default_with_hard_deny": (ALL_FEATURES, {"resolution_timeout_s": 120, "block_action": "deny"}),
}
PUMPING_WARMUP_MIN = 130     # crosses an hour boundary with >= 200 resolved legitimate sends in the previous hour bucket


def study_pumping(seeds, minutes=20):
    specs, index = [], []
    for aname, a in PUMPING_ATTACKERS.items():
        for vname, (feats, cfg) in PUMPING_VARIANTS.items():
            for s in seeds:
                specs.append(SimSpec(attacker=randomised(a, s), minutes=minutes, features=feats, cfg_overrides=dict(cfg),
                                     caps_lifted=True, warmup_minutes=PUMPING_WARMUP_MIN, seed=s))
                index.append((aname, vname, s))
    return specs, index


import json as _json
import pathlib as _pathlib

PROTOCOL_PATH = _pathlib.Path(__file__).resolve().parents[3] / "config" / "evaluation_protocol.json"
PROTOCOL = _json.loads(PROTOCOL_PATH.read_text())
MC = PROTOCOL["matched_comparison"]
TUNING_SEEDS, EVAL_SEEDS = PROTOCOL["seeds"]["tuning"], PROTOCOL["seeds"]["evaluation"]
DENSITIES = {"200": 200, "1000": 1000, "uniform": None}
_COUNTER_FEATS = frozenset(ALL_FEATURES | {"block_count_limit"})
_NO_TESTS = {"block_tests": ()}


def _credit_label(c):
    return "inf" if c == "unbounded" else (str(int(c)) if float(c).is_integer() else str(c))


def _setting_name(kind, *args):
    if kind == "sequential":
        t, c = args
        return f"sequential T{t} c{_credit_label(c)}"
    if kind == "counter_graded_daily":
        return f"counter graded {args[0]}/day"
    if kind == "counter_graded_short":
        n, w = args
        return f"counter graded {n}/{w // 60} min"
    if kind == "counter_refuse_daily":
        return f"counter refuse {args[0]}/day"
    return "none"


DEFAULT_SETTING = _setting_name("sequential", 1000, 1.0)


def matched_settings():
    """name -> (family, features, cfg overrides): the protocol's grids on one common pipeline."""
    g = MC["grids"]
    out = {"none": ("none", ALL_FEATURES, dict(_NO_TESTS))}
    for t in g["sequential_thresholds"]:
        for c in g["sequential_credits"]:
            cfg = {"sprt_threshold": float(t)}
            cfg.update({"block_test": "sprt"} if c == "unbounded" else {"block_credit_thresholds": float(c)})
            out[_setting_name("sequential", t, c)] = ("sequential", ALL_FEATURES, cfg)
    for n in g["counter_graded_daily_limits"]:
        out[_setting_name("counter_graded_daily", n)] = ("counter_graded_daily", _COUNTER_FEATS,
                                                          dict(_NO_TESTS, block_count_limit=(n, 86400), block_count_action="graded"))
    for n, w in g["counter_graded_short"]:
        out[_setting_name("counter_graded_short", n, w)] = ("counter_graded_short", _COUNTER_FEATS,
                                                             dict(_NO_TESTS, block_count_limit=(n, w), block_count_action="graded"))
    for n in g["counter_refuse_daily_limits"]:
        out[_setting_name("counter_refuse_daily", n)] = ("counter_refuse_daily", _COUNTER_FEATS,
                                                          dict(_NO_TESTS, block_count_limit=(n, 86400), block_count_action="refuse"))
    return out


MATCHED = matched_settings()
MATCHED_FAMILIES = ["sequential", "counter_graded_daily", "counter_graded_short", "counter_refuse_daily"]
MATCHED_ATTACKERS = MC["attack_runs"]["attackers"]


def _settings_at(density):
    if density == MC["full_grid_density"]:
        return list(MATCHED)
    return [n for n, (fam, _, _) in MATCHED.items() if fam != "sequential"] + [DEFAULT_SETTING]


def _legit_spec(setting, density, conversion, seed, minutes=None):
    _, feats, cfg = MATCHED[setting]
    lr = MC["legitimate_runs"]
    legit = LegitSpec(conversion=conversion, autofill_fraction=lr["autofill"], blocks=DENSITIES[density],
                      whatsapp_fraction=lr["whatsapp_fraction"])
    return SimSpec(attacker=ATTACKERS["naive_single_client"], legit=legit, legit_only=True, features=feats, cfg_overrides=dict(cfg),
                   minutes=minutes or lr["minutes"], warmup_minutes=0, caps_lifted=True, seed=seed, record_requests=True)


def _attack_spec(setting, aname, seed, minutes=None):
    _, feats, cfg = MATCHED[setting]
    ar = MC["attack_runs"]
    return SimSpec(attacker=randomised(PUMPING_ATTACKERS[aname], seed), minutes=minutes or ar["minutes"], features=feats,
                   cfg_overrides=dict(cfg), caps_lifted=ar["caps_lifted"], warmup_minutes=ar["warmup_minutes"], seed=seed)


def study_matched_tuning(seeds=None, legit_minutes=None):
    """Stage 1 of the protocol: every setting on the tuning seeds, legitimate side at 65 % per density
    and attack side against the four pumpers."""
    seeds = seeds or TUNING_SEEDS
    specs, index = [], []
    conv = MC["legitimate_runs"]["conversion_tuning"]
    for density in DENSITIES:
        for name in _settings_at(density):
            for s in seeds:
                specs.append(_legit_spec(name, density, conv, s, legit_minutes))
                index.append(("legit", density, name, conv, s))
    for name in MATCHED:
        for aname in MATCHED_ATTACKERS:
            for s in seeds:
                specs.append(_attack_spec(name, aname, s))
                index.append(("attack", None, name, aname, s))
    return specs, index


def select_matched(tuning):
    """Apply the protocol's selection rules to the tuning results. tuning: {("legit", density, name): [runs],
    ("attack", name, attacker): [runs]}. Returns (selection record, settings to evaluate per density)."""
    import statistics as st
    completion = {(d, n): st.mean(r["friction"]["completed_pct"] for r in rs) for (kind, d, n), rs in tuning.items() if kind == "legit"}
    events = {(d, n): st.mean(r["block_verdicts"] for r in rs) for (kind, d, n), rs in tuning.items() if kind == "legit"}
    leak = {}
    for (kind, n, aname), rs in tuning.items():
        if kind == "attack":
            leak[n] = leak.get(n, 0.0) + st.mean(r["attack"]["leaked_total"] for r in rs)
    sel, evaluate = {}, {}
    for density in DENSITIES:
        target = completion[(density, DEFAULT_SETTING)] - 0.5
        chosen = {"default": DEFAULT_SETTING, "none": "none"}
        for fam in MATCHED_FAMILIES:
            cands = [n for n in _settings_at(density) if MATCHED[n][0] == fam and completion.get((density, n), -1) >= target]
            if cands:
                # lowest leakage; ties to the more permissive (higher completion) setting
                chosen[f"best {fam} at the service target"] = min(cands, key=lambda n: (round(leak[n], 6), -completion[(density, n)]))
        if density == MC["full_grid_density"]:
            fa = events[(density, DEFAULT_SETTING)]
            for c in MC["grids"]["sequential_credits"]:
                row = [n for n in MATCHED if MATCHED[n][0] == "sequential" and n.endswith(f" c{_credit_label(c)}")]
                ok = [n for n in row if events[(density, n)] <= fa]
                if ok:
                    chosen[f"matched false alarms, credit {_credit_label(c)}"] = min(ok, key=lambda n: float(n.split()[1][1:]))
        sel[density] = {"service_target_completion_pct": target, "default_completion_pct": completion[(density, DEFAULT_SETTING)],
                        "default_verdict_events": events[(density, DEFAULT_SETTING)], "chosen": chosen,
                        "tuning_completion_pct": {n: completion[(density, n)] for n in _settings_at(density)},
                        "tuning_verdict_events": {n: events[(density, n)] for n in _settings_at(density)},
                        "tuning_leak_sum": {n: leak[n] for n in _settings_at(density)}}
        evaluate[density] = sorted(set(chosen.values()))
    return sel, evaluate


def study_matched_eval(evaluate, seeds=None, legit_minutes=None):
    """Stage 2: the selected settings on the evaluation seeds, legitimate side at 65 % and 80 %, attack side."""
    seeds = seeds or EVAL_SEEDS
    specs, index = [], []
    for density, names in evaluate.items():
        for name in names:
            for conv in MC["legitimate_runs"]["conversion_evaluation"]:
                for s in seeds:
                    specs.append(_legit_spec(name, density, conv, s, legit_minutes))
                    index.append(("legit", density, name, conv, s))
    for name in sorted({n for names in evaluate.values() for n in names}):
        for aname in MATCHED_ATTACKERS:
            for s in seeds:
                specs.append(_attack_spec(name, aname, s))
                index.append(("attack", None, name, aname, s))
    return specs, index


FALLBACK_LEVELS = [0.0, 0.7, 1.0]
FALLBACK_SETTINGS = [DEFAULT_SETTING, "counter graded 20/day", "none"]


def study_fallback(seeds, minutes=24 * 60):
    """R1: the same policies with no, the modelled, and universal WhatsApp reachability (200 blocks, 65 %)."""
    specs, index = [], []
    for name in FALLBACK_SETTINGS:
        for w in FALLBACK_LEVELS:
            for s in seeds:
                spec = _legit_spec(name, "200", 0.65, s, minutes)
                spec.legit.whatsapp_fraction = w
                specs.append(spec)
                index.append((name, w, s))
    return specs, index


POISONER_VARIANTS = {
    # name -> (cfg overrides, active minutes, run minutes, whatsapp fraction)
    "graded verdicts (default)": ({}, None, 20, 0.7),
    "graded, no fallback channel": ({}, None, 20, 0.0),
    "graded, every user reachable on WhatsApp": ({}, None, 20, 1.0),
    "hard deny (24 h denylist)": ({"block_action": "deny"}, None, 20, 0.7),
    "observe only (counterfactual: verdicts recorded, nothing enforced)": ({"block_action": "observe"}, None, 20, 0.7),
    "graded, attacker stops after 10 min (recovery, 70-minute run)": ({}, 10, 70, 0.7),
    # observe-only counterfactuals for the variants that change the offered trace or the run
    "observe only, no fallback channel": ({"block_action": "observe"}, None, 20, 0.0),
    "observe only, every user reachable on WhatsApp": ({"block_action": "observe"}, None, 20, 1.0),
    "observe only, attacker stops after 10 min (70-minute run)": ({"block_action": "observe"}, 10, 70, 0.7),
}
POISONER_REFERENCE = "observe only (counterfactual: verdicts recorded, nothing enforced)"


def poisoner_reference(vname):
    """The observe-only variant with the same run length, attack length and fallback reachability (same offered trace)."""
    cfg, active, minutes, wa = POISONER_VARIANTS[vname]
    if cfg.get("block_action") == "observe":
        return None
    for rname, (rcfg, ractive, rminutes, rwa) in POISONER_VARIANTS.items():
        if rcfg.get("block_action") == "observe" and (ractive, rminutes, rwa) == (active, minutes, wa):
            return rname
    return None


def study_poisoner(seeds):
    specs, index = [], []
    base = ADAPTIVE_ATTACKERS["block_poisoner"]
    for vname, (cfg, active, minutes, wa) in POISONER_VARIANTS.items():
        for s in seeds:
            a = replace(randomised(base, s), active_minutes=active)
            specs.append(SimSpec(attacker=a, legit=LegitSpec(blocks=20, whatsapp_fraction=wa), minutes=minutes, caps_lifted=True,
                                 cfg_overrides=dict(cfg), seed=s, record_requests=True))
            index.append((vname, s))
    return specs, index


ALTERNATIVES = {
    "default": {},
    "trust budget (8 exempt requests/min)": {"known_good_budget_per_min": 8},
    "receipt-robust block tests": {"receipt_policy": "robust"},
    "both": {"known_good_budget_per_min": 8, "receipt_policy": "robust"},
}
ALTERNATIVE_ATTACKERS = ["trust_building_pumper", "trust_building_concentrated", "receipt_faking_carrier", "threshold_aware_carrier"]


def study_alternatives(seeds, minutes=20):
    """R16: the two design alternatives against the attackers that defeat the default, with and without caps."""
    specs, index = [], []
    for mode, lifted in MODES.items():
        for aname in ALTERNATIVE_ATTACKERS:
            a = ADAPTIVE_ATTACKERS[aname]
            for vname, cfg in ALTERNATIVES.items():
                for s in seeds:
                    specs.append(SimSpec(attacker=randomised(a, s), minutes=minutes, caps_lifted=lifted, cfg_overrides=dict(cfg), seed=s,
                                         warmup_minutes=30 if a.trust_building_minutes else 10))
                    index.append((mode, aname, vname, s))
    return specs, index


def study_alternatives_fp(seeds, minutes=24 * 60):
    """What the alternatives cost real users: 24 hours on 200 blocks, 80 % conversion, caps on, with 5 %
    of blocks on a poor route that loses half its messages (the case receipt-robust tests can misread)."""
    specs, index = [], []
    for vname, cfg in ALTERNATIVES.items():
        for s in seeds:
            legit = LegitSpec(blocks=200, bad_route_fraction=0.05, bad_route_failure=0.5)
            specs.append(SimSpec(attacker=ATTACKERS["naive_single_client"], legit=legit, legit_only=True, minutes=minutes,
                                 warmup_minutes=0, caps_lifted=False, cfg_overrides=dict(cfg), seed=s))
            index.append((vname, s))
    return specs, index


BASELINE_VARIANTS = {
    # name -> SimSpec overrides
    "oracle: told the modelled legitimate rate (main study)": dict(baseline="oracle"),
    "learned, cold start: no closed hour of history": dict(baseline="learned"),
    "learned, three closed hours": dict(baseline="learned", warmup_minutes=190),
    "learned, weekly profile (3 previous weeks)": dict(baseline="learned", profile_weeks=3),
    "learned, weekly profile, stale (legitimate rate halved since)": dict(baseline="learned", profile_weeks=3, profile_rate_multiple=2.0),
    "learned, weekly profile, stale (legitimate rate doubled since)": dict(baseline="learned", profile_weeks=3, profile_rate_multiple=0.5),
    "learned, weekly profile poisoned at that hour each week (schedule-aware)": dict(baseline="learned", profile_weeks=3,
                                                                                    warmup_attack_rate=cal("legit_traffic_rate_per_min")),
    "learned, weekly profile, two workers": dict(baseline="learned", profile_weeks=3, baseline_workers=2),
    "learned, weekly profile, worker restarts at minute 10": dict(baseline="learned", profile_weeks=3, baseline_restart_min=10),
}
BASELINE_REFERENCE = "learned, weekly profile (3 previous weeks)"


def study_baseline(seeds, attacker_names=("residential_captcha_farm", "residential_bot"), minutes=20):
    """R14: the deployed baseline job against the oracle, over the weekly profile it is designed for:
    cold start, short history, three previous weeks, stale profiles, schedule-aware poisoning of the
    profile, two concurrent workers and a restart. Paired effects against the clean weekly profile."""
    specs, index = [], []
    for name in attacker_names:
        for vname, ov in BASELINE_VARIANTS.items():
            for s in seeds:
                kw = dict(attacker=randomised(ATTACKERS[name], s), minutes=minutes, caps_lifted=False, seed=s)
                kw.update(ov)
                specs.append(SimSpec(**kw))
                index.append((name, vname, s))
    return specs, index


LONG_ATTACK_MIN = 60


def study_long_attack(seeds):
    """R13: the default against the concentrated pumpers over a 60-minute attack (survival of containment)."""
    specs, index = [], []
    for aname in MATCHED_ATTACKERS:
        for s in seeds:
            specs.append(_attack_spec(DEFAULT_SETTING, aname, s, minutes=LONG_ATTACK_MIN))
            index.append((aname, s))
    return specs, index


VARIANCE_ATTACKERS = ["residential_captcha_farm", "sequential_numbers", "datacenter_rotation", "residential_bot"]


def study_variance(seeds):
    """A fixed-parameter sensitivity comparison: the same attackers with the per-seed randomisation
    on, and with it fixed at the profile's own parameters (a comparison of two spreads, not a
    decomposition; see study_variance_nested)."""
    specs, index = [], []
    for name in VARIANCE_ATTACKERS:
        for randomise in (True, False):
            for s in seeds:
                a = randomised(ATTACKERS[name], s) if randomise else replace(ATTACKERS[name])
                specs.append(SimSpec(attacker=a, caps_lifted=False, seed=s))
                index.append((name, "randomised" if randomise else "fixed parameters", s))
    return specs, index


NESTED_CONFIGS, NESTED_SIMS = 10, 3


def study_variance_nested(n_configs=NESTED_CONFIGS, n_sims=NESTED_SIMS):
    """A nested design for the variance decomposition: n_configs attacker configurations drawn as the
    main study draws them (configuration seeds 1000+), each run with n_sims simulation seeds."""
    specs, index = [], []
    for name in VARIANCE_ATTACKERS:
        for c in range(n_configs):
            a = randomised(ATTACKERS[name], 1000 + c)
            for m in range(n_sims):
                specs.append(SimSpec(attacker=a, caps_lifted=False, seed=2000 + 10 * c + m))
                index.append((name, c, m))
    return specs, index


INTERACTIONS = [("sequential_numbers", "feedback", "fine_destination_key"),
                ("sequential_numbers", "risk_engine", "feedback"),
                ("residential_reused_profile", "feedback", "session"),
                ("residential_captcha_farm", "adaptive_caps", "risk_engine")]


def study_interactions(seeds, minutes=20, caps_lifted=False):
    """Selected two-layer removals, on the ablation's seeds and attacker draws, so the interaction
    contrast (both removed) - (first removed) - (second removed) + (full) is paired per seed."""
    specs, index = [], []
    for name, f1, f2 in INTERACTIONS:
        for s in seeds:
            specs.append(SimSpec(attacker=randomised(ATTACKERS[name], s), minutes=minutes,
                                 features=frozenset(ALL_FEATURES - {f1, f2}), caps_lifted=caps_lifted, seed=s))
            index.append((name, f1, f2, s))
    return specs, index


# ---------------------------------------------------------------- robustness (predeclared)
ROB = PROTOCOL["robustness"]


def robustness_points():
    """The protocol's Latin hypercube over its ranges, generator seed 2026."""
    rng = random.Random(2026)
    names = list(ROB["ranges"])
    k = ROB["points"]
    cols = {}
    for n in names:
        lo, hi = ROB["ranges"][n]
        strata = list(range(k))
        rng.shuffle(strata)
        cols[n] = [lo + (hi - lo) * (i + rng.random()) / k for i in strata]
    return [{n: cols[n][i] for n in names} for i in range(k)]


def _human_beta(mean, concentration=10.5):
    return (mean * concentration, (1 - mean) * concentration)


def _rob_legit(pt, blocks=None):
    het = ROB["held_out_family"]["legitimate_heterogeneity"]
    return LegitSpec(conversion=pt["conversion"], autofill_fraction=pt["autofill_fraction"], captcha_beta=_human_beta(pt["human_captcha_mean"]),
                     whatsapp_fraction=pt["whatsapp_fraction"], returning_fraction=pt["returning_fraction"], rate_per_min=pt["legit_rate_per_min"],
                     blocks=blocks, block_conversion_sd=het["block_conversion_sd"], bad_route_fraction=het["bad_route_fraction"],
                     bad_route_failure=het["bad_route_failure"], resend_prob=het["resend_prob"], bursts=tuple(tuple(b) for b in het["bursts"]))


def _held_out_attacker(a, seed):
    """Attack rate and pool drawn from the held-out ranges (outside the tuned ones)."""
    r = random.Random(seed * 104729 + 7)
    lo, hi = ROB["held_out_family"]["attacker_rates_per_min"]
    plo, phi = ROB["held_out_family"]["attacker_pool_sizes"]
    s = replace(a)
    s.rate_per_min = r.uniform(lo, hi)
    if a.network != "single_ip":
        s.pool_size = int(10 ** r.uniform(math.log10(plo), math.log10(phi)))
    return s


ROB_SCENARIOS = ["no_attack", "datacenter_rotation", "premium_pumping", "naive_single_client", "farm_caps_lifted",
                 "farm_caps_v1", "farm_caps_v2", "pumper_no_verify", "legit_6h_200_blocks"]


def study_robustness():
    specs, index = [], []
    for i, pt in enumerate(robustness_points()):
        for s in range(ROB["seeds_per_point"]):
            seed = 5000 + 100 * i + s
            legit = _rob_legit(pt)
            for sc in ROB_SCENARIOS:
                if sc == "no_attack":
                    spec = SimSpec(attacker=ATTACKERS["naive_single_client"], legit=legit, legit_only=True, caps_lifted=False, seed=seed)
                elif sc in ("datacenter_rotation", "premium_pumping", "naive_single_client"):
                    spec = SimSpec(attacker=_held_out_attacker(ATTACKERS[sc], seed), legit=legit, caps_lifted=False, seed=seed)
                elif sc == "farm_caps_lifted":
                    spec = SimSpec(attacker=_held_out_attacker(ATTACKERS["residential_captcha_farm"], seed), legit=legit, caps_lifted=True, seed=seed)
                elif sc in ("farm_caps_v1", "farm_caps_v2"):
                    spec = SimSpec(attacker=_held_out_attacker(ATTACKERS["residential_captcha_farm"], seed), legit=legit, caps_lifted=False,
                                   features=V1_FEATURES if sc.endswith("v1") else ALL_FEATURES, seed=seed)
                elif sc == "pumper_no_verify":
                    spec = SimSpec(attacker=_held_out_attacker(PUMPING_ATTACKERS["concentrated_pumper_no_verify"], seed), legit=legit,
                                   caps_lifted=True, warmup_minutes=PUMPING_WARMUP_MIN, seed=seed)
                else:
                    spec = SimSpec(attacker=ATTACKERS["naive_single_client"], legit=_rob_legit(pt, blocks=200), legit_only=True,
                                   minutes=360, warmup_minutes=0, caps_lifted=True, seed=seed)
                specs.append(spec)
                index.append((i, sc, s))
    return specs, index


def judge_robustness(by_cell):
    """Apply the protocol's claims. by_cell: {(point, scenario, seed): result}."""
    pts = robustness_points()

    def verdict(cells):
        ok = sum(1 for c in cells if c)
        return {"cells": len(cells), "true": ok, "share": ok / max(len(cells), 1), "holds": len(cells) > 0 and ok >= 0.9 * len(cells)}
    c1, c2, c3, c4, c4_low, c5 = [], [], [], [], [], []
    for (i, sc, s), r in by_cell.items():
        if sc in ("datacenter_rotation", "premium_pumping", "naive_single_client"):
            base = by_cell[(i, "no_attack", s)]["friction"]["completed_pct"]
            frac = r["attack"]["leaked_total"] / max(r["attack"]["requests"], 1)
            c1.append(frac <= 0.05 and r["friction"]["completed_pct"] >= base - 2.0)
        elif sc == "farm_caps_lifted":
            c2.append(r["attack"]["leaked_total"] >= 0.9 * max(r["attack"]["requests"], 1))
        elif sc == "pumper_no_verify":
            c3.append(r["attack"]["time_to_containment_min"] is not None and r["attack"]["leaked_total"] <= 0.3 * max(r["attack"]["requests"], 1))
        elif sc == "legit_6h_200_blocks":
            per_k = 1000.0 * r["block_verdicts"] / max(r["friction"]["users"], 1)
            (c4 if pts[i]["conversion"] >= 0.75 else c4_low).append(per_k <= 1.0)
        elif sc == "farm_caps_v2":
            v1 = by_cell[(i, "farm_caps_v1", s)]
            c5.append(r["attack"]["leaked_total"] <= 0.7 * v1["attack"]["leaked_total"] and
                      r["friction"]["first_time"]["refusal_rate_pct"] >= v1["friction"]["first_time"]["refusal_rate_pct"] + 10.0)
    out = {"C1": verdict(c1), "C2": verdict(c2), "C3": verdict(c3), "C4": verdict(c4), "C5": verdict(c5),
           "C4_points_below_0.75": dict(verdict(c4_low), judged=False), "points": pts}
    return out


SPREAD_BLOCKS = [3, 30, 300]
SPREAD_RANGE_DIGITS = {9: "1 000", 8: "10 000", 7: "100 000"}     # numbers per range; the key is 8 digits


def study_spread(seeds, minutes=20):
    """How widely the pumper spreads its destinations, with ranges that do and do not align with the
    8-digit key. At the far end the pumper is the diluting flooder."""
    specs, index = [], []
    for verify in (0.0, 1.0):
        for nb in SPREAD_BLOCKS:
            for digits in SPREAD_RANGE_DIGITS:
                a = AttackerSpec(f"spread_{nb}x{digits}", numbers="concentrated", n_blocks=nb, block_range_digits=digits,
                                 fp_mode="aged", captcha_beta=(9, 1.5), verify_fraction=verify, verify_delay_s=1.0, earns_revenue=True)
                for s in seeds:
                    specs.append(SimSpec(attacker=randomised(a, s), minutes=minutes, caps_lifted=True, seed=s))
                    index.append((verify, nb, digits, s))
    return specs, index


DILUTION_MULTIPLES = [0.5, 1, 2, 5, 10]


def study_dilution(seeds, minutes=60):
    """The captcha-farm attacker at multiples of the legitimate rate for an hour: where does the
    conversion signal start to fire, how much still leaks, and what does it cost real users."""
    specs, index = [], []
    for m in DILUTION_MULTIPLES:
        a = replace(ATTACKERS["residential_captcha_farm"], rate_multiple_of_legit=m)
        for s in seeds:
            spec = SimSpec(attacker=randomised(a, s), minutes=minutes, caps_lifted=True, seed=s)
            spec.attacker.rate_multiple_of_legit = m          # randomised() set a rate; the multiple overrides it
            specs.append(spec)
            index.append((m, s))
    return specs, index


CAP_SWEEP = {"adaptive_floor": [0.1, 0.25, 0.5, 1.0], "base_cap_multiple": [1.5, 2.0, 3.0, 5.0]}
CADENCES = {"every minute (worker default)": 60, "every 2 minutes": 120, "every 5 minutes": 300, "every 10 minutes": 600, "hourly": 3600}
CADENCE_PHASES = {"tick aligned with the attack start": 0, "tick offset by half a period": 1}
CADENCE_LONG_ATTACK_MIN = 60


def study_cadence(seeds, attacker_names=("residential_captcha_farm", "residential_bot"), minutes=20):
    """The adaptive controller at the worker's cadence versus slower ones, at two tick phases relative
    to the attack start, plus a 60-minute attack for the hourly job (which a 20-minute attack can
    straddle or miss depending on the phase)."""
    specs, index = [], []
    for name in attacker_names:
        for cname, tick in CADENCES.items():
            for pname, half in CADENCE_PHASES.items():
                if tick == 60 and half:
                    continue                                   # a one-minute tick has no phase
                for s in seeds:
                    specs.append(SimSpec(attacker=randomised(ATTACKERS[name], s), minutes=minutes, caps_lifted=False,
                                         adaptive_tick_s=tick, adaptive_phase_s=(tick // 2 if half else 0), seed=s))
                    index.append((name, cname, pname, minutes, s))
        for pname, half in CADENCE_PHASES.items():
            for s in seeds:
                specs.append(SimSpec(attacker=randomised(ATTACKERS[name], s), minutes=CADENCE_LONG_ATTACK_MIN, caps_lifted=False,
                                     adaptive_tick_s=3600, adaptive_phase_s=(1800 if half else 0), seed=s))
                index.append((name, "hourly", pname, CADENCE_LONG_ATTACK_MIN, s))
    return specs, index


def study_cap_sweep(seeds, attacker_names=("residential_captcha_farm", "residential_bot"), minutes=20):
    specs, index = [], []
    for name in attacker_names:
        for floor in CAP_SWEEP["adaptive_floor"]:
            for mult in CAP_SWEEP["base_cap_multiple"]:
                for s in seeds:
                    specs.append(SimSpec(attacker=randomised(ATTACKERS[name], s), minutes=minutes, caps_lifted=False,
                                         adaptive_floor=floor, base_cap_multiple=mult, seed=s))
                    index.append((name, floor, mult, s))
    return specs, index


SWEEP_AXES = {
    "tier_scale": [0.6, 0.8, 1.0, 1.2, 1.4],            # multiplies (20, 40, 60, 80)
    "conversion_weight": [0, 10, 25, 40],
    "fresh_fp_weight": [0, 10, 20, 30, 40],
    "flood_points": [0, 15, 30],
    "resolution_timeout_s": [60, 120, 300, 600],
}


def sweep_spec(base: AttackerSpec, axis, val, seed, minutes=20):
    cfg, w = {}, {}
    if axis == "tier_scale":
        cfg["tier_bounds"] = tuple(int(round(b * val)) for b in (20, 40, 60, 80))
    elif axis == "conversion_weight":
        w["conversion"] = val
    elif axis == "fresh_fp_weight":
        w["fresh_fp_5min"], w["fresh_fp_1h"] = val, val // 2
    elif axis == "flood_points":
        cfg["conversion_flood_points"] = val
    elif axis == "resolution_timeout_s":
        cfg["resolution_timeout_s"] = val
    return SimSpec(attacker=randomised(base, seed), minutes=minutes, cfg_overrides=cfg, weight_overrides=w, seed=seed)


def study_sweep(seeds, attacker_names=("residential_captcha_farm", "residential_aged_fps"), minutes=20):
    specs, index = [], []
    for name in attacker_names:
        for axis, vals in SWEEP_AXES.items():
            for v in vals:
                for s in seeds:
                    specs.append(sweep_spec(ATTACKERS[name], axis, v, s, minutes))
                    index.append((name, axis, v, s))
    return specs, index


def study_adaptive(seeds, minutes=20, modes=MODES):
    specs, index = [], []
    for mode, lifted in modes.items():
        for name, a in ADAPTIVE_ATTACKERS.items():
            for s in seeds:
                legit = LegitSpec(blocks=20) if a.numbers == "poison" else LegitSpec()   # the poisoner needs shared blocks
                run_min = a.trust_building_minutes + 30 if a.trust_building_minutes >= 20 else minutes
                specs.append(SimSpec(attacker=a if a.network == "multi_asn" else randomised(a, s), legit=legit,
                                     minutes=run_min, caps_lifted=lifted, seed=s,
                                     warmup_minutes=30 if a.trust_building_minutes else 10))
                index.append((mode, name, s))
    return specs, index


ECON_SHARES = [0.05, 0.1, 0.2, 0.3, 0.5]
ECON_PRICE_MULTIPLES = [0.5, 1.0, 2.0]


def attacker_bill(summ):
    """Event-level attacker cost for one run summary: a CAPTCHA token for every session attempt (refused
    ones included) and every request that reached the pipeline, a paid solution for every interactive
    challenge, and proxy traffic for every request. Not included: identity preparation, phone numbers,
    carrier contracts, fixed costs and the attacker's own verifications."""
    proxy_per_req = cal("request_bytes") / 1e9 * cal("residential_proxy_cost_per_gb_usd")
    solve = cal("captcha_solve_cost_usd")
    reqs = summ["requests"][0]
    tokens = (summ["attacker_session_attempts"][0] or 0) + reqs
    solved = summ["attacker_challenges_solved"][0] or 0
    return {"tokens": tokens, "requests": reqs, "challenges_solved": solved,
            "cost_usd": tokens * solve + solved * solve + reqs * proxy_per_req}


def economics(summary_v1, summary_v2, attacker_name, earns_revenue):
    """Scenario accounting, not measured profit. Revenue = leaked SMS x retail termination price x an
    ASSUMED revenue share, and only for pumping attackers. For each design: the event-level bill, the
    break-even share (the share at which revenue equals the bill: share* = cost / (leaked x price)) and
    profit over a grid of shares and price multiples, so no single assumed share decides the sign."""
    sms = cal("sms_unit_cost_usd")
    rows = []
    for label, summ in (("v1", summary_v1), ("v2", summary_v2)):
        leaked = summ["leaked_total"][0]
        bill = attacker_bill(summ)
        breakeven = (bill["cost_usd"] / (leaked * sms)) if (earns_revenue and leaked > 0) else None
        surface = {f"share={sh},price x{pm}": (leaked * sms * pm * sh - bill["cost_usd"]) if earns_revenue else -bill["cost_usd"]
                   for sh in ECON_SHARES for pm in ECON_PRICE_MULTIPLES}
        rows.append({"design": label, "leaked_sms": leaked, "requests": bill["requests"], "tokens": bill["tokens"],
                     "challenges_solved": bill["challenges_solved"], "attacker_cost_usd": bill["cost_usd"],
                     "breakeven_share": breakeven, "profit_surface_usd": surface,
                     "defender_cost_usd": summ["attacker_cost_usd"][0], "verified_codes": summ["attacker_verifications"][0]})
    return rows


# ---------------------------------------------------------------- false positives of the block tests

FP_CONVERSIONS = [0.5, 0.65, 0.8, 0.9]
FP_FAST_SHARES = [0.0, 0.05, 0.1, 0.2, 0.3]
FP_SENDS_PER_BLOCK = [10, 30, 100]


def block_test_false_positives(cfg, trials=20_000, seed=3, conversions=FP_CONVERSIONS, fast_shares=FP_FAST_SHARES,
                               sends=FP_SENDS_PER_BLOCK):
    """Monte Carlo of the exact sequential tests on one block that sees only legitimate traffic: the
    block starts with empty statistics, receives exactly `n` resolved sends in the window, and the
    quantity estimated is P(at least one verdict in that sequence), by true conversion and true share
    of fast (autofill) verifications, with the tests parameterised as deployed (cfg). Each cell reports
    the event count, the number of trials and a 95 % Wilson interval; a zero count is an upper bound
    of about 3/trials, not evidence of a zero probability. This is one block's per-window hazard, not
    the full day's harm process (verdict TTLs, resets and exemptions), which section H2 simulates."""
    import math
    thr = math.log(cfg.sprt_threshold)
    floor = -cfg.block_credit_thresholds * thr if cfg.block_test == "cusum" else -math.inf
    cv, cf = math.log(cfg.sprt_attack_conversion / cfg.sprt_legit_conversion), \
        math.log((1 - cfg.sprt_attack_conversion) / (1 - cfg.sprt_legit_conversion))
    sv, ss = math.log(cfg.sprt_attack_fast / cfg.sprt_legit_fast), math.log((1 - cfg.sprt_attack_fast) / (1 - cfg.sprt_legit_fast))
    rng = random.Random(seed)
    out = {}
    for n in sends:
        for p in conversions:
            for f in fast_shares:
                verdicts = {"never_verified": 0, "machine_verified": 0}
                for _ in range(trials):
                    v = fl = 0
                    conv = speed = 0.0          # the running statistics exactly as feedback._block_event keeps them
                    for _ in range(n):
                        if rng.random() < p:
                            v += 1
                            conv = max(floor, conv + cv)
                            speed = max(floor, speed + (sv if rng.random() < f else ss))
                            if v >= cfg.sprt_min_events and speed > thr:
                                verdicts["machine_verified"] += 1
                                break
                        else:
                            fl += 1
                            conv = max(floor, conv + cf)
                        if v + fl >= cfg.sprt_min_events and conv > thr:
                            verdicts["never_verified"] += 1
                            break
                total = verdicts["never_verified"] + verdicts["machine_verified"]
                _, lo, hi = fraction_ci(total, trials)
                out[(n, p, f)] = {k: val / trials for k, val in verdicts.items()} | {
                    "events": total, "trials": trials, "p_lo": float(lo), "p_hi": float(hi)}
    return out


LEGIT_ONLY_BLOCKS = {200: "144 / block / day", 1000: "29 / block / day", None: "4 / block / day (uniform over 7 prefixes)"}
LEGIT_ONLY_CONVERSIONS = [0.8, 0.65]
LEGIT_ONLY_AUTOFILL = [0.0, 0.2, 0.3]


LEGIT_ONLY_CALIBRATION = {"fixed (deployed calibration)": False, "recalibrated to this population": True}


def study_legit_only_24h(seeds, minutes=24 * 60):
    """Twenty-four hours of legitimate traffic only, at realistic sends per destination block, over
    the conversion and autofill shares the tests might meet: how many blocks reach a verdict and how
    many real users that touches. Run twice: with the speed test's legitimate-fast rate fixed at the
    deployed calibration (robustness to a wrong assumption) and recalibrated to the population."""
    specs, index = [], []
    for calib, recal in LEGIT_ONLY_CALIBRATION.items():
        for blocks in LEGIT_ONLY_BLOCKS:
            for conv in LEGIT_ONLY_CONVERSIONS:
                for af in LEGIT_ONLY_AUTOFILL:
                    for s in seeds:
                        legit = LegitSpec(conversion=conv, autofill_fraction=af, blocks=blocks)
                        specs.append(SimSpec(attacker=ATTACKERS["naive_single_client"], legit=legit, legit_only=True,
                                             minutes=minutes, warmup_minutes=0, caps_lifted=True, seed=s, recalibrate_speed=recal))
                        index.append((calib, blocks, conv, af, s))
    return specs, index


OUTAGE_VARIANTS = {
    "receipts + outage detector (default)": {},
    "receipts, detector off": {"outage_min_blocks": 10 ** 9},
    "no receipts (send-clocked, the earlier design)": {"delivery_receipts": False, "outage_min_blocks": 10 ** 9},
}


def study_outage(seeds, minutes=60):
    """A 30-minute carrier outage on one prefix during legitimate traffic at 144 sends per block
    per day: with receipts and the detector, without the detector, and without receipts."""
    from .sim import OutageSpec
    specs, index = [], []
    for kind in ("failed_receipts", "silent"):
        for vname, cfg in OUTAGE_VARIANTS.items():
            for s in seeds:
                legit = LegitSpec(blocks=200)
                specs.append(SimSpec(attacker=ATTACKERS["naive_single_client"], legit=legit, legit_only=True, minutes=minutes,
                                     warmup_minutes=30, caps_lifted=True, seed=s, cfg_overrides=dict(cfg),
                                     outage=OutageSpec(prefix="96650", start_min=10, duration_min=30, kind=kind)))
                index.append((kind, vname, s))
    return specs, index
