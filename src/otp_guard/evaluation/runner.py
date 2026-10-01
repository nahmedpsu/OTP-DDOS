"""Studies built on the simulation: attacker catalogue, randomised multi-seed runs with
confidence intervals, leave-one-layer-out ablation, weight and boundary sweeps, adaptive
attackers, and attacker economics."""
import copy
import multiprocessing as mp
import random
from dataclasses import replace

from ..config import ALL_FEATURES, V1_FEATURES, OPTIONAL_FEATURES, BASELINE_DESIGNS, BASELINE_CFG
from .calibration import value as cal
from .sim import AttackerSpec, LegitSpec, SimSpec, run_sim
from .stats import mean_ci, fraction_ci

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


def _verdict_fields(results):
    """Verdict accounting shared by every summary: events (not blocks), unique blocks, stages, the
    requests hit (by stage) and those that never completed, and the block-minutes under a verdict."""
    def col(f):
        return [f(r) for r in results]
    return {
        "block_verdicts": mean_ci(col(lambda r: r["block_verdicts"])),                 # verdict events
        "blocks_with_verdict": mean_ci(col(lambda r: r["blocks_with_verdict"])),       # distinct blocks
        "verdicts_stage1": mean_ci(col(lambda r: r["verdicts_stage1"])),
        "verdicts_stage2": mean_ci(col(lambda r: r["verdicts_stage2"])),
        "verdict_exposure_block_min": mean_ci(col(lambda r: r["verdict_exposure_block_min"])),
        "legit_hit_by_verdict": mean_ci(col(lambda r: r["legit_hit_by_verdict"])),
        "legit_hit_stage1": mean_ci(col(lambda r: r["legit_hit_stage1"])),
        "legit_hit_stage2": mean_ci(col(lambda r: r["legit_hit_stage2"])),
        "legit_hit_lost": mean_ci(col(lambda r: r["legit_hit_lost"])),
        "legit_hit_by_verdict_pct": mean_ci([100.0 * r["legit_hit_by_verdict"] / max(r["friction"]["users"], 1) for r in results]),
        "pending_at_end": sum(r["pending_at_end"]["events"] + r["pending_at_end"]["timeouts"] for r in results),
    }


def summarise_legit_only(results):
    """Aggregate false-positive runs: verdict events and the real users they touched."""
    def col(f):
        return [f(r) for r in results]
    out = {
        "n": len(results),
        "legit_users": mean_ci(col(lambda r: r["friction"]["users"])),
        "legit_delivered_pct": mean_ci(col(lambda r: r["friction"]["delivered_pct"])),
        "legit_completed_pct": mean_ci(col(lambda r: r["friction"]["completed_pct"])),
        "legit_challenge_rate_pct": mean_ci(col(lambda r: r["friction"]["challenge_rate_pct"])),
        "legit_refusal_rate_pct": mean_ci(col(lambda r: r["friction"]["refusal_rate_pct"])),
        "outage_alerts": mean_ci(col(lambda r: r["outage_alerts"])),
        "occupancy_median": mean_ci(col(lambda r: r["legit_block_occupancy"]["median"])),
        "occupancy_max": mean_ci(col(lambda r: r["legit_block_occupancy"]["max"])),
        "blocks_touched": mean_ci(col(lambda r: r["legit_block_occupancy"]["touched"])),
    }
    out.update(_verdict_fields(results))
    return out


def summarise(results):
    """Aggregate a list of run results into means with 95 % CIs."""
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
        # horizon-filled mean (uncontained runs counted as `minutes`); the tables report the conditional one below
        "time_to_containment_horizon_filled_min": mean_ci([t if t is not None else minutes for t in ttc]),
        "leaked_before_containment": mean_ci(col(("attack", "leaked_before_containment"))),
        "leaked_total": mean_ci(col(("attack", "leaked_total"))),
        "steady_state_leak_per_min": mean_ci(col(("attack", "steady_state_leak_per_min"))),
        "attacker_cost_usd": mean_ci(col(("attack", "cost_usd"))),
        "requests": mean_ci(col(("attack", "requests"))),
        "time_to_containment_if_contained_min": mean_ci([t for t in ttc if t is not None]),
        "legit_dispatched_pct": mean_ci(col(("friction", "dispatched_pct"))),
        "legit_delivered_pct": mean_ci(col(("friction", "delivered_pct"))),
        "legit_completed_pct": mean_ci(col(("friction", "completed_pct"))),
        "legit_challenge_rate_pct": mean_ci(col(("friction", "challenge_rate_pct"))),
        "legit_refusal_rate_pct": mean_ci(col(("friction", "refusal_rate_pct"))),
        "legit_mean_added_delay_s": mean_ci(col(("friction", "mean_added_delay_s"))),
        "first_time_refusal_rate_pct": mean_ci(col(("friction", "first_time", "refusal_rate_pct"))),
        "first_time_delivered_pct": mean_ci(col(("friction", "first_time", "delivered_pct"))),
        "first_time_challenge_rate_pct": mean_ci(col(("friction", "first_time", "challenge_rate_pct"))),
        "returning_refusal_rate_pct": mean_ci(col(("friction", "returning", "refusal_rate_pct"))),
        "returning_delivered_pct": mean_ci(col(("friction", "returning", "delivered_pct"))),
        "returning_users": mean_ci(col(("friction", "returning", "users"))),
        "attacker_session_attempts": mean_ci(col(("attacker_session_attempts",))),
        "attacker_sessions_refused": mean_ci(col(("attacker_sessions_refused",))),
        "attacker_blocks_requested": mean_ci(col(("attacker_blocks_requested",))),
        "attacker_blocks_leaked": mean_ci(col(("attacker_blocks_leaked",))),
        "attacker_verifications": mean_ci(col(("attacker_verifications",))),
        "attacker_challenges_solved": mean_ci(col(("attacker_challenges_solved",))),
        "legit_gate_loss_pct": mean_ci([100.0 * r["friction"]["refused_by"].get("gate", 0) / max(r["friction"]["users"], 1) for r in results]),
        "legit_undelivered_pct": mean_ci([100.0 * r["friction"]["refused_by"].get("undelivered", 0) / max(r["friction"]["users"], 1) for r in results]),
        "prep_requests": mean_ci([r["attack_phase"]["prep"].get("requests", 0) for r in results]),
        "prep_leaked": mean_ci([r["attack_phase"]["prep"].get("leaked", 0) for r in results]),
        "prep_verified": mean_ci([r["attack_phase"]["prep"].get("verified", 0) for r in results]),
        "flood_requests": mean_ci([r["attack_phase"]["flood"].get("requests", 0) for r in results]),
        "flood_leaked": mean_ci([r["attack_phase"]["flood"].get("leaked", 0) for r in results]),
        "flood_verified": mean_ci([r["attack_phase"]["flood"].get("verified", 0) for r in results]),
        "legit_hit_after_stop": mean_ci([sum(r["legit_hit_per_min"][active:]) if active else 0 for r in results]),
    }
    out.update(_verdict_fields(results))
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
    return mean_ci(diffs)


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


_COUNTER = frozenset({"attestation", "session", "block_count_limit"})
DETECTOR_SETTINGS = {
    # name -> (features, cfg overrides). The sequential tests at several thresholds and credit floors (a
    # floor of -c x log(threshold) is a zero-floor CUSUM with threshold (1 + c) x log(threshold) and head
    # start c x log(threshold)), the flat per-block counter at several limits with a refusing and a graded
    # action, all run on the same seeds against the concentrated pumpers and against legitimate traffic.
    "sequential, threshold 1000, credit 1 (default)": (ALL_FEATURES, {}),
    "sequential, threshold 1000, credit 0 (Page's CUSUM)": (ALL_FEATURES, {"block_credit_thresholds": 0.0}),
    "sequential, threshold 1000, credit 0.5": (ALL_FEATURES, {"block_credit_thresholds": 0.5}),
    "sequential, threshold 1000, credit 2": (ALL_FEATURES, {"block_credit_thresholds": 2.0}),
    "sequential, threshold 1000, unbounded credit (SPRT)": (ALL_FEATURES, {"block_test": "sprt"}),
    "sequential, threshold 100, credit 0": (ALL_FEATURES, {"sprt_threshold": 100.0, "block_credit_thresholds": 0.0}),
    "sequential, threshold 100, credit 1": (ALL_FEATURES, {"sprt_threshold": 100.0}),
    "sequential, threshold 10000, credit 0": (ALL_FEATURES, {"sprt_threshold": 10000.0, "block_credit_thresholds": 0.0}),
    "sequential, threshold 10000, credit 1": (ALL_FEATURES, {"sprt_threshold": 10000.0}),
    "counter, 5 per block per day, refuse": (_COUNTER, {"block_count_limit": (5, 86400)}),
    "counter, 20 per block per day, refuse": (_COUNTER, {"block_count_limit": (20, 86400)}),
    "counter, 5 per block per day, graded": (_COUNTER, {"block_count_limit": (5, 86400), "block_count_action": "graded"}),
    "counter, 10 per block per day, graded": (_COUNTER, {"block_count_limit": (10, 86400), "block_count_action": "graded"}),
    "counter, 20 per block per day, graded": (_COUNTER, {"block_count_limit": (20, 86400), "block_count_action": "graded"}),
}
DETECTOR_ATTACKERS = ["concentrated_pumper_no_verify", "concentrated_pumper_verifies_instantly",
                      "concentrated_pumper_verifies_humanlike", "concentrated_pumper_solves_challenges"]


def study_detectors(seeds, minutes=20):
    """Every detector setting against the four concentrated pumpers, on the same seeds and warm-up as the
    pumping study: the attack side of the matched comparison."""
    specs, index = [], []
    for aname in DETECTOR_ATTACKERS:
        a = PUMPING_ATTACKERS[aname]
        for dname, (feats, cfg) in DETECTOR_SETTINGS.items():
            for s in seeds:
                specs.append(SimSpec(attacker=randomised(a, s), minutes=minutes, features=feats, cfg_overrides=dict(cfg),
                                     caps_lifted=True, warmup_minutes=PUMPING_WARMUP_MIN, seed=s))
                index.append((aname, dname, s))
    return specs, index


DETECTOR_FP_CONVERSIONS = [0.8, 0.65]


def study_detector_fp(seeds, minutes=24 * 60):
    """The legitimate-traffic side of the matched comparison: every detector setting for 24 hours at
    144 sends per block per day (200 distinct blocks), 20 % autofill, deployed calibration, at the
    calibrated conversion and at Twilio's global 65 %."""
    specs, index = [], []
    for dname, (feats, cfg) in DETECTOR_SETTINGS.items():
        for conv in DETECTOR_FP_CONVERSIONS:
            for s in seeds:
                legit = LegitSpec(conversion=conv, autofill_fraction=0.2, blocks=200)
                specs.append(SimSpec(attacker=ATTACKERS["naive_single_client"], legit=legit, legit_only=True, features=feats,
                                     cfg_overrides=dict(cfg), minutes=minutes, warmup_minutes=0, caps_lifted=True, seed=s))
                index.append((dname, conv, s))
    return specs, index


POISONER_VARIANTS = {
    # name -> (cfg overrides, active minutes, run minutes)
    "graded verdicts (default)": ({}, None, 20),
    "hard deny (24 h denylist)": ({"block_action": "deny"}, None, 20),
    "graded, attacker stops after 10 min (recovery)": ({}, 10, 30),
}


def study_poisoner(seeds):
    specs, index = [], []
    base = ADAPTIVE_ATTACKERS["block_poisoner"]
    for vname, (cfg, active, minutes) in POISONER_VARIANTS.items():
        for s in seeds:
            a = replace(randomised(base, s), active_minutes=active)
            specs.append(SimSpec(attacker=a, legit=LegitSpec(blocks=20), minutes=minutes, caps_lifted=True,
                                 cfg_overrides=dict(cfg), seed=s))
            index.append((vname, s))
    return specs, index


BASELINE_VARIANTS = {
    # name -> (baseline, warm-up minutes, attacker requests/min during the warm-up)
    "oracle: told the modelled legitimate rate (main study)": ("oracle", 10, 0.0),
    "learned, cold start: no closed hour of history": ("learned", 10, 0.0),
    "learned, one closed hour": ("learned", 70, 0.0),
    "learned, three closed hours": ("learned", 190, 0.0),
    "learned, three hours poisoned at the legitimate rate": ("learned", 190, cal("legit_traffic_rate_per_min")),
}


def study_baseline(seeds, attacker_names=("residential_captcha_farm", "residential_bot"), minutes=20):
    """The deployed baseline job against the oracle the main study uses: cold start, little history,
    and a profile poisoned by a sustained low-rate attack during the learning period."""
    specs, index = [], []
    for name in attacker_names:
        for vname, (baseline, warm, poison) in BASELINE_VARIANTS.items():
            for s in seeds:
                specs.append(SimSpec(attacker=randomised(ATTACKERS[name], s), minutes=minutes, caps_lifted=False, seed=s,
                                     baseline=baseline, warmup_minutes=warm, warmup_attack_rate=poison))
                index.append((name, vname, s))
    return specs, index


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
                specs.append(SimSpec(attacker=a if a.network == "multi_asn" else randomised(a, s), legit=legit,
                                     minutes=minutes, caps_lifted=lifted, seed=s,
                                     warmup_minutes=30 if a.trust_building_minutes else 10))
                index.append((mode, name, s))
    return specs, index


def economics(summary_v1, summary_v2, attacker_name, earns_revenue):
    """Attacker profit over the 20-minute window under v1 and v2, per revenue-share assumption.
    Only pumping attackers (earns_revenue) are paid; a flooder's revenue is zero whatever leaks."""
    share = cal("pumping_revenue_share")
    sms = cal("sms_unit_cost_usd")
    proxy_per_req = cal("request_bytes") / 1e9 * cal("residential_proxy_cost_per_gb_usd")
    solve = cal("captcha_solve_cost_usd")
    rows = []
    for label, summ in (("v1", summary_v1), ("v2", summary_v2)):
        leaked = summ["leaked_total"][0]
        reqs = summ["requests"][0]
        solved = summ["attacker_challenges_solved"][0] or 0
        cost = reqs * (proxy_per_req + solve) + solved * solve
        for k in ("low", "high"):
            revenue = leaked * sms * share[k] if earns_revenue else 0.0
            rows.append({"design": label, "share": share[k] if earns_revenue else 0.0, "leaked_sms": leaked, "requests": reqs,
                         "attacker_revenue_usd": revenue, "attacker_cost_usd": cost,
                         "attacker_profit_usd": revenue - cost, "defender_cost_usd": summ["attacker_cost_usd"][0],
                         "verified_fake_accounts": summ["attacker_verifications"][0]})
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
