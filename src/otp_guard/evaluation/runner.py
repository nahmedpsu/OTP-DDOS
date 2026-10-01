"""Studies built on the simulation: attacker catalogue, randomised multi-seed runs with
confidence intervals, leave-one-layer-out ablation, weight and boundary sweeps, adaptive
attackers, and attacker economics."""
import copy
import multiprocessing as mp
import random
from dataclasses import replace

from ..config import ALL_FEATURES, V1_FEATURES, OPTIONAL_FEATURES
from .calibration import value as cal
from .sim import AttackerSpec, LegitSpec, SimSpec, run_sim
from .stats import mean_ci

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
    "spoofed_platform": AttackerSpec("spoofed_platform", "Residential pool, HTTP_PLATFORM: ios without attestation",
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
    return {
        "n": len(results),
        "contained_fraction": n_contained / len(results),
        "time_to_containment_min": mean_ci([t if t is not None else minutes for t in ttc]),
        "leaked_before_containment": mean_ci(col(("attack", "leaked_before_containment"))),
        "leaked_total": mean_ci(col(("attack", "leaked_total"))),
        "steady_state_leak_per_min": mean_ci(col(("attack", "steady_state_leak_per_min"))),
        "attacker_cost_usd": mean_ci(col(("attack", "cost_usd"))),
        "requests": mean_ci(col(("attack", "requests"))),
        "legit_delivered_pct": mean_ci(col(("friction", "delivered_pct"))),
        "legit_challenge_rate_pct": mean_ci(col(("friction", "challenge_rate_pct"))),
        "legit_refusal_rate_pct": mean_ci(col(("friction", "refusal_rate_pct"))),
        "legit_mean_added_delay_s": mean_ci(col(("friction", "mean_added_delay_s"))),
        "attacker_verifications": mean_ci(col(("attacker_verifications",))),
        "attacker_challenges_solved": mean_ci(col(("attacker_challenges_solved",))),
    }


MODES = {"behavioural_only": True, "with_adaptive_caps": False}     # name -> caps_lifted


def study_multi_seed(seeds, features=ALL_FEATURES, attackers=None, minutes=20, modes=MODES):
    specs, index = [], []
    for mode, lifted in modes.items():
        for name, a in (attackers or ATTACKERS).items():
            for s in seeds:
                specs.append(SimSpec(attacker=randomised(a, s), minutes=minutes, features=features, caps_lifted=lifted, seed=s))
                index.append((mode, name, s))
    return specs, index


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
    "otp_ttl_s": [120, 300, 600],
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
    elif axis == "otp_ttl_s":
        cfg["otp_ttl"] = val
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
                specs.append(SimSpec(attacker=a if a.network == "multi_asn" else randomised(a, s), minutes=minutes,
                                     caps_lifted=lifted, seed=s))
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
