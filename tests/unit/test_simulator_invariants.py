"""Invariants of the simulator that the second-round review found violated: the offered workload
is identical across designs (M1), measurement cohorts reconcile (M2, M3), the clock advances by the
nominal duration whatever the gate does (M4), the run drains to its horizon (M5), legitimate blocks
are distinct (M19), trust-building phases are accounted separately (M22) and verdicts are counted
as events (M9)."""
from dataclasses import replace

from otp_guard.config import ALL_FEATURES, V1_FEATURES
from otp_guard.evaluation.runner import ATTACKERS, ADAPTIVE_ATTACKERS, PUMPING_ATTACKERS, randomised
from otp_guard.evaluation.sim import AttackerSpec, LegitSpec, SimSpec, Simulation, run_sim


def _spec(name="datacenter_rotation", seed=0, **kw):
    kw.setdefault("minutes", 6); kw.setdefault("warmup_minutes", 2)
    return SimSpec(attacker=randomised(ATTACKERS[name], seed), seed=seed, **kw)


def test_offered_workload_is_identical_across_designs():
    for name in ("datacenter_rotation", "residential_captcha_farm", "sequential_numbers"):
        digests = set()
        for feats, lifted in ((ALL_FEATURES, False), (frozenset(ALL_FEATURES - {"risk_engine"}), False),
                              (V1_FEATURES, False), (ALL_FEATURES, True)):
            r = run_sim(_spec(name, features=feats, caps_lifted=lifted))
            digests.add((r["workload_digest"], r["attack"]["requests"], r["friction"]["users"]))
        assert len(digests) == 1, (name, digests)


def test_cohorts_reconcile_and_the_funnel_is_monotone():
    for name in ("datacenter_rotation", "residential_captcha_farm"):
        for lifted in (True, False):
            r = run_sim(_spec(name, caps_lifted=lifted))              # result() asserts the conservation laws
            f, fu = r["friction"], r["funnel"]
            assert f["first_time"]["delivered"] + f["returning"]["delivered"] == f["delivered"]
            assert fu["offered"] >= fu["past_gate"] >= fu["dispatched"] >= fu["delivered"] >= fu["completed"]
            assert fu["offered"] - fu["dispatched"] == sum(v for k, v in fu["lost"].items() if k != "undelivered")


def test_gate_losses_are_in_the_denominator():
    legit = LegitSpec(captcha_beta=(0.5, 20))                       # most people fail the CAPTCHA gate
    r = run_sim(_spec(legit=legit))
    f = r["friction"]
    assert f["refused_by"].get("gate", 0) > 0 and f["users"] == r["funnel"]["offered"]
    assert f["refusal_rate_pct"] >= 100.0 * f["refused_by"]["gate"] / f["users"] - 1e-9


def test_clock_advances_the_nominal_duration_whatever_the_gate_does():
    a = replace(ATTACKERS["residential_captcha_farm"], captcha_beta=(0.1, 100), rate_per_min=30)   # every attempt fails
    spec = SimSpec(attacker=a, minutes=6, warmup_minutes=2, seed=0)
    sim = Simulation(spec)
    t0 = sim.h.clock.now()
    r = sim.run()
    assert sim.h.clock.now() - t0 >= 8 * 60 and len(r["attack"]["leaked_per_min"]) == 6
    assert r["attacker_sessions_refused"] == r["attacker_session_attempts"] > 0


def test_run_drains_to_its_horizon():
    r = run_sim(_spec("residential_captcha_farm"))
    assert r["pending_at_end"] == {"events": 0, "timeouts": 0, "effect_batches": 0}
    assert r["friction"]["completed"] > 0


def test_legitimate_blocks_are_distinct_and_occupancy_is_reported():
    r = run_sim(_spec(legit=LegitSpec(blocks=50), legit_only=True))
    occ = r["legit_block_occupancy"]
    assert occ["distinct_blocks"] == 50 and occ["touched"] <= 50 and occ["max"] >= occ["median"] >= occ["min"]


def test_trust_builder_phases_add_up_and_pairs_are_one_to_one():
    a = ADAPTIVE_ATTACKERS["trust_building_pumper"]
    spec = SimSpec(attacker=replace(a, trust_building_minutes=3, trust_pool=50), minutes=6, warmup_minutes=1, seed=1)
    sim = Simulation(spec)
    r = sim.run()
    ph = r["attack_phase"]
    assert ph["prep"]["requests"] + ph["flood"]["requests"] == r["attack"]["requests"]
    assert ph["prep"].get("leaked", 0) + ph["flood"].get("leaked", 0) == r["attack"]["leaked_total"]
    pool = sim.attack_state["trust_pool"]
    assert len({fp for fp, _ in pool}) == len({n for _, n in pool}) == 50


def test_verdicts_are_counted_as_events_with_stages():
    spec = SimSpec(attacker=randomised(ADAPTIVE_ATTACKERS["block_poisoner"], 0), legit=LegitSpec(blocks=20),
                   minutes=8, warmup_minutes=2, seed=0)
    r = run_sim(spec)
    assert r["block_verdicts"] == r["verdicts_stage1"] + r["verdicts_stage2"] >= r["blocks_with_verdict"] > 0
    assert r["block_verdicts_incl_drain"] >= r["block_verdicts"]
    assert r["legit_hit_by_verdict"] == r["legit_hit_stage1"] + r["legit_hit_stage2"]
    assert r["verdict_exposure_block_min"] > 0 and r["legit_hit_lost"] <= r["legit_hit_by_verdict"]


def test_attack_can_stop_early_for_recovery_studies():
    a = replace(randomised(ADAPTIVE_ATTACKERS["block_poisoner"], 0), active_minutes=3)
    r = run_sim(SimSpec(attacker=a, legit=LegitSpec(blocks=20), minutes=8, warmup_minutes=1, seed=0))
    assert sum(r["attack"]["leaked_per_min"][3:]) == 0 and len(r["legit_hit_per_min"]) == 8


# ---------------- third round ----------------

from otp_guard.evaluation.sim import unbits                                      # noqa: E402


def _graded_counter_spec(whatsapp, minutes=30, seed=0):
    return SimSpec(attacker=ATTACKERS["naive_single_client"], legit=LegitSpec(blocks=20, whatsapp_fraction=whatsapp),
                   legit_only=True, minutes=minutes, warmup_minutes=0, seed=seed,
                   features=frozenset({"attestation", "session", "block_count_limit"}),
                   cfg_overrides={"block_count_limit": (5, 86400), "block_count_action": "graded"})


def test_fallback_availability_reaches_the_channel_selector():
    """R1: the drawn WhatsApp reachability must change dispatch. 0 %: no WhatsApp at all; 70 %: about
    70 % of downgraded first-time users are served over WhatsApp; 100 %: no downgraded user is lost
    for want of a channel. The offered trace is the same in all three except for the draw itself."""
    out = {w: run_sim(_graded_counter_spec(w)) for w in (0.0, 0.7, 1.0)}
    ch = {w: r["friction"]["by_channel"] for w, r in out.items()}
    assert ch[0.0].get("whatsapp", 0) == 0 and ch[1.0].get("whatsapp", 0) > ch[0.7].get("whatsapp", 0) > 0
    nc = {w: r["friction"]["refused_by"].get("no_channel", 0) for w, r in out.items()}
    assert nc[0.0] > nc[0.7] > nc[1.0] == 0
    served = ch[0.7]["whatsapp"] / (ch[0.7]["whatsapp"] + nc[0.7])
    assert 0.6 < served < 0.8
    assert out[0.0]["friction"]["completed_pct"] < out[0.7]["friction"]["completed_pct"] < out[1.0]["friction"]["completed_pct"]


def test_verdict_estimands_are_bounded_by_the_window():
    """R2: exposure is never negative and never exceeds blocks x window; drain-time verdicts are
    counted only in the 'including drain' estimand."""
    spec = SimSpec(attacker=randomised(ADAPTIVE_ATTACKERS["block_poisoner"], 0), legit=LegitSpec(blocks=20),
                   minutes=6, warmup_minutes=2, seed=0)
    r = run_sim(spec)
    assert 0 <= r["verdict_exposure_block_min"] <= 20 * 6
    assert r["block_verdicts_incl_drain"] >= r["block_verdicts"] and r["first_verdict_min"] is not None
    one = SimSpec(attacker=randomised(PUMPING_ATTACKERS["concentrated_pumper_no_verify"], 1), minutes=1, warmup_minutes=1, seed=1)
    r1 = run_sim(one)                                       # the verdicts all land in the drain
    assert r1["block_verdicts"] == 0 and r1["block_verdicts_incl_drain"] > 0 and r1["verdict_exposure_block_min"] == 0


def test_request_records_pair_across_designs():
    a = run_sim(SimSpec(**dict(_graded_counter_spec(0.7, minutes=10).__dict__, record_requests=True)))
    b = run_sim(SimSpec(**dict(_graded_counter_spec(0.7, minutes=10).__dict__, record_requests=True,
                               features=frozenset({"attestation", "session"}))))
    assert a["requests"]["n"] == b["requests"]["n"] == a["friction"]["users"]
    assert len(unbits(a["requests"]["completed"])) == a["friction"]["completed"]
    assert unbits(a["requests"]["hit"]) and not unbits(b["requests"]["hit"])


def test_returning_population_is_stable_and_known_good():
    r = run_sim(_spec("datacenter_rotation"))
    ret = r["friction"]["returning"]
    assert ret["users"] > 0 and ret["known_good"] == ret["dispatched"]


def test_heterogeneous_population_options_run_and_conserve():
    legit = LegitSpec(blocks=50, block_conversion_sd=0.15, bad_route_fraction=0.2, resend_prob=0.5, bursts=((2, 4, 3.0),))
    r = run_sim(SimSpec(attacker=ATTACKERS["naive_single_client"], legit=legit, legit_only=True, minutes=8, warmup_minutes=0, seed=2))
    assert r["reactions"].get("resend", 0) > 0 and r["friction"]["refused_by"].get("undelivered", 0) > 0
    base = run_sim(SimSpec(attacker=ATTACKERS["naive_single_client"], legit=LegitSpec(blocks=50), legit_only=True, minutes=8, warmup_minutes=0, seed=2))
    assert r["friction"]["users"] > base["friction"]["users"]          # the burst


def test_threshold_aware_carrier_evades_by_verifying_near_the_zero_drift_share():
    """A white-box carrier that replays its pending outcomes in the deployed order (entries at their
    time, failures at the worker tick after the resolution timeout) never draws a verdict, at the
    price of entering close to the zero-drift share of codes (42 %) when it times entries late."""
    a = replace(PUMPING_ATTACKERS["concentrated_pumper_no_verify"], verify_policy="threshold_aware", verify_delay_s=100.0, rate_per_min=30)
    r = run_sim(SimSpec(attacker=a, minutes=12, warmup_minutes=1, seed=3))
    leaked, verified = r["attack"]["leaked_total"], r["attacker_verifications"]
    assert r["block_verdicts_incl_drain"] == 0 and 0.4 < verified / leaked < 0.6


def test_containment_needs_a_sustained_quiet_period():
    from otp_guard.evaluation.metrics import containment
    rate = [30] * 10
    assert containment([30] * 9 + [0], rate, min_sustain=1) == 9
    assert containment([30] * 9 + [0], rate, min_sustain=5) is None
    assert containment([30] * 4 + [0] * 6, rate, min_sustain=5) == 4
