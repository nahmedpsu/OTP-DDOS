"""Invariants of the simulator that the second-round review found violated: the offered workload
is identical across designs (M1), measurement cohorts reconcile (M2, M3), the clock advances by the
nominal duration whatever the gate does (M4), the run drains to its horizon (M5), legitimate blocks
are distinct (M19), trust-building phases are accounted separately (M22) and verdicts are counted
as events (M9)."""
from dataclasses import replace

from otp_guard.config import ALL_FEATURES, V1_FEATURES
from otp_guard.evaluation.runner import ATTACKERS, ADAPTIVE_ATTACKERS, randomised
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
    assert r["pending_at_end"] == {"events": 0, "timeouts": 0}
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
    assert r["legit_hit_by_verdict"] == r["legit_hit_stage1"] + r["legit_hit_stage2"]
    assert r["verdict_exposure_block_min"] > 0 and r["legit_hit_lost"] <= r["legit_hit_by_verdict"]


def test_attack_can_stop_early_for_recovery_studies():
    a = replace(randomised(ADAPTIVE_ATTACKERS["block_poisoner"], 0), active_minutes=3)
    r = run_sim(SimSpec(attacker=a, legit=LegitSpec(blocks=20), minutes=8, warmup_minutes=1, seed=0))
    assert sum(r["attack"]["leaked_per_min"][3:]) == 0 and len(r["legit_hit_per_min"]) == 8
