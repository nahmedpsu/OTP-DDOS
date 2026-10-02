import numpy as np

from otp_guard.evaluation.metrics import containment, AttackMetrics, CostModel
from otp_guard.evaluation.stats import mean_ci, ks_2samp
from otp_guard.evaluation.sim import SimSpec, run_sim
from otp_guard.evaluation.runner import ATTACKERS, randomised, summarise, economics
from otp_guard.config import V1_FEATURES


def test_containment_definition():
    rate = [30] * 10
    assert containment([30, 30, 30, 1, 0, 0, 0, 0, 0, 0], rate) == 3
    assert containment([30, 30, 30, 0, 0, 5, 0, 0, 0, 0], rate) == 6          # a later spike resets it
    assert containment([30] * 10, rate) is None
    assert containment([0] * 10, rate) == 0
    m = AttackMetrics.build([30, 30, 0, 0], [30, 30, 30, 30], hlr_calls=60, recaptcha_calls=120, cost_model=CostModel(0.1, 0.01, 0.001), stopped_by={})
    assert m.time_to_containment_min == 2 and m.leaked_before_containment == 60 and m.steady_state_leak_per_min == 0
    assert abs(m.cost_usd - (60 * 0.1 + 60 * 0.01 + 120 * 0.001)) < 1e-9


def test_mean_ci_and_ks():
    m, lo, hi, n = mean_ci([1, 2, 3, 4, 5])
    assert m == 3 and lo < 3 < hi and n == 5
    rng = np.random.default_rng(0)
    same = ks_2samp(rng.normal(size=300), rng.normal(size=300))
    diff = ks_2samp(rng.normal(size=300), rng.normal(0.8, size=300))
    assert same[1] > 0.01 and diff[1] < 1e-6


def test_simulation_runs_and_is_deterministic():
    spec = SimSpec(attacker=randomised(ATTACKERS["datacenter_rotation"], 3), minutes=4, warmup_minutes=1, seed=3)
    a, b = run_sim(spec), run_sim(spec)
    assert a["attack"] == b["attack"] and a["friction"] == b["friction"]
    assert a["attack"]["leaked_total"] == 0 and a["friction"]["users"] > 0


def test_v1_leaks_more_than_v2_for_datacenter_attacker():
    spec2 = SimSpec(attacker=randomised(ATTACKERS["datacenter_rotation"], 5), minutes=4, warmup_minutes=1, seed=5)
    spec1 = SimSpec(attacker=spec2.attacker, minutes=4, warmup_minutes=1, seed=5, features=V1_FEATURES)
    r1, r2 = run_sim(spec1), run_sim(spec2)
    assert r1["attack"]["leaked_total"] > 0 and r2["attack"]["leaked_total"] == 0
    s1, s2 = summarise([r1]), summarise([r2])
    rows = economics(s1, s2, "datacenter_rotation", earns_revenue=False)
    assert [r["design"] for r in rows] == ["v1", "v2"] and all(r["breakeven_share"] is None for r in rows)
    assert all(v < 0 for v in rows[0]["profit_surface_usd"].values())          # a flooder only pays
    rows = economics(s1, s2, "datacenter_rotation", earns_revenue=True)
    assert rows[0]["breakeven_share"] is not None and rows[1]["breakeven_share"] is None   # v2 leaked nothing
    assert rows[0]["attacker_cost_usd"] > 0 and rows[0]["tokens"] >= rows[0]["requests"]


def test_every_enforcing_poisoner_variant_has_a_matched_observe_reference():
    from otp_guard.evaluation import runner as R_
    for vname, (cfg, active, minutes, wa) in R_.POISONER_VARIANTS.items():
        ref = R_.poisoner_reference(vname)
        if cfg.get("block_action") == "observe":
            assert ref is None
            continue
        assert ref is not None, vname
        rcfg, ractive, rminutes, rwa = R_.POISONER_VARIANTS[ref]
        assert rcfg == {"block_action": "observe"} and (ractive, rminutes, rwa) == (active, minutes, wa)


def test_checkpoint_rows_from_other_code_are_rejected(tmp_path):
    import json
    from otp_guard.evaluation.jobs import JobRunner, spec_hash
    from otp_guard.evaluation.runner import ATTACKERS
    from otp_guard.evaluation.sim import SimSpec
    spec = SimSpec(attacker=ATTACKERS["naive_single_client"], minutes=1, warmup_minutes=0, seed=1)
    ck = tmp_path / "ck.jsonl"
    runner = JobRunner(procs=1, checkpoint=ck)
    ck.write_text(json.dumps({"spec_hash": spec_hash(spec), "seed": 1, "code_hash": "0" * 64, "result": {"stale": True}}) + "\n"
                  + json.dumps({"spec_hash": spec_hash(spec), "seed": 1, "code_hash": runner.code, "result": {"fresh": True}}) + "\n")
    runner = JobRunner(procs=1, checkpoint=ck)
    assert runner.counts["stale_rejected"] == 1
    assert runner.run([spec]) == [{"fresh": True}]
    assert runner.meta()["invocation"] == "resumed"


def test_variance_components_separate_configurations_from_noise():
    import numpy as np
    from otp_guard.evaluation.stats import variance_components
    rng = np.random.default_rng(0)
    groups = [list(c + rng.normal(0, 1, 5)) for c in rng.normal(0, 10, 40)]
    vc = variance_components(groups)
    assert vc["between_share"] > 0.9 and 0.5 < vc["within_var"] < 2.0
    flat = [list(rng.normal(0, 1, 5)) for _ in range(40)]
    assert variance_components(flat)["between_share"] < 0.2
