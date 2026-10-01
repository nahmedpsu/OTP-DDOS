"""Regression tests for the third-round review's implementation counterexamples: graded escalation
under concurrency (R3), the mixed-receipt race and the timeout/receipt interleaving (R7), crash
consistency of feedback effects (R8), the block counter's units (R4) and channel fallback (R1).
Every test runs on the memory store and on fakeredis."""
import threading

import pytest

from otp_guard.config import ALL_FEATURES


def _open(h):
    h.lift_source_caps(); h.cfg.asn_limit_default = 10**9; h.cfg.ip_limit = (10**9, 60)
    h.svc.sender.instant_receipts = False
    return h


def _send(h, i, block="96650123", **kw):
    return h.send(h.web_request(session=h.session(age_hours=3)[0], ip=f"198.71.{i // 250}.{i % 250 + 1}",
                                mobile=f"{block}{i:04d}", **kw))


def _rep(h, log_id):
    return h.p.rep.get("num:" + h.p.sms_history[log_id]["phone_number"])


def _entry(h, log_id):
    return h.p.store.get(f"otp:code:{log_id}")


# ---------------- R3: graded escalation is decided inside the block document ----------------

def test_concurrent_crossings_escalate_to_stage_two(h):
    _open(h)
    barrier = threading.Barrier(10)
    def worker():
        barrier.wait()
        h.p.feedback._block_event("block:96650321", verified=False)
    ts = [threading.Thread(target=worker) for _ in range(10)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert [e["stage"] for e in h.p.feedback.verdict_events()] == [1, 2]
    assert h.p.feedback.block_verdict("block:96650321")["stage"] == 2


def test_two_crossings_at_the_same_instant_are_two_events(h):
    _open(h)
    for _ in range(10):
        h.p.feedback._block_event("block:96650322", verified=False)
    ev = h.p.feedback.verdict_events()
    assert len({e["id"] for e in ev}) == 2 and [e["stage"] for e in ev] == [1, 2]


def test_a_verdict_after_expiry_starts_again_at_stage_one(h):
    _open(h)
    for _ in range(5):
        h.p.feedback._block_event("block:96650323", verified=False)
    h.clock.advance(h.cfg.block_verdict_ttl + 1)
    assert h.p.feedback.block_verdict("block:96650323") is None
    for _ in range(5):
        h.p.feedback._block_event("block:96650323", verified=False)
    assert [e["stage"] for e in h.p.feedback.verdict_events()] == [1, 1]


def test_observe_action_records_verdicts_without_enforcing(h):
    _open(h)
    h.cfg.block_action = "observe"
    for _ in range(5):
        h.p.feedback._block_event("block:96650555", verified=False)
    assert len(h.p.feedback.verdict_events()) == 1
    r = h.send(h.web_request(session=h.session(age_hours=0)[0], ip="198.72.0.1", mobile="966505550001"))
    assert r.channel == "sms" and not any(s.startswith("block_") for s in r.signals)


# ---------------- R7: compound receipt transitions ----------------

def test_negative_receipt_marks_failed_and_undelivered_in_one_transition(h):
    _open(h)
    r = _send(h, 1)
    assert h.p.feedback.on_delivery(r.log_id, False) == "failed"
    e = _entry(h, r.log_id)
    assert (e["delivery"], e["resolution"], e["timed_out"]) == ("failed", "undelivered", True)


def test_correcting_receipt_inside_the_negative_path_leaves_a_consistent_entry(h):
    """The reviewer's interleaving: the positive receipt lands while the negative path is applying
    its effects. The entry must end delivered and unresolved, with the undelivered count reversed."""
    _open(h)
    r = _send(h, 2)
    fb = h.p.feedback
    orig = fb._apply
    fired = []
    def interleaved(log_id, rec, batch):
        if not fired:
            fired.append(1)
            fb.on_delivery(log_id, True)               # the correcting receipt arrives here
        orig(log_id, rec, batch)
    fb._apply = interleaved
    fb.on_delivery(r.log_id, False)
    fb._apply = orig
    e = _entry(h, r.log_id)
    assert (e["delivery"], e["resolution"], e["timed_out"]) == ("delivered", None, False)
    assert _rep(h, r.log_id).undelivered == 0
    h.clock.advance(h.cfg.resolution_timeout_s + 1); fb.run_due_timeouts()
    assert _rep(h, r.log_id).failed == 1                       # a delivered failure feeds the tests


def test_timeout_and_correcting_receipt_in_either_order(h):
    _open(h)
    a = _send(h, 3)
    b = _send(h, 4)
    h.clock.advance(h.cfg.receipt_grace_s + 1)
    h.p.feedback.on_delivery(a.log_id, True)                   # receipt first, then the worker
    h.p.feedback.run_due_timeouts()
    assert _entry(h, a.log_id)["resolution"] is None and _rep(h, a.log_id).undelivered == 0
    h.p.feedback.on_delivery(b.log_id, True)                   # b: the worker already resolved it? no: same tick
    for log_id in (a.log_id, b.log_id):
        e = _entry(h, log_id)
        assert not (e["delivery"] == "delivered" and e["resolution"] == "undelivered")
    c = _send(h, 5)
    h.clock.advance(h.cfg.receipt_grace_s + 1)
    h.p.feedback.run_due_timeouts()                            # worker first: undelivered
    assert h.p.feedback.on_delivery(c.log_id, True) == "reopened"
    assert _rep(h, c.log_id).undelivered == 0 and _entry(h, c.log_id)["resolution"] is None


def test_exhausting_attempts_after_a_timeout_does_not_count_the_failure_twice(h):
    _open(h)
    r = _send(h, 6)
    h.p.feedback.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1); h.p.feedback.run_due_timeouts()
    for _ in range(h.cfg.otp_max_attempts):
        h.p.feedback.verify("s", r.log_id, "xxxx")
    assert _rep(h, r.log_id).failed == 1 and _entry(h, r.log_id)["done"]


def test_concurrent_right_code_submissions_verify_once_and_one_caller_wins(h):
    _open(h)
    r = _send(h, 7)
    h.p.feedback.on_delivery(r.log_id, True)
    code = h.p.feedback.code_for(r.log_id)
    sid = h.p.sms_history[r.log_id]["session_id"]
    out = []
    barrier = threading.Barrier(6)
    def worker():
        barrier.wait()
        out.append(h.p.feedback.verify(sid, r.log_id, code))
    ts = [threading.Thread(target=worker) for _ in range(6)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert out.count(True) == 1 and _rep(h, r.log_id).verified == 1


# ---------------- R8: effects are exactly once across crashes and replays ----------------

class Crash(Exception):
    pass


def _crash_after(fb, n_effects):
    """Make the next _apply stop after n effects, as a process that dies mid-way would."""
    orig = fb._apply
    def crashing(log_id, rec, batch):
        fb._apply = orig
        cut = dict(batch, effects=batch["effects"][:n_effects])
        orig_clear = fb.p.store.update
        # apply the first n effects but not the clearing step
        for eff in cut["effects"]:
            one = dict(batch, effects=[eff])
            fb.p.store.update = lambda *a, **k: (None, False)
            try:
                orig(log_id, rec, one)
            finally:
                fb.p.store.update = orig_clear
        raise Crash()
    fb._apply = crashing


@pytest.mark.parametrize("n_effects", [0, 1, 2, 4])
def test_verification_effects_survive_a_crash_and_apply_once(h, n_effects):
    _open(h)
    r = _send(h, 8)
    h.p.feedback.on_delivery(r.log_id, True)
    sid = h.p.sms_history[r.log_id]["session_id"]
    _crash_after(h.p.feedback, n_effects)
    with pytest.raises(Crash):
        h.p.feedback.verify(sid, r.log_id, h.p.feedback.code_for(r.log_id))
    assert _entry(h, r.log_id)["done"] and _entry(h, r.log_id)["pending"]       # claimed, effects recorded
    h.clock.advance(h.p.feedback.RECOVER_AFTER_S + 1)
    assert h.p.feedback.recover() == 1
    rep = _rep(h, r.log_id)
    assert rep.verified == 1 and not _entry(h, r.log_id)["pending"]
    assert h.p.rep.is_trusted("num:" + h.p.sms_history[r.log_id]["phone_number"])
    h.p.feedback.recover(older_than=0)
    assert _rep(h, r.log_id).verified == 1


@pytest.mark.parametrize("n_effects", [0, 2, 3])
def test_failure_effects_survive_a_crash_and_feed_the_block_test_once(h, n_effects):
    _open(h)
    h.cfg.block_action = "deny"
    rs = [_send(h, 20 + i, block="96650444") for i in range(5)]
    for r in rs:
        h.p.feedback.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1)
    _crash_after(h.p.feedback, n_effects)
    with pytest.raises(Crash):
        h.p.feedback.run_due_timeouts()                        # the first timeout's process dies mid-way
    h.clock.advance(h.p.feedback.RECOVER_AFTER_S + 1)
    h.p.feedback.run_due_timeouts()                            # the rest, then the sweep
    rep = h.p.rep.get("block:96650444")
    assert rep.failed == 5
    assert len(h.p.feedback.verdict_events()) == 1 and h.p.feedback.block_denied("block:96650444")


def test_replaying_a_batch_changes_nothing(h):
    _open(h)
    r = _send(h, 30, block="96650445")
    h.p.feedback.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1)
    captured = []
    orig = h.p.feedback._apply
    h.p.feedback._apply = lambda log_id, rec, batch: (captured.append((log_id, rec, batch)), orig(log_id, rec, batch))[1]
    h.p.feedback.run_due_timeouts()
    h.p.feedback._apply = orig
    before = (h.p.rep.get("block:96650445"), h.p.feedback.block_llr("block:96650445"))
    for log_id, rec, batch in captured:
        orig(log_id, rec, batch)                               # a duplicate worker replays the same batch
    assert (h.p.rep.get("block:96650445"), h.p.feedback.block_llr("block:96650445")) == before


def test_crash_between_audit_and_enqueue_resolves_as_undelivered(h):
    """Step 11 is not one transaction: a send whose process dies before the sender is called leaves
    an entry that resolves as undelivered at the grace period and feeds no test."""
    _open(h)
    def dead(*a, **k):
        raise Crash()
    h.svc.sender.enqueue = dead
    with pytest.raises(Crash):
        _send(h, 40)
    log_id = int(h.p.store.get("smslog:seq"))
    h.clock.advance(h.cfg.receipt_grace_s + 1); h.p.feedback.run_due_timeouts()
    rep = _rep(h, log_id)
    assert rep.undelivered == 1 and rep.failed == 0 and _entry(h, log_id)["resolution"] == "undelivered"


# ---------------- R16: receipt-robust policy ----------------

def test_robust_receipt_policy_counts_failed_receipts_as_block_failures(h):
    _open(h)
    h.cfg.receipt_policy, h.cfg.block_action = "robust", "deny"
    for i in range(5):
        r = _send(h, 50 + i, block="96650777")
        h.p.feedback.on_delivery(r.log_id, False)
    assert h.p.feedback.block_denied("block:96650777")
    assert h.p.rep.get("block:96650777").undelivered == 5 and h.p.rep.get("block:96650777").failed == 0


def test_robust_policy_reverses_the_block_failure_when_the_receipt_is_corrected(h):
    _open(h)
    h.cfg.receipt_policy = "robust"
    r = _send(h, 60, block="96650778")
    h.p.feedback.on_delivery(r.log_id, False)
    assert h.p.feedback.block_llr("block:96650778")[2] == (0, 1, 0)
    h.p.feedback.on_delivery(r.log_id, True)
    assert h.p.feedback.block_llr("block:96650778")[2] == (0, 0, 0)


# ---------------- R4: the counter counts sends, and a retry is not charged ----------------

def _counter(h, limit, action, window=86400):
    _open(h)
    h.cfg.features = frozenset({"attestation", "session", "block_count_limit"})
    h.cfg.block_count_limit, h.cfg.block_count_action = (limit, window), action


def test_graded_counter_charges_sends_not_attempts(h):
    """The reviewer's sequence with a limit of one: request 1 sends; request 2 is challenged; its
    retry with a valid proof sends (stage 1 allows a solved challenge). Two sends, two charges."""
    _counter(h, 1, "graded")
    tok1, tok2 = h.session(age_hours=3)[0], h.session(age_hours=3)[0]
    r1 = h.send(h.web_request(session=tok1, ip="198.70.0.1", mobile="966501230001"))
    r2 = h.send(h.web_request(session=tok2, ip="198.70.0.2", mobile="966501230002"))
    assert r1.channel == "sms" and h.p.block_count("966501230001") == 1
    assert r2.rejected_at == "step7" and r2.tier == "challenge" and h.p.block_count("966501230002") == 1
    r3 = h.send(h.web_request(session=tok2, ip="198.70.0.2", mobile="966501230002", challenge_proof="challenge-ok"))
    assert r3.channel == "sms" and "block_count_stage1" in r3.signals and h.p.block_count("966501230002") == 2
    tok3 = h.session(age_hours=3)[0]
    r4 = h.send(h.web_request(session=tok3, ip="198.70.0.3", mobile="966501230003", challenge_proof="challenge-ok"))
    assert r4.channel != "sms" and "block_count_stage2" in r4.signals and h.p.block_count("966501230003") == 2


def test_refusing_counter_refuses_after_limit_sends_and_signals_it(h):
    _counter(h, 2, "refuse")
    out = [h.send(h.web_request(session=h.session(age_hours=3)[0], ip=f"198.70.1.{i + 1}", mobile=f"96650124{i:04d}")) for i in range(4)]
    assert [r.channel for r in out] == ["sms", "sms", None, None]
    assert all("block_count_refused" in r.signals and r.rejected_at == "step5" for r in out[2:])
    assert h.p.block_count("966501240000") == 2


def test_counter_slot_is_returned_when_no_sms_is_sent(h):
    _counter(h, 2, "refuse")
    h.cfg.features = h.cfg.features | {"circuit_breaker"}           # the hard ceiling belongs to this layer
    h.cfg.global_sms_per_hour = 1
    a = h.send(h.web_request(session=h.session(age_hours=3)[0], ip="198.70.2.1", mobile="966501250001"))
    b = h.send(h.web_request(session=h.session(age_hours=3)[0], ip="198.70.2.2", mobile="966501250002"))
    assert a.channel == "sms" and b.channel != "sms" and "budget_exhausted" in b.signals
    assert h.p.block_count("966501250001") == 1


def test_counter_short_window_refills(h):
    _counter(h, 1, "refuse", window=600)
    a = h.send(h.web_request(session=h.session(age_hours=3)[0], ip="198.70.3.1", mobile="966501260001"))
    b = h.send(h.web_request(session=h.session(age_hours=3)[0], ip="198.70.3.2", mobile="966501260002"))
    h.clock.advance(601)
    c = h.send(h.web_request(session=h.session(age_hours=3)[0], ip="198.70.3.3", mobile="966501260003"))
    assert (a.channel, b.channel, c.channel) == ("sms", None, "sms")


def test_concurrent_requests_cannot_overshoot_the_counter(h):
    _counter(h, 3, "refuse")
    reqs = [h.web_request(session=h.session(age_hours=3)[0], ip=f"198.70.4.{i + 1}", mobile=f"96650127{i:04d}") for i in range(16)]
    out = []
    barrier = threading.Barrier(16)
    def worker(req):
        barrier.wait()
        out.append(h.send(req))
    ts = [threading.Thread(target=worker, args=(q,)) for q in reqs]
    for t in ts: t.start()
    for t in ts: t.join()
    assert sum(r.channel == "sms" for r in out) == 3 and h.p.block_count("966501270000") == 3


# ---------------- R16: a bounded trust budget for the verified-history exemption ----------------

def test_known_good_budget_bounds_exempt_requests_per_minute(h):
    _open(h)
    h.cfg.known_good_budget_per_min = 2
    toks = []
    for i in range(4):
        tok, fp = h.session(fingerprint=f"kg-{i}", age_hours=30)
        r = h.send(h.web_request(session=tok, ip=f"198.70.5.{i + 1}", mobile=f"96650128{i:04d}"))
        h.p.feedback.verify(h.p.sms_history[r.log_id]["session_id"], r.log_id, h.p.feedback.code_for(r.log_id))
        toks.append(h.session(fingerprint=f"kg-{i}", age_hours=30)[0])
    h.clock.advance(120)
    out = [h.send(h.web_request(session=t, ip=f"198.70.6.{i + 1}", mobile=f"96650129{i:04d}")) for i, t in enumerate(toks)]
    flags = [h.p.sms_history[r.log_id]["known_good"] for r in out]
    assert flags == [True, True, False, False]
    assert all("known_good_budget_exhausted" in r.signals for r in out[2:])


# ---------------- R14: the baseline job across workers, restarts and partial hours ----------------

def _traffic_minutes(h, n, per_min=20):
    key = "App/RegisterOTP|web|966"
    for _ in range(n):
        for _ in range(per_min):
            h.p.record_volume("App/RegisterOTP", "web", "966")
        h.clock.advance(60)
    return key


def test_two_baseline_workers_neither_double_sample_nor_double_tighten(h):
    from otp_guard.baseline import BaselineJob
    h.clock.t = (int(h.clock.now() // 3600) + 1) * 3600              # start on an hour boundary
    key = _traffic_minutes(h, 1)
    a, b = BaselineJob(h.p), BaselineJob(h.p)
    a.tick(); b.tick()
    _traffic_minutes(h, 120)
    for _ in range(3):
        a.tick(); b.tick()
    hour = int(h.clock.now() // 3600)
    samples = [h.p.store.get(f"profile:{key}:{a._hour_of_week(hh * 3600)}") for hh in (hour - 2, hour - 1)]
    assert all(s is not None and len(s) == 1 for s in samples)       # one sample per hour, not two
    m0 = h.p.adaptive.multiplier("App/RegisterOTP", "web", "966")
    for _ in range(80):
        h.p.record_volume("App/RegisterOTP", "web", "966")          # a surge in the current minute
    h.clock.advance(60)
    a.tick(); b.tick()
    assert h.p.adaptive.multiplier("App/RegisterOTP", "web", "966") == max(h.p.adaptive.floor, m0 - 0.5)   # one step down


def test_partial_first_hour_is_not_a_sample_and_restart_keeps_the_last_hour(h):
    from otp_guard.baseline import BaselineJob
    h.clock.t = (int(h.clock.now() // 3600) + 1) * 3600 + 1800      # traffic starts half-way through an hour
    key = _traffic_minutes(h, 1)
    job = BaselineJob(h.p)
    job.tick()
    _traffic_minutes(h, 45)                                         # into the next hour
    job = BaselineJob(h.p)                                          # the worker restarts
    job.tick()
    first_hour = int((h.clock.now() - 46 * 60) // 3600)
    assert not h.p.store.exists(f"volh:{key}:{first_hour}")         # the partial hour is not a sample
    _traffic_minutes(h, 60)
    job.tick()
    assert h.p.store.exists(f"volh:{key}:{first_hour + 1}")          # the first full hour is, despite the restart
    med, _ = job.expected(key, h.clock.now())
    assert abs(med - 20.0) < 1e-9


def test_weekly_profile_is_learned_in_the_simulation():
    from otp_guard.evaluation.runner import ATTACKERS, randomised
    from otp_guard.evaluation.sim import SimSpec, Simulation
    spec = SimSpec(attacker=randomised(ATTACKERS["residential_captcha_farm"], 0), caps_lifted=False, baseline="learned",
                   profile_weeks=2, minutes=5, warmup_minutes=2, seed=0)
    sim = Simulation(spec)
    sim.run()
    key = "App/RegisterOTP|web|966"
    job = sim.baseline_jobs[0]
    samples = sim.h.p.store.get(f"profile:{key}:{job._hour_of_week(sim.t_attack_start)}")
    assert samples is not None and len(samples) == 2 and all(15 < x < 25 for x in samples)
