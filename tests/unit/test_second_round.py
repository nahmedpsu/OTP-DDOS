"""Regression tests for the second-round review's implementation counterexamples: a sender callback
that runs before the OTP state exists (M6), repeated and conflicting receipts (M7, M24), concurrent
callbacks and block events (M8), verdict events versus affected blocks (M9), and the circuit-breaker
ablation that kept the hard ceiling (M27). Every test runs on the memory store and on fakeredis."""
import threading

from otp_guard.config import ALL_FEATURES
from otp_guard.providers.senders import RoutingSender
from otp_guard.testing import Harness


def _open(h):
    h.lift_source_caps(); h.cfg.asn_limit_default = 10**9; h.cfg.ip_limit = (10**9, 60)
    h.svc.sender.instant_receipts = False
    return h


def _send(h, i, block="96650123"):
    return h.send(h.web_request(session=h.session(age_hours=3)[0], ip=f"198.70.{i // 250}.{i % 250 + 1}",
                                mobile=f"{block}{i:04d}"))


def _entry(h, log_id):
    return h.p.store.get(f"otp:code:{log_id}")


# ---------------- M6: durable state before the sender can call back ----------------

def test_synchronous_sender_callback_lands_on_registered_state(h):
    """The default scheduler sends a zero-delay message inline, so on_result runs inside enqueue().
    The receipt it posts must find the OTP entry: previously it was discarded and the send resolved
    as undelivered 61 s later."""
    _open(h)
    seen = []
    sender = RoutingSender({"PROVIDER_A": lambda mobile, text, log_id: {"sid": "SM1"}},
                           on_result=lambda log_id, ch, ok, d: seen.append(h.p.feedback.on_delivery(log_id, ok)))
    h.svc.sender = sender
    r = h.send(h.web_request(session=h.session(age_hours=3)[0]))
    assert r.channel == "sms" and seen == ["delivered"]
    assert _entry(h, r.log_id)["delivery"] == "delivered"
    h.clock.advance(h.cfg.receipt_grace_s + 1); h.p.feedback.run_due_timeouts()
    assert h.p.rep.get("num:966501234567").undelivered == 0


def test_synchronous_provider_failure_is_classified(h):
    _open(h)
    def boom(mobile, text, log_id):
        raise RuntimeError("provider down")
    h.svc.sender = RoutingSender({"PROVIDER_A": boom}, on_result=lambda log_id, ch, ok, d: h.p.feedback.on_delivery(log_id, ok))
    r = h.send(h.web_request(session=h.session(age_hours=3)[0]))
    assert _entry(h, r.log_id)["delivery"] == "failed" and _entry(h, r.log_id)["resolution"] == "undelivered"
    assert h.p.rep.get("num:966501234567").undelivered == 1


# ---------------- M7 / M24: the receipt state machine ----------------

def test_repeated_positive_receipt_does_not_move_the_delivery_clock(h):
    _open(h)
    r = _send(h, 1)
    assert h.p.feedback.on_delivery(r.log_id, True) == "delivered"
    t0 = _entry(h, r.log_id)["delivered_at"]
    h.clock.advance(30)
    assert h.p.feedback.on_delivery(r.log_id, True) == "duplicate"
    assert _entry(h, r.log_id)["delivered_at"] == t0
    # the resolution deadline is the first receipt's, not the repeated one's
    h.clock.advance(h.cfg.resolution_timeout_s - 30 + 1); h.p.feedback.run_due_timeouts()
    assert h.p.rep.get("num:" + _entry_mobile(h, r.log_id)).failed == 1


def _entry_mobile(h, log_id):
    return h.p.sms_history[log_id]["phone_number"]


def test_negative_receipt_after_delivery_is_a_counted_conflict(h):
    _open(h)
    r = _send(h, 2)
    h.p.feedback.on_delivery(r.log_id, True)
    assert h.p.feedback.on_delivery(r.log_id, False) == "conflict"
    e = _entry(h, r.log_id)
    assert e["delivery"] == "delivered" and e["conflicts"] == 1 and e["resolution"] is None
    assert h.p.feedback.verify("s", r.log_id, h.p.feedback.code_for(r.log_id))     # the person can still verify


def test_late_positive_receipt_reopens_an_undelivered_send(h):
    """No receipt inside the grace period: undelivered. The receipt then arrives late: the send is
    reopened, the undelivered count reversed, and the resolution clock runs from the receipt."""
    _open(h)
    r = _send(h, 3)
    mobile = _entry_mobile(h, r.log_id)
    h.clock.advance(h.cfg.receipt_grace_s + 1); h.p.feedback.run_due_timeouts()
    assert h.p.rep.get("num:" + mobile).undelivered == 1
    assert h.p.feedback.on_delivery(r.log_id, True) == "reopened"
    assert h.p.rep.get("num:" + mobile).undelivered == 0
    h.clock.advance(h.cfg.resolution_timeout_s + 1); h.p.feedback.run_due_timeouts()
    rep = h.p.rep.get("num:" + mobile)
    assert rep.failed == 1 and rep.undelivered == 0


def test_positive_receipt_corrects_an_earlier_failed_one(h):
    _open(h)
    r = _send(h, 4)
    assert h.p.feedback.on_delivery(r.log_id, False) == "failed"
    assert h.p.feedback.on_delivery(r.log_id, False) == "duplicate"
    assert h.p.feedback.on_delivery(r.log_id, True) == "reopened"
    assert _entry(h, r.log_id)["delivery"] == "delivered" and h.p.rep.get("num:" + _entry_mobile(h, r.log_id)).undelivered == 0


def test_receipt_after_the_code_expired_or_was_used_is_ignored(h):
    _open(h)
    r = _send(h, 5)
    h.p.feedback.on_delivery(r.log_id, True)
    assert h.p.feedback.verify("s", r.log_id, h.p.feedback.code_for(r.log_id))
    assert h.p.feedback.on_delivery(r.log_id, True) == "ignored"
    r2 = _send(h, 6)
    h.clock.advance(h.cfg.otp_ttl + 1)
    assert h.p.feedback.on_delivery(r2.log_id, True) == "expired"


def test_late_verification_after_failed_is_reclassified_but_a_verdict_stands(h):
    """A send resolved 'failed' fed the block test; the person verifies late. The counts move from
    failed to verified and the block statistic gets the failure increment back, but a verdict the
    failure already caused is not revoked."""
    _open(h)
    h.cfg.block_action = "deny"
    rs = [_send(h, i, block="96650777") for i in range(5)]
    for r in rs:
        h.p.feedback.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1); h.p.feedback.run_due_timeouts()
    assert h.p.store.exists("deny:block:96650777")
    assert h.p.feedback.verify("s", rs[0].log_id, h.p.feedback.code_for(rs[0].log_id))
    rep = h.p.rep.get("block:96650777")
    assert rep.verified == 1 and rep.failed == 4
    assert h.p.store.exists("deny:block:96650777")                      # not revoked
    assert len(h.p.feedback.verdict_events()) == 1


# ---------------- M8: concurrent callbacks ----------------

def test_concurrent_verifications_of_one_message_count_once(h):
    _open(h)
    r = _send(h, 7)
    mobile = _entry_mobile(h, r.log_id)
    h.p.feedback.on_delivery(r.log_id, True)
    barrier = threading.Barrier(8)
    def worker():
        barrier.wait()
        h.p.feedback.on_verified(r.log_id)
    ts = [threading.Thread(target=worker) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert h.p.rep.get("num:" + mobile).verified == 1


def test_concurrent_block_events_are_all_counted_and_cross_once(h):
    """Eight workers each resolve one failed send on the same block at the same moment: the test
    sees eight failures and issues exactly one verdict."""
    _open(h)
    h.cfg.block_action = "deny"
    barrier = threading.Barrier(8)
    def worker():
        barrier.wait()
        h.p.feedback._block_event("block:96650555", verified=False)
    ts = [threading.Thread(target=worker) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    st = h.p.store.get("blocktest:block:96650555")
    assert st["verdicts"] == 1 and st["f"] == 3                          # 5 crossed and reset, 3 counted since
    assert len(h.p.feedback.verdict_events()) == 1


def test_concurrent_duplicate_receipts_apply_once(h):
    _open(h)
    r = _send(h, 8)
    barrier = threading.Barrier(6)
    outcomes = []
    def worker():
        barrier.wait()
        outcomes.append(h.p.feedback.on_delivery(r.log_id, True))
    ts = [threading.Thread(target=worker) for _ in range(6)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert sorted(outcomes) == ["delivered"] + ["duplicate"] * 5


def test_store_update_is_a_serialised_read_modify_write(h):
    store = h.p.store
    barrier = threading.Barrier(16)
    def worker():
        barrier.wait()
        for _ in range(25):
            store.update("k", lambda cur: {"n": (cur or {"n": 0})["n"] + 1})
    ts = [threading.Thread(target=worker) for _ in range(16)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert store.get("k")["n"] == 400


# ---------------- M9: verdict events, not affected blocks ----------------

def test_verdict_log_records_every_event_with_its_stage(h):
    _open(h)
    for i in range(10):
        h.p.feedback._block_event("block:96650321", verified=False)
    ev = h.p.feedback.verdict_events()
    assert [e["stage"] for e in ev] == [1, 2] and {e["block"] for e in ev} == {"block:96650321"}
    assert h.p.feedback.block_verdict("block:96650321")["stage"] == 2


# ---------------- M27: the ablation flag must remove the whole layer ----------------

def test_circuit_breaker_off_removes_the_hard_ceiling_too(h):
    """Without the layer the hourly counters are still kept (dashboards) but nothing is refused on
    them; with it back on, the sends made meanwhile count against the ceiling."""
    _open(h)
    h.cfg.global_sms_per_hour = 2
    h.cfg.features = frozenset(ALL_FEATURES - {"circuit_breaker"})
    sent = [_send(h, (i * 7919) % 10000, block="96650900") for i in range(5)]
    assert sum(r.channel == "sms" for r in sent) == 5
    assert h.p.store.get(f"global:sms:count:{h.p.current_hour()}") == 5
    h.cfg.features = ALL_FEATURES
    r = _send(h, 4242, block="96650901")
    assert r.channel != "sms" and "budget_exhausted" in r.signals


# ---------------- M11: the baseline job's cold start; M13: the graded counter ----------------

def test_baseline_job_cold_start_uses_only_recorded_hours(h):
    """One recorded clean hour at 20 requests/min must read as 20/min, not 20/24; with no closed hour
    the job leaves the static cap alone."""
    from otp_guard.baseline import BaselineJob
    job = BaselineJob(h.p)
    key = "App/RegisterOTP|web|966"
    h.p.store.sadd("vol:keys", key)
    assert job.expected(key, h.clock.now()) == (None, None)
    hour = int(h.clock.now() // 3600)
    h.p.store.set(f"volh:{key}:{hour - 1}", 1200, 86400)
    med, mad = job.expected(key, h.clock.now())
    assert abs(med - 20.0) < 1e-9 and abs(mad - 5.0) < 1e-9


def test_graded_block_counter_challenges_then_downgrades_first_time_clients(h):
    _open(h)
    h.cfg.features = frozenset({"attestation", "session", "block_count_limit"})
    h.cfg.block_count_limit, h.cfg.block_count_action = (3, 86400), "graded"
    outcomes = [_send(h, (i * 7919) % 10000, block="96650808") for i in range(8)]
    tiers = [(r.channel, r.tier, r.rejected_at) for r in outcomes]
    assert all(c == "sms" for c, _, _ in tiers[:3])
    assert all(rj == "step7" and t == "challenge" for _, t, rj in tiers[3:6])       # requests 4..6: challenge
    assert all(t == "downgrade" and c != "sms" for c, t, _ in tiers[6:])             # beyond twice the limit: off SMS
