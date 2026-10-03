"""Regression tests for the sixth-round review (2.8.2).

M4   the outage detector's distinct-block set keeps a block's newest failure time under replay: a
     replayed older failure on the same block must not erase the recency of a newer one.
M5   block-test events are applied at their transition's time, with a defined interaction between old
     and new events: a crossing caused by a replayed event issues its verdict at the event's time (and
     escalates against the verdict active at that time), and an event dated before the last crossing
     belongs to a concluded test and is recorded but not counted.
Every test runs on the memory store and on fakeredis; tests/integration/test_real_redis.py repeats
the two principal cases across two instances on a real Redis. The defect tests
(test_replayed_older_failure_keeps_the_block_newest_time, test_replayed_crossing_is_dated_at_its_transition,
test_replayed_crossing_escalates_against_the_verdict_active_at_its_time,
test_event_dated_before_the_last_crossing_is_not_counted_in_the_next_test) fail on 2.8.1; the others
guard behaviour that must not change (newer failures still raise the block's time, live events are
unchanged) and the reading of documents written by 2.8.1."""
import pytest

from test_fifth_round import _crash_after_outage_record
from test_fourth_round import Crash, _crash_before_block_effect, _open, _req


def _live(h):
    """Block tests on (the default), no instant receipts, source caps lifted."""
    h.lift_source_caps(); h.cfg.asn_limit_default = 10**9; h.cfg.ip_limit = (10**9, 60)
    h.svc.sender.instant_receipts = False
    return h


def _fail(h, i, block, **kw):
    """One send on the block that resolves as failed: delivered, no code within the resolution timeout."""
    fb = h.p.feedback
    r = h.send(_req(h, i, block=block, **kw))
    assert r.rejected_at is None and r.channel == "sms"
    fb.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1)
    fb.run_due_timeouts()
    return r


def _record_failure_without_applying(h, i, block, **kw):
    """A failure whose transition is recorded but whose process dies before any effect is applied.
    Returns (send, time of the transition)."""
    fb = h.p.feedback
    r = h.send(_req(h, i, block=block, **kw))
    assert r.rejected_at is None and r.channel == "sms"
    fb.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1)
    _crash_before_block_effect(fb)
    with pytest.raises(Crash):
        fb.run_due_timeouts()
    assert h.p.store.get(f"otp:code:{r.log_id}")["pending"]
    return r, h.clock.now()


# ---------------- M4: block recency in the outage detector ----------------

def test_replayed_older_failure_keeps_the_block_newest_time(h):
    """The reviewer's case: a negative receipt at t = 0 is recorded in the outage detector and the
    process dies before its batch clears; at 900 another negative receipt on the same block records a
    recent failure; recovery at 900 replays the old batch. The block's score must stay 900, so at 1801
    the 1800-s distinct-block window still holds the block (2.8.1 moved it back to 0 and lost it)."""
    _open(h)
    fb = h.p.feedback
    block = "96650811"
    r1 = h.send(_req(h, 1, block=block))
    _crash_after_outage_record(fb)
    with pytest.raises(Crash):
        fb.on_delivery(r1.log_id, False)
    t0 = h.clock.now()
    h.clock.advance(900)
    r2 = h.send(_req(h, 2, block=block))
    assert fb.on_delivery(r2.log_id, False) == "failed"
    rec = h.p.sms_history.get(r2.log_id)
    key = f"outage:blocks:{fb._carrier(rec)}"
    member = rec["phone_number"][:h.cfg.destination_block_digits]
    assert h.p.store.zscore(key, member) == t0 + 900
    assert fb.recover() >= 1                                              # replays the batch from t0
    assert not (h.p.store.get(f"otp:code:{r1.log_id}") or {}).get("pending")
    assert h.p.store.zscore(key, member) == t0 + 900
    h.clock.advance(901)                                                  # t0 + 1801
    now = h.clock.now()
    assert h.p.store.zcount_many([key], now - h.cfg.outage_kg_window_s, now) == [1]


def test_newer_failure_after_a_replayed_old_one_raises_the_block_time(h):
    """The other order: the old failure is replayed first, then a newer one arrives; the score rises."""
    _open(h)
    fb = h.p.feedback
    block = "96650812"
    r1 = h.send(_req(h, 1, block=block))
    _crash_after_outage_record(fb)
    with pytest.raises(Crash):
        fb.on_delivery(r1.log_id, False)
    t0 = h.clock.now()
    rec = h.p.sms_history.get(r1.log_id)
    key = f"outage:blocks:{fb._carrier(rec)}"
    member = rec["phone_number"][:h.cfg.destination_block_digits]
    h.clock.advance(fb.RECOVER_AFTER_S + 1)
    fb.recover()
    assert h.p.store.zscore(key, member) == t0
    h.clock.advance(500)
    r2 = h.send(_req(h, 2, block=block))
    fb.on_delivery(r2.log_id, False)
    assert h.p.store.zscore(key, member) == h.clock.now()


# ---------------- M5: block-test events at their transition's time ----------------

def test_replayed_crossing_is_dated_at_its_transition(h):
    """The reviewer's case: four failures are counted; a fifth is recorded and its process dies before
    applying it; 600 s later the sweep replays it and the test crosses. The verdict must be dated at the
    transition and expire block_verdict_ttl after it, not after the recovery."""
    _live(h)
    fb = h.p.feedback
    block, key = "96650821", "block:96650821"
    for i in range(4):
        _fail(h, i, block)
    assert fb.block_verdict(key) is None
    r, t_fail = _record_failure_without_applying(h, 4, block)
    h.clock.advance(600)
    assert fb.recover() >= 1
    v = fb.block_verdict(key)
    assert v is not None and v["stage"] == 1
    assert v["at"] == t_fail and v["until"] == t_fail + h.cfg.block_verdict_ttl
    assert [e["at"] for e in fb.verdict_events()] == [t_fail]
    assert h.p.store.get(f"blocktest:{key}")["test_since"] == t_fail


def test_replayed_crossing_escalates_against_the_verdict_active_at_its_time(h):
    """A second crossing whose event is dated before the first verdict's expiry, but processed after
    it, is stage 2 (the verdict was active at the event's time); processing time would say stage 1."""
    _live(h)
    fb = h.p.feedback
    block, key = "96650822", "block:96650822"
    for i in range(5):
        _fail(h, i, block)
    v1 = fb.block_verdict(key)
    assert v1 is not None and v1["stage"] == 1
    step = h.cfg.resolution_timeout_s + 1
    h.clock.advance(v1["until"] - h.clock.now() - 5 * step - 30)          # the fifth failure lands 30 s before expiry
    for i in range(10, 14):                                                # under the stage-1 verdict a first-time
        _fail(h, i, block, challenge_proof="challenge-ok")                 # client is sent only with a solved challenge
    r, t_fail = _record_failure_without_applying(h, 14, block, challenge_proof="challenge-ok")
    assert t_fail < v1["until"]
    h.clock.advance(120)                                                  # past the first verdict's expiry
    assert h.clock.now() > v1["until"]
    assert fb.recover() >= 1
    v2 = fb.block_verdict(key)
    assert v2 is not None and v2["stage"] == 2
    assert v2["at"] == t_fail and v2["until"] == t_fail + h.cfg.block_verdict_ttl


def test_event_dated_before_the_last_crossing_is_not_counted_in_the_next_test(h):
    """Reordered arrival: a failure recorded at t_a is applied only after a later failure crossed the
    threshold at t_b > t_a. It belongs to the concluded test: recorded, not counted, and a further
    replay of it is ignored too. 2.8.1 counted it toward the new test."""
    _live(h)
    fb = h.p.feedback
    block, key = "96650823", "block:96650823"
    for i in range(4):
        _fail(h, i, block)
    r, t_a = _record_failure_without_applying(h, 4, block)
    _fail(h, 5, block)                                                     # the fifth counted failure: crossing at t_b
    v = fb.block_verdict(key)
    assert v is not None and v["at"] == h.clock.now() > t_a
    assert fb.block_llr(key)[2] == (0, 0, 0)                               # the next test starts from zero
    h.clock.advance(fb.RECOVER_AFTER_S + 1)
    fb.recover()                                                           # replays the failure dated t_a
    assert not (h.p.store.get(f"otp:code:{r.log_id}") or {}).get("pending")
    assert fb.block_llr(key)[2] == (0, 0, 0)
    seen = h.p.store.get(f"blocktest:{key}")["seen"]
    ids = [i for i in seen if i.startswith(f"{r.log_id}:")]
    assert len(ids) == 1 and seen[ids[0]][1] == t_a                        # recorded with its event time
    rec = h.p.sms_history.get(r.log_id)
    fb._block_event(key, verified=False, event_id=ids[0], at=t_a)          # a second replay
    assert fb.block_llr(key)[2] == (0, 0, 0)


def test_live_events_are_unchanged(h):
    """On the live path the event's time is the clock's: five failures cross at the fifth, dated now."""
    _live(h)
    fb = h.p.feedback
    block, key = "96650824", "block:96650824"
    for i in range(5):
        _fail(h, i, block)
    v = fb.block_verdict(key)
    assert v is not None and v["at"] == h.clock.now() and v["until"] == h.clock.now() + h.cfg.block_verdict_ttl


def test_old_documents_without_event_times_are_read(h):
    """A block document written by 2.8.1 (seen: id -> recorded time, no test_since) is accepted."""
    _live(h)
    fb = h.p.feedback
    key = "block:96650825"
    st = fb._empty_block_state()
    del st["test_since"]
    st["seen"] = {"old:1": h.clock.now() - 5}
    st["f"], st["conv"] = 1, fb._increments()["fail"]
    h.p.store.set(f"blocktest:{key}", st, 86400)
    fb._block_event(key, verified=False, event_id="old:1")                 # already applied
    assert fb.block_llr(key)[2][1] == 1
    fb._block_event(key, verified=False, event_id="new:1")
    assert fb.block_llr(key)[2][1] == 2
    assert h.p.store.get(f"blocktest:{key}")["seen"]["old:1"] == [h.clock.now() - 5, h.clock.now() - 5]
