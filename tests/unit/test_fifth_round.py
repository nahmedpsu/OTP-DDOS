"""Regression tests for the fifth-round review (2.8.1).

M8   a replayed outage observation keeps its own time, so recovery cannot move an old delivery
     failure into the current outage window; a replayed reputation increment lands in its own hour.
M9   the cases disclosed as open in 2.8.0, now closed or pinned down:
     - a late reversal recovered after the failure's old identifier lifetime still finds the failure;
     - a timeout rescheduled by a correcting receipt during the timeout worker's transition survives;
     - a request that Step 11 turns into a challenge does not use the source's SMS caps;
     - a released claim whose window has expired does not come back as a negative count;
     - the app path at stage 1 (no challenge surface: non-SMS channels), serially and at Step 11;
     - Step 11's documented crash semantics (it is not one transaction).
Every test runs on the memory store and on fakeredis; tests/integration/test_real_redis.py repeats
the replay and counter cases on a real Redis, and tests/integration/test_api.py the HTTP stage-1 path."""
import pytest

from test_fourth_round import Crash, _concurrent, _counter, _open, _req


def _crash_after_outage_record(fb):
    """The reviewer's injection: the next _outage_record is applied, then the process dies before the
    batch is cleared."""
    orig = fb._outage_record

    def dying(*a, **k):
        fb._outage_record = orig
        orig(*a, **k)
        raise Crash()
    fb._outage_record = dying


def _window_count(h, key, window):
    now = h.clock.now()
    return h.p.store.zcount_many([key], now - window, now)[0]


# ---------------- M8: event time on replay ----------------

def test_replayed_outage_event_keeps_its_time(h):
    """A negative receipt updates the outage detector, the process dies before clearing its batch,
    601 s pass (outside the 600-s delivery window) and recovery runs inside the replay horizon. The
    old observation must stay outside the current window (the reviewer saw 0 -> 1)."""
    _open(h)
    fb = h.p.feedback
    r = h.send(_req(h, 1, block="96650790"))
    _crash_after_outage_record(fb)
    with pytest.raises(Crash):
        fb.on_delivery(r.log_id, False)
    assert h.p.store.get(f"otp:code:{r.log_id}")["pending"]
    carrier = fb._carrier(h.p.sms_history.get(r.log_id))
    key = f"outage:undelivered:{carrier}"
    h.clock.advance(h.cfg.outage_window_s + 1)
    assert _window_count(h, key, h.cfg.outage_window_s) == 0
    assert fb.recover() >= 1
    assert not (h.p.store.get(f"otp:code:{r.log_id}") or {}).get("pending")
    assert _window_count(h, key, h.cfg.outage_window_s) == 0


def test_replayed_outage_event_inside_its_window_still_counts(h):
    """The same replay before the window has passed counts the observation once, at its own time."""
    _open(h)
    fb = h.p.feedback
    r = h.send(_req(h, 2, block="96650791"))
    _crash_after_outage_record(fb)
    with pytest.raises(Crash):
        fb.on_delivery(r.log_id, False)
    t_event = h.clock.now()
    carrier = fb._carrier(h.p.sms_history.get(r.log_id))
    key = f"outage:undelivered:{carrier}"
    h.clock.advance(fb.RECOVER_AFTER_S + 1)
    fb.recover()
    assert _window_count(h, key, h.cfg.outage_window_s) == 1
    assert h.p.store.zrangebyscore(key, t_event - 1e-6, t_event + 1e-6) == [str(r.log_id)]   # at its own time


def test_replayed_reputation_effect_lands_in_its_own_hour(h):
    """A reputation increment replayed after an hour boundary is counted in the hour of the event."""
    _open(h)
    fb = h.p.feedback
    h.clock.advance(3600 - (h.clock.now() % 3600) - 120)          # two minutes before an hour boundary
    r = h.send(_req(h, 3, block="96650792"))
    orig = fb._apply

    def dying(log_id, rec, batch):
        fb._apply = orig
        raise Crash()
    fb._apply = dying
    with pytest.raises(Crash):
        fb.on_delivery(r.log_id, False)
    hour_event = int(h.clock.now() // 3600)
    h.clock.advance(600)                                            # recovery in the next hour, inside the horizon
    fb.recover()
    assert int(h.clock.now() // 3600) == hour_event + 1
    key = "block:96650792"
    assert h.p.store.hgetall(f"rep:{key}:{hour_event}").get("undelivered") == 1
    assert not h.p.store.hgetall(f"rep:{key}:{hour_event + 1}").get("undelivered")


# ---------------- M9 (1): a late reversal recovered after the old identifier lifetime ----------------

def test_late_reversal_recovered_after_thirteen_minutes_still_finds_the_failure(h):
    """The failure is applied; the person enters the code about eight minutes later, but that
    transition's process dies before its block effect; the first sweep reaches it 14 minutes later,
    inside the reversal's own horizon. In 2.8.0 the failure's identifier was gone by then and the
    failure stayed counted; identifiers are now kept for the horizon plus the code lifetime."""
    _open(h)
    fb = h.p.feedback
    r = h.send(_req(h, 4, block="96650793"))
    fb.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1)
    fb.run_due_timeouts()                                           # resolved failed, block failure applied
    assert fb.block_llr("block:96650793")[2][:2] == (0, 1)
    h.clock.advance(h.cfg.otp_ttl - h.cfg.resolution_timeout_s - 10)   # the latest valid verification
    orig = fb._apply

    def dying(log_id, rec, batch):
        fb._apply = orig
        raise Crash()
    fb._apply = dying
    sid = h.p.sms_history[r.log_id]["session_id"]
    with pytest.raises(Crash):
        fb.verify(sid, r.log_id, fb.code_for(r.log_id))
    h.clock.advance(14 * 60)
    assert h.clock.now() - h.p.store.get(f"otp:code:{r.log_id}")["pending"][0]["at"] < fb.replay_horizon_s()
    fb.recover()
    assert fb.block_llr("block:96650793")[2][:2] == (1, 0)


# ---------------- M9 (2): the timeout worker's read/act separation ----------------

def test_timeout_rescheduled_during_the_timeout_transition_survives(h):
    """The worker resolves a send as undelivered (no receipt inside the grace period); a correcting
    receipt then reopens it and reschedules the resolution timeout under the same member before the
    worker removes the member. The rescheduled timeout must stay, and the send must resolve later."""
    _open(h)
    fb = h.p.feedback
    r = h.send(_req(h, 5, block="96650794"))
    h.clock.advance(h.cfg.receipt_grace_s + 1)
    orig = fb._transition
    fired = []

    def interleaved(log_id, decide):
        out = orig(log_id, decide)
        if not fired:
            fired.append(True)
            fb._transition = orig
            assert fb.on_delivery(log_id, True) == "reopened"    # between the transition and the removal
        return out
    fb._transition = interleaved
    fb.run_due_timeouts()
    fb._transition = orig
    assert str(r.log_id) in h.p.store.zrangebyscore(fb.TIMEOUTS, float("-inf"), float("inf"))
    h.clock.advance(min(h.cfg.resolution_timeout_s, h.cfg.otp_ttl) + 1)
    fb.run_due_timeouts()
    entry = h.p.store.get(f"otp:code:{r.log_id}")
    assert entry["resolution"] == "failed"
    assert fb.block_llr("block:96650794")[2][1] == 1


# ---------------- M9 (3): Step 11 challenges and the source caps ----------------

def test_step11_challenge_does_not_use_the_source_caps(h):
    """Eight concurrent requests at the 4-per-10-minute counter: four send, four are challenged at
    Step 11. Only the four sends count against the source's per-minute web cap, as for a request
    challenged at Step 7 (which never reaches Step 9)."""
    _counter(h)
    sl = h.cfg.source_limits["App/RegisterOTP"]
    sl["per_minute_web"], sl["per_hour_web"] = 50, 500
    resps = _concurrent(h, [_req(h, i) for i in range(8)])
    assert sum(1 for x in resps if x.channel == "sms" and x.rejected_at is None) == 4
    assert sum(1 for x in resps if x.rejected_at == "step11") == 4
    used = h.p.store.get("sms_cap_per_minute_web:limit:App/RegisterOTP:966") or 0
    assert int(used) == 4


def test_released_claim_after_its_window_does_not_go_negative(h):
    """Releasing a counter whose window has already expired gives nothing back (no negative count
    without a TTL on Redis)."""
    assert h.p.store.try_reserve("claim:test", 1, 5, 60)
    h.clock.advance(61)
    h.p.store.release("claim:test", 1)
    assert h.p.store.get("claim:test") is None


# ---------------- M9 (4): the app path at stage 1 ----------------

def _app_req(h, i, block="96650123"):
    return h.app_request(platform="ios", session=h.session("ios", age_hours=3)[0], ip=f"198.72.{i // 250}.{i % 250 + 1}",
                         mobile=f"{block}{i % 10}{(i // 10) % 1000:03d}")


def test_app_client_at_stage_one_moves_to_non_sms_channels(h):
    """Past the limit, an app client (no challenge surface) is moved to non-SMS channels: WhatsApp
    when the number has it, otherwise no channel. Serial requests take the Step 7 path."""
    _counter(h)
    for i in range(4):
        assert h.send(_app_req(h, i)).channel == "sms"
    wa = _app_req(h, 10)
    h.svc.channels.whatsapp_numbers.add(wa.mobile)
    r = h.send(wa)
    assert r.channel == "whatsapp" and r.tier == "downgrade"
    r = h.send(_app_req(h, 11))
    assert r.rejected_at == "no_channel"
    assert h.p.block_count("966501230000") == 4


def test_app_client_at_stage_one_under_concurrency_moves_to_non_sms_channels(h):
    """The same at Step 11, when the requests all read a count below the limit at Step 5."""
    _counter(h)
    reqs = [_app_req(h, 20 + i) for i in range(8)]
    for q in reqs:
        h.svc.channels.whatsapp_numbers.add(q.mobile)
    resps = _concurrent(h, reqs)
    assert sum(1 for x in resps if x.channel == "sms") == 4
    assert sum(1 for x in resps if x.channel == "whatsapp") == 4
    assert h.p.block_count("966501230000") == 4


# ---------------- M9 (5): Step 11 is not one transaction: its crash semantics ----------------

def test_step11_crash_between_entry_and_enqueue_is_conservative(h):
    """A crash after the send's entry is written and before the message is handed to the sender: the
    reserved hourly budget unit stays reserved, nothing is sent, and the entry resolves as undelivered
    at the grace period without feeding the block test (the documented crash semantics)."""
    _open(h)
    h.svc.sender.instant_receipts = False
    orig = h.svc.sender.enqueue

    def dying(*a, **k):
        h.svc.sender.enqueue = orig
        raise Crash()
    h.svc.sender.enqueue = dying
    before = h.sms_sent
    with pytest.raises(Crash):
        h.send(_req(h, 6, block="96650795"))
    assert h.sms_sent == before
    log_id = int(h.p.store.get("smslog:seq"))
    assert int(h.p.store.get(f"global:sms:count:{h.p.current_hour()}") or 0) >= 1
    h.clock.advance(h.cfg.receipt_grace_s + 1)
    h.p.feedback.run_due_timeouts()
    assert h.p.store.get(f"otp:code:{log_id}")["resolution"] == "undelivered"
    assert h.p.feedback.block_llr("block:96650795")[2] == (0, 0, 0)
