"""Regression tests for the fourth-round review's implementation counterexamples: the graded
destination counter's first boundary under concurrency (M5) and replay of a block effect after
its identifier has left the block's bounded memory (M6). Every test runs on the memory store and
on fakeredis; tests/integration/test_real_redis.py repeats the concurrency cases on a real Redis."""
import threading

import pytest

from otp_guard.evaluation.runner import MATCHED


def _counter(h, setting="counter graded 4/10 min"):
    _, feats, cfg = MATCHED[setting]
    h.cfg.features = set(feats)
    for k, v in cfg.items():
        setattr(h.cfg, k, v)
    h.lift_source_caps(); h.cfg.asn_limit_default = 10**9; h.cfg.ip_limit = (10**9, 60)
    return h


def _req(h, i, block="96650123", **kw):
    # a web client whose fingerprint is old enough to be sent to directly, but with no verified history
    # numbers spread over the block's 9-digit ranges, so Step 5's narrow-range rule stays out of the way
    return h.web_request(session=h.session(age_hours=3)[0], ip=f"198.71.{i // 250}.{i % 250 + 1}",
                         mobile=f"{block}{i % 10}{(i // 10) % 1000:03d}", **kw)


def _outcomes(resps):
    return {"sms": sum(1 for r in resps if r.rejected_at is None and r.channel == "sms"),
            "challenge": sum(1 for r in resps if r.tier == "challenge" and r.rejected_at is not None)}


def _concurrent(h, reqs):
    """Run the requests on threads that all finish Step 5 (where the block count is read) before any
    proceeds: every request has read the count before any reserves a send."""
    barrier = threading.Barrier(len(reqs))
    out = [None] * len(reqs)
    orig = h.p.step5_number

    def gated(req):
        ok = orig(req)
        barrier.wait(timeout=10)
        return ok
    h.p.step5_number = gated

    def run(i):
        out[i] = h.send(reqs[i])
    ts = [threading.Thread(target=run, args=(i,)) for i in range(len(reqs))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    h.p.step5_number = orig
    return out


def test_counter_serial_first_boundary(h):
    """4 per 10 minutes, graded: the first four sends go out, the next four are challenged."""
    _counter(h)
    resps = [h.send(_req(h, i)) for i in range(8)]
    assert _outcomes(resps) == {"sms": 4, "challenge": 4}
    assert h.p.block_count("966501230000") == 4


def test_counter_concurrent_first_boundary_is_enforced(h):
    """The reviewer's counterexample: eight requests that all read a count below the limit at Step 5
    must not all send. The stage is decided again on the count the reservation changes."""
    _counter(h)
    resps = _concurrent(h, [_req(h, i) for i in range(8)])
    assert _outcomes(resps) == {"sms": 4, "challenge": 4}
    assert h.p.block_count("966501230000") == 4


def test_counter_concurrent_solved_challenges_fill_the_second_tier_only(h):
    """Requests that solved the challenge may use the second tier (up to twice the limit), never more."""
    _counter(h)
    for i in range(4):
        h.send(_req(h, i))
    assert h.p.block_count("966501230000") == 4
    resps = _concurrent(h, [_req(h, 100 + i, challenge_proof="challenge-ok") for i in range(8)])
    assert _outcomes(resps)["sms"] == 4
    assert h.p.block_count("966501230000") == 8
    # beyond twice the limit nothing is sent, solved or not
    r = h.send(_req(h, 200, challenge_proof="challenge-ok"))
    assert r.channel != "sms"


def test_counter_concurrent_unsolved_at_second_boundary(h):
    _counter(h)
    for i in range(4):
        h.send(_req(h, i))
    for i in range(4):
        h.send(_req(h, 50 + i, challenge_proof="challenge-ok"))
    resps = _concurrent(h, [_req(h, 100 + i) for i in range(6)])
    assert _outcomes(resps)["sms"] == 0
    assert h.p.block_count("966501230000") == 8


def test_counter_challenged_request_releases_its_number_claim(h):
    """A request turned into a challenge at Step 11 must not hold the number's window: its retry with
    the proof goes through."""
    _counter(h)
    resps = _concurrent(h, [_req(h, i) for i in range(5)])
    ch = [i for i, r in enumerate(resps) if r.tier == "challenge"]
    assert len(ch) == 1
    i = ch[0]
    r = h.send(_req(h, i, challenge_proof="challenge-ok"))
    assert r.rejected_at is None and r.channel == "sms"


# ---------------- M6: replay after the block's identifier memory has moved on ----------------

class Crash(Exception):
    pass


def _open(h):
    h.lift_source_caps(); h.cfg.asn_limit_default = 10**9; h.cfg.ip_limit = (10**9, 60)
    h.svc.sender.instant_receipts = False
    h.cfg.block_tests = ()               # isolate accounting from verdict issuance, as the reviewer did
    return h


def _crash_after_block_event(fb):
    """The next _block_event is applied, then the process dies before the batch is cleared."""
    orig = fb._block_event
    def dying(*a, **k):
        fb._block_event = orig
        orig(*a, **k)
        raise Crash()
    fb._block_event = dying


def test_block_effect_is_not_replayed_after_many_later_events(h):
    """The reviewer's counterexample: a failure's block effect is applied, the process dies before
    clearing its batch, 256 later events reach the same block, and recovery runs while the entry is
    alive. The failure must be counted once (257, not 258)."""
    _open(h)
    fb = h.p.feedback
    r = h.send(_req(h, 1, block="96650777"))
    fb.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1)
    _crash_after_block_event(fb)
    with pytest.raises(Crash):
        fb.run_due_timeouts()
    entry = h.p.store.get(f"otp:code:{r.log_id}")
    assert entry is not None and entry["pending"]                       # a replayable batch is left
    for i in range(256):                                                # the old fixed memory
        fb._block_event("block:96650777", verified=False, event_id=f"synthetic:{i}")
    assert fb.block_llr("block:96650777")[2][1] == 257
    h.clock.advance(fb.RECOVER_AFTER_S + 1)
    fb.recover()
    assert not (h.p.store.get(f"otp:code:{r.log_id}") or {}).get("pending")
    assert fb.block_llr("block:96650777")[2][1] == 257


def test_event_identifiers_are_kept_for_the_replay_horizon(h):
    """Identifiers are retained by age, not by count: any number of events inside the horizon are
    remembered, and an identifier is dropped only after its retention (the replay horizon plus the
    code lifetime plus a margin, so a late reversal's own replay still finds it; 2.8.1) has passed."""
    _open(h)
    fb = h.p.feedback
    for i in range(2000):
        fb._block_event("block:96650778", verified=False, event_id=f"e{i}")
    fb._block_event("block:96650778", verified=False, event_id="e0")       # a replay inside the horizon
    assert fb.block_llr("block:96650778")[2][1] == 2000
    h.clock.advance(fb.replay_horizon_s() + 61)                            # past the horizon, inside the retention
    fb._block_event("block:96650778", verified=False, event_id="mid")
    assert "e0" in h.p.store.get("blocktest:block:96650778")["seen"]
    h.clock.advance(fb.id_retention_s() - fb.replay_horizon_s())
    fb._block_event("block:96650778", verified=False, event_id="late")
    st = h.p.store.get("blocktest:block:96650778")
    assert set(st["seen"]) == {"mid", "late"}                              # the old identifiers are gone


def test_a_batch_older_than_the_replay_horizon_is_abandoned_not_replayed(h):
    """Past the horizon an identifier may be gone, so a batch that old is not applied again: its
    counting effects are skipped (and counted as abandoned) rather than possibly applied twice."""
    _open(h)
    fb = h.p.feedback
    r = h.send(_req(h, 2, block="96650779"))
    fb.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1)
    _crash_after_block_event(fb)
    with pytest.raises(Crash):
        fb.run_due_timeouts()
    rec = h.p.sms_history.get(r.log_id)
    batch = h.p.store.get(f"otp:code:{r.log_id}")["pending"][0]
    h.clock.advance(fb.replay_horizon_s() + 61)
    fb._block_event("block:96650779", verified=False, event_id="after")   # prunes the old identifier
    fb._apply(r.log_id, rec, batch)                                       # a very late replay
    assert fb.block_llr("block:96650779")[2][1] == 2
    assert int(h.p.store.get("otp:fx:abandoned") or 0) == 1


# ---------------- M15: a reversal that reaches the block before the failure it reverses ----------------

def _crash_before_block_effect(fb):
    """The next batch's process dies before any of its effects is applied."""
    orig = fb._apply
    def dying(log_id, rec, batch):
        fb._apply = orig
        raise Crash()
    fb._apply = dying


def test_late_verification_reversal_before_the_failure_is_applied(h):
    """A send times out as failed, but that transition's process dies before its block effect; the
    person then enters the code late (the reversal is applied at once), and recovery applies the
    failure afterwards. The block must end with one verification and no failure, whatever the order."""
    _open(h)
    fb = h.p.feedback
    r = h.send(_req(h, 3, block="96650780"))
    fb.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1)
    _crash_before_block_effect(fb)
    with pytest.raises(Crash):
        fb.run_due_timeouts()                                  # resolved 'failed', effects pending
    sid = h.p.sms_history[r.log_id]["session_id"]
    fb.verify(sid, r.log_id, fb.code_for(r.log_id))          # late verification: reversal applied first
    h.clock.advance(fb.RECOVER_AFTER_S + 1)
    fb.recover()                                               # then the failure
    assert fb.block_llr("block:96650780")[2][:2] == (1, 0)
    rep = h.p.rep.get("block:96650780")
    assert rep.verified == 1 and rep.failed == 0


def test_corrected_receipt_reversal_before_the_failure_is_applied(h):
    """The same ordering for the receipt-robust policy: a failed receipt's block failure is pending
    when the corrected (positive) receipt's reversal is applied."""
    _open(h)
    h.cfg.receipt_policy = "robust"
    fb = h.p.feedback
    r = h.send(_req(h, 4, block="96650781"))
    _crash_before_block_effect(fb)
    with pytest.raises(Crash):
        fb.on_delivery(r.log_id, False)
    fb.on_delivery(r.log_id, True)
    h.clock.advance(fb.RECOVER_AFTER_S + 1)
    fb.recover()
    assert fb.block_llr("block:96650781")[2] == (0, 0, 0)


# ---------------- the token-bucket destination limiter ----------------

def _bucket(h, n=4, window=600, burst=None):
    _counter(h)
    h.cfg.block_count_mode, h.cfg.block_count_limit, h.cfg.block_bucket_burst = "token_bucket", (n, window), burst
    return h


def test_token_bucket_burst_then_refill(h):
    _bucket(h)
    resps = [h.send(_req(h, i)) for i in range(6)]
    assert _outcomes(resps) == {"sms": 4, "challenge": 2}
    h.clock.advance(150)                                    # 4 tokens / 600 s: one token back
    assert _outcomes([h.send(_req(h, 10))])["sms"] == 1
    assert _outcomes([h.send(_req(h, 11))])["challenge"] == 1


def test_token_bucket_burst_is_separate_from_the_rate(h):
    _bucket(h, n=4, window=600, burst=10)
    resps = [h.send(_req(h, i)) for i in range(12)]
    assert _outcomes(resps) == {"sms": 10, "challenge": 2}


def test_token_bucket_concurrent_first_boundary_and_second_tier(h):
    _bucket(h)
    resps = _concurrent(h, [_req(h, i) for i in range(8)])
    assert _outcomes(resps) == {"sms": 4, "challenge": 4}
    resps = _concurrent(h, [_req(h, 100 + i, challenge_proof="challenge-ok") for i in range(6)])
    assert _outcomes(resps)["sms"] == 4                     # the second bucket, nothing beyond it


def test_token_bucket_returns_the_token_when_no_sms_is_sent(h):
    _bucket(h)
    h.cfg.global_sms_per_hour = 1
    h.send(_req(h, 0, block="96650999"))                    # spends the hour's budget on another block
    for i in range(6):
        h.send(_req(h, i))                                  # each reservation is made, then returned at the budget
    a, b = h.p._bucket_levels(h.p.store.get(h.p.block_count_key("966501230000")), h.clock.now())
    assert (a, b) == (4.0, 4.0)
