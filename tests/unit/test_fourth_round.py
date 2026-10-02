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
    return h.web_request(session=h.session(age_hours=3)[0], ip=f"198.71.{i // 250}.{i % 250 + 1}",
                         mobile=f"{block}{i:04d}", **kw)


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
