"""Concurrency properties on a real redis-server, across two pipeline instances that share nothing
but Redis (two worker processes in production). Skipped when redis-server is not installed.

What is established here, and only here (the unit suite runs on the memory store and on fakeredis):
  * the hourly SMS budget is a hard ceiling under concurrent sends from two instances;
  * one number cannot be claimed twice under concurrent requests from two instances;
  * concurrent verification callbacks for one message count once;
  * concurrent block-test events from two instances are all counted and cross the threshold once,
    under the denylist action and under the default graded action, where the second crossing
    while a verdict is active is stage 2 whichever instance processed it;
  * a feedback transition whose process dies before its effects are applied is completed by the
    other instance's recovery sweep, once, including after 256 later events on the same block
    (identifiers are kept for the replay horizon, not by count);
  * concurrent mixed receipts for one send leave a consistent entry;
  * the graded destination counter's first boundary holds under concurrent requests from two
    instances (requests past it are challenged), and its second tier admits only solved challenges
    up to twice the limit;
  * store.update (WATCH/MULTI/EXEC) serialises conflicting writers.
Not established: behaviour under network partitions or a Redis failover, Redis Cluster (the Lua
scripts assume one shard), and process crashes at points other than the injected ones.
Not established anywhere in this repository: behaviour against live vendors (attestation, CAPTCHA,
HLR, SMS), which needs credentials and a real device."""
import shutil
import socket
import subprocess
import threading
import time

import pytest

from otp_guard import Pipeline
from otp_guard.store import RedisStore
from otp_guard.testing import Harness

pytestmark = pytest.mark.skipif(shutil.which("redis-server") is None, reason="redis-server not installed")


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    return port


@pytest.fixture(scope="module")
def redis_url():
    port = _free_port()
    proc = subprocess.Popen(["redis-server", "--port", str(port), "--save", "", "--appendonly", "no", "--loglevel", "warning"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import redis
    client = redis.Redis(port=port)
    for _ in range(100):
        try:
            client.ping(); break
        except Exception:
            time.sleep(0.05)
    yield f"redis://127.0.0.1:{port}/0"
    proc.terminate(); proc.wait(timeout=5)


def two_instances(redis_url):
    """Two pipelines on the same Redis, sharing one controllable clock and the fake services."""
    import redis
    redis.Redis.from_url(redis_url).flushall()
    h = Harness()
    h.lift_source_caps(); h.cfg.asn_limit_default = 10**9; h.cfg.ip_limit = (10**9, 60)
    h.svc.sender.instant_receipts = False
    pipes = [Pipeline(h.cfg, h.svc, h.clock, store=RedisStore(redis.Redis.from_url(redis_url), h.clock)) for _ in range(2)]
    h.p = pipes[0]
    return h, pipes


def _req(h, i, block="96650444"):
    return h.web_request(session=h.session(age_hours=3)[0], ip=f"198.60.{i // 250}.{i % 250 + 1}", mobile=f"{block}{(i * 7919) % 10000:04d}")


def _run(workers):
    barrier = threading.Barrier(len(workers))
    def wrap(fn):
        def go():
            barrier.wait(); fn()
        return go
    ts = [threading.Thread(target=wrap(w)) for w in workers]
    for t in ts: t.start()
    for t in ts: t.join()


def test_budget_ceiling_holds_across_instances(redis_url):
    h, pipes = two_instances(redis_url)
    h.cfg.global_sms_per_hour = 7
    reqs = [_req(h, i) for i in range(24)]
    out = []
    lock = threading.Lock()
    def worker(k):
        def go():
            r = pipes[k % 2].process(reqs[k])
            with lock: out.append(r)
        return go
    _run([worker(k) for k in range(24)])
    assert sum(r.channel == "sms" for r in out) == 7
    assert int(pipes[0].store.get(f"global:sms:count:{pipes[0].current_hour()}")) == 7


def test_one_number_cannot_be_claimed_twice_across_instances(redis_url):
    h, pipes = two_instances(redis_url)
    reqs = [h.web_request(session=h.session(age_hours=3)[0], ip=f"198.61.{k}.1", mobile="966501234567") for k in range(16)]
    out = []
    lock = threading.Lock()
    def worker(k):
        def go():
            r = pipes[k % 2].process(reqs[k])
            with lock: out.append(r)
        return go
    _run([worker(k) for k in range(16)])
    assert sum(r.channel == "sms" for r in out) == 1


def test_concurrent_verification_callbacks_count_once_across_instances(redis_url):
    h, pipes = two_instances(redis_url)
    rs = [pipes[0].process(_req(h, i)) for i in range(10)]
    for r in rs:
        pipes[1].feedback.on_delivery(r.log_id, True)
    _run([(lambda p, lid: (lambda: p.feedback.on_verified(lid)))(pipes[k % 2], r.log_id) for r in rs for k in range(6)])
    for r in rs:
        rep = pipes[0].rep.get("num:" + pipes[0].sms_history[r.log_id]["phone_number"])
        assert rep.verified == 1


def test_concurrent_block_events_across_instances_count_exactly(redis_url):
    h, pipes = two_instances(redis_url)
    h.cfg.block_action = "deny"
    _run([(lambda p: (lambda: p.feedback._block_event("block:96650444", verified=False)))(pipes[k % 2]) for k in range(23)])
    st = pipes[0].store.get("blocktest:block:96650444")
    events = pipes[1].feedback.verdict_events()
    assert st["verdicts"] == 4 and st["f"] == 3 and len(events) == 4      # 23 = 4 x 5 + 3


def test_graded_escalation_across_instances(redis_url):
    """The default action: ten concurrent failures from two instances give two crossings, and the
    second, inside the first verdict's hour, is stage 2."""
    h, pipes = two_instances(redis_url)
    assert h.cfg.block_action == "graded"
    _run([(lambda p: (lambda: p.feedback._block_event("block:96650446", verified=False)))(pipes[k % 2]) for k in range(10)])
    events = pipes[1].feedback.verdict_events()
    assert [e["stage"] for e in events] == [1, 2] and len({e["id"] for e in events}) == 2
    assert pipes[0].feedback.block_verdict("block:96650446")["stage"] == 2


def test_crash_recovery_across_instances(redis_url):
    """Instance 0 claims a verification and dies before applying its effects; instance 1's sweep
    applies them once, and a second sweep changes nothing."""
    h, pipes = two_instances(redis_url)
    r = pipes[0].process(_req(h, 7))
    pipes[0].feedback.on_delivery(r.log_id, True)
    sid = pipes[0].sms_history[r.log_id]["session_id"]
    code = pipes[0].feedback.code_for(r.log_id)

    class Crash(Exception):
        pass

    def die(*a, **k):
        raise Crash()
    pipes[0].feedback._apply = die
    with pytest.raises(Crash):
        pipes[0].feedback.verify(sid, r.log_id, code)
    mobile = pipes[0].sms_history[r.log_id]["phone_number"]
    assert pipes[1].rep.get("num:" + mobile).verified == 0
    h.clock.advance(pipes[1].feedback.RECOVER_AFTER_S + 1)
    assert pipes[1].feedback.recover() == 1
    pipes[1].feedback.recover(older_than=0)
    assert pipes[1].rep.get("num:" + mobile).verified == 1


def test_concurrent_mixed_receipts_leave_a_consistent_entry(redis_url):
    h, pipes = two_instances(redis_url)
    rs = [pipes[0].process(_req(h, 100 + i)) for i in range(20)]
    _run([(lambda p, lid, ok: (lambda: p.feedback.on_delivery(lid, ok)))(pipes[k % 2], r.log_id, k % 2 == 0)
          for r in rs for k in range(4)])
    for r in rs:
        e = pipes[0].store.get(f"otp:code:{r.log_id}")
        assert not (e["delivery"] == "delivered" and e["resolution"] == "undelivered"), e
        mobile = pipes[0].sms_history[r.log_id]["phone_number"]
        assert pipes[0].rep.get("num:" + mobile).undelivered == (1 if e["resolution"] == "undelivered" else 0)


def test_store_update_serialises_conflicting_writers(redis_url):
    h, pipes = two_instances(redis_url)
    def worker(k):
        def go():
            for _ in range(50):
                pipes[k % 2].store.update("counter", lambda cur: (cur or 0) + 1)
        return go
    _run([worker(k) for k in range(8)])
    assert pipes[0].store.get("counter") == 400


def _counter_instances(redis_url, setting="counter graded 4/10 min"):
    from otp_guard.evaluation.runner import MATCHED
    h, pipes = two_instances(redis_url)
    _, feats, cfg = MATCHED[setting]
    h.cfg.features = set(feats)
    for k, v in cfg.items():
        setattr(h.cfg, k, v)
    return h, pipes


def _gate_after_step5(pipes, n):
    """Every request finishes Step 5 (the counter read) before any proceeds to its reservation."""
    barrier = threading.Barrier(n)
    for p in pipes:
        orig = p.step5_number
        p.step5_number = (lambda o: (lambda req: (o(req), barrier.wait(timeout=10))[0]))(orig)


def test_graded_counter_first_boundary_across_instances(redis_url):
    """Fourth-round M5: eight requests to one block that all read a count below the limit of 4 at
    Step 5, split over two instances: four send, four are challenged."""
    h, pipes = _counter_instances(redis_url)
    reqs = [_req(h, i) for i in range(8)]
    _gate_after_step5(pipes, 8)
    out, lock = [], threading.Lock()
    def worker(k):
        def go():
            r = pipes[k % 2].process(reqs[k])
            with lock: out.append(r)
        return go
    _run([worker(k) for k in range(8)])
    assert sum(r.channel == "sms" and r.rejected_at is None for r in out) == 4
    assert sum(r.tier == "challenge" for r in out) == 4
    assert int(pipes[0].store.get(pipes[0].block_count_key(reqs[0].mobile))) == 4


def test_graded_counter_second_tier_across_instances(redis_url):
    """Solved challenges fill the second tier to twice the limit and no further; unsolved requests
    past the first boundary never send."""
    h, pipes = _counter_instances(redis_url)
    for i in range(4):
        pipes[0].process(_req(h, i))
    reqs = [_req(h, 100 + i) for i in range(6)]
    for r in reqs[:3]:
        r.challenge_proof = "challenge-ok"
    reqs += [_req(h, 200 + i) for i in range(3)]
    for r in reqs[6:]:
        r.challenge_proof = "challenge-ok"
    _gate_after_step5(pipes, len(reqs))
    out, lock = [], threading.Lock()
    def worker(k):
        def go():
            r = pipes[k % 2].process(reqs[k])
            with lock: out.append((k, r))
        return go
    _run([worker(k) for k in range(len(reqs))])
    sent = {k for k, r in out if r.channel == "sms" and r.rejected_at is None}
    assert len(sent) == 4 and all(reqs[k].challenge_proof for k in sent)
    assert int(pipes[0].store.get(pipes[0].block_count_key(reqs[0].mobile))) == 8


def test_replay_after_many_later_block_events_across_instances(redis_url):
    """Fourth-round M6: instance 0 applies a failure's block effect and dies before clearing the
    batch; 256 later events reach the block through instance 1; instance 1's sweep must not count
    the failure again."""
    h, pipes = two_instances(redis_url)
    h.cfg.block_tests = ()                                     # accounting only, no verdicts
    r = pipes[0].process(_req(h, 9, block="96650447"))
    pipes[0].feedback.on_delivery(r.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1)

    class Crash(Exception):
        pass
    fb0 = pipes[0].feedback
    orig = fb0._block_event
    def dying(*a, **k):
        orig(*a, **k)
        raise Crash()
    fb0._block_event = dying
    with pytest.raises(Crash):
        fb0.run_due_timeouts()
    for i in range(256):
        pipes[1].feedback._block_event("block:96650447", verified=False, event_id=f"synthetic:{i}")
    h.clock.advance(pipes[1].feedback.RECOVER_AFTER_S + 1)
    pipes[1].feedback.recover()
    assert pipes[1].feedback.block_llr("block:96650447")[2][1] == 257


def test_token_bucket_first_boundary_across_instances(redis_url):
    """The token-bucket limiter's first bucket under concurrent requests from two instances
    (store.update: WATCH/MULTI/EXEC): four send, four are challenged."""
    h, pipes = _counter_instances(redis_url)
    h.cfg.block_count_mode = "token_bucket"
    reqs = [_req(h, i) for i in range(8)]
    _gate_after_step5(pipes, 8)
    out, lock = [], threading.Lock()
    def worker(k):
        def go():
            r = pipes[k % 2].process(reqs[k])
            with lock: out.append(r)
        return go
    _run([worker(k) for k in range(8)])
    assert sum(r.channel == "sms" and r.rejected_at is None for r in out) == 4
    assert sum(r.tier == "challenge" for r in out) == 4
