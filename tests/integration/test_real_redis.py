"""Concurrency properties on a real redis-server, across two pipeline instances that share nothing
but Redis (two worker processes in production). Skipped when redis-server is not installed.

What is established here, and only here (the unit suite runs on the memory store and on fakeredis):
  * the hourly SMS budget is a hard ceiling under concurrent sends from two instances;
  * one number cannot be claimed twice under concurrent requests from two instances;
  * concurrent verification callbacks for one message count once;
  * concurrent block-test events from two instances are all counted and cross the threshold once;
  * store.update (WATCH/MULTI/EXEC) serialises conflicting writers.
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


def test_store_update_serialises_conflicting_writers(redis_url):
    h, pipes = two_instances(redis_url)
    def worker(k):
        def go():
            for _ in range(50):
                pipes[k % 2].store.update("counter", lambda cur: (cur or 0) + 1)
        return go
    _run([worker(k) for k in range(8)])
    assert pipes[0].store.get("counter") == 400
