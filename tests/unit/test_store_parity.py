"""Seventh-round review, M1: the in-memory store, on which every simulation runs, must keep state as
Redis does. Each test runs the same operations on a MemoryStore and on a RedisStore over fakeredis,
both driven by one clock, and compares every result.

Up to 2.8.3 the memory store kept a sorted set's expiry from the write that created it, so the outage
detector's and Step 5c's sorted sets emptied a fixed time after their first write while new members
kept arriving; on Redis, whose ZADD is followed by EXPIRE, they live TTL seconds from the latest write.
test_sorted_set_written_with_a_ttl_lives_from_its_latest_write and the zadd_max case fail on 2.8.3.
The other rules compared here (expiry when the clock passes the expiry time, whole-second TTLs, no
expiry for a zero TTL, EXPIRE NX on hashes, deletion of an emptied sorted set, member order among equal
scores, sorted scan) also differed before 2.9.0 or had no test. The random sequences cover every store
operation the pipeline uses. test_simulation_is_identical_on_both_stores runs a whole simulation on
both stores."""
import random
import time

import fakeredis
import pytest

from otp_guard.store import Clock, MemoryStore, RedisStore

INF = float("inf")


@pytest.fixture
def stores(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(time, "time", clock.now)          # fakeredis expires keys by time.time()
    return clock, MemoryStore(clock), RedisStore(fakeredis.FakeRedis(), clock)


def both(stores, name, *args, **kw):
    _, m, r = stores
    return getattr(m, name)(*args, **kw), getattr(r, name)(*args, **kw)


def test_sorted_set_written_with_a_ttl_lives_from_its_latest_write(stores):
    """The reviewer's case: members keep arriving while the first write's TTL runs out. Step 5c writes
    its number sets with TTL 2 x window and trims them to the window; the recent members must stay."""
    clock, m, r = stores
    window = 600
    for i in range(13):                                      # a write every 300 s for an hour
        t = clock.now()
        for s in (m, r):
            s.zremrangebyscore("numseq:k", -INF, t - window)
            s.zadd("numseq:k", t, f"m{i}", ttl=2 * window)
        got = both(stores, "zrangebyscore", "numseq:k", t - window, INF)
        assert got[0] == got[1] == [f"m{j}" for j in range(max(0, i - 1), i + 1)], (i, got)
        clock.advance(300)


def test_zadd_max_refreshes_the_ttl_even_when_the_score_is_not_raised(stores):
    clock, m, r = stores
    for s in (m, r):
        s.zadd_max("outage:blocks:c", 100.0, "b1", ttl=60)
    clock.advance(50)
    for s in (m, r):
        s.zadd_max("outage:blocks:c", 90.0, "b1", ttl=60)    # older: the score stays, the TTL restarts
    clock.advance(50)
    assert both(stores, "zscore", "outage:blocks:c", "b1") == (100.0, 100.0)
    clock.advance(11)
    assert both(stores, "zscore", "outage:blocks:c", "b1") == (None, None)


def test_a_key_lives_until_the_clock_passes_its_expiry(stores):
    """Redis expires a key when now > expiry time; at the expiry instant it is still there."""
    clock, m, r = stores
    both(stores, "set", "s", 1, ttl=10)
    clock.advance(10)
    assert both(stores, "get", "s") == (1, 1)
    clock.advance(0.001)
    assert both(stores, "get", "s") == (None, None)


def test_ttls_are_whole_seconds_and_zero_means_none(stores):
    clock, m, r = stores
    both(stores, "set", "a", 1, ttl=2.9)                     # EX 2
    both(stores, "set", "b", 1, ttl=0)                       # no expiry
    clock.advance(2.5)
    assert both(stores, "get", "a") == (None, None)
    clock.advance(10 ** 6)
    assert both(stores, "get", "b") == (1, 1)


def test_hincrby_gives_a_ttl_only_to_a_hash_without_one(stores):
    clock, m, r = stores
    both(stores, "hincrby", "h", "f", 1)                     # no TTL
    both(stores, "hincrby", "h", "f", 1, ttl=30)             # EXPIRE NX: now 30 s
    clock.advance(20)
    both(stores, "hincrby", "h", "f", 1, ttl=30)             # keeps the running TTL
    clock.advance(11)
    assert both(stores, "hgetall", "h") == ({}, {})


def test_an_emptied_sorted_set_is_deleted_and_restarts_with_its_next_write(stores):
    clock, m, r = stores
    for s in (m, r):
        s.zadd("z", 1.0, "a", ttl=100)
    clock.advance(90)
    both(stores, "zremrangebyscore", "z", -INF, INF)
    assert both(stores, "exists", "z") == (False, False)
    for s in (m, r):
        s.zadd("z", 2.0, "b")                                # no TTL given: a new key without expiry
    clock.advance(1000)
    assert both(stores, "zrangebyscore", "z", -INF, INF) == (["b"], ["b"])


def test_members_with_equal_scores_come_in_member_order(stores):
    _, m, r = stores
    for member in ("17", "3", "b", "a", "100"):
        for s in (m, r):
            s.zadd("t", 5.0, member)
    assert both(stores, "zrangebyscore", "t", -INF, INF) == (["100", "17", "3", "a", "b"],) * 2


def _random_ops(rng, n):
    """A sequence of (operation, args) over every store method the pipeline uses, with clock steps that
    often land exactly on an expiry instant."""
    keys = {k: [f"{k}{i}" for i in range(3)] for k in "schzmt"}
    ttls = [None, 0, 1, 5, 10, 10, 30]
    steps = [0, 0, 0.5, 1, 5, 5, 10, 10.001, 30]
    for _ in range(n):
        op = rng.choice(["set", "setnx", "update", "incr", "expire", "hincrby", "batch", "zadd", "zadd_max", "zrem",
                         "zremrange", "zrem_if", "acquire", "acquire_all", "reserve", "tiered", "release", "sadd", "tick"])
        k = lambda t: rng.choice(keys[t])                    # noqa: E731
        if op == "set":
            yield "set", (k("s"), rng.choice([1, "x", {"a": 1}]), rng.choice(ttls))
        elif op == "setnx":
            yield "setnx", (k("s"), 7, rng.choice(ttls))
        elif op == "update":
            yield "update", (k("s"), rng.choice(ttls))
        elif op == "incr":
            yield "incr", (k("c"), rng.choice([1, 1, -1, 3]))
        elif op == "expire":
            # positive TTLs only: fakeredis keeps a key given EXPIRE 0 until the clock moves, whereas Redis
            # deletes it at once (as the memory store does; tests/integration/test_real_redis.py)
            yield "expire", (rng.choice(keys["c"] + keys["z"] + keys["h"]), rng.choice([1, 5, 10, 30]))
        elif op == "hincrby":
            yield "hincrby", (k("h"), rng.choice("fg"), rng.choice([1, 2]), rng.choice(ttls))
        elif op == "batch":
            yield "hincrby_batch_once", (k("m"), [(k("h"), "f", 1, rng.choice([5, 10, 30]))], rng.choice([5, 10]))
        elif op == "zadd":
            yield "zadd", (k("z"), float(rng.randint(0, 40)), rng.choice("abcd"), rng.choice(ttls))
        elif op == "zadd_max":
            yield "zadd_max", (k("z"), float(rng.randint(0, 40)), rng.choice("abcd"), rng.choice(ttls))
        elif op == "zrem":
            yield "zrem", (k("z"), rng.choice("abcd"))
        elif op == "zremrange":
            lo = float(rng.randint(0, 40))
            yield "zremrangebyscore", (k("z"), -INF if rng.random() < 0.5 else lo, lo + rng.randint(0, 20))
        elif op == "zrem_if":
            yield "zrem_if_score", (k("z"), rng.choice("abcd"), float(rng.randint(0, 40)))
        elif op == "acquire":
            yield "try_acquire", (k("c"), 3, rng.choice([5, 10]))
        elif op == "acquire_all":
            yield "try_acquire_all", ([(k("c"), 3, 10), (k("c"), 4, 5)],)
        elif op == "reserve":
            yield "try_reserve", (k("c"), rng.choice([1, 2]), 4, rng.choice([5, 10]))
        elif op == "tiered":
            yield "try_reserve_tiered", (k("c"), 1, 2, 4, 10, rng.random() < 0.5)
        elif op == "release":
            yield "release", (k("c"), 1)
        elif op == "sadd":
            yield "sadd", (k("t"), rng.choice("xy"))
        else:
            yield "tick", (rng.choice(steps),)


def _observe(s, keys):
    out = []
    for key in keys:
        if key[0] in "scm":
            out.append(("get", key, s.get(key), s.exists(key)))
        elif key[0] == "h":
            out.append(("hgetall", key, s.hgetall(key)))
        elif key[0] == "z":
            out.append(("zrange", key, s.zrangebyscore(key, -INF, INF),
                        [None if x is None else float(x) for x in (s.zscore(key, m) for m in "abcd")],
                        s.zcount_many([key], 10, 30)))
        else:
            out.append(("smembers", key, sorted(s.smembers(key)), s.sismember(key, "x")))
    out.append(("scan", [k for p in "schzmt" for k in s.scan(p)]))
    return out


@pytest.mark.parametrize("seed", range(6))
def test_random_operation_sequences_agree(stores, seed):
    clock, m, r = stores
    keys = [f"{k}{i}" for k in "schzmt" for i in range(3)]
    for i, (op, args) in enumerate(_random_ops(random.Random(seed), 400)):
        if op == "tick":
            clock.advance(args[0])
        elif op == "update":
            res = [s.update(args[0], lambda cur: None if cur == 3 else 3 if not isinstance(cur, int) else cur + 1,
                            args[1]) for s in (m, r)]
            assert res[0] == res[1], (seed, i, op, args, res)
        else:
            res = [getattr(s, op)(*args) for s in (m, r)]
            assert res[0] == res[1], (seed, i, op, args, res)
        assert _observe(m, keys) == _observe(r, keys), (seed, i, op, args)


def test_simulation_is_identical_on_both_stores():
    """A whole run (warm-up and attack spanning several 20-minute sorted-set TTLs, destination counter,
    sequential tests, outage detector and Step 5c) gives the same record on the memory store and on
    RedisStore; scripts/check_store_parity.py runs recorded study specs the same way."""
    import dataclasses
    from otp_guard.evaluation import counter_study as C
    from otp_guard.evaluation.sim import run_sim
    base = next(s for s in C.study_e4()[0] if s.minutes == 20 and s.attacker.n_blocks == 3)
    spec = dataclasses.replace(base, warmup_minutes=15, seed=11,
                               legit=dataclasses.replace(base.legit, rate_per_min=min(base.legit.rate_per_min, 20.0)))
    a, b = run_sim(spec, "memory"), run_sim(spec, "redis")
    a.pop("wall_s"), b.pop("wall_s")
    assert a == b
    assert a["attack"]["leaked_before_containment"] > 0
