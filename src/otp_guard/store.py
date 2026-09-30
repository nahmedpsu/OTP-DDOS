"""State backends. Everything the pipeline remembers goes through one small interface so
the same code runs on the in-memory store (tests) and on Redis (production)."""
import json
import threading

LUA_TRY_ACQUIRE = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
if current > tonumber(ARGV[1]) then
    redis.call('DECR', KEYS[1])
    return 0
end
return 1
"""

# KEYS = limit keys; ARGV = max1, window1, max2, window2, ...
LUA_TRY_ACQUIRE_ALL = """
for i = 1, #KEYS do
    local cur = tonumber(redis.call('GET', KEYS[i]) or '0')
    if cur >= tonumber(ARGV[2 * i - 1]) then return 0 end
end
for i = 1, #KEYS do
    local cur = redis.call('INCR', KEYS[i])
    if cur == 1 then redis.call('EXPIRE', KEYS[i], ARGV[2 * i]) end
end
return 1
"""


class Clock:
    """Controllable clock so tests can move time instead of sleeping."""

    def __init__(self, start=1_700_000_000.0):
        self.t = float(start)

    def now(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class SystemClock:
    def now(self):
        import time
        return time.time()


class MemoryStore:
    """Redis-like store with TTLs driven by the clock. Values are kept as Python objects."""

    def __init__(self, clock):
        self.clock = clock
        self._d = {}
        self.lock = threading.RLock()

    # ---- internals ----
    def _live(self, key):
        v = self._d.get(key)
        if v is None:
            return None
        if v[1] is not None and v[1] <= self.clock.now():
            del self._d[key]
            return None
        return v

    def _put(self, key, val, keep_ttl_from=None, ttl=None):
        exp = None
        if keep_ttl_from is not None:
            exp = keep_ttl_from[1]
        elif ttl is not None:
            exp = self.clock.now() + ttl
        self._d[key] = (val, exp)

    # ---- strings / numbers ----
    def get(self, key):
        with self.lock:
            v = self._live(key)
            return None if v is None else v[0]

    def set(self, key, val, ttl=None):
        with self.lock:
            self._put(key, val, ttl=ttl)

    def setnx(self, key, val, ttl=None):
        with self.lock:
            if self._live(key) is not None:
                return False
            self._put(key, val, ttl=ttl)
            return True

    def incr(self, key, by=1):
        with self.lock:
            v = self._live(key)
            cur = 0 if v is None else v[0]
            self._put(key, cur + by, keep_ttl_from=v)
            return cur + by

    def decr(self, key):
        return self.incr(key, -1)

    def expire(self, key, ttl):
        with self.lock:
            v = self._live(key)
            if v is not None:
                self._put(key, v[0], ttl=ttl)

    def exists(self, key):
        with self.lock:
            return self._live(key) is not None

    def delete(self, key):
        with self.lock:
            self._d.pop(key, None)

    # ---- hashes ----
    def hincrby(self, key, field, by=1, ttl=None):
        with self.lock:
            v = self._live(key)
            h = dict(v[0]) if v is not None else {}
            h[field] = h.get(field, 0) + by
            if v is None:
                self._put(key, h, ttl=ttl)
            else:
                self._put(key, h, keep_ttl_from=v)
            return h[field]

    def hgetall(self, key):
        with self.lock:
            v = self._live(key)
            return dict(v[0]) if v is not None else {}

    def hgetall_many(self, keys):
        return [self.hgetall(k) for k in keys]

    # ---- sorted sets ----
    def zadd(self, key, score, member, ttl=None):
        with self.lock:
            v = self._live(key)
            z = dict(v[0]) if v is not None else {}
            z[member] = score
            if v is None:
                self._put(key, z, ttl=ttl)
            else:
                self._put(key, z, keep_ttl_from=v)

    def zrangebyscore(self, key, lo, hi):
        with self.lock:
            v = self._live(key)
            if v is None:
                return []
            return [m for m, s in sorted(v[0].items(), key=lambda kv: kv[1]) if lo <= s <= hi]

    def zrem(self, key, member):
        with self.lock:
            v = self._live(key)
            if v is not None:
                z = dict(v[0]); z.pop(member, None)
                self._put(key, z, keep_ttl_from=v)

    def zremrangebyscore(self, key, lo, hi):
        with self.lock:
            v = self._live(key)
            if v is not None:
                z = {m: s for m, s in v[0].items() if not (lo <= s <= hi)}
                self._put(key, z, keep_ttl_from=v)

    # ---- sets ----
    def sadd(self, key, member):
        with self.lock:
            v = self._live(key)
            s = set(v[0]) if v is not None else set()
            s.add(member)
            self._put(key, s, keep_ttl_from=v)

    def sismember(self, key, member):
        with self.lock:
            v = self._live(key)
            return v is not None and member in v[0]

    # ---- atomic rate limiting ----
    def try_acquire(self, key, max_count, window):
        with self.lock:
            cur = self.incr(key)
            if cur == 1:
                self.expire(key, window)
            if cur > max_count:
                self.decr(key)
                return False
            return True

    def try_acquire_all(self, specs):
        """specs: list of (key, max_count, window). All-or-nothing."""
        with self.lock:
            for key, max_count, _ in specs:
                if (self.get(key) or 0) >= max_count:
                    return False
            for key, _, window in specs:
                if self.incr(key) == 1:
                    self.expire(key, window)
            return True


class RedisStore:
    """Same interface on a redis-py client. Values are JSON so dicts and floats round-trip.
    Counters used with INCR are plain integers, which JSON encodes as the digits Redis expects."""

    def __init__(self, client, clock=None):
        self.r = client
        self.clock = clock or SystemClock()
        self._acquire = self.r.register_script(LUA_TRY_ACQUIRE)
        self._acquire_all = self.r.register_script(LUA_TRY_ACQUIRE_ALL)
        self.round_trips = 0        # one per method call below; a pipeline counts once

    @staticmethod
    def _enc(v):
        return json.dumps(v)

    @staticmethod
    def _dec(raw):
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return raw

    def get(self, key):
        self.round_trips += 1
        return self._dec(self.r.get(key))

    def set(self, key, val, ttl=None):
        self.round_trips += 1
        self.r.set(key, self._enc(val), ex=int(ttl) if ttl else None)

    def setnx(self, key, val, ttl=None):
        self.round_trips += 1
        return bool(self.r.set(key, self._enc(val), ex=int(ttl) if ttl else None, nx=True))

    def incr(self, key, by=1):
        self.round_trips += 1
        return self.r.incrby(key, by)

    def decr(self, key):
        self.round_trips += 1
        return self.r.decr(key)

    def expire(self, key, ttl):
        self.round_trips += 1
        self.r.expire(key, int(ttl))

    def exists(self, key):
        self.round_trips += 1
        return bool(self.r.exists(key))

    def delete(self, key):
        self.round_trips += 1
        self.r.delete(key)

    def hincrby(self, key, field, by=1, ttl=None):
        self.round_trips += 1
        pipe = self.r.pipeline()
        pipe.hincrby(key, field, by)
        if ttl:
            pipe.expire(key, int(ttl), nx=True)
        return pipe.execute()[0]

    def hgetall(self, key):
        self.round_trips += 1
        return {(k.decode() if isinstance(k, bytes) else k): int(v) for k, v in self.r.hgetall(key).items()}

    def hgetall_many(self, keys):
        self.round_trips += 1
        """One round trip for many hashes (the 24 hourly reputation buckets of a key)."""
        pipe = self.r.pipeline(transaction=False)
        for k in keys:
            pipe.hgetall(k)
        return [{(k.decode() if isinstance(k, bytes) else k): int(v) for k, v in h.items()} for h in pipe.execute()]

    def zadd(self, key, score, member, ttl=None):
        self.round_trips += 1
        pipe = self.r.pipeline()
        pipe.zadd(key, {member: score})
        if ttl:
            pipe.expire(key, int(ttl))
        pipe.execute()

    def zrangebyscore(self, key, lo, hi):
        self.round_trips += 1
        return [m.decode() if isinstance(m, bytes) else m for m in self.r.zrangebyscore(key, lo, hi)]

    def zrem(self, key, member):
        self.round_trips += 1
        self.r.zrem(key, member)

    def zremrangebyscore(self, key, lo, hi):
        self.round_trips += 1
        self.r.zremrangebyscore(key, lo, hi)

    def sadd(self, key, member):
        self.round_trips += 1
        self.r.sadd(key, member)

    def sismember(self, key, member):
        self.round_trips += 1
        return bool(self.r.sismember(key, member))

    def try_acquire(self, key, max_count, window):
        self.round_trips += 1
        return int(self._acquire(keys=[key], args=[int(max_count), int(window)])) == 1

    def try_acquire_all(self, specs):
        self.round_trips += 1
        if not specs:
            return True
        args = []
        for _, max_count, window in specs:
            args += [int(max_count), int(window)]
        return int(self._acquire_all(keys=[k for k, _, _ in specs], args=args)) == 1


class RateLimit:
    """Fixed-window limiter; check-and-consume is atomic in the backing store."""

    def __init__(self, store):
        self.store = store
        self.max = None
        self.window = None
        self.key = None
        self.ident = None

    def set_limit(self, max_count, window_seconds):
        self.max = int(max_count)
        self.window = int(window_seconds)
        return self

    def set_key(self, key):
        self.key = key
        return self

    def set_identifier(self, ident):
        self.ident = str(ident)
        return self

    @property
    def redis_key(self):
        return f"{self.key}:{self.ident}"

    def try_acquire(self):
        return self.store.try_acquire(self.redis_key, self.max, self.window)

    def current_count(self):
        return int(self.store.get(self.redis_key) or 0)

    @staticmethod
    def try_acquire_all(limits):
        if not limits:
            return True
        return limits[0].store.try_acquire_all([(l.redis_key, l.max, l.window) for l in limits])
