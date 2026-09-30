import threading


class Clock:
    """Controllable clock so tests can move time instead of sleeping."""

    def __init__(self, start=1_700_000_000.0):
        self.t = float(start)

    def now(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class MemoryStore:
    """Minimal Redis-like key/value store with TTLs driven by the clock."""

    def __init__(self, clock):
        self.clock = clock
        self._d = {}
        self.lock = threading.RLock()

    def _live(self, key):
        v = self._d.get(key)
        if v is None:
            return None
        val, exp = v
        if exp is not None and exp <= self.clock.now():
            del self._d[key]
            return None
        return v

    def get(self, key):
        with self.lock:
            v = self._live(key)
            return None if v is None else v[0]

    def set(self, key, val, ttl=None):
        with self.lock:
            self._d[key] = (val, None if ttl is None else self.clock.now() + ttl)

    def setnx(self, key, val, ttl=None):
        with self.lock:
            if self._live(key) is not None:
                return False
            self.set(key, val, ttl)
            return True

    def incr(self, key, by=1):
        with self.lock:
            v = self._live(key)
            cur, exp = (0, None) if v is None else v
            self._d[key] = (cur + by, exp)
            return cur + by

    def decr(self, key):
        return self.incr(key, -1)

    def expire(self, key, ttl):
        with self.lock:
            v = self._live(key)
            if v is not None:
                self._d[key] = (v[0], self.clock.now() + ttl)

    def exists(self, key):
        with self.lock:
            return self._live(key) is not None

    def delete(self, key):
        with self.lock:
            self._d.pop(key, None)


class RateLimit:
    """Fixed-window limiter. try_acquire() is the atomic check-and-consume from the Lua
    script in the design; the store lock stands in for Redis single-threaded EVAL."""

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
        with self.store.lock:
            cur = self.store.incr(self.redis_key)
            if cur == 1:
                self.store.expire(self.redis_key, self.window)
            if cur > self.max:
                self.store.decr(self.redis_key)
                return False
            return True

    def current_count(self):
        return self.store.get(self.redis_key) or 0

    @staticmethod
    def try_acquire_all(limits):
        """Check every limit first, then consume all of them, in one critical section."""
        if not limits:
            return True
        store = limits[0].store
        with store.lock:
            for lim in limits:
                if lim.current_count() >= lim.max:
                    return False
            for lim in limits:
                cur = store.incr(lim.redis_key)
                if cur == 1:
                    store.expire(lim.redis_key, lim.window)
            return True
