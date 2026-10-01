from dataclasses import dataclass


@dataclass
class Rep:
    sent: int = 0
    verified: int = 0
    failed: int = 0
    fast_verified: int = 0     # verified within cfg.fast_verify_seconds of delivery (of the send, without receipts)
    undelivered: int = 0       # no delivery receipt, or a failed one: resolves as neither verified nor failed


class ReputationStore:
    """Rolling 24-hour counters per key, kept as hourly hash buckets in the store."""

    BUCKET_TTL = 25 * 3600

    def __init__(self, store, clock):
        self.store, self.clock = store, clock

    def _hour(self):
        return int(self.clock.now() // 3600)

    def incr(self, key, field, by=1):
        self.store.hincrby(f"rep:{key}:{self._hour()}", field, by, ttl=self.BUCKET_TTL)

    def get(self, key):
        return self.get_many([key])[key]

    @staticmethod
    def _sum(buckets):
        total = Rep()
        for b in buckets:
            if b:
                total.sent += b.get("sent", 0)
                total.verified += b.get("verified", 0)
                total.failed += b.get("failed", 0)
                total.fast_verified += b.get("fast_verified", 0)
                total.undelivered += b.get("undelivered", 0)
        return total

    def get_many(self, keys):
        """All 24 buckets of every key in one store round trip."""
        return {k: v[0] for k, v in self.get_split(keys, 24).items()}

    def get_split(self, keys, recent_hours):
        """For each key: (total over 24 h, recent window, baseline = the rest). One round trip."""
        h = self._hour()
        hours = list(range(h - 23, h + 1))
        flat = [f"rep:{k}:{hour}" for k in keys for hour in hours]
        buckets = self.store.hgetall_many(flat)
        out = {}
        for i, k in enumerate(keys):
            mine = buckets[i * 24:(i + 1) * 24]
            recent = mine[24 - recent_hours:]
            base = mine[:24 - recent_hours]
            out[k] = (self._sum(mine), self._sum(recent), self._sum(base))
        return out

    def conversion_ratio(self, key, min_sample):
        """verified / resolved, where resolved = verified + failed (failed includes timeouts).
        Sends still inside their verification window are not counted, so a burst of fresh
        legitimate traffic is neutral rather than penalised."""
        r = self.get(key)
        resolved = r.verified + r.failed
        if resolved < min_sample:
            return None
        return r.verified / resolved

    def mark_trusted(self, key):
        self.store.sadd("rep:trusted", key)

    def is_trusted(self, key):
        return self.store.sismember("rep:trusted", key)


class AdaptiveLimits:
    """Multipliers produced by the hourly baseline job (Step 9) and per-ASN caps."""

    def __init__(self, store, floor=0.25, ceil=1.5):
        self.store = store
        self.floor, self.ceil = floor, ceil

    @staticmethod
    def _k(source, platform, cc):
        return f"adaptive:mult:{source}:{platform}:{cc}"

    def multiplier(self, source, platform, cc):
        o = self.store.get(f"adaptive:override:{source}:{platform}:{cc}")
        if o is not None:
            return float(o)
        m = self.store.get(self._k(source, platform, cc))
        return 1.0 if m is None else float(m)

    def set_marketing_override(self, source, platform, cc, m):
        self.store.set(f"adaptive:override:{source}:{platform}:{cc}", float(m))

    def recompute(self, source, platform, cc, observed, expected_median, mad, conversion):
        """One baseline-job tick for a key. Healthy traffic drifts up, abusive drifts down."""
        m = float(self.store.get(self._k(source, platform, cc)) or 1.0)
        over = observed > expected_median + 3 * mad
        bad_conv = conversion is not None and conversion < 0.3
        healthy = (conversion is None or conversion >= 0.5) and observed <= expected_median + 2 * mad
        if over or bad_conv:
            m = max(self.floor, m - 0.5)
        elif healthy:
            m = min(self.ceil, m + 0.25)
        self.store.set(self._k(source, platform, cc), m)
        return m

    def asn_limit(self, asn, default):
        v = self.store.get(f"adaptive:asn:{asn}")
        return default if v is None else int(v)

    def set_asn_limit(self, asn, limit):
        self.store.set(f"adaptive:asn:{asn}", int(limit))
