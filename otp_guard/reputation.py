from dataclasses import dataclass


@dataclass
class Rep:
    sent: int = 0
    verified: int = 0
    failed: int = 0


class ReputationStore:
    """Rolling 24-hour counters per key, kept as hourly buckets."""

    def __init__(self, clock):
        self.clock = clock
        self.buckets = {}
        self.trusted = set()

    def _hour(self):
        return int(self.clock.now() // 3600)

    def incr(self, key, field, by=1):
        h = self._hour()
        b = self.buckets.setdefault(key, {}).setdefault(h, Rep())
        setattr(b, field, getattr(b, field) + by)

    def get(self, key):
        h = self._hour()
        total = Rep()
        for hour, b in list(self.buckets.get(key, {}).items()):
            if hour <= h - 24:
                del self.buckets[key][hour]
                continue
            total.sent += b.sent
            total.verified += b.verified
            total.failed += b.failed
        return total

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
        self.trusted.add(key)

    def is_trusted(self, key):
        return key in self.trusted


class AdaptiveLimits:
    """Multipliers produced by the hourly baseline job (Step 9) and per-ASN caps."""

    def __init__(self, floor=0.25, ceil=1.5):
        self.floor, self.ceil = floor, ceil
        self.multipliers = {}
        self.overrides = {}
        self.asn_limits = {}

    def multiplier(self, source, platform, cc):
        k = (source, platform, cc)
        if k in self.overrides:
            return self.overrides[k]
        return self.multipliers.get(k, 1.0)

    def set_marketing_override(self, source, platform, cc, m):
        self.overrides[(source, platform, cc)] = m

    def recompute(self, source, platform, cc, observed, expected_median, mad, conversion):
        """One baseline-job tick for a key. Healthy traffic drifts up, abusive drifts down."""
        k = (source, platform, cc)
        m = self.multipliers.get(k, 1.0)
        over = observed > expected_median + 3 * mad
        bad_conv = conversion is not None and conversion < 0.3
        healthy = (conversion is None or conversion >= 0.5) and observed <= expected_median + 2 * mad
        if over or bad_conv:
            m = max(self.floor, m - 0.5)
        elif healthy:
            m = min(self.ceil, m + 0.25)
        self.multipliers[k] = m
        return m

    def asn_limit(self, asn, default):
        return self.asn_limits.get(asn, default)
