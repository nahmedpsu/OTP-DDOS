"""The adaptive baseline job of Step 9, as the default worker runs it.

Every tick (one minute) it reads, for each active (source, platform, country) key, the
number of requests that reached the source cap in the last full minute (Pipeline.record_volume),
compares it with the key's expected rate for this hour of the week, and calls
AdaptiveLimits.recompute with that observation, the key's conversion ratio and the deviation.

The expected rate is the median of the key's per-minute mean for the same hour of the week
over the last `weeks` weeks; the MAD is the median absolute deviation of those samples. Until
a key has at least two weekly samples, the mean of the closed hours recorded in the last 24
(however many there are: one, after the first hour) stands in, with 25 % of it as the deviation;
with no closed hour at all the job leaves the static cap alone. Hourly samples are written at
each hour boundary from the minute counters. The job learns from every request that reached
Step 9, accepted or refused, so a sustained attack raises the profile it learns from: the
evaluation measures that (section B3).
"""
import statistics


class BaselineJob:
    def __init__(self, pipeline, weeks=4):
        self.p = pipeline
        self.weeks = weeks
        self._last_hour = {}

    @staticmethod
    def _hour_of_week(ts):
        import datetime as dt
        d = dt.datetime.utcfromtimestamp(ts)
        return d.weekday() * 24 + d.hour

    def _minute_count(self, key, minute):
        return int(self.p.store.get(f"vol:{key}:{minute}") or 0)

    def _hour_sum(self, key, hour_index):
        return int(self.p.store.get(f"volh:{key}:{hour_index}") or 0)

    def _close_hour(self, key, hour_index):
        """Write the per-minute mean of a finished hour as this week's sample for that hour of the week."""
        total = sum(self._minute_count(key, m) for m in range(hour_index * 60, hour_index * 60 + 60))
        self.p.store.set(f"volh:{key}:{hour_index}", total, 2 * 86400)
        how = self._hour_of_week(hour_index * 3600)
        pk = f"profile:{key}:{how}"
        samples = list(self.p.store.get(pk) or [])
        samples.append(total / 60.0)
        self.p.store.set(pk, samples[-self.weeks:], (self.weeks + 1) * 7 * 86400)

    def expected(self, key, now):
        how = self._hour_of_week(now)
        samples = list(self.p.store.get(f"profile:{key}:{how}") or [])
        if len(samples) >= 2:
            med = statistics.median(samples)
            mad = statistics.median(abs(s - med) for s in samples)
            return med, max(mad, 0.05 * med, 0.5)
        hour_index = int(now // 3600)
        closed = [self._hour_sum(key, h) for h in range(hour_index - 24, hour_index)
                  if self.p.store.exists(f"volh:{key}:{h}")]          # only hours that were actually recorded
        if not closed:
            return None, None                                        # cold start: no history, the static cap stands
        mean = sum(closed) / (len(closed) * 60.0)
        if mean <= 0:
            return None, None
        return mean, max(0.25 * mean, 0.5)

    def tick(self):
        now = self.p.clock.now()
        minute = int(now // 60)
        hour_index = int(now // 3600)
        for key in self.p.store.smembers("vol:keys"):
            last = self._last_hour.get(key)
            if last is not None and hour_index > last:
                for h in range(last, hour_index):
                    self._close_hour(key, h)
            self._last_hour[key] = hour_index
            observed = self._minute_count(key, minute - 1)
            med, mad = self.expected(key, now)
            if med is None:
                continue
            source, platform, cc = key.split("|")
            conv = self.p.rep.conversion_ratio("country:" + cc, self.p.cfg.conversion_min_sample)
            self.p.adaptive.recompute(source, platform, cc, observed=observed, expected_median=med, mad=mad, conversion=conv)
