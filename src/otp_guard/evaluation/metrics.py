"""Metric definitions. See docs/evaluation.md for the prose version.

Containment: the attack is *contained* at minute m when, for every minute >= m, leaked SMS
are at most `tail_fraction` of the attack request rate for that minute. time_to_containment
is the earliest such m (in minutes from attack start); None when the run never satisfies it.
"""
from dataclasses import dataclass, field, asdict


@dataclass
class CostModel:
    sms: float
    hlr: float
    recaptcha: float

    def total(self, sms, hlr, recaptcha):
        return sms * self.sms + hlr * self.hlr + recaptcha * self.recaptcha


def containment(leaked_per_min, attack_per_min, tail_fraction=0.05):
    n = len(leaked_per_min)
    for m in range(n):
        if all(leaked_per_min[i] <= tail_fraction * max(attack_per_min[i], 1) for i in range(m, n)):
            return m
    return None


@dataclass
class AttackMetrics:
    requests: int = 0
    leaked_total: int = 0
    time_to_containment_min: float = None       # None: never contained within the run
    leaked_before_containment: int = 0
    steady_state_leak_per_min: float = 0.0      # mean leaked per minute after containment (or last 5 min if never)
    contained: bool = False
    hlr_calls: int = 0
    recaptcha_calls: int = 0
    cost_usd: float = 0.0
    leaked_per_min: list = field(default_factory=list)
    stopped_by: dict = field(default_factory=dict)

    @staticmethod
    def build(leaked_per_min, attack_per_min, hlr_calls, recaptcha_calls, cost_model, stopped_by, tail_fraction=0.05):
        """time_to_containment_min is None for an uncontained run (a censored observation: the run
        ended first). steady_state_leak_per_min is the mean leakage per minute after containment, or
        over the final five minutes of an uncontained run; it is a late-window rate, not evidence of
        stationarity."""
        m = containment(leaked_per_min, attack_per_min, tail_fraction)
        total = sum(leaked_per_min)
        if m is None:
            tail = leaked_per_min[-5:] or [0]
            steady = sum(tail) / len(tail)
            before = total
        else:
            after = leaked_per_min[m:]
            steady = sum(after) / len(after) if after else 0.0
            before = sum(leaked_per_min[:m])
        return AttackMetrics(
            requests=sum(attack_per_min), leaked_total=total, time_to_containment_min=m,
            leaked_before_containment=before, steady_state_leak_per_min=steady, contained=m is not None,
            hlr_calls=hlr_calls, recaptcha_calls=recaptcha_calls,
            cost_usd=cost_model.total(total, hlr_calls, recaptcha_calls),
            leaked_per_min=list(leaked_per_min), stopped_by=dict(stopped_by))


@dataclass
class FrictionGroup:
    """Outcomes for one legitimate population. users: requests offered (counted before the session
    gate). dispatched: a channel was chosen and the message handed to the sender. delivered: the
    provider's receipt said delivered. completed: the person entered the code. refused: lost at the
    gate, rejected by a hard step, downgraded with no channel, or undelivered (refused_by names the
    stage). Subgroup counters add up to the whole and completed <= delivered <= dispatched <= users."""
    users: int = 0
    dispatched: int = 0
    delivered: int = 0
    completed: int = 0
    challenged: int = 0
    refused: int = 0
    refused_by: dict = field(default_factory=dict)     # gate | step | no_channel | undelivered -> count
    delayed: int = 0
    added_delay_s_total: float = 0.0
    by_channel: dict = field(default_factory=dict)
    dispatched_pct: float = 0.0
    delivered_pct: float = 0.0
    completed_pct: float = 0.0
    challenge_rate_pct: float = 0.0
    refusal_rate_pct: float = 0.0
    mean_added_delay_s: float = 0.0

    def finish(self):
        u = max(self.users, 1)
        self.dispatched_pct = 100.0 * self.dispatched / u
        self.delivered_pct = 100.0 * self.delivered / u
        self.completed_pct = 100.0 * self.completed / u
        self.challenge_rate_pct = 100.0 * self.challenged / u
        self.refusal_rate_pct = 100.0 * self.refused / u
        self.mean_added_delay_s = self.added_delay_s_total / max(self.dispatched, 1)
        return self


@dataclass
class FrictionMetrics(FrictionGroup):
    """All legitimate requests, plus the same outcomes for first-time clients (no verified history)
    and returning clients (a fingerprint that verified before)."""
    first_time: FrictionGroup = field(default_factory=FrictionGroup)
    returning: FrictionGroup = field(default_factory=FrictionGroup)

    def finish(self):
        super().finish()
        self.first_time.finish()
        self.returning.finish()
        return self


def as_dict(m):
    return asdict(m)
