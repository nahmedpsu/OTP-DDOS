import math

import numpy as np
from scipy import stats as sps


def mean_ci(values, confidence=0.95):
    """Mean with a t-based confidence interval. Returns (mean, lo, hi, n)."""
    x = np.asarray([v for v in values if v is not None], dtype=float)
    n = len(x)
    if n == 0:
        return (None, None, None, 0)
    m = float(x.mean())
    if n == 1:
        return (m, m, m, 1)
    se = float(x.std(ddof=1)) / math.sqrt(n)
    h = sps.t.ppf((1 + confidence) / 2, n - 1) * se
    return (m, m - h, m + h, n)


_BOOT = 2000


def boot_ci(values, confidence=0.95, seed=12345):
    """Mean with a percentile-bootstrap interval over the runs (seeds). Returns (mean, lo, hi, n).
    The interval stays inside the range of the data, so a nonnegative quantity never gets a negative
    bound; with a handful of seeds it is still only as good as those seeds."""
    x = np.asarray([v for v in values if v is not None], dtype=float)
    n = len(x)
    if n == 0:
        return (None, None, None, 0)
    m = float(x.mean())
    if n == 1 or np.all(x == x[0]):
        return (m, m, m, n)
    rng = np.random.default_rng(seed + n)
    means = x[rng.integers(0, n, size=(_BOOT, n))].mean(axis=1)
    lo, hi = np.quantile(means, [(1 - confidence) / 2, (1 + confidence) / 2])
    return (m, float(lo), float(hi), n)


def tail(values):
    """Distribution summary across runs: median, 90th percentile and maximum."""
    x = np.asarray([v for v in values if v is not None], dtype=float)
    if len(x) == 0:
        return {"p50": None, "p90": None, "max": None, "n": 0}
    return {"p50": float(np.quantile(x, 0.5)), "p90": float(np.quantile(x, 0.9)), "max": float(x.max()), "n": int(len(x))}


def fmt_ci(values, digits=1):
    m, lo, hi, n = mean_ci(values)
    if m is None:
        return "n/a"
    return f"{m:.{digits}f} [{lo:.{digits}f}, {hi:.{digits}f}]"


def fraction_ci(successes, n, confidence=0.95):
    """Wilson interval for a proportion."""
    if n == 0:
        return (None, None, None)
    z = sps.norm.ppf((1 + confidence) / 2)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (p, centre - half, centre + half)


def ks_2samp(a, b):
    r = sps.ks_2samp(a, b)
    return float(r.statistic), float(r.pvalue)


def tost_mean_diff(a, b, margin):
    """Two one-sided t-tests: H0 |mean(a) - mean(b)| >= margin. Small p means equivalent within the margin."""
    a, b = np.asarray(a, float), np.asarray(b, float)
    diff = float(a.mean() - b.mean())
    se = math.sqrt(a.var(ddof=1) / len(a) + b.var(ddof=1) / len(b))
    df = len(a) + len(b) - 2
    p_lower = 1 - sps.t.cdf((diff + margin) / se, df)      # H0: diff <= -margin
    p_upper = sps.t.cdf((diff - margin) / se, df)          # H0: diff >= +margin
    return {"mean_diff": diff, "p_value": float(max(p_lower, p_upper)), "margin": margin}


def variance_components(groups, seed=12345):
    """One-way random-effects decomposition for a nested design: groups = [[values of the simulation
    seeds of one attacker configuration], ...], equal sizes. Returns the between-configuration and
    within-configuration (simulation noise) variance components (ANOVA estimators, the between part
    truncated at 0), the share of the between part, and a percentile-bootstrap interval for that
    share obtained by resampling configurations."""
    g = [np.asarray(x, float) for x in groups]
    k, m = len(g), len(g[0])
    assert k >= 2 and m >= 2 and all(len(x) == m for x in g)

    def comps(gs):
        means = np.array([x.mean() for x in gs])
        msw = float(np.mean([x.var(ddof=1) for x in gs]))
        msb = float(m * means.var(ddof=1))
        between = max(0.0, (msb - msw) / m)
        tot = between + msw
        return between, msw, (between / tot if tot > 0 else 0.0)
    between, within, share = comps(g)
    rng = np.random.default_rng(seed)
    shares = [comps([g[i] for i in rng.integers(0, k, size=k)])[2] for _ in range(_BOOT)]
    lo, hi = np.quantile(shares, [0.025, 0.975])
    return {"configs": k, "sims_per_config": m, "between_var": between, "within_var": within,
            "between_share": share, "between_share_ci": (float(lo), float(hi))}
