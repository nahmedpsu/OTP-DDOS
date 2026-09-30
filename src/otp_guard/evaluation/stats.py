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
