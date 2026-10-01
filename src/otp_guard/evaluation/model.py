"""Closed-form leakage model for a pumper under the destination-block tests.

Leakage depends on the number of 8-digit blocks the pumper touches (B), not on how many
numbers it uses. Each block costs the defender k sends before its verdict, plus whatever is
still in flight when the verdicts land:

    leak(no verifying carrier)  ~= min(N, k_conv * B + lambda * (tau_res + tau_dlv + tau_sched / 2))
    leak(instant verifier)      ~= min(N, k_fast * B + lambda * (tau_dlv + tau_verify))

with N the attacker's requests, lambda its rate, tau_res the resolution timeout, tau_dlv the
delivery delay and k the sends a sequential test needs to reach its threshold when every send
goes the attacker's way. A carrier can evade the conversion test by verifying at least s*
of its codes, at the price of s* verified fake accounts per pumped SMS.
"""
import math


def sends_to_verdict(cfg):
    thr = math.log(cfg.sprt_threshold)
    per_fail = math.log((1 - cfg.sprt_attack_conversion) / (1 - cfg.sprt_legit_conversion))
    per_fast = math.log(cfg.sprt_attack_fast / cfg.sprt_legit_fast)
    k_conv = max(cfg.sprt_min_events, math.ceil(thr / per_fail))
    k_fast = max(cfg.sprt_min_events, math.ceil(thr / per_fast))
    return k_conv, k_fast


def evasion_share(cfg):
    """Verified share above which the conversion test drifts away from a verdict."""
    per_fail = math.log((1 - cfg.sprt_attack_conversion) / (1 - cfg.sprt_legit_conversion))
    per_verify = math.log(cfg.sprt_attack_conversion / cfg.sprt_legit_conversion)   # negative
    return per_fail / (per_fail - per_verify)


def predicted_leak(cfg, blocks_touched, rate_per_min, requests, verifying, delivery_s=3.0, verify_delay_s=1.0,
                   scheduler_period_s=60.0):
    """scheduler_period_s: the worker that resolves timeouts runs this often, so a timeout lands on
    average half a period late."""
    k_conv, k_fast = sends_to_verdict(cfg)
    if verifying:
        inflight = rate_per_min * (delivery_s + verify_delay_s) / 60.0
        return min(requests, k_fast * blocks_touched + inflight)
    inflight = rate_per_min * (cfg.resolution_timeout_s + delivery_s + scheduler_period_s / 2) / 60.0
    return min(requests, k_conv * blocks_touched + inflight)


def blocks_touched(n_ranges, range_digits, key_digits=8):
    """Nominal distinct key blocks for n distinct ranges of 10^(12 - range_digits) numbers. The
    evaluation reports and uses the observed count of blocks actually requested instead, since a
    finite attack does not touch every block of a wide range."""
    return n_ranges * max(1, 10 ** (key_digits - range_digits))
