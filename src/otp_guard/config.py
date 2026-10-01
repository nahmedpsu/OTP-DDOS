from dataclasses import dataclass, field


def default_weights():
    """Risk points per signal (Step 7). Every number here is swept in results/evaluation.md."""
    return {
        "recaptcha": 25,          # scaled by (1 - score)
        "datacenter": 15,
        "abuse": 15,              # scaled by abuse score
        "fresh_fp_5min": 20,
        "fresh_fp_1h": 10,
        "session_repeat": 5,      # per previous request in the session
        "conversion": 25,         # scaled by shortfall below the threshold
        "geo_mismatch": 10,
        "sequential_number": 15, "narrow_range_burst": 15, "elevated_prefix": 10,
        "unknown_prefix": 10, "voip_number": 10, "legacy_app": 20, "challenge_passed": -20,
        "verified_number": -20, "verified_fingerprint": -15,
    }


def default_source_limits():
    return {
        "App/RegisterOTP": {
            "per_minute_ios": 10, "per_hour_ios": 100,
            "per_minute_web": 5, "per_hour_web": 50,
            "per_minute_android": 8, "per_hour_android": 80,
            "per_minute_legacy_app": 8, "per_hour_legacy_app": 80,
            "per_country": {"968": {"per_minute_web": 2, "per_hour_web": 20}},
        }
    }


ALL_FEATURES = frozenset({
    "attestation",          # Step 0 derives platform from attestation (off: trust the header, v1 behaviour)
    "session",              # Step 1 signed session, nonce replay, per-session cap
    "network_subnet_asn",   # Step 2 subnet and ASN throttles (IP throttle is always on)
    "number_intelligence",  # Step 5b-5d prefix cost class, pattern detection, HLR
    "risk_engine",          # Step 7 (off: every request is tier allow)
    "feedback",             # conversion signals and auto-denylist
    "backoff",              # Step 8 progressive backoff and daily cap (off: fixed 1 per minute)
    "circuit_breaker",      # Step 10
    "adaptive_caps",        # Step 9 multiplier from the baseline job and the known-good exemption (off: static caps)
    "fine_destination_key", # reputation on the 8-digit destination block (the range a pumper cannot rotate)
})
# Evaluated but not a default: it needs hours of per-key history (see results/evaluation.md, section F).
OPTIONAL_FEATURES = frozenset({"relative_baseline"})
# Baseline designs the evaluation compares against (docs/evaluation.md, "Baselines"):
BASELINE_DESIGNS = {
    "v1": frozenset(),                                                    # header-trusted platform, static caps
    "v1_corrected": frozenset({"attestation"}),                           # v1 with trusted platform handling
    "budget_only": frozenset({"attestation", "session", "circuit_breaker"}),   # static caps and a hard budget, no scoring
    "block_limit_only": frozenset({"attestation", "session", "block_count_limit"}),  # a per-block daily count, no scoring
    "conversion_only": frozenset(ALL_FEATURES),                           # v2 with the speed test off (cfg.block_tests)
    "speed_only": frozenset(ALL_FEATURES),                                # v2 with the conversion test off
}
BASELINE_CFG = {"conversion_only": {"block_tests": ("conversion",)}, "speed_only": {"block_tests": ("speed",)}}
V1_FEATURES = frozenset()   # the v1 design: header-trusted platform, IP cap, reCAPTCHA, country, text, 1/min, static source caps


@dataclass
class Config:
    features: frozenset = ALL_FEATURES
    weights: dict = field(default_factory=default_weights)
    allowed_domains: tuple = ("admin.example.com", "example.com", "api.example.com", "partner.example.com")
    allowed_country_codes: tuple = ("966", "971", "965", "968")
    excluded_numbers: tuple = ()
    source_limits: dict = field(default_factory=default_source_limits)
    host: str = "example.com"

    recaptcha_min_score: float = 0.5
    recaptcha_min_score_elevated: float = 0.7

    session_ttl: int = 1800
    session_otp_limit: tuple = (3, 600)
    nonce_ttl: int = 600

    ip_limit: tuple = (5, 60)
    cgnat_asns: tuple = ()               # mobile carriers behind carrier-grade NAT: many users share one IP
    ip_limit_cgnat: tuple = (30, 60)
    subnet_limit: tuple = (30, 60)
    asn_limit_default: int = 300
    asn_datacenter_limit: int = 50

    elevated_prefix_limit: tuple = (20, 3600)
    pattern_radius: int = 5
    pattern_window: int = 600
    narrow_range_threshold: int = 10
    hlr_cache_ttl: int = 30 * 86400

    sms_max_len: int = 420
    is_test_server: bool = False

    conversion_penalty_threshold: float = 0.3
    conversion_min_sample: int = 20
    conversion_flood_min_sample: int = 100   # sustained flood on a key: many resolved sends, almost none verified
    conversion_flood_ratio: float = 0.1
    conversion_flood_points: int = 15
    destination_block_digits: int = 8         # fine destination key: first 8 digits (10 000 numbers)
    resolution_timeout_s: int = 120           # an unverified send counts as failed for reputation after this long
    conversion_recent_hours: int = 1          # relative baseline: recent window vs the rest of the 24 h history
    conversion_baseline_min_resolved: int = 200
    conversion_relative_drop: float = 0.6     # penalise when recent ratio < drop x baseline ratio
    fast_verify_seconds: float = 5.0         # a code entered this soon after the send was not typed by a person
    fast_verify_min_verified: int = 20
    fast_verify_ratio: float = 0.8
    fast_verify_points: int = 15
    # Sequential probability-ratio tests on destination blocks (keys only an attacker would dominate; legitimate
    # traffic touches a 10 000-number block a fraction of a time per day). Deny when the likelihood ratio
    # attacker:legitimate exceeds sprt_threshold.
    sprt_threshold: float = 1000.0
    sprt_legit_conversion: float = 0.8      # P(verify | real user)
    sprt_attack_conversion: float = 0.1     # P(verify | flooder)
    sprt_legit_fast: float = 0.2            # P(verify within fast_verify_seconds of delivery | real user). Set this from
                                            # the deployment's own measured distribution: with OS autofill (iOS AutoFill,
                                            # Android SMS Retriever, WebOTP) a fifth or more of real users are this fast.
    sprt_attack_fast: float = 0.9           # P(verify within fast_verify_seconds | machine)
    sprt_min_events: int = 3
    block_test: str = "cusum"               # 'cusum': evidence against the attacker hypothesis is floored at zero, so a
                                            # block cannot bank goodwill (a trust-building carrier); 'sprt': plain cumulative
    block_tests: tuple = ("conversion", "speed")
    block_count_limit: tuple = (5, 86400)   # the 'block_limit_only' baseline: sends per destination block per day
    budget_hard_ceiling: bool = True        # no SMS at all beyond the hourly budget; reserved atomically before sending
    sms_text_template: str = "Your verification code is {code}"
    # Delivery receipts. With receipts on, a send counts as failed for reputation only after the
    # carrier confirmed delivery and the resolution timeout then passed; a send with no receipt, or a
    # failed one, is 'undelivered' and feeds neither the conversion ratio nor the block tests.
    # Verification speed is clocked from the receipt, not from the send.
    delivery_receipts: bool = True
    receipt_grace_s: int = 60                 # a send with no receipt this long after the send is undelivered
    # Carrier outage detector: a conversion or delivery collapse across many destination blocks of one
    # carrier (prefix) at once is an outage, not a pumper. While it is set, block tests are suspended.
    outage_window_s: int = 600
    outage_min_sends: int = 20
    outage_undelivered_ratio: float = 0.5     # undelivered share of the carrier's recent sends
    outage_min_blocks: int = 10               # distinct blocks with a failure in the window
    outage_kg_window_s: int = 1800            # the conversion signal needs more history: known-good clients are fewer
    outage_min_known_good: int = 10           # resolved sends of clients with verified history in that window
    outage_conversion: float = 0.3            # their conversion below this: delivered but not received
    outage_ttl: int = 900
    # What a block verdict does. 'graded': first verdict makes the block's new clients solve an
    # interactive challenge (apps: non-SMS channels); a second verdict inside the TTL moves them to
    # non-SMS channels only. Clients with verified history are never affected. 'deny': the earlier
    # design, a 24-hour denylist at Step 5.
    block_action: str = "graded"
    block_verdict_ttl: int = 3600
    tier_bounds: tuple = (20, 40, 60, 80)
    elevated_shift: int = 10

    adaptive_reduction_spares_known_good: bool = True   # the reduced cap never rations clients with verified history
    per_number_base_window: int = 60
    per_number_max_window: int = 3600
    per_number_daily_cap: int = 5

    global_sms_per_hour: int = 10_000
    global_spend_units_per_hour: int = 10_000
    kill_switch: bool = False
    breaker_soft: float = 0.8

    attestation_grace_until: float = 0.0   # timestamp; tests set relative to the clock
    response_floor_ms: float = 0.0         # design default is 400; tests keep it at 0 for speed
    provider: str = "PROVIDER_A"

    denylist_ratio: float = 0.1
    denylist_min_sample: int = 50
    denylist_ttl: int = 86400
    otp_ttl: int = 600
    otp_max_attempts: int = 5
    verify_session_limit: tuple = (20, 600)
