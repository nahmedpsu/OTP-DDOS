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
})
V1_FEATURES = frozenset()   # the v1 design: header-trusted platform, IP cap, reCAPTCHA, country, text, 1/min, source caps


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
    fast_verify_seconds: float = 5.0         # a code entered this soon after the send was not typed by a person
    fast_verify_min_verified: int = 20
    fast_verify_ratio: float = 0.8
    fast_verify_points: int = 15
    tier_bounds: tuple = (20, 40, 60, 80)
    elevated_shift: int = 10

    adaptive_reduction_spares_allow_tier: bool = True   # the reduced cap rations delay/downgrade tiers, not clean traffic
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
