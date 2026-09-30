from dataclasses import dataclass, field


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


@dataclass
class Config:
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
    tier_bounds: tuple = (20, 40, 60, 80)
    elevated_shift: int = 10

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
