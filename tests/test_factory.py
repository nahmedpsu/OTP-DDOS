from otp_guard.factory import build_pipeline, build_config


def test_empty_env_builds_all_fakes_and_reports_them():
    p, report = build_pipeline({})
    assert not report.is_production_ready()
    for comp in ("store", "recaptcha", "attestation", "ip_intel", "proxy", "hlr", "sender", "prefixes"):
        assert comp in report.fake
    assert p.cfg.response_floor_ms == 400.0 and p.cfg.kill_switch is False
    assert any("SESSION_HMAC_KEY" in n for n in report.notes)


def test_full_env_wires_real_adapters(tmp_path):
    prefixes = tmp_path / "prefixes.json"
    prefixes.write_text('[{"prefix": "96650"}, {"prefix": "96699", "class": "premium", "cost_units": 12}]')
    limits = tmp_path / "limits.json"
    limits.write_text('{"App/RegisterOTP": {"per_minute_web": 3, "per_hour_web": 30}}')
    env = {
        "REDIS_URL": "redis://localhost:6379/0", "SESSION_HMAC_KEY": "k" * 32,
        "RECAPTCHA_SECRET": "rs", "RECAPTCHA_ACTION": "otp", "RECAPTCHA_HOSTNAMES": "example.com,app.example.com",
        "APP_ATTEST_APP_ID": "TEAM.com.example", "IPINFO_TOKEN": "ip", "ABUSEIPDB_KEY": "ab",
        "TWILIO_ACCOUNT_SID": "AC", "TWILIO_AUTH_TOKEN": "tok", "TWILIO_FROM": "+1555", "TWILIO_WHATSAPP_FROM": "+1556",
        "SLACK_ALERT_WEBHOOK": "https://hooks/x", "INTERNAL_SERVICE_CREDENTIALS": "svc-1,svc-2",
        "PREFIX_TABLE_PATH": str(prefixes), "SOURCE_LIMITS_PATH": str(limits),
        "ALLOWED_COUNTRY_CODES": "966,971", "HOST": "otp.example.com", "SMS_KILL_SWITCH": "false",
        "ATTESTATION_GRACE_UNTIL": "2030-01-01T00:00:00Z", "GLOBAL_SMS_PER_HOUR": "5000", "RESPONSE_FLOOR_MS": "350",
    }
    p, report = build_pipeline(env)
    assert report.is_production_ready(), report.fake
    assert report.real["store"] == "RedisStore" and report.real["recaptcha"] == "GoogleRecaptcha"
    assert report.real["attestation"] == "CompositeAttestationVerifier(ios)"
    assert report.real["ip_intel"] == "CompositeIpIntel" and report.real["hlr"] == "TwilioLookup"
    assert "whatsapp" in report.real["sender"] and "PROVIDER_A" in report.real["sender"]
    assert any("android" in n for n in report.notes)          # no Play Integrity configured
    assert p.svc.prefixes.lookup("966991234567").cls == "premium"
    assert p.cfg.source_limits["App/RegisterOTP"]["per_minute_web"] == 3
    assert p.cfg.allowed_country_codes == ("966", "971") and p.cfg.host == "otp.example.com"
    assert p.cfg.attestation_grace_until > 1.8e9 and p.cfg.global_sms_per_hour == 5000 and p.cfg.response_floor_ms == 350
    assert p.svc.internal_credentials == {"svc-1", "svc-2"}


def test_kill_switch_and_grace_parsing():
    cfg = build_config({"SMS_KILL_SWITCH": "1", "ATTESTATION_GRACE_UNTIL": "1900000000"})
    assert cfg.kill_switch is True and cfg.attestation_grace_until == 1900000000.0
