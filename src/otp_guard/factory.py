"""Build a Pipeline from environment variables. Every external component that has no
configuration falls back to its in-memory fake, and the returned WiringReport says which
ones did, so a deployment can refuse to start with anything fake in production."""
import datetime as _dt
import json
import os
from dataclasses import dataclass, field

from .config import Config
from .pipeline import Pipeline
from .services import Services, PrefixTable
from .store import MemoryStore, RedisStore, SystemClock


@dataclass
class WiringReport:
    real: dict = field(default_factory=dict)     # component -> class name
    fake: list = field(default_factory=list)     # components still on fakes
    notes: list = field(default_factory=list)

    def is_production_ready(self):
        return not self.fake


def _csv(v):
    return tuple(x.strip() for x in v.split(",") if x.strip()) if v else None


def _grace_ts(v):
    if not v:
        return 0.0
    try:
        return float(v)
    except ValueError:
        return _dt.datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()


def build_config(env):
    cfg = Config()
    if env.get("ALLOWED_DOMAINS"):
        cfg.allowed_domains = _csv(env["ALLOWED_DOMAINS"])
    if env.get("ALLOWED_COUNTRY_CODES"):
        cfg.allowed_country_codes = _csv(env["ALLOWED_COUNTRY_CODES"])
    if env.get("EXCLUDED_NUMBERS"):
        cfg.excluded_numbers = _csv(env["EXCLUDED_NUMBERS"])
    if env.get("HOST"):
        cfg.host = env["HOST"]
    if env.get("CGNAT_ASNS"):
        cfg.cgnat_asns = _csv(env["CGNAT_ASNS"])
    if env.get("SOURCE_LIMITS_PATH"):
        with open(env["SOURCE_LIMITS_PATH"]) as f:
            cfg.source_limits = json.load(f)
    for name, attr, cast in [
        ("RECAPTCHA_MIN_SCORE", "recaptcha_min_score", float),
        ("GLOBAL_SMS_PER_HOUR", "global_sms_per_hour", int),
        ("GLOBAL_SPEND_UNITS_PER_HOUR", "global_spend_units_per_hour", int),
        ("RESPONSE_FLOOR_MS", "response_floor_ms", float),
        ("SMS_PROVIDER", "provider", str),
    ]:
        if env.get(name):
            setattr(cfg, attr, cast(env[name]))
    cfg.kill_switch = env.get("SMS_KILL_SWITCH", "").lower() in ("1", "true", "yes", "on")
    cfg.is_test_server = env.get("IS_TEST_SERVER", "").lower() in ("1", "true", "yes", "on")
    cfg.attestation_grace_until = _grace_ts(env.get("ATTESTATION_GRACE_UNTIL"))
    if "RESPONSE_FLOOR_MS" not in env:
        cfg.response_floor_ms = 400.0       # the design default; tests override to 0
    return cfg


def build_pipeline(env=None):
    env = dict(os.environ if env is None else env)
    report = WiringReport()
    cfg = build_config(env)
    svc = Services()
    clock = SystemClock()

    # ---- store ----
    if env.get("REDIS_URL"):
        import redis
        store = RedisStore(redis.Redis.from_url(env["REDIS_URL"]), clock)
        report.real["store"] = "RedisStore"
    else:
        store = MemoryStore(clock)
        report.fake.append("store")

    # ---- prefix table ----
    if env.get("PREFIX_TABLE_PATH"):
        table = PrefixTable()
        with open(env["PREFIX_TABLE_PATH"]) as f:
            for row in json.load(f):
                table.add(row["prefix"], row.get("class", "standard"), int(row.get("cost_units", 1)))
        svc.prefixes = table
        report.real["prefixes"] = f"PrefixTable({len(table.entries)} entries)"
    else:
        report.fake.append("prefixes")
        report.notes.append("No PREFIX_TABLE_PATH: every number is class 'unknown' (+10 risk) and premium ranges are not blocked.")

    # ---- reCAPTCHA ----
    if env.get("RECAPTCHA_SECRET"):
        from .providers.recaptcha import GoogleRecaptcha
        svc.recaptcha = GoogleRecaptcha(env["RECAPTCHA_SECRET"], expected_action=env.get("RECAPTCHA_ACTION"),
                                        expected_hostnames=_csv(env.get("RECAPTCHA_HOSTNAMES")))
        report.real["recaptcha"] = "GoogleRecaptcha"
    else:
        report.fake.append("recaptcha")

    # ---- attestation ----
    from .providers.attestation import (AppAttestKeyStore, AppAttestVerifier, CompositeAttestationVerifier,
                                        GoogleServiceAccountTokenProvider, PlayIntegrityVerifier)
    verifiers = {}
    google_token = None
    if env.get("GOOGLE_APPLICATION_CREDENTIALS"):
        google_token = GoogleServiceAccountTokenProvider(
            env["GOOGLE_APPLICATION_CREDENTIALS"],
            ["https://www.googleapis.com/auth/playintegrity", "https://www.googleapis.com/auth/firebase.messaging"])
    if env.get("PLAY_INTEGRITY_PACKAGE") and google_token:
        verifiers["android"] = PlayIntegrityVerifier(env["PLAY_INTEGRITY_PACKAGE"], google_token)
    if env.get("APP_ATTEST_APP_ID"):
        verifiers["ios"] = AppAttestVerifier(env["APP_ATTEST_APP_ID"], AppAttestKeyStore(store))
    if verifiers:
        svc.attestation = CompositeAttestationVerifier(verifiers)
        report.real["attestation"] = "CompositeAttestationVerifier(" + ",".join(sorted(verifiers)) + ")"
        for p in ("ios", "android"):
            if p not in verifiers:
                report.notes.append(f"No attestation verifier for {p}: its attestations will be rejected.")
    else:
        report.fake.append("attestation")

    # ---- IP intelligence and proxy detection ----
    if env.get("IPINFO_TOKEN"):
        from .providers.ip_intel import IpinfoIntel, AbuseIpdbIntel, CompositeIpIntel, IpIntelProxyDetector
        intel = IpinfoIntel(env["IPINFO_TOKEN"], store=store)
        if env.get("ABUSEIPDB_KEY"):
            intel = CompositeIpIntel(intel, AbuseIpdbIntel(env["ABUSEIPDB_KEY"]))
        svc.ip_intel = intel
        svc.proxy = IpIntelProxyDetector(intel)
        report.real["ip_intel"] = type(intel).__name__
        report.real["proxy"] = "IpIntelProxyDetector"
    else:
        report.fake += ["ip_intel", "proxy"]

    # ---- HLR ----
    twilio = env.get("TWILIO_ACCOUNT_SID") and env.get("TWILIO_AUTH_TOKEN")
    if twilio:
        from .providers.hlr import TwilioLookup
        svc.hlr = TwilioLookup(env["TWILIO_ACCOUNT_SID"], env["TWILIO_AUTH_TOKEN"])
        report.real["hlr"] = "TwilioLookup"
    else:
        report.fake.append("hlr")

    # ---- senders ----
    from .providers.senders import RoutingSender, TwilioMessaging, FcmPush
    providers, channels = {}, {}
    if twilio and (env.get("TWILIO_FROM") or env.get("TWILIO_MESSAGING_SERVICE_SID")):
        tm = TwilioMessaging(env["TWILIO_ACCOUNT_SID"], env["TWILIO_AUTH_TOKEN"], from_number=env.get("TWILIO_FROM"),
                             messaging_service_sid=env.get("TWILIO_MESSAGING_SERVICE_SID"),
                             whatsapp_from=env.get("TWILIO_WHATSAPP_FROM"),
                             status_callback=env.get("TWILIO_STATUS_CALLBACK"))
        providers[cfg.provider] = tm.send_sms
        if env.get("TWILIO_WHATSAPP_FROM"):
            channels["whatsapp"] = tm.send_whatsapp
    if env.get("FCM_PROJECT_ID") and google_token:
        push = FcmPush(env["FCM_PROJECT_ID"], google_token, device_token_lookup=lambda mobile: store.get(f"push:token:{mobile}"))
        channels["push"] = push.send_push
    if providers or channels:
        def on_result(log_id, channel, ok, detail):
            store.set(f"smslog:delivery:{log_id}", {"channel": channel, "ok": ok, "detail": str(detail)[:500]}, 30 * 86400)
        svc.sender = RoutingSender(providers, channels, on_result=on_result)
        report.real["sender"] = "RoutingSender(sms=" + ",".join(providers) + "; channels=" + ",".join(channels) + ")"
        if not providers:
            report.notes.append("No SMS provider configured: SMS-tier sends will be logged as failed.")
    else:
        report.fake.append("sender")

    # ---- alerts ----
    from .providers.alerts import LoggingAlerts, SlackWebhookAlerts, MultiAlerts
    sinks = [LoggingAlerts()]
    if env.get("SLACK_ALERT_WEBHOOK"):
        sinks.append(SlackWebhookAlerts(env["SLACK_ALERT_WEBHOOK"]))
        report.real["alerts"] = "Slack+log"
    else:
        report.real["alerts"] = "log"
    svc.alerts = MultiAlerts(sinks)

    # ---- internal credentials, session key ----
    svc.internal_credentials = set(_csv(env.get("INTERNAL_SERVICE_CREDENTIALS")) or ())
    if not svc.internal_credentials:
        report.notes.append("No INTERNAL_SERVICE_CREDENTIALS: bulk and test-server bypasses are disabled (safe).")
    session_key = env.get("SESSION_HMAC_KEY", "").encode()
    if not session_key:
        import secrets
        session_key = secrets.token_bytes(32)
        report.notes.append("No SESSION_HMAC_KEY: generated a random key; sessions will not survive a restart or span instances.")

    pipeline = Pipeline(cfg, svc, clock, store=store, session_key=session_key)
    return pipeline, report
