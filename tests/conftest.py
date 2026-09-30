import itertools
import pytest

from otp_guard import Clock, Config, Pipeline, Request
from otp_guard.services import Services, IpInfo

_nonce = itertools.count(1)


class Harness:
    """Builds requests that pass every step unless a test breaks something on purpose."""

    def __init__(self, cfg=None):
        self.clock = Clock()
        self.cfg = cfg or Config()
        if self.cfg.attestation_grace_until == 0.0:
            self.cfg.attestation_grace_until = self.clock.now() + 30 * 86400
        self.svc = Services()
        self.svc.recaptcha.scores["good"] = 0.9
        self.svc.recaptcha.scores["low"] = 0.3
        self.svc.recaptcha.scores["mid"] = 0.6
        self.svc.recaptcha.scores["challenge-ok"] = 0.9
        self.svc.prefixes.add("96650", "standard", 1)
        self.svc.prefixes.add("96655", "standard", 1)
        self.svc.prefixes.add("97150", "standard", 1)
        self.svc.prefixes.add("96590", "standard", 1)
        self.svc.prefixes.add("96890", "standard", 1)
        self.svc.prefixes.add("96699", "premium", 12)
        self.svc.prefixes.add("97159", "elevated", 3)
        self.p = Pipeline(self.cfg, self.svc, self.clock)
        self._fp = itertools.count(1)

    # ---- sessions ----
    def session(self, platform="web", fingerprint=None, age_hours=2.0):
        fp = fingerprint or f"fp{next(self._fp)}"
        tok = self.p.sessions.issue(platform, fp, self.cfg.session_ttl)
        if age_hours:
            # pretend the fingerprint was first seen earlier so tests start with a mature client
            self.p.sessions.first_seen[fp] = self.clock.now() - age_hours * 3600
        return tok, fp

    # ---- requests ----
    def lift_source_caps(self):
        """For step-focused tests that need more than the web cap of 5 sends a minute."""
        sl = self.cfg.source_limits["App/RegisterOTP"]
        for k in list(sl):
            if k.startswith("per_minute_") or k.startswith("per_hour_"):
                sl[k] = 100000
        sl["per_country"] = {}
        return self

    def web_request(self, mobile="966501234567", session=None, recaptcha="good", **kw):
        tok = self.session("web")[0] if session is None else session
        kw.setdefault("post", {"g-recaptcha-response": recaptcha})
        return Request(mobile=mobile, session_token=tok, nonce=f"n{next(_nonce)}", **kw)

    def app_request(self, platform="ios", mobile="966501234567", session=None, valid=True, host="app.local", **kw):
        tok = self.session(platform)[0] if session is None else session
        return Request(mobile=mobile, session_token=tok, nonce=f"n{next(_nonce)}",
                       header_platform=platform, app_version="5.2.0", host=host,
                       attestation={"platform": platform, "valid": valid}, **kw)

    def legacy_app_request(self, platform="ios", mobile="966501234567", session=None, **kw):
        tok = self.session("legacy_app")[0] if session is None else session
        return Request(mobile=mobile, session_token=tok, nonce=f"n{next(_nonce)}",
                       header_platform=platform, app_version="4.0.0", host="app.local", **kw)

    def send(self, req):
        return self.p.process(req)

    @property
    def sms_sent(self):
        return len(self.svc.sender.by_channel("sms"))


@pytest.fixture
def h():
    return Harness()
