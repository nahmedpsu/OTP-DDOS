import itertools

import pytest
from fastapi.testclient import TestClient

from conftest import Harness
from otp_guard.api import create_app
from otp_guard.factory import WiringReport

_n = itertools.count(1)


@pytest.fixture
def api():
    h = Harness()
    h.cfg.response_floor_ms = 0
    app = create_app(h.p, WiringReport(fake=["everything"]), trusted_proxies=["0.0.0.0/32", "10.0.0.0/8"])
    return h, TestClient(app, base_url="https://example.com")


def web_session(client):
    r = client.post("/session", json={"platform": "web", "fingerprint": "fp-web-1", "recaptcha_token": "good"})
    assert r.status_code == 200
    return r.json()["session_token"]


def otp(client, token, mobile="966501234567", ip="198.51.100.10", **extra):
    body = {"mobile": mobile, "nonce": f"n{next(_n)}", "recaptcha_token": "good"}
    body.update(extra)
    return client.post("/otp/request", json=body, headers={
        "Authorization": f"Bearer {token}", "Origin": "https://example.com", "X-Forwarded-For": ip})


def test_health_reports_wiring(api):
    h, c = api
    body = c.get("/healthz").json()
    assert body["mode"] == "normal" and body["wiring"]["fake"] == ["everything"]


def test_web_session_requires_recaptcha(api):
    h, c = api
    assert c.post("/session", json={"platform": "web", "fingerprint": "f", "recaptcha_token": "nope"}).status_code == 403
    assert c.post("/session", json={"platform": "web", "fingerprint": "f", "recaptcha_token": "low"}).status_code == 403
    assert c.post("/session", json={"platform": "tv", "fingerprint": "f"}).status_code == 403
    assert web_session(c)


def test_full_web_flow_request_then_verify(api):
    h, c = api
    tok = web_session(c)
    r = otp(c, tok)
    assert r.status_code == 200 and r.json()["status"] == "ok" and "log" not in r.json()
    assert h.sms_sent == 1
    rec = h.p.sms_history[1]
    assert rec["ip"] == "198.51.100.10" and rec["trusted_platform"] == "web"
    code = h.p.feedback.code_for(1)
    wrong = "0000" if code != "0000" else "1111"
    assert c.post("/otp/verify", json={"mobile": "+966 50 123 4567", "code": wrong}, headers={"Authorization": f"Bearer {tok}"}).json()["status"] == "invalid"
    assert c.post("/otp/verify", json={"mobile": "+966501234567", "code": code}, headers={"Authorization": f"Bearer {tok}"}).json()["status"] == "verified"
    assert h.p.rep.is_trusted("num:966501234567")


def test_rejected_and_sent_requests_are_indistinguishable(api):
    h, c = api
    tok = web_session(c)
    sent = otp(c, tok)
    rejected = otp(c, tok, mobile="14155550100")                 # country not allowed
    assert sent.status_code == rejected.status_code == 200 and sent.json() == rejected.json()
    assert h.sms_sent == 1


def test_no_session_and_spoofed_platform(api):
    h, c = api
    r = c.post("/otp/request", json={"mobile": "966501234567", "nonce": "x"}, headers={"Origin": "https://example.com"})
    assert r.status_code == 200 and r.json()["status"] == "ok" and h.sms_sent == 0      # uniform reject
    tok = web_session(c)
    r = c.post("/otp/request", json={"mobile": "966501234567", "nonce": "y", "attestation": {"platform": "ios", "valid": False}},
               headers={"Authorization": f"Bearer {tok}", "Host": "evil.net"})
    assert r.status_code == 403


def test_attested_app_session_uses_one_time_challenge(api):
    h, c = api
    ch = c.get("/attest/challenge").json()["challenge"]
    r = c.post("/session", json={"platform": "ios", "fingerprint": "fp-ios", "attestation": {"platform": "ios", "valid": True}, "challenge": ch})
    assert r.status_code == 200
    tok = r.json()["session_token"]
    replay = c.post("/session", json={"platform": "ios", "fingerprint": "fp-ios", "attestation": {"platform": "ios", "valid": True}, "challenge": ch})
    assert replay.status_code == 403
    bad = c.post("/session", json={"platform": "ios", "fingerprint": "fp-ios", "attestation": {"platform": "ios", "valid": False},
                                   "challenge": c.get("/attest/challenge").json()["challenge"]})
    assert bad.status_code == 403
    r = c.post("/otp/request", json={"mobile": "966501234567", "nonce": "n-ios", "attestation": {"platform": "ios", "valid": True}},
               headers={"Authorization": f"Bearer {tok}", "Host": "anything.local", "X-Forwarded-For": "198.51.100.77"})
    assert r.status_code == 200 and h.sms_sent == 1 and h.p.sms_history[1]["trusted_platform"] == "ios"


def test_legacy_app_session_only_during_grace(api):
    h, c = api
    r = c.post("/session", json={"platform": "android", "fingerprint": "fp-old", "app_version": "3.9"})
    assert r.status_code == 200
    h.clock.advance(31 * 86400)
    r = c.post("/session", json={"platform": "android", "fingerprint": "fp-old", "app_version": "3.9"})
    assert r.status_code == 426
    r = c.post("/session", json={"platform": "android", "fingerprint": "fp-old"})
    assert r.status_code == 426


def test_client_ip_ignores_forged_forwarded_for_from_untrusted_peer():
    from otp_guard.api import client_ip
    import ipaddress
    class Http:
        def __init__(self, host, xff): self.client = type("c", (), {"host": host})(); self.headers = {"x-forwarded-for": xff}
    trusted = [ipaddress.ip_network("10.0.0.0/8")]
    assert client_ip(Http("10.0.0.5", "1.1.1.1, 10.0.0.9"), trusted) == "1.1.1.1"
    assert client_ip(Http("203.0.113.9", "1.1.1.1"), trusted) == "203.0.113.9"      # peer not a proxy: header ignored
    assert client_ip(Http("10.0.0.5", "garbage"), trusted) == "10.0.0.5"
    assert client_ip(Http("testclient", ""), []) == "0.0.0.0"


def test_internal_timeout_tick_requires_credential(api):
    h, c = api
    assert c.post("/internal/timeouts/run").status_code == 403
    tok = web_session(c)
    otp(c, tok)
    h.clock.advance(601)
    assert c.post("/internal/timeouts/run", headers={"X-Service-Credential": "svc-secret"}).status_code == 200
    assert h.p.rep.get("num:966501234567").failed == 1
