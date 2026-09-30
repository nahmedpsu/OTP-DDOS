import base64
import hashlib
import json

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from fakes import FakeSession
from otp_guard.store import Clock, MemoryStore
from otp_guard.providers.recaptcha import GoogleRecaptcha
from otp_guard.providers.attestation import (AppAttestKeyStore, AppAttestVerifier, CompositeAttestationVerifier,
                                             PlayIntegrityVerifier, _b64url)
from otp_guard.providers.ip_intel import IpinfoIntel, AbuseIpdbIntel, CompositeIpIntel, IpIntelProxyDetector
from otp_guard.providers.hlr import TwilioLookup
from otp_guard.providers.senders import TwilioMessaging, HttpSmsProvider, FcmPush, RoutingSender
from otp_guard.providers.alerts import SlackWebhookAlerts, MultiAlerts, LoggingAlerts


# ---------------- reCAPTCHA ----------------

def test_recaptcha_maps_success_and_score():
    s = FakeSession().respond({"success": True, "score": 0.7, "action": "otp", "hostname": "example.com"})
    r = GoogleRecaptcha("secret", s, expected_action="otp", expected_hostnames=["example.com"])
    assert r.verify({"g-recaptcha-response": "tok"}) == {"valid": True, "score": 0.7}
    method, url, kw = s.calls[0]
    assert method == "POST" and "siteverify" in url and kw["data"] == {"secret": "secret", "response": "tok"}


def test_recaptcha_rejects_wrong_action_or_hostname_and_fails_closed():
    s = FakeSession().respond({"success": True, "score": 0.9, "action": "login", "hostname": "example.com"})
    assert GoogleRecaptcha("k", s, expected_action="otp").verify({"g-recaptcha-response": "t"})["valid"] is False
    s = FakeSession().respond({"success": True, "score": 0.9, "action": "otp", "hostname": "evil.net"})
    assert GoogleRecaptcha("k", s, expected_hostnames=["example.com"]).verify({"g-recaptcha-response": "t"})["valid"] is False
    s = FakeSession(); s.fail_with = ConnectionError("down")
    res = GoogleRecaptcha("k", s).verify({"g-recaptcha-response": "t"})
    assert res["valid"] is False and res.get("error") == "unavailable"
    assert GoogleRecaptcha("k", FakeSession()).verify({}) == {"valid": False, "score": 0.0}


# ---------------- Play Integrity ----------------

def _integrity_payload(nonce, **over):
    payload = {
        "requestDetails": {"requestPackageName": "com.example.app", "nonce": _b64url(nonce.encode())},
        "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED"},
        "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
        "accountDetails": {"appLicensingVerdict": "LICENSED"},
    }
    for k, v in over.items():
        payload[k] = v
    return {"tokenPayloadExternal": payload}


def test_play_integrity_accepts_good_verdict_and_sends_bearer():
    s = FakeSession().respond(_integrity_payload("nonce-1"))
    v = PlayIntegrityVerifier("com.example.app", lambda: "access-token", s)
    res = v.verify({"platform": "android", "token": "integrity-token"}, "nonce-1")
    assert res.valid and res.platform == "android"
    _, url, kw = s.calls[0]
    assert url.endswith("com.example.app:decodeIntegrityToken")
    assert kw["headers"]["Authorization"] == "Bearer access-token" and kw["json"] == {"integrity_token": "integrity-token"}


@pytest.mark.parametrize("override", [
    {"requestDetails": {"requestPackageName": "com.other.app", "nonce": _b64url(b"nonce-1")}},
    {"requestDetails": {"requestPackageName": "com.example.app", "nonce": _b64url(b"other")}},
    {"deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY"]}},
    {"appIntegrity": {"appRecognitionVerdict": "UNRECOGNIZED_VERSION"}},
    {"accountDetails": {"appLicensingVerdict": "UNLICENSED"}},
])
def test_play_integrity_rejects_bad_verdicts(override):
    s = FakeSession().respond(_integrity_payload("nonce-1", **override))
    v = PlayIntegrityVerifier("com.example.app", lambda: "t", s)
    assert v.verify({"platform": "android", "token": "x"}, "nonce-1").valid is False


def test_play_integrity_fails_closed_when_google_is_down():
    s = FakeSession(); s.fail_with = TimeoutError()
    assert PlayIntegrityVerifier("com.example.app", lambda: "t", s).verify({"platform": "android", "token": "x"}, "n").valid is False


# ---------------- App Attest ----------------

APP_ID = "TEAMID1234.com.example.app"


def _assertion(priv, nonce, counter, app_id=APP_ID, tamper=False):
    client_data = json.dumps({"challenge": nonce}).encode()
    auth_data = hashlib.sha256(app_id.encode()).digest() + b"\x40" + counter.to_bytes(4, "big")
    to_sign = hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest()
    sig = priv.sign(to_sign, ec.ECDSA(hashes.SHA256()))
    if tamper:
        sig = sig[:-1] + bytes([sig[-1] ^ 1])
    blob = cbor2.dumps({"signature": sig, "authenticatorData": auth_data})
    return {"platform": "ios", "key_id": "key-1", "assertion": base64.b64encode(blob).decode(),
            "client_data": base64.b64encode(client_data).decode()}


@pytest.fixture
def attest():
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    keys = AppAttestKeyStore(MemoryStore(Clock()))
    keys.register_key("key-1", pem)
    return priv, AppAttestVerifier(APP_ID, keys), keys


def test_app_attest_valid_assertion_and_counter_advances(attest):
    priv, v, keys = attest
    res = v.verify(_assertion(priv, "n1", counter=1), "n1")
    assert res.valid and res.platform == "ios" and keys.counter("key-1") == 1
    assert v.verify(_assertion(priv, "n2", counter=2), "n2").valid


def test_app_attest_rejects_replay_wrong_nonce_bad_signature_wrong_app_unknown_key(attest):
    priv, v, keys = attest
    assert v.verify(_assertion(priv, "n1", counter=5), "n1").valid
    assert v.verify(_assertion(priv, "n2", counter=5), "n2").valid is False          # counter not advancing = replay
    assert v.verify(_assertion(priv, "n3", counter=6), "different").valid is False   # challenge mismatch
    assert v.verify(_assertion(priv, "n4", counter=7, tamper=True), "n4").valid is False
    assert v.verify(_assertion(priv, "n5", counter=8, app_id="OTHER.com.x"), "n5").valid is False
    other = _assertion(priv, "n6", counter=9); other["key_id"] = "unknown"
    assert v.verify(other, "n6").valid is False
    assert v.verify({"platform": "ios"}, "n7").valid is False
    assert keys.counter("key-1") == 5


def test_composite_dispatches_on_platform(attest):
    priv, v, _ = attest
    c = CompositeAttestationVerifier({"ios": v})
    assert c.verify(_assertion(priv, "n1", 1), "n1").valid
    assert c.verify({"platform": "android", "token": "x"}, "n1").valid is False
    assert c.verify(None, "n1").valid is False


# ---------------- IP intelligence ----------------

def test_ipinfo_maps_asn_privacy_and_caches():
    store = MemoryStore(Clock())
    s = FakeSession().respond({"ip": "1.2.3.4", "country": "DE", "asn": {"asn": "AS24940", "type": "hosting"},
                               "privacy": {"vpn": True, "proxy": False, "tor": False, "relay": False, "hosting": True}})
    intel = IpinfoIntel("tok", s, store=store)
    info = intel.lookup("1.2.3.4")
    assert info.asn == "AS24940" and info.is_datacenter and info.is_proxy and not info.is_tor and info.country == "DE"
    assert intel.lookup("1.2.3.4").asn == "AS24940" and len(s.calls) == 1        # cached
    assert IpIntelProxyDetector(intel).is_proxy("1.2.3.4") is True


def test_ipinfo_basic_plan_and_outage():
    s = FakeSession().respond({"ip": "5.6.7.8", "country": "SA", "org": "AS39386 Saudi Telecom"})
    info = IpinfoIntel("tok", s).lookup("5.6.7.8")
    assert info.asn == "AS39386" and not info.is_datacenter and not info.is_proxy
    s = FakeSession(); s.fail_with = ConnectionError()
    info = IpinfoIntel("tok", s).lookup("5.6.7.8")
    assert info.asn == "AS0" and not info.is_proxy and not info.is_tor            # fail open, neutral


def test_abuseipdb_composite_raises_abuse_score():
    s1 = FakeSession().respond({"ip": "9.9.9.9", "country": "US", "org": "AS1 X"})
    s2 = FakeSession().respond({"data": {"abuseConfidenceScore": 87}})
    info = CompositeIpIntel(IpinfoIntel("t", s1), AbuseIpdbIntel("k", s2)).lookup("9.9.9.9")
    assert info.abuse_score == 0.87
    assert s2.calls[0][2]["headers"]["Key"] == "k"


# ---------------- HLR ----------------

@pytest.mark.parametrize("valid,line_type,assigned,reachable,voip", [
    (True, "mobile", True, True, False),
    (True, "landline", True, False, False),
    (True, "nonFixedVoip", True, True, True),
    (True, "premium", True, False, False),
    (False, None, False, False, False),
])
def test_twilio_lookup_mapping(valid, line_type, assigned, reachable, voip):
    body = {"valid": valid, "line_type_intelligence": {"type": line_type} if line_type else None}
    s = FakeSession().respond(body)
    r = TwilioLookup("sid", "tok", s).lookup("966501234567")
    assert (r.assigned, r.reachable, r.is_voip) == (assigned, reachable, voip)
    _, url, kw = s.calls[0]
    assert url.endswith("/v2/PhoneNumbers/+966501234567") and kw["auth"] == ("sid", "tok")


def test_twilio_lookup_fails_open():
    s = FakeSession(); s.fail_with = TimeoutError()
    r = TwilioLookup("sid", "tok", s).lookup("966501234567")
    assert r.assigned and r.reachable


# ---------------- Senders ----------------

def test_twilio_messaging_request_shapes():
    s = FakeSession().respond({"sid": "SM1"}).respond({"sid": "SM2"}).respond({"sid": "SM3"})
    t = TwilioMessaging("AC1", "tok", from_number="+15550000000", whatsapp_from="+15550000001", status_callback="https://x/cb", session=s)
    t.send_sms("966501234567", "code 1234", 7)
    form = s.calls[0][2]["data"]
    assert form["To"] == "+966501234567" and form["From"] == "+15550000000" and form["StatusCallback"] == "https://x/cb"
    t.send_whatsapp("966501234567", "code 1234", 8)
    assert s.calls[1][2]["data"]["To"] == "whatsapp:+966501234567"
    t2 = TwilioMessaging("AC1", "tok", messaging_service_sid="MG1", session=s)
    t2.send_sms("966501234567", "x", 9)
    assert s.calls[2][2]["data"]["MessagingServiceSid"] == "MG1" and "From" not in s.calls[2][2]["data"]


def test_http_provider_and_fcm():
    s = FakeSession().respond({"ok": True})
    HttpSmsProvider("PROVIDER_B", "https://gw/send", lambda m, t, i: {"to": m, "msg": t, "ref": i},
                    headers={"X-Key": "k"}, session=s).send_sms("966501234567", "hi", 1)
    assert s.calls[0][2]["json"] == {"to": "966501234567", "msg": "hi", "ref": 1} and s.calls[0][2]["headers"]["X-Key"] == "k"
    s = FakeSession().respond({"name": "projects/p/messages/1"})
    FcmPush("p", lambda: "tok", lambda m: "device-token", s).send_push("966501234567", "hi", 2)
    assert s.calls[0][2]["json"]["message"]["token"] == "device-token"
    with pytest.raises(RuntimeError):
        FcmPush("p", lambda: "tok", lambda m: None, FakeSession()).send_push("966501234567", "hi", 3)


def test_routing_sender_routes_delays_and_reports():
    class RecordingScheduler:
        def __init__(self): self.jobs = []
        def schedule(self, delay, fn): self.jobs.append(delay); fn()
    sched, results = RecordingScheduler(), []
    calls = []
    sender = RoutingSender(
        providers={"PROVIDER_A": lambda m, t, i: calls.append(("sms", m)) or {"sid": "x"}},
        channels={"whatsapp": lambda m, t, i: (_ for _ in ()).throw(RuntimeError("boom"))},
        scheduler=sched, on_result=lambda log_id, ch, ok, d: results.append((log_id, ch, ok)))
    sender.enqueue("sms", "966501234567", "t", 1, 10, "PROVIDER_A")
    sender.enqueue("whatsapp", "966501234567", "t", 2, 0)
    sender.enqueue("push", "966501234567", "t", 3, 0)
    assert sched.jobs == [10, 0] and calls == [("sms", "966501234567")]
    assert results == [(1, "sms", True), (2, "whatsapp", False), (3, "push", False)]
    assert len(sender.by_channel("sms")) == 1


# ---------------- Alerts ----------------

def test_slack_alert_posts_and_survives_failure():
    s = FakeSession().respond({"ok": True})
    a = SlackWebhookAlerts("https://hooks.slack/x", s)
    a.alert("SMS circuit breaker: elevated", 0.81)
    assert "elevated" in s.calls[0][2]["json"]["text"]
    s.fail_with = ConnectionError()
    a.alert("again")                                     # must not raise
    m = MultiAlerts([LoggingAlerts(), a])
    m.alert("x")
    assert m.alerts[-1][0] == "x" and a.alerts[-1][0] == "x"
