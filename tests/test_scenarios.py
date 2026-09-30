"""End-to-end attack and user scenarios from Problem_Statement.md."""
import random

from otp_guard.services import IpInfo


def test_original_incident_random_number_flood_from_one_ip(h):
    """v1 problem: one client hammering the endpoint with random numbers."""
    rng = random.Random(1)
    tok, _ = h.session()
    for _ in range(200):
        h.send(h.web_request(session=tok, mobile=f"9665{rng.randrange(10**8):08d}"))
    assert h.sms_sent <= 3        # session cap stops it before the IP cap does


def test_rotating_ips_across_datacenter_asn(h):
    """Gap B: 300 requests, each from a different IP, spread across many /24s of one hosting ASN,
    each with a fresh session so the per-session cap never triggers."""
    h.lift_source_caps()                       # isolate the network layer from the source cap
    h.svc.ip_intel.register("203.0.0.0/8", IpInfo(asn="AS64500", asn_type="hosting", is_datacenter=True, country="DE"))
    rng = random.Random(2)
    for i in range(300):
        ip = f"203.{i % 256}.{(i * 13) % 256}.{(i * 7) % 250 + 1}"
        h.send(h.web_request(ip=ip, mobile=f"9665{rng.randrange(10**8):08d}"))
    # the datacenter ASN cap (50/min) bounds the damage on its own; with the real source cap it is 5
    assert h.sms_sent <= 50


def test_rotating_residential_ips_are_caught_by_conversion_feedback(h):
    """Gap B with a residential proxy pool: every IP unique, every /24 unique, ASN residential.
    Only the feedback loop can catch this. Over an hour the attacker gets far fewer than the
    unconstrained 3000 messages a 50/hour source cap would otherwise allow."""
    h.cfg.source_limits["App/RegisterOTP"]["per_minute_web"] = 1000
    h.cfg.source_limits["App/RegisterOTP"]["per_hour_web"] = 100000
    h.cfg.asn_limit_default = 100000
    h.svc.ip_intel.register("100.64.0.0/10", IpInfo(asn="AS9000", asn_type="residential"))
    rng = random.Random(3)
    sent_per_minute = []
    for minute in range(20):
        before = h.sms_sent
        for i in range(30):
            n = minute * 30 + i
            ip = f"100.{64 + (n // 65536) % 64}.{(n // 256) % 256}.{n % 256}"
            h.send(h.web_request(ip=ip, mobile=f"9665{rng.randrange(10**8):08d}"))
        h.clock.advance(60)
        h.p.feedback.run_due_timeouts()
        sent_per_minute.append(h.sms_sent - before)
    # first ~10 minutes flow (no OTP has timed out yet); once timeouts land the ASN's
    # conversion collapses, every later request is downgraded, and finally the ASN is denylisted
    assert sent_per_minute[0] == 30
    assert sent_per_minute[-1] == 0
    assert h.sms_sent < 20 * 30 * 0.7
    assert h.p.store.exists("deny:asn:AS9000")


def test_sms_pumping_to_premium_range_is_impossible(h):
    """Gap D."""
    for i in range(50):
        h.send(h.web_request(ip=f"198.60.{i}.1", mobile=f"96699{i:07d}"))
    assert h.sms_sent == 0


def test_sequential_number_walk_is_stopped_early(h):
    """Gap C: attacker walks 966501000000 upward from many IPs and sessions."""
    for i in range(40):
        h.send(h.web_request(ip=f"198.61.{i}.1", mobile=f"966501{i:06d}"))
    assert h.sms_sent <= 12       # narrow-range threshold (10) plus source cap bound it


def test_legitimate_user_journey(h):
    """A real user requests a code, verifies it, and is trusted afterwards."""
    tok, fp = h.session()
    r = h.send(h.web_request(session=tok))
    assert r.channel == "sms"
    code = h.p.feedback.code_for(r.log_id)
    assert h.p.feedback.verify("s1", r.log_id, "0000" if code != "0000" else "1111") is False
    assert h.p.feedback.verify("s1", r.log_id, code) is True
    assert h.p.rep.get("fp:" + fp).verified == 1
    assert h.p.rep.is_trusted("num:966501234567")
    # a week later, same person, new session: lower score and no HLR spend
    h.clock.advance(7 * 86400)
    hlr_before = h.svc.hlr.calls
    tok2, _ = h.session(fingerprint=fp, age_hours=None)
    r2 = h.send(h.web_request(session=tok2))
    assert r2.rejected_at is None and r2.risk_score == 0 and h.svc.hlr.calls == hlr_before


def test_verify_endpoint_brute_force_protection(h):
    r = h.send(h.web_request())
    code = h.p.feedback.code_for(r.log_id)
    wrong = "9999" if code != "9999" else "8888"
    for _ in range(5):
        assert h.p.feedback.verify("s1", r.log_id, wrong) is False
    assert h.p.feedback.verify("s1", r.log_id, code) is False      # invalidated after 5 attempts
    assert h.p.rep.get("num:966501234567").failed == 1


def test_verify_endpoint_session_rate_limit(h):
    r = h.send(h.web_request())
    for _ in range(20):
        h.p.feedback.verify("sX", 999, "0000")
    assert h.p.feedback.verify("sX", r.log_id, h.p.feedback.code_for(r.log_id)) is False


def test_marketing_campaign_override_lifts_cap(h):
    h.p.adaptive.set_marketing_override("App/RegisterOTP", "web", "966", 1.5)
    ok = sum(h.send(h.web_request(ip=f"198.62.{i}.1", mobile=f"9665{i:08d}")).rejected_at is None for i in range(10))
    assert ok == 8
