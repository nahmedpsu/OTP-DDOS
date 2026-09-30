"""One or more tests per pipeline step, in step order."""
import threading

from otp_guard import Request, UNIFORM_BODY, RateLimit, MemoryStore, Clock
from otp_guard.services import IpInfo


# ---------------- Happy paths ----------------

def test_web_happy_path_sends_sms_and_logs(h):
    r = h.send(h.web_request())
    assert r.http_status == 200 and r.body == UNIFORM_BODY
    assert r.rejected_at is None and r.channel == "sms" and r.tier == "allow"
    rec = h.p.sms_history[r.log_id]
    assert rec["phone_number"] == "966501234567" and rec["sms_provider"] == "PROVIDER_A"
    assert rec["trusted_platform"] == "web" and rec["risk_score"] < 20
    assert h.sms_sent == 1


def test_attested_ios_from_any_host_is_allowed(h):
    r = h.send(h.app_request("ios", host="someotherhost.com"))
    assert r.rejected_at is None and r.channel == "sms"
    assert h.p.sms_history[r.log_id]["trusted_platform"] == "ios"
    assert h.svc.recaptcha.calls == 0        # apps never call reCAPTCHA


# ---------------- Step 0 ----------------

def test_step0_proxy_is_blocked_regardless_of_host(h):
    h.svc.proxy.proxy_ips.add("198.51.100.10")
    r = h.send(h.web_request())
    assert r.http_status == 403 and r.rejected_at == "step0" and h.sms_sent == 0


def test_step0_platform_header_spoofing_gets_no_exemption(h):
    """Gap A: HTTP_PLATFORM: ios with no attestation is treated as web."""
    req = h.web_request(host="someotherhost.com", header_platform="ios")
    r = h.send(req)
    assert r.http_status == 403 and req.trusted_platform == "web"


def test_step0_spoofed_platform_still_needs_recaptcha(h):
    req = h.web_request(header_platform="ios", recaptcha="invalid-token")
    r = h.send(req)
    assert r.rejected_at == "step3" and h.svc.recaptcha.calls == 1


def test_step0_invalid_attestation_is_blocked(h):
    r = h.send(h.app_request("ios", valid=False))
    assert r.http_status == 403 and r.rejected_at == "step0"


def test_step0_legacy_app_allowed_during_grace_with_delay_tier(h):
    r = h.send(h.legacy_app_request())
    assert r.rejected_at is None
    assert r.tier == "delay"                 # never better than delay
    assert "legacy_app" in h.p.sms_history[r.log_id]["signals"]


def test_step0_legacy_app_blocked_after_grace(h):
    h.clock.advance(31 * 86400)
    r = h.send(h.legacy_app_request())
    assert r.http_status == 426 and r.body == {"status": "update_required"}


def test_step0_web_from_unauthorized_host_blocked(h):
    r = h.send(h.web_request(host="evil.example.net"))
    assert r.http_status == 403


# ---------------- Step 1 ----------------

def test_step1_missing_or_forged_session_rejected(h):
    assert h.send(h.web_request(session="")).rejected_at == "step1"
    tok, _ = h.session()
    forged = tok[:-4] + "0000"
    assert h.send(h.web_request(session=forged)).rejected_at == "step1"


def test_step1_expired_session_rejected(h):
    tok, _ = h.session()
    h.clock.advance(h.cfg.session_ttl + 1)
    assert h.send(h.web_request(session=tok)).rejected_at == "step1"


def test_step1_session_platform_must_match_trusted_platform(h):
    web_tok, _ = h.session("web")
    # an attested iOS request presenting a web session token
    r = h.send(h.app_request("ios", session=web_tok))
    assert r.rejected_at == "step1"


def test_step1_nonce_replay_rejected(h):
    tok, _ = h.session()
    req = h.web_request(session=tok)
    assert h.send(req).rejected_at is None
    replay = h.web_request(session=tok)
    replay.nonce = req.nonce
    assert h.send(replay).rejected_at == "step1"


def test_step1_session_cap_three_per_ten_minutes(h):
    tok, _ = h.session()
    results = [h.send(h.web_request(session=tok, mobile=f"9665012345{i:02d}")) for i in range(4)]
    assert [r.rejected_at for r in results[:3]] == [None, None, None]
    assert results[3].rejected_at == "step1"
    h.clock.advance(601)
    assert h.send(h.web_request(session=tok, mobile="966501234599")).rejected_at is None


# ---------------- Step 2 ----------------

def test_step2_ip_limit_five_per_minute(h):
    rs = [h.send(h.web_request(mobile=f"9665012345{i:02d}")) for i in range(6)]
    assert [r.rejected_at for r in rs] == [None] * 5 + ["step2"]
    h.clock.advance(61)
    assert h.send(h.web_request(mobile="966501234599")).rejected_at is None


def test_step2_cgnat_asn_gets_the_higher_ip_cap(h):
    """Many subscribers of a mobile carrier share one public IP; a listed CGNAT ASN gets 30/min per IP."""
    h.lift_source_caps()
    h.svc.ip_intel.register("198.51.100.0/24", IpInfo(asn="AS39386", asn_type="isp"))
    h.cfg.cgnat_asns = ("AS39386",)
    ok = sum(h.send(h.web_request(mobile=f"9665{i * 1234567:08d}")).rejected_at is None for i in range(35))
    assert ok == 30


def test_step2_subnet_limit_catches_ip_rotation_inside_a_block(h):
    """Gap B: rotating through a /24 stays under the per-IP cap but hits the subnet cap."""
    h.lift_source_caps()
    # numbers are spread out on purpose: a sequential walk would (correctly) trip Step 5 first
    rs = [h.send(h.web_request(ip=f"198.51.100.{i}", mobile=f"9665{i * 1234567:08d}")) for i in range(1, 36)]
    assert all(r.rejected_at is None for r in rs[:30])
    assert all(r.rejected_at == "step2" for r in rs[30:])


def test_step2_datacenter_asn_capped_at_fifty(h):
    h.lift_source_caps()
    h.svc.ip_intel.register("203.0.0.0/8", IpInfo(asn="AS64500", asn_type="hosting", is_datacenter=True))
    ok = 0
    for i in range(60):
        ip = f"203.{i // 200}.{(i * 7) % 250 + 1}.{i % 250 + 1}"    # spread across many /24s
        r = h.send(h.web_request(ip=ip, mobile=f"96650{i:07d}"))
        ok += r.rejected_at is None
    assert ok == 50


def test_step2_tor_exit_blocked(h):
    h.svc.ip_intel.register("198.51.100.10", IpInfo(is_tor=True))
    assert h.send(h.web_request()).rejected_at == "step2"


def test_rate_limit_is_atomic_under_concurrency():
    store = MemoryStore(Clock())
    lim = RateLimit(store).set_limit(50, 60).set_key("k").set_identifier("x")
    acquired = []
    def worker():
        for _ in range(20):
            if lim.try_acquire():
                acquired.append(1)
    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert len(acquired) == 50 and lim.current_count() == 50


def test_try_acquire_all_consumes_nothing_when_one_limit_is_full():
    store = MemoryStore(Clock())
    a = RateLimit(store).set_limit(10, 60).set_key("a").set_identifier("x")
    b = RateLimit(store).set_limit(1, 60).set_key("b").set_identifier("x")
    assert RateLimit.try_acquire_all([a, b])
    assert not RateLimit.try_acquire_all([a, b])
    assert a.current_count() == 1 and b.current_count() == 1


# ---------------- Step 3 / 4 ----------------

def test_step3_invalid_token_and_low_score_rejected(h):
    assert h.send(h.web_request(recaptcha="nope")).rejected_at == "step3"
    assert h.send(h.web_request(recaptcha="low")).rejected_at == "step3"


def test_step3_threshold_rises_in_elevated_mode(h):
    assert h.send(h.web_request(recaptcha="mid")).rejected_at is None
    h.p.mode = "elevated"
    assert h.send(h.web_request(recaptcha="mid")).rejected_at == "step3"


def test_step4_origin_must_be_allowed_domain(h):
    assert h.send(h.web_request(origin="https://app.example.com/x")).rejected_at is None
    assert h.send(h.web_request(origin="https://example.com.evil.net/x")).rejected_at == "step4"
    assert h.send(h.web_request(origin="https://phish.net/x")).rejected_at == "step4"


# ---------------- Step 5 ----------------

def test_step5_normalises_plus_and_leading_zeros(h):
    r = h.send(h.web_request(mobile="+00966501234567"))
    assert r.rejected_at is None and h.p.sms_history[r.log_id]["phone_number"] == "966501234567"


def test_step5_country_not_in_allow_list(h):
    assert h.send(h.web_request(mobile="+1 415 555 0100")).rejected_at == "step5"


def test_step5_oman_blocked_from_web_and_legacy_but_allowed_from_attested_app(h):
    assert h.send(h.web_request(mobile="96890123456")).rejected_at == "step5"
    assert h.send(h.legacy_app_request(mobile="96890123456")).rejected_at == "step5"
    assert h.send(h.app_request("android", mobile="96890123456")).rejected_at is None


def test_step5_bulk_flag_alone_does_not_skip_country_check(h):
    """Gap G."""
    assert h.send(h.web_request(mobile="14155550100", is_bulk=True)).rejected_at == "step5"
    ok = h.send(h.web_request(mobile="14155550100", is_bulk=True, service_credential="svc-secret"))
    assert ok.rejected_at is None


def test_step5_premium_prefix_blocked(h):
    """Gap D: SMS pumping ranges never get an OTP."""
    assert h.send(h.web_request(mobile="966991234567")).rejected_at == "step5"


def test_step5_elevated_prefix_capped_per_hour_and_flagged(h):
    h.lift_source_caps()
    rs = []
    for i in range(22):
        rs.append(h.send(h.web_request(ip=f"198.51.{i}.1", mobile=f"97159{i:07d}")))
    assert sum(r.rejected_at is None for r in rs) == 20
    assert "elevated_prefix" in h.p.sms_history[rs[0].log_id]["signals"]


def test_step5_sequential_numbers_flagged_then_blocked(h):
    """Gap C: a flooder walking through 966501000001, 000002, ... from one client."""
    h.lift_source_caps()
    tok, _ = h.session()
    r1 = h.send(h.web_request(session=tok, mobile="966501000001"))
    r2 = h.send(h.web_request(session=tok, mobile="966501000002"))
    assert r1.rejected_at is None
    assert "sequential_number" in h.p.sms_history[r2.log_id]["signals"]
    # now saturate the narrow range from many other clients; for the original client the next
    # neighbouring number is sequential + narrow => hard block. Other clients only get the signal.
    for i in range(3, 14):
        h.send(h.web_request(ip=f"198.51.{i}.1", mobile=f"966501{i:06d}"))
    blocked = h.send(h.web_request(session=tok, ip="198.51.99.1", mobile="966501000003"))
    assert blocked.rejected_at == "step5"
    other = h.send(h.web_request(ip="198.51.98.1", mobile="966501000099"))
    assert other.rejected_at is None and "narrow_range_burst" in h.p.sms_history[other.log_id]["signals"]


def test_step5_hlr_rejects_dead_numbers_and_is_cached(h):
    h.svc.hlr.unassigned.add("966501234567")
    assert h.send(h.web_request()).rejected_at == "step5"
    assert h.send(h.web_request(ip="198.51.101.1")).rejected_at == "step5"
    assert h.svc.hlr.calls == 1               # second lookup served from cache


def test_step5_verified_number_skips_hlr(h):
    r = h.send(h.web_request())
    assert h.svc.hlr.calls == 1
    h.p.feedback.on_verified(r.log_id)
    h.clock.advance(120)
    r2 = h.send(h.web_request())
    assert r2.rejected_at is None and h.svc.hlr.calls == 1


def test_step5_voip_number_is_a_risk_signal(h):
    h.svc.hlr.voip.add("966501234567")
    r = h.send(h.web_request())
    assert "voip_number" in h.p.sms_history[r.log_id]["signals"]


# ---------------- Step 6 ----------------

def test_step6_text_rules(h):
    assert h.send(h.web_request(text="")).rejected_at == "step6"
    assert h.send(h.web_request(text="x" * 421)).rejected_at == "step6"
    assert h.send(h.web_request(text="x" * 420)).rejected_at is None


def test_step6_excluded_number(h):
    h.cfg.excluded_numbers = ("966501234567",)
    assert h.send(h.web_request()).rejected_at == "step6"


def test_step6_test_server_skip_needs_credential(h):
    h.cfg.is_test_server = True
    assert h.send(h.web_request(text="")).rejected_at == "step6"
    assert h.send(h.web_request(text="", service_credential="svc-secret")).rejected_at is None


# ---------------- Step 7 ----------------

def test_step7_clean_user_scores_under_twenty(h):
    r = h.send(h.web_request())
    assert r.risk_score < 20 and r.tier == "allow"


def test_step7_single_strong_signal_only_delays(h):
    """A young fingerprint alone (+20) must land in delay, never block."""
    tok, _ = h.session(age_hours=0)
    r = h.send(h.web_request(session=tok))
    assert r.tier == "delay" and r.channel == "sms" and 20 <= r.risk_score < 40


def test_step7_stacked_signals_block(h):
    """Datacenter IP (+15) + brand-new fingerprint (+20) + low-ish captcha + geo mismatch + unknown prefix."""
    h.svc.ip_intel.register("203.0.113.5", IpInfo(asn="AS64500", is_datacenter=True, abuse_score=1.0, country="RU"))
    tok, _ = h.session(age_hours=0)
    r = h.send(h.web_request(session=tok, ip="203.0.113.5", recaptcha="mid", mobile="966571234567"))
    assert r.risk_score >= 80 and r.tier == "block" and r.rejected_at == "step7" and h.sms_sent == 0


def test_step7_challenge_tier_returns_challenge_then_retry_passes(h):
    h.svc.ip_intel.register("198.51.100.10", IpInfo(is_datacenter=True, abuse_score=0.5))
    tok, _ = h.session(age_hours=0.5)                # +15 datacenter, +7.5 abuse, +10 young fp, +10 captcha 0.6
    r = h.send(h.web_request(session=tok, recaptcha="mid"))
    assert r.body["status"] == "challenge" and r.tier == "challenge" and h.sms_sent == 0
    assert 40 <= r.risk_score < 60
    r2 = h.send(h.web_request(session=tok, recaptcha="mid", challenge_proof="challenge-ok"))
    assert r2.rejected_at is None and r2.channel == "sms" and r2.tier == "delay"   # 42.5 - 20 + 5 prior = 27.5


def test_step7_low_conversion_reputation_raises_score(h):
    """The feedback loop: 20 unverified sends from one ASN push later requests up a tier."""
    h.lift_source_caps()
    h.svc.ip_intel.register("198.51.0.0/16", IpInfo(asn="AS777"))
    for i in range(20):
        r = h.send(h.web_request(ip=f"198.51.{i}.1", mobile=f"96650{i:07d}"))
        assert r.rejected_at is None and r.tier == "allow"
    h.clock.advance(601)
    h.p.feedback.run_due_timeouts()
    r = h.send(h.web_request(ip="198.51.200.1", mobile="966509999999"))
    assert r.risk_score >= 25 and r.tier in ("delay", "challenge")


def test_step7_fresh_burst_of_legitimate_traffic_is_not_penalised(h):
    """20 sends in a few seconds from one country must not read as 0 % conversion before
    anyone could have typed a code. Only resolved sends count."""
    h.lift_source_caps()
    for i in range(25):
        r = h.send(h.web_request(ip=f"198.58.{i}.1", mobile=f"9665{i * 7654321:08d}"))
        assert r.rejected_at is None and r.tier == "allow", (i, r.tier, r.risk_score)
    assert h.p.rep.conversion_ratio("country:966", 20) is None


# ---------------- Step 8 ----------------

def test_step8_progressive_backoff_and_daily_cap(h):
    def req():
        return h.web_request(ip=f"198.51.{h.sms_sent}.7")     # fresh IP each time to isolate step 8
    assert h.send(req()).rejected_at is None                  # send 1
    assert h.send(req()).rejected_at == "step8"
    h.clock.advance(61)
    assert h.send(req()).rejected_at is None                  # send 2 after 60 s
    h.clock.advance(61)
    assert h.send(req()).rejected_at == "step8"               # needs 120 s now
    h.clock.advance(60)
    assert h.send(req()).rejected_at is None                  # send 3
    h.clock.advance(241)
    assert h.send(req()).rejected_at is None                  # send 4 after 240 s
    h.clock.advance(481)
    assert h.send(req()).rejected_at is None                  # send 5 after 480 s
    h.clock.advance(3601)
    assert h.send(req()).rejected_at == "step8"               # daily cap of 5
    h.clock.advance(86400)
    assert h.send(req()).rejected_at is None                  # window rolled


# ---------------- Step 9 ----------------

def test_step9_web_per_minute_cap_and_adaptive_tightening(h):
    offset = [0]
    def burst(n):
        base = offset[0]; offset[0] += 100
        return sum(h.send(h.web_request(ip=f"198.52.{i}.1", mobile=f"9665{base + i:08d}")).rejected_at is None
                   for i in range(n))
    assert burst(7) == 5                                   # web base limit 5 / minute
    h.clock.advance(61)
    m = h.p.adaptive.recompute("App/RegisterOTP", "web", "966", observed=400, expected_median=50, mad=10, conversion=0.05)
    assert m == 0.5                                        # one abusive tick halves it
    assert burst(7) == 3                                   # ceil(5 * 0.5)
    h.clock.advance(61)
    for _ in range(6):
        h.p.adaptive.recompute("App/RegisterOTP", "web", "966", observed=50, expected_median=50, mad=10, conversion=0.8)
    assert h.p.adaptive.multiplier("App/RegisterOTP", "web", "966") == 1.5
    assert burst(9) == 8                                   # ceil(5 * 1.5)


def test_step9_per_country_override_applies(h):
    ok = sum(h.send(h.app_request("android", ip=f"198.56.{i}.1", mobile=f"96890{i:06d}")).rejected_at is None
             for i in range(10))
    assert ok == 8                                         # android base 8 / minute (no override for android)
    h.clock.advance(61)
    h.cfg.source_limits["App/RegisterOTP"]["per_country"]["968"]["per_minute_android"] = 2
    ok = sum(h.send(h.app_request("android", ip=f"198.57.{i}.1", mobile=f"96890{i + 50:06d}")).rejected_at is None
             for i in range(10))
    assert ok == 2                                         # per-country override wins


# ---------------- Step 10 ----------------

def test_step10_breaker_moves_to_elevated_then_emergency(h):
    h.lift_source_caps()
    h.cfg.global_sms_per_hour = 10
    for i in range(8):
        h.send(h.web_request(ip=f"198.53.{i}.1", mobile=f"96650{i:07d}"))
    assert h.p.mode == "normal"                            # 8/10 = 80% is evaluated on the next request
    r = h.send(h.web_request(ip="198.53.50.1", mobile="966509999990"))
    assert h.p.mode == "elevated" and r.channel == "sms"
    assert any("elevated" in a[0] for a in h.svc.alerts.alerts)
    h.send(h.web_request(ip="198.53.51.1", mobile="966509999991"))   # 10th SMS
    # emergency: a clean client (score < 10) still gets SMS, anything riskier is downgraded
    clean = h.send(h.web_request(ip="198.53.52.1", mobile="966509999992"))
    assert h.p.mode == "emergency" and clean.channel == "sms" and clean.risk_score < 10
    young_tok, _ = h.session(age_hours=0)
    risky = h.send(h.web_request(session=young_tok, ip="198.53.54.1", mobile="966509999994"))
    assert risky.channel is None and risky.rejected_at == "no_channel" and risky.tier == "downgrade"
    h.clock.advance(3600)
    r = h.send(h.web_request(ip="198.53.53.1", mobile="966509999993"))
    assert h.p.mode == "normal" and r.channel == "sms"


def test_step10_spend_units_trip_breaker_before_count(h):
    h.cfg.global_spend_units_per_hour = 10
    h.cfg.global_sms_per_hour = 1000
    # elevated prefix costs 3 units: 4 sends = 12 units >= 100%
    for i in range(4):
        h.send(h.web_request(ip=f"198.54.{i}.1", mobile=f"97159{i:07d}"))
    young_tok, _ = h.session(age_hours=0)
    r = h.send(h.web_request(session=young_tok, ip="198.54.9.1", mobile="966501234567"))
    assert h.p.mode == "emergency" and r.channel is None


def test_step10_kill_switch(h):
    h.cfg.kill_switch = True
    r = h.send(h.web_request())
    assert h.p.mode == "emergency" and r.channel is None and h.sms_sent == 0


# ---------------- Step 11 ----------------

def test_step11_delay_tier_queues_sms_with_backoff(h):
    tok, fp = h.session(age_hours=0)
    r1 = h.send(h.web_request(session=tok, mobile="966501000001", ip="198.55.1.1"))
    r2 = h.send(h.web_request(session=tok, mobile="966501900002", ip="198.55.1.2"))
    sent = {m.log_id: m for m in h.svc.sender.sent}
    assert r1.tier == "delay" and sent[r1.log_id].delay == 5
    assert r2.tier == "delay" and sent[r2.log_id].delay == 10


def test_step11_downgrade_uses_push_or_whatsapp_never_sms(h):
    h.svc.ip_intel.register("198.51.100.0/24", IpInfo(is_datacenter=True, abuse_score=1.0))  # 15 + 15 + 10 = 40
    r = h.send(h.app_request("android", session=h.session("android", age_hours=0.5)[0], ip="198.51.100.10"))
    assert r.tier == "downgrade" and r.channel is None and h.sms_sent == 0  # app: challenge -> downgrade, no channel
    h.svc.channels.whatsapp_numbers.add("966501234567")
    r = h.send(h.app_request("android", session=h.session("android", age_hours=0.5)[0], ip="198.51.100.11"))
    assert r.channel == "whatsapp" and h.sms_sent == 0
    h.clock.advance(61)                                                 # clear the per-number window
    fp_tok, fp = h.session("android", age_hours=0.5)
    h.svc.channels.push_devices.add(fp)
    r = h.send(h.app_request("android", session=fp_tok, ip="198.51.100.12"))
    assert r.channel == "push"


def test_step11_uniform_response_for_reject_and_send(h):
    sent = h.send(h.web_request())
    rejected = h.send(h.web_request(mobile="14155550100"))            # step 5 reject
    assert sent.http_status == rejected.http_status == 200
    assert sent.body == rejected.body == UNIFORM_BODY


def test_step11_timing_floor_hides_which_step_rejected(h):
    h.cfg.response_floor_ms = 20
    sent = h.send(h.web_request())
    early = h.send(h.web_request(session=""))                          # step 1 reject, cheapest path
    assert sent.elapsed_ms >= 20 and early.elapsed_ms >= 20


def test_step11_audit_log_has_risk_fields(h):
    r = h.send(h.web_request())
    rec = h.p.sms_history[r.log_id]
    for k in ("risk_score", "signals", "tier", "channel", "operating_mode", "session_id", "fingerprint", "ip", "asn"):
        assert k in rec


# ---------------- Feedback loop denylist scope ----------------

def test_datacenter_asn_is_denylisted_but_residential_asn_is_not(h):
    h.lift_source_caps(); h.cfg.asn_limit_default = 100000
    h.svc.ip_intel.register("203.0.0.0/8", IpInfo(asn="AS64500", asn_type="hosting", is_datacenter=True))
    h.svc.ip_intel.register("100.64.0.0/10", IpInfo(asn="AS9000", asn_type="isp"))
    for i in range(60):
        h.send(h.web_request(ip=f"203.{i % 200}.{(i * 7) % 200}.1", mobile=f"96650{(i * 7654321) % 10**7:07d}"))
        h.send(h.web_request(ip=f"100.{64 + i % 60}.{(i * 7) % 200}.1", mobile=f"96655{(i * 7654321) % 10**7:07d}"))
    h.clock.advance(601); h.p.feedback.run_due_timeouts()
    assert h.p.store.exists("deny:asn:AS64500")
    assert not h.p.store.exists("deny:asn:AS9000")


def test_sustained_flood_bonus_reaches_challenge_without_other_signals(h):
    """An attacker with pre-aged unique fingerprints and a good captcha only ever scores
    2.5 + 25 from conversion; the flood bonus adds 15 once a key has 100 resolved failures."""
    h.lift_source_caps(); h.cfg.asn_limit_default = 100000
    h.svc.ip_intel.register("100.64.0.0/10", IpInfo(asn="AS9000", asn_type="isp"))
    for i in range(100):
        h.send(h.web_request(ip=f"100.{64 + i % 60}.{(i * 7) % 200}.{i % 250 + 1}", mobile=f"96650{(i * 7654321) % 10**7:07d}"))
    h.clock.advance(601); h.p.feedback.run_due_timeouts()
    r = h.send(h.web_request(ip="100.70.70.70", mobile="966509999999"))
    assert r.tier == "challenge" and r.risk_score == 42.5          # 2.5 captcha + 25 conversion + 15 flood


# ---------------- Feature flags ----------------

def test_v1_feature_profile_reproduces_the_original_gaps():
    """With every v2 feature off, the pipeline is the v1 design: header-trusted platform, no session,
    no subnet/ASN, no number intelligence, no risk engine, no feedback."""
    from otp_guard.config import V1_FEATURES
    from otp_guard.testing import Harness
    h = Harness(); h.cfg.features = V1_FEATURES
    # Gap A: a spoofed platform header now skips reCAPTCHA and the host check
    r = h.send(h.web_request(header_platform="ios", host="evil.net", recaptcha="nope"))
    assert r.rejected_at is None and h.p.sms_history[r.log_id]["trusted_platform"] == "ios"
    # Gap D: premium prefix goes through
    assert h.send(h.web_request(mobile="966991234567", ip="198.51.100.11")).rejected_at is None
    # risk engine off: even a datacenter IP with a brand-new fingerprint is tier allow
    from otp_guard.services import IpInfo
    h.svc.ip_intel.register("203.0.113.5", IpInfo(is_datacenter=True, abuse_score=1.0, country="RU"))
    tok, _ = h.session(age_hours=0)
    r = h.send(h.web_request(session=tok, ip="203.0.113.5", mobile="966501234568"))
    assert r.tier == "allow" and r.risk_score == 0.0
    # backoff off: fixed 1 per minute, no daily cap
    h.clock.advance(61)
    for _ in range(6):
        assert h.send(h.web_request(ip="198.51.100.12")).rejected_at is None
        h.clock.advance(61)
