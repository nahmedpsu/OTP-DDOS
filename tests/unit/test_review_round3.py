"""Tests for the implementation defects raised in the Reviewer 2 report (section A) and the
code-level items of sections B and C."""
import re
import threading

from otp_guard.config import ALL_FEATURES
from otp_guard.services import IpInfo
from otp_guard.testing import Harness


def test_sent_message_carries_the_code_that_verifies(h):
    """A1: the sender receives the code; a user reading the SMS can verify with it."""
    r = h.send(h.web_request(text="Your code is {code}. It expires in 10 minutes."))
    msg = h.svc.sender.sent[-1].text
    code = re.search(r"\b(\d{4})\b", msg).group(1)
    assert "{code}" not in msg and h.p.feedback.code_for(r.log_id) == code
    assert h.p.feedback.verify("s1", r.log_id, code)
    assert h.p.sms_history[r.log_id]["content"] == "Your code is {code}. It expires in 10 minutes."   # never logged in clear


def test_template_without_placeholder_gets_the_code_appended(h):
    h.send(h.web_request(text="Welcome"))
    assert re.fullmatch(r"Welcome \d{4}", h.svc.sender.sent[-1].text)


def test_challenge_proof_goes_through_the_adapter_interface(h):
    """A2: the pipeline must not reach into FakeRecaptcha.scores; a real adapter has verify_challenge()."""
    class RealLike:
        def __init__(self):
            self.calls = 0
            self.good = {"challenge-ok"}
        def verify(self, post):
            self.calls += 1
            return {"valid": True, "score": 0.6}          # 10 + 15 datacenter + 7.5 abuse + 10 young fp = 42.5
        def verify_challenge(self, token):
            self.calls += 1
            return token in self.good
    h.svc.recaptcha = RealLike()
    h.svc.ip_intel.register("198.51.100.10", IpInfo(is_datacenter=True, abuse_score=0.5))
    tok, _ = h.session(age_hours=0.5)
    r = h.send(h.web_request(session=tok, recaptcha="any"))
    assert r.tier == "challenge"
    r2 = h.send(h.web_request(session=tok, recaptcha="any", challenge_proof="challenge-ok"))
    assert r2.channel == "sms" and "challenge_passed" in r2.signals
    r3 = h.send(h.web_request(session=tok, recaptcha="any", mobile="966509999999", challenge_proof="forged"))
    assert r3.tier == "challenge"


def test_google_adapter_verify_challenge_shape():
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).parent))
    from fakes import FakeSession
    from otp_guard.providers.recaptcha import GoogleRecaptcha
    s = FakeSession().respond({"success": True, "hostname": "example.com"}).respond({"success": False})
    g = GoogleRecaptcha("v3-secret", s, expected_action="otp", expected_hostnames=["example.com"], challenge_secret="v2-secret")
    assert g.verify_challenge("tok") is True and s.calls[0][2]["data"]["secret"] == "v2-secret"
    assert g.verify_challenge("tok2") is False


def test_per_number_claim_is_atomic_under_concurrency():
    """C32: two concurrent requests for one number cannot both pass Step 8."""
    hh = Harness(); hh.lift_source_caps(); hh.cfg.asn_limit_default = 10**9; hh.cfg.ip_limit = (10**9, 60)
    toks = [hh.session(age_hours=3)[0] for _ in range(16)]
    results = []
    def worker(i):
        results.append(hh.send(hh.web_request(session=toks[i], ip=f"198.90.{i}.1")))
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert sum(r.channel == "sms" for r in results) == 1


def test_number_claim_released_when_a_later_step_refuses(h):
    """A refusal at Step 9 must not burn the number's window and daily slot."""
    h.cfg.source_limits["App/RegisterOTP"]["per_minute_web"] = 1
    h.cfg.source_limits["App/RegisterOTP"]["per_country"] = {}
    assert h.send(h.web_request(ip="198.91.1.1", mobile="966501000001")).channel == "sms"
    refused = h.send(h.web_request(ip="198.91.2.1", mobile="966501000002"))
    assert refused.rejected_at == "step9"
    assert not h.p.store.exists("num_window:966501000002") and (h.p.store.get("num_daily:966501000002") or 0) == 0


def test_duplicate_callbacks_are_idempotent(h):
    r = h.send(h.web_request())
    code = h.p.feedback.code_for(r.log_id)
    h.p.feedback.on_delivery(r.log_id, True); h.p.feedback.on_delivery(r.log_id, True)
    assert h.p.feedback.verify("s1", r.log_id, code)
    h.p.feedback.on_verified(r.log_id); h.p.feedback.on_verified(r.log_id)
    rep = h.p.rep.get("num:966501234567")
    assert rep.verified == 1 and rep.failed == 0
    r2 = h.send(h.web_request(ip="198.92.1.1", mobile="966501234568"))
    h.p.feedback.on_delivery(r2.log_id, True)
    h.clock.advance(h.cfg.resolution_timeout_s + 1); h.p.feedback.run_due_timeouts(); h.p.feedback.run_due_timeouts()
    h.p.feedback.on_failed_or_timeout(r2.log_id, keep_code=True)
    assert h.p.rep.get("num:966501234568").failed == 1


def test_hard_budget_ceiling_is_atomic_and_unconditional(h):
    """C31: no SMS beyond the hourly budget, reserved before the send."""
    h.lift_source_caps(); h.cfg.asn_limit_default = 10**9; h.cfg.ip_limit = (10**9, 60)
    h.cfg.global_sms_per_hour = 5
    sent = [h.send(h.web_request(session=h.session(age_hours=3)[0], ip=f"198.93.{i}.1", mobile=f"96650{(i * 7654321) % 10**7:07d}")) for i in range(8)]
    assert sum(r.channel == "sms" for r in sent) == 5 and all("budget_exhausted" in r.signals for r in sent[5:])
    assert h.p.store.get(f"global:sms:count:{h.p.current_hour()}") == 5


def _block_events(h, key, seq):
    for ev in seq:
        h.p.feedback._block_event(key, verified=ev != "f", fast=ev == "fast")


def test_cusum_block_test_banks_only_bounded_goodwill(h):
    """B13: after 100 slow verifications a block holds one threshold of credit, so a verdict needs
    about ten failures instead of five, not the 143 a plain SPRT would need; with no credit, five."""
    h.cfg.block_action = "deny"
    _block_events(h, "block:96650123", ["v"] * 100 + ["f"] * 5)
    assert not h.p.store.exists("deny:block:96650123")
    _block_events(h, "block:96650123", ["f"] * 5)
    assert h.p.store.exists("deny:block:96650123")
    h.cfg.block_credit_thresholds = 0.0
    _block_events(h, "block:96650127", ["v"] * 100 + ["f"] * 5)
    assert h.p.store.exists("deny:block:96650127")


def test_plain_sprt_banks_goodwill_for_comparison(h):
    h.cfg.block_action = "deny"; h.cfg.block_test = "sprt"
    _block_events(h, "block:96650124", ["v"] * 100 + ["f"] * 5)
    assert not h.p.store.exists("deny:block:96650124")


def test_block_tests_can_be_restricted(h):
    h.cfg.block_action = "deny"; h.cfg.block_tests = ("speed",)
    _block_events(h, "block:96650125", ["f"] * 10)
    assert not h.p.store.exists("deny:block:96650125")
    _block_events(h, "block:96650126", ["fast"] * 5)      # ln(0.9/0.2) per event: five cross ln(1000)
    assert h.p.store.exists("deny:block:96650126")


def test_default_worker_runs_the_baseline_job(h):
    """A8: the worker adapts the cap from the pipeline's own volume counters, no custom source needed."""
    from otp_guard.baseline import BaselineJob
    from otp_guard.worker import tick
    h.lift_source_caps(); h.cfg.asn_limit_default = 10**9
    job = BaselineJob(h.p)
    # 25 hours of quiet traffic: 2 requests a minute, 80 % of them verified
    for m in range(25 * 60):
        for i in range(2):
            r = h.send(h.web_request(ip=f"198.94.{(m * 2 + i) % 250}.{(m * 2 + i) // 250 + 1}", mobile=f"9665{(m * 2 + i) * 7654321 % 10**8:08d}"))
            if r.log_id and (m * 2 + i) % 5:
                h.clock.advance(20); h.p.feedback.verify(h.p.sms_history[r.log_id]["session_id"], r.log_id, h.p.feedback.code_for(r.log_id))
        h.clock.advance(20); tick(h.p, baseline_job=job)
    assert h.p.adaptive.multiplier("App/RegisterOTP", "web", "966") >= 1.0
    # a burst of 40 a minute for five minutes drives the multiplier down
    for m in range(5):
        for i in range(40):
            h.send(h.web_request(session=h.session(age_hours=0)[0], ip=f"198.95.{m}.{i + 1}", mobile=f"9665{(m * 40 + i) * 1234567 % 10**8:08d}"))
        h.clock.advance(60); tick(h.p, baseline_job=job)
    assert h.p.adaptive.multiplier("App/RegisterOTP", "web", "966") <= 0.5
