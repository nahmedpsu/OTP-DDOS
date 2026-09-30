"""Verification feedback loop and the OTP verify endpoint's own protections."""
import heapq
import secrets


class FeedbackLoop:
    def __init__(self, pipeline):
        self.p = pipeline
        self.timeouts = []      # heap of (due, log_id)
        self.codes = {}         # log_id -> {"code", "attempts", "expires", "done"}

    # ---- send side ----
    def on_sent(self, log_id):
        cfg = self.p.cfg
        now = self.p.clock.now()
        self.codes[log_id] = {"code": f"{secrets.randbelow(10**4):04d}", "attempts": 0,
                              "expires": now + cfg.otp_ttl, "done": False}
        heapq.heappush(self.timeouts, (now + cfg.otp_ttl, log_id))

    def run_due_timeouts(self):
        now = self.p.clock.now()
        while self.timeouts and self.timeouts[0][0] <= now:
            _, log_id = heapq.heappop(self.timeouts)
            if not self.codes[log_id]["done"]:
                self.on_failed_or_timeout(log_id)

    # ---- verify endpoint ----
    def verify(self, session_id, log_id, code):
        cfg = self.p.cfg
        if not self.p.rl("otp:verify:session", session_id, cfg.verify_session_limit).try_acquire():
            return False
        entry = self.codes.get(log_id)
        if entry is None or entry["done"] or entry["expires"] < self.p.clock.now():
            return False
        entry["attempts"] += 1
        if entry["code"] == code:
            self.on_verified(log_id)
            return True
        if entry["attempts"] >= cfg.otp_max_attempts:
            self.on_failed_or_timeout(log_id)
        return False

    def code_for(self, log_id):
        """Test helper: what the user would have received."""
        return self.codes[log_id]["code"]

    # ---- reputation effects ----
    def on_verified(self, log_id):
        rec = self.p.sms_history[log_id]
        self.codes[log_id]["done"] = True
        for key in rec["reputation_keys"]:
            self.p.rep.incr(key, "verified")
        self.p.rep.mark_trusted("num:" + rec["phone_number"])

    def on_failed_or_timeout(self, log_id):
        rec = self.p.sms_history[log_id]
        self.codes[log_id]["done"] = True
        cfg = self.p.cfg
        for key in rec["reputation_keys"]:
            self.p.rep.incr(key, "failed")
            r = self.p.rep.get(key)
            resolved = r.verified + r.failed
            if resolved >= cfg.denylist_min_sample and r.verified / resolved < cfg.denylist_ratio:
                if not key.startswith(("num:", "country:", "prefix:", "sess:")):
                    self.p.store.set("deny:" + key, 1, cfg.denylist_ttl)
