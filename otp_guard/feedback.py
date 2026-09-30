"""Verification feedback loop and the OTP verify endpoint's own protections.
All state lives in the pipeline's store so any instance can verify any code."""
import secrets


class FeedbackLoop:
    TIMEOUTS = "otp:timeouts"

    def __init__(self, pipeline):
        self.p = pipeline

    def _key(self, log_id):
        return f"otp:code:{log_id}"

    # ---- send side ----
    def on_sent(self, log_id):
        cfg = self.p.cfg
        now = self.p.clock.now()
        self.p.store.set(self._key(log_id), {"code": f"{secrets.randbelow(10**4):04d}", "attempts": 0,
                                             "expires": now + cfg.otp_ttl, "done": False}, cfg.otp_ttl * 2)
        self.p.store.zadd(self.TIMEOUTS, now + cfg.otp_ttl, str(log_id))

    def run_due_timeouts(self):
        """Called by a scheduler (cron, worker loop) every minute or so."""
        now = self.p.clock.now()
        for member in self.p.store.zrangebyscore(self.TIMEOUTS, float("-inf"), now):
            log_id = int(member)
            entry = self.p.store.get(self._key(log_id))
            if entry is not None and not entry["done"]:
                self.on_failed_or_timeout(log_id)
            self.p.store.zrem(self.TIMEOUTS, member)

    # ---- verify endpoint ----
    def verify(self, session_id, log_id, code):
        cfg = self.p.cfg
        if not self.p.rl("otp:verify:session", session_id, cfg.verify_session_limit).try_acquire():
            return False
        entry = self.p.store.get(self._key(log_id))
        if entry is None or entry["done"] or entry["expires"] < self.p.clock.now():
            return False
        entry["attempts"] += 1
        self.p.store.set(self._key(log_id), entry, cfg.otp_ttl * 2)
        if secrets.compare_digest(entry["code"], str(code)):
            self.on_verified(log_id)
            return True
        if entry["attempts"] >= cfg.otp_max_attempts:
            self.on_failed_or_timeout(log_id)
        return False

    def verify_by_session(self, session_id, mobile, code):
        """Verify without a log id: the client only knows its session and the number it used.
        A session with no pending code still consumes a verify attempt and gets the same answer."""
        from .pipeline import Pipeline
        mobile = Pipeline.parse_e164(mobile or "") or ""
        log_id = self.p.store.get(f"otp:latest:{session_id}:{mobile}")
        if log_id is None:
            self.p.rl("otp:verify:session", session_id, self.p.cfg.verify_session_limit).try_acquire()
            return False
        return self.verify(session_id, int(log_id), code)

    def code_for(self, log_id):
        """Test helper: what the user would have received."""
        return self.p.store.get(self._key(log_id))["code"]

    def _finish(self, log_id):
        entry = self.p.store.get(self._key(log_id))
        if entry is None:
            return None
        if entry["done"]:
            return None
        entry["done"] = True
        self.p.store.set(self._key(log_id), entry, self.p.cfg.otp_ttl * 2)
        return entry

    # ---- reputation effects ----
    def on_verified(self, log_id):
        rec = self.p.sms_history[log_id]
        self._finish(log_id)
        for key in rec["reputation_keys"]:
            self.p.rep.incr(key, "verified")
        self.p.rep.mark_trusted("num:" + rec["phone_number"])

    def on_failed_or_timeout(self, log_id):
        rec = self.p.sms_history[log_id]
        self._finish(log_id)
        cfg = self.p.cfg
        for key in rec["reputation_keys"]:
            self.p.rep.incr(key, "failed")
            r = self.p.rep.get(key)
            resolved = r.verified + r.failed
            if resolved >= cfg.denylist_min_sample and r.verified / resolved < cfg.denylist_ratio:
                if not key.startswith(("num:", "country:", "prefix:", "sess:")):
                    self.p.store.set("deny:" + key, 1, cfg.denylist_ttl)
