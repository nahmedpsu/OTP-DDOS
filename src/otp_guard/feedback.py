"""Verification feedback loop and the OTP verify endpoint's own protections.
All state lives in the pipeline's store so any instance can verify any code.

A send moves through: sent -> (delivery receipt) -> verified | failed | undelivered.
Only verified and failed feed the conversion ratio and the destination-block tests; an
undelivered send (no receipt inside the grace period, or a failed one) is counted on its own
and tells nothing about the person behind the number. Verification speed is clocked from the
receipt. A carrier whose blocks all fail at once is an outage, not a pumper, and the block
tests are suspended for that carrier while it lasts."""
import math
import secrets


class FeedbackLoop:
    TIMEOUTS = "otp:timeouts"
    VERDICT_LOG = "verdict:log"       # blocks that reached a verdict in the last 24 h

    def __init__(self, pipeline):
        self.p = pipeline

    def _key(self, log_id):
        return f"otp:code:{log_id}"

    # ---- send side ----
    def on_sent(self, log_id):
        cfg = self.p.cfg
        now = self.p.clock.now()
        self.p.store.set(self._key(log_id), {"code": f"{secrets.randbelow(10**4):04d}", "attempts": 0,
                                             "expires": now + cfg.otp_ttl, "done": False, "timed_out": False,
                                             "resolution": None, "delivery": None, "delivered_at": None},
                         cfg.otp_ttl * 2)
        # reputation resolves resolution_timeout_s after delivery (a late verification is reclassified);
        # the code itself stays valid for otp_ttl. Without receipts the clock runs from the send.
        due = now + (cfg.receipt_grace_s if cfg.delivery_receipts else min(cfg.resolution_timeout_s, cfg.otp_ttl))
        self.p.store.zadd(self.TIMEOUTS, due, str(log_id))

    def on_delivery(self, log_id, ok, at=None):
        """Delivery receipt from the provider (status callback) or the sender adapter."""
        cfg = self.p.cfg
        if not cfg.delivery_receipts:
            return                                           # send-clocked mode ignores receipts
        entry = self.p.store.get(self._key(log_id))
        if entry is None or entry["done"] or entry.get("resolution"):
            return
        now = self.p.clock.now()
        rec = self.p.sms_history[log_id]
        self._outage_record(rec, "delivered" if ok else "undelivered", now)
        if ok:
            entry["delivery"], entry["delivered_at"] = "delivered", (at if at is not None else now)
            self.p.store.set(self._key(log_id), entry, cfg.otp_ttl * 2)
            self.p.store.zadd(self.TIMEOUTS, entry["delivered_at"] + min(cfg.resolution_timeout_s, cfg.otp_ttl), str(log_id))
        else:
            entry["delivery"] = "failed"
            self.p.store.set(self._key(log_id), entry, cfg.otp_ttl * 2)
            self._resolve_undelivered(log_id)

    def run_due_timeouts(self):
        """Called by a scheduler (cron, worker loop) every minute or so."""
        cfg = self.p.cfg
        now = self.p.clock.now()
        for member in list(self.p.store.zrangebyscore(self.TIMEOUTS, float("-inf"), now)):
            log_id = int(member)
            entry = self.p.store.get(self._key(log_id))
            if entry is None or entry["done"] or entry.get("resolution"):
                self.p.store.zrem(self.TIMEOUTS, member)
                continue
            if cfg.delivery_receipts and entry.get("delivery") != "delivered":
                self._resolve_undelivered(log_id)            # no receipt inside the grace period
            elif cfg.delivery_receipts and now < entry["delivered_at"] + min(cfg.resolution_timeout_s, cfg.otp_ttl):
                continue                                     # rescheduled by on_delivery; not due yet
            else:
                self.on_failed_or_timeout(log_id, keep_code=True)
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

    def _finish(self, log_id, resolution=None):
        """resolution None closes the code; 'failed' or 'undelivered' resolves reputation but keeps
        the code valid until otp_ttl."""
        entry = self.p.store.get(self._key(log_id))
        if entry is None or entry["done"]:
            return None
        if resolution:
            entry["resolution"], entry["timed_out"] = resolution, True
        else:
            entry["done"] = True
        self.p.store.set(self._key(log_id), entry, self.p.cfg.otp_ttl * 2)
        return entry

    # ---- reputation effects ----
    def on_verified(self, log_id):
        rec = self.p.sms_history[log_id]
        cfg = self.p.cfg
        before = self.p.store.get(self._key(log_id)) or {}
        entry = self._finish(log_id)
        earlier = before.get("resolution")                   # already counted: reclassify
        clock_from = before.get("delivered_at") if (cfg.delivery_receipts and before.get("delivered_at") is not None) \
            else float(rec.get("sent_at", 0))
        fast = (self.p.clock.now() - clock_from) < cfg.fast_verify_seconds
        if rec.get("known_good"):
            self._outage_record(rec, "kg_verified", self.p.clock.now())
        suspended = self._outage_active(rec)
        for key in rec["reputation_keys"]:
            self.p.rep.incr(key, "verified")
            if earlier:
                self.p.rep.incr(key, earlier, -1)
            if fast:
                self.p.rep.incr(key, "fast_verified")
            if key.startswith("block:") and not suspended:
                self._block_event(key, verified=True, fast=fast, undo=earlier == "failed")
        self.p.rep.mark_trusted("num:" + rec["phone_number"])

    def on_failed_or_timeout(self, log_id, keep_code=False):
        rec = self.p.sms_history[log_id]
        self._finish(log_id, resolution="failed" if keep_code else None)
        cfg = self.p.cfg
        self._outage_record(rec, "kg_failed" if rec.get("known_good") else "failed", self.p.clock.now())
        suspended = self._outage_active(rec)
        for key in rec["reputation_keys"]:
            self.p.rep.incr(key, "failed")
            if key.startswith("block:"):
                if not suspended:
                    self._block_event(key, verified=False)
                continue
            r = self.p.rep.get(key)
            resolved = r.verified + r.failed
            if resolved >= cfg.denylist_min_sample and r.verified / resolved < cfg.denylist_ratio \
                    and "feedback" in cfg.features:
                # Fine-grained keys only. A residential ASN is thousands of real people; denylisting it
                # would hand the attacker a denial of service. Hosting ASNs carry no such users.
                if key.startswith(("ip:", "subnet:", "fp:")) or \
                        (key.startswith("asn:") and rec.get("asn_is_datacenter")):
                    self.p.store.set("deny:" + key, 1, cfg.denylist_ttl)

    def _resolve_undelivered(self, log_id):
        rec = self.p.sms_history[log_id]
        if self._finish(log_id, resolution="undelivered") is None:
            return
        for key in rec["reputation_keys"]:
            self.p.rep.incr(key, "undelivered")

    # ---- carrier outage detector ----
    def _carrier(self, rec):
        return rec.get("prefix") or "unknown"

    def _outage_record(self, rec, event, now):
        """event: 'delivered' | 'undelivered' (from receipts: the carrier's own report), 'failed' (any
        client's code was not entered) or 'kg_verified' | 'kg_failed' (outcomes of clients with verified
        history, whom an attacker cannot impersonate). The delivery signal uses all sends; the
        conversion signal uses only known-good clients, so a decoy flood cannot buy a suspension."""
        cfg = self.p.cfg
        c = self._carrier(rec)
        windows = {"delivered": cfg.outage_window_s, "undelivered": cfg.outage_window_s, "failed": cfg.outage_kg_window_s,
                   "kg_verified": cfg.outage_kg_window_s, "kg_failed": cfg.outage_kg_window_s, "blocks": cfg.outage_kg_window_s}
        self.p.store.zadd(f"outage:{event}:{c}", now, str(rec["log_id"]), ttl=2 * windows[event])
        self.p.store.zremrangebyscore(f"outage:{event}:{c}", float("-inf"), now - windows[event])   # each key trims itself
        if event in ("undelivered", "failed", "kg_failed"):
            self.p.store.zadd(f"outage:blocks:{c}", now, rec["phone_number"][:cfg.destination_block_digits], ttl=2 * windows["blocks"])
            self.p.store.zremrangebyscore(f"outage:blocks:{c}", float("-inf"), now - windows["blocks"])
        if self.p.store.exists(f"outage:{c}"):
            return
        names = list(windows)
        counts = self.p.store.zcount_many([f"outage:{k}:{c}" for k in names], now - max(windows.values()), now)
        n = {k: v for k, v in zip(names, counts)}
        # the counts above use the longest window; the receipt signal gets its own, shorter one
        short = self.p.store.zcount_many([f"outage:delivered:{c}", f"outage:undelivered:{c}"], now - cfg.outage_window_s, now)
        n["delivered"], n["undelivered"] = short
        if n["blocks"] < cfg.outage_min_blocks:
            return
        dlv = n["delivered"] + n["undelivered"]
        kg = n["kg_verified"] + n["kg_failed"]
        delivery_collapse = dlv >= cfg.outage_min_sends and n["undelivered"] / dlv >= cfg.outage_undelivered_ratio
        conversion_collapse = kg >= cfg.outage_min_known_good and n["kg_verified"] / kg < cfg.outage_conversion
        if delivery_collapse or conversion_collapse:
            # many unrelated blocks of one carrier failing together: the carrier, not a pumper
            kind = "delivery" if delivery_collapse else "conversion"
            self.p.store.set(f"outage:{c}", dict(n, since=now, kind=kind), cfg.outage_ttl)
            self.p.svc.alerts.alert(f"Carrier outage suspected on prefix {c} ({kind} collapse across {n['blocks']} blocks); "
                                    f"block tests suspended for {cfg.outage_ttl} s", n)

    def _outage_active(self, rec):
        return self.p.store.exists(f"outage:{self._carrier(rec)}")

    # ---- destination-block tests ----
    def _block_event(self, key, verified, fast=False, undo=False):
        """One resolved send on a destination block, fed to the sequential tests. Counters live apart
        from the reputation hash so that a verdict restarts them and an outage leaves them untouched."""
        cfg = self.p.cfg
        if "feedback" not in cfg.features:
            return
        skey = "sprt:" + key
        if verified:
            self.p.store.hincrby(skey, "v", 1, ttl=cfg.denylist_ttl)
            if fast:
                self.p.store.hincrby(skey, "fv", 1, ttl=cfg.denylist_ttl)
            if undo:
                self.p.store.hincrby(skey, "f", -1, ttl=cfg.denylist_ttl)
        else:
            self.p.store.hincrby(skey, "f", 1, ttl=cfg.denylist_ttl)
        self._sprt_block(key)

    def block_llr(self, key):
        """(conversion LLR, speed LLR, counts) for a block from its sequential-test counters."""
        cfg = self.p.cfg
        c = self.p.store.hgetall("sprt:" + key)
        v, f, fv = max(c.get("v", 0), 0), max(c.get("f", 0), 0), max(c.get("fv", 0), 0)
        conv = v * math.log(cfg.sprt_attack_conversion / cfg.sprt_legit_conversion) + \
            f * math.log((1 - cfg.sprt_attack_conversion) / (1 - cfg.sprt_legit_conversion))
        speed = fv * math.log(cfg.sprt_attack_fast / cfg.sprt_legit_fast) + \
            (v - fv) * math.log((1 - cfg.sprt_attack_fast) / (1 - cfg.sprt_legit_fast))
        return conv, speed, (v, f, fv)

    def _sprt_block(self, key):
        """Sequential probability-ratio tests on a destination block. Two hypothesis pairs:
        conversion (a flooder's numbers never verify) and verification speed (a machine enters codes
        within seconds of delivery). A verdict is reached when either log-likelihood ratio exceeds
        log(sprt_threshold); what the verdict does depends on cfg.block_action."""
        cfg = self.p.cfg
        conv, speed, (v, f, fv) = self.block_llr(key)
        thr = math.log(cfg.sprt_threshold)
        hit = (v + f >= cfg.sprt_min_events and conv > thr) or (v >= cfg.sprt_min_events and speed > thr)
        if not hit:
            return
        self.p.store.delete("sprt:" + key)                   # the next test starts from zero
        reason = "never_verified" if conv > thr else "machine_verified"
        self.p.store.zadd(self.VERDICT_LOG, self.p.clock.now(), key, ttl=cfg.denylist_ttl)   # for dashboards and audits
        if cfg.block_action == "deny":
            self.p.store.set("deny:" + key, reason, cfg.denylist_ttl)
            return
        current = self.p.store.get("verdict:" + key)
        stage = 2 if current else 1                         # a second verdict inside the TTL escalates
        self.p.store.set("verdict:" + key, {"stage": stage, "reason": reason, "at": self.p.clock.now()}, cfg.block_verdict_ttl)

    def block_verdict(self, key):
        """None, or {'stage': 1|2, 'reason': ...} for a block under a graded verdict."""
        return self.p.store.get("verdict:" + key)
