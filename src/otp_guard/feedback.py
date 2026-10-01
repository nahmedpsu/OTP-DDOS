"""Verification feedback loop and the OTP verify endpoint's own protections.
All state lives in the pipeline's store so any instance can verify any code.

State machine of one send (otp:code:<log_id>), every transition an atomic read-modify-write
(store.update: a lock on the memory store, WATCH/MULTI/EXEC on Redis), so two workers handling
callbacks for the same message cannot both apply an effect:

    delivery:   none --(positive receipt)--> delivered      first transition wins; a repeated
                none --(negative receipt)--> failed         positive receipt changes nothing
                none --(no receipt for receipt_grace_s)--> resolution 'undelivered'
    resolution: none -> 'failed' (delivered, resolution_timeout_s passed, no code entered)
                none -> 'undelivered' (failed receipt or no receipt)
    done:       the code was entered (verified) or exhausted its attempts

Receipt rules (on_delivery): a duplicate positive receipt is ignored (delivered_at is never
moved); a negative receipt after a positive one is a *conflict*, counted on the entry and
ignored (the carrier said it delivered; the person may still enter the code); a positive receipt
after a negative one, or after the grace period resolved the send as undelivered, *reopens* the
send if the code is still valid: the undelivered count is reversed and the resolution clock
starts from this receipt (the carrier corrected itself, or delivered late). A receipt for a
finished or unknown send is ignored.

Only verified and failed feed the conversion ratio and the destination-block tests; an
undelivered send tells nothing about the person behind the number. A late verification of a
send already resolved 'failed' is reclassified: the reputation counts move from failed to
verified and the block statistic gets the failure increment subtracted (then re-floored). That
subtraction is exact unless the statistic hit its floor in between, and a verdict already
issued is not revoked by it: it expires with its own TTL. Verification speed is clocked from the
receipt. A carrier whose blocks all fail at once is an outage, not a pumper, and the block
tests are suspended for that carrier while it lasts."""
import math
import secrets


class FeedbackLoop:
    TIMEOUTS = "otp:timeouts"
    VERDICT_LOG = "verdict:log"       # every verdict event of the last 24 h: member "<block>|<stage>|<time>"
    BLOCK = "blocktest:"              # per-block sequential-test state: counts and the two running statistics

    def __init__(self, pipeline):
        self.p = pipeline

    def _key(self, log_id):
        return f"otp:code:{log_id}"

    # ---- send side ----
    @staticmethod
    def new_code():
        return f"{secrets.randbelow(10**4):04d}"

    def on_sent(self, log_id, code):
        """Called after the message carrying `code` was handed to the sender."""
        cfg = self.p.cfg
        now = self.p.clock.now()
        self.p.store.set(self._key(log_id), {"code": code, "attempts": 0,
                                             "expires": now + cfg.otp_ttl, "done": False, "timed_out": False,
                                             "resolution": None, "delivery": None, "delivered_at": None,
                                             "conflicts": 0},
                         cfg.otp_ttl * 2)
        # reputation resolves resolution_timeout_s after delivery (a late verification is reclassified);
        # the code itself stays valid for otp_ttl. Without receipts the clock runs from the send.
        due = now + (cfg.receipt_grace_s if cfg.delivery_receipts else min(cfg.resolution_timeout_s, cfg.otp_ttl))
        self.p.store.zadd(self.TIMEOUTS, due, str(log_id))

    def on_delivery(self, log_id, ok, at=None):
        """Delivery receipt from the provider (status callback) or the sender adapter. Returns what
        happened: 'delivered', 'failed', 'duplicate', 'conflict', 'reopened', 'expired' or 'ignored'
        (see the module docstring for the rules)."""
        cfg = self.p.cfg
        if not cfg.delivery_receipts:
            return "ignored"                                 # send-clocked mode ignores receipts
        now = self.p.clock.now()
        out = {}

        def fn(entry):
            if entry is None or entry["done"]:
                out["t"] = "ignored"
                return None
            if ok:
                if entry["delivery"] == "delivered":
                    out["t"] = "duplicate"                   # the first delivery transition stands
                    return None
                if entry["expires"] < now:
                    out["t"] = "expired"
                    return None
                e = dict(entry)
                e["delivery"], e["delivered_at"] = "delivered", (at if at is not None else now)
                if e.get("resolution") == "undelivered":    # late or corrected report: reopen
                    e["resolution"], e["timed_out"] = None, False
                    out["t"] = "reopened"
                else:
                    out["t"] = "delivered"
                return e
            if entry["delivery"] == "delivered":
                out["t"] = "conflict"                        # delivered, then "failed": keep the delivery
                e = dict(entry); e["conflicts"] = e.get("conflicts", 0) + 1
                return e
            if entry["delivery"] == "failed" or entry.get("resolution"):
                out["t"] = "duplicate"
                return None
            e = dict(entry); e["delivery"] = "failed"
            out["t"] = "failed"
            return e

        entry, _ = self.p.store.update(self._key(log_id), fn, cfg.otp_ttl * 2)
        t = out["t"]
        if t in ("delivered", "reopened"):
            rec = self.p.sms_history[log_id]
            self._outage_record(rec, "delivered", now)
            if t == "reopened":
                for key in rec["reputation_keys"]:
                    self.p.rep.incr(key, "undelivered", -1)
            self.p.store.zadd(self.TIMEOUTS, entry["delivered_at"] + min(cfg.resolution_timeout_s, cfg.otp_ttl), str(log_id))
        elif t == "failed":
            self._outage_record(self.p.sms_history[log_id], "undelivered", now)
            self._resolve_undelivered(log_id)
        return t

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
        now = self.p.clock.now()

        def fn(entry):
            if entry is None or entry["done"] or entry["expires"] < now:
                return None
            e = dict(entry); e["attempts"] += 1
            return e

        entry, counted = self.p.store.update(self._key(log_id), fn, cfg.otp_ttl * 2)
        if not counted:
            return False
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
        """Atomically claims the transition. resolution None closes the code; 'failed' or
        'undelivered' resolves reputation but keeps the code valid until otp_ttl. Returns the entry
        as it was *before* the transition when this call made it, else None (already done, already
        resolved, or unknown): exactly one of several concurrent callers gets a non-None result."""
        before = {}

        def fn(entry):
            if entry is None or entry["done"]:
                return None
            if resolution and entry.get("resolution"):
                return None
            before["entry"] = entry
            e = dict(entry)
            if resolution:
                e["resolution"], e["timed_out"] = resolution, True
            else:
                e["done"] = True
            return e

        _, changed = self.p.store.update(self._key(log_id), fn, self.p.cfg.otp_ttl * 2)
        return before["entry"] if changed else None

    # ---- reputation effects ----
    def on_verified(self, log_id):
        rec = self.p.sms_history[log_id]
        cfg = self.p.cfg
        before = self._finish(log_id)
        if before is None:
            return                                            # already closed: a duplicate or concurrent callback
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
        if self._finish(log_id, resolution="failed" if keep_code else None) is None:
            return                                            # already resolved or closed: a duplicate
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
    def _increments(self):
        cfg = self.p.cfg
        return {"verify": math.log(cfg.sprt_attack_conversion / cfg.sprt_legit_conversion),
                "fail": math.log((1 - cfg.sprt_attack_conversion) / (1 - cfg.sprt_legit_conversion)),
                "fast": math.log(cfg.sprt_attack_fast / cfg.sprt_legit_fast),
                "slow": math.log((1 - cfg.sprt_attack_fast) / (1 - cfg.sprt_legit_fast))}

    @staticmethod
    def _empty_block_state(verdicts=0):
        return {"v": 0, "f": 0, "fv": 0, "conv": 0.0, "speed": 0.0, "verdicts": verdicts}

    def _block_event(self, key, verified, fast=False, undo=False):
        """One resolved send on a destination block, fed to the sequential tests. The block's counts
        and its two running statistics live in one document updated atomically, so concurrent
        events from several workers are all counted and the threshold is crossed exactly once; the
        crossing resets the document and the verdict is issued by the caller that crossed it. The
        statistics are floored at -block_credit_thresholds x log(threshold) ('cusum'; 0 is Page's
        CUSUM, which banks nothing) or unbounded ('sprt')."""
        cfg = self.p.cfg
        if "feedback" not in cfg.features:
            return
        inc = self._increments()
        thr = math.log(cfg.sprt_threshold)
        floor = -cfg.block_credit_thresholds * thr if cfg.block_test == "cusum" else -math.inf
        out = {}

        def fn(cur):
            out.clear()                                      # fn may run again after a lost compare-and-set
            st = dict(cur) if cur else self._empty_block_state()
            if verified:
                st["v"] += 1
                st["conv"] += inc["verify"]
                if fast:
                    st["fv"] += 1
                    st["speed"] += inc["fast"]
                else:
                    st["speed"] += inc["slow"]
                if undo:                                     # a late verification of a send counted as failed
                    st["f"] = max(0, st["f"] - 1)
                    st["conv"] -= inc["fail"]
            else:
                st["f"] += 1
                st["conv"] += inc["fail"]
            st["conv"], st["speed"] = max(floor, st["conv"]), max(floor, st["speed"])
            conv_hit = "conversion" in cfg.block_tests and st["v"] + st["f"] >= cfg.sprt_min_events and st["conv"] > thr
            speed_hit = "speed" in cfg.block_tests and st["v"] >= cfg.sprt_min_events and st["speed"] > thr
            if conv_hit or speed_hit:
                out["reason"] = "never_verified" if conv_hit else "machine_verified"
                return self._empty_block_state(st.get("verdicts", 0) + 1)   # the next test starts from zero
            return st

        self.p.store.update(self.BLOCK + key, fn, cfg.denylist_ttl)
        if "reason" in out:
            self._issue_verdict(key, out["reason"])

    def block_llr(self, key):
        """(conversion statistic, speed statistic, (verified, failed, fast) counts) for a block."""
        st = self.p.store.get(self.BLOCK + key) or self._empty_block_state()
        return st["conv"], st["speed"], (st["v"], st["f"], st["fv"])

    def _issue_verdict(self, key, reason):
        """Record one verdict event and apply cfg.block_action: 'deny' is a 24-hour denylist; 'graded'
        makes the block's first-time clients solve a challenge (stage 1) and, on a second verdict
        inside block_verdict_ttl, moves them to non-SMS channels (stage 2)."""
        cfg = self.p.cfg
        now = self.p.clock.now()
        if cfg.block_action == "deny":
            self.p.store.set("deny:" + key, reason, cfg.denylist_ttl)
            stage = "deny"
        else:
            current = self.p.store.get("verdict:" + key)
            stage = 2 if current else 1                     # a second verdict inside the TTL escalates
            self.p.store.set("verdict:" + key, {"stage": stage, "reason": reason, "at": now}, cfg.block_verdict_ttl)
        # one member per event (not per block), so verdict counts, affected blocks and exposure can be told apart;
        # the sequence number keeps two verdicts at the same instant distinct
        seq = self.p.store.incr("verdict:seq")
        self.p.store.zadd(self.VERDICT_LOG, now, f"{key}|{stage}|{now:.3f}|{seq}", ttl=cfg.denylist_ttl)

    def verdict_events(self, since=float("-inf"), until=float("inf")):
        """Every verdict event in the window: [{'block', 'stage', 'at'}], oldest first."""
        out = []
        for m in self.p.store.zrangebyscore(self.VERDICT_LOG, since, until):
            block, stage, at, _seq = m.rsplit("|", 3)
            out.append({"block": block, "stage": int(stage) if stage.isdigit() else stage, "at": float(at)})
        return out

    def block_verdict(self, key):
        """None, or {'stage': 1|2, 'reason': ...} for a block under a graded verdict."""
        return self.p.store.get("verdict:" + key)
