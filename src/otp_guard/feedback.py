"""Verification feedback loop and the OTP verify endpoint's own protections.
All state lives in the pipeline's store so any instance can verify any code.

Transitions of one send (otp:code:<log_id>)
-------------------------------------------
Every transition is one compare-and-set on the send's entry (store.update: a lock on the memory
store, WATCH/MULTI/EXEC on Redis). The function that decides the transition sees the whole entry,
so a decision and the state it depends on cannot be separated by another worker:

    receipt +   none -> delivered                    (first positive receipt wins; delivered_at never moves)
                undelivered -> delivered ("reopened") (a late or corrected report while the code is valid)
    receipt -   none -> failed AND resolution 'undelivered' in the same transition
                delivered -> delivered ("conflict", counted, ignored)
    timeout     not delivered by receipt_grace_s -> resolution 'undelivered'
                delivered, resolution_timeout_s passed, no code -> resolution 'failed'
    verify      attempts + 1, and in the same transition: correct code -> done (verified);
                attempts exhausted -> done (failed, unless already resolved)

Effects, at most once, and once unless abandoned
-----------------------------------------------
A transition does not apply its effects directly. It records them in the entry, in the same
compare-and-set, as a batch with a sequence number and the transition's time; the caller then
applies the batch and removes it. Effects are applied at the recorded time, not at the time of a
replay: an outage observation is inserted at its own time (the detector's windows end now, so a
replayed old observation cannot enter the current window) and a reputation increment lands in its
own hour (fifth-round review, M8; up to 2.8.0 a replay used the recovery time). Since 2.8.2 (sixth-round
review, M4, M5) the outage detector's distinct-block set keeps each block's newest failure time under
replay (a replayed older failure never lowers it), and a block-test event is applied at its own time
too: it counts toward the test that was running then (an event dated before the last crossing
belongs to a concluded test and is recorded but not counted), a crossing it causes issues its verdict
at the event's time and escalates against the verdict active at that time, and the verdict's lifetime
runs from the event's time (see _block_event). So reputation, outage and block-test effects all apply
at the transition's time; what a replay can still differ in is when the operator learns of a verdict.
Before a transition the caller writes a write-ahead intent (otp:intents);
run_due_timeouts() sweeps intents older than RECOVER_AFTER_S and applies whatever batches are still
recorded, so a process that dies between the compare-and-set and the end of its effects leaves work
a later sweep completes.

Applying is idempotent within a replay horizon H = replay_horizon_s() (the entry's lifetime,
2 x otp_ttl): the reputation increments of a batch are one once-only script
(store.hincrby_batch_once, keyed by log id and batch number, marker kept H + 1 h), and block-test
events carry an event id the block document remembers for id_retention_s() = H + otp_ttl + 60 s:
a reversal can be recorded up to otp_ttl after the failure it names and is itself replayable for H,
so the failure's id outlives every replay of its reversal. Identifiers are kept by age,
not by count, so no volume of later events can push one out early (an earlier version kept the
last 256 and could count a replayed failure twice). A batch is applied only while it is younger than
H; an older one (possible only if its entry was kept alive by later writes and no sweep ran for
H) has its counting effects skipped and counted in otp:fx:abandoned, never applied twice. The
remaining effects (outage records, the trusted-number set, timeout scheduling, denylist checks)
are idempotent by construction. So: every recorded effect is applied at most once, and exactly once
if a sweep runs within H of the transition. Out of scope: an entry that expires before a sweep
reaches it (its effects are lost, not doubled), and Redis Cluster (the scripts assume one shard).
The size of a block document grows with the events it receives within its retention, which the
hourly SMS ceiling bounds.

Two races disclosed in 2.8.0 are closed in 2.8.1 (fifth-round review, M9; regression tests in
tests/unit/test_fifth_round.py and on a real Redis). (1) A reversal whose failure id had expired:
ids lived H + 60 s from the failure, so a late verification whose first sweep came more than about
13 minutes after it found no failure to subtract; ids now live H + otp_ttl + 60 s. (2) The timeout
worker's read/act separation: run_due_timeouts() removed a send's member from otp:timeouts after
its transition, so a correcting receipt that reopened the send in between lost its rescheduled
timeout; the member is now removed only if its due time is unchanged (store.zrem_if_score, one
script on Redis).

Step 11 is not one transaction (budget reservation, audit record, `sent` counters, OTP entry,
enqueue). Its crash semantics: a crash before on_sent leaves a reserved budget unit and possibly
`sent` counts without a send (both conservative); a crash after on_sent and before enqueue leaves
an entry that resolves as undelivered at the grace period and feeds no test.

Block tests and verdicts
------------------------
A destination block's counts, its two running statistics, its current verdict (stage, reason,
issued, until) and its verdict history live in one document (blocktest:<block>) updated by one
compare-and-set. A threshold crossing resets the statistics and decides the stage from the verdict
already active in the same document: a second crossing while a verdict is active escalates to
stage 2, whichever worker processed it. Actions: 'graded' (stage 1: first-time clients solve a
challenge; stage 2: non-SMS channels only), 'deny' (24-hour denylist), 'observe' (tests run and
verdicts are recorded, nothing is enforced: the counterfactual for attributable-harm studies).

Only verified and failed feed the conversion ratio and the block tests; an undelivered send tells
nothing about the person behind the number (receipt_policy 'standard'). Under receipt_policy
'robust' a failed receipt also counts as a failure for the block test unless the carrier is in an
outage. A late verification of a send resolved 'failed' is reclassified: counts move from failed to
verified and the block statistic gets the failure increment subtracted (then re-floored); a verdict
already issued is not revoked. A carrier whose blocks all fail at once is an outage, not a pumper,
and the block tests are suspended for that carrier while it lasts."""
import math
import secrets
import uuid


class FeedbackLoop:
    TIMEOUTS = "otp:timeouts"
    INTENTS = "otp:intents"           # write-ahead intents: "<log_id>:<token>" scored by time
    BLOCK = "blocktest:"              # per-block sequential-test state, current verdict and verdict history
    RECOVER_AFTER_S = 30
    SEEN_MARGIN_S = 60                # identifiers outlive the replay horizon by this (clock skew between workers)
    ABANDONED = "otp:fx:abandoned"    # batches too old to replay safely (counting effects skipped)

    def __init__(self, pipeline):
        self.p = pipeline

    def _key(self, log_id):
        return f"otp:code:{log_id}"

    def _ttl(self):
        return self.p.cfg.otp_ttl * 2

    def replay_horizon_s(self):
        """How long after a transition its recorded effects may still be applied (see the module notes)."""
        return self._ttl()

    def id_retention_s(self):
        """How long a block remembers an event identifier: the replay horizon, plus the code lifetime (a
        reversal can be recorded up to otp_ttl after the failure it reverses and is itself replayable for
        the horizon), plus a margin for clock skew between workers."""
        return self.replay_horizon_s() + self.p.cfg.otp_ttl + self.SEEN_MARGIN_S

    # ---------------------------------------------------------------- send side
    @staticmethod
    def new_code():
        return f"{secrets.randbelow(10**4):04d}"

    def on_sent(self, log_id, code):
        """Called after the audit record exists and before the message is handed to the sender."""
        cfg = self.p.cfg
        now = self.p.clock.now()
        self.p.store.set(self._key(log_id), {"code": code, "attempts": 0, "sent_at": now,
                                             "expires": now + cfg.otp_ttl, "done": False, "timed_out": False,
                                             "resolution": None, "delivery": None, "delivered_at": None,
                                             "conflicts": 0, "tseq": 0, "pending": [], "receipt_block_fail": False},
                         self._ttl())
        # reputation resolves resolution_timeout_s after delivery (a late verification is reclassified);
        # the code itself stays valid for otp_ttl. Without receipts the clock runs from the send.
        due = now + (cfg.receipt_grace_s if cfg.delivery_receipts else min(cfg.resolution_timeout_s, cfg.otp_ttl))
        self.p.store.zadd(self.TIMEOUTS, due, str(log_id))

    # ---------------------------------------------------------------- transition machinery
    def _transition(self, log_id, decide):
        """decide(entry, rec, now) -> (new entry or None, kind, effects or None). Returns (kind, entry)."""
        rec = self.p.sms_history.get(log_id)
        if rec is None:
            return "ignored", None
        store = self.p.store
        now = self.p.clock.now()
        token = f"{log_id}:{uuid.uuid4().hex[:12]}"
        store.zadd(self.INTENTS, now, token)
        out = {}

        def fn(entry):
            out.clear()                                      # may run again after a lost compare-and-set
            if entry is None:
                out["kind"] = "ignored"
                return None
            new, kind, effects = decide(entry, rec, now)
            out["kind"] = kind
            if new is None:
                return None
            if effects:
                tseq = new.get("tseq", 0) + 1
                batch = {"tseq": tseq, "at": now, "effects": effects}
                new["tseq"] = tseq
                if any(f[0] == "block" and not f[2] and not f[4] for f in effects):
                    new["block_fail_tseq"] = tseq          # a later reversal names this failure
                new["pending"] = list(new.get("pending") or []) + [batch]
                out["batch"] = batch
            out["entry"] = new
            return new

        store.update(self._key(log_id), fn, self._ttl())
        if "batch" in out:
            self._apply(log_id, rec, out["batch"])
        store.zrem(self.INTENTS, token)
        return out.get("kind", "ignored"), out.get("entry")

    def _apply(self, log_id, rec, batch):
        """Apply one recorded batch of effects (idempotent), then remove it from the entry."""
        cfg = self.p.cfg
        tseq = batch["tseq"]
        now = self.p.clock.now()
        at = batch.get("at", now)                            # the transition's time: a replay keeps it
        suspended = None
        stale = now - at > self.replay_horizon_s()
        if stale:
            self.p.store.incr(self.ABANDONED)
        for eff in batch["effects"]:
            kind = eff[0]
            if stale and kind in ("rep", "block", "block_unfail"):
                continue                                     # identifiers may be gone: never risk a second application
            if kind == "outage":
                self._outage_record(rec, eff[1], at, now)
            elif kind == "rep":
                self.p.rep.incr_batch_once(f"fx:{log_id}:{tseq}", [tuple(op) for op in eff[1]], self._ttl() + 3600, at=at)
            elif kind == "block":
                if suspended is None:
                    suspended = self._suspension_decision(log_id, batch, rec)
                if not suspended:
                    key, verified, fast, undo = eff[1:5]
                    of = eff[5] if len(eff) > 5 and eff[5] is not None else None
                    self._block_event(key, verified=verified, fast=fast, undo=undo, event_id=f"{log_id}:{tseq}",
                                      undo_of=f"{log_id}:{of}" if of is not None else None, at=at)
            elif kind == "block_unfail":
                if suspended is None:
                    suspended = self._suspension_decision(log_id, batch, rec)
                if not suspended:
                    of = eff[2] if len(eff) > 2 and eff[2] is not None else None
                    self._block_event(eff[1], verified=False, undo_fail_only=True, event_id=f"{log_id}:{tseq}",
                                      undo_of=f"{log_id}:{of}" if of is not None else None, at=at)
            elif kind == "trusted":
                self.p.rep.mark_trusted(eff[1])
            elif kind == "timeout":
                self.p.store.zadd(self.TIMEOUTS, eff[1], str(log_id))
            elif kind == "deny_check":
                self._deny_check(rec, eff[1])

        def clear(entry):
            if entry is None or not any(b["tseq"] == tseq for b in entry.get("pending") or []):
                return None
            e = dict(entry)
            e["pending"] = [b for b in e["pending"] if b["tseq"] != tseq]
            return e
        self.p.store.update(self._key(log_id), clear, self._ttl())

    def _suspension_decision(self, log_id, batch, rec):
        """Whether the carrier is in an outage, decided once per batch and remembered in it, so a
        replay after a crash feeds the block test exactly as the first attempt would have."""
        if "suspended" in batch:
            return batch["suspended"]
        decided = self._outage_active(rec)
        tseq = batch["tseq"]

        def remember(entry):
            if entry is None:
                return None
            e = dict(entry)
            e["pending"] = [dict(b, suspended=b.get("suspended", decided)) if b["tseq"] == tseq else b for b in e.get("pending") or []]
            return e
        entry, _ = self.p.store.update(self._key(log_id), remember, self._ttl())
        for b in (entry or {}).get("pending") or []:
            if b["tseq"] == tseq:
                batch["suspended"] = b["suspended"]
                return b["suspended"]
        batch["suspended"] = decided
        return decided

    def recover(self, older_than=None):
        """Apply effect batches left recorded by a transition whose process stopped before finishing
        them. Called from run_due_timeouts(); safe to run concurrently with live transitions."""
        now = self.p.clock.now()
        age = self.RECOVER_AFTER_S if older_than is None else older_than
        n = 0
        for token in list(self.p.store.zrangebyscore(self.INTENTS, float("-inf"), now - age)):
            log_id = int(token.split(":", 1)[0])
            entry = self.p.store.get(self._key(log_id))
            rec = self.p.sms_history.get(log_id)
            if entry is not None and rec is not None:
                for batch in list(entry.get("pending") or []):
                    self._apply(log_id, rec, batch)
                    n += 1
            self.p.store.zrem(self.INTENTS, token)
        return n

    # ---------------------------------------------------------------- effect lists
    def _rep_ops(self, rec, *field_by):
        return [[k, f, by] for k in rec["reputation_keys"] for f, by in field_by]

    def _failed_effects(self, rec):
        fx = [["outage", "kg_failed" if rec.get("known_good") else "failed"],
              ["rep", self._rep_ops(rec, ("failed", 1))]]
        fx += [["block", k, False, False, False] for k in rec["reputation_keys"] if k.startswith("block:")]
        fx += [["deny_check", k] for k in rec["reputation_keys"] if not k.startswith("block:")]
        return fx

    def _deny_check(self, rec, key):
        cfg = self.p.cfg
        if "feedback" not in cfg.features:
            return
        r = self.p.rep.get(key)
        resolved = r.verified + r.failed
        if resolved >= cfg.denylist_min_sample and r.verified / resolved < cfg.denylist_ratio:
            # Fine-grained keys only. A residential ASN is thousands of real people; denylisting it
            # would hand the attacker a denial of service. Hosting ASNs carry no such users.
            if key.startswith(("ip:", "subnet:", "fp:")) or (key.startswith("asn:") and rec.get("asn_is_datacenter")):
                self.p.store.set("deny:" + key, 1, cfg.denylist_ttl)

    # ---------------------------------------------------------------- receipts
    def on_delivery(self, log_id, ok, at=None):
        """Delivery receipt from the provider (status callback) or the sender adapter. Returns what
        happened: 'delivered', 'failed', 'duplicate', 'conflict', 'reopened', 'expired' or 'ignored'."""
        cfg = self.p.cfg
        if not cfg.delivery_receipts:
            return "ignored"                                 # send-clocked mode ignores receipts
        res_window = min(cfg.resolution_timeout_s, cfg.otp_ttl)

        def decide(e, rec, now):
            if e["done"]:
                return None, "ignored", None
            if ok:
                if e["delivery"] == "delivered":
                    return None, "duplicate", None           # the first delivery transition stands
                if e["expires"] < now:
                    return None, "expired", None
                n = dict(e)
                n["delivery"], n["delivered_at"] = "delivered", (at if at is not None else now)
                fx = [["outage", "delivered"], ["timeout", n["delivered_at"] + res_window]]
                if e.get("resolution") == "undelivered":    # late or corrected report: reopen
                    n["resolution"], n["timed_out"] = None, False
                    fx.append(["rep", self._rep_ops(rec, ("undelivered", -1))])
                    if e.get("receipt_block_fail"):
                        fx += [["block_unfail", k, e.get("block_fail_tseq")] for k in rec["reputation_keys"] if k.startswith("block:")]
                        n["receipt_block_fail"] = False
                    return n, "reopened", fx
                return n, "delivered", fx
            if e["delivery"] == "delivered":
                n = dict(e)
                n["conflicts"] = e.get("conflicts", 0) + 1   # delivered, then "failed": keep the delivery
                return n, "conflict", None
            if e["delivery"] == "failed" or e.get("resolution"):
                return None, "duplicate", None
            n = dict(e)
            n["delivery"], n["resolution"], n["timed_out"] = "failed", "undelivered", True    # one transition
            fx = [["outage", "undelivered"], ["rep", self._rep_ops(rec, ("undelivered", 1))]]
            if cfg.receipt_policy == "robust":
                fx += [["block", k, False, False, False] for k in rec["reputation_keys"] if k.startswith("block:")]
                n["receipt_block_fail"] = True
            return n, "failed", fx

        kind, _ = self._transition(log_id, decide)
        return kind

    # ---------------------------------------------------------------- timeouts
    def _timeout_decide(self, force=False):
        cfg = self.p.cfg
        res_window = min(cfg.resolution_timeout_s, cfg.otp_ttl)

        def decide(e, rec, now):
            if e["done"] or e.get("resolution"):
                return None, "settled", None
            if cfg.delivery_receipts and e.get("delivery") != "delivered" and not force:
                n = dict(e)
                n["resolution"], n["timed_out"] = "undelivered", True      # no receipt inside the grace period
                return n, "undelivered", [["rep", self._rep_ops(rec, ("undelivered", 1))]]
            if cfg.delivery_receipts and not force and now < e["delivered_at"] + res_window:
                return None, "not_due", None
            n = dict(e)
            n["resolution"], n["timed_out"] = "failed", True
            return n, "failed", self._failed_effects(rec)
        return decide

    def run_due_timeouts(self):
        """Called by a scheduler (cron, worker loop) every minute or so. Also completes any effect
        batches a stopped process left behind."""
        now = self.p.clock.now()
        for member in list(self.p.store.zrangebyscore(self.TIMEOUTS, float("-inf"), now)):
            due = self.p.store.zscore(self.TIMEOUTS, member)
            kind, _ = self._transition(int(member), self._timeout_decide())
            if kind != "not_due":
                # a correcting receipt may have reopened the send and rescheduled it under the same
                # member after the transition: remove the member only if its due time is unchanged
                self.p.store.zrem_if_score(self.TIMEOUTS, member, due)
        self.recover()

    # ---------------------------------------------------------------- verify endpoint
    def _verified_effects(self, e, rec, now):
        cfg = self.p.cfg
        earlier = e.get("resolution")
        clock_from = e.get("delivered_at") if (cfg.delivery_receipts and e.get("delivered_at") is not None) \
            else float(e.get("sent_at", rec.get("sent_at", 0)))
        fast = (now - clock_from) < cfg.fast_verify_seconds
        ops = [("verified", 1)] + ([(earlier, -1)] if earlier else []) + ([("fast_verified", 1)] if fast else [])
        fx = ([["outage", "kg_verified"]] if rec.get("known_good") else []) + [["rep", self._rep_ops(rec, *ops)]]
        undo = earlier == "failed" or bool(e.get("receipt_block_fail"))
        fx += [["block", k, True, fast, undo, e.get("block_fail_tseq") if undo else None]
               for k in rec["reputation_keys"] if k.startswith("block:")]
        fx.append(["trusted", "num:" + rec["phone_number"]])
        return fx

    def verify(self, session_id, log_id, code):
        """One atomic transition: the attempt is counted and, if the code is right, the send is
        closed as verified; concurrent submissions of the right code verify it once."""
        cfg = self.p.cfg
        if not self.p.rl("otp:verify:session", session_id, cfg.verify_session_limit).try_acquire():
            return False

        def decide(e, rec, now):
            if e["done"] or e["expires"] < now:
                return None, "invalid", None
            n = dict(e)
            n["attempts"] = e["attempts"] + 1
            if secrets.compare_digest(e["code"], str(code)):
                n["done"] = True
                return n, "verified", self._verified_effects(e, rec, now)
            if n["attempts"] >= cfg.otp_max_attempts:
                n["done"] = True
                return n, "exhausted", (None if e.get("resolution") else self._failed_effects(rec))
            return n, "wrong", None

        kind, _ = self._transition(log_id, decide)
        return kind == "verified"

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

    # direct transitions (operator tools and tests)
    def on_verified(self, log_id):
        def decide(e, rec, now):
            if e["done"]:
                return None, "ignored", None
            n = dict(e)
            n["done"] = True
            return n, "verified", self._verified_effects(e, rec, now)
        return self._transition(log_id, decide)[0]

    def on_failed_or_timeout(self, log_id, keep_code=False):
        if keep_code:
            return self._transition(log_id, self._timeout_decide(force=True))[0]

        def decide(e, rec, now):
            if e["done"]:
                return None, "ignored", None
            n = dict(e)
            n["done"] = True
            return n, "exhausted", (None if e.get("resolution") else self._failed_effects(rec))
        return self._transition(log_id, decide)[0]

    # ---------------------------------------------------------------- carrier outage detector
    def _carrier(self, rec):
        return rec.get("prefix") or "unknown"

    def _outage_record(self, rec, event, at, now=None):
        """event: 'delivered' | 'undelivered' (from receipts: the carrier's own report), 'failed' (any
        client's code was not entered) or 'kg_verified' | 'kg_failed' (outcomes of clients with verified
        history, whom an attacker cannot impersonate). The delivery signal uses all sends; the
        conversion signal uses only known-good clients, so a decoy flood cannot buy a suspension.
        Idempotent per (event, send): the sets are keyed by log id. The event is inserted at its own time
        `at` (the transition's), and the windows end at `now`: a replay after a crash cannot move an old
        observation into the current window (fifth-round review, M8). The distinct-block set has one
        member per block scored with that block's newest failure, so a replayed older failure never
        lowers it (sixth-round review, M4; up to 2.8.1 a replay overwrote the score)."""
        cfg = self.p.cfg
        now = at if now is None else now
        c = self._carrier(rec)
        windows = {"delivered": cfg.outage_window_s, "undelivered": cfg.outage_window_s, "failed": cfg.outage_kg_window_s,
                   "kg_verified": cfg.outage_kg_window_s, "kg_failed": cfg.outage_kg_window_s, "blocks": cfg.outage_kg_window_s}
        self.p.store.zadd(f"outage:{event}:{c}", at, str(rec["log_id"]), ttl=2 * windows[event])
        self.p.store.zremrangebyscore(f"outage:{event}:{c}", float("-inf"), now - windows[event])   # each key trims itself
        if event in ("undelivered", "failed", "kg_failed"):
            self.p.store.zadd_max(f"outage:blocks:{c}", at, rec["phone_number"][:cfg.destination_block_digits], ttl=2 * windows["blocks"])
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
            if self.p.store.setnx(f"outage:{c}", dict(n, since=now, kind=kind), cfg.outage_ttl):
                self.p.svc.alerts.alert(f"Carrier outage suspected on prefix {c} ({kind} collapse across {n['blocks']} blocks); "
                                        f"block tests suspended for {cfg.outage_ttl} s", n)

    def _outage_active(self, rec):
        return self.p.store.exists(f"outage:{self._carrier(rec)}")

    # ---------------------------------------------------------------- destination-block tests
    def _increments(self):
        cfg = self.p.cfg
        return {"verify": math.log(cfg.sprt_attack_conversion / cfg.sprt_legit_conversion),
                "fail": math.log((1 - cfg.sprt_attack_conversion) / (1 - cfg.sprt_legit_conversion)),
                "fast": math.log(cfg.sprt_attack_fast / cfg.sprt_legit_fast),
                "slow": math.log((1 - cfg.sprt_attack_fast) / (1 - cfg.sprt_legit_fast))}

    @staticmethod
    def _empty_block_state(verdicts=0):
        return {"v": 0, "f": 0, "fv": 0, "conv": 0.0, "speed": 0.0, "verdicts": verdicts,
                "verdict": None, "history": [], "seen": {}, "test_since": 0.0}

    @staticmethod
    def _seen_times(seen, now):
        """Normalise the identifier memory to id -> [recorded_at, event_at]. Older documents held a
        list of ids (2.7.0) or id -> recorded_at (2.8.0, 2.8.1)."""
        if isinstance(seen, list):
            return {i: [now, now] for i in seen}
        return {i: (list(t) if isinstance(t, (list, tuple)) else [t, t]) for i, t in (seen or {}).items()}

    def _block_event(self, key, verified, fast=False, undo=False, event_id=None, undo_fail_only=False, undo_of=None, at=None):
        """One resolved send on a destination block, dated `at` (the time of the transition that recorded
        it; the clock's time on the live path, the recorded time on a replay). Counts, statistics, the
        current verdict and the verdict history are one document updated by one compare-and-set:
        concurrent events are all counted, a crossing happens once, and its stage is decided from the
        verdict active at the event's time (a crossing while a verdict is active escalates to stage 2).

        Event time (sixth-round review, M5). The document remembers when its current test began
        (`test_since`: the time of the last crossing, 0 for a fresh block). An event is counted toward
        the test that was running at its time: one dated before `test_since` belongs to a test that a
        crossing has already concluded, so it is recorded (a later replay is still ignored) but not
        counted, and it cannot cause a crossing. A crossing caused by an event dated `at` issues its
        verdict at `at`, in force until `at + block_verdict_ttl` (a verdict replayed long after its
        event may already have expired, exactly as if the event had been processed on time) and starts
        the next test at `at`. A reversal (undo, undo_fail_only) names the failure it reverses (undo_of)
        and subtracts it only if that failure was counted in the current test (its recorded event time
        is at or after `test_since`); if the failure has not reached the block yet, the reversal records
        its id as a tombstone, so the failure is ignored when it arrives: the outcome does not depend on
        the order in which a failure and its reversal are applied. Identifiers are kept by the time they
        were recorded (processing time), for id_retention_s(). The statistics are floored at
        -block_credit_thresholds x log(threshold) ('cusum'; 0 is Page's CUSUM) or unbounded ('sprt')."""
        cfg = self.p.cfg
        if "feedback" not in cfg.features:
            return None
        inc = self._increments()
        thr = math.log(cfg.sprt_threshold)
        floor = -cfg.block_credit_thresholds * thr if cfg.block_test == "cusum" else -math.inf
        now = self.p.clock.now()
        at = now if at is None else at
        out = {}

        def fn(cur):
            out.clear()
            st = dict(cur) if cur else self._empty_block_state()
            st.setdefault("history", []); st.setdefault("verdict", None); st.setdefault("test_since", 0.0)
            keep_after = now - self.id_retention_s()
            seen = {i: t for i, t in self._seen_times(st.get("seen"), now).items() if t[0] > keep_after}
            if event_id is not None and event_id in seen:
                return None                                  # already applied
            in_test = at >= st["test_since"]                 # dated inside the test now running
            if event_id is not None:
                seen = dict(seen, **{event_id: [now, at]})
            st["seen"] = seen
            if not in_test:                                  # belongs to a test a crossing has concluded
                return st
            if undo_of is not None and undo_of not in seen:
                seen = dict(seen, **{undo_of: [now, at]})    # tombstone: the failure will be ignored
                st["seen"] = seen
                reverses = False
            else:
                reverses = undo_of is not None and seen[undo_of][1] >= st["test_since"]   # counted in this test
            if undo_fail_only:
                if reverses:
                    st["f"] = max(0, st["f"] - 1)
                    st["conv"] -= inc["fail"]
            elif verified:
                st["v"] += 1
                st["conv"] += inc["verify"]
                if fast:
                    st["fv"] += 1
                    st["speed"] += inc["fast"]
                else:
                    st["speed"] += inc["slow"]
                if undo and reverses:                        # a late verification of a send counted as failed
                    st["f"] = max(0, st["f"] - 1)
                    st["conv"] -= inc["fail"]
            else:
                st["f"] += 1
                st["conv"] += inc["fail"]
            st["conv"], st["speed"] = max(floor, st["conv"]), max(floor, st["speed"])
            conv_hit = "conversion" in cfg.block_tests and st["v"] + st["f"] >= cfg.sprt_min_events and st["conv"] > thr
            speed_hit = "speed" in cfg.block_tests and st["v"] >= cfg.sprt_min_events and st["speed"] > thr
            if not (conv_hit or speed_hit):
                return st
            reason = "never_verified" if conv_hit else "machine_verified"
            active = st["verdict"] is not None and st["verdict"]["until"] > at
            if cfg.block_action == "deny":
                stage, until = "deny", at + cfg.denylist_ttl
            else:
                stage, until = (2 if active else 1), at + cfg.block_verdict_ttl
            n = st["verdicts"] + 1
            event = {"id": f"{key}#{n}@{at:.3f}", "stage": stage, "reason": reason, "at": at, "until": until}
            new = self._empty_block_state(n)                 # the next test starts from zero, at the crossing's time
            new["test_since"] = at
            new["verdict"] = {"stage": stage, "reason": reason, "at": at, "until": until}
            new["history"] = [h for h in st["history"] if h["until"] > now - 86400] + [event]
            new["seen"] = st["seen"]
            out["event"] = event
            return new

        self.p.store.update(self.BLOCK + key, fn, cfg.denylist_ttl)
        return out.get("event")

    def block_llr(self, key):
        """(conversion statistic, speed statistic, (verified, failed, fast) counts) for a block."""
        st = self.p.store.get(self.BLOCK + key) or self._empty_block_state()
        return st["conv"], st["speed"], (st["v"], st["f"], st["fv"])

    def block_verdict(self, key):
        """The verdict in force on a block now ({'stage': 1 | 2 | 'deny', 'reason', 'at', 'until'}), or None."""
        st = self.p.store.get(self.BLOCK + key)
        v = (st or {}).get("verdict")
        return v if v is not None and v["until"] > self.p.clock.now() else None

    def block_denied(self, key):
        v = self.block_verdict(key)
        return v is not None and v["stage"] == "deny"

    def verdict_events(self, since=float("-inf"), until=float("inf")):
        """Every verdict event recorded in the block documents (last 24 h), oldest first:
        [{'block', 'stage', 'reason', 'at', 'until', 'id'}]."""
        out = []
        for doc_key in self.p.store.scan(self.BLOCK):
            st = self.p.store.get(doc_key) or {}
            for h in st.get("history") or []:
                if since <= h["at"] <= until:
                    out.append(dict(h, block=doc_key[len(self.BLOCK):]))
        return sorted(out, key=lambda e: (e["at"], e["id"]))
