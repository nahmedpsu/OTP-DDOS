"""Minute-by-minute simulation of one source under attack with legitimate traffic in the
background. Attackers and users are drawn from calibrated distributions (calibration.py);
verification happens after a realistic delay; the feedback loop runs as it would in production.

Two random streams: `rng_w` drives the exogenous workload (arrivals, identities, numbers,
addresses, CAPTCHA scores, delivery and verification outcomes and delays), `rng_p` drives
decisions that depend on the defence's response (whether a challenged party solves the
challenge). Every workload draw happens when a request is created, so two runs with the same
seed offer the same traffic whatever the defence does (paired comparison).

Events (delivery receipts, verifications) are processed at their own timestamps: the clock is
moved to each event before it is handled. A challenged party retries with the same session,
number and address. Sessions are acquired through the same CAPTCHA gate as /session.
"""
import collections
import heapq
import itertools
import math
import random
import time
from dataclasses import dataclass, field, asdict

from ..config import ALL_FEATURES
from ..services import IpInfo
from ..testing import Harness
from .calibration import value as cal, legit_fast_share
from .metrics import AttackMetrics, FrictionMetrics, CostModel

STANDARD_PREFIXES = ["96650", "96653", "96654", "96655", "96656", "96658", "96659"]
ELEVATED_PREFIX = "96657"       # a range with high historical AIT: capped and flagged, not blocked
PREMIUM_PREFIX = "96699"        # revenue-share range: blocked


@dataclass
class AttackerSpec:
    name: str
    description: str = ""
    network: str = "residential"      # single_ip | datacenter | residential | multi_asn
    pool_size: int = 10_000            # distinct addresses the attacker can use
    rate_per_min: float = 30.0
    captcha_beta: tuple = (9, 1.5)     # reCAPTCHA v3 score distribution
    captcha_classes: tuple = ("captcha_farm",)   # classes the per-seed randomisation may draw from
    fp_mode: str = "fresh"             # fresh | aged | reused | single
    numbers: str = "random"            # random | sequential | premium | elevated | concentrated | poison
    n_blocks: int = 3                  # concentrated: how many destination ranges the pumper's carrier serves
    block_range_digits: int = 8        # concentrated: fixed leading digits per range (8 = 10 000 numbers, 7 = 100 000, 9 = 1 000)
    earns_revenue: bool = False        # pumping attackers are paid per terminated SMS; flooders are not
    rate_multiple_of_legit: float = None   # if set, rate_per_min = multiple x legitimate rate (dilution study)
    verify_fraction: float = 0.0       # colluding carrier submits codes
    verify_delay_s: float = 1.0
    solves_challenges: bool = False    # pays a solving service for interactive challenges
    platform_spoof: bool = False       # sends HTTP_PLATFORM: ios without attestation (host and session are valid)
    n_asns: int = 1
    ip_country: str = "SA"
    trust_building_minutes: int = 0    # phase 1: a pool of identities and numbers verifies everything (human-like delay)
    trust_pool: int = 500              # identities and numbers in that pool, reused in phase 2 without verifying
    fake_failed_receipts: bool = False # the colluding carrier reports its own deliveries as failed


@dataclass
class LegitSpec:
    rate_per_min: float = cal("legit_traffic_rate_per_min")
    conversion: float = cal("legit_conversion")
    verify_median_s: float = cal("legit_verify_delay_s")["lognormal_median_s"]
    verify_sigma: float = cal("legit_verify_delay_s")["sigma"]
    fresh_fp_fraction: float = cal("legit_fresh_fingerprint_fraction")
    captcha_beta: tuple = (cal("recaptcha_human_scores")["beta_a"], cal("recaptcha_human_scores")["beta_b"])
    solves_challenges: float = 0.9     # fraction of real users who complete an interactive challenge
    delivery_median_s: float = cal("sms_delivery_delay_s")["lognormal_median_s"]
    delivery_sigma: float = cal("sms_delivery_delay_s")["sigma"]
    autofill_fraction: float = cal("otp_autofill_fraction")          # users whose OS fills the code in
    autofill_median_s: float = cal("otp_autofill_entry_delay_s")["lognormal_median_s"]
    autofill_sigma: float = cal("otp_autofill_entry_delay_s")["sigma"]
    blocks: int = None                 # draw legitimate numbers from this many 8-digit blocks (None: uniform)
    returning_fraction: float = cal("legit_returning_fraction")   # requests from a browser that verified before
    corporate_egress_fraction: float = 0.05   # office traffic leaving through an in-country hosting range
    roaming_fraction: float = 0.05            # in-country number, connecting from abroad
    cloud_egress_abroad_fraction: float = 0.02  # a company proxy abroad: hosting range + geo mismatch
    whatsapp_fraction: float = 0.7     # users reachable on WhatsApp (the downgrade channel for new users)
    push_fraction: float = 0.0         # new registrations have no app device yet


@dataclass
class OutageSpec:
    """A carrier (prefix) stops delivering for a while. 'failed_receipts': the provider reports
    failure. 'silent': the provider reports delivery, nobody receives anything."""
    prefix: str = "96650"
    start_min: int = 0
    duration_min: int = 30
    kind: str = "failed_receipts"


@dataclass
class SimSpec:
    attacker: AttackerSpec
    legit: LegitSpec = field(default_factory=LegitSpec)
    minutes: int = 20
    features: frozenset = ALL_FEATURES
    cfg_overrides: dict = field(default_factory=dict)
    weight_overrides: dict = field(default_factory=dict)
    caps_lifted: bool = True            # True: behavioural layers only. False: source caps with the adaptive job
    base_cap_multiple: float = 3.0      # per-minute web cap = multiple x legitimate rate; per-hour = 60 x that
    adaptive_floor: float = 0.25
    adaptive_tick_s: int = 60           # how often the baseline job runs (the worker's tick); 3600 = hourly
    warmup_minutes: int = 10            # legitimate-only traffic before the attack, so history exists
    seed: int = 0
    outage: OutageSpec = None
    legit_only: bool = False            # no attacker at all (false-positive runs)
    recalibrate_speed: bool = False     # True: set sprt_legit_fast from this run's own legitimate population


def cost_model():
    return CostModel(cal("sms_unit_cost_usd"), cal("hlr_lookup_cost_usd"), cal("recaptcha_cost_usd"))


def _res_ip(idx):
    x = (idx * 2654435761) % (1 << 22)
    return f"100.{64 + (x >> 16)}.{(x >> 8) & 255}.{x & 255}"


def _dc_ip(idx):
    x = (idx * 2654435761) % (1 << 24)
    return f"203.{x >> 16}.{(x >> 8) & 255}.{x & 255}"


def _asn_ip(asn_index, idx):
    x = (idx * 2654435761) % (1 << 24)
    return f"{11 + asn_index}.{x >> 16}.{(x >> 8) & 255}.{x & 255}"


class Simulation:
    def __init__(self, spec: SimSpec):
        self.spec = spec
        if spec.attacker.rate_multiple_of_legit is not None:
            spec.attacker.rate_per_min = spec.attacker.rate_multiple_of_legit * spec.legit.rate_per_min
        self.rng_w = random.Random(spec.seed)                 # workload
        self.rng_p = random.Random(spec.seed * 1_000_003 + 7)  # policy-dependent decisions
        self.rng = self.rng_w
        h = Harness()
        self.h = h
        h.cfg.features = spec.features
        for k, v in spec.cfg_overrides.items():
            setattr(h.cfg, k, v)
        h.cfg.weights = dict(h.cfg.weights, **spec.weight_overrides)
        h.cfg.asn_limit_default = 10 ** 9
        if spec.recalibrate_speed and "sprt_legit_fast" not in spec.cfg_overrides:
            h.cfg.sprt_legit_fast = max(0.005, legit_fast_share(h.cfg.fast_verify_seconds, spec.legit.autofill_fraction, n=20_000))
        if spec.caps_lifted:
            h.lift_source_caps()
        else:
            per_min = max(1, int(spec.base_cap_multiple * spec.legit.rate_per_min))
            sl = h.cfg.source_limits["App/RegisterOTP"]
            sl["per_minute_web"], sl["per_hour_web"] = per_min, per_min * 60
            sl["per_country"] = {}
            h.p.adaptive.floor = spec.adaptive_floor
        h.svc.prefixes.entries.clear()
        for p in STANDARD_PREFIXES:
            h.svc.prefixes.add(p, "standard", 1)
        h.svc.prefixes.add(ELEVATED_PREFIX, "elevated", 3)
        h.svc.prefixes.add(PREMIUM_PREFIX, "premium", 12)
        h.svc.ip_intel.register("100.64.0.0/10", IpInfo(asn="AS9000", asn_type="isp", country="SA"))
        h.svc.ip_intel.register("192.0.2.0/24", IpInfo(asn="AS64501", asn_type="hosting", is_datacenter=True, country="SA"))
        h.svc.ip_intel.register("198.51.200.0/24", IpInfo(asn="AS5384", asn_type="isp", country="AE"))
        h.svc.ip_intel.register("198.51.201.0/24", IpInfo(asn="AS64502", asn_type="hosting", is_datacenter=True, country="DE"))
        h.svc.ip_intel.register("203.0.0.0/8", IpInfo(asn="AS64500", asn_type="hosting", is_datacenter=True,
                                                       country=spec.attacker.ip_country if spec.attacker.network == "datacenter" else "DE"))
        for i in range(spec.attacker.n_asns):
            h.svc.ip_intel.register(f"{11 + i}.0.0.0/8", IpInfo(asn=f"AS{9100 + i}", asn_type="isp", country=spec.attacker.ip_country))
        self.tokens = itertools.count(1)
        self.events = []                    # heap of (t, seq, kind, payload)
        self.seq = itertools.count()
        h.svc.sender.instant_receipts = False      # receipts arrive after a delivery delay, from schedule_delivery
        self.legit_blocks = None
        if spec.legit.blocks:
            self.legit_blocks = [f"{self.rng_w.choice(STANDARD_PREFIXES)}{self.rng_w.randrange(1000):03d}" for _ in range(spec.legit.blocks)]
        self.verdict_blocks = set()
        self.legit_hit_by_verdict = 0
        self.outage_alerts = 0
        self.verified_fps = []              # fingerprints of legitimate users who verified: the returning population
        self.attack_state = {}
        self.stopped_by = collections.Counter()
        self.leaked_per_min, self.attack_per_min = [], []
        self.friction = FrictionMetrics()
        self.attacker_hlr = self.attacker_recaptcha = 0
        self.attacker_challenges_solved = 0
        self.attacker_verifications = 0
        self.attacker_session_attempts = 0
        self.attacker_sessions_refused = 0
        self.legit_sessions_refused = 0
        self.attacker_blocks_requested, self.attacker_blocks_leaked = set(), set()
        self.ctx_by_log = {}

    # ---- helpers ----
    def captcha_token(self, beta, rng=None):
        score = (rng or self.rng_w).betavariate(*beta)
        tok = f"t{next(self.tokens)}"
        self.h.svc.recaptcha.scores[tok] = score
        return tok, score

    def session_through_gate(self, platform, captcha_beta, fingerprint=None, age_hours=0, attacker=True, max_attempts=10):
        """/session issues a token only after a CAPTCHA pass; each attempt costs a token."""
        for _ in range(max_attempts):
            if attacker:
                self.attacker_session_attempts += 1
            _, score = self.captcha_token(captcha_beta)
            if score >= self.h.p.recaptcha_min_score():
                return self.h.session(platform, fingerprint=fingerprint, age_hours=age_hours)[0]
            if attacker:
                self.attacker_sessions_refused += 1
            else:
                self.legit_sessions_refused += 1
                return None
        return None

    def _ranges(self):
        a = self.spec.attacker
        if "blocks" not in self.attack_state:
            fixed = a.block_range_digits - 5
            universe = len(STANDARD_PREFIXES) * 10 ** fixed            # distinct ranges that exist
            picks = self.rng_w.sample(range(universe), min(a.n_blocks, universe))   # without replacement
            self.attack_state["blocks"] = [f"{STANDARD_PREFIXES[i // 10 ** fixed]}{i % 10 ** fixed:0{fixed}d}" for i in picks]
        return self.attack_state["blocks"]

    def attacker_number(self, k):
        a = self.spec.attacker
        if a.trust_building_minutes:
            pool = self.attack_state.setdefault("num_pool", [f"{self.rng_w.choice(STANDARD_PREFIXES)}{self.rng_w.randrange(10**7):07d}" for _ in range(a.trust_pool)])
            return self.rng_w.choice(pool)
        if a.numbers == "sequential":
            return f"966501{k:06d}"
        if a.numbers == "premium":
            return f"{PREMIUM_PREFIX}{k:07d}"
        if a.numbers == "elevated":
            return f"{ELEVATED_PREFIX}{k:07d}"
        if a.numbers == "poison":
            blocks = self.legit_blocks or [f"{STANDARD_PREFIXES[0]}000"]
            return f"{self.rng_w.choice(blocks)}{self.rng_w.randrange(10**4):04d}"
        if a.numbers == "concentrated":
            tail = 12 - a.block_range_digits
            return f"{self.rng_w.choice(self._ranges())}{self.rng_w.randrange(10**tail):0{tail}d}"
        return f"{self.rng_w.choice(STANDARD_PREFIXES)}{self.rng_w.randrange(10**7):07d}"

    def attacker_ip(self, k):
        a = self.spec.attacker
        idx = self.rng_w.randrange(a.pool_size)
        if a.network == "single_ip":
            return "198.51.100.10"
        if a.network == "datacenter":
            return _dc_ip(idx)
        if a.network == "multi_asn":
            return _asn_ip(k % a.n_asns, idx)
        return _res_ip(idx)

    def attacker_session(self, k):
        a, h, st = self.spec.attacker, self.h, self.attack_state
        gate = lambda fp=None, age=0: self.session_through_gate("web", a.captcha_beta, fingerprint=fp, age_hours=age)
        if a.trust_building_minutes:
            pool = st.setdefault("fp_pool", [f"trust-fp-{i}" for i in range(a.trust_pool)])
            return gate(self.rng_w.choice(pool), 48)
        if a.fp_mode == "single":
            if "tok" not in st:
                st["tok"] = gate(age=2)
            return st["tok"]
        if a.fp_mode == "reused":
            if k % 3 == 0 or "tok" not in st:
                st["tok"] = gate("bot-browser-profile", 48)
            return st["tok"]
        return gate(age=2 if a.fp_mode == "aged" else 0)

    def make_attacker_ctx(self, k, minute):
        a = self.spec.attacker
        tok = self.attacker_session(k)
        in_trust_phase = a.trust_building_minutes and minute < a.trust_building_minutes
        verify = (self.rng_w.random() < (1.0 if in_trust_phase else a.verify_fraction))
        return dict(attacker=True, session=tok, ip=self.attacker_ip(k), mobile=self.attacker_number(k),
                    recaptcha=self.captcha_token(a.captcha_beta)[0], verify=verify,
                    verify_delay=(30.0 if in_trust_phase else a.verify_delay_s),
                    delivery=self.spec.legit.delivery_median_s * math.exp(self.rng_w.gauss(0, self.spec.legit.delivery_sigma)),
                    spoof=a.platform_spoof, group=None, returning=False)

    def make_legit_ctx(self, minute):
        l = self.spec.legit
        returning = bool(self.verified_fps) and self.rng_w.random() < l.returning_fraction
        if returning:
            tok = self.session_through_gate("web", l.captcha_beta, fingerprint=self.rng_w.choice(self.verified_fps), age_hours=24, attacker=False)
        else:
            fresh = self.rng_w.random() < l.fresh_fp_fraction
            tok = self.session_through_gate("web", l.captcha_beta, age_hours=0 if fresh else 24, attacker=False)
        u = self.rng_w.random()
        if u < l.corporate_egress_fraction:
            ip = f"192.0.2.{self.rng_w.randrange(1, 255)}"
        elif u < l.corporate_egress_fraction + l.roaming_fraction:
            ip = f"198.51.200.{self.rng_w.randrange(1, 255)}"
        elif u < l.corporate_egress_fraction + l.roaming_fraction + l.cloud_egress_abroad_fraction:
            ip = f"198.51.201.{self.rng_w.randrange(1, 255)}"
        else:
            ip = _res_ip(self.rng_w.randrange(1 << 22))
        if self.legit_blocks:
            mobile = f"{self.rng_w.choice(self.legit_blocks)}{self.rng_w.randrange(10**4):04d}"
        else:
            mobile = f"{self.rng_w.choice(STANDARD_PREFIXES)}{self.rng_w.randrange(10**7):07d}"
        converts = self.rng_w.random() < l.conversion
        autofill = self.rng_w.random() < l.autofill_fraction
        entry = (l.autofill_median_s * math.exp(self.rng_w.gauss(0, l.autofill_sigma)) if autofill
                 else l.verify_median_s * math.exp(self.rng_w.gauss(0, l.verify_sigma)))
        if self.rng_w.random() < l.whatsapp_fraction:
            self.h.svc.channels.whatsapp_numbers.add(mobile)
        return dict(attacker=False, session=tok, ip=ip, mobile=mobile, recaptcha=self.captcha_token(l.captcha_beta)[0],
                    verify=converts, verify_delay=entry, solves=self.rng_p.random() < l.solves_challenges,
                    delivery=l.delivery_median_s * math.exp(self.rng_w.gauss(0, l.delivery_sigma)),
                    spoof=False, returning=returning, group=(self.friction.returning if returning else self.friction.first_time))

    def request_from(self, ctx, challenge_proof=None):
        kw = dict(session=ctx["session"], ip=ctx["ip"], mobile=ctx["mobile"], recaptcha=ctx["recaptcha"])
        if ctx["spoof"]:
            kw.update(header_platform="ios")               # the only thing spoofed: host and session are valid
        if challenge_proof:
            kw["challenge_proof"] = challenge_proof
        return self.h.web_request(**kw)

    def send_counting(self, req, is_attacker):
        h = self.h
        hl, rc = h.svc.hlr.calls, h.svc.recaptcha.calls
        r = h.send(req)
        if is_attacker:
            self.attacker_hlr += h.svc.hlr.calls - hl
            self.attacker_recaptcha += h.svc.recaptcha.calls - rc
        return r

    # ---- events ----
    def push(self, t, kind, payload):
        heapq.heappush(self.events, (t, next(self.seq), kind, payload))

    def process_due_events(self):
        """Handle every event whose time has come, at its own timestamp."""
        now = self.h.clock.now()
        fb = self.h.p.feedback
        while self.events and self.events[0][0] <= now:
            t, _, kind, payload = heapq.heappop(self.events)
            self.h.clock.t = t
            ctx = self.ctx_by_log.get(payload["log_id"])
            if kind == "receipt":
                fb.on_delivery(payload["log_id"], payload["ok"])
                if ctx is not None and not ctx["attacker"]:
                    for g in (self.friction, ctx["group"]):
                        if payload["ok"]:
                            g.delivered += 1
                        else:
                            g.refused += 1                       # a failed delivery is not a served user
            else:
                msg = payload["message"]
                code = msg.rsplit(" ", 1)[-1].rstrip(".")      # what the recipient reads from the SMS
                ok = fb.verify(payload["sid"], payload["log_id"], code)
                if payload["attacker"]:
                    if ok:
                        self.attacker_verifications += 1
                elif ok:
                    for g in (self.friction, ctx["group"]):
                        g.completed += 1
                    if len(self.verified_fps) < 5000:
                        self.verified_fps.append(self.h.p.sms_history[payload["log_id"]]["fingerprint"])
        self.h.clock.t = now

    def in_outage(self, mobile, minute):
        o = self.spec.outage
        return o is not None and mobile.startswith(o.prefix) and o.start_min <= minute < o.start_min + o.duration_min

    def schedule_delivery(self, r, ctx, minute):
        """Receipt after the sender's queue delay plus the delivery delay, then (maybe) a verification
        clocked from the receipt. The verification uses the code as it appears in the message."""
        a = self.spec.attacker
        now = self.h.clock.now()
        rec = self.h.p.sms_history[r.log_id]
        sent = self.h.svc.sender.sent[-1]
        self.ctx_by_log[r.log_id] = ctx
        t_receipt = now + sent.delay + ctx["delivery"]
        if ctx["attacker"] and a.fake_failed_receipts:
            self.push(t_receipt, "receipt", {"log_id": r.log_id, "ok": False})     # billed, delivered, reported failed
            return
        if self.in_outage(rec["phone_number"], minute) and not ctx["attacker"]:
            self.push(t_receipt, "receipt", {"log_id": r.log_id, "ok": self.spec.outage.kind != "failed_receipts"})
            return
        self.push(t_receipt, "receipt", {"log_id": r.log_id, "ok": True})
        if ctx["verify"]:
            self.push(t_receipt + ctx["verify_delay"], "verify",
                      {"sid": rec["session_id"], "log_id": r.log_id, "attacker": ctx["attacker"], "message": sent.text})

    def baseline_job_tick(self, observed, minute):
        """The baseline job of Step 9 at the worker's cadence, with the modelled legitimate rate as
        the profile it would have learned (the deployed job learns it: otp_guard.baseline)."""
        if self.spec.caps_lifted or (minute * 60) % self.spec.adaptive_tick_s != 0:
            return
        l = self.spec.legit
        conv = self.h.p.rep.conversion_ratio("country:966", self.h.cfg.conversion_min_sample)
        per_tick = max(1, self.spec.adaptive_tick_s // 60)
        self.h.p.adaptive.recompute("App/RegisterOTP", "web", "966", observed=observed / per_tick,
                                    expected_median=l.rate_per_min, mad=0.25 * l.rate_per_min, conversion=conv)

    # ---- main loop ----
    def run(self):
        spec, h = self.spec, self.h
        k_attack = 0
        reached_cap_acc = 0
        for minute in range(-spec.warmup_minutes, spec.minutes):
            warm = minute < 0
            na = 0 if (warm or spec.legit_only) else self._poisson(spec.attacker.rate_per_min)
            nl = self._poisson(spec.legit.rate_per_min)
            order = [True] * na + [False] * nl
            self.rng_w.shuffle(order)
            step = 60.0 / max(len(order), 1)
            leaked, reached_cap = 0, 0
            for is_attacker in order:
                self.process_due_events()
                if is_attacker:
                    ctx = self.make_attacker_ctx(k_attack, minute)
                    k_attack += 1
                    if ctx["session"] is None:
                        self.stopped_by["session_gate"] += 1
                        continue
                    self.attacker_blocks_requested.add(ctx["mobile"][:8])
                    r = self.send_counting(self.request_from(ctx), True)
                    if r.tier == "challenge" and spec.attacker.solves_challenges:
                        self.attacker_challenges_solved += 1
                        r = self.send_counting(self.request_from(ctx, challenge_proof=self.captcha_token((9, 1.5))[0]), True)
                    outcome = r.rejected_at or f"sent:{r.channel}:{r.tier}"
                    self.stopped_by[outcome] += 1
                    reached_cap += r.rejected_at in (None, "step9") and r.tier != "downgrade"
                    if r.channel == "sms":
                        leaked += 1
                        self.attacker_blocks_leaked.add(ctx["mobile"][:8])
                        self.schedule_delivery(r, ctx, minute)
                else:
                    ctx = self.make_legit_ctx(minute)
                    if ctx["session"] is None:
                        continue                                  # lost at /session: counted in legit_sessions_refused
                    groups = (self.friction, ctx["group"])
                    for g in groups:
                        g.users += 1
                    r = self.send_counting(self.request_from(ctx), False)
                    reached_cap += r.rejected_at in (None, "step9") and r.tier != "downgrade"
                    if any(sig.startswith("block_") for sig in r.signals):
                        self.legit_hit_by_verdict += 1
                    if r.tier == "challenge":
                        for g in groups:
                            g.challenged += 1
                        if ctx["solves"]:
                            r = self.send_counting(self.request_from(ctx, challenge_proof=self.captcha_token((9, 1.5))[0]), False)
                    if r.channel is not None:
                        for g in groups:
                            g.dispatched += 1
                            g.by_channel[r.channel] = g.by_channel.get(r.channel, 0) + 1
                            if r.tier == "delay":
                                g.delayed += 1
                                g.added_delay_s_total += h.svc.sender.sent[-1].delay
                        self.schedule_delivery(r, ctx, minute)
                    else:
                        for g in groups:
                            g.refused += 1
                h.clock.advance(step)
            self.process_due_events()
            h.p.feedback.run_due_timeouts()
            reached_cap_acc += reached_cap
            if (minute * 60) % spec.adaptive_tick_s == 0:
                self.baseline_job_tick(reached_cap_acc, minute)
                reached_cap_acc = 0
            if warm:
                self.friction = FrictionMetrics()      # warm-up friction is not counted
                continue
            self.leaked_per_min.append(leaked)
            self.attack_per_min.append(na)
        # let the last receipts and verifications land (they belong to sends inside the window)
        h.clock.advance(max(60.0, self.spec.legit.verify_median_s * 4))
        self.process_due_events()
        h.p.feedback.run_due_timeouts()
        self.verdict_blocks = set(h.p.store.zrangebyscore(h.p.feedback.VERDICT_LOG, float("-inf"), float("inf")))
        self.outage_alerts = sum(1 for a in h.svc.alerts.alerts if "outage" in a[0])
        attack = AttackMetrics.build(self.leaked_per_min, self.attack_per_min, self.attacker_hlr, self.attacker_recaptcha,
                                     cost_model(), self.stopped_by)
        return {"attack": asdict(attack), "friction": asdict(self.friction.finish()),
                "attacker_challenges_solved": self.attacker_challenges_solved,
                "attacker_verifications": self.attacker_verifications,
                "attacker_session_attempts": self.attacker_session_attempts,
                "attacker_sessions_refused": self.attacker_sessions_refused,
                "legit_sessions_refused": self.legit_sessions_refused,
                "attacker_blocks_requested": len(self.attacker_blocks_requested),
                "attacker_blocks_leaked": len(self.attacker_blocks_leaked),
                "block_verdicts": len(self.verdict_blocks), "legit_hit_by_verdict": self.legit_hit_by_verdict,
                "outage_alerts": self.outage_alerts,
                "spec": {"attacker": asdict(spec.attacker), "legit": asdict(spec.legit), "minutes": spec.minutes,
                         "features": sorted(spec.features), "cfg_overrides": spec.cfg_overrides,
                         "weight_overrides": spec.weight_overrides, "seed": spec.seed,
                         "caps_lifted": spec.caps_lifted, "base_cap_multiple": spec.base_cap_multiple,
                         "adaptive_floor": spec.adaptive_floor, "adaptive_tick_s": spec.adaptive_tick_s,
                         "warmup_minutes": spec.warmup_minutes, "recalibrate_speed": spec.recalibrate_speed}}

    def _poisson(self, lam):
        if lam <= 0:
            return 0
        L, k, p = math.exp(-lam), 0, 1.0
        while True:
            k += 1
            p *= self.rng_w.random()
            if p <= L:
                return k - 1


def run_sim(spec: SimSpec):
    t0 = time.perf_counter()
    out = Simulation(spec).run()
    out["wall_s"] = time.perf_counter() - t0
    return out
