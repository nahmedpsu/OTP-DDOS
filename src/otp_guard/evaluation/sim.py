"""Event-driven simulation of one registration source under attack, with legitimate traffic in the
background. Attackers and users are drawn from calibrated distributions (calibration.py); the
pipeline runs inside the simulation on fakes (CAPTCHA scores, IP intelligence, HLR, sender) with
delivery receipts and code entries arriving as timed events; the feedback loop and the adaptive
baseline job run as deployed, except where a substitution is named below.

Offered workload (M1). Every exogenous quantity of a request is drawn from `rng_w` at the
moment the request is created, before the pipeline sees it: arrival times, identity (fresh or
returning, and which returning identity), address, destination number, CAPTCHA scores for every
session attempt the client might need, whether the person would verify and after how long,
delivery delay, the CAPTCHA token a challenge retry would present, and channel reachability.
Returning identities are chosen from the identities the trace itself offered earlier, never from
what the defence verified. The only policy-dependent random decision (does a challenged person
solve the challenge) comes from `rng_p`. Two runs with the same seed therefore offer the same
trace of requests whatever the defence does; `workload_digest` in the result is a hash of that
trace and is asserted equal across designs in the tests.

Measurement cohorts (M2, M3). A request is bound at creation to one immutable pair of accumulators
(all users, and first-time or returning); every later outcome of that request (receipt, code
entry) lands there. Warm-up requests are bound to discarded accumulators. A legitimate request is
counted as a user when it is offered, before the session gate, so the funnel runs from offered
demand: gate -> pipeline -> dispatched -> delivered -> completed, with every loss named.

Time (M4, M5). Arrivals carry timestamps inside their minute and the clock moves to each
arrival and to each minute boundary regardless of what the pipeline decides; events are
processed at their own timestamps. After the last minute the run drains to a declared horizon
(receipt grace + resolution timeout + the slowest modelled entry delay) and reports what, if
anything, was still pending.

Substitutions, all named: vendors are fakes with zero latency; the sender's receipts are
simulated; `baseline="oracle"` (the default of the main study) hands the adaptive job the
modelled legitimate rate, `baseline="learned"` runs the deployed BaselineJob on the pipeline's
own counters; a challenged party retries with the same session, number and address.
"""
import collections
import hashlib
import heapq
import itertools
import math
import random
import time
from dataclasses import dataclass, field, asdict

from ..baseline import BaselineJob
from ..config import ALL_FEATURES
from ..services import IpInfo
from ..testing import Harness
from .calibration import value as cal, legit_fast_share
from .metrics import AttackMetrics, FrictionMetrics, FrictionGroup, CostModel

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
    trust_building_minutes: int = 0    # phase 1: a pool of (identity, number) pairs verifies everything (human-like delay)
    trust_pool: int = 500              # pairs in that pool; phase 2 reuses the same pairs without verifying
    trust_concentrated: bool = False   # the pool's numbers lie inside the attacker's concentrated blocks
    fake_failed_receipts: bool = False # the colluding carrier reports its own deliveries as failed
    active_minutes: int = None         # the attack stops after this many minutes (recovery studies); None = whole run


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
    blocks: int = None                 # draw legitimate numbers from this many distinct 8-digit blocks (None: uniform)
    returning_fraction: float = cal("legit_returning_fraction")   # requests from an identity the trace offered before
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
    adaptive_phase_s: int = 0           # offset of the job's ticks inside its period (phase sensitivity)
    baseline: str = "oracle"            # 'oracle': the job is told the modelled legitimate rate; 'learned': the deployed BaselineJob
    warmup_minutes: int = 10            # legitimate-only traffic before the attack, so history exists
    warmup_attack_rate: float = 0.0     # attacker requests/min during the warm-up (poisons a learned baseline)
    seed: int = 0
    outage: OutageSpec = None
    legit_only: bool = False            # no attacker at all (false-positive runs)
    recalibrate_speed: bool = False     # True: set sprt_legit_fast from this run's own legitimate population
    drain_horizon_s: int = None         # None: receipt grace + resolution timeout + slowest modelled entry (10 min)


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


MAX_SESSION_ATTEMPTS = 10


class Simulation:
    def __init__(self, spec: SimSpec):
        self.spec = spec
        if spec.attacker.rate_multiple_of_legit is not None:
            spec.attacker.rate_per_min = spec.attacker.rate_multiple_of_legit * spec.legit.rate_per_min
        self.rng_w = random.Random(spec.seed)                 # workload
        self.rng_p = random.Random(spec.seed * 1_000_003 + 7)  # policy-dependent decisions
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
        self.baseline_job = BaselineJob(h.p) if spec.baseline == "learned" else None
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
        # legitimate destinations: a fixed set of *distinct* blocks (sampled without replacement), or uniform
        self.legit_blocks = None
        if spec.legit.blocks:
            universe = len(STANDARD_PREFIXES) * 1000
            picks = self.rng_w.sample(range(universe), min(spec.legit.blocks, universe))
            self.legit_blocks = [f"{STANDARD_PREFIXES[i // 1000]}{i % 1000:03d}" for i in picks]
        self.legit_block_sends = collections.Counter()
        self.legit_identities = []          # fingerprints the trace has offered so far (the returning population)
        self.attack_state = {}
        self.stopped_by = collections.Counter()
        self.leaked_per_min, self.attack_per_min, self.legit_hit_per_min = [], [], []
        # measurement cohorts: one immutable pair per request; warm-up requests go to discarded accumulators
        self.friction = FrictionMetrics()
        self.warmup_friction = FrictionMetrics()
        self.attacker_hlr = self.attacker_recaptcha = 0
        self.attacker_challenges_solved = 0
        self.attacker_verifications = 0
        self.attacker_session_attempts = 0
        self.attacker_sessions_refused = 0
        self.attacker_blocks_requested, self.attacker_blocks_leaked = set(), set()
        self.phase = {ph: collections.Counter() for ph in ("prep", "flood")}    # trust-building attackers
        self.ctx_by_log = {}
        self.legit_ctxs = []                # every measured legitimate request, for verdict-harm accounting
        self.digest = hashlib.sha1()
        self.pending_at_end = {}

    # ---- helpers ----
    def _token(self, score):
        tok = f"t{next(self.tokens)}"
        self.h.svc.recaptcha.scores[tok] = score
        return tok

    def _scores(self, beta, n):
        return [self.rng_w.betavariate(*beta) for _ in range(n)]

    def session_through_gate(self, platform, scores, fingerprint=None, age_hours=0, attacker=True):
        """/session issues a token only after a CAPTCHA pass; each attempt costs a token. The scores
        were drawn at request creation; how many are consumed depends on the threshold."""
        for score in scores:
            if attacker:
                self.attacker_session_attempts += 1
            self._token(score)
            if score >= self.h.p.recaptcha_min_score():
                return self.h.session(platform, fingerprint=fingerprint, age_hours=age_hours)[0]
            if attacker:
                self.attacker_sessions_refused += 1
            else:
                return None                                   # a person gives up after one refusal
        return None

    def _ranges(self):
        a = self.spec.attacker
        if "blocks" not in self.attack_state:
            fixed = a.block_range_digits - 5
            universe = len(STANDARD_PREFIXES) * 10 ** fixed            # distinct ranges that exist
            picks = self.rng_w.sample(range(universe), min(a.n_blocks, universe))   # without replacement
            self.attack_state["blocks"] = [f"{STANDARD_PREFIXES[i // 10 ** fixed]}{i % 10 ** fixed:0{fixed}d}" for i in picks]
        return self.attack_state["blocks"]

    def _concentrated_number(self):
        a = self.spec.attacker
        tail = 12 - a.block_range_digits
        return f"{self.rng_w.choice(self._ranges())}{self.rng_w.randrange(10**tail):0{tail}d}"

    def _trust_pool(self):
        """(identity, number) pairs, one-to-one, drawn once; the flood phase reuses exactly these."""
        a = self.spec.attacker
        if "trust_pool" not in self.attack_state:
            nums = [self._concentrated_number() if a.trust_concentrated
                    else f"{self.rng_w.choice(STANDARD_PREFIXES)}{self.rng_w.randrange(10**7):07d}" for _ in range(a.trust_pool)]
            self.attack_state["trust_pool"] = [(f"trust-fp-{i}", nums[i]) for i in range(a.trust_pool)]
        return self.attack_state["trust_pool"]

    def attacker_number(self, k):
        a = self.spec.attacker
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
            return self._concentrated_number()
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

    def attacker_identity(self, k):
        """(fingerprint or None for a fresh one, age in hours, reuse an existing session?)"""
        a = self.spec.attacker
        if a.fp_mode == "single":
            return "single-client-fp", 2, True
        if a.fp_mode == "reused":
            return "bot-browser-profile", 48, k % 3 != 0
        return None, (2 if a.fp_mode == "aged" else 0), False

    def make_attacker_ctx(self, k, minute):
        """Every exogenous quantity of this request, drawn now from the workload stream."""
        a, l = self.spec.attacker, self.spec.legit
        in_trust_phase = bool(a.trust_building_minutes) and 0 <= minute < a.trust_building_minutes
        if a.trust_building_minutes:
            fp, mobile = self.rng_w.choice(self._trust_pool())
            age, reuse = 48, False
        else:
            fp, age, reuse = self.attacker_identity(k)
            mobile = self.attacker_number(k)
        ctx = dict(attacker=True, k=k, minute=minute, fp=fp, age=age, reuse_session=reuse, ip=self.attacker_ip(k), mobile=mobile,
                   gate_scores=self._scores(a.captcha_beta, MAX_SESSION_ATTEMPTS), recaptcha_score=self.rng_w.betavariate(*a.captcha_beta),
                   verify=self.rng_w.random() < (1.0 if in_trust_phase else a.verify_fraction),
                   verify_delay=(30.0 if in_trust_phase else a.verify_delay_s),
                   delivery=l.delivery_median_s * math.exp(self.rng_w.gauss(0, l.delivery_sigma)),
                   retry_score=self.rng_w.betavariate(9, 1.5), spoof=a.platform_spoof, returning=False,
                   phase=("prep" if in_trust_phase else "flood"), cohort=None, hit_stage=None)
        self._digest(ctx)
        return ctx

    def make_legit_ctx(self, minute, warm):
        l = self.spec.legit
        returning = bool(self.legit_identities) and self.rng_w.random() < l.returning_fraction
        if returning:
            fp, age = self.rng_w.choice(self.legit_identities), 24
        else:
            fresh = self.rng_w.random() < l.fresh_fp_fraction
            fp, age = f"legit-fp-{len(self.legit_identities)}", (0 if fresh else 24)
            self.legit_identities.append(fp)
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
        whatsapp = self.rng_w.random() < l.whatsapp_fraction
        fm = self.warmup_friction if warm else self.friction
        ctx = dict(attacker=False, minute=minute, fp=fp, age=age, reuse_session=False, ip=ip, mobile=mobile,
                   gate_scores=self._scores(l.captcha_beta, 1), recaptcha_score=self.rng_w.betavariate(*l.captcha_beta),
                   verify=converts, verify_delay=entry, delivery=l.delivery_median_s * math.exp(self.rng_w.gauss(0, l.delivery_sigma)),
                   retry_score=self.rng_w.betavariate(9, 1.5), whatsapp=whatsapp, spoof=False, returning=returning,
                   solves=self.rng_p.random() < l.solves_challenges,
                   cohort=(fm, fm.returning if returning else fm.first_time), hit_stage=None, warm=warm,
                   dispatched=False, delivered=False, completed=False, refused=None)
        self._digest(ctx)
        return ctx

    def _digest(self, ctx):
        """Hash of the offered request, policy-independent fields only."""
        keys = ("attacker", "minute", "fp", "age", "ip", "mobile", "gate_scores", "recaptcha_score", "verify", "verify_delay",
                "delivery", "retry_score", "returning", "whatsapp")
        self.digest.update(repr([ctx.get(k) for k in keys]).encode())

    def open_session(self, ctx):
        """Acquire the session this request presents (an attacker may reuse one)."""
        a, st = self.spec.attacker, self.attack_state
        beta_platform = "web"
        if ctx["attacker"]:
            if ctx["reuse_session"] and "tok" in st:
                return st["tok"]
            tok = self.session_through_gate(beta_platform, ctx["gate_scores"], fingerprint=ctx["fp"], age_hours=ctx["age"])
            if ctx["fp"] in ("single-client-fp", "bot-browser-profile") and tok is not None:
                st["tok"] = tok
            return tok
        return self.session_through_gate(beta_platform, ctx["gate_scores"], fingerprint=ctx["fp"], age_hours=ctx["age"], attacker=False)

    def request_from(self, ctx, session, challenge=False):
        kw = dict(session=session, ip=ctx["ip"], mobile=ctx["mobile"], recaptcha=self._token(ctx["recaptcha_score"]))
        if ctx["spoof"]:
            kw.update(header_platform="ios")               # the only thing spoofed: host and session are valid
        if challenge:
            kw["challenge_proof"] = self._token(ctx["retry_score"])
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

    def process_due_events(self, until=None):
        """Handle every event due by `until` (default: now), at its own timestamp; the clock ends at `until`."""
        until = self.h.clock.now() if until is None else until
        fb = self.h.p.feedback
        while self.events and self.events[0][0] <= until:
            t, _, kind, payload = heapq.heappop(self.events)
            self.h.clock.t = t
            ctx = self.ctx_by_log.get(payload["log_id"])
            if kind == "receipt":
                fb.on_delivery(payload["log_id"], payload["ok"])
                if ctx is not None and not ctx["attacker"]:
                    if payload["ok"]:
                        ctx["delivered"] = True
                        for g in ctx["cohort"]:
                            g.delivered += 1
                    else:
                        self._refuse(ctx, "undelivered")
            else:
                msg = payload["message"]
                code = msg.rsplit(" ", 1)[-1].rstrip(".")      # what the recipient reads from the SMS
                ok = fb.verify(payload["sid"], payload["log_id"], code)
                if payload["attacker"]:
                    if ok:
                        self.attacker_verifications += 1
                        self.phase[ctx["phase"]]["verified"] += 1
                elif ok:
                    ctx["completed"] = True
                    for g in ctx["cohort"]:
                        g.completed += 1
        self.h.clock.t = until

    def _refuse(self, ctx, why):
        """A legitimate request lost at `why`: gate | step | no_channel | undelivered."""
        ctx["refused"] = why
        for g in ctx["cohort"]:
            g.refused += 1
            g.refused_by[why] = g.refused_by.get(why, 0) + 1

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

    def baseline_tick(self, observed_per_min):
        """The adaptive job of Step 9 at the worker's cadence. 'oracle': told the modelled legitimate
        rate (what a perfectly learned profile would say). 'learned': the deployed job, reading the
        pipeline's own per-minute volume counters, so cold start, contamination by refused attack
        volume and missing history are all in play."""
        if self.spec.caps_lifted:
            return
        if self.baseline_job is not None:
            self.baseline_job.tick()
            return
        l = self.spec.legit
        conv = self.h.p.rep.conversion_ratio("country:966", self.h.cfg.conversion_min_sample)
        self.h.p.adaptive.recompute("App/RegisterOTP", "web", "966", observed=observed_per_min,
                                    expected_median=l.rate_per_min, mad=0.25 * l.rate_per_min, conversion=conv)

    # ---- one request ----
    def handle_attacker(self, ctx, minute):
        self.phase[ctx["phase"]]["requests"] += 1
        tok = self.open_session(ctx)
        if tok is None:
            self.stopped_by["session_gate"] += 1
            return 0, 0
        self.attacker_blocks_requested.add(ctx["mobile"][:8])
        r = self.send_counting(self.request_from(ctx, tok), True)
        if r.tier == "challenge" and self.spec.attacker.solves_challenges:
            self.attacker_challenges_solved += 1
            r = self.send_counting(self.request_from(ctx, tok, challenge=True), True)
        self.stopped_by[r.rejected_at or f"sent:{r.channel}:{r.tier}"] += 1
        reached_cap = int(r.rejected_at in (None, "step9") and r.tier != "downgrade")
        if r.channel == "sms":
            self.attacker_blocks_leaked.add(ctx["mobile"][:8])
            self.phase[ctx["phase"]]["leaked"] += 1
            self.schedule_delivery(r, ctx, minute)
            return 1, reached_cap
        return 0, reached_cap

    def handle_legit(self, ctx, minute):
        h = self.h
        for g in ctx["cohort"]:
            g.users += 1
        if not ctx["warm"]:
            self.legit_ctxs.append(ctx)
            if self.legit_blocks:
                self.legit_block_sends[ctx["mobile"][:8]] += 1
        tok = self.open_session(ctx)
        if tok is None:
            self._refuse(ctx, "gate")
            return 0
        r = self.send_counting(self.request_from(ctx, tok), False)
        reached_cap = int(r.rejected_at in (None, "step9") and r.tier != "downgrade")
        hit = 0
        for sig in r.signals:
            if sig.startswith("block_stage") or sig.startswith("block_count_stage"):
                ctx["hit_stage"] = int(sig[-1]); hit = 1
            elif sig.startswith("block_") and ctx["hit_stage"] is None:
                ctx["hit_stage"] = "deny"; hit = 1
        if r.tier == "challenge":
            for g in ctx["cohort"]:
                g.challenged += 1
            if ctx["solves"]:
                r = self.send_counting(self.request_from(ctx, tok, challenge=True), False)
        if r.channel is not None:
            ctx["dispatched"] = True
            for g in ctx["cohort"]:
                g.dispatched += 1
                g.by_channel[r.channel] = g.by_channel.get(r.channel, 0) + 1
                if r.tier == "delay":
                    g.delayed += 1
                    g.added_delay_s_total += h.svc.sender.sent[-1].delay
            self.schedule_delivery(r, ctx, minute)
        else:
            self._refuse(ctx, "step" if r.rejected_at not in (None, "no_channel") else "no_channel")
        if not ctx["warm"]:
            self.legit_hit_minute += hit
        return reached_cap

    # ---- main loop ----
    def run(self):
        spec, h = self.spec, self.h
        a = spec.attacker
        k_attack = 0
        cap_acc = 0
        t_start = h.clock.now()
        tick = spec.adaptive_tick_s
        for minute in range(-spec.warmup_minutes, spec.minutes):
            warm = minute < 0
            minute_start = t_start + (minute + spec.warmup_minutes) * 60.0
            attacking = not spec.legit_only and (
                (not warm and (a.active_minutes is None or minute < a.active_minutes)) or (warm and spec.warmup_attack_rate > 0))
            na = self._poisson(spec.warmup_attack_rate if warm else a.rate_per_min) if attacking else 0
            nl = self._poisson(spec.legit.rate_per_min)
            # arrival times inside the minute are part of the offered workload
            arrivals = sorted([(self.rng_w.random() * 60.0, True) for _ in range(na)] +
                              [(self.rng_w.random() * 60.0, False) for _ in range(nl)])
            leaked = 0
            self.legit_hit_minute = 0
            for offset, is_attacker in arrivals:
                t = minute_start + offset
                self.process_due_events(until=t)             # the clock is now t, whatever the pipeline decided before
                if is_attacker:
                    ctx = self.make_attacker_ctx(k_attack, minute)
                    k_attack += 1
                    if ctx["fp"] is None:
                        ctx["fp"] = f"attacker-fp-{k_attack}"
                    lk, rc = self.handle_attacker(ctx, minute)
                    leaked += lk; cap_acc += rc
                else:
                    cap_acc += self.handle_legit(self.make_legit_ctx(minute, warm), minute)
            minute_end = minute_start + 60.0
            self.process_due_events(until=minute_end)        # the minute boundary is reached regardless of acceptance
            h.p.feedback.run_due_timeouts()
            elapsed = int(minute_end - t_start)
            if (elapsed - spec.adaptive_phase_s) % tick == 0:
                self.baseline_tick(cap_acc / max(1, tick // 60))
                cap_acc = 0
            if not warm:
                self.leaked_per_min.append(leaked)
                self.attack_per_min.append(na)
                self.legit_hit_per_min.append(self.legit_hit_minute)
        # drain to the declared horizon: every receipt, entry and resolution timeout of a send inside the window
        horizon = spec.drain_horizon_s if spec.drain_horizon_s is not None else \
            h.cfg.receipt_grace_s + h.cfg.resolution_timeout_s + 600
        t_end = h.clock.now()
        while h.clock.now() < t_end + horizon and (self.events or h.p.store.zrangebyscore(h.p.feedback.TIMEOUTS, float("-inf"), float("inf"))):
            self.process_due_events(until=h.clock.now() + 60.0)
            h.p.feedback.run_due_timeouts()
        self.pending_at_end = {"events": len(self.events),
                               "timeouts": len(h.p.store.zrangebyscore(h.p.feedback.TIMEOUTS, float("-inf"), float("inf")))}
        return self.result(t_start, t_end)

    def result(self, t_start, t_end):
        spec, h = self.spec, self.h
        events = h.p.feedback.verdict_events()
        attack_start = t_start + spec.warmup_minutes * 60.0
        measured = [e for e in events if e["at"] >= attack_start]
        ttl = h.cfg.denylist_ttl if h.cfg.block_action == "deny" else h.cfg.block_verdict_ttl
        exposure = 0.0
        for block in {e["block"] for e in measured}:
            intervals = sorted((e["at"], min(e["at"] + ttl, t_end)) for e in measured if e["block"] == block)
            cur_s, cur_e = None, None
            for s_, e_ in intervals:
                if cur_e is None or s_ > cur_e:
                    if cur_e is not None:
                        exposure += cur_e - cur_s
                    cur_s, cur_e = s_, e_
                else:
                    cur_e = max(cur_e, e_)
            if cur_e is not None:
                exposure += cur_e - cur_s
        hits = [c for c in self.legit_ctxs if c["hit_stage"] is not None]
        fr = self.friction.finish()
        self._check_cohorts(fr)
        attack = AttackMetrics.build(self.leaked_per_min, self.attack_per_min, self.attacker_hlr, self.attacker_recaptcha,
                                     cost_model(), self.stopped_by)
        occ = sorted(self.legit_block_sends.values()) if self.legit_blocks else []
        return {"attack": asdict(attack), "friction": asdict(fr),
                "funnel": {"offered": fr.users, "past_gate": fr.users - fr.refused_by.get("gate", 0), "dispatched": fr.dispatched,
                           "delivered": fr.delivered, "completed": fr.completed, "lost": dict(fr.refused_by)},
                "attacker_challenges_solved": self.attacker_challenges_solved,
                "attacker_verifications": self.attacker_verifications,
                "attacker_session_attempts": self.attacker_session_attempts,
                "attacker_sessions_refused": self.attacker_sessions_refused,
                "attacker_blocks_requested": len(self.attacker_blocks_requested),
                "attacker_blocks_leaked": len(self.attacker_blocks_leaked),
                "attack_phase": {ph: dict(c) for ph, c in self.phase.items()},
                # verdicts: events, not blocks
                "block_verdicts": len(measured),
                "blocks_with_verdict": len({e["block"] for e in measured}),
                "verdicts_stage1": sum(1 for e in measured if e["stage"] == 1),
                "verdicts_stage2": sum(1 for e in measured if e["stage"] == 2),
                "verdict_exposure_block_min": exposure / 60.0,
                "legit_hit_by_verdict": len(hits),
                "legit_hit_stage1": sum(1 for c in hits if c["hit_stage"] == 1),
                "legit_hit_stage2": sum(1 for c in hits if c["hit_stage"] == 2),
                "legit_hit_lost": sum(1 for c in hits if not c["completed"]),
                "legit_hit_per_min": list(self.legit_hit_per_min),
                "legit_block_occupancy": {"distinct_blocks": len(self.legit_blocks or []), "touched": len(occ),
                                          "min": occ[0] if occ else 0, "median": occ[len(occ) // 2] if occ else 0, "max": occ[-1] if occ else 0},
                "outage_alerts": sum(1 for al in h.svc.alerts.alerts if "outage" in al[0]),
                "pending_at_end": self.pending_at_end,
                "workload_digest": self.digest.hexdigest(),
                "spec": {"attacker": asdict(spec.attacker), "legit": asdict(spec.legit), "minutes": spec.minutes,
                         "features": sorted(spec.features), "cfg_overrides": spec.cfg_overrides,
                         "weight_overrides": spec.weight_overrides, "seed": spec.seed,
                         "caps_lifted": spec.caps_lifted, "base_cap_multiple": spec.base_cap_multiple,
                         "adaptive_floor": spec.adaptive_floor, "adaptive_tick_s": spec.adaptive_tick_s,
                         "adaptive_phase_s": spec.adaptive_phase_s, "baseline": spec.baseline,
                         "warmup_minutes": spec.warmup_minutes, "warmup_attack_rate": spec.warmup_attack_rate,
                         "recalibrate_speed": spec.recalibrate_speed}}

    @staticmethod
    def _check_cohorts(fr: FrictionMetrics):
        """Conservation laws of the measurement: subgroups add up to the whole, and the funnel is monotone."""
        for f in ("users", "dispatched", "delivered", "completed", "challenged", "refused"):
            assert getattr(fr.first_time, f) + getattr(fr.returning, f) == getattr(fr, f), f
        for g in (fr, fr.first_time, fr.returning):
            assert g.completed <= g.delivered <= g.dispatched <= g.users, (g.users, g.dispatched, g.delivered, g.completed)
            assert g.refused == sum(g.refused_by.values())

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
