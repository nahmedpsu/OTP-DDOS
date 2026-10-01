"""Minute-by-minute simulation of one source under attack with legitimate traffic in the
background. Attackers and users are drawn from calibrated distributions (calibration.py);
verification happens after a realistic delay; the feedback loop runs as it would in production.
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
    numbers: str = "random"            # random | sequential | premium | elevated | concentrated
    n_blocks: int = 3                  # concentrated: how many destination ranges the pumper's carrier serves
    block_range_digits: int = 8        # concentrated: fixed leading digits per range (8 = 10 000 numbers, 7 = 100 000, 9 = 1 000)
    earns_revenue: bool = False        # pumping attackers are paid per terminated SMS; flooders are not
    rate_multiple_of_legit: float = None   # if set, rate_per_min = multiple x legitimate rate (dilution study)
    verify_fraction: float = 0.0       # colluding carrier submits codes
    verify_delay_s: float = 1.0
    solves_challenges: bool = False    # pays a solving service for interactive challenges
    platform_spoof: bool = False
    n_asns: int = 1
    ip_country: str = "SA"


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
    warmup_minutes: int = 10            # legitimate-only traffic before the attack, so history exists
    seed: int = 0
    outage: OutageSpec = None
    legit_only: bool = False            # no attacker at all (false-positive runs)


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
        self.rng = random.Random(spec.seed)
        h = Harness()
        self.h = h
        h.cfg.features = spec.features
        for k, v in spec.cfg_overrides.items():
            setattr(h.cfg, k, v)
        h.cfg.weights = dict(h.cfg.weights, **spec.weight_overrides)
        h.cfg.asn_limit_default = 10 ** 9
        if "sprt_legit_fast" not in spec.cfg_overrides:
            # the speed test's legitimate rate comes from the (modelled) legitimate distribution, as it
            # would come from a deployment's own measurements
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
        self.events = []                    # heap of (t, seq, kind, payload): receipts and verifications
        self.seq = itertools.count()
        h.svc.sender.instant_receipts = False      # receipts arrive after a delivery delay, from schedule_delivery
        self.legit_blocks = None
        if spec.legit.blocks:
            self.legit_blocks = [f"{self.rng.choice(STANDARD_PREFIXES)}{self.rng.randrange(1000):03d}" for _ in range(spec.legit.blocks)]
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

    # ---- helpers ----
    def captcha_token(self, beta):
        score = self.rng.betavariate(*beta)
        tok = f"t{next(self.tokens)}"
        self.h.svc.recaptcha.scores[tok] = score
        return tok

    def attacker_number(self, k):
        a = self.spec.attacker
        if a.numbers == "sequential":
            return f"966501{k:06d}"
        if a.numbers == "premium":
            return f"{PREMIUM_PREFIX}{k:07d}"
        if a.numbers == "elevated":
            return f"{ELEVATED_PREFIX}{k:07d}"
        if a.numbers == "concentrated":
            # the pumper is paid only on the ranges its partner carrier terminates: n_blocks ranges of
            # 10**(12 - block_range_digits) numbers inside a standard prefix, chosen once per attacker
            fixed, tail = a.block_range_digits - 5, 12 - a.block_range_digits
            if "blocks" not in self.attack_state:
                self.attack_state["blocks"] = [f"{STANDARD_PREFIXES[0]}{self.rng.randrange(10**fixed):0{fixed}d}" for _ in range(a.n_blocks)]
            return f"{self.rng.choice(self.attack_state['blocks'])}{self.rng.randrange(10**tail):0{tail}d}"
        return f"{self.rng.choice(STANDARD_PREFIXES)}{self.rng.randrange(10**7):07d}"

    def attacker_ip(self, k):
        a = self.spec.attacker
        idx = self.rng.randrange(a.pool_size)
        if a.network == "single_ip":
            return "198.51.100.10"
        if a.network == "datacenter":
            return _dc_ip(idx)
        if a.network == "multi_asn":
            return _asn_ip(k % a.n_asns, idx)
        return _res_ip(idx)

    def attacker_session(self, k):
        a, h, st = self.spec.attacker, self.h, self.attack_state
        if a.fp_mode == "single":
            if "tok" not in st:
                st["tok"], _ = h.session("web", age_hours=2)
            return st["tok"]
        if a.fp_mode == "reused":
            if k % 3 == 0 or "tok" not in st:
                st["tok"], _ = h.session("web", fingerprint="bot-browser-profile", age_hours=48)
            return st["tok"]
        return h.session("web", age_hours=2 if a.fp_mode == "aged" else 0)[0]

    def attacker_request(self, k, challenge_proof=None, session=None):
        a = self.spec.attacker
        tok = session or self.attacker_session(k)
        kw = dict(session=tok, ip=self.attacker_ip(k), mobile=self.attacker_number(k),
                  recaptcha=self.captcha_token(a.captcha_beta))
        if a.platform_spoof:
            kw.update(header_platform="ios", host="attacker.local")
        if challenge_proof:
            kw["challenge_proof"] = challenge_proof
        return self.h.web_request(**kw)

    def legit_request(self, k, challenge_proof=None, session=None):
        l, h = self.spec.legit, self.h
        if session is None:
            if self.verified_fps and self.rng.random() < l.returning_fraction:
                session, _ = h.session("web", fingerprint=self.rng.choice(self.verified_fps), age_hours=24)
            else:
                fresh = self.rng.random() < l.fresh_fp_fraction
                session, _ = h.session("web", age_hours=0 if fresh else 24)
        u = self.rng.random()
        if u < l.corporate_egress_fraction:
            ip = f"192.0.2.{self.rng.randrange(1, 255)}"
        elif u < l.corporate_egress_fraction + l.roaming_fraction:
            ip = f"198.51.200.{self.rng.randrange(1, 255)}"
        elif u < l.corporate_egress_fraction + l.roaming_fraction + l.cloud_egress_abroad_fraction:
            ip = f"198.51.201.{self.rng.randrange(1, 255)}"
        else:
            ip = _res_ip(self.rng.randrange(1 << 22))
        if self.legit_blocks:
            mobile = f"{self.rng.choice(self.legit_blocks)}{self.rng.randrange(10**4):04d}"
        else:
            mobile = f"{self.rng.choice(STANDARD_PREFIXES)}{self.rng.randrange(10**7):07d}"
        kw = dict(session=session, ip=ip, mobile=mobile, recaptcha=self.captcha_token(l.captcha_beta))
        if challenge_proof:
            kw["challenge_proof"] = challenge_proof
        return h.web_request(**kw)

    def send_counting(self, req, is_attacker):
        h = self.h
        hl, rc = h.svc.hlr.calls, h.svc.recaptcha.calls
        r = h.send(req)
        if is_attacker:
            self.attacker_hlr += h.svc.hlr.calls - hl
            self.attacker_recaptcha += h.svc.recaptcha.calls - rc
        return r

    def push(self, t, kind, payload):
        heapq.heappush(self.events, (t, next(self.seq), kind, payload))

    def process_due_events(self):
        now = self.h.clock.now()
        fb = self.h.p.feedback
        while self.events and self.events[0][0] <= now:
            _, _, kind, payload = heapq.heappop(self.events)
            if kind == "receipt":
                fb.on_delivery(payload["log_id"], payload["ok"])
            else:
                ok = fb.verify(payload["sid"], payload["log_id"], fb.code_for(payload["log_id"]))
                if payload["attacker"] and ok:
                    self.attacker_verifications += 1
                elif ok and len(self.verified_fps) < 5000:
                    self.verified_fps.append(self.h.p.sms_history[payload["log_id"]]["fingerprint"])

    def in_outage(self, mobile, minute):
        o = self.spec.outage
        return o is not None and mobile.startswith(o.prefix) and o.start_min <= minute < o.start_min + o.duration_min

    def schedule_delivery(self, r, is_attacker, minute):
        """Receipt after the delivery delay, then (maybe) a verification clocked from the receipt."""
        a, l, rng = self.spec.attacker, self.spec.legit, self.rng
        now = self.h.clock.now()
        rec = self.h.p.sms_history[r.log_id]
        sid, mobile = rec["session_id"], rec["phone_number"]
        delivery = l.delivery_median_s * math.exp(rng.gauss(0, l.delivery_sigma))
        if self.in_outage(mobile, minute) and not is_attacker:
            o = self.spec.outage
            if o.kind == "failed_receipts":
                self.push(now + delivery, "receipt", {"log_id": r.log_id, "ok": False})
            else:
                self.push(now + delivery, "receipt", {"log_id": r.log_id, "ok": True})   # says delivered; nobody gets it
            return
        self.push(now + delivery, "receipt", {"log_id": r.log_id, "ok": True})
        if is_attacker:
            if rng.random() < a.verify_fraction:
                self.push(now + delivery + a.verify_delay_s, "verify", {"sid": sid, "log_id": r.log_id, "attacker": True})
        elif rng.random() < l.conversion:
            if rng.random() < l.autofill_fraction:
                entry = l.autofill_median_s * math.exp(rng.gauss(0, l.autofill_sigma))
            else:
                entry = l.verify_median_s * math.exp(rng.gauss(0, l.verify_sigma))
            self.push(now + delivery + entry, "verify", {"sid": sid, "log_id": r.log_id, "attacker": False})

    def baseline_job_tick(self, observed):
        """The hourly baseline job of Step 9, run once per simulated minute with a minute-level baseline."""
        if self.spec.caps_lifted:
            return
        l = self.spec.legit
        conv = self.h.p.rep.conversion_ratio("country:966", self.h.cfg.conversion_min_sample)
        self.h.p.adaptive.recompute("App/RegisterOTP", "web", "966", observed=observed,
                                    expected_median=l.rate_per_min, mad=0.25 * l.rate_per_min, conversion=conv)

    # ---- main loop ----
    def run(self):
        spec, h, rng = self.spec, self.h, self.rng
        k_attack = 0
        for minute in range(-spec.warmup_minutes, spec.minutes):
            warm = minute < 0
            na = 0 if (warm or spec.legit_only) else self._poisson(spec.attacker.rate_per_min)
            nl = self._poisson(spec.legit.rate_per_min)
            order = [True] * na + [False] * nl
            rng.shuffle(order)
            step = 60.0 / max(len(order), 1)
            leaked, reached_cap = 0, 0
            for is_attacker in order:
                self.process_due_events()
                if is_attacker:
                    req = self.attacker_request(k_attack)
                    r = self.send_counting(req, True)
                    if r.tier == "challenge" and spec.attacker.solves_challenges:
                        proof = self.captcha_token((9, 1.5))
                        self.attacker_challenges_solved += 1
                        r = self.send_counting(self.attacker_request(k_attack, challenge_proof=proof, session=req.session_token), True)
                    k_attack += 1
                    outcome = r.rejected_at or f"sent:{r.channel}:{r.tier}"
                    self.stopped_by[outcome] += 1
                    reached_cap += r.rejected_at in (None, "step9") and r.tier != "downgrade"
                    if r.channel == "sms":
                        leaked += 1
                        self.schedule_delivery(r, True, minute)
                else:
                    req = self.legit_request(minute)
                    r = self.send_counting(req, False)
                    f = self.friction
                    f.users += 1
                    reached_cap += r.rejected_at in (None, "step9") and r.tier != "downgrade"
                    if any(sig.startswith("block_") for sig in r.signals):
                        self.legit_hit_by_verdict += 1
                    if r.tier == "challenge":
                        f.challenged += 1
                        if rng.random() < spec.legit.solves_challenges:
                            r = self.send_counting(self.legit_request(minute, challenge_proof=self.captcha_token((9, 1.5)), session=req.session_token), False)
                    if r.channel is not None:
                        f.delivered += 1
                        if r.tier == "delay":
                            f.delayed += 1
                            f.added_delay_s_total += h.svc.sender.sent[-1].delay
                        self.schedule_delivery(r, False, minute)
                    else:
                        f.refused += 1
                h.clock.advance(step)
            self.process_due_events()
            h.p.feedback.run_due_timeouts()
            self.baseline_job_tick(reached_cap)
            if warm:
                self.friction = FrictionMetrics()      # warm-up friction is not counted
                continue
            self.leaked_per_min.append(leaked)
            self.attack_per_min.append(na)
        self.process_due_events()
        self.verdict_blocks = set(h.p.store.zrangebyscore(h.p.feedback.VERDICT_LOG, float("-inf"), float("inf")))
        self.outage_alerts = sum(1 for a in h.svc.alerts.alerts if "outage" in a[0])
        attack = AttackMetrics.build(self.leaked_per_min, self.attack_per_min, self.attacker_hlr, self.attacker_recaptcha,
                                     cost_model(), self.stopped_by)
        return {"attack": asdict(attack), "friction": asdict(self.friction.finish()),
                "attacker_challenges_solved": self.attacker_challenges_solved,
                "attacker_verifications": self.attacker_verifications,
                "block_verdicts": len(self.verdict_blocks), "legit_hit_by_verdict": self.legit_hit_by_verdict,
                "outage_alerts": self.outage_alerts,
                "spec": {"attacker": asdict(spec.attacker), "legit": asdict(spec.legit), "minutes": spec.minutes,
                         "features": sorted(spec.features), "cfg_overrides": spec.cfg_overrides,
                         "weight_overrides": spec.weight_overrides, "seed": spec.seed,
                         "caps_lifted": spec.caps_lifted, "base_cap_multiple": spec.base_cap_multiple,
                         "adaptive_floor": spec.adaptive_floor}}

    def _poisson(self, lam):
        if lam <= 0:
            return 0
        L, k, p = math.exp(-lam), 0, 1.0
        while True:
            k += 1
            p *= self.rng.random()
            if p <= L:
                return k - 1


def run_sim(spec: SimSpec):
    t0 = time.perf_counter()
    out = Simulation(spec).run()
    out["wall_s"] = time.perf_counter() - t0
    return out
