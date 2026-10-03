"""Event-driven simulation of one registration source under attack, with legitimate traffic in the
background. Attackers and users are drawn from calibrated distributions (calibration.py); the
pipeline runs inside the simulation on fakes (CAPTCHA scores, IP intelligence, HLR, sender, the
WhatsApp registry) with delivery receipts and code entries arriving as timed events; the feedback
loop and the adaptive baseline job run as deployed, except where a substitution is named below.

Offered workload. Every exogenous quantity of a request is drawn when the request is created, before
the pipeline sees it, from one of two independent streams: `rng_l` for legitimate traffic and
`rng_w` for the attacker. Legitimate arrivals and attributes therefore do not depend on whether or
how hard anyone attacks: at a given seed, every scenario (no attack included) offers the same
legitimate users, so cross-scenario service comparisons are paired. The quantities: arrival time, identity, address, destination number, CAPTCHA
scores for every session attempt, whether the person would verify and after how long, delivery
delay, the token a challenge retry would present, whether the number is reachable on WhatsApp,
whether a poorly performing route loses the message, and whether the person would press "resend".
The only policy-dependent random decision (does a challenged person solve the challenge) comes
from `rng_p`. Two runs with the same seed therefore offer the same trace of first requests whatever
the defence does; `workload_digest` hashes that trace and the tests assert it equal across designs.
Reactions to the defence (a resend after a code that never came, a threshold-aware carrier's
choice to verify) are not part of the digest and are counted separately.

Channel fallback. The number's WhatsApp reachability is a stable property of the number by default
(`whatsapp_mode='per_number'`: a hash of the seed and the number, below `whatsapp_fraction`;
`'per_request'` draws it per request as versions before 2.8.0 did). It is written into the channel
registry the selector reads (svc.channels.whatsapp_numbers) before each request is processed:
reachable numbers are added, unreachable ones removed. A downgraded first-time client is therefore
served over WhatsApp with probability `whatsapp_fraction` over numbers and refused otherwise.
Attacker numbers are never registered.

Legitimate users. Each first request creates a user record; its later requests (a challenge retry,
a resend) attach to the same record. Outcomes are aggregated per user at the end, into the all-user
and the cohort accumulators: users >= dispatched >= delivered >= completed, refused = users -
delivered, and the cohorts add up to the whole (asserted at the end of every run). Cohorts:
'returning' requests come from a pre-existing population of account holders (stable identity and
number, verified history seeded before the run: `returning_mode='population'`), or, in the second
round's design, from identities the trace offered earlier (`'trace'`); 'first-time' is everyone
else. Whether a request was actually treated as known-good is recorded separately.

Time. Arrivals carry timestamps inside their minute and the clock moves to each arrival and each
minute boundary whatever the pipeline decides; events are processed at their own timestamps.
After the last minute the run drains to a declared horizon (receipt grace + resolution timeout +
the slowest modelled entry, and a resend) and reports anything still pending.

Verdict estimands, reported separately: incidence (verdict events issued inside the observation
window [attack start, end of last minute]); exposure (block-minutes under a verdict inside that
window, the union of active intervals intersected with the window, including verdicts issued
before it that were still active); and eventual events (issued at or after the attack start,
including the drain, i.e. caused by sends inside the window).

Substitutions, all named: vendors are fakes with zero latency; the sender's receipts are simulated;
`baseline='oracle'` (the main study) hands the adaptive job the modelled legitimate rate,
`baseline='learned'` runs the deployed BaselineJob on the pipeline's own counters.
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
    verify_policy: str = "fixed"       # 'fixed': verify with probability verify_fraction; 'threshold_aware': the carrier
                                       # knows the deployed test parameters, mirrors each block's conversion statistic and
                                       # verifies a code only when not doing so would bring it within `threshold_margin`
    threshold_margin: float = 1.0      # (natural-log units) of the verdict threshold
    solves_challenges: bool = False    # pays a solving service for interactive challenges
    platform_spoof: bool = False       # sends HTTP_PLATFORM: ios without attestation (host and session are valid)
    n_asns: int = 1
    ip_country: str = "SA"
    trust_building_minutes: int = 0    # phase 1: a pool of (identity, number) pairs verifies everything (human-like delay)
    trust_pool: int = 500              # pairs in that pool; phase 2 reuses the same pairs without verifying
    trust_concentrated: bool = False   # the pool's numbers lie inside the attacker's concentrated blocks
    fake_failed_receipts: bool = False # the colluding carrier reports its own deliveries as failed
    active_minutes: int = None         # the attack stops after this many minutes (recovery studies); None = whole run
    shared_blocks: bool = False        # concentrated: the carrier's ranges are blocks real users also use (legit hot blocks
                                       # if any, else the legitimate block set); needs 8-digit ranges
    quota: tuple = None                # (sends, window_s): a quota-aware pumper that knows the destination counter and
                                       # sends at most this many per block per window, moving to another of its blocks


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
    returning_fraction: float = cal("legit_returning_fraction")   # requests from returning account holders
    returning_mode: str = "population" # 'population': a pre-existing population with stable numbers and verified history;
                                       # 'trace': identities the trace offered earlier, a new number each time (round 2)
    returning_population: int = 5000
    corporate_egress_fraction: float = 0.05   # office traffic leaving through an in-country hosting range
    roaming_fraction: float = 0.05            # in-country number, connecting from abroad
    cloud_egress_abroad_fraction: float = 0.02  # a company proxy abroad: hosting range + geo mismatch
    whatsapp_fraction: float = 0.7     # numbers reachable on WhatsApp (the downgrade channel for new users)
    # heterogeneity (all zero/empty: the homogeneous population of the main study)
    block_conversion_sd: float = 0.0   # per-block conversion ~ Beta(mean = conversion, sd); stable for the run
    bad_route_fraction: float = 0.0    # share of 8-digit blocks on a persistently poor route
    bad_route_failure: float = 0.5     # probability that a message to such a block is lost (failed receipt)
    resend_prob: float = 0.0           # a converting user whose code has not been entered after resend_after_s asks again
    resend_after_s: float = 90.0
    bursts: tuple = ()                 # ((start minute, end minute, rate multiplier), ...): campaign-like demand bursts
    whatsapp_mode: str = "per_number"  # 'per_number': reachability is a stable property of the number (hash of seed and
                                       # number); 'per_request': redrawn for every request (up to 2.7.0)
    no_whatsapp_solves: float = None   # challenge completion of users without WhatsApp (None: solves_challenges); a
                                       # correlated-failure stress: those who cannot fall back also fail challenges
    hot_blocks: int = 0                # this many hot 8-digit blocks receive hot_fraction of legitimate requests
    hot_fraction: float = 0.0
    hot_bad_route: bool = False        # the hot blocks are on a poor route (lose bad_route_failure of their messages)
    launch: tuple = ()                 # (start minute, end minute, rate multiplier, hot fraction): a product launch, i.e. a
                                       # burst of first-time users with fresh fingerprints concentrated on the hot blocks


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
    captcha_outage: tuple = None        # (start minute, duration): the CAPTCHA vendor fails every assessment (correlated failure)
    legit_only: bool = False            # no attacker at all (false-positive runs)
    recalibrate_speed: bool = False     # True: set sprt_legit_fast from this run's own legitimate population
    drain_horizon_s: int = None         # None: receipt grace + resolution timeout + 10 min + a resend
    containment_sustain_min: int = 5    # containment needs at least this many quiet minutes before the run ends
    record_requests: bool = False       # keep per-request outcome bitmaps (paired counterfactual comparisons)
    profile_weeks: int = 0              # learned baseline: simulate this many earlier weeks of the attack's hour of week
    profile_rate_multiple: float = 1.0  # legitimate rate in those weeks relative to the attack week (a stale profile)
    baseline_workers: int = 1           # learned baseline: this many workers tick concurrently
    baseline_restart_min: int = None    # learned baseline: the job process is replaced at this minute (restart)


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


def _bits(indices, n):
    """Bit-packed set of request ids, as hex (paired per-request comparisons)."""
    b = bytearray((n + 7) // 8)
    for i in indices:
        b[i // 8] |= 1 << (i % 8)
    return b.hex()


def unbits(hexstr):
    b = bytes.fromhex(hexstr)
    return {i * 8 + j for i, byte in enumerate(b) for j in range(8) if byte >> j & 1}


MAX_SESSION_ATTEMPTS = 10


class Simulation:
    def __init__(self, spec: SimSpec):
        self.spec = spec
        if spec.attacker.rate_multiple_of_legit is not None:
            spec.attacker.rate_per_min = spec.attacker.rate_multiple_of_legit * spec.legit.rate_per_min
        self.rng_w = random.Random(spec.seed)                 # workload: the attacker's requests
        self.rng_l = random.Random(f"{spec.seed}:legit")      # workload: legitimate traffic, independent of the attacker
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
        self.baseline_jobs = [BaselineJob(h.p) for _ in range(spec.baseline_workers)] if spec.baseline == "learned" else []
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
            picks = self.rng_l.sample(range(universe), min(spec.legit.blocks, universe))
            self.legit_blocks = [f"{STANDARD_PREFIXES[i // 1000]}{i % 1000:03d}" for i in picks]
        self.hot_blocks = []
        if spec.legit.hot_blocks:
            pool = self.legit_blocks or [f"{STANDARD_PREFIXES[i // 1000]}{i % 1000:03d}" for i in
                                         self.rng_l.sample(range(len(STANDARD_PREFIXES) * 1000), spec.legit.hot_blocks)]
            self.hot_blocks = pool[:spec.legit.hot_blocks]
        self.block_traits = {}              # block -> (conversion, bad route), drawn once per block from its own stream
        self.legit_block_sends = collections.Counter()
        self.legit_identities = []          # returning_mode 'trace': fingerprints the trace has offered so far
        self.population = []                # returning_mode 'population': (fingerprint, number) of existing account holders
        self.attack_state = {}
        self.stopped_by = collections.Counter()
        self.leaked_per_min, self.attack_per_min = [], []
        self.users = []                     # legitimate user records (warm-up ones are flagged and not measured)
        self.n_measured = 0
        self.attacker_hlr = self.attacker_recaptcha = 0
        self.attacker_challenges_solved = 0
        self.attacker_verifications = 0
        self.attacker_session_attempts = 0
        self.attacker_sessions_refused = 0
        self.attacker_requests_offered = 0
        self.attacker_blocks_requested, self.attacker_blocks_leaked = set(), set()
        self.phase = {ph: collections.Counter() for ph in ("prep", "flood")}    # trust-building attackers
        self.mirror = {}                                                         # threshold-aware carrier's view per block
        self.t_tick0 = self.h.clock.now()                                        # the worker ticks on minute boundaries from here
        self.ctx_by_log = {}
        self.digest = hashlib.sha1()
        self.legit_digest = hashlib.sha1()  # the legitimate part alone: equal across attackers at a given seed
        self.reactions = collections.Counter()    # policy-dependent requests: resends, challenge retries
        self.pending_at_end = {}
        self.t_attack_start = self.t_end = None
        self.captcha_down = False
        if spec.legit.returning_mode == "population":
            self._seed_population()

    # ---- helpers ----
    def _seed_population(self):
        """Existing account holders: a stable identity and number each, with verified history written
        before the run (a fingerprint that verified, a trusted number). Policy-independent."""
        l, h = self.spec.legit, self.h
        for i in range(l.returning_population):
            mobile = self._legit_number()
            fp = f"account-fp-{i}"
            self.population.append((fp, mobile))
            h.p.sessions.set_first_seen(fp, h.clock.now() - 30 * 86400)
            h.p.rep.mark_trusted("num:" + mobile)
            h.p.rep.incr("fp:" + fp, "verified", 1)        # the account holder's device has verified before

    def _token(self, score):
        tok = f"t{next(self.tokens)}"
        if not self.captcha_down:                            # a CAPTCHA vendor outage: every assessment fails
            self.h.svc.recaptcha.scores[tok] = score
        return tok

    def _scores(self, beta, n, rng=None):
        rng = rng or self.rng_w
        return [rng.betavariate(*beta) for _ in range(n)]

    def session_through_gate(self, platform, scores, fingerprint=None, age_hours=0, attacker=True):
        """/session issues a token only after a CAPTCHA pass; each attempt costs a token. The scores
        were drawn at request creation; how many are consumed depends on the threshold."""
        for score in scores:
            if attacker:
                self.attacker_session_attempts += 1
            self._token(score)
            if not self.captcha_down and score >= self.h.p.recaptcha_min_score():
                return self.h.session(platform, fingerprint=fingerprint, age_hours=age_hours)[0]
            if attacker:
                self.attacker_sessions_refused += 1
            else:
                return None                                   # a person gives up after one refusal
        return None

    def _traits(self, block):
        """Per-block conversion and route quality, drawn from a stream keyed by the block, so every
        run with the same seed sees the same block population whatever the order of requests."""
        if block not in self.block_traits:
            l = self.spec.legit
            r = random.Random(f"{self.spec.seed}:{block}")
            conv = l.conversion
            if l.block_conversion_sd > 0:
                m, sd = l.conversion, l.block_conversion_sd
                k = max(m * (1 - m) / (sd * sd) - 1, 1e-3)
                conv = r.betavariate(m * k, (1 - m) * k)
            bad = r.random() < l.bad_route_fraction or (l.hot_bad_route and block in self.hot_blocks)
            self.block_traits[block] = (conv, bad)
        return self.block_traits[block]

    def _ranges(self):
        a = self.spec.attacker
        if "blocks" not in self.attack_state and a.shared_blocks:
            assert a.block_range_digits == 8, "shared blocks are 8-digit blocks"
            pool = self.hot_blocks or self.legit_blocks
            assert pool, "a shared-block attacker needs legitimate blocks (legit.blocks or legit.hot_blocks)"
            self.attack_state["blocks"] = list(pool[:a.n_blocks])
        if "blocks" not in self.attack_state:
            fixed = a.block_range_digits - 5
            universe = len(STANDARD_PREFIXES) * 10 ** fixed            # distinct ranges that exist
            picks = self.rng_w.sample(range(universe), min(a.n_blocks, universe))   # without replacement
            self.attack_state["blocks"] = [f"{STANDARD_PREFIXES[i // 10 ** fixed]}{i % 10 ** fixed:0{fixed}d}" for i in picks]
        return self.attack_state["blocks"]

    def _concentrated_number(self):
        a = self.spec.attacker
        tail = 12 - a.block_range_digits
        blocks = self._ranges()
        u_block, u_tail = self.rng_w.random(), self.rng_w.randrange(10**tail)   # drawn whatever the policy below
        if a.quota:
            # quota-aware: the first of its blocks (from a random start) with quota left in the current window
            n, w = a.quota
            now = self.h.clock.now()
            sent = self.attack_state.setdefault("quota", {})
            start = int(u_block * len(blocks))
            for k in range(len(blocks)):
                b = blocks[(start + k) % len(blocks)]
                times = [t for t in sent.get(b, []) if t > now - w]
                if len(times) < n:
                    sent[b] = times + [now]
                    return f"{b}{u_tail:0{tail}d}"
            return None                                     # every block's quota is spent: the pumper waits
        return f"{blocks[int(u_block * len(blocks))]}{u_tail:0{tail}d}"

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
        u_verify = self.rng_w.random()
        if mobile is None:
            return None                                       # a quota-aware pumper with no quota left waits
        verify = True if in_trust_phase else (None if a.verify_policy == "threshold_aware" else u_verify < a.verify_fraction)
        ctx = dict(attacker=True, k=k, minute=minute, fp=fp, age=age, reuse_session=reuse, ip=self.attacker_ip(k), mobile=mobile,
                   gate_scores=self._scores(a.captcha_beta, MAX_SESSION_ATTEMPTS), recaptcha_score=self.rng_w.betavariate(*a.captcha_beta),
                   verify=verify, verify_delay=(30.0 if in_trust_phase else a.verify_delay_s),
                   delivery=l.delivery_median_s * math.exp(self.rng_w.gauss(0, l.delivery_sigma)),
                   retry_score=self.rng_w.betavariate(9, 1.5), spoof=a.platform_spoof, returning=False, whatsapp=False,
                   phase=("prep" if in_trust_phase else "flood"))
        self._digest(ctx)
        return ctx

    def _legit_number(self, hot_fraction=None):
        l = self.spec.legit
        hf = l.hot_fraction if hot_fraction is None else hot_fraction
        if self.hot_blocks and hf > 0 and self.rng_l.random() < hf:
            return f"{self.rng_l.choice(self.hot_blocks)}{self.rng_l.randrange(10**4):04d}"
        if self.legit_blocks:
            return f"{self.rng_l.choice(self.legit_blocks)}{self.rng_l.randrange(10**4):04d}"
        return f"{self.rng_l.choice(STANDARD_PREFIXES)}{self.rng_l.randrange(10**7):07d}"

    def _in_launch(self, minute):
        la = self.spec.legit.launch
        return bool(la) and la[0] <= minute < la[1]

    def _reachable(self, mobile, u):
        """WhatsApp reachability of a legitimate number: stable per number (default) or the per-request draw u."""
        l = self.spec.legit
        if l.whatsapp_mode == "per_request":
            return u < l.whatsapp_fraction
        h = int(hashlib.blake2b(f"{self.spec.seed}:{mobile}".encode(), digest_size=8).hexdigest(), 16)
        return h / 2 ** 64 < l.whatsapp_fraction

    def make_legit_ctx(self, minute, warm):
        l = self.spec.legit
        launch = self._in_launch(minute)
        returning = self.rng_l.random() < l.returning_fraction and not launch
        mobile = None
        if returning and l.returning_mode == "population":
            fp, mobile = self.rng_l.choice(self.population)
            age = 30 * 24
        elif returning and self.legit_identities:
            fp, age = self.rng_l.choice(self.legit_identities), 24
        else:
            returning = False
            fresh = self.rng_l.random() < l.fresh_fp_fraction or launch
            fp, age = f"legit-fp-{len(self.legit_identities)}", (0 if fresh else 24)
            self.legit_identities.append(fp)
        u = self.rng_l.random()
        if u < l.corporate_egress_fraction:
            ip = f"192.0.2.{self.rng_l.randrange(1, 255)}"
        elif u < l.corporate_egress_fraction + l.roaming_fraction:
            ip = f"198.51.200.{self.rng_l.randrange(1, 255)}"
        elif u < l.corporate_egress_fraction + l.roaming_fraction + l.cloud_egress_abroad_fraction:
            ip = f"198.51.201.{self.rng_l.randrange(1, 255)}"
        else:
            ip = _res_ip(self.rng_l.randrange(1 << 22))
        if mobile is None:
            mobile = self._legit_number(l.launch[3] if launch else None)
        u_convert = self.rng_l.random()
        autofill = self.rng_l.random() < l.autofill_fraction
        entry = (l.autofill_median_s * math.exp(self.rng_l.gauss(0, l.autofill_sigma)) if autofill
                 else l.verify_median_s * math.exp(self.rng_l.gauss(0, l.verify_sigma)))
        whatsapp = self._reachable(mobile, self.rng_l.random())
        u_route = self.rng_l.random()
        resends = self.rng_l.random() < l.resend_prob
        conv_b, bad_route = self._traits(mobile[:8])
        ctx = dict(attacker=False, minute=minute, fp=fp, age=age, reuse_session=False, ip=ip, mobile=mobile,
                   gate_scores=self._scores(l.captcha_beta, 1, self.rng_l), recaptcha_score=self.rng_l.betavariate(*l.captcha_beta),
                   verify=u_convert < conv_b, verify_delay=entry,
                   delivery=l.delivery_median_s * math.exp(self.rng_l.gauss(0, l.delivery_sigma)),
                   retry_score=self.rng_l.betavariate(9, 1.5), whatsapp=whatsapp, spoof=False, returning=returning,
                   lost_on_route=bad_route and u_route < l.bad_route_failure, resends=resends,
                   solves=self.rng_p.random() < (l.solves_challenges if whatsapp or l.no_whatsapp_solves is None
                                                 else l.no_whatsapp_solves))
        self._digest(ctx)
        user = dict(rid=None if warm else self.n_measured, warm=warm, cohort="returning" if returning else "first_time",
                    minute=minute, block=mobile[:8], challenged=False, dispatched=False, delivered=False, completed=False, loss=None,
                    delayed=False, delay_s=0.0, channel=None, hit_stage=None, hit_minute=None, known_good=None, requests=0)
        if not warm:
            self.n_measured += 1
        self.users.append(user)
        ctx["user"] = user
        return ctx

    def _digest(self, ctx):
        """Hash of the offered request, policy-independent fields only."""
        keys = ("attacker", "minute", "fp", "age", "ip", "mobile", "gate_scores", "recaptcha_score", "verify", "verify_delay",
                "delivery", "retry_score", "returning", "whatsapp", "lost_on_route", "resends")
        row = repr([ctx.get(k) for k in keys]).encode()
        self.digest.update(row)
        if not ctx["attacker"]:
            self.legit_digest.update(row)

    def _register_channels(self, ctx):
        """Write the number's WhatsApp reachability, drawn with the request, into the registry the
        channel selector reads. Attacker numbers are never reachable."""
        reg = self.h.svc.channels.whatsapp_numbers
        if ctx["whatsapp"]:
            reg.add(ctx["mobile"])
        else:
            reg.discard(ctx["mobile"])

    def open_session(self, ctx):
        """Acquire the session this request presents (an attacker may reuse one)."""
        st = self.attack_state
        if ctx["attacker"]:
            if ctx["reuse_session"] and "tok" in st:
                return st["tok"]
            tok = self.session_through_gate("web", ctx["gate_scores"], fingerprint=ctx["fp"], age_hours=ctx["age"])
            if ctx["fp"] in ("single-client-fp", "bot-browser-profile") and tok is not None:
                st["tok"] = tok
            return tok
        return self.session_through_gate("web", ctx["gate_scores"], fingerprint=ctx["fp"], age_hours=ctx["age"], attacker=False)

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
            if kind == "resend":
                ctx = payload["ctx"]
                if not ctx["user"]["completed"]:
                    self.reactions["resend"] += 1
                    self.legit_request(ctx, payload["minute"], resend=True)
                continue
            ctx = self.ctx_by_log.get(payload["log_id"])
            if kind == "receipt":
                fb.on_delivery(payload["log_id"], payload["ok"])
                if ctx is not None and not ctx["attacker"]:
                    if payload["ok"]:
                        ctx["user"]["delivered"] = True
                    elif not ctx["user"]["delivered"]:
                        ctx["user"]["loss"] = "undelivered"
            else:
                msg = payload["message"]
                code = msg.rsplit(" ", 1)[-1].rstrip(".")      # what the recipient reads from the message
                ok = fb.verify(payload["sid"], payload["log_id"], code)
                if payload["attacker"]:
                    if ok:
                        self.attacker_verifications += 1
                        self.phase[ctx["phase"]]["verified"] += 1
                elif ok:
                    ctx["user"]["completed"] = True
        self.h.clock.t = until

    def in_outage(self, mobile, minute):
        o = self.spec.outage
        return o is not None and mobile.startswith(o.prefix) and o.start_min <= minute < o.start_min + o.duration_min

    def _carrier_verifies(self, ctx, t_receipt):
        """The threshold-aware carrier (white box: it knows the deployed increments, floor, threshold,
        resolution timeout and the worker's one-minute tick). Per block it keeps its own pending
        outcomes in the order the deployment will apply them: a verification at its entry time, a
        failure at the first worker tick after the resolution timeout. For each new delivery it
        replays that trajectory with the candidate failure and verifies only if the statistic would
        come within `threshold_margin` of the threshold at any point."""
        cfg, a = self.h.cfg, self.spec.attacker
        inc_fail = math.log((1 - cfg.sprt_attack_conversion) / (1 - cfg.sprt_legit_conversion))
        inc_verify = math.log(cfg.sprt_attack_conversion / cfg.sprt_legit_conversion)
        thr = math.log(cfg.sprt_threshold)
        floor = -cfg.block_credit_thresholds * thr if cfg.block_test == "cusum" else -math.inf
        block = ctx["mobile"][:8]
        base, pending = self.mirror.get(block, (0.0, []))
        now = self.h.clock.now()
        applied = [e for e in pending if e[0] <= now]
        pending = [e for e in pending if e[0] > now]
        for _, inc in sorted(applied):
            base = max(floor, base + inc)
        t_fail = math.ceil((t_receipt + min(cfg.resolution_timeout_s, cfg.otp_ttl) - self.t_tick0) / 60.0) * 60.0 + self.t_tick0
        t_verify = t_receipt + a.verify_delay_s

        def peak(events):
            x, top = base, base
            for _, inc in sorted(events):
                x = max(floor, x + inc)
                top = max(top, x)
            return top
        verify = peak(pending + [(t_fail, inc_fail)]) > thr - a.threshold_margin
        pending.append((t_verify, inc_verify) if verify else (t_fail, inc_fail))
        self.mirror[block] = (base, pending)
        return verify

    def schedule_delivery(self, r, ctx, minute):
        """Receipt after the sender's queue delay plus the delivery delay, then (maybe) a verification
        clocked from the receipt. The verification uses the code as it appears in the message."""
        a = self.spec.attacker
        now = self.h.clock.now()
        rec = self.h.p.sms_history[r.log_id]
        sent = self.h.svc.sender.sent[-1]
        self.ctx_by_log[r.log_id] = ctx
        t_receipt = now + sent.delay + ctx["delivery"]
        if ctx["attacker"]:
            if a.fake_failed_receipts:
                self.push(t_receipt, "receipt", {"log_id": r.log_id, "ok": False})     # billed, delivered, reported failed
                return
            verify = ctx["verify"] if ctx["verify"] is not None else self._carrier_verifies(ctx, t_receipt)
        else:
            if (self.in_outage(rec["phone_number"], minute) or ctx["lost_on_route"]) and r.channel == "sms":
                silent = self.in_outage(rec["phone_number"], minute) and self.spec.outage.kind == "silent"
                self.push(t_receipt, "receipt", {"log_id": r.log_id, "ok": silent})
                return
            verify = ctx["verify"]
        self.push(t_receipt, "receipt", {"log_id": r.log_id, "ok": True})
        if verify:
            self.push(t_receipt + ctx["verify_delay"], "verify",
                      {"sid": rec["session_id"], "log_id": r.log_id, "attacker": ctx["attacker"], "message": sent.text})

    def baseline_tick(self, observed_per_min):
        """The adaptive job of Step 9 at the worker's cadence. 'oracle': told the modelled legitimate
        rate (what a perfectly learned profile would say). 'learned': the deployed job, reading the
        pipeline's own per-minute volume counters, so cold start, contamination by refused attack
        volume and missing history are all in play."""
        if self.spec.caps_lifted:
            return
        if self.baseline_jobs:
            for job in self.baseline_jobs:
                job.tick()
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
        self.h.svc.channels.whatsapp_numbers.discard(ctx["mobile"])
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

    def legit_request(self, ctx, minute, resend=False):
        """One request of a legitimate user (the first, or a resend); outcomes go to the user record."""
        user = ctx["user"]
        user["requests"] += 1
        if not user["warm"] and self.legit_blocks and not resend:
            self.legit_block_sends[ctx["mobile"][:8]] += 1
        tok = ctx.get("session") if resend else self.open_session(ctx)
        if tok is None:
            if not user["dispatched"]:
                user["loss"] = "gate"
            return 0
        ctx["session"] = tok
        self._register_channels(ctx)
        r = self.send_counting(self.request_from(ctx, tok), False)
        reached_cap = int(r.rejected_at in (None, "step9") and r.tier != "downgrade")
        for sig in r.signals:
            if sig.startswith("block_stage") or sig.startswith("block_count_stage"):
                stage = int(sig[-1])
            elif sig in ("block_denied", "block_count_refused"):
                stage = "refuse"
            else:
                continue
            if user["hit_stage"] is None:
                user["hit_stage"], user["hit_minute"] = stage, minute
        if r.tier == "challenge":
            user["challenged"] = True
            if ctx["solves"]:
                self.reactions["challenge_retry"] += 1
                r = self.send_counting(self.request_from(ctx, tok, challenge=True), False)
        if r.log_id is not None and user["known_good"] is None:
            user["known_good"] = bool(self.h.p.sms_history[r.log_id].get("known_good"))
        if r.channel is not None:
            user["dispatched"] = True
            user["channel"] = r.channel
            if r.tier == "delay":
                user["delayed"] = True
                user["delay_s"] += self.h.svc.sender.sent[-1].delay
            self.schedule_delivery(r, ctx, minute)
        elif not user["dispatched"]:
            user["loss"] = "step" if r.rejected_at not in (None, "no_channel") else "no_channel"
        if not resend and ctx["resends"] and ctx["verify"]:
            self.push(self.h.clock.now() + self.spec.legit.resend_after_s, "resend", {"ctx": ctx, "minute": minute, "log_id": None})
        return reached_cap

    # ---- main loop ----
    def _learn_previous_weeks(self):
        """Learned baseline: run the attack's hour of week, aligned to the hour, with legitimate traffic
        (times profile_rate_multiple, and the warm-up attack rate if any: schedule-aware poisoning) in
        each of the `profile_weeks` previous weeks; the clock jumps a week between them and the run
        starts at the same hour of the week after the last."""
        spec, h = self.spec, self.h
        week = 7 * 86400
        h.clock.t = math.ceil(h.clock.now() / 3600.0) * 3600.0
        self.t_tick0 = h.clock.now()
        hour_start = h.clock.now()
        for w in range(spec.profile_weeks):
            for minute in range(60):
                t0 = h.clock.now()
                nl = self._poisson(spec.legit.rate_per_min * spec.profile_rate_multiple, self.rng_l)
                na = self._poisson(spec.warmup_attack_rate) if spec.warmup_attack_rate else 0
                for offset, is_attacker in sorted([(self.rng_l.random() * 60.0, False) for _ in range(nl)] +
                                                  [(self.rng_w.random() * 60.0, True) for _ in range(na)]):
                    self.process_due_events(until=t0 + offset)
                    if is_attacker:
                        ctx = self.make_attacker_ctx(-1, -1)
                        if ctx is None:
                            continue
                        ctx["fp"] = ctx["fp"] or f"poison-fp-{next(self.tokens)}"
                        self.handle_attacker(ctx, -1)
                    else:
                        self.legit_request(self.make_legit_ctx(-1, True), -1)
                self.process_due_events(until=t0 + 60.0)
                h.p.feedback.run_due_timeouts()
                self.baseline_tick(0)
            self.process_due_events(until=h.clock.now() + 900)
            hour_start += week
            h.clock.t = hour_start                                   # the same hour of the next week
            self.t_tick0 = hour_start
            self.baseline_tick(0)

    def run(self):
        spec, h = self.spec, self.h
        a = spec.attacker
        if spec.profile_weeks:
            self._learn_previous_weeks()
        k_attack = 0
        cap_acc = 0
        t_start = h.clock.now()
        self.t_attack_start = t_start + spec.warmup_minutes * 60.0
        tick = spec.adaptive_tick_s
        bursts = spec.legit.bursts
        for minute in range(-spec.warmup_minutes, spec.minutes):
            warm = minute < 0
            minute_start = t_start + (minute + spec.warmup_minutes) * 60.0
            co = spec.captcha_outage
            self.captcha_down = co is not None and co[0] <= minute < co[0] + co[1]
            attacking = not spec.legit_only and (
                (not warm and (a.active_minutes is None or minute < a.active_minutes)) or (warm and spec.warmup_attack_rate > 0))
            na = self._poisson(spec.warmup_attack_rate if warm else a.rate_per_min) if attacking else 0
            mult = next((b[2] for b in bursts if b[0] <= minute < b[1]), 1.0)
            nl = self._poisson(spec.legit.rate_per_min * mult, self.rng_l)
            # arrival times inside the minute are part of the offered workload (each from its own stream)
            arrivals = sorted([(self.rng_w.random() * 60.0, True) for _ in range(na)] +
                              [(self.rng_l.random() * 60.0, False) for _ in range(nl)])
            leaked = 0
            for offset, is_attacker in arrivals:
                t = minute_start + offset
                self.process_due_events(until=t)             # the clock is now t, whatever the pipeline decided before
                if is_attacker:
                    ctx = self.make_attacker_ctx(k_attack, minute)
                    k_attack += 1
                    if ctx is None:
                        na -= 1                              # not sent: the attack rate is what was actually offered
                        continue
                    if not warm:
                        self.attacker_requests_offered += 1
                    if ctx["fp"] is None:
                        ctx["fp"] = f"attacker-fp-{k_attack}"
                    lk, rc = self.handle_attacker(ctx, minute)
                    leaked += lk; cap_acc += rc
                else:
                    cap_acc += self.legit_request(self.make_legit_ctx(minute, warm), minute)
            minute_end = minute_start + 60.0
            self.process_due_events(until=minute_end)        # the minute boundary is reached regardless of acceptance
            h.p.feedback.run_due_timeouts()
            elapsed = int(minute_end - t_start)
            if spec.baseline_restart_min is not None and minute == spec.baseline_restart_min and self.baseline_jobs:
                self.baseline_jobs = [BaselineJob(h.p) for _ in self.baseline_jobs]      # the worker process restarts
            if (elapsed - spec.adaptive_phase_s) % tick == 0:
                self.baseline_tick(cap_acc / max(1, tick // 60))
                cap_acc = 0
            if not warm:
                self.leaked_per_min.append(leaked)
                self.attack_per_min.append(na)
        self.captcha_down = False
        # drain to the declared horizon: every receipt, entry, resend and resolution timeout of a send inside the window
        self.t_end = h.clock.now()
        horizon = spec.drain_horizon_s if spec.drain_horizon_s is not None else \
            h.cfg.receipt_grace_s + h.cfg.resolution_timeout_s + 600 + int(spec.legit.resend_after_s)
        while h.clock.now() < self.t_end + horizon and (self.events or h.p.store.zrangebyscore(h.p.feedback.TIMEOUTS, float("-inf"), float("inf"))):
            self.process_due_events(until=h.clock.now() + 60.0)
            h.p.feedback.run_due_timeouts()
        self.pending_at_end = {"events": len(self.events),
                               "timeouts": len(h.p.store.zrangebyscore(h.p.feedback.TIMEOUTS, float("-inf"), float("inf"))),
                               "effect_batches": len(h.p.store.zrangebyscore(h.p.feedback.INTENTS, float("-inf"), float("inf")))}
        return self.result()

    # ---- results ----
    def _verdict_estimands(self):
        """Incidence, exposure and eventual verdict events (see the module docstring)."""
        h = self.h
        w0, w1 = self.t_attack_start, self.t_end
        events = h.p.feedback.verdict_events()
        in_window = [e for e in events if w0 <= e["at"] < w1]
        eventual = [e for e in events if e["at"] >= w0]
        exposure = 0.0
        by_block = collections.defaultdict(list)
        for e in events:                                     # includes verdicts issued before the window
            lo, hi = max(e["at"], w0), min(e["until"], w1)
            if hi > lo:
                by_block[e["block"]].append((lo, hi))
        for intervals in by_block.values():
            intervals.sort()
            cs, ce = intervals[0]
            for s_, e_ in intervals[1:]:
                if s_ > ce:
                    exposure += ce - cs
                    cs, ce = s_, e_
                else:
                    ce = max(ce, e_)
            exposure += ce - cs
        first = min((e["at"] for e in eventual), default=None)
        return {"block_verdicts": len(in_window),
                "blocks_with_verdict": len({e["block"] for e in in_window}),
                "verdicts_stage1": sum(1 for e in in_window if e["stage"] == 1),
                "verdicts_stage2": sum(1 for e in in_window if e["stage"] == 2),
                "verdict_exposure_block_min": max(0.0, exposure / 60.0),
                "block_verdicts_incl_drain": len(eventual),
                "first_verdict_min": None if first is None else (first - w0) / 60.0}

    def _friction(self):
        fm = FrictionMetrics()
        for u in self.users:
            if u["warm"]:
                continue
            for g in (fm, fm.returning if u["cohort"] == "returning" else fm.first_time):
                g.users += 1
                g.challenged += u["challenged"]
                g.dispatched += u["dispatched"]
                g.delivered += u["delivered"]
                g.completed += u["completed"]
                g.known_good += bool(u["known_good"])
                if not u["delivered"]:
                    g.refused += 1
                    why = u["loss"] or ("undelivered" if u["dispatched"] else "step")
                    g.refused_by[why] = g.refused_by.get(why, 0) + 1
                if u["delayed"]:
                    g.delayed += 1
                    g.added_delay_s_total += u["delay_s"]
                if u["channel"]:
                    g.by_channel[u["channel"]] = g.by_channel.get(u["channel"], 0) + 1
        return fm.finish()

    def result(self):
        spec, h = self.spec, self.h
        fr = self._friction()
        self._check_cohorts(fr)
        attack = AttackMetrics.build(self.leaked_per_min, self.attack_per_min, self.attacker_hlr, self.attacker_recaptcha,
                                     cost_model(), self.stopped_by, min_sustain=spec.containment_sustain_min)
        measured = [u for u in self.users if not u["warm"]]
        hits = [u for u in measured if u["hit_stage"] is not None]
        hit_per_min = [0] * spec.minutes
        for u in hits:
            if 0 <= u["hit_minute"] < spec.minutes:
                hit_per_min[u["hit_minute"]] += 1
        occ = sorted(self.legit_block_sends.values()) if self.legit_blocks else []
        out = {"attack": asdict(attack), "friction": asdict(fr),
               "funnel": {"offered": fr.users, "past_gate": fr.users - fr.refused_by.get("gate", 0), "dispatched": fr.dispatched,
                          "delivered": fr.delivered, "completed": fr.completed, "lost": dict(fr.refused_by)},
               "attacker_challenges_solved": self.attacker_challenges_solved,
               "attacker_verifications": self.attacker_verifications,
               "attacker_session_attempts": self.attacker_session_attempts,
               "attacker_sessions_refused": self.attacker_sessions_refused,
               "attacker_blocks_requested": len(self.attacker_blocks_requested),
               "attacker_blocks_leaked": len(self.attacker_blocks_leaked),
               "attack_phase": {ph: dict(c) for ph, c in self.phase.items()},
               "legit_hit_by_verdict": len(hits),           # requests that met any destination-policy intervention
               "legit_hit_stage1": sum(1 for u in hits if u["hit_stage"] == 1),
               "legit_hit_stage2": sum(1 for u in hits if u["hit_stage"] == 2),
               "legit_hit_refused": sum(1 for u in hits if u["hit_stage"] == "refuse"),
               "legit_hit_lost": sum(1 for u in hits if not u["completed"]),     # descriptive: hit and never completed
               "legit_hit_per_min": hit_per_min,
               "reactions": dict(self.reactions),
               "legit_block_occupancy": {"distinct_blocks": len(self.legit_blocks or []), "touched": len(occ),
                                         "min": occ[0] if occ else 0, "median": occ[len(occ) // 2] if occ else 0, "max": occ[-1] if occ else 0},
               "outage_alerts": sum(1 for al in h.svc.alerts.alerts if "outage" in al[0]),
               "pending_at_end": self.pending_at_end,
               "workload_digest": self.digest.hexdigest(),
               "legit_workload_digest": self.legit_digest.hexdigest(),
               "spec": {"attacker": asdict(spec.attacker), "legit": asdict(spec.legit), "minutes": spec.minutes,
                        "features": sorted(spec.features), "cfg_overrides": {k: list(v) if isinstance(v, tuple) else v for k, v in spec.cfg_overrides.items()},
                        "weight_overrides": spec.weight_overrides, "seed": spec.seed,
                        "caps_lifted": spec.caps_lifted, "base_cap_multiple": spec.base_cap_multiple,
                        "adaptive_floor": spec.adaptive_floor, "adaptive_tick_s": spec.adaptive_tick_s,
                        "adaptive_phase_s": spec.adaptive_phase_s, "baseline": spec.baseline, "profile_weeks": spec.profile_weeks,
                        "profile_rate_multiple": spec.profile_rate_multiple, "baseline_workers": spec.baseline_workers,
                        "baseline_restart_min": spec.baseline_restart_min,
                        "warmup_minutes": spec.warmup_minutes, "warmup_attack_rate": spec.warmup_attack_rate,
                        "recalibrate_speed": spec.recalibrate_speed, "captcha_outage": spec.captcha_outage,
                        "outage": asdict(spec.outage) if spec.outage else None,
                        "containment_sustain_min": spec.containment_sustain_min}}
        out.update(self._verdict_estimands())
        if spec.record_requests:
            n = self.n_measured
            attacked = self.attacker_blocks_requested
            stop = spec.attacker.active_minutes
            out["requests"] = {"n": n, "completed": _bits([u["rid"] for u in measured if u["completed"]], n),
                               "hit": _bits([u["rid"] for u in hits], n),
                               "returning": _bits([u["rid"] for u in measured if u["cohort"] == "returning"], n),
                               "attacked_block": _bits([u["rid"] for u in measured if u.get("block") in attacked], n),
                               "after_stop": _bits([u["rid"] for u in measured if stop is not None and u["minute"] >= stop], n),
                               "hot_block": _bits([u["rid"] for u in measured if u.get("block") in set(self.hot_blocks)], n)}
        return out

    @staticmethod
    def _check_cohorts(fr: FrictionMetrics):
        """Conservation laws of the measurement: subgroups add up to the whole, and the funnel is monotone."""
        for f in ("users", "dispatched", "delivered", "completed", "challenged", "refused"):
            assert getattr(fr.first_time, f) + getattr(fr.returning, f) == getattr(fr, f), f
        for g in (fr, fr.first_time, fr.returning):
            assert g.completed <= g.delivered <= g.dispatched <= g.users, (g.users, g.dispatched, g.delivered, g.completed)
            assert g.refused == g.users - g.delivered == sum(g.refused_by.values())

    def _poisson(self, lam, rng=None):
        rng = rng or self.rng_w
        if lam <= 0:
            return 0
        L, k, p = math.exp(-lam), 0, 1.0
        while True:
            k += 1
            p *= rng.random()
            if p <= L:
                return k - 1


def run_sim(spec: SimSpec):
    t0 = time.perf_counter()
    out = Simulation(spec).run()
    out["wall_s"] = time.perf_counter() - t0
    return out
