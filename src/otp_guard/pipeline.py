"""The 12-step v2 pipeline. Step numbering and names follow SMS_Validation_Process.md."""
import base64
import hashlib
import hmac
import ipaddress
import json
import time
from dataclasses import dataclass, field

from .config import Config
from .reputation import ReputationStore, AdaptiveLimits
from .services import Services
from .store import Clock, MemoryStore, RateLimit

UNIFORM_BODY = {"status": "ok", "message": "If this number is eligible, a code has been sent."}
COUNTRY_OF_CODE = {"966": "SA", "971": "AE", "965": "KW", "968": "OM", "973": "BH", "974": "QA"}


@dataclass
class Request:
    mobile: str
    text: str = "Your verification code is 1234"
    source: str = "App/RegisterOTP"
    host: str = "example.com"
    ip: str = "198.51.100.10"
    origin: str = "https://example.com/register"
    header_platform: str = "web"
    app_version: str = None          # X-App-Version; presence marks an app client
    attestation: dict = None
    session_token: str = None
    nonce: str = None
    post: dict = field(default_factory=dict)
    challenge_proof: str = None
    is_bulk: bool = False
    service_credential: str = None
    headers: dict = field(default_factory=dict)

    # populated by the pipeline
    trusted_platform: str = None
    session_id: str = None
    fingerprint: str = None
    fingerprint_age_hours: float = None
    ip_info: object = None
    recaptcha_score: float = None
    country_code: str = None
    prefix: object = None
    signals: list = field(default_factory=list)
    timings_ms: dict = field(default_factory=dict)
    rep_cache: dict = field(default_factory=dict)
    rep_split: dict = field(default_factory=dict)
    number_claims: list = field(default_factory=list)
    count_stage: int = None            # set by the graded per-block counter (block_count_action = 'graded')
    known_good: bool = None            # decided once per request (is_known_good)
    risk_score: float = None
    tier: str = None
    requires_challenge: bool = False
    update_required: bool = False


@dataclass
class Response:
    http_status: int
    body: dict
    # server-side only (never sent to the client); exposed for tests and logs
    rejected_at: str = None
    tier: str = None
    channel: str = None
    log_id: int = None
    risk_score: float = None
    elapsed_ms: float = 0.0
    timings_ms: dict = None
    signals: list = None


class SessionService:
    FP_TTL = 90 * 86400

    def __init__(self, store, clock, key=b"session-hmac-key"):
        self.store, self.clock, self.key = store, clock, key

    def set_first_seen(self, fingerprint, when):
        self.store.set("fp_first_seen:" + fingerprint, when, self.FP_TTL)

    def issue(self, platform, fingerprint, ttl):
        n = self.store.incr("session:seq")
        self.store.setnx("fp_first_seen:" + fingerprint, self.clock.now(), self.FP_TTL)
        payload = {"session_id": f"s{n}", "fingerprint_hash": fingerprint,
                   "platform": platform, "issued_at": self.clock.now(),
                   "expires_at": self.clock.now() + ttl}
        raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        sig = hmac.new(self.key, raw.encode(), hashlib.sha256).hexdigest()
        return f"{raw}.{sig}"

    def verify(self, token):
        try:
            raw, sig = token.split(".")
        except (ValueError, AttributeError):
            return None
        if not hmac.compare_digest(sig, hmac.new(self.key, raw.encode(), hashlib.sha256).hexdigest()):
            return None
        return json.loads(base64.urlsafe_b64decode(raw))

    def fingerprint_age_hours(self, fp):
        first = self.store.get("fp_first_seen:" + fp)
        return 0.0 if first is None else (self.clock.now() - float(first)) / 3600


class NumberTracker:
    """Feeds the sequential and narrow-range detectors of Step 5c. Sorted sets keyed by
    client key and by 9-digit prefix, scored by request time."""

    def __init__(self, store, clock, window):
        self.store, self.clock, self.window = store, clock, window

    def record(self, mobile, keys):
        t = self.clock.now()
        for k in keys:
            self.store.zremrangebyscore(f"numseq:{k}", float("-inf"), t - self.window)
            self.store.zadd(f"numseq:{k}", t, mobile, ttl=self.window * 2)
        pk = f"numpfx:{mobile[:9]}"
        self.store.zremrangebyscore(pk, float("-inf"), t - self.window)
        self.store.zadd(pk, t, mobile, ttl=self.window * 2)

    def neighbour_requested(self, mobile, radius, keys, window):
        n, t0 = int(mobile), self.clock.now() - window
        for k in keys:
            for m in self.store.zrangebyscore(f"numseq:{k}", t0, float("inf")):
                if int(m) != n and abs(int(m) - n) <= radius:
                    return True
        return False

    def distinct_with_prefix(self, prefix9, window):
        return len(self.store.zrangebyscore(f"numpfx:{prefix9}", self.clock.now() - window, float("inf")))


def subnet_of(ip):
    addr = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f"{ip}/{24 if addr.version == 4 else 48}", strict=False))


class SmsHistory:
    """Audit records in the store (a relational table in production; same interface)."""

    TTL = 30 * 86400

    def __init__(self, store):
        self.store = store

    def next_id(self):
        return self.store.incr("smslog:seq")

    def put(self, record):
        self.store.set(f"smslog:{record['log_id']}", record, self.TTL)

    def get(self, log_id):
        return self.store.get(f"smslog:{log_id}")

    def __getitem__(self, log_id):
        rec = self.get(log_id)
        if rec is None:
            raise KeyError(log_id)
        return rec


class Pipeline:
    def __init__(self, config=None, services=None, clock=None, store=None, session_key=b"session-hmac-key"):
        self.cfg = config or Config()
        self.svc = services or Services()
        self.clock = clock or Clock()
        self.store = store or MemoryStore(self.clock)
        self.rep = ReputationStore(self.store, self.clock)
        self.adaptive = AdaptiveLimits(self.store)
        self.sessions = SessionService(self.store, self.clock, session_key)
        self.numbers = NumberTracker(self.store, self.clock, self.cfg.pattern_window)
        self.sms_history = SmsHistory(self.store)
        from .feedback import FeedbackLoop
        self.feedback = FeedbackLoop(self)

    @property
    def mode(self):
        return self.store.get("otp:mode") or "normal"

    @mode.setter
    def mode(self, value):
        self.store.set("otp:mode", value)

    # ---------- helpers ----------
    def rl(self, key, ident, limit):
        return RateLimit(self.store).set_limit(*limit).set_key(key).set_identifier(ident)

    def operating_mode(self):
        return self.mode

    def has_internal_credential(self, req):
        return req.service_credential in self.svc.internal_credentials

    def block_key(self, mobile):
        return "block:" + mobile[:self.cfg.destination_block_digits]

    def reputation_keys(self, req):
        keys = ["ip:" + req.ip, "subnet:" + subnet_of(req.ip), "asn:" + req.ip_info.asn,
                "fp:" + req.fingerprint, "sess:" + req.session_id, "country:" + req.country_code,
                "prefix:" + req.prefix.id, "num:" + req.mobile]
        if self.on("fine_destination_key"):
            keys.append(self.block_key(req.mobile))
        return keys

    def rep_get(self, req, key):
        """Reputation read memoised for the life of one request (the same keys are read in several steps)."""
        if key not in req.rep_cache:
            req.rep_cache[key] = self.rep.get(key)
        return req.rep_cache[key]

    def rep_prefetch(self, req, keys):
        missing = [k for k in keys if k not in req.rep_cache]
        if missing:
            split = self.rep.get_split(missing, self.cfg.conversion_recent_hours)
            req.rep_split.update(split)
            req.rep_cache.update({k: v[0] for k, v in split.items()})

    def previous_session_requests(self, sid):
        return max(0, self.rl("otp:session", sid, self.cfg.session_otp_limit).current_count() - 1)

    # ---------- Step 0 ----------
    def on(self, feature):
        return feature in self.cfg.features

    def establish_trusted_platform(self, req):
        if not self.on("attestation"):
            return req.header_platform if req.header_platform in ("ios", "android") else "web"
        if req.attestation is not None:
            r = self.svc.attestation.verify(req.attestation, req.nonce)
            if not r.valid:
                return "invalid"
            return r.platform
        if req.app_version is not None:
            if self.clock.now() < self.cfg.attestation_grace_until:
                req.signals.append("legacy_app")
                return "legacy_app"
            return "update_required"
        return "web"

    def step0_connection_and_client_integrity(self, req):
        if self.svc.proxy.is_proxy(req.ip):
            return False
        req.trusted_platform = self.establish_trusted_platform(req)
        if req.trusted_platform == "invalid":
            return False
        if req.trusted_platform == "update_required":
            req.update_required = True
            return False
        if req.host != self.cfg.host and req.trusted_platform == "web":
            return False
        return True

    # ---------- Step 1 ----------
    def step1_session(self, req):
        if not self.on("session"):
            # layer off: no enforcement, but keep the client's identity so other layers see the same
            # traffic they would with it on (otherwise every request collapses into one client)
            tok = self.sessions.verify(req.session_token) if req.session_token else None
            req.session_id = tok["session_id"] if tok else (req.session_token or "anon")
            req.fingerprint = tok["fingerprint_hash"] if tok else "none"
            req.fingerprint_age_hours = self.sessions.fingerprint_age_hours(req.fingerprint) if tok else 24.0
            return True
        tok = self.sessions.verify(req.session_token) if req.session_token else None
        if tok is None or tok["expires_at"] < self.clock.now():
            return False
        if tok["platform"] != req.trusted_platform:
            return False
        if not req.nonce or not self.store.setnx("nonce:" + req.nonce, 1, self.cfg.nonce_ttl):
            return False
        req.session_id = tok["session_id"]
        req.fingerprint = tok["fingerprint_hash"]
        req.fingerprint_age_hours = self.sessions.fingerprint_age_hours(req.fingerprint)
        if self.on("feedback") and self.store.exists("deny:fp:" + req.fingerprint):
            return False
        return self.rl("otp:session", req.session_id, self.cfg.session_otp_limit).try_acquire()

    # ---------- Step 2 ----------
    def step2_network_throttles(self, req):
        info = self.svc.ip_intel.lookup(req.ip)
        req.ip_info = info
        if info.is_tor:
            return False
        sub = subnet_of(req.ip)
        for k in (("ip:" + req.ip, "subnet:" + sub, "asn:" + info.asn) if self.on("feedback") else ()):
            if self.store.exists("deny:" + k):
                return False
        asn_cap = self.cfg.asn_datacenter_limit if info.is_datacenter \
            else self.adaptive.asn_limit(info.asn, self.cfg.asn_limit_default)
        ip_cap = self.cfg.ip_limit_cgnat if info.asn in self.cfg.cgnat_asns else self.cfg.ip_limit
        limits = [self.rl("otp:ip", req.ip, ip_cap)]
        if self.on("network_subnet_asn"):
            limits += [self.rl("otp:subnet", sub, self.cfg.subnet_limit),
                       self.rl("otp:asn", info.asn, (asn_cap, 60))]
        return RateLimit.try_acquire_all(limits)

    # ---------- Step 3 ----------
    def recaptcha_min_score(self):
        return self.cfg.recaptcha_min_score_elevated if self.mode == "elevated" else self.cfg.recaptcha_min_score

    def step3_recaptcha(self, req):
        if req.trusted_platform != "web":
            return True
        result = self.svc.recaptcha.verify(req.post)
        req.recaptcha_score = result["score"] if result["valid"] else 0.0
        if not result["valid"]:
            return False
        return result["score"] >= self.recaptcha_min_score()

    # ---------- Step 4 ----------
    @staticmethod
    def root_domain(origin):
        host = origin.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    def step4_origin(self, req):
        if req.trusted_platform != "web":
            return True
        return self.root_domain(req.origin or "") in self.cfg.allowed_domains

    # ---------- Step 5 ----------
    @staticmethod
    def parse_e164(raw):
        digits = "".join(ch for ch in raw if ch.isdigit()).lstrip("0")
        return digits if 8 <= len(digits) <= 15 else None

    def step5_number(self, req):
        mobile = self.parse_e164(req.mobile)
        if mobile is None:
            return False
        req.mobile = mobile
        cc = mobile[:3]
        req.country_code = cc

        # 5a country
        if not (req.is_bulk and self.has_internal_credential(req)):
            if cc == "968" and req.trusted_platform not in ("ios", "android"):
                return False
            if cc not in self.cfg.allowed_country_codes:
                return False

        # 5b prefix cost class
        prefix = self.svc.prefixes.lookup(mobile)
        req.prefix = prefix
        if self.on("block_count_limit"):
            # the destination counter: SMS sends already dispatched to this block in its window. Read
            # only here; the send itself is reserved atomically at Step 11, so a refused request, a
            # challenge and its retry cost nothing unless an SMS goes out.
            limit, _ = self.cfg.block_count_limit
            n = self.block_count(mobile)
            if self.cfg.block_count_action == "refuse":
                if n >= limit:
                    req.signals.append("block_count_refused")
                    return False
            elif n >= limit:
                req.count_stage = 1 if n < 2 * limit else 2
        if self.on("fine_destination_key") and self.on("feedback") and self.cfg.block_action == "deny" \
                and self.feedback.block_denied(self.block_key(mobile)):
            req.signals.append("block_denied")        # a destination block under a hard-deny verdict
            return False
        if not self.on("number_intelligence"):
            return True
        if prefix.cls == "premium":
            return False
        if prefix.cls == "elevated":
            if not self.rl("otp:prefix", prefix.id, self.cfg.elevated_prefix_limit).try_acquire():
                return False
            req.signals.append("elevated_prefix")
        if prefix.cls == "unknown":
            req.signals.append("unknown_prefix")

        # 5c pattern detection
        keys = [req.fingerprint, req.ip, subnet_of(req.ip)]
        sequential = self.numbers.neighbour_requested(mobile, self.cfg.pattern_radius, keys, self.cfg.pattern_window)
        narrow = self.numbers.distinct_with_prefix(mobile[:9], self.cfg.pattern_window) > self.cfg.narrow_range_threshold
        self.numbers.record(mobile, keys)
        if sequential and narrow:
            return False
        if sequential:
            req.signals.append("sequential_number")
        if narrow:
            req.signals.append("narrow_range_burst")

        # 5d HLR
        if self.rep_get(req, "num:" + mobile).verified == 0 and not self.rep.is_trusted("num:" + mobile):
            cache_key = "hlr:" + mobile
            hlr = self.store.get(cache_key)
            if hlr is None:
                res = self.svc.hlr.lookup(mobile)
                hlr = {"assigned": res.assigned, "reachable": res.reachable, "is_voip": res.is_voip}
                self.store.set(cache_key, hlr, self.cfg.hlr_cache_ttl)
            if not hlr["assigned"] or not hlr["reachable"]:
                return False
            if hlr["is_voip"]:
                req.signals.append("voip_number")
        return True

    # ---------- Step 6 ----------
    def step6_text(self, req):
        if self.cfg.is_test_server and self.has_internal_credential(req):
            return True
        if req.mobile in self.cfg.excluded_numbers:
            return False
        return 1 <= len(req.text or "") <= self.cfg.sms_max_len

    # ---------- Step 7 ----------
    def compute_risk_score(self, req):
        w = self.cfg.weights
        s = 0.0
        if req.trusted_platform == "web":
            s += (1 - (req.recaptcha_score or 0.0)) * w["recaptcha"]
        if req.ip_info.is_datacenter:
            s += w["datacenter"]
        s += req.ip_info.abuse_score * w["abuse"]
        if req.fingerprint_age_hours < 1 / 12:
            s += w["fresh_fp_5min"]
        elif req.fingerprint_age_hours < 1:
            s += w["fresh_fp_1h"]
        s += w["session_repeat"] * self.previous_session_requests(req.session_id)

        worst, flood, instant, rel_drop = 1.0, False, False, 0.0
        keys = ["ip:" + req.ip, "subnet:" + subnet_of(req.ip), "asn:" + req.ip_info.asn,
                "fp:" + req.fingerprint, "country:" + req.country_code, "prefix:" + req.prefix.id]
        if self.on("fine_destination_key"):
            keys.append(self.block_key(req.mobile))
        self.rep_prefetch(req, keys + ["num:" + req.mobile])
        for key in (keys if self.on("feedback") else []):
            r = self.rep_get(req, key)
            resolved = r.verified + r.failed
            ratio = r.verified / resolved if resolved >= self.cfg.conversion_min_sample else None
            if ratio is not None:
                worst = min(worst, ratio)
                if resolved >= self.cfg.conversion_flood_min_sample and ratio < self.cfg.conversion_flood_ratio:
                    flood = True
            if self.on("relative_baseline"):
                _, recent, base = req.rep_split[key]
                rr, br = recent.verified + recent.failed, base.verified + base.failed
                if rr >= self.cfg.conversion_min_sample and br >= self.cfg.conversion_baseline_min_resolved and base.verified > 0:
                    recent_ratio, base_ratio = recent.verified / rr, base.verified / br
                    if recent_ratio < self.cfg.conversion_relative_drop * base_ratio:
                        rel_drop = max(rel_drop, 1 - recent_ratio / base_ratio)
            # codes entered within seconds of the send, nearly every time, are not being typed by people:
            # the tell of a colluding carrier verifying its own pumped traffic
            if r.verified >= self.cfg.fast_verify_min_verified and r.fast_verified / r.verified > self.cfg.fast_verify_ratio:
                instant = True
        th = self.cfg.conversion_penalty_threshold
        conv_pen = (th - worst) / th * w["conversion"] if worst < th else 0.0
        if rel_drop > 0:
            req.signals.append("conversion_drop")
            conv_pen = max(conv_pen, rel_drop * w["conversion"])
        s += conv_pen
        if flood:
            req.signals.append("sustained_flood")
            s += self.cfg.conversion_flood_points
        if instant:
            req.signals.append("instant_verification")
            s += self.cfg.fast_verify_points

        if req.ip_info.country != COUNTRY_OF_CODE.get(req.country_code, req.ip_info.country):
            s += w["geo_mismatch"]
        for sig in req.signals:
            s += w.get(sig, 0)
        if self.rep_get(req, "num:" + req.mobile).verified > 0 or self.rep.is_trusted("num:" + req.mobile):
            s += w["verified_number"]
        if self.rep_get(req, "fp:" + req.fingerprint).verified > 0:
            s += w["verified_fingerprint"]
        return max(0.0, min(100.0, s))

    def decide_tier(self, score, mode):
        d, c, dg, b = self.cfg.tier_bounds
        shift = self.cfg.elevated_shift if mode == "elevated" else 0
        if mode == "emergency":
            return "allow" if score < 10 else "downgrade"
        if score >= b - shift:
            return "block"
        if score >= dg - shift:
            return "downgrade"
        if score >= c - shift:
            return "challenge"
        if score >= d - shift:
            return "delay"
        return "allow"

    def step7_risk(self, req):
        if req.challenge_proof and self.svc.recaptcha.verify_challenge(req.challenge_proof):
            req.signals.append("challenge_passed")
        if not self.on("risk_engine"):
            req.risk_score, req.tier = 0.0, "allow"
            self.apply_block_count(req)
            return req.tier != "challenge" or self._challenge_outcome(req)
        req.risk_score = self.compute_risk_score(req)
        req.tier = self.decide_tier(req.risk_score, self.mode)
        if req.trusted_platform == "legacy_app" and req.tier == "allow":
            req.tier = "delay"
        self.apply_block_verdict(req)
        self.apply_block_count(req)
        if req.tier == "block":
            return False
        if req.tier == "challenge":
            return self._challenge_outcome(req)
        return True

    def _challenge_outcome(self, req):
        """A web client is asked to solve the interactive challenge (and retries with the proof); an
        app client has no challenge surface and is moved to non-SMS channels."""
        if req.trusted_platform == "web":
            req.requires_challenge = True
            return False
        req.tier = "downgrade"
        return True

    TIER_RANK = {"allow": 0, "delay": 1, "challenge": 2, "downgrade": 3, "block": 4}

    def apply_block_count(self, req):
        """The graded form of the flat per-block counter (cfg.block_count_action = 'graded'): the same
        actions as a block verdict, so the counter and the sequential tests can be compared on equal
        terms. Clients with verified history are exempt, as for a verdict."""
        stage = getattr(req, "count_stage", None)
        if not stage or self.is_known_good(req):
            return
        req.signals.append(f"block_count_stage{stage}")
        floor = ("delay" if "challenge_passed" in req.signals else "challenge") if stage == 1 else "downgrade"
        if self.TIER_RANK[req.tier] < self.TIER_RANK[floor]:
            req.tier = floor

    def apply_block_verdict(self, req):
        """Graded action on a destination block under a sequential-test verdict: stage 1 makes the
        block's new clients solve an interactive challenge (apps: non-SMS channels), stage 2 moves
        them to non-SMS channels only. A client with verified history is never affected, so the
        cost of a wrong verdict falls on first-time sign-ups to that block for block_verdict_ttl,
        not on 10 000 numbers for a day."""
        if not (self.on("fine_destination_key") and self.on("feedback")) or self.cfg.block_action != "graded":
            return
        verdict = self.feedback.block_verdict(self.block_key(req.mobile))
        if not verdict or self.is_known_good(req):
            return
        req.signals.append(f"block_{verdict['reason']}")
        req.signals.append(f"block_stage{verdict['stage']}")
        if verdict["stage"] == 1:
            floor = "delay" if "challenge_passed" in req.signals else "challenge"   # solved it: send, with delay
        else:
            floor = "downgrade"
        if self.TIER_RANK[req.tier] < self.TIER_RANK[floor]:
            req.tier = floor

    # ---------- Step 8 ----------
    def step8_per_number(self, req):
        """Claims the number's window and daily slot atomically (SETNX with the window as TTL, and a
        capped counter), so two concurrent requests for one number cannot both pass. A later step
        that refuses the request releases the claim (release_number_claims)."""
        sends = self.rep_get(req, "num:" + req.mobile).sent          # sends so far; this one would be sends + 1
        base, cap = self.cfg.per_number_base_window, self.cfg.per_number_max_window
        # the claim carries the window that applies after this send: 60 s after the first, 120 after the second...
        window = min(base * 2 ** sends, cap) if self.on("backoff") else base
        if not self.store.setnx("num_window:" + req.mobile, self.clock.now(), int(window)):
            return False
        req.number_claims.append(("num_window:" + req.mobile, None))
        if self.on("backoff"):
            daily = "num_daily:" + req.mobile
            if not self.store.try_reserve(daily, 1, self.cfg.per_number_daily_cap, 86400):
                self.release_number_claims(req)
                return False
            req.number_claims.append((daily, 1))
        return True

    def release_number_claims(self, req):
        for key, units in req.number_claims:
            if units is None:
                self.store.delete(key)
            else:
                self.store.release(key, units)
        req.number_claims = []

    def release_block_count(self, req):
        key = self.block_count_key(req.mobile)
        for k, units in [c for c in req.number_claims if c[0] == key]:
            self.store.release(k, units)
        req.number_claims = [c for c in req.number_claims if c[0] != key]

    def block_count_key(self, mobile):
        return "otp:blockcount:" + mobile[:self.cfg.destination_block_digits]

    def block_count(self, mobile):
        return int(self.store.get(self.block_count_key(mobile)) or 0)

    def reserve_block_count(self, req):
        """Atomic reservation of one send against the destination counter (Step 11). Returns 'ok', or
        the stage the request belongs to if it may not send: 'refused' (refusing action, at the
        limit), 'stage1' (graded: the block is past the limit and this request has not solved the
        challenge) or 'stage2' (graded: at twice the limit). The graded stage is decided again here,
        on the count the reservation changes, so requests that all read a count below the limit at
        Step 5 cannot together pass the first boundary without a challenge. A client with verified
        history is exempt from the graded caps but still counted."""
        limit, window = self.cfg.block_count_limit
        key = self.block_count_key(req.mobile)
        if self.cfg.block_count_action == "refuse":
            if not self.store.try_reserve(key, 1, limit, window):
                return "refused"
        elif self.is_known_good(req):
            self.store.try_reserve(key, 1, 10 ** 9, window)
        else:
            tier = self.store.try_reserve_tiered(key, 1, limit, 2 * limit, window, "challenge_passed" in req.signals)
            if tier == -1:
                return "stage1"
            if tier == -2:
                return "stage2"
        req.number_claims.append((key, 1))     # released if the send is not made
        return "ok"

    # ---------- Step 9 ----------
    def is_known_good(self, req):
        """A client that has verified a code before: its fingerprint has verified history or the
        number is trusted. A low risk score alone is not enough; an attacker can buy that. With
        known_good_budget_per_min set, at most that many requests per minute per (source, country)
        are granted the exemption; the rest are treated as first-time clients. Decided once per request."""
        if req.known_good is not None:
            return req.known_good
        kg = self.rep_get(req, "fp:" + req.fingerprint).verified > 0 or self.rep.is_trusted("num:" + req.mobile)
        budget = self.cfg.known_good_budget_per_min
        if kg and budget is not None:
            kg = self.rl("kg_exempt", f"{req.source}:{req.country_code}", (budget, 60)).try_acquire()
            if not kg:
                req.signals.append("known_good_budget_exhausted")
        req.known_good = kg
        return kg

    def record_volume(self, source, platform, cc):
        """Per-minute count of requests that reached the source cap; the worker's baseline job reads it."""
        minute = int(self.clock.now() // 60)
        k = f"{source}|{platform}|{cc}"
        self.store.incr(f"vol:{k}:{minute}")
        self.store.expire(f"vol:{k}:{minute}", 2 * 86400)
        self.store.setnx(f"vol:first:{k}", minute, 35 * 86400)     # the baseline job skips partially observed hours
        self.store.sadd("vol:keys", k)

    def effective_limit(self, source, sl, period, platform, cc, known_good=False):
        base = sl.get("per_country", {}).get(cc, {}).get(f"{period}_{platform}")
        if base is None:
            base = sl.get(f"{period}_{platform}")
        if base is None:
            return None
        m = self.adaptive.multiplier(source, platform, cc) if self.on("adaptive_caps") else 1.0
        if known_good and self.cfg.adaptive_reduction_spares_known_good:
            m = max(m, 1.0)                      # a tightened cap rations unknown clients, not returning ones
        return max(1, int(-(-base * m // 1)))   # ceil

    def step9_source_limits(self, req):
        sl = self.cfg.source_limits.get(req.source)
        if sl is None or req.tier == "downgrade":
            return True                      # the source caps are SMS caps; a non-SMS channel spends none of it
        p, cc = req.trusted_platform, req.country_code
        self.record_volume(req.source, p, cc)
        kg = self.is_known_good(req)
        minute_cap = self.effective_limit(req.source, sl, "per_minute", p, cc, kg)
        hour_cap = self.effective_limit(req.source, sl, "per_hour", p, cc, kg)
        if minute_cap is None or hour_cap is None:
            return True
        limits = [self.rl(f"sms_cap_per_minute_{p}:limit", f"{req.source}:{cc}", (minute_cap, 60)),
                  self.rl(f"sms_cap_per_hour_{p}:limit", f"{req.source}:{cc}", (hour_cap, 3600))]
        return RateLimit.try_acquire_all(limits)

    # ---------- Step 10 ----------
    def current_hour(self):
        return int(self.clock.now() // 3600)

    def utilisation(self):
        h = self.current_hour()
        count = self.store.get(f"global:sms:count:{h}") or 0
        spend = self.store.get(f"global:sms:spend:{h}") or 0
        return max(count / self.cfg.global_sms_per_hour, spend / self.cfg.global_spend_units_per_hour)

    def step10_circuit_breaker(self, req):
        if not self.on("circuit_breaker"):
            return True
        util = self.utilisation()
        mode = "emergency" if (util >= 1.0 or self.cfg.kill_switch) else \
               "elevated" if util >= self.cfg.breaker_soft else "normal"
        if mode != self.mode:
            self.svc.alerts.alert(f"SMS circuit breaker: {mode}", util)
        self.mode = mode
        if req.tier in ("allow", "delay"):
            if self.cfg.kill_switch or (mode == "emergency" and req.risk_score >= 10):
                req.tier = "downgrade"
        return True

    # ---------- Step 11 ----------
    def select_channel(self, req):
        ch = self.svc.channels
        if req.tier in ("allow", "delay"):
            return "push" if req.fingerprint in ch.push_devices else "sms"
        # downgrade: never SMS
        if req.fingerprint in ch.push_devices:
            return "push"
        if req.mobile in ch.whatsapp_numbers:
            return "whatsapp"
        if req.trusted_platform in ch.silent_auth_platforms:
            return "silent_auth"
        return None

    def reserve_budget(self, req):
        """Atomic reservation against the hourly count and spend budgets. With the hard ceiling on,
        a send that would exceed either budget is not made."""
        h = self.current_hour()
        cfg = self.cfg
        if not cfg.budget_hard_ceiling or not self.on("circuit_breaker"):     # the ceiling is part of the breaker layer
            self.store.incr(f"global:sms:count:{h}"); self.store.expire(f"global:sms:count:{h}", 7200)
            self.store.incr(f"global:sms:spend:{h}", req.prefix.cost_units); self.store.expire(f"global:sms:spend:{h}", 7200)
            return True
        if not self.store.try_reserve(f"global:sms:count:{h}", 1, cfg.global_sms_per_hour, 7200):
            return False
        if not self.store.try_reserve(f"global:sms:spend:{h}", req.prefix.cost_units, cfg.global_spend_units_per_hour, 7200):
            self.store.release(f"global:sms:count:{h}", 1)
            return False
        return True

    def step11_log_and_send(self, req):
        channel = self.select_channel(req)
        held = self.reserve_block_count(req) if channel == "sms" and self.on("block_count_limit") else "ok"
        if held == "refused":
            # a concurrent send took the block's last slot between Step 5 and here
            req.signals.append("block_count_refused")
            self.release_number_claims(req)
            return Response(200, dict(UNIFORM_BODY), rejected_at="step5", tier=req.tier, risk_score=req.risk_score)
        if held == "stage1":
            # concurrent sends moved the block past its limit after Step 5: the stage-1 action applies
            req.signals.append("block_count_stage1")
            if req.trusted_platform == "web":
                self.release_number_claims(req)        # the retry with the proof claims the number again
                req.tier = "challenge"
                return Response(200, {"status": "challenge", "challenge": "interactive_recaptcha"},
                                rejected_at="step11", tier="challenge", risk_score=req.risk_score)
            req.tier = "downgrade"                     # apps have no challenge surface: non-SMS channels
            channel = self.select_channel(req)
        elif held == "stage2":
            req.tier = "downgrade"
            req.signals.append("block_count_stage2")
            channel = self.select_channel(req)
        if channel == "sms" and not self.reserve_budget(req):
            req.tier = "downgrade"                     # over the hard ceiling: never SMS
            req.signals.append("budget_exhausted")
            if self.on("block_count_limit"):
                self.release_block_count(req)          # the block slot is not used either
            channel = self.select_channel(req)
        if channel is None:
            self.release_number_claims(req)
            return Response(200, dict(UNIFORM_BODY), rejected_at="no_channel", tier=req.tier, risk_score=req.risk_score)
        log_id = self.sms_history.next_id()
        code = self.feedback.new_code()
        template = req.text if "{code}" in (req.text or "") else (req.text or self.cfg.sms_text_template)
        if "{code}" not in template:
            template = template.rstrip() + " {code}"
        message = template.replace("{code}", code)
        record = {
            "log_id": log_id, "source": req.source, "phone_number": req.mobile,
            "headers": json.dumps(req.headers), "content": template,      # the template; the code is never logged in clear
            "sms_provider": self.cfg.provider if channel == "sms" else None,
            "channel": channel, "trusted_platform": req.trusted_platform,
            "risk_score": req.risk_score, "signals": list(req.signals), "tier": req.tier,
            "operating_mode": self.mode, "session_id": req.session_id,
            "fingerprint": req.fingerprint, "ip": req.ip, "asn": req.ip_info.asn,
            "asn_is_datacenter": bool(req.ip_info.is_datacenter), "prefix": req.prefix.id,
            "known_good": self.is_known_good(req),
            "reputation_keys": self.reputation_keys(req), "sent_at": self.clock.now(),
        }
        self.sms_history.put(record)
        # Every piece of durable state is written before the message is handed to the sender: a
        # synchronous sender (the default scheduler sends a zero-delay message inline) can report its
        # result, and a provider can post a receipt, before enqueue() returns.
        for key in record["reputation_keys"]:
            self.rep.incr(key, "sent")
        self.store.set("num_last_send:" + req.mobile, self.clock.now(), 86400)
        self.store.set(f"otp:latest:{req.session_id}:{req.mobile}", log_id, self.cfg.otp_ttl)
        self.feedback.on_sent(log_id, code)

        delay = 0
        if channel == "sms":
            if req.tier == "delay":
                delay = min(5 * 2 ** self.previous_session_requests(req.session_id), 60)
            self.svc.sender.enqueue("sms", req.mobile, message, log_id, delay, self.cfg.provider)
        else:
            self.svc.sender.enqueue(channel, req.mobile, message, log_id, 0)
        if self.cfg.delivery_receipts and getattr(self.svc.sender, "instant_receipts", False):
            self.feedback.on_delivery(log_id, True)   # a fake or receipt-less provider: delivered on send
        return Response(200, dict(UNIFORM_BODY), tier=req.tier, channel=channel, log_id=log_id, risk_score=req.risk_score)

    # ---------- Full pipeline ----------
    def process(self, req, apply_floor=True, started=None):
        """apply_floor pads every 200 response to cfg.response_floor_ms measured from `started`
        (default: now). The API passes its own handler-entry time so parsing and response
        building are inside the floor too."""
        start = started if started is not None else time.perf_counter()
        resp = self._process(req)
        if apply_floor:
            self.pad_to_floor(resp, start)
        resp.elapsed_ms = (time.perf_counter() - start) * 1000
        return resp

    def pad_to_floor(self, resp, start):
        floor = self.cfg.response_floor_ms / 1000.0
        if resp.http_status == 200 and floor > 0:
            remaining = floor - (time.perf_counter() - start)
            if remaining > 0:
                time.sleep(remaining)

    def _timed(self, req, name, fn):
        t0 = time.perf_counter()
        try:
            return fn(req)
        finally:
            req.timings_ms[name] = (time.perf_counter() - t0) * 1000

    def _process(self, req):
        def finish(resp):
            resp.timings_ms = req.timings_ms
            resp.signals = list(req.signals)
            return resp

        def reject(step):
            return finish(Response(200, dict(UNIFORM_BODY), rejected_at=step, tier=req.tier, risk_score=req.risk_score))

        if not self._timed(req, "step0", self.step0_connection_and_client_integrity):
            if req.update_required:
                return finish(Response(426, {"status": "update_required"}, rejected_at="step0"))
            return finish(Response(403, {"status": "forbidden"}, rejected_at="step0"))
        if not self._timed(req, "step1", self.step1_session):
            return reject("step1")
        if not self._timed(req, "step2", self.step2_network_throttles):
            return reject("step2")
        if not self._timed(req, "step3", self.step3_recaptcha):
            return reject("step3")
        if not self._timed(req, "step4", self.step4_origin):
            return reject("step4")
        if not self._timed(req, "step5", self.step5_number):
            return reject("step5")
        if not self._timed(req, "step6", self.step6_text):
            return reject("step6")
        if not self._timed(req, "step7", self.step7_risk):
            if req.requires_challenge:
                return finish(Response(200, {"status": "challenge", "challenge": "interactive_recaptcha"},
                                       rejected_at="step7", tier="challenge", risk_score=req.risk_score))
            return reject("step7")
        if not self._timed(req, "step8", self.step8_per_number):
            return reject("step8")
        if not self._timed(req, "step9", self.step9_source_limits):
            self.release_number_claims(req)
            return reject("step9")
        self._timed(req, "step10", self.step10_circuit_breaker)
        return finish(self._timed(req, "step11", self.step11_log_and_send))
