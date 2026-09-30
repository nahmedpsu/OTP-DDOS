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

    def reputation_keys(self, req):
        return ["ip:" + req.ip, "subnet:" + subnet_of(req.ip), "asn:" + req.ip_info.asn,
                "fp:" + req.fingerprint, "sess:" + req.session_id, "country:" + req.country_code,
                "prefix:" + req.prefix.id, "num:" + req.mobile]

    def previous_session_requests(self, sid):
        return max(0, self.rl("otp:session", sid, self.cfg.session_otp_limit).current_count() - 1)

    # ---------- Step 0 ----------
    def establish_trusted_platform(self, req):
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
        if self.store.exists("deny:fp:" + req.fingerprint):
            return False
        return self.rl("otp:session", req.session_id, self.cfg.session_otp_limit).try_acquire()

    # ---------- Step 2 ----------
    def step2_network_throttles(self, req):
        info = self.svc.ip_intel.lookup(req.ip)
        req.ip_info = info
        if info.is_tor:
            return False
        sub = subnet_of(req.ip)
        for k in ("ip:" + req.ip, "subnet:" + sub, "asn:" + info.asn):
            if self.store.exists("deny:" + k):
                return False
        asn_cap = self.cfg.asn_datacenter_limit if info.is_datacenter \
            else self.adaptive.asn_limit(info.asn, self.cfg.asn_limit_default)
        limits = [self.rl("otp:ip", req.ip, self.cfg.ip_limit),
                  self.rl("otp:subnet", sub, self.cfg.subnet_limit),
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
        if self.rep.get("num:" + mobile).verified == 0 and not self.rep.is_trusted("num:" + mobile):
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
    SIGNAL_POINTS = {"sequential_number": 15, "narrow_range_burst": 15, "elevated_prefix": 10,
                     "unknown_prefix": 10, "voip_number": 10, "legacy_app": 20, "challenge_passed": -20}

    def compute_risk_score(self, req):
        s = 0.0
        if req.trusted_platform == "web":
            s += (1 - (req.recaptcha_score or 0.0)) * 25
        if req.ip_info.is_datacenter:
            s += 15
        s += req.ip_info.abuse_score * 15
        if req.fingerprint_age_hours < 1 / 12:
            s += 20
        elif req.fingerprint_age_hours < 1:
            s += 10
        s += 5 * self.previous_session_requests(req.session_id)

        worst = 1.0
        for key in ["ip:" + req.ip, "subnet:" + subnet_of(req.ip), "asn:" + req.ip_info.asn,
                    "fp:" + req.fingerprint, "country:" + req.country_code, "prefix:" + req.prefix.id]:
            ratio = self.rep.conversion_ratio(key, self.cfg.conversion_min_sample)
            if ratio is not None:
                worst = min(worst, ratio)
        th = self.cfg.conversion_penalty_threshold
        if worst < th:
            s += (th - worst) / th * 25

        if req.ip_info.country != COUNTRY_OF_CODE.get(req.country_code, req.ip_info.country):
            s += 10
        for sig in req.signals:
            s += self.SIGNAL_POINTS.get(sig, 0)
        if self.rep.get("num:" + req.mobile).verified > 0 or self.rep.is_trusted("num:" + req.mobile):
            s -= 20
        if self.rep.get("fp:" + req.fingerprint).verified > 0:
            s -= 15
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
        if req.challenge_proof and req.challenge_proof in self.svc.recaptcha.scores:
            req.signals.append("challenge_passed")
        req.risk_score = self.compute_risk_score(req)
        req.tier = self.decide_tier(req.risk_score, self.mode)
        if req.trusted_platform == "legacy_app" and req.tier == "allow":
            req.tier = "delay"
        if req.tier == "block":
            return False
        if req.tier == "challenge":
            if req.trusted_platform == "web":
                req.requires_challenge = True
                return False
            req.tier = "downgrade"
        return True

    # ---------- Step 8 ----------
    def step8_per_number(self, req):
        sends = self.rep.get("num:" + req.mobile).sent
        if sends >= self.cfg.per_number_daily_cap:
            return False
        base, cap = self.cfg.per_number_base_window, self.cfg.per_number_max_window
        window = min(base * 2 ** max(sends - 1, 0), cap) if sends > 0 else base
        # A shrinking or growing window must apply to the existing key, so refresh its TTL
        # relative to the last send rather than trusting the TTL set at that send.
        last = self.store.get("num_last_send:" + req.mobile)
        if last is not None and self.clock.now() - float(last) < window:
            return False
        return True

    # ---------- Step 9 ----------
    def effective_limit(self, source, sl, period, platform, cc):
        base = sl.get("per_country", {}).get(cc, {}).get(f"{period}_{platform}")
        if base is None:
            base = sl.get(f"{period}_{platform}")
        if base is None:
            return None
        m = self.adaptive.multiplier(source, platform, cc)
        return max(1, int(-(-base * m // 1)))   # ceil

    def step9_source_limits(self, req):
        sl = self.cfg.source_limits.get(req.source)
        if sl is None:
            return True
        p, cc = req.trusted_platform, req.country_code
        minute_cap = self.effective_limit(req.source, sl, "per_minute", p, cc)
        hour_cap = self.effective_limit(req.source, sl, "per_hour", p, cc)
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

    def step11_log_and_send(self, req):
        channel = self.select_channel(req)
        if channel is None:
            return Response(200, dict(UNIFORM_BODY), rejected_at="no_channel", tier=req.tier, risk_score=req.risk_score)
        log_id = self.sms_history.next_id()
        record = {
            "log_id": log_id, "source": req.source, "phone_number": req.mobile,
            "headers": json.dumps(req.headers), "content": req.text,
            "sms_provider": self.cfg.provider if channel == "sms" else None,
            "channel": channel, "trusted_platform": req.trusted_platform,
            "risk_score": req.risk_score, "signals": list(req.signals), "tier": req.tier,
            "operating_mode": self.mode, "session_id": req.session_id,
            "fingerprint": req.fingerprint, "ip": req.ip, "asn": req.ip_info.asn,
            "reputation_keys": self.reputation_keys(req), "sent_at": self.clock.now(),
        }
        self.sms_history.put(record)

        delay = 0
        if channel == "sms":
            h = self.current_hour()
            self.store.incr(f"global:sms:count:{h}")
            self.store.incr(f"global:sms:spend:{h}", req.prefix.cost_units)
            if req.tier == "delay":
                delay = min(5 * 2 ** self.previous_session_requests(req.session_id), 60)
            self.svc.sender.enqueue("sms", req.mobile, req.text, log_id, delay, self.cfg.provider)
        else:
            self.svc.sender.enqueue(channel, req.mobile, req.text, log_id, 0)

        for key in record["reputation_keys"]:
            self.rep.incr(key, "sent")
        self.store.set("num_last_send:" + req.mobile, self.clock.now(), 86400)
        self.feedback.on_sent(log_id)
        return Response(200, dict(UNIFORM_BODY), tier=req.tier, channel=channel, log_id=log_id, risk_score=req.risk_score)

    # ---------- Full pipeline ----------
    def process(self, req):
        start = time.perf_counter()
        resp = self._process(req)
        floor = self.cfg.response_floor_ms / 1000.0
        if resp.http_status == 200 and floor > 0:
            remaining = floor - (time.perf_counter() - start)
            if remaining > 0:
                time.sleep(remaining)
        resp.elapsed_ms = (time.perf_counter() - start) * 1000
        return resp

    def _process(self, req):
        def reject(step):
            return Response(200, dict(UNIFORM_BODY), rejected_at=step, tier=req.tier, risk_score=req.risk_score)

        if not self.step0_connection_and_client_integrity(req):
            if req.update_required:
                return Response(426, {"status": "update_required"}, rejected_at="step0")
            return Response(403, {"status": "forbidden"}, rejected_at="step0")
        if not self.step1_session(req):
            return reject("step1")
        if not self.step2_network_throttles(req):
            return reject("step2")
        if not self.step3_recaptcha(req):
            return reject("step3")
        if not self.step4_origin(req):
            return reject("step4")
        if not self.step5_number(req):
            return reject("step5")
        if not self.step6_text(req):
            return reject("step6")
        if not self.step7_risk(req):
            if req.requires_challenge:
                return Response(200, {"status": "challenge", "challenge": "interactive_recaptcha"},
                                rejected_at="step7", tier="challenge", risk_score=req.risk_score)
            return reject("step7")
        if not self.step8_per_number(req):
            return reject("step8")
        if not self.step9_source_limits(req):
            return reject("step9")
        self.step10_circuit_breaker(req)
        return self.step11_log_and_send(req)
