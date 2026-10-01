"""In-memory fakes for every external dependency of the pipeline."""
import ipaddress
from dataclasses import dataclass, field


class FakeProxyDetector:
    def __init__(self):
        self.proxy_ips = set()

    def is_proxy(self, ip):
        return ip in self.proxy_ips


@dataclass
class AttestResult:
    valid: bool
    platform: str = None


class FakeAttestation:
    """An attestation is a dict {"platform": "ios"|"android", "valid": bool}."""

    def verify(self, attestation, nonce):
        if not attestation or not attestation.get("valid"):
            return AttestResult(False)
        return AttestResult(True, attestation["platform"])


def _vendor_sleep(obj):
    """Load tests only: a fake with `latency_ms` set blocks like a vendor call would (lognormal, sigma 0.5)."""
    ms = getattr(obj, "latency_ms", 0.0)
    if ms:
        import math
        import random
        import time
        time.sleep(ms / 1000.0 * math.exp(random.gauss(0, 0.5)))


class FakeRecaptcha:
    def __init__(self):
        self.scores = {}       # token -> score
        self.calls = 0
        self.latency_ms = 0.0

    def verify(self, post):
        self.calls += 1
        _vendor_sleep(self)
        token = (post or {}).get("g-recaptcha-response")
        if token in self.scores:
            return {"valid": True, "score": self.scores[token]}
        return {"valid": False, "score": 0.0}

    def verify_challenge(self, token):
        """Interactive (v2 checkbox / image) challenge: valid or not, no score."""
        self.calls += 1
        _vendor_sleep(self)
        return token in self.scores


@dataclass
class IpInfo:
    asn: str = "AS1000"
    asn_type: str = "residential"
    is_datacenter: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    abuse_score: float = 0.0
    country: str = "SA"


class FakeIpIntel:
    def __init__(self, default=None):
        self.default = default or IpInfo()
        self.by_ip = {}
        self.by_network = []   # (ip_network, IpInfo)

    def register(self, ip_or_cidr, info):
        if "/" in ip_or_cidr:
            self.by_network.append((ipaddress.ip_network(ip_or_cidr, strict=False), info))
        else:
            self.by_ip[ip_or_cidr] = info

    def lookup(self, ip):
        if ip in self.by_ip:
            return self.by_ip[ip]
        addr = ipaddress.ip_address(ip)
        best = None
        for net, info in self.by_network:
            if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, info)
        return best[1] if best else self.default


@dataclass
class HlrResult:
    assigned: bool = True
    reachable: bool = True
    is_voip: bool = False


class FakeHlr:
    def __init__(self):
        self.unassigned = set()
        self.unreachable = set()
        self.voip = set()
        self.calls = 0
        self.latency_ms = 0.0

    def lookup(self, mobile):
        self.calls += 1
        _vendor_sleep(self)
        return HlrResult(
            assigned=mobile not in self.unassigned,
            reachable=mobile not in self.unreachable,
            is_voip=mobile in self.voip,
        )


@dataclass
class PrefixInfo:
    id: str
    cls: str = "standard"      # standard | premium | elevated | unknown
    cost_units: int = 1


class PrefixTable:
    """Longest-prefix match. Numbers matching no entry are class 'unknown' (cost 1)."""

    def __init__(self):
        self.entries = {}

    def add(self, prefix, cls="standard", cost_units=1):
        self.entries[prefix] = PrefixInfo(prefix, cls, cost_units)

    def lookup(self, mobile):
        best = None
        for p, info in self.entries.items():
            if mobile.startswith(p) and (best is None or len(p) > len(best.id)):
                best = info
        return best or PrefixInfo(mobile[:5], "unknown", 1)


class FakeChannels:
    def __init__(self):
        self.push_devices = set()          # fingerprints with a registered push device
        self.whatsapp_numbers = set()
        self.silent_auth_platforms = set()  # e.g. {"ios", "android"}


@dataclass
class SentMessage:
    channel: str
    mobile: str
    text: str
    log_id: int
    delay: int
    provider: str = None


class FakeSender:
    def __init__(self, instant_receipts=True):
        self.sent = []
        self.instant_receipts = instant_receipts   # the pipeline treats every send as delivered at once
        self.latency_ms = 0.0

    def enqueue(self, channel, mobile, text, log_id, delay, provider=None):
        _vendor_sleep(self)                        # a synchronous provider call, when latency is simulated
        self.sent.append(SentMessage(channel, mobile, text, log_id, delay, provider))

    def by_channel(self, channel):
        return [m for m in self.sent if m.channel == channel]


class AlertSink:
    def __init__(self):
        self.alerts = []

    def alert(self, msg, detail=None):
        self.alerts.append((msg, detail))


@dataclass
class Services:
    proxy: FakeProxyDetector = field(default_factory=FakeProxyDetector)
    attestation: FakeAttestation = field(default_factory=FakeAttestation)
    recaptcha: FakeRecaptcha = field(default_factory=FakeRecaptcha)
    ip_intel: FakeIpIntel = field(default_factory=FakeIpIntel)
    hlr: FakeHlr = field(default_factory=FakeHlr)
    prefixes: PrefixTable = field(default_factory=PrefixTable)
    channels: FakeChannels = field(default_factory=FakeChannels)
    sender: FakeSender = field(default_factory=FakeSender)
    alerts: AlertSink = field(default_factory=AlertSink)
    internal_credentials: set = field(default_factory=lambda: {"svc-secret"})
