"""IP intelligence. Failure policy: FAIL OPEN with a neutral IpInfo. A vendor outage must not
block every user; the per-IP, per-subnet, per-number and conversion layers still hold."""
from ..services import IpInfo
from .http import default_session, json_or_error, log


class IpinfoIntel:
    """ipinfo.io. Needs the ASN and privacy add-ons for full signal; degrades gracefully."""

    def __init__(self, token, session=None, store=None, cache_ttl=3600, timeout=2.0):
        self.token = token
        self.session = session or default_session()
        self.store = store
        self.cache_ttl = cache_ttl
        self.timeout = timeout

    def lookup(self, ip):
        cache_key = f"ipintel:{ip}"
        if self.store is not None:
            cached = self.store.get(cache_key)
            if cached is not None:
                return IpInfo(**cached)
        try:
            data = json_or_error(self.session.get(f"https://ipinfo.io/{ip}/json",
                                                  params={"token": self.token}, timeout=self.timeout))
        except Exception as e:
            log.warning("ipinfo unavailable for %s: %s", ip, e)
            return IpInfo(asn="AS0", asn_type="unknown", country="")
        info = self._map(data)
        if self.store is not None:
            self.store.set(cache_key, info.__dict__, self.cache_ttl)
        return info

    @staticmethod
    def _map(d):
        asn_obj = d.get("asn") or {}
        asn = asn_obj.get("asn") or (d.get("org", "").split(" ")[0] if d.get("org", "").startswith("AS") else "AS0")
        asn_type = asn_obj.get("type") or "unknown"
        privacy = d.get("privacy") or {}
        is_hosting = asn_type == "hosting" or bool(privacy.get("hosting"))
        return IpInfo(
            asn=asn, asn_type=asn_type, is_datacenter=is_hosting,
            is_tor=bool(privacy.get("tor")),
            is_proxy=bool(privacy.get("vpn") or privacy.get("proxy") or privacy.get("relay")),
            abuse_score=0.0, country=d.get("country", ""),
        )


class AbuseIpdbIntel:
    """Adds abuseConfidenceScore (0..100) as abuse_score (0..1)."""

    def __init__(self, api_key, session=None, timeout=2.0, max_age_days=30):
        self.api_key, self.session, self.timeout, self.max_age = api_key, session or default_session(), timeout, max_age_days

    def score(self, ip):
        try:
            data = json_or_error(self.session.get("https://api.abuseipdb.com/api/v2/check",
                                                  params={"ipAddress": ip, "maxAgeInDays": self.max_age},
                                                  headers={"Key": self.api_key, "Accept": "application/json"},
                                                  timeout=self.timeout))
            return float(data.get("data", {}).get("abuseConfidenceScore", 0)) / 100.0
        except Exception as e:
            log.warning("abuseipdb unavailable for %s: %s", ip, e)
            return 0.0


class CompositeIpIntel:
    def __init__(self, primary, abuse=None):
        self.primary, self.abuse = primary, abuse

    def lookup(self, ip):
        info = self.primary.lookup(ip)
        if self.abuse is not None:
            info.abuse_score = max(info.abuse_score, self.abuse.score(ip))
        return info


class IpIntelProxyDetector:
    """Step 0 proxy detection from the same lookup Step 2 uses."""

    def __init__(self, intel):
        self.intel = intel

    def is_proxy(self, ip):
        return bool(self.intel.lookup(ip).is_proxy)
