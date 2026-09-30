import logging

log = logging.getLogger("otp_guard.providers")


def default_session():
    import requests
    s = requests.Session()
    s.headers["User-Agent"] = "otp-guard/1.0"
    return s


class ProviderError(Exception):
    pass


def json_or_error(resp):
    """Raise ProviderError on non-2xx, return parsed JSON otherwise."""
    if not (200 <= resp.status_code < 300):
        raise ProviderError(f"HTTP {resp.status_code}: {getattr(resp, 'text', '')[:200]}")
    return resp.json()
