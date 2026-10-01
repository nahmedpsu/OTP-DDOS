"""Google reCAPTCHA v3 siteverify. Failure policy: FAIL CLOSED. A web request whose token
cannot be verified is treated as invalid, because web is the platform bots come from."""
from .http import default_session, json_or_error, log


class GoogleRecaptcha:
    URL = "https://www.google.com/recaptcha/api/siteverify"

    def __init__(self, secret, session=None, expected_action=None, expected_hostnames=None, timeout=3.0,
                 challenge_secret=None):
        self.secret = secret
        self.challenge_secret = challenge_secret or secret   # the interactive (v2) site key's secret
        self.session = session or default_session()
        self.expected_action = expected_action
        self.expected_hostnames = set(expected_hostnames or [])
        self.timeout = timeout

    def verify(self, post):
        token = (post or {}).get("g-recaptcha-response")
        if not token:
            return {"valid": False, "score": 0.0}
        try:
            data = json_or_error(self.session.post(self.URL, data={"secret": self.secret, "response": token},
                                                   timeout=self.timeout))
        except Exception as e:  # network, JSON, HTTP
            log.warning("recaptcha unavailable: %s", e)
            return {"valid": False, "score": 0.0, "error": "unavailable"}
        valid = bool(data.get("success"))
        if valid and self.expected_action and data.get("action") != self.expected_action:
            valid = False
        if valid and self.expected_hostnames and data.get("hostname") not in self.expected_hostnames:
            valid = False
        return {"valid": valid, "score": float(data.get("score", 0.0) or 0.0)}

    def verify_challenge(self, token):
        """An interactive reCAPTCHA (v2) response for the challenge tier: success only, no score or
        action. Fails closed."""
        if not token:
            return False
        try:
            data = json_or_error(self.session.post(self.URL, data={"secret": self.challenge_secret, "response": token},
                                                   timeout=self.timeout))
        except Exception as e:
            log.warning("recaptcha challenge verify unavailable: %s", e)
            return False
        if self.expected_hostnames and data.get("hostname") not in self.expected_hostnames:
            return False
        return bool(data.get("success"))
