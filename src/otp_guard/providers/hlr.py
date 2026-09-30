"""Number liveness. Failure policy: FAIL OPEN (assigned and reachable) so a lookup outage
does not stop every registration; the result is not cached in that case."""
from ..services import HlrResult
from .http import default_session, json_or_error, log

VOIP_TYPES = {"voip", "nonFixedVoip", "fixedVoip"}
SMS_REACHABLE_TYPES = {"mobile", "personal", "voip", "nonFixedVoip", "fixedVoip", "unknown"}


class TwilioLookup:
    """Twilio Lookup v2 with line_type_intelligence. This is number validity and line type,
    not a true network HLR ping; swap in a dedicated HLR vendor with the same interface if
    you need live reachability."""

    def __init__(self, account_sid, auth_token, session=None, timeout=3.0):
        self.auth = (account_sid, auth_token)
        self.session = session or default_session()
        self.timeout = timeout

    def lookup(self, mobile):
        try:
            data = json_or_error(self.session.get(
                f"https://lookups.twilio.com/v2/PhoneNumbers/+{mobile}",
                params={"Fields": "line_type_intelligence"}, auth=self.auth, timeout=self.timeout))
        except Exception as e:
            log.warning("twilio lookup unavailable for %s: %s", mobile, e)
            return HlrResult(assigned=True, reachable=True, is_voip=False)
        valid = bool(data.get("valid"))
        lti = data.get("line_type_intelligence") or {}
        line_type = lti.get("type") or "unknown"
        return HlrResult(
            assigned=valid,
            reachable=valid and line_type in SMS_REACHABLE_TYPES,
            is_voip=line_type in VOIP_TYPES,
        )
