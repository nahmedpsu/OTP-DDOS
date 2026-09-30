import logging

from .http import default_session

log = logging.getLogger("otp_guard.alerts")


class LoggingAlerts:
    def __init__(self):
        self.alerts = []

    def alert(self, msg, detail=None):
        self.alerts.append((msg, detail))
        log.warning("ALERT %s %s", msg, detail)


class SlackWebhookAlerts:
    def __init__(self, webhook_url, session=None, timeout=3.0):
        self.url, self.session, self.timeout = webhook_url, session or default_session(), timeout
        self.alerts = []

    def alert(self, msg, detail=None):
        self.alerts.append((msg, detail))
        try:
            self.session.post(self.url, json={"text": f":rotating_light: {msg} {detail if detail is not None else ''}"},
                              timeout=self.timeout)
        except Exception as e:
            log.error("slack alert failed: %s", e)


class MultiAlerts:
    def __init__(self, sinks):
        self.sinks = sinks
        self.alerts = []

    def alert(self, msg, detail=None):
        self.alerts.append((msg, detail))
        for s in self.sinks:
            s.alert(msg, detail)
