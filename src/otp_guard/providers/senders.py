"""Delivery channels. Sends are handed to a scheduler so the delay tier works; the default
scheduler is an in-process timer, which is fine for one instance and should be a job queue
(Celery, RQ, SQS) in production, using the same enqueue interface."""
import threading

from .http import default_session, json_or_error, log


class TimerScheduler:
    def schedule(self, delay, fn):
        if delay <= 0:
            fn()
        else:
            t = threading.Timer(delay, fn)
            t.daemon = True
            t.start()


class TwilioMessaging:
    def __init__(self, account_sid, auth_token, from_number=None, messaging_service_sid=None,
                 whatsapp_from=None, status_callback=None, session=None, timeout=5.0):
        self.sid = account_sid
        self.auth = (account_sid, auth_token)
        self.from_number = from_number
        self.messaging_service_sid = messaging_service_sid
        self.whatsapp_from = whatsapp_from
        self.status_callback = status_callback
        self.session = session or default_session()
        self.timeout = timeout

    @property
    def url(self):
        return f"https://api.twilio.com/2010-04-01/Accounts/{self.sid}/Messages.json"

    def _post(self, form):
        if self.status_callback:
            form["StatusCallback"] = self.status_callback
        return json_or_error(self.session.post(self.url, data=form, auth=self.auth, timeout=self.timeout))

    def send_sms(self, mobile, text, log_id):
        form = {"To": f"+{mobile}", "Body": text}
        if self.messaging_service_sid:
            form["MessagingServiceSid"] = self.messaging_service_sid
        else:
            form["From"] = self.from_number
        return self._post(form)

    def send_whatsapp(self, mobile, text, log_id):
        return self._post({"To": f"whatsapp:+{mobile}", "From": f"whatsapp:{self.whatsapp_from}", "Body": text})


class HttpSmsProvider:
    """Generic REST SMS gateway (PROVIDER_A/B/C in the design). body_builder(mobile, text, log_id) -> dict."""

    def __init__(self, name, url, body_builder, headers=None, session=None, timeout=5.0):
        self.name, self.url, self.body_builder = name, url, body_builder
        self.headers = headers or {}
        self.session = session or default_session()
        self.timeout = timeout

    def send_sms(self, mobile, text, log_id):
        return json_or_error(self.session.post(self.url, json=self.body_builder(mobile, text, log_id),
                                               headers=self.headers, timeout=self.timeout))


class FcmPush:
    """Firebase Cloud Messaging HTTP v1. device_token_lookup(mobile) -> registration token or None."""

    def __init__(self, project_id, access_token_provider, device_token_lookup, session=None, timeout=5.0):
        self.project_id = project_id
        self.access_token_provider = access_token_provider
        self.device_token_lookup = device_token_lookup
        self.session = session or default_session()
        self.timeout = timeout

    def send_push(self, mobile, text, log_id):
        token = self.device_token_lookup(mobile)
        if not token:
            raise RuntimeError("no device token")
        body = {"message": {"token": token, "data": {"otp_text": text, "log_id": str(log_id)}}}
        return json_or_error(self.session.post(
            f"https://fcm.googleapis.com/v1/projects/{self.project_id}/messages:send", json=body,
            headers={"Authorization": f"Bearer {self.access_token_provider()}"}, timeout=self.timeout))


class RoutingSender:
    """Implements the pipeline's sender interface: enqueue(channel, mobile, text, log_id, delay, provider).
    channels: {"push": fn, "whatsapp": fn, "silent_auth": fn}; providers: {"PROVIDER_A": fn, ...}
    where each fn is (mobile, text, log_id) -> result. on_result(log_id, channel, ok, detail) is
    called after every attempt so delivery status can be written to the audit log."""

    def __init__(self, providers, channels=None, scheduler=None, on_result=None):
        self.providers = providers
        self.channels = channels or {}
        self.scheduler = scheduler or TimerScheduler()
        self.on_result = on_result or (lambda *a: None)
        self.sent = []

    def enqueue(self, channel, mobile, text, log_id, delay, provider=None):
        fn = self.providers.get(provider) if channel == "sms" else self.channels.get(channel)
        if fn is None:
            log.error("no sender for channel=%s provider=%s", channel, provider)
            self.on_result(log_id, channel, False, "no_sender")
            return
        self.sent.append((channel, mobile, log_id, delay))

        def run():
            try:
                detail = fn(mobile, text, log_id)
                self.on_result(log_id, channel, True, detail)
            except Exception as e:
                log.error("send failed log_id=%s channel=%s: %s", log_id, channel, e)
                self.on_result(log_id, channel, False, str(e))

        self.scheduler.schedule(delay, run)

    def by_channel(self, channel):
        return [s for s in self.sent if s[0] == channel]
