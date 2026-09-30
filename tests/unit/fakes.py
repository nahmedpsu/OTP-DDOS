"""A requests.Session stand-in that records calls and returns queued responses."""
import json as _json


class FakeResponse:
    def __init__(self, status_code=200, body=None, text=None):
        self.status_code = status_code
        self._body = body
        self.text = text if text is not None else _json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self):
        self.calls = []
        self.queue = []
        self.fail_with = None

    def respond(self, body, status_code=200):
        self.queue.append(FakeResponse(status_code, body))
        return self

    def _do(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if self.fail_with:
            raise self.fail_with
        if not self.queue:
            raise AssertionError(f"unexpected {method} {url}")
        return self.queue.pop(0)

    def get(self, url, **kw):
        return self._do("GET", url, **kw)

    def post(self, url, **kw):
        return self._do("POST", url, **kw)
