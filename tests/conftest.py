import pytest

from otp_guard.testing import Harness, make_store  # noqa: F401  (re-exported for tests)


@pytest.fixture(params=["memory", "redis"])
def h(request, monkeypatch):
    harness = Harness(backend=request.param)
    if request.param == "redis":
        # fakeredis expires keys by time.time(); drive it from the test clock
        import time
        monkeypatch.setattr(time, "time", harness.clock.now)
    return harness
