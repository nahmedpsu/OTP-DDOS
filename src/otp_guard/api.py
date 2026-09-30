"""HTTP API around the pipeline (FastAPI).

    GET  /attest/challenge      -> {"challenge": ...}         one-time nonce for app attestation
    POST /session               -> {"session_token": ...}    web: reCAPTCHA; apps: attestation
    POST /otp/request           -> uniform body               the pipeline
    POST /otp/verify            -> {"status": "verified" | "invalid"}
    POST /internal/timeouts/run -> feedback loop tick          needs X-Service-Credential
    GET  /healthz               -> mode and wiring report
"""
import asyncio
import ipaddress
import secrets
import time

from fastapi import FastAPI, Header, Request as HttpRequest
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .pipeline import Request

CHALLENGE_TTL = 300


class SessionBody(BaseModel):
    platform: str
    fingerprint: str
    recaptcha_token: str | None = None
    attestation: dict | None = None
    challenge: str | None = None
    app_version: str | None = None


class OtpRequestBody(BaseModel):
    mobile: str
    nonce: str
    text: str | None = None
    source: str = "App/RegisterOTP"
    recaptcha_token: str | None = None
    attestation: dict | None = None
    challenge_proof: str | None = None
    is_bulk: bool = False


class VerifyBody(BaseModel):
    mobile: str
    code: str


def client_ip(http: HttpRequest, trusted_proxies):
    peer = http.client.host if http.client else "0.0.0.0"
    try:
        ipaddress.ip_address(peer)
    except ValueError:
        peer = "0.0.0.0"          # unix sockets, test clients
    if not trusted_proxies:
        return peer
    if not any(ipaddress.ip_address(peer) in n for n in trusted_proxies):
        return peer
    xff = [p.strip() for p in http.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    # walk from the right, skipping our own proxies, to the first address we did not add
    for hop in reversed(xff):
        try:
            if not any(ipaddress.ip_address(hop) in n for n in trusted_proxies):
                return hop
        except ValueError:
            return peer
    return peer


def create_app(pipeline, report=None, trusted_proxies=(), debug_outcome_header=False):
    """debug_outcome_header=True adds X-Debug-Outcome (server-side outcome and per-step timings) to
    /otp/request responses. It exists for load tests only; it defeats the uniform response."""
    app = FastAPI(title="OTP Guard")
    p = pipeline
    proxies = [ipaddress.ip_network(x, strict=False) for x in trusted_proxies]

    @app.middleware("http")
    async def response_floor(request: HttpRequest, call_next):
        """Constant-time floor for /otp/request, measured from the moment the request reaches the
        app (before body parsing) to just before the response is written. Async sleep, so a padded
        request does not hold a worker thread."""
        started = time.perf_counter()
        response = await call_next(request)
        floor = p.cfg.response_floor_ms / 1000.0
        if floor > 0 and request.url.path == "/otp/request" and response.status_code == 200:
            remaining = floor - (time.perf_counter() - started)
            if remaining > 0:
                await asyncio.sleep(remaining)
        return response

    def bearer(auth):
        return auth.split(" ", 1)[1] if auth and auth.lower().startswith("bearer ") else None

    @app.get("/healthz")
    def healthz():
        body = {"status": "ok", "mode": p.mode}
        if report is not None:
            body["wiring"] = {"real": report.real, "fake": report.fake, "notes": report.notes}
        return body

    @app.get("/attest/challenge")
    def challenge():
        c = secrets.token_urlsafe(24)
        p.store.set("attest:challenge:" + c, 1, CHALLENGE_TTL)
        return {"challenge": c}

    @app.post("/session")
    def session(body: SessionBody, http: HttpRequest):
        platform = body.platform
        if platform == "web":
            res = p.svc.recaptcha.verify({"g-recaptcha-response": body.recaptcha_token})
            if not res["valid"] or res["score"] < p.recaptcha_min_score():
                return JSONResponse({"status": "forbidden"}, status_code=403)
        elif platform in ("ios", "android"):
            if body.attestation is None:
                # legacy app without attestation: only during the grace window
                if body.app_version and p.clock.now() < p.cfg.attestation_grace_until:
                    platform = "legacy_app"
                else:
                    return JSONResponse({"status": "update_required"}, status_code=426)
            else:
                if not body.challenge or not p.store.exists("attest:challenge:" + body.challenge):
                    return JSONResponse({"status": "forbidden"}, status_code=403)
                p.store.delete("attest:challenge:" + body.challenge)
                res = p.svc.attestation.verify(body.attestation, body.challenge)
                if not res.valid or res.platform != platform:
                    return JSONResponse({"status": "forbidden"}, status_code=403)
        else:
            return JSONResponse({"status": "forbidden"}, status_code=403)
        token = p.sessions.issue(platform, body.fingerprint, p.cfg.session_ttl)
        return {"session_token": token, "expires_in": p.cfg.session_ttl}

    @app.post("/otp/request")
    def otp_request(body: OtpRequestBody, http: HttpRequest,
                    authorization: str | None = Header(default=None),
                    x_app_version: str | None = Header(default=None),
                    x_service_credential: str | None = Header(default=None),
                    origin: str | None = Header(default=None),
                    host: str | None = Header(default=None)):
        req = Request(
            mobile=body.mobile, text=body.text or "Your verification code is {code}", source=body.source,
            host=(host or "").split(":")[0], ip=client_ip(http, proxies), origin=origin or "",
            header_platform=(body.attestation or {}).get("platform", "web"), app_version=x_app_version,
            attestation=body.attestation, session_token=bearer(authorization), nonce=body.nonce,
            post={"g-recaptcha-response": body.recaptcha_token} if body.recaptcha_token else {},
            challenge_proof=body.challenge_proof, is_bulk=body.is_bulk, service_credential=x_service_credential,
            headers={"User-Agent": http.headers.get("user-agent", "")},
        )
        resp = p.process(req, apply_floor=False)        # the middleware above applies the floor
        headers = {}
        if debug_outcome_header:
            import json as _json
            headers["X-Debug-Outcome"] = _json.dumps({"rejected_at": resp.rejected_at, "tier": resp.tier,
                                                      "channel": resp.channel, "timings_ms": resp.timings_ms})
        return JSONResponse(resp.body, status_code=resp.http_status, headers=headers)

    @app.post("/otp/verify")
    def otp_verify(body: VerifyBody, authorization: str | None = Header(default=None)):
        tok = p.sessions.verify(bearer(authorization) or "")
        if tok is None or tok["expires_at"] < p.clock.now():
            return JSONResponse({"status": "invalid"}, status_code=200)
        ok = p.feedback.verify_by_session(tok["session_id"], body.mobile, body.code)
        return {"status": "verified" if ok else "invalid"}

    @app.post("/internal/timeouts/run")
    def run_timeouts(x_service_credential: str | None = Header(default=None)):
        if x_service_credential not in p.svc.internal_credentials:
            return JSONResponse({"status": "forbidden"}, status_code=403)
        p.feedback.run_due_timeouts()
        return {"status": "ok"}

    return app


def main():
    """`python -m otp_guard.api` runs the service with uvicorn, configured from the environment."""
    import os
    import uvicorn
    from .factory import build_pipeline
    pipeline, report = build_pipeline()
    if report.fake and os.environ.get("REQUIRE_REAL_PROVIDERS", "").lower() in ("1", "true", "yes"):
        raise SystemExit(f"Refusing to start with fake components: {report.fake}")
    for n in report.notes:
        print("wiring:", n)
    app = create_app(pipeline, report, trusted_proxies=[x for x in os.environ.get("TRUSTED_PROXIES", "").split(",") if x],
                     debug_outcome_header=os.environ.get("LOAD_TEST_DEBUG_HEADER", "").lower() in ("1", "true"))
    uvicorn.run(app, host=os.environ.get("BIND", "0.0.0.0"), port=int(os.environ.get("PORT", "8000")))


if __name__ == "__main__":
    main()
