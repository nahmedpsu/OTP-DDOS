# OTP Flood Protection

Design and reference implementation of the SMS/OTP abuse protection pipeline.

| File | What it is |
|------|------------|
| `Problem_Statement.md` | The original incident, the v1 mitigation, the gaps an adapted attacker exploits (A to H), and the v2 objectives. |
| `SMS_Validation_Process.md` | The v2 design: 12 validation steps, the verification feedback loop, default values and their rationale. |
| `otp_guard/` | A Python implementation of the v2 pipeline, step for step. State goes through one store interface with in-memory and Redis backends. |
| `otp_guard/providers/` | Real vendor adapters: Google reCAPTCHA, Play Integrity, App Attest, ipinfo, AbuseIPDB, Twilio Lookup, Twilio SMS and WhatsApp, FCM push, Slack alerts. |
| `otp_guard/api.py` | FastAPI service: session issuance, OTP request, OTP verify, feedback tick, health. |
| `otp_guard/factory.py` | Builds a pipeline from environment variables and reports which components are real and which are still fakes. |
| `tests/` | 160 tests: every pipeline test runs on both the memory and the Redis backend, plus adapter tests with recorded HTTP, factory tests and API tests. |

## Running the tests

```
pip install -r requirements-dev.txt
python3 -m pytest tests -q
```

The suite uses a controllable clock, so rate-limit windows, OTP timeouts and the 30-day
attestation grace period are exercised without sleeping. `tests/conftest.py` builds
requests that pass every step unless a test breaks something on purpose.

## Layout of the implementation

- `otp_guard/store.py`: clock, in-memory key/value store with TTLs, and the atomic
  `RateLimit` (the Lua check-and-consume from the design).
- `otp_guard/reputation.py`: rolling 24-hour reputation counters, conversion ratio, and
  the adaptive-limit multipliers.
- `otp_guard/services.py`: fakes for every external dependency.
- `otp_guard/pipeline.py`: `Pipeline.process(Request)` runs steps 0 to 11 and returns a
  `Response` whose `body` is the uniform client response and whose other fields are
  server-side only (which step rejected, tier, channel, log id, risk score).
- `otp_guard/feedback.py`: the verification feedback loop, OTP verify endpoint limits,
  and the auto-denylist.
- `otp_guard/providers/`: one module per vendor. Each adapter takes an injectable HTTP
  session so it is tested offline with recorded responses.
- `otp_guard/api.py`: the HTTP surface. `otp_guard/worker.py`: the background tick that
  resolves OTP timeouts and runs the adaptive baseline job.

## Deploying with real providers

```
cp .env.example .env        # fill in the vendor keys
pip install -r requirements.txt
python3 -m otp_guard.api    # the HTTP service
python3 -m otp_guard.worker # one background worker per deployment
```

`GET /healthz` shows the wiring report. With `REQUIRE_REAL_PROVIDERS=true` the service
refuses to start while any component is still a fake.

### Endpoints

| Method and path | Purpose |
|---|---|
| `GET /attest/challenge` | One-time nonce an app includes in its attestation. |
| `POST /session` | Web clients send a reCAPTCHA token, apps send an attestation and the challenge. Returns a signed session token. Legacy apps get one only during the grace window. |
| `POST /otp/request` | The pipeline. Bearer session token, `nonce`, `mobile`, and for web a fresh `recaptcha_token`. Always the uniform body on 200. |
| `POST /otp/verify` | Bearer session token, `mobile`, `code`. The client never sees a log id; the latest code for that session and number is used. |
| `POST /internal/timeouts/run` | Feedback loop tick, for schedulers that cannot run the worker. Needs `X-Service-Credential`. |
| `GET /healthz` | Operating mode and wiring report. |

### What each adapter does and how it fails

| Component | Adapter | On vendor outage |
|---|---|---|
| reCAPTCHA | `GoogleRecaptcha` (siteverify, optional action and hostname checks) | Fails closed: web request rejected |
| Android attestation | `PlayIntegrityVerifier` (decodeIntegrityToken, checks package, nonce, device, app and licence verdicts) | Fails closed |
| iOS attestation | `AppAttestVerifier` (per-request assertion: signature, RP ID hash, challenge, monotonic counter) | Fails closed |
| IP intelligence and proxy detection | `IpinfoIntel` plus optional `AbuseIpdbIntel` | Fails open with a neutral result; other layers still hold |
| Number liveness | `TwilioLookup` (validity and line type; swap in a true HLR vendor with the same interface for live reachability) | Fails open, result not cached |
| SMS and WhatsApp | `TwilioMessaging`, or `HttpSmsProvider` for a generic gateway | Delivery failure recorded against the audit log |
| Push | `FcmPush` (HTTP v1) | Delivery failure recorded |
| Alerts | `SlackWebhookAlerts` plus logging | Logged |

### App Attest enrolment

The per-request assertion check is implemented. Enrolling a key (validating the one-time
attestation object and its certificate chain against Apple's App Attest root CA, then
storing the public key) is the app's first-launch flow and is not part of the OTP
pipeline. Once validated, call `AppAttestKeyStore.register_key(key_id, public_key_pem)`.

### Google credentials

Play Integrity and FCM need a service account with the Play Integrity API and Firebase
Messaging scopes. Set `GOOGLE_APPLICATION_CREDENTIALS` to its JSON file; tokens are
fetched with `google-auth`.

### Scheduling of delayed sends

The delay tier hands sends to a scheduler. The default is an in-process timer, which is
fine for one instance. For several instances use a job queue behind the same
`RoutingSender.enqueue` interface.

