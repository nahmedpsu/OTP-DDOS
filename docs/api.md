# HTTP API

All bodies are JSON. The service is `src/otp_guard/api.py`; run it with `make run-api`.

## `GET /attest/challenge`

Returns `{"challenge": "<random>"}`, valid for 5 minutes, single use. Apps include it in
the attestation they send to `POST /session`.

## `POST /session`

| Field | Web | iOS / Android |
|---|---|---|
| `platform` | `"web"` | `"ios"` or `"android"` |
| `fingerprint` | hash of stable browser attributes | attestation key id |
| `recaptcha_token` | reCAPTCHA v3 token from page load | – |
| `attestation` | – | `{"platform": ..., ...}` (see below) |
| `challenge` | – | value from `GET /attest/challenge` |
| `app_version` | – | present on legacy apps that cannot attest |

Responses: `200 {"session_token", "expires_in"}`; `403` on a failed reCAPTCHA or
attestation; `426 {"status": "update_required"}` for an app without attestation once the
grace window has passed.

Attestation shapes:

- Android: `{"platform": "android", "token": "<Play Integrity token>"}`
- iOS: `{"platform": "ios", "key_id": "<b64>", "assertion": "<b64 CBOR>", "client_data": "<b64 JSON with {"challenge": ...}>"}`

## `POST /otp/request`

Headers: `Authorization: Bearer <session_token>`, `Origin` (web), `X-App-Version` (apps),
`X-Service-Credential` (internal bulk or test-server callers only).

Body: `mobile`, `nonce` (fresh per request), optional `text`, `source` (default
`App/RegisterOTP`), `recaptcha_token` (web, a fresh token per request), `attestation`
(apps, a fresh assertion per request), `challenge_proof` (web, after a challenge response),
`is_bulk`.

Responses:

- `200 {"status": "ok", "message": "If this number is eligible, a code has been sent."}` for
  every outcome from Step 1 onward, sent or not, after a constant-time floor.
- `200 {"status": "challenge", "challenge": "interactive_recaptcha"}` on the challenge tier
  (web only). The client solves it and retries with `challenge_proof`.
- `403 {"status": "forbidden"}` for proxy connections and failed attestations (Step 0).
- `426 {"status": "update_required"}` for a legacy app after the grace window.

## `POST /otp/verify`

Header `Authorization: Bearer <session_token>`; body `mobile`, `code`. Returns
`{"status": "verified"}` or `{"status": "invalid"}`. The latest code sent for this session
and number is checked; five wrong attempts invalidate it; codes expire after 10 minutes; a
session may call verify 20 times per 10 minutes.

## `POST /internal/timeouts/run`

Header `X-Service-Credential`. Runs one feedback-loop tick (resolves timed-out codes).
Use the worker instead where you can.

## `GET /healthz`

`{"status", "mode", "wiring": {"real", "fake", "notes"}}`.

## `POST /internal/delivery`

Delivery receipt for one send. Needs `X-Service-Credential`. Body:
`{"log_id": 123, "delivered": true, "at": 1700000000.0}` (`at` optional, provider
timestamp in epoch seconds). Wire the provider's status callback (Twilio `StatusCallback`
with the message SID mapped to the log id) to a small adapter that posts here. A send
with no receipt inside `receipt_grace_s` resolves as undelivered; see
`docs/sms_validation_process.md`, "Delivery receipts gate the tests".

