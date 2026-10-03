# Deployment

```
cp .env.example .env            # fill in vendor keys and policy
pip install -e ".[google]"
otp-guard-api                   # or: make run-api
otp-guard-worker                # one per deployment, or: make run-worker
```

`GET /healthz` shows the wiring report. With `REQUIRE_REAL_PROVIDERS=true` the service
refuses to start while any component is still a fake.

## Environment variables

| Variable | Purpose |
|---|---|
| `REDIS_URL` | State backend. Without it the in-memory store is used (single instance, lost on restart). |
| `SESSION_HMAC_KEY` | Signs session tokens. Required for more than one instance. |
| `HOST`, `ALLOWED_DOMAINS`, `ALLOWED_COUNTRY_CODES`, `EXCLUDED_NUMBERS` | Policy (Steps 0, 4, 5, 6). |
| `PREFIX_TABLE_PATH` | JSON list of `{"prefix", "class", "cost_units"}`; see `config/prefixes.json`. Without it every number is class `unknown` and premium ranges are not blocked. |
| `SOURCE_LIMITS_PATH` | JSON of per-source limits; see `config/source_limits.json`. |
| `ATTESTATION_GRACE_UNTIL` | ISO timestamp or epoch. Legacy apps are tolerated until then. |
| `GLOBAL_SMS_PER_HOUR`, `GLOBAL_SPEND_UNITS_PER_HOUR` | Circuit breaker budgets. Set to about twice the p99 legitimate hourly volume. |
| `RESPONSE_FLOOR_MS` | Constant-time floor (default 400). |
| `SMS_KILL_SWITCH` | `true` stops all SMS immediately. |
| `INTERNAL_SERVICE_CREDENTIALS` | Comma-separated secrets for bulk, test-server and the timeouts endpoint. |
| `TRUSTED_PROXIES` | CIDRs whose `X-Forwarded-For` is trusted. |
| `ASN_LIMIT_DEFAULT`, `IP_LIMIT_PER_MINUTE` | Override the per-ASN (300/min) and per-IP (5/min) caps. |
| `CGNAT_ASNS` | Carrier ASNs behind carrier-grade NAT; their addresses get 30 requests per minute instead of 5. |
| `RECAPTCHA_SECRET`, `RECAPTCHA_ACTION`, `RECAPTCHA_HOSTNAMES` | Google reCAPTCHA v3. |
| `GOOGLE_APPLICATION_CREDENTIALS` | Service-account JSON for Play Integrity and FCM. |
| `PLAY_INTEGRITY_PACKAGE` | Android package name. |
| `APP_ATTEST_APP_ID` | `<TEAMID>.<bundle id>`. |
| `APP_ATTEST_ROOT_CA_PATH` | Apple App Attestation Root CA (PEM); enables `POST /attest/enroll`. |
| `APP_ATTEST_ALLOW_DEVELOPMENT` | `1` to accept development-environment attestations. |
| `IPINFO_TOKEN`, `ABUSEIPDB_KEY` | IP intelligence and proxy detection. |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` | Twilio Lookup (number liveness) and Messaging. |
| `TWILIO_FROM` or `TWILIO_MESSAGING_SERVICE_SID`, `TWILIO_WHATSAPP_FROM`, `TWILIO_STATUS_CALLBACK` | SMS and WhatsApp sending. With a status callback, delivery receipts are expected at `POST /internal/delivery`; without one, a send the provider accepts counts as delivered and a send it refuses as undelivered. |
| `FCM_PROJECT_ID` | Push channel. Device tokens are read from `push:token:<mobile>` in the store. |
| `SLACK_ALERT_WEBHOOK` | Circuit breaker alerts. |

## Adapters and their failure policy

| Component | Adapter | On vendor outage |
|---|---|---|
| reCAPTCHA | `GoogleRecaptcha` | Fails closed: web request rejected |
| Android attestation | `PlayIntegrityVerifier` | Fails closed |
| iOS attestation | `AppAttestVerifier` (per-request assertion) | Fails closed |
| IP intelligence, proxy detection | `IpinfoIntel` + optional `AbuseIpdbIntel` | Fails open with a neutral result |
| Number liveness | `TwilioLookup` (validity and line type; swap in a true HLR vendor for live reachability) | Fails open, not cached |
| SMS, WhatsApp | `TwilioMessaging` or `HttpSmsProvider` | Failure recorded against the audit log |
| Push | `FcmPush` | Failure recorded |
| Alerts | `SlackWebhookAlerts` + logging | Logged |

## Delivery receipts and carrier outages

The destination-block tests only count sends the carrier confirmed delivered. Post the
provider's delivery reports to `POST /internal/delivery` (an adapter maps the provider's
message id to the pipeline's log id, which the sender records in `smslog:delivery:<id>`).
Without reports, set `delivery_receipts = false` in the config so that the clock runs
from the send; the tests then cannot tell an outage from a flood, and the outage
detector (`outage:<prefix>` in the store, with an alert) is what protects real users
during one. The speed test's legitimate rate (`sprt_legit_fast`) must be set from the
deployment's own measured share of verifications within 5 s of delivery, autofill
included; the default assumes 20 %.

## App Attest enrolment

`POST /attest/enroll` validates the one-time attestation object an app produces at first
launch (`DCAppAttestService.attestKey`) against a challenge from `GET /attest/challenge`,
following Apple's published steps: the certificate chain to the App Attestation root CA, the
nonce extension, the key identifier, the relying-party hash, a zero counter, the AAGUID and
the credential id (`providers/attestation.py`, `AppAttestEnrollment`). On success the key is
registered for per-request assertions. Set `APP_ATTEST_ROOT_CA_PATH` to Apple's root
certificate, downloaded from
https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem (it is not
embedded here), and `APP_ATTEST_ALLOW_DEVELOPMENT=1` only for development builds. Without
the root path the endpoint answers 501 and keys must be registered out of band
(`AppAttestKeyStore.register_key`). The verifier is tested against a synthetic chain; no
Apple-issued attestation from a real device has been run through it.

## Feedback recovery, trust budget and receipt policy

The worker's minute tick also runs the feedback recovery sweep: an effect batch whose
process died is completed after 30 s. Effects are applied at most once, and exactly once
if the sweep runs within the 20-minute replay horizon; a batch found older than that is
skipped and counted in `otp:fx:abandoned` (alert on any increase). Run at least one worker,
and alert on a tick gap of several minutes: two bounded races remain open (top of
`feedback.py`), one of which needs a sweep gap of 13 minutes or more after a late
verification to leave a reversed failure counted; the other, a correcting receipt landing
between the worker's timeout transition and its bookkeeping, loses that send's resolution
timeout (the failure is lost, never doubled).
`known_good_budget_per_min` (default off) bounds how many requests per minute per (source,
country) are granted the verified-history exemption; set it to about twice the measured
returning-user rate. `receipt_policy = "robust"` (default `standard`) counts a failed
delivery receipt as a block-test failure unless the carrier is in an outage: it resists a
carrier that fakes failed receipts and costs false verdicts on persistently poor routes
(`results/evaluation.md`, section D3).

## Delayed sends

The delay tier hands sends to a scheduler. The default is an in-process timer, fine for
one instance. With several instances put a job queue behind the same
`RoutingSender.enqueue` interface.

## Operations

- Run one worker: it resolves OTP timeouts every minute (the feedback loop depends on it)
  and runs the adaptive baseline job.
- Watch `/healthz` `mode`; `elevated` and `emergency` page on-call through the alert sink.
- Dashboards should show conversion by country, platform and ASN; the thresholds in the
  design's "Default Values" table were chosen against those numbers.
