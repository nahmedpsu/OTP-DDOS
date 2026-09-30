# Changelog

## 2.0.0

- v2 design (`docs/sms_validation_process.md`): 12-step pipeline addressing gaps A to H from
  the problem statement, plus a verification feedback loop, risk score engine, progressive
  backoff, adaptive limits, global circuit breaker, channel downgrade and uniform responses.
- Implementation in `src/otp_guard/` with one store interface (memory and Redis backends).
- Real provider adapters: Google reCAPTCHA, Play Integrity, App Attest assertions, ipinfo,
  AbuseIPDB, Twilio Lookup, Twilio SMS/WhatsApp, FCM push, Slack alerts.
- FastAPI service, environment-driven factory with wiring report, background worker.
- Test suite (159 tests) on both backends; scenario runner; recorded results.
- Design fixes found by testing: conversion ratio counts resolved sends only; the manual
  kill switch stops all SMS while automatic emergency mode keeps prioritising clean traffic.

## 1.0.0

- Reconciled the original v1 documents (`docs/original/`) into one consistent design:
  per-number limit aligned to 1 SMS/minute, IP throttling step added, Step 0 logic corrected,
  reCAPTCHA score threshold added, pseudocode parameters completed, counter ordering fixed.
