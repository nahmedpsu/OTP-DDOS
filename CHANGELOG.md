# Changelog

## 2.1.0

- Analysis runner (`scripts/run_analysis.py`, `results/analysis.md`): attacker profiles per
  layer, legitimate use cases, v1 versus v2 cost, sensitivity to OTP timeout.
- `docs/use_cases.md`.
- Feature flags (`Config.features`, `V1_FEATURES`) for staged rollout and the v1 baseline.
- Design changes found by the analysis: the auto-denylist no longer applies to residential
  ASNs (only IP, subnet, fingerprint and datacenter ASNs); a sustained-flood bonus (+15 at
  100 resolved sends under 10 % conversion) moves rotating residential attacks to the
  challenge tier instead; listed carrier-grade NAT ASNs get a 30/min per-IP cap.

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
