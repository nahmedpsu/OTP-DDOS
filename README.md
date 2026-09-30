# OTP Guard: OTP flood protection

A layered SMS validation, risk-scoring and rate-limiting pipeline that stops OTP flood
abuse against a registration endpoint. This repository holds the problem statement, the
design with pseudocode, a full implementation with real vendor adapters, a test suite, and
recorded results.

[![CI](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml/badge.svg)](https://github.com/nahmedpsu/OTP-DDOS/actions/workflows/ci.yml)

## Repository layout

```
docs/
  problem_statement.md          the incident, the v1 mitigation, gaps A to H, v2 objectives
  sms_validation_process.md     the v2 design: 12 steps, feedback loop, defaults and reasons
  pseudocode/                   one file per step, extracted from the design, mapped to code
  architecture.md               components, request flow, state keys
  api.md                        HTTP endpoints
  deployment.md                 environment variables, adapters, failure policies, operations
  original/                     the three source documents this work started from
src/otp_guard/
  pipeline.py                   Steps 0 to 11, one method each
  store.py                      MemoryStore and RedisStore behind one interface; atomic RateLimit
  reputation.py                 rolling reputation counters, conversion ratio, adaptive limits
  feedback.py                   verification feedback loop, verify endpoint limits, auto-denylist
  services.py                   fakes and shared dataclasses
  providers/                    real adapters: reCAPTCHA, Play Integrity, App Attest, ipinfo,
                                AbuseIPDB, Twilio Lookup, Twilio SMS/WhatsApp, FCM, Slack
  factory.py                    build a pipeline from the environment; wiring report
  api.py                        FastAPI service       worker.py   background tick
  testing.py                    harness shared by tests and scripts
tests/
  unit/                         per step, per adapter, factory
  integration/                  HTTP API, end-to-end attack and user scenarios
scripts/
  run_scenarios.py              attack scenarios -> results/scenarios.{md,json}
  extract_pseudocode.py         design -> docs/pseudocode/ (CI checks it is in sync)
  smoke_api.py                  boots the real service and drives a flow -> results/api_smoke.txt
results/                        recorded outputs of the above (deterministic)
config/                         sample prefix cost table and source limits
```

## Quick start

```
make install        # pip install -e ".[dev,google]"
make test           # 159 tests, every pipeline test on both memory and Redis backends
make scenarios      # the attack scenarios, written to results/
make smoke          # boot the HTTP service on fakes and drive one flow
make results        # regenerate everything under results/
```

## The pipeline in one table

| Step | Check | Problem it addresses |
|---|---|---|
| 0 | Connection and client integrity: proxy block, platform from attestation | VPN/proxy, header spoofing |
| 1 | Signed session token, fingerprint, nonce replay, per-session cap | IP rotation, replay |
| 2 | IP, subnet and ASN throttles, atomic | IP rotation, race conditions |
| 3 | reCAPTCHA v3 with score threshold | Bots |
| 4 | Origin validation | Domain whitelisting |
| 5 | Number intelligence: country, prefix cost class, pattern detection, HLR | Random numbers, SMS pumping |
| 6 | Text validation | Body restrictions |
| 7 | Risk score engine: allow, delay, challenge, downgrade, block | Probeable binary decisions |
| 8 | Per-number progressive backoff and daily cap | Per-number flooding |
| 9 | Adaptive limits per source, platform, country | Aggregate caps |
| 10 | Global circuit breaker on count and spend | No global cap |
| 11 | Channel selection, audit log, uniform response | Enumeration |
| FB | Verification feedback loop: verify-to-send ratio feeds reputation | The signal an attacker cannot fake |

Full detail, pseudocode and the reasoning behind every default: `docs/sms_validation_process.md`.

## Headline results

From `results/scenarios.md`. Attackers present a fresh fingerprint per request, as a
rotating attacker must; default configuration unless noted.

| Scenario | Requests | SMS sent |
|---|---:|---:|
| One client, random numbers (the original incident) | 200 | 3 |
| 300 rotating datacenter IPs, fresh session each | 300 | 0 |
| 600 unique residential IPs over 20 minutes, every static cap lifted | 600 | 300, then 0 per minute once the feedback loop denylists the ASN |
| Sequential number walk, every cap lifted, then 10 more after the verification window | 40 + 10 | 40, then 0 |
| SMS pumping to a premium prefix | 50 | 0 |
| Circuit breaker at a 10-per-hour budget | 12 | elevated at 80 %, emergency at 100 %; clean traffic still served, risky traffic downgraded |

## Status

Design and implementation are complete and tested against fakes and recorded vendor
responses. No live vendor call has been made from this repository; see `docs/deployment.md`
for what to watch on first contact with real accounts, App Attest key enrolment, and the
delayed-send scheduler.
