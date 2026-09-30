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
  use_cases.md                  flows, operational situations, internal callers, staged rollout
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
  run_analysis.py               attacker profiles, false positives, v1 vs v2 cost, sensitivity -> results/analysis.{md,json}
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
make analysis       # attacker profiles, false positives, v1 vs v2, sensitivity
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

From `results/analysis.md`. Attackers send 30 requests a minute for 20 minutes with every
source cap lifted, so the numbers show what the other layers do. v1 is the original design
run through the same code with the v2 features switched off.

| Attacker | v1 SMS / 20 min | v2 SMS / 20 min | v2 sustained after detection |
|---|---:|---:|---:|
| One client, random numbers | 100 | 6 | 0 |
| Datacenter IP rotation | 600 | 0 | 0 |
| Residential proxy pool, fresh fingerprints, good reCAPTCHA | 600 | 300 | 0 |
| Residential pool, unique fingerprints pre-aged two hours | 600 | 390 | 0 |
| Sequential numbers | 600 | 300 | 0 |
| Premium-prefix pumping, spoofed platform header | 600 | 0 | 0 |

The residential cases show the one exposure that remains: attack rate times OTP timeout,
until the verification feedback loop has data. Section D of the analysis shows that
timeout is the only knob that moves it.

Legitimate traffic (section B): normal, retrying, roaming, corporate, legacy-app and
returning users are all delivered. Two situations need configuration, both measured:
a campaign burst needs the source cap lifted (12.5 % delivered otherwise), and carriers
behind carrier-grade NAT need their ASN listed (50 % delivered otherwise). A real user on
an ISP that is hosting an attack gets one interactive challenge, then delivery; the ISP is
never denylisted.

## Status

Design and implementation are complete and tested against fakes and recorded vendor
responses. No live vendor call has been made from this repository; see `docs/deployment.md`
for what to watch on first contact with real accounts, App Attest key enrolment, and the
delayed-send scheduler.
