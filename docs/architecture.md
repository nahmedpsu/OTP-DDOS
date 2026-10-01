# Architecture

## Components

```
                 ┌──────────────────────────────────────────────────────────┐
  client ──HTTP──▶  api.py (FastAPI)                                         │
                 │   /session  /otp/request  /otp/verify  /healthz          │
                 └───────────────┬──────────────────────────────────────────┘
                                 ▼
                 ┌──────────────────────────────────────────────────────────┐
                 │  pipeline.py  Pipeline.process(Request) -> Response       │
                 │   Step 0..11 (see docs/sms_validation_process.md)         │
                 │   SessionService · NumberTracker · SmsHistory             │
                 ├───────────────┬───────────────────┬──────────────────────┤
                 │ reputation.py │ feedback.py       │ services / providers  │
                 │ ReputationStore│ FeedbackLoop     │ proxy, attestation,   │
                 │ AdaptiveLimits │ (verify, timeouts│ recaptcha, ip_intel,  │
                 │               │  auto-denylist)   │ hlr, prefixes,        │
                 │               │                   │ channels, sender,     │
                 │               │                   │ alerts                │
                 └───────┬───────┴───────────────────┴──────────────────────┘
                         ▼
                 ┌──────────────────────────────┐      ┌──────────────────┐
                 │ store.py  MemoryStore        │      │ worker.py        │
                 │           RedisStore (Lua)   │◀─────│ timeouts tick,   │
                 └──────────────────────────────┘      │ baseline job     │
                                                        └──────────────────┘
```

- `pipeline.py` is a straight transcription of the design: one method per step, each
  returning `True` to continue. `Pipeline.process` wraps `_process` with the constant-time
  response floor.
- `services.py` holds the fakes and the dataclasses (`IpInfo`, `HlrResult`, `PrefixInfo`)
  that the real adapters in `providers/` also return. The pipeline never knows which it has.
- `factory.py` reads the environment, picks a real adapter where configured and the fake
  otherwise, and returns a `WiringReport` listing what is still fake.
- `testing.py` is the harness used by the tests and by `scripts/run_scenarios.py`.

## Request flow

1. `api.py` maps the HTTP request to a `Request` (client IP from the peer or a trusted
   forwarding header, bearer session token, attestation, headers).
2. Steps 0 to 6 are cheap or local checks and hard rejects.
3. Step 7 turns the collected signals into a risk score and a tier.
4. Steps 8 to 10 are the capacity controls (per number, per source, global).
5. Step 11 picks a channel, writes the audit record, hands the send to the sender, and
   returns the uniform body.
6. Asynchronously, the feedback loop resolves each send as verified, failed or timed out,
   updating the reputation counters every later request reads in Step 7.

## State keys (store)

| Prefix | Type | Purpose | TTL |
|---|---|---|---|
| `otp:session:*`, `otp:ip:*`, `otp:subnet:*`, `otp:asn:*`, `otp:prefix:*`, `sms_cap_*`, `send_global_sms:limit:*`, `otp:verify:session:*` | counter | fixed-window rate limits | window |
| `nonce:*` | flag | replay protection | 10 min |
| `fp_first_seen:*` | float | fingerprint age | 90 d |
| `deny:*` | flag | auto-denylist for ip, subnet, asn, fp (and blocks in `block_action = deny`) | 24 h |
| `sprt:block:*` | hash | sequential-test counters per destination block (v, f, fv); restart after a verdict | 24 h |
| `verdict:block:*`, `verdict:log` | json, zset | graded verdicts per block (stage, reason), and the blocks that reached one | 1 h, 24 h |
| `outage:<prefix>`, `outage:{delivered,undelivered,failed,kg_verified,kg_failed,blocks}:<prefix>` | json, zset | carrier outage flag and the sliding windows behind it | 15 min, 2x window |
| `rep:<key>:<hour>` | hash | sent, verified, failed per hour | 25 h |
| `rep:trusted` | set | numbers that verified once | none |
| `numseq:<client key>`, `numpfx:<prefix9>` | zset | sequential and narrow-range detection | 2 × window |
| `hlr:*`, `ipintel:*` | json | vendor lookup caches | 30 d, 1 h |
| `num_last_send:*`, `otp:latest:<session>:<mobile>` | value | progressive backoff, session-scoped verify | 24 h, 10 min |
| `smslog:seq`, `smslog:<id>`, `smslog:delivery:<id>` | json | audit log and delivery status | 30 d |
| `otp:code:<id>`, `otp:timeouts` | json, zset | pending codes (with delivery state and resolution) and their deadlines | 20 min |
| `global:sms:count:<hour>`, `global:sms:spend:<hour>`, `otp:mode` | counter, value | circuit breaker | hour |
| `adaptive:mult:*`, `adaptive:override:*`, `adaptive:asn:*` | float, int | adaptive limits | none |
| `appattest:key:*`, `appattest:counter:*` | value | enrolled App Attest keys | none |
| `attest:challenge:*` | flag | one-time attestation challenges | 5 min |

Every key is namespaced so one Redis database can serve several sources.
