# OTP Flood Protection

Design and reference implementation of the SMS/OTP abuse protection pipeline.

| File | What it is |
|------|------------|
| `Problem_Statement.md` | The original incident, the v1 mitigation, the gaps an adapted attacker exploits (A to H), and the v2 objectives. |
| `SMS_Validation_Process.md` | The v2 design: 12 validation steps, the verification feedback loop, default values and their rationale. |
| `otp_guard/` | A Python reference implementation of the v2 pipeline, step for step, with in-memory fakes for Redis, attestation, reCAPTCHA, HLR, IP intelligence and the SMS providers. |
| `tests/` | 62 tests: one or more per step, plus end-to-end attack and user scenarios. |

## Running the tests

```
pip install pytest
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
