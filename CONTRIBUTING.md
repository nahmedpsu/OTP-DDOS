# Contributing

- The design document is the source of truth. Change `docs/sms_validation_process.md` first,
  then the code, then run `make pseudocode` so `docs/pseudocode/` stays in sync (CI checks this).
- Every pipeline change needs a test in `tests/unit/test_steps.py`; every new attack you can
  think of belongs in `tests/integration/test_scenarios.py` and `scripts/run_scenarios.py`.
- Thresholds are configuration, but their defaults are documented with a reason in the
  "Default Values" section of the design. Change the reason when you change the number.
- New vendor adapters go in `src/otp_guard/providers/`, take an injectable HTTP session,
  state their failure policy in the module docstring, and are tested offline with
  `tests/unit/fakes.py`.
- Run `make results` before opening a pull request so `results/` reflects the change.
