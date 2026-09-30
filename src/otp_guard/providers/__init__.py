"""Real provider adapters. Each one implements the same duck-typed interface as the fake in
otp_guard.services, takes an injectable HTTP session for offline tests, and documents its
failure policy (fail closed or fail open) at the top of the class."""
