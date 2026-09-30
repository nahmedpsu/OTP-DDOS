"""Reference implementation of the v2 SMS validation pipeline (SMS_Validation_Process.md).

Everything external (Redis, attestation, reCAPTCHA, HLR, IP intelligence, SMS providers)
is behind a small interface with an in-memory fake so the algorithm can be tested
deterministically with a controllable clock.
"""
from .config import Config
from .pipeline import Pipeline, Request, Response, UNIFORM_BODY
from .store import Clock, MemoryStore, RateLimit
