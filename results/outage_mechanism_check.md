# Why the sequential tests' leakage against the instant verifier fell (seventh-round review, M1)

One E5 evaluation run (200, sequential T300 c0, concentrated_pumper_verifies_instantly, 301), replayed by `scripts/outage_mechanism_check.py`. Recorded leakage: 2.8.x 115, 2.9.0 13.

| Store | Leaked | Outage alerts | Counts the detector saw at each alert |
|---|---:|---:|---|
| 2.9.0 | 13 | 0 | none |
| 2.9.0 with the 2.8.x sorted-set TTL (first write only) | 115 | 1 | conversion collapse: blocks 24, kg_verified 1, kg_failed 9, delivered 36, undelivered 0 |

With the TTL set by the first write, the set of known-good verifications on the carrier emptied while failures written later were kept, so the detector saw conversion collapse across many blocks, inferred a carrier outage and suspended the block tests for its hold time; the pumper's requests went through meanwhile.
