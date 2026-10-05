# Code identity with release 2.9.0 (eighth-round review)

Compared with commit 9af3100 (release 2.9.0, which produced every simulated result) by `scripts/check_code_identity.py`: 39 files that can change a result (package source, configuration, driving scripts). 38 are byte-identical; 1 differs: `src/otp_guard/feedback.py` (same code; docstrings or comments differ).

No file differs in code: this tree runs the code that produced the results.
