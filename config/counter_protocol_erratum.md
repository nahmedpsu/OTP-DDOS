# Dated corrections to `counter_protocol.json`

`counter_protocol.json` is kept byte-for-byte as committed before its runs (commit 2a91d78), because
`results/counter_study.json` records its SHA-256 (`4282e483...`). Corrections are listed here instead.
Each one changes a description only; no seed, policy, claim, threshold or pass rule changes.

## 2026-10-03: seed note (`seeds.note`)

The note says "Seeds 300-309 and 6000+ were never used before this protocol." The 300-series seeds
were new. Of the held-out family's seed values (`6000 + 100 x point + seed index`), six (6000-6002
and 6100-6102) had been used before, by the main evaluation's robustness study at points 10 and 11
(`5000 + 100 x point + seed`), for evaluation only, never for selection. What is new in E2 is each
combination of seed value and shifted workload, not every seed value. First stated in commit 802464d
(README, CHANGELOG, `docs/evaluation.md`, `results/counter_study.md`); this file attaches the
correction to the protocol itself (fifth-round review, numerical audit).

## 2026-10-03: token-bucket label (`exploratory_alternatives`)

"token bucket 4/10 min burst 12" is described as one that "tolerates a legitimate burst of 12". It
tolerates any burst of 12, an attacker's included, and E1 shows it (against the shared-block
poisoner it leaked 1,974 messages, as with no policy). Its challenge-tier bucket refills
independently at the same rate, unlike the excess bucket of RFC 2697, which fills only from the
committed bucket's overflow. Both token-bucket arms are exploratory, untuned comparators.
