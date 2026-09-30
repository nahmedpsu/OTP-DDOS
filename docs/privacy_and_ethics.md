# Privacy, data retention and ethics

The pipeline processes personal data: phone numbers, IP addresses, browser and device
fingerprints, and verification behaviour. This document states what is kept, for how long,
why, and what remains to be done before production use or publication. It is a statement
of the design's position, not legal advice; review it with counsel for each jurisdiction.

## Data inventory and retention

| Data | Where | Purpose | Retention (default) | Notes |
|---|---|---|---|---|
| Phone number | audit record, reputation keys, HLR cache, per-number limits | deliver the code; per-number limits; number trust | audit 30 d; reputation 24 h; HLR cache 30 d; trusted-number set until cleared | Store hashed in the audit record where the operational path does not need the plain number (delivery does; analytics does not). |
| IP address, subnet, ASN | rate-limit counters, reputation keys, audit record, intel cache | throttling; reputation; abuse investigation | counters ≤ 1 h; reputation 24 h; audit 30 d; intel cache 1 h | |
| Browser fingerprint hash | session token, first-seen record, reputation keys, denylist | client identity that survives IP rotation | first-seen 90 d; reputation 24 h; denylist 24 h | Only a hash leaves the client. The attributes hashed should be documented in the privacy notice. |
| Attestation key id (apps) | App Attest key store | app integrity | until the app is uninstalled or the key rotates | Public keys and counters only. |
| Session id, nonces | store | replay protection, per-session limits | ≤ 30 min | |
| Message content | audit record | dispute handling | 30 d | OTP codes are stored separately for 20 minutes and never logged in the clear after that. |
| Verification outcome and time | reputation buckets, audit | feedback loop | 24 h buckets; audit 30 d | |
| reCAPTCHA token, score | request only; score in the audit record | bot detection | audit 30 d | Google processes the token under its own terms; disclose in the privacy notice. |

Retention values are configuration (`TTL` constants in `src/otp_guard/`), chosen as the
shortest that still serve the purpose: 24 hours for reputation because attacks are measured
in hours; 30 days for the audit log to handle billing disputes and incident review.

## Lawful basis and regulatory notes

- **GDPR (EU users).** Processing for fraud prevention is a recognised legitimate interest
  (Recital 47). A legitimate-interest assessment and, given fingerprinting and automated
  decisions that can refuse a service, a data-protection impact assessment (Article 35)
  should be completed before production. Users must be informed (Articles 13 and 14), and
  the automated-decision safeguards of Article 22 apply to the block and challenge tiers:
  provide a route to human review.
- **Saudi PDPL.** The Personal Data Protection Law and its implementing regulations govern
  processing of Saudi residents' data. Fraud prevention and securing the service can
  support processing without consent under the legitimate-interest provisions introduced by
  the 2023 amendments, subject to a documented assessment and to the data-transfer rules if
  vendors process data outside the Kingdom (reCAPTCHA, IP intelligence, HLR and messaging
  providers all do). Confirm each vendor's transfer basis with counsel.
- **Data minimisation.** The pipeline never needs the plain phone number after delivery,
  never needs raw fingerprint attributes server-side, and never needs to keep IP addresses
  beyond the reputation window. The defaults above follow that.
- **Automated refusal.** The uniform response means a refused user is not told why. Provide
  a support path that can look up the audit record (with the user's own identifiers) and
  explain or override a decision.

## Ethics and permissions

- **Production logs.** The evaluation used no production logs. If logs from the incident
  are later replayed through `scripts/replay_logs.py`, they must be exported in the hashed
  form of `docs/replay_schema.md`, under an approval from the organisation's data
  protection officer and, where the work is academic, from the institution's research
  ethics board. Record the approval reference here: _(none yet)_.
- **Description of the incident.** The problem statement describes an incident at a real
  organisation. Publishing it, and any figures derived from its logs, requires the
  employer's permission. Record it here: _(pending)_.
- **Dual use.** The attacker models in `src/otp_guard/evaluation/` describe techniques
  that are already public (proxy pools, CAPTCHA solving services, SMS pumping). They are
  included so defenders can measure themselves against them; no operational tooling for
  carrying out an attack is provided.
