# Log replay schema

`scripts/replay_logs.py` replays a CSV of anonymised OTP requests through the pipeline under
the v1 and v2 feature sets and reports the metrics defined in `docs/evaluation.md`. One row
per OTP request. Identifiers must be hashed before export (see `docs/privacy_and_ethics.md`);
the replay never needs a real phone number, address or fingerprint.

| Column | Required | Meaning |
|---|---|---|
| `ts` | yes | Request time, epoch seconds. |
| `ip` | yes | Dotted IPv4, or a hash. With a hash, supply `subnet_hash` so subnet limits can be reproduced. |
| `subnet_hash` | no | Hash of the /24 (or /48). |
| `asn`, `asn_type` | yes | ASN and its type (`isp`, `hosting`, `business`, ...). |
| `ip_country` | yes | ISO country of the address. |
| `is_proxy` | no | `1` if the address was a VPN/proxy/relay. |
| `abuse_score` | no | 0 to 1. |
| `platform` | yes | `web`, `ios`, `android`, `legacy_app`. |
| `attested` | no | `1` if the request carried a valid attestation. |
| `fingerprint` | yes | Hash of the client fingerprint. |
| `fp_first_seen` | no | Epoch seconds the fingerprint was first seen (otherwise first row). |
| `session` | yes | Hash of the session. |
| `mobile_cc`, `mobile_prefix` | yes | Country code and the first 5 digits. Needed for country and prefix logic. |
| `prefix_class`, `prefix_cost` | no | `standard`, `elevated`, `premium`; cost units. |
| `mobile_hash` | yes | Hash of the full number; the replay synthesises a consistent placeholder number from it. |
| `recaptcha_score` | yes | 0 to 1 (empty for apps). |
| `text_len` | no | Message length. |
| `hlr_assigned` | no | `0` if the lookup said unassigned. |
| `verified` | yes | `1` if the code was entered correctly. |
| `verify_delay_s` | yes | Seconds from send to verification (empty if not verified). |
| `label` | no | `attack`, `legit`, or `unknown`, from the incident investigation. Metrics are reported per label. |

Generate a synthetic file in this schema with `scripts/generate_synthetic_logs.py`.
