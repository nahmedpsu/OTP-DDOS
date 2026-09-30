# Use cases

How the pipeline behaves for each kind of traffic the registration and login flows see,
with the configuration each one needs. Measured outcomes are in
[`results/analysis.md`](../results/analysis.md), section B.

## Primary flows

| Flow | Source key | What is different |
|---|---|---|
| Registration OTP | `App/RegisterOTP` | The flow the problem statement is about. Every layer applies. |
| Login second factor | `App/LoginOTP` | The number is already verified for this account, so `num:` reputation is trusted from the start: no HLR spend, -20 risk. Give it its own source limits: login volume peaks differently from sign-ups. |
| Password reset | `App/ResetOTP` | Same as login, but attackers target it to enumerate accounts. The uniform response covers this; also rate-limit reset by account id in the calling service. |
| Phone number change | `App/ChangePhoneOTP` | The new number is untrusted: full number intelligence, HLR and backoff apply. Require the session to be authenticated by the calling service (`X-Service-Credential` is not for this; use your normal auth). |

## Operational situations

### Campaign launch (a burst of new users)

New visitors have fresh fingerprints (+20), so they land in the `delay` tier: delivered,
with a few seconds of delay. The only thing that refuses them is the static source cap.
Before a campaign, raise the cap for its (source, platform, country) with a marketing
override:

```
pipeline.adaptive.set_marketing_override("App/RegisterOTP", "web", "966", 1.5)
```

or set higher base limits in `SOURCE_LIMITS_PATH`. The measured difference in
`results/analysis.md` is 12.5 % delivered with the default cap versus 100 % with it lifted,
with no change in what the attacker profiles get.

### Markets with carrier-grade NAT

Mobile carriers put hundreds of subscribers behind one public address. At the default
5 requests per IP per minute, half of a normal 10-per-minute sign-up flow behind one
carrier IP is refused. List the carrier ASNs in `CGNAT_ASNS`; they get 30 per minute per
IP. The subnet and ASN caps, the per-session cap and the risk score still apply, so this
does not reopen the flood: a bot behind the same NAT still has a fresh fingerprint and
never verifies.

### A residential ISP being used as a proxy pool

The attacker's requests arrive from thousands of the ISP's customer addresses. The
pipeline never denylists a residential ASN, because that would block the ISP's real
customers for a day. Instead the conversion penalty (+25) and the sustained-flood bonus
(+15) move every request on that ISP into the `challenge` tier: real customers solve one
interactive challenge and are delivered; the bot is not. Exposure before this happens is
the attack rate times the OTP timeout, which is why the timeout is the one knob worth
tuning (section D of the analysis).

### Users on VPNs

Blocked at Step 0 by policy, as the problem statement requires. If the business later
wants to allow VPN users, the right change is to make `is_proxy` a risk signal (+20)
instead of a hard block, not to remove the check.

### Corporate egress through a hosting ASN

Office traffic that leaves through a cloud NAT looks like a datacenter (+15). A returning
employee's browser is fine (`allow`); a brand-new browser from that egress is challenged
once. If a large customer is affected, register the egress range as residential in the IP
intelligence cache rather than lowering the datacenter penalty globally.

### Roaming users

A Saudi number connecting from abroad gets +10 for the geo mismatch. On its own that is
still `allow`.

### Legacy app versions

Apps that cannot attest are served in the `delay` tier during the grace window and told
to update after it (`426 update_required`). Set `ATTESTATION_GRACE_UNTIL` to the date the
last non-attesting version is out of support.

### Returning users

Anyone who verified once is trusted: no HLR lookup, -20 risk, `allow` even on a slightly
risky network. This is where the feedback loop pays for itself on the legitimate side.

## Internal and partner callers

| Caller | Mechanism |
|---|---|
| Bulk transactional SMS (order updates, alerts) | `is_bulk=true` plus `X-Service-Credential` from `INTERNAL_SERVICE_CREDENTIALS`. Skips the country check only; everything else applies. Give bulk its own source key and limits. |
| Test server | `IS_TEST_SERVER=true` plus the credential skips text validation. Never set on production. |
| Partner API | One source key per partner (`Partner/<name>`), its own limits, and the credential. Partners never get platform exemptions. |
| Ops | `SMS_KILL_SWITCH=true` stops all SMS at once; `/healthz` shows the breaker mode; the worker must run for the feedback loop to work. |

## Staged rollout

`Config.features` lists the v2 controls individually. A rollout can enable them one at a
time (for example `risk_engine` in shadow by logging `risk_score` before acting on it),
and `V1_FEATURES` reproduces the original design for comparison, which is how section C of
the analysis was produced.
