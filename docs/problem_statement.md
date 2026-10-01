# Problem Statement: OTP Flood Protection

## 1. Original incident

During the initial phase of the registration flow, the SMS-based phone number verification
system was abused. The registration API was repeatedly triggered with randomly generated
mobile numbers. Because the system sent an SMS to any unregistered number without
safeguards, attackers could flood the endpoint and consume SMS resources at scale.

### Security gaps identified

- No restriction on how many SMS messages could be sent to a single phone number.
- No validation or limits on SMS body content.
- No country-level restriction on recipients.
- No IP-based throttling.
- No filtering of VPN, proxy or anonymized sources.
- No bot or automation protection.

### Initial mitigation (v1)

1. Hidden Google reCAPTCHA with score-based validation.
2. Rate limiting per phone number (1 SMS per number per minute).
3. IP-based throttling (5 requests per IP per minute).
4. Country whitelisting.
5. SMS body character limits.
6. VPN and proxy blocking.
7. Platform- and country-based rate limits tuned to historical usage and marketing peaks.

## 2. Evolved abuse

After v1 the abuse adapted. Attackers rotated IPs, spoofed client attributes and stayed
under individual thresholds. Reviewing v1 against this adapted attacker exposed a second
set of gaps. These are the problems the v2 design must solve.

### Gap A: Platform header spoofing

v1 exempts iOS from the host check and exempts non-web platforms from reCAPTCHA. The
platform is read from a client-controlled header (`HTTP_PLATFORM`). Any attacker can send
`HTTP_PLATFORM: ios` and skip both controls. **Every platform-based exemption is
bypassable.**

### Gap B: IP rotation defeats per-IP throttling

Residential proxy networks and botnets provide thousands of clean IPs. A 5-per-minute
limit on a single IP is irrelevant when each request comes from a different address.
There is no throttle at subnet or ASN level, and no client identity that survives an IP
change.

### Gap C: Numbers are never validated before sending

Random numbers are passed straight to the SMS provider. Numbers that cannot exist,
numbers on dead ranges, and obviously generated sequences (`+96650000001`,
`+96650000002`, ...) all cost the same as a real message.

### Gap D: SMS pumping (toll fraud)

Country whitelisting is too coarse. Inside an allowed country, premium-rate and
revenue-share prefixes cost many times a standard message. Attackers colluding with
carriers target exactly those ranges (Artificially Inflated Traffic, AIT). v1 has no
notion of per-prefix cost.

### Gap E: No global spending cap

Every v1 limit is per key (per number, per IP, per source and platform). A wide attack
that stays under each individual cap still burns budget without bound. Nothing watches
total SMS volume or total spend, and nothing degrades the system automatically when
either spikes.

### Gap F: Rate limiting is not atomic

The v1 pseudocode checks the counter, then increments it, as two operations. Across
multiple application instances two concurrent requests can both pass the check. Under a
flood this race is hit constantly.

### Gap G: Bulk and test-server bypasses

Bulk SMS skips country validation and test-server requests skip text validation, but
neither path requires stronger authentication than a normal request. A leaked flag or
header turns them into a bypass.

### Gap H: Binary decisions and informative responses

Every check is pass or fail, and the response tells the caller which layer rejected the
request. An attacker can probe each threshold, tune the attack to sit just under it, and
enumerate which numbers are already registered.

## 3. v2 objectives (what makes the solution distinctive)

The v2 design keeps every v1 control and adds the following. The unifying idea is to
stop relying only on static thresholds the attacker can measure and instead use signals
the attacker cannot cheaply fake.

1. **Client integrity, not client claims.** Platform exemptions are granted only after
   app attestation (Apple App Attest, Google Play Integrity). Web clients must hold a
   signed session token bound to a device fingerprint before they may request an OTP.
2. **Layered network throttling.** Atomic limits at IP, subnet and ASN level, with lower
   caps for datacenter and hosting ASNs.
3. **Number intelligence.** Normalize, validate country and prefix cost class, detect
   sequential and low-entropy bursts, and confirm the number is live via HLR lookup
   before spending on SMS.
4. **Verification feedback loop.** Track the verify-to-send ratio for every IP, subnet,
   ASN, fingerprint, session, country and prefix. Flooders request codes but never verify
   them. Low conversion lowers trust automatically. An attacker can only supply this
   signal by controlling the destination numbers, which a colluding carrier does; the
   evaluation measures what that costs it.
5. **Risk score engine with tiered responses.** Combine all signals into one score and
   respond with allow, delay, challenge, channel downgrade or block, instead of a binary
   pass/fail.
6. **Channel downgrade.** Route medium-risk requests to push notification, WhatsApp OTP or
   silent network authentication. Keep SMS for trusted traffic.
7. **Progressive backoff.** Repeated requests for the same number or client wait longer
   each time.
8. **Adaptive limits.** Baseline normal traffic per source, platform, country and hour,
   tighten caps automatically on deviation, relax when traffic normalizes.
9. **Global circuit breaker.** System-wide SMS count and spend caps with soft and hard
   thresholds that switch the pipeline into elevated and emergency modes.
10. **Uniform responses.** The same response body and timing for sent, downgraded and
    blocked requests, so the pipeline cannot be probed and registered numbers cannot be
    enumerated.

The full design is in `sms_validation_process.md`.
