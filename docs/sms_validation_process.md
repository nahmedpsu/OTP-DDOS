# SMS Validation Process (v2)

## Overview

The SMS validation process is a layered security, risk-scoring and rate-limiting pipeline
that every OTP request passes through before a message is sent. It addresses the original
OTP flood incident and the evolved attacks described in `problem_statement.md`.

Two principles drive the design:

1. **Cheapest checks first.** Steps 0 to 2 cost a store lookup or an attestation or IP
   intelligence call; the reCAPTCHA assessment (Step 3) and the HLR lookup (Step 5) are the
   paid vendor calls, made only for requests that survived the earlier steps, and the SMS
   itself (Step 11) only for those that survived everything.
2. **Trust is earned by behaviour, not claimed by headers.** Platform exemptions require
   attestation, clients need a signed session, and every client key carries a reputation
   derived from whether the OTPs it requested were ever verified.

The pipeline has **12 sequential steps, numbered 0 to 11**, followed by an asynchronous
**verification feedback loop**. Each step returns `true` to continue or `false` to reject.
The first failing step stops processing. Whatever the outcome, the client receives the
same uniform response (Step 11).

| Step | Check                                            | Problem it addresses                     |
|------|--------------------------------------------------|------------------------------------------|
| 0    | Connection and client integrity (proxy, attestation, host) | VPN/proxy blocking, **Gap A** header spoofing |
| 1    | Client session token and fingerprint             | **Gap B** IP rotation, replay            |
| 2    | IP, subnet and ASN throttling (atomic)           | IP throttling, **Gap B**, **Gap F**      |
| 3    | Google reCAPTCHA (score-based)                   | Bot protection                           |
| 4    | HTTP Origin validation                           | Domain whitelisting                      |
| 5    | Number intelligence (country, prefix cost, pattern, HLR) | Country whitelisting, **Gap C**, **Gap D** |
| 6    | SMS text validation                              | Body restrictions                        |
| 7    | Risk score engine and tier decision              | **Gap H** binary decisions               |
| 8    | Per-number rate limit with progressive backoff   | Per-number flooding                      |
| 9    | Adaptive rate limits per source, platform, country | Platform/country caps                  |
| 10   | Global circuit breaker: operating mode from the hourly count and spend budgets | **Gap E** no global cap |
| 11   | Atomic budget reservation (the hard ceiling), channel selection, send, log, uniform response | Audit, **Gap E**, **Gap H** enumeration |
| FB   | Verification feedback loop (async)               | Conversion-based reputation              |

An implementation of this pipeline lives in `src/otp_guard/` with real vendor adapters
in `src/otp_guard/providers/` and an HTTP API in `src/otp_guard/api.py`. The pseudocode
below is extracted per section into `docs/pseudocode/` with a pointer to the implementing
function; `tests/` exercises every step on both the memory and Redis backends, and
`results/` records the outcomes. See the repository `README.md`.

## Shared Components

### Atomic RateLimit

All rate limits use one `RateLimit` class backed by Redis. Check and increment happen in a
single Lua script so that concurrent requests across application instances cannot both
pass (**Gap F**). The window is a fixed window keyed by `key:identifier`; the key expires
with the window.

```
// RateLimit.tryAcquire(): returns true and consumes one slot, or false without consuming
// Executed atomically inside Redis (EVAL)
LUA_TRY_ACQUIRE = """
    local current = redis.call('INCR', KEYS[1])
    if current == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[2])
    end
    if current > tonumber(ARGV[1]) then
        redis.call('DECR', KEYS[1])          -- do not consume the slot
        return 0
    end
    return 1
"""

class RateLimit:
    setLimit(maxCount, windowSeconds)
    setKey(key)
    setIdentifier(identifier)

    tryAcquire():
        return redis.eval(LUA_TRY_ACQUIRE, [key + ":" + identifier], [maxCount, windowSeconds]) == 1

    // Read-only helper used by the risk engine
    currentCount():
        return int(redis.get(key + ":" + identifier) or 0)
```

`tryAcquire()` replaces the separate `hasExceededLimit()` and `incrementCount()` calls
from v1. Where a step must check several limits before consuming any of them (Step 9),
it uses a multi-key variant `tryAcquireAll([...])` implemented with the same script over
all keys in one transaction, rolling back on the first failure.

### Reputation Store

A Redis hash per reputation key holding `sent`, `verified`, `failed`, `last_seen` over a
rolling 24-hour window (implemented as hourly buckets). Reputation keys:

| Key type      | Example                       |
|---------------|-------------------------------|
| `ip`          | `ip:203.0.113.7`              |
| `subnet`      | `subnet:203.0.113.0/24`       |
| `asn`         | `asn:AS64500`                 |
| `fingerprint` | `fp:9f2c...`                  |
| `session`     | `sess:...`                    |
| `country`     | `country:966`                 |
| `prefix`      | `prefix:96650`                |
| `number`      | `num:966501234567`            |
| `block`       | `block:96650123` (first 8 digits: 10 000 numbers) | the one key a pumper cannot rotate: it is paid only on the ranges its partner carrier terminates |

The ratio counts only **resolved** sends (verified, or failed after five wrong attempts
or the **resolution timeout**, 2 minutes by default; 99 % of real users verify within
about 100 seconds, so waiting the full 10-minute code validity only delays the signal).
A verification that arrives after the resolution timeout is reclassified from failed to
verified. Sends still inside the window are excluded, so a burst of fresh legitimate
traffic, such as a campaign launch, is neutral until the codes have had time to be
entered.

A second reading, the **recent hour versus the key's own baseline** (the other 23
hours), is implemented behind the `relative_baseline` flag. It needs at least 200
resolved sends of history on the key and so cannot act in the first hours of a key's
life; in the evaluation it adds nothing on top of the destination-block key, and it is not
a default (`results/evaluation.md`, section F).

**Destination blocks are judged by sequential tests with bounded credit**, not by the
shared-key thresholds above. Each block keeps two statistics, conversion and verification
speed, that accumulate the log-likelihood ratio of each resolved send and are floored at
minus one threshold (`block_credit_thresholds = 1`), so a block can bank only a bounded
amount of goodwill: a carrier that verifies a hundred codes and then stops is caught after
about ten unverified sends. A plain cumulative SPRT (`block_test = "sprt"`) would need 143
more after that history; Page's CUSUM with no credit (`block_credit_thresholds = 0`) would
need five but, on a busy block whose users convert at 65 %, reaches a false verdict
roughly a hundred times a day (`results/evaluation.md`, sections F and H). The credit is
the dial between trust-building resistance and false positives. A 10 000-number block is touched by legitimate traffic a
fraction of a time per day, so a block with several sends is almost certainly one
party's. Two tests, each reaching a verdict when the likelihood ratio attacker:legitimate
exceeds 1 000: conversion (real users verify 80 %, a flooder at most 10 %: five
unverified sends in a row give a ratio of 1 845 and a false-positive probability of
0.2⁵ = 0.03 % per block), and verification speed (a machine enters a code within 5 s
of delivery about 90 % of the time; real users do so whenever the OS fills the code in
for them, which the design assumes for 20 % of verifications and which **must be set
from the deployment's own measured distribution**: five instant verifications in a row
give a ratio above 1 000 at that setting). The test counters restart after each verdict.

**What a verdict does is graded**, because a wrong verdict on a block is a wrong verdict
on 10 000 numbers. The first verdict makes the block's first-time clients solve an
interactive challenge (apps: non-SMS channels) for one hour; a second verdict inside that
hour moves them to non-SMS channels only. Clients with verified history (a fingerprint or
a number that verified before) are never affected, so a returning user on a flagged
block is served as usual. The earlier 24-hour denylist at Step 5 remains available as
`block_action = deny`; it stops a challenge-solving pumper a few SMS sooner and locks
real first-time users out of the block for a day.

**Delivery receipts gate the tests.** A send resolves as *failed* only after the carrier
confirmed delivery and the resolution timeout then passed; a send with no receipt inside
the grace period (60 s), or a failed one, is *undelivered* and feeds neither the
conversion ratio nor the block tests. Verification speed is clocked from the receipt, not
from the send, so a slow route cannot make a human look like a machine. A provider with
no delivery reports is configured as `delivery_receipts = false`, in which case the
clock runs from the send, as in the first version of this design.

**A carrier outage is not a pumper.** The tests are suspended for a carrier (prefix) for
15 minutes when, across at least 10 of its destination blocks, either its delivery
receipts collapse (at least half of 20 recent sends undelivered) or its *returning*
clients stop verifying (fewer than 30 % of 10 resolved sends in half an hour). Only
clients with verified history count toward the second signal, so an attacker cannot buy a
suspension with a decoy flood: it would need verified accounts, and burn them. A
colluding carrier could fake failed receipts for other people's sends to suspend the tests
on its own prefix, at the cost of an outage alert to the operator on every such window.

```
function conversionRatio(repKey, minSample = 20):
    r = reputation.get(repKey)
    resolved = r.verified + r.failed
    if resolved < minSample:
        return null                          // not enough data: neutral
    return r.verified / resolved
```

### Operating Mode

A global flag set by the circuit breaker (Step 10): `normal`, `elevated` or `emergency`.
Several steps read it to tighten their behaviour.

## Validation Steps

### Step 0: Connection and Client Integrity

**Purpose:** Block high-risk connections and establish a **trusted platform** value
before any platform-based exemption is applied.

**Rules:**

- A proxy or VPN connection (`check_is_proxy_connection()`) is blocked outright.
- The platform is **never** taken from the `HTTP_PLATFORM` header alone. It is derived
  from attestation:
  - iOS: a valid Apple App Attest assertion for this request → platform `ios`.
  - Android: a valid Google Play Integrity verdict (`MEETS_DEVICE_INTEGRITY`, app
    recognised, licensed) → platform `android`.
  - Attestation present but invalid → **blocked**. A forged or replayed attestation is a
    stronger abuse signal than none at all.
  - No attestation and no app version header → platform `web`. The request has no
    exemptions and must pass reCAPTCHA and origin validation like any browser.
  - No attestation but an app version header (`X-App-Version`) → a **legacy app**.
    Attestation is mandatory for app clients; legacy apps are tolerated only during the
    30-day rollout grace window (`ATTESTATION_GRACE_UNTIL`):
    - During the window: platform `legacy_app`. Skips reCAPTCHA and origin (an app cannot
      run a browser challenge) but carries a `legacy_app` risk signal (+20) and can never
      be better than the `delay` tier.
    - After the window: **blocked** with an `update_required` response. This response is
      safe to reveal because it says nothing about the number and only reaches clients
      that identify themselves as an app.
- `HTTP_HOST` must be `example.com` unless the trusted platform is `ios`, `android` or
  `legacy_app`.

**Examples:**

| Host              | Header platform | Attestation | Proxy | Trusted platform | Result                       |
|-------------------|-----------------|-------------|-------|------------------|------------------------------|
| example.com       | web             | none        | no    | web              | Allowed                      |
| example.com       | web             | none        | yes   | web              | Blocked (proxy)              |
| someotherhost.com | ios             | none        | no    | web              | Blocked (spoofed platform, unauthorized host) |
| someotherhost.com | ios             | valid       | no    | ios              | Allowed (attested app)       |
| someotherhost.com | ios             | invalid     | no    | -                | Blocked (bad attestation)    |
| someotherhost.com | ios + X-App-Version | none    | no    | legacy_app       | Allowed with +20 risk during grace window; blocked (update required) after |

```
// Pseudocode for Validation Step 0
function establishTrustedPlatform(request):
    if request.hasAttestation():
        result = verifyAttestation(request.attestation, request.nonce)
        if not result.valid:
            return "invalid"
        return result.platform                // "ios" or "android"
    if request.headers.has("X-App-Version"):
        if now() < ATTESTATION_GRACE_UNTIL:
            request.signals.add("legacy_app")
            return "legacy_app"
        return "update_required"
    return "web"

function connectionAndClientIntegrityCheck(request):
    if check_is_proxy_connection():
        return false

    request.trustedPlatform = establishTrustedPlatform(request)
    if request.trustedPlatform == "invalid":
        logSecurity("attestation_failed", request)
        return false
    if request.trustedPlatform == "update_required":
        request.updateRequired = true        // Step 11 returns the update_required response
        return false

    if request.host != "example.com" and request.trustedPlatform == "web":
        return false

    return true
```

### Step 1: Client Session Token and Fingerprint

**Purpose:** Give every client an identity that survives an IP change, and stop replay.
Rate limits and reputation are keyed on this identity as well as on the network.

**How a session token is issued:**

- Web: on page load the client runs invisible reCAPTCHA v3 and calls `/session`. If the
  score passes, the server returns a signed token.
- Apps: after attestation succeeds the app calls `/session` and receives a token.

**Token contents** (HMAC-SHA256 signed, 30-minute expiry):
`{ session_id, fingerprint_hash, platform, issued_at, expires_at }`.

**Fingerprint:** a hash of stable client attributes. Web: user agent, language, timezone,
screen size, canvas and audio hashes. Apps: the attestation key ID. The fingerprint is
stored with its first-seen time; **fingerprint age** is a risk signal.

**Rules:**

- Every OTP request must carry a valid, unexpired session token whose platform matches
  the trusted platform from Step 0. Legacy apps obtain a token from `/session` without
  attestation during the grace window only.
- Each request carries a fresh nonce; a nonce seen before is a replay and is blocked.
- A session may make at most **3 OTP requests per 10 minutes**.

```
// Pseudocode for Validation Step 1
function validateSession(request):
    token = verifySignedToken(request.sessionToken, SESSION_HMAC_KEY)
    if token is null or token.expires_at < now():
        return false
    if token.platform != request.trustedPlatform:
        return false                         // token issued to a different platform

    if not redis.setnx("nonce:" + request.nonce, 1, ttl = 600):
        return false                         // replay

    request.sessionId = token.session_id
    request.fingerprint = token.fingerprint_hash
    request.fingerprintAgeHours = fingerprintAge(request.fingerprint)

    sessionLimit = new RateLimit()
    sessionLimit.setLimit(3, 600)            // 3 OTP requests per 10 minutes per session
    sessionLimit.setKey("otp:session")
    sessionLimit.setIdentifier(request.sessionId)
    return sessionLimit.tryAcquire()
```

### Step 2: IP, Subnet and ASN Throttling

**Purpose:** Limit request volume from a single source at three network granularities so
that rotating within a pool of addresses does not reset the budget (**Gap B**).

**Limits (defaults, all atomic):**

| Scope                    | Limit              | Notes                                          |
|--------------------------|--------------------|------------------------------------------------|
| IP                       | 5 / minute         | The v1 control. 30 / minute for ASNs listed as carrier-grade NAT (`CGNAT_ASNS`), where hundreds of subscribers share one address |
| Subnet (/24 IPv4, /48 IPv6) | 30 / minute     | Catches rotation inside one block              |
| ASN (residential/ISP)    | 300 / minute       | Adaptive: replaced by the baseline job (Step 9) |
| ASN (datacenter/hosting) | 50 / minute        | Datacenter traffic is not a normal user        |

The IP is taken from the connection, or from the forwarding header only when the request
arrived through the platform's own load balancer. IP reputation (datacenter, Tor exit,
known abuse lists) is recorded as a risk signal for Step 7 and is not a hard block here
except for Tor exits, which are treated as proxies in Step 0.

```
// Pseudocode for Validation Step 2
function validateNetworkThrottles(request):
    ip = clientIp(request)
    ipInfo = lookupIpIntel(ip)               // { asn, asnType, isDatacenter, isTor, abuseScore, country }
    request.ipInfo = ipInfo

    ipLimit = new RateLimit(); ipLimit.setLimit(5, 60); ipLimit.setKey("otp:ip"); ipLimit.setIdentifier(ip)
    subnetLimit = new RateLimit(); subnetLimit.setLimit(30, 60); subnetLimit.setKey("otp:subnet"); subnetLimit.setIdentifier(subnetOf(ip))

    asnCap = 50 if ipInfo.isDatacenter else adaptiveLimit("asn", ipInfo.asn, default = 300)
    asnLimit = new RateLimit(); asnLimit.setLimit(asnCap, 60); asnLimit.setKey("otp:asn"); asnLimit.setIdentifier(ipInfo.asn)

    if not RateLimit.tryAcquireAll([ipLimit, subnetLimit, asnLimit]):
        logError("Network cap reached for " + ip)
        return false
    return true
```

### Step 3: Google reCAPTCHA Validation

**Purpose:** Prevent automated submissions from browsers.

Applies when the **trusted** platform is `web`. Attested apps and legacy apps (grace
window only) skip it, since an app cannot render a browser challenge; legacy apps pay for
the skip with a +20 risk signal in Step 7. The token must be valid and its score must meet `RECAPTCHA_MIN_SCORE`
(default 0.5; raised to 0.7 in `elevated` mode). The raw score is also passed to the risk
engine.

```
// Pseudocode for Validation Step 3
function validateReCaptcha(request, minScore):
    if request.trustedPlatform != "web":
        return true

    result = verifyGoogleReCaptcha(request.post)
    request.recaptchaScore = result["score"] if result["valid"] else 0.0
    if not result["valid"]:
        return false
    if result["score"] < minScore:
        logError("reCAPTCHA score below threshold: " + result["score"])
        return false
    return true
```

### Step 4: HTTP Origin Validation

**Purpose:** Ensure browser requests come from approved domains.

Extracts the root domain from the `Origin` header and checks it against the allowed
domains list (`admin.example.com`, `example.com`, `api.example.com`,
`partner.example.com`). Attested app requests have no browser origin and skip this step.

```
// Pseudocode for Validation Step 4
function validateHttpOrigin(request, allowedDomains):
    if request.trustedPlatform != "web":
        return true
    return extractRootDomainFromUrl(request.origin) in allowedDomains
```

### Step 5: Number Intelligence

**Purpose:** Refuse to spend on numbers that are disallowed, overpriced, generated or
dead (**Gap C**, **Gap D**), and produce number-related risk signals.

**5a. Normalize and country check** (the v1 control):

- Remove `+` and leading zeros; parse to E.164; reject unparseable numbers.
- The country code must be in the allowed list.
- Oman (`968`) is blocked unless the trusted platform is `ios` or `android`. Legacy apps
  are not exempt.
- Bulk SMS skips the country check **only** when the request carries a valid internal
  service credential (mTLS or a signed service token); the bulk flag alone is not enough
  (**Gap G**).

**5b. Prefix cost class:** look up the number's prefix in the cost table.

| Class      | Meaning                               | Action                                  |
|------------|---------------------------------------|-----------------------------------------|
| `standard` | Normal mobile range                   | Continue                                |
| `premium`  | Revenue-share or premium-rate range   | Blocked for OTP                         |
| `elevated` | Ranges with high historical AIT rates | Continue, cap 20 / hour per prefix, risk signal |
| `unknown`  | Not in table                          | Continue, risk signal                   |

**5c. Pattern detection:** flooders generate numbers in sequence or from a narrow range.

- **Sequential burst:** within the last 10 minutes the same fingerprint, IP or subnet
  requested a number within ±5 of this one.
- **Narrow-range burst:** more than 10 distinct numbers sharing the first 9 digits were
  requested platform-wide in the last 10 minutes.

Either raises a risk signal; both together block.

**5d. HLR lookup:** for a number never verified before, query the HLR (cached 30 days) to
confirm it is assigned and reachable. Unassigned or unreachable numbers are rejected. A
number in the reputation store with `verified > 0` skips the lookup. HLR costs a fraction
of an SMS and is skipped in `emergency` mode only for numbers already known.

```
// Pseudocode for Validation Step 5
function validateNumber(request):
    mobile = parseE164(removeLeadingZeros(removePlusSign(request.mobile)))
    if mobile is null:
        return false
    request.mobile = mobile
    countryCode = getFirstThreeDigits(mobile)
    request.countryCode = countryCode

    // 5a country
    if request.isBulkSms and verifyInternalServiceCredential(request):
        pass                                 // authenticated bulk path skips country check
    else:
        if countryCode == "968" and request.trustedPlatform not in ["ios", "android"]:
            return false
        if countryCode not in ALLOWED_COUNTRY_CODES:
            return false

    // 5b prefix cost class
    prefix = lookupPrefix(mobile)            // { class, costUnits }
    request.prefix = prefix
    if prefix.class == "premium":
        return false
    if prefix.class == "elevated":
        prefixLimit = new RateLimit(); prefixLimit.setLimit(20, 3600)
        prefixLimit.setKey("otp:prefix"); prefixLimit.setIdentifier(prefix.id)
        if not prefixLimit.tryAcquire():
            return false
        request.signals.add("elevated_prefix")
    if prefix.class == "unknown":
        request.signals.add("unknown_prefix")

    // 5c pattern detection
    sequential = recentNeighbourRequested(mobile, radius = 5, keys = [request.fingerprint, request.ip, subnetOf(request.ip)], window = 600)
    narrowRange = distinctNumbersWithPrefix(mobile[0:9], window = 600) > 10
    if sequential and narrowRange:
        return false
    if sequential:  request.signals.add("sequential_number")
    if narrowRange: request.signals.add("narrow_range_burst")
    recordNumberRequest(mobile, request)      // feeds the two detectors above

    // 5d HLR
    if reputation.get("num:" + mobile).verified == 0:
        hlr = hlrLookup(mobile)              // cached 30 days
        if not hlr.assigned or not hlr.reachable:
            return false
        if hlr.isVoip: request.signals.add("voip_number")
    return true
```

### Step 6: SMS Text Validation

**Purpose:** Ensure the SMS content meets requirements and the recipient is not blocked.

**Requirements:**

- Test-server requests skip this step **only** with a valid internal service credential
  (**Gap G**).
- Text length between 1 and 420 characters (3 SMS units of 140).
- The number is not in `EXCLUDED_NUMBERS`.

```
// Pseudocode for Validation Step 6
function validateSmsText(request, excludedNumbers):
    if IS_TEST_SERVER and verifyInternalServiceCredential(request):
        return true
    if request.mobile in excludedNumbers:
        return false
    n = length(request.text)
    return n >= 1 and n <= 420
```

### Step 7: Risk Score Engine and Tier Decision

**Purpose:** Replace a chain of binary thresholds with one score built from signals the
attacker cannot cheaply fake, and choose a graded response (**Gap H**).

**Signals and weights** (score 0 to 100, higher is riskier):

| Signal                                   | Points                                     |
|------------------------------------------|--------------------------------------------|
| reCAPTCHA score (web)                    | `(1 - score) * 25`                         |
| IP is datacenter / hosting               | +15                                        |
| IP abuse list score                      | `abuseScore * 15` (0..1)                   |
| Fingerprint age < 1 hour                 | +10 (< 5 minutes: +20)                     |
| Session OTP request count                | +5 per previous request in this session    |
| Conversion ratio of IP / subnet / ASN / fingerprint / country / prefix | `max over keys of (0.3 - ratio) / 0.3 * 25`, only when ratio < 0.3 |
| Relative drop (opt-in `relative_baseline`): recent-hour ratio below 0.6 × the key's own 23-hour baseline (≥ 20 recent and ≥ 200 baseline resolved) | `(1 - recent/baseline) * 25`, taking the larger of this and the absolute penalty (`conversion_drop`) |
| Sustained flood on any of those keys: ≥ 100 resolved sends and ratio < 0.1 | +15 (`sustained_flood`) |
| Instant verification on a shared key: ≥ 20 verified and > 80 % of them within 5 s of the send | +15 (`instant_verification`): codes entered by a machine, the tell of a colluding carrier verifying its own pumped traffic |
| Geo mismatch: IP country != number country | +10                                      |
| `sequential_number`, `narrow_range_burst` | +15 each                                  |
| `elevated_prefix`, `unknown_prefix`, `voip_number` | +10 each                         |
| `legacy_app` (no attestation, grace window) | +20, and tier is never better than `delay` |
| Number previously verified               | -20                                        |
| Fingerprint with verified history         | -15                                        |

**Tiers:**

| Score        | Tier        | Response                                                      |
|--------------|-------------|---------------------------------------------------------------|
| 0 to 19      | `allow`     | Continue to send via preferred channel                        |
| 20 to 39     | `delay`     | Continue, but the send is queued with a delay (Step 11)       |
| 40 to 59     | `challenge` | Web: require an interactive challenge, then re-enter at Step 7 with a `challenge_passed` signal (-20). Apps: treated as `downgrade` |
| 60 to 79     | `downgrade` | Continue only via a non-SMS channel; if none is available, block |
| 80 to 100    | `block`     | Rejected                                                      |

In `elevated` mode every tier boundary moves down by 10 points. In `emergency` mode only
`allow` with score < 10 may use SMS; everything else is downgraded or blocked.

**What the conversion signal can and cannot separate** (measured in
`results/evaluation.md`). The penalty attaches to keys. On a key the attacker shares with
real users (country, prefix, a residential ASN) it raises everyone's score by the same
amount: it rations rather than separates, and below about 1.8 times the legitimate volume
it does not fire at all. It separates only on keys the attacker dominates. Every
client-side key (IP, fingerprint, session) can be rotated for almost nothing, so the key
that matters is the **destination block**: a pumper is paid only on the numbers its
partner carrier terminates. A block that never verifies reaches a verdict after five
sends; a block whose codes are almost all entered within seconds of delivery is
machine-verified and reaches one too. A carrier that verifies with human-like delay
defeats the conversion test (it must verify at least 42 % of its codes to do so, each a
verified fake account, `evaluation/model.py`); whether the speed test still catches it
depends on the credit its block has banked (`block_credit_thresholds`: 158 leaked of 600
with none, 440 with the default one threshold, all with unbounded credit), and it turns
the pumping into verified fake accounts, whose cost falls on whatever the account is for.
The `challenge_passed` credit can be bought from a solving service; it reduces friction
for people, it is not a defence against solvers.

**A single signal never blocks.** The largest single contribution is the conversion penalty
(+25), which on its own moves a clean-looking web client only to `delay`, a tier that still
sends. That is deliberate: it protects a legitimate country or prefix from a penalty caused
by someone else's attack. Stopping traffic needs signals to stack, and a distributed
attacker supplies them by construction: a rotating client has a fresh fingerprint (+20),
a reused one accumulates its own conversion history, generated numbers trip the pattern
detectors, and any network key that keeps failing is denylisted outright by the feedback
loop. `results/scenarios.md` shows both halves of this in the sequential-walk scenario.

```
// Pseudocode for Validation Step 7
function computeRiskScore(request):
    s = 0
    if request.trustedPlatform == "web":
        s += (1 - request.recaptchaScore) * 25
    if request.ipInfo.isDatacenter: s += 15
    s += request.ipInfo.abuseScore * 15
    if request.fingerprintAgeHours < 1/12: s += 20
    else if request.fingerprintAgeHours < 1: s += 10
    s += 5 * previousSessionRequests(request.sessionId)

    worst = 1.0
    for key in ["ip:" + request.ip, "subnet:" + subnetOf(request.ip), "asn:" + request.ipInfo.asn,
                "fp:" + request.fingerprint, "country:" + request.countryCode, "prefix:" + request.prefix.id]:
        ratio = conversionRatio(key)
        if ratio is not null: worst = min(worst, ratio)
    if worst < 0.3: s += (0.3 - worst) / 0.3 * 25

    if request.ipInfo.country != countryOf(request.countryCode): s += 10
    for sig in request.signals:
        s += { "sequential_number": 15, "narrow_range_burst": 15,
               "elevated_prefix": 10, "unknown_prefix": 10, "voip_number": 10,
               "legacy_app": 20, "challenge_passed": -20 }.get(sig, 0)
    if reputation.get("num:" + request.mobile).verified > 0: s -= 20
    if reputation.get("fp:" + request.fingerprint).verified > 0: s -= 15
    return clamp(s, 0, 100)

function decideTier(score, mode):
    shift = 10 if mode == "elevated" else 0
    if mode == "emergency":
        return "allow" if score < 10 else "downgrade"
    if score >= 80 - shift: return "block"
    if score >= 60 - shift: return "downgrade"
    if score >= 40 - shift: return "challenge"
    if score >= 20 - shift: return "delay"
    return "allow"

function riskDecision(request):
    request.riskScore = computeRiskScore(request)
    request.tier = decideTier(request.riskScore, operatingMode())
    if request.trustedPlatform == "legacy_app" and request.tier == "allow":
        request.tier = "delay"
    if request.tier == "block":
        return false
    if request.tier == "challenge":
        if request.trustedPlatform == "web":
            request.requiresChallenge = true // Step 11 returns the challenge; client retries with proof
            return false
        request.tier = "downgrade"
    return true
```

### Step 8: Per-Number Rate Limit with Progressive Backoff

**Purpose:** Prevent flooding an individual number, and make each repeat request wait
longer than the last.

**Rules:**

- The base window is 60 seconds (1 SMS per number per minute, the v1 control).
- The window doubles with each send to the same number in the last 24 hours:
  60 s, 120 s, 240 s, 480 s, 960 s, capped at 3600 s.
- Hard cap of **5 sends per number per 24 hours**.

**Example:**

| Send # in 24h | Minimum wait since previous send |
|---------------|----------------------------------|
| 1             | none                             |
| 2             | 60 s                             |
| 3             | 120 s                            |
| 4             | 240 s                            |
| 5             | 480 s                            |
| 6             | rejected (daily cap)             |

```
// Pseudocode for Validation Step 8
function validateRateLimitPerMobile(mobile):
    sends = reputation.get("num:" + mobile).sent      // rolling 24h
    if sends >= 5:
        return false

    window = min(60 * 2 ** max(sends - 1, 0), 3600) if sends > 0 else 60
    rateLimit = new RateLimit()
    rateLimit.setLimit(1, window)
    rateLimit.setKey("send_global_sms:limit")
    rateLimit.setIdentifier(mobile)
    return rateLimit.tryAcquire()
```

### Step 9: Adaptive Rate Limits per Source, Platform and Country

**Purpose:** Enforce aggregate caps that follow real traffic instead of a fixed number.

Limits are keyed on **source** (e.g. `App/RegisterOTP`), **trusted platform**, and
**recipient country**, for per-minute and per-hour windows. Configured base limits are
multiplied by an **adaptive multiplier** in the range 0.25 to 1.5 produced by the
baseline job (the multiplier and the known-good exemption below are v2 behaviour behind
the `adaptive_caps` flag; v1 had static caps, and the evaluation runs v1 that way):

- The worker runs the job every minute (`otp_guard.baseline.BaselineJob`): the observed
  volume is the last minute's count of requests that reached the cap, recorded by Step 9;
  the expected volume for each (source, platform, country) is the median per-minute rate
  for this hour of the week over the last 4 weeks, with its MAD, learned by the same job
  from those counters (until two weekly samples exist, the trailing 24-hour mean stands in).
  The evaluation runs the job at this cadence and also at 10-minute and hourly cadences
  (`results/evaluation.md`, B2).
- Multiplier rises toward 1.5 when the key's conversion ratio is healthy (≥ 0.5) and
  traffic is within 2 MAD of expected.
- Multiplier falls toward 0.25 when traffic exceeds expected by more than 3 MAD or the
  key's conversion ratio drops below 0.3.
- Marketing calendar entries override the multiplier upward for planned campaigns.

Both windows are checked before either counter is consumed. The per-number controls of
Step 8 are atomic too: the request claims the number's window with `SETNX` (TTL = the
window that applies after this send) and a slot in the capped daily counter; a later step
that refuses the request releases both. Two concurrent requests for one number cannot both
pass. What is *not* one operation is the sequence of steps itself: the atomic parts are
each counter's check-and-consume, and the delivery and verification callbacks are
idempotent (a duplicate receipt or verification is ignored), which is what concurrent
requests and repeated provider callbacks require.

**Rationing spares known-good clients only.** When the multiplier is below 1 the reduced
cap applies to every client except those with verified history (a fingerprint that has
verified a code before, or a trusted number); those keep the base cap. A low risk score
is deliberately not enough to be spared: an attacker with pre-aged fingerprints and farmed
CAPTCHA scores has a low score too, and an earlier version that spared the `allow` tier
let exactly that attacker through while rationing real new users (`results/evaluation.md`).
For a registration endpoint almost every real user is also unknown, so under a diluting
attack the cap is blunt for them; the cap sweep quantifies the trade-off.

**Example base limits:**

| Platform | Per minute | Per hour |
|----------|-----------:|---------:|
| iOS      | 10         | 100      |
| Web      | 5          | 50       |
| Android  | 8          | 80       |

```
// Pseudocode for Validation Step 9
function effectiveLimit(sourceLimit, period, platform, countryCode):
    base = sourceLimit.get("per_country", {}).get(countryCode, {}).get(period + "_" + platform)
    if base is null:
        base = sourceLimit[period + "_" + platform]
    return ceil(base * adaptiveMultiplier(source, platform, countryCode))

function validateSourceRateLimit(request, limits):
    source = request.source; platform = request.trustedPlatform; cc = request.countryCode
    if source not in limits or request.tier == "downgrade":
        return true                          // SMS caps; a non-SMS channel spends none of it
    sl = limits[source]

    minuteLimit = new RateLimit()
    minuteLimit.setLimit(effectiveLimit(sl, "per_minute", platform, cc), 60)
    minuteLimit.setKey("sms_cap_per_minute_" + platform + ":limit")
    minuteLimit.setIdentifier(source + ":" + cc)

    hourLimit = new RateLimit()
    hourLimit.setLimit(effectiveLimit(sl, "per_hour", platform, cc), 3600)
    hourLimit.setKey("sms_cap_per_hour_" + platform + ":limit")
    hourLimit.setIdentifier(source + ":" + cc)

    if not RateLimit.tryAcquireAll([minuteLimit, hourLimit]):
        logError(platform + " SMS cap reached for " + source + "/" + cc)
        return false
    return true
```

### Step 10: Global Circuit Breaker

**Purpose:** Bound total SMS count and total spend regardless of how the traffic is
distributed across keys (**Gap E**), and switch the whole pipeline into a defensive mode
automatically.

**Budgets** (configurable): `GLOBAL_SMS_PER_HOUR` and `GLOBAL_SPEND_UNITS_PER_HOUR`, where
spend is the sum of prefix cost units from Step 5b.

| Utilisation of either budget | Operating mode | Effect                                                     |
|------------------------------|----------------|------------------------------------------------------------|
| < 80 %                       | `normal`       | Default behaviour                                          |
| 80 % to < 100 %              | `elevated`     | Tier boundaries down 10 points, reCAPTCHA min 0.7, page on-call |
| ≥ 100 %                      | `emergency`    | SMS only for score < 10; everything else downgraded or blocked; page on-call |

The mode is recomputed on every request from the current hourly counters and resets when
the window rolls. **The budget is a hard ceiling**: before any SMS, Step 11 reserves one
unit of the hourly count and the message's cost units atomically (`INCRBY` with a cap, one
Lua script); a reservation that would exceed either budget fails and the request is
downgraded to a non-SMS channel or refused, whatever its score. Between 80 % and 100 %
(`emergency`) only the cleanest traffic (score < 10) may still use SMS, so the last part
of the budget goes to the users most likely to be real.
The manual **kill switch** (`SMS_KILL_SWITCH`) is different: it forces `emergency` and
stops **all** SMS; every request is downgraded to a non-SMS channel or dropped.

```
// Pseudocode for Validation Step 10
function circuitBreaker(request):
    if request.tier not in ["allow", "delay"]:
        return true                          // non-SMS channels do not spend SMS budget

    count = redis.get("global:sms:count:" + currentHour()) or 0
    spend = redis.get("global:sms:spend:" + currentHour()) or 0
    util = max(count / GLOBAL_SMS_PER_HOUR, spend / GLOBAL_SPEND_UNITS_PER_HOUR)

    mode = "emergency" if (util >= 1.0 or SMS_KILL_SWITCH) else "elevated" if util >= 0.8 else "normal"
    setOperatingMode(mode)
    if mode != "normal": alertOnCall("SMS circuit breaker: " + mode, util)

    if SMS_KILL_SWITCH or (mode == "emergency" and request.riskScore >= 10):
        request.tier = "downgrade"           // Step 11 will try a non-SMS channel
    return true
```

### Step 11: Channel Selection, Send, Log and Uniform Response

**Purpose:** Deliver the code over the cheapest channel appropriate to the risk tier,
write the audit record, and answer the client without revealing what happened.

**Channel preference by tier:**

| Tier        | Channels tried in order                                        |
|-------------|----------------------------------------------------------------|
| `allow`     | push (if the device is registered), SMS                        |
| `delay`     | push, SMS after a delay of `min(5 * 2^k, 60)` s where k = previous requests in session |
| `downgrade` | push, WhatsApp OTP, silent network authentication; **never SMS**; block if none available |

**State before the send.** Step 11 writes the audit record, the reputation `sent` counters
and the OTP entry (code, expiry, delivery state) *before* it hands the message to the
sender, because the default scheduler sends a zero-delay message synchronously and a
provider can report its result, or post a receipt, before `enqueue()` returns. Every later
transition of that entry (receipt, code entry, resolution) is an atomic read-modify-write
on the store (a lock in memory, WATCH/MULTI/EXEC on Redis): a repeated positive receipt
never moves the delivery time, a negative receipt after a positive one is a counted
conflict and ignored, a positive receipt after a negative one or after the grace period
reopens the send while the code is valid, and two workers verifying the same code count it
once. The rules are spelled out at the top of `src/otp_guard/feedback.py` and exercised in
`tests/unit/test_second_round.py` and, across two instances on a real Redis, in
`tests/integration/test_real_redis.py`.

**The code travels in the message.** Step 11 generates the code before the send, fills the
message template (`{code}`), hands the filled message to the sender and stores the code
separately for 20 minutes; the audit record keeps the template, never the code.

**Audit log** includes the v1 fields plus `trusted_platform`, `risk_score`, `signals`,
`tier`, `channel`, `operating_mode`, `session_id`, `fingerprint`, `ip`, `asn`.

**Response contract** (**Gap H**). The observable contract is: Step 0 refusals return
403 (proxy, failed attestation) or 426 (app update required); the `challenge` tier on web
returns 200 with a body naming the interactive challenge to render; every other outcome
from Step 1 onward, sent or refused, returns 200 with the same body, `{"status": "ok",
"message": "If this number is eligible, a code has been sent."}`. So a caller can learn
that it was not a legitimate client (Step 0), or that it must solve a challenge, but not
whether a code was sent or which later step refused it. An ASGI middleware pads the whole
request, from arrival to just before the response is written, to a minimum
`RESPONSE_FLOOR_MS = 400`; this is a floor, not a constant response time, and
`results/performance.md` reports what an attacker measuring latency can and cannot
distinguish. The floor must sit
above the deployment's p99 processing time under production load, including vendor calls;
`results/performance.md` reports the fraction of requests that exceeded it in the load
test (those leak timing), and a single uvicorn worker at high concurrency exceeds it, so
size the worker count so that it does not. Two exceptions: the
`challenge` tier on web returns the challenge to render, and a legacy app past the grace
window receives `update_required`. Step 0 proxy and attestation failures return a
generic 403 because those clients are not legitimate users.

```
// Pseudocode for Validation Step 11
function logAndSend(request, providerConfig):
    channel = selectChannel(request.tier, request)
    if channel is null:
        return uniformResponse()             // downgrade with no channel: silently dropped

    logId = addSmsHistoryToDatabase({
        "source": request.source, "phone_number": request.mobile,
        "headers": jsonEncode(request.headers), "content": request.text,
        "sms_provider": providerConfig.provider if channel == "sms" else null,
        "channel": channel, "trusted_platform": request.trustedPlatform,
        "risk_score": request.riskScore, "signals": request.signals, "tier": request.tier,
        "operating_mode": operatingMode(), "session_id": request.sessionId,
        "fingerprint": request.fingerprint, "ip": request.ip, "asn": request.ipInfo.asn
    })

    if channel == "sms":
        redis.incr("global:sms:count:" + currentHour())
        redis.incrby("global:sms:spend:" + currentHour(), request.prefix.costUnits)
        delay = 0 if request.tier == "allow" else min(5 * 2 ** previousSessionRequests(request.sessionId), 60)
        enqueueSend(providerConfig.provider, request.mobile, request.text, logId, delay)
    else:
        enqueueSend(channel, request.mobile, request.text, logId, 0)

    recordSent(request)                      // increments `sent` on every reputation key
    scheduleVerificationTimeout(logId, 600)  // feedback loop: unverified after 10 min counts as failed
    return uniformResponse()
```

## Verification Feedback Loop (asynchronous)

**Purpose:** Turn the attacker's own behaviour into the strongest signal in the system.
Legitimate users verify the code they asked for; flooders never do.

**Events:**

- `otp_verified(logId)`: the code was entered correctly. Increment `verified` on every
  reputation key attached to the send (ip, subnet, asn, fingerprint, session, country,
  prefix, number).
- `otp_failed(logId)`: five wrong attempts. Increment `failed`.
- `otp_delivered(logId)` / `otp_undelivered(logId)`: the provider's delivery receipt. An
  undelivered send increments `undelivered` and nothing else.
- `otp_timeout(logId)`: the resolution timeout (2 minutes) passed after delivery with no
  verification. Increment `failed`; the code stays valid until its 10-minute expiry and a
  late verification is reclassified.

**Derived effects:**

- `conversionRatio(key)` feeds Step 7 on every later request from that key. A ratio
  under 0.3 with at least 20 resolved sends adds up to 25 risk points.
- Keys whose ratio drops below 0.1 with at least 50 resolved sends are placed on a
  24-hour **auto-denylist** and blocked at Step 2 (IP, subnet, and ASN only when it is a
  hosting or datacenter ASN) or Step 1 (fingerprints). A residential ASN is never
  denylisted: it holds thousands of real users, and blocking it would hand the attacker a
  denial of service. Residential attacks are handled by the score instead: the conversion
  penalty (+25) plus the sustained-flood bonus (+15) push every request on that key into
  the `challenge` tier, so real users on the same ISP solve an interactive challenge and
  are served while the bot is not.
- A verified number is marked trusted: it skips HLR lookup and receives -20 risk points.
- The adaptive limits job (Step 9) reads conversion per (source, platform, country).

**Protecting the verify endpoint itself:** 5 attempts per OTP, then the code is
invalidated; 20 verify calls per session per 10 minutes; codes expire after 10 minutes.

```
// Pseudocode for the feedback loop
function onOtpVerified(logId):
    send = smsHistory.get(logId)
    for key in reputationKeysOf(send): reputation.incr(key, "verified")
    reputation.markTrusted("num:" + send.phone_number)

function onOtpFailedOrTimeout(logId):
    send = smsHistory.get(logId)
    for key in reputationKeysOf(send):
        reputation.incr(key, "failed")
        r = reputation.get(key)
        resolved = r.verified + r.failed
        if resolved >= 50 and r.verified / resolved < 0.1:
            if key is ip, subnet, fingerprint, or a datacenter asn:
                denylist.add(key, ttl = 86400)
```

## Observability

- Metrics per step: requests, rejects, latency; per tier and channel: sends, verifies,
  conversion; global: SMS count, spend units, operating mode.
- Alerts: circuit breaker mode change, conversion ratio for any country below 0.3 over an
  hour, HLR reject rate above 30 %, any single ASN above 20 % of traffic.
- Dashboards show conversion by country, platform and ASN so that limit tuning is based
  on evidence.

## Full Pipeline

```
function processOtpRequest(request):
    if not connectionAndClientIntegrityCheck(request):
        return updateRequiredResponse() if request.updateRequired else forbidden()     // Step 0
    if not validateSession(request):                          return uniformResponse() // Step 1
    if not validateNetworkThrottles(request):                 return uniformResponse() // Step 2
    if not validateReCaptcha(request, recaptchaMinScore()):   return uniformResponse() // Step 3
    if not validateHttpOrigin(request, ALLOWED_DOMAINS):      return uniformResponse() // Step 4
    if not validateNumber(request):                           return uniformResponse() // Step 5
    if not validateSmsText(request, EXCLUDED_NUMBERS):        return uniformResponse() // Step 6
    if not riskDecision(request):
        return challengeResponse() if request.requiresChallenge else uniformResponse() // Step 7
    if not validateRateLimitPerMobile(request.mobile):        return uniformResponse() // Step 8
    if not validateSourceRateLimit(request, SOURCE_LIMITS):   return uniformResponse() // Step 9
    circuitBreaker(request)                                                            // Step 10
    return logAndSend(request, PROVIDER_CONFIG)                                        // Step 11
```

## Summary

v2 keeps every v1 control and closes the gaps an adapted attacker exploits. Platform
exemptions require attestation, clients carry a signed identity, network throttles work
at IP, subnet and ASN level atomically, and numbers are validated for country, cost,
pattern and liveness before any money is spent. A risk score built on those signals and
on the verify-to-send ratio decides between allow, delay, challenge, downgrade and block,
with progressive backoff, adaptive caps and a global circuit breaker bounding the damage
of anything that gets through. Uniform responses stop the pipeline from being probed.

## Default Values and the Reasoning Behind Them

All thresholds are configuration, but the defaults below are deliberate choices and
should be changed only with evidence from the dashboards.

| Setting                          | Default | Reason                                                                 |
|----------------------------------|---------|------------------------------------------------------------------------|
| Risk tier boundaries             | 20 / 40 / 60 / 80 | Even bands. A clean web user scores under 15; one strong abuse signal alone (+25) lands in `delay`, never `block`; blocking needs three or more independent signals. |
| Conversion penalty threshold     | 0.3, min 20 resolved sends | Legitimate OTP conversion runs 70 to 90 %. Anything under 30 % is not a bad UX day, it is a flood. 20 resolved sends keeps a single user's typos from triggering it, and counting only resolved sends keeps a fresh burst of real traffic neutral. |
| Auto-denylist threshold          | 0.1, min 50 resolved sends, 24 h; IP, subnet, fingerprint and datacenter ASNs only | Under 10 % on 50 resolved sends has no legitimate explanation. 24 hours limits the blast radius of a shared NAT being denylisted. Residential ASNs are excluded: blocking one is a denial of service against its customers. |
| Sustained-flood bonus            | +15 at ≥ 100 resolved and ratio < 0.1 | Lets a residential attack that rotates IPs and pre-aged fingerprints reach the `challenge` tier (25 + 15 + 2.5 = 42.5) without denylisting anything shared. Real users on the attacked key see one interactive challenge, not a refusal. |
| Resolution timeout               | 120 s (code validity stays 600 s) | The reputation signal fires five times sooner; late verifications are reclassified, so nothing is lost. |
| Destination block key            | first 8 digits | 10 000 numbers: small enough that legitimate traffic rarely shares a block with a pumper, large enough that a pumper's carrier range fills it. |
| Relative baseline (opt-in)       | recent hour < 0.6 × own 23-hour baseline, ≥ 200 resolved history | Reacts to a drop on a key whose cumulative ratio is propped up by history; needs hours of history and added nothing in the evaluation, so it is not a default. |
| Block SPRT thresholds            | likelihood ratio 1 000; legitimate conversion 0.8 vs attacker 0.1; legitimate instant-verify 0.005 vs machine 0.9; at least 3 events | A block is a key only one party uses, so a sequential test decides in a handful of events: five unverified sends (false-positive 0.03 %) or three instant verifications. Fixed sample sizes of 50 or 100 were set for shared keys and let a pumper leak 50 SMS per block. |
| Per-IP cap on CGNAT carriers     | 30 / minute for listed ASNs | Mobile carriers put hundreds of subscribers behind one address; at 5 / minute half of a normal sign-up flow would be refused (see `results/analysis.md`). |
| Circuit breaker soft / hard      | 80 % / 100 % of hourly budget | 80 % leaves room for the elevated mode to take effect before the hard cap. The hourly budget itself should be set to 2x the p99 legitimate hourly volume from the last quarter. |
| reCAPTCHA minimum score          | 0.5 normal, 0.7 elevated | Google's documented midpoint; 0.7 in elevated mode trades some friction for protection only while under attack. |
| Apps without attestation         | 30-day grace as `legacy_app` (+20 risk, `delay` at best), then blocked with `update_required` | Attestation is mandatory; a permanent exemption would recreate Gap A. A fixed grace window with a forced-update cutoff is the standard mobile rollout pattern and gives users a clear action. |
| Response time floor              | 400 ms | Above the pipeline p95 including HLR, so early rejects and full sends are indistinguishable by timing. |
| Per-number daily cap             | 5      | A real user who fails to receive a code retries two or three times; five covers a bad network day. |
| Session OTP requests             | 3 per 10 min | Matches a normal resend flow with one retry to spare. |
| Subnet / datacenter ASN caps     | 30 / 50 per minute | A residential /24 rarely produces more than a handful of registrations per minute; datacenter ranges should produce almost none. |

## Change Log

### v2 (this revision)

Addresses Gaps A to H from `problem_statement.md` and adds the distinctive controls:

1. Step 0 derives platform from attestation, not the header (Gap A).
2. Step 1 adds signed session tokens, fingerprints and nonce replay protection (Gap B).
3. Step 2 adds subnet and ASN throttles with datacenter caps (Gap B).
4. All rate limits use an atomic Lua check-and-increment (Gap F).
5. Step 5 adds prefix cost classes, sequential and narrow-range detection, and HLR lookup
   (Gaps C and D).
6. Bulk and test-server bypasses require an internal service credential (Gap G).
7. Step 7 risk score engine with tiered responses (Gap H).
8. Step 8 progressive backoff and a daily cap per number.
9. Step 9 adaptive multipliers from a traffic baseline and conversion ratio.
10. Step 10 global circuit breaker on count and spend with elevated and emergency modes
    (Gap E).
11. Step 11 channel downgrade, delayed sends and uniform responses (Gap H).
12. Verification feedback loop and auto-denylist.
13. Attestation made mandatory for apps with a 30-day legacy grace window, and default
    values fixed with rationale (see "Default Values").

### v1 reconciliation (previous revision)

1. Per-number limit aligned to 1 SMS per minute per the problem statement.
2. IP throttling step added (5 per IP per minute).
3. Step 0 logic corrected so a proxy is always blocked.
4. reCAPTCHA gained a minimum-score threshold.
5. Country validation pseudocode received the platform and bulk parameters it used.
6. Text validation pseudocode gained the `EXCLUDED_NUMBERS` check.
7. Source rate limit checks both windows before consuming either.
8. Per-country overrides added to source limits.
9. "Sliding window" wording removed where the implementation is a fixed window.
10. Step count and Markdown heading levels fixed.
