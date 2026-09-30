# SMS Validation Process (v2)

## Overview

The SMS validation process is a layered security, risk-scoring and rate-limiting pipeline
that every OTP request passes through before a message is sent. It addresses the original
OTP flood incident and the evolved attacks described in `Problem_Statement.md`.

Two principles drive the design:

1. **Cheap, local checks first.** Reject obvious abuse before spending on network calls
   (reCAPTCHA, HLR lookup) and long before spending on an SMS.
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
| 10   | Global circuit breaker (count and spend)         | **Gap E** no global cap                  |
| 11   | Channel selection, send, log, uniform response   | Audit, **Gap H** enumeration             |
| FB   | Verification feedback loop (async)               | Conversion-based reputation              |

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

```
function conversionRatio(repKey, minSample = 20):
    r = reputation.get(repKey)
    if r.sent < minSample:
        return null                          // not enough data: neutral
    return r.verified / r.sent
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
  - No attestation → platform `web`. The request then has no exemptions and must pass
    reCAPTCHA and origin validation like any browser.
- `HTTP_HOST` must be `example.com` unless the trusted platform is `ios` or `android`.

**Examples:**

| Host              | Header platform | Attestation | Proxy | Trusted platform | Result                       |
|-------------------|-----------------|-------------|-------|------------------|------------------------------|
| example.com       | web             | none        | no    | web              | Allowed                      |
| example.com       | web             | none        | yes   | web              | Blocked (proxy)              |
| someotherhost.com | ios             | none        | no    | web              | Blocked (spoofed platform, unauthorized host) |
| someotherhost.com | ios             | valid       | no    | ios              | Allowed (attested app)       |
| someotherhost.com | ios             | invalid     | no    | -                | Blocked (bad attestation)    |

```
// Pseudocode for Validation Step 0
function establishTrustedPlatform(request):
    if request.hasAttestation():
        result = verifyAttestation(request.attestation, request.nonce)
        if not result.valid:
            return "invalid"
        return result.platform                // "ios" or "android"
    return "web"

function connectionAndClientIntegrityCheck(request):
    if check_is_proxy_connection():
        return false

    request.trustedPlatform = establishTrustedPlatform(request)
    if request.trustedPlatform == "invalid":
        logSecurity("attestation_failed", request)
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
  the trusted platform from Step 0.
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
| IP                       | 5 / minute         | The v1 control                                 |
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

Applies when the **trusted** platform is `web` (which now includes any app request that
did not attest). The token must be valid and its score must meet `RECAPTCHA_MIN_SCORE`
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
- Oman (`968`) is blocked unless the trusted platform is `ios` or `android`.
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
| Geo mismatch: IP country != number country | +10                                      |
| `sequential_number`, `narrow_range_burst` | +15 each                                  |
| `elevated_prefix`, `unknown_prefix`, `voip_number` | +10 each                         |
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
               "challenge_passed": -20 }.get(sig, 0)
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
baseline job:

- Every hour, compute the expected volume for each (source, platform, country,
  hour-of-day, day-of-week) from the last 4 weeks (median and MAD).
- Multiplier rises toward 1.5 when the key's conversion ratio is healthy (≥ 0.5) and
  traffic is within 2 MAD of expected.
- Multiplier falls toward 0.25 when traffic exceeds expected by more than 3 MAD or the
  key's conversion ratio drops below 0.3.
- Marketing calendar entries override the multiplier upward for planned campaigns.

Both windows are checked before either counter is consumed.

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
    if source not in limits:
        return true
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
the window rolls. A manual **kill switch** (`SMS_KILL_SWITCH`) forces `emergency`.

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

    if mode == "emergency" and request.riskScore >= 10:
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

**Audit log** includes the v1 fields plus `trusted_platform`, `risk_score`, `signals`,
`tier`, `channel`, `operating_mode`, `session_id`, `fingerprint`, `ip`, `asn`.

**Uniform response** (**Gap H**): every outcome from Step 1 onward returns HTTP 200 with
the same body, `{"status": "ok", "message": "If this number is eligible, a code has been
sent."}`, and the handler pads its processing time to a constant floor so that timing does
not reveal which step rejected the request. The one exception is the `challenge` tier on
web, which returns the challenge to render. Step 0 failures return a generic 403 because
those clients are not legitimate users.

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
- `otp_timeout(logId)`: 10 minutes elapsed with no verification. Increment `failed`.

**Derived effects:**

- `conversionRatio(key)` feeds Step 7 on every later request from that key. A ratio
  under 0.3 with at least 20 sends adds up to 25 risk points.
- Keys whose ratio drops below 0.1 with at least 50 sends are placed on a 24-hour
  **auto-denylist** and blocked at Step 2 (network keys) or Step 1 (fingerprints).
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
        if r.sent >= 50 and r.verified / r.sent < 0.1:
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
    if not connectionAndClientIntegrityCheck(request):        return forbidden()     // Step 0
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

## Change Log

### v2 (this revision)

Addresses Gaps A to H from `Problem_Statement.md` and adds the distinctive controls:

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
