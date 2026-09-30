# SMS Validation Process

## Overview

The SMS validation process is a layered security and rate-limiting pipeline that every
SMS request passes through before a message is sent. It exists to stop the OTP flood
abuse described in the problem statement: attackers hitting the registration API with
randomly generated mobile numbers and burning SMS budget at scale.

The pipeline has **9 sequential steps, numbered 0 to 8**. Each step returns `true` to
continue or `false` to reject the request. The first failing step stops processing.

| Step | Check                                     | Control from the problem statement            |
|------|-------------------------------------------|-----------------------------------------------|
| 0    | Initial security check (proxy / host)     | VPN and proxy blocking                        |
| 1    | IP-based throttling                       | IP-based throttling (5 requests / IP / minute)|
| 2    | Google reCAPTCHA (score-based)            | Hidden reCAPTCHA with score-based validation  |
| 3    | HTTP Origin validation                    | Domain whitelisting                           |
| 4    | Mobile number country validation          | Country whitelisting                          |
| 5    | SMS text validation                       | SMS body restrictions                         |
| 6    | Rate limiting per mobile number           | 1 SMS per number per minute                   |
| 7    | Rate limiting per source, platform, country| Platform- and country-based rate limits      |
| 8    | Logging and sending                       | Audit trail                                   |

The steps are ordered so that cheap, local checks run before expensive or network-bound
ones (for example, the IP throttle runs before the reCAPTCHA call to Google).

## Validation Steps

### Step 0: Initial Security Check

**Purpose:** Block high-risk requests before any further processing.

Blocks a request when **either** of the following is true:

- The connection comes through a proxy or VPN (detected via `check_is_proxy_connection()`).
- The `HTTP_HOST` is not `example.com` **and** the platform is not iOS.

Both conditions are independent. A proxy connection is blocked regardless of host or
platform. A non-iOS request from an unauthorized host is blocked regardless of proxy status.

**Examples:**

| Host              | Platform | Proxy | Result                                   |
|-------------------|----------|-------|------------------------------------------|
| example.com       | web      | no    | Allowed                                  |
| example.com       | web      | yes   | Blocked (proxy)                          |
| someotherhost.com | web      | no    | Blocked (unauthorized host, not iOS)     |
| someotherhost.com | ios      | no    | Allowed (iOS exemption)                  |
| someotherhost.com | ios      | yes   | Blocked (proxy)                          |

```
// Pseudocode for Validation Step 0
function initialSecurityCheck(host, platform, isProxyConnection):
    if isProxyConnection:
        return false

    if host != "example.com" and platform != "ios":
        return false

    return true

// Example
host = "randomhost.com"
platform = "web"
isProxy = false
isAllowed = initialSecurityCheck(host, platform, isProxy)
// isAllowed = false (blocked: unauthorized host and platform is not iOS)
```

### Step 1: IP-Based Throttling

**Purpose:** Limit how many SMS requests a single client IP can make, so that a single
source cannot flood the endpoint even when it varies the target phone number.

**Limit rule:** Maximum **5 requests per IP address per minute**.

The IP is taken from the connection (or from the trusted forwarding header when the
request passes through the platform's own load balancer). Because attackers rotate IPs,
this step is a first-line throttle only and is complemented by the per-number and
per-source limits in Steps 6 and 7.

```
// Pseudocode for Validation Step 1
function validateRateLimitPerIp(ip):
    rateLimit = new RateLimit()
    rateLimit.setLimit(5, 60)               // 5 requests per 60 seconds
    rateLimit.setKey("send_global_sms:ip")
    rateLimit.setIdentifier(ip)

    if rateLimit.hasExceededLimit():
        logError("IP request cap reached: " + ip)
        return false

    rateLimit.incrementCount()
    return true

// Example
ip = "203.0.113.7"
canProceed = validateRateLimitPerIp(ip)
// canProceed = false if this IP has already made 5 requests in the last minute
```

### Step 2: Google reCAPTCHA Validation

**Purpose:** Prevent automated or bot submissions on the web platform.

For web platform requests only:

- The request must include a hidden reCAPTCHA token (`g-recaptcha-response`).
- The token is verified through Google's reCAPTCHA service using `verifyGoogleReCaptcha()`.
- The verification result must be **valid** and its **score must meet or exceed the
  configured threshold** (`RECAPTCHA_MIN_SCORE`, default `0.5`). Low-trust traffic with a
  valid token but a low score is still rejected.
- Non-web platforms (iOS, Android) skip this step.

**Example:**

- Platform: web
- reCAPTCHA token: `03AGdBq24PBgq8...`
- Verification result: valid, score 0.9
- Result: Allowed (valid token and score above threshold)

```
// Pseudocode for Validation Step 2
function validateReCaptcha(post, platform, minScore):
    if platform != "web":
        return true                          // Skip for non-web platforms

    recaptchaResult = verifyGoogleReCaptcha(post)
    if not recaptchaResult["valid"]:
        return false

    if recaptchaResult["score"] < minScore:
        logError("reCAPTCHA score below threshold: " + recaptchaResult["score"])
        return false

    return true

// Example
post = {
    "g-recaptcha-response": "03AGdBq24PBgq8...",
    "other_data": "..."
}
platform = "web"
isValidCaptcha = validateReCaptcha(post, platform, 0.5)
// isValidCaptcha = true if the token is valid and the score is >= 0.5
```

### Step 3: HTTP Origin Validation

**Purpose:** Ensure requests come from approved domains.

Extracts the root domain from the `Origin` header and checks it against the allowed
domains list. Only requests from allowed domains are processed.

**Approved domains (example):**

- admin.example.com
- example.com
- api.example.com
- partner.example.com

**Example:**

- Origin: `https://app.example.com/send-sms`
- Extracted root domain: `example.com`
- Result: Allowed (in allowed domains list)

```
// Pseudocode for Validation Step 3
function validateHttpOrigin(origin, allowedDomains):
    extractedDomain = extractRootDomainFromUrl(origin)
    return extractedDomain in allowedDomains

// Example
origin = "https://app.example.com/send-sms"
allowedDomains = ["admin.example.com", "example.com", "api.example.com", "partner.example.com"]
isValidOrigin = validateHttpOrigin(origin, allowedDomains)
// isValidOrigin = true (example.com is in allowedDomains)
```

### Step 4: Mobile Number Country Validation

**Purpose:** Restrict SMS sending to approved countries.

**Key rules:**

- The mobile number must begin with a country code from the approved list.
- Special restriction: Oman (`968`) numbers are blocked unless the platform is iOS or
  Android (they are not allowed from web).
- Bulk SMS requests skip this step entirely.

**Processing steps:**

1. Remove the `+` sign and any leading zeros from the number.
2. Take the first 3 digits as the country code.
3. Apply the Oman-from-web restriction.
4. Verify the country code against the allowed list.

**Example:**

- Mobile: `+966501234567` (Saudi Arabia)
- Platform: web
- Result: Allowed if `966` is in the allowed country codes list

```
// Pseudocode for Validation Step 4
function validateMobileCountry(mobile, platform, isBulkSms, allowedCountryCodes):
    if isBulkSms:
        return true                          // Bulk SMS skips country validation

    mobile = removePlusSign(mobile)
    mobile = removeLeadingZeros(mobile)
    countryCode = getFirstThreeDigits(mobile)

    // Special case: block Oman (968) from web
    if countryCode == "968" and platform != "ios" and platform != "android":
        return false

    return countryCode in allowedCountryCodes

// Example
mobile = "+966501234567"
platform = "web"
isBulk = false
allowedCountryCodes = ["966", "971", "965", "968"]   // Example country codes
isValidMobile = validateMobileCountry(mobile, platform, isBulk, allowedCountryCodes)
// isValidMobile = true (966 is in allowedCountryCodes)
```

### Step 5: SMS Text Validation

**Purpose:** Ensure SMS content meets requirements and the recipient is not blocked.

**Requirements:**

- Request is not from the test server (test server requests skip this step).
- SMS text is not empty (minimum 1 character).
- SMS text does not exceed **420 characters** (3 SMS units of 140 characters).
- The mobile number is **not** in the `EXCLUDED_NUMBERS` list.

**Example:**

- SMS text: `Your verification code is 1234` (30 chars)
- Mobile: `966501234567`, not in `EXCLUDED_NUMBERS`
- Result: Allowed

```
// Pseudocode for Validation Step 5
function validateSmsText(text, mobile, isTestServer, excludedNumbers):
    if isTestServer:
        return true                          // Skip for test server

    if mobile in excludedNumbers:
        return false

    textLength = length(text)
    if textLength < 1 or textLength > 420:
        return false

    return true

// Example
smsText = "Your verification code is 1234. Please enter this code in the app to verify your account."
mobile = "966501234567"
isTestServer = false
excludedNumbers = ["966500000000", "971500000000"]
isValidText = validateSmsText(smsText, mobile, isTestServer, excludedNumbers)
// isValidText = true (text is within 1..420 chars and the number is not excluded)
```

### Step 6: Rate Limiting Per Mobile Number

**Purpose:** Prevent SMS flooding to an individual number.

**Limit rule:** Maximum **1 SMS per mobile number per minute** (60-second window).

The `RateLimit` class tracks the request count for each mobile number within the window.
A second request for the same number inside the window is rejected until the window
expires.

**Example:**

- Mobile: `966501234567`
- Previous SMS sent: 20 seconds ago
- Result: Rejected (less than 60 seconds since the last SMS)

```
// Pseudocode for Validation Step 6
function validateRateLimitPerMobile(mobile):
    rateLimit = new RateLimit()
    rateLimit.setLimit(1, 60)               // 1 SMS per 60 seconds
    rateLimit.setKey("send_global_sms:limit")
    rateLimit.setIdentifier(mobile)

    if rateLimit.hasExceededLimit():
        return false

    rateLimit.incrementCount()
    return true

// Example
mobile = "966501234567"
canSendSms = validateRateLimitPerMobile(mobile)
// canSendSms = false if another SMS was sent to this number in the last 60 seconds
```

### Step 7: Rate Limiting Per Source, Platform and Country

**Purpose:** Enforce aggregate sending caps so that a burst of otherwise-valid requests
cannot exhaust SMS resources.

Limits are keyed on:

- **Source** (e.g. `App/RegisterOTP`)
- **Platform** (iOS, Android, web)
- **Country code** of the recipient (optional override; falls back to the platform limit)
- **Time period** (per minute and per hour)

Thresholds are tuned per platform and per country from historical usage and peak
marketing periods. If no limits are configured for a source, the step passes.

Both the per-minute and per-hour limits are **checked before either counter is
incremented**, so a request rejected by the hour cap does not consume a minute slot.

**Example limits:**

| Platform | Per minute | Per hour |
|----------|-----------:|---------:|
| iOS      | 10         | 100      |
| Web      | 5          | 50       |
| Android  | 8          | 80       |

**Example:**

- Source: `App/RegisterOTP`
- Platform: iOS
- Country: `966`, no country override configured
- Per-minute limit: 10 SMS; current count: 9 in the last minute
- Per-hour limit: 100 SMS; current count: 40 in the last hour
- Result: Allowed (under both limits)

```
// Pseudocode for Validation Step 7
function resolveLimit(sourceLimit, period, platform, countryCode):
    // period is "per_minute" or "per_hour"
    // A per-country override wins over the platform default when present
    overrides = sourceLimit.get("per_country", {})
    if countryCode in overrides and (period + "_" + platform) in overrides[countryCode]:
        return overrides[countryCode][period + "_" + platform]
    return sourceLimit[period + "_" + platform]

function validateSourceRateLimit(source, platform, countryCode, limits):
    if source not in limits:
        return true                          // No limits configured for this source

    sourceLimit = limits[source]

    minuteLimit = new RateLimit()
    minuteLimit.setLimit(resolveLimit(sourceLimit, "per_minute", platform, countryCode), 60)
    minuteLimit.setKey("sms_cap_per_minute_" + platform + ":limit")
    minuteLimit.setIdentifier(source + ":" + countryCode)

    hourLimit = new RateLimit()
    hourLimit.setLimit(resolveLimit(sourceLimit, "per_hour", platform, countryCode), 3600)
    hourLimit.setKey("sms_cap_per_hour_" + platform + ":limit")
    hourLimit.setIdentifier(source + ":" + countryCode)

    // Check both limits first, then increment both
    if minuteLimit.hasExceededLimit():
        logError(platform + " SMS PerMinute Cap Reached!")
        return false

    if hourLimit.hasExceededLimit():
        logError(platform + " SMS PerHour Cap Reached!")
        return false

    minuteLimit.incrementCount()
    hourLimit.incrementCount()
    return true

// Example
source = "App/RegisterOTP"
platform = "ios"
countryCode = "966"
limits = {
    "App/RegisterOTP": {
        "per_minute_ios": 10,
        "per_hour_ios": 100,
        "per_minute_web": 5,
        "per_hour_web": 50,
        "per_minute_android": 8,
        "per_hour_android": 80,
        "per_country": {
            "968": { "per_minute_web": 2, "per_hour_web": 20 }
        }
    }
}
isWithinLimits = validateSourceRateLimit(source, platform, countryCode, limits)
// isWithinLimits = true if under both the per-minute and per-hour limits
```

### Step 8: Logging and Sending SMS

**Purpose:** Final processing of a fully validated request.

After all validations pass:

1. Write an audit log of the SMS request: source, recipient number, request headers,
   message content and selected provider.
2. Send the SMS through the configured provider (`PROVIDER_A`, `PROVIDER_B` or
   `PROVIDER_C`).
3. Return the success or failure status to the requester.

**Example log entry:**

```json
{
  "source": "App/RegisterOTP",
  "phone_number": "966501234567",
  "headers": {"User-Agent": "Mozilla/5.0..."},
  "content": "Your verification code is 1234",
  "sms_provider": "PROVIDER_A"
}
```

```
// Pseudocode for Validation Step 8
function logAndSendSms(source, mobile, headers, message, provider):
    log = {
        "source": source,
        "phone_number": mobile,
        "headers": jsonEncode(headers),
        "content": message,
        "sms_provider": provider
    }
    logId = addSmsHistoryToDatabase(log)

    if provider == "PROVIDER_A":
        return sendViaProviderA(mobile, message, logId)
    else if provider == "PROVIDER_B":
        return sendViaProviderB(mobile, message, logId)
    else:                                    // Default to PROVIDER_C
        return sendViaProviderC(mobile, message, logId)

// Example
source = "App/RegisterOTP"
mobile = "966501234567"
headers = {"User-Agent": "Mozilla/5.0..."}
message = "Your verification code is 1234"
provider = "PROVIDER_A"
success = logAndSendSms(source, mobile, headers, message, provider)
// success = true if the SMS was sent successfully
```

## Full Pipeline

```
function processSmsRequest(request):
    if not initialSecurityCheck(request.host, request.platform, check_is_proxy_connection()):
        return reject("blocked_connection")
    if not validateRateLimitPerIp(request.ip):
        return reject("ip_rate_limited")
    if not validateReCaptcha(request.post, request.platform, RECAPTCHA_MIN_SCORE):
        return reject("recaptcha_failed")
    if not validateHttpOrigin(request.origin, ALLOWED_DOMAINS):
        return reject("invalid_origin")
    if not validateMobileCountry(request.mobile, request.platform, request.isBulkSms, ALLOWED_COUNTRY_CODES):
        return reject("country_not_allowed")
    if not validateSmsText(request.text, request.mobile, IS_TEST_SERVER, EXCLUDED_NUMBERS):
        return reject("invalid_text_or_excluded_number")
    if not validateRateLimitPerMobile(request.mobile):
        return reject("mobile_rate_limited")
    if not validateSourceRateLimit(request.source, request.platform, countryCodeOf(request.mobile), SOURCE_LIMITS):
        return reject("source_rate_limited")
    return logAndSendSms(request.source, request.mobile, request.headers, request.text, SMS_PROVIDER)
```

## Summary

The SMS validation process provides multiple layers of security and rate limiting to
allow legitimate use while preventing abuse. Each step addresses a specific risk, from
proxy and bot prevention through per-IP, per-number and per-source flood protection,
with comprehensive logging for auditing. The system maintains strict controls while
allowing flexibility for different platforms, countries and use cases.

## Reconciliation Notes

This document supersedes the earlier `sms_1.md` and the SMS Validation Process PDF. The
following inconsistencies between those documents and the Problem Statement were resolved:

1. **Per-number limit.** The Problem Statement specifies 1 SMS per number per minute; the
   earlier validation docs said 1 per 5 seconds. Aligned to **1 per 60 seconds** (Step 6).
2. **IP throttling was missing.** The Problem Statement lists 5 requests per IP per
   minute, but no validation step implemented it. Added as **Step 1**.
3. **Step 0 logic.** The earlier pseudocode combined host, platform and proxy with AND, so
   a proxy from the correct host was allowed. Rewritten so a proxy is always blocked and a
   non-iOS request from an unauthorized host is always blocked.
4. **reCAPTCHA scoring.** The Problem Statement describes score-based validation; the
   earlier docs only checked token validity. Added a minimum-score threshold (Step 2).
5. **Country validation pseudocode** referenced `platform` without receiving it and
   omitted the bulk-SMS skip. Both added (Step 4).
6. **SMS text pseudocode** omitted the `EXCLUDED_NUMBERS` check described in the prose.
   Added (Step 5).
7. **Source rate limit counter ordering.** The minute counter was incremented before the
   hour check, so hour-capped requests still consumed minute slots. Both limits are now
   checked before either is incremented (Step 7).
8. **Country-based rate limits** from the Problem Statement were absent. Added an
   optional per-country override to the source limits (Step 7).
9. **"Sliding window" wording.** The PDF claimed sliding-window tracking for Step 6 but
   the pseudocode shows a fixed-window counter. The document now describes the window
   without asserting a sliding implementation.
10. **Step count and heading levels.** The overview said "7 steps" for a 0–7 pipeline and
    the Markdown heading depth grew with each step (up to ten `#`). Fixed to a 0–8
    pipeline with consistent `###` headings.
