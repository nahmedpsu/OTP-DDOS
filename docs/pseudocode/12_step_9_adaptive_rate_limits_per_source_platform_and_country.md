# Step 9: Adaptive Rate Limits per Source, Platform and Country

Source: `docs/sms_validation_process.md`, section "Step 9: Adaptive Rate Limits per Source, Platform and Country".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.effective_limit, Pipeline.step9_source_limits; src/otp_guard/reputation.py: AdaptiveLimits`

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
