# Step 5: Number Intelligence

Source: `docs/sms_validation_process.md`, section "Step 5: Number Intelligence".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.step5_number, NumberTracker`

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
