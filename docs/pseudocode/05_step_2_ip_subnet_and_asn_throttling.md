# Step 2: IP, Subnet and ASN Throttling

Source: `docs/sms_validation_process.md`, section "Step 2: IP, Subnet and ASN Throttling".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.step2_network_throttles`

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
