# Step 7: Risk Score Engine and Tier Decision

Source: `docs/sms_validation_process.md`, section "Step 7: Risk Score Engine and Tier Decision".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.compute_risk_score, Pipeline.decide_tier, Pipeline.step7_risk`

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
