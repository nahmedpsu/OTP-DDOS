# Full Pipeline

Source: `docs/sms_validation_process.md`, section "Full Pipeline".

Implemented in: `src/otp_guard/pipeline.py: Pipeline._process, Pipeline.process`

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
