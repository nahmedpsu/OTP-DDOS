# Step 3: Google reCAPTCHA Validation

Source: `docs/sms_validation_process.md`, section "Step 3: Google reCAPTCHA Validation".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.step3_recaptcha`

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
