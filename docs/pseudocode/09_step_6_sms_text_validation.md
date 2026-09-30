# Step 6: SMS Text Validation

Source: `docs/sms_validation_process.md`, section "Step 6: SMS Text Validation".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.step6_text`

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
