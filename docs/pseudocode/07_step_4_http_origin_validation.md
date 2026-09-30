# Step 4: HTTP Origin Validation

Source: `docs/sms_validation_process.md`, section "Step 4: HTTP Origin Validation".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.step4_origin`

```
// Pseudocode for Validation Step 4
function validateHttpOrigin(request, allowedDomains):
    if request.trustedPlatform != "web":
        return true
    return extractRootDomainFromUrl(request.origin) in allowedDomains
```
