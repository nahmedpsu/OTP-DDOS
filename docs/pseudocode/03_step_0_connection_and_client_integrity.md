# Step 0: Connection and Client Integrity

Source: `docs/sms_validation_process.md`, section "Step 0: Connection and Client Integrity".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.establish_trusted_platform, Pipeline.step0_connection_and_client_integrity`

```
// Pseudocode for Validation Step 0
function establishTrustedPlatform(request):
    if request.hasAttestation():
        result = verifyAttestation(request.attestation, request.nonce)
        if not result.valid:
            return "invalid"
        return result.platform                // "ios" or "android"
    if request.headers.has("X-App-Version"):
        if now() < ATTESTATION_GRACE_UNTIL:
            request.signals.add("legacy_app")
            return "legacy_app"
        return "update_required"
    return "web"

function connectionAndClientIntegrityCheck(request):
    if check_is_proxy_connection():
        return false

    request.trustedPlatform = establishTrustedPlatform(request)
    if request.trustedPlatform == "invalid":
        logSecurity("attestation_failed", request)
        return false
    if request.trustedPlatform == "update_required":
        request.updateRequired = true        // Step 11 returns the update_required response
        return false

    if request.host != "example.com" and request.trustedPlatform == "web":
        return false

    return true
```
