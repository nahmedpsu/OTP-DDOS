# Step 1: Client Session Token and Fingerprint

Source: `docs/sms_validation_process.md`, section "Step 1: Client Session Token and Fingerprint".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.step1_session, SessionService`

```
// Pseudocode for Validation Step 1
function validateSession(request):
    token = verifySignedToken(request.sessionToken, SESSION_HMAC_KEY)
    if token is null or token.expires_at < now():
        return false
    if token.platform != request.trustedPlatform:
        return false                         // token issued to a different platform

    if not redis.setnx("nonce:" + request.nonce, 1, ttl = 600):
        return false                         // replay

    request.sessionId = token.session_id
    request.fingerprint = token.fingerprint_hash
    request.fingerprintAgeHours = fingerprintAge(request.fingerprint)

    sessionLimit = new RateLimit()
    sessionLimit.setLimit(3, 600)            // 3 OTP requests per 10 minutes per session
    sessionLimit.setKey("otp:session")
    sessionLimit.setIdentifier(request.sessionId)
    return sessionLimit.tryAcquire()
```
