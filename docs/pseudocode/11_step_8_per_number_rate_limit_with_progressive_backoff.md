# Step 8: Per-Number Rate Limit with Progressive Backoff

Source: `docs/sms_validation_process.md`, section "Step 8: Per-Number Rate Limit with Progressive Backoff".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.step8_per_number`

```
// Pseudocode for Validation Step 8
function validateRateLimitPerMobile(mobile):
    sends = reputation.get("num:" + mobile).sent      // rolling 24h
    if sends >= 5:
        return false

    window = min(60 * 2 ** max(sends - 1, 0), 3600) if sends > 0 else 60
    rateLimit = new RateLimit()
    rateLimit.setLimit(1, window)
    rateLimit.setKey("send_global_sms:limit")
    rateLimit.setIdentifier(mobile)
    return rateLimit.tryAcquire()
```
