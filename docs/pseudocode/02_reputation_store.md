# Reputation Store

Source: `docs/sms_validation_process.md`, section "Reputation Store".

Implemented in: `src/otp_guard/reputation.py: ReputationStore.conversion_ratio`

```
function conversionRatio(repKey, minSample = 20):
    r = reputation.get(repKey)
    resolved = r.verified + r.failed
    if resolved < minSample:
        return null                          // not enough data: neutral
    return r.verified / resolved
```
